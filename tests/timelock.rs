//! Integration tests for timelock functionality against Bitcoin Core.
//!
//! These tests verify that the `is_timelocked`, `is_block_timelocked`, `is_time_timelocked`,
//! and `is_spendable` methods correctly predict when transactions can be broadcast.

use bdk_chain::miniscript::ForEachKey;
use bdk_testenv::{MineParams, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, CanonicalUnspents,
    ConfirmationStatus, FeeStrategy, Input, Output, PsbtParams, ScriptSource, SelectorParams,
};
use bdk_tx_testenv::{TestEnvExt, Wallet, EXTERNAL, INTERNAL};
use bitcoin::{
    absolute, key::Secp256k1, relative, transaction, Amount, FeeRate, Sequence, Transaction, TxIn,
    TxOut,
};
use miniscript::{plan::Assets, Descriptor};

// Test xprv for creating timelocked descriptors
const TEST_XPRV: &str = "tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj";

/// Test absolute block-height timelock checking logic.
///
/// This test verifies that `is_block_timelocked` and `is_spendable` correctly
/// identify when an input with an absolute block height timelock can be spent.
#[test]
fn test_absolute_block_height_timelock_logic() -> anyhow::Result<()> {
    // Create a timelocked descriptor
    let lock_height = 110u32;
    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/*),after({lock_height})))");

    let env = TestEnv::new()?;
    let client = env.old_rpc_client()?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    env.mine_blocks(101, None)?;

    let mut wallet = Wallet::single_keychain(genesis_header, &desc_str)?;
    wallet.sync(&env)?;

    // Fund the wallet
    let addr = wallet.next_address(EXTERNAL).expect("must derive address");
    env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;

    assert!(wallet.balance().confirmed > Amount::ZERO);

    let current_height = wallet.tip_height();
    println!("Current height: {current_height}, lock height: {lock_height}");
    assert!(
        current_height < lock_height,
        "test setup: should be below lock height"
    );

    // Create assets with the lock height requirement
    let abs_lock = absolute::LockTime::from_height(lock_height)?;
    let assets = Assets::new().after(abs_lock).add({
        let mut pks = vec![];
        for (_, desc) in wallet.graph.index.keychains() {
            desc.for_each_key(|k| {
                pks.extend(k.clone().into_single_keys());
                true
            });
        }
        pks
    });

    // Get the input
    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();

    assert!(!inputs.is_empty(), "should have at least one input");
    let input = &inputs[0];

    // Verify the input has an absolute timelock
    assert!(
        input.absolute_timelock().is_some(),
        "input should have absolute timelock"
    );
    println!("Input absolute timelock: {:?}", input.absolute_timelock());

    // BEFORE lock height: should be locked
    assert!(
        input.is_block_timelocked(tip_height),
        "should be block-timelocked at height {} (lock: {})",
        tip_height.to_consensus_u32(),
        lock_height
    );
    assert_eq!(
        input.is_spendable(tip_height, Some(tip_mtp)),
        Some(false),
        "should not be spendable before lock height"
    );

    // Mine to reach lock height
    let blocks_to_mine = lock_height.saturating_sub(current_height) + 1;
    env.mine_blocks(blocks_to_mine as usize, None)?;
    wallet.sync(&env)?;

    let (new_tip_height, new_tip_mtp) = wallet.tip_info(&client)?;
    println!("New height: {}", new_tip_height.to_consensus_u32());

    // Refresh input
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();

    let input = &inputs[0];

    // AFTER lock height: should NOT be locked
    assert!(
        !input.is_block_timelocked(new_tip_height),
        "should NOT be block-timelocked at height {} (lock: {})",
        new_tip_height.to_consensus_u32(),
        lock_height
    );
    assert_eq!(
        input.is_spendable(new_tip_height, Some(new_tip_mtp)),
        Some(true),
        "should be spendable after lock height"
    );

    Ok(())
}

/// Test relative block-height timelock checking logic.
///
/// This test verifies that `is_block_timelocked` and `is_spendable` correctly
/// identify when an input with a relative block timelock (CSV) can be spent.
#[test]
fn test_relative_block_height_timelock_logic() -> anyhow::Result<()> {
    // Create a descriptor with relative timelock
    let relative_lock_blocks = 5u16;
    let desc_str =
        format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/*),older({relative_lock_blocks})))");

    let env = TestEnv::new()?;
    let client = env.old_rpc_client()?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    env.mine_blocks(101, None)?;

    let mut wallet = Wallet::multi_keychain(
        genesis_header,
        [
            (EXTERNAL, desc_str.as_str()),
            (INTERNAL, bdk_testenv::utils::DESCRIPTORS[4]),
        ],
    )?;
    wallet.sync(&env)?;

    // Fund the wallet
    let addr = wallet.next_address(EXTERNAL).expect("must derive address");
    let funding_txid = env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;

    let confirmation_height = wallet.tip_height();
    println!("Funding tx {funding_txid} confirmed at height {confirmation_height}");

    assert!(wallet.balance().confirmed > Amount::ZERO);

    // Create assets with relative timelock requirement
    let rel_lock = relative::LockTime::from_height(relative_lock_blocks);
    let assets = Assets::new()
        .after(absolute::LockTime::from_height(wallet.tip_height()).expect("must be valid height"))
        .older(rel_lock)
        .add({
            let mut pks = vec![];
            for (_, desc) in wallet.graph.index.keychains() {
                desc.for_each_key(|k| {
                    pks.extend(k.clone().into_single_keys());
                    true
                });
            }
            pks
        });

    // Get the input
    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();

    assert!(!inputs.is_empty(), "should have at least one input");
    let input = &inputs[0];

    // Verify the input has a relative timelock
    assert!(
        input.relative_timelock().is_some(),
        "input should have relative timelock"
    );
    println!("Input relative timelock: {:?}", input.relative_timelock());
    println!(
        "Input confirmed at height: {:?}",
        input.status().map(|s| s.height.to_consensus_u32())
    );

    // IMMEDIATELY after confirmation: should be locked
    assert!(
        input.is_block_timelocked(tip_height),
        "should be block-timelocked immediately after confirmation"
    );
    assert_eq!(
        input.is_spendable(tip_height, Some(tip_mtp)),
        Some(false),
        "should not be spendable immediately after confirmation"
    );

    // Mine blocks to satisfy relative timelock
    env.mine_blocks(relative_lock_blocks as usize, None)?;
    wallet.sync(&env)?;

    let (new_tip_height, new_tip_mtp) = wallet.tip_info(&client)?;
    let blocks_since_confirm = new_tip_height.to_consensus_u32() - confirmation_height + 1;
    println!(
        "New height: {}, blocks since confirmation: {}",
        new_tip_height.to_consensus_u32(),
        blocks_since_confirm
    );

    // Refresh input
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();

    let input = &inputs[0];

    // AFTER relative lock: should NOT be locked
    assert!(
        !input.is_block_timelocked(new_tip_height),
        "should NOT be block-timelocked after {} blocks",
        blocks_since_confirm
    );
    assert_eq!(
        input.is_spendable(new_tip_height, Some(new_tip_mtp)),
        Some(true),
        "should be spendable after relative lock expires"
    );

    Ok(())
}

/// Test coinbase maturity (100 blocks required).
///
/// This test verifies the full flow: maturity checking AND actual broadcast.
#[test]
fn test_coinbase_maturity() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    let client = env.old_rpc_client()?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    // Only mine a few blocks initially
    env.mine_blocks(10, None)?;

    let mut wallet = Wallet::multi_keychain(
        genesis_header,
        [
            (EXTERNAL, bdk_testenv::utils::DESCRIPTORS[3]),
            (INTERNAL, bdk_testenv::utils::DESCRIPTORS[4]),
        ],
    )?;
    wallet.sync(&env)?;

    // Get wallet address and mine a block to it (creates coinbase output)
    let addr = wallet.next_address(EXTERNAL).expect("must derive address");
    env.mine_blocks(1, Some(addr.clone()))?;
    wallet.sync(&env)?;

    let confirmation_height = wallet.tip_height();
    println!("Coinbase at height {confirmation_height}");

    // Get the coinbase input
    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    let assets = wallet.assets();
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();

    // Find the coinbase input
    let coinbase_input = inputs.iter().find(|i| i.is_coinbase());
    assert!(coinbase_input.is_some(), "should have coinbase input");
    let input = coinbase_input.unwrap();

    // Check immaturity
    let is_immature = input.is_immature(tip_height);
    println!(
        "At height {} (0 blocks after coinbase), is_immature: {}",
        tip_height.to_consensus_u32(),
        is_immature
    );
    assert!(is_immature, "coinbase should be immature");

    // Verify is_spendable returns false
    let is_spendable = input.is_spendable(tip_height, Some(tip_mtp));
    assert_eq!(
        is_spendable,
        Some(false),
        "immature coinbase should not be spendable"
    );

    // Mine 99 more blocks (total 100 for maturity)
    env.mine_blocks(99, None)?;
    wallet.sync(&env)?;

    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    println!(
        "After 99 more blocks, tip height: {}",
        tip_height.to_consensus_u32()
    );

    // Refresh input
    let assets = wallet.assets();
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();

    let coinbase_input = inputs.iter().find(|i| i.is_coinbase()).unwrap();

    let is_immature = coinbase_input.is_immature(tip_height);
    let is_spendable = coinbase_input.is_spendable(tip_height, Some(tip_mtp));
    println!(
        "At height {}: is_immature={}, is_spendable={:?}",
        tip_height.to_consensus_u32(),
        is_immature,
        is_spendable
    );

    assert!(!is_immature, "coinbase should be mature after 100 blocks");
    assert_eq!(
        is_spendable,
        Some(true),
        "mature coinbase should be spendable"
    );

    // Verify we can actually broadcast
    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .address()?
        .assume_checked();

    let selection = wallet
        .all_candidates_with(&assets)
        .regroup(group_by_spk())
        .filter(filter_unspendable_now(tip_height, Some(tip_mtp)))
        .into_selection(
            selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb_unchecked(1), 100_000),
            SelectorParams::new(
                FeeStrategy::FeeRate(FeeRate::from_sat_per_vb_unchecked(10)),
                vec![Output::with_script(
                    recipient_addr.script_pubkey(),
                    Amount::from_sat(10_000),
                )],
                ScriptSource::Descriptor(Box::new(wallet.definite_descriptor(INTERNAL, 0)?)),
                wallet.change_policy(),
            ),
        )?;

    let mut psbt = selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;
    let finalizer = selection.into_finalizer();

    let _ = psbt.sign(&wallet.signer, &wallet.secp);
    let res = finalizer.finalize(&mut psbt);
    assert!(res.is_finalized(), "should finalize");

    let tx = psbt.extract_tx()?;
    let txid = env.rpc_client().send_raw_transaction(&tx)?.txid()?;
    println!("Mature coinbase spent: {txid}");

    Ok(())
}

/// Unit test for `is_block_timelocked` using directly constructed Input.
///
/// This test creates Input objects directly to test the timelock checking logic
/// without needing a full wallet setup.
#[test]
fn test_is_block_timelocked_unit() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    // Create a simple timelocked descriptor
    let lock_height = 100u32;
    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/0),after({lock_height})))");
    let (desc, _keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;
    let def_desc = desc.at_derivation_index(0)?;

    // Create a dummy transaction to get an outpoint
    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            script_pubkey: def_desc.script_pubkey(),
            value: Amount::ONE_BTC,
        }],
    };

    // Create assets for planning - must include the lock height and keys
    let mut pks = vec![];
    desc.for_each_key(|k| {
        pks.extend(k.clone().into_single_keys());
        true
    });
    let assets = Assets::new()
        .after(absolute::LockTime::from_height(lock_height)?)
        .add(pks);

    let plan = def_desc.plan(&assets).expect("should create plan");

    // Create input without confirmation status (unconfirmed)
    let input = Input::from_prev_tx(plan, prev_tx, 0, None)?;

    // Verify the input has the expected absolute timelock
    assert_eq!(
        input.absolute_timelock(),
        Some(absolute::LockTime::from_height(lock_height)?)
    );

    // Test at various heights.
    // Bitcoin Core `IsFinalTx` checks: `nLockTime < nBlockHeight` where nBlockHeight = tip + 1.
    // So the tx is final (unlocked) when `lock_height < tip + 1`, i.e., `tip >= lock_height`.
    let below_lock = absolute::Height::from_consensus(lock_height - 10)?;
    let at_lock_minus_1 = absolute::Height::from_consensus(lock_height - 1)?; // spending_height = lock_height
    let at_lock = absolute::Height::from_consensus(lock_height)?; // spending_height = lock_height + 1
    let above_lock = absolute::Height::from_consensus(lock_height + 10)?;

    // Well below lock height: should be timelocked
    assert!(
        input.is_block_timelocked(below_lock),
        "should be timelocked at tip {} (lock: {})",
        below_lock.to_consensus_u32(),
        lock_height
    );

    // At tip = lock_height - 1 (spending_height = lock_height): still locked
    // Core: lock < spending_height → 100 < 100 → false → non-final
    assert!(
        input.is_block_timelocked(at_lock_minus_1),
        "should be timelocked at tip {} (spending_height = lock = {})",
        at_lock_minus_1.to_consensus_u32(),
        lock_height
    );

    // At tip = lock_height (spending_height = lock_height + 1): unlocked
    // Core: lock < spending_height → 100 < 101 → true → final
    assert!(
        !input.is_block_timelocked(at_lock),
        "should NOT be timelocked at tip {} (spending_height {} > lock {})",
        at_lock.to_consensus_u32(),
        at_lock.to_consensus_u32() + 1,
        lock_height
    );

    // Above lock height: should NOT be timelocked
    assert!(
        !input.is_block_timelocked(above_lock),
        "should NOT be timelocked at tip {} (lock: {})",
        above_lock.to_consensus_u32(),
        lock_height
    );

    Ok(())
}

/// Unit test for relative timelock checking.
#[test]
fn test_is_block_timelocked_relative_unit() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    // Create a descriptor with relative timelock
    let rel_blocks = 10u16;
    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/0),older({rel_blocks})))");
    let (desc, _keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;
    let def_desc = desc.at_derivation_index(0)?;

    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            script_pubkey: def_desc.script_pubkey(),
            value: Amount::ONE_BTC,
        }],
    };

    // Create assets with keys and timelocks
    let mut pks = vec![];
    desc.for_each_key(|k| {
        pks.extend(k.clone().into_single_keys());
        true
    });
    let assets = Assets::new()
        .after(absolute::LockTime::from_height(200)?)
        .older(relative::LockTime::from_height(rel_blocks))
        .add(pks);

    let plan = def_desc.plan(&assets).expect("should create plan");

    // Confirmed at height 100
    let conf_height = 100u32;
    let status = ConfirmationStatus::new(conf_height, None)?;

    let input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;

    // Verify the input has the expected relative timelock
    assert_eq!(
        input.relative_timelock(),
        Some(relative::LockTime::from_height(rel_blocks))
    );

    // Test at various heights relative to confirmation
    // spending_height = tip_height + 1
    // height_diff = spending_height - conf_height

    // 5 blocks after confirmation: height_diff = 6 < 10, should be locked
    let tip_5_after = absolute::Height::from_consensus(conf_height + 4)?;
    assert!(
        input.is_block_timelocked(tip_5_after),
        "should be timelocked 5 blocks after confirmation (need {})",
        rel_blocks
    );

    // 10 blocks after confirmation: height_diff = 11 >= 10, should NOT be locked
    let tip_10_after = absolute::Height::from_consensus(conf_height + 9)?;
    assert!(
        !input.is_block_timelocked(tip_10_after),
        "should NOT be timelocked 10 blocks after confirmation"
    );

    // 15 blocks after confirmation: should NOT be locked
    let tip_15_after = absolute::Height::from_consensus(conf_height + 14)?;
    assert!(
        !input.is_block_timelocked(tip_15_after),
        "should NOT be timelocked 15 blocks after confirmation"
    );

    Ok(())
}

/// Test absolute time-based timelock boundary: BDK's prediction must match Bitcoin Core.
///
/// At MTP = lock_time - 1: BDK says locked, Bitcoin Core rejects broadcast.
/// At MTP = lock_time:     BDK says unlocked, Bitcoin Core accepts broadcast.
#[test]
fn test_absolute_time_timelock_logic() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    let client = env.old_rpc_client()?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    env.mine_blocks(101, None)?;

    // We need to know the current MTP to choose a lock_time in the future.
    // Create a temporary wallet just to read MTP.
    let mut wallet = Wallet::single_keychain(genesis_header, bdk_testenv::utils::DESCRIPTORS[0])?;
    wallet.sync(&env)?;
    let (_, initial_mtp) = wallet.tip_info(&client)?;
    let lock_time = initial_mtp.to_consensus_u32() + 1800; // 30 minutes in the future
    println!(
        "Initial MTP: {}, lock_time: {lock_time}",
        initial_mtp.to_consensus_u32()
    );

    // Now create the actual timelocked wallet
    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/*),after({lock_time})))");
    let mut wallet = Wallet::multi_keychain(
        genesis_header,
        [
            (EXTERNAL, desc_str.as_str()),
            (INTERNAL, bdk_testenv::utils::DESCRIPTORS[4]),
        ],
    )?;
    wallet.sync(&env)?;

    // Fund the wallet
    let addr = wallet.next_address(EXTERNAL).expect("must derive address");
    env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;

    assert!(wallet.balance().confirmed > Amount::ZERO);

    // Build assets with the time-based lock
    let abs_lock = absolute::LockTime::from_consensus(lock_time);
    let assets = Assets::new().after(abs_lock).add({
        let mut pks = vec![];
        for (_, desc) in wallet.graph.index.keychains() {
            desc.for_each_key(|k| {
                pks.extend(k.clone().into_single_keys());
                true
            });
        }
        pks
    });

    // Verify the input has a time-based absolute timelock
    {
        let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
        let inputs: Vec<Input> = wallet
            .graph
            .index
            .outpoints()
            .iter()
            .filter_map(|(_, op)| {
                let plan = wallet.plan_of_output(*op, &assets)?;
                canon_utxos.try_get_unspent(*op, plan)
            })
            .collect();
        assert!(!inputs.is_empty(), "should have at least one input");
        assert!(
            matches!(
                inputs[0].absolute_timelock(),
                Some(absolute::LockTime::Seconds(_))
            ),
            "input should have time-based absolute timelock, got: {:?}",
            inputs[0].absolute_timelock()
        );
    }

    // Build + sign + finalize the spending tx once
    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .address()?
        .assume_checked();

    let selection = wallet
        .all_candidates_with(&assets)
        .regroup(group_by_spk())
        .into_selection(
            selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb_unchecked(1), 100_000),
            SelectorParams::new(
                FeeStrategy::FeeRate(FeeRate::from_sat_per_vb_unchecked(10)),
                vec![Output::with_script(
                    recipient_addr.script_pubkey(),
                    Amount::from_sat(50_000),
                )],
                ScriptSource::Descriptor(Box::new(wallet.definite_descriptor(INTERNAL, 0)?)),
                wallet.change_policy(),
            ),
        )?;

    let mut psbt = selection.create_psbt(PsbtParams {
        fallback_locktime: abs_lock,
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;
    let finalizer = selection.into_finalizer();
    let _ = psbt.sign(&wallet.signer, &wallet.secp);
    let res = finalizer.finalize(&mut psbt);
    assert!(res.is_finalized(), "should finalize");
    let tx = psbt.extract_tx()?;

    // Verify the tx has the expected time-based locktime
    assert_eq!(
        tx.lock_time, abs_lock,
        "tx locktime should match the absolute time lock"
    );

    // --- BOUNDARY - 1: MTP = lock_time - 1 ---
    // Mine 6 blocks at lock_time - 1 to shift MTP. After 6 blocks at timestamp T,
    // the last 11 blocks are [old*5, T*6], so the 6th value (median) = T.
    for _ in 0..6 {
        let mut params = MineParams::default();
        params.time = Some(lock_time - 1);
        env.mine_block(params)?;
    }
    wallet.sync(&env)?;

    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    println!(
        "After mining at lock_time-1: tip_height={}, tip_mtp={}",
        tip_height.to_consensus_u32(),
        tip_mtp.to_consensus_u32()
    );
    assert_eq!(
        tip_mtp.to_consensus_u32(),
        lock_time - 1,
        "MTP should be exactly lock_time - 1"
    );

    // Refresh input and check BDK says locked
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();
    let input = &inputs[0];

    assert_eq!(
        input.is_time_timelocked(tip_mtp),
        Some(true),
        "BDK should say time-timelocked at MTP = lock_time - 1"
    );
    assert_eq!(
        input.is_spendable(tip_height, Some(tip_mtp)),
        Some(false),
        "BDK should say not spendable at MTP = lock_time - 1"
    );

    // Bitcoin Core should reject the broadcast
    let broadcast_result = env.rpc_client().send_raw_transaction(&tx);
    assert!(
        broadcast_result.is_err(),
        "Bitcoin Core should reject broadcast at MTP = lock_time - 1"
    );
    println!("Broadcast correctly rejected at MTP = lock_time - 1");

    // --- AT MTP = lock_time: still locked ---
    // Bitcoin Core: nLockTime < MTP → lock_time < lock_time → false → non-final
    // Mine 6 more blocks at lock_time to shift median
    for _ in 0..6 {
        let mut params = MineParams::default();
        params.time = Some(lock_time);
        env.mine_block(params)?;
    }
    wallet.sync(&env)?;

    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    println!(
        "After mining at lock_time: tip_height={}, tip_mtp={}",
        tip_height.to_consensus_u32(),
        tip_mtp.to_consensus_u32()
    );
    assert_eq!(
        tip_mtp.to_consensus_u32(),
        lock_time,
        "MTP should be exactly lock_time"
    );

    // Refresh input and check BDK says locked
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();
    let input = &inputs[0];

    assert_eq!(
        input.is_time_timelocked(tip_mtp),
        Some(true),
        "BDK should say time-timelocked at MTP = lock_time"
    );
    assert_eq!(
        input.is_spendable(tip_height, Some(tip_mtp)),
        Some(false),
        "BDK should say not spendable at MTP = lock_time"
    );

    // Bitcoin Core should reject
    let broadcast_result = env.rpc_client().send_raw_transaction(&tx);
    assert!(
        broadcast_result.is_err(),
        "Bitcoin Core should reject broadcast at MTP = lock_time"
    );
    println!("Broadcast correctly rejected at MTP = lock_time");

    // --- EXACT BOUNDARY: MTP = lock_time + 1 ---
    // Bitcoin Core: nLockTime < MTP → lock_time < lock_time+1 → true → final
    for _ in 0..6 {
        let mut params = MineParams::default();
        params.time = Some(lock_time + 1);
        env.mine_block(params)?;
    }
    wallet.sync(&env)?;

    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    println!(
        "After mining at lock_time+1: tip_height={}, tip_mtp={}",
        tip_height.to_consensus_u32(),
        tip_mtp.to_consensus_u32()
    );
    assert_eq!(
        tip_mtp.to_consensus_u32(),
        lock_time + 1,
        "MTP should be exactly lock_time + 1"
    );

    // Refresh input and check BDK says unlocked
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();
    let input = &inputs[0];

    assert_eq!(
        input.is_time_timelocked(tip_mtp),
        Some(false),
        "BDK should say NOT time-timelocked at MTP = lock_time + 1"
    );
    assert_eq!(
        input.is_spendable(tip_height, Some(tip_mtp)),
        Some(true),
        "BDK should say spendable at MTP = lock_time + 1"
    );

    // Bitcoin Core should accept the broadcast
    let txid = env.rpc_client().send_raw_transaction(&tx)?.txid()?;
    println!("Broadcast accepted at MTP = lock_time + 1: {txid}");

    Ok(())
}

/// Test relative time-based timelock boundary: BDK's prediction must match Bitcoin Core.
///
/// At time_diff = (lock_value * 512) - 1: BDK says locked, Bitcoin Core rejects.
/// At time_diff = (lock_value * 512):     BDK says unlocked, Bitcoin Core accepts.
#[test]
fn test_relative_time_timelock_logic() -> anyhow::Result<()> {
    // Relative lock = 2 units of 512 seconds = 1024 seconds
    // Raw older() value with time flag: 0x400000 | 2 = 4194306
    let relative_lock_units = 2u16;
    let relative_lock_seconds = relative_lock_units as u32 * 512; // 1024
    let older_value = 0x400000u32 | relative_lock_units as u32; // 4194306
    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/*),older({older_value})))");

    let env = TestEnv::new()?;
    let client = env.old_rpc_client()?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    env.mine_blocks(101, None)?;

    let mut wallet = Wallet::multi_keychain(
        genesis_header,
        [
            (EXTERNAL, desc_str.as_str()),
            (INTERNAL, bdk_testenv::utils::DESCRIPTORS[4]),
        ],
    )?;
    wallet.sync(&env)?;

    // Fund the wallet
    let addr = wallet.next_address(EXTERNAL).expect("must derive address");
    env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;

    assert!(wallet.balance().confirmed > Amount::ZERO);

    // Build assets with the relative time lock
    let rel_lock = relative::LockTime::from_512_second_intervals(relative_lock_units);
    let assets = Assets::new()
        .after(absolute::LockTime::from_height(wallet.tip_height()).expect("must be valid height"))
        .older(rel_lock)
        .add({
            let mut pks = vec![];
            for (_, desc) in wallet.graph.index.keychains() {
                desc.for_each_key(|k| {
                    pks.extend(k.clone().into_single_keys());
                    true
                });
            }
            pks
        });

    // Find the input's prev_mtp (MTP of the block before confirmation)
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();
    assert!(!inputs.is_empty(), "should have at least one input");

    let input = &inputs[0];
    assert!(
        matches!(input.relative_timelock(), Some(relative::LockTime::Time(_))),
        "input should have time-based relative timelock, got: {:?}",
        input.relative_timelock()
    );

    let prev_mtp = input
        .status()
        .expect("input should be confirmed")
        .prev_mtp
        .expect("prev_mtp should be available")
        .to_consensus_u32();
    println!("Input prev_mtp: {prev_mtp}");

    // Build + sign + finalize the spending tx once
    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .address()?
        .assume_checked();

    let selection = wallet
        .all_candidates_with(&assets)
        .regroup(group_by_spk())
        .into_selection(
            selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb_unchecked(1), 100_000),
            SelectorParams::new(
                FeeStrategy::FeeRate(FeeRate::from_sat_per_vb_unchecked(10)),
                vec![Output::with_script(
                    recipient_addr.script_pubkey(),
                    Amount::from_sat(50_000),
                )],
                ScriptSource::Descriptor(Box::new(wallet.definite_descriptor(INTERNAL, 0)?)),
                wallet.change_policy(),
            ),
        )?;

    let mut psbt = selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;
    let finalizer = selection.into_finalizer();
    let _ = psbt.sign(&wallet.signer, &wallet.secp);
    let res = finalizer.finalize(&mut psbt);
    assert!(res.is_finalized(), "should finalize");
    let tx = psbt.extract_tx()?;

    // --- BOUNDARY - 1: time_diff = relative_lock_seconds - 1 ---
    // Mine 6 blocks at the target timestamp to shift MTP. After 6 blocks at timestamp T,
    // the last 11 blocks are [old*5, T*6], so the 6th value (median) = T.
    let target_mtp_before = prev_mtp + relative_lock_seconds - 1;
    for _ in 0..6 {
        let mut params = MineParams::default();
        params.time = Some(target_mtp_before);
        env.mine_block(params)?;
    }
    wallet.sync(&env)?;

    let (_tip_height, tip_mtp) = wallet.tip_info(&client)?;
    let time_diff = tip_mtp.to_consensus_u32().saturating_sub(prev_mtp);
    println!(
        "Before boundary: tip_mtp={}, time_diff={}, required={}",
        tip_mtp.to_consensus_u32(),
        time_diff,
        relative_lock_seconds
    );
    assert_eq!(
        tip_mtp.to_consensus_u32(),
        target_mtp_before,
        "MTP should be prev_mtp + lock_seconds - 1"
    );

    // Refresh input and check BDK says locked
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();
    let input = &inputs[0];

    assert_eq!(
        input.is_time_timelocked(tip_mtp),
        Some(true),
        "BDK should say time-timelocked at time_diff = {} (need {})",
        time_diff,
        relative_lock_seconds
    );

    // Bitcoin Core should reject
    let broadcast_result = env.rpc_client().send_raw_transaction(&tx);
    assert!(
        broadcast_result.is_err(),
        "Bitcoin Core should reject at time_diff = {}",
        time_diff
    );
    println!("Broadcast correctly rejected at time_diff = {time_diff}");

    // --- EXACT BOUNDARY: time_diff = relative_lock_seconds ---
    let target_mtp_at = prev_mtp + relative_lock_seconds;
    for _ in 0..6 {
        let mut params = MineParams::default();
        params.time = Some(target_mtp_at);
        env.mine_block(params)?;
    }
    wallet.sync(&env)?;

    let (_tip_height, tip_mtp) = wallet.tip_info(&client)?;
    let time_diff = tip_mtp.to_consensus_u32().saturating_sub(prev_mtp);
    println!(
        "At boundary: tip_mtp={}, time_diff={}, required={}",
        tip_mtp.to_consensus_u32(),
        time_diff,
        relative_lock_seconds
    );
    assert_eq!(
        tip_mtp.to_consensus_u32(),
        target_mtp_at,
        "MTP should be prev_mtp + lock_seconds"
    );

    // Refresh input and check BDK says unlocked
    let canon_utxos = CanonicalUnspents::new(wallet.canonical_txs());
    let inputs: Vec<Input> = wallet
        .graph
        .index
        .outpoints()
        .iter()
        .filter_map(|(_, op)| {
            let plan = wallet.plan_of_output(*op, &assets)?;
            canon_utxos.try_get_unspent(*op, plan)
        })
        .collect();
    let input = &inputs[0];

    assert_eq!(
        input.is_time_timelocked(tip_mtp),
        Some(false),
        "BDK should say NOT time-timelocked at time_diff = {}",
        time_diff
    );

    // Bitcoin Core should accept
    let txid = env.rpc_client().send_raw_transaction(&tx)?.txid()?;
    println!("Broadcast accepted at time_diff = {time_diff}: {txid}");

    Ok(())
}

/// Unit test for absolute time-based `is_time_timelocked` at exact boundaries.
#[test]
fn test_is_time_timelocked_absolute_unit() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    let lock_time = 500_000_100u32;
    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/0),after({lock_time})))");
    let (desc, _keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;
    let def_desc = desc.at_derivation_index(0)?;

    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            script_pubkey: def_desc.script_pubkey(),
            value: Amount::ONE_BTC,
        }],
    };

    let mut pks = vec![];
    desc.for_each_key(|k| {
        pks.extend(k.clone().into_single_keys());
        true
    });
    let assets = Assets::new()
        .after(absolute::LockTime::from_consensus(lock_time))
        .add(pks);

    let plan = def_desc.plan(&assets).expect("should create plan");
    let input = Input::from_prev_tx(plan, prev_tx, 0, None)?;

    // Verify it has a time-based absolute timelock
    assert!(
        matches!(
            input.absolute_timelock(),
            Some(absolute::LockTime::Seconds(_))
        ),
        "should have time-based absolute timelock"
    );

    // Bitcoin Core `IsFinalTx` checks: `nLockTime < MTP(tip)`.
    // So the tx is final (unlocked) when `lock_time < MTP`, i.e., `MTP > lock_time`.

    // Boundary - 1: mtp = lock_time - 1 → locked
    let mtp_before = absolute::Time::from_consensus(lock_time - 1)?;
    assert_eq!(
        input.is_time_timelocked(mtp_before),
        Some(true),
        "should be timelocked at MTP = lock_time - 1"
    );

    // At mtp = lock_time → still locked (Core: lock < lock is false → non-final)
    let mtp_at = absolute::Time::from_consensus(lock_time)?;
    assert_eq!(
        input.is_time_timelocked(mtp_at),
        Some(true),
        "should be timelocked at MTP = lock_time"
    );

    // At mtp = lock_time + 1 → unlocked (Core: lock < lock+1 → final)
    let mtp_after = absolute::Time::from_consensus(lock_time + 1)?;
    assert_eq!(
        input.is_time_timelocked(mtp_after),
        Some(false),
        "should NOT be timelocked at MTP = lock_time + 1"
    );

    Ok(())
}

/// Unit test for relative time-based `is_time_timelocked` at exact boundaries.
#[test]
fn test_is_time_timelocked_relative_unit() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    // Relative lock = 2 units of 512 seconds = 1024 seconds
    let relative_lock_units = 2u16;
    let relative_lock_seconds = relative_lock_units as u32 * 512; // 1024
    let older_value = 0x400000u32 | relative_lock_units as u32; // 4194306

    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/0),older({older_value})))");
    let (desc, _keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;
    let def_desc = desc.at_derivation_index(0)?;

    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            script_pubkey: def_desc.script_pubkey(),
            value: Amount::ONE_BTC,
        }],
    };

    let mut pks = vec![];
    desc.for_each_key(|k| {
        pks.extend(k.clone().into_single_keys());
        true
    });
    let assets = Assets::new()
        .after(absolute::LockTime::from_consensus(500_000_000))
        .older(relative::LockTime::from_512_second_intervals(
            relative_lock_units,
        ))
        .add(pks);

    let plan = def_desc.plan(&assets).expect("should create plan");

    // Confirmed at height 100, prev_mtp = 500_001_000
    let conf_prev_mtp = 500_001_000u32;
    let status = ConfirmationStatus::new(100, Some(conf_prev_mtp))?;
    let input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;

    // Verify it has a time-based relative timelock
    assert!(
        matches!(input.relative_timelock(), Some(relative::LockTime::Time(_))),
        "should have time-based relative timelock"
    );

    // BDK check: value * 512 > (tip_mtp - prev_mtp) → locked
    // i.e. 1024 > diff → locked

    // Boundary - 1: diff = 1023 → locked (1024 > 1023)
    let mtp_before = absolute::Time::from_consensus(conf_prev_mtp + relative_lock_seconds - 1)?;
    assert_eq!(
        input.is_time_timelocked(mtp_before),
        Some(true),
        "should be timelocked at time_diff = {} (need {})",
        relative_lock_seconds - 1,
        relative_lock_seconds
    );

    // Exact boundary: diff = 1024 → NOT locked (1024 > 1024 is false)
    let mtp_at = absolute::Time::from_consensus(conf_prev_mtp + relative_lock_seconds)?;
    assert_eq!(
        input.is_time_timelocked(mtp_at),
        Some(false),
        "should NOT be timelocked at time_diff = {}",
        relative_lock_seconds
    );

    // After boundary: diff = 1025 → NOT locked
    let mtp_after = absolute::Time::from_consensus(conf_prev_mtp + relative_lock_seconds + 1)?;
    assert_eq!(
        input.is_time_timelocked(mtp_after),
        Some(false),
        "should NOT be timelocked at time_diff = {}",
        relative_lock_seconds + 1
    );

    Ok(())
}
