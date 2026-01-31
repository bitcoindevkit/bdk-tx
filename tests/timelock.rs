//! Integration tests for timelock functionality against Bitcoin Core.
//!
//! These tests verify that the `is_timelocked`, `is_block_timelocked`, `is_time_timelocked`,
//! and `is_spendable` methods correctly predict when transactions can be broadcast.

use std::{fmt::Debug, sync::Arc};

use bdk_bitcoind_rpc::{bitcoincore_rpc::RpcApi, Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_chain::{
    miniscript::ForEachKey, Anchor, Balance, BlockId, CanonicalizationParams, ChainPosition,
    ToBlockHash, ToBlockTime,
};
use bdk_coin_select::ChangePolicy;
use bdk_testenv::TestEnv;
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, CanonicalUnspents,
    ConfirmationStatus, FeeStrategy, Input, InputCandidates, Output, PsbtParams, ScriptSource,
    SelectorParams, TxWithStatus,
};
use bitcoin::{
    absolute::{self, Time},
    block::Header,
    key::Secp256k1,
    relative, transaction, Address, Amount, FeeRate, OutPoint, Sequence, Transaction, TxIn, TxOut,
};
use miniscript::{
    descriptor::KeyMap,
    plan::{Assets, Plan},
    Descriptor, DescriptorPublicKey,
};

const EXTERNAL: &str = "external";
const INTERNAL: &str = "internal";

// Test xprv for creating timelocked descriptors
const TEST_XPRV: &str = "tprv8ZgxMBicQKsPd3krDUsBAmtnRsK3rb8u5yi1zhQgMhF1tR8MW7xfE4rnrbbsrbPR52e7rKapu6ztw1jXveJSCGHEriUGZV7mCe88duLp5pj";

/// A minimal wallet for testing timelocks.
struct TestWallet {
    chain: bdk_chain::local_chain::LocalChain<Header>,
    graph: bdk_chain::IndexedTxGraph<
        BlockId,
        bdk_chain::keychain_txout::KeychainTxOutIndex<&'static str>,
    >,
    view: bdk_chain::CanonicalView<BlockId>,
    signer: KeyMap,
    secp: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
}

fn old_rpc_client(env: &TestEnv) -> anyhow::Result<bdk_bitcoind_rpc::bitcoincore_rpc::Client> {
    Ok(bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
        &env.bitcoind.rpc_url(),
        bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(
            (&env.bitcoind.params).cookie_file.clone(),
        ),
    )?)
}

impl TestWallet {
    fn new(
        genesis_header: Header,
        external: Descriptor<DescriptorPublicKey>,
        internal: Descriptor<DescriptorPublicKey>,
        keymap: KeyMap,
    ) -> anyhow::Result<Self> {
        let mut indexer = bdk_chain::keychain_txout::KeychainTxOutIndex::default();
        indexer.insert_descriptor(EXTERNAL, external)?;
        indexer.insert_descriptor(INTERNAL, internal)?;
        let graph = bdk_chain::IndexedTxGraph::new(indexer);
        let (chain, _) = bdk_chain::local_chain::LocalChain::from_genesis(genesis_header);
        let view = graph.canonical_view(
            &chain,
            chain.tip().block_id(),
            CanonicalizationParams::default(),
        );
        Ok(Self {
            chain,
            graph,
            view,
            signer: keymap,
            secp: Secp256k1::new(),
        })
    }

    fn sync(&mut self, env: &TestEnv) -> anyhow::Result<()> {
        let client = old_rpc_client(env)?;
        let last_cp = self.chain.tip();
        let mut emitter = Emitter::new(&client, last_cp, 0, NO_EXPECTED_MEMPOOL_TXS);
        while let Some(event) = emitter.next_block()? {
            let _ = self
                .graph
                .apply_block_relevant(&event.block, event.block_height());
            let _ = self.chain.apply_update(event.checkpoint);
        }
        let mempool = emitter.mempool()?;
        let _ = self.graph.batch_insert_relevant_unconfirmed(mempool.update);
        let _ = self.graph.batch_insert_relevant_evicted_at(mempool.evicted);
        self.view = self.graph.canonical_view(
            &self.chain,
            self.chain.tip().block_id(),
            CanonicalizationParams::default(),
        );
        Ok(())
    }

    fn next_address(&mut self) -> Option<Address> {
        let ((_, spk), _) = self.graph.index.next_unused_spk(EXTERNAL)?;
        Address::from_script(&spk, bitcoin::consensus::Params::REGTEST).ok()
    }

    fn balance(&self) -> Balance {
        self.view
            .balance(self.graph.index.outpoints().clone(), |_, _| true, 0)
    }

    fn tip_height(&self) -> u32 {
        self.chain.tip().block_id().height
    }

    fn tip_info(&self, client: &impl RpcApi) -> anyhow::Result<(absolute::Height, absolute::Time)> {
        let tip_hash = self.chain.tip().block_id().hash;
        let tip_info = client.get_block_header_info(&tip_hash)?;
        let tip_height = absolute::Height::from_consensus(tip_info.height as u32)?;
        let tip_mtp = absolute::Time::from_consensus(
            tip_info.median_time.expect("must have median time") as _,
        )?;
        Ok((tip_height, tip_mtp))
    }

    fn assets(&self) -> Assets {
        let index = &self.graph.index;
        let tip = self.chain.tip().block_id();
        Assets::new()
            .after(absolute::LockTime::from_height(tip.height).expect("must be valid height"))
            .add({
                let mut pks = vec![];
                for (_, desc) in index.keychains() {
                    desc.for_any_key(|k| {
                        pks.extend(k.clone().into_single_keys());
                        true
                    });
                }
                pks
            })
    }

    fn plan_of_output(&self, outpoint: OutPoint, assets: &Assets) -> Option<Plan> {
        let index = &self.graph.index;
        let ((k, i), _txout) = index.txout(outpoint)?;
        let desc = index.get_descriptor(k)?.at_derivation_index(i).ok()?;
        desc.plan(assets).ok()
    }

    fn canonical_txs(&self) -> impl Iterator<Item = TxWithStatus<Arc<Transaction>>> + '_ {
        pub fn status_from_position<D>(
            cp_tip: bdk_chain::CheckPoint<D>,
            pos: ChainPosition<BlockId>,
        ) -> Option<ConfirmationStatus>
        where
            D: ToBlockHash + ToBlockTime + Clone + Debug,
        {
            match pos {
                bdk_chain::ChainPosition::Confirmed { anchor, .. } => {
                    let cp = cp_tip.get(anchor.height)?;
                    if cp.hash() != anchor.hash {
                        // TODO: This should only happen if anchor is transitive.
                        return None;
                    }
                    let prev_mtp = cp
                        .prev()
                        .and_then(|prev_cp| prev_cp.median_time_past())
                        .map(|time| Time::from_consensus(time).expect("must convert!"));

                    Some(ConfirmationStatus {
                        height: absolute::Height::from_consensus(
                            anchor.confirmation_height_upper_bound(),
                        )
                        .expect("must convert to height"),
                        prev_mtp,
                    })
                }
                bdk_chain::ChainPosition::Unconfirmed { .. } => None,
            }
        }
        self.view
            .txs()
            .map(|c_tx| (c_tx.tx, status_from_position(self.chain.tip(), c_tx.pos)))
    }

    fn drain_weights(&self) -> bdk_coin_select::DrainWeights {
        let desc = self
            .graph
            .index
            .get_descriptor(INTERNAL)
            .unwrap()
            .at_derivation_index(0)
            .unwrap();

        let output_weight = TxOut {
            script_pubkey: desc.script_pubkey(),
            value: Amount::ZERO,
        }
        .weight()
        .to_wu();

        let assets = self.assets();
        let plan = desc.plan(&assets).expect("failed to create Plan");
        let spend_weight =
            bitcoin::TxIn::default().segwit_weight().to_wu() + plan.satisfaction_weight() as u64;

        bdk_coin_select::DrainWeights {
            output_weight,
            spend_weight,
            n_outputs: 1,
        }
    }

    fn change_policy(&self) -> ChangePolicy {
        let spk_0 = self
            .graph
            .index
            .spk_at_index(INTERNAL, 0)
            .expect("spk should exist");
        ChangePolicy {
            min_value: spk_0.minimal_non_dust().to_sat(),
            drain_weights: self.drain_weights(),
        }
    }

    fn all_candidates(&self, assets: &Assets) -> InputCandidates {
        let index = &self.graph.index;
        let canon_utxos = CanonicalUnspents::new(self.canonical_txs());
        let can_select = canon_utxos.try_get_unspents(
            index
                .outpoints()
                .iter()
                .filter_map(|(_, op)| Some((*op, self.plan_of_output(*op, assets)?))),
        );
        InputCandidates::new([], can_select)
    }
}

/// Test absolute block-height timelock checking logic.
///
/// This test verifies that `is_block_timelocked` and `is_spendable` correctly
/// identify when an input with an absolute block height timelock can be spent.
#[test]
fn test_absolute_block_height_timelock_logic() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    // Create a timelocked descriptor
    let lock_height = 110u32;
    let desc_str = format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/*),after({lock_height})))");
    let (external, external_keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;

    let (internal, internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let keymap = {
        let mut keymap = KeyMap::new();
        keymap.extend(external_keymap);
        keymap.extend(internal_keymap);
        keymap
    };

    let env = TestEnv::new()?;
    let client = old_rpc_client(&env)?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    env.mine_blocks(101, None)?;

    let mut wallet = TestWallet::new(genesis_header, external, internal, keymap)?;
    wallet.sync(&env)?;

    // Fund the wallet
    let addr = wallet.next_address().expect("must derive address");
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
    let secp = Secp256k1::new();

    // Create a descriptor with relative timelock
    let relative_lock_blocks = 5u16;
    let desc_str =
        format!("wsh(and_v(v:pk({TEST_XPRV}/86'/1'/0'/0/*),older({relative_lock_blocks})))");
    let (external, external_keymap) = Descriptor::parse_descriptor(&secp, &desc_str)?;

    let (internal, internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let keymap = {
        let mut keymap = KeyMap::new();
        keymap.extend(external_keymap);
        keymap.extend(internal_keymap);
        keymap
    };

    let env = TestEnv::new()?;
    let client = old_rpc_client(&env)?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    env.mine_blocks(101, None)?;

    let mut wallet = TestWallet::new(genesis_header, external, internal, keymap)?;
    wallet.sync(&env)?;

    // Fund the wallet
    let addr = wallet.next_address().expect("must derive address");
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
    let secp = Secp256k1::new();

    let (external, external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[3])?;
    let (internal, internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let keymap = {
        let mut km = KeyMap::new();
        km.extend(external_keymap);
        km.extend(internal_keymap);
        km
    };

    let env = TestEnv::new()?;
    let client = old_rpc_client(&env)?;

    let genesis_hash = env.genesis_hash()?;
    let genesis_header = env
        .rpc_client()
        .get_block_header(&genesis_hash)?
        .block_header()?;

    // Only mine a few blocks initially
    env.mine_blocks(10, None)?;

    let mut wallet = TestWallet::new(genesis_header, external, internal.clone(), keymap)?;
    wallet.sync(&env)?;

    // Get wallet address and mine a block to it (creates coinbase output)
    let addr = wallet.next_address().expect("must derive address");
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
        .all_candidates(&assets)
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
                ScriptSource::Descriptor(Box::new(internal.at_derivation_index(0)?)),
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

    // Test at various heights
    let below_lock = absolute::Height::from_consensus(lock_height - 10)?;
    let at_lock = absolute::Height::from_consensus(lock_height - 1)?; // spending_height = lock_height
    let above_lock = absolute::Height::from_consensus(lock_height + 10)?;

    // Below lock height: should be timelocked
    assert!(
        input.is_block_timelocked(below_lock),
        "should be timelocked at height {} (lock: {})",
        below_lock.to_consensus_u32(),
        lock_height
    );

    // At lock height (spending_height = tip + 1 = lock_height): should NOT be timelocked
    assert!(
        !input.is_block_timelocked(at_lock),
        "should NOT be timelocked when spending_height = {} (lock: {})",
        at_lock.to_consensus_u32() + 1,
        lock_height
    );

    // Above lock height: should NOT be timelocked
    assert!(
        !input.is_block_timelocked(above_lock),
        "should NOT be timelocked at height {} (lock: {})",
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
