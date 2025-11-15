#![allow(dead_code)]

use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, ChangePolicyType,
    Output, PsbtParams, ScriptSource, SelectorParams, Signer,
};
use bitcoin::{absolute::LockTime, key::Secp256k1, Amount, FeeRate, Sequence, Transaction};
use miniscript::Descriptor;

mod common;
use common::Wallet;

fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let (external, external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[3])?;
    let (internal, internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let signer = Signer(external_keymap.into_iter().chain(internal_keymap).collect());

    let env = TestEnv::new()?;
    let genesis_hash = env.genesis_hash()?;
    env.mine_blocks(101, None)?;

    let mut wallet = Wallet::new(genesis_hash, external, internal.clone())?;
    wallet.sync(&env)?;

    let addr = wallet.next_address().expect("must derive address");
    println!("Wallet address: {addr}");

    // Fund the wallet with two transactions
    env.send(&addr, Amount::from_sat(100_000_000))?;
    env.send(&addr, Amount::from_sat(100_000_000))?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("Balance: {}", wallet.balance());

    // Create two low-fee parent transactions
    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
    let mut parent_txids = vec![];
    for i in 0..4 {
        let low_fee_selection = wallet
            .all_candidates()
            .regroup(group_by_spk())
            .filter(filter_unspendable_now(tip_height, tip_time))
            .into_selection(
                selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb_unchecked(1), 100_000),
                SelectorParams::new(
                    FeeRate::from_sat_per_vb_unchecked(1),
                    vec![Output::with_script(
                        addr.script_pubkey(),
                        Amount::from_sat(49_000_000),
                    )],
                    ScriptSource::Descriptor(Box::new(internal.at_derivation_index(i)?)),
                    ChangePolicyType::NoDustAndLeastWaste {
                        longterm_feerate: FeeRate::from_sat_per_vb_unchecked(1),
                    },
                    wallet.change_weight(),
                ),
            )?;
        let mut parent_psbt = low_fee_selection.create_psbt(PsbtParams {
            fallback_sequence: Sequence::MAX,
            ..Default::default()
        })?;
        let parent_finalizer = low_fee_selection.into_finalizer();
        parent_psbt.sign(&signer, &secp).expect("failed to sign");
        assert!(parent_finalizer.finalize(&mut parent_psbt).is_finalized());
        let parent_tx = parent_psbt.extract_tx()?;
        let parent_txid = env.rpc_client().send_raw_transaction(&parent_tx)?;
        println!("Parent tx {} broadcasted: {}", i + 1, parent_txid);
        parent_txids.push(parent_txid);
        wallet.sync(&env)?;
    }
    println!("Balance after parent txs: {}", wallet.balance());

    // Verify parent transactions are in mempool
    let mempool = env.rpc_client().get_raw_mempool()?;
    for (i, txid) in parent_txids.iter().enumerate() {
        if mempool.contains(txid) {
            println!("Parent TX {} {} is in mempool", i + 1, txid);
        } else {
            println!("Parent TX {} {} is NOT in mempool", i + 1, txid);
        }
    }

    // Create CPFP transaction to boost both parents
    let cpfp_selection = wallet.create_cpfp_tx(
        parent_txids.clone(),
        FeeRate::from_sat_per_vb_unchecked(10), // user specified
    )?;

    let mut cpfp_psbt = cpfp_selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::MAX,
        fallback_locktime: LockTime::ZERO,
        ..Default::default()
    })?;
    let cpfp_finalizer = cpfp_selection.into_finalizer();
    cpfp_psbt.sign(&signer, &secp).expect("failed to sign");
    assert!(cpfp_finalizer.finalize(&mut cpfp_psbt).is_finalized());
    let cpfp_tx = cpfp_psbt.extract_tx()?;
    let cpfp_txid = env.rpc_client().send_raw_transaction(&cpfp_tx)?;

    wallet.sync(&env)?;
    println!("Balance after CPFP: {}", wallet.balance());

    // Verify all transactions are in mempool
    let mempool = env.rpc_client().get_raw_mempool()?;
    println!("\nChecking transactions in mempool:");
    for (i, txid) in parent_txids.iter().enumerate() {
        if mempool.contains(txid) {
            println!("Parent TX {} {} is in mempool", i + 1, txid);
        } else {
            println!("Parent TX {} {} is NOT in mempool", i + 1, txid);
        }
    }
    if mempool.contains(&cpfp_txid) {
        println!("CPFP TX {cpfp_txid} is in mempool");
    } else {
        println!("CPFP TX {cpfp_txid} is NOT in mempool");
    }

    // Verify child spends parents
    for (i, parent_txid) in parent_txids.iter().enumerate() {
        let parent_tx = env.rpc_client().get_raw_transaction(parent_txid, None)?;
        if child_spends_parent(&parent_tx, &cpfp_tx) {
            println!("CPFP transaction spends an output of parent {}.", i + 1);
        } else {
            println!(
                "CPFP transaction does NOT spend outputs of parent {}.",
                i + 1
            );
        }
    }

    println!("\n=== MINING BLOCK TO CONFIRM TRANSACTIONS ===");
    let block_hashes = env.mine_blocks(1, None)?; // Revert to None, rely on mempool
    println!("Mined block: {}", block_hashes[0]);
    wallet.sync(&env)?;

    println!("Final wallet balance: {}", wallet.balance());

    println!("\nChecking transactions in mempool again:");
    let mempool = env.rpc_client().get_raw_mempool()?;
    for (i, txid) in parent_txids.iter().enumerate() {
        if mempool.contains(txid) {
            println!("Parent TX {} {} is in mempool", i + 1, txid);
        } else {
            println!("Parent TX {} {} is NOT in mempool", i + 1, txid);
        }
    }
    if mempool.contains(&cpfp_txid) {
        println!("CPFP TX {cpfp_txid} is in mempool");
    } else {
        println!("CPFP TX {cpfp_txid} is NOT in mempool");
    }
    Ok(())
}

fn child_spends_parent(parent_tx: &Transaction, child_tx: &Transaction) -> bool {
    let parent_txid = parent_tx.compute_txid();
    child_tx
        .input
        .iter()
        .any(|input| input.previous_output.txid == parent_txid)
}
