#![allow(dead_code)]

use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable, group_by_spk, selection_algorithm_lowest_fee_bnb, CanonicalUnspents,
    InputCandidates, Output, PsbtParams, Selection, SelectorParams, Signer,
};
use bitcoin::{key::Secp256k1, Amount, FeeRate, OutPoint, ScriptBuf, Transaction, Txid};
use miniscript::Descriptor;

mod common;

use common::Wallet;

fn feerate_sat_vb(fee: u64, weight: bitcoin::Weight) -> f32 {
    fee as f32 / weight.to_vbytes_ceil() as f32
}

fn sign_and_extract_tx(
    selection: Selection,
    signer: &Signer,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> anyhow::Result<Transaction> {
    let mut psbt = selection.create_psbt(PsbtParams::default())?;
    let finalizer = selection.into_finalizer();
    psbt.sign(signer, secp).expect("failed to sign");
    assert!(
        finalizer.finalize(&mut psbt).is_finalized(),
        "must finalize"
    );
    Ok(psbt.extract_tx()?)
}

struct TxStats {
    fee: u64,
    weight: bitcoin::Weight,
}

fn finalize_child_tx_stats(
    candidates: InputCandidates,
    child_recipient: ScriptBuf,
    change_script: bdk_tx::ChangeScript,
    target_feerate: FeeRate,
    signer: &Signer,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> anyhow::Result<TxStats> {
    let selection = candidates.into_selection(
        selection_algorithm_lowest_fee_bnb(
            FeeRate::from_sat_per_vb(1).expect("valid fee rate"),
            100_000,
        ),
        SelectorParams::new(
            target_feerate,
            vec![Output::with_script(
                child_recipient,
                Amount::from_sat(25_000_000),
            )],
            change_script,
        ),
    )?;
    let inputs: u64 = selection
        .inputs()
        .iter()
        .map(|input| input.prev_txout().value.to_sat())
        .sum();
    let outputs: u64 = selection
        .outputs()
        .iter()
        .map(|output| output.value.to_sat())
        .sum();
    let fee = inputs - outputs;
    let tx = sign_and_extract_tx(selection, signer, secp)?;
    Ok(TxStats {
        fee,
        weight: tx.weight(),
    })
}

fn wallet_output_from_parent_tx(wallet: &Wallet, txid: Txid) -> Option<OutPoint> {
    wallet
        .graph
        .index
        .outpoints()
        .iter()
        .map(|(_, outpoint)| *outpoint)
        .find(|outpoint| outpoint.txid == txid)
}

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

    let funding_addr = wallet.next_address().expect("must derive address");
    let funding_txid = env.send(&funding_addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("Received confirmed funding tx: {funding_txid}");

    let (tip_height, tip_mtp) = wallet.tip_info(env.rpc_client())?;
    let longterm_feerate = FeeRate::from_sat_per_vb(1).expect("valid fee rate");

    let parent_recipient = wallet.next_address().expect("must derive address");
    let low_fee_parent = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable(tip_height, Some(tip_mtp)))
        .into_selection(
            selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
            SelectorParams {
                change_longterm_feerate: Some(longterm_feerate),
                ..SelectorParams::new(
                    FeeRate::from_sat_per_vb(1).expect("valid fee rate"),
                    vec![Output::with_script(
                        parent_recipient.script_pubkey(),
                        Amount::from_sat(50_000_000),
                    )],
                    bdk_tx::ChangeScript::from_descriptor(internal.at_derivation_index(0)?),
                )
            },
        )?;
    let low_fee_parent = sign_and_extract_tx(low_fee_parent, &signer, &secp)?;
    let parent_fee = wallet
        .graph
        .graph()
        .calculate_fee(&low_fee_parent)?
        .to_sat();
    let parent_weight = low_fee_parent.weight();
    let parent_txid = env.rpc_client().send_raw_transaction(&low_fee_parent)?;
    wallet.sync(&env)?;
    println!("Broadcast low-fee unconfirmed parent: {parent_txid}");

    let child_outpoint = wallet_output_from_parent_tx(&wallet, parent_txid)
        .expect("wallet must track an output from the parent");
    let assets = wallet.assets();
    let child_plan = wallet
        .plan_of_output(child_outpoint, &assets)
        .expect("wallet must plan child input");
    let canonical_unspents = CanonicalUnspents::new(wallet.canonical_txs());

    let child_recipient = env
        .rpc_client()
        .get_new_address(None, None)?
        .assume_checked()
        .script_pubkey();
    let target_feerate = FeeRate::from_sat_per_vb(50).expect("valid fee rate");

    let child_input = || {
        canonical_unspents
            .try_get_unspent(child_outpoint, child_plan.clone())
            .expect("wallet output must be spendable")
    };
    let without_ancestors = finalize_child_tx_stats(
        InputCandidates::new([child_input()], []),
        child_recipient.clone(),
        bdk_tx::ChangeScript::from_descriptor(internal.at_derivation_index(1)?),
        target_feerate,
        &signer,
        &secp,
    )?;
    let with_ancestors = finalize_child_tx_stats(
        InputCandidates::new([child_input()], [])
            .with_unconfirmed_ancestors(&canonical_unspents)?,
        child_recipient,
        bdk_tx::ChangeScript::from_descriptor(internal.at_derivation_index(2)?),
        target_feerate,
        &signer,
        &secp,
    )?;

    let child_bump = with_ancestors.fee - without_ancestors.fee;
    let parent_target_fee = target_feerate
        .fee_wu(parent_weight)
        .expect("fee fits")
        .to_sat();
    let expected_bump = parent_target_fee.saturating_sub(parent_fee);
    let package_fee = parent_fee + with_ancestors.fee;
    let package_weight = parent_weight + with_ancestors.weight;

    println!("parent fee:             {parent_fee} sat");
    println!("parent target fee:      {parent_target_fee} sat");
    println!(
        "parent feerate:         {:.2} sat/vB",
        feerate_sat_vb(parent_fee, parent_weight)
    );
    println!(
        "package feerate:        {:.2} sat/vB",
        feerate_sat_vb(package_fee, package_weight)
    );
    println!(
        "target feerate:         {} sat/vB",
        target_feerate.to_sat_per_vb_ceil()
    );
    println!("child fee without CPFP: {} sat", without_ancestors.fee);
    println!("child fee with CPFP:    {} sat", with_ancestors.fee);
    println!("child bump:            {child_bump} sat");
    println!("expected CPFP bump:    {expected_bump} sat");

    assert_eq!(
        child_bump, expected_bump,
        "child should pay exactly the missing parent fee"
    );

    Ok(())
}
