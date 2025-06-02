#![allow(dead_code)]
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, Output, PsbtParams,
    SelectorParams,
};
use bitcoin::{absolute::LockTime, key::Secp256k1, Amount, FeeRate, Sequence};
use miniscript::Descriptor;

mod common;

use common::Wallet;

fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let (external, _) = Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[0])?;
    let (internal, _) = Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[1])?;

    let env = TestEnv::new()?;
    let genesis_hash = env.genesis_hash()?;
    env.mine_blocks(101, None)?;

    let mut wallet = Wallet::new(genesis_hash, external, internal.clone())?;
    wallet.sync(&env)?;

    let addr = wallet.next_address().expect("must derive address");

    let txid = env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("Received {}", txid);
    println!("Balance (confirmed): {}", wallet.balance());

    let txid = env.send(&addr, Amount::ONE_BTC)?;
    wallet.sync(&env)?;
    println!("Received {txid}");
    println!("Balance (pending): {}", wallet.balance());

    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
    println!("Height: {}", tip_height);
    let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);

    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .assume_checked();

    // Okay now create tx.
    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable_now(tip_height, tip_time))
        .into_selection(
            selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
            SelectorParams::new(
                FeeRate::from_sat_per_vb_unchecked(10),
                vec![Output::with_script(
                    recipient_addr.script_pubkey(),
                    Amount::from_sat(21_000_000),
                )],
                internal.at_derivation_index(0)?,
                bdk_tx::ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
            ),
        )?;

    // Convert the consensus‐height (u32) into an absolute::LockTime
    let fallback_locktime: LockTime = LockTime::from_consensus(tip_height.to_consensus_u32());

    let psbt = selection.create_psbt(PsbtParams {
        enable_anti_fee_sniping: true,
        fallback_locktime,
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;

    let tx = psbt.unsigned_tx;

    // Locktime is used, if rbf is disabled or any input requires locktime
    // (e.g. non-taproot, unconfirmed, or >65535 confirmation) or there are
    // no taproot inputs or the 50/50 coin flip chose locktime (USE_NLOCKTIME_PROBABILITY)
    // Further-back randomness with 10% chance (FURTHER_BACK_PROBABILITY),
    // will subtract a random 0–99 block offset to desynchronize from tip
    //
    // Sequence will use the opposite condition of locktime, and locktime will
    // be set to zero. Further-back randomness: with 10% chance, will
    // subtract a random 0–99 block offset (but at least 1).
    //
    // Whenever locktime is used, the sequence value will remain as it is.

    if tx.lock_time != LockTime::ZERO {
        let height_val = tx.lock_time.to_consensus_u32();
        let min_expected = tip_height.to_consensus_u32().saturating_sub(99);
        let max_expected = tip_height.to_consensus_u32();

        assert!(
            (min_expected..=max_expected).contains(&height_val),
            "Value {} is out of range {}..={}",
            height_val,
            min_expected,
            max_expected
        );

        if height_val >= min_expected && height_val <= max_expected {
            println!("✓ Locktime is within expected range");
        } else {
            println!("⚠ Locktime is outside expected range");
        }
    } else {
        for (i, inp) in tx.input.iter().enumerate() {
            let sequence_value = inp.sequence.to_consensus_u32();

            let min_expected = 1;
            let max_expected = Sequence(0xFFFFFFFE).to_consensus_u32();
            let index = i + 1;

            if sequence_value >= min_expected && sequence_value <= max_expected {
                println!(
                    "✓ Input #{}: sequence {} is within anti-fee sniping range",
                    index, sequence_value
                );
            } else if sequence_value == 0xfffffffd || sequence_value == 0xfffffffe {
                println!("✓ Input #{}: using standard RBF sequence", index);
            } else {
                println!(
                    "⚠ Input #{}: sequence {} outside typical ranges",
                    index, sequence_value
                );
            }
        }
    }

    Ok(())
}
