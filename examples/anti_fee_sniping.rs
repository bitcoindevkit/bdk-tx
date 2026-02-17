#![allow(dead_code)]
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable, group_by_spk, selection_algorithm_lowest_fee_bnb, Output, PsbtParams,
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

    let txid1 = env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("Received confirmed input: {}", txid1);

    let txid2 = env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("Received confirmed input: {}", txid2);

    println!("Balance (confirmed): {}", wallet.balance());

    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
    println!("Current height: {}", tip_height);
    let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);

    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .assume_checked();

    // When anti-fee-sniping is enabled, the transaction will either use nLockTime or nSequence.
    //
    // Locktime approach is used when:
    // - RBF is disabled, OR
    // - Any input requires locktime (non-taproot, unconfirmed, or >65535 confirmations), OR
    // - There are no taproot inputs, OR
    // - Random 50/50 coin flip chose locktime
    //
    // Sequence approach is used otherwise:
    // - Sets tx.lock_time to ZERO
    // - Modifies one randomly selected taproot input's sequence
    //
    // Once the approach is selected, to reduce transaction fingerprinting,
    // - For nLockTime: With 10% probability, subtract a random 0-99 block offset from current height
    // - For nSequence: With 10% probability, subtract a random 0-99 block offset (minimum value of 1)
    //
    // Note: When locktime is used, all sequence values remain unchanged.

    let mut locktime_count = 0;
    let mut sequence_count = 0;

    for _ in 0..10 {
        let selection = wallet
            .all_candidates()
            .regroup(group_by_spk())
            .filter(filter_unspendable(tip_height, Some(tip_time)))
            .into_selection(
                selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
                SelectorParams::new(
                    FeeRate::from_sat_per_vb_unchecked(10),
                    vec![Output::with_script(
                        recipient_addr.script_pubkey(),
                        Amount::from_sat(50_000_000),
                    )],
                    bdk_tx::ChangeScript::Descriptor(Box::new(internal.at_derivation_index(0)?)),
                    bdk_tx::ChangePolicy::NoDustLeastWaste {
                        longterm_feerate,
                        min_value: None,
                    },
                ),
            )?;

        let fallback_locktime: LockTime = LockTime::from_consensus(tip_height.to_consensus_u32());

        let selection_inputs = selection.inputs.clone();

        let psbt = selection.create_psbt(PsbtParams {
            enable_anti_fee_sniping: true,
            fallback_locktime,
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        })?;

        let tx = psbt.unsigned_tx;

        if tx.lock_time != LockTime::ZERO {
            locktime_count += 1;
            let locktime_value = tx.lock_time.to_consensus_u32();
            let current_height = tip_height.to_consensus_u32();

            let offset = current_height.saturating_sub(locktime_value);
            if offset > 0 {
                println!(
                    "nLockTime = {} (tip height: {}, offset: -{})",
                    locktime_value, current_height, offset
                );
            } else {
                println!(
                    "nLockTime = {} (tip height: {}, no offset)",
                    locktime_value, current_height
                );
            }
        } else {
            sequence_count += 1;

            for (i, inp) in tx.input.iter().enumerate() {
                let sequence_value = inp.sequence.to_consensus_u32();

                if (1..0xFFFFFFFD).contains(&sequence_value) {
                    let input_confirmations = selection_inputs[i].confirmations(tip_height);
                    let offset = input_confirmations.saturating_sub(sequence_value);

                    if offset > 0 {
                        println!(
                            "nSequence[{}] = {} (confirmations: {}, offset: -{})",
                            i, sequence_value, input_confirmations, offset
                        );
                    } else {
                        println!(
                            "nSequence[{}] = {} (confirmations: {}, no offset)",
                            i, sequence_value, input_confirmations
                        );
                    }

                    break;
                }
            }
        }
    }

    println!("nLockTime approach used: {} times", locktime_count);
    println!("nSequence approach used: {} times", sequence_count);

    Ok(())
}
