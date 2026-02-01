use bdk_testenv::TestEnv;
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, FeeStrategy, Output,
    PsbtParams, ScriptSource, SelectorParams,
};
use bdk_tx_testenv::TestEnvExt;
use bitcoin::{Amount, FeeRate, Sequence};

mod common;

use common::{Wallet, EXTERNAL, INTERNAL};

fn main() -> anyhow::Result<()> {
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
            (EXTERNAL, bdk_testenv::utils::DESCRIPTORS[3]),
            (INTERNAL, bdk_testenv::utils::DESCRIPTORS[4]),
        ],
    )?;
    wallet.sync(&env)?;

    let addr = wallet.next_address(EXTERNAL).expect("must derive address");

    let txid = env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("Received {txid}");
    println!("Balance (confirmed): {}", wallet.balance());

    let txid = env.send(&addr, Amount::ONE_BTC)?;
    wallet.sync(&env)?;
    println!("Received {txid}");
    println!("Balance (pending): {}", wallet.balance());

    let (tip_height, tip_mtp) = wallet.tip_info(&client)?;
    let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);

    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .address()?
        .assume_checked();

    // Okay now create tx.
    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable_now(tip_height, Some(tip_mtp)))
        .into_selection(
            selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
            SelectorParams::new(
                FeeStrategy::FeeRate(FeeRate::from_sat_per_vb_unchecked(10)),
                vec![Output::with_script(
                    recipient_addr.script_pubkey(),
                    Amount::from_sat(21_000_000),
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
    assert!(res.is_finalized());

    let tx = psbt.extract_tx()?;
    assert_eq!(tx.input.len(), 2);
    let fee = wallet.graph.graph().calculate_fee(&tx)?;
    println!(
        "ORIGINAL TX: inputs={}, outputs={}, fee={}, feerate={}",
        tx.input.len(),
        tx.output.len(),
        fee,
        ((fee.to_sat() as f32) / (tx.weight().to_vbytes_ceil() as f32)),
    );

    // We will try bump this tx fee.
    let txid = env.rpc_client().send_raw_transaction(&tx)?.txid()?;
    println!("tx broadcasted: {txid}");
    wallet.sync(&env)?;
    println!("Balance (send tx): {}", wallet.balance());

    // Try cancel a tx.
    // We follow all the rules as specified by
    // https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md#current-replace-by-fee-policy
    println!("OKAY LET's TRY CANCEL {txid}");
    {
        let original_tx = wallet
            .graph
            .graph()
            .get_tx_node(txid)
            .expect("must find tx");
        assert_eq!(txid, original_tx.txid);

        // We canonicalize first.
        //
        // This ensures all input candidates are of a consistent UTXO set.
        // The canonicalization is modified by excluding the original txs and their
        // descendants. This way, the prevouts of the original txs are avaliable for spending
        // and we won't end up picking outputs of the original txs.
        //
        // Additionally, we need to guarantee atleast one prevout of each original tx is picked,
        // otherwise we may not actually replace the original txs. The policy used here is to
        // choose the largest value prevout of each original tx.
        //
        // Filters out unconfirmed input candidates unless it was already an input of an
        // original tx we are replacing (as mentioned in rule 2 of Bitcoin Core Mempool
        // Replacement Policy).
        let (rbf_candidates, rbf_params) = wallet.rbf_candidates([txid], tip_height)?;

        let selection = rbf_candidates
            // Do coin selection.
            .into_selection(
                // Coin selection algorithm.
                selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
                SelectorParams {
                    // This is just a lower-bound feerate. The actual result will be much higher to
                    // satisfy mempool-replacement policy.
                    fee_strategy: FeeStrategy::FeeRate(FeeRate::from_sat_per_vb_unchecked(1)),
                    // We cancel the tx by specifying no target outputs. This way, all excess returns
                    // to our change output (unless if the prevouts picked are so small that it will
                    // be less wasteful to have no output, however that will not be a valid tx).
                    // If you only want to fee bump, put the original txs' recipients here.
                    target_outputs: vec![],
                    change_script: ScriptSource::Descriptor(Box::new(
                        wallet.definite_descriptor(INTERNAL, 1)?,
                    )),
                    change_policy: wallet.change_policy(),
                    // This ensures that we satisfy mempool-replacement policy rules 4 and 6.
                    replace: Some(rbf_params),
                },
            )?;

        let mut psbt = selection.create_psbt(PsbtParams {
            // Not strictly necessary, but it may help us replace the tx faster.
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        })?;
        println!(
            "selected inputs: {:?}",
            selection
                .inputs
                .iter()
                .map(|input| input.prev_outpoint())
                .collect::<Vec<_>>()
        );

        let finalizer = selection.into_finalizer();
        psbt.sign(&wallet.signer, &wallet.secp)
            .expect("failed to sign");
        assert!(
            finalizer.finalize(&mut psbt).is_finalized(),
            "must finalize"
        );

        let tx = psbt.extract_tx()?;
        let fee = wallet.graph.graph().calculate_fee(&tx)?;
        println!(
            "REPLACEMENT TX: inputs={}, outputs={}, fee={}, feerate={}",
            tx.input.len(),
            tx.output.len(),
            fee,
            ((fee.to_sat() as f32) / (tx.weight().to_vbytes_ceil() as f32)),
        );
        let txid = env.rpc_client().send_raw_transaction(&tx)?.txid()?;
        println!("tx broadcasted: {txid}");
        wallet.sync(&env)?;
        println!("Balance (RBF): {}", wallet.balance());
    }

    Ok(())
}
