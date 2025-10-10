use anyhow::{anyhow, Result};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, ChangePolicyType, Finalizer, Output, PsbtParams,
    ScriptSource, SelectorParams, Signer,
};
use bitcoin::{
    consensus::encode::serialize_hex, key::Secp256k1, psbt, secp256k1::All, Amount, FeeRate, Psbt,
    Sequence, Transaction, TxIn,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use payjoin::{
    io::fetch_ohttp_keys,
    persist::{NoopSessionPersister, OptionalTransitionOutcome},
    receive::{
        v2::{PayjoinProposal, Receiver, ReceiverBuilder, UncheckedOriginalPayload, WantsInputs},
        InputPair,
    },
    send::v2::SenderBuilder,
    ImplementationError, PjUri, Request, Uri, UriExt,
};
use std::str::FromStr;
use url::Url;

mod common;

use common::Wallet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let ohttp_relay = Url::parse("https://pj.bobspacebkk.com")?;
    let payjoin_directory = Url::parse("https://payjo.in")?;
    let ohttp_keys = fetch_ohttp_keys(ohttp_relay.as_str(), payjoin_directory.as_str()).await?;

    let (mut receiver_wallet, receiver_signer, env, mut sender_wallet, sender_signer, sender_desc) =
        setup_wallets()?;
    let recv_persister = NoopSessionPersister::default();
    let send_persister = NoopSessionPersister::default();
    let http = reqwest::Client::new();

    // RECEIVER INITIALIZE PAYJOIN SESSION
    let session = ReceiverBuilder::new(
        receiver_wallet.next_address().unwrap(),
        payjoin_directory.as_str(),
        ohttp_keys,
    )?
    .build()
    .save(&recv_persister)?;
    let (req, ctx) = session.create_poll_request(ohttp_relay.as_str())?;
    let response = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;
    assert!(
        response.status().is_success(),
        "error response: {}",
        response.status()
    );
    let response_body = session
        .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
        .save(&recv_persister)?;

    let session = if let OptionalTransitionOutcome::Stasis(current_state) = response_body {
        current_state
    } else {
        panic!("Should still be in initialized state")
    };

    // SENDER PARSE THE PAYJOIN URI, BUILD PSBT
    let pj_uri = Uri::from_str(&session.pj_uri().to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .assume_checked()
        .check_pj_supported()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let psbt = build_psbt(
        &env,
        &sender_wallet,
        &sender_signer,
        &pj_uri,
        &sender_desc,
        &secp,
    )?;
    let req_ctx = SenderBuilder::new(psbt, pj_uri)
        .build_recommended(FeeRate::BROADCAST_MIN)?
        .save(&send_persister)?;

    // SENDER SENDS PAYJOIN REQUEST
    let (req, send_ctx) = req_ctx.create_v2_post_request(ohttp_relay.as_str())?;
    let response = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "error response: {}",
        response.status()
    );
    let send_ctx = req_ctx
        .process_response(&response.bytes().await?, send_ctx)
        .save(&send_persister)?;

    // RECEIVER PROCESSES AND POST PSBT
    let (req, ctx) = session.create_poll_request(ohttp_relay.as_str())?;
    let response = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;
    let outcome = session
        .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
        .save(&recv_persister)?;

    let proposal = match outcome {
        OptionalTransitionOutcome::Progress(psbt) => psbt,
        _ => return Err(anyhow::anyhow!("Expected a payjoin proposal!")),
    };

    let payjoin_proposal =
        handle_directory_proposal(&receiver_wallet, &env, proposal, &receiver_signer, &secp)?;
    let (req, _) = payjoin_proposal.create_post_request(ohttp_relay.as_str())?;

    let _response = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;

    // SENDER SIGNS, FINALIZES AND BROADCASTS THE PAYJOIN TRANSACTION
    let (
        Request {
            url,
            body,
            content_type,
            ..
        },
        ohttp_ctx,
    ) = send_ctx.create_poll_request(ohttp_relay.as_str())?;
    let response = http
        .post(url)
        .header("Content-Type", content_type)
        .body(body)
        .send()
        .await?;
    println!("Response: {:#?}", &response);
    let response = send_ctx
        .process_response(&response.bytes().await?, ohttp_ctx)
        .save(&send_persister)
        .expect("psbt should exist");

    let checked_payjoin_proposal_psbt = if let OptionalTransitionOutcome::Progress(psbt) = response
    {
        psbt
    } else {
        panic!("psbt should exist");
    };
    let network_fees = checked_payjoin_proposal_psbt.fee()?;

    let payjoin_tx = extract_pj_tx(
        &sender_wallet,
        checked_payjoin_proposal_psbt,
        &sender_signer,
        &secp,
    )?;
    let txid = env.rpc_client().send_raw_transaction(&payjoin_tx)?;
    println!("Sent: {}", txid);

    assert_eq!(payjoin_tx.input.len(), 2);
    assert_eq!(payjoin_tx.output.len(), 2);

    // MINE A BLOCK TO CONFIRM THE TRANSACTION
    env.mine_blocks(1, None)?;
    receiver_wallet.sync(&env)?;
    sender_wallet.sync(&env)?;

    // RECEIVER WALLET SHOULD NOW SEE THE TRANSACTION
    if let Some(tx_node) = receiver_wallet.graph.graph().get_tx(txid) {
        let tx = tx_node.as_ref();
        dbg!(tx);
    } else {
        println!("Transaction not in receiver's graph yet");
    }

    assert_eq!(
        sender_wallet.balance().confirmed,
        Amount::from_btc(45.0)? - network_fees
    );
    assert_eq!(receiver_wallet.balance().confirmed, Amount::from_btc(55.0)?);

    Ok(())
}

fn extract_pj_tx(
    wallet: &Wallet,
    mut psbt: Psbt,
    signer: &Signer,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Transaction> {
    let assets = wallet.assets();
    let mut plans = Vec::new();

    for (index, input) in psbt.unsigned_tx.input.iter().enumerate() {
        let outpoint = input.previous_output;

        if let Some(plan) = wallet.plan_of_output(outpoint, &assets) {
            let psbt_input = &mut psbt.inputs[index];

            // Only update if not already finalized
            if psbt_input.final_script_sig.is_none() && psbt_input.final_script_witness.is_none() {
                plan.update_psbt_input(psbt_input);

                if let Some(prev_tx) = wallet.graph.graph().get_tx(outpoint.txid) {
                    psbt_input.non_witness_utxo = Some(prev_tx.as_ref().clone());
                    if let Some(txout) = prev_tx.output.get(outpoint.vout as usize) {
                        psbt_input.witness_utxo = Some(txout.clone());
                    }
                }
            }

            plans.push((outpoint, plan));
        }
    }

    let finalizer = Finalizer::new(plans);
    let _ = psbt.sign(signer, secp);
    let finalize_map = finalizer.finalize(&mut psbt);

    if !finalize_map.is_finalized() {
        return Err(anyhow!("Failed to finalize PSBT: {finalize_map:?}"));
    }

    Ok(psbt.extract_tx()?)
}

fn handle_directory_proposal(
    wallet: &Wallet,
    env: &TestEnv,
    proposal: Receiver<UncheckedOriginalPayload>,
    signer: &Signer,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Receiver<PayjoinProposal>> {
    let noop_persister = NoopSessionPersister::default();
    let client = env.rpc_client();

    // Receive Check 1: Can Broadcast
    let proposal = proposal
        .check_broadcast_suitability(None, |tx| {
            let test_mempool_suitability = client
                .test_mempool_accept(&[serialize_hex(tx)])
                .map_err(ImplementationError::new)?;
            let check_broadcast = test_mempool_suitability
                .first()
                .ok_or(ImplementationError::from(
                    "testmempoolaccept should return a result",
                ))?
                .allowed;
            Ok(check_broadcast)
        })
        .save(&noop_persister)?;

    let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

    // Receive Check 2: receiver can't sign for proposal inputs
    let proposal = proposal
        .check_inputs_not_owned(&mut |input| {
            let address = bitcoin::Address::from_script(input, bitcoin::Network::Regtest)
                .map_err(ImplementationError::new)?;
            let script_pubkey = address.script_pubkey();
            Ok(wallet.graph.index.index_of_spk(script_pubkey).is_some())
        })
        .save(&noop_persister)?;

    // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
    let payjoin = proposal
        .check_no_inputs_seen_before(&mut |_| Ok(false))
        .save(&noop_persister)?
        .identify_receiver_outputs(&mut |output_script| {
            let address = bitcoin::Address::from_script(output_script, bitcoin::Network::Regtest)
                .map_err(ImplementationError::new)?;
            let script_pubkey = address.script_pubkey();
            Ok(wallet.graph.index.index_of_spk(script_pubkey).is_some())
        })
        .save(&noop_persister)?;

    let payjoin = payjoin.commit_outputs().save(&noop_persister)?;
    let inputs = select_inputs(wallet, &payjoin, env)?;

    let payjoin = payjoin
        .contribute_inputs(inputs)
        .map_err(|e| anyhow!("Failed to contribute inputs: {e:?}"))?
        .commit_inputs()
        .save(&noop_persister)?;

    let payjoin = payjoin
        .apply_fee_range(
            Some(FeeRate::BROADCAST_MIN),
            Some(FeeRate::from_sat_per_vb_unchecked(2)),
        )
        .save(&noop_persister)?;

    // Sign and finalize proposal PSBT
    let payjoin = payjoin
        .finalize_proposal(|psbt: &Psbt| {
            let mut psbt = psbt.clone();

            finalize_psbt(&mut psbt, wallet, signer, secp)
                .map_err(|e| ImplementationError::from(e.to_string().as_str()))?;

            Ok(psbt)
        })
        .save(&noop_persister)?;

    Ok(payjoin)
}

fn build_psbt(
    env: &TestEnv,
    wallet: &Wallet,
    signer: &Signer,
    pj_uri: &PjUri,
    desc: &Descriptor<DescriptorPublicKey>,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Psbt> {
    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;

    let target_amount = Amount::from_btc(5.0)?;
    let target_feerate = FeeRate::from_sat_per_vb_unchecked(2);
    let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);

    let target_outputs = vec![Output::with_script(
        pj_uri.address.script_pubkey(),
        target_amount,
    )];

    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable_now(tip_height, tip_time))
        .into_selection(
            |selector| -> anyhow::Result<()> {
                selector.select_all();
                Ok(())
            },
            SelectorParams::new(
                target_feerate,
                target_outputs,
                ScriptSource::Descriptor(Box::new(desc.at_derivation_index(0)?)),
                ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
                wallet.change_weight(),
            ),
        )?;

    let mut psbt = selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;

    let finalizer = selection.into_finalizer();
    let _ = psbt.sign(signer, secp);
    let res = finalizer.finalize(&mut psbt);

    if !res.is_finalized() {
        return Err(anyhow!("Failed to finalize PSBT: {res:?}"));
    }

    Ok(psbt)
}

fn finalize_psbt(
    psbt: &mut Psbt,
    wallet: &Wallet,
    signer: &Signer,
    secp: &Secp256k1<All>,
) -> anyhow::Result<()> {
    let assets = wallet.assets();
    let mut plans = Vec::new();

    for input in psbt.unsigned_tx.input.iter() {
        let outpoint = input.previous_output;
        if let Some(plan) = wallet.plan_of_output(outpoint, &assets) {
            plans.push((outpoint, plan));
        }
    }

    let finalizer = Finalizer::new(plans);
    let _ = psbt.sign(signer, secp);
    finalizer.finalize(psbt);

    Ok(())
}

fn select_inputs(
    wallet: &Wallet,
    payjoin: &Receiver<WantsInputs>,
    env: &TestEnv,
) -> anyhow::Result<Vec<InputPair>> {
    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
    let assets = wallet.assets();

    let candidates = wallet
        .all_candidates()
        .filter(|input| input.is_spendable_now(tip_height, tip_time));

    let inputs = candidates
        .inputs()
        .filter_map(|input| {
            let outpoint = input.prev_outpoint();
            let plan = wallet.plan_of_output(outpoint, &assets)?;

            let txin = TxIn {
                previous_output: outpoint,
                sequence: input.sequence().unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
                ..Default::default()
            };

            let mut psbt_input = psbt::Input {
                witness_utxo: Some(input.prev_txout().clone()),
                non_witness_utxo: input.prev_tx().cloned(),
                ..Default::default()
            };

            // Update PSBT input with plan information
            plan.update_psbt_input(&mut psbt_input);

            InputPair::new(txin, psbt_input, None).ok()
        })
        .collect::<Vec<_>>();

    if inputs.is_empty() {
        return Err(anyhow!("No suitable inputs available"));
    }

    let selected_input = payjoin
        .try_preserving_privacy(inputs)
        .map_err(|e| anyhow!("Failed to make privacy preserving selection: {e:?}"))?;

    Ok(vec![selected_input])
}

// SETUP WALLET
pub fn setup_wallets() -> Result<(
    Wallet,
    Signer,
    TestEnv,
    Wallet,
    Signer,
    Descriptor<DescriptorPublicKey>,
)> {
    let secp = Secp256k1::new();

    // RECEIVER DESCRIPTOR
    let (receiver_external, receiver_external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[0])?;
    let (receiver_internal, receiver_internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[1])?;

    // RECEIVER SIGNER
    let receiver_signer: Signer = Signer(
        receiver_external_keymap
            .into_iter()
            .chain(receiver_internal_keymap)
            .collect(),
    );

    // SENDER DESCRIPTOR
    let (sender_external, sender_external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[3])?;
    let (sender_internal, sender_internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    // SENDER SIGNER
    let sender_signer: Signer = Signer(
        sender_external_keymap
            .into_iter()
            .chain(sender_internal_keymap)
            .collect(),
    );

    // INIT CLIENT AND MINE BLOCKS
    let env = TestEnv::new()?;
    let genesis_hash = env.genesis_hash()?;
    env.mine_blocks(101, None)?;

    // SETUP RECEIVER WALLET
    let mut receiver_wallet =
        Wallet::new(genesis_hash, receiver_external, receiver_internal.clone())?;
    receiver_wallet.sync(&env)?;

    let receiver_addr = receiver_wallet.next_address().expect("must derive address");

    // FUND RECEIVER WALLET
    let receiver_txid = env.send(&receiver_addr, Amount::from_btc(50.0)?)?;
    env.mine_blocks(1, None)?;
    receiver_wallet.sync(&env)?;
    println!("Receiver Received {receiver_txid}");
    println!(
        "Receiver Balance (confirmed): {}",
        receiver_wallet.balance()
    );

    // SETUP SENDER WALLET
    let mut sender_wallet = Wallet::new(genesis_hash, sender_external, sender_internal.clone())?;
    sender_wallet.sync(&env)?;

    let sender_addr = sender_wallet.next_address().expect("must derive address");

    // FUND SENDER WALLET
    let sender_txid = env.send(&sender_addr, Amount::from_btc(50.0)?)?;
    env.mine_blocks(1, None)?;
    sender_wallet.sync(&env)?;

    println!("Sender Received {sender_txid}");
    println!("Sender Balance (confirmed): {}", sender_wallet.balance());

    Ok((
        receiver_wallet,
        receiver_signer,
        env,
        sender_wallet,
        sender_signer,
        sender_internal,
    ))
}
