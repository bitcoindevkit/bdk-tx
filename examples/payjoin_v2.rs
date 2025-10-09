use anyhow::{anyhow, Result};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, ChangePolicyType, Finalizer, Output, PsbtParams,
    ScriptSource, SelectorParams, Signer,
};
use bitcoin::{
    consensus::encode::serialize_hex, key::Secp256k1, psbt, secp256k1::All, Amount, FeeRate, Psbt,
    Sequence, TxIn,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use std::str::FromStr;
use url::Url;

mod common;

use common::Wallet;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let ohttp_relay = Url::parse("https://pj.bobspacebkk.com")?;
    let payjoin_directory = Url::parse("https://payjo.in")?;
    let ohttp_keys = fetch_ohttp_keys(ohttp_relay.as_str(), payjoin_directory.as_str()).await?;

    let (mut receiver_wallet, receiver_signer, env, sender_wallet, sender_signer, sender_desc) =
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
    // No proposal yet since sender has not responded
    let session = if let OptionalTransitionOutcome::Stasis(current_state) = response_body {
        current_state
    } else {
        panic!("Should still be in initialized state")
    };

    // SENDER PARSE THE PAYJOIN URI, BUILD PSBT AND SEND PAYJOIN REQUEST
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

    dbg!(&psbt.clone().extract_tx());

    let req_ctx = SenderBuilder::new(psbt, pj_uri)
        .build_recommended(FeeRate::BROADCAST_MIN)?
        .save(&send_persister)?;

    let (
        Request {
            url,
            body,
            content_type,
            ..
        },
        send_ctx,
    ) = req_ctx.create_v2_post_request(ohttp_relay.as_str())?;
    let response = http
        .post(url)
        .header("Content-Type", content_type)
        .body(body)
        .send()
        .await?;
    println!("Response: {response:?}");

    assert!(
        response.status().is_success(),
        "error response: {}",
        response.status()
    );
    let _send_ctx = req_ctx
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

    let _payjoin_proposal =
        handle_directory_proposal(&receiver_wallet, &env, proposal, &receiver_signer, &secp)?;

    Ok(())
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
            Some(FeeRate::from_sat_per_vb_unchecked(1)),
            Some(FeeRate::from_sat_per_vb_unchecked(2)),
        )
        .save(&noop_persister)?;

    //Sign anf finalize proposal PSBT
    let payjoin = payjoin
        .finalize_proposal(|psbt: &Psbt| {
            finalize_psbt(psbt, wallet, signer, secp)
                .map_err(|e| ImplementationError::from(e.to_string().as_str()))
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
    let target_feerate = FeeRate::from_sat_per_vb_unchecked(5);
    // let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);

    let target_outputs = vec![Output::with_script(
        pj_uri.address.script_pubkey(),
        target_amount,
    )];

    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable_now(tip_height, tip_time))
        .into_selection(
            |selector| selector.select_until_target_met(),
            SelectorParams::new(
                target_feerate,
                target_outputs,
                ScriptSource::Descriptor(Box::new(desc.at_derivation_index(0)?)),
                ChangePolicyType::NoDust,
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
    psbt: &Psbt,
    wallet: &Wallet,
    signer: &Signer,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Psbt> {
    let mut psbt = psbt.clone();

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
    let _finalize_map = finalizer.finalize(&mut psbt);

    // if !finalize_map.is_finalized() {
    //     return Err(anyhow!("Failed to finalize PSBT: {:?}", res));
    // }

    Ok(psbt)
}

fn select_inputs(
    wallet: &Wallet,
    payjoin: &Receiver<WantsInputs>,
    env: &TestEnv,
) -> anyhow::Result<Vec<InputPair>> {
    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;

    let candidates = wallet
        .all_candidates()
        .filter(|input| input.is_spendable_now(tip_height, tip_time));

    let inputs = candidates
        .inputs()
        .map(|input| {
            let txin = TxIn {
                previous_output: input.prev_outpoint(),
                sequence: input.sequence().unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
                ..Default::default()
            };

            let psbt_input = psbt::Input {
                witness_utxo: Some(input.prev_txout().clone()),
                ..Default::default()
            };
            InputPair::new(txin, psbt_input, None)
                .map_err(|e| anyhow!("Failed to create InputPair: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let selected_inputs = payjoin
        .try_preserving_privacy(inputs)
        .map_err(|e| anyhow!("Failed to make privacy preserving selection: {e:?}"))?;

    Ok(vec![selected_inputs])
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
