use anyhow::{anyhow, Result};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable, group_by_spk, ChangeScript, Finalizer, Output, PsbtParams, SelectorParams,
    Signer,
};
use bitcoin::{
    consensus::encode::serialize_hex, key::Secp256k1, psbt, secp256k1::All, Amount, FeeRate, Psbt,
    Sequence, Transaction, TxIn, Txid, Weight,
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
    ImplementationError, OhttpKeys, PjUri, Request, Uri, UriExt,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;
use url::Url;

mod common;

use common::Wallet;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ohttp_relay = Url::parse("https://pj.bobspacebkk.com")?;
    let payjoin_directory = Url::parse("https://payjo.in")?;
    let ohttp_keys = fetch_ohttp_keys(ohttp_relay.as_str(), payjoin_directory.as_str()).await?;

    let (receiver_wallet, receiver_signer, env, sender_wallet, sender_signer, sender_change_desc) =
        setup_wallets()?;
    let env = Arc::new(env);

    // Receiver tells the sender its BIP21 / Payjoin URI out-of-band (e.g. QR code). We model
    // that here with a oneshot channel — the sender task blocks on it.
    let (uri_tx, uri_rx) = oneshot::channel::<String>();

    let receiver_task = tokio::spawn(run_receiver(
        env.clone(),
        receiver_wallet,
        receiver_signer,
        ohttp_relay.clone(),
        payjoin_directory.clone(),
        ohttp_keys,
        uri_tx,
    ));

    let sender_task = tokio::spawn(run_sender(
        env.clone(),
        sender_wallet,
        sender_signer,
        sender_change_desc,
        ohttp_relay.clone(),
        uri_rx,
    ));

    let (receiver_res, sender_res) = tokio::join!(receiver_task, sender_task);
    let mut receiver_wallet = receiver_res??;
    let (mut sender_wallet, txid, network_fees) = sender_res??;
    println!("Sent: {txid}");

    // Confirm the payjoin tx and have both wallets observe it.
    env.mine_blocks(1, None)?;
    receiver_wallet.sync(&env)?;
    sender_wallet.sync(&env)?;

    let payjoin_tx = receiver_wallet
        .graph
        .graph()
        .get_tx(txid)
        .ok_or_else(|| anyhow!("payjoin tx not in receiver graph"))?;
    assert_eq!(payjoin_tx.input.len(), 2);
    assert_eq!(payjoin_tx.output.len(), 2);

    println!(
        "Sender confirmed: {} | Receiver confirmed: {} | Network fee: {}",
        sender_wallet.balance().confirmed,
        receiver_wallet.balance().confirmed,
        network_fees,
    );

    // In payjoin both parties may contribute to the fee, so each lost amount is somewhere
    // between zero and `network_fees`. Sender starts at 50 BTC, pays 5 BTC, so confirmed
    // ends in `[45 BTC - network_fees, 45 BTC]`. Receiver starts at 50 BTC, receives 5 BTC,
    // so confirmed ends in `[55 BTC - network_fees, 55 BTC]`.
    let sender_balance = sender_wallet.balance().confirmed;
    let receiver_balance = receiver_wallet.balance().confirmed;
    let forty_five = Amount::from_btc(45.0)?;
    let fifty_five = Amount::from_btc(55.0)?;
    assert!(sender_balance >= forty_five - network_fees && sender_balance <= forty_five);
    assert!(receiver_balance >= fifty_five - network_fees && receiver_balance <= fifty_five);

    Ok(())
}

/// Receiver task: initialize the v2 session, share the PJ URI with the sender, poll the
/// directory for the sender's original PSBT, contribute receiver inputs, then publish the
/// signed payjoin proposal back to the directory.
async fn run_receiver(
    env: Arc<TestEnv>,
    mut wallet: Wallet,
    signer: Signer,
    ohttp_relay: Url,
    payjoin_directory: Url,
    ohttp_keys: OhttpKeys,
    uri_tx: oneshot::Sender<String>,
) -> Result<Wallet> {
    let secp = Secp256k1::new();
    let persister = NoopSessionPersister::default();
    let http = reqwest::Client::new();

    let receiver_address = wallet.next_address().ok_or_else(|| anyhow!("no address"))?;
    let mut session = ReceiverBuilder::new(receiver_address, payjoin_directory.as_str(), ohttp_keys)?
        .build()
        .save(&persister)?;

    uri_tx
        .send(session.pj_uri().to_string())
        .map_err(|_| anyhow!("sender dropped before receiving pj_uri"))?;

    // Poll for the sender's original PSBT.
    let proposal = loop {
        let (req, ctx) = session.create_poll_request(ohttp_relay.as_str())?;
        let response = http
            .post(req.url)
            .header("Content-Type", req.content_type)
            .body(req.body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!("directory error: {}", response.status()));
        }
        let outcome = session
            .process_response(response.bytes().await?.as_ref(), ctx)
            .save(&persister)?;
        match outcome {
            OptionalTransitionOutcome::Progress(p) => break p,
            OptionalTransitionOutcome::Stasis(current) => {
                session = current;
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    };

    let payjoin_proposal = handle_directory_proposal(&wallet, &env, proposal, &signer, &secp)?;
    let (req, _) = payjoin_proposal.create_post_request(ohttp_relay.as_str())?;
    let _response = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;

    Ok(wallet)
}

/// Sender task: receive the PJ URI from the receiver, build and post the original PSBT,
/// poll for the receiver's payjoin proposal, then sign, finalize, and broadcast the tx.
async fn run_sender(
    env: Arc<TestEnv>,
    wallet: Wallet,
    signer: Signer,
    change_desc: Descriptor<DescriptorPublicKey>,
    ohttp_relay: Url,
    uri_rx: oneshot::Receiver<String>,
) -> Result<(Wallet, Txid, Amount)> {
    let secp = Secp256k1::new();
    let persister = NoopSessionPersister::default();
    let http = reqwest::Client::new();

    let uri_str = uri_rx.await.map_err(|_| anyhow!("receiver dropped pj_uri"))?;
    let pj_uri = Uri::try_from(uri_str.as_str())
        .map_err(|e| anyhow!("{e}"))?
        .assume_checked()
        .check_pj_supported()
        .map_err(|e| anyhow!("{e}"))?;

    let psbt = build_psbt(&env, &wallet, &signer, &pj_uri, &change_desc, &secp)?;

    let req_ctx = SenderBuilder::new(psbt, pj_uri)
        .build_recommended(FeeRate::BROADCAST_MIN)?
        .save(&persister)?;

    // Post the original PSBT.
    let (req, send_ctx) = req_ctx.create_v2_post_request(ohttp_relay.as_str())?;
    let response = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!("directory error: {}", response.status()));
    }
    let mut send_ctx = req_ctx
        .process_response(&response.bytes().await?, send_ctx)
        .save(&persister)?;

    // Poll for the receiver's payjoin proposal.
    let checked_proposal_psbt = loop {
        let (Request { url, body, content_type, .. }, ohttp_ctx) =
            send_ctx.create_poll_request(ohttp_relay.as_str())?;
        let response = http
            .post(url)
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .await?;
        let outcome = send_ctx
            .process_response(&response.bytes().await?, ohttp_ctx)
            .save(&persister)?;
        match outcome {
            OptionalTransitionOutcome::Progress(psbt) => break psbt,
            OptionalTransitionOutcome::Stasis(current) => {
                send_ctx = current;
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    };

    let network_fees = checked_proposal_psbt.fee()?;
    let payjoin_tx = extract_pj_tx(&wallet, checked_proposal_psbt, &signer, &secp)?;
    let txid = env.rpc_client().send_raw_transaction(&payjoin_tx)?;

    Ok((wallet, txid, network_fees))
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
            Some(FeeRate::from_sat_per_vb(2).expect("valid fee rate")),
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
    change_desc: &Descriptor<DescriptorPublicKey>,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Psbt> {
    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;

    let target_amount = Amount::from_btc(5.0)?;
    let target_feerate = FeeRate::from_sat_per_vb(2).expect("valid fee rate");
    let longterm_feerate = FeeRate::from_sat_per_vb(1).expect("valid fee rate");

    let target_outputs = vec![Output::with_script(
        pj_uri.address.script_pubkey(),
        target_amount,
    )];

    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable(tip_height, Some(tip_time)))
        .into_selection(
            |selector| -> anyhow::Result<()> {
                selector.select_all();
                Ok(())
            },
            SelectorParams {
                change_longterm_feerate: Some(longterm_feerate),
                ..SelectorParams::new(
                    target_feerate,
                    target_outputs,
                    ChangeScript::from_descriptor(change_desc.at_derivation_index(0)?),
                )
            },
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
        .filter(|input| input.is_spendable(tip_height, Some(tip_time)).unwrap_or(false));

    let inputs = candidates
        .inputs()
        .filter_map(|input| {
            let outpoint = input.prev_outpoint();
            let plan = wallet.plan_of_output(outpoint, &assets)?;
            let txout = input.prev_txout().clone();

            let txin = TxIn {
                previous_output: outpoint,
                sequence: input.sequence().unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
                ..Default::default()
            };

            let mut psbt_input = psbt::Input {
                witness_utxo: Some(txout.clone()),
                non_witness_utxo: input.prev_tx().cloned(),
                ..Default::default()
            };
            plan.update_psbt_input(&mut psbt_input);

            // payjoin's `InputPair::new` cannot infer the input weight for unsigned P2TR or
            // P2WSH inputs (no witness yet), so we provide it explicitly. For input types it
            // *can* infer (P2WPKH, P2PKH, etc.) we pass `None` — passing `Some` for those
            // would be rejected as `ProvidedUnnecessaryWeight`.
            let needs_explicit_weight =
                txout.script_pubkey.is_p2tr() || txout.script_pubkey.is_p2wsh();
            let expected_weight = needs_explicit_weight.then(|| {
                // Total input weight = base txin (41 bytes × 4 wu) + witness satisfaction.
                Weight::from_wu(input.satisfaction_weight() + 41 * 4)
            });

            InputPair::new(txin, psbt_input, expected_weight).ok()
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
