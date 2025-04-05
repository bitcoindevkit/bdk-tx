use bdk_chain::spk_client::{FullScanRequestBuilder, FullScanResponse, SyncResponse};
use bdk_chain::KeychainIndexed;
use bdk_esplora::esplora_client;
use bdk_esplora::esplora_client::Builder;
use bdk_esplora::EsploraExt;
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    create_psbt, create_selection, CreatePsbtParams, CreateSelectionParams, InputCandidates,
    InputGroup, Output,
};
use bdk_wallet::{AddressInfo, KeychainKind, LocalOutput, SignOptions};
use bitcoin::address::NetworkChecked;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint};
use miniscript::descriptor::KeyMap;
use miniscript::plan::Assets;
use miniscript::{Descriptor, DescriptorPublicKey};
use std::collections::BTreeMap;
use std::process::exit;
use std::str::FromStr;

#[test]
fn bdk_wallet_simple_tx() -> anyhow::Result<()> {
    const STOP_GAP: usize = 20;
    const PARALLEL_REQUESTS: usize = 1;
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let descriptor_private: &str = "tr(tprv8ZgxMBicQKsPdNRGG6HuFapxQCFxsDDf7TDsV8tdUgZDdiiyA6dB2ssN4RSXyp52V3MRBm4KqAps3Txng59rNMUtUEtMPDphKkKDXmamd2T/86'/1'/0'/0/*)#usy7l3tt";
    let change_descriptor_private: &str = "tr(tprv8ZgxMBicQKsPdNRGG6HuFapxQCFxsDDf7TDsV8tdUgZDdiiyA6dB2ssN4RSXyp52V3MRBm4KqAps3Txng59rNMUtUEtMPDphKkKDXmamd2T/86'/1'/0'/1/*)#dyplzymn";

    let (descriptor, _): (Descriptor<DescriptorPublicKey>, KeyMap) = Descriptor::parse_descriptor(&secp, "tr(tprv8ZgxMBicQKsPdNRGG6HuFapxQCFxsDDf7TDsV8tdUgZDdiiyA6dB2ssN4RSXyp52V3MRBm4KqAps3Txng59rNMUtUEtMPDphKkKDXmamd2T/86'/1'/0'/0/*)#usy7l3tt")?;
    let (change_descriptor, _): (Descriptor<DescriptorPublicKey>, KeyMap) = Descriptor::parse_descriptor(&secp, "tr(tprv8ZgxMBicQKsPdNRGG6HuFapxQCFxsDDf7TDsV8tdUgZDdiiyA6dB2ssN4RSXyp52V3MRBm4KqAps3Txng59rNMUtUEtMPDphKkKDXmamd2T/86'/1'/0'/1/*)#dyplzymn")?;

    // Create the wallet
    let mut wallet = bdk_wallet::Wallet::create(descriptor_private, change_descriptor_private)
        .network(Network::Regtest)
        .create_wallet_no_persist()?;

    let client: esplora_client::BlockingClient =
        Builder::new("http://127.0.0.1:3002").build_blocking();

    println!("Syncing wallet...");
    let full_scan_request: FullScanRequestBuilder<KeychainKind> = wallet.start_full_scan();
    let update: FullScanResponse<KeychainKind> =
        client.full_scan(full_scan_request, STOP_GAP, PARALLEL_REQUESTS)?;

    // Apply the update from the full scan to the wallet
    wallet.apply_update(update)?;

    let balance = wallet.balance();
    println!("Wallet balance: {} sat", balance.total().to_sat());

    if balance.total().to_sat() < 300000 {
        println!("Your wallet does not have sufficient balance for the following steps!");
        // Reveal a new address from your external keychain
        let address: AddressInfo = wallet.reveal_next_address(KeychainKind::External);
        println!(
            "Send coins to {} (address generated at index {})",
            address.address, address.index
        );
        exit(0)
    }

    let local_outputs: Vec<LocalOutput> = wallet.list_unspent().collect();
    dbg!(&local_outputs.len());
    // dbg!(&local_outputs);
    let outpoints: Vec<KeychainIndexed<KeychainKind, OutPoint>> = local_outputs
        .into_iter()
        .map(|o| ((o.keychain, o.derivation_index), o.outpoint.clone()))
        .collect();

    let mut descriptors_map = BTreeMap::new();
    descriptors_map.insert(KeychainKind::External, descriptor.clone());
    descriptors_map.insert(KeychainKind::Internal, change_descriptor.clone());

    let input_candidates: Vec<InputGroup> = InputCandidates::new(
        &wallet.tx_graph(),
        &wallet.local_chain(),
        wallet.local_chain().tip().block_id(),
        outpoints,
        descriptors_map,
        Assets::new(),
    )?
    .into_single_groups(|_| true);

    let recipient_address: Address<NetworkChecked> =
        Address::from_str("bcrt1qe908k9zu8m4jgzdddgg0lkj73yctfqueg7pea9")?
            .require_network(Network::Regtest)?;

    let (selection, metrics) = create_selection(CreateSelectionParams::new(
        input_candidates,
        change_descriptor.at_derivation_index(0)?,
        vec![Output::with_script(
            recipient_address.script_pubkey(),
            Amount::from_sat(200_000),
        )],
        FeeRate::from_sat_per_vb(5).unwrap(),
    ))?;

    dbg!(&selection);

    let (mut psbt, _) = create_psbt(CreatePsbtParams::new(selection))?;
    let signed = wallet.sign(&mut psbt, SignOptions::default())?;
    assert!(signed);
    let tx = psbt.extract_tx()?;

    client.broadcast(&tx)?;
    dbg!("tx broadcast: {}", tx.compute_txid());

    println!("Syncing wallet again...");
    let sync_request = wallet.start_sync_with_revealed_spks();
    let update_2: SyncResponse = client.sync(sync_request, PARALLEL_REQUESTS)?;

    wallet.apply_update(update_2)?;

    let balance_2 = wallet.balance();
    println!("Wallet balance: {} sat", balance_2.total().to_sat());

    Ok(())
}
