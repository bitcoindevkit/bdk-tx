#[path = "../examples/common.rs"]
mod common;
use common::Wallet;

use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{Output, PsbtParams, ScriptSource, SelectorParams, Signer};
use bitcoin::{key::Secp256k1, Amount, FeeRate, Sequence, Transaction, Weight};
use miniscript::{bitcoin, DefiniteDescriptorKey, Descriptor};

fn setup_wallet_with_funds() -> anyhow::Result<(TestEnv, Wallet, Signer)> {
    let secp = bitcoin::key::Secp256k1::new();
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

    // Fund the wallet with 1 BTC
    env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;

    Ok((env, wallet, signer))
}

fn create_and_verify_parent_tx(
    wallet: &mut Wallet,
    env: &TestEnv,
    signer: &Signer,
    target_feerate: FeeRate,
    output_value: Amount,
    addr: &bitcoin::Address,
    internal_desc: Descriptor<DefiniteDescriptorKey>,
) -> anyhow::Result<(Transaction, bitcoin::Txid, Amount, Weight)> {
    let secp = Secp256k1::new();
    let selection = wallet.all_candidates().into_selection(
        bdk_tx::selection_algorithm_lowest_fee_bnb(target_feerate, 100_000),
        SelectorParams::new(
            target_feerate,
            vec![Output::with_script(addr.script_pubkey(), output_value)],
            ScriptSource::Descriptor(Box::new(internal_desc)),
            bdk_tx::ChangePolicyType::NoDustAndLeastWaste {
                longterm_feerate: target_feerate,
            },
            wallet.change_weight(),
        ),
    )?;
    let mut parent_psbt = selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::MAX,
        ..Default::default()
    })?;
    let parent_finalizer = selection.into_finalizer();
    parent_psbt
        .sign(signer, &secp)
        .map_err(|_| anyhow::anyhow!("failed to sign parent PSBT"))?;
    assert!(parent_finalizer.finalize(&mut parent_psbt).is_finalized());
    let parent_tx = parent_psbt.extract_tx()?;
    let parent_txid = env.rpc_client().send_raw_transaction(&parent_tx)?;
    wallet.sync(env)?;

    // Verify parent transaction fee rate
    let parent_fee = wallet.graph.graph().calculate_fee(&parent_tx)?;
    let parent_weight = parent_tx.weight();
    let parent_feerate = parent_fee / parent_weight;
    assert!(
        parent_feerate
            .to_sat_per_kwu()
            .abs_diff(target_feerate.to_sat_per_kwu())
            <= 1,
        "Parent transaction fee rate {} does not match target {}",
        parent_feerate.to_sat_per_kwu(),
        target_feerate.to_sat_per_kwu()
    );

    Ok((parent_tx, parent_txid, parent_fee, parent_weight))
}

fn create_and_verify_cpfp_tx(
    wallet: &mut Wallet,
    signer: &Signer,
    parent_txid: bitcoin::Txid,
    parent_fee: Amount,
    parent_weight: Weight,
    target_package_feerate: FeeRate,
) -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let cpfp_selection = wallet.create_cpfp_tx([parent_txid], target_package_feerate)?;
    let mut cpfp_psbt = cpfp_selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::MAX,
        ..Default::default()
    })?;
    let cpfp_finalizer = cpfp_selection.into_finalizer();
    cpfp_psbt
        .sign(signer, &secp)
        .map_err(|_| anyhow::anyhow!("failed to sign CPFP PSBT"))?;
    assert!(cpfp_finalizer.finalize(&mut cpfp_psbt).is_finalized());
    let cpfp_tx = cpfp_psbt.extract_tx()?;

    // Verify CPFP transaction fee rate
    let cpfp_fee = wallet.graph.graph().calculate_fee(&cpfp_tx)?;
    let cpfp_weight = cpfp_tx.weight();
    let package_fee = parent_fee + cpfp_fee;
    let package_weight = parent_weight + cpfp_weight;
    let package_feerate = package_fee / package_weight;
    assert!(
        package_feerate
            .to_sat_per_vb_ceil()
            .abs_diff(target_package_feerate.to_sat_per_vb_ceil())
            <= 1,
        "Package fee rate {} does not match target {}",
        package_feerate.to_sat_per_vb_ceil(),
        target_package_feerate.to_sat_per_vb_ceil()
    );

    Ok(())
}

#[test]
fn test_cpfp_same_feerate() -> anyhow::Result<()> {
    let (env, mut wallet, signer) = setup_wallet_with_funds()?;
    let addr = wallet.next_address().expect("must derive address");
    let derivation_index = 0;
    let internal_desc = wallet
        .graph
        .index
        .get_descriptor("internal")
        .expect("must have internal descriptor")
        .at_derivation_index(derivation_index)?;

    // Create a parent transaction with fee rate x = 1 sat/vB
    let target_feerate = FeeRate::from_sat_per_vb_unchecked(1);
    let output_value = Amount::from_sat(50_000_000); // 0.5 BTC
    let (_, parent_txid, parent_fee, parent_weight) = create_and_verify_parent_tx(
        &mut wallet,
        &env,
        &signer,
        target_feerate,
        output_value,
        &addr,
        internal_desc,
    )?;

    // Create and verify CPFP transaction with target_package_feerate = x (1 sat/vB)
    create_and_verify_cpfp_tx(
        &mut wallet,
        &signer,
        parent_txid,
        parent_fee,
        parent_weight,
        target_feerate,
    )?;

    Ok(())
}

#[test]
fn test_cpfp_higher_feerate() -> anyhow::Result<()> {
    let (env, mut wallet, signer) = setup_wallet_with_funds()?;
    let addr = wallet.next_address().expect("must derive address");
    let derivation_index = 0;
    let internal_desc = wallet
        .graph
        .index
        .get_descriptor("internal")
        .expect("must have internal descriptor")
        .at_derivation_index(derivation_index)?;

    // Create a parent transaction with fee rate x = 1 sat/vB
    let x_feerate = FeeRate::from_sat_per_vb_unchecked(1);
    let output_value = Amount::from_sat(50_000_000); // 0.5 BTC
    let (_, parent_txid, parent_fee, parent_weight) = create_and_verify_parent_tx(
        &mut wallet,
        &env,
        &signer,
        x_feerate,
        output_value,
        &addr,
        internal_desc,
    )?;

    // Create CPFP transaction with target_package_feerate = x + y (1 + 2 = 3 sat/vB)
    let target_package_feerate = FeeRate::from_sat_per_vb_unchecked(3);
    create_and_verify_cpfp_tx(
        &mut wallet,
        &signer,
        parent_txid,
        parent_fee,
        parent_weight,
        target_package_feerate,
    )?;

    Ok(())
}
