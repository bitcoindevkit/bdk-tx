//! End-to-end tests of the three-stage pipeline over a deterministically-funded `bdk_wallet`.

use bdk_tx::{BuildPsbtParams, ChangeScript};
use bdk_wallet::test_utils::{get_funded_wallet, get_test_tr_single_sig_xprv_and_change_desc};
use bdk_wallet::{KeychainKind, SignOptions};
use bdk_wallet_tx::{SelectError, SelectParams, SelectionStrategy, WalletTxExt};
use bitcoin::secp256k1::rand;
use bitcoin::{Amount, FeeRate};

/// Sign the PSBT with the wallet's keys (without finalizing), then finalize with the `bdk_tx`
/// finalizer returned by stage 3.
fn sign_and_finalize(
    wallet: &bdk_wallet::Wallet,
    psbt: &mut bitcoin::Psbt,
    finalizer: &bdk_tx::Finalizer,
) {
    // `Wallet::sign` returns the PSBT's *finalization* status (false here, since we leave
    // finalization to the `bdk_tx` finalizer); it still fills in the signatures.
    let _ = wallet
        .sign(
            psbt,
            SignOptions {
                try_finalize: false,
                ..Default::default()
            },
        )
        .expect("signing failed");
    assert!(finalizer.finalize(psbt).is_finalized(), "must finalize");
}

#[test]
fn select_and_build_psbt_pays_recipient() -> anyhow::Result<()> {
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (wallet, _txid) = get_funded_wallet(desc, change);

    // Stage 1.
    let coins = wallet.candidates()?;
    assert!(!coins.is_empty(), "funded wallet must have candidates");

    // Stage 2.
    let recipient = wallet
        .peek_address(KeychainKind::External, 99)
        .script_pubkey();
    let params = SelectParams {
        recipients: vec![(recipient.clone(), Amount::from_sat(10_000))],
        coin_selection: SelectionStrategy::SingleRandomDraw,
        feerate: FeeRate::from_sat_per_vb(2).unwrap(),
        change_script: None,
        longterm_feerate: None,
    };
    let (template, _change) = wallet.select(&coins, params, &mut rand::thread_rng())?;

    // Stage 3.
    let (mut psbt, finalizer) = template.build_psbt(BuildPsbtParams::default())?;
    sign_and_finalize(&wallet, &mut psbt, &finalizer);

    let tx = psbt.extract_tx()?;
    assert!(
        tx.output
            .iter()
            .any(|o| o.script_pubkey == recipient && o.value == Amount::from_sat(10_000)),
        "recipient output must be present with the exact amount"
    );
    // recipient + change.
    assert_eq!(tx.output.len(), 2);
    Ok(())
}

#[test]
fn sweep_all_to_single_output() -> anyhow::Result<()> {
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (wallet, _txid) = get_funded_wallet(desc, change);

    let coins = wallet.candidates()?;
    let params = SelectParams {
        coin_selection: SelectionStrategy::SweepAll,
        feerate: FeeRate::from_sat_per_vb(1).unwrap(),
        ..Default::default()
    };
    let (template, _change) = wallet.select(&coins, params, &mut rand::thread_rng())?;
    let (mut psbt, finalizer) = template.build_psbt(BuildPsbtParams::default())?;
    sign_and_finalize(&wallet, &mut psbt, &finalizer);

    let tx = psbt.extract_tx()?;
    assert_eq!(tx.output.len(), 1, "a sweep has a single (change) output");
    Ok(())
}

#[test]
fn lowest_fee_selection_pays_recipient() -> anyhow::Result<()> {
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (wallet, _txid) = get_funded_wallet(desc, change);

    let coins = wallet.candidates()?;
    let recipient = wallet
        .peek_address(KeychainKind::External, 7)
        .script_pubkey();
    let params = SelectParams {
        recipients: vec![(recipient.clone(), Amount::from_sat(10_000))],
        coin_selection: SelectionStrategy::LowestFee {
            max_rounds: 100_000,
        },
        feerate: FeeRate::from_sat_per_vb(2).unwrap(),
        longterm_feerate: Some(FeeRate::from_sat_per_vb(1).unwrap()),
        change_script: None,
    };
    let (template, _change) = wallet.select(&coins, params, &mut rand::thread_rng())?;
    let (mut psbt, finalizer) = template.build_psbt(BuildPsbtParams::default())?;
    sign_and_finalize(&wallet, &mut psbt, &finalizer);

    let tx = psbt.extract_tx()?;
    assert!(tx
        .output
        .iter()
        .any(|o| o.script_pubkey == recipient && o.value == Amount::from_sat(10_000)));
    Ok(())
}

#[test]
fn add_global_xpubs_populates_psbt() -> anyhow::Result<()> {
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (wallet, _txid) = get_funded_wallet(desc, change);

    let coins = wallet.candidates()?;
    let recipient = wallet
        .peek_address(KeychainKind::External, 1)
        .script_pubkey();
    let (template, _change) = wallet.select(
        &coins,
        SelectParams {
            recipients: vec![(recipient, Amount::from_sat(10_000))],
            feerate: FeeRate::from_sat_per_vb(2).unwrap(),
            ..Default::default()
        },
        &mut rand::thread_rng(),
    )?;
    let (mut psbt, _finalizer) = template.build_psbt(BuildPsbtParams::default())?;

    assert!(psbt.xpub.is_empty(), "no global xpubs before");
    wallet.add_global_xpubs(&mut psbt)?;
    assert!(!psbt.xpub.is_empty(), "global xpubs should be populated");
    Ok(())
}

#[test]
fn select_is_a_pure_read_change_reserve_is_explicit() -> anyhow::Result<()> {
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (mut wallet, _txid) = get_funded_wallet(desc, change);

    let before = wallet.next_derivation_index(KeychainKind::Internal);
    let coins = wallet.candidates()?;
    let recipient = wallet
        .peek_address(KeychainKind::External, 5)
        .script_pubkey();
    let (_template, change) = wallet.select(
        &coins,
        SelectParams {
            recipients: vec![(recipient, Amount::from_sat(10_000))],
            feerate: FeeRate::from_sat_per_vb(2).unwrap(),
            ..Default::default()
        },
        &mut rand::thread_rng(),
    )?;

    // `select` reports the change output but does not touch wallet state.
    let change = change.expect("a change output was produced");
    assert_eq!(change.keychain, KeychainKind::Internal);
    assert_eq!(
        wallet.next_derivation_index(KeychainKind::Internal),
        before,
        "select must not reveal/mutate"
    );

    // Committing reveals it (keychain advances) and marks it used (no longer offered as unused --
    // i.e. the next select won't reuse it).
    wallet.reserve_change(&change);
    assert!(
        wallet.next_derivation_index(KeychainKind::Internal) > before,
        "reserve_change reveals the change address"
    );
    assert!(
        !wallet
            .list_unused_addresses(KeychainKind::Internal)
            .any(|a| a.index == change.index),
        "reserve_change marks the change address used (prevents reuse)"
    );
    Ok(())
}

#[test]
fn no_change_output_yields_none() -> anyhow::Result<()> {
    // A caller-supplied change script auto-derives nothing.
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (wallet, _txid) = get_funded_wallet(desc, change);
    let coins = wallet.candidates()?;
    let recipient = wallet
        .peek_address(KeychainKind::External, 6)
        .script_pubkey();
    let explicit_change = ChangeScript::from_descriptor(
        wallet
            .public_descriptor(KeychainKind::External)
            .at_derivation_index(50)?,
    );
    let (_template, change) = wallet.select(
        &coins,
        SelectParams {
            recipients: vec![(recipient, Amount::from_sat(10_000))],
            change_script: Some(explicit_change),
            feerate: FeeRate::from_sat_per_vb(2).unwrap(),
            ..Default::default()
        },
        &mut rand::thread_rng(),
    )?;
    assert!(
        change.is_none(),
        "a caller-supplied change script yields no auto-derived change address"
    );
    Ok(())
}

#[test]
fn locked_outpoints_are_excluded_from_candidates() -> anyhow::Result<()> {
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (mut wallet, _txid) = get_funded_wallet(desc, change);

    let utxo = wallet
        .list_unspent()
        .next()
        .expect("funded wallet has a utxo")
        .outpoint;
    assert!(
        wallet
            .candidates()?
            .inputs()
            .any(|i| i.prev_outpoint() == utxo),
        "utxo is a candidate before locking"
    );

    wallet.lock_outpoint(utxo);
    assert!(
        !wallet
            .candidates()?
            .inputs()
            .any(|i| i.prev_outpoint() == utxo),
        "locked outpoint must not be a candidate"
    );
    Ok(())
}

#[test]
fn select_without_recipients_errors() {
    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (wallet, _txid) = get_funded_wallet(desc, change);

    let coins = wallet.candidates().unwrap();
    // The default strategy (LowestFee) is a non-sweep one, which requires at least one recipient.
    let err = wallet
        .select(&coins, SelectParams::new(), &mut rand::thread_rng())
        .unwrap_err();
    assert!(matches!(err, SelectError::NoRecipients));
}

#[test]
fn immature_coinbase_is_excluded_unless_allowed() -> anyhow::Result<()> {
    use bdk_wallet::chain::{ConfirmationBlockTime, TxUpdate};
    use bdk_wallet::Update;
    use bdk_wallet_tx::CandidateParams;
    use bitcoin::{absolute, transaction, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
    use std::sync::Arc;

    let (desc, change) = get_test_tr_single_sig_xprv_and_change_desc();
    let (mut wallet, _txid) = get_funded_wallet(desc, change);
    let tip = wallet.latest_checkpoint().block_id();

    // A coinbase output paying the wallet, confirmed *at the tip* -- so it is still immature.
    let spk = wallet
        .peek_address(KeychainKind::External, 0)
        .script_pubkey();
    let coinbase = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: spk,
        }],
    };
    assert!(coinbase.is_coinbase());
    let cb = OutPoint::new(coinbase.compute_txid(), 0);
    // Insert the coinbase confirmed, with no mempool `seen_at` (coinbase txs can't be in mempool).
    let mut tx_update = TxUpdate::default();
    tx_update.txs = vec![Arc::new(coinbase)];
    tx_update.anchors = [(
        ConfirmationBlockTime {
            block_id: tip,
            confirmation_time: 0,
        },
        cb.txid,
    )]
    .into();
    wallet
        .apply_update(Update {
            tx_update,
            ..Default::default()
        })
        .expect("apply update");

    // Default: the immature coinbase is excluded.
    assert!(
        !wallet
            .candidates()?
            .inputs()
            .any(|i| i.prev_outpoint() == cb),
        "immature coinbase must be excluded by default"
    );

    // `allow_immature`: it is included.
    let coins = wallet.candidates_with(&CandidateParams {
        allow_immature: true,
        ..Default::default()
    })?;
    assert!(
        coins.inputs().any(|i| i.prev_outpoint() == cb),
        "allow_immature must include the immature coinbase"
    );
    Ok(())
}
