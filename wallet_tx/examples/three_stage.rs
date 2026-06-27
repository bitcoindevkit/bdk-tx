//! Build, sign and finalize a transaction from a `bdk_wallet::Wallet` using the three-stage
//! `bdk_wallet_tx` bridge: candidates -> select -> build_psbt.
//!
//! Run with: `cargo run -p bdk_wallet_tx --example three_stage`
//!
//! The wallet here is funded deterministically via `bdk_wallet`'s `test-utils` so the example
//! needs no network or `bitcoind`. A real application would sync the wallet from its chain source
//! instead; everything from `candidates()` onward is identical.

use bdk_tx::BuildPsbtParams;
use bdk_wallet::test_utils::{get_funded_wallet, get_test_tr_single_sig_xprv_and_change_desc};
use bdk_wallet::{KeychainKind, SignOptions};
use bdk_wallet_tx::{SelectParams, SelectionStrategy, WalletTxExt};
use bitcoin::secp256k1::rand;
use bitcoin::{absolute, Amount, FeeRate};

fn main() -> anyhow::Result<()> {
    let (descriptor, change_descriptor) = get_test_tr_single_sig_xprv_and_change_desc();
    let (mut wallet, _funding_txid) = get_funded_wallet(descriptor, change_descriptor);
    println!("balance: {}", wallet.balance().total());

    // A destination (here, a far-future address of our own wallet just for demonstration).
    let recipient = wallet
        .peek_address(KeychainKind::External, 42)
        .script_pubkey();

    // Stage 1 -- resolve the spendable candidate set.
    let coins = wallet.candidates()?;
    println!("candidates: {}", coins.inputs().count());

    // The caller supplies the RNG (here used by the input/output shuffling and anti-fee-sniping
    // below; SingleRandomDraw selection would use it too, but this example uses LowestFee).
    let mut rng = rand::thread_rng();

    // Stage 2 -- run coin selection (a pure read), yielding a `bdk_tx::TxTemplate` and the
    // auto-derived change address (peeked, not yet revealed).
    let (template, change) = wallet.select(
        &coins,
        SelectParams {
            recipients: vec![(recipient.clone(), Amount::from_sat(10_000))],
            coin_selection: SelectionStrategy::LowestFee {
                max_rounds: 210_000,
            },
            feerate: FeeRate::from_sat_per_vb(4).expect("valid feerate"),
            longterm_feerate: Some(FeeRate::from_sat_per_vb(1).expect("valid feerate")),
            change_script: None,
        },
        &mut rng,
    )?;

    // Reserve this selection's change address: reveal + mark it used (then persist the change set),
    // so a later `select` (e.g. when batching several txs before broadcasting) won't hand out the
    // same change address. Skip it to leave the wallet untouched; if you reserve but then drop this
    // tx, release the address with `unmark_used`.
    if let Some(change) = &change {
        wallet.reserve_change(change);
    }

    // Stage 3 -- shape the template and emit, all in one chain: shuffle inputs/outputs (so the
    // change output isn't in a predictable position), apply anti-fee-sniping to bind the tx to the
    // chain tip (this seals the template), then build the PSBT + finalizer directly via `bdk_tx`
    // (no wallet needed for emission).
    let tip_height = absolute::Height::from_consensus(wallet.latest_checkpoint().height())?;
    let (mut psbt, finalizer) = template
        .shuffle_inputs(&mut rng)
        .shuffle_outputs(&mut rng)
        .apply_anti_fee_sniping(tip_height, &mut rng)?
        .build_psbt(BuildPsbtParams::default())?;
    // ...then optionally fill the wallet's global xpubs (the one emission step that needs it).
    wallet.add_global_xpubs(&mut psbt)?;

    // Sign with the wallet's keys, then finalize with the `bdk_tx` finalizer.
    let _ = wallet.sign(
        &mut psbt,
        SignOptions {
            try_finalize: false,
            ..Default::default()
        },
    )?;
    assert!(
        finalizer.finalize(&mut psbt).is_finalized(),
        "must finalize"
    );

    let tx = psbt.extract_tx()?;
    println!(
        "built tx {}: {} input(s), {} output(s)",
        tx.compute_txid(),
        tx.input.len(),
        tx.output.len(),
    );
    Ok(())
}
