# bdk_wallet_tx

A bridge crate between [`bdk_wallet`](https://github.com/bitcoindevkit/bdk_wallet) and
[`bdk_tx`](https://github.com/bitcoindevkit/bdk-tx).

`bdk_wallet` is the stable, batteries-included wallet; `bdk_tx` is a fast-moving, low-level
transaction-building library. This crate depends on **both** and exposes their integration as an
extension trait, `WalletTxExt`, implemented for `bdk_wallet::Wallet`.

Keeping the integration in a separate crate means neither base crate depends on the other:
`bdk_wallet` stays stable, `bdk_tx` stays free to move, and every breaking `bdk_tx` release is
absorbed here rather than forcing a `bdk_wallet` major. (See
[bitcoindevkit/bdk_wallet#297](https://github.com/bitcoindevkit/bdk_wallet/pull/297#issuecomment-4810411011).)

## Three-stage pipeline

```rust,ignore
use bdk_tx::BuildPsbtParams;
use bdk_wallet_tx::{WalletTxExt, SelectParams, SelectionStrategy};

// 1. Candidates -- resolve the wallet's spendable inputs.
let coins = wallet.candidates()?;

// 2. Select -- coin selection (a pure read), yielding a `bdk_tx::TxTemplate` and the auto-derived
//    change address. The template is unshuffled with no anti-fee-sniping; shape it here if desired.
let (template, change) = wallet.select(&coins, SelectParams {
    recipients: vec![(recipient_spk, amount)],
    coin_selection: SelectionStrategy::LowestFee { max_rounds: 210_000 },
    feerate,
    longterm_feerate: None,
    change_script: None,
}, &mut rng)?;
// Reserve the change address so a later `select` won't reuse it (reveal + mark used; then persist
// the change set). Skip it to leave the wallet untouched; release later with `unmark_used`.
if let Some(change) = &change { wallet.reserve_change(change); }

// 3. Emit the PSBT directly via bdk_tx (no wallet needed)...
let (mut psbt, finalizer) = template.build_psbt(BuildPsbtParams::default())?;
// ...optionally fill the wallet's global xpubs (the only emission step that needs the wallet).
wallet.add_global_xpubs(&mut psbt)?;
```

Sign the PSBT however you like, then `finalizer.finalize(&mut psbt)`.

See `examples/three_stage.rs` for a complete, runnable flow.

## Notes

- **Anti-fee-sniping / MTP.** `select` returns an *unshuffled* template with *no* anti-fee-sniping --
  apply `template.apply_anti_fee_sniping(tip_height, rng)` and `template.shuffle_outputs(rng)`
  yourself before `build_psbt`. `bdk_wallet` checkpoints carry no median-time-past, so per-input
  `prev_mtp` is taken from the optional `CandidateParams::fetch_mtp` oracle (never fabricated) and
  left `None` without one; supply `tip_mtp` / `fetch_mtp` for time-based (CSV/CLTV-time) timelock
  filtering.
- **Change address.** `select` is a pure read: when no change script is supplied it *peeks* the
  next unused internal address and returns it, without mutating the wallet. Reserve it with
  `reserve_change` (reveal + mark used; then persist the change set) so a later `select` won't
  reuse it -- handy across several maybe-broadcast txs. Release an unused one with `unmark_used`;
  reserve nothing and the wallet is left untouched.
