# bdk-tx workspace

A Cargo workspace with two crates:

- [`tx/`](tx) -- **`bdk_tx`**, a low-level Bitcoin transaction-building library (coin selection,
  tx-template shaping, PSBT emission and finalization). See [`tx/README.md`](tx/README.md).
- [`wallet_tx/`](wallet_tx) -- **`bdk_wallet_tx`**, a bridge crate that drives `bdk_tx`'s multi-stage
  transaction building from a `bdk_wallet::Wallet` via the `WalletTxExt` extension trait. See
  [`wallet_tx/README.md`](wallet_tx/README.md).

`wallet_tx` depends on both `bdk_wallet` and `bdk_tx`, so neither base crate depends on the other:
`bdk_wallet` stays stable, `bdk_tx` stays free to move, and the bridge absorbs the coupling.

## Building

```sh
cargo build --workspace
cargo test --workspace
```

`bdk_tx` additionally supports `no_std`:

```sh
cargo check -p bdk_tx --no-default-features --features miniscript/no-std
```
