# `bdk-tx`

This is a transaction building library based on `rust-miniscript` that lets you build, update, and finalize PSBTs with minimal dependencies.

<!-- links to relevant literature -->
Because the project builds upon [miniscript] we support [descriptors] natively.

Refer to [BIP174], [BIP370], and [BIP371] to learn more about partially signed bitcoin transactions (PSBT).

## Example

To get started see the `DataProvider` trait and the methods for adding inputs and outputs.

```rust
use bdk_transaction::Builder;
use bdk_transaction::DataProvider;

impl DataProvider for MyType { ... }

let mut builder = Builder::new();
builder.add_input(plan_utxo);
builder.add_output(script_pubkey, amount);
let (mut psbt, finalizer) = builder.build_tx(data_provider)?;

// Your PSBT signing flow...

let result = finalizer.finalize(&mut psbt)?;
assert!(result.is_finalized());
```

## Contributing
Found a bug, have an issue or a feature request? Feel free to open an issue on GitHub. This library is open source licensed under MIT.

[miniscript]: https://github.com/bitcoin/bips/blob/master/bip-0379.md
[descriptors]: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
[BIP174]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
[BIP370]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
[BIP371]: https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki
