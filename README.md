# `bdk_tx`

This is a transaction building library based on `rust-miniscript` that lets you build, update, and finalize PSBTs with minimal dependencies.

<!-- links to relevant literature -->
Because the project builds upon [miniscript] we support [descriptors] natively.

Refer to [BIP174], [BIP370], and [BIP371] to learn more about partially signed bitcoin transactions (PSBT).

**Note:**
The library is unstable and API changes should be expected. Check the [examples] directory for detailed usage examples.


## Contributing
Found a bug, have an issue or a feature request? Feel free to open an issue on GitHub.

[miniscript]: https://github.com/bitcoin/bips/blob/master/bip-0379.md
[descriptors]: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
[BIP174]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
[BIP370]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
[BIP371]: https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki
[examples]: ./examples

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
