# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [0.2.0]

### Added

- Added methods `is_block_timelocked` and `is_time_timelocked` for `Input` and `InputGroup` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `enable_anti_fee_sniping` field is added to `PsbtParams` for BIP326 anti-fee-sniping protection [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- Added error variants `InvalidLockTime` and `UnsupportedVersion` to `CreatePsbtError` [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- Added `Selection::create_psbt_with_rng` method for custom RNG [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- Added `FeeStrategy` enum which defines the fee target as either a feerate or fee amount [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)
- Added optional `sighash_type` member field to `PsbtParams` [#25](https://github.com/bitcoindevkit/bdk-tx/pull/25)
- feat: Update signer impl for `XOnlyPublicKey` [#20](https://github.com/bitcoindevkit/bdk-tx/pull/20)
- feat(selector): allow multiple change sources on `SelectorParams` [#18](https://github.com/bitcoindevkit/bdk-tx/pull/18)

### Changed

- `is_timelocked` is changed for `Input` and `InputGroup` to take an optional `absolute::Time` and returns `Option<bool>` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `TxStatus` is renamed to `ConfirmationStatus` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `filter_unspendable_now` is renamed to `filter_unspendable` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `CreatePsbtError::MissingFullTxForLegacyInput` and `CreatePsbtError::MissingFullTxForSegwitV0Input` now wraps `Input` in `Box` [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- docs: Improve documentation of `Finalizer` [#34](https://github.com/bitcoindevkit/bdk-tx/pull/34)
- chore: Bump MSRV to 1.85.0 [#23](https://github.com/bitcoindevkit/bdk-tx/pull/23)
- `SelectorParams::target_feerate` field is renamed to `fee_strategy`. [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)
- `SelectorParams::change_policy` field is changed to have type `bdk_coin_select::ChangePolicy`. [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)
- `SelectorParams::new` is changed to accept the `FeeStrategy` and `ChangePolicy` as inputs. [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)
- deps: Bump `miniscript` to 12.3.5
- deps: Bump `bdk_coin_select` to 0.4.1

### Fixed

- Fix locktime calculations and improve API [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- fix: Include `fallback_locktime` in locktime accumulation [#24](https://github.com/bitcoindevkit/bdk-tx/pull/24)

### Removed

- `SelectorParams::change_weight` field is removed now that the change weights are represented in the actual change policy. [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)
- Removed `SelectorParams::to_cs_change_policy` as the conversion is no longer necessary. [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)
- Removed `ChangePolicyType` enum to allow the user to construct the intended `ChangePolicy`. [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)

## [0.1.0]

### Added

- The new "Tx builder" [#1](https://github.com/bitcoindevkit/bdk-tx/pull/1)

[unreleased]: https://github.com/bitcoindevkit/bdk-tx/compare/0.2.0...HEAD
[0.2.0]: https://github.com/bitcoindevkit/bdk-tx/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/bitcoindevkit/bdk-tx/releases/tag/0.1.0
