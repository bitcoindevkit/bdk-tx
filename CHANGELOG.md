# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [0.2.0]

### Added

- Add `SelectorError::InsufficientAssets` variant [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- Add members `change_script`, `change_dust_relay_feerate`, `change_min_value`, `change_longterm_feerate` to `SelectorParams` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- feat: Add trait `FeeRateExt` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- Added methods `is_block_timelocked` and `is_time_timelocked` for `Input` and `InputGroup` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `enable_anti_fee_sniping` field is added to `PsbtParams` for BIP326 anti-fee-sniping protection [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- Added error variants `InvalidLockTime` and `UnsupportedVersion` to `CreatePsbtError` [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- Added `Selection::create_psbt_with_rng` method for custom RNG [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- Added optional `sighash_type` member field to `PsbtParams` [#25](https://github.com/bitcoindevkit/bdk-tx/pull/25)
- feat: Update signer impl for `XOnlyPublicKey` [#20](https://github.com/bitcoindevkit/bdk-tx/pull/20)
- feat(selector): allow multiple change sources on `SelectorParams` [#18](https://github.com/bitcoindevkit/bdk-tx/pull/18)

### Changed

- ci: update CI actions and enable caching [#46](https://github.com/bitcoindevkit/bdk-tx/pull/46)
- ci: add code coverage workflow [#45](https://github.com/bitcoindevkit/bdk-tx/pull/45)
- `SelectorParams::new` is changed to accept `target_feerate`, `target_outputs`, and `change_script` as inputs. [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- `SelectorParams` is no longer Clone [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- `is_timelocked` is changed for `Input` and `InputGroup` to take an optional `absolute::Time` and returns `Option<bool>` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `TxStatus` is renamed to `ConfirmationStatus` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `filter_unspendable_now` is renamed to `filter_unspendable` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `CreatePsbtError::MissingFullTxForLegacyInput` and `CreatePsbtError::MissingFullTxForSegwitV0Input` now wraps `Input` in `Box` [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- docs: Improve documentation of `Finalizer` [#34](https://github.com/bitcoindevkit/bdk-tx/pull/34)
- chore: Bump MSRV to 1.85.0 [#23](https://github.com/bitcoindevkit/bdk-tx/pull/23)
- deps: Bump `miniscript` to 12.3.6
- deps: Bump `bdk_coin_select` to 0.4.1

### Fixed

- fix: replace deprecated `FeeRate::from_sat_per_vb_unchecked` [#51](https://github.com/bitcoindevkit/bdk-tx/pull/51)
- fix(finalizer): set finalized to false on error and add full coverage [#44](https://github.com/bitcoindevkit/bdk-tx/pull/44)
- fix(selection): Improve handling of fallback locktime [#43](https://github.com/bitcoindevkit/bdk-tx/pull/43)
- Fix locktime calculations and improve API [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- fix: Include `fallback_locktime` in locktime accumulation [#24](https://github.com/bitcoindevkit/bdk-tx/pull/24)

### Removed

- Removed `change_descriptor` field from `SelectorParams` [#18](https://github.com/bitcoindevkit/bdk-tx/pull/18)
- Removed `ChangePolicyType` enum [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)

## [0.1.0]

### Added

- The new "Tx builder" [#1](https://github.com/bitcoindevkit/bdk-tx/pull/1)

[unreleased]: https://github.com/bitcoindevkit/bdk-tx/compare/0.2.0...HEAD
[0.2.0]: https://github.com/bitcoindevkit/bdk-tx/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/bitcoindevkit/bdk-tx/releases/tag/0.1.0
