# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]


## [0.2.0]

### Added

- `PsbtParams::enable_anti_fee_sniping` field for BIP326 anti-fee-sniping protection #5
- `CreatePsbtError::InvalidLockTime` and `CreatePsbtError::UnsupportedVersion` error variants #5
- `Selection::create_psbt_with_rng` method for custom RNG #5
- feat: Added `FeeStrategy` enum which defines the fee target as either a feerate or fee amount #32
- feat: Add member `PsbtParams::sighash_type` #25
- feat: Update signer impl for `XOnlyPublicKey` #20
- feat: Allow multiple change sources #18

### Changed

- `CreatePsbtError::MissingFullTxForLegacyInput` and `CreatePsbtError::MissingFullTxForSegwitV0Input` now wrap `Input` in `Box` #5
- doc: Improve documentation of `Finalizer` #34
- chore: Bump MSRV to 1.85.0 #23
- `SelectorParams::target_feerate` field is renamed to `fee_strategy`. #32
- `SelectorParams::change_policy` field is changed to have type `bdk_coin_select::ChangePolicy`. #32
- `SelectorParams::new` is changed to accept the `FeeStrategy` and `ChangePolicy` as inputs. #32
- deps: Bump `miniscript` to 12.3.5
- deps: Bump `bdk_coin_select` to 0.4.1

### Fixed

- fix: Include `fallback_locktime` in locktime accumulation #24

### Removed

- `SelectorParams::change_weight` field is removed now that the change weights are represented in the actual change policy. #32
- Removed `SelectorParams::to_cs_change_policy` as the conversion is no longer necessary. #32
- Removed `ChangePolicyType` enum to allow the user to construct the intended `ChangePolicy`. #32

## [0.1.0]

### Added

- The new "Tx builder" #1

[unreleased]: https://github.com/bitcoindevkit/bdk-tx/compare/0.2.0...HEAD
[0.2.0]: https://github.com/bitcoindevkit/bdk-tx/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/bitcoindevkit/bdk-tx/releases/tag/0.1.0
