# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [0.2.0]

### Added

- Add `SelectorError::InsufficientAssets` variant [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- Add `SelectorError::LockTypeMismatch` variant [#72](https://github.com/bitcoindevkit/bdk-tx/pull/72)
- Add members `change_script`, `change_dust_relay_feerate`, `change_min_value`, `change_longterm_feerate` to `SelectorParams` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- Add trait `FeeRateExt` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- Add `is_block_timelocked` and `is_time_timelocked` methods for `Input` and `InputGroup` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- Add `anti_fee_sniping: Option<Height>` field to `PsbtParams` for BIP326 anti-fee-sniping protection [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5) [#65](https://github.com/bitcoindevkit/bdk-tx/pull/65)
- Add `AntiFeeSnipingError` enum with `UnsupportedLockTime` and `UnsupportedVersion` variants; `CreatePsbtError::AntiFeeSniping` wraps this type [#65](https://github.com/bitcoindevkit/bdk-tx/pull/65)
- Add `Selection::create_psbt_with_rng` method for custom RNG [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- Update signer impl for `XOnlyPublicKey` [#20](https://github.com/bitcoindevkit/bdk-tx/pull/20)
- Allow multiple change sources on `SelectorParams` via `ChangeScript` [#18](https://github.com/bitcoindevkit/bdk-tx/pull/18)
- Re-export `bdk_coin_select` crate
- Add `ChangeScript` enum for specifying change outputs via `Descriptor` (with optional `Assets`) or raw `Script` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- Add `SetSequenceError` enum for errors when calling `set_sequence` on an input [#66](https://github.com/bitcoindevkit/bdk-tx/pull/66)
- Add `InputMut` struct providing mutable access to an `Input`, exposing `set_sequence` [#72](https://github.com/bitcoindevkit/bdk-tx/pull/72)
- Add `Input::set_sequence` method [#66](https://github.com/bitcoindevkit/bdk-tx/pull/66)
- Add `Input::is_spendable` and `InputGroup::is_spendable` methods [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- Add `FromPsbtInputError::AbsoluteTimelockDisabled` variant [#66](https://github.com/bitcoindevkit/bdk-tx/pull/66)
- Add `Selection::input_mut` and `Selection::inputs_mut` for mutable input access [#72](https://github.com/bitcoindevkit/bdk-tx/pull/72)
- Add `Selection::inputs()` and `Selection::outputs()` accessor methods [#72](https://github.com/bitcoindevkit/bdk-tx/pull/72)
- Add `Selection::shuffle_inputs`, `shuffle_outputs`, `sort_inputs_by`, `sort_outputs_by` for ordering inputs and outputs [#72](https://github.com/bitcoindevkit/bdk-tx/pull/72)
- Add `RbfParams::descendant_fee` field [#50](https://github.com/bitcoindevkit/bdk-tx/pull/50)
- Add `Output::from((ScriptSource, Amount))` conversion impl [#18](https://github.com/bitcoindevkit/bdk-tx/pull/18)
- Add `PsbtParams::min_locktime` field [#65](https://github.com/bitcoindevkit/bdk-tx/pull/65)

### Changed

- ci: update CI actions and enable caching [#46](https://github.com/bitcoindevkit/bdk-tx/pull/46)
- ci: add code coverage workflow [#45](https://github.com/bitcoindevkit/bdk-tx/pull/45)
- `SelectorParams::new` is changed to accept `target_feerate`, `target_outputs`, and `change_script` as inputs [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- `SelectorParams` is no longer `Clone` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- `SelectorParams::to_cs_change_policy` now returns `Result<_, SelectorError>` instead of `Result<_, miniscript::Error>` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- `is_timelocked` is changed for `Input` and `InputGroup` to take `(tip_height: Height, tip_mtp: Option<Time>)` and return `Option<bool>` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `TxStatus` is renamed to `ConfirmationStatus`; its `time: Time` field is replaced by `prev_mtp: Option<Time>`, and `ConfirmationStatus::new` takes `prev_mtp: Option<u32>` instead of `time: u64` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `filter_unspendable_now` is renamed to `filter_unspendable` [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- `CreatePsbtError::MissingFullTxForLegacyInput` and `CreatePsbtError::MissingFullTxForSegwitV0Input` now wrap `Input` in `Box` [#5](https://github.com/bitcoindevkit/bdk-tx/pull/5)
- `PsbtParams::fallback_locktime` renamed to `min_locktime` [#65](https://github.com/bitcoindevkit/bdk-tx/pull/65)
- `Selection::inputs` and `Selection::outputs` changed from public fields to accessor methods [#72](https://github.com/bitcoindevkit/bdk-tx/pull/72)
- `ScriptSource::Descriptor` now wraps `DefiniteDescriptor` in `Box` [#11](https://github.com/bitcoindevkit/bdk-tx/pull/11)
- `CanonicalUnspents::try_get_foreign_unspent` and `try_get_foreign_unspents` now accept an `absolute_timelock: Option<LockTime>` parameter [#66](https://github.com/bitcoindevkit/bdk-tx/pull/66)
- `RbfParams::new` and `RbfSet::new` now require a `descendant_fee: Amount` parameter [#50](https://github.com/bitcoindevkit/bdk-tx/pull/50)
- `Selector::change_policy` renamed to `cs_change_policy` [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- docs: Improve documentation of `Finalizer` [#34](https://github.com/bitcoindevkit/bdk-tx/pull/34)
- chore: Bump MSRV to 1.85.0 [#23](https://github.com/bitcoindevkit/bdk-tx/pull/23)
- deps: Bump `miniscript` to 12.3.7
- deps: Bump `bdk_coin_select` to 0.4.1
- deps: Bump `bitcoin` to 0.32.10
- deps: Bump `bdk_bitcoind_rpc` to 0.22.0
- deps: Bump `bdk_chain` to 0.23.3

### Fixed

- fix: replace deprecated `FeeRate::from_sat_per_vb_unchecked` [#51](https://github.com/bitcoindevkit/bdk-tx/pull/51)
- fix(finalizer): set finalized to false on error and add full coverage [#44](https://github.com/bitcoindevkit/bdk-tx/pull/44)
- fix(selection): Improve handling of fallback locktime [#43](https://github.com/bitcoindevkit/bdk-tx/pull/43)
- Fix locktime calculations and improve API [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)
- fix: Include `fallback_locktime` in locktime accumulation [#24](https://github.com/bitcoindevkit/bdk-tx/pull/24)

### Removed

- Removed `change_descriptor` field from `SelectorParams` [#18](https://github.com/bitcoindevkit/bdk-tx/pull/18)
- Removed `ChangePolicyType` enum [#32](https://github.com/bitcoindevkit/bdk-tx/pull/32)
- Removed `PolicyFailure<PF>` enum and `MissingOutputs` struct [#53](https://github.com/bitcoindevkit/bdk-tx/pull/53)
- Removed `CreatePsbtError::LockTypeMismatch` variant [#72](https://github.com/bitcoindevkit/bdk-tx/pull/72)
- Removed `PsbtParams::fallback_sequence` field [#66](https://github.com/bitcoindevkit/bdk-tx/pull/66)
- Removed `SelectorParams::to_cs_change_weights` method [#39](https://github.com/bitcoindevkit/bdk-tx/pull/39)
- Removed `Input::is_spendable_now` (replaced by `Input::is_spendable`) [#36](https://github.com/bitcoindevkit/bdk-tx/pull/36)

## [0.1.0]

### Added

- The new "Tx builder" [#1](https://github.com/bitcoindevkit/bdk-tx/pull/1)

[unreleased]: https://github.com/bitcoindevkit/bdk-tx/compare/0.2.0...HEAD
[0.2.0]: https://github.com/bitcoindevkit/bdk-tx/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/bitcoindevkit/bdk-tx/releases/tag/0.1.0
