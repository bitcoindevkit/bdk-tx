//! Tx-shaping stage between coin selection and the final [`Psbt`] or [`Transaction`].
//!
//! A [`TxTemplate`] is obtained from [`Selector::try_finalize`] or
//! [`InputCandidates::into_tx_template`], then mutated (sort, shuffle, anti-fee-sniping,
//! set_version, set_locktime, set_fallback_sequence, per-input sequence overrides) before
//! being emitted as a PSBT or a [`Transaction`].
//!
//! [`Selector::try_finalize`]: crate::Selector::try_finalize
//! [`InputCandidates::into_tx_template`]: crate::InputCandidates::into_tx_template
//! [`Transaction`]: bitcoin::Transaction

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt::Display;

use miniscript::bitcoin;
use miniscript::bitcoin::{absolute, transaction, OutPoint, Psbt, Sequence, Transaction, TxIn};
use miniscript::psbt::PsbtExt;
use rand_core::RngCore;

use crate::{
    apply_anti_fee_sniping, fisher_yates_shuffle, AntiFeeSnipingError, Finalizer, Input, InputMut,
    Output,
};

/// Default `nSequence` for plan-based inputs that don't specify their own.
///
/// Matches Bitcoin Core's wallet default (`0xfffffffd`,
/// [`Sequence::ENABLE_RBF_NO_LOCKTIME`]).
pub const FALLBACK_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// Error returned by [`TxTemplate::set_version`].
#[derive(Debug, Clone, PartialEq)]
pub enum SetVersionError {
    /// A relative-timelock input requires `version >= 2` (BIP-68).
    RelativeTimelockRequiresV2 {
        /// The version the caller attempted to set.
        attempted: transaction::Version,
    },
}

impl Display for SetVersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RelativeTimelockRequiresV2 { attempted } => write!(
                f,
                "version {attempted} is invalid: an input has a relative timelock, which requires version >= 2 (BIP-68)",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SetVersionError {}

/// Error returned by [`TxTemplate::set_locktime`].
#[derive(Debug, Clone, PartialEq)]
pub enum SetLockTimeError {
    /// The provided lock_time is below an input's required CLTV.
    BelowInputCltv {
        /// CLTV required by an input.
        required: absolute::LockTime,
        /// LockTime the caller attempted to set.
        attempted: absolute::LockTime,
    },
    /// The provided lock_time uses a different unit (block-height vs. time) than an input's CLTV.
    UnitMismatch {
        /// CLTV required by an input.
        input: absolute::LockTime,
        /// LockTime the caller attempted to set.
        attempted: absolute::LockTime,
    },
}

impl Display for SetLockTimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BelowInputCltv {
                required,
                attempted,
            } => write!(
                f,
                "lock_time {attempted} is below an input's required CLTV {required}",
            ),
            Self::UnitMismatch { input, attempted } => write!(
                f,
                "lock_time {attempted} has a different unit than an input's CLTV {input}",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SetLockTimeError {}

/// A fully-resolved tx shape — the workspace between coin selection and the final [`Psbt`]
/// or [`Transaction`].
///
/// Typically obtained from [`Selector::try_finalize`] (or
/// [`InputCandidates::into_tx_template`]). Exposes the operations that *shape* the resulting
/// transaction: input/output ordering, anti-fee-sniping, version/locktime overrides, and
/// final emission to PSBT or [`Transaction`].
///
/// New templates start with `version = TWO`, `lock_time = max(input CLTVs)` (or `ZERO`), and
/// `fallback_sequence = ENABLE_RBF_NO_LOCKTIME`.
///
/// [`Selector::try_finalize`]: crate::Selector::try_finalize
/// [`InputCandidates::into_tx_template`]: crate::InputCandidates::into_tx_template
#[derive(Debug, Clone)]
#[must_use]
pub struct TxTemplate {
    version: transaction::Version,
    lock_time: absolute::LockTime,
    fallback_sequence: Sequence,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

/// Parameters for emitting a [`Psbt`] from a [`TxTemplate`].
///
/// Carries only PSBT-specific options. Transaction-shape decisions (version, locktime,
/// sequence, anti-fee-sniping, input/output ordering) all live on [`TxTemplate`].
#[derive(Debug, Clone)]
pub struct PsbtBuildParams {
    /// Whether to require the full tx (aka [`non_witness_utxo`]) for segwit v0 inputs.
    ///
    /// Default: `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,

    /// Sighash type for each input.
    ///
    /// Only applies to [`Input`]s that include a plan; PSBT-input-based inputs are expected to
    /// set their own sighash type. Defaults to `None` (no explicit sighash type, which
    /// typically covers all of the outputs).
    pub sighash_type: Option<bitcoin::psbt::PsbtSighashType>,
}

impl Default for PsbtBuildParams {
    fn default() -> Self {
        Self {
            mandate_full_tx_for_segwit_v0: true,
            sighash_type: None,
        }
    }
}

/// Error returned by [`TxTemplate::create_psbt`].
#[derive(Debug)]
pub enum BuildPsbtError {
    /// Missing tx for legacy input.
    MissingFullTxForLegacyInput(Box<Input>),
    /// Missing tx for segwit v0 input.
    MissingFullTxForSegwitV0Input(Box<Input>),
    /// Psbt error.
    Psbt(bitcoin::psbt::Error),
    /// Update psbt output with descriptor error.
    OutputUpdate(miniscript::psbt::OutputUpdateError),
}

impl Display for BuildPsbtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingFullTxForLegacyInput(input) => write!(
                f,
                "legacy input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            Self::MissingFullTxForSegwitV0Input(input) => write!(
                f,
                "segwit v0 input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            Self::Psbt(e) => Display::fmt(e, f),
            Self::OutputUpdate(e) => Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildPsbtError {}

impl TxTemplate {
    pub(crate) fn from_parts(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        let lock_time = max_input_cltv(&inputs).unwrap_or(absolute::LockTime::ZERO);
        Self {
            version: transaction::Version::TWO,
            lock_time,
            fallback_sequence: FALLBACK_SEQUENCE,
            inputs,
            outputs,
        }
    }

    /// Resolved transaction version.
    pub fn version(&self) -> transaction::Version {
        self.version
    }

    /// Override `tx.version`.
    ///
    /// Default is [`transaction::Version::TWO`]. Setting a different value is allowed only when
    /// no input has a relative timelock (BIP-68 requires v2 in that case).
    ///
    /// # Errors
    ///
    /// - [`SetVersionError::RelativeTimelockRequiresV2`] if `version < 2` and any input has a
    ///   relative timelock.
    pub fn set_version(mut self, version: transaction::Version) -> Result<Self, SetVersionError> {
        if version < transaction::Version::TWO
            && self.inputs.iter().any(|i| i.relative_timelock().is_some())
        {
            return Err(SetVersionError::RelativeTimelockRequiresV2 { attempted: version });
        }
        self.version = version;
        Ok(self)
    }

    /// Resolved transaction lock_time.
    pub fn lock_time(&self) -> absolute::LockTime {
        self.lock_time
    }

    /// Set the fallback `nSequence` used for inputs that don't specify their own.
    ///
    /// The fallback is applied lazily at materialization (in [`Self::to_unsigned_tx`] and
    /// [`Self::create_psbt`]); calling this method after other transformations does not
    /// retroactively change inputs whose sequence has already been set explicitly (e.g. by
    /// [`apply_anti_fee_sniping`](Self::apply_anti_fee_sniping)).
    pub fn set_fallback_sequence(mut self, sequence: Sequence) -> Self {
        self.fallback_sequence = sequence;
        self
    }

    /// Override `tx.lock_time`.
    ///
    /// Returns an error if `lock_time` would conflict with an input's required CLTV
    /// (either by being below the requirement, or by using a different unit).
    ///
    /// Setting `lock_time` to a non-zero value when *every* input has `nSequence::MAX`
    /// is *not* rejected, but per BIP-65 / Bitcoin's `IsFinalTx` rule the lock_time will
    /// then be ignored at validation time.
    ///
    /// # Errors
    ///
    /// - [`SetLockTimeError::BelowInputCltv`] if `lock_time < required` (same unit).
    /// - [`SetLockTimeError::UnitMismatch`] if `lock_time` is height-based and an input's
    ///   CLTV is time-based (or vice versa).
    pub fn set_locktime(mut self, lock_time: absolute::LockTime) -> Result<Self, SetLockTimeError> {
        for input in &self.inputs {
            let Some(required) = input.absolute_timelock() else {
                continue;
            };
            if !required.is_same_unit(lock_time) {
                return Err(SetLockTimeError::UnitMismatch {
                    input: required,
                    attempted: lock_time,
                });
            }
            if !required.is_implied_by(lock_time) {
                return Err(SetLockTimeError::BelowInputCltv {
                    required,
                    attempted: lock_time,
                });
            }
        }
        self.lock_time = lock_time;
        Ok(self)
    }

    /// Fallback `nSequence` applied to inputs that don't specify their own.
    pub fn fallback_sequence(&self) -> Sequence {
        self.fallback_sequence
    }

    /// Inputs in this template.
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Outputs in this template.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Mutable handle to the input spending `outpoint`, if any.
    ///
    /// Returns [`None`] if no input in this template spends `outpoint`. The returned
    /// [`InputMut`] only permits mutations that preserve the template's invariants — see
    /// [`InputMut`] for the available operations.
    pub fn input_mut(&mut self, outpoint: OutPoint) -> Option<InputMut<'_>> {
        self.inputs
            .iter_mut()
            .find(|input| input.prev_outpoint() == outpoint)
            .map(InputMut::new)
    }

    /// Iterator yielding a mutable handle to every input in this template.
    ///
    /// Each yielded [`InputMut`] only permits mutations that preserve the template's
    /// invariants — see [`InputMut`] for the available operations.
    pub fn inputs_mut(&mut self) -> impl Iterator<Item = InputMut<'_>> {
        self.inputs.iter_mut().map(InputMut::new)
    }

    /// Reorder inputs using `compare`. Uses a stable sort.
    ///
    /// Typical use is BIP-69 lexicographic ordering by previous outpoint.
    pub fn sort_inputs_by<F>(mut self, compare: F) -> Self
    where
        F: FnMut(&Input, &Input) -> Ordering,
    {
        self.inputs.sort_by(compare);
        self
    }

    /// Randomly shuffle inputs using `rng`.
    ///
    /// Useful for chain-analysis resistance when no deterministic ordering is required.
    pub fn shuffle_inputs<R: RngCore>(mut self, rng: &mut R) -> Self {
        fisher_yates_shuffle(&mut self.inputs, rng);
        self
    }

    /// Reorder outputs using `compare`. Uses a stable sort.
    ///
    /// Typical use is BIP-69 (ascending by amount, then by `script_pubkey`).
    pub fn sort_outputs_by<F>(mut self, compare: F) -> Self
    where
        F: FnMut(&Output, &Output) -> Ordering,
    {
        self.outputs.sort_by(compare);
        self
    }

    /// Randomly shuffle outputs using `rng`.
    ///
    /// Useful for chain-analysis resistance — in particular, hiding which output is the
    /// change.
    pub fn shuffle_outputs<R: RngCore>(mut self, rng: &mut R) -> Self {
        fisher_yates_shuffle(&mut self.outputs, rng);
        self
    }

    /// Materialize the unsigned `bitcoin::Transaction` represented by this template.
    ///
    /// Each input's `nSequence` is its own [`Input::sequence`] if set, otherwise
    /// [`fallback_sequence`](Self::fallback_sequence).
    pub fn to_unsigned_tx(&self) -> Transaction {
        Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self
                .inputs
                .iter()
                .map(|input| TxIn {
                    previous_output: input.prev_outpoint(),
                    sequence: input.sequence().unwrap_or(self.fallback_sequence),
                    ..Default::default()
                })
                .collect(),
            output: self.outputs.iter().map(Output::txout).collect(),
        }
    }

    /// Apply BIP-326 anti-fee-sniping (AFS) protection using `tip_height` as the chain tip.
    ///
    /// AFS discourages miners from reorganizing recent blocks to capture fees by constraining
    /// the transaction to only be valid at or after the chain tip. This sets either
    /// `tx.lock_time` (via [`set_locktime`](Self::set_locktime)) or the `nSequence` of one
    /// Taproot input (via [`Input::set_sequence`]).
    ///
    /// AFS only operates on a height-based `tx.lock_time`. If any input's CLTV is time-based,
    /// this returns [`AntiFeeSnipingError::UnsupportedLockTime`].
    ///
    /// If `tx.lock_time` is already a block height greater than `tip_height` (e.g., because an
    /// input's CLTV pins the tx to a future block), this leaves the template unchanged.
    ///
    /// See [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki).
    ///
    /// # Errors
    ///
    /// - [`AntiFeeSnipingError::UnsupportedVersion`] if `version < 2`.
    /// - [`AntiFeeSnipingError::UnsupportedLockTime`] if `lock_time` is time-based.
    pub fn apply_anti_fee_sniping<R: RngCore>(
        self,
        tip_height: absolute::Height,
        rng: &mut R,
    ) -> Result<Self, AntiFeeSnipingError> {
        apply_anti_fee_sniping(self, tip_height, rng)
    }

    /// Build the [`Psbt`] and its associated [`Finalizer`].
    #[cfg(feature = "std")]
    pub fn create_psbt(self, params: PsbtBuildParams) -> Result<(Psbt, Finalizer), BuildPsbtError> {
        self.create_psbt_with_rng(params, &mut rand::thread_rng())
    }

    /// Build the [`Psbt`] and its associated [`Finalizer`] with a custom `rng`.
    pub fn create_psbt_with_rng(
        self,
        params: PsbtBuildParams,
        _rng: &mut impl RngCore,
    ) -> Result<(Psbt, Finalizer), BuildPsbtError> {
        let tx = self.to_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).map_err(BuildPsbtError::Psbt)?;

        for (plan_input, psbt_input) in self.inputs.iter().zip(psbt.inputs.iter_mut()) {
            if let Some(finalized_psbt_input) = plan_input.psbt_input() {
                *psbt_input = finalized_psbt_input.clone();
                continue;
            }
            if let Some(plan) = plan_input.plan() {
                plan.update_psbt_input(psbt_input);

                let witness_version = plan.witness_version();
                if witness_version.is_some() {
                    psbt_input.witness_utxo = Some(plan_input.prev_txout().clone());
                }
                psbt_input.non_witness_utxo = plan_input.prev_tx().cloned();
                if psbt_input.non_witness_utxo.is_none() {
                    if witness_version.is_none() {
                        return Err(BuildPsbtError::MissingFullTxForLegacyInput(Box::new(
                            plan_input.clone(),
                        )));
                    }
                    if params.mandate_full_tx_for_segwit_v0
                        && witness_version == Some(bitcoin::WitnessVersion::V0)
                    {
                        return Err(BuildPsbtError::MissingFullTxForSegwitV0Input(Box::new(
                            plan_input.clone(),
                        )));
                    }
                }
                psbt_input.sighash_type = params.sighash_type;
                continue;
            }
            unreachable!("input candidate must either have finalized psbt input or plan");
        }

        for (output_index, output) in self.outputs.iter().enumerate() {
            if let Some(desc) = output.descriptor() {
                psbt.update_output_with_descriptor(output_index, desc)
                    .map_err(BuildPsbtError::OutputUpdate)?;
            }
        }

        let finalizer = Finalizer::new(self.inputs.into_iter().filter_map(|input| {
            let outpoint = input.prev_outpoint();
            let plan = input.plan().cloned()?;
            Some((outpoint, plan))
        }));

        Ok((psbt, finalizer))
    }
}

/// Maximum CLTV requirement across `inputs`, or `None` if no input has a CLTV.
///
/// # Panics
///
/// In debug builds, panics if inputs have CLTVs of different units (height vs. time).
/// `Selector::new` rejects such candidates upstream, so this should never fire in practice.
fn max_input_cltv(inputs: &[Input]) -> Option<absolute::LockTime> {
    inputs
        .iter()
        .filter_map(Input::absolute_timelock)
        .reduce(|a, b| {
            debug_assert!(
                a.is_same_unit(b),
                "Selector::new should reject mixed-unit candidates",
            );
            if a.is_implied_by(b) {
                b
            } else {
                a
            }
        })
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::{self, LockTime, Time},
        relative,
        secp256k1::Secp256k1,
        transaction::Version,
        Amount, ScriptBuf, Transaction, TxIn, TxOut,
    };
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};
    use rand::thread_rng;
    use rand_core::OsRng;

    const TEST_DESCRIPTOR: &str = "tr([83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*)";
    const TEST_DESCRIPTOR_PK: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";
    const TEST_HEX_PK: &str = "032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3";

    fn setup_cltv_input(
        cltv: absolute::LockTime,
    ) -> anyhow::Result<(Input, Descriptor<DescriptorPublicKey>)> {
        let secp = Secp256k1::new();
        let desc_str = format!("wsh(and_v(v:pk({TEST_HEX_PK}),after({cltv})))");
        let desc_pk: DescriptorPublicKey = TEST_HEX_PK.parse()?;
        let (desc, _) = Descriptor::parse_descriptor(&secp, &desc_str)?;
        let plan = desc
            .at_derivation_index(0)?
            .plan(&Assets::new().add(desc_pk).after(cltv))
            .unwrap();
        let prev_tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.at_derivation_index(0)?.script_pubkey(),
                value: Amount::ONE_BTC,
            }],
        };
        let input = Input::from_prev_tx(plan, prev_tx, 0, None)?;
        Ok((input, desc))
    }

    fn setup_test_input(confirmation_height: u32) -> anyhow::Result<Input> {
        let secp = Secp256k1::new();
        let desc = Descriptor::parse_descriptor(&secp, TEST_DESCRIPTOR)
            .unwrap()
            .0;
        let def_desc = desc.at_derivation_index(0).unwrap();
        let script_pubkey = def_desc.script_pubkey();
        let desc_pk: DescriptorPublicKey = TEST_DESCRIPTOR_PK.parse()?;
        let assets = Assets::new().add(desc_pk);
        let plan = def_desc.plan(&assets).expect("failed to create plan");

        let prev_tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey,
                value: Amount::from_sat(10_000),
            }],
        };

        let status = crate::ConfirmationStatus {
            height: absolute::Height::from_consensus(confirmation_height)?,
            prev_mtp: Some(Time::from_consensus(500_000_000)?),
        };

        Ok(Input::from_prev_tx(plan, prev_tx, 0, Some(status))?)
    }

    /// Construction takes lock_time from the input CLTV; `set_locktime` bumps it above.
    #[test]
    fn set_locktime_height_above_input_cltv() -> anyhow::Result<()> {
        let cltv = absolute::LockTime::from_consensus(100_000);
        let (input, desc) = setup_cltv_input(cltv)?;
        let selection = TxTemplate::from_parts(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        let template = selection.clone();
        assert_eq!(
            template.lock_time(),
            cltv,
            "construction takes lock_time from input CLTV"
        );

        let higher = absolute::LockTime::from_consensus(100_100);
        let bumped = selection.set_locktime(higher)?;
        assert_eq!(bumped.lock_time(), higher);

        Ok(())
    }

    /// `set_locktime` rejects values below an input's CLTV requirement.
    #[test]
    fn set_locktime_below_input_cltv_errors() -> anyhow::Result<()> {
        let cltv = absolute::LockTime::from_consensus(100_000);
        let (input, desc) = setup_cltv_input(cltv)?;
        let selection = TxTemplate::from_parts(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        let too_low = absolute::LockTime::from_consensus(99_999);
        let result = selection.set_locktime(too_low);

        assert!(matches!(
            result,
            Err(SetLockTimeError::BelowInputCltv { required, attempted })
                if required == cltv && attempted == too_low
        ));
        Ok(())
    }

    /// A time-based input CLTV propagates to the template's lock_time at construction.
    #[test]
    fn lock_time_takes_time_based_cltv_from_input() -> anyhow::Result<()> {
        let time_locktime = absolute::LockTime::from_consensus(1_734_230_218);
        let (input, desc) = setup_cltv_input(time_locktime)?;
        let selection = TxTemplate::from_parts(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        assert_eq!(selection.lock_time(), time_locktime);

        Ok(())
    }

    /// `set_locktime` errors when the supplied unit conflicts with an input's CLTV unit.
    #[test]
    fn set_locktime_unit_mismatch_errors() -> anyhow::Result<()> {
        let height_cltv = absolute::LockTime::from_consensus(100_000);
        let (input, desc) = setup_cltv_input(height_cltv)?;
        let selection = TxTemplate::from_parts(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        let time_attempt = absolute::LockTime::from_consensus(1_734_230_218);
        let result = selection.set_locktime(time_attempt);

        assert!(matches!(
            result,
            Err(SetLockTimeError::UnitMismatch { input, attempted })
                if input == height_cltv && attempted == time_attempt
        ));
        Ok(())
    }

    /// `set_locktime` propagates the chosen value through PSBT creation.
    #[test]
    fn set_locktime_propagates_to_psbt() -> anyhow::Result<()> {
        let current_height = 2_500;
        let input = setup_test_input(2_000)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = TxTemplate::from_parts(vec![input], vec![output]);

        let (psbt, _) = selection
            .set_locktime(absolute::LockTime::from_consensus(current_height))?
            .create_psbt(PsbtBuildParams::default())?;
        assert_eq!(
            psbt.unsigned_tx.lock_time.to_consensus_u32(),
            current_height
        );
        Ok(())
    }

    #[test]
    fn test_anti_fee_sniping_protection() -> anyhow::Result<()> {
        let current_height = 2_500;
        let tip = absolute::Height::from_consensus(current_height)?;
        let input = setup_test_input(2_000)?;

        let mut used_locktime = false;
        let mut used_sequence = false;
        let mut loops = 0;

        while !used_locktime || !used_sequence {
            let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
            let selection = TxTemplate::from_parts(vec![input.clone()], vec![output]);

            let (psbt, _) = selection
                .apply_anti_fee_sniping(tip, &mut thread_rng())?
                .create_psbt(PsbtBuildParams::default())?;

            let tx = psbt.unsigned_tx;

            if tx.lock_time > absolute::LockTime::ZERO {
                used_locktime = true;
                let locktime_value = tx.lock_time.to_consensus_u32();
                let min_height = current_height.saturating_sub(100);
                assert!((min_height..=current_height).contains(&locktime_value));
            } else {
                used_sequence = true;
                let sequence_value = tx.input[0].sequence.to_consensus_u32();
                let confirmations =
                    input.confirmations(absolute::Height::from_consensus(current_height).unwrap());
                let min_sequence = confirmations.saturating_sub(100);
                assert!((min_sequence..=confirmations).contains(&sequence_value));
                assert!(sequence_value >= 1, "Sequence must be at least 1");
            }

            loops += 1;
            assert!(loops < 20, "Failed to observe both behaviors");
        }
        Ok(())
    }

    #[test]
    fn test_anti_fee_sniping_multiple_taproot_inputs() {
        let current_height = 3_000;
        let tip = absolute::Height::from_consensus(current_height).unwrap();
        let input1 = setup_test_input(2_500).unwrap();
        let input2 = setup_test_input(2_700).unwrap();
        let input3 = setup_test_input(3_000).unwrap();
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(18_000));

        let mut used_locktime = false;
        let mut used_sequence = false;
        let mut loops = 0;

        while !used_locktime || !used_sequence {
            let selection = TxTemplate::from_parts(
                vec![input1.clone(), input2.clone(), input3.clone()],
                vec![output.clone()],
            );
            let (psbt, _) = selection
                .apply_anti_fee_sniping(tip, &mut thread_rng())
                .unwrap()
                .create_psbt(PsbtBuildParams::default())
                .unwrap();

            let tx = psbt.unsigned_tx;

            if tx.lock_time > absolute::LockTime::ZERO {
                used_locktime = true;
            } else {
                used_sequence = true;
                let has_modified_sequence = tx.input.iter().any(|txin| {
                    let seq = txin.sequence.to_consensus_u32();
                    seq > 0 && seq < 65_535
                });
                assert!(has_modified_sequence);
            }

            loops += 1;
            assert!(
                loops < 20,
                "Failed to observe both behaviors within reasonable attempts"
            );
        }
    }

    /// Regression: pre-fix, AFS's nLockTime path could overwrite `tx.lock_time` with a value
    /// lower than an input's required CLTV.
    #[test]
    fn test_anti_fee_sniping_preserves_input_cltv() -> anyhow::Result<()> {
        let cltv = absolute::LockTime::from_consensus(100_000);
        let (input, desc) = setup_cltv_input(cltv)?;
        let tip = absolute::Height::from_consensus(50_000)?;

        let selection = TxTemplate::from_parts(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        for _ in 0..100 {
            let (psbt, _) = selection
                .clone()
                .apply_anti_fee_sniping(tip, &mut thread_rng())?
                .create_psbt(PsbtBuildParams::default())?;
            assert_eq!(
                psbt.unsigned_tx.lock_time, cltv,
                "AFS must not overwrite an input's CLTV with a lower value",
            );
        }

        Ok(())
    }

    /// Regression: pre-fix, AFS's nSequence path could pick a Taproot input that already carried
    /// a CSV (relative-timelock) requirement and overwrite its sequence.
    #[test]
    fn test_anti_fee_sniping_skips_taproot_csv_input() -> anyhow::Result<()> {
        let tip = absolute::Height::from_consensus(3_000)?;
        let csv_blocks = 10;

        let regular_input = setup_test_input(2_500)?;
        let regular_outpoint = regular_input.prev_outpoint();

        let secp = Secp256k1::new();
        let desc_str =
            format!("tr({TEST_HEX_PK},and_v(v:pk({TEST_DESCRIPTOR_PK}),older({csv_blocks})))");
        let desc = Descriptor::parse_descriptor(&secp, &desc_str)?
            .0
            .at_derivation_index(0)?;
        let prev_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.script_pubkey(),
                value: Amount::from_sat(10_000),
            }],
        };
        let assets = Assets::new()
            .add(TEST_DESCRIPTOR_PK.parse::<DescriptorPublicKey>()?)
            .older(relative::LockTime::from_height(csv_blocks));
        let plan = desc.plan(&assets).expect("script-path plan with CSV");
        let status = crate::ConfirmationStatus {
            height: absolute::Height::from_consensus(2_500)?,
            prev_mtp: Some(Time::from_consensus(500_000_000)?),
        };
        let csv_input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;
        let csv_outpoint = csv_input.prev_outpoint();
        let csv_sequence = csv_input.sequence().expect("plan-derived sequence");

        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(18_000));

        let mut observed_sequence_path = false;

        for _ in 0..100 {
            let selection = TxTemplate::from_parts(
                vec![regular_input.clone(), csv_input.clone()],
                vec![output.clone()],
            );
            let (psbt, _) = selection
                .apply_anti_fee_sniping(tip, &mut thread_rng())?
                .create_psbt(PsbtBuildParams::default())?;
            let tx = psbt.unsigned_tx;

            let csv_txin = tx
                .input
                .iter()
                .find(|t| t.previous_output == csv_outpoint)
                .expect("csv input must be present");
            assert_eq!(
                csv_txin.sequence, csv_sequence,
                "AFS must not overwrite the sequence of a CSV-bearing Taproot input",
            );

            let regular_txin = tx
                .input
                .iter()
                .find(|t| t.previous_output == regular_outpoint)
                .expect("regular input must be present");
            if regular_txin.sequence != FALLBACK_SEQUENCE {
                observed_sequence_path = true;
            }
        }

        assert!(
            observed_sequence_path,
            "AFS nSequence path must fire at least once across the 100 trials",
        );

        Ok(())
    }

    /// A time-based CLTV propagates to `tx.lock_time`; AFS only supports height-based locktimes.
    #[test]
    fn test_anti_fee_sniping_rejects_time_based_locktime() -> anyhow::Result<()> {
        let time_locktime = absolute::LockTime::from_consensus(1_734_230_218);
        let (input, desc) = setup_cltv_input(time_locktime)?;
        let tip = absolute::Height::from_consensus(800_000)?;

        let selection = TxTemplate::from_parts(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        let result = selection.apply_anti_fee_sniping(tip, &mut thread_rng());

        assert!(matches!(
            result,
            Err(AntiFeeSnipingError::UnsupportedLockTime(lt)) if lt == time_locktime
        ));

        Ok(())
    }

    #[test]
    fn test_anti_fee_sniping_unsupported_version_error() -> anyhow::Result<()> {
        let confirmation_height = 800_000;
        let input = setup_test_input(confirmation_height)?;
        let current_height = absolute::Height::from_consensus(confirmation_height + 50)?;

        let selection = TxTemplate::from_parts(
            vec![input],
            vec![Output::with_script(
                ScriptBuf::new(),
                Amount::from_sat(9_000),
            )],
        );

        let result = selection
            .set_version(Version::ONE)?
            .apply_anti_fee_sniping(current_height, &mut OsRng);

        assert!(matches!(
            result,
            Err(AntiFeeSnipingError::UnsupportedVersion(_))
        ));

        Ok(())
    }

    /// `set_version` rejects v1 when any input has a relative timelock (BIP-68).
    #[test]
    fn set_version_below_two_with_relative_timelock_errors() -> anyhow::Result<()> {
        let csv_blocks = 10;
        let secp = Secp256k1::new();
        let desc_str =
            format!("tr({TEST_HEX_PK},and_v(v:pk({TEST_DESCRIPTOR_PK}),older({csv_blocks})))");
        let desc = Descriptor::parse_descriptor(&secp, &desc_str)?
            .0
            .at_derivation_index(0)?;
        let prev_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.script_pubkey(),
                value: Amount::from_sat(10_000),
            }],
        };
        let assets = Assets::new()
            .add(TEST_DESCRIPTOR_PK.parse::<DescriptorPublicKey>()?)
            .older(relative::LockTime::from_height(csv_blocks));
        let plan = desc.plan(&assets).expect("script-path plan with CSV");
        let status = crate::ConfirmationStatus {
            height: absolute::Height::from_consensus(2_500)?,
            prev_mtp: Some(Time::from_consensus(500_000_000)?),
        };
        let csv_input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;

        let selection = TxTemplate::from_parts(
            vec![csv_input],
            vec![Output::with_script(
                ScriptBuf::new(),
                Amount::from_sat(9_000),
            )],
        );

        assert_eq!(
            selection.version(),
            Version::TWO,
            "construction defaults to v2",
        );

        let result = selection.set_version(Version::ONE);
        assert!(matches!(
            result,
            Err(SetVersionError::RelativeTimelockRequiresV2 { attempted })
                if attempted == Version::ONE
        ));

        Ok(())
    }
}
