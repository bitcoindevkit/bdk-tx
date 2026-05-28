use alloc::boxed::Box;
use alloc::vec::Vec;
use bitcoin::{EcdsaSighashType, TapSighashType};
use core::cmp::Ordering;
use core::fmt::{Debug, Display};
use miniscript::bitcoin;
use miniscript::bitcoin::{absolute, transaction, OutPoint, Psbt, Sequence};
use miniscript::psbt::PsbtExt;
use rand_core::RngCore;

use crate::{
    apply_anti_fee_sniping, fisher_yates_shuffle, AntiFeeSnipingError, Finalizer, Input, InputMut,
    Output,
};

/// Final selection of inputs and outputs.
#[derive(Debug, Clone)]
#[must_use]
pub struct Selection {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

/// Parameters for creating a psbt.
#[derive(Debug, Clone)]
pub struct PsbtParams {
    /// Use a specific [`transaction::Version`].
    pub version: transaction::Version,

    /// Minimum tx locktime — a floor on the resulting `tx.lock_time`.
    ///
    /// The final `tx.lock_time` is the maximum of this value and any absolute locktime required by
    /// an input's CLTV, provided the locktime units agree. If `min_locktime` uses a different unit
    /// (block-height vs. time) than an input's CLTV, it is ignored — a height-based `min_locktime`
    /// will not be combined with a time-based CLTV (and vice versa).
    pub min_locktime: absolute::LockTime,

    /// Whether to require the full tx, aka [`non_witness_utxo`] for segwit v0 inputs.
    ///
    /// Default is `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,

    /// Apply BIP-326 anti-fee-sniping (AFS) protection, using the given block height.
    ///
    /// * `None` (default) — no AFS is applied.
    /// * `Some(tip_height)` — AFS is applied with `tip_height` as the current chain tip.
    ///
    /// AFS discourages miners from reorganizing recent blocks to capture fees by constraining the
    /// transaction to only be valid at or after the chain tip. When enabled,
    /// [`Selection::create_psbt`] sets either the transaction's `nLockTime` or the `nSequence` of
    /// one Taproot input to a value derived from `tip_height`.
    ///
    /// AFS only operates on a height-based `tx.lock_time`. If [`min_locktime`] or any input's
    /// CLTV is time-based, enabling AFS produces [`AntiFeeSnipingError::UnsupportedLockTime`].
    ///
    /// If `tx.lock_time` is already a block height greater than `tip_height` (e.g., because an
    /// input's CLTV pins the tx to a future block), AFS leaves the transaction unchanged — the
    /// existing CLTV already provides equivalent protection.
    ///
    /// # Errors
    ///
    /// When `Some(..)`, [`Selection::create_psbt`] returns [`CreatePsbtError::AntiFeeSniping`] if:
    /// - the transaction version is less than 2
    ///   ([`AntiFeeSnipingError::UnsupportedVersion`]) — v2 is required for relative locktimes; or
    /// - a time-based (MTP) locktime is in effect
    ///   ([`AntiFeeSnipingError::UnsupportedLockTime`]) — AFS only supports height-based locktimes.
    ///
    /// See [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki) for more details.
    ///
    /// [`min_locktime`]: Self::min_locktime
    pub anti_fee_sniping: Option<absolute::Height>,

    /// Whether to write `sighash_type` on every Plan-derived input (default: `true`).
    ///
    /// A safety auto-lock fires independent of this flag: any Plan that contains a 64B Schnorr
    /// signature in its witness template gets `TapSighashType::Default` written. The Plan's
    /// `satisfaction_weight` already budgeted 64B, so a 65B sig would silently under-fund the
    /// tx.
    ///
    /// For inputs not hit by the safety lock, this flag selects what to write:
    ///
    /// | Plan's Schnorr placeholders | `false`        | `true`                  |
    /// |-----------------------------|----------------|-------------------------|
    /// | All 65B                     | unset          | `TapSighashType::All`   |
    /// | None (ECDSA)                | unset          | `EcdsaSighashType::All` |
    ///
    /// `unset` leaves the choice to the signer (BIP-174 implicit `SIGHASH_ALL`); `true`
    /// declares the policy explicitly so finalizers enforce it.
    ///
    /// PSBT-derived inputs ([`Input::from_psbt_input`]) are never touched regardless of this
    /// flag.
    ///
    /// For non-`ALL` sighashes (`SINGLE`, `NONE`, `*_ANYONECANPAY`) on a Plan-derived input,
    /// set `psbt.inputs[i].sighash_type` directly on the returned PSBT. Plans needing non-`ALL`
    /// semantics on every key should be built with uniform
    /// `TaprootCanSign::sighash_default = false` so the safety auto-lock doesn't fire.
    ///
    /// [`Input::from_psbt_input`]: crate::Input::from_psbt_input
    pub declare_sighash: bool,
}

impl Default for PsbtParams {
    fn default() -> Self {
        Self {
            version: transaction::Version::TWO,
            min_locktime: absolute::LockTime::ZERO,
            mandate_full_tx_for_segwit_v0: true,
            anti_fee_sniping: None,
            declare_sighash: true,
        }
    }
}

/// Occurs when creating a psbt fails.
#[derive(Debug)]
pub enum CreatePsbtError {
    /// Missing tx for legacy input.
    MissingFullTxForLegacyInput(Box<Input>),
    /// Missing tx for segwit v0 input.
    MissingFullTxForSegwitV0Input(Box<Input>),
    /// Psbt error.
    Psbt(bitcoin::psbt::Error),
    /// Update psbt output with descriptor error.
    OutputUpdate(miniscript::psbt::OutputUpdateError),
    /// Occurs when applying anti-fee-sniping fails.
    AntiFeeSniping(AntiFeeSnipingError),
}

impl From<AntiFeeSnipingError> for CreatePsbtError {
    fn from(e: AntiFeeSnipingError) -> Self {
        Self::AntiFeeSniping(e)
    }
}

impl core::fmt::Display for CreatePsbtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CreatePsbtError::MissingFullTxForLegacyInput(input) => write!(
                f,
                "legacy input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            CreatePsbtError::MissingFullTxForSegwitV0Input(input) => write!(
                f,
                "segwit v0 input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            CreatePsbtError::Psbt(error) => Display::fmt(&error, f),
            CreatePsbtError::OutputUpdate(output_update_error) => {
                Display::fmt(&output_update_error, f)
            }
            CreatePsbtError::AntiFeeSniping(e) => Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreatePsbtError {}

impl Selection {
    pub(crate) fn new(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Self { inputs, outputs }
    }

    /// Inputs in this selection.
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Outputs in this selection.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Mutable handle to the input spending `outpoint`, if any.
    ///
    /// Returns [`None`] if no input in this selection spends `outpoint`. The returned
    /// [`InputMut`] only permits mutations that preserve the selection's coin-selection
    /// invariants — see [`InputMut`] for the available operations.
    pub fn input_mut(&mut self, outpoint: OutPoint) -> Option<InputMut<'_>> {
        self.inputs
            .iter_mut()
            .find(|input| input.prev_outpoint() == outpoint)
            .map(InputMut::new)
    }

    /// Iterator yielding a mutable handle to every input in this selection.
    ///
    /// Each yielded [`InputMut`] only permits mutations that preserve the selection's
    /// coin-selection invariants — see [`InputMut`] for the available operations.
    pub fn inputs_mut(&mut self) -> impl Iterator<Item = InputMut<'_>> {
        self.inputs.iter_mut().map(InputMut::new)
    }

    /// Reorder inputs in-place using `compare`.
    ///
    /// Uses a stable sort: inputs that compare equal retain their relative order.
    /// Typical use is BIP-69 lexicographic ordering by previous outpoint.
    pub fn sort_inputs_by<F>(&mut self, compare: F)
    where
        F: FnMut(&Input, &Input) -> Ordering,
    {
        self.inputs.sort_by(compare);
    }

    /// Randomly shuffle inputs in-place using `rng`.
    ///
    /// Useful for chain-analysis resistance when no deterministic ordering is required.
    pub fn shuffle_inputs<R: RngCore>(&mut self, rng: &mut R) {
        fisher_yates_shuffle(&mut self.inputs, rng);
    }

    /// Reorder outputs in-place using `compare`.
    ///
    /// Uses a stable sort: outputs that compare equal retain their relative order.
    /// Typical use is BIP-69 (ascending by amount, then by `script_pubkey`).
    pub fn sort_outputs_by<F>(&mut self, compare: F)
    where
        F: FnMut(&Output, &Output) -> Ordering,
    {
        self.outputs.sort_by(compare);
    }

    /// Randomly shuffle outputs in-place using `rng`.
    ///
    /// Useful for chain-analysis resistance — in particular, hiding which output
    /// is the change.
    pub fn shuffle_outputs<R: RngCore>(&mut self, rng: &mut R) {
        fisher_yates_shuffle(&mut self.outputs, rng);
    }

    /// Accumulates the maximum locktime from an iterator of input-required locktimes.
    ///
    /// Returns `min_locktime` if the locktimes iterator is empty, otherwise the maximum locktime
    /// across the inputs (with `min_locktime` only applied when compatible with the inputs' unit).
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `locktimes` contains values with different units (height vs.
    /// time). `Selector::new` rejects such candidates upstream, so this should never fire in
    /// practice.
    fn accumulate_max_locktime(
        locktimes: impl IntoIterator<Item = absolute::LockTime>,
        min_locktime: absolute::LockTime,
    ) -> absolute::LockTime {
        // Accumulate locktimes required by inputs. An input-vs-input unit mismatch is rejected
        // upstream by `Selector::new`. `min_locktime` is only used when it is compatible with
        // the input requirements; a different unit is intentionally ignored so that, e.g., a
        // height-based `min_locktime` does not conflict with a time-based CLTV requirement.
        let inputs_max = locktimes.into_iter().reduce(|a, b| {
            debug_assert!(
                a.is_same_unit(b),
                "Selector::new should reject mixed-unit candidates",
            );
            if a.is_implied_by(b) {
                b
            } else {
                a
            }
        });
        match inputs_max {
            Some(lt) if lt.is_implied_by(min_locktime) => min_locktime,
            Some(lt) => lt,
            None => min_locktime,
        }
    }

    /// Create PSBT.
    #[cfg(feature = "std")]
    pub fn create_psbt(&self, params: PsbtParams) -> Result<bitcoin::Psbt, CreatePsbtError> {
        self.create_psbt_with_rng(params, &mut rand::thread_rng())
    }

    /// Create PSBT with `rng`.
    pub fn create_psbt_with_rng(
        &self,
        params: PsbtParams,
        rng: &mut impl RngCore,
    ) -> Result<bitcoin::Psbt, CreatePsbtError> {
        let mut tx = bitcoin::Transaction {
            version: params.version,
            lock_time: Self::accumulate_max_locktime(
                self.inputs
                    .iter()
                    .filter_map(|input| input.absolute_timelock()),
                params.min_locktime,
            ),
            input: self
                .inputs
                .iter()
                .map(|input| bitcoin::TxIn {
                    previous_output: input.prev_outpoint(),
                    sequence: input.sequence().unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
                    ..Default::default()
                })
                .collect(),
            output: self.outputs.iter().map(|output| output.txout()).collect(),
        };

        if let Some(tip_height) = params.anti_fee_sniping {
            apply_anti_fee_sniping(&mut tx, &self.inputs, tip_height, rng)?;
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).map_err(CreatePsbtError::Psbt)?;

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
                // We are allowed to have full tx for segwit inputs. Might as well include it.
                // If the caller does not wish to include the full tx in Segwit V0 inputs, they should not
                // include it in `crate::Input`.
                psbt_input.non_witness_utxo = plan_input.prev_tx().cloned();
                if psbt_input.non_witness_utxo.is_none() {
                    if witness_version.is_none() {
                        return Err(CreatePsbtError::MissingFullTxForLegacyInput(Box::new(
                            plan_input.clone(),
                        )));
                    }
                    if params.mandate_full_tx_for_segwit_v0
                        && witness_version == Some(bitcoin::WitnessVersion::V0)
                    {
                        return Err(CreatePsbtError::MissingFullTxForSegwitV0Input(Box::new(
                            plan_input.clone(),
                        )));
                    }
                }

                // Safety auto-lock: any 64B Schnorr placeholder forces `Default`, independent
                // of `declare_sighash`. A 64B-budgeted Plan signed with a 65B sig would
                // silently under-fund the tx, and there is no caller scenario where that's
                // intended — so this fires even when declaration is opted out.
                use miniscript::miniscript::satisfy::Placeholder;
                let any_64b_schnorr = plan
                    .witness_template()
                    .iter()
                    .filter_map(|p| match p {
                        Placeholder::SchnorrSigPk(_, _, size)
                        | Placeholder::SchnorrSigPkHash(_, _, size) => Some(*size == 64),
                        _ => None,
                    })
                    .reduce(|a, b| a || b);
                psbt_input.sighash_type = match (any_64b_schnorr, params.declare_sighash) {
                    (Some(true), _) => Some(TapSighashType::Default.into()),
                    (Some(false), true) => Some(TapSighashType::All.into()),
                    (None, true) => Some(EcdsaSighashType::All.into()),
                    (_, false) => None,
                };

                continue;
            }
            unreachable!("input candidate must either have finalized psbt input or plan");
        }
        for (output_index, output) in self.outputs.iter().enumerate() {
            if let Some(desc) = output.descriptor() {
                psbt.update_output_with_descriptor(output_index, desc)
                    .map_err(CreatePsbtError::OutputUpdate)?;
            }
        }

        Ok(psbt)
    }

    /// Into psbt finalizer.
    pub fn into_finalizer(self) -> Finalizer {
        Finalizer::new(
            self.inputs
                .iter()
                .filter_map(|input| Some((input.prev_outpoint(), input.plan().cloned()?))),
        )
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::{self, LockTime, Time},
        relative,
        secp256k1::Secp256k1,
        transaction::{self, Version},
        Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    };
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};
    use rand_core::OsRng;

    const TEST_KEY_HEX: &str = "032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3";
    const TEST_KEY_TR: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";
    const TEST_KEY_TR_2: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/1/*";
    const TEST_KEY_TR_3: &str = "[44444444/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/2/*";
    const TEST_KEY_WPKH: &str = "[83737d5e/84h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";

    fn setup_cltv_input(
        cltv: absolute::LockTime,
    ) -> anyhow::Result<(Input, Descriptor<DescriptorPublicKey>)> {
        let secp = Secp256k1::new();
        let desc_str = format!("wsh(and_v(v:pk({TEST_KEY_HEX}),after({cltv})))");
        let desc_pk: DescriptorPublicKey = TEST_KEY_HEX.parse()?;
        let (desc, _) = Descriptor::parse_descriptor(&secp, &desc_str)?;
        let plan = desc
            .at_derivation_index(0)?
            .plan(&Assets::new().add(desc_pk).after(cltv))
            .unwrap();
        let prev_tx = Transaction {
            version: transaction::Version::TWO,
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

    #[test]
    fn test_min_locktime_height() -> anyhow::Result<()> {
        let abs_locktime = absolute::LockTime::from_consensus(100_000);

        let (input, desc) = setup_cltv_input(abs_locktime)?;

        let selection = Selection::new(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        struct TestCase {
            name: &'static str,
            psbt_params: PsbtParams,
            exp_locktime: u32,
        }

        let cases = vec![
            TestCase {
                name: "no min_locktime, use plan locktime",
                psbt_params: PsbtParams::default(),
                exp_locktime: 100_000,
            },
            TestCase {
                name: "larger min_locktime is used",
                psbt_params: PsbtParams {
                    min_locktime: absolute::LockTime::from_consensus(100_100),
                    ..Default::default()
                },
                exp_locktime: 100_100,
            },
            TestCase {
                name: "smaller min_locktime is ignored",
                psbt_params: PsbtParams {
                    min_locktime: absolute::LockTime::from_consensus(99_900),
                    ..Default::default()
                },
                exp_locktime: 100_000,
            },
        ];

        for test in cases {
            let psbt = selection.create_psbt(test.psbt_params)?;
            assert_eq!(
                psbt.unsigned_tx.lock_time.to_consensus_u32(),
                test.exp_locktime,
                "Test failed {}",
                test.name,
            );
        }

        Ok(())
    }

    /// Tests that a height-based `min_locktime` is ignored when the input
    /// requires a time-based (UNIX timestamp) CLTV, and that an explicit time-based
    /// `min_locktime` greater than the requirement is respected.
    #[test]
    fn test_min_locktime_respects_lock_type() -> anyhow::Result<()> {
        let time_locktime = absolute::LockTime::from_consensus(1_734_230_218);

        let (input, desc) = setup_cltv_input(time_locktime)?;

        let selection = Selection::new(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        // Default `min_locktime` is height 0 (block-height unit). It is incompatible with
        // the time-based CLTV requirement, so it must be ignored.
        let psbt = selection.create_psbt(PsbtParams::default())?;
        assert_eq!(
            psbt.unsigned_tx.lock_time, time_locktime,
            "time-based CLTV requirement should be used; height-based `min_locktime` must be ignored",
        );

        // An explicit time-based `min_locktime` *greater* than the requirement should be respected.
        let larger_time = absolute::LockTime::from_consensus(1_772_167_108);
        assert!(larger_time > time_locktime);
        let psbt = selection.create_psbt(PsbtParams {
            min_locktime: larger_time,
            ..Default::default()
        })?;
        assert_eq!(
            psbt.unsigned_tx.lock_time, larger_time,
            "a larger time-based `min_locktime` should override the CLTV requirement",
        );

        Ok(())
    }

    pub fn setup_test_input(confirmation_height: u32) -> anyhow::Result<Input> {
        let secp = Secp256k1::new();
        let desc = Descriptor::parse_descriptor(&secp, &format!("tr({TEST_KEY_TR})"))
            .unwrap()
            .0;
        let def_desc = desc.at_derivation_index(0).unwrap();
        let script_pubkey = def_desc.script_pubkey();
        let desc_pk: DescriptorPublicKey = TEST_KEY_TR.parse()?;
        let assets = Assets::new().add(desc_pk);
        let plan = def_desc.plan(&assets).expect("failed to create plan");

        let prev_tx = Transaction {
            version: transaction::Version::TWO,
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

        let input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;

        Ok(input)
    }

    #[test]
    fn test_anti_fee_sniping_disabled() -> anyhow::Result<()> {
        let current_height = 2_500;
        let input = setup_test_input(2_000).unwrap();
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        // Disabled - default behavior is disable
        let psbt = selection.create_psbt(PsbtParams {
            min_locktime: absolute::LockTime::from_consensus(current_height),
            ..Default::default()
        })?;
        let tx = psbt.unsigned_tx;
        assert_eq!(tx.lock_time.to_consensus_u32(), current_height);

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
            let selection = Selection::new(vec![input.clone()], vec![output]);

            let psbt = selection.create_psbt(PsbtParams {
                anti_fee_sniping: Some(tip),
                ..Default::default()
            })?;

            let tx = psbt.unsigned_tx;

            if tx.lock_time > absolute::LockTime::ZERO {
                used_locktime = true;
                let locktime_value = tx.lock_time.to_consensus_u32();
                let min_height = current_height.saturating_sub(100);
                assert!((min_height..=current_height).contains(&locktime_value));
                assert!(locktime_value <= current_height);
                assert!(locktime_value >= current_height.saturating_sub(100));
            } else {
                used_sequence = true;
                let sequence_value = tx.input[0].sequence.to_consensus_u32();
                let confirmations =
                    input.confirmations(absolute::Height::from_consensus(current_height).unwrap());

                let min_sequence = confirmations.saturating_sub(100);
                assert!((min_sequence..=confirmations).contains(&sequence_value));
                assert!(sequence_value >= 1, "Sequence must be at least 1");
                assert!(sequence_value <= confirmations);
                assert!(sequence_value >= confirmations.saturating_sub(100));
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
            let selection = Selection::new(
                vec![input1.clone(), input2.clone(), input3.clone()],
                vec![output.clone()],
            );
            let psbt = selection
                .create_psbt(PsbtParams {
                    anti_fee_sniping: Some(tip),
                    ..Default::default()
                })
                .unwrap();

            let tx = psbt.unsigned_tx;

            if tx.lock_time > absolute::LockTime::ZERO {
                used_locktime = true;
            } else {
                used_sequence = true;
                // One of the inputs should have modified sequence
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

    /// Regression: pre-fix, the AFS nLockTime path could overwrite `tx.lock_time` with a value
    /// lower than an input's required CLTV.
    #[test]
    fn test_anti_fee_sniping_preserves_input_cltv() -> anyhow::Result<()> {
        let cltv = absolute::LockTime::from_consensus(100_000);
        let (input, desc) = setup_cltv_input(cltv)?;
        // Tip is well below the input's CLTV requirement.
        let tip = absolute::Height::from_consensus(50_000)?;

        let selection = Selection::new(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        // The input is wsh (not Taproot), so AFS deterministically takes the locktime path; loop a
        // few times anyway as cheap insurance against future control-flow changes.
        for _ in 0..100 {
            let psbt = selection.create_psbt(PsbtParams {
                anti_fee_sniping: Some(tip),
                ..Default::default()
            })?;
            assert_eq!(
                psbt.unsigned_tx.lock_time, cltv,
                "AFS must not overwrite an input's CLTV with a lower value",
            );
        }

        Ok(())
    }

    /// Regression: pre-fix, the AFS nSequence path could pick a Taproot input that already carried
    /// a CSV (relative-timelock) requirement and overwrite its sequence. The presence of a regular
    /// Taproot input ensures the sequence path remains reachable — so the test also catches a
    /// regression where AFS degrades to "never use the sequence path."
    #[test]
    fn test_anti_fee_sniping_skips_taproot_csv_input() -> anyhow::Result<()> {
        let tip = absolute::Height::from_consensus(3_000)?;
        let csv_blocks = 10;

        // Input A: regular Taproot, no CSV.
        let regular_input = setup_test_input(2_500)?;
        let regular_outpoint = regular_input.prev_outpoint();

        // Input B: Taproot whose script-path requires CSV. The internal key is omitted from
        // `assets`, forcing planning to use the script-path leaf (which sets
        // `plan.relative_timelock`).
        let secp = Secp256k1::new();
        let desc_str = format!("tr({TEST_KEY_HEX},and_v(v:pk({TEST_KEY_TR}),older({csv_blocks})))");
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
            .add(TEST_KEY_TR.parse::<DescriptorPublicKey>()?)
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

        // We will run AFS for 100 rounds.
        // Track whether AFS's nSequence path actually fired for at least one of the rounds.
        let mut observed_sequence_path = false;

        for _ in 0..100 {
            let selection = Selection::new(
                vec![regular_input.clone(), csv_input.clone()],
                vec![output.clone()],
            );
            let psbt = selection.create_psbt(PsbtParams {
                anti_fee_sniping: Some(tip),
                ..Default::default()
            })?;
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
            if regular_txin.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME {
                observed_sequence_path = true;
            }
        }

        assert!(
            observed_sequence_path,
            "AFS nSequence path must fire at least once across the 100 trials (otherwise the \
            CSV-preservation check above doesn't exercise the candidate-pool exclusion)",
        );

        Ok(())
    }

    /// A time-based CLTV propagates to `tx.lock_time`; AFS only supports height-based locktimes, so
    /// it must surface `UnsupportedLockTime`.
    #[test]
    fn test_anti_fee_sniping_rejects_time_based_locktime() -> anyhow::Result<()> {
        let time_locktime = absolute::LockTime::from_consensus(1_734_230_218);
        let (input, desc) = setup_cltv_input(time_locktime)?;
        let tip = absolute::Height::from_consensus(800_000)?;

        let selection = Selection::new(
            vec![input],
            vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        );

        let result = selection.create_psbt(PsbtParams {
            anti_fee_sniping: Some(tip),
            ..Default::default()
        });

        assert!(matches!(
            result,
            Err(CreatePsbtError::AntiFeeSniping(AntiFeeSnipingError::UnsupportedLockTime(lt)))
                if lt == time_locktime
        ));

        Ok(())
    }

    #[test]
    fn test_anti_fee_sniping_unsupported_version_error() {
        let confirmation_height = 800_000;
        let input = setup_test_input(confirmation_height).unwrap();
        let inputs = vec![input];
        let current_height = absolute::Height::from_consensus(confirmation_height + 50).unwrap();

        let mut tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::from_height(current_height.to_consensus_u32()).unwrap(),
            input: vec![TxIn {
                previous_output: inputs[0].prev_outpoint(),
                ..Default::default()
            }],
            output: vec![],
        };

        let result = apply_anti_fee_sniping(&mut tx, &inputs, current_height, &mut OsRng);

        assert!(
            matches!(result, Err(AntiFeeSnipingError::UnsupportedVersion(_))),
            "should return UnsupportedVersion error for version < 2"
        );
    }

    #[test]
    fn test_fisher_yates_shuffle_preserves_multiset() {
        let original: Vec<u32> = (0..32).collect();
        let mut shuffled = original.clone();
        fisher_yates_shuffle(&mut shuffled, &mut OsRng);
        shuffled.sort();
        assert_eq!(shuffled, original);
    }

    fn input_with_assets(desc_str: &str, assets: Assets) -> anyhow::Result<Input> {
        let secp = Secp256k1::new();
        let (desc, _) = Descriptor::parse_descriptor(&secp, desc_str)?;
        let def_desc = desc.at_derivation_index(0)?;
        let script_pubkey = def_desc.script_pubkey();
        let plan = def_desc.plan(&assets).expect("plan");
        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey,
                value: Amount::from_sat(100_000),
            }],
        };
        Ok(Input::from_prev_tx(plan, prev_tx, 0, None)?)
    }

    fn non_default_taproot_assets(key: &DescriptorPublicKey) -> Assets {
        use miniscript::plan::{CanSign, TaprootCanSign};
        let mut assets = Assets::default();
        for deriv_path in key.full_derivation_paths() {
            let can_sign = CanSign {
                ecdsa: true,
                taproot: TaprootCanSign {
                    sighash_default: false,
                    ..TaprootCanSign::default()
                },
            };
            assets
                .keys
                .insert(((key.master_fingerprint(), deriv_path), can_sign));
        }
        assets
    }

    fn run_sighash_case(input: Input, params: PsbtParams) -> anyhow::Result<bitcoin::Psbt> {
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);
        Ok(selection.create_psbt(params)?)
    }

    /// `create_psbt` writes the correct `sighash_type` on Plan-derived inputs across every
    /// (witness-template, `declare_sighash`) combination:
    ///
    /// - 64B Schnorr Plan → `Default` (safety lock, regardless of `declare_sighash`).
    /// - 65B Schnorr Plan → `All` if `declare_sighash`, else unset.
    /// - Mixed 64B+65B Schnorr Plan → `Default` (safety lock fires on *any* 64B placeholder).
    /// - ECDSA Plan → `EcdsaSighashType::All` if `declare_sighash`, else unset.
    #[test]
    fn test_sighash_policy() -> anyhow::Result<()> {
        use miniscript::plan::{CanSign, TaprootCanSign};

        let tr_key: DescriptorPublicKey = TEST_KEY_TR.parse()?;
        let wpkh_key: DescriptorPublicKey = TEST_KEY_WPKH.parse()?;

        // Mixed-Assets Plan: one key budgeted 64B, one key budgeted 65B. Pins the "any 64B"
        // (not "uniformly 64B") predicate for the safety auto-lock.
        let mixed_assets = {
            let key_default: DescriptorPublicKey = TEST_KEY_TR_2.parse()?;
            let key_non_default: DescriptorPublicKey = TEST_KEY_TR_3.parse()?;
            let mut assets = Assets::default();
            for deriv_path in key_default.full_derivation_paths() {
                assets.keys.insert((
                    (key_default.master_fingerprint(), deriv_path),
                    CanSign::default(),
                ));
            }
            for deriv_path in key_non_default.full_derivation_paths() {
                assets.keys.insert((
                    (key_non_default.master_fingerprint(), deriv_path),
                    CanSign {
                        ecdsa: true,
                        taproot: TaprootCanSign {
                            sighash_default: false,
                            ..TaprootCanSign::default()
                        },
                    },
                ));
            }
            assets
        };

        type Expected = Option<bitcoin::psbt::PsbtSighashType>;
        let cases: Vec<(&str, Input, bool, Expected)> = vec![
            (
                "64B Tap, declare=true",
                input_with_assets(
                    &format!("tr({TEST_KEY_TR})"),
                    Assets::new().add(tr_key.clone()),
                )?,
                true,
                Some(TapSighashType::Default.into()),
            ),
            (
                "64B Tap, declare=false (safety lock fires)",
                input_with_assets(
                    &format!("tr({TEST_KEY_TR})"),
                    Assets::new().add(tr_key.clone()),
                )?,
                false,
                Some(TapSighashType::Default.into()),
            ),
            (
                "65B Tap, declare=true",
                input_with_assets(
                    &format!("tr({TEST_KEY_TR})"),
                    non_default_taproot_assets(&tr_key),
                )?,
                true,
                Some(TapSighashType::All.into()),
            ),
            (
                "65B Tap, declare=false",
                input_with_assets(
                    &format!("tr({TEST_KEY_TR})"),
                    non_default_taproot_assets(&tr_key),
                )?,
                false,
                None,
            ),
            (
                "ECDSA, declare=true",
                input_with_assets(
                    &format!("wpkh({TEST_KEY_WPKH})"),
                    Assets::new().add(wpkh_key.clone()),
                )?,
                true,
                Some(EcdsaSighashType::All.into()),
            ),
            (
                "ECDSA, declare=false",
                input_with_assets(
                    &format!("wpkh({TEST_KEY_WPKH})"),
                    Assets::new().add(wpkh_key),
                )?,
                false,
                None,
            ),
            (
                "Mixed Tap (64B + 65B)",
                input_with_assets(
                    &format!("tr({TEST_KEY_TR},multi_a(2,{TEST_KEY_TR_2},{TEST_KEY_TR_3}))"),
                    mixed_assets,
                )?,
                true,
                Some(TapSighashType::Default.into()),
            ),
        ];

        for (name, input, declare_sighash, expected) in cases {
            let psbt = run_sighash_case(
                input,
                PsbtParams {
                    declare_sighash,
                    ..Default::default()
                },
            )?;
            assert_eq!(psbt.inputs[0].sighash_type, expected, "{name}");
        }
        Ok(())
    }
}
