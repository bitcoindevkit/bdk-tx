use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use miniscript::bitcoin;
use miniscript::bitcoin::{absolute, transaction, Psbt, Sequence};
use miniscript::psbt::PsbtExt;
use rand_core::RngCore;

use crate::{apply_anti_fee_sniping, AntiFeeSnipingError, Finalizer, Input, Output};

/// Final selection of inputs and outputs.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Inputs in this selection.
    pub inputs: Vec<Input>,
    /// Outputs in this selection.
    pub outputs: Vec<Output>,
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

    /// Sighash type to be used for each input.
    ///
    /// This option only applies to [`Input`]s that include a plan, as otherwise the given PSBT
    /// input can be expected to set a specific sighash type. Defaults to `None` which will not
    /// set an explicit sighash type for any input. (In that case the sighash will typically
    /// cover all of the outputs).
    pub sighash_type: Option<bitcoin::psbt::PsbtSighashType>,

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
}

impl Default for PsbtParams {
    fn default() -> Self {
        Self {
            version: transaction::Version::TWO,
            min_locktime: absolute::LockTime::ZERO,
            mandate_full_tx_for_segwit_v0: true,
            sighash_type: None,
            anti_fee_sniping: None,
        }
    }
}

/// Occurs when creating a psbt fails.
#[derive(Debug)]
pub enum CreatePsbtError {
    /// Attempted to mix locktime types.
    LockTypeMismatch,
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
            CreatePsbtError::LockTypeMismatch => write!(f, "cannot mix locktime units"),
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
    /// Accumulates the maximum locktime from an iterator of input-required locktimes.
    ///
    /// Returns the `min_locktime` if the locktimes iterator is empty, `Ok(lock_time)` with
    /// the maximum locktime if all items share the same unit. Errors if there is a mismatch of
    /// lock type units among the required locktimes.
    fn accumulate_max_locktime(
        locktimes: impl IntoIterator<Item = absolute::LockTime>,
        min_locktime: absolute::LockTime,
    ) -> Result<absolute::LockTime, CreatePsbtError> {
        // Accumulate locktimes required by inputs. An input-vs-input unit mismatch is an error.
        // `min_locktime` is only used when it is compatible with the input requirements.
        // If it is a different unit from the required locktime it is intentionally ignored
        // so that a height-based `min_locktime` does not conflict with a time-based CLTV
        // requirement.
        let mut acc = Option::<absolute::LockTime>::None;
        for locktime in locktimes {
            match &mut acc {
                Some(acc) => {
                    if !acc.is_same_unit(locktime) {
                        return Err(CreatePsbtError::LockTypeMismatch);
                    }
                    if acc.is_implied_by(locktime) {
                        *acc = locktime;
                    }
                }
                acc => *acc = Some(locktime),
            };
        }
        match acc {
            // No required locktimes from inputs: use `min_locktime` directly.
            None => Ok(min_locktime),
            // Same unit as `min_locktime`: take the maximum of required and `min_locktime`.
            Some(lock_time) if lock_time.is_same_unit(min_locktime) => {
                if lock_time.is_implied_by(min_locktime) {
                    Ok(min_locktime)
                } else {
                    Ok(lock_time)
                }
            }
            // `min_locktime` is a different unit: use required locktime and ignore it.
            Some(lock_time) => Ok(lock_time),
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
            )?,
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

                psbt_input.sighash_type = params.sighash_type;

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
        secp256k1::Secp256k1,
        transaction::{self, Version},
        Amount, ScriptBuf, Transaction, TxIn, TxOut,
    };
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};
    use rand_core::OsRng;

    const TEST_DESCRIPTOR: &str = "tr([83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*)";
    const TEST_DESCRIPTOR_PK: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";

    fn setup_cltv_input(
        cltv: absolute::LockTime,
    ) -> anyhow::Result<(Input, Descriptor<DescriptorPublicKey>)> {
        let secp = Secp256k1::new();
        let pk = "032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3";
        let desc_str = format!("wsh(and_v(v:pk({pk}),after({cltv})))");
        let desc_pk: DescriptorPublicKey = pk.parse()?;
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

        let selection = Selection {
            inputs: vec![input],
            outputs: vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        };

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

        let selection = Selection {
            inputs: vec![input],
            outputs: vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        };

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
        let desc = Descriptor::parse_descriptor(&secp, TEST_DESCRIPTOR)
            .unwrap()
            .0;
        let def_desc = desc.at_derivation_index(0).unwrap();
        let script_pubkey = def_desc.script_pubkey();
        let desc_pk: DescriptorPublicKey = TEST_DESCRIPTOR_PK.parse()?;
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
        let selection = Selection {
            inputs: vec![input],
            outputs: vec![output],
        };

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
            let selection = Selection {
                inputs: vec![input.clone()],
                outputs: vec![output],
            };

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
            let selection = Selection {
                inputs: vec![input1.clone(), input2.clone(), input3.clone()],
                outputs: vec![output.clone()],
            };
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
}
