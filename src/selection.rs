use core::fmt::{Debug, Display};
use std::vec::Vec;

use bdk_coin_select::FeeRate;
use bitcoin::{absolute, transaction, Sequence};
use miniscript::bitcoin;
use miniscript::psbt::PsbtExt;

use crate::{Finalizer, Input, Output};

const FALLBACK_SEQUENCE: bitcoin::Sequence = bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF;

pub(crate) fn cs_feerate(feerate: bitcoin::FeeRate) -> bdk_coin_select::FeeRate {
    FeeRate::from_sat_per_wu(feerate.to_sat_per_kwu() as f32 / 1000.0)
}

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

    /// Fallback tx locktime.
    ///
    /// The locktime to use if no input specifies a required absolute locktime.
    ///
    /// It is best practice to set this to the latest block height to avoid fee sniping.
    pub fallback_locktime: absolute::LockTime,

    /// [`Sequence`] value to use by default if not provided by the input.
    pub fallback_sequence: Sequence,

    /// Whether to require the full tx, aka [`non_witness_utxo`] for segwit v0 inputs,
    /// default is `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,
}

impl Default for PsbtParams {
    fn default() -> Self {
        Self {
            version: transaction::Version::TWO,
            fallback_locktime: absolute::LockTime::ZERO,
            fallback_sequence: FALLBACK_SEQUENCE,
            mandate_full_tx_for_segwit_v0: true,
        }
    }
}

/// Occurs when creating a psbt fails.
#[derive(Debug)]
pub enum CreatePsbtError {
    /// Attempted to mix locktime types.
    LockTypeMismatch,
    /// Missing tx for legacy input.
    MissingFullTxForLegacyInput(Input),
    /// Missing tx for segwit v0 input.
    MissingFullTxForSegwitV0Input(Input),
    /// Psbt error.
    Psbt(bitcoin::psbt::Error),
    /// Update psbt output with descriptor error.
    OutputUpdate(miniscript::psbt::OutputUpdateError),
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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreatePsbtError {}

impl Selection {
    /// Returns none if there is a mismatch of units in `locktimes`.
    fn _accumulate_max_locktime(
        locktimes: impl IntoIterator<Item = absolute::LockTime>,
    ) -> Option<absolute::LockTime> {
        let mut acc = Option::<absolute::LockTime>::None;
        for locktime in locktimes {
            match &mut acc {
                Some(acc) => {
                    if !acc.is_same_unit(locktime) {
                        return None;
                    }
                    if acc.is_implied_by(locktime) {
                        *acc = locktime;
                    }
                }
                acc => *acc = Some(locktime),
            };
        }
        acc
    }

    /// Create psbt.
    pub fn create_psbt(&self, params: PsbtParams) -> Result<bitcoin::Psbt, CreatePsbtError> {
        let mut psbt = bitcoin::Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: params.version,
            lock_time: Self::_accumulate_max_locktime(
                self.inputs
                    .iter()
                    .filter_map(|input| input.absolute_timelock())
                    .chain([params.fallback_locktime]),
            )
            .ok_or(CreatePsbtError::LockTypeMismatch)?,
            input: self
                .inputs
                .iter()
                .map(|input| bitcoin::TxIn {
                    previous_output: input.prev_outpoint(),
                    sequence: input.sequence().unwrap_or(params.fallback_sequence),
                    ..Default::default()
                })
                .collect(),
            output: self.outputs.iter().map(|output| output.txout()).collect(),
        })
        .map_err(CreatePsbtError::Psbt)?;

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
                        return Err(CreatePsbtError::MissingFullTxForLegacyInput(
                            plan_input.clone(),
                        ));
                    }
                    if params.mandate_full_tx_for_segwit_v0
                        && witness_version == Some(bitcoin::WitnessVersion::V0)
                    {
                        return Err(CreatePsbtError::MissingFullTxForSegwitV0Input(
                            plan_input.clone(),
                        ));
                    }
                }
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
