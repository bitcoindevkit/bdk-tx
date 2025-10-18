use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use bdk_coin_select::FeeRate;
use miniscript::bitcoin;
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction, Psbt, Sequence,
};

use miniscript::psbt::PsbtExt;

use crate::{apply_anti_fee_sniping, Finalizer, Input, Output};

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
    /// The locktime to use if no inputs specifies a required absolute locktime.
    ///
    /// It is best practive to set this to the latest block height to avoid fee sniping.
    pub fallback_locktime: absolute::LockTime,

    /// [`Sequence`] value to use by default if not provided by the input.
    pub fallback_sequence: Sequence,

    /// Whether to require the full tx, aka [`non_witness_utxo`] for segwit v0 inputs,
    /// default is `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,

    /// Whether to use BIP326 anti-fee-sniping protection.
    ///
    /// When enabled, the transaction's nLockTime or nSequence will be set to indicate
    /// the transaction should only be valid at or after the current block height.
    /// This discourages miners from reorganizing recent blocks to capture fees.
    ///
    /// # Assumptions
    /// - The current height is determined by the transaction's locktime (must be a block height)
    /// - Transaction version must be >= 2 to support relative locktimes
    ///
    /// # Effects on Transaction
    /// When enabled, this will modify the transaction in one of two ways:
    /// - **nLockTime approach**: Sets `tx.lock_time` to current height (possibly with random offset)
    /// - **nSequence approach**: Sets sequence on a randomly selected Taproot input to current
    ///   confirmation depth (possibly with random offset)
    ///
    /// The choice between approaches is randomized based on BIP326 probabilities, with
    /// certain conditions forcing nLockTime usage (unconfirmed inputs, non-Taproot inputs,
    /// RBF disabled, etc.).
    ///
    /// # Error Cases
    /// - Returns [`CreatePsbtError::InvalidLockTime`] if the locktime is not a block height
    /// - Returns [`CreatePsbtError::UnsupportedVersion`] if transaction version is less than 2
    ///
    /// # Default
    /// - Disabled by default (`false`).
    ///
    /// # Example
    /// ```
    /// use miniscript::bitcoin::absolute::{LockTime, Height};
    /// use bdk_tx::{PsbtParams, Selection, Output};
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let params = PsbtParams {
    ///         fallback_locktime: LockTime::from_height(800000).expect("valid height"),
    ///         enable_anti_fee_sniping: true,
    ///         ..PsbtParams::default()
    ///     };
    ///     let selection = Selection {
    ///         inputs: vec![], /* Inputs */
    ///         outputs: vec![], /* Outputs */
    ///     };
    ///     let psbt = selection.create_psbt(params)?;
    ///     // the resulting transaction will have anti-fee-sniping applied.
    ///     Ok(())
    /// }
    /// ```
    ///
    /// See [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki) for more details.
    pub enable_anti_fee_sniping: bool,
}

impl Default for PsbtParams {
    fn default() -> Self {
        Self {
            version: transaction::Version::TWO,
            fallback_locktime: absolute::LockTime::ZERO,
            fallback_sequence: FALLBACK_SEQUENCE,
            mandate_full_tx_for_segwit_v0: true,
            enable_anti_fee_sniping: false,
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
    /// Invalid locktime
    InvalidLockTime(absolute::LockTime),
    /// Unsupported version for anti fee snipping
    UnsupportedVersion(transaction::Version),
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
            CreatePsbtError::InvalidLockTime(locktime) => {
                write!(f, "The locktime - {}, is invalid", locktime)
            }
            CreatePsbtError::UnsupportedVersion(version) => {
                write!(f, "Unsupported version {}", version)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreatePsbtError {}

impl Selection {
    /// Returns none if there is a mismatch of units in `locktimes`.
    ///
    // TODO: As according to BIP-64... ?
    fn _accumulate_max_locktime(
        locktimes: impl IntoIterator<Item = absolute::LockTime>,
        fallback: absolute::LockTime,
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
        if acc.is_none() {
            acc = Some(fallback);
        }
        acc
    }

    /// Create psbt.
    pub fn create_psbt(&self, params: PsbtParams) -> Result<bitcoin::Psbt, CreatePsbtError> {
        let mut tx = bitcoin::Transaction {
            version: params.version,
            lock_time: Self::_accumulate_max_locktime(
                self.inputs
                    .iter()
                    .filter_map(|input| input.absolute_timelock()),
                params.fallback_locktime,
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
        };

        if params.enable_anti_fee_sniping {
            let rbf_enabled = tx.is_explicitly_rbf();
            let current_height = match tx.lock_time {
                LockTime::Blocks(height) => height,
                LockTime::Seconds(_) => {
                    return Err(CreatePsbtError::InvalidLockTime(tx.lock_time));
                }
            };

            apply_anti_fee_sniping(&mut tx, &self.inputs, current_height, rbf_enabled)?;
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
