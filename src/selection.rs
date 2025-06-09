use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use bdk_coin_select::FeeRate;
use miniscript::bitcoin;
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction, OutPoint, Psbt, Sequence,
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

    /// Whether to use BIP326 anti-fee-sniping
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
    MissingFullTxForLegacyInput(OutPoint),
    /// Missing tx for segwit v0 input.
    MissingFullTxForSegwitV0Input(OutPoint),
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
            CreatePsbtError::MissingFullTxForLegacyInput(outpoint) => write!(
                f,
                "legacy input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                outpoint
            ),
            CreatePsbtError::MissingFullTxForSegwitV0Input(outpoint) => write!(
                f,
                "segwit v0 input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                outpoint
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
                        return Err(CreatePsbtError::MissingFullTxForLegacyInput(
                            plan_input.prev_outpoint(),
                        ));
                    }
                    if params.mandate_full_tx_for_segwit_v0
                        && witness_version == Some(bitcoin::WitnessVersion::V0)
                    {
                        return Err(CreatePsbtError::MissingFullTxForSegwitV0Input(
                            plan_input.prev_outpoint(),
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

#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::{
        absolute, secp256k1::Secp256k1, transaction, Amount, ScriptBuf, Transaction, TxIn, TxOut,
    };
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};

    #[test]
    fn test_enable_anti_fee_sniping() -> anyhow::Result<()> {
        let secp = Secp256k1::new();

        let s = "tr([83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*)";
        let desc = Descriptor::parse_descriptor(&secp, s).unwrap().0;
        let def_desc = desc.at_derivation_index(0).unwrap();
        let script_pubkey = def_desc.script_pubkey();
        let desc_pk: DescriptorPublicKey = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*".parse()?;
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

        // Assume the current height is 2500, and previous tx confirms at height 2000.
        let current_height = 2_500;
        let status = crate::TxStatus {
            height: absolute::Height::from_consensus(2_000)?,
            time: absolute::Time::from_consensus(500_000_000)?,
        };
        let input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection {
            inputs: vec![input.clone()],
            outputs: vec![output],
        };

        let psbt = selection.create_psbt(PsbtParams {
            fallback_locktime: absolute::LockTime::from_consensus(current_height),
            enable_anti_fee_sniping: true,
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        })?;

        let tx = psbt.unsigned_tx;

        if tx.lock_time > absolute::LockTime::ZERO {
            // Check locktime
            let min_height = current_height.saturating_sub(100);
            assert!((min_height..=current_height).contains(&tx.lock_time.to_consensus_u32()));
        } else {
            // Check sequence
            let confirmations =
                input.confirmations(absolute::Height::from_consensus(current_height)?);
            let min_sequence = confirmations.saturating_sub(100);
            let sequence_value = tx.input[0].sequence.to_consensus_u32();
            assert!((min_sequence..=confirmations).contains(&sequence_value));
        }

        Ok(())
    }
}
