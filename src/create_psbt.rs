use bitcoin::{absolute, transaction};
use miniscript::{bitcoin, psbt::PsbtExt};

use crate::{Finalizer, Input, Selection};

/// Parameters for creating a psbt.
#[derive(Debug, Clone)]
pub struct CreatePsbtParams {
    /// Inputs and outputs to fund the tx.
    pub selection: Selection,

    /// Use a specific [`transaction::Version`].
    pub version: transaction::Version,

    /// Fallback tx locktime.
    ///
    /// The locktime to use if no inputs specifies a required absolute locktime.
    ///
    /// It is best practive to set this to the latest block height to avoid fee sniping.
    pub fallback_locktime: absolute::LockTime,

    /// Recommended.
    pub mandate_full_tx_for_segwit_v0: bool,
}

impl CreatePsbtParams {
    /// With default values.
    pub fn new(selection: Selection) -> Self {
        Self {
            selection,
            version: transaction::Version::TWO,
            fallback_locktime: absolute::LockTime::ZERO,
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
            CreatePsbtError::Psbt(error) => error.fmt(f),
            CreatePsbtError::OutputUpdate(output_update_error) => output_update_error.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreatePsbtError {}

const FALLBACK_SEQUENCE: bitcoin::Sequence = bitcoin::Sequence::MAX;

/// Returns none if there is a mismatch of units in `locktimes`.
///
/// As according to BIP-64...
pub fn accumulate_max_locktime(
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
pub fn create_psbt(
    params: CreatePsbtParams,
) -> Result<(bitcoin::Psbt, Finalizer), CreatePsbtError> {
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(bitcoin::Transaction {
        version: params.version,
        lock_time: accumulate_max_locktime(
            params
                .selection
                .inputs
                .iter()
                .filter_map(|input| input.plan().absolute_timelock),
            params.fallback_locktime,
        )
        .ok_or(CreatePsbtError::LockTypeMismatch)?,
        input: params
            .selection
            .inputs
            .iter()
            .map(|input| bitcoin::TxIn {
                previous_output: input.prev_outpoint(),
                sequence: input
                    .plan()
                    .relative_timelock
                    .map_or(FALLBACK_SEQUENCE, |locktime| locktime.to_sequence()),
                ..Default::default()
            })
            .collect(),
        output: params
            .selection
            .outputs
            .iter()
            .map(|output| output.txout())
            .collect(),
    })
    .map_err(CreatePsbtError::Psbt)?;

    for (plan_input, psbt_input) in params.selection.inputs.iter().zip(psbt.inputs.iter_mut()) {
        let txout = plan_input.prev_txout();

        plan_input.plan().update_psbt_input(psbt_input);

        let witness_version = plan_input.plan().witness_version();
        if witness_version.is_some() {
            psbt_input.witness_utxo = Some(txout.clone());
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
    }
    for (output_index, output) in params.selection.outputs.iter().enumerate() {
        if let Some(desc) = output.descriptor() {
            psbt.update_output_with_descriptor(output_index, desc)
                .map_err(CreatePsbtError::OutputUpdate)?;
        }
    }

    let finalizer = Finalizer {
        plans: params
            .selection
            .inputs
            .into_iter()
            .map(|input| (input.prev_outpoint(), input.plan().clone()))
            .collect(),
    };

    Ok((psbt, finalizer))
}
