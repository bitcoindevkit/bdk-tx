//! `bdk_tx`

#![warn(missing_docs)]
#![no_std]

extern crate alloc;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

mod finalizer;
mod input;
mod output;
mod signer;

use alloc::vec::Vec;

use bitcoin::{
    absolute,
    transaction::{self, Version},
    Psbt,
};
pub use finalizer::*;
pub use input::*;
pub use miniscript::bitcoin;
use miniscript::{psbt::PsbtExt, DefiniteDescriptorKey, Descriptor};
pub use output::*;
pub use signer::*;

pub(crate) mod collections {
    #![allow(unused)]

    #[cfg(feature = "std")]
    pub use std::collections::*;

    #[cfg(not(feature = "std"))]
    pub type HashMap<K, V> = alloc::collections::BTreeMap<K, V>;
    pub use alloc::collections::*;
}

/// Definite descriptor.
pub type DefiniteDescriptor = Descriptor<DefiniteDescriptorKey>;

/// Parameters for creating a psbt.
#[derive(Debug, Clone)]
pub struct PsbtParams {
    /// Inputs to fund the tx.
    ///
    /// It is up to the caller to not duplicate inputs, spend from 2 conflicting txs, spend from
    /// invalid inputs, etc.
    pub inputs: Vec<Input>,
    /// Outputs.
    pub outputs: Vec<Output>,

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

impl Default for PsbtParams {
    fn default() -> Self {
        Self {
            version: Version::TWO,
            inputs: Default::default(),
            outputs: Default::default(),
            fallback_locktime: absolute::LockTime::ZERO,
            mandate_full_tx_for_segwit_v0: true,
        }
    }
}

/// Occurs when creating a psbt fails.
#[derive(Debug)]
pub enum PsbtError {
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

impl core::fmt::Display for PsbtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PsbtError::LockTypeMismatch => write!(f, "cannot mix locktime units"),
            PsbtError::MissingFullTxForLegacyInput(input) => write!(
                f,
                "legacy input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            PsbtError::MissingFullTxForSegwitV0Input(input) => write!(
                f,
                "segwit v0 input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            PsbtError::Psbt(error) => error.fmt(f),
            PsbtError::OutputUpdate(output_update_error) => output_update_error.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PsbtError {}

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
pub fn create_psbt(params: PsbtParams) -> Result<(bitcoin::Psbt, Finalizer), PsbtError> {
    let mut psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
        version: params.version,
        lock_time: accumulate_max_locktime(
            params
                .inputs
                .iter()
                .filter_map(|input| input.plan().absolute_timelock),
            params.fallback_locktime,
        )
        .ok_or(PsbtError::LockTypeMismatch)?,
        input: params
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
        output: params.outputs.iter().map(|output| output.txout()).collect(),
    })
    .map_err(PsbtError::Psbt)?;

    for (plan_input, psbt_input) in params.inputs.iter().zip(psbt.inputs.iter_mut()) {
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
                return Err(PsbtError::MissingFullTxForLegacyInput(plan_input.clone()));
            }
            if params.mandate_full_tx_for_segwit_v0
                && witness_version == Some(bitcoin::WitnessVersion::V0)
            {
                return Err(PsbtError::MissingFullTxForSegwitV0Input(plan_input.clone()));
            }
        }
    }
    for (output_index, output) in params.outputs.iter().enumerate() {
        if let Some(desc) = output.descriptor() {
            psbt.update_output_with_descriptor(output_index, desc)
                .map_err(PsbtError::OutputUpdate)?;
        }
    }

    let finalizer = Finalizer {
        plans: params
            .inputs
            .into_iter()
            .map(|input| (input.prev_outpoint(), input.plan().clone()))
            .collect(),
    };

    Ok((psbt, finalizer))
}
