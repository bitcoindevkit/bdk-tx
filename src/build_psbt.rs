//! Parameters and error type for [`TxTemplate::build_psbt`].
//!
//! The build logic itself lives as an inherent method on [`TxTemplate`]; only the standalone
//! parameter and error types are housed here to keep `tx_template.rs` focused on tx shaping.
//!
//! [`TxTemplate::build_psbt`]: crate::TxTemplate::build_psbt

use alloc::boxed::Box;
use core::fmt::Display;

use miniscript::bitcoin;

use crate::Input;

/// Parameters for emitting a [`Psbt`] from a [`TxTemplate`].
///
/// Carries only PSBT-specific options. Transaction-shape decisions (version, locktime,
/// sequence, anti-fee-sniping, input/output ordering) all live on [`TxTemplate`].
///
/// [`Psbt`]: bitcoin::Psbt
/// [`TxTemplate`]: crate::TxTemplate
#[derive(Debug, Clone)]
pub struct BuildPsbtParams {
    /// Whether to require the full tx (aka [`non_witness_utxo`]) for segwit v0 inputs.
    ///
    /// Default: `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,
}

impl Default for BuildPsbtParams {
    fn default() -> Self {
        Self {
            mandate_full_tx_for_segwit_v0: true,
        }
    }
}

/// Error returned by [`TxTemplate::build_psbt`].
///
/// [`TxTemplate::build_psbt`]: crate::TxTemplate::build_psbt
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
