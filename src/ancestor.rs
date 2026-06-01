use core::fmt;

use miniscript::bitcoin::{OutPoint, Txid};

/// Intrinsic fee data for an unconfirmed ancestor transaction.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AncestorFee {
    pub(crate) weight: u64,
    pub(crate) fee_paid: u64,
}

/// Error computing the unconfirmed-ancestor package used for CPFP bump-fee calculation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AncestorFeeError {
    /// An unconfirmed ancestor transaction is absent from the canonical view.
    MissingTx(Txid),
    /// A previous output required to compute an ancestor's fee is absent from the canonical view.
    MissingPrevout(OutPoint),
}

impl fmt::Display for AncestorFeeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTx(txid) => {
                write!(f, "unconfirmed ancestor transaction not found: {txid}")
            }
            Self::MissingPrevout(op) => {
                write!(f, "previous output not found for ancestor fee: {op}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AncestorFeeError {}
