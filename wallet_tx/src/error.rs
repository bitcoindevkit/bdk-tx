//! Error types for the three PSBT-building stages.

use core::fmt;

use bdk_tx::bdk_coin_select;
use bitcoin::{bip32::Xpub, OutPoint, Txid};

/// Error when resolving the spendable [`CandidateSet`] (PSBT-building stage 1).
///
/// [`CandidateSet`]: crate::CandidateSet
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidatesError {
    /// A manually-selected outpoint the wallet can't spend: untracked, spent by a transaction that
    /// isn't being replaced, or (in an RBF) an output of a transaction being replaced -- which the
    /// replacement evicts.
    CannotSpend(OutPoint),
    /// Failed to create a spending plan for a manually selected output.
    Plan(OutPoint),
    /// A transaction being replaced (RBF) could not be found.
    MissingTransaction(Txid),
    /// The wallet controls none of the inputs of a transaction to be replaced (RBF), so it cannot
    /// build a replacement that conflicts with (and therefore evicts) it.
    CannotReplace(Txid),
    /// Failed to compute the fee of a transaction being replaced (RBF).
    PreviousFee(bdk_wallet::chain::tx_graph::CalculateFeeError),
}

impl fmt::Display for CandidatesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotSpend(op) => {
                write!(f, "cannot spend outpoint {op}: not a spendable wallet UTXO")
            }
            Self::Plan(op) => write!(f, "failed to create a plan for txout with outpoint {op}"),
            Self::MissingTransaction(txid) => write!(f, "missing transaction: {txid}"),
            Self::CannotReplace(txid) => write!(
                f,
                "cannot replace transaction {txid}: the wallet controls none of its inputs"
            ),
            Self::PreviousFee(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for CandidatesError {}

/// Error from [`CandidateSet::push_must_select`](crate::CandidateSet::push_must_select) /
/// [`push_can_select`](crate::CandidateSet::push_can_select): the pushed input spends an output of
/// a transaction in the replaced (RBF) set, which the replacement evicts -- so the input would be
/// invalid.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConflictingInput {
    /// The pushed input's outpoint, which spends an output of the replaced (RBF) set.
    pub outpoint: OutPoint,
}

impl fmt::Display for ConflictingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pushed input {} spends an output of a transaction being replaced",
            self.outpoint
        )
    }
}

impl core::error::Error for ConflictingInput {}

/// Error when running coin selection (PSBT-building stage 2,
/// [`select`](crate::WalletTxExt::select)).
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectError {
    /// No Bnb solution.
    Bnb(bdk_coin_select::NoBnbSolution),
    /// No recipients were configured with a non-sweep coin selection. A [`select`] requires at
    /// least one recipient; to send all funds to a single destination, use
    /// [`SelectionStrategy::SweepEffective`] / [`SweepAll`] with no recipients.
    ///
    /// [`select`]: crate::WalletTxExt::select
    /// [`SelectionStrategy::SweepEffective`]: crate::SelectionStrategy::SweepEffective
    /// [`SweepAll`]: crate::SelectionStrategy::SweepAll
    NoRecipients,
    /// The transaction would have no outputs: its sole change/drain output fell below the dust
    /// threshold and was dropped to fees. Arises from a no-recipient sweep whose remaining amount
    /// is dust after fees -- reachable cleanly via [`SweepEffective`]. (A [`SweepAll`] that also
    /// drags in *uneconomical* inputs -- ones costing more to spend than they're worth -- can
    /// instead surface as [`CannotMeetTarget`](Self::CannotMeetTarget).)
    ///
    /// [`SweepEffective`]: crate::SelectionStrategy::SweepEffective
    /// [`SweepAll`]: crate::SelectionStrategy::SweepAll
    ChangeBelowDust,
    /// The change policy could not be built from the selection params.
    ChangePolicy(bdk_tx::ChangePolicyError),
    /// The input candidates have absolute timelocks of mixed units (height vs time).
    LockTypeMismatch,
    /// Not enough funds: the target is unreachable even when selecting every effective input at the
    /// target feerate. This is the single "insufficient funds" error, covering an empty candidate
    /// set as the degenerate case.
    CannotMeetTarget {
        /// The shortfall in satoshis at best-case (all effective inputs selected).
        missing: u64,
    },
    /// The selection algorithm returned successfully but its selection still falls short.
    AlgorithmFellShort,
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bnb(e) => write!(f, "{e}"),
            Self::NoRecipients => write!(f, "no output destinations were configured"),
            Self::ChangeBelowDust => {
                write!(f, "the change output is below the dust threshold, leaving no outputs")
            }
            Self::ChangePolicy(e) => write!(f, "{e}"),
            Self::LockTypeMismatch => {
                write!(f, "input candidates have absolute timelocks of mixed units")
            }
            Self::CannotMeetTarget { missing } => write!(
                f,
                "meeting the target is not possible with the input candidates; {missing} sats missing"
            ),
            Self::AlgorithmFellShort => write!(
                f,
                "the selection algorithm returned successfully but did not meet the target"
            ),
        }
    }
}

impl core::error::Error for SelectError {}

/// Error from [`add_global_xpubs`](crate::WalletTxExt::add_global_xpubs): an extended key in a
/// descriptor is neither a master key (depth 0) nor carries an explicit origin, so its global-xpub
/// key source cannot be determined.
#[derive(Debug)]
#[non_exhaustive]
pub struct MissingKeyOrigin {
    /// The extended key whose global-xpub key source couldn't be determined.
    pub xpub: Xpub,
}

impl fmt::Display for MissingKeyOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing key origin for xpub: {}", self.xpub)
    }
}

impl core::error::Error for MissingKeyOrigin {}

/// Map an [`IntoTxTemplateError`](bdk_tx::IntoTxTemplateError) into a [`SelectError`], routing the
/// algorithm-specific error variant through `on_algorithm`.
pub(crate) fn map_into_tx_template_error<E>(
    err: bdk_tx::IntoTxTemplateError<E>,
    on_algorithm: impl FnOnce(E) -> SelectError,
) -> SelectError {
    use bdk_tx::IntoTxTemplateError as E2;
    match err {
        E2::ChangePolicy(e) => SelectError::ChangePolicy(e),
        E2::LockTypeMismatch => SelectError::LockTypeMismatch,
        E2::CannotMeetTarget { missing } => SelectError::CannotMeetTarget { missing },
        E2::Algorithm(e) => on_algorithm(e),
        E2::AlgorithmFellShort => SelectError::AlgorithmFellShort,
    }
}
