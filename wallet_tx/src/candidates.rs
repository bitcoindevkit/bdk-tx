//! The resolved spendable candidate set (PSBT-building stage 1 output).

use bdk_tx::{Input, InputCandidates, RbfParams};
use bdk_wallet::LocalOutput;
use bitcoin::Txid;
use std::collections::HashSet;

use crate::ConflictingInput;

/// A resolved set of spendable input candidates (output of PSBT-building stage 1).
///
/// Produced by [`WalletTxExt::candidates_with`] from [`CandidateParams`]: every owned UTXO has been
/// planned against the wallet's descriptors and spendability filters applied. It owns its inputs
/// (no wallet borrow), so it can be held as a snapshot and used to build one or more PSBTs via
/// [`WalletTxExt::select`].
///
/// Add foreign (non-wallet) inputs with [`push_must_select`](Self::push_must_select) /
/// [`push_can_select`](Self::push_can_select), and apply your own post-resolution filters with
/// [`filter`](Self::filter) / [`regroup`](Self::regroup).
///
/// If the [`CandidateParams`] had a non-empty [`replace`](crate::CandidateParams::replace) list,
/// the set carries the [`RbfParams`] (replaced-tx fee statistics) forward so stage 2 applies the
/// correct fee floor, and exposes the wallet-owned outputs being stripped by the replacement via
/// [`replaced_unspent`](Self::replaced_unspent).
///
/// [`WalletTxExt::candidates_with`]: crate::WalletTxExt::candidates_with
/// [`WalletTxExt::select`]: crate::WalletTxExt::select
/// [`CandidateParams`]: crate::CandidateParams
/// [`CandidateParams::replace`]: crate::CandidateParams::replace
#[derive(Debug, Clone)]
pub struct CandidateSet {
    pub(crate) candidates: InputCandidates,
    pub(crate) rbf: Option<RbfParams>,
    /// Txids being replaced/evicted (direct conflicts + descendants). A pushed input may not spend
    /// an output of any of these.
    pub(crate) replaced: HashSet<Txid>,
    /// Wallet-owned UTXOs stripped from the canonical view by the replacement.
    pub(crate) replaced_unspent: Vec<LocalOutput>,
}

impl CandidateSet {
    /// Iterate over all resolved input candidates (both must-select and optional).
    pub fn inputs(&self) -> impl Iterator<Item = &Input> + '_ {
        self.candidates.inputs()
    }

    /// Whether the set contains no candidates at all.
    pub fn is_empty(&self) -> bool {
        self.candidates.inputs().next().is_none()
    }

    /// Whether this set is a Replace-By-Fee set (built from a non-empty
    /// [`CandidateParams::replace`](crate::CandidateParams::replace) list).
    pub fn is_rbf(&self) -> bool {
        self.rbf.is_some()
    }

    /// Wallet-owned UTXOs that the replacement strips out of the canonical view -- the outputs of
    /// the replaced (and descendant) txs that were unspent in the wallet's view before the replace.
    ///
    /// These are the still-live payments of the txs being replaced; a caller batching several txs
    /// into one replacement can use them to decide which payments to re-create. Empty for a
    /// non-Replace-By-Fee set.
    pub fn replaced_unspent(&self) -> &[LocalOutput] {
        &self.replaced_unspent
    }

    /// Add a foreign [`Input`] to the must-select group (always spent).
    ///
    /// Use this for a UTXO that did not originate from the wallet, supplied with a pre-built
    /// plan -- its validity (UTXO existence, satisfaction weight, ...) relies on the
    /// caller-supplied values, so only push inputs you trust.
    ///
    /// If the outpoint is already a candidate (must- or can-select), it is **upserted**: the
    /// existing entry is replaced with `input` and ends up in the must-select group (a can-select
    /// one is promoted).
    ///
    /// # Errors
    ///
    /// Returns [`ConflictingInput`] if the input spends an output of a transaction being replaced
    /// (RBF) -- it would be evicted with that transaction.
    pub fn push_must_select(mut self, input: Input) -> Result<Self, ConflictingInput> {
        self.ensure_not_replaced(&input)?;
        self.candidates = self.candidates.push_must_select(input);
        Ok(self)
    }

    /// Add a foreign [`Input`] as an optional (can-select) candidate.
    ///
    /// If the outpoint is already a candidate, it is **upserted** (replaced with `input`).
    /// Must-select takes precedence: an outpoint already in the must-select group stays there (its
    /// data replaced) rather than being demoted.
    ///
    /// # Errors
    ///
    /// Returns [`ConflictingInput`] if the input spends an output of a transaction being replaced
    /// (RBF) -- it would be evicted with that transaction.
    pub fn push_can_select(mut self, input: Input) -> Result<Self, ConflictingInput> {
        self.ensure_not_replaced(&input)?;
        self.candidates = self.candidates.push_can_select(input);
        Ok(self)
    }

    /// Reject an input that spends an output of a transaction in the replaced (RBF) set.
    fn ensure_not_replaced(&self, input: &Input) -> Result<(), ConflictingInput> {
        let op = input.prev_outpoint();
        if self.replaced.contains(&op.txid) {
            return Err(ConflictingInput { outpoint: op });
        }
        Ok(())
    }

    /// Keep only the optional candidates for which `policy` returns `true`.
    ///
    /// Forwards to [`bdk_tx::InputCandidates::filter`], which filters only the can-select group:
    /// must-select inputs (manually-selected and foreign-pushed) are **always retained**, whatever
    /// `policy` returns.
    pub fn filter<P>(mut self, policy: P) -> Self
    where
        P: FnMut(&Input) -> bool,
    {
        self.candidates = self.candidates.filter(policy);
        self
    }

    /// Regroup the candidates by the group key returned by `policy`.
    ///
    /// Forwards to [`bdk_tx::InputCandidates::regroup`].
    pub fn regroup<P, G>(mut self, policy: P) -> Self
    where
        P: FnMut(&Input) -> G,
        G: Ord + Clone,
    {
        self.candidates = self.candidates.regroup(policy);
        self
    }

    /// Consume into the underlying `bdk_tx` parts: the [`InputCandidates`] and, if this is a
    /// Replace-By-Fee set (see [`is_rbf`](Self::is_rbf)), the [`RbfParams`] carrying the
    /// replaced-tx fee floor.
    ///
    /// Pass both on to `bdk_tx` (e.g. via
    /// [`SelectionParams::replace`](bdk_tx::SelectionParams::replace)) to build a `TxTemplate`
    /// directly while still enforcing the RBF minimum fee.
    pub fn into_parts(self) -> (InputCandidates, Option<RbfParams>) {
        (self.candidates, self.rbf)
    }
}
