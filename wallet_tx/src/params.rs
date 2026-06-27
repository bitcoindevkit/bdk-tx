//! Parameters for the three PSBT-building stages.
//!
//! 1. **Candidate construction** -- [`CandidateParams`] configures which coins may fund the
//!    transaction; [`WalletTxExt::candidates_with`] resolves them into a [`CandidateSet`]. A
//!    replacement (RBF) is a candidate set built from options whose [`replace`] list is non-empty
//!    (or via the [`WalletTxExt::rbf_candidates`] shortcut).
//! 2. **Selection** -- [`SelectParams`] describes the recipients, fee rate and coin-selection
//!    strategy; passed alongside a [`CandidateSet`] to [`WalletTxExt::select`], which runs coin
//!    selection and returns a [`bdk_tx::TxTemplate`]. To sweep, use no recipients with
//!    [`SelectionStrategy::SweepEffective`] (or [`SweepAll`](SelectionStrategy::SweepAll)).
//! 3. **Emission** -- the caller shapes the [`bdk_tx::TxTemplate`] (version, locktime, ordering,
//!    anti-fee-sniping) using its own methods, then emits the final [`Psbt`](bitcoin::Psbt)
//!    directly with [`bdk_tx::TxTemplate::build_psbt`] (optionally filling global xpubs from the
//!    wallet via [`WalletTxExt::add_global_xpubs`]).
//!
//! [`replace`]: CandidateParams::replace
//! [`CandidateSet`]: crate::CandidateSet
//! [`WalletTxExt::candidates_with`]: crate::WalletTxExt::candidates_with
//! [`WalletTxExt::rbf_candidates`]: crate::WalletTxExt::rbf_candidates
//! [`WalletTxExt::select`]: crate::WalletTxExt::select
//! [`WalletTxExt::add_global_xpubs`]: crate::WalletTxExt::add_global_xpubs

use bdk_tx::ChangeScript;
use bdk_wallet::chain::{BlockId, CanonicalizationParams};
use bitcoin::{absolute, Amount, FeeRate, OutPoint, ScriptBuf, Txid};
use miniscript::plan::Assets;
use std::collections::BTreeSet;

/// A function mapping a block to its median-time-past (MTP); see [`CandidateParams::fetch_mtp`].
///
/// `bdk_wallet` retains no MTP, so the caller computes it from their chain backend. Used boxed in
/// [`CandidateParams::fetch_mtp`] (`Option<Box<MtpOracle>>`).
///
/// # Caveats
///
/// This is a deliberate stopgap, with two rough edges worth knowing before you reach for it:
///
/// - **Not sans-I/O.** The closure is called *during* candidate resolution
///   ([`candidates_with`](crate::WalletTxExt::candidates_with)), so any lookup it does runs inline
///   and blocking. Answer from an in-memory map of already-synced block times -- don't make a
///   network round-trip per call.
/// - **No error channel.** It returns `Option`, so a *failed* lookup is indistinguishable from "no
///   MTP for this block": the affected input is then conservatively treated as time-locked and
///   silently excluded, with no way to surface why.
///
/// Both go away with the proper upstream fix -- once `bdk_wallet` keeps block headers (e.g. a
/// `CheckPoint<Header>` chain), MTP is derivable from wallet state and this oracle is unnecessary.
/// Treat `MtpOracle` as the stopgap until then.
pub type MtpOracle = dyn Fn(BlockId) -> Option<absolute::Time> + Send + Sync;

/// Parameters for building the set of spendable input candidates (PSBT-building stage 1).
///
/// Configures how candidates are derived **from the wallet** -- manually selected ("must spend")
/// UTXOs, the spend [`Assets`], canonicalization, and Replace-By-Fee. Pass it to
/// [`WalletTxExt::candidates_with`] to resolve a [`CandidateSet`](crate::CandidateSet).
///
/// All fields are public; construct with [`new`](Self::new) (or [`Default`]) and set what you need.
///
/// To spend a UTXO that did not originate from this wallet (a pre-built foreign
/// [`Input`](bdk_tx::Input)), don't configure it here -- push it onto the resolved
/// [`CandidateSet`](crate::CandidateSet) with
/// [`push_must_select`](crate::CandidateSet::push_must_select) /
/// [`push_can_select`](crate::CandidateSet::push_can_select).
///
/// [`WalletTxExt::candidates_with`]: crate::WalletTxExt::candidates_with
#[derive(Default)]
pub struct CandidateParams {
    /// Manually-selected UTXO outpoints that must be spent.
    ///
    /// Each outpoint must be a wallet-tracked output that is still spendable -- unspent, or (in an
    /// RBF) spent only by a transaction being replaced, which the replacement frees. An unknown or
    /// genuinely-spent outpoint yields [`CannotSpend`](crate::CandidatesError::CannotSpend).
    pub must_spend: BTreeSet<OutPoint>,
    /// Only include inputs selected manually via [`must_spend`](Self::must_spend) (plus any foreign
    /// inputs pushed onto the resolved [`CandidateSet`](crate::CandidateSet)); skip coin selection
    /// for additional candidates.
    pub manually_selected_only: bool,
    /// Txids to replace (Replace-By-Fee).
    ///
    /// Each replaced transaction's **wallet-owned** inputs become must-spend inputs of the
    /// resulting [`CandidateSet`](crate::CandidateSet) -- so the replacement conflicts with (and
    /// evicts) them -- and the set carries the replaced-tx fee floor forward. There should be no
    /// ancestry linking these txids (replacing an ancestor invalidates the descendant); such
    /// ancestry is sanitized away during resolution.
    ///
    /// Only *owned* inputs are forced: a replaced tx's foreign inputs (not controlled by this
    /// wallet -- e.g. a collaborative/coinjoin tx) can't be planned and are dropped from the
    /// must-spend set. Re-add them as pre-built [`Input`](bdk_tx::Input)s via
    /// [`push_must_select`](crate::CandidateSet::push_must_select) if the replacement needs them.
    pub replace: Vec<Txid>,

    /// Spend [`Assets`] used to create spending plans for the wallet's own outputs.
    ///
    /// An empty value (the default) means no signing keys are provided, in which case all of the
    /// wallet's keys are assumed available so wallet-controlled outputs can still be planned.
    pub assets: Assets,
    /// Parameters for modifying the wallet's view of canonical transactions.
    pub canonical_params: CanonicalizationParams,

    /// Chain **height** at which height-based spendability is evaluated -- coinbase maturity and
    /// height-based CLTV/CSV timelocks, in both planning and the post-planning filter. Defaults to
    /// the chain tip when `None`.
    ///
    /// This is the *height* axis only. Time-based (CLTV-time / CSV-time) locks are governed by
    /// [`tip_mtp`](Self::tip_mtp), which is always evaluated as of the chain tip -- so a future
    /// `maturity_height` looks ahead for height-based locks while time-based locks stay at the tip
    /// (a future MTP isn't knowable).
    pub maturity_height: Option<absolute::Height>,
    /// Include immature coinbase outputs (still within the 100-block maturity window) among the
    /// auto-gathered candidates. Defaults to `false` -- immature coins are excluded.
    pub allow_immature: bool,
    /// Include outputs whose CLTV/CSV timelock is not yet satisfied at the evaluation height among
    /// the auto-gathered candidates. Defaults to `false` -- time-locked coins are excluded.
    ///
    /// Height-based locks resolve exactly. Time-based locks need median-time-past (which
    /// `bdk_wallet` doesn't retain): [`tip_mtp`](Self::tip_mtp) for absolute (CLTV-time) locks and
    /// the tip side of relative locks, plus [`fetch_mtp`](Self::fetch_mtp) for the per-input side
    /// of relative (CSV-time) locks. Without the needed value, such inputs stay unresolved and are
    /// excluded.
    pub allow_timelocked: bool,
    /// The chain tip's median-time-past (MTP) -- the **time** axis for evaluating time-based
    /// timelocks, always as of the chain tip (the only knowable MTP).
    ///
    /// `bdk_wallet` retains no MTP, so supply the tip's value -- a single, cheap-to-obtain number
    /// from your chain backend. Every time-based lock needs it: absolute (CLTV-time), and the tip
    /// side of relative (CSV-time). `None` leaves them unresolved (excluded when
    /// [`allow_timelocked`](Self::allow_timelocked) is `false`). Unlike
    /// [`maturity_height`](Self::maturity_height) (the height axis), this can't follow a future
    /// evaluation height -- a future MTP isn't knowable.
    pub tip_mtp: Option<absolute::Time>,
    /// Per-block MTP oracle filling each confirmed input's
    /// [`prev_mtp`](bdk_tx::ConfirmationStatus), queried with the input's confirmation block.
    ///
    /// Needed **only** for relative (CSV-time) locks, which compare [`tip_mtp`](Self::tip_mtp)
    /// against the input's confirmation MTP. Absolute (CLTV-time) locks need only `tip_mtp`;
    /// height-based locks need neither -- so most callers leave this `None`. The caller computes
    /// MTP from their backend; `None` for a block (or leaving this `None`) leaves that input's
    /// `prev_mtp` unset.
    pub fetch_mtp: Option<Box<MtpOracle>>,
}

impl core::fmt::Debug for CandidateParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CandidateParams")
            .field("must_spend", &self.must_spend)
            .field("manually_selected_only", &self.manually_selected_only)
            .field("replace", &self.replace)
            .field("assets", &self.assets)
            .field("canonical_params", &self.canonical_params)
            .field("maturity_height", &self.maturity_height)
            .field("allow_immature", &self.allow_immature)
            .field("allow_timelocked", &self.allow_timelocked)
            .field("tip_mtp", &self.tip_mtp)
            .field("fetch_mtp", &self.fetch_mtp.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

impl CandidateParams {
    /// Create new, empty [`CandidateParams`].
    pub fn new() -> Self {
        Self::default()
    }
}

/// Parameters to create a PSBT that pays a set of recipients (PSBT-building stage 2).
///
/// Built with [`SelectParams::new`], passed alongside a [`CandidateSet`](crate::CandidateSet) to
/// [`WalletTxExt::select`], which runs coin selection and returns a [`bdk_tx::TxTemplate`]. The
/// caller then shapes the template (version, locktime, anti-fee-sniping, input/output ordering)
/// using the template's own methods before emitting the PSBT via
/// [`bdk_tx::TxTemplate::build_psbt`].
///
/// [`WalletTxExt::select`]: crate::WalletTxExt::select
#[derive(Debug)]
pub struct SelectParams {
    /// List of recipient script/amount pairs.
    pub recipients: Vec<(ScriptBuf, Amount)>,
    /// Optional script or descriptor designated for change. When `None`, the wallet's next unused
    /// internal address is revealed and used.
    pub change_script: Option<ChangeScript>,
    /// Coin selection strategy to use.
    ///
    /// Defaults to [`SelectionStrategy::LowestFee`] (a waste-minimizing BnB). Use
    /// [`SelectionStrategy::SweepEffective`] (with no recipients) to sweep the spendable balance.
    pub coin_selection: SelectionStrategy,
    /// Target feerate.
    pub feerate: FeeRate,
    /// Long-term feerate for waste optimization -- the hypothetical feerate at which the resulting
    /// coins are later spent.
    ///
    /// Feeds the waste-aware change policy for **every** strategy, and the bnb metric of
    /// [`SelectionStrategy::LowestFee`]. `None` (the default) means "assume it matches
    /// [`feerate`](Self::feerate)".
    pub longterm_feerate: Option<FeeRate>,
}

impl Default for SelectParams {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectParams {
    /// Create `SelectParams` with no recipients, default coin selection, and the
    /// `FeeRate::BROADCAST_MIN` feerate.
    pub fn new() -> Self {
        Self {
            recipients: Vec::new(),
            change_script: None,
            coin_selection: SelectionStrategy::default(),
            feerate: FeeRate::BROADCAST_MIN,
            longterm_feerate: None,
        }
    }
}

/// Coin selection strategy.
///
/// Defaults to [`LowestFee`](Self::LowestFee) with a generous round budget -- a waste-minimizing
/// Branch and Bound search that, allowing change, finds a target-meeting solution for any fundable
/// candidate set (it only gives up after `max_rounds` branches without one, which needs a candidate
/// count on the order of `max_rounds` itself).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SelectionStrategy {
    /// Single random draw.
    SingleRandomDraw,
    /// Lowest fee, a variation of Branch 'n Bound that allows for change while minimizing
    /// transaction fees. Refer to the [`LowestFee`] metric for more.
    ///
    /// `max_rounds` is the search budget, not a success/failure threshold: a solution is found
    /// early, and the search keeps refining toward the lowest-waste one until it proves optimality
    /// (stopping early) or hits the cap. Higher values only help in the large-candidate-set tail.
    ///
    /// [`LowestFee`]: bdk_tx::bdk_coin_select::metrics::LowestFee
    LowestFee {
        /// How many BnB branches to explore before returning the best solution found so far.
        max_rounds: usize,
    },
    /// Spend **every** available candidate -- including *uneconomical* ones (inputs that cost more
    /// in fees to spend than they add in value) -- ignoring any target amount.
    ///
    /// The remainder (everything minus fees) goes to change: with no recipients this sweeps the
    /// whole candidate set to a single output; with recipients it pays them and sends the rest to
    /// change. Use it to fully empty a wallet (e.g. closing it), accepting that uneconomical inputs
    /// reduce the swept amount. See [`SweepEffective`](Self::SweepEffective) to skip those inputs.
    SweepAll,
    /// Spend every **economical** candidate -- those with positive *effective value* (their value
    /// minus the fee to spend them at the target `feerate`) -- ignoring any target amount.
    ///
    /// Like [`SweepAll`](Self::SweepAll), but drops inputs that would cost more to spend than they
    /// are worth, maximizing the swept amount. This is the usual "sweep my spendable balance".
    SweepEffective,
}

impl Default for SelectionStrategy {
    fn default() -> Self {
        Self::LowestFee {
            max_rounds: 210_000,
        }
    }
}

/// Merge the available signing keys and hash preimages from `src` into `dst`.
///
/// Only these additive (set-union) secrets are merged. The absolute/relative timelocks are
/// deliberately left untouched -- they are single-valued ceilings with no unambiguous merge.
pub(crate) fn merge_assets_secrets(dst: &mut Assets, src: &Assets) {
    dst.keys.extend(src.keys.clone());
    dst.sha256_preimages.extend(src.sha256_preimages.clone());
    dst.hash256_preimages.extend(src.hash256_preimages.clone());
    dst.ripemd160_preimages
        .extend(src.ripemd160_preimages.clone());
    dst.hash160_preimages.extend(src.hash160_preimages.clone());
}
