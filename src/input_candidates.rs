use alloc::{vec, vec::Vec};
use core::fmt;

use bdk_coin_select::{metrics::LowestFee, Candidate, CoinSelector, NoBnbSolution};
use bitcoin::{absolute, Amount, OutPoint};
use miniscript::bitcoin;

use crate::collections::{BTreeMap, HashSet};
use crate::{
    ChangePolicyError, FeeRateExt, Input, InputGroup, Output, Selection, SelectionContext,
    SelectionParams,
};

/// Input candidates.
#[must_use]
#[derive(Debug, Clone)]
pub struct InputCandidates {
    /// Pre-selected input group that is included before optional candidates.
    must_select: Option<InputGroup>,
    /// Optional input groups that coin selection may add.
    can_select: Vec<InputGroup>,
    /// Cached coin-select candidate metadata, kept in the same order as [`Self::groups`].
    cs_candidates: Vec<Candidate>,
    /// Cached outpoints used for deduplication and O(1) membership checks.
    contains: HashSet<OutPoint>,
}

impl InputCandidates {
    /// Construct [`InputCandidates`] with a list of inputs that must be selected as well as
    /// those that may additionally be selected. If the same outpoint occurs in both `must_select` and
    /// `can_select`, the one in `must_select` is retained.
    pub fn new<A, B>(must_select: A, can_select: B) -> Self
    where
        A: IntoIterator<Item = Input>,
        B: IntoIterator<Item = Input>,
    {
        let mut contains = HashSet::<OutPoint>::new();
        let must_select = InputGroup::from_inputs(
            must_select
                .into_iter()
                .filter(|input| contains.insert(input.prev_outpoint())),
        );
        let can_select = can_select
            .into_iter()
            .filter(|input| contains.insert(input.prev_outpoint()))
            .map(InputGroup::from_input)
            .collect::<Vec<_>>();
        let cs_candidates = Self::build_cs_candidates(&must_select, &can_select);
        InputCandidates {
            must_select,
            can_select,
            cs_candidates,
            contains,
        }
    }

    fn build_cs_candidates(
        must_select: &Option<InputGroup>,
        can_select: &[InputGroup],
    ) -> Vec<Candidate> {
        must_select
            .iter()
            .chain(can_select)
            .map(|group| Candidate {
                value: group.value().to_sat(),
                weight: group.weight(),
                input_count: group.input_count(),
                is_segwit: group.is_segwit(),
            })
            .collect()
    }

    /// Iterate over all contained inputs of all groups.
    pub fn inputs(&self) -> impl Iterator<Item = &Input> + '_ {
        self.groups().flat_map(InputGroup::inputs)
    }

    /// Consume and iterate over all contained inputs of all groups.
    pub fn into_inputs(self) -> impl Iterator<Item = Input> {
        self.into_groups().flat_map(InputGroup::into_inputs)
    }

    /// Iterate over all contained groups.
    pub fn groups(&self) -> impl Iterator<Item = &InputGroup> + '_ {
        self.must_select.iter().chain(&self.can_select)
    }

    /// Consume and iterate over all contained groups.
    pub fn into_groups(self) -> impl Iterator<Item = InputGroup> {
        self.must_select.into_iter().chain(self.can_select)
    }

    /// Inputs that coin selection may choose from.
    pub fn can_select(&self) -> &[InputGroup] {
        &self.can_select
    }

    /// Inputs that must be selected, if any.
    pub fn must_select(&self) -> Option<&InputGroup> {
        self.must_select.as_ref()
    }

    /// Cached candidate metadata used by `bdk_coin_select`.
    pub fn coin_select_candidates(&self) -> &Vec<Candidate> {
        &self.cs_candidates
    }

    /// Whether the outpoint is an input candidate.
    pub fn contains(&self, outpoint: OutPoint) -> bool {
        self.contains.contains(&outpoint)
    }

    /// Regroup inputs with given `policy`.
    ///
    /// Anything grouped with `must_select` inputs also becomes `must_select`.
    pub fn regroup<P, G>(self, mut policy: P) -> Self
    where
        P: FnMut(&Input) -> G,
        G: Ord + Clone,
    {
        let mut order = Vec::<G>::with_capacity(self.contains.len());
        let mut groups = BTreeMap::<G, Vec<Input>>::new();
        for input in self
            .can_select
            .into_iter()
            .flat_map(InputGroup::into_inputs)
        {
            let group_id = policy(&input);
            use crate::collections::btree_map::Entry;
            let entry = match groups.entry(group_id.clone()) {
                Entry::Vacant(entry) => {
                    order.push(group_id.clone());
                    entry.insert(vec![])
                }
                Entry::Occupied(entry) => entry.into_mut(),
            };
            entry.push(input);
        }

        let mut must_select = self.must_select.map_or(vec![], |g| g.into_inputs());
        let must_select_order = must_select.iter().map(&mut policy).collect::<Vec<_>>();
        for g_id in must_select_order {
            if let Some(inputs) = groups.remove(&g_id) {
                must_select.extend(inputs);
            }
        }
        let must_select = InputGroup::from_inputs(must_select);

        let mut can_select = Vec::<InputGroup>::new();
        for g_id in order {
            if let Some(inputs) = groups.remove(&g_id) {
                if let Some(group) = InputGroup::from_inputs(inputs) {
                    can_select.push(group);
                }
            }
        }

        let cs_candidates = Self::build_cs_candidates(&must_select, &can_select);
        let no_dup = self.contains;

        Self {
            must_select,
            can_select,
            cs_candidates,
            contains: no_dup,
        }
    }

    /// Filters out inputs.
    ///
    /// If a filtered-out input is part of a group, the group will also be filtered out.
    /// Does not filter `must_select` inputs.
    pub fn filter<P>(mut self, mut policy: P) -> Self
    where
        P: FnMut(&Input) -> bool,
    {
        let mut to_rm = Vec::<OutPoint>::new();
        self.can_select.retain(|group| {
            let retain = group.all(&mut policy);
            if !retain {
                for input in group.inputs() {
                    to_rm.push(input.prev_outpoint());
                }
            }
            retain
        });
        for op in to_rm {
            self.contains.remove(&op);
        }
        self.cs_candidates = Self::build_cs_candidates(&self.must_select, &self.can_select);
        self
    }

    /// Attempt to convert the input candidates into a valid [`Selection`].
    ///
    /// This drives the whole selection lifecycle: it resolves `params`, validates the candidates,
    /// runs the provided `algorithm` against a [`CoinSelector`], then finalizes the result. The
    /// `algorithm` is handed the [`CoinSelector`] to drive and a [`SelectionContext`] describing
    /// the resolved target, change policy and long-term feerate.
    ///
    /// # Errors
    ///
    /// - [`IntoSelectionError::ChangePolicy`] if the change policy cannot be built from the params.
    /// - [`IntoSelectionError::LockTypeMismatch`] if the candidates have incompatible absolute
    ///   timelock units.
    /// - [`IntoSelectionError::CannotMeetTarget`] if the target is unreachable even when selecting
    ///   every effective input at the target feerate - i.e. genuinely impossible.
    /// - [`IntoSelectionError::Algorithm`] if the `algorithm` itself errors.
    /// - [`IntoSelectionError::AlgorithmFellShort`] if the `algorithm` returns successfully but
    ///   its selection still falls short of the target.
    pub fn into_selection<A, E>(
        self,
        algorithm: A,
        params: SelectionParams,
    ) -> Result<Selection, IntoSelectionError<E>>
    where
        A: FnOnce(&mut CoinSelector, SelectionContext) -> Result<(), E>,
    {
        let target = params.to_cs_target();
        let change_policy = params
            .to_cs_change_policy()
            .map_err(IntoSelectionError::ChangePolicy)?;
        let longterm_feerate = params
            .longterm_feerate
            .unwrap_or(params.target_feerate)
            .into_cs_feerate();
        let change_script = params.change_script.source();
        let target_outputs = params.target_outputs;

        // Verify that all inputs agree on absolute timelock unit (height vs time). Downstream
        // stages (create_psbt, apply_anti_fee_sniping) rely on this invariant.
        let mut unit: Option<absolute::LockTime> = None;
        for lt in self.inputs().filter_map(Input::absolute_timelock) {
            match unit {
                Some(existing_unit) => {
                    if !existing_unit.is_same_unit(lt) {
                        return Err(IntoSelectionError::LockTypeMismatch);
                    }
                }
                None => unit = Some(lt),
            }
        }

        let mut cs = CoinSelector::new(self.coin_select_candidates());
        if self.must_select().is_some() {
            cs.select_next();
        }

        // Reachability pre-check.
        {
            let mut check = cs.clone();
            check.select_all_effective(target.fee.rate);
            let max_excess = check.excess(target, bdk_coin_select::Drain::NONE);
            if max_excess < 0 {
                return Err(IntoSelectionError::CannotMeetTarget {
                    missing: max_excess.unsigned_abs(),
                });
            }
        }

        algorithm(
            &mut cs,
            SelectionContext {
                target,
                change_policy,
                longterm_feerate,
            },
        )
        .map_err(IntoSelectionError::Algorithm)?;

        // Ensure target is actually met after selection. The target was already proven reachable,
        // so a shortfall here is the algorithm under-selecting.
        let drain = cs.drain(target, change_policy);
        if cs.excess(target, drain) < 0 {
            return Err(IntoSelectionError::AlgorithmFellShort);
        }

        let to_apply = self.groups().collect::<Vec<_>>();
        let inputs = cs
            .apply_selection(&to_apply)
            .copied()
            .flat_map(InputGroup::inputs)
            .cloned()
            .collect();
        let mut outputs = target_outputs;
        if drain.is_some() {
            outputs.push(Output::from((change_script, Amount::from_sat(drain.value))));
        }
        Ok(Selection::new(inputs, outputs))
    }
}

/// Error returned by [`InputCandidates::into_selection`].
///
/// Covers every way the lifecycle can fail: an unbuildable change policy, incompatible candidate
/// timelocks, an impossible target, a failing algorithm, or an algorithm that finished without
/// meeting the target.
#[derive(Debug)]
pub enum IntoSelectionError<E> {
    /// The change policy could not be built from the params (see [`ChangePolicyError`]).
    ChangePolicy(ChangePolicyError),
    /// Input candidates have absolute timelocks of mixed units (some height-based, others
    /// time-based), which is unbuildable since `nLockTime` is a single field on a transaction.
    LockTypeMismatch,
    /// The target is impossible: unreachable even when selecting every effective input at the
    /// target feerate.
    CannotMeetTarget {
        /// The shortfall in satoshis at best-case (all effective inputs selected).
        missing: u64,
    },
    /// The selection algorithm itself returned an error.
    Algorithm(E),
    /// The algorithm returned successfully but its selection still falls short of the target.
    ///
    /// This is an algorithm contract violation as the target *was* reachable — the algorithm simply
    /// did not select enough inputs. A correct algorithm either meets the target or returns its own
    /// error.
    AlgorithmFellShort,
}

impl<E: fmt::Display> fmt::Display for IntoSelectionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntoSelectionError::ChangePolicy(error) => write!(f, "{error}"),
            IntoSelectionError::LockTypeMismatch => {
                write!(f, "input candidates have absolute timelocks of mixed units")
            }
            IntoSelectionError::CannotMeetTarget { missing } => write!(
                f,
                "meeting the target is not possible with the input candidates; {missing} sats missing"
            ),
            IntoSelectionError::Algorithm(error) => {
                write!(f, "selection algorithm failed: {error}")
            }
            IntoSelectionError::AlgorithmFellShort => write!(
                f,
                "the selection algorithm returned successfully but did not meet the target"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for IntoSelectionError<E> {}

/// Select for lowest fee with bnb.
///
/// The long-term feerate is taken from the [`SelectionContext`] (resolved from
/// [`SelectionParams::longterm_feerate`](crate::SelectionParams::longterm_feerate)), so the same
/// estimate drives both this metric and the change policy.
pub fn selection_algorithm_lowest_fee_bnb(
    max_rounds: usize,
) -> impl FnOnce(&mut CoinSelector, SelectionContext) -> Result<(), NoBnbSolution> {
    move |cs, cx| {
        cs.run_bnb(
            LowestFee {
                target: cx.target,
                long_term_feerate: cx.longterm_feerate,
                change_policy: cx.change_policy,
            },
            max_rounds,
        )
        .map(|_| ())
    }
}

/// Default group policy.
pub fn group_by_spk() -> impl Fn(&Input) -> bitcoin::ScriptBuf {
    |input| input.prev_txout().script_pubkey.clone()
}

/// Filter out inputs that cannot be spent now.
///
/// If an input's spendability cannot be determined, it will also be filtered out.
pub fn filter_unspendable(
    tip_height: absolute::Height,
    tip_mtp: Option<absolute::Time>,
) -> impl Fn(&Input) -> bool {
    move |input| input.is_spendable(tip_height, tip_mtp).unwrap_or(false)
}

/// No filtering.
pub fn no_filtering() -> impl Fn(&InputGroup) -> bool {
    |_| true
}
