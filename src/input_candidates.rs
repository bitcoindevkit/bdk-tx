use alloc::{vec, vec::Vec};
use core::fmt;

use bdk_coin_select::{metrics::LowestFee, Candidate, CoinSelector, InsufficientFunds, NoBnbSolution};
use bitcoin::{absolute, Amount, OutPoint};
use miniscript::bitcoin;
use rand_core::RngCore;

use crate::collections::{BTreeMap, HashSet};
use crate::{
    FeeRateExt, Input, InputGroup, Output, SelectionContext, SelectionError, SelectionParams,
    TxTemplate,
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

    /// Add `input` to the must-select group (always included by coin selection).
    ///
    /// All must-select inputs form a single group spent together.
    ///
    /// If `input`'s outpoint is already a candidate it is *upserted*: the existing candidate is
    /// replaced with `input` and moved into the must-select group. When the previous candidate was
    /// part of a multi-input `can_select` group, it is detached and the remaining members stay
    /// grouped together.
    pub fn push_must_select(mut self, input: impl Into<Input>) -> Self {
        let input = input.into();
        self.take_input(input.prev_outpoint());
        self.contains.insert(input.prev_outpoint());
        let mut inputs = self
            .must_select
            .take()
            .map_or_else(Vec::new, InputGroup::into_inputs);
        inputs.push(input);
        self.must_select = InputGroup::from_inputs(inputs);
        self.cs_candidates = Self::build_cs_candidates(&self.must_select, &self.can_select);
        self
    }

    /// Add `input` as its own optional (can-select) group.
    ///
    /// If `input`'s outpoint is already a candidate it is *upserted*: the existing candidate is
    /// replaced with `input`. As must-select takes precedence over can-select (consistent with
    /// [`new`](Self::new)), an outpoint that is already must-select keeps its data replaced but is
    /// *not* demoted to can-select.
    pub fn push_can_select(mut self, input: impl Into<Input>) -> Self {
        let input = input.into();
        let outpoint = input.prev_outpoint();
        let in_must_select = self
            .must_select
            .as_ref()
            .is_some_and(|g| g.inputs().iter().any(|i| i.prev_outpoint() == outpoint));
        if in_must_select {
            return self.push_must_select(input);
        }
        self.take_input(outpoint);
        self.contains.insert(outpoint);
        self.can_select.push(InputGroup::from_input(input));
        self.cs_candidates = Self::build_cs_candidates(&self.must_select, &self.can_select);
        self
    }

    /// Remove and return the candidate input with `outpoint` from wherever it currently lives.
    ///
    /// When the input was part of a multi-input `can_select` group, the remaining members are kept
    /// together as a group (in the same position). Returns `None` if `outpoint` is not a candidate.
    /// Does not rebuild [`Self::cs_candidates`]; callers must do so.
    fn take_input(&mut self, outpoint: OutPoint) -> Option<Input> {
        if !self.contains.remove(&outpoint) {
            return None;
        }
        if let Some(group) = self.must_select.take() {
            let mut inputs = group.into_inputs();
            if let Some(pos) = inputs.iter().position(|i| i.prev_outpoint() == outpoint) {
                let removed = inputs.remove(pos);
                self.must_select = InputGroup::from_inputs(inputs);
                return Some(removed);
            }
            self.must_select = InputGroup::from_inputs(inputs);
        }
        for idx in 0..self.can_select.len() {
            let pos = self.can_select[idx]
                .inputs()
                .iter()
                .position(|i| i.prev_outpoint() == outpoint);
            if let Some(pos) = pos {
                let mut inputs = self.can_select.remove(idx).into_inputs();
                let removed = inputs.remove(pos);
                if let Some(group) = InputGroup::from_inputs(inputs) {
                    self.can_select.insert(idx, group);
                }
                return Some(removed);
            }
        }
        None
    }

    /// Run coin selection with `algorithm` and `params`, returning a [`TxTemplate`].
    ///
    /// This drives the whole selection lifecycle: it resolves `params`, validates the candidates,
    /// runs the provided `algorithm` against a [`CoinSelector`], then finalizes the result into a
    /// [`TxTemplate`]. The `algorithm` is handed the [`CoinSelector`] to drive and a
    /// [`SelectionContext`] describing the resolved target, change policy and long-term feerate.
    ///
    /// # Errors
    ///
    /// - [`IntoTxTemplateError::Setup`] if the change policy cannot be built or the candidates have
    ///   incompatible absolute timelock units.
    /// - [`IntoTxTemplateError::CannotMeetTarget`] if the target is unreachable even when selecting
    ///   every effective input at the target feerate - i.e. genuinely impossible.
    /// - [`IntoTxTemplateError::Algorithm`] if the `algorithm` itself errors.
    /// - [`IntoTxTemplateError::AlgorithmFellShort`] if the `algorithm` returns successfully but
    ///   its selection still falls short of the target.
    pub fn into_tx_template<A, E>(
        self,
        algorithm: A,
        params: SelectionParams,
    ) -> Result<TxTemplate, IntoTxTemplateError<E>>
    where
        A: FnOnce(&mut CoinSelector, SelectionContext) -> Result<(), E>,
    {
        let target = params.to_cs_target();
        let change_policy = params
            .to_cs_change_policy()
            .map_err(IntoTxTemplateError::Setup)?;
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
                        return Err(IntoTxTemplateError::Setup(SelectionError::LockTypeMismatch));
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
                return Err(IntoTxTemplateError::CannotMeetTarget {
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
        .map_err(IntoTxTemplateError::Algorithm)?;

        // Ensure target is actually met after selection. The target was already proven reachable,
        // so a shortfall here is the algorithm under-selecting.
        let drain = cs.drain(target, change_policy);
        if cs.excess(target, drain) < 0 {
            return Err(IntoTxTemplateError::AlgorithmFellShort);
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
        Ok(TxTemplate::new(inputs, outputs))
    }
}

/// Error returned by [`InputCandidates::into_tx_template`].
///
/// Covers every way the lifecycle can fail: setup/validation, an impossible target, a failing
/// algorithm, or an algorithm that finished without meeting the target.
#[derive(Debug)]
pub enum IntoTxTemplateError<E> {
    /// Setting up the selection failed (invalid change policy or incompatible timelock units).
    Setup(SelectionError),
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

impl<E: fmt::Display> fmt::Display for IntoTxTemplateError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntoTxTemplateError::Setup(error) => write!(f, "{error}"),
            IntoTxTemplateError::CannotMeetTarget { missing } => write!(
                f,
                "meeting the target is not possible with the input candidates; {missing} sats missing"
            ),
            IntoTxTemplateError::Algorithm(error) => {
                write!(f, "selection algorithm failed: {error}")
            }
            IntoTxTemplateError::AlgorithmFellShort => write!(
                f,
                "the selection algorithm returned successfully but did not meet the target"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for IntoTxTemplateError<E> {}

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

/// Coin selection algorithm that selects candidates in a uniformly-random order until the target
/// is met (single random draw).
///
/// The `rng` is carried by the returned algorithm, so candidate construction stays deterministic
/// and randomness lives at the selection step. Pass the result to
/// [`InputCandidates::into_tx_template`].
pub fn selection_algorithm_single_random_draw(
    rng: &mut impl RngCore,
) -> impl FnOnce(&mut CoinSelector, SelectionContext) -> Result<(), InsufficientFunds> + '_ {
    move |cs, cx| {
        // Assign every candidate a random sort key, then sort by it to obtain a uniform shuffle.
        // The keys are precomputed (one per candidate) so the closure handed to
        // `sort_candidates_by_key` is a deterministic lookup: that closure is invoked multiple
        // times per comparison, so it must not draw from the rng itself.
        let n = cs.candidates().len();
        let keys: Vec<u64> = (0..n).map(|_| rng.next_u64()).collect();
        cs.sort_candidates_by_key(|(i, _)| keys[i]);
        cs.select_until_target_met(cx.target)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Input;
    use bitcoin::{hashes::Hash, Amount, OutPoint, TxOut, Txid};
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    const TEST_XPUB: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";

    /// Build an [`Input`] at `vout` carrying `value` sats; `value` doubles as an identity tag so
    /// tests can assert an upsert actually replaced the previous candidate's data.
    fn input_at(vout: u32, value: u64) -> Input {
        let desc =
            Descriptor::<DescriptorPublicKey>::from_str(&format!("tr({TEST_XPUB})")).unwrap();
        let definite = desc.at_derivation_index(0).unwrap();
        let script_pubkey = definite.script_pubkey();
        let assets = Assets::new().add(DescriptorPublicKey::from_str(TEST_XPUB).unwrap());
        let plan = definite.plan(&assets).unwrap();
        let outpoint = OutPoint::new(Txid::all_zeros(), vout);
        let txout = TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        };
        Input::from_prev_txout(plan, outpoint, txout, None, false)
    }

    fn op(vout: u32) -> OutPoint {
        OutPoint::new(Txid::all_zeros(), vout)
    }

    fn value_at(c: &InputCandidates, outpoint: OutPoint) -> Option<u64> {
        c.inputs()
            .find(|i| i.prev_outpoint() == outpoint)
            .map(|i| i.prev_txout().value.to_sat())
    }

    fn is_must(c: &InputCandidates, outpoint: OutPoint) -> bool {
        c.must_select()
            .is_some_and(|g| g.inputs().iter().any(|i| i.prev_outpoint() == outpoint))
    }

    fn is_can(c: &InputCandidates, outpoint: OutPoint) -> bool {
        c.can_select()
            .iter()
            .any(|g| g.inputs().iter().any(|i| i.prev_outpoint() == outpoint))
    }

    #[test]
    fn push_must_select_promotes_and_replaces_can_select_candidate() {
        let c = InputCandidates::new([], [input_at(0, 100)]);
        assert!(is_can(&c, op(0)));

        let c = c.push_must_select(input_at(0, 200));
        assert!(
            is_must(&c, op(0)),
            "outpoint should be promoted to must-select"
        );
        assert!(
            !is_can(&c, op(0)),
            "outpoint should no longer be can-select"
        );
        assert_eq!(
            value_at(&c, op(0)),
            Some(200),
            "candidate data should be replaced"
        );
        assert_eq!(c.inputs().count(), 1, "no duplicate candidate");
        assert_eq!(c.coin_select_candidates().len(), 1);
    }

    #[test]
    fn push_can_select_does_not_demote_must_select_but_replaces_data() {
        let c = InputCandidates::new([input_at(0, 100)], []);

        let c = c.push_can_select(input_at(0, 200));
        assert!(
            is_must(&c, op(0)),
            "must-select takes precedence; no demotion"
        );
        assert!(!is_can(&c, op(0)));
        assert_eq!(
            value_at(&c, op(0)),
            Some(200),
            "candidate data should be replaced"
        );
        assert_eq!(c.inputs().count(), 1);
    }

    #[test]
    fn push_must_select_detaches_outpoint_from_multi_input_group() {
        // All inputs share a script pubkey, so grouping by spk yields a single can-select group.
        let c = InputCandidates::new([], [input_at(0, 100), input_at(1, 100), input_at(2, 100)])
            .regroup(group_by_spk());
        assert_eq!(c.can_select().len(), 1);
        assert_eq!(c.can_select()[0].inputs().len(), 3);

        let c = c.push_must_select(input_at(1, 999));
        assert!(is_must(&c, op(1)));
        assert_eq!(value_at(&c, op(1)), Some(999));
        assert_eq!(c.can_select().len(), 1, "remaining members stay grouped");
        assert_eq!(c.can_select()[0].inputs().len(), 2);
        assert_eq!(c.inputs().count(), 3, "no input lost or duplicated");
        assert_eq!(c.coin_select_candidates().len(), 2);
    }
}
