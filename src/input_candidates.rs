use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

use bdk_coin_select::{metrics::LowestFee, Candidate, NoBnbSolution};
use bitcoin::{absolute, FeeRate, OutPoint};
use miniscript::bitcoin;

use crate::collections::{BTreeMap, HashSet};
use crate::{
    cs_feerate, CannotMeetTarget, Input, InputGroup, Selection, Selector, SelectorError,
    SelectorParams,
};

/// Input candidates.
#[must_use]
#[derive(Debug, Clone)]
pub struct InputCandidates {
    contains: HashSet<OutPoint>,
    must_select: Option<InputGroup>,
    can_select: Vec<InputGroup>,
    cs_candidates: Vec<Candidate>,
}

fn cs_candidate_from_group(group: &InputGroup) -> Candidate {
    Candidate {
        value: group.value().to_sat(),
        weight: group.weight(),
        input_count: group.input_count(),
        is_segwit: group.is_segwit(),
    }
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
            contains,
            must_select,
            can_select,
            cs_candidates,
        }
    }

    fn build_cs_candidates(
        must_select: &Option<InputGroup>,
        can_select: &[InputGroup],
    ) -> Vec<Candidate> {
        must_select
            .iter()
            .chain(can_select)
            .map(cs_candidate_from_group)
            .collect()
    }

    /// Iterate over all contained inputs of all groups.
    pub fn inputs(&self) -> impl Iterator<Item = &Input> + '_ {
        self.groups().flat_map(InputGroup::inputs)
    }

    /// Consume and iterate over all conatined inputs of all groups.
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

    /// Can select
    pub fn can_select(&self) -> &[InputGroup] {
        &self.can_select
    }

    /// Must select
    pub fn must_select(&self) -> Option<&InputGroup> {
        self.must_select.as_ref()
    }

    /// cs candidates
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
            contains: no_dup,
            must_select,
            can_select,
            cs_candidates,
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

    /// Attempt to convert the input candidates into a valid [`Selection`] with a given
    /// `algorithm` and selector `params`.
    pub fn into_selection<A, E>(
        self,
        mut algorithm: A,
        params: SelectorParams,
    ) -> Result<Selection, IntoSelectionError<E>>
    where
        A: FnMut(&mut Selector) -> Result<(), E>,
    {
        let mut selector = Selector::new(&self, params).map_err(IntoSelectionError::Selector)?;
        algorithm(&mut selector).map_err(IntoSelectionError::SelectionAlgorithm)?;
        let selection = selector
            .try_finalize()
            .ok_or(IntoSelectionError::CannotMeetTarget(CannotMeetTarget))?;
        Ok(selection)
    }
}

/// Occurs when we cannot find a solution for selection.
#[derive(Debug)]
pub enum IntoSelectionError<E> {
    /// Coin selector returned an error
    Selector(SelectorError),
    /// Selection algorithm failed.
    SelectionAlgorithm(E),
    /// The target cannot be met
    CannotMeetTarget(CannotMeetTarget),
}

impl<E: fmt::Display> fmt::Display for IntoSelectionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntoSelectionError::Selector(error) => {
                write!(f, "{}", error)
            }
            IntoSelectionError::SelectionAlgorithm(error) => {
                write!(f, "selection algorithm failed: {}", error)
            }
            IntoSelectionError::CannotMeetTarget(error) => write!(f, "{}", error),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for IntoSelectionError<E> {}

/// Occurs when we are missing outputs.
#[derive(Debug)]
pub struct MissingOutputs(HashSet<OutPoint>);

impl Deref for MissingOutputs {
    type Target = HashSet<OutPoint>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for MissingOutputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: should not use fmt::Debug on Display
        write!(f, "missing outputs: {:?}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MissingOutputs {}

/// Occurs when a must-select policy cannot be fulfilled.
#[derive(Debug)]
pub enum PolicyFailure<PF> {
    /// Missing outputs.
    MissingOutputs(MissingOutputs),
    /// Policy failure.
    PolicyFailure(PF),
}

impl<PF: fmt::Display> fmt::Display for PolicyFailure<PF> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyFailure::MissingOutputs(err) => write!(f, "{}", err),
            PolicyFailure::PolicyFailure(err) => {
                write!(f, "policy failure: {}", err)
            }
        }
    }
}

#[cfg(feature = "std")]
impl<PF: fmt::Debug + fmt::Display> std::error::Error for PolicyFailure<PF> {}

/// Select for lowest fee with bnb
pub fn selection_algorithm_lowest_fee_bnb(
    longterm_feerate: FeeRate,
    max_rounds: usize,
) -> impl FnMut(&mut Selector) -> Result<(), NoBnbSolution> {
    let long_term_feerate = cs_feerate(longterm_feerate);
    move |selector| {
        let target = selector.target();
        let change_policy = selector.change_policy();
        selector
            .inner_mut()
            .run_bnb(
                LowestFee {
                    target,
                    long_term_feerate,
                    change_policy,
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
pub fn filter_unspendable_now(
    tip_height: absolute::Height,
    tip_time: absolute::Time,
) -> impl Fn(&Input) -> bool {
    move |input| input.is_spendable_now(tip_height, tip_time)
}

/// No filtering.
pub fn no_filtering() -> impl Fn(&InputGroup) -> bool {
    |_| true
}
