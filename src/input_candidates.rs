use core::{
    fmt::{Debug, Display},
    ops::Deref,
};

use crate::{collections::HashSet, cs_feerate, Selection, Selector, SelectorParams};
use alloc::vec::Vec;
use bdk_coin_select::{metrics::LowestFee, Candidate, NoBnbSolution};
use bitcoin::{FeeRate, OutPoint};
use miniscript::bitcoin;

use crate::InputGroup;

/// Candidates ready for coin selection.
#[must_use]
#[derive(Debug, Clone)]
pub struct InputCandidates {
    must_select_count: usize,
    groups: Vec<InputGroup>,
    cs_candidates: Vec<Candidate>,
}

/// Occurs when we cannot find a solution for selection.
#[derive(Debug)]
pub enum IntoSelectionError<E> {
    /// Parameters provided created an invalid change policy.
    InvalidChangePolicy(miniscript::Error),
    /// Selection algorithm failed.
    SelectionAlgorithm(E),
    /// Cannot meet target.
    CannotMeetTarget,
}

impl<E: Display> Display for IntoSelectionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IntoSelectionError::InvalidChangePolicy(error) => {
                write!(f, "invalid change policy: {}", error)
            }
            IntoSelectionError::SelectionAlgorithm(error) => {
                write!(f, "selection algorithm failed: {}", error)
            }
            IntoSelectionError::CannotMeetTarget => write!(f, "cannot meet target"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: Debug + Display> std::error::Error for IntoSelectionError<E> {}

/// Occurs when we are missing ouputs.
#[derive(Debug)]
pub struct MissingOutputs(HashSet<OutPoint>);

impl Deref for MissingOutputs {
    type Target = HashSet<OutPoint>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for MissingOutputs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl<PF: Debug> Display for PolicyFailure<PF> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PolicyFailure::MissingOutputs(missing_outputs) => Debug::fmt(missing_outputs, f),
            PolicyFailure::PolicyFailure(failure) => {
                write!(f, "policy failure: {:?}", failure)
            }
        }
    }
}

#[cfg(feature = "std")]
impl<PF: Debug> std::error::Error for PolicyFailure<PF> {}

/// Select for lowest fee with bnb
pub fn selection_algorithm_lowest_fee_bnb(
    longterm_feerate: FeeRate,
    max_rounds: usize,
) -> impl FnMut(&InputCandidates, &mut Selector) -> Result<(), NoBnbSolution> {
    let long_term_feerate = cs_feerate(longterm_feerate);
    move |_, selector| {
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

impl InputCandidates {
    /// Create
    ///
    /// Caller should ensure there are no duplicates.
    pub fn new<A, B, G>(must_select: A, can_select: B) -> Self
    where
        A: IntoIterator<Item = G>,
        B: IntoIterator<Item = G>,
        G: Into<InputGroup>,
    {
        let mut groups = must_select.into_iter().map(Into::into).collect::<Vec<_>>();
        let must_select_count = groups.len();
        groups.extend(can_select.into_iter().map(Into::into));
        let cs_candidates = groups
            .iter()
            .map(|group| Candidate {
                value: group.value().to_sat(),
                weight: group.weight(),
                input_count: group.input_count(),
                is_segwit: group.is_segwit(),
            })
            .collect();
        InputCandidates {
            must_select_count,
            groups,
            cs_candidates,
        }
    }

    /// Try create a new [`InputCandidates`] with the provided `outpoints` as "must spend".
    ///
    /// TODO: This can be optimized later. Right API first.
    ///
    /// # Error
    ///
    /// Returns the original [`InputCandidates`] if any outpoint is not found.
    pub fn with_must_select(self, outpoints: HashSet<OutPoint>) -> Result<Self, MissingOutputs> {
        let (must_select, can_select) = self.groups.iter().partition::<Vec<_>, _>(|group| {
            group.any(|input| outpoints.contains(&input.prev_outpoint()))
        });

        // `must_select` must contaon all outpoints.
        let must_select_map = must_select
            .iter()
            .flat_map(|group| group.inputs().iter().map(|input| input.prev_outpoint()))
            .collect::<HashSet<OutPoint>>();
        if !must_select_map.is_superset(&outpoints) {
            return Err(MissingOutputs(
                outpoints.difference(&must_select_map).copied().collect(),
            ));
        }

        let must_select_count = must_select.len();
        let groups = must_select
            .into_iter()
            .chain(can_select)
            .cloned()
            .collect::<Vec<_>>();
        let cs_candidates = groups
            .iter()
            .map(|group| Candidate {
                value: group.value().to_sat(),
                weight: group.weight(),
                input_count: group.input_count(),
                is_segwit: group.is_segwit(),
            })
            .collect();
        Ok(InputCandidates {
            must_select_count,
            groups,
            cs_candidates,
        })
    }

    /// Like [`InputCandidates::with_must_select`], but with a policy closure.
    pub fn with_must_select_policy<P, PF>(self, mut policy: P) -> Result<Self, PolicyFailure<PF>>
    where
        P: FnMut(&Self) -> Result<HashSet<OutPoint>, PF>,
    {
        let outpoints = policy(&self).map_err(PolicyFailure::PolicyFailure)?;
        self.with_must_select(outpoints)
            .map_err(PolicyFailure::MissingOutputs)
    }

    /// Into selection.
    pub fn into_selection<A, E>(
        self,
        mut selection_algorithm: A,
        params: SelectorParams,
    ) -> Result<Selection, IntoSelectionError<E>>
    where
        A: FnMut(&Self, &mut Selector) -> Result<(), E>,
    {
        let mut selector =
            Selector::new(&self, params).map_err(IntoSelectionError::InvalidChangePolicy)?;
        selection_algorithm(&self, &mut selector)
            .map_err(IntoSelectionError::SelectionAlgorithm)?;
        let selection = selector
            .try_finalize()
            .ok_or(IntoSelectionError::CannotMeetTarget)?;
        Ok(selection)
    }

    /// Whether the outpoint is contained in our candidates.
    pub fn contains(&self, outpoint: OutPoint) -> bool {
        self.groups.iter().any(|group| {
            group
                .inputs()
                .iter()
                .any(|input| input.prev_outpoint() == outpoint)
        })
    }

    /// Iterate all groups (both must_select and can_select).
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (InputGroup, Candidate)> + '_ {
        self.groups
            .iter()
            .cloned()
            .zip(self.cs_candidates.iter().cloned())
    }

    /// Iterate only must_select
    pub fn iter_must_select(&self) -> impl ExactSizeIterator<Item = (InputGroup, Candidate)> + '_ {
        self.iter().take(self.must_select_count)
    }

    /// Iterate only can_select
    pub fn iter_can_select(&self) -> impl ExactSizeIterator<Item = (InputGroup, Candidate)> + '_ {
        self.iter().skip(self.must_select_count)
    }

    /// Must select count
    pub fn must_select_len(&self) -> usize {
        self.must_select_count
    }

    /// Can select count
    pub fn can_select_len(&self) -> usize {
        self.groups.len() - self.must_select_count
    }

    /// Input groups
    pub fn groups(&self) -> &Vec<InputGroup> {
        &self.groups
    }

    /// cs candidates
    pub fn coin_select_candidates(&self) -> &Vec<Candidate> {
        &self.cs_candidates
    }
}
