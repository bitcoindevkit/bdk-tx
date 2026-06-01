use alloc::{vec, vec::Vec};
use core::fmt;

use bdk_coin_select::{metrics::LowestFee, Candidate, NoBnbSolution, UnconfirmedAncestor};
use bitcoin::{absolute, FeeRate, OutPoint, Txid};
use miniscript::bitcoin;

use crate::ancestor::AncestorFee;
use crate::collections::{BTreeMap, BTreeSet, HashSet};
use crate::{
    AncestorFeeError, CannotMeetTarget, CanonicalUnspents, FeeRateExt, Input, InputGroup,
    Selection, Selector, SelectorError, SelectorParams,
};

#[derive(Debug, Clone)]
struct InputCandidateAncestor {
    weight: u64,
    fee_paid: u64,
    dependent_outpoints: BTreeSet<OutPoint>,
}

impl From<AncestorFee> for InputCandidateAncestor {
    fn from(fee: AncestorFee) -> Self {
        Self {
            weight: fee.weight,
            fee_paid: fee.fee_paid,
            dependent_outpoints: BTreeSet::new(),
        }
    }
}

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
    /// Source-of-truth CPFP ancestor data keyed by dependent [`OutPoint`]s.
    ancestors: Vec<InputCandidateAncestor>,
    /// Cached coin-select ancestor metadata with indices into [`Self::cs_candidates`].
    cs_ancestors: Vec<UnconfirmedAncestor>,
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
            ancestors: Vec::new(),
            cs_ancestors: Vec::new(),
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

    fn build_cs_ancestors(
        ancestors: &[InputCandidateAncestor],
        must_select: &Option<InputGroup>,
        can_select: &[InputGroup],
    ) -> Vec<UnconfirmedAncestor> {
        ancestors
            .iter()
            .filter_map(|ancestor| {
                let mut dependent_candidates = Vec::new();
                for (candidate_index, group) in must_select.iter().chain(can_select).enumerate() {
                    let group_depends_on_ancestor = group.inputs().iter().any(|input| {
                        ancestor
                            .dependent_outpoints
                            .contains(&input.prev_outpoint())
                    });
                    if group_depends_on_ancestor {
                        dependent_candidates.push(candidate_index);
                    }
                }

                if dependent_candidates.is_empty() {
                    None
                } else {
                    Some(UnconfirmedAncestor {
                        weight: ancestor.weight,
                        fee_paid: ancestor.fee_paid,
                        dependent_candidates,
                    })
                }
            })
            .collect()
    }

    fn rebuild_coin_select_cache(&mut self) {
        self.cs_candidates = Self::build_cs_candidates(&self.must_select, &self.can_select);
        self.cs_ancestors =
            Self::build_cs_ancestors(&self.ancestors, &self.must_select, &self.can_select);
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

    /// Shared CPFP ancestor table for `bdk_coin_select`.
    pub(crate) fn coin_select_ancestors(&self) -> &[UnconfirmedAncestor] {
        &self.cs_ancestors
    }

    /// Attach CPFP ancestor data for these inputs.
    ///
    /// Use this only when unconfirmed inputs should bump fees for their ancestors.
    /// Otherwise, selection targets only the child transaction fee.
    ///
    /// Confirmed inputs are skipped. Repeated calls replace prior ancestor metadata.
    ///
    /// # Errors
    ///
    /// Returns [`AncestorFeeError`] if `graph` lacks required unconfirmed-ancestor data.
    ///
    /// # Panics
    ///
    /// If `graph` is inconsistent with an unconfirmed ancestor transaction.
    pub fn with_unconfirmed_ancestors(
        self,
        graph: &CanonicalUnspents,
    ) -> Result<Self, AncestorFeeError> {
        self.attach_ancestor_data(|outpoint| graph.unconfirmed_ancestors(outpoint.txid))
    }

    /// Record which candidate inputs depend on each ancestor.
    fn attach_ancestor_data<F>(
        mut self,
        mut ancestors_for_input: F,
    ) -> Result<Self, AncestorFeeError>
    where
        F: FnMut(OutPoint) -> Result<Vec<(Txid, AncestorFee)>, AncestorFeeError>,
    {
        let mut ancestors = Vec::<InputCandidateAncestor>::new();
        let mut ancestor_index_by_txid = BTreeMap::<Txid, usize>::new();

        for input in self.groups().flat_map(InputGroup::inputs) {
            // Confirmed inputs need no CPFP bump.
            if input.status().is_some() {
                continue;
            }
            let prev_outpoint = input.prev_outpoint();
            for (ancestor_txid, ancestor_fee) in ancestors_for_input(prev_outpoint)? {
                // Deduplicate ancestors into the stable bdk_tx table.
                let next_ancestor_index = ancestors.len();
                let ancestor_index = *ancestor_index_by_txid
                    .entry(ancestor_txid)
                    .or_insert(next_ancestor_index);
                if ancestor_index == next_ancestor_index {
                    ancestors.push(ancestor_fee.into());
                }
                ancestors[ancestor_index]
                    .dependent_outpoints
                    .insert(prev_outpoint);
            }
        }

        self.ancestors = ancestors;
        self.rebuild_coin_select_cache();
        Ok(self)
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

        let no_dup = self.contains;

        let mut candidates = Self {
            must_select,
            can_select,
            cs_candidates: Vec::new(),
            contains: no_dup,
            ancestors: self.ancestors,
            cs_ancestors: Vec::new(),
        };
        candidates.rebuild_coin_select_cache();
        candidates
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
        self.rebuild_coin_select_cache();
        self
    }

    /// Attempt to convert the input candidates into a valid [`Selection`] with a given
    /// `algorithm` and selector `params`.
    pub fn into_selection<A, E>(
        self,
        algorithm: A,
        params: SelectorParams,
    ) -> Result<Selection, IntoSelectionError<E>>
    where
        A: FnMut(&mut Selector) -> Result<(), E>,
    {
        let mut selector = Selector::new(&self, params).map_err(IntoSelectionError::Selector)?;
        selector
            .select_with_algorithm(algorithm)
            .map_err(IntoSelectionError::SelectionAlgorithm)?;
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
                write!(f, "{error}")
            }
            IntoSelectionError::SelectionAlgorithm(error) => {
                write!(f, "selection algorithm failed: {error}")
            }
            IntoSelectionError::CannotMeetTarget(error) => write!(f, "{error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for IntoSelectionError<E> {}

/// Select for lowest fee with bnb
pub fn selection_algorithm_lowest_fee_bnb(
    longterm_feerate: FeeRate,
    max_rounds: usize,
) -> impl FnMut(&mut Selector) -> Result<(), NoBnbSolution> {
    let long_term_feerate = longterm_feerate.into_cs_feerate();
    move |selector| {
        let target = selector.target();
        let change_policy = selector.cs_change_policy();
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

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalUnspents, ConfirmationStatus};
    use bitcoin::{
        key::Secp256k1, secp256k1::SecretKey, transaction, Amount, Network, PrivateKey, ScriptBuf,
        Transaction, TxIn, TxOut,
    };
    use miniscript::{plan::Assets, plan::Plan, Descriptor, DescriptorPublicKey};
    use std::string::ToString;

    /// A single-key `wpkh` descriptor we can both pay to and build a spending [`Plan`] for.
    fn spk_and_plan() -> (ScriptBuf, Plan) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).expect("valid key");
        let pk = PrivateKey::new(sk, Network::Regtest).public_key(&secp);
        let desc_pk: DescriptorPublicKey = pk.to_string().parse().expect("valid pk");
        let (descriptor, _) =
            Descriptor::parse_descriptor(&secp, &format!("wpkh({pk})")).expect("valid descriptor");
        let definite = descriptor
            .at_derivation_index(0)
            .expect("definite descriptor");
        let plan = definite
            .clone()
            .plan(&Assets::new().add(desc_pk))
            .expect("plan");
        (definite.script_pubkey(), plan)
    }

    fn tx_with(prev: Option<OutPoint>, spk: &ScriptBuf, output_values: &[u64]) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev.unwrap_or_default(),
                ..Default::default()
            }],
            output: output_values
                .iter()
                .map(|v| TxOut {
                    value: Amount::from_sat(*v),
                    script_pubkey: spk.clone(),
                })
                .collect(),
        }
    }

    fn confirmed(height: u32) -> ConfirmationStatus {
        ConfirmationStatus::new(height, None).expect("valid height")
    }

    #[test]
    fn test_candidates_have_no_ancestors_by_default() {
        let (spk, plan) = spk_and_plan();
        let grandparent = tx_with(None, &spk, &[100_000]);
        let parent = tx_with(
            Some(OutPoint::new(grandparent.compute_txid(), 0)),
            &spk,
            &[90_000],
        );
        let parent_txid = parent.compute_txid();
        let graph =
            CanonicalUnspents::new(vec![(grandparent, Some(confirmed(100))), (parent, None)]);
        let input = graph
            .try_get_unspent(OutPoint::new(parent_txid, 0), plan)
            .expect("unspent input");

        // Without `with_unconfirmed_ancestors`, nothing changes versus pre-CPFP behaviour.
        let candidates = InputCandidates::new([], [input]);
        assert!(candidates.coin_select_ancestors().is_empty());
    }

    #[test]
    fn test_shared_unconfirmed_ancestor_is_deduplicated() {
        let (spk, plan) = spk_and_plan();
        let grandparent = tx_with(None, &spk, &[200_000]);
        // One unconfirmed parent with two spendable outputs.
        let parent = tx_with(
            Some(OutPoint::new(grandparent.compute_txid(), 0)),
            &spk,
            &[90_000, 90_000],
        );
        let parent_txid = parent.compute_txid();
        let graph =
            CanonicalUnspents::new(vec![(grandparent, Some(confirmed(100))), (parent, None)]);

        let in0 = graph
            .try_get_unspent(OutPoint::new(parent_txid, 0), plan.clone())
            .unwrap();
        let in1 = graph
            .try_get_unspent(OutPoint::new(parent_txid, 1), plan)
            .unwrap();
        let candidates = InputCandidates::new([], [in0, in1])
            .with_unconfirmed_ancestors(&graph)
            .expect("ancestors resolve");

        // Both inputs descend from the same unconfirmed parent: a single shared ancestor entry,
        // depended on by both candidate indices.
        assert_eq!(candidates.coin_select_ancestors().len(), 1);
        assert_eq!(
            candidates.coin_select_ancestors()[0].dependent_candidates,
            vec![0, 1]
        );
    }

    #[test]
    fn test_regroup_rebuilds_dependent_candidates_and_skips_confirmed_inputs() {
        let (spk, plan) = spk_and_plan();
        // grandparent[0] funds the unconfirmed parent; grandparent[1] is a confirmed UTXO.
        let grandparent = tx_with(None, &spk, &[200_000, 50_000]);
        let grandparent_txid = grandparent.compute_txid();
        let parent = tx_with(
            Some(OutPoint::new(grandparent_txid, 0)),
            &spk,
            &[90_000, 90_000],
        );
        let parent_txid = parent.compute_txid();
        let graph =
            CanonicalUnspents::new(vec![(grandparent, Some(confirmed(100))), (parent, None)]);

        let in0 = graph
            .try_get_unspent(OutPoint::new(parent_txid, 0), plan.clone())
            .unwrap();
        let in1 = graph
            .try_get_unspent(OutPoint::new(parent_txid, 1), plan.clone())
            .unwrap();
        let in_confirmed = graph
            .try_get_unspent(OutPoint::new(grandparent_txid, 1), plan)
            .unwrap();
        assert!(
            in_confirmed.status().is_some(),
            "the grandparent output is confirmed"
        );

        // Regrouping must union ancestor indices and skip confirmed inputs.
        let candidates = InputCandidates::new([], [in0, in1, in_confirmed])
            .with_unconfirmed_ancestors(&graph)
            .expect("ancestors resolve")
            .regroup(group_by_spk());

        assert_eq!(candidates.coin_select_ancestors().len(), 1);
        assert_eq!(
            candidates.coin_select_ancestors()[0].dependent_candidates,
            vec![0]
        );
    }
}
