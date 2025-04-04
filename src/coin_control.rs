use core::{convert::Infallible, fmt::Display};

use crate::{
    collections::{BTreeMap, HashMap, HashSet},
    Input, InputCandidates, InputGroup, InputStatus,
};
use alloc::vec::Vec;
use bdk_chain::{BlockId, ChainOracle, ConfirmationBlockTime, TxGraph};
use bitcoin::{absolute, OutPoint, Txid};
use miniscript::{bitcoin, plan::Plan};

/// Coin control.
///
/// Builds the set of input candidates.
/// Tries to ensure that all candidates are part of a consistent view of history.
///
/// Does not check ownership of coins before placing them in candidate set.
#[must_use]
pub struct CoinControl<'g, C> {
    /// Chain Oracle.
    chain: &'g C,
    /// Consistent chain tip.
    chain_tip: BlockId,

    /// Tx graph.
    tx_graph: &'g TxGraph<ConfirmationBlockTime>,
    /// Stops the caller from adding inputs (local or foreign) that are definitely not canonical.
    ///
    /// This is not a perfect check for callers that add foreign inputs, or if the caller's
    /// `TxGraph` has incomplete information. However, this will stop most unintended double-spends
    /// and/or money-printing-txs.
    canonical: HashSet<Txid>,

    /// All candidates.
    candidate_inputs: HashMap<OutPoint, Input>,
    ///// Maintains candidate order.
    //pub order: VecDeque<OutPoint>,
    /// Excluded stuff goes here.
    excluded_inputs: HashMap<OutPoint, ExcludeInputReason>,
}

/// ExcludedReason.
#[derive(Debug, Clone)]
pub enum ExcludeInputReason {
    /// Cannot find outpoint in the graph.
    DoesNotExist,
    /// Input already spent.
    AlreadySpent,
    /// Input spends from an output that is not canonical.
    NotCanonical,
}

impl Display for ExcludeInputReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExcludeInputReason::DoesNotExist => {
                write!(f, "outpoint does not exist")
            }
            ExcludeInputReason::AlreadySpent => {
                write!(f, "including this input is a double spend")
            }
            ExcludeInputReason::NotCanonical => {
                write!(f, "outpoint is in tx that is not canonical")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExcludeInputReason {}

impl<'g, C: ChainOracle<Error = Infallible>> CoinControl<'g, C> {
    /// New
    ///
    /// TODO: Replace `to_exclude` with `CanonicalizationParams` when that is available.
    pub fn new(
        tx_graph: &'g TxGraph<ConfirmationBlockTime>,
        chain: &'g C,
        chain_tip: BlockId,
        replace: impl IntoIterator<Item = Txid>,
    ) -> Self {
        let mut canonical = tx_graph
            .canonical_iter(chain, chain_tip)
            .map(|r| r.expect("infallible"))
            .flat_map(|(txid, tx, _)| {
                tx.input
                    .iter()
                    .map(|txin| txin.previous_output.txid)
                    .chain([txid])
                    .collect::<Vec<_>>()
            })
            .collect::<HashSet<Txid>>();
        let exclude = replace
            .into_iter()
            .filter_map(|txid| tx_graph.get_tx(txid))
            .flat_map(|tx| {
                let txid = tx.compute_txid();
                tx_graph
                    .walk_descendants(txid, move |_, txid| Some(txid))
                    .chain(core::iter::once(txid))
                    .collect::<Vec<_>>()
            });
        for txid in exclude {
            canonical.remove(&txid);
        }
        Self {
            tx_graph,
            chain,
            canonical,
            chain_tip,
            candidate_inputs: HashMap::new(),
            excluded_inputs: HashMap::new(),
        }
    }

    /// Try include the given input.
    pub fn try_include_input(&mut self, outpoint: OutPoint, plan: Plan) -> &mut Self {
        match self._try_include_input(outpoint, plan) {
            Ok(_) => self.excluded_inputs.remove(&outpoint),
            Err(err) => self.excluded_inputs.insert(outpoint, err),
        };
        self
    }

    /// Try include the given inputs.
    pub fn try_include_inputs<I>(&mut self, inputs: I) -> &mut Self
    where
        I: IntoIterator<Item = (OutPoint, Plan)>,
    {
        for (outpoint, plan) in inputs {
            self.try_include_input(outpoint, plan);
        }
        self
    }

    fn _try_include_input(
        &mut self,
        outpoint: OutPoint,
        plan: Plan,
    ) -> Result<(), ExcludeInputReason> {
        let tx_node = self
            .tx_graph
            .get_tx_node(outpoint.txid)
            .ok_or(ExcludeInputReason::DoesNotExist)?;
        if !self.canonical.contains(&tx_node.txid) {
            return Err(ExcludeInputReason::NotCanonical);
        }
        if self.is_spent(outpoint) {
            return Err(ExcludeInputReason::AlreadySpent);
        }

        let status = tx_node
            .anchors
            .iter()
            .find(|anchor| {
                self.chain
                    .is_block_in_chain(anchor.block_id, self.chain_tip)
                    .expect("infallible")
                    .unwrap_or(false)
            })
            .map(|anchor| InputStatus {
                height: absolute::Height::from_consensus(anchor.block_id.height)
                    .expect("height must not overflow"),
                time: absolute::Time::from_consensus(anchor.confirmation_time as u32)
                    .expect("time must not overflow"),
            });

        let input = Input::from_prev_tx(
            plan,
            tx_node.tx,
            outpoint.vout.try_into().expect("u32 must fit into usize"),
            status,
        )
        .map_err(|_| ExcludeInputReason::DoesNotExist)?;

        self.candidate_inputs.insert(outpoint, input);
        Ok(())
    }

    /// Whether the outpoint is spent already.
    ///
    /// Spent outputs cannot be candidates for coin selection.
    fn is_spent(&self, outpoint: OutPoint) -> bool {
        self.tx_graph
            .outspends(outpoint)
            .iter()
            .any(|txid| self.canonical.contains(txid))
    }

    /// Map of excluded inputs and their exclusion reasons.
    pub fn excluded(&self) -> &HashMap<OutPoint, ExcludeInputReason> {
        &self.excluded_inputs
    }

    /// Into candidates.
    pub fn into_candidates<G: Ord>(
        self,
        group_policy: impl Fn(&Input) -> G,
        filter_policy: impl Fn(&InputGroup) -> bool,
    ) -> InputCandidates {
        let mut group_map = BTreeMap::<G, InputGroup>::new();
        for input in self.candidate_inputs.into_values() {
            let group_key = group_policy(&input);
            use std::collections::btree_map::Entry;
            match group_map.entry(group_key) {
                Entry::Vacant(entry) => {
                    entry.insert(InputGroup::from_input(input));
                }
                Entry::Occupied(mut entry) => entry.get_mut().push(input),
            };
        }
        InputCandidates::new(None, group_map.into_values().filter(filter_policy))
    }
}

/// Default group policy.
pub fn group_by_spk() -> impl Fn(&Input) -> bitcoin::ScriptBuf {
    |input| input.prev_txout().script_pubkey.clone()
}

/// No grouping.
pub fn no_grouping() -> impl Fn(&Input) -> OutPoint {
    |input| input.prev_outpoint()
}

/// Filter out inputs that cannot be spent now.
pub fn filter_unspendable_now(
    tip_height: absolute::Height,
    tip_time: absolute::Time,
) -> impl Fn(&InputGroup) -> bool {
    move |group| group.is_spendable_now(tip_height, tip_time)
}

/// No filtering.
pub fn no_filtering() -> impl Fn(&InputGroup) -> bool {
    |_| true
}
