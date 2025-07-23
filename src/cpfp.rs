use crate::{CPFPParams, CanonicalUnspents, Input};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bdk_chain::tx_graph::CalculateFeeError;
use bdk_chain::Anchor;
use miniscript::bitcoin::{absolute::Height, Amount, FeeRate, OutPoint, Transaction, Txid, Weight};
use std::collections::HashSet;

/// Set of CPFP
#[derive(Debug, Clone)]
pub struct CPFPSet {
    /// Parent transactions and their unconfirmed ancestors.
    pub txs: BTreeMap<Txid, Arc<Transaction>>,
    /// Total fee of parent transactions and their ancestors.
    pub total_fee: Amount,
    /// Total weight of parent transactions and their ancestors.
    pub total_weight: Weight,
}

/// CPFP errors.
#[derive(Debug)]
pub enum CPFPError {
    /// A specified parent transaction ID does not exist in the transaction graph.
    MissingParent(Txid),
    /// A previous transaction (prevout) referenced by a parent transaction is missing.
    MissingPrevTx(Txid),
    /// An output referenced by an outpoint in a parent transaction is missing.
    MissingPrevTxOut(OutPoint),
    /// No parent transactions were provided for the CPFP operation.
    NoParents,
    /// A parent transaction has no unspent outputs available to spend in the CPFP transaction.
    NoUnspentOutput(Txid),
    /// The number of unconfirmed ancestors exceeds the Bitcoin protocol limit (25).
    ExcessUnconfirmedAncestor,
    /// An error occurred while calculating the fee for a transaction.
    CalculateFee(CalculateFeeError),
}

impl core::fmt::Display for CPFPError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingParent(txid) => write!(f, "parent transaction {} not found", txid),
            Self::MissingPrevTx(txid) => write!(f, "previous transaction {} not found", txid),
            Self::MissingPrevTxOut(outpoint) => write!(f, "previous output {} not found", outpoint),
            Self::NoParents => write!(f, "no parent transactions provided"),
            Self::ExcessUnconfirmedAncestor => write!(f, "too many unconfirmed ancestor"),
            Self::NoUnspentOutput(txid) => {
                write!(f, "no unspent output found for parent transaction {}", txid)
            }
            Self::CalculateFee(err) => write!(f, "failed to calculate fee: {}", err),
        }
    }
}

impl From<CalculateFeeError> for CPFPError {
    fn from(err: CalculateFeeError) -> Self {
        CPFPError::CalculateFee(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CPFPError {}

impl CPFPSet {
    /// Create a new CPFPSet from parent transactions and their ancestors.
    pub fn new(
        parent_txids: impl IntoIterator<Item = Txid>,
        graph: &bdk_chain::TxGraph,
        tip_height: Height,
    ) -> Result<Self, CPFPError> {
        let mut parent_fee = Amount::ZERO;
        let mut parent_weight = Weight::ZERO;

        let mut txs: BTreeMap<Txid, Arc<Transaction>> = BTreeMap::new();

        let parent_txids: Vec<Txid> = parent_txids.into_iter().collect();

        for txid in parent_txids {
            let mut stack = vec![txid];
            while let Some(current_txid) = stack.pop() {
                if let Some(tx_node) = graph.get_tx_node(current_txid) {
                    // Check if transaction is unconfirmed
                    let is_unconfirmed = tx_node.anchors.is_empty()
                        || tx_node.anchors.iter().all(|anchor| {
                            anchor.anchor_block().height > tip_height.to_consensus_u32()
                        });

                    if is_unconfirmed {
                        // Calculate fees and weights for all unconfirmed ancestors
                        let tx = tx_node.tx;
                        parent_fee += graph.calculate_fee(&tx)?;
                        parent_weight += tx.weight();
                        txs.insert(txid, tx.clone());

                        for input in &tx.input {
                            stack.push(input.previous_output.txid);
                        }
                    }
                } else {
                    return Err(CPFPError::MissingParent(txid));
                }
            }
        }

        const MAX_ANCESTORS: usize = 25;
        if txs.len() > MAX_ANCESTORS {
            return Err(CPFPError::NoParents);
        }

        Ok(Self {
            txs,
            total_fee: parent_fee,
            total_weight: parent_weight,
        })
    }

    /// Select the largest unspent output for each parent transaction.
    pub fn must_select_largest_input_of_each_parent(
        &self,
        canon_utxos: &CanonicalUnspents,
    ) -> Result<HashSet<OutPoint>, CPFPError> {
        let mut must_select = HashSet::new();

        for (txid, tx) in &self.txs {
            let outpoint = tx
                .output
                .iter()
                .enumerate()
                .map(|(vout, _)| OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                })
                .filter(|op| canon_utxos.is_unspent(*op))
                .max_by_key(|op| {
                    canon_utxos
                        .get_tx(&op.txid)
                        .and_then(|tx| tx.output.get(op.vout as usize))
                        .map(|txout| txout.value)
                        .unwrap_or(Amount::ZERO)
                })
                .ok_or_else(|| CPFPError::NoUnspentOutput(*txid))?;

            must_select.insert(outpoint);
        }

        Ok(must_select)
    }

    /// Filter input for candidates
    pub fn candidate_filter<'a>(
        &'a self,
        canon_utxos: &'a CanonicalUnspents,
        tip_height: Height,
    ) -> impl Fn(&Input) -> bool + 'a {
        let parent_outpoints = self
            .txs
            .values()
            .flat_map(|tx| tx.input.iter().map(|txin| txin.previous_output))
            .collect::<HashSet<OutPoint>>();

        move |input: &Input| {
            if parent_outpoints.contains(&input.prev_outpoint()) {
                return true;
            }

            input.confirmations(tip_height) > 0
                || canon_utxos
                    .get_spend(&input.prev_outpoint())
                    .map_or(false, |txid| self.txs.contains_key(txid))
        }
    }

    /// Generate CPFP parameters for coin selection.
    pub fn selector_cpfp_params(&self, target_feerate: FeeRate) -> CPFPParams {
        CPFPParams::new(
            self.txs.keys().cloned(),
            target_feerate,
            self.total_fee,
            self.total_weight,
        )
    }
}
