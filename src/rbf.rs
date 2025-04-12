use alloc::sync::Arc;
use core::fmt::Display;

use alloc::vec::Vec;
use bitcoin::{absolute, Amount, OutPoint, Transaction, TxOut, Txid};
use miniscript::bitcoin;

use crate::collections::{HashMap, HashSet};
use crate::{CanonicalUnspents, Input, RbfParams};

/// Set of txs to replace.
pub struct RbfSet {
    txs: HashMap<Txid, Arc<Transaction>>,
    prev_txouts: HashMap<OutPoint, TxOut>,
}

/// Occurs when the given original tx has no input spend that is still available for spending.
#[derive(Debug)]
pub struct OriginalTxHasNoInputsAvailable {
    /// Original txid.
    pub txid: Txid,
}

impl Display for OriginalTxHasNoInputsAvailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "original tx {} has no input spend that is still available",
            self.txid
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OriginalTxHasNoInputsAvailable {}

impl RbfSet {
    /// Create.
    ///
    /// Returns `None` if we have missing `prev_txouts` for the `txs`.
    ///
    /// Do not include transactions in `txs` that are descendants of transactions that are already
    /// in `txs`.
    pub fn new<T, O>(txs: T, prev_txouts: O) -> Option<Self>
    where
        T: IntoIterator,
        T::Item: Into<Arc<Transaction>>,
        O: IntoIterator<Item = (OutPoint, TxOut)>,
    {
        let set = Self {
            txs: txs
                .into_iter()
                .map(|tx| {
                    let tx: Arc<Transaction> = tx.into();
                    (tx.compute_txid(), tx)
                })
                .collect(),
            prev_txouts: prev_txouts.into_iter().collect(),
        };
        let no_missing_previous_txouts = set
            .txs
            .values()
            .flat_map(|tx| tx.input.iter().map(|txin| txin.previous_output))
            .all(|op: OutPoint| set.prev_txouts.contains_key(&op));
        if no_missing_previous_txouts {
            Some(set)
        } else {
            None
        }
    }

    /// Txids of the original txs that are to be replaced.
    pub fn txids(&self) -> impl ExactSizeIterator<Item = Txid> + '_ {
        self.txs.keys().copied()
    }

    /// Contains tx.
    pub fn contains_tx(&self, txid: Txid) -> bool {
        self.txs.contains_key(&txid)
    }

    /// Filters input candidates according to rule 2.
    ///
    /// According to rule 2, we cannot spend unconfirmed txs in the replacement unless it
    /// was a spend that was already part of the original tx.
    pub fn candidate_filter(&self, tip_height: absolute::Height) -> impl Fn(&Input) -> bool + '_ {
        let prev_spends = self
            .txs
            .values()
            .flat_map(|tx| {
                tx.input
                    .iter()
                    .map(|txin| txin.previous_output)
                    .collect::<Vec<_>>()
            })
            .collect::<HashSet<OutPoint>>();
        move |input| {
            prev_spends.contains(&input.prev_outpoint()) || input.confirmations(tip_height) > 0
        }
    }

    /// Tries to find the largest input per original tx.
    ///
    /// The returned outpoints can be used to create the `must_select` inputs to pass into
    /// `InputCandidates`. This guarantees that the all transactions within this set gets replaced.
    pub fn must_select_largest_input_of_each_original_tx(
        &self,
        canon_utxos: &CanonicalUnspents,
    ) -> Result<HashSet<OutPoint>, OriginalTxHasNoInputsAvailable> {
        let mut must_select = HashSet::new();

        for original_tx in self.txs.values() {
            let mut largest_value = Amount::ZERO;
            let mut largest_spend = Option::<OutPoint>::None;
            let original_tx_spends = original_tx.input.iter().map(|txin| txin.previous_output);
            for spend in original_tx_spends {
                // If this spends from another original tx , we do not consider it as replacing
                // the parent will replace this one.
                if self.txs.contains_key(&spend.txid) {
                    continue;
                }
                let txout = self.prev_txouts.get(&spend).expect("must have prev txout");

                // not available
                if !canon_utxos.is_unspent(spend) {
                    continue;
                }

                if txout.value > largest_value {
                    largest_value = txout.value;
                    largest_spend = Some(spend);
                }
            }
            let largest_spend = largest_spend.ok_or(OriginalTxHasNoInputsAvailable {
                txid: original_tx.compute_txid(),
            })?;
            must_select.insert(largest_spend);
        }

        Ok(must_select)
    }

    fn _fee(&self, tx: &Transaction) -> Amount {
        let output_sum: Amount = tx.output.iter().map(|txout| txout.value).sum();
        let input_sum: Amount = tx
            .input
            .iter()
            .map(|txin| {
                self.prev_txouts
                    .get(&txin.previous_output)
                    .expect("prev output must exist")
                    .value
            })
            .sum();
        input_sum - output_sum
    }

    /// Coin selector RBF parameters.
    pub fn selector_rbf_params(&self) -> RbfParams {
        RbfParams::new(self.txs.values().map(|tx| (tx.as_ref(), self._fee(tx))))
    }
}
