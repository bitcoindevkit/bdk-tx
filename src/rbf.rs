use core::fmt::Display;

use alloc::vec::Vec;
use bitcoin::{absolute, Amount, OutPoint, Transaction, TxOut, Txid};
use miniscript::bitcoin;

use crate::collections::{HashMap, HashSet};
use crate::{InputCandidates, InputGroup, RbfParams};

/// Set of txs to replace.
pub struct RbfSet<'t> {
    txs: HashMap<Txid, &'t Transaction>,
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

impl<'t> RbfSet<'t> {
    /// Create.
    ///
    /// Returns `None` if we have missing `prev_txouts` for the `txs`.
    ///
    /// If any transactions in `txs` are ancestors or descendants of others in `txs`, be sure to
    /// include any intermediary transactions needed to resolve those dependencies.
    ///
    /// TODO: Error if trying to replace coinbase.
    pub fn new<T, O>(txs: T, prev_txouts: O) -> Option<Self>
    where
        T: IntoIterator<Item = &'t Transaction>,
        O: IntoIterator<Item = (OutPoint, TxOut)>,
    {
        let set = Self {
            txs: txs.into_iter().map(|tx| (tx.compute_txid(), tx)).collect(),
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
    ///
    /// Used for modifying canonicalization to exclude the original txs.
    pub fn txids(&self) -> impl ExactSizeIterator<Item = Txid> + '_ {
        self.txs.keys().copied()
    }

    /// Filters input candidates according to rule 2.
    ///
    /// According to rule 2, we cannot spend unconfirmed txs in the replacement unless it
    /// was a spend that was already part of the original tx.
    pub fn candidate_filter(
        &self,
        tip_height: absolute::Height,
    ) -> impl Fn(&InputGroup) -> bool + '_ {
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
        move |group| {
            group.all(|input| {
                prev_spends.contains(&input.prev_outpoint()) || input.confirmations(tip_height) > 0
            })
        }
    }

    /// Returns a policy that selects the largest input of every original tx.
    ///
    /// This guarantees that the txs are replaced.
    pub fn must_select_largest_input_per_tx(
        &self,
    ) -> impl FnMut(&InputCandidates) -> Result<HashSet<OutPoint>, OriginalTxHasNoInputsAvailable> + '_
    {
        |input_candidates| {
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
                    if !input_candidates.contains(spend) {
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
    }

    fn _fee(&self, tx: &'t Transaction) -> Amount {
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
        RbfParams::new(self.txs.values().map(|tx| (*tx, self._fee(tx))))
    }
}
