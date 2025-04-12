use alloc::vec::Vec;

use alloc::sync::Arc;

use bitcoin::{psbt, OutPoint, Sequence, Transaction, TxOut, Txid};
use miniscript::{bitcoin, plan::Plan};

use crate::{collections::HashMap, Input, InputStatus, RbfSet};

/// Tx with confirmation status.
pub type TxWithStatus<T> = (T, Option<InputStatus>);

/// Our canonical view of unspent outputs.
#[derive(Debug, Clone)]
pub struct CanonicalUnspents {
    txs: HashMap<Txid, Arc<Transaction>>,
    statuses: HashMap<Txid, InputStatus>,
    spends: HashMap<OutPoint, Txid>,
}

impl CanonicalUnspents {
    /// Construct.
    pub fn new<T>(canonical_txs: impl IntoIterator<Item = TxWithStatus<T>>) -> Self
    where
        T: Into<Arc<Transaction>>,
    {
        let mut txs = HashMap::new();
        let mut statuses = HashMap::new();
        let mut spends = HashMap::new();
        for (tx, status) in canonical_txs {
            let tx: Arc<Transaction> = tx.into();
            let txid = tx.compute_txid();
            spends.extend(tx.input.iter().map(|txin| (txin.previous_output, txid)));
            txs.insert(txid, tx);
            if let Some(status) = status {
                statuses.insert(txid, status);
            }
        }
        Self {
            txs,
            statuses,
            spends,
        }
    }

    /// TODO: This should return a descriptive error on why it failed.
    /// TODO: Error if trying to replace coinbase.
    pub fn extract_replacements(
        &mut self,
        replace: impl IntoIterator<Item = Txid>,
    ) -> Option<RbfSet> {
        let mut rbf_txs = replace
            .into_iter()
            .map(|txid| self.txs.get(&txid).cloned().map(|tx| (txid, tx)))
            .collect::<Option<HashMap<Txid, _>>>()?;

        // Remove txs in this set which have ancestors of other members of this set.
        let mut to_remove_from_rbf_txs = Vec::<Txid>::new();
        let mut to_remove_stack = rbf_txs
            .iter()
            .map(|(txid, tx)| (*txid, tx.clone()))
            .collect::<Vec<_>>();
        while let Some((txid, tx)) = to_remove_stack.pop() {
            if to_remove_from_rbf_txs.contains(&txid) {
                continue;
            }
            for vout in 0..tx.output.len() as u32 {
                let op = OutPoint::new(txid, vout);
                if let Some(next_txid) = self.spends.get(&op) {
                    if let Some(next_tx) = self.txs.get(next_txid) {
                        to_remove_from_rbf_txs.push(*next_txid);
                        to_remove_stack.push((*next_txid, next_tx.clone()));
                    }
                }
            }
        }
        for txid in &to_remove_from_rbf_txs {
            rbf_txs.remove(txid);
        }

        // Find prev outputs of all txs in the set.
        // Fail when on prev output is not found. We need to use the prevouts to determine fee fr
        // rbf!
        let prev_txouts = rbf_txs
            .values()
            .flat_map(|tx| &tx.input)
            .map(|txin| txin.previous_output)
            .map(|op| -> Option<(OutPoint, TxOut)> {
                let txout = self
                    .txs
                    .get(&op.txid)
                    .and_then(|tx| tx.output.get(op.vout as usize))
                    .cloned()?;
                Some((op, txout))
            })
            .collect::<Option<HashMap<_, _>>>()?;

        // Remove rbf txs (and their descendants) from canoncial unspents.
        let to_remove_from_canoncial_unspents = rbf_txs.keys().chain(&to_remove_from_rbf_txs);
        for txid in to_remove_from_canoncial_unspents {
            if let Some(tx) = self.txs.remove(txid) {
                self.statuses.remove(txid);
                for txin in &tx.input {
                    self.spends.remove(&txin.previous_output);
                }
            }
        }

        RbfSet::new(rbf_txs.into_values(), prev_txouts)
    }

    /// Whether outpoint is a leaf (unspent).
    pub fn is_unspent(&self, outpoint: OutPoint) -> bool {
        if self.spends.contains_key(&outpoint) {
            return false;
        }
        match self.txs.get(&outpoint.txid) {
            Some(tx) => {
                let vout: usize = outpoint.vout.try_into().expect("vout must fit into usize");
                vout < tx.output.len()
            }
            None => false,
        }
    }

    /// Try get leaf (unspent) of given `outpoint`.
    pub fn try_get_unspent(&self, outpoint: OutPoint, plan: Plan) -> Option<Input> {
        if self.spends.contains_key(&outpoint) {
            return None;
        }
        let prev_tx = Arc::clone(self.txs.get(&outpoint.txid)?);
        Input::from_prev_tx(
            plan,
            prev_tx,
            outpoint.vout.try_into().expect("vout must fit into usize"),
            self.statuses.get(&outpoint.txid).cloned(),
        )
        .ok()
    }

    /// Try get leaves of given `outpoints`.
    pub fn try_get_unspents<'a, O>(&'a self, outpoints: O) -> impl Iterator<Item = Input> + 'a
    where
        O: IntoIterator<Item = (OutPoint, Plan)>,
        O::IntoIter: 'a,
    {
        outpoints
            .into_iter()
            .filter_map(|(op, plan)| self.try_get_unspent(op, plan))
    }

    /// Try get foreign leaf.
    /// TODO: Check psbt_input data with our own prev tx data.
    /// TODO: Create `try_get_foreign_leaves` method.
    pub fn try_get_foreign_unspent(
        &self,
        outpoint: OutPoint,
        sequence: Sequence,
        psbt_input: psbt::Input,
        satisfaction_weight: usize,
    ) -> Option<Input> {
        if self.spends.contains_key(&outpoint) {
            return None;
        }
        let prev_tx = Arc::clone(self.txs.get(&outpoint.txid)?);
        let output_index: usize = outpoint.vout.try_into().expect("vout must fit into usize");
        let _txout = prev_tx.output.get(output_index)?;
        let status = self.statuses.get(&outpoint.txid).cloned();
        Input::from_psbt_input(outpoint, sequence, psbt_input, satisfaction_weight, status)
    }
}
