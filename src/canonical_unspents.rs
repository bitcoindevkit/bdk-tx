use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use bitcoin::{psbt, OutPoint, Sequence, Transaction, TxOut, Txid};
use miniscript::{bitcoin, plan::Plan};

use crate::{
    collections::HashMap, input::CoinbaseMismatch, ConfirmationStatus, FromPsbtInputError, Input,
    RbfSet,
};

/// Tx with confirmation status.
pub type TxWithStatus<T> = (T, Option<ConfirmationStatus>);

/// Our canonical view of unspent outputs.
#[derive(Debug, Clone)]
pub struct CanonicalUnspents {
    txs: HashMap<Txid, Arc<Transaction>>,
    statuses: HashMap<Txid, ConfirmationStatus>,
    spends: HashMap<OutPoint, Txid>,
}

impl CanonicalUnspents {
    /// Construct [`CanonicalUnspents`] from an iterator of txs with confirmation status.
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

    /// Extract txs in the set of `replace` from the canonical view of unspents.
    ///
    /// Returns the [`RbfSet`] if the replacements are valid and succesfully extracted.
    /// Errors if the replacements cannot be extracted (e.g. due to missing data).
    pub fn extract_replacements(
        &mut self,
        replace: impl IntoIterator<Item = Txid>,
    ) -> Result<RbfSet, ExtractReplacementsError> {
        let mut rbf_txs = replace
            .into_iter()
            .map(|txid| -> Result<(Txid, Arc<Transaction>), _> {
                let tx = self
                    .txs
                    .get(&txid)
                    .cloned()
                    .ok_or(ExtractReplacementsError::TransactionNotFound(txid))?;
                if tx.is_coinbase() {
                    return Err(ExtractReplacementsError::CannotReplaceCoinbase);
                }
                Ok((tx.compute_txid(), tx))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

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
        // Fail when a prev output is not found. We need to use the prevouts to determine fee for RBF!
        let prev_txouts = rbf_txs
            .values()
            .flat_map(|tx| &tx.input)
            .map(|txin| txin.previous_output)
            .map(|op| -> Result<(OutPoint, TxOut), _> {
                let txout = self
                    .txs
                    .get(&op.txid)
                    .and_then(|tx| tx.output.get(op.vout as usize))
                    .cloned()
                    .ok_or(ExtractReplacementsError::PreviousOutputNotFound(op))?;
                Ok((op, txout))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        // Remove rbf txs (and their descendants) from canonical unspents.
        let to_remove_from_canonical_unspents = rbf_txs.keys().chain(&to_remove_from_rbf_txs);
        for txid in to_remove_from_canonical_unspents {
            if let Some(tx) = self.txs.remove(txid) {
                self.statuses.remove(txid);
                for txin in &tx.input {
                    self.spends.remove(&txin.previous_output);
                }
            }
        }

        Ok(
            RbfSet::new(rbf_txs.into_values(), prev_txouts)
                .expect("must not have missing prevouts"),
        )
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

    /// Try get foreign leaf (unspent).
    pub fn try_get_foreign_unspent(
        &self,
        outpoint: OutPoint,
        sequence: Sequence,
        psbt_input: psbt::Input,
        satisfaction_weight: usize,
        is_coinbase: bool,
    ) -> Result<Input, GetForeignUnspentError> {
        if !self.is_unspent(outpoint) {
            return Err(GetForeignUnspentError::OutputIsAlreadySpent(outpoint));
        }
        if let Some(prev_tx) = self.txs.get(&outpoint.txid) {
            let non_witness_utxo = psbt_input.non_witness_utxo.as_ref();
            if non_witness_utxo.is_some() && non_witness_utxo != Some(prev_tx) {
                return Err(GetForeignUnspentError::UtxoMismatch(outpoint));
            }
            let witness_utxo = psbt_input.witness_utxo.as_ref();
            if witness_utxo.is_some()
                && psbt_input.witness_utxo.as_ref() != prev_tx.output.get(outpoint.vout as usize)
            {
                return Err(GetForeignUnspentError::UtxoMismatch(outpoint));
            }
            if is_coinbase != prev_tx.is_coinbase() {
                return Err(GetForeignUnspentError::Coinbase(CoinbaseMismatch {
                    txid: outpoint.txid,
                    expected: is_coinbase,
                    got: prev_tx.is_coinbase(),
                }));
            }
        }
        let status = self.statuses.get(&outpoint.txid).cloned();
        Input::from_psbt_input(
            outpoint,
            sequence,
            psbt_input,
            satisfaction_weight,
            status,
            is_coinbase,
        )
        .map_err(GetForeignUnspentError::FromPsbtInput)
    }

    /// Try get foreign leaves (unspent).
    pub fn try_get_foreign_unspents<'a, O>(
        &'a self,
        outpoints: O,
    ) -> impl Iterator<Item = Result<Input, GetForeignUnspentError>> + 'a
    where
        O: IntoIterator<Item = (OutPoint, Sequence, psbt::Input, usize, bool)>,
        O::IntoIter: 'a,
    {
        outpoints
            .into_iter()
            .map(|(op, seq, input, sat_wu, is_coinbase)| {
                self.try_get_foreign_unspent(op, seq, input, sat_wu, is_coinbase)
            })
    }
}

/// Canonical unspents error
#[derive(Debug)]
pub enum GetForeignUnspentError {
    /// Invalid parameter for `is_coinbase`
    Coinbase(CoinbaseMismatch),
    /// Error creating an input from a PSBT input
    FromPsbtInput(FromPsbtInputError),
    /// Cannot get unspent input from output that is already spent
    OutputIsAlreadySpent(OutPoint),
    /// The witness or non-witness UTXO in the PSBT input does not match the expected outpoint
    UtxoMismatch(OutPoint),
}

impl fmt::Display for GetForeignUnspentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coinbase(err) => write!(f, "{err}"),
            Self::FromPsbtInput(err) => write!(f, "{err}"),
            Self::OutputIsAlreadySpent(op) => {
                write!(f, "outpoint is already spent: {op}")
            }
            Self::UtxoMismatch(op) => write!(f, "UTXO mismatch: {op}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetForeignUnspentError {}

/// Error when attempting to do [`extract_replacements`](CanonicalUnspents::extract_replacements).
#[derive(Debug)]
pub enum ExtractReplacementsError {
    /// Transaction not found in canonical unspents
    TransactionNotFound(Txid),
    /// Cannot replace a coinbase transaction
    CannotReplaceCoinbase,
    /// Previous output not found for input
    PreviousOutputNotFound(OutPoint),
}

impl fmt::Display for ExtractReplacementsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionNotFound(txid) => write!(f, "transaction not found: {txid}"),
            Self::CannotReplaceCoinbase => write!(f, "cannot replace a coinbase transaction"),
            Self::PreviousOutputNotFound(op) => write!(f, "previous output not found: {op}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractReplacementsError {}
