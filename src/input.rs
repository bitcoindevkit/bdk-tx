use std::{sync::Arc, vec::Vec};

use bdk_coin_select::TXIN_BASE_WEIGHT;
use bitcoin::transaction::OutputsIndexError;
use miniscript::bitcoin;
use miniscript::bitcoin::{OutPoint, Transaction, TxOut};
use miniscript::plan::Plan;

/// Single-input plan.
#[derive(Debug, Clone)]
pub struct Input {
    outpoint: OutPoint,
    txout: TxOut,
    tx: Option<Arc<Transaction>>,
    plan: Plan,
}

impl From<(Plan, OutPoint, TxOut)> for Input {
    fn from((plan, prev_outpoint, prev_txout): (Plan, OutPoint, TxOut)) -> Self {
        Self::from_prev_txout(plan, prev_outpoint, prev_txout)
    }
}

impl<T> TryFrom<(Plan, T, usize)> for Input
where
    T: Into<Arc<Transaction>>,
{
    type Error = OutputsIndexError;

    fn try_from((plan, prev_tx, output_index): (Plan, T, usize)) -> Result<Self, Self::Error> {
        Self::from_prev_tx(plan, prev_tx, output_index)
    }
}

impl Input {
    /// Create
    ///
    /// Returns `None` if `prev_output_index` does not exist in `prev_tx`.
    pub fn from_prev_tx<T>(
        plan: Plan,
        prev_tx: T,
        output_index: usize,
    ) -> Result<Self, OutputsIndexError>
    where
        T: Into<Arc<Transaction>>,
    {
        let tx: Arc<Transaction> = prev_tx.into();
        Ok(Self {
            outpoint: OutPoint::new(tx.compute_txid(), output_index as _),
            txout: tx.tx_out(output_index).cloned()?,
            tx: Some(tx),
            plan,
        })
    }

    /// Create
    pub fn from_prev_txout(plan: Plan, prev_outpoint: OutPoint, prev_txout: TxOut) -> Self {
        Self {
            outpoint: prev_outpoint,
            txout: prev_txout,
            tx: None,
            plan,
        }
    }

    /// Plan
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Previous outpoint.
    pub fn prev_outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Previous txout.
    pub fn prev_txout(&self) -> &TxOut {
        &self.txout
    }

    /// Previous tx (if any).
    pub fn prev_tx(&self) -> Option<&Transaction> {
        self.tx.as_ref().map(|tx| tx.as_ref())
    }

    /// To coin selection candidate.
    pub fn to_candidate(&self) -> bdk_coin_select::Candidate {
        bdk_coin_select::Candidate::new(
            self.prev_txout().value.to_sat(),
            self.plan.satisfaction_weight() as _,
            self.plan.witness_version().is_some(),
        )
    }
}

/// Input group. Cannot be empty.
#[derive(Debug, Clone)]
pub struct InputGroup(Vec<Input>);

impl InputGroup {
    /// From a single input.
    pub fn from_input(input: impl Into<Input>) -> Self {
        Self(vec![input.into()])
    }

    /// This return `None` to avoid creating empty input groups.
    pub fn from_inputs(inputs: impl IntoIterator<Item = impl Into<Input>>) -> Option<Self> {
        let group = inputs.into_iter().map(Into::into).collect::<Vec<Input>>();
        if group.is_empty() {
            None
        } else {
            Some(Self(group))
        }
    }

    /// Reference to the inputs of this group.
    pub fn inputs(&self) -> &Vec<Input> {
        &self.0
    }

    /// To coin selection candidate.
    pub fn to_candidate(&self) -> bdk_coin_select::Candidate {
        bdk_coin_select::Candidate {
            value: self
                .inputs()
                .iter()
                .map(|input| input.prev_txout().value.to_sat())
                .sum(),
            weight: self
                .inputs()
                .iter()
                .map(|input| TXIN_BASE_WEIGHT + input.plan().satisfaction_weight() as u64)
                .sum(),
            input_count: self.inputs().len(),
            is_segwit: self
                .inputs()
                .iter()
                .any(|input| input.plan().witness_version().is_some()),
        }
    }
}
