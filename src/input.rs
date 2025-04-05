use std::{sync::Arc, vec::Vec};

use bdk_coin_select::TXIN_BASE_WEIGHT;
use bitcoin::constants::COINBASE_MATURITY;
use bitcoin::transaction::OutputsIndexError;
use bitcoin::{absolute, relative};
use miniscript::bitcoin;
use miniscript::bitcoin::{OutPoint, Transaction, TxOut};
use miniscript::plan::Plan;

/// Confirmation status of a tx.
#[derive(Debug, Clone, Copy)]
pub struct InputStatus {
    /// Confirmation block height.
    pub height: absolute::Height,
    /// Confirmation block median time past.
    ///
    /// TODO: Currently BDK cannot fetch MTP time. We can pretend that the latest block time is the
    /// MTP time for now.
    pub time: absolute::Time,
}

impl InputStatus {
    /// New
    pub fn new(height: u32, time: u64) -> Result<Self, absolute::ConversionError> {
        Ok(Self {
            height: absolute::Height::from_consensus(height)?,
            time: absolute::Time::from_consensus(time as _)?,
        })
    }
}

/// Single-input plan.
#[derive(Debug, Clone)]
pub struct Input {
    outpoint: OutPoint,
    txout: TxOut,
    tx: Option<Arc<Transaction>>,
    plan: Plan,
    status: Option<InputStatus>,
    is_coinbase: bool,
}

impl Input {
    /// Create
    ///
    /// Returns `None` if `prev_output_index` does not exist in `prev_tx`.
    pub fn from_prev_tx<T>(
        plan: Plan,
        prev_tx: T,
        output_index: usize,
        status: Option<InputStatus>,
    ) -> Result<Self, OutputsIndexError>
    where
        T: Into<Arc<Transaction>>,
    {
        let tx: Arc<Transaction> = prev_tx.into();
        let is_coinbase = tx.is_coinbase();
        Ok(Self {
            outpoint: OutPoint::new(tx.compute_txid(), output_index as _),
            txout: tx.tx_out(output_index).cloned()?,
            tx: Some(tx),
            plan,
            status,
            is_coinbase,
        })
    }

    /// Create
    pub fn from_prev_txout(
        plan: Plan,
        prev_outpoint: OutPoint,
        prev_txout: TxOut,
        status: Option<InputStatus>,
        is_coinbase: bool,
    ) -> Self {
        Self {
            outpoint: prev_outpoint,
            txout: prev_txout,
            tx: None,
            plan,
            status,
            is_coinbase,
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

    /// Confirmation status.
    pub fn status(&self) -> Option<InputStatus> {
        self.status
    }

    /// Whether prev output resides in coinbase.
    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }

    /// Whether prev output is an immature coinbase output and cannot be spent in the next block.
    pub fn is_immature(&self, tip_height: absolute::Height) -> bool {
        if !self.is_coinbase {
            return false;
        }
        match self.status {
            Some(status) => {
                let age = tip_height
                    .to_consensus_u32()
                    .saturating_sub(status.height.to_consensus_u32());
                age + 1 < COINBASE_MATURITY
            }
            None => {
                debug_assert!(false, "coinbase should never be unconfirmed");
                true
            }
        }
    }

    /// Whether the output is still locked by timelock constraints and cannot be spent in the
    /// next block.
    pub fn is_timelocked(&self, tip_height: absolute::Height, tip_time: absolute::Time) -> bool {
        if let Some(locktime) = self.plan.absolute_timelock {
            if !locktime.is_satisfied_by(tip_height, tip_time) {
                return true;
            }
        }
        if let Some(locktime) = self.plan.relative_timelock {
            // TODO: Make sure this logic is right.
            let (relative_height, relative_time) = match self.status {
                Some(status) => {
                    let relative_height = tip_height
                        .to_consensus_u32()
                        .saturating_sub(status.height.to_consensus_u32());
                    let relative_time = tip_time
                        .to_consensus_u32()
                        .saturating_sub(status.time.to_consensus_u32());
                    (
                        relative::Height::from_height(
                            relative_height.try_into().unwrap_or(u16::MAX),
                        ),
                        relative::Time::from_seconds_floor(relative_time)
                            .unwrap_or(relative::Time::MAX),
                    )
                }
                None => (relative::Height::ZERO, relative::Time::ZERO),
            };
            if !locktime.is_satisfied_by(relative_height, relative_time) {
                return true;
            }
        }
        false
    }

    /// Whether this output can be spent now.
    pub fn is_spendable_now(&self, tip_height: absolute::Height, tip_time: absolute::Time) -> bool {
        !self.is_immature(tip_height) && !self.is_timelocked(tip_height, tip_time)
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

impl From<Input> for InputGroup {
    fn from(input: Input) -> Self {
        Self::from_input(input)
    }
}

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

    /// Consume the input group and return all inputs.
    pub fn into_inputs(self) -> Vec<Input> {
        self.0
    }

    /// Push input in group.
    pub fn push(&mut self, input: Input) {
        self.0.push(input);
    }

    /// Whether any contained inputs are immature.
    pub fn is_immature(&self, tip_height: absolute::Height) -> bool {
        self.0.iter().any(|input| input.is_immature(tip_height))
    }

    /// Whether any contained inputs are time locked.
    pub fn is_timelocked(&self, tip_height: absolute::Height, tip_time: absolute::Time) -> bool {
        self.0
            .iter()
            .any(|input| input.is_timelocked(tip_height, tip_time))
    }

    /// Whether all contained inputs are spendable now.
    pub fn is_spendable_now(&self, tip_height: absolute::Height, tip_time: absolute::Time) -> bool {
        self.0
            .iter()
            .all(|input| input.is_spendable_now(tip_height, tip_time))
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
