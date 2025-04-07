use std::{sync::Arc, vec::Vec};

use bitcoin::constants::COINBASE_MATURITY;
use bitcoin::transaction::OutputsIndexError;
use bitcoin::{absolute, relative, Amount};
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
    /// Helper method.
    pub fn new(height: u32, time: u64) -> Result<Self, absolute::ConversionError> {
        Ok(Self {
            height: absolute::Height::from_consensus(height)?,
            time: absolute::Time::from_consensus(time as _)?,
        })
    }
}

#[derive(Debug, Clone)]
enum PlanOrPsbtInput {
    Plan(Plan),
    PsbtInput {
        psbt_input: bitcoin::psbt::Input,
        sequence: bitcoin::Sequence,
        absolute_timelock: absolute::LockTime,
        satisfaction_weight: usize,
    },
}

impl PlanOrPsbtInput {
    /// Returns `None` if input index does not exist or input is not finalized.
    ///
    /// TODO: Check whether satisfaction_weight calculations are correct.
    /// TODO: Return an error type: out of bounds, not finalized, etc.
    ///
    /// # WHy do we only support finalized psbt inputs?
    ///
    /// There is no mulit-party tx building protocol that requires choosing from foreign,
    /// non-finalized PSBT inputs.
    fn from_finalized_psbt(psbt: &bitcoin::Psbt, input_index: usize) -> Option<Self> {
        let psbt_input = psbt.inputs.get(input_index).cloned()?;
        let input = psbt.unsigned_tx.input.get(input_index)?;
        let absolute_timelock = psbt.unsigned_tx.lock_time;

        if psbt_input.final_script_witness.is_none() && psbt_input.final_script_sig.is_none() {
            return None;
        }

        let mut temp_txin = input.clone();
        if let Some(s) = &psbt_input.final_script_sig {
            temp_txin.script_sig = s.clone();
        }
        if let Some(w) = &psbt_input.final_script_witness {
            temp_txin.witness = w.clone();
        }
        let satisfaction_weight = temp_txin.segwit_weight().to_wu() as usize;

        Some(Self::PsbtInput {
            psbt_input,
            sequence: input.sequence,
            absolute_timelock,
            satisfaction_weight,
        })
    }

    pub fn plan(&self) -> Option<&Plan> {
        match self {
            PlanOrPsbtInput::Plan(plan) => Some(plan),
            _ => None,
        }
    }

    pub fn psbt_input(&self) -> Option<&bitcoin::psbt::Input> {
        match self {
            PlanOrPsbtInput::PsbtInput { psbt_input, .. } => Some(psbt_input),
            _ => None,
        }
    }

    pub fn absolute_timelock(&self) -> Option<absolute::LockTime> {
        match self {
            PlanOrPsbtInput::Plan(plan) => plan.absolute_timelock,
            PlanOrPsbtInput::PsbtInput {
                absolute_timelock, ..
            } => Some(*absolute_timelock),
        }
    }

    pub fn relative_timelock(&self) -> Option<relative::LockTime> {
        match self {
            PlanOrPsbtInput::Plan(plan) => plan.relative_timelock,
            PlanOrPsbtInput::PsbtInput { sequence, .. } => sequence.to_relative_lock_time(),
        }
    }

    pub fn sequence(&self) -> Option<bitcoin::Sequence> {
        match self {
            PlanOrPsbtInput::Plan(plan) => plan.relative_timelock.map(|rtl| rtl.to_sequence()),
            PlanOrPsbtInput::PsbtInput { sequence, .. } => Some(*sequence),
        }
    }

    pub fn satisfaction_weight(&self) -> usize {
        match self {
            PlanOrPsbtInput::Plan(plan) => plan.satisfaction_weight(),
            PlanOrPsbtInput::PsbtInput {
                satisfaction_weight,
                ..
            } => *satisfaction_weight,
        }
    }

    pub fn is_segwit(&self) -> bool {
        match self {
            PlanOrPsbtInput::Plan(plan) => plan.witness_version().is_some(),
            PlanOrPsbtInput::PsbtInput { psbt_input, .. } => {
                psbt_input.final_script_witness.is_some()
            }
        }
    }

    pub fn tx(&self) -> Option<&Transaction> {
        match self {
            PlanOrPsbtInput::Plan(_) => None,
            PlanOrPsbtInput::PsbtInput { psbt_input, .. } => psbt_input.non_witness_utxo.as_ref(),
        }
    }
}

/// Single-input plan.
#[derive(Debug, Clone)]
pub struct Input {
    outpoint: OutPoint,
    txout: TxOut,
    tx: Option<Arc<Transaction>>,
    plan: PlanOrPsbtInput,
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
            plan: PlanOrPsbtInput::Plan(plan),
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
            plan: PlanOrPsbtInput::Plan(plan),
            status,
            is_coinbase,
        }
    }

    /// Create
    ///
    /// TODO: Return error type: out of bounds, not finalized, etc.
    pub fn from_finalized_psbt_input(
        psbt: &bitcoin::Psbt,
        input_index: usize,
        status: Option<InputStatus>,
        is_coinbase: bool,
    ) -> Option<Self> {
        let txin = psbt.unsigned_tx.input.get(input_index)?;
        let psbt_input = psbt.inputs.get(input_index).cloned()?;
        let plan = PlanOrPsbtInput::from_finalized_psbt(psbt, input_index)?;
        Some(Self {
            outpoint: txin.previous_output,
            txout: psbt_input.witness_utxo.clone().or(psbt_input
                .non_witness_utxo
                .clone()
                .and_then(|tx| tx.output.get(input_index).cloned()))?,
            tx: psbt_input.non_witness_utxo.map(Arc::new),
            plan,
            status,
            is_coinbase,
        })
    }

    /// Plan
    pub fn plan(&self) -> Option<&Plan> {
        self.plan.plan()
    }

    /// Psbt input
    pub fn psbt_input(&self) -> Option<&bitcoin::psbt::Input> {
        self.plan.psbt_input()
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
        self.tx.as_ref().map(|tx| tx.as_ref()).or(self.plan.tx())
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
        if let Some(locktime) = self.plan.absolute_timelock() {
            if !locktime.is_satisfied_by(tip_height, tip_time) {
                return true;
            }
        }
        if let Some(locktime) = self.plan.relative_timelock() {
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

    /// Absolute timelock.
    pub fn absolute_timelock(&self) -> Option<absolute::LockTime> {
        self.plan.absolute_timelock()
    }

    /// Relative timelock.
    pub fn relative_timelock(&self) -> Option<relative::LockTime> {
        self.plan.relative_timelock()
    }

    /// Sequence value.
    pub fn sequence(&self) -> Option<bitcoin::Sequence> {
        self.plan.sequence()
    }

    /// In weight units.
    ///
    /// TODO: Describe what fields are actually included in this calculation.
    pub fn satisfaction_weight(&self) -> u64 {
        self.plan
            .satisfaction_weight()
            .try_into()
            .expect("usize must fit into u64")
    }

    /// Is segwit.
    pub fn is_segwit(&self) -> bool {
        self.plan.is_segwit()
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

    /// Total value of all contained inputs.
    pub fn value(&self) -> Amount {
        self.inputs().iter().map(|input| input.txout.value).sum()
    }

    /// Total weight of all contained inputs (excluding input count varint).
    pub fn weight(&self) -> u64 {
        /// Txin "base" fields include `outpoint` (32+4) and `nSequence` (4) and 1 byte for the scriptSig
        /// length.
        pub const TXIN_BASE_WEIGHT: u64 = (32 + 4 + 4 + 1) * 4;
        self.inputs()
            .iter()
            .map(|input| TXIN_BASE_WEIGHT + input.satisfaction_weight())
            .sum()
    }

    /// Input count.
    pub fn input_count(&self) -> usize {
        self.inputs().len()
    }

    /// Whether any contained input is a segwit spend.
    pub fn is_segwit(&self) -> bool {
        self.inputs().iter().any(|input| input.is_segwit())
    }
}
