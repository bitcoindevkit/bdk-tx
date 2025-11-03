use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use core::fmt;

use bitcoin::constants::COINBASE_MATURITY;
use bitcoin::transaction::OutputsIndexError;
use bitcoin::{absolute, psbt, relative, Amount, Sequence, Txid};
use miniscript::bitcoin;
use miniscript::bitcoin::{OutPoint, Transaction, TxOut};
use miniscript::plan::Plan;

/// Confirmation status of a tx data.
#[derive(Debug, Clone, Copy)]
pub struct TxStatus {
    /// Confirmation block height.
    pub height: absolute::Height,
    /// Confirmation block median time past.
    ///
    /// TODO: Currently BDK cannot fetch MTP time. We can pretend that the latest block time is the
    /// MTP time for now.
    pub time: absolute::Time,
}

impl TxStatus {
    /// From consensus `height` and `time`.
    pub fn new(height: u32, time: u64) -> Result<Self, absolute::ConversionError> {
        Ok(Self {
            height: absolute::Height::from_consensus(height)?,
            // TODO: handle `.try_into::<u32>()`
            time: absolute::Time::from_consensus(time as _)?,
        })
    }
}

#[derive(Debug, Clone)]
enum PlanOrPsbtInput {
    Plan(Box<Plan>),
    PsbtInput {
        psbt_input: Box<psbt::Input>,
        sequence: Sequence,
        absolute_timelock: absolute::LockTime,
        satisfaction_weight: usize,
    },
}

impl PlanOrPsbtInput {
    /// From [`psbt::Input`].
    ///
    /// Errors if neither the witness- or non-witness UTXO are present in `psbt_input`.
    fn from_psbt_input(
        sequence: Sequence,
        psbt_input: psbt::Input,
        satisfaction_weight: usize,
    ) -> Result<Self, FromPsbtInputError> {
        // We require at least one of the witness or non-witness utxo
        if psbt_input.witness_utxo.is_none() && psbt_input.non_witness_utxo.is_none() {
            return Err(FromPsbtInputError::UtxoCheck);
        }
        Ok(Self::PsbtInput {
            psbt_input: Box::new(psbt_input),
            sequence,
            absolute_timelock: absolute::LockTime::ZERO,
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

/// Mismatch between the expected and actual value of [`Transaction::is_coinbase`].
#[derive(Debug, Clone)]
pub struct CoinbaseMismatch {
    /// txid
    pub txid: Txid,
    /// expected value of whether a tx is coinbase
    pub expected: bool,
    /// whether the actual tx is coinbase
    pub got: bool,
}

impl fmt::Display for CoinbaseMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid coinbase parameter for txid {}; expected `is_coinbase`: {}, found: {}",
            self.txid, self.expected, self.got
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CoinbaseMismatch {}

/// Error creating [`Input`] from a PSBT input
#[derive(Debug, Clone)]
pub enum FromPsbtInputError {
    /// Invalid `is_coinbase` parameter
    Coinbase(CoinbaseMismatch),
    /// Invalid outpoint
    InvalidOutPoint(OutPoint),
    /// The input's UTXO is missing or invalid
    UtxoCheck,
}

impl fmt::Display for FromPsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coinbase(err) => write!(f, "{err}"),
            Self::InvalidOutPoint(op) => {
                write!(f, "invalid outpoint: {op}")
            }
            Self::UtxoCheck => {
                write!(
                    f,
                    "one of the witness or non-witness utxo is missing or invalid"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromPsbtInputError {}

/// Single-input plan.
#[derive(Debug, Clone)]
pub struct Input {
    prev_outpoint: OutPoint,
    prev_txout: TxOut,
    prev_tx: Option<Arc<Transaction>>,
    plan: PlanOrPsbtInput,
    status: Option<TxStatus>,
    is_coinbase: bool,
}

impl Input {
    /// Create [`Input`] from a previous transaction.
    ///
    /// # Errors
    ///
    /// Returns `OutputsIndexError` if the previous txout is not found in `prev_tx`
    /// at `output_index`.
    pub fn from_prev_tx<T>(
        plan: Plan,
        prev_tx: T,
        output_index: usize,
        status: Option<TxStatus>,
    ) -> Result<Self, OutputsIndexError>
    where
        T: Into<Arc<Transaction>>,
    {
        let tx: Arc<Transaction> = prev_tx.into();
        let is_coinbase = tx.is_coinbase();
        Ok(Self {
            prev_outpoint: OutPoint::new(tx.compute_txid(), output_index as _),
            prev_txout: tx.tx_out(output_index).cloned()?,
            prev_tx: Some(tx),
            plan: PlanOrPsbtInput::Plan(Box::new(plan)),
            status,
            is_coinbase,
        })
    }

    /// Create [`Input`] from a previous txout and plan.
    pub fn from_prev_txout(
        plan: Plan,
        prev_outpoint: OutPoint,
        prev_txout: TxOut,
        status: Option<TxStatus>,
        is_coinbase: bool,
    ) -> Self {
        Self {
            prev_outpoint,
            prev_txout,
            prev_tx: None,
            plan: PlanOrPsbtInput::Plan(Box::new(plan)),
            status,
            is_coinbase,
        }
    }

    /// Create [`Input`] from a [`psbt::Input`].
    ///
    /// # Errors
    ///
    /// - If neither the witness or non-witness utxo are present in `psbt_input`.
    /// - If `prev_outpoint` doesn't agree with the previous transaction.
    /// - If the previous transaction is known but doesn't match the provided `is_coinbase`
    ///   parameter.
    pub fn from_psbt_input(
        prev_outpoint: OutPoint,
        sequence: Sequence,
        psbt_input: psbt::Input,
        satisfaction_weight: usize,
        status: Option<TxStatus>,
        is_coinbase: bool,
    ) -> Result<Self, FromPsbtInputError> {
        let outpoint = prev_outpoint;
        let prev_txout = match (
            psbt_input.non_witness_utxo.as_ref(),
            psbt_input.witness_utxo.as_ref(),
        ) {
            (Some(prev_tx), witness_utxo) => {
                // The outpoint must be valid
                if prev_tx.compute_txid() != outpoint.txid {
                    return Err(FromPsbtInputError::InvalidOutPoint(outpoint));
                }
                let prev_txout = prev_tx
                    .output
                    .get(outpoint.vout as usize)
                    .cloned()
                    .ok_or(FromPsbtInputError::InvalidOutPoint(outpoint))?;
                // In case the witness-utxo is present, the txout must match
                if let Some(txout) = witness_utxo {
                    if txout != &prev_txout {
                        return Err(FromPsbtInputError::UtxoCheck);
                    }
                }
                // The value of `is_coinbase` must match that of the previous tx
                if is_coinbase != prev_tx.is_coinbase() {
                    return Err(FromPsbtInputError::Coinbase(CoinbaseMismatch {
                        txid: outpoint.txid,
                        expected: is_coinbase,
                        got: prev_tx.is_coinbase(),
                    }));
                }
                prev_txout
            }
            (_, Some(txout)) => txout.clone(),
            _ => return Err(FromPsbtInputError::UtxoCheck),
        };
        let prev_tx = psbt_input.non_witness_utxo.clone().map(Arc::new);
        let plan = PlanOrPsbtInput::from_psbt_input(sequence, psbt_input, satisfaction_weight)?;
        Ok(Self {
            prev_outpoint,
            prev_txout,
            prev_tx,
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
        self.prev_outpoint
    }

    /// Previous txout.
    pub fn prev_txout(&self) -> &TxOut {
        &self.prev_txout
    }

    /// Previous tx (if any).
    pub fn prev_tx(&self) -> Option<&Transaction> {
        self.prev_tx
            .as_ref()
            .map(|tx| tx.as_ref())
            .or(self.plan.tx())
    }

    /// Confirmation status.
    pub fn status(&self) -> Option<TxStatus> {
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

    /// Confirmations of this tx.
    pub fn confirmations(&self, tip_height: absolute::Height) -> u32 {
        self.status.map_or(0, |status| {
            tip_height
                .to_consensus_u32()
                .saturating_sub(status.height.to_consensus_u32().saturating_sub(1))
        })
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

    /// The weight in witness units needed for satisfying the [`Input`].
    ///
    /// The satisfaction weight is the combined size of the fully satisfied input's witness
    /// and scriptSig expressed in weight units. See <https://en.bitcoin.it/wiki/Weight_units>.
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

    /// Returns the tx confirmation count this is the smallest in this group.
    pub fn min_confirmations(&self, tip_height: absolute::Height) -> u32 {
        self.inputs()
            .iter()
            .map(|input| input.confirmations(tip_height))
            .min()
            .expect("group must not be empty")
    }

    /// Whether any contained input satisfies the predicate.
    pub fn any<F>(&self, f: F) -> bool
    where
        F: FnMut(&Input) -> bool,
    {
        self.inputs().iter().any(f)
    }

    /// Whether all of the contained inputs satisfies the predicate.
    pub fn all<F>(&self, f: F) -> bool
    where
        F: FnMut(&Input) -> bool,
    {
        self.inputs().iter().all(f)
    }

    /// Total value of all contained inputs.
    pub fn value(&self) -> Amount {
        self.inputs()
            .iter()
            .map(|input| input.prev_txout.value)
            .sum()
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
