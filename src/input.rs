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

/// Confirmation status of tx data.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmationStatus {
    /// Confirmation block height.
    pub height: absolute::Height,
    /// Previous block's MTP (median time past) value as per BIP-0068, if available.
    ///
    /// If this is `None` and the input has a relative time-based lock, timelock
    /// checking methods ([`Input::is_time_timelocked`], [`Input::is_timelocked`],
    /// [`Input::is_spendable`]) will return `None` to indicate the lock status
    /// cannot be determined.
    pub prev_mtp: Option<absolute::Time>,
}

impl ConfirmationStatus {
    /// From consensus `height` and `prev_mtp`.
    ///
    /// * `height` - Height of the block that the transaction is confirmed in.
    /// * `prev_mtp` - The previous block's MTP value. I.e. MTP(`height` - 1).
    pub fn new(height: u32, prev_mtp: Option<u32>) -> Result<Self, absolute::ConversionError> {
        Ok(Self {
            height: absolute::Height::from_consensus(height)?,
            prev_mtp: prev_mtp.map(absolute::Time::from_consensus).transpose()?,
        })
    }
}

/// Error returned by [`Input::set_sequence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetSequenceError {
    /// The new sequence value does not satisfy the input's relative-timelock requirement.
    RelativeTimelockNotSatisfied {
        /// The relative timelock required by the input's plan.
        required: relative::LockTime,
        /// The sequence value the caller attempted to set.
        new: Sequence,
    },
    /// The input executes CLTV (absolute timelock), but `Sequence::MAX` disables `nLockTime`,
    /// which would cause CLTV to always fail at script execution.
    AbsoluteTimelockDisabled {
        /// The absolute timelock that will be executed by this input.
        required: absolute::LockTime,
    },
}

impl fmt::Display for SetSequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeTimelockNotSatisfied { required, new } => write!(
                f,
                "sequence {} does not satisfy required relative timelock {}",
                new, required,
            ),
            Self::AbsoluteTimelockDisabled { required } => write!(
                f,
                "Sequence::MAX disables nLockTime, but this input executes CLTV with absolute timelock {}",
                required,
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SetSequenceError {}

/// Internal representation of an input's spending data.
#[derive(Debug, Clone)]
enum PlanOrPsbtInput {
    /// Input described by a miniscript [`Plan`].
    Plan {
        /// The plan describing how to satisfy this input.
        plan: Box<Plan>,
        /// Sequence override.
        ///
        /// Takes precedence over the sequence implied by `plan.relative_timelock`
        /// when computing [`Input::sequence`].
        sequence_override: Option<Sequence>,
        sighash_type: Option<psbt::PsbtSighashType>,
    },
    PsbtInput {
        psbt_input: Box<psbt::Input>,
        sequence: Sequence,
        absolute_timelock: Option<absolute::LockTime>,
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
        absolute_timelock: Option<absolute::LockTime>,
    ) -> Result<Self, FromPsbtInputError> {
        // We require at least one of the witness or non-witness utxo
        if psbt_input.witness_utxo.is_none() && psbt_input.non_witness_utxo.is_none() {
            return Err(FromPsbtInputError::UtxoCheck);
        }
        Ok(Self::PsbtInput {
            psbt_input: Box::new(psbt_input),
            sequence,
            absolute_timelock,
            satisfaction_weight,
        })
    }

    pub fn plan(&self) -> Option<&Plan> {
        match self {
            PlanOrPsbtInput::Plan { plan, .. } => Some(plan),
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
            PlanOrPsbtInput::Plan { plan, .. } => plan.absolute_timelock,
            PlanOrPsbtInput::PsbtInput {
                absolute_timelock, ..
            } => *absolute_timelock,
        }
    }

    pub fn relative_timelock(&self) -> Option<relative::LockTime> {
        match self {
            PlanOrPsbtInput::Plan { plan, .. } => plan.relative_timelock,
            PlanOrPsbtInput::PsbtInput { sequence, .. } => sequence.to_relative_lock_time(),
        }
    }

    pub fn sequence(&self) -> Option<bitcoin::Sequence> {
        match self {
            PlanOrPsbtInput::Plan {
                plan,
                sequence_override,
                ..
            } => sequence_override.or_else(|| {
                plan.relative_timelock
                    .map(|relative_timelock| relative_timelock.to_sequence())
            }),
            PlanOrPsbtInput::PsbtInput { sequence, .. } => Some(*sequence),
        }
    }

    pub fn sighash_type(&self) -> Option<psbt::PsbtSighashType> {
        match self {
            PlanOrPsbtInput::Plan { sighash_type, .. } => *sighash_type,
            PlanOrPsbtInput::PsbtInput { psbt_input, .. } => psbt_input.sighash_type,
        }
    }

    pub fn satisfaction_weight(&self) -> usize {
        match self {
            PlanOrPsbtInput::Plan { plan, .. } => plan.satisfaction_weight(),
            PlanOrPsbtInput::PsbtInput {
                satisfaction_weight,
                ..
            } => *satisfaction_weight,
        }
    }

    pub fn is_segwit(&self) -> bool {
        match self {
            PlanOrPsbtInput::Plan { plan, .. } => plan.witness_version().is_some(),
            PlanOrPsbtInput::PsbtInput { psbt_input, .. } => {
                psbt_input.final_script_witness.is_some()
            }
        }
    }

    pub fn tx(&self) -> Option<&Transaction> {
        match self {
            PlanOrPsbtInput::Plan { .. } => None,
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
    /// Input uses CLTV (absolute timelock) but sequence is `Sequence::MAX`,
    /// which disables locktime and causes CLTV to fail.
    AbsoluteTimelockDisabled {
        /// Outpoint of the input.
        outpoint: OutPoint,
        /// The absolute timelock the input requires.
        timelock: absolute::LockTime,
    },
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
            Self::AbsoluteTimelockDisabled { outpoint, timelock } => write!(
                f,
                "input {outpoint} has CLTV {timelock}, but nSequence is 0xFFFFFFFF which disables nLockTime"
            ),
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
    status: Option<ConfirmationStatus>,
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
        status: Option<ConfirmationStatus>,
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
            plan: PlanOrPsbtInput::Plan {
                plan: Box::new(plan),
                sequence_override: None,
                sighash_type: None,
            },
            status,
            is_coinbase,
        })
    }

    /// Create [`Input`] from a previous txout and plan.
    pub fn from_prev_txout(
        plan: Plan,
        prev_outpoint: OutPoint,
        prev_txout: TxOut,
        status: Option<ConfirmationStatus>,
        is_coinbase: bool,
    ) -> Self {
        Self {
            prev_outpoint,
            prev_txout,
            prev_tx: None,
            plan: PlanOrPsbtInput::Plan {
                plan: Box::new(plan),
                sequence_override: None,
                sighash_type: None,
            },
            status,
            is_coinbase,
        }
    }

    /// Create [`Input`] from a [`psbt::Input`].
    ///
    /// # Parameters
    ///
    /// - `prev_outpoint` - The outpoint being spent.
    /// - `sequence` - The `nSequence` value for this input.
    /// - `psbt_input` - The PSBT input. Must contain at least one of `witness_utxo` or `non_witness_utxo`.
    /// - `satisfaction_weight` - The estimated weight of the input's witness/scriptSig when satisfied.
    /// - `status` - Confirmation status of the previous transaction, if known.
    /// - `is_coinbase` - Whether the previous output is from a coinbase transaction.
    /// - `absolute_timelock` - Pass `None` if the spending path does not execute `CLTV`. If `Some`,
    ///   contributes to `tx.nLockTime` and is validated against `Sequence::MAX`. Passing `None` for
    ///   a script that does execute `CLTV` will produce a consensus-invalid transaction.
    ///
    /// # Errors
    ///
    /// - If neither the witness or non-witness utxo are present in `psbt_input`.
    /// - If `prev_outpoint` doesn't agree with the previous transaction.
    /// - If the previous transaction is known but doesn't match the provided `is_coinbase`
    ///   parameter.
    /// - If `absolute_timelock` is set but `sequence` is `Sequence::MAX`, which disables
    ///   `nLockTime` and causes CLTV to fail.
    pub fn from_psbt_input(
        prev_outpoint: OutPoint,
        sequence: Sequence,
        psbt_input: psbt::Input,
        satisfaction_weight: usize,
        status: Option<ConfirmationStatus>,
        is_coinbase: bool,
        absolute_timelock: Option<absolute::LockTime>,
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

        if let Some(timelock) = absolute_timelock {
            if sequence == Sequence::MAX {
                return Err(FromPsbtInputError::AbsoluteTimelockDisabled {
                    outpoint: prev_outpoint,
                    timelock,
                });
            }
        }

        let prev_tx = psbt_input.non_witness_utxo.clone().map(Arc::new);
        let plan = PlanOrPsbtInput::from_psbt_input(
            sequence,
            psbt_input,
            satisfaction_weight,
            absolute_timelock,
        )?;
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
    pub fn status(&self) -> Option<ConfirmationStatus> {
        self.status
    }

    /// Whether prev output resides in coinbase.
    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }

    /// Whether prev output is an immature coinbase output.
    pub fn is_immature(&self, tip_height: absolute::Height) -> bool {
        if !self.is_coinbase {
            return false;
        }
        match self.status {
            Some(status) => {
                let spending_height = tip_height
                    .to_consensus_u32()
                    .checked_add(1)
                    .expect("must not overflow");
                let age = spending_height.saturating_sub(status.height.to_consensus_u32());
                age < COINBASE_MATURITY
            }
            None => {
                debug_assert!(false, "coinbase should never be unconfirmed");
                true
            }
        }
    }

    /// Whether this is locked by a block-based timelock (absolute or relative).
    pub fn is_block_timelocked(&self, tip_height: absolute::Height) -> bool {
        let spending_height = tip_height
            .to_consensus_u32()
            .checked_add(1)
            .expect("must not overflow");
        if let Some(absolute::LockTime::Blocks(lt_height)) = self.plan.absolute_timelock() {
            // Bitcoin Core's `IsFinalTx` uses strict less-than: a tx is final (unlocked) when
            // `nLockTime < blockHeight`. This means `nLockTime = 100` is first spendable in
            // block 101, not block 100. We return "locked" when the inverse is true.
            return lt_height.to_consensus_u32() >= spending_height;
        }

        match (self.plan.relative_timelock(), self.status) {
            (Some(relative::LockTime::Blocks(lt_height)), Some(conf_status)) => {
                // BIP 68: relative lock is satisfied when `height_diff >= lock_value`.
                // We return "locked" when `lock_value > height_diff`.
                let height_diff =
                    spending_height.saturating_sub(conf_status.height.to_consensus_u32());
                lt_height.to_consensus_u32() > height_diff
            }
            // A block-timelocked output that is unconfirmed must be locked.
            (Some(relative::LockTime::Blocks(_)), None) => true,
            // No relative block-timelock.
            _ => false,
        }
    }

    /// Whether this is locked by a time-based timelock (absolute or relative).
    ///
    /// Returns `None` if [`ConfirmationStatus::prev_mtp`] is required but unavailable.
    ///
    /// `tip_mtp` is `MTP(tip)`, or `MTP(spending_block - 1)`, as per BIP-0068.
    pub fn is_time_timelocked(&self, tip_mtp: absolute::Time) -> Option<bool> {
        if let Some(absolute::LockTime::Seconds(lt_time)) = self.plan.absolute_timelock() {
            // Bitcoin Core's `IsFinalTx` (with BIP 113) uses strict less-than: a tx is final
            // (unlocked) when `nLockTime < MTP`. This means `nLockTime = T` is first spendable
            // when `MTP > T`, not when `MTP == T`. We return "locked" when the inverse is true.
            return Some(lt_time.to_consensus_u32() >= tip_mtp.to_consensus_u32());
        }

        match (self.plan.relative_timelock(), self.status) {
            (Some(relative::LockTime::Time(lt_time)), Some(conf_status)) => {
                // BIP 68: relative time lock is satisfied when `time_diff >= lock_value * 512`.
                // We return "locked" when `lock_value * 512 > time_diff`.
                let time_diff = tip_mtp
                    .to_consensus_u32()
                    // If we are missing `prev_mtp`, we cannot determine whether the output is still
                    // locked.
                    .saturating_sub(conf_status.prev_mtp?.to_consensus_u32());
                Some(lt_time.value() as u32 * 512 > time_diff)
            }
            // A time-timelocked output that is unconfirmed must be locked.
            (Some(relative::LockTime::Time(_)), None) => Some(true),
            // No relative time-timelock.
            _ => Some(false),
        }
    }

    /// Whether this is locked by any timelock constraint.
    ///
    /// Returns `None` if a time-based lock exists but `tip_mtp` is not provided or
    /// [`ConfirmationStatus::prev_mtp`] is unavailable.
    ///
    /// `tip_mtp` is `MTP(tip)`, or `MTP(spending_block - 1)`, as per BIP-0068.
    pub fn is_timelocked(
        &self,
        tip_height: absolute::Height,
        tip_mtp: Option<absolute::Time>,
    ) -> Option<bool> {
        if self.is_block_timelocked(tip_height) {
            return Some(true);
        }

        let has_time_timelock = self
            .plan
            .absolute_timelock()
            .is_some_and(|l| l.is_block_time())
            || self
                .plan
                .relative_timelock()
                .is_some_and(|l| l.is_block_time());

        if has_time_timelock {
            if let Some(mtp) = tip_mtp {
                return self.is_time_timelocked(mtp);
            }
            return None;
        }

        // No timelock exists
        Some(false)
    }

    /// Confirmations of this tx.
    pub fn confirmations(&self, tip_height: absolute::Height) -> u32 {
        self.status.map_or(0, |status| {
            tip_height
                .to_consensus_u32()
                .saturating_sub(status.height.to_consensus_u32().saturating_sub(1))
        })
    }

    /// Whether this output can be spent at the given height and mtp time.
    ///
    /// `tip_mtp` is `MTP(tip)`, or `MTP(spending_block - 1)`, as per BIP-0068.
    pub fn is_spendable(
        &self,
        tip_height: absolute::Height,
        tip_mtp: Option<absolute::Time>,
    ) -> Option<bool> {
        Some(!self.is_immature(tip_height) && !self.is_timelocked(tip_height, tip_mtp)?)
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

    /// Sighash type.
    pub fn sighash_type(&self) -> Option<psbt::PsbtSighashType> {
        self.plan.sighash_type()
    }

    /// Set the sighash type for this input.
    ///
    /// This overrides any sighash type already attached to the input — whether carried in via
    /// [`Input::from_psbt_input`] (as [`psbt::Input::sighash_type`]) or set by a prior call.
    ///
    /// Accepts anything convertible into [`psbt::PsbtSighashType`], including the standard
    /// `EcdsaSighashType` and `TapSighashType` from `rust-bitcoin`.
    pub fn set_sighash_type(&mut self, sighash_type: impl Into<psbt::PsbtSighashType>) {
        let new = Some(sighash_type.into());
        match &mut self.plan {
            PlanOrPsbtInput::Plan { sighash_type, .. } => *sighash_type = new,
            PlanOrPsbtInput::PsbtInput { psbt_input, .. } => psbt_input.sighash_type = new,
        }
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

    /// Override the sequence value this input contributes to the resulting transaction.
    ///
    /// This takes precedence over the sequence implied by the plan's relative timelock.
    ///
    /// # Errors
    ///
    /// - [`SetSequenceError::RelativeTimelockNotSatisfied`] if the input has a plan-required
    ///   relative timelock and `sequence` does not satisfy it (BIP-68 / OP_CSV).
    /// - [`SetSequenceError::AbsoluteTimelockDisabled`] if the input executes CLTV and
    ///   `sequence` is `Sequence::MAX`, which would disable `nLockTime` and cause CLTV to fail.
    pub fn set_sequence(&mut self, sequence: Sequence) -> Result<(), SetSequenceError> {
        match &mut self.plan {
            PlanOrPsbtInput::Plan {
                plan,
                sequence_override,
                ..
            } => {
                if let Some(required) = plan.absolute_timelock {
                    if sequence == Sequence::MAX {
                        return Err(SetSequenceError::AbsoluteTimelockDisabled { required });
                    }
                }
                if let Some(required) = plan.relative_timelock {
                    let satisfied = sequence
                        .to_relative_lock_time()
                        .is_some_and(|new_rlt| required.is_implied_by(new_rlt));
                    if !satisfied {
                        return Err(SetSequenceError::RelativeTimelockNotSatisfied {
                            required,
                            new: sequence,
                        });
                    }
                }
                *sequence_override = Some(sequence);
            }
            PlanOrPsbtInput::PsbtInput {
                sequence: seq,
                absolute_timelock,
                ..
            } => {
                if let Some(required) = *absolute_timelock {
                    if sequence == Sequence::MAX {
                        return Err(SetSequenceError::AbsoluteTimelockDisabled { required });
                    }
                }
                *seq = sequence;
            }
        }
        Ok(())
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

    /// Whether any contained input is immature.
    pub fn is_immature(&self, tip_height: absolute::Height) -> bool {
        self.0.iter().any(|input| input.is_immature(tip_height))
    }

    /// Whether any contained input is locked by a block-based timelock (absolute or relative).
    pub fn is_block_timelocked(&self, tip_height: absolute::Height) -> bool {
        self.0
            .iter()
            .any(|input| input.is_block_timelocked(tip_height))
    }

    /// Whether any contained input is locked by a time-based timelock (absolute or relative).
    ///
    /// `tip_mtp` is `MTP(tip)`, or `MTP(spending_block - 1)`, as per BIP-0068.
    pub fn is_time_timelocked(&self, tip_mtp: absolute::Time) -> Option<bool> {
        for input in &self.0 {
            if input.is_time_timelocked(tip_mtp)? {
                return Some(true);
            }
        }
        Some(false)
    }

    /// Whether any contained input is locked by any timelock constraint.
    ///
    /// `tip_mtp` is `MTP(tip)`, or `MTP(spending_block - 1)`, as per BIP-0068.
    pub fn is_timelocked(
        &self,
        tip_height: absolute::Height,
        tip_mtp: Option<absolute::Time>,
    ) -> Option<bool> {
        for input in &self.0 {
            if input.is_timelocked(tip_height, tip_mtp)? {
                return Some(true);
            }
        }
        Some(false)
    }

    /// Whether all contained inputs are spendable now.
    ///
    /// `tip_mtp` is `MTP(tip)`, or `MTP(spending_block - 1)`, as per BIP-0068.
    pub fn is_spendable(
        &self,
        tip_height: absolute::Height,
        tip_mtp: Option<absolute::Time>,
    ) -> Option<bool> {
        for input in &self.0 {
            if !input.is_spendable(tip_height, tip_mtp)? {
                return Some(false);
            }
        }
        Some(true)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut};
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    const TEST_XPUB: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";

    fn input_with_plan(desc_str: &str) -> Input {
        let desc = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
        let definite = desc.at_derivation_index(0).unwrap();
        let script_pubkey = definite.script_pubkey();
        let assets = Assets::new()
            .add(DescriptorPublicKey::from_str(TEST_XPUB).unwrap())
            .older(relative::LockTime::from_height(10));

        let plan = definite.plan(&assets).unwrap();

        let txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        };
        Input::from_prev_txout(plan, OutPoint::null(), txout, None, false)
    }

    #[test]
    fn test_set_sequence_overrides_value_returned_by_sequence() {
        let mut input = input_with_plan(&format!("tr({TEST_XPUB})"));
        assert_eq!(input.sequence(), None, "no plan-derived sequence expected");

        let new_seq = Sequence::from_consensus(42);
        input.set_sequence(new_seq).unwrap();
        assert_eq!(input.sequence(), Some(new_seq));

        let other = Sequence::ENABLE_RBF_NO_LOCKTIME;
        input.set_sequence(other).unwrap();
        assert_eq!(input.sequence(), Some(other));
    }

    #[test]
    fn test_set_sequence_rejects_sequence_below_required_relative_timelock() {
        let mut input = input_with_plan(&format!("wsh(and_v(v:pk({TEST_XPUB}),older(10)))"));
        assert!(matches!(
            input.relative_timelock(),
            Some(relative::LockTime::Blocks(_))
        ));

        let too_low = Sequence::from_height(5);
        let err = input.set_sequence(too_low).unwrap_err();
        assert!(matches!(
            err,
            SetSequenceError::RelativeTimelockNotSatisfied { .. }
        ));

        assert!(matches!(
            input.set_sequence(Sequence::MAX).unwrap_err(),
            SetSequenceError::RelativeTimelockNotSatisfied { .. }
        ));

        let wrong_unit = Sequence::from_512_second_intervals(20);
        assert!(matches!(
            input.set_sequence(wrong_unit).unwrap_err(),
            SetSequenceError::RelativeTimelockNotSatisfied { .. }
        ));
    }

    #[test]
    fn test_set_sequence_on_psbt_input_replaces_sequence() {
        let sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

        let txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new(),
        };
        let psbt_input = psbt::Input {
            witness_utxo: Some(txout),
            ..Default::default()
        };
        let mut input = Input::from_psbt_input(
            OutPoint::null(),
            sequence,
            psbt_input,
            100,
            None,
            false,
            None,
        )
        .unwrap();

        assert_eq!(input.sequence(), Some(sequence));

        let new_seq = Sequence::from_height(42);
        input.set_sequence(new_seq).unwrap();
        assert_eq!(input.sequence(), Some(new_seq));
    }

    #[test]
    fn test_from_psbt_input_rejects_max_sequence() {
        let txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new(),
        };
        let psbt_input = || psbt::Input {
            witness_utxo: Some(txout.clone()),
            ..Default::default()
        };
        let outpoint = OutPoint::null();
        let timelock = absolute::LockTime::from_height(100).unwrap();

        let result = Input::from_psbt_input(
            outpoint,
            Sequence::MAX,
            psbt_input(),
            100,
            None,
            false,
            Some(timelock),
        );
        assert!(matches!(
            result,
            Err(FromPsbtInputError::AbsoluteTimelockDisabled { .. })
        ));
    }
}
