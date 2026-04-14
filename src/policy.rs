use crate::{
    bitcoin::{
        absolute::{self, LockTime},
        policy::MAX_STANDARD_TX_WEIGHT,
        transaction::Version,
        Amount, OutPoint, Transaction, Weight,
    },
    utils::is_standard_script,
    Input, Selection,
};

/// Default minimum relay feerate.
///
/// Lowered from 1000 sat/kvB to 100 sat/kvB in Bitcoin Core.
const DEFAULT_MIN_RELAY_TX_FEE: u64 = 100;

/// Maximum standardness weight for a TRUC (version-3) transaction.
const MAX_TRUC_TX_WEIGHT: u64 = 40_000;

/// Minimum non-witness size for a standard transaction
///
/// Lowered from 82 to 65 in Bitcoin Core.
const MIN_STANDARD_TX_NONWITNESS_SIZE: u32 = 65;

/// Maximum witness stack items allowed under standard mempool policy.
const MAX_WITNESS_STACK_ITEMS: usize = 100;

/// Mempool acceptance policy checks for a fully-built [`Selection`].
///
/// Pairs with [`SelectorParams::check_standardness`] for output-only checks
/// (dust, OP_RETURN, output script types) that run before coin selection.
pub struct MempoolPolicy {
    /// Current block height
    pub tip_height: absolute::Height,
    /// Current median time past
    pub tip_mtp: absolute::Time,
}

impl MempoolPolicy {
    /// Check that no input exceeds the maximum witness stack item count.
    pub fn check_max_witness_stack(&self, inputs: &[Input]) -> Result<(), MempoolPolicyError> {
        for input in inputs {
            if !input.prev_txout().script_pubkey.is_p2wsh() {
                continue;
            }

            if let Some(count) = input.witness_item_count() {
                if count.saturating_sub(1) > MAX_WITNESS_STACK_ITEMS {
                    return Err(MempoolPolicyError::MaxWitnessStackExceeded {
                        outpoint: input.prev_outpoint(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Check that the transaction weight does not exceed MAX_STANDARD_TX_WEIGHT (400,000 WU).
    pub fn check_max_tx_weight(
        &self,
        weight: Weight,
        version: Version,
    ) -> Result<(), MempoolPolicyError> {
        let limit = if version == Version(3) {
            Weight::from_wu(MAX_TRUC_TX_WEIGHT)
        } else {
            Weight::from_wu(MAX_STANDARD_TX_WEIGHT as u64)
        };

        if weight > limit {
            return Err(MempoolPolicyError::MaxWeightExceeded { weight });
        }

        Ok(())
    }

    /// Check that the transaction version is standard (version 1, 2, or 3).
    ///
    /// Version 3 (TRUC, BIP 431) is standard under Bitcoin Core v30+.
    pub fn check_tx_version(&self, tx: &Transaction) -> Result<(), MempoolPolicyError> {
        if !matches!(tx.version, Version::ONE | Version::TWO | Version(3)) {
            return Err(MempoolPolicyError::UnsupportedVersion(tx.version));
        }
        Ok(())
    }

    /// Check that the transaction's absolute locktime is satisfied by the current
    /// chain tip height or median time past.
    pub fn check_abs_locktime(&self, tx: &Transaction) -> Result<(), MempoolPolicyError> {
        match tx.lock_time {
            LockTime::Blocks(locktime) => {
                if locktime > self.tip_height {
                    return Err(MempoolPolicyError::LockTimeNotMet(tx.lock_time));
                }
            }
            LockTime::Seconds(locktime) => {
                if locktime >= self.tip_mtp {
                    return Err(MempoolPolicyError::LockTimeNotMet(tx.lock_time));
                }
            }
        }
        Ok(())
    }

    /// Check that the transaction meets the minimum relay fee rate.
    pub fn check_min_fee_relay(
        &self,
        fee: Amount,
        expected_weight: Weight,
    ) -> Result<(), MempoolPolicyError> {
        // ceiling division: BIP 141 vsize = ceil(weight / 4)
        let expected_vsize = expected_weight.to_wu().div_ceil(4);

        let required = Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE * expected_vsize / 1000);

        if fee < required {
            return Err(MempoolPolicyError::MinRelayFeeNotMet {
                fee,
                required,
                expected_vsize,
            });
        }
        Ok(())
    }

    /// Check that the transaction's non-witness size is at least 65 bytes.
    pub fn check_min_non_witness_size(&self, tx: &Transaction) -> Result<(), MempoolPolicyError> {
        let non_witness_size = tx.base_size();
        if non_witness_size < MIN_STANDARD_TX_NONWITNESS_SIZE as usize {
            return Err(MempoolPolicyError::TxTooSmall { non_witness_size });
        }
        Ok(())
    }

    /// Check that all inputs are currently spendable.
    pub fn check_input_spendability(&self, inputs: &[Input]) -> Result<(), MempoolPolicyError> {
        for input in inputs {
            match input.is_spendable(self.tip_height, Some(self.tip_mtp)) {
                Some(true) => continue,
                Some(false) => {
                    return Err(MempoolPolicyError::InputNotSpendable {
                        outpoint: input.prev_outpoint(),
                    })
                }
                None => {
                    return Err(MempoolPolicyError::InputSpendabilityUnknown {
                        outpoint: input.prev_outpoint(),
                    })
                }
            }
        }
        Ok(())
    }

    /// Check that all inputs spend a standard script type.
    pub fn check_input_script_type(&self, inputs: &[Input]) -> Result<(), MempoolPolicyError> {
        for input in inputs {
            if !is_standard_script(&input.prev_txout().script_pubkey) {
                return Err(MempoolPolicyError::NonStandardInputScript {
                    outpoint: input.prev_outpoint(),
                });
            }
        }
        Ok(())
    }

    /// Run all post-selection mempool policy checks against `selection` and `tx`.
    ///
    /// This is the second part of the two-layer policy split; the first part
    /// lives in [`crate::SelectorParams::check_standardness`] and runs before coin selection.
    pub fn check_all(
        &self,
        selection: &Selection,
        tx: &Transaction,
    ) -> Result<(), MempoolPolicyError> {
        if selection.inputs.len() != tx.input.len() || selection.outputs.len() != tx.output.len() {
            return Err(MempoolPolicyError::SelectionTxMismatch);
        }

        if !selection
            .inputs
            .iter()
            .zip(&tx.input)
            .all(|(input, txin)| input.prev_outpoint() == txin.previous_output)
        {
            return Err(MempoolPolicyError::SelectionTxMismatch);
        }

        if !selection
            .outputs
            .iter()
            .zip(&tx.output)
            .all(|(o, txo)| o.value == txo.value && o.script_pubkey() == txo.script_pubkey)
        {
            return Err(MempoolPolicyError::SelectionTxMismatch);
        }

        self.check_tx_version(tx)?;
        self.check_abs_locktime(tx)?;
        self.check_min_non_witness_size(tx)?;

        // tx.weight() excludes witness data since the tx is unsigned.
        // Add each input's satisfaction weight and the segwit marker/flag.
        let satisfaction: Weight = selection
            .inputs
            .iter()
            .map(|i| Weight::from_wu(i.satisfaction_weight()))
            .sum();
        let segwit_overhead = if selection.inputs.iter().any(|i| i.is_segwit()) {
            Weight::from_wu(2)
        } else {
            Weight::ZERO
        };
        let expected_weight = tx.weight() + satisfaction + segwit_overhead;

        // Total fee: sum of input values minus sum of output values.
        let input_value: Amount = selection
            .inputs
            .iter()
            .map(|input| input.prev_txout().value)
            .sum();
        let output_value: Amount = selection.outputs.iter().map(|output| output.value).sum();
        let fee = input_value
            .checked_sub(output_value)
            .ok_or(MempoolPolicyError::NegativeFee)?;

        self.check_max_tx_weight(expected_weight, tx.version)?;
        self.check_input_spendability(&selection.inputs)?;
        self.check_input_script_type(&selection.inputs)?;
        self.check_max_witness_stack(&selection.inputs)?;
        self.check_min_fee_relay(fee, expected_weight)?;

        Ok(())
    }
}

/// Mempool policy validation errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum MempoolPolicyError {
    /// Transaction weight exceeds MAX_STANDARD_TX_WEIGHT (400,000 WU).
    MaxWeightExceeded {
        /// The actual weight of the transaction that exceeded the limit.
        weight: Weight,
    },
    /// Transaction version is not standard (must be 1, 2, or 3).
    UnsupportedVersion(Version),
    /// Transaction's absolute locktime is not satisfied by the current chain tip.
    LockTimeNotMet(absolute::LockTime),
    /// An input's witness stack exceeds 100 items.
    MaxWitnessStackExceeded {
        /// The outpoint whose witness stack exceeded the limit.
        outpoint: OutPoint,
    },
    /// Transaction fee is below the minimum relay fee rate.
    MinRelayFeeNotMet {
        /// The calculated fee for the transaction.
        fee: Amount,
        /// The virtual size of the transaction.
        required: Amount,
        /// The minimum relay feerate in satoshis per kilobyte (sat/kvB) that the transaction failed to meet.
        expected_vsize: u64,
    },
    /// Transaction's non-witness size is below 65 bytes.
    TxTooSmall {
        /// The non-witness size of the transaction.
        non_witness_size: usize,
    },
    /// Input is definitively not yet spendable (immature coinbase or unmet timelock).
    InputNotSpendable {
        /// The outpoint of the input that is not yet spendable.
        outpoint: OutPoint,
    },
    /// Input spends non-standard script type.
    NonStandardInputScript {
        /// The outpoint of the input that spends a non-standard script type.
        outpoint: OutPoint,
    },
    /// Fee is negative (outputs exceed inputs).
    NegativeFee,

    /// Input spendability could not be determined. Currently this happens when an input
    /// has a time-based relative timelock and is missing the `prev_mtp` data needed to evaluate it.
    InputSpendabilityUnknown {
        /// The outpoint whose spendability could not be determined.
        outpoint: OutPoint,
    },
    /// The provided `Selection` and `Transaction` do not correspond. Their
    /// input counts differ, or their inputs reference different outpoints.
    SelectionTxMismatch,
}

impl core::fmt::Display for MempoolPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MaxWeightExceeded { weight } => {
                write!(f, "transaction weight {weight} exceeds the standard limit of {MAX_STANDARD_TX_WEIGHT} WU")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "transaction version {version} is not standard (only 1, 2 and 3 are accepted)"
                )
            }
            Self::LockTimeNotMet(lock_time) => {
                write!(f, "transaction locktime {lock_time} is not yet satisfied by the current chain tip")
            }
            Self::MaxWitnessStackExceeded { outpoint } => {
                write!(
                    f, "input {outpoint} witness stack exceeds the limit of {MAX_WITNESS_STACK_ITEMS} items"
                )
            }
            Self::MinRelayFeeNotMet {
                fee,
                required,
                expected_vsize,
            } => {
                write!(
                    f,
                    "fee {fee} for {expected_vsize} vB is below the required minimum of {required}"
                )
            }
            Self::TxTooSmall { non_witness_size } => {
                write!(f, "non-witness size {non_witness_size} bytes is below the minimum of {MIN_STANDARD_TX_NONWITNESS_SIZE} bytes")
            }
            Self::InputNotSpendable { outpoint } => {
                write!(f, "input {outpoint} is not yet spendable")
            }
            Self::NonStandardInputScript { outpoint } => {
                write!(f, "input {outpoint} spends a non-standard script type")
            }
            Self::NegativeFee => {
                write!(f, "total output value exceeds total input value")
            }
            Self::InputSpendabilityUnknown { outpoint } => {
                write!(
                    f,
                    "input {outpoint} spendability is unknown (missing prev_mtp for time-based relative timelock evaluation)"
                )
            }
            Self::SelectionTxMismatch => {
                write!(
                    f,
                    "the provided Selection and Transaction do not correspond"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MempoolPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::*, Output};
    use alloc::vec::Vec;
    use bitcoin::{transaction::Version, Amount, ScriptBuf, Transaction, TxOut};

    fn default_policy() -> MempoolPolicy {
        MempoolPolicy {
            tip_height: absolute::Height::from_consensus(3_000).unwrap(),
            tip_mtp: absolute::Time::from_consensus(500_001_000).unwrap(),
        }
    }

    #[test]
    fn test_tx_version() {
        let policy = default_policy();
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);
        let (selection, mut tx) = build_selection_with_tx(&[input], &[output]);

        // Default version is 2, which is standard.
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Test version 1, which is also standard.
        tx.version = Version::ONE;
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Version 3 (TRUC) is standard under v30+.
        tx.version = Version(3);
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Test version 4, which is non-standard.
        tx.version = Version(4);
        assert!(matches!(
            policy.check_all(&selection, &tx),
            Err(MempoolPolicyError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_tx_locktime() {
        let policy = default_policy();
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);
        let (selection, mut tx) = build_selection_with_tx(&[input], &[output]);

        // Locktime exactly equal to the tip height.
        tx.lock_time = absolute::LockTime::from_consensus(3_000);
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Locktime below the tip height.
        tx.lock_time = absolute::LockTime::from_consensus(2_500);
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Locktime above the tip height.
        tx.lock_time = absolute::LockTime::from_consensus(3_001);
        assert!(matches!(
            policy.check_all(&selection, &tx),
            Err(MempoolPolicyError::LockTimeNotMet(_))
        ));

        // Locktime one second below the tip MTP.
        tx.lock_time = absolute::LockTime::from_consensus(500_000_999);
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Locktime exactly equal to the tip MTP.
        tx.lock_time = absolute::LockTime::from_consensus(500_001_000);
        assert!(matches!(
            policy.check_all(&selection, &tx),
            Err(MempoolPolicyError::LockTimeNotMet(_))
        ));

        // Locktime above the tip MTP.
        tx.lock_time = absolute::LockTime::from_consensus(500_002_000);
        assert!(matches!(
            policy.check_all(&selection, &tx),
            Err(MempoolPolicyError::LockTimeNotMet(_))
        ));
    }

    #[test]
    fn test_max_tx_weight() {
        let policy = default_policy();

        // A normal transaction with 1 input and 1 output.
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);
        let (selection, tx) = build_selection_with_tx(core::slice::from_ref(&input), &[output]);
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Heavy transaction with excess weight.
        let outputs_with_excess_weight: Vec<Output> = (0..2_350)
            .map(|_| create_output(p2tr_script(), 1_000))
            .collect();

        let (_, heavy_tx) =
            build_selection_with_tx(&[input], outputs_with_excess_weight.as_slice());

        assert!(heavy_tx.weight().to_wu() > MAX_STANDARD_TX_WEIGHT as u64);
        assert!(matches!(
            policy.check_max_tx_weight(heavy_tx.weight(), heavy_tx.version),
            Err(MempoolPolicyError::MaxWeightExceeded { .. })
        ));
    }

    #[test]
    fn test_tx_min_non_witness_size() {
        let policy = default_policy();
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);

        // Transaction with 1 input and 1 output.
        let (selection, tx) = build_selection_with_tx(&[input], &[output]);
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Transaction with no inputs and 1 output.
        let tx_below_min_non_witness_size = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::ZERO,
            }],
        };
        let empty_selection = Selection {
            inputs: vec![],
            outputs: vec![Output::with_script(ScriptBuf::new(), Amount::ZERO)],
        };
        assert!(
            tx_below_min_non_witness_size.base_size() < MIN_STANDARD_TX_NONWITNESS_SIZE as usize
        );
        assert!(matches!(
            policy.check_all(&empty_selection, &tx_below_min_non_witness_size),
            Err(MempoolPolicyError::TxTooSmall { .. })
        ));
    }

    #[test]
    fn test_min_fee_relay() {
        let policy = default_policy();

        // Sufficient fee passes.
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);

        let (selection, tx) = build_selection_with_tx(&[input], &[output]);
        assert!(policy.check_all(&selection, &tx).is_ok());

        // Fee below the 1 sat/vB minimum is rejected.
        let input_with_insufficient_fee = setup_test_input(2_000).unwrap();
        let output_with_insufficient_fee = create_output(p2tr_script(), 9_999);

        let (selection_with_insufficient_fee, tx_with_insufficient_fee) = build_selection_with_tx(
            &[input_with_insufficient_fee],
            &[output_with_insufficient_fee],
        );
        assert!(matches!(
            policy.check_all(&selection_with_insufficient_fee, &tx_with_insufficient_fee),
            Err(MempoolPolicyError::MinRelayFeeNotMet { .. })
        ));
    }

    #[test]
    fn test_max_witness_stack() {
        let policy = default_policy();
        let input = setup_test_input(2_000).unwrap();

        assert!(policy.check_max_witness_stack(&[input]).is_ok());
    }

    #[test]
    fn test_input_spendability() {
        let policy = default_policy();
        // A confirmed input
        let input = setup_test_input(2_000).unwrap();
        assert!(policy.check_input_spendability(&[input]).is_ok());

        // An immature input
        let input_with_immature_coinbase = setup_test_input(2_950).unwrap();
        assert!(policy
            .check_input_spendability(&[input_with_immature_coinbase])
            .is_err());
    }

    #[test]
    fn test_input_script_type() {
        let policy = default_policy();
        let input = setup_test_input(2_000).unwrap();
        assert!(policy.check_input_script_type(&[input]).is_ok());
    }
}
