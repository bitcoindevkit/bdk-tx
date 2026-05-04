use crate::{
    bitcoin::{
        absolute::{self, LockTime},
        transaction::Version,
        Amount, FeeRate, OutPoint, Transaction, Weight,
    },
    utils::is_standard_script,
    Input, Selection,
};

/// Chain tip context for policy checks that depend on current chain state.
///
/// `MempoolPolicy` is static node configuration; `ChainTip` is per-call dynamic
/// state. They have different lifetimes and update cadences and are passed
/// separately on purpose.
#[derive(Debug, Clone, Copy)]
pub struct ChainTip {
    /// Current best block height.
    pub height: absolute::Height,
    /// Current median time past.
    pub mtp: absolute::Time,
}

/// Mempool acceptance policy applied after coin selection.
///
/// Pairs with [`SelectorParams::check_standardness`], which runs the
/// output-only subset of these rules before coin selection.
pub struct MempoolPolicy {
    /// Dust relay feerate used to compute per-output dust thresholds
    pub dust_relay_feerate: FeeRate,
    /// Minimum relay feerate for transaction acceptance
    pub min_relay_feerate: FeeRate,
    /// Aggregate `OP_RETURN` scriptPubKey size limit
    pub max_op_return_aggregate_bytes: usize,
    /// Maximum standard transaction weight.
    pub max_standard_tx_weight: Weight,
    /// Maximum TRUC (BIP 431, version-3) transaction weight.
    pub max_truc_tx_weight: Weight,
    /// Minimum transaction non-witness size.
    pub min_standard_tx_nonwitness_size: usize,
    /// Maximum P2WSH witness stack item count.
    pub max_witness_stack_items: usize,
    /// Allowed transaction `nVersion` values.
    pub allowed_versions: &'static [Version],
}

impl MempoolPolicy {
    /// Policy matching Bitcoin Core v30 defaults (October 2025).
    pub const fn bitcoin_core_v30() -> Self {
        Self {
            dust_relay_feerate: FeeRate::from_sat_per_kwu(750),
            min_relay_feerate: FeeRate::from_sat_per_kwu(25),
            max_op_return_aggregate_bytes: 100_000,
            max_standard_tx_weight: Weight::from_wu(400_000),
            max_truc_tx_weight: Weight::from_wu(40_000),
            min_standard_tx_nonwitness_size: 65,
            max_witness_stack_items: 100,
            allowed_versions: &[Version::ONE, Version::TWO, Version(3)],
        }
    }

    /// Check that `tx.version` is in [`Self::allowed_versions`].
    pub fn check_tx_version(&self, tx: &Transaction) -> Result<(), MempoolPolicyError> {
        if !self.allowed_versions.contains(&tx.version) {
            return Err(MempoolPolicyError::UnsupportedVersion(tx.version));
        }
        Ok(())
    }

    /// Check that the absolute locktime is satisfied by the current chain tip height or median time past.
    pub fn check_abs_locktime(
        &self,
        tx: &Transaction,
        tip: ChainTip,
    ) -> Result<(), MempoolPolicyError> {
        match tx.lock_time {
            LockTime::Blocks(locktime) => {
                if locktime > tip.height {
                    return Err(MempoolPolicyError::LockTimeNotMet(tx.lock_time));
                }
            }
            LockTime::Seconds(locktime) => {
                if locktime >= tip.mtp {
                    return Err(MempoolPolicyError::LockTimeNotMet(tx.lock_time));
                }
            }
        }
        Ok(())
    }

    /// Check that the transaction's non-witness size is at least [`Self::min_standard_tx_nonwitness_size`].
    pub fn check_min_non_witness_size(&self, tx: &Transaction) -> Result<(), MempoolPolicyError> {
        let non_witness_size = tx.base_size();
        if non_witness_size < self.min_standard_tx_nonwitness_size {
            return Err(MempoolPolicyError::TxTooSmall {
                non_witness_size,
                min: self.min_standard_tx_nonwitness_size,
            });
        }
        Ok(())
    }

    /// Check the transaction weight against the appropriate limit.
    ///
    /// TRUC (v3) transactions use [`Self::max_truc_tx_weight`], all other
    /// versions use [`Self::max_standard_tx_weight`].
    pub fn check_max_tx_weight(
        &self,
        weight: Weight,
        version: Version,
    ) -> Result<(), MempoolPolicyError> {
        let limit = if version == Version(3) {
            self.max_truc_tx_weight
        } else {
            self.max_standard_tx_weight
        };

        if weight > limit {
            return Err(MempoolPolicyError::MaxWeightExceeded { weight, limit });
        }
        Ok(())
    }

    /// Check all inputs are spendable at `tip` (no immature coinbases, all timelocks satisfied).
    pub fn check_input_spendability(
        &self,
        inputs: &[Input],
        tip: ChainTip,
    ) -> Result<(), MempoolPolicyError> {
        for input in inputs {
            match input.is_spendable(tip.height, Some(tip.mtp)) {
                Some(true) => continue,
                Some(false) => {
                    return Err(MempoolPolicyError::InputNotSpendable {
                        outpoint: input.prev_outpoint(),
                    });
                }
                None => {
                    return Err(MempoolPolicyError::InputSpendabilityUnknown {
                        outpoint: input.prev_outpoint(),
                    });
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

    /// Check that no P2WSH input exceeds [`Self::max_witness_stack_items`].
    pub fn check_max_witness_stack(&self, inputs: &[Input]) -> Result<(), MempoolPolicyError> {
        for input in inputs {
            if !input.prev_txout().script_pubkey.is_p2wsh() {
                continue;
            }
            if let Some(count) = input.witness_item_count() {
                // Bitcoin Core counts the witness script itself separately.
                if count.saturating_sub(1) > self.max_witness_stack_items {
                    return Err(MempoolPolicyError::MaxWitnessStackExceeded {
                        outpoint: input.prev_outpoint(),
                        limit: self.max_witness_stack_items,
                    });
                }
            }
        }
        Ok(())
    }

    /// Check that `fee` meets [`Self::min_relay_feerate`] for the expected signed weight.
    pub fn check_min_fee_relay(
        &self,
        fee: Amount,
        expected_weight: Weight,
    ) -> Result<(), MempoolPolicyError> {
        // BIP 141 vsize = ceil(weight / 4).
        let expected_vsize = expected_weight.to_wu().div_ceil(4);

        // Convert sat/kwu to sat/kvB (1 kvB = 4 kwu) so the calculation
        // matches Core's `GetMinFee(GetVirtualTransactionSize)` shape exactly.
        let sat_per_kvb = self.min_relay_feerate.to_sat_per_kwu().saturating_mul(4);
        let required = Amount::from_sat(sat_per_kvb.saturating_mul(expected_vsize) / 1000);

        if fee < required {
            return Err(MempoolPolicyError::MinRelayFeeNotMet {
                fee,
                required,
                expected_vsize,
            });
        }
        Ok(())
    }

    /// Run all post-selection checks against the constructed transaction.
    ///
    /// This is invoked by [`Selection::create_psbt_with_policy`] after the
    /// crate builds the transaction itself, so the `selection`/`tx`
    /// correspondence is a constructor invariant rather than a runtime check.
    /// Not exposed publicly: callers who need fine-grained control should call
    /// the individual `check_*` methods on this struct directly.
    pub(crate) fn check_post_selection(
        &self,
        selection: &Selection,
        tx: &Transaction,
        tip: ChainTip,
    ) -> Result<(), MempoolPolicyError> {
        self.check_tx_version(tx)?;
        self.check_abs_locktime(tx, tip)?;
        self.check_min_non_witness_size(tx)?;

        // tx.weight() excludes witness data because the tx is unsigned. Add
        // each input's satisfaction weight and the segwit marker/flag.
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
        let output_value: Amount = selection.outputs.iter().map(|o| o.value).sum();
        let fee = input_value
            .checked_sub(output_value)
            .ok_or(MempoolPolicyError::NegativeFee)?;

        self.check_max_tx_weight(expected_weight, tx.version)?;
        self.check_input_spendability(&selection.inputs, tip)?;
        self.check_input_script_type(&selection.inputs)?;
        self.check_max_witness_stack(&selection.inputs)?;
        self.check_min_fee_relay(fee, expected_weight)?;

        Ok(())
    }
}

impl Default for MempoolPolicy {
    fn default() -> Self {
        Self::bitcoin_core_v30()
    }
}

/// Mempool policy validation errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum MempoolPolicyError {
    /// Transaction weight exceeds the policy limit.
    MaxWeightExceeded {
        /// The actual weight of the transaction.
        weight: Weight,
        /// Configured limit (depends on `tx.version`).
        limit: Weight,
    },
    /// Transaction version is not in [`MempoolPolicy::allowed_versions`].
    UnsupportedVersion(Version),
    /// Transaction's absolute locktime is not satisfied by the current chain tip.
    LockTimeNotMet(absolute::LockTime),
    /// A P2WSH input's witness stack exceeds the limit.
    MaxWitnessStackExceeded {
        /// Outpoint of the offending input.
        outpoint: OutPoint,
        /// Configured limit.
        limit: usize,
    },
    /// Fee is below [`MempoolPolicy::min_relay_feerate`].
    MinRelayFeeNotMet {
        /// Actual fee.
        fee: Amount,
        /// Required minimum fee for `expected_vsize` at the configured feerate.
        required: Amount,
        /// Expected virtual size in bytes (`ceil(weight / 4)`).
        expected_vsize: u64,
    },
    /// Transaction's non-witness size is below the minimum.
    TxTooSmall {
        /// Actual non-witness size in bytes.
        non_witness_size: usize,
        /// Configured minimum.
        min: usize,
    },
    /// Input is definitively unspendable (immature coinbase or unmet timelock).
    InputNotSpendable {
        /// Outpoint of the unspendable input.
        outpoint: OutPoint,
    },
    /// Input spends a non-standard script type.
    NonStandardInputScript {
        /// Outpoint of the offending input.
        outpoint: OutPoint,
    },
    /// Total output value exceeds total input value.
    NegativeFee,
    /// Input spendability could not be determined (typically a time-based
    /// relative timelock with missing `prev_mtp`).
    InputSpendabilityUnknown {
        /// Outpoint whose spendability could not be evaluated.
        outpoint: OutPoint,
    },
}

impl core::fmt::Display for MempoolPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MaxWeightExceeded { weight, limit } => {
                write!(
                    f,
                    "transaction weight {weight} exceeds the configured limit of {limit}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "transaction version {version} is not standard")
            }
            Self::LockTimeNotMet(lock_time) => {
                write!(
                    f,
                    "transaction locktime {lock_time} is not yet satisfied by the current chain tip"
                )
            }
            Self::MaxWitnessStackExceeded { outpoint, limit } => {
                write!(
                    f,
                    "input {outpoint} witness stack exceeds the limit of {limit} items"
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
            Self::TxTooSmall {
                non_witness_size,
                min,
            } => {
                write!(
                    f,
                    "non-witness size {non_witness_size} bytes is below the minimum of {min} bytes"
                )
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

    fn default_tip() -> ChainTip {
        ChainTip {
            height: absolute::Height::from_consensus(3_000).unwrap(),
            mtp: absolute::Time::from_consensus(500_001_000).unwrap(),
        }
    }

    #[test]
    fn default_policy_matches_bitcoin_core_v30() {
        let default_policy = MempoolPolicy::default();
        let v30 = MempoolPolicy::bitcoin_core_v30();
        assert_eq!(default_policy.dust_relay_feerate, v30.dust_relay_feerate);
        assert_eq!(default_policy.min_relay_feerate, v30.min_relay_feerate);
        assert_eq!(
            default_policy.max_op_return_aggregate_bytes,
            v30.max_op_return_aggregate_bytes
        );
        assert_eq!(
            default_policy.max_standard_tx_weight,
            v30.max_standard_tx_weight
        );
        assert_eq!(default_policy.max_truc_tx_weight, v30.max_truc_tx_weight);
        assert_eq!(
            default_policy.min_standard_tx_nonwitness_size,
            v30.min_standard_tx_nonwitness_size
        );
        assert_eq!(
            default_policy.max_witness_stack_items,
            v30.max_witness_stack_items
        );
        assert_eq!(default_policy.allowed_versions, v30.allowed_versions);
    }

    #[test]
    fn test_tx_version() {
        let policy = MempoolPolicy::default();
        let tip = default_tip();
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);
        let (selection, mut tx) = build_selection_with_tx(&[input], &[output]);

        // Default version is 2, which is standard.
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Test version 1, which is also standard.
        tx.version = Version::ONE;
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Version 3 (TRUC) is standard under v30+.
        tx.version = Version(3);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Test version 4, which is non-standard.
        tx.version = Version(4);
        assert!(matches!(
            policy.check_post_selection(&selection, &tx, tip),
            Err(MempoolPolicyError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_tx_locktime() {
        let policy = MempoolPolicy::default();
        let tip = default_tip();
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);
        let (selection, mut tx) = build_selection_with_tx(&[input], &[output]);

        // Locktime exactly equal to the tip height.
        tx.lock_time = absolute::LockTime::from_consensus(3_000);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Locktime below the tip height.
        tx.lock_time = absolute::LockTime::from_consensus(2_500);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Locktime above the tip height.
        tx.lock_time = absolute::LockTime::from_consensus(3_001);
        assert!(matches!(
            policy.check_post_selection(&selection, &tx, tip),
            Err(MempoolPolicyError::LockTimeNotMet(_))
        ));

        // Locktime one second below the tip MTP.
        tx.lock_time = absolute::LockTime::from_consensus(500_000_999);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Locktime exactly equal to the tip MTP.
        tx.lock_time = absolute::LockTime::from_consensus(500_001_000);
        assert!(matches!(
            policy.check_post_selection(&selection, &tx, tip),
            Err(MempoolPolicyError::LockTimeNotMet(_))
        ));

        // Locktime above the tip MTP.
        tx.lock_time = absolute::LockTime::from_consensus(500_002_000);
        assert!(matches!(
            policy.check_post_selection(&selection, &tx, tip),
            Err(MempoolPolicyError::LockTimeNotMet(_))
        ));
    }

    #[test]
    fn test_max_tx_weight() {
        let policy = MempoolPolicy::default();
        let tip = default_tip();

        // A normal transaction with 1 input and 1 output.
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);
        let (selection, tx) = build_selection_with_tx(core::slice::from_ref(&input), &[output]);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Heavy transaction with excess weight.
        let outputs_with_excess_weight: Vec<Output> = (0..2_350)
            .map(|_| create_output(p2tr_script(), 1_000))
            .collect();

        let (_, heavy_tx) =
            build_selection_with_tx(&[input], outputs_with_excess_weight.as_slice());

        assert!(heavy_tx.weight() > policy.max_standard_tx_weight);
        assert!(matches!(
            policy.check_max_tx_weight(heavy_tx.weight(), heavy_tx.version),
            Err(MempoolPolicyError::MaxWeightExceeded { .. })
        ));
    }

    #[test]
    fn test_tx_min_non_witness_size() {
        let policy = MempoolPolicy::default();
        let tip = default_tip();
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);

        // Transaction with 1 input and 1 output.
        let (selection, tx) = build_selection_with_tx(&[input], &[output]);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

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
        assert!(tx_below_min_non_witness_size.base_size() < policy.min_standard_tx_nonwitness_size);
        assert!(matches!(
            policy.check_post_selection(&empty_selection, &tx_below_min_non_witness_size, tip),
            Err(MempoolPolicyError::TxTooSmall { .. })
        ));
    }

    #[test]
    fn test_min_fee_relay() {
        let policy = MempoolPolicy::default();
        let tip = default_tip();

        // Sufficient fee passes.
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);

        let (selection, tx) = build_selection_with_tx(&[input], &[output]);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());

        // Fee below the 1 sat/vB minimum is rejected.
        let input_with_insufficient_fee = setup_test_input(2_000).unwrap();
        let output_with_insufficient_fee = create_output(p2tr_script(), 9_999);

        let (selection_with_insufficient_fee, tx_with_insufficient_fee) = build_selection_with_tx(
            &[input_with_insufficient_fee],
            &[output_with_insufficient_fee],
        );
        assert!(matches!(
            policy.check_post_selection(
                &selection_with_insufficient_fee,
                &tx_with_insufficient_fee,
                tip
            ),
            Err(MempoolPolicyError::MinRelayFeeNotMet { .. })
        ));
    }

    #[test]
    fn test_max_witness_stack() {
        let policy = MempoolPolicy::default();
        let input = setup_test_input(2_000).unwrap();

        assert!(policy.check_max_witness_stack(&[input]).is_ok());
    }

    #[test]
    fn test_input_spendability() {
        let policy = MempoolPolicy::default();
        let tip = default_tip();

        // Confirmed input.
        let input = setup_test_input(2_000).unwrap();
        assert!(policy.check_input_spendability(&[input], tip).is_ok());

        // Immature coinbase (within COINBASE_MATURITY of the tip).
        let input_with_immature_coinbase = setup_test_input(2_950).unwrap();
        assert!(policy
            .check_input_spendability(&[input_with_immature_coinbase], tip)
            .is_err());
    }

    #[test]
    fn test_input_script_type() {
        let policy = MempoolPolicy::default();
        let input = setup_test_input(2_000).unwrap();
        assert!(policy.check_input_script_type(&[input]).is_ok());
    }

    #[test]
    fn test_custom_policy_overrides_default() {
        // A custom policy that allows only v3 (TRUC) transactions.
        static V3_ONLY: &[Version] = &[Version(3)];
        let policy = MempoolPolicy {
            allowed_versions: V3_ONLY,
            ..MempoolPolicy::default()
        };

        let tip = default_tip();
        let input = setup_test_input(2_000).unwrap();
        let output = create_output(p2tr_script(), 9_000);
        let (selection, mut tx) = build_selection_with_tx(&[input], &[output]);

        // v2 (the default tx version) is now rejected.
        tx.version = Version::TWO;
        assert!(matches!(
            policy.check_post_selection(&selection, &tx, tip),
            Err(MempoolPolicyError::UnsupportedVersion(_))
        ));

        // v3 passes.
        tx.version = Version(3);
        assert!(policy.check_post_selection(&selection, &tx, tip).is_ok());
    }
}
