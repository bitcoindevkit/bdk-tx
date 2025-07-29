use crate::{CanonicalUnspents, Input, Output, Selection};
use alloc::vec::Vec;
use bdk_chain::tx_graph::CalculateFeeError;
use miniscript::{
    bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, TxOut, Txid, Weight},
    plan::Plan,
};

/// A structure for creating a CPFP (Child Pays For Parent) transaction.
#[derive(Debug, Clone)]
pub struct CPFPSet {
    /// The total fee paid by the parent transactions.
    pub parent_fee: Amount,
    /// The total weight of the parent transactions.
    pub parent_weight: Weight,
    /// Selected outpoints from parent transactions used to fund the child transaction.
    pub selected_outpoints: Vec<OutPoint>,
}

impl CPFPSet {
    /// Creates a new '[CPFPSet]' from given parent fee, weight, and selected outpoints.
    pub fn new(
        parent_fee: Amount,
        parent_weight: Weight,
        selected_outpoints: Vec<OutPoint>,
    ) -> Self {
        Self {
            parent_fee,
            parent_weight,
            selected_outpoints,
        }
    }

    /// Creates a child transaction that pays for its unconfirmed parent(s)
    pub fn create_cpfp_transaction(
        &self,
        canon_utxos: &CanonicalUnspents,
        target_package_feerate: FeeRate,
        script_pubkey: &ScriptBuf,
        plans: impl IntoIterator<Item = Plan>,
    ) -> Result<Selection, CPFPError> {
        let mut inputs = Vec::new();
        let mut total_input_value = Amount::ZERO;

        // Get inputs from selected outpoints
        for (outpoint, plan) in self.selected_outpoints.iter().zip(plans) {
            if let Some(input) = canon_utxos.try_get_unspent(*outpoint, plan) {
                total_input_value += input.prev_txout().value;
                inputs.push(input);
            } else {
                return Err(CPFPError::NoUnspentOutput(outpoint.txid));
            }
        }

        if inputs.is_empty() {
            return Err(CPFPError::NoSpendableOutputs);
        }

        let child_weight = self.estimate_child_tx_weight(&inputs, script_pubkey);

        // Calculate required child fee
        let child_fee = self.calculate_child_fee(child_weight, target_package_feerate)?;

        // Calculate output value
        let output_value = total_input_value
            .checked_sub(child_fee)
            .ok_or(CPFPError::InsufficientInputValue)?;

        // Check dust threshold
        let dust_threshold = script_pubkey.minimal_non_dust();
        if output_value < dust_threshold {
            return Err(CPFPError::OutputBelowDustLimit);
        }

        // Check if the actual package feerate is lower than the target feerate
        let actual_package_feerate = self.package_feerate(child_fee, child_weight);
        if actual_package_feerate < target_package_feerate {
            return Err(CPFPError::InsufficientPackageFeerate {
                actual: actual_package_feerate,
                target: target_package_feerate,
            });
        }

        let outputs = vec![Output::with_script(script_pubkey.clone(), output_value)];

        Ok(Selection { inputs, outputs })
    }

    fn estimate_child_tx_weight(&self, inputs: &[Input], script_pubkey: &ScriptBuf) -> Weight {
        const BASE_TX_WEIGHT: u64 = 40;

        let inputs_base_weight = inputs.len() as u64 * (36 + 1 + 4) * 4;
        let satisfaction_weight = inputs
            .iter()
            .map(|input| input.satisfaction_weight())
            .sum::<u64>();

        let output = TxOut {
            value: Amount::ZERO,
            script_pubkey: script_pubkey.clone(),
        };
        let output_weight = output.weight().to_wu();

        Weight::from_wu(BASE_TX_WEIGHT + inputs_base_weight + satisfaction_weight + output_weight)
    }

    /// Calculate the required child fee to achieve target package feerate
    pub fn calculate_child_fee(
        &self,
        child_weight: Weight,
        target_package_feerate: FeeRate,
    ) -> Result<Amount, CPFPError> {
        let total_target_weight = self.parent_weight + child_weight;
        let required_package_fee = target_package_feerate * total_target_weight;

        required_package_fee
            .checked_sub(self.parent_fee)
            .ok_or(CPFPError::InvalidFeeCalculation)
    }

    /// Computes the effective package feerate given the child fee and weight.
    pub fn package_feerate(&self, child_fee: Amount, child_weight: Weight) -> FeeRate {
        let total_fee = self.parent_fee + child_fee;
        let total_weight = self.parent_weight + child_weight;

        total_fee / total_weight
    }
}

/// CPFP errors.
#[derive(Debug)]
pub enum CPFPError {
    /// A specified parent transaction ID does not exist.
    MissingParent(Txid),
    /// A parent transaction has no unspent outputs available.
    NoUnspentOutput(Txid),
    /// The number of unconfirmed ancestors exceeds the Bitcoin protocol limit (25).
    ExcessUnconfirmedAncestor,
    /// An error occurred while calculating the fee for a transaction.
    CalculateFee(CalculateFeeError),
    /// Output value is below the dust threshold.
    OutputBelowDustLimit,
    /// The package feerate (parent + child) is lower than the target feerate.
    InsufficientPackageFeerate {
        /// The actual feerate of the package.
        actual: FeeRate,
        /// The target feerate that the package should meet or exceed.
        target: FeeRate,
    },
    /// No spendable outputs were found.
    NoSpendableOutputs,
    /// Failed to compute a valid fee for the child transaction.
    InvalidFeeCalculation,
    /// Total input value is insufficient.
    InsufficientInputValue,
}

impl core::fmt::Display for CPFPError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingParent(txid) => write!(f, "parent transaction {txid} not found"),
            Self::ExcessUnconfirmedAncestor => write!(f, "too many unconfirmed ancestor"),
            Self::NoUnspentOutput(txid) => {
                write!(f, "no unspent output found for parent transaction {txid}")
            }
            Self::CalculateFee(err) => write!(f, "failed to calculate fee: {err}"),
            Self::OutputBelowDustLimit => write!(f, "output value is below dust threshold"),
            Self::InsufficientPackageFeerate { actual, target } => write!(
                f,
                "package feerate {actual} is below target feerate {target}"
            ),

            Self::NoSpendableOutputs => {
                write!(f, "no spendable outputs found in parent transactions")
            }
            Self::InvalidFeeCalculation => {
                write!(f, "failed to calculate valid child transaction fee")
            }
            Self::InsufficientInputValue => {
                write!(f, "input value insufficient to cover required fee")
            }
        }
    }
}

impl From<CalculateFeeError> for CPFPError {
    fn from(err: CalculateFeeError) -> Self {
        CPFPError::CalculateFee(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CPFPError {}
