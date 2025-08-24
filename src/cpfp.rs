use crate::{cs_feerate, Input, Output, ScriptSource, Selection};
use alloc::vec::Vec;
use bdk_coin_select::{Candidate, CoinSelector, Target, TargetFee, TargetOutputs};
use miniscript::bitcoin::{Amount, FeeRate, TxOut, Weight};

/// Parameters for creating a Child-Pays-For-Parent (CPFP) transaction.
///
/// # Assumptions
///
/// This struct assumes the caller has constructed it correctly with:
/// - `package_fee` accurately represents the total fees paid by all parent transactions
/// - `package_weight` accurately represents the total weight of all parent transactions
/// - `inputs` that reference valid, spendable UTXO
/// - `target_package_feerate` is set to a value higher than the current effective
///   package feerate (package_fee / package_weight) to make the CPFP effective
/// - `output_script` that produces a valid output script
///
/// Violating these assumptions may result in errors during selection or invalid transactions.
pub struct CpfpParams {
    /// Total fee paid by all parent transactions in the package
    pub package_fee: Amount,
    /// Total weight of all parent transactions in the package
    pub package_weight: Weight,
    /// Inputs to spend in the CPFP transaction
    pub inputs: Vec<Input>,
    /// Target feerate for the entire package (parent txs + child tx)
    pub target_package_feerate: FeeRate,
    /// Script to use for the CPFP transaction output
    pub output_script: ScriptSource,
}

impl CpfpParams {
    /// Create a new [CpfpParams] instance.
    pub fn new(
        package_fee: Amount,
        package_weight: Weight,
        inputs: impl IntoIterator<Item = impl Into<Input>>,
        target_package_feerate: FeeRate,
        output_script: crate::ScriptSource,
    ) -> Self {
        Self {
            package_fee,
            package_weight,
            inputs: inputs.into_iter().map(Into::into).collect(),
            target_package_feerate,
            output_script,
        }
    }

    /// Convert the CPFP parameters into selection.
    ///
    /// This method calculates the required child transaction fee to achieve the
    /// target package feerate and creates a selection with the appropriate inputs
    /// and outputs.
    pub fn into_selection(self) -> Result<Selection, CpfpError> {
        if self.inputs.is_empty() {
            return Err(CpfpError::NoSpendableOutputs);
        }

        // Create candidates for coin selection
        let candidates = self
            .inputs
            .iter()
            .map(|input| {
                Candidate::new(
                    input.prev_txout().value.to_sat(),
                    input.satisfaction_weight(),
                    input.is_segwit(),
                )
            })
            .collect::<Vec<_>>();

        // Select all inputs
        let mut selector = CoinSelector::new(&candidates);
        selector.select_all();

        // Prepare output to calculate weight
        let script_pubkey = self.output_script.script();
        let output = TxOut {
            value: Amount::ZERO,
            script_pubkey: script_pubkey.clone(),
        };
        let output_weight = output.weight().to_wu();

        // Calculate required child fee
        let child_weight = self.compute_child_tx_weight(&selector, output_weight);
        let child_fee = self.compute_child_fee(child_weight)?;

        let total_input_value = Amount::from_sat(selector.selected_value());

        let output_value = total_input_value
            .checked_sub(child_fee)
            .ok_or(CpfpError::InsufficientInputValue)?;

        let dust_threshold = script_pubkey.minimal_non_dust();
        if output_value < dust_threshold {
            return Err(CpfpError::OutputBelowDustLimit);
        }

        // Validate we achieve the target package feerate
        let actual_package_feerate = self.compute_package_feerate(child_fee, child_weight);
        if actual_package_feerate < self.target_package_feerate {
            return Err(CpfpError::InsufficientPackageFeerate {
                actual: actual_package_feerate,
                target: self.target_package_feerate,
            });
        }

        // Verify the selection meets coin selection constraints
        let target = Target {
            fee: TargetFee {
                rate: cs_feerate(self.target_package_feerate),
                replace: None,
            },
            outputs: TargetOutputs::fund_outputs(vec![(output_weight, output_value.to_sat())]),
        };
        if !selector.is_target_met(target) {
            return Err(CpfpError::InsufficientInputValue);
        }

        let outputs = vec![Output::with_script(script_pubkey, output_value)];

        Ok(Selection {
            inputs: self.inputs,
            outputs,
        })
    }

    /// Computes the effective package feerate given the child fee and weight.
    pub fn compute_package_feerate(&self, child_fee: Amount, child_weight: Weight) -> FeeRate {
        let total_fee = self.package_fee + child_fee;
        let total_weight = self.package_weight + child_weight;

        total_fee / total_weight
    }

    /// Computes the required child fee to achieve target package feerate
    pub fn compute_child_fee(&self, child_weight: Weight) -> Result<Amount, CpfpError> {
        let total_target_weight = self.package_weight + child_weight;
        let required_package_fee = self.target_package_feerate * total_target_weight;

        required_package_fee
            .checked_sub(self.package_fee)
            .ok_or(CpfpError::InvalidFeeCalculation)
    }

    /// Computes the weight of the child transaction.
    ///
    /// Uses the provided `selector` for input weights and `output_weight` for the output.
    fn compute_child_tx_weight(&self, selector: &CoinSelector, output_weight: u64) -> Weight {
        const BASE_TX_WEIGHT: u64 = 10 * 4; // version, locktime, input/output counts
        let input_weight = selector.input_weight();

        Weight::from_wu(BASE_TX_WEIGHT + input_weight + output_weight)
    }
}

/// CPFP errors.
#[derive(Debug)]
pub enum CpfpError {
    /// Output value is below the dust threshold.
    OutputBelowDustLimit,
    /// Total input value is insufficient.
    InsufficientInputValue,
    /// No spendable outputs were found.
    NoSpendableOutputs,
    /// Failed to compute a valid fee for the child transaction.
    InvalidFeeCalculation,
    /// The package feerate (parent + child) is lower than the target feerate.
    InsufficientPackageFeerate {
        /// The actual feerate of the package.
        actual: FeeRate,
        /// The target feerate that the package should meet or exceed.
        target: FeeRate,
    },
    /// Output script is invalid
    InvalidOutputScript,
}

impl core::fmt::Display for CpfpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutputBelowDustLimit => write!(f, "output value is below dust threshold"),
            Self::InsufficientInputValue => {
                write!(f, "input value insufficient to cover required fee")
            }
            Self::NoSpendableOutputs => {
                write!(f, "no spendable outputs found in parent transactions")
            }
            Self::InvalidFeeCalculation => {
                write!(f, "failed to calculate valid child transaction fee")
            }
            Self::InsufficientPackageFeerate { actual, target } => write!(
                f,
                "package feerate {actual} is below target feerate {target}"
            ),
            Self::InvalidOutputScript => write!(f, "output script is invalid or empty"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CpfpError {}
