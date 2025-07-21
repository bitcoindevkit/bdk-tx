use crate::{Input, Output, ScriptSource, Selection};
use alloc::{vec, vec::Vec};
use bdk_coin_select::{Candidate, CoinSelector, DrainWeights, TargetOutputs};
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
#[derive(Debug, Clone)]
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
    /// Convert the CPFP parameters into selection.
    ///
    /// This method calculates the required child transaction fee to achieve the
    /// target package feerate and creates a selection with the appropriate inputs
    /// and outputs.
    pub fn into_selection(self) -> Result<Selection, InsufficientInputValue> {
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

        let total_input_value = Amount::from_sat(selector.selected_value());

        // Prepare output to calculate weight
        let script_pubkey = self.output_script.script();
        let output = TxOut {
            value: Amount::ZERO,
            script_pubkey: script_pubkey.clone(),
        };

        let target_outputs = TargetOutputs::fund_outputs(vec![(output.weight().to_wu(), 0)]);
        let cpfp_tx_weight = Weight::from_wu(selector.weight(target_outputs, DrainWeights::NONE));

        // Calculate required child fee
        let total_package_weight = self.package_weight + cpfp_tx_weight;
        let required_total_package_fee = self.target_package_feerate * total_package_weight;
        let required_child_fee = required_total_package_fee - self.package_fee;

        let output_value = match total_input_value.checked_sub(required_child_fee) {
            Some(value) => value,
            None => {
                let missing = required_child_fee - total_input_value;
                return Err(InsufficientInputValue { missing });
            }
        };

        let outputs = vec![Output::with_script(script_pubkey, output_value)];

        Ok(Selection {
            inputs: self.inputs,
            outputs,
        })
    }
}

/// Error indicating total input value is insufficient to create a valid CPFP transaction.
#[derive(Debug)]
pub struct InsufficientInputValue {
    /// The additional amount needed to create a valid CPFP transaction
    pub missing: Amount,
}

impl core::fmt::Display for InsufficientInputValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "input value insufficient: need {} more satoshis",
            self.missing.to_sat()
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsufficientInputValue {}
