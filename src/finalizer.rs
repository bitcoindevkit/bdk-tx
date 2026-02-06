use crate::collections::{BTreeMap, HashMap};
use bitcoin::{OutPoint, Psbt, Witness};
use miniscript::{bitcoin, plan::Plan, psbt::PsbtInputSatisfier};

/// Type used to finalize inputs of a Partially Signed Bitcoin Transaction (PSBT) using
/// a collection of pre-computed spending plans.
///
/// Finalizing a PSBT involves locating signatures and filling in the `final_script_sig`
/// and/or `final_script_witness` fields of the PSBT input, as specified in [BIP174]. The
/// [`Finalizer`] is able to satisfy inputs for which a valid signature has been provided using
/// the pre-computed spending [`Plan`] for each input. This process converts a PSBT input from a
/// partially signed state to a fully signed state, making it ready for extraction into a valid
/// Bitcoin [`Transaction`].
///
/// # Usage
///
/// Construct a [`Finalizer`] from a list of `(outpoint, plan)` pairs, or by calling
/// [`into_finalizer`] on a particular [`Selection`]. Use [`finalize_input`] to finalize a single
/// input, or [`finalize`] to finalize every input and return a map containing the result of
/// finalization at each index. Upon finalizing the PSBT, the [`Finalizer`] also clears metadata
/// from non-essential fields of the PSBT inputs and outputs, ensuring that only the necessary
/// information remains for transaction extraction.
///
/// # Example
///
/// ```rust,no_run
/// # use bdk_tx::PsbtParams;
/// # let secp = bitcoin::secp256k1::Secp256k1::new();
/// # let keymap = miniscript::descriptor::KeyMap::new();
/// # let selection = bdk_tx::Selection { inputs: vec![], outputs: vec![] };
/// // Create PSBT from a selection of inputs and outputs.
/// let mut psbt = selection.create_psbt(PsbtParams::default())?;
///
/// // Sign the PSBT using your preferred method.
/// let _ = psbt.sign(&keymap, &secp);
///
/// // Finalize the PSBT.
/// let finalizer = selection.into_finalizer();
/// let finalize_map = finalizer.finalize(&mut psbt);
/// assert!(finalize_map.is_finalized());
///
/// // Extract the final transaction.
/// let tx = psbt.extract_tx()?;
/// # Ok::<_, anyhow::Error>(())
/// ```
///
/// [BIP174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer>
/// [`Selection`]: crate::Selection
/// [`into_finalizer`]: crate::Selection::into_finalizer
/// [`Plan`]: miniscript::plan::Plan
/// [`Transaction`]: bitcoin::Transaction
/// [`finalize_input`]: Finalizer::finalize_input
/// [`finalize`]: Finalizer::finalize
#[derive(Debug)]
pub struct Finalizer {
    pub(crate) plans: HashMap<OutPoint, Plan>,
}

impl Finalizer {
    /// Create.
    pub fn new(plans: impl IntoIterator<Item = (OutPoint, Plan)>) -> Self {
        Self {
            plans: plans.into_iter().collect(),
        }
    }

    /// Finalize a PSBT input and return whether finalization was successful or input was already
    /// finalized.
    ///
    /// # Errors
    ///
    /// If the spending plan associated with the PSBT input cannot be satisfied,
    /// then a [`miniscript::Error`] is returned.
    ///
    /// # Panics
    ///
    /// - If `input_index` is outside the bounds of the PSBT input vector.
    pub fn finalize_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
    ) -> Result<bool, miniscript::Error> {
        // return true if already finalized.
        {
            let psbt_input = &psbt.inputs[input_index];
            if psbt_input.final_script_sig.is_some() || psbt_input.final_script_witness.is_some() {
                return Ok(true);
            }
        }

        let mut finalized = false;
        let outpoint = psbt
            .unsigned_tx
            .input
            .get(input_index)
            .expect("index out of range")
            .previous_output;
        if let Some(plan) = self.plans.get(&outpoint) {
            let stfr = PsbtInputSatisfier::new(psbt, input_index);
            let (stack, script) = plan.satisfy(&stfr)?;
            // clearing all fields and setting back the utxo, final scriptsig and witness
            let original = core::mem::take(&mut psbt.inputs[input_index]);
            let psbt_input = &mut psbt.inputs[input_index];
            psbt_input.non_witness_utxo = original.non_witness_utxo;
            psbt_input.witness_utxo = original.witness_utxo;
            if !script.is_empty() {
                psbt_input.final_script_sig = Some(script);
            }
            if !stack.is_empty() {
                psbt_input.final_script_witness = Some(Witness::from_slice(&stack));
            }
            finalized = true;
        }

        Ok(finalized)
    }

    /// Attempt to finalize all of the inputs.
    ///
    /// This method returns a [`FinalizeMap`] that contains the result of finalization
    /// for each input.
    pub fn finalize(&self, psbt: &mut Psbt) -> FinalizeMap {
        let mut finalized = true;
        let mut result = FinalizeMap(BTreeMap::new());

        for input_index in 0..psbt.inputs.len() {
            let psbt_input = &psbt.inputs[input_index];
            if psbt_input.final_script_sig.is_some() || psbt_input.final_script_witness.is_some() {
                continue;
            }
            match self.finalize_input(psbt, input_index) {
                Ok(is_final) => {
                    if finalized && !is_final {
                        finalized = false;
                    }
                    result.0.insert(input_index, Ok(is_final));
                }
                Err(e) => {
                    result.0.insert(input_index, Err(e));
                }
            }
        }

        // clear psbt outputs
        if finalized {
            for psbt_output in &mut psbt.outputs {
                psbt_output.bip32_derivation.clear();
                psbt_output.tap_key_origins.clear();
                psbt_output.tap_internal_key.take();
            }
        }

        result
    }
}

/// Holds the results of finalization
#[derive(Debug)]
pub struct FinalizeMap(BTreeMap<usize, Result<bool, miniscript::Error>>);

impl FinalizeMap {
    /// Whether all inputs were finalized
    pub fn is_finalized(&self) -> bool {
        self.0.values().all(|res| matches!(res, Ok(true)))
    }

    /// Get the results as a map of `input_index` to `finalize_input` result.
    pub fn results(self) -> BTreeMap<usize, Result<bool, miniscript::Error>> {
        self.0
    }
}
