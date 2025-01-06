use bitcoin::{OutPoint, Psbt, Transaction, TxOut, Txid, Witness};
use miniscript::{
    bitcoin,
    descriptor::DefiniteDescriptorKey,
    plan::Plan,
    psbt::{PsbtExt, PsbtInputSatisfier},
    Descriptor,
};

use crate::collections::{BTreeMap, HashMap};
use crate::PlannedUtxo;

/// Trait describing the actions required to update a PSBT.
pub trait DataProvider {
    /// Get transaction by txid
    fn get_tx(&self, txid: Txid) -> Option<Transaction>;

    /// Get descriptor for txout
    fn get_descriptor_for_txout(&self, txout: &TxOut) -> Option<Descriptor<DefiniteDescriptorKey>>;

    /// Sort transaction inputs and outputs.
    ///
    /// This has a default implementation that does no sorting. The implementation must not alter
    /// the semantics of the transaction in any way, like changing the number of inputs and outputs,
    /// changing scripts or amounts, or otherwise interfere with transaction building.
    fn sort_transaction(&self, _tx: &mut Transaction) {}
}

/// Updater
#[derive(Debug, Default)]
pub(crate) struct Updater {
    pub map: HashMap<OutPoint, PlannedUtxo>,
}

impl Updater {
    /// New
    pub fn new() -> Self {
        Self::default()
    }

    /// Get plan
    fn get_plan(&self, outpoint: &OutPoint) -> Option<&Plan> {
        Some(&self.map.get(outpoint)?.plan)
    }

    // Get txout
    fn get_txout(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.map.get(outpoint).map(|p| p.txout.clone())
    }

    /// Update psbt
    pub fn update_psbt<D>(&self, psbt: &mut Psbt, provider: &D)
    where
        D: DataProvider,
    {
        // update inputs
        for (input_index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
            let outpoint = txin.previous_output;
            let plan = self.get_plan(&outpoint).expect("must have plan");
            let psbt_input = &mut psbt.inputs[input_index];
            plan.update_psbt_input(psbt_input);

            // add non-/witness utxo
            let prevout = self.get_txout(&outpoint).expect("must have txout");
            if prevout.script_pubkey.witness_version().is_some() {
                psbt_input.witness_utxo = Some(prevout);
            } else {
                psbt_input.non_witness_utxo = provider.get_tx(outpoint.txid);
            }
        }

        // update outputs
        for (output_index, txout) in psbt.unsigned_tx.output.clone().into_iter().enumerate() {
            if let Some(desc) = provider.get_descriptor_for_txout(&txout) {
                psbt.update_output_with_descriptor(output_index, &desc)
                    .expect("failed to update psbt output");
            }
        }
    }
}

impl From<Updater> for Finalizer {
    fn from(u: Updater) -> Self {
        Self { map: u.map }
    }
}

/// Finalizer
#[derive(Debug)]
pub struct Finalizer {
    map: HashMap<OutPoint, PlannedUtxo>,
}

impl Finalizer {
    /// Get plan
    fn get_plan(&self, outpoint: &OutPoint) -> Option<&Plan> {
        Some(&self.map.get(outpoint)?.plan)
    }

    /// Finalize a PSBT input and return whether finalization was successful.
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
        let mut finalized = false;
        let outpoint = psbt
            .unsigned_tx
            .input
            .get(input_index)
            .expect("index out of range")
            .previous_output;
        if let Some(plan) = self.get_plan(&outpoint) {
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

        for i in 0..psbt.inputs.len() {
            match self.finalize_input(psbt, i) {
                Ok(is_final) => {
                    if finalized && !is_final {
                        finalized = false;
                    }
                    result.0.insert(i, Ok(is_final));
                }
                Err(e) => {
                    result.0.insert(i, Err(e));
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
