use bitcoin::{
    bip32::{self, DerivationPath, Fingerprint},
    psbt::{self, PsbtSighashType},
    OutPoint, Psbt, Transaction, TxOut, Txid, Witness,
};
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
    fn sort_transaction(&mut self, _tx: &mut Transaction) {}
}

/// Updater
#[derive(Debug)]
pub struct PsbtUpdater {
    psbt: Psbt,
    map: HashMap<OutPoint, PlannedUtxo>,
}

impl PsbtUpdater {
    /// New from `unsigned_tx` and `utxos`
    pub fn new(
        unsigned_tx: Transaction,
        utxos: impl IntoIterator<Item = PlannedUtxo>,
    ) -> Result<Self, psbt::Error> {
        let map: HashMap<_, _> = utxos.into_iter().map(|p| (p.outpoint, p)).collect();
        debug_assert!(
            unsigned_tx
                .input
                .iter()
                .all(|txin| map.contains_key(&txin.previous_output)),
            "all spends must be accounted for",
        );
        let psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        Ok(Self { psbt, map })
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
    pub fn update_psbt<D>(&mut self, provider: &D, opt: UpdateOptions)
    where
        D: DataProvider,
    {
        // update inputs
        for (input_index, txin) in self.psbt.unsigned_tx.input.iter().enumerate() {
            let outpoint = txin.previous_output;
            let plan = self.get_plan(&outpoint).expect("must have plan").clone();
            let prevout = self.get_txout(&outpoint).expect("must have txout");

            // update input with plan
            let psbt_input = &mut self.psbt.inputs[input_index];
            plan.update_psbt_input(psbt_input);

            // add non-/witness utxo
            if prevout.script_pubkey.witness_version().is_some() {
                psbt_input.witness_utxo = Some(prevout.clone());
            }
            if !prevout.script_pubkey.is_p2tr() && !opt.only_witness_utxo {
                psbt_input.non_witness_utxo = provider.get_tx(outpoint.txid);
            }
        }

        // update outputs
        for (output_index, txout) in self.psbt.unsigned_tx.output.clone().into_iter().enumerate() {
            if let Some(desc) = provider.get_descriptor_for_txout(&txout) {
                self.psbt
                    .update_output_with_descriptor(output_index, &desc)
                    .expect("failed to update psbt output");
            }
        }
    }

    /// Add a [`bip32::Xpub`] and key origin to the psbt global xpubs
    pub fn add_global_xpub(&mut self, xpub: bip32::Xpub, origin: (Fingerprint, DerivationPath)) {
        self.psbt.xpub.insert(xpub, origin);
    }

    /// Set a `sighash_type` for the psbt input at `index`
    pub fn sighash_type(&mut self, index: usize, sighash_type: Option<PsbtSighashType>) {
        if let Some(psbt_input) = self.psbt.inputs.get_mut(index) {
            psbt_input.sighash_type = sighash_type;
        }
    }

    /// Convert this updater into a [`Finalizer`] and return the updated [`Psbt`].
    pub fn into_finalizer(self) -> (Psbt, Finalizer) {
        (self.psbt, Finalizer { map: self.map })
    }
}

/// Options for updating a PSBT
#[derive(Debug, Default)]
pub struct UpdateOptions {
    /// Only set the input `witness_utxo` if applicable, i.e. do not set `non_witness_utxo`.
    ///
    /// Defaults to `false` which will set the `non_witness_utxo` for non-taproot inputs
    pub only_witness_utxo: bool,
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
