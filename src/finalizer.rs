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
/// For an unfinalized input, only the spending path selected by its `Plan` is used. Signatures
/// for another valid path do not cause the finalizer to select a different plan. Inputs with
/// either `final_script_sig` or `final_script_witness` already set are treated as finalized
/// without checking their satisfaction against the plan.
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
/// # let keymap = std::collections::BTreeMap::new();
/// # let selection: bdk_tx::Selection = unimplemented!();
/// // Create PSBT from a selection of inputs and outputs.
/// let mut psbt = selection.create_psbt(PsbtParams::default())?;
///
/// // Sign the PSBT using your preferred method.
/// let signer = bdk_tx::Signer(keymap);
/// let _ = psbt.sign(&signer, &secp);
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
    /// An unfinalized input is satisfied using the plan registered for its outpoint, without
    /// searching for alternative spending paths. Returns `Ok(false)` if no plan is registered.
    /// If either `final_script_sig` or `final_script_witness` is already set, returns `Ok(true)`
    /// without consulting the plan or validating the final scripts, and leaves the PSBT unchanged.
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
    /// for each input that was not already finalized. Inputs with either `final_script_sig` or
    /// `final_script_witness` already set are skipped without checking their satisfaction against
    /// the plan and are omitted from the map. If all remaining inputs finalize successfully,
    /// the `bip32_derivation`, `tap_key_origins`, and `tap_internal_key` fields of each output
    /// are cleared, including when every input was already finalized.
    pub fn finalize(&self, psbt: &mut Psbt) -> FinalizeMap {
        let mut result = FinalizeMap(BTreeMap::new());

        for input_index in 0..psbt.inputs.len() {
            let psbt_input = &psbt.inputs[input_index];
            if psbt_input.final_script_sig.is_some() || psbt_input.final_script_witness.is_some() {
                continue;
            }
            result
                .0
                .insert(input_index, self.finalize_input(psbt, input_index));
        }

        // clear psbt outputs
        if result.is_finalized() {
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

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use crate::{Finalizer, Output, PsbtParams, Selection, Signer};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{absolute, transaction, Amount, ScriptBuf, TxIn, TxOut};
    use miniscript::bitcoin;
    use miniscript::bitcoin::Transaction;
    use miniscript::plan::Assets;
    use miniscript::Descriptor;

    const TR_XPRV: &str = "tr(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/86h/1h/0h/0/*)";
    const WPKH_XPRV: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84h/1h/0h/0/*)";
    const PKH_XPRV: &str = "pkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/44h/1h/0h/0/*)";

    fn create_input_from_descriptor_at(
        descriptor: &str,
        derivation_index: u32,
    ) -> anyhow::Result<(crate::Input, miniscript::descriptor::KeyMap)> {
        let secp = Secp256k1::new();
        let (desc, keymap) = Descriptor::parse_descriptor(&secp, descriptor)?;
        let def_desc = desc.at_derivation_index(derivation_index)?;
        let script_pubkey = def_desc.script_pubkey();

        let assets = keymap.keys().fold(Assets::new(), |a, k| a.add(k.clone()));
        let plan = def_desc.plan(&assets).expect("failed to create plan");

        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey,
                value: Amount::from_sat(100_000),
            }],
        };

        let status = crate::ConfirmationStatus::new(1_000, Some(500_000_000))?;
        let input = crate::Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;
        Ok((input, keymap))
    }

    fn derive_descriptor_at(
        descriptor: &str,
        derivation_index: u32,
    ) -> anyhow::Result<crate::DefiniteDescriptor> {
        let secp = Secp256k1::new();
        let (descriptor, _) = Descriptor::parse_descriptor(&secp, descriptor)?;
        Ok(descriptor.at_derivation_index(derivation_index)?)
    }

    #[test]
    fn test_finalize_single_input() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        let is_finalized = finalizer.finalize_input(&mut psbt, 0)?;
        assert!(is_finalized);
        assert!(psbt.inputs[0].final_script_witness.is_some());

        Ok(())
    }

    #[test]
    fn test_finalize_sets_final_script_sig() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(PKH_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        assert!(finalizer.finalize_input(&mut psbt, 0)?);
        assert!(psbt.inputs[0].final_script_sig.is_some());

        Ok(())
    }

    #[test]
    fn test_finalize_all_inputs() -> anyhow::Result<()> {
        let (input_0, keymap_0) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let (input_1, keymap_1) = create_input_from_descriptor_at(TR_XPRV, 1)?;
        let (input_2, keymap_2) = create_input_from_descriptor_at(TR_XPRV, 2)?;
        let taproot_output_descriptor = derive_descriptor_at(TR_XPRV, 10)?;
        let wpkh_output_descriptor = derive_descriptor_at(WPKH_XPRV, 11)?;

        let selection = Selection::new(
            vec![input_0, input_1, input_2],
            vec![
                Output::with_descriptor(taproot_output_descriptor, Amount::from_sat(20_000)),
                Output::with_descriptor(wpkh_output_descriptor, Amount::from_sat(22_000)),
            ],
        );

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        assert!(!psbt.outputs[0].tap_key_origins.is_empty());
        assert!(psbt.outputs[0].tap_internal_key.is_some());
        assert!(!psbt.outputs[1].bip32_derivation.is_empty());

        let secp = Secp256k1::new();
        let mut combined_keymap = keymap_0;
        combined_keymap.extend(keymap_1);
        combined_keymap.extend(keymap_2);
        let signer = Signer(combined_keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        let finalized = finalizer.finalize(&mut psbt);
        assert!(finalized.is_finalized());
        let finalize_results = finalized.results();

        assert!(finalize_results
            .values()
            .all(|result| matches!(result, Ok(true))));

        for psbt_input in psbt.inputs.iter() {
            assert!(psbt_input.final_script_witness.is_some());
        }

        // Output metadata should be cleared after finalization.
        for psbt_output in psbt.outputs.iter() {
            assert!(psbt_output.bip32_derivation.is_empty());
            assert!(psbt_output.tap_key_origins.is_empty());
            assert!(psbt_output.tap_internal_key.is_none());
        }

        Ok(())
    }

    #[test]
    fn test_finalize_missing_plan() -> anyhow::Result<()> {
        let (input_0, keymap_0) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let (input_1, keymap_1) = create_input_from_descriptor_at(TR_XPRV, 1)?;
        let taproot_output_descriptor = derive_descriptor_at(TR_XPRV, 10)?;
        let wpkh_output_descriptor = derive_descriptor_at(WPKH_XPRV, 11)?;
        let finalizer = Finalizer::new([(
            input_0.prev_outpoint(),
            input_0.plan().cloned().expect("plan must exist"),
        )]);

        let selection = Selection::new(
            vec![input_0, input_1],
            vec![
                Output::with_descriptor(taproot_output_descriptor, Amount::from_sat(20_000)),
                Output::with_descriptor(wpkh_output_descriptor, Amount::from_sat(22_000)),
            ],
        );

        let mut psbt = selection.create_psbt(PsbtParams::default())?;

        let tap_key_origins = psbt.outputs[0].tap_key_origins.clone();
        let tap_internal_key = psbt.outputs[0].tap_internal_key;
        let bip32_derivation = psbt.outputs[1].bip32_derivation.clone();

        let secp = Secp256k1::new();
        let mut combined_keymap = keymap_0;
        combined_keymap.extend(keymap_1);
        let signer = Signer(combined_keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        let finalized = finalizer.finalize(&mut psbt);
        assert!(!finalized.is_finalized());
        let finalize_results = finalized.results();

        assert!(matches!(finalize_results.get(&0), Some(Ok(true))));
        assert!(matches!(finalize_results.get(&1), Some(Ok(false))));
        assert!(psbt.inputs[0].final_script_witness.is_some());
        assert!(psbt.inputs[1].final_script_witness.is_none());
        assert_eq!(psbt.outputs[0].tap_key_origins, tap_key_origins);
        assert_eq!(psbt.outputs[0].tap_internal_key, tap_internal_key);
        assert_eq!(psbt.outputs[1].bip32_derivation, bip32_derivation);

        Ok(())
    }

    #[test]
    fn test_finalize_returns_error_and_preserves_output_metadata() -> anyhow::Result<()> {
        let (input, _) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let taproot_output_descriptor = derive_descriptor_at(TR_XPRV, 10)?;
        let wpkh_output_descriptor = derive_descriptor_at(WPKH_XPRV, 11)?;
        let selection = Selection::new(
            vec![input],
            vec![
                Output::with_descriptor(taproot_output_descriptor, Amount::from_sat(20_000)),
                Output::with_descriptor(wpkh_output_descriptor, Amount::from_sat(22_000)),
            ],
        );

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let tap_key_origins = psbt.outputs[0].tap_key_origins.clone();
        let tap_internal_key = psbt.outputs[0].tap_internal_key;
        let bip32_derivation = psbt.outputs[1].bip32_derivation.clone();

        // Skip signing to create error
        let finalized = finalizer.finalize(&mut psbt);
        assert!(!finalized.is_finalized());
        let finalize_results = finalized.results();

        assert!(matches!(finalize_results.get(&0), Some(Err(_))));
        assert!(psbt.inputs[0].final_script_sig.is_none());
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert_eq!(psbt.outputs[0].tap_key_origins, tap_key_origins);
        assert_eq!(psbt.outputs[0].tap_internal_key, tap_internal_key);
        assert_eq!(psbt.outputs[1].bip32_derivation, bip32_derivation);

        Ok(())
    }

    #[test]
    fn test_finalize_selected_plan() -> anyhow::Result<()> {
        use alloc::{format, string::ToString, vec::Vec};
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Message, PublicKey, SecretKey};
        use bitcoin::sighash::{Prevouts, SighashCache};
        use bitcoin::{ecdsa, EcdsaSighashType, OutPoint, Psbt, Sequence, Txid};
        use core::str::FromStr;
        use miniscript::{psbt::PsbtExt, DescriptorPublicKey, Interpreter};

        let secp = Secp256k1::new();
        let secrets = [1_u8, 2, 3].map(|byte| SecretKey::from_slice(&[byte; 32]).unwrap());
        let public = secrets
            .map(|secret| bitcoin::PublicKey::new(PublicKey::from_secret_key(&secp, &secret)));
        // This P2WSH script can be spent by A alone or by B and C together.
        // Raw public keys and the synthetic prevout are network-independent.
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "wsh(or_d(pk({}),and_v(v:pk({}),pk({}))))",
            public[0], public[1], public[2]
        ))?
        .at_derivation_index(0)?;
        let assets = Assets::new().add(DescriptorPublicKey::from_str(&public[0].to_string())?);
        let plan = descriptor.clone().plan(&assets).expect("A plan must exist");
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: descriptor.script_pubkey(),
        };
        let outpoint = OutPoint::new(Txid::from_byte_array([3; 32]), 0);
        let (taproot_output_descriptor, _) = Descriptor::parse_descriptor(&secp, TR_XPRV)?;
        let (wpkh_output_descriptor, _) = Descriptor::parse_descriptor(&secp, WPKH_XPRV)?;
        let output_descriptors = [
            taproot_output_descriptor.at_derivation_index(10)?,
            wpkh_output_descriptor.at_derivation_index(11)?,
        ];
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }],
            output: output_descriptors
                .iter()
                .map(|descriptor| TxOut {
                    value: Amount::from_sat(45_000),
                    script_pubkey: descriptor.script_pubkey(),
                })
                .collect(),
        };
        let witness_script = descriptor.explicit_script()?;
        let sighash = SighashCache::new(&tx).p2wsh_signature_hash(
            0,
            &witness_script,
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let message = Message::from_digest(sighash.to_byte_array());
        let signatures =
            secrets.map(|secret| ecdsa::Signature::sighash_all(secp.sign_ecdsa(&message, &secret)));
        let mut psbt = Psbt::from_unsigned_tx(tx)?;
        for (index, descriptor) in output_descriptors.iter().enumerate() {
            psbt.update_output_with_descriptor(index, descriptor)?;
        }
        psbt.inputs[0].witness_utxo = Some(prevout.clone());
        plan.update_psbt_input(&mut psbt.inputs[0]);
        let mut a = psbt.clone();
        a.inputs[0].partial_sigs.insert(public[0], signatures[0]);
        let mut bc = psbt;
        bc.inputs[0].partial_sigs.insert(public[1], signatures[1]);
        bc.inputs[0].partial_sigs.insert(public[2], signatures[2]);
        let finalizer = Finalizer::new([(outpoint, plan)]);

        // The selected A path succeeds with A's signature.
        assert!(finalizer.finalize_input(&mut a, 0)?);
        assert!(a.inputs[0].final_script_witness.is_some());

        // Valid signatures for B+C cannot satisfy the selected A plan.
        let before = bc.serialize();
        assert!(finalizer.finalize_input(&mut bc, 0).is_err());
        assert!(bc.inputs[0].final_script_sig.is_none());
        assert!(bc.inputs[0].final_script_witness.is_none());
        assert_eq!(bc.serialize(), before);

        // Generic Miniscript finalization can choose the alternative B+C path.
        bc.finalize_mut(&secp).expect("B+C path must finalize");
        assert!(bc.inputs[0].final_script_witness.is_some());
        assert!(!bc.outputs[0].tap_key_origins.is_empty());
        assert!(bc.outputs[0].tap_internal_key.is_some());
        assert!(!bc.outputs[1].bip32_derivation.is_empty());
        let before = bc.serialize();
        // An already-finalized input bypasses the selected plan check.
        assert!(finalizer.finalize_input(&mut bc, 0)?);
        assert_eq!(bc.serialize(), before);
        // Unlike finalize_input, finalize clears output metadata even when it skips every input.
        let finalized = finalizer.finalize(&mut bc);
        assert!(finalized.is_finalized());
        assert!(finalized.results().is_empty());
        for output in &bc.outputs {
            assert!(output.bip32_derivation.is_empty());
            assert!(output.tap_key_origins.is_empty());
            assert!(output.tap_internal_key.is_none());
        }

        // Check both witnesses and their signatures against the spending transaction.
        for psbt in [a, bc] {
            let tx = psbt.extract_tx()?;
            let input = &tx.input[0];
            let interpreter = Interpreter::from_txdata(
                &prevout.script_pubkey,
                &input.script_sig,
                &input.witness,
                input.sequence,
                tx.lock_time,
            )?;
            let prevouts = [prevout.clone()];
            let conditions = interpreter
                .iter(&secp, &tx, 0, &Prevouts::All(&prevouts))
                .collect::<Result<Vec<_>, _>>()?;
            assert!(!conditions.is_empty());
        }

        Ok(())
    }

    #[test]
    fn test_already_finalized_input() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        assert!(finalizer.finalize_input(&mut psbt, 0)?);

        let final_script_sig = psbt.inputs[0].final_script_sig.clone();
        let final_script_witness = psbt.inputs[0].final_script_witness.clone();

        // 2nd finalize_input should not change anything
        assert!(finalizer.finalize_input(&mut psbt, 0)?);
        assert_eq!(psbt.inputs[0].final_script_sig, final_script_sig);
        assert_eq!(psbt.inputs[0].final_script_witness, final_script_witness);

        let finalized = finalizer.finalize(&mut psbt);
        assert!(finalized.is_finalized());
        let results = finalized.results();

        assert!(results.is_empty());
        assert_eq!(psbt.inputs[0].final_script_sig, final_script_sig);
        assert_eq!(psbt.inputs[0].final_script_witness, final_script_witness);

        Ok(())
    }
}
