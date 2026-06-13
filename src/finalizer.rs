use crate::collections::{BTreeMap, HashMap};
use bitcoin::{psbt::PsbtSighashType, OutPoint, Psbt, Witness};
use miniscript::{bitcoin, miniscript::satisfy::Placeholder, plan::Plan, psbt::PsbtInputSatisfier};

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
/// This type fills the [BIP174] *Input Finalizer* role: it consumes signatures already present in
/// the PSBT and assembles the final witness/scriptSig.
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
    /// Create a [`Finalizer`] from a set of `(outpoint, plan)` pairs, mapping each input's
    /// previous output to the spending [`Plan`] used to satisfy it.
    pub fn new(plans: impl IntoIterator<Item = (OutPoint, Plan)>) -> Self {
        Self {
            plans: plans.into_iter().collect(),
        }
    }

    /// Finalize a single PSBT input using its registered spending [`Plan`].
    ///
    /// * Returns `Ok(true)` if the input was finalized (or was already finalized).
    /// * Returns `Ok(false)` if no plan is registered for the input's outpoint (in which case the
    ///   input is left untouched).
    ///
    /// On success, the signature data is consumed into `final_script_sig` /`final_script_witness`
    /// and all non-essential fields are cleared. Only the UTXO, the finalized scripts, and any
    /// unknown/proprietary fields are retained.
    ///
    /// # Errors
    ///
    /// Returns a [`FinalizeError`]:
    ///
    /// * [`SighashMismatch`] - a signature's sighash type disagrees with the input's declared
    ///   `PSBT_IN_SIGHASH_TYPE`.
    /// * [`SighashNotAllowed`] - no type is declared and a signature is neither `DEFAULT` nor `ALL`.
    /// * [`SignatureTooLarge`] - a satisfied witness is larger than the plan committed to.
    /// * [`Satisfaction`] - the plan cannot be satisfied from the data present in the PSBT.
    ///
    /// Only [`SighashMismatch`] is mandated by [BIP174]; [`SighashNotAllowed`] and
    /// [`SignatureTooLarge`] are stricter-than-spec safeguards this finalizer adds.
    ///
    /// [BIP174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer>
    ///
    /// # Panics
    ///
    /// - If `input_index` is out of bounds for the PSBT's input vector.
    ///
    /// [`SighashMismatch`]: FinalizeError::SighashMismatch
    /// [`SighashNotAllowed`]: FinalizeError::SighashNotAllowed
    /// [`SignatureTooLarge`]: FinalizeError::SignatureTooLarge
    /// [`Satisfaction`]: FinalizeError::Satisfaction
    pub fn finalize_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
    ) -> Result<bool, FinalizeError> {
        let psbt_in = &psbt.inputs[input_index];
        let outpoint = psbt.unsigned_tx.input[input_index].previous_output;

        // return true if already finalized.
        if psbt_in.final_script_sig.is_some() || psbt_in.final_script_witness.is_some() {
            return Ok(true);
        }

        // We cannot finalize inputs which have no registered plan.
        let plan = match self.plans.get(&outpoint) {
            Some(plan) => plan,
            None => return Ok(false),
        };

        // Ensure `PSBT_IN_SIGHASH_TYPE` is respected (as per BIP174).
        // If unset, only permit ALL/DEFAULT (stricter-than-spec safeguard).
        let mut psbt_in_sighashes = {
            let partial_sigs = psbt_in.partial_sigs.values().map(|s| s.sighash_type as u32);
            let tap_key_sig = psbt_in.tap_key_sig.iter().map(|s| s.sighash_type as u32);
            let tap_script_sigs = psbt_in
                .tap_script_sigs
                .values()
                .map(|s| s.sighash_type as u32);
            partial_sigs.chain(tap_key_sig).chain(tap_script_sigs)
        };
        if let Some(in_sighash_type) = psbt_in.sighash_type {
            let exp_sighash_type = in_sighash_type.to_u32();
            if let Some(sighash_mismatch) = psbt_in_sighashes.find(|&t| t != exp_sighash_type) {
                return Err(FinalizeError::SighashMismatch {
                    expected: PsbtSighashType::from_u32(exp_sighash_type),
                    got: PsbtSighashType::from_u32(sighash_mismatch),
                });
            }
        } else if let Some(sighash_mismatch) = psbt_in_sighashes.find(|&t| t > 0x01 /*ALL*/) {
            return Err(FinalizeError::SighashNotAllowed {
                got: PsbtSighashType::from_u32(sighash_mismatch),
            });
        }

        // Ensure input can be satisfied.
        let stfr = PsbtInputSatisfier::new(psbt, input_index);
        let (stack, script) = plan.satisfy(&stfr).map_err(FinalizeError::Satisfaction)?;

        // Compare signature sizes against plan.
        //
        // Only schnorr placeholders are checked, because schnorr is the only signature type whose
        // size is a plan-time choice: 64 bytes for SIGHASH_DEFAULT vs 65 for an explicit sighash.
        //
        // TODO: Add ECDSA checks once upstream adds them.
        for (temp, stack_item) in plan.witness_template().iter().zip(&stack) {
            if let Placeholder::SchnorrSigPk(_, _, size)
            | Placeholder::SchnorrSigPkHash(_, _, size) = temp
            {
                // Only a witness *larger* than the plan is dangerous.
                if stack_item.len() > *size {
                    return Err(FinalizeError::SignatureTooLarge {
                        expected: *size,
                        got: stack_item.len(),
                    });
                }
            }
        }

        // Clear all fields and set back the utxo, final scriptsig, witness and unknown fields.
        let original = core::mem::take(&mut psbt.inputs[input_index]);
        let psbt_input = &mut psbt.inputs[input_index];
        psbt_input.non_witness_utxo = original.non_witness_utxo;
        psbt_input.witness_utxo = original.witness_utxo;
        psbt_input.unknown = original.unknown;
        psbt_input.proprietary = original.proprietary;
        if !script.is_empty() {
            psbt_input.final_script_sig = Some(script);
        }
        if !stack.is_empty() {
            psbt_input.final_script_witness = Some(Witness::from_slice(&stack));
        }

        Ok(true)
    }

    /// Attempt to finalize all of the inputs.
    ///
    /// Inputs that are already finalized are skipped. Returns a [`FinalizeMap`] holding the
    /// per-input result.
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
pub struct FinalizeMap(BTreeMap<usize, Result<bool, FinalizeError>>);

impl FinalizeMap {
    /// Whether all inputs were finalized
    pub fn is_finalized(&self) -> bool {
        self.0.values().all(|res| matches!(res, Ok(true)))
    }

    /// Get the results as a map of `input_index` to `finalize_input` result.
    pub fn results(self) -> BTreeMap<usize, Result<bool, FinalizeError>> {
        self.0
    }
}

/// Error returned when finalizing a PSBT input.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum FinalizeError {
    /// One of the input's signatures uses a sighash type that disagrees with the input's declared
    /// `PSBT_IN_SIGHASH_TYPE`.
    ///
    /// [BIP174] requires finalizers to fail in this case rather than produce a transaction whose
    /// signatures commit to a different sighash type than was declared.
    ///
    /// [BIP174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer>
    SighashMismatch {
        /// The sighash type declared by the input's `PSBT_IN_SIGHASH_TYPE` field.
        expected: PsbtSighashType,
        /// The sighash type found on the offending signature.
        got: PsbtSighashType,
    },
    /// A signature sighash is not `ALL` or `DEFAULT` while `PSBT_IN_SIGHASH_TYPE` is unset.
    ///
    /// When an input omits `PSBT_IN_SIGHASH_TYPE`, the finalizer assumes the default signing
    /// behavior and accepts only `DEFAULT` or `ALL`. A signature committing to anything else would
    /// silently change the transaction's signing semantics.
    SighashNotAllowed {
        /// The sighash type found on the offending signature.
        got: PsbtSighashType,
    },
    /// A satisfied signature is larger than the size the spending [`Plan`] committed to (e.g. a
    /// 65-byte `SIGHASH_ALL` sig where 64-byte `SIGHASH_DEFAULT` was planned).
    ///
    /// A heavier witness makes the finalized transaction undershoot its target feerate,
    /// potentially leaving it unbroadcastable. Finalization fails rather than emit such a
    /// transaction. A *smaller* witness is permitted, as it would only overpay the fee and stays
    /// broadcastable.
    SignatureTooLarge {
        /// The witness-item size the plan committed to.
        expected: usize,
        /// The actual (larger) size of the satisfied witness item.
        got: usize,
    },
    /// The input's spending [`Plan`] cannot be satisfied with the data present in the PSBT.
    Satisfaction(miniscript::Error),
}

impl core::fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FinalizeError::SighashMismatch { expected, got } => write!(
                f,
                "signature has sighash type ({got}) when ({expected}) is declared in PSBT_IN_SIGHASH_TYPE"
            ),
            FinalizeError::SighashNotAllowed { got } => write!(
                f,
                "signature has sighash type ({got}) but no PSBT_IN_SIGHASH_TYPE is declared; only ALL or DEFAULT are permitted"
            ),
            FinalizeError::SignatureTooLarge { expected, got } => write!(
                f,
                "satisfied signature has size {got} but the plan committed to {expected}; finalizing would undershoot the plan's feerate estimate"
            ),
            FinalizeError::Satisfaction(error) => {
                write!(f, "failed to satisfy spending plan: {error}")
            }
        }
    }
}

impl core::error::Error for FinalizeError {}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use crate::{FinalizeError, Finalizer, Output, PsbtParams, Selection, Signer};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{absolute, transaction, Amount, ScriptBuf, TapSighashType, TxIn, TxOut};
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

    #[test]
    fn test_finalize_sighash_mismatch() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();
        psbt.sign(&Signer(keymap), &Secp256k1::new())
            .expect("signing failed");

        // The signature commits to DEFAULT, but we declare ALL, so the two disagree.
        psbt.inputs[0].sighash_type = Some(TapSighashType::All.into());

        let err = finalizer.finalize_input(&mut psbt, 0).unwrap_err();
        assert!(matches!(err, FinalizeError::SighashMismatch { .. }));

        Ok(())
    }

    #[test]
    fn test_finalize_sighash_not_allowed() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();
        psbt.sign(&Signer(keymap), &Secp256k1::new())
            .expect("signing failed");

        // No PSBT_IN_SIGHASH_TYPE declared, yet the signature uses neither DEFAULT nor ALL.
        psbt.inputs[0]
            .tap_key_sig
            .as_mut()
            .expect("tap key sig")
            .sighash_type = TapSighashType::Single;

        let err = finalizer.finalize_input(&mut psbt, 0).unwrap_err();
        assert!(matches!(err, FinalizeError::SighashNotAllowed { .. }));

        Ok(())
    }
}
