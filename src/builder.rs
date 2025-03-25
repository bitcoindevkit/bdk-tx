use alloc::vec::Vec;
use core::fmt;

use bitcoin::{
    absolute, transaction, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, SignedAmount,
    Transaction, TxIn, TxOut, Weight,
};
use miniscript::{bitcoin, plan::Plan};

use crate::{DataProvider, Finalizer, PsbtUpdater, UpdatePsbtError};

/// A UTXO with spend plan
#[derive(Debug, Clone)]
pub struct PlanUtxo {
    /// plan
    pub plan: Plan,
    /// outpoint
    pub outpoint: OutPoint,
    /// txout
    pub txout: TxOut,
}

/// An output in the transaction, includes a txout and whether the output should be
/// treated as change.
#[derive(Debug, Clone)]
struct Output {
    txout: TxOut,
    is_change: bool,
}

impl Output {
    /// Create a new output
    fn new(script: ScriptBuf, amount: Amount) -> Self {
        Self::from((script, amount))
    }

    /// Create a new change output
    fn new_change(script: ScriptBuf, amount: Amount) -> Self {
        let mut output = Self::new(script, amount);
        output.is_change = true;
        output
    }
}

impl Default for Output {
    fn default() -> Self {
        Self {
            txout: TxOut {
                script_pubkey: ScriptBuf::default(),
                value: Amount::default(),
            },
            is_change: false,
        }
    }
}

impl From<(ScriptBuf, Amount)> for Output {
    fn from(tup: (ScriptBuf, Amount)) -> Self {
        Self {
            txout: TxOut {
                script_pubkey: tup.0,
                value: tup.1,
            },
            ..Default::default()
        }
    }
}

/// Transaction builder
#[derive(Debug, Clone, Default)]
pub struct Builder {
    utxos: Vec<PlanUtxo>,
    outputs: Vec<Output>,
    version: Option<transaction::Version>,
    locktime: Option<absolute::LockTime>,

    sequence: Option<Sequence>,
    check_fee: CheckFee,
}

impl Builder {
    /// New
    pub fn new() -> Self {
        Self::default()
    }

    /// Add outputs to the transaction.
    ///
    /// This should be used for setting outgoing scripts and amounts. If adding a change output,
    /// use [`Builder::add_change_output`] instead.
    pub fn add_outputs(
        &mut self,
        outputs: impl IntoIterator<Item = (ScriptBuf, Amount)>,
    ) -> &mut Self {
        self.outputs.extend(outputs.into_iter().map(Output::from));
        self
    }

    /// Add an output with the given `script` and `amount` to the transaction.
    ///
    /// See also [`add_outputs`](Self::add_outputs).
    pub fn add_output(&mut self, script: ScriptBuf, amount: Amount) -> &mut Self {
        self.add_outputs([(script, amount)]);
        self
    }

    /// Get the target amounts based on the weight and value of all outputs not including change.
    ///
    /// This is a convenience method used for passing target values to a coin selection
    /// implementation.
    pub fn target_outputs(&self) -> impl Iterator<Item = (Weight, Amount)> + '_ {
        self.outputs
            .iter()
            .filter(|out| !out.is_change)
            .cloned()
            .map(|out| (out.txout.weight(), out.txout.value))
    }

    /// Add a change output.
    ///
    /// This should only be used for adding a change output. See [`Builder::add_output`] for
    /// adding an outgoing output. Note that only one output may be designated as change, which
    /// means only the last call to this method will apply to the transaction.
    ///
    /// Note: if combined with [`Builder::check_fee`], the given amount may be adjusted to
    /// meet the desired transaction fee.
    pub fn add_change_output(&mut self, script: ScriptBuf, amount: Amount) -> &mut Self {
        if self.is_change_added() {
            let out = self
                .outputs
                .iter_mut()
                .find(|out| out.is_change)
                .expect("must have change output");
            out.txout = TxOut {
                script_pubkey: script,
                value: amount,
            };
        } else {
            self.outputs.push(Output::new_change(script, amount));
        }
        self
    }

    /// Add an input to fund the tx
    pub fn add_input(&mut self, utxo: impl Into<PlanUtxo>) -> &mut Self {
        self.utxos.push(utxo.into());
        self
    }

    /// Add inputs to be used to fund the tx
    pub fn add_inputs<I>(&mut self, utxos: I) -> &mut Self
    where
        I: IntoIterator,
        I::Item: Into<PlanUtxo>,
    {
        self.utxos.extend(utxos.into_iter().map(Into::into));
        self
    }

    /// Whether a change output has been added to this [`Builder`]
    fn is_change_added(&self) -> bool {
        self.outputs.iter().any(|out| out.is_change)
    }

    /// Target a given fee / feerate of the transaction.
    ///
    /// If change is added, this allows making an adjustment to the value of the change
    /// output to meet the given fee and/or feerate. By default we target a minimum
    /// feerate of 1 sat/vbyte.
    ///
    /// Note: this option may be ignored if meeting the specified fee or feerate would
    /// consume the entire amount of the change.
    pub fn check_fee(&mut self, fee: Option<Amount>, feerate: Option<FeeRate>) {
        let mut check = CheckFee::default();
        if let Some(fee) = fee {
            check.fee = fee;
        }
        if let Some(feerate) = feerate {
            check.feerate = feerate;
        }
        self.check_fee = check;
    }

    /// Use a specific [`transaction::Version`]
    pub fn version(&mut self, version: transaction::Version) -> &mut Self {
        self.version = Some(version);
        self
    }

    /// Use a specific transaction [`LockTime`](absolute::LockTime).
    ///
    /// Note that building a transaction may raise an error if the given locktime has a
    /// different lock type than that of a planned input. The greatest locktime value
    /// among all of the spend plans is what goes into the final tx, so this value
    /// may be ignored if it doesn't increase the overall maximum.
    pub fn locktime(&mut self, locktime: absolute::LockTime) -> &mut Self {
        self.locktime = Some(locktime);
        self
    }

    /// Set a default [`Sequence`] for all inputs. Note that building the tx may raise an
    /// error if the given `sequence` is incompatible with the relative locktime of a
    /// planned input.
    pub fn sequence(&mut self, sequence: Sequence) -> &mut Self {
        self.sequence = Some(sequence);
        self
    }

    /// Add a data-carrying output using `OP_RETURN`.
    ///
    /// # Errors
    ///
    /// - If `data` exceeds 80 bytes in size.
    /// - If this is not the first `OP_RETURN` output being added to this builder.
    ///
    /// Refer to <https://github.com/bitcoin/bitcoin/blob/v28.0/src/policy/policy.cpp> for more
    /// details about transaction standardness.
    pub fn add_data<T>(&mut self, data: T) -> Result<&mut Self, Error>
    where
        T: AsRef<[u8]>,
    {
        if self
            .outputs
            .iter()
            .any(|out| out.txout.script_pubkey.is_op_return())
        {
            return Err(Error::TooManyOpReturn);
        }
        if data.as_ref().len() > 80 {
            return Err(Error::MaxOpReturnRelay);
        }

        let mut bytes = bitcoin::script::PushBytesBuf::new();
        bytes.extend_from_slice(data.as_ref()).expect("should push");

        self.outputs
            .push(Output::new(ScriptBuf::new_op_return(bytes), Amount::ZERO));

        Ok(self)
    }

    /// Build a PSBT with the given data provider and return a [`PsbtUpdater`].
    ///
    /// # Errors
    ///
    /// - If attempting to mix locktime units
    /// - If the tx is illegally constructed or fails one of a number of sanity checks
    ///     defined by the library.
    /// - If a requested locktime or sequence interferes with the locktime constraints
    ///     of a planned input.
    pub fn build_psbt<D>(self, provider: &mut D) -> Result<PsbtUpdater, Error>
    where
        D: DataProvider,
    {
        use absolute::LockTime;

        let version = self.version.unwrap_or(transaction::Version::TWO);

        // accumulate the max required locktime
        let mut lock_time: Option<LockTime> = self.utxos.iter().try_fold(None, |acc, u| match u
            .plan
            .absolute_timelock
        {
            None => Ok(acc),
            Some(lock) => match acc {
                None => Ok(Some(lock)),
                Some(acc) => {
                    if !lock.is_same_unit(acc) {
                        Err(Error::LockTypeMismatch)
                    } else if acc.is_implied_by(lock) {
                        Ok(Some(lock))
                    } else {
                        Ok(Some(acc))
                    }
                }
            },
        })?;

        if let Some(param) = self.locktime {
            match lock_time {
                Some(lt) => {
                    if !lt.is_same_unit(param) {
                        return Err(Error::LockTypeMismatch);
                    }
                    if param.to_consensus_u32() < lt.to_consensus_u32() {
                        return Err(Error::LockTimeCltv {
                            requested: param,
                            required: lt,
                        });
                    }
                    if lt.is_implied_by(param) {
                        lock_time = Some(param);
                    }
                }
                None => lock_time = Some(param),
            }
        }

        let lock_time = lock_time.unwrap_or(LockTime::ZERO);

        let input = self
            .utxos
            .iter()
            .map(|PlanUtxo { plan, outpoint, .. }| {
                Ok(TxIn {
                    previous_output: *outpoint,
                    sequence: match (self.sequence, plan.relative_timelock) {
                        (Some(requested), Some(lt)) => {
                            let required = lt.to_sequence();
                            if !check_nsequence(requested, required) {
                                return Err(Error::SequenceCsv {
                                    requested,
                                    required,
                                });
                            }
                            requested
                        }
                        (None, Some(lt)) => lt.to_sequence(),
                        (Some(seq), None) => seq,
                        (None, None) => Sequence::ENABLE_RBF_NO_LOCKTIME,
                    },
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<TxIn>, Error>>()?;

        let output = self
            .outputs
            .iter()
            .cloned()
            .map(|out| out.txout)
            .collect::<Vec<_>>();

        let mut unsigned_tx = Transaction {
            version,
            lock_time,
            input,
            output,
        };

        // check, validate
        self.sanity_check()?;

        if self.is_change_added() {
            self.do_check_fee(&mut unsigned_tx);
        }

        provider.sort_transaction(&mut unsigned_tx);

        Ok(PsbtUpdater::new(unsigned_tx, self.utxos)?)
    }

    /// Convenience method to build an updated [`Psbt`] and return a [`Finalizer`].
    /// Refer to [`build_psbt`](Self::build_psbt) for more.
    ///
    /// # Errors
    ///
    /// This method returns an error if a problem occurs when either building or updating
    /// the PSBT.
    pub fn build_tx<D>(self, provider: &mut D) -> Result<(Psbt, Finalizer), Error>
    where
        D: DataProvider,
    {
        let mut updater = self.build_psbt(provider)?;
        updater
            .update_psbt(provider, crate::UpdateOptions::default())
            .map_err(Error::Update)?;
        Ok(updater.into_finalizer())
    }

    /// Sanity checks the tx for
    ///
    /// - Negative fee
    /// - Absurd fee: The absurd fee threshold is currently 2x the sum of the outputs
    //
    // TODO: check total amounts, max tx weight, is standard spk
    // - vin/vout not empty
    fn sanity_check(&self) -> Result<(), Error> {
        let total_in: Amount = self.utxos.iter().map(|p| p.txout.value).sum();
        let total_out: Amount = self.outputs.iter().map(|out| out.txout.value).sum();
        if total_out > total_in {
            return Err(Error::NegativeFee(SignedAmount::from_sat(
                total_in.to_sat() as i64 - total_out.to_sat() as i64,
            )));
        }
        let weight = self.estimate_weight();
        if total_in > total_out * 2 {
            let fee = total_in - total_out;
            let feerate = fee / weight;
            return Err(Error::InsaneFee(feerate));
        }

        Ok(())
    }

    /// This will shift the allocation of funds from the change output to the
    /// transaction fee in two cases:
    ///
    /// - if the computed feerate of tx is below a target feerate
    /// - if the computed fee of tx is below a target fee amount
    ///
    /// We have to set an amount by which the change output is allowed to shrink
    /// and still be positive. This will be the value of the change output minus
    /// some amount of dust (546).
    ///
    /// If the target fee or feerate cannot be met without shrinking the change output
    /// to below the dust limit, then no shrinking will occur.
    ///
    /// Panics if `tx` is not a sane tx
    fn do_check_fee(&self, tx: &mut Transaction) {
        const DUST: u64 = 546;
        if !self.is_change_added() {
            return;
        }
        let CheckFee {
            fee: exp_fee,
            feerate: exp_feerate,
        } = self.check_fee;

        // We use these units in the below calculation:
        // fee: u64 satoshi
        // weight: u64 wu
        // feerate: f32 satoshi per 1000 wu
        let fee = self.fee_amount(tx).expect("must be sane tx").to_sat();
        let weight = self.estimate_weight().to_wu();
        let feerate = 1000.0 * fee as f32 / weight as f32;

        let txout = self
            .outputs
            .iter()
            .find(|out| out.is_change)
            .map(|out| out.txout.clone())
            .expect("must have change output");
        let (output_index, _) = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, txo)| **txo == txout)
            .expect("must have txout");

        // check feerate
        if feerate < exp_feerate.to_sat_per_kwu() as f32 {
            let exp_feerate = exp_feerate.to_sat_per_kwu() as f32;
            let exp_fee = (exp_feerate * (weight as f32 / 1000.0)) as u64;
            let delta = exp_fee.saturating_sub(fee);

            let txout = &mut tx.output[output_index];
            if txout.value.to_sat() >= delta + DUST {
                txout.value -= Amount::from_sat(delta);
            }
        }

        // check fee
        let fee = self.fee_amount(tx).expect("must be sane tx");
        if fee < exp_fee {
            let delta = exp_fee - fee;
            let txout = &mut tx.output[output_index];
            if txout.value >= delta + Amount::from_sat(DUST) {
                txout.value -= delta;
            }
        }
    }

    /// Get an estimate of the current tx weight
    pub fn estimate_weight(&self) -> Weight {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: (0..self.utxos.len()).map(|_| TxIn::default()).collect(),
            output: self.outputs.iter().cloned().map(|out| out.txout).collect(),
        }
        .weight()
            + self
                .utxos
                .iter()
                .map(|p| Weight::from_wu_usize(p.plan.satisfaction_weight()))
                .sum()
    }

    /// Returns the tx fee as the sum of the inputs minus the sum of the outputs
    /// returning `None` on overflowing subtraction.
    fn fee_amount(&self, tx: &Transaction) -> Option<Amount> {
        self.utxos
            .iter()
            .map(|p| p.txout.value)
            .sum::<Amount>()
            .checked_sub(tx.output.iter().map(|txo| txo.value).sum::<Amount>())
    }
}

/// Checks that the given `sequence` is compatible with `csv`. To be compatible, both
/// must enable relative locktime, have the same lock type unit, and the requested
/// sequence must be at least the value of `csv`.
fn check_nsequence(sequence: Sequence, csv: Sequence) -> bool {
    debug_assert!(
        csv.is_relative_lock_time(),
        "csv must enable relative locktime"
    );
    if !sequence.is_relative_lock_time() {
        return false;
    }
    if sequence.is_height_locked() != csv.is_height_locked() {
        return false;
    }
    if sequence < csv {
        return false;
    }

    true
}

/// Check fee
#[derive(Debug, Copy, Clone)]
struct CheckFee {
    fee: Amount,
    feerate: FeeRate,
}

impl Default for CheckFee {
    fn default() -> Self {
        Self {
            feerate: FeeRate::from_sat_per_vb_unchecked(1),
            fee: Amount::default(),
        }
    }
}

/// [`Builder`] error
#[derive(Debug)]
pub enum Error {
    /// insane feerate
    InsaneFee(FeeRate),
    /// requested locktime is incompatible with required CLTV
    LockTimeCltv {
        /// requested locktime
        requested: absolute::LockTime,
        /// required locktime
        required: absolute::LockTime,
    },
    /// attempted to mix locktime types
    LockTypeMismatch,
    /// output exceeds data carrier limit
    MaxOpReturnRelay,
    /// negative fee
    NegativeFee(SignedAmount),
    /// bitcoin psbt error
    Psbt(bitcoin::psbt::Error),
    /// requested sequence is incompatible with requirement
    SequenceCsv {
        /// requested sequence
        requested: Sequence,
        /// required sequence
        required: Sequence,
    },
    /// too many `OP_RETURN` in a single tx
    TooManyOpReturn,
    /// error when updating a PSBT
    Update(UpdatePsbtError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsaneFee(r) => write!(f, "absurd feerate: {r:#}"),
            Self::LockTimeCltv {
                requested,
                required,
            } => write!(
                f,
                "requested locktime {requested} must be at least {required}"
            ),
            Self::LockTypeMismatch => write!(f, "cannot mix locktime units"),
            Self::MaxOpReturnRelay => write!(f, "non-standard: output exceeds data carrier limit"),
            Self::NegativeFee(e) => write!(f, "illegal tx: negative fee: {}", e.display_dynamic()),
            Self::Psbt(e) => e.fmt(f),
            Self::SequenceCsv {
                requested,
                required,
            } => write!(f, "{requested} is incompatible with required {required}"),
            Self::TooManyOpReturn => write!(f, "non-standard: only 1 OP_RETURN output permitted"),
            Self::Update(e) => e.fmt(f),
        }
    }
}

impl From<bitcoin::psbt::Error> for Error {
    fn from(e: bitcoin::psbt::Error) -> Self {
        Self::Psbt(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Signer;
    use alloc::string::String;

    use bitcoin::{
        secp256k1::{self, Secp256k1},
        Txid,
    };
    use miniscript::{
        descriptor::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, KeyMap},
        plan::Assets,
        ForEachKey,
    };

    use bdk_chain::{
        bdk_core, keychain_txout::KeychainTxOutIndex, local_chain::LocalChain, IndexedTxGraph,
        TxGraph,
    };
    use bdk_core::{CheckPoint, ConfirmationBlockTime};

    const XPRV: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
    const WIF: &str = "cU6BxEezV8FnkEPBCaFtc4WNuUKmgFaAu6sJErB154GXgMUjhgWe";
    const SPK: &str = "00143f027073e6f341c481f55b7baae81dda5e6a9fba";

    fn get_single_sig_tr_xprv() -> Vec<String> {
        (0..2)
            .map(|i| format!("tr({XPRV}/86h/1h/0h/{i}/*)"))
            .collect()
    }

    fn get_single_sig_cltv_timestamp() -> String {
        format!("wsh(and_v(v:pk({WIF}),after(1735877503)))")
    }

    type KeychainTxGraph = IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<usize>>;

    #[derive(Debug)]
    struct TestProvider {
        assets: Assets,
        signer: Signer,
        secp: Secp256k1<secp256k1::All>,
        chain: LocalChain,
        graph: KeychainTxGraph,
    }

    impl DataProvider for TestProvider {
        fn get_tx(&self, txid: Txid) -> Option<Transaction> {
            self.graph
                .graph()
                .get_tx(txid)
                .map(|tx| tx.as_ref().clone())
        }

        fn get_descriptor_for_txout(
            &self,
            txout: &TxOut,
        ) -> Option<Descriptor<DefiniteDescriptorKey>> {
            let indexer = &self.graph.index;

            let (keychain, index) = indexer.index_of_spk(txout.script_pubkey.clone())?;
            let desc = indexer.get_descriptor(*keychain)?;

            desc.at_derivation_index(*index).ok()
        }
    }

    impl TestProvider {
        /// Set max absolute timelock
        fn after(mut self, lt: absolute::LockTime) -> Self {
            self.assets = self.assets.after(lt);
            self
        }

        /// Get a reference to the tx graph
        fn graph(&self) -> &TxGraph {
            self.graph.graph()
        }

        /// Get a reference to the indexer
        fn index(&self) -> &KeychainTxOutIndex<usize> {
            &self.graph.index
        }

        /// Get the script pubkey at the specified `index` from the first keychain
        /// (by Ord).
        fn spk_at_index(&self, index: u32) -> Option<ScriptBuf> {
            let keychain = self.graph.index.keychains().next().unwrap().0;
            self.graph.index.spk_at_index(keychain, index)
        }

        /// Get next unused internal script pubkey
        fn next_internal_spk(&mut self) -> ScriptBuf {
            let keychain = self.graph.index.keychains().last().unwrap().0;
            let ((_, spk), _) = self.graph.index.next_unused_spk(keychain).unwrap();
            spk
        }

        /// Get balance
        fn balance(&self) -> bdk_chain::Balance {
            let chain = &self.chain;
            let chain_tip = chain.tip().block_id();

            let outpoints = self.graph.index.outpoints().clone();
            let graph = self.graph.graph();
            graph.balance(chain, chain_tip, outpoints, |_, _| true)
        }

        /// Get a list of planned utxos sorted largest first
        fn planned_utxos(&self) -> Vec<PlanUtxo> {
            let chain = &self.chain;
            let chain_tip = chain.tip().block_id();
            let op = self.index().outpoints().clone();

            let mut utxos = vec![];

            for (indexed, txo) in self.graph().filter_chain_unspents(chain, chain_tip, op) {
                let (keychain, index) = indexed;
                let desc = self.index().get_descriptor(keychain).unwrap();
                let def = desc.at_derivation_index(index).unwrap();
                if let Ok(plan) = def.plan(&self.assets) {
                    utxos.push(PlanUtxo {
                        plan,
                        outpoint: txo.outpoint,
                        txout: txo.txout,
                    });
                }
            }

            utxos.sort_by_key(|p| p.txout.value);
            utxos.reverse();

            utxos
        }

        /// Attempt to create all the required signatures for this psbt
        fn sign(&self, psbt: &mut Psbt) {
            let _ = psbt.sign(&self.signer, &self.secp);
        }
    }

    macro_rules! block_id {
        ( $height:expr, $hash:expr ) => {
            bdk_chain::BlockId {
                height: $height,
                hash: $hash,
            }
        };
    }

    fn new_tx(lt: u32) -> Transaction {
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::from_consensus(lt),
            input: vec![TxIn::default()],
            output: vec![],
        }
    }

    fn parse_descriptor(s: &str) -> (Descriptor<DescriptorPublicKey>, KeyMap) {
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&Secp256k1::new(), s).unwrap()
    }

    /// Initialize a [`TestProvider`] with the given `descriptors`.
    ///
    /// The returned object contains a local chain at height 1000 and an indexed tx graph
    /// with 10 x 1Msat utxos.
    fn init_graph(descriptors: &[String]) -> TestProvider {
        use bitcoin::{constants, hashes::Hash, Network};

        let mut keys = vec![];
        let mut keymap = KeyMap::new();

        let mut index = KeychainTxOutIndex::new(10);
        for (keychain, desc_str) in descriptors.iter().enumerate() {
            let (desc, km) = parse_descriptor(desc_str);
            desc.for_each_key(|k| {
                keys.push(k.clone());
                true
            });
            keymap.extend(km);
            index.insert_descriptor(keychain, desc).unwrap();
        }

        let mut graph = KeychainTxGraph::new(index);

        let genesis_hash = constants::genesis_block(Network::Regtest).block_hash();
        let mut cp = CheckPoint::new(block_id!(0, genesis_hash));

        for height in 1..11 {
            let ((_, script_pubkey), _) = graph.index.reveal_next_spk(0).unwrap();

            let tx = Transaction {
                output: vec![TxOut {
                    value: Amount::from_btc(0.01).unwrap(),
                    script_pubkey,
                }],
                ..new_tx(height)
            };
            let txid = tx.compute_txid();
            let _ = graph.insert_tx(tx);

            let block_id = block_id!(height, Hash::hash(height.to_be_bytes().as_slice()));
            let anchor = ConfirmationBlockTime {
                block_id,
                confirmation_time: height as u64,
            };
            let _ = graph.insert_anchor(txid, anchor);

            cp = cp.insert(block_id);
        }

        let tip = block_id!(1000, Hash::hash(b"Z"));
        cp = cp.insert(tip);
        let chain = LocalChain::from_tip(cp).unwrap();

        let assets = Assets::new().add(keys);

        TestProvider {
            assets,
            signer: Signer(keymap),
            secp: Secp256k1::new(),
            chain,
            graph,
        }
    }

    #[test]
    fn test_build_tx_finalize() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());
        assert_eq!(graph.balance().total().to_btc(), 0.1);

        let recip = ScriptBuf::from_hex(SPK).unwrap();
        let mut builder = Builder::new();
        builder.add_output(recip, Amount::from_sat(2_500_000));

        let selection = graph.planned_utxos().into_iter().take(3);
        builder.add_inputs(selection);
        builder.add_change_output(graph.next_internal_spk(), Amount::from_sat(499_500));

        let (mut psbt, finalizer) = builder.build_tx(&mut graph).unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 3);
        assert_eq!(psbt.unsigned_tx.output.len(), 2);

        graph.sign(&mut psbt);
        assert!(finalizer.finalize(&mut psbt).is_finalized());
    }

    #[test]
    fn test_build_tx_insane_fee() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        let recip = ScriptBuf::from_hex(SPK).unwrap();
        let mut builder = Builder::new();
        builder.add_output(recip, Amount::from_btc(0.01).unwrap());

        let selection = graph
            .planned_utxos()
            .into_iter()
            .take(3)
            .collect::<Vec<_>>();
        assert_eq!(
            selection
                .iter()
                .map(|p| p.txout.value)
                .sum::<Amount>()
                .to_btc(),
            0.03
        );
        builder.add_inputs(selection);

        let err = builder.build_tx(&mut graph).unwrap_err();
        assert!(matches!(err, Error::InsaneFee(..)));
    }

    #[test]
    fn test_build_tx_negative_fee() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        let recip = ScriptBuf::from_hex(SPK).unwrap();

        let mut builder = Builder::new();
        builder.add_output(recip, Amount::from_btc(0.02).unwrap());
        builder.add_inputs(graph.planned_utxos().into_iter().take(1));

        let err = builder.build_tx(&mut graph).unwrap_err();
        assert!(matches!(err, Error::NegativeFee(..)));
    }

    #[test]
    fn test_build_tx_add_data() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        let mut builder = Builder::new();
        builder.add_inputs(graph.planned_utxos().into_iter().take(1));
        builder.add_output(graph.next_internal_spk(), Amount::from_sat(999_000));
        builder.add_data(b"satoshi nakamoto").unwrap();

        let psbt = builder.build_tx(&mut graph).unwrap().0;
        assert!(psbt
            .unsigned_tx
            .output
            .iter()
            .any(|txo| txo.script_pubkey.is_op_return()));

        // try to add more than 80 bytes of data
        let data = [0x90; 81];
        builder = Builder::new();
        assert!(matches!(
            builder.add_data(data),
            Err(Error::MaxOpReturnRelay)
        ));

        // try to add more than 1 op return
        let data = [0x90; 80];
        builder = Builder::new();
        builder.add_data(data).unwrap();
        assert!(matches!(
            builder.add_data(data),
            Err(Error::TooManyOpReturn)
        ));
    }

    #[test]
    fn test_build_tx_version() {
        use transaction::Version;
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        // test default tx version (2)
        let mut builder = Builder::new();
        let recip = graph.spk_at_index(0).unwrap();
        let utxo = graph.planned_utxos().first().unwrap().clone();
        let amt = utxo.txout.value - Amount::from_sat(256);
        builder.add_input(utxo.clone());
        builder.add_output(recip.clone(), amt);

        let psbt = builder.build_tx(&mut graph).unwrap().0;
        assert_eq!(psbt.unsigned_tx.version, Version::TWO);

        // allow any potentially non-standard version
        builder = Builder::new();
        builder.version(Version(3));
        builder.add_input(utxo);
        builder.add_output(recip, amt);

        let psbt = builder.build_tx(&mut graph).unwrap().0;
        assert_eq!(psbt.unsigned_tx.version, Version(3));
    }

    #[test]
    fn test_timestamp_timelock() {
        #[derive(Clone)]
        struct InOut {
            input: PlanUtxo,
            output: (ScriptBuf, Amount),
        }
        fn check_locktime(graph: &mut TestProvider, in_out: InOut, lt: u32, exp_lt: Option<u32>) {
            let InOut {
                input,
                output: (recip, amount),
            } = in_out;

            let mut builder = Builder::new();
            builder.add_output(recip, amount);
            builder.add_input(input);
            builder.locktime(absolute::LockTime::from_consensus(lt));

            let res = builder.build_tx(graph);

            match res {
                Ok((mut psbt, finalizer)) => {
                    assert_eq!(
                        psbt.unsigned_tx.lock_time.to_consensus_u32(),
                        exp_lt.unwrap()
                    );
                    graph.sign(&mut psbt);
                    assert!(finalizer.finalize(&mut psbt).is_finalized());
                }
                Err(e) => {
                    assert!(exp_lt.is_none());
                    if absolute::LockTime::from_consensus(lt).is_block_height() {
                        assert!(matches!(e, Error::LockTypeMismatch));
                    } else if lt < 1735877503 {
                        assert!(matches!(e, Error::LockTimeCltv { .. }));
                    }
                }
            }
        }

        // initial state
        let mut graph = init_graph(&[get_single_sig_cltv_timestamp()]);
        let mut t = 1735877503;
        let locktime = absolute::LockTime::from_consensus(t);

        // supply the assets needed to create plans
        graph = graph.after(locktime);

        let in_out = InOut {
            input: graph.planned_utxos().first().unwrap().clone(),
            output: (ScriptBuf::from_hex(SPK).unwrap(), Amount::from_sat(999_000)),
        };

        // Test: tx should use the planned locktime
        check_locktime(&mut graph, in_out.clone(), t, Some(t));

        // Test: requesting a lower timelock should error
        check_locktime(
            &mut graph,
            in_out.clone(),
            absolute::LOCK_TIME_THRESHOLD,
            None,
        );

        // Test: tx may use a custom locktime
        t += 1;
        check_locktime(&mut graph, in_out.clone(), t, Some(t));

        // Test: error if lock type mismatch
        check_locktime(&mut graph, in_out, 100, None);
    }

    #[test]
    fn test_build_zero_fee_tx() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        let recip = ScriptBuf::from_hex(SPK).unwrap();
        let utxos = graph.planned_utxos();

        // case: 1-in/1-out
        let mut builder = Builder::new();
        builder.add_inputs(utxos.iter().take(1).cloned());
        builder.add_output(recip.clone(), Amount::from_sat(1_000_000));
        let psbt = builder.build_tx(&mut graph).unwrap().0;
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        assert_eq!(psbt.unsigned_tx.output[0].value.to_btc(), 0.01);

        // case: 1-in/2-out
        let mut builder = Builder::new();
        builder.add_inputs(utxos.iter().take(1).cloned());
        builder.add_output(recip, Amount::from_sat(500_000));
        builder.add_change_output(graph.next_internal_spk(), Amount::from_sat(500_000));
        builder.check_fee(Some(Amount::ZERO), Some(FeeRate::from_sat_per_kwu(0)));

        let psbt = builder.build_tx(&mut graph).unwrap().0;
        assert_eq!(psbt.unsigned_tx.output.len(), 2);
        assert!(psbt
            .unsigned_tx
            .output
            .iter()
            .all(|txo| txo.value.to_sat() == 500_000));
    }
}
