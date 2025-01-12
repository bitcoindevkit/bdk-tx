use alloc::vec::Vec;
use core::fmt;

use bitcoin::{
    absolute, transaction, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, SignedAmount,
    Transaction, TxIn, TxOut, Weight,
};
use miniscript::{bitcoin, plan::Plan};

use crate::{DataProvider, Finalizer, PsbtUpdater};

/// Transaction builder
#[derive(Debug, Clone, Default)]
pub struct Builder {
    recipients: Vec<(ScriptBuf, Amount)>,
    utxos: Vec<PlannedUtxo>,
    drain_to: Option<(ScriptBuf, Amount)>,
    version: Option<transaction::Version>,
    locktime: Option<absolute::LockTime>,
}

/// Planned utxo
#[derive(Debug, Clone)]
pub struct PlannedUtxo {
    /// plan
    pub plan: Plan,
    /// outpoint
    pub outpoint: OutPoint,
    /// txout
    pub txout: TxOut,
}

impl Builder {
    /// New
    pub fn new() -> Self {
        Self::default()
    }

    /// Add recipients
    pub fn add_recipients(
        &mut self,
        recipients: impl IntoIterator<Item = (ScriptBuf, Amount)>,
    ) -> &mut Self {
        self.recipients.extend(recipients);
        self
    }

    /// Add recipient
    pub fn add_recipient(&mut self, script: ScriptBuf, amount: Amount) -> &mut Self {
        self.recipients.push((script, amount));
        self
    }

    /// Get the target amounts based on the weight + value of all recipients
    ///
    /// This is used for passing target values to a coin selection implementation.
    pub fn target_outputs(&self) -> impl Iterator<Item = (Weight, Amount)> + '_ {
        self.recipients
            .iter()
            .cloned()
            .map(|(script_pubkey, value)| {
                let txout = TxOut {
                    value,
                    script_pubkey,
                };
                (txout.weight(), value)
            })
    }

    /// Set the drain output
    pub fn drain_to(&mut self, script: ScriptBuf, amount: Amount) -> &mut Self {
        self.drain_to = Some((script, amount));
        self
    }

    /// Add an input to fund the tx
    pub fn add_input(&mut self, utxo: impl Into<PlannedUtxo>) -> &mut Self {
        self.utxos.push(utxo.into());
        self
    }

    /// Add inputs to be used to fund the tx
    pub fn add_inputs<I>(&mut self, utxos: I) -> &mut Self
    where
        I: IntoIterator,
        I::Item: Into<PlannedUtxo>,
    {
        self.utxos.extend(utxos.into_iter().map(Into::into));
        self
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

    /// Add a data-carrying output using `OP_RETURN`.
    ///
    /// # Errors
    ///
    /// - If `data` exceeds 80 bytes in size.
    /// - If this is not the first `OP_RETURN` output being added to this builder.
    ///
    /// Refer to https://github.com/bitcoin/bitcoin/blob/v28.0/src/policy/policy.cpp for more
    /// details about transaction standardness.
    pub fn add_data<T>(&mut self, data: T) -> Result<&mut Self, Error>
    where
        T: AsRef<[u8]>,
    {
        if self.recipients.iter().any(|(s, _)| s.is_op_return()) {
            return Err(Error::TooManyOpReturn);
        }
        if data.as_ref().len() > 80 {
            return Err(Error::MaxOpReturnRelay);
        }

        let mut bytes = bitcoin::script::PushBytesBuf::new();
        bytes.extend_from_slice(data.as_ref()).expect("should push");

        self.recipients
            .push((ScriptBuf::new_op_return(bytes), Amount::ZERO));

        Ok(self)
    }

    /// Build a [`Psbt`] with the given data provider and return a [`PsbtUpdater`].
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
                    if lt.is_implied_by(param) {
                        lock_time = Some(param);
                    }
                }
                None => lock_time = Some(param),
            }
        }

        let lock_time = lock_time.unwrap_or(LockTime::ZERO);

        // set outputs
        let mut output = self
            .recipients
            .into_iter()
            .map(|(script_pubkey, value)| TxOut {
                value,
                script_pubkey,
            })
            .collect::<Vec<_>>();

        if let Some((spk, value)) = self.drain_to {
            output.push(TxOut {
                value,
                script_pubkey: spk,
            });
        }

        // set inputs
        let input = self
            .utxos
            .iter()
            .map(|PlannedUtxo { plan, outpoint, .. }| TxIn {
                previous_output: *outpoint,
                sequence: plan
                    .relative_timelock
                    .map_or(Sequence::ENABLE_RBF_NO_LOCKTIME, |lt| lt.to_sequence()),
                ..Default::default()
            })
            .collect();

        let mut unsigned_tx = Transaction {
            version,
            lock_time,
            input,
            output,
        };

        provider.sort_transaction(&mut unsigned_tx);

        // check, validate
        // TODO: check output script size, total output amount, max tx weight
        let total_inputs: Amount = self.utxos.iter().map(|p| p.txout.value).sum();
        let total_outputs: Amount = unsigned_tx.output.iter().map(|txo| txo.value).sum();
        if total_outputs > total_inputs {
            return Err(Error::NegativeFee(SignedAmount::from_sat(
                total_inputs.to_sat() as i64 - total_outputs.to_sat() as i64,
            )));
        }
        // The absurd fee threshold is currently set to 2x the value of the outputs
        if total_inputs > total_outputs * 2 {
            let fee = total_inputs - total_outputs;
            let total_sat_wu: Weight = self
                .utxos
                .iter()
                .map(|p| Weight::from_wu_usize(p.plan.satisfaction_weight()))
                .sum();
            let est_wu = unsigned_tx.weight() + total_sat_wu;
            let computed = fee / est_wu;
            return Err(Error::InsaneFee(computed));
        }

        Ok(PsbtUpdater::new(unsigned_tx, self.utxos)?)
    }

    /// Convenience method to build an updated [`Psbt`] and return a [`Finalizer`].
    pub fn build_tx<D>(self, provider: &mut D) -> Result<(Psbt, Finalizer), Error>
    where
        D: DataProvider,
    {
        let mut updater = self.build_psbt(provider)?;
        updater.update_psbt(provider);
        Ok(updater.into_finalizer())
    }
}

/// [`Builder`] error
#[derive(Debug)]
pub enum Error {
    /// insane feerate
    InsaneFee(FeeRate),
    /// attempted to mix locktime types
    LockTypeMismatch,
    /// output exceeds data carrier limit
    MaxOpReturnRelay,
    /// negative fee
    NegativeFee(SignedAmount),
    /// bitcoin psbt error
    Psbt(bitcoin::psbt::Error),
    /// too many OP_RETURN in a single tx
    TooManyOpReturn,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsaneFee(r) => write!(f, "absurd feerate: {r:#}"),
            Self::LockTypeMismatch => write!(f, "cannot mix locktime units"),
            Self::MaxOpReturnRelay => write!(f, "non-standard: output exceeds data carrier limit"),
            Self::NegativeFee(e) => write!(f, "illegal tx: negative fee: {}", e.display_dynamic()),
            Self::Psbt(e) => e.fmt(f),
            Self::TooManyOpReturn => write!(f, "non-standard: only 1 OP_RETURN output permitted"),
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
    use alloc::string::String;

    use bitcoin::{
        secp256k1::{self, Secp256k1},
        Txid,
    };
    use miniscript::{
        descriptor::{
            DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, DescriptorSecretKey, KeyMap,
        },
        plan::Assets,
        ForEachKey,
    };

    use bdk_chain::{
        bdk_core, keychain_txout::KeychainTxOutIndex, local_chain::LocalChain, IndexedTxGraph,
        TxGraph,
    };
    use bdk_coin_select::{Drain, TargetOutputs};
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
    struct Signer(KeyMap);

    #[derive(Debug)]
    struct TestProvider {
        assets: Assets,
        signer: Signer,
        secp: Secp256k1<secp256k1::All>,
        chain: LocalChain,
        graph: KeychainTxGraph,
    }

    use bitcoin::psbt::{GetKey, GetKeyError, KeyRequest};

    impl GetKey for Signer {
        type Error = GetKeyError;

        fn get_key<C: secp256k1::Signing>(
            &self,
            key_request: KeyRequest,
            secp: &Secp256k1<C>,
        ) -> Result<Option<bitcoin::PrivateKey>, Self::Error> {
            for entry in &self.0 {
                match entry {
                    (_, DescriptorSecretKey::Single(prv)) => {
                        let pk = prv.key.public_key(secp);
                        if key_request == KeyRequest::Pubkey(pk) {
                            return Ok(Some(prv.key));
                        }
                    }
                    (_, desc_sk) => {
                        for desc_sk in desc_sk.clone().into_single_keys() {
                            if let DescriptorSecretKey::XPrv(k) = desc_sk {
                                if let Ok(Some(prv)) =
                                    GetKey::get_key(&k.xkey, key_request.clone(), secp)
                                {
                                    return Ok(Some(prv));
                                }
                            }
                        }
                    }
                }
            }
            Ok(None)
        }
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
        fn planned_utxos(&self) -> Vec<PlannedUtxo> {
            let chain = &self.chain;
            let chain_tip = chain.tip().block_id();
            let op = self.index().outpoints().clone();

            let mut utxos = vec![];

            for (indexed, txo) in self.graph().filter_chain_unspents(chain, chain_tip, op) {
                let (keychain, index) = indexed;
                let desc = self.index().get_descriptor(keychain).unwrap();
                let def = desc.at_derivation_index(index).unwrap();
                if let Ok(plan) = def.plan(&self.assets) {
                    utxos.push(PlannedUtxo {
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
        for (k, s) in descriptors.iter().enumerate() {
            let (desc, km) = parse_descriptor(s);
            desc.for_each_key(|k| {
                keys.push(k.clone());
                true
            });
            keymap.extend(km);
            index.insert_descriptor(k, desc).unwrap();
        }

        let mut graph = KeychainTxGraph::new(index);

        let genesis_hash = constants::genesis_block(Network::Regtest).block_hash();
        let mut cp = CheckPoint::new(block_id!(0, genesis_hash));

        for h in 1..11 {
            let ((_, script_pubkey), _) = graph.index.reveal_next_spk(0).unwrap();

            let tx = Transaction {
                output: vec![TxOut {
                    value: Amount::from_btc(0.01).unwrap(),
                    script_pubkey,
                }],
                ..new_tx(h)
            };
            let txid = tx.compute_txid();
            let _ = graph.insert_tx(tx);

            let block_id = block_id!(h, Hash::hash(h.to_be_bytes().as_slice()));
            let anchor = ConfirmationBlockTime {
                block_id,
                confirmation_time: h as u64,
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

    /// Fund outputs helper
    fn fund_outputs(builder: &Builder) -> TargetOutputs {
        TargetOutputs::fund_outputs(
            builder
                .target_outputs()
                .map(|(wu, val)| (wu.to_wu() as u32, val.to_sat())),
        )
    }

    /// Select from the list of utxos at a given feerate until the target is met.
    fn select_coins(
        utxos: &[PlannedUtxo],
        outputs: TargetOutputs,
        feerate: f32,
    ) -> (Vec<PlannedUtxo>, Drain) {
        use bdk_coin_select::{
            Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, Target, TargetFee,
        };

        let candidates = utxos
            .iter()
            .map(|p| Candidate {
                value: p.txout.value.to_sat(),
                weight: p.plan.satisfaction_weight() as u32,
                input_count: 1,
                is_segwit: p.plan.witness_version().is_some(),
            })
            .collect::<Vec<_>>();

        let mut selector = CoinSelector::new(&candidates);

        let min_value = 1000;
        let target = Target {
            fee: TargetFee {
                rate: FeeRate::from_sat_per_vb(feerate),
                ..Default::default()
            },
            outputs,
        };
        let change_policy = ChangePolicy {
            min_value,
            drain_weights: DrainWeights::TR_KEYSPEND,
        };
        selector
            .select_until_target_met(target)
            .expect("failed to select coins");

        let selection = selector.apply_selection(utxos).cloned().collect();

        let drain = selector.drain(target, change_policy);

        (selection, drain)
    }

    fn extract(f: Finalizer, mut psbt: Psbt) -> anyhow::Result<Transaction> {
        if f.finalize(&mut psbt).is_finalized() {
            Ok(psbt.extract_tx()?)
        } else {
            anyhow::bail!("failed to finalize");
        }
    }

    #[test]
    fn test_build_tx_finalize() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());
        assert_eq!(graph.balance().total().to_btc(), 0.1);

        let recip = ScriptBuf::from_hex(SPK).unwrap();
        let mut b = Builder::new();
        b.add_recipient(recip, Amount::from_sat(2_500_000));

        let outputs = fund_outputs(&b);
        let (selection, drain) = select_coins(&graph.planned_utxos(), outputs, 2.0);
        b.add_inputs(selection);
        if drain.is_some() {
            b.drain_to(graph.next_internal_spk(), Amount::from_sat(drain.value));
        }

        let (mut psbt, f) = b.build_tx(&mut graph).unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 3);
        assert_eq!(psbt.unsigned_tx.output.len(), 2);

        graph.sign(&mut psbt);
        let _tx = extract(f, psbt).unwrap();
    }

    #[test]
    fn test_build_tx_insane_fee() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        let recip = ScriptBuf::from_hex(SPK).unwrap();
        let mut b = Builder::new();
        b.add_recipient(recip, Amount::from_btc(0.01).unwrap());

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
        b.add_inputs(selection);

        let err = b.build_tx(&mut graph).unwrap_err();
        assert!(matches!(err, Error::InsaneFee(_)));
    }

    #[test]
    fn test_build_tx_negative_fee() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        let recip = ScriptBuf::from_hex(SPK).unwrap();

        let mut b = Builder::new();
        b.add_recipient(recip, Amount::from_btc(0.02).unwrap());
        b.add_inputs(graph.planned_utxos().into_iter().take(1));

        let err = b.build_tx(&mut graph).unwrap_err();
        assert!(matches!(err, Error::NegativeFee(_)));
    }

    #[test]
    fn test_build_tx_add_data() {
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        let mut b = Builder::new();
        b.add_inputs(graph.planned_utxos().into_iter().take(1));
        b.add_recipient(graph.next_internal_spk(), Amount::from_sat(999_000));
        b.add_data(b"satoshi nakamoto").unwrap();

        let psbt = b.build_tx(&mut graph).unwrap().0;
        assert!(psbt
            .unsigned_tx
            .output
            .iter()
            .any(|txo| txo.script_pubkey.is_op_return()));

        // try to add more than 80 bytes of data
        let data = [0x90; 81];
        b = Builder::new();
        assert!(matches!(b.add_data(data), Err(Error::MaxOpReturnRelay)));

        // try to add more than 1 op return
        let data = [0x90; 80];
        b = Builder::new();
        b.add_data(data).unwrap();
        assert!(matches!(b.add_data(data), Err(Error::TooManyOpReturn)));
    }

    #[test]
    fn test_build_tx_version() {
        use transaction::Version;
        let mut graph = init_graph(&get_single_sig_tr_xprv());

        // test default tx version (2)
        let mut b = Builder::new();
        let recip = graph.spk_at_index(0).unwrap();
        let utxo = graph.planned_utxos().first().unwrap().clone();
        let amt = utxo.txout.value - Amount::from_sat(256);
        b.add_input(utxo.clone());
        b.add_recipient(recip.clone(), amt);

        let psbt = b.build_tx(&mut graph).unwrap().0;
        assert_eq!(psbt.unsigned_tx.version, Version::TWO);

        // allow any potentially non-standard version
        b = Builder::new();
        b.version(Version(3));
        b.add_input(utxo);
        b.add_recipient(recip, amt);

        let psbt = b.build_tx(&mut graph).unwrap().0;
        assert_eq!(psbt.unsigned_tx.version, Version(3));
    }

    #[test]
    fn test_timestamp_timelock() {
        #[derive(Clone)]
        struct InOut {
            input: PlannedUtxo,
            output: (ScriptBuf, Amount),
        }
        fn check_locktime(graph: &mut TestProvider, in_out: InOut, lt: u32, exp_lt: Option<u32>) {
            let InOut {
                input,
                output: (recip, amount),
            } = in_out;

            let mut b = Builder::new();
            b.add_recipient(recip, amount);
            b.add_input(input);
            b.locktime(absolute::LockTime::from_consensus(lt));

            let res = b.build_tx(graph);

            match res {
                Ok((mut psbt, f)) => {
                    assert_eq!(
                        psbt.unsigned_tx.lock_time.to_consensus_u32(),
                        exp_lt.unwrap()
                    );
                    graph.sign(&mut psbt);
                    assert!(f.finalize(&mut psbt).is_finalized());
                }
                Err(e) => {
                    assert!(exp_lt.is_none());
                    assert!(matches!(e, Error::LockTypeMismatch));
                }
            }
        }

        // initial state
        let mut graph = init_graph(&[get_single_sig_cltv_timestamp()]);
        let mut t = 1735877503;
        let lt = absolute::LockTime::from_consensus(t);

        // supply the assets needed to create plans
        graph = graph.after(lt);

        let in_out = InOut {
            input: graph.planned_utxos().first().unwrap().clone(),
            output: (ScriptBuf::from_hex(SPK).unwrap(), Amount::from_sat(999_000)),
        };

        // Test: tx should use the planned locktime
        check_locktime(&mut graph, in_out.clone(), t, Some(t));

        // Test: setting lower timelock has no effect
        check_locktime(
            &mut graph,
            in_out.clone(),
            absolute::LOCK_TIME_THRESHOLD,
            Some(t),
        );

        // Test: tx may use a custom locktime
        t += 1;
        check_locktime(&mut graph, in_out.clone(), t, Some(t));

        // Test: error if locktime incompatible
        check_locktime(&mut graph, in_out, 100, None);
    }
}
