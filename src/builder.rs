use alloc::vec::Vec;
use core::fmt;

use bitcoin::{
    absolute, transaction, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Weight,
};
use miniscript::{bitcoin, plan::Plan};

use crate::{DataProvider, Finalizer, Updater};

/// Transaction builder
#[derive(Debug, Clone, Default)]
pub struct Builder {
    recipients: Vec<(ScriptBuf, Amount)>,
    utxos: Vec<PlannedUtxo>,
    drain_to: Option<(ScriptBuf, Amount)>,
    /* TODO: to have feature-parity with `bdk_wallet` */
    // drain_wallet: bool,
    // fee_policy: Option<FeePolicy>,
    // unspendable: HashSet<OutPoint>,
    // manually_selected_only: bool,
    // sighash: Option<psbt::PsbtSighashType>,
    // ordering: TxOrdering,
    // locktime: Option<absolute::LockTime>,
    // sequence: Option<Sequence>,
    // version: Option<Version>,
    // change_policy: ChangeSpendPolicy,
    // only_witness_utxo: bool,
    // add_global_xpubs: bool,
    // include_output_redeem_witness_script: bool,
    // bumping_fee: Option<PreviousFee>,
    // allow_dust: bool,
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

    /// Add utxos which will be used to fund the inputs
    pub fn add_inputs<I>(&mut self, utxos: I) -> &mut Self
    where
        I: IntoIterator,
        I::Item: Into<PlannedUtxo>,
    {
        self.utxos.extend(utxos.into_iter().map(Into::into));
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

    /// Build a [`Psbt`] with the given data provider
    pub fn build_tx<D>(self, provider: &D) -> Result<(Psbt, Finalizer), Error>
    where
        D: DataProvider,
    {
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
            // Note: It would be nice if the drain value could grow/shrink to
            // meet the target feerate. For now we rely on `bdk_coin_select` to
            // determine the drain value
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
                    .map(|lt| lt.to_sequence())
                    .unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
                ..Default::default()
            })
            .collect();

        let unsigned_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        // check, validate
        let total_inputs: Amount = self.utxos.iter().map(|p| p.txout.value).sum();
        let total_outputs: Amount = unsigned_tx.output.iter().map(|txo| txo.value).sum();
        if total_outputs > total_inputs {
            return Err(Error::NegativeFee);
        }
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

        // update psbt
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("failed to create Psbt");
        let mut updater = Updater::new();
        for plan_utxo in self.utxos {
            updater.map.insert(plan_utxo.outpoint, plan_utxo);
        }
        updater.update_psbt(&mut psbt, provider);

        Ok((psbt, updater.into()))
    }
}

/// [`Builder`] error
#[derive(Debug)]
pub enum Error {
    /// output exceeds data carrier limit
    MaxOpReturnRelay,
    /// insane feerate
    InsaneFee(FeeRate),
    /// negative fee
    NegativeFee,
    /// too many OP_RETURN in a single tx
    TooManyOpReturn,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxOpReturnRelay => write!(f, "non-standard: output exceeds data carrier limit"),
            Self::InsaneFee(r) => write!(f, "absurd feerate: {r:#}"),
            Self::NegativeFee => write!(f, "illegal tx: negative fee"),
            Self::TooManyOpReturn => write!(f, "non-standard: only 1 OP_RETURN output permitted"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::string::String;

    use bitcoin::{secp256k1::Secp256k1, Txid};
    use miniscript::{
        descriptor::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, KeyMap},
        plan::Assets,
    };

    use bdk_chain::{
        bdk_core, keychain_txout::KeychainTxOutIndex, local_chain::LocalChain, IndexedTxGraph,
        TxGraph,
    };
    use bdk_coin_select::{Drain, TargetOutputs};
    use bdk_core::{CheckPoint, ConfirmationBlockTime};

    const XPRV: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";

    type KeychainTxGraph = IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<usize>>;

    #[derive(Debug)]
    struct TestProvider {
        assets: Assets,
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
        /// Get a reference to the tx graph
        fn graph(&self) -> &TxGraph {
            self.graph.graph()
        }

        /// Get a reference to the indexer
        fn index(&self) -> &KeychainTxOutIndex<usize> {
            &self.graph.index
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
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::from_consensus(lt),
            input: vec![TxIn::default()],
            output: vec![],
        }
    }

    fn parse_descriptor(s: &str) -> (Descriptor<DescriptorPublicKey>, KeyMap) {
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&Secp256k1::new(), s).unwrap()
    }

    /// Initialize a [`TestProvider`] with:
    ///
    /// - 2 descriptors
    /// - local chain at height 1000
    /// - 10 x 1M sat utxos
    fn init_provider() -> TestProvider {
        use bitcoin::{constants, hashes::Hash, Network};
        let deriv = "86h/1h/0h";
        let mut iter_desc = (0..2).map(|i| format!("tr({XPRV}/{deriv}/{i}/*)"));
        let (desc, ext_keymap) = parse_descriptor(iter_desc.next().unwrap().as_str());
        let (change_desc, int_keymap) = parse_descriptor(iter_desc.next().unwrap().as_str());

        let assets = Assets::new().add(ext_keymap).add(int_keymap);

        let mut graph = KeychainTxGraph::new({
            let mut index = KeychainTxOutIndex::new(10);
            index.insert_descriptor(0, desc).unwrap();
            index.insert_descriptor(1, change_desc).unwrap();
            index
        });

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

        TestProvider {
            assets,
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

    #[allow(unused)]
    fn sign(psbt: &mut Psbt) -> Result<(), String> {
        use core::str::FromStr;
        let xprv = bitcoin::bip32::Xpriv::from_str(XPRV).unwrap();
        psbt.sign(&xprv, &Secp256k1::new())
            .map(|_| ())
            .map_err(|(_, e)| format!("{e:?}"))
    }

    #[allow(unused)]
    fn extract(f: Finalizer, mut psbt: Psbt) -> anyhow::Result<Transaction> {
        if f.finalize(&mut psbt).is_finalized() {
            Ok(psbt.extract_tx()?)
        } else {
            anyhow::bail!("failed to finalize");
        }
    }

    #[test]
    fn test_build_tx() {
        let mut graph = init_provider();
        assert_eq!(graph.balance().total().to_btc(), 0.1);

        let recip = ScriptBuf::from_hex("00143f027073e6f341c481f55b7baae81dda5e6a9fba").unwrap();
        let mut b = Builder::new();
        b.add_recipient(recip, Amount::from_sat(2_500_000));

        let outputs = fund_outputs(&b);
        let (selection, drain) = select_coins(&graph.planned_utxos(), outputs, 2.0);
        b.add_inputs(selection);
        if drain.is_some() {
            b.drain_to(graph.next_internal_spk(), Amount::from_sat(drain.value));
        }

        let psbt = b.build_tx(&graph).unwrap().0;
        assert_eq!(psbt.unsigned_tx.input.len(), 3);
        assert_eq!(psbt.unsigned_tx.output.len(), 2);
    }

    #[test]
    fn test_build_tx_insane_fee() {
        let graph = init_provider();

        let recip = ScriptBuf::from_hex("00143f027073e6f341c481f55b7baae81dda5e6a9fba").unwrap();
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

        let err = b.build_tx(&graph).unwrap_err();
        assert!(matches!(err, Error::InsaneFee(_)));
    }

    #[test]
    fn test_build_tx_negative_fee() {
        let graph = init_provider();

        let recip = ScriptBuf::from_hex("00143f027073e6f341c481f55b7baae81dda5e6a9fba").unwrap();

        let mut b = Builder::new();
        b.add_recipient(recip, Amount::from_btc(0.02).unwrap());
        b.add_inputs(graph.planned_utxos().into_iter().take(1));

        let err = b.build_tx(&graph).unwrap_err();
        assert!(matches!(err, Error::NegativeFee));
    }

    #[test]
    fn test_build_tx_add_data() {
        let mut graph = init_provider();

        let mut b = Builder::new();
        b.add_inputs(graph.planned_utxos().into_iter().take(1));
        b.add_recipient(graph.next_internal_spk(), Amount::from_sat(999_000));
        b.add_data(b"satoshi nakamoto").unwrap();

        let psbt = b.build_tx(&graph).unwrap().0;
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
}
