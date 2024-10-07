use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use bdk_chain::bitcoin::{
    absolute, psbt, transaction, Address, Amount, FeeRate, Network, Psbt, Sequence, Transaction,
    TxIn, TxOut, Weight,
};
use bdk_chain::miniscript::{
    plan::Assets, plan::Plan, psbt::PsbtExt, DefiniteDescriptorKey, Descriptor,
};
use bdk_chain::{
    keychain_txout::KeychainTxOutIndex, local_chain::LocalChain, ConfirmationBlockTime,
    DescriptorExt, FullTxOut, IndexedTxGraph,
};
use bdk_coin_select::{
    metrics::LowestFee, Candidate, ChangePolicy, CoinSelector, DrainWeights, Target, TargetFee,
    TargetOutputs,
};
use rand_core::RngCore;

use crate::coin_selection::{BranchAndBoundCoinSelection, SingleRandomDraw};
use crate::TxBuilder;
use crate::{coin_selection::CoinSelectionAlgorithm, AssetsExt, TxParams};

/// Alias for a `IndexedTxGraph` with specific `Anchor` and `Indexer`.
pub type KeychainTxGraph<K> = IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<K>>;

/// A minimal set of core wallet structures.
#[derive(Debug)]
pub struct Wallet<'a, K> {
    /// Chain
    pub chain: &'a LocalChain,
    /// Graph
    pub graph: &'a KeychainTxGraph<K>,
    /// Network
    pub network: Network,
    /// Change info
    pub change_info: Option<ChangeInfo<K>>,
}

#[allow(unused)]
impl<'a, K> Wallet<'a, K> {
    /// New from chain and indexed tx-graph.
    pub fn new(chain: &'a LocalChain, graph: &'a KeychainTxGraph<K>) -> Self {
        Self {
            chain,
            graph,
            network: Network::Testnet,
            change_info: None,
        }
    }

    /// Set [`Network`].
    pub fn set_network(&mut self, network: Network) {
        self.network = network;
    }

    /// Get a reference to the keychain index.
    pub fn index(&self) -> &KeychainTxOutIndex<K> {
        &self.graph.index
    }

    /// Internally collect the baseline [`Assets`].
    fn assets(&mut self) -> Assets
    where
        K: fmt::Debug + Clone + Ord,
    {
        use bdk_chain::miniscript::ForEachKey;
        let mut pks = vec![];
        for (_, desc) in self.index().keychains() {
            desc.for_each_key(|key| {
                pks.push(key.clone());
                true
            });
        }
        Assets::new().add(pks.into_iter().collect::<Vec<_>>())
    }

    /// Get a new [`TxBuilder`].
    pub fn tx_builder(
        &mut self,
    ) -> TxBuilder<BranchAndBoundCoinSelection<SingleRandomDraw>, Wallet<'a, K>> {
        TxBuilder::new(
            BranchAndBoundCoinSelection::<SingleRandomDraw>::default(),
            self,
        )
    }
}

/// Trait for types that can create transactions.
pub trait CreateTx {
    /// Error
    type Error: core::fmt::Debug;

    /// Create a new unsigned PSBT from the given `params` and `rng`.
    fn create_tx(
        &mut self,
        params: TxParams,
        coin_selection: impl CoinSelectionAlgorithm,
        rng: &mut impl RngCore,
    ) -> Result<Psbt, Self::Error>;
}

impl<K: fmt::Debug + Clone + Ord> CreateTx for Wallet<'_, K> {
    type Error = Error;

    fn create_tx(
        &mut self,
        params: crate::TxParams,
        _coin_selection: impl CoinSelectionAlgorithm,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<Psbt, Self::Error> {
        // aggregate the given assets
        let mut assets = self.assets();
        assets.extend(&params.assets);

        // get planned utxos
        let plan_utxos = self.planned_utxos(&assets)?;

        // build candidate set
        let candidates: Vec<Candidate> = plan_utxos
            .iter()
            .map(|(plan, utxo)| {
                Candidate::new(
                    utxo.txout.value.to_sat(),
                    plan.satisfaction_weight() as u32,
                    plan.witness_version().is_some(),
                )
            })
            .collect();

        // create recipient output(s)
        let mut outputs = vec![];
        for (script_pubkey, amt) in params.recipients.into_iter() {
            let txout = TxOut {
                script_pubkey,
                value: amt,
            };
            outputs.push(txout);
        }

        // set change policy.
        // we assume the change keychain is the last one added,
        // which is generally true for 1 or 2 keychain wallets
        let min_drain_value: u64 = self
            .graph
            .index
            .keychains()
            .last()
            .map(|(_k, desc)| 3 * desc.dust_value())
            .expect("must have keychain");
        let change_policy = ChangePolicy {
            min_value: min_drain_value,
            // TODO: make drain weights a tx param?
            drain_weights: DrainWeights::TR_KEYSPEND,
        };

        // run coin selection
        let mut selector = CoinSelector::new(&candidates);
        let target = Target {
            outputs: TargetOutputs::fund_outputs(
                outputs
                    .iter()
                    .map(|output| (output.weight().to_wu() as u32, output.value.to_sat())),
            ),
            fee: TargetFee::default(),
        };
        let metric = LowestFee {
            target,
            long_term_feerate: bdk_coin_select::FeeRate::from_sat_per_vb(10.0),
            change_policy,
        };
        match selector.run_bnb(metric, 10_000) {
            Ok(_) => {}
            Err(_) => selector
                .select_until_target_met(target)
                .map_err(Error::InsufficientFunds)?,
        }
        let selection: Vec<_> = selector.apply_selection(&plan_utxos).collect();

        let input_amount: f64 = selection
            .iter()
            .map(|(_, utxo)| utxo.txout.value.to_sat() as f64)
            .sum();

        // add change output if needed. note, we require the caller to provide
        // a drain script so we can avoid deriving it here.
        let drain = selector.drain(target, change_policy);
        if drain.value > min_drain_value {
            if let Some(spk) = params.drain_to {
                let mut change_info = ChangeInfo {
                    address: Address::from_script(&spk, self.network)
                        .expect("must be valid Address script"),
                    index: None,
                };
                // if drain script belongs to this wallet we include the keychain-index in
                // `ChangeInfo` to let the caller decide when to mark it used and persist changes
                if let Some(index) = self.index().index_of_spk(spk.clone()).cloned() {
                    change_info.index = Some(index);
                }
                self.change_info = Some(change_info);
                // add change output
                let change_output = TxOut {
                    value: Amount::from_sat(drain.value),
                    script_pubkey: spk,
                };
                outputs.push(change_output);
            }
        }

        let output_amount: f64 = outputs
            .iter()
            .map(|txout| txout.value.to_sat() as f64)
            .sum();

        // create psbt
        let lock_time = assets.absolute_timelock.unwrap_or(
            absolute::LockTime::from_height(self.chain.tip().height()).expect("valid height"),
        );
        let inputs: Vec<_> = selection
            .iter()
            .map(|(plan, utxo)| TxIn {
                previous_output: utxo.outpoint,
                sequence: plan
                    .relative_timelock
                    .map_or(Sequence::ENABLE_RBF_NO_LOCKTIME, Sequence::from),
                ..Default::default()
            })
            .collect();
        let unsigned_tx = Transaction {
            version: params.version.unwrap_or(transaction::Version(1)),
            lock_time,
            input: inputs,
            output: outputs,
        };
        let unsigned_weight = unsigned_tx.weight();

        // update psbt with plan
        let mut satisfaction_weight = Weight::ZERO;
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).map_err(Error::Psbt)?;
        for (input_index, (plan, utxo)) in selection.iter().enumerate() {
            let psbt_input = &mut psbt.inputs[input_index];
            plan.update_psbt_input(psbt_input);
            if plan.witness_version().is_some() {
                psbt_input.witness_utxo = Some(utxo.txout.clone());
            }
            let spk = psbt.unsigned_tx.output[input_index].script_pubkey.clone();
            if let Some((keychain, index)) = self.index().index_of_spk(spk) {
                #[rustfmt::skip]
                let (_, desc) = self.index().keychains().find(|(k, _)| k == keychain).expect("must find keychain");
                let definite_desc = desc.at_derivation_index(*index).unwrap();
                psbt.update_output_with_descriptor(input_index, &definite_desc)
                    .unwrap();
            }
            satisfaction_weight += Weight::from_wu_usize(plan.satisfaction_weight());
        }

        // check for absurd feerate.
        // TODO: we should make the absurdity threshold configurable via tx params
        let tx_weight = unsigned_weight + satisfaction_weight;
        if output_amount < 0.9 * input_amount {
            let amount = Amount::from_sat(input_amount as u64 - output_amount as u64);
            let feerate = amount / tx_weight;
            return Err(Error::InsaneFeeRate { amount, feerate });
        }

        params
            .ordering
            .sort_tx_with_aux_rand(&mut psbt.unsigned_tx, rng);

        Ok(psbt)
    }
}

impl<K: fmt::Debug + Clone + Ord> Wallet<'_, K> {
    /// Planned utxos.
    #[rustfmt::skip]
    fn planned_utxos(&self, assets: &Assets) -> Result<Vec<(Plan, FullTxOut<ConfirmationBlockTime>)>, Error> {
        let chain_tip = self.chain.tip().block_id();
        let outpoints = self.index().outpoints().clone();
        let unspent = self.graph.graph().filter_chain_unspents(self.chain, chain_tip, outpoints);
        let mut ret = vec![];
        for ((keychain, index), utxo) in unspent {
            let (_, desc) = self.index().keychains().find(|(k, _)| *k == keychain).expect("must find keychain");
            let def_desc = desc.at_derivation_index(index).expect("i cannot be hardened");
            let plan = def_desc.plan(assets).map_err(Error::Plan)?;
            ret.push((plan, utxo));
        }
        Ok(ret)
    }
}

/// Records changes to the change keychain when we have to
/// include a change output during tx creation.
#[derive(Debug)]
pub struct ChangeInfo<K> {
    /// Address
    pub address: Address,
    /// Keychain + index, will only be `Some(_)` for indexed SPKs
    pub index: Option<(K, u32)>,
}

/// Error
#[derive(Debug)]
pub enum Error {
    /// insane feerate
    InsaneFeeRate {
        /// amount
        amount: Amount,
        /// feerate
        feerate: FeeRate,
    },
    /// insufficient funds
    InsufficientFunds(bdk_coin_select::InsufficientFunds),
    /// bitcoin psbt error
    Psbt(psbt::Error),
    /// miniscript plan error
    Plan(Descriptor<DefiniteDescriptorKey>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsaneFeeRate { amount, feerate } => write!(
                f,
                "Calculated insane feerate: {feerate:#}, amount: {}",
                amount.display_dynamic()
            ),
            Self::InsufficientFunds(e) => e.fmt(f),
            Self::Psbt(e) => e.fmt(f),
            Self::Plan(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod test {
    use super::*;
    use bdk_chain::bitcoin::{constants, key::Secp256k1, Address, Network, OutPoint, ScriptBuf};
    use bdk_chain::miniscript::descriptor::KeyMap;
    use bdk_chain::{
        miniscript::{Descriptor, DescriptorPublicKey},
        BlockId,
    };
    use core::str::FromStr;
    use rand::thread_rng;
    use transaction::Txid;

    const DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";

    macro_rules! hash {
        ($n:expr) => {{
            use bdk_chain::bitcoin::hashes::Hash;
            let n = $n as i32;
            Hash::hash(n.to_be_bytes().as_slice())
        }};
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum Keychain {
        External,
    }

    fn parse_descriptor(desc: &str) -> (Descriptor<DescriptorPublicKey>, KeyMap) {
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&Secp256k1::new(), desc).unwrap()
    }

    fn new_tx() -> Transaction {
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                ..Default::default()
            }],
            output: vec![],
        }
    }

    fn insert_tx_at_block(
        graph: &mut KeychainTxGraph<Keychain>,
        chain: &mut LocalChain,
        tx: Transaction,
        block_id: BlockId,
    ) -> Txid {
        let txid = tx.compute_txid();
        let _ = graph.insert_tx(tx);
        let _ = chain
            .insert_block(block_id)
            .expect("cannot insert existing block");
        let anchor = ConfirmationBlockTime {
            block_id,
            confirmation_time: block_id.height as u64,
        };
        let _ = graph.insert_anchor(txid, anchor);
        txid
    }

    /// Returns new chain and graph structures with a tx paying 100,000 sats to spk 0.
    fn get_funded_structs(desc: &str) -> (LocalChain, KeychainTxGraph<Keychain>) {
        let genesis_hash = constants::genesis_block(Network::Testnet).block_hash();
        let (mut chain, _) = LocalChain::from_genesis_hash(genesis_hash);
        let mut index = KeychainTxOutIndex::default();
        let (desc, _) = parse_descriptor(desc);
        index.insert_descriptor(Keychain::External, desc).unwrap();
        let spk = index.spk_at_index(Keychain::External, 0).unwrap();
        let mut graph = IndexedTxGraph::new(index);
        let tx = Transaction {
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk.clone(),
            }],
            ..new_tx()
        };
        let block = BlockId {
            height: 1_000,
            hash: hash!(21),
        };
        let _ = insert_tx_at_block(&mut graph, &mut chain, tx, block);
        (chain, graph)
    }

    fn get_balance(wallet: &Wallet<Keychain>) -> Amount {
        let chain_tip = wallet.chain.tip().block_id();
        let outpoints = wallet.index().outpoints().clone();
        wallet
            .graph
            .graph()
            .balance(wallet.chain, chain_tip, outpoints, |_, _| true)
            .total()
    }

    fn peek_spk(wallet: &Wallet<Keychain>, index: u32) -> ScriptBuf {
        let desc = wallet.index().get_descriptor(Keychain::External).unwrap();
        desc.at_derivation_index(index).unwrap().script_pubkey()
    }

    #[test]
    fn create_tx() {
        let (chain, graph) = get_funded_structs(DESC);
        let mut wallet = Wallet::new(&chain, &graph);
        let recip = peek_spk(&wallet, 1);

        let mut builder = wallet.tx_builder();
        let _ = builder
            .add_recipient(recip, Amount::from_sat(99_000))
            .build_tx_with_aux_rand(&mut thread_rng())
            .unwrap();
    }

    #[test]
    fn create_tx_change_info() {
        let (chain, graph) = get_funded_structs(DESC);
        let mut wallet = Wallet::new(&chain, &graph);
        assert!(wallet.change_info.is_none());

        let recip = peek_spk(&wallet, 1);
        let change_index = 0;
        let drain_to = peek_spk(&wallet, change_index);

        let mut builder = wallet.tx_builder();
        let _ = builder
            .add_recipient(recip, Amount::from_sat(1_000))
            .set_drain_to(drain_to.clone())
            .build_tx_with_aux_rand(&mut thread_rng())
            .unwrap();

        let change_info = wallet.change_info.unwrap();
        assert_eq!(change_info.address.script_pubkey(), drain_to);
        let keychain_index = change_info.index.unwrap();
        assert_eq!(keychain_index, (Keychain::External, change_index));
    }

    #[test]
    fn create_tx_change_info_no_index() {
        let (chain, graph) = get_funded_structs(DESC);
        let mut wallet = Wallet::new(&chain, &graph);
        let recip = peek_spk(&wallet, 1);

        let drain_to = Address::from_str("tb1q3qtze4ys45tgdvguj66zrk4fu6hq3a3v8gsjna")
            .unwrap()
            .assume_checked();

        let mut builder = wallet.tx_builder();
        let _ = builder
            .add_recipient(recip, Amount::from_sat(1_000))
            .set_drain_to(drain_to.script_pubkey())
            .build_tx_with_aux_rand(&mut thread_rng())
            .unwrap();

        let change_info = wallet.change_info.unwrap();
        assert_eq!(change_info.address, drain_to);
        assert!(change_info.index.is_none());
    }

    #[test]
    fn create_tx_fail_insufficient_assets() {
        let desc =
            "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(10000)))";
        let (chain, graph) = get_funded_structs(desc);
        let mut wallet = Wallet::new(&chain, &graph);
        let recip = peek_spk(&wallet, 0);
        let balance = get_balance(&wallet);
        let fee = Amount::from_sat(200);

        // missing locktime in spend assets
        let mut builder = wallet.tx_builder();
        let res = builder
            .add_recipient(recip, balance - fee)
            .build_tx_with_aux_rand(&mut thread_rng())
            .unwrap_err();
        assert!(matches!(res, Error::Plan(_)));
    }

    #[test]
    fn create_tx_fail_insufficient_funds() {
        let (chain, graph) = get_funded_structs(DESC);
        let mut wallet = Wallet::new(&chain, &graph);
        let recip = peek_spk(&wallet, 1);
        let total_bal = get_balance(&wallet);

        // try to send the entire balance with no fee
        let mut builder = wallet.tx_builder();
        let res = builder
            .add_recipient(recip, total_bal)
            .build_tx_with_aux_rand(&mut thread_rng())
            .unwrap_err();
        assert!(matches!(res, Error::InsufficientFunds(_)));
    }

    #[test]
    fn create_tx_fail_insane_feerate() {
        let (chain, graph) = get_funded_structs(DESC);
        let mut wallet = Wallet::new(&chain, &graph);
        let recip = peek_spk(&wallet, 1);

        // here we forget to set a `drain_to` script, triggering
        // an absurd feerate
        let mut builder = wallet.tx_builder();
        let res = builder
            .add_recipient(recip, Amount::from_sat(1_000))
            .build_tx_with_aux_rand(&mut thread_rng())
            .unwrap_err();
        assert!(matches!(res, Error::InsaneFeeRate { .. }));
    }
}
