use std::sync::Arc;

use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXIDS};
use bdk_chain::{
    bdk_core, Anchor, Balance, CanonicalizationParams, ChainPosition, ConfirmationBlockTime,
};
use bdk_coin_select::DrainWeights;
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{CanonicalUnspents, Input, InputCandidates, RbfParams, TxStatus, TxWithStatus};
use bitcoin::{absolute, Address, Amount, BlockHash, OutPoint, Transaction, TxOut, Txid};
use miniscript::{
    plan::{Assets, Plan},
    Descriptor, DescriptorPublicKey, ForEachKey,
};

const EXTERNAL: &str = "external";
const INTERNAL: &str = "internal";

pub struct Wallet {
    pub chain: bdk_chain::local_chain::LocalChain,
    pub graph: bdk_chain::IndexedTxGraph<
        bdk_core::ConfirmationBlockTime,
        bdk_chain::keychain_txout::KeychainTxOutIndex<&'static str>,
    >,
}

impl Wallet {
    pub fn new(
        genesis_hash: BlockHash,
        external: Descriptor<DescriptorPublicKey>,
        internal: Descriptor<DescriptorPublicKey>,
    ) -> anyhow::Result<Self> {
        let mut indexer = bdk_chain::keychain_txout::KeychainTxOutIndex::default();
        indexer.insert_descriptor(EXTERNAL, external)?;
        indexer.insert_descriptor(INTERNAL, internal)?;
        let graph = bdk_chain::IndexedTxGraph::new(indexer);
        let (chain, _) = bdk_chain::local_chain::LocalChain::from_genesis_hash(genesis_hash);
        Ok(Self { chain, graph })
    }

    pub fn sync(&mut self, env: &TestEnv) -> anyhow::Result<()> {
        let client = env.rpc_client();
        let last_cp = self.chain.tip();
        let mut emitter = Emitter::new(client, last_cp, 0, NO_EXPECTED_MEMPOOL_TXIDS);
        while let Some(event) = emitter.next_block()? {
            let _ = self
                .graph
                .apply_block_relevant(&event.block, event.block_height());
            let _ = self.chain.apply_update(event.checkpoint);
        }
        let mempool = emitter.mempool()?;
        let _ = self
            .graph
            .batch_insert_relevant_unconfirmed(mempool.new_txs);
        Ok(())
    }

    pub fn next_address(&mut self) -> Option<Address> {
        let ((_, spk), _) = self.graph.index.next_unused_spk(EXTERNAL)?;
        Address::from_script(&spk, bitcoin::consensus::Params::REGTEST).ok()
    }

    pub fn balance(&self) -> Balance {
        let outpoints = self.graph.index.outpoints().clone();
        self.graph.graph().balance(
            &self.chain,
            self.chain.tip().block_id(),
            CanonicalizationParams::default(),
            outpoints,
            |_, _| true,
        )
    }

    /// TODO: Add to chain sources.
    pub fn tip_info(
        &self,
        client: &impl RpcApi,
    ) -> anyhow::Result<(absolute::Height, absolute::Time)> {
        let tip = self.chain.tip().block_id();
        let tip_info = client.get_block_header_info(&tip.hash)?;
        let tip_height = absolute::Height::from_consensus(tip.height)?;
        let tip_time =
            absolute::Time::from_consensus(tip_info.median_time.unwrap_or(tip_info.time) as _)?;
        Ok((tip_height, tip_time))
    }

    // TODO: Maybe create an `AssetsBuilder` or `AssetsExt` that makes it easier to add
    // assets from descriptors, etc.
    pub fn assets(&self) -> Assets {
        let index = &self.graph.index;
        let tip = self.chain.tip().block_id();
        Assets::new()
            .after(absolute::LockTime::from_height(tip.height).expect("must be valid height"))
            .add({
                let mut pks = vec![];
                for (_, desc) in index.keychains() {
                    desc.for_each_key(|k| {
                        pks.extend(k.clone().into_single_keys());
                        true
                    });
                }
                pks
            })
    }

    pub fn plan_of_output(&self, outpoint: OutPoint, assets: &Assets) -> Option<Plan> {
        let index = &self.graph.index;
        let ((k, i), _txout) = index.txout(outpoint)?;
        let desc = index.get_descriptor(k)?.at_derivation_index(i).ok()?;
        let plan = desc.plan(assets).ok()?;
        Some(plan)
    }

    pub fn canonical_txs(&self) -> impl Iterator<Item = TxWithStatus<Arc<Transaction>>> + '_ {
        pub fn status_from_position(pos: ChainPosition<ConfirmationBlockTime>) -> Option<TxStatus> {
            match pos {
                bdk_chain::ChainPosition::Confirmed { anchor, .. } => Some(TxStatus {
                    height: absolute::Height::from_consensus(
                        anchor.confirmation_height_upper_bound(),
                    )
                    .expect("must convert to height"),
                    time: absolute::Time::from_consensus(anchor.confirmation_time as _)
                        .expect("must convert from time"),
                }),
                bdk_chain::ChainPosition::Unconfirmed { .. } => None,
            }
        }
        self.graph
            .graph()
            .list_canonical_txs(
                &self.chain,
                self.chain.tip().block_id(),
                CanonicalizationParams::default(),
            )
            .map(|c_tx| (c_tx.tx_node.tx, status_from_position(c_tx.chain_position)))
    }

    /// Computes an upper bound on the weight of a change output plus the future weight to spend it.
    pub fn change_weight(&self) -> DrainWeights {
        let desc = self
            .graph
            .index
            .get_descriptor(INTERNAL)
            .unwrap()
            .at_derivation_index(0)
            .unwrap();
        let output_weight = TxOut {
            script_pubkey: desc.script_pubkey(),
            value: Amount::ZERO,
        }
        .weight()
        .to_wu();
        let spend_weight = desc.max_weight_to_satisfy().unwrap().to_wu();

        DrainWeights {
            output_weight,
            spend_weight,
            n_outputs: 1,
        }
    }

    pub fn all_candidates(&self) -> bdk_tx::InputCandidates {
        let index = &self.graph.index;
        let assets = self.assets();
        let canon_utxos = CanonicalUnspents::new(self.canonical_txs());
        let can_select = canon_utxos.try_get_unspents(
            index
                .outpoints()
                .iter()
                .filter_map(|(_, op)| Some((*op, self.plan_of_output(*op, &assets)?))),
        );
        InputCandidates::new([], can_select)
    }

    pub fn rbf_candidates(
        &self,
        replace: impl IntoIterator<Item = Txid>,
        tip_height: absolute::Height,
    ) -> anyhow::Result<(bdk_tx::InputCandidates, RbfParams)> {
        let index = &self.graph.index;
        let assets = self.assets();
        let mut canon_utxos = CanonicalUnspents::new(self.canonical_txs());

        // Exclude txs that reside-in `rbf_set`.
        let rbf_set = canon_utxos.extract_replacements(replace)?;
        let must_select = rbf_set
            .must_select_largest_input_of_each_original_tx(&canon_utxos)?
            .into_iter()
            .map(|op| canon_utxos.try_get_unspent(op, self.plan_of_output(op, &assets)?))
            .collect::<Option<Vec<Input>>>()
            .ok_or(anyhow::anyhow!(
                "failed to find input of tx we are intending to replace"
            ))?;

        let can_select = index.outpoints().iter().filter_map(|(_, op)| {
            canon_utxos.try_get_unspent(*op, self.plan_of_output(*op, &assets)?)
        });
        Ok((
            InputCandidates::new(must_select, can_select)
                .filter(rbf_set.candidate_filter(tip_height)),
            rbf_set.selector_rbf_params(),
        ))
    }
}
