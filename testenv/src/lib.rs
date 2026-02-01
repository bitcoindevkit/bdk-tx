use std::{fmt::Debug, sync::Arc};

use bdk_bitcoind_rpc::{bitcoincore_rpc::RpcApi, Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_chain::{
    Anchor, Balance, BlockId, CanonicalView, CanonicalizationParams, ChainPosition, CheckPoint,
    ToBlockHash, ToBlockTime,
};
use bdk_coin_select::{ChangePolicy, DrainWeights};
use bdk_testenv::TestEnv;
use bdk_tx::{
    CanonicalUnspents, ConfirmationStatus, Input, InputCandidates, RbfParams, TxWithStatus,
};
use bitcoin::{
    absolute::{self, Time},
    block::Header,
    key::Secp256k1,
    Address, Amount, OutPoint, Transaction, TxOut, Txid,
};
use miniscript::{
    descriptor::KeyMap,
    plan::{Assets, Plan},
    DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, ForEachKey,
};

pub const EXTERNAL: &str = "external";
pub const INTERNAL: &str = "internal";

pub trait TestEnvExt {
    fn old_rpc_client(&self) -> anyhow::Result<bdk_bitcoind_rpc::bitcoincore_rpc::Client>;
}

impl TestEnvExt for TestEnv {
    fn old_rpc_client(&self) -> anyhow::Result<bdk_bitcoind_rpc::bitcoincore_rpc::Client> {
        Ok(bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
            &self.bitcoind.rpc_url(),
            bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(
                self.bitcoind.params.cookie_file.clone(),
            ),
        )?)
    }
}

pub struct Wallet {
    pub chain: bdk_chain::local_chain::LocalChain<Header>,
    pub graph: bdk_chain::IndexedTxGraph<
        BlockId,
        bdk_chain::keychain_txout::KeychainTxOutIndex<&'static str>,
    >,
    pub view: CanonicalView<BlockId>,
    pub signer: KeyMap,
    pub secp: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
}

impl Wallet {
    pub fn new(
        genesis_header: Header,
        keychains: impl IntoIterator<Item = (&'static str, Descriptor<DescriptorPublicKey>)>,
        keymap: KeyMap,
    ) -> anyhow::Result<Self> {
        let mut indexer = bdk_chain::keychain_txout::KeychainTxOutIndex::default();
        for (k, desc) in keychains {
            indexer.insert_descriptor(k, desc)?;
        }
        let graph = bdk_chain::IndexedTxGraph::new(indexer);
        let (chain, _) = bdk_chain::local_chain::LocalChain::from_genesis(genesis_header);
        let view = graph.canonical_view(
            &chain,
            chain.tip().block_id(),
            CanonicalizationParams::default(),
        );
        Ok(Self {
            chain,
            graph,
            view,
            signer: keymap,
            secp: bitcoin::secp256k1::Secp256k1::new(),
        })
    }

    pub fn multi_keychain<'a>(
        genesis_header: Header,
        keychains: impl IntoIterator<Item = (&'static str, &'a str)>,
    ) -> anyhow::Result<Self> {
        let secp = Secp256k1::new();
        let mut keymap = KeyMap::new();
        let mut pk_keychains = Vec::<(&'static str, Descriptor<DescriptorPublicKey>)>::new();
        for (k, s) in keychains {
            let (desc, km) = Descriptor::parse_descriptor(&secp, s)?;
            pk_keychains.push((k, desc));
            keymap.extend(km);
        }
        Self::new(genesis_header, pk_keychains, keymap)
    }

    pub fn single_keychain(genesis_header: Header, descriptor_str: &str) -> anyhow::Result<Self> {
        Self::multi_keychain(genesis_header, core::iter::once((EXTERNAL, descriptor_str)))
    }

    pub fn sync(&mut self, env: &TestEnv) -> anyhow::Result<()> {
        let client = env.old_rpc_client()?;
        let last_cp = self.chain.tip();
        let mut emitter = Emitter::new(&client, last_cp, 0, NO_EXPECTED_MEMPOOL_TXS);
        while let Some(event) = emitter.next_block()? {
            let _ = self
                .graph
                .apply_block_relevant(&event.block, event.block_height());
            let _ = self.chain.apply_update(event.checkpoint);
        }
        let mempool = emitter.mempool()?;
        let _ = self.graph.batch_insert_relevant_unconfirmed(mempool.update);
        let _ = self.graph.batch_insert_relevant_evicted_at(mempool.evicted);
        self.view = self.graph.canonical_view(
            &self.chain,
            self.chain.tip().block_id(),
            CanonicalizationParams::default(),
        );
        Ok(())
    }

    pub fn next_address(&mut self, keychain: &'static str) -> Option<Address> {
        let ((_, spk), _) = self.graph.index.next_unused_spk(keychain)?;
        Address::from_script(&spk, bitcoin::consensus::Params::REGTEST).ok()
    }

    pub fn balance(&self) -> Balance {
        let outpoints = self.graph.index.outpoints().clone();
        self.view.balance(outpoints, |_, _| true, 0)
    }

    pub fn tip_height(&self) -> u32 {
        self.chain.tip().block_id().height
    }

    /// Info for the block at the tip.
    ///
    /// Returns a tuple of:
    /// - Tip's height. I.e. `tip.height`
    /// - Tip's MTP. I.e. `MTP(tip.height)`
    pub fn tip_info(
        &self,
        client: &impl RpcApi,
    ) -> anyhow::Result<(absolute::Height, absolute::Time)> {
        let tip_hash = self.chain.tip().block_id().hash;
        let tip_info = client.get_block_header_info(&tip_hash)?;
        let tip_height = absolute::Height::from_consensus(tip_info.height as u32)?;
        let tip_mtp = absolute::Time::from_consensus(
            tip_info.median_time.expect("must have median time") as _,
        )?;
        Ok((tip_height, tip_mtp))
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
                    desc.for_any_key(|k| {
                        pks.extend(k.clone().into_single_keys());
                        true
                    });
                }
                pks
            })
    }

    pub fn definite_descriptor(
        &self,
        keychain: &'static str,
        index: u32,
    ) -> anyhow::Result<Descriptor<DefiniteDescriptorKey>> {
        Ok(self
            .graph
            .index
            .get_descriptor(keychain)
            .ok_or(anyhow::anyhow!("keychain not found"))?
            .at_derivation_index(index)?)
    }

    pub fn plan_of_output(&self, outpoint: OutPoint, assets: &Assets) -> Option<Plan> {
        let index = &self.graph.index;
        let ((k, i), _txout) = index.txout(outpoint)?;
        let desc = index.get_descriptor(k)?.at_derivation_index(i).ok()?;
        desc.plan(assets).ok()
    }

    pub fn canonical_txs(&self) -> impl Iterator<Item = TxWithStatus<Arc<Transaction>>> + '_ {
        pub fn status_from_position<D>(
            cp_tip: CheckPoint<D>,
            pos: ChainPosition<BlockId>,
        ) -> Option<ConfirmationStatus>
        where
            D: ToBlockHash + ToBlockTime + Clone + Debug,
        {
            match pos {
                bdk_chain::ChainPosition::Confirmed { anchor, .. } => {
                    let cp = cp_tip.get(anchor.height)?;
                    if cp.hash() != anchor.hash {
                        // TODO: This should only happen if anchor is transitive.
                        return None;
                    }
                    let prev_mtp = cp
                        .prev()
                        .and_then(|prev_cp| prev_cp.median_time_past())
                        .map(|time| Time::from_consensus(time).expect("must convert!"));

                    Some(ConfirmationStatus {
                        height: absolute::Height::from_consensus(
                            anchor.confirmation_height_upper_bound(),
                        )
                        .expect("must convert to height"),
                        prev_mtp,
                    })
                }
                bdk_chain::ChainPosition::Unconfirmed { .. } => None,
            }
        }
        self.view
            .txs()
            .map(|c_tx| (c_tx.tx, status_from_position(self.chain.tip(), c_tx.pos)))
    }

    /// Computes the weight of a change output plus the future weight to spend it.
    pub fn drain_weights(&self) -> DrainWeights {
        // Get descriptor of change keychain at a derivation index.
        let desc = self.definite_descriptor(INTERNAL, 0).unwrap();

        // Compute the weight of a change output for this wallet.
        let output_weight = TxOut {
            script_pubkey: desc.script_pubkey(),
            value: Amount::ZERO,
        }
        .weight()
        .to_wu();

        // The spend weight is the default input weight plus the plan satisfaction weight
        // (this code assumes that we're only dealing with segwit transactions).
        let assets = self.assets();
        let plan = desc.plan(&assets).expect("failed to create Plan");
        let spend_weight =
            bitcoin::TxIn::default().segwit_weight().to_wu() + plan.satisfaction_weight() as u64;

        DrainWeights {
            output_weight,
            spend_weight,
            n_outputs: 1,
        }
    }

    /// Get the default change policy for this wallet.
    pub fn change_policy(&self) -> ChangePolicy {
        let spk_0 = self
            .graph
            .index
            .spk_at_index(INTERNAL, 0)
            .expect("spk should exist in wallet");
        ChangePolicy {
            min_value: spk_0.minimal_non_dust().to_sat(),
            drain_weights: self.drain_weights(),
        }
    }

    pub fn all_candidates(&self) -> InputCandidates {
        let assets = self.assets();
        self.all_candidates_with(&assets)
    }

    pub fn all_candidates_with(&self, assets: &Assets) -> InputCandidates {
        let index = &self.graph.index;
        let canon_utxos = CanonicalUnspents::new(self.canonical_txs());
        let can_select = canon_utxos.try_get_unspents(
            index
                .outpoints()
                .iter()
                .filter_map(|(_, op)| Some((*op, self.plan_of_output(*op, assets)?))),
        );
        InputCandidates::new([], can_select)
    }

    pub fn rbf_candidates(
        &self,
        replace: impl IntoIterator<Item = Txid>,
        tip_height: absolute::Height,
    ) -> anyhow::Result<(InputCandidates, RbfParams)> {
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
