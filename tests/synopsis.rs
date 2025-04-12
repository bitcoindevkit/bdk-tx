use std::sync::Arc;

use bdk_bitcoind_rpc::Emitter;
use bdk_chain::{bdk_core, Anchor, Balance, ChainPosition, ConfirmationBlockTime};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, CanonicalUnspents,
    ChangePolicyType, Input, InputCandidates, InputStatus, Output, PsbtParams, RbfParams,
    SelectorParams, Signer, TxWithStatus,
};
use bitcoin::{
    absolute, key::Secp256k1, Address, Amount, BlockHash, FeeRate, OutPoint, Sequence, Transaction,
    Txid,
};
use miniscript::{
    plan::{Assets, Plan},
    Descriptor, DescriptorPublicKey, ForEachKey,
};

const EXTERNAL: &str = "external";
const INTERNAL: &str = "internal";

pub struct Wallet {
    chain: bdk_chain::local_chain::LocalChain,
    graph: bdk_chain::IndexedTxGraph<
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
        let mut emitter = Emitter::new(client, last_cp, 0);
        while let Some(event) = emitter.next_block()? {
            let _ = self
                .graph
                .apply_block_relevant(&event.block, event.block_height());
            let _ = self.chain.apply_update(event.checkpoint);
        }
        let mempool = emitter.mempool()?;
        let _ = self.graph.batch_insert_relevant_unconfirmed(mempool);
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
        pub fn status_from_position(
            pos: ChainPosition<ConfirmationBlockTime>,
        ) -> Option<InputStatus> {
            match pos {
                bdk_chain::ChainPosition::Confirmed { anchor, .. } => Some(InputStatus {
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
            .list_canonical_txs(&self.chain, self.chain.tip().block_id())
            .map(|c_tx| (c_tx.tx_node.tx, status_from_position(c_tx.chain_position)))
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
        let rbf_set = canon_utxos
            .extract_replacements(replace)
            .ok_or(anyhow::anyhow!("cannot replace given txs"))?;
        // TODO: We should really be returning an error if we fail to select an input of a tx we
        // are intending to replace.
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

#[test]
fn synopsis() -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let (external, external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[3])?;
    let (internal, internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let signer = Signer(external_keymap.into_iter().chain(internal_keymap).collect());

    let env = TestEnv::new()?;
    let genesis_hash = env.genesis_hash()?;
    env.mine_blocks(101, None)?;

    let mut wallet = Wallet::new(genesis_hash, external, internal.clone())?;
    wallet.sync(&env)?;

    let addr = wallet.next_address().expect("must derive address");

    env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("balance: {}", wallet.balance());

    env.send(&addr, Amount::ONE_BTC)?;
    wallet.sync(&env)?;
    println!("balance: {}", wallet.balance());

    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
    let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);

    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .assume_checked();

    // okay now create tx.
    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable_now(tip_height, tip_time))
        .into_selection(
            selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
            SelectorParams::new(
                FeeRate::from_sat_per_vb_unchecked(10),
                vec![Output::with_script(
                    recipient_addr.script_pubkey(),
                    Amount::from_sat(21_000_000),
                )],
                internal.at_derivation_index(0)?,
                bdk_tx::ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
            ),
        )?;

    let mut psbt = selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;
    let finalizer = selection.into_finalizer();

    let _ = psbt.sign(&signer, &secp);
    let res = finalizer.finalize(&mut psbt);
    assert!(res.is_finalized());

    let tx = psbt.extract_tx()?;
    assert_eq!(tx.input.len(), 2);
    let fee = wallet.graph.graph().calculate_fee(&tx)?;
    println!(
        "ORIGINAL TX: inputs={}, outputs={}, fee={}, feerate={}",
        tx.input.len(),
        tx.output.len(),
        fee,
        ((fee.to_sat() as f32) / (tx.weight().to_vbytes_ceil() as f32)),
    );

    // We will try bump this tx fee.
    let txid = env.rpc_client().send_raw_transaction(&tx)?;
    println!("tx broadcasted: {}", txid);
    wallet.sync(&env)?;
    println!("balance: {}", wallet.balance());

    // Try cancel a tx.
    // We follow all the rules as specified by
    // https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md#current-replace-by-fee-policy
    println!("OKAY LET's TRY CANCEL {}", txid);
    {
        let original_tx = wallet
            .graph
            .graph()
            .get_tx_node(txid)
            .expect("must find tx");
        assert_eq!(txid, original_tx.txid);

        // We canonicalize first.
        //
        // This ensures all input candidates are of a consistent UTXO set.
        // The canonicalization is modified by excluding the original txs and their
        // descendants. This way, the prevouts of the original txs are avaliable for spending
        // and we won't end up picking outputs of the original txs.
        //
        // Additionally, we need to guarantee atleast one prevout of each original tx is picked,
        // otherwise we may not actually replace the original txs. The policy used here is to
        // choose the largest value prevout of each original tx.
        //
        // Filters out unconfirmed input candidates unless it was already an input of an
        // original tx we are replacing (as mentioned in rule 2 of Bitcoin Core Mempool
        // Replacement Policy).
        let (rbf_candidates, rbf_params) = wallet.rbf_candidates([txid], tip_height)?;

        let selection = rbf_candidates
            // Do coin selection.
            .into_selection(
                // Coin selection algorithm.
                selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
                SelectorParams {
                    // This is just a lower-bound feerate. The actual result will be much higher to
                    // satisfy mempool-replacement policy.
                    target_feerate: FeeRate::from_sat_per_vb_unchecked(1),
                    // We cancel the tx by specifying no target outputs. This way, all excess returns
                    // to our change output (unless if the prevouts picked are so small that it will
                    // be less wasteful to have no output, however that will not be a valid tx).
                    // If you only want to fee bump, put the original txs' recipients here.
                    target_outputs: vec![],
                    change_descriptor: internal.at_derivation_index(1)?,
                    change_policy: ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
                    // This ensures that we satisfy mempool-replacement policy rules 4 and 6.
                    replace: Some(rbf_params),
                },
            )?;

        let mut psbt = selection.create_psbt(PsbtParams {
            // Not strictly necessary, but it may help us replace this replacement faster.
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        })?;
        println!(
            "selected inputs: {:?}",
            selection
                .inputs
                .iter()
                .map(|input| input.prev_outpoint())
                .collect::<Vec<_>>()
        );

        let finalizer = selection.into_finalizer();
        psbt.sign(&signer, &secp).expect("failed to sign");
        assert!(
            finalizer.finalize(&mut psbt).is_finalized(),
            "must finalize"
        );

        let tx = psbt.extract_tx()?;
        let fee = wallet.graph.graph().calculate_fee(&tx)?;
        println!(
            "REPLACEMENT TX: inputs={}, outputs={}, fee={}, feerate={}",
            tx.input.len(),
            tx.output.len(),
            fee,
            ((fee.to_sat() as f32) / (tx.weight().to_vbytes_ceil() as f32)),
        );
        let txid = env.rpc_client().send_raw_transaction(&tx)?;
        println!("tx broadcasted: {}", txid);
        wallet.sync(&env)?;
        println!("balance: {}", wallet.balance());
    }

    Ok(())
}
