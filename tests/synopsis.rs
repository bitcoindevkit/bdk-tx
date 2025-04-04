use bdk_bitcoind_rpc::Emitter;
use bdk_chain::{bdk_core, local_chain::LocalChain, Balance};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, no_grouping, selection_algorithm_lowest_fee_bnb,
    ChangePolicyType, CoinControl, Output, PsbtParams, RbfSet, Selector, SelectorParams, Signer,
};
use bitcoin::{absolute, key::Secp256k1, Address, Amount, BlockHash, FeeRate, Sequence, Txid};
use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey, ForEachKey};

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

    pub fn coin_control(
        &self,
        replace: impl IntoIterator<Item = Txid>,
    ) -> anyhow::Result<CoinControl<LocalChain>> {
        let index = &self.graph.index;
        let tip = self.chain.tip().block_id();

        // TODO: Maybe create an `AssetsBuilder` or `AssetsExt` that makes it easier to add
        // assets from descriptors, etc.
        let assets = Assets::new()
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
            });

        let mut coin_control = CoinControl::new(self.graph.graph(), &self.chain, tip, replace);
        coin_control.try_include_inputs(index.outpoints().iter().filter_map(|((k, i), op)| {
            let descriptor = index.get_descriptor(k)?.at_derivation_index(*i).ok()?;
            let plan = descriptor.plan(&assets).ok()?;
            println!("considering output: {}", op);
            Some((*op, plan))
        }));
        Ok(coin_control)
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
        .coin_control(None)?
        .into_candidates(group_by_spk(), filter_unspendable_now(tip_height, tip_time))
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

        // We keep the set of original txs here.
        // Original txs are transactions we intend to replace.
        let rbf_set = RbfSet::new(
            [original_tx.as_ref()],
            original_tx.input.iter().filter_map(|txin| {
                let op = txin.previous_output;
                let txout = wallet.graph.graph().get_txout(op).cloned()?;
                Some((op, txout))
            }),
        )
        .expect("must have no missing prevouts");

        // Input candidates.
        let selection = wallet
            // We canonicalize first.
            // This ensures all input candidates are of a consistent UTXO set.
            // The canonicalization is modified by excluding the original txs and their
            // descendants. This way, the prevouts of the original txs are avaliable for spending
            // and we won't end up picking outputs of the original txs.
            .coin_control(rbf_set.txids())?
            // Filters out unconfirmed input candidates unless it was already an input of an
            // original tx we are replacing (as mentioned in rule 2 of Bitcoin Core Mempool
            // Replacement Policy).
            .into_candidates(no_grouping(), rbf_set.candidate_filter(tip_height))
            // Previously, we only allowed the selection of the original tx's prevouts. However, we
            // need to guarantee atleast one prevout of each original tx is picked, otherwise we
            // may not actually replace the original txs.
            // The policy used here is to choose the largest value prevout of each original tx.
            .with_must_select_policy(rbf_set.must_select_largest_input_per_tx())?
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
                    replace: Some(rbf_set.selector_rbf_params()),
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
