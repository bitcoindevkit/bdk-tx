use bdk_bitcoind_rpc::Emitter;
use bdk_chain::{bdk_core, Balance};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    create_psbt, create_selection, get_candidate_inputs, CreatePsbtParams, CreateSelectionParams,
    InputGroup, Output, Signer,
};
use bitcoin::{key::Secp256k1, Address, Amount, BlockHash, FeeRate};
use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};

const EXTERNAL: &str = "external";
const INTERNAL: &str = "internal";

struct Wallet {
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

    pub fn candidates(&self) -> anyhow::Result<Vec<InputGroup>> {
        let outpoints = self.graph.index.outpoints().clone();
        let internal = self.graph.index.get_descriptor(INTERNAL).unwrap().clone();
        let external = self.graph.index.get_descriptor(EXTERNAL).unwrap().clone();
        let inputs = get_candidate_inputs(
            self.graph.graph(),
            &self.chain,
            outpoints,
            [(INTERNAL, internal), (EXTERNAL, external)].into(),
            Assets::new(),
        )?;
        Ok(inputs.into_iter().map(Into::into).collect())
    }
}

#[test]
fn synopsis() -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let (external, external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[3])?;
    let (internal, internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let external_signer = Signer(external_keymap);
    let internal_signer = Signer(internal_keymap);

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

    let recipient_addr = env
        .rpc_client()
        .get_new_address(None, None)?
        .assume_checked();

    // okay now create tx.
    let input_candidates = wallet.candidates()?;
    println!("input candidates: {}", input_candidates.len());

    let selection = create_selection(CreateSelectionParams {
        input_candidates,
        must_spend: Default::default(),
        // TODO: get this from the wallet.
        change_descriptor: internal.at_derivation_index(0)?,
        target_feerate: FeeRate::from_sat_per_vb(5).unwrap(),
        long_term_feerate: Some(FeeRate::from_sat_per_vb(1).unwrap()),
        target_outputs: vec![Output::with_script(
            recipient_addr.script_pubkey(),
            Amount::from_sat(100_000),
        )],
        max_rounds: 100_000,
    })?;

    let (mut psbt, finalizer) = create_psbt(CreatePsbtParams {
        inputs: selection.inputs,
        outputs: selection.outputs,
        ..Default::default()
    })?;
    let _ = psbt.sign(&external_signer, &secp);
    let _ = psbt.sign(&internal_signer, &secp);
    let res = finalizer.finalize(&mut psbt);
    assert!(res.is_finalized());
    let tx = psbt.extract_tx()?;
    let txid = env.rpc_client().send_raw_transaction(&tx)?;
    println!("tx broadcasted: {}", txid);

    wallet.sync(&env)?;
    println!("balance: {}", wallet.balance());

    Ok(())
}
