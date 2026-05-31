use bdk_tx::bitcoin::{
    absolute, key::Secp256k1, secp256k1::SecretKey, transaction, Amount, FeeRate, Network,
    OutPoint, PrivateKey, ScriptBuf, Transaction, TxIn, TxOut, Weight,
};
use bdk_tx::miniscript::{plan::Assets, plan::Plan, Descriptor, DescriptorPublicKey};
use bdk_tx::{
    CanonicalUnspents, ChangeScript, ConfirmationStatus, DefiniteDescriptor, InputCandidates,
    Output, Selection, Selector, SelectorParams,
};

/// A single-key `wpkh` descriptor we can pay to, plus a [`Plan`] to spend it.
fn spk_plan_descriptor() -> (ScriptBuf, Plan, DefiniteDescriptor) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[7u8; 32]).expect("valid key");
    let pk = PrivateKey::new(sk, Network::Regtest).public_key(&secp);
    let desc_pk: DescriptorPublicKey = pk.to_string().parse().expect("valid pk");
    let (descriptor, _) =
        Descriptor::parse_descriptor(&secp, &format!("wpkh({pk})")).expect("valid descriptor");
    let definite = descriptor
        .at_derivation_index(0)
        .expect("definite descriptor");
    let plan = definite
        .clone()
        .plan(&Assets::new().add(desc_pk))
        .expect("plan");
    (definite.script_pubkey(), plan, definite)
}

fn tx_spending(prev: Option<OutPoint>, spk: &ScriptBuf, output_values: &[u64]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev.unwrap_or_default(),
            ..Default::default()
        }],
        output: output_values
            .iter()
            .map(|v| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: spk.clone(),
            })
            .collect(),
    }
}

fn confirmed(height: u32) -> ConfirmationStatus {
    ConfirmationStatus::new(height, None).expect("valid height")
}

fn total_fee(selection: &Selection) -> u64 {
    let inputs: u64 = selection
        .inputs()
        .iter()
        .map(|i| i.prev_txout().value.to_sat())
        .sum();
    let outputs: u64 = selection.outputs().iter().map(|o| o.value.to_sat()).sum();
    inputs - outputs
}

struct LowFeeParent {
    /// Canonical view holding the confirmed funding tx and the unconfirmed parent.
    graph: CanonicalUnspents,
    /// The parent's output that a child will spend.
    spendable_outpoint: OutPoint,
    /// Fee (sats) the parent already paid, deliberately too low for the target feerate.
    fee: u64,
    /// Weight of the parent transaction.
    weight: Weight,
}

/// Set up a confirmed funding tx feeding a single low-fee unconfirmed parent.
fn setup_low_fee_parent(spk: &ScriptBuf, spendable: u64, fee: u64) -> LowFeeParent {
    let funding = tx_spending(None, spk, &[spendable + fee]);
    let parent = tx_spending(
        Some(OutPoint::new(funding.compute_txid(), 0)),
        spk,
        &[spendable],
    );
    let weight = parent.weight();
    let spendable_outpoint = OutPoint::new(parent.compute_txid(), 0);
    let graph = CanonicalUnspents::new(vec![(funding, Some(confirmed(100))), (parent, None)]);
    LowFeeParent {
        graph,
        spendable_outpoint,
        fee,
        weight,
    }
}

/// Select the given child `candidates` to meet `target_feerate`, finalize, and return the tx fee.
fn finalize_child_fee(
    candidates: InputCandidates,
    spk: &ScriptBuf,
    change: &DefiniteDescriptor,
    target_feerate: FeeRate,
) -> u64 {
    let params = SelectorParams::new(
        target_feerate,
        vec![Output::with_script(spk.clone(), Amount::from_sat(100_000))],
        ChangeScript::from_descriptor(change.clone()),
    );
    let mut selector = Selector::new(&candidates, params).expect("selector builds");
    selector
        .select_until_target_met()
        .expect("single 1M input covers the 100k target");
    let selection = selector.try_finalize().expect("target met");
    total_fee(&selection)
}

#[test]
fn test_cpfp_child_pays_ancestor_bump_fee() {
    let (spk, plan, definite) = spk_plan_descriptor();
    let target_feerate = FeeRate::from_sat_per_vb(50).expect("valid feerate");

    // An unconfirmed parent stuck at a 2_000 sat fee, far below the target feerate.
    let parent = setup_low_fee_parent(&spk, 1_000_000, 2_000);
    let child_input = || {
        parent
            .graph
            .try_get_unspent(parent.spendable_outpoint, plan.clone())
            .expect("child input")
    };

    // Spend the parent's output twice: once oblivious to ancestors, once ancestor-aware.
    let fee_without_ancestors = finalize_child_fee(
        InputCandidates::new([child_input()], []),
        &spk,
        &definite,
        target_feerate,
    );
    let fee_with_ancestors = finalize_child_fee(
        InputCandidates::new([child_input()], [])
            .with_unconfirmed_ancestors(&parent.graph)
            .expect("ancestors resolve"),
        &spk,
        &definite,
        target_feerate,
    );

    // The ancestor-aware child overpays by exactly the CPFP bump needed to lift the parent to the
    // target feerate.
    let child_bump = fee_with_ancestors - fee_without_ancestors;
    let parent_target_fee = target_feerate
        .fee_wu(parent.weight)
        .expect("fee fits")
        .to_sat();
    let expected_bump = parent_target_fee.saturating_sub(parent.fee);
    assert!(expected_bump > 0, "fixture parent must be below target");

    assert_eq!(
        child_bump,
        expected_bump,
        "child bump should cover the CPFP deficit \
         (parent fee {}, weight {} wu)",
        parent.fee,
        parent.weight.to_wu(),
    );
}
