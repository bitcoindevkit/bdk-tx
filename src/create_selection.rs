use core::fmt::{Debug, Display};
use std::collections::{BTreeMap, HashSet};
use std::vec::Vec;

use bdk_chain::KeychainIndexed;
use bdk_chain::{local_chain::LocalChain, Anchor, TxGraph};
use bdk_coin_select::float::Ordf32;
use bdk_coin_select::metrics::LowestFee;
use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, NoBnbSolution, Target, TargetFee,
    TargetOutputs,
};
use bitcoin::{absolute, Amount, OutPoint, TxOut};
use miniscript::bitcoin;
use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey, ForEachKey};

use crate::{DefiniteDescriptor, Input, InputGroup, Output};

/// Error
#[derive(Debug)]
pub enum GetCandidateInputsError<K> {
    /// Descriptor is missing for keychain K.
    MissingDescriptor(K),
    /// Cannot plan descriptor. Missing assets?
    CannotPlan(DefiniteDescriptor),
}

impl<K: Debug> Display for GetCandidateInputsError<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GetCandidateInputsError::MissingDescriptor(k) => {
                write!(f, "missing descriptor for keychain {:?}", k)
            }
            GetCandidateInputsError::CannotPlan(descriptor) => {
                write!(f, "cannot plan input with descriptor {}", descriptor)
            }
        }
    }
}

#[cfg(feature = "std")]
impl<K: Debug> std::error::Error for GetCandidateInputsError<K> {}

/// Get candidate inputs.
///
/// This does not do any UTXO filtering or grouping.
pub fn get_candidate_inputs<A: Anchor, K: Clone + Ord + core::fmt::Debug>(
    tx_graph: &TxGraph<A>,
    chain: &LocalChain,
    outpoints: impl IntoIterator<Item = KeychainIndexed<K, OutPoint>>,
    owned_descriptors: BTreeMap<K, Descriptor<DescriptorPublicKey>>,
    additional_assets: Assets,
) -> Result<Vec<Input>, GetCandidateInputsError<K>> {
    let tip = chain.tip().block_id();

    let mut pks = vec![];
    for desc in owned_descriptors.values() {
        desc.for_each_key(|k| {
            pks.extend(k.clone().into_single_keys());
            true
        });
    }

    let assets = Assets::new()
        .after(absolute::LockTime::from_height(tip.height).expect("must be valid height"))
        .add(pks)
        .add(additional_assets);

    tx_graph
        .filter_chain_unspents(chain, tip, outpoints)
        .map(
            move |((k, i), txo)| -> Result<_, GetCandidateInputsError<K>> {
                let descriptor = owned_descriptors
                    .get(&k)
                    .ok_or(GetCandidateInputsError::MissingDescriptor(k))?
                    .at_derivation_index(i)
                    // TODO: Is this safe?
                    .expect("derivation index must not overflow");

                let plan = match descriptor.desc_type().segwit_version() {
                    Some(_) => descriptor.plan(&assets),
                    None => descriptor.plan_mall(&assets),
                }
                .map_err(GetCandidateInputsError::CannotPlan)?;

                // BDK cannot spend from floating txouts so we will always have the full tx.
                let tx = tx_graph
                    .get_tx(txo.outpoint.txid)
                    .expect("must have full tx");

                let input = Input::from_prev_tx(plan, tx, txo.outpoint.vout as _)
                    .expect("tx must have output");
                Ok(input)
            },
        )
        .collect()
}

/// Parameters for creating tx.
#[derive(Debug, Clone)]
pub struct CreateSelectionParams {
    /// All candidate inputs.
    pub input_candidates: Vec<InputGroup>,

    /// Inputs that must be included in the final tx, given that they exist in `input_candidates`.
    pub must_spend: HashSet<OutPoint>,

    /// To derive change output.
    ///
    /// Will error if this is unsatisfiable descriptor.
    ///
    pub change_descriptor: DefiniteDescriptor,

    /// Feerate target!
    pub target_feerate: bitcoin::FeeRate,

    /// Uses `target_feerate` as a fallback.
    pub long_term_feerate: Option<bitcoin::FeeRate>,

    /// Outputs that must be included.
    pub target_outputs: Vec<Output>,

    /// Max rounds of branch-and-bound.
    pub max_rounds: usize,
}

/// Final selection of inputs and outputs.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Inputs in this selection.
    pub inputs: Vec<Input>,
    /// Outputs in this selection.
    pub outputs: Vec<Output>,
    /// Selection score.
    pub score: Ordf32,
    /// Whether there is a change output in this selection.
    pub has_change: bool,
}

/// When create_tx fails.
#[derive(Debug)]
pub enum CreateSelectionError {
    /// No solution.
    NoSolution(NoBnbSolution),
    /// Cannot satisfy change descriptor.
    CannotSatisfyChangeDescriptor(miniscript::Error),
}

impl Display for CreateSelectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CreateSelectionError::NoSolution(no_bnb_solution) => Display::fmt(&no_bnb_solution, f),
            CreateSelectionError::CannotSatisfyChangeDescriptor(error) => Display::fmt(&error, f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreateSelectionError {}

/// TODO
pub fn create_selection(params: CreateSelectionParams) -> Result<Selection, CreateSelectionError> {
    fn convert_feerate(feerate: bitcoin::FeeRate) -> bdk_coin_select::FeeRate {
        FeeRate::from_sat_per_wu(feerate.to_sat_per_kwu() as f32 / 1000.0)
    }

    let (must_spend, may_spend) =
        params
            .input_candidates
            .into_iter()
            .partition::<Vec<_>, _>(|group: &InputGroup| {
                group
                    .inputs()
                    .iter()
                    .any(|input| params.must_spend.contains(&input.prev_outpoint()))
            });

    let candidates = must_spend
        .iter()
        .chain(&may_spend)
        .map(|group| group.to_candidate())
        .collect::<Vec<Candidate>>();

    let target_feerate = convert_feerate(params.target_feerate);
    let long_term_feerate =
        convert_feerate(params.long_term_feerate.unwrap_or(params.target_feerate));
    println!("target_feerate: {} sats/vb", target_feerate.as_sat_vb());

    let target = Target {
        fee: TargetFee::from_feerate(target_feerate),
        outputs: TargetOutputs::fund_outputs(
            params
                .target_outputs
                .iter()
                .map(|output| (output.txout().weight().to_wu(), output.value.to_sat())),
        ),
    };

    let change_policy = ChangePolicy::min_value_and_waste(
        DrainWeights {
            output_weight: (TxOut {
                script_pubkey: params.change_descriptor.script_pubkey(),
                value: Amount::ZERO,
            })
            .weight()
            .to_wu(),
            spend_weight: params
                .change_descriptor
                .max_weight_to_satisfy()
                .map_err(CreateSelectionError::CannotSatisfyChangeDescriptor)?
                .to_wu(),
            n_outputs: 1,
        },
        params
            .change_descriptor
            .script_pubkey()
            .minimal_non_dust()
            .to_sat(),
        target_feerate,
        long_term_feerate,
    );

    let bnb_metric = LowestFee {
        target,
        long_term_feerate,
        change_policy,
    };

    let mut selector = CoinSelector::new(&candidates);

    // Select input candidates that must be spent.
    for index in 0..must_spend.len() {
        selector.select(index);
    }

    // We assume that this still works if the current selection is already a solution.
    let score = selector
        .run_bnb(bnb_metric, params.max_rounds)
        .map_err(CreateSelectionError::NoSolution)?;

    let maybe_drain = selector.drain(target, change_policy);
    Ok(Selection {
        inputs: selector
            .apply_selection(&must_spend.into_iter().chain(may_spend).collect::<Vec<_>>())
            .flat_map(|group| group.inputs())
            .cloned()
            .collect::<Vec<Input>>(),
        outputs: {
            let mut outputs = params.target_outputs;
            if maybe_drain.is_some() {
                outputs.push(Output::with_descriptor(
                    params.change_descriptor,
                    Amount::from_sat(maybe_drain.value),
                ));
            }
            outputs
        },
        score,
        has_change: maybe_drain.is_some(),
    })
}
