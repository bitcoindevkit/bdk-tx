use std::{collections::BTreeSet, vec::Vec};

use crate::{collections::BTreeMap, DefiniteDescriptor, InputGroup, InputStatus};
use bdk_chain::{
    local_chain::LocalChain, BlockId, ConfirmationBlockTime, KeychainIndexed, TxGraph,
};
use bitcoin::{absolute, OutPoint, ScriptBuf};
use core::fmt::{Debug, Display};
use miniscript::{bitcoin, plan::Assets, Descriptor, DescriptorPublicKey, ForEachKey};

use crate::Input;

/// Input candidates that are not processed (filtered and/or grouped).
///
/// Some inputs may be unspendable now (due to unsatisfied time-locks for they are immature
/// coinbase spends).
///
/// TODO: This should live in `bdk_chain` after we move `Input`, `InputGroup`, types to
/// `bdk_tx_core`.
#[derive(Debug, Clone)]
pub struct InputCandidates {
    inputs: Vec<Input>,
}

/// Error
#[derive(Debug)]
pub enum InputCandidatesError<K> {
    /// Descriptor is missing for keychain K.
    MissingDescriptor(K),
    /// Cannot plan descriptor. Missing assets?
    CannotPlan(DefiniteDescriptor),
}

impl<K: Debug> Display for InputCandidatesError<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InputCandidatesError::MissingDescriptor(k) => {
                write!(f, "missing descriptor for keychain {:?}", k)
            }
            InputCandidatesError::CannotPlan(descriptor) => {
                write!(f, "cannot plan input with descriptor {}", descriptor)
            }
        }
    }
}

#[cfg(feature = "std")]
impl<K: Debug> std::error::Error for InputCandidatesError<K> {}

/// Default group policy.
pub fn group_by_spk(input: &Input) -> ScriptBuf {
    input.prev_txout().script_pubkey.clone()
}

/// No grouping.
pub fn no_groups(input: &Input) -> OutPoint {
    input.prev_outpoint()
}

/// Filter out inputs that cannot be spent now.
pub fn filter_unspendable_now(
    tip_height: absolute::Height,
    tip_time: absolute::Time,
) -> impl Fn(&InputGroup) -> bool {
    move |group| group.is_spendable_now(tip_height, tip_time)
}

impl InputCandidates {
    /// Construct.
    ///
    /// # Error
    ///
    /// Requires a descriptor for each corresponding K value.
    pub fn new<K>(
        tx_graph: &TxGraph<ConfirmationBlockTime>,
        chain: &LocalChain,
        chain_tip: BlockId,
        outpoints: impl IntoIterator<Item = KeychainIndexed<K, OutPoint>>,
        descriptors: BTreeMap<K, Descriptor<DescriptorPublicKey>>,
        allow_malleable: BTreeSet<K>,
        additional_assets: Assets,
    ) -> Result<Self, InputCandidatesError<K>>
    where
        K: Clone + Ord + Debug,
    {
        let mut pks = vec![];
        for desc in descriptors.values() {
            desc.for_each_key(|k| {
                pks.extend(k.clone().into_single_keys());
                true
            });
        }

        let assets = Assets::new()
            .after(absolute::LockTime::from_height(chain_tip.height).expect("must be valid height"))
            .add(pks)
            .add(additional_assets);

        let inputs = tx_graph
            .filter_chain_unspents(chain, chain_tip, outpoints)
            .map(move |((k, i), txo)| -> Result<_, InputCandidatesError<K>> {
                let allow_malleable = allow_malleable.contains(&k);
                let descriptor = descriptors
                    .get(&k)
                    .ok_or(InputCandidatesError::MissingDescriptor(k))?
                    .at_derivation_index(i)
                    // TODO: Is this safe?
                    .expect("derivation index must not overflow");

                let mut plan_res = descriptor.plan(&assets);
                if allow_malleable {
                    plan_res = plan_res.or_else(|descriptor| descriptor.plan_mall(&assets));
                }
                let plan = plan_res.map_err(InputCandidatesError::CannotPlan)?;

                // TODO: BDK cannot spend from floating txouts so we will always have the full tx.
                let tx = tx_graph
                    .get_tx(txo.outpoint.txid)
                    .expect("must have full tx");

                let status = match txo.chain_position {
                    bdk_chain::ChainPosition::Confirmed { anchor, .. } => Some(
                        InputStatus::new(anchor.block_id.height, anchor.confirmation_time)
                            .expect("height and time must not overflow"),
                    ),
                    bdk_chain::ChainPosition::Unconfirmed { .. } => None,
                };

                let input = Input::from_prev_tx(
                    plan,
                    tx,
                    txo.outpoint
                        .vout
                        .try_into()
                        .expect("u32 must fit into usize"),
                    status,
                )
                .expect("tx must have output");
                Ok(input)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { inputs })
    }

    /// The unprocessed inputs.
    pub fn inputs(&self) -> &Vec<Input> {
        &self.inputs
    }

    /// Into groups of 1-input-per-group.
    pub fn into_single_groups(
        self,
        filter_policy: impl Fn(&InputGroup) -> bool,
    ) -> Vec<InputGroup> {
        self.inputs
            .into_iter()
            .map::<InputGroup, _>(Into::into)
            .filter(filter_policy)
            .collect()
    }

    /// Into groups.
    pub fn into_groups<G>(
        self,
        group_policy: impl Fn(&Input) -> G,
        filter_policy: impl Fn(&InputGroup) -> bool,
    ) -> Vec<InputGroup>
    where
        G: Clone + Ord + Debug,
    {
        let mut groups = BTreeMap::<G, InputGroup>::new();
        for input in self.inputs.into_iter() {
            let group_key = group_policy(&input);
            use std::collections::btree_map::Entry;
            match groups.entry(group_key) {
                Entry::Vacant(entry) => {
                    entry.insert(InputGroup::from_input(input));
                }
                Entry::Occupied(mut entry) => entry.get_mut().push(input),
            };
        }
        groups.into_values().filter(filter_policy).collect()
    }
}
