use bdk_coin_select::{
    float::Ordf32, metrics::LowestFee, ChangePolicy, DrainWeights, InsufficientFunds,
    NoBnbSolution, Replace, Target, TargetFee, TargetOutputs,
};
use bitcoin::{Amount, FeeRate, Transaction, TxOut, Weight};
use miniscript::bitcoin;

use crate::{cs_feerate, DefiniteDescriptor, InputCandidates, InputGroup, Output, Selection};
use alloc::vec::Vec;

/// You seeing this?
#[derive(Debug, Clone)]
pub struct Selector<'c> {
    candidates: &'c InputCandidates,
    target_outputs: Vec<Output>,
    target: Target,
    change_policy: bdk_coin_select::ChangePolicy,
    change_descriptor: DefiniteDescriptor,
    inner: bdk_coin_select::CoinSelector<'c>,
}

/// Parameters for creating tx.
///
/// TODO: Create a builder interface on this that does checks. I.e.
/// * Error if recipient is dust.
/// * Error on multi OP_RETURN outputs.
/// * Error on anything that does not satisfy mempool policy.
///     If the caller wants to create non-mempool-policy conforming txs, they can just fill in the
///     fields directly.
#[derive(Debug, Clone)]
pub struct SelectorParams {
    /// Feerate target!
    ///
    /// This can end up higher.
    pub target_feerate: bitcoin::FeeRate,

    ///// Uses `target_feerate` as a fallback.
    //pub long_term_feerate: bitcoin::FeeRate,
    /// Outputs that must be included.
    pub target_outputs: Vec<Output>,

    /// To derive change output.
    ///
    /// Will error if this is unsatisfiable descriptor.
    pub change_descriptor: DefiniteDescriptor,

    /// The policy to determine whether we create a change output.
    pub change_policy: ChangePolicyType,

    /// Params for replacing tx(s).
    pub replace: Option<RbfParams>,
}

/// Rbf original tx stats.
#[derive(Debug, Clone, Copy)]
pub struct OriginalTxStats {
    /// Total weight of the original tx.
    pub weight: Weight,
    /// Total fee amount of the original tx.
    pub fee: Amount,
}

impl From<(Weight, Amount)> for OriginalTxStats {
    fn from((weight, fee): (Weight, Amount)) -> Self {
        Self { weight, fee }
    }
}

impl From<(&Transaction, Amount)> for OriginalTxStats {
    fn from((tx, fee): (&Transaction, Amount)) -> Self {
        let weight = tx.weight();
        Self { weight, fee }
    }
}

/// Rbf params.
#[derive(Debug, Clone)]
pub struct RbfParams {
    /// Original txs.
    pub original_txs: Vec<OriginalTxStats>,
    /// Incremental relay feerate.
    pub incremental_relay_feerate: FeeRate,
}

/// TODO: Make this more flexible.
#[derive(Debug, Clone, Copy)]
pub enum ChangePolicyType {
    /// Avoid creating dust change output.
    NoDust,
    /// Avoid creating dust change output and minimize waste.
    NoDustAndLeastWaste {
        /// Long term feerate.
        longterm_feerate: bitcoin::FeeRate,
    },
}

impl OriginalTxStats {
    /// Feerate.
    ///
    /// TODO: Make sure this is correct with the rounding.
    pub fn feerate(&self) -> FeeRate {
        FeeRate::from_sat_per_vb_unchecked(
            ((self.fee.to_sat() as f32) / (self.weight.to_vbytes_ceil() as f32)) as _,
        )
    }
}

impl RbfParams {
    /// Construct RBF parameters.
    pub fn new<I>(tx_to_replace: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<OriginalTxStats>,
    {
        Self {
            original_txs: tx_to_replace.into_iter().map(Into::into).collect(),
            incremental_relay_feerate: FeeRate::from_sat_per_vb_unchecked(1),
        }
    }

    /// To coin select `Replace` params.
    pub fn to_cs_replace(&self) -> Replace {
        let replace = Replace {
            fee: self.original_txs.iter().map(|otx| otx.fee.to_sat()).sum(),
            incremental_relay_feerate: cs_feerate(self.incremental_relay_feerate),
        };
        replace
    }

    /// Max feerate of all the original txs.
    ///
    /// The replacement tx must have a feerate larger than this value.
    pub fn max_feerate(&self) -> FeeRate {
        self.original_txs
            .iter()
            .map(|otx| otx.feerate())
            .min()
            .unwrap_or(FeeRate::ZERO)
    }
}

impl SelectorParams {
    /// With default params.
    pub fn new(
        target_feerate: bitcoin::FeeRate,
        target_outputs: Vec<Output>,
        change_descriptor: DefiniteDescriptor,
        change_policy: ChangePolicyType,
    ) -> Self {
        Self {
            change_descriptor,
            change_policy,
            target_feerate,
            target_outputs,
            replace: None,
        }
    }

    /// To coin select target.
    pub fn to_cs_target(&self) -> Target {
        let feerate_lb = self
            .replace
            .as_ref()
            .map_or(FeeRate::ZERO, |r| r.max_feerate());
        Target {
            fee: TargetFee {
                rate: cs_feerate(self.target_feerate.max(feerate_lb)),
                replace: self.replace.as_ref().map(|r| r.to_cs_replace()),
            },
            outputs: TargetOutputs::fund_outputs(
                self.target_outputs
                    .iter()
                    .map(|output| (output.txout().weight().to_wu(), output.value.to_sat())),
            ),
        }
    }

    /// To change output weights.
    ///
    /// # Error
    ///
    /// Fails if `change_descriptor` cannot be satisfied.
    pub fn to_cs_change_weights(&self) -> Result<bdk_coin_select::DrainWeights, miniscript::Error> {
        Ok(DrainWeights {
            output_weight: (TxOut {
                script_pubkey: self.change_descriptor.script_pubkey(),
                value: Amount::ZERO,
            })
            .weight()
            .to_wu(),
            spend_weight: self.change_descriptor.max_weight_to_satisfy()?.to_wu(),
            n_outputs: 1,
        })
    }

    /// To change policy.
    ///
    /// # Error
    ///
    /// Fails if `change_descriptor` cannot be satisfied.
    pub fn to_cs_change_policy(&self) -> Result<bdk_coin_select::ChangePolicy, miniscript::Error> {
        let change_weights = self.to_cs_change_weights()?;
        let dust_value = self
            .change_descriptor
            .script_pubkey()
            .minimal_non_dust()
            .to_sat();
        Ok(match self.change_policy {
            ChangePolicyType::NoDust => ChangePolicy::min_value(change_weights, dust_value),
            ChangePolicyType::NoDustAndLeastWaste { longterm_feerate } => {
                ChangePolicy::min_value_and_waste(
                    change_weights,
                    dust_value,
                    cs_feerate(self.target_feerate),
                    cs_feerate(longterm_feerate),
                )
            }
        })
    }
}

impl<'c> Selector<'c> {
    /// Create new input selector.
    ///
    /// TODO: Have this return custom error with more check:
    /// * Whether selection is even possible.
    pub fn new(
        candidates: &'c InputCandidates,
        params: SelectorParams,
    ) -> Result<Self, miniscript::Error> {
        let target = params.to_cs_target();
        let change_policy = params.to_cs_change_policy()?;
        let target_outputs = params.target_outputs;
        let change_descriptor = params.change_descriptor;
        let mut inner = bdk_coin_select::CoinSelector::new(candidates.coin_select_candidates());
        for _ in 0..candidates.must_select_len() {
            inner.select_next();
        }
        Ok(Self {
            candidates,
            target,
            target_outputs,
            change_policy,
            change_descriptor,
            inner,
        })
    }

    /// Get the inner coin selector.
    pub fn inner(&self) -> &bdk_coin_select::CoinSelector<'c> {
        &self.inner
    }

    /// Get a mutable reference to the inner coin selector.
    pub fn inner_mut(&mut self) -> &mut bdk_coin_select::CoinSelector<'c> {
        &mut self.inner
    }

    /// Coin selection target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// Coin selection change policy.
    pub fn change_policy(&self) -> bdk_coin_select::ChangePolicy {
        self.change_policy
    }

    /// Do branch-and-bound selection with `LowestFee` metric.
    pub fn select_for_lowest_fee(
        &mut self,
        longterm_feerate: FeeRate,
        max_bnb_rounds: usize,
    ) -> Result<Ordf32, NoBnbSolution> {
        self.inner.run_bnb(
            LowestFee {
                target: self.target,
                long_term_feerate: cs_feerate(longterm_feerate),
                change_policy: self.change_policy,
            },
            max_bnb_rounds,
        )
    }

    /// Select all.
    pub fn select_all(&mut self) {
        self.inner.select_all();
    }

    /// Select in order until target is met.
    pub fn select_until_target_met(&mut self) -> Result<(), InsufficientFunds> {
        self.inner.select_until_target_met(self.target)
    }

    /// Whether we added the change output to the selection.
    ///
    /// Return `None` if target is not met yet.
    pub fn has_change(&self) -> Option<bool> {
        if !self.inner.is_target_met(self.target) {
            return None;
        }
        let has_drain = self
            .inner
            .drain_value(self.target, self.change_policy)
            .is_some();
        Some(has_drain)
    }

    /// Try get final selection.
    ///
    /// Return `None` if target is not met yet.
    pub fn try_finalize(&self) -> Option<Selection> {
        if !self.inner.is_target_met(self.target) {
            return None;
        }
        let maybe_change = self.inner.drain(self.target, self.change_policy);
        Some(Selection {
            inputs: self
                .inner
                .apply_selection(self.candidates.groups())
                .flat_map(InputGroup::inputs)
                .cloned()
                .collect(),
            outputs: {
                let mut outputs = self.target_outputs.clone();
                if maybe_change.is_some() {
                    outputs.push(Output::with_descriptor(
                        self.change_descriptor.clone(),
                        Amount::from_sat(maybe_change.value),
                    ));
                }
                outputs
            },
        })
    }
}
