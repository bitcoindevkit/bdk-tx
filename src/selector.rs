use bdk_coin_select::{
    ChangePolicy, DrainWeights, InsufficientFunds, Replace, Target, TargetFee, TargetOutputs,
};
use bitcoin::{Amount, FeeRate, Transaction, Weight};
use miniscript::bitcoin;

use crate::{cs_feerate, InputCandidates, InputGroup, Output, ScriptSource, Selection};
use alloc::vec::Vec;
use core::fmt;

/// A coin selector
#[derive(Debug, Clone)]
pub struct Selector<'c> {
    candidates: &'c InputCandidates,
    target_outputs: Vec<Output>,
    target: Target,
    change_policy: bdk_coin_select::ChangePolicy,
    change_script: ScriptSource,
    inner: bdk_coin_select::CoinSelector<'c>,
}

/// Parameters for creating tx.
///
/// TODO: Create a builder interface on this that does checks. I.e.
/// * Error if recipient is dust.
/// * Error on multi OP_RETURN outputs.
/// * Error on anything that does not satisfy mempool policy.
///   If the caller wants to create non-mempool-policy conforming txs, they can just fill in the
///   fields directly.
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
    pub change_script: ScriptSource,

    /// The policy to determine whether we create a change output.
    pub change_policy: ChangePolicyType,

    /// Weight of the change output plus the future weight to spend the change
    pub change_weight: DrainWeights,

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

/// Change policy type
// TODO: Make this more flexible.
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
    /// Return the [`FeeRate`] of the original tx.
    pub fn feerate(&self) -> FeeRate {
        self.fee / self.weight
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
        Replace {
            fee: self.original_txs.iter().map(|otx| otx.fee.to_sat()).sum(),
            incremental_relay_feerate: cs_feerate(self.incremental_relay_feerate),
        }
    }

    /// Max feerate of all the original txs.
    ///
    /// The replacement tx must have a feerate larger than this value.
    pub fn max_feerate(&self) -> FeeRate {
        self.original_txs
            .iter()
            .map(|otx| otx.feerate())
            .max()
            .unwrap_or(FeeRate::ZERO)
    }
}

impl SelectorParams {
    /// With default params.
    pub fn new(
        target_feerate: bitcoin::FeeRate,
        target_outputs: Vec<Output>,
        change_script: ScriptSource,
        change_policy: ChangePolicyType,
        change_weight: DrainWeights,
    ) -> Self {
        Self {
            target_feerate,
            target_outputs,
            change_script,
            change_policy,
            change_weight,
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

    /// To change policy.
    ///
    /// # Error
    ///
    /// Fails if `change_descriptor` cannot be satisfied.
    pub fn to_cs_change_policy(&self) -> Result<bdk_coin_select::ChangePolicy, miniscript::Error> {
        let change_weights = self.change_weight;
        let dust_value = self.change_script.script().minimal_non_dust().to_sat();
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

/// Error when the selection is impossible with the input candidates
#[derive(Debug)]
pub struct CannotMeetTarget;

impl fmt::Display for CannotMeetTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "meeting the target is not possible with the input candidates"
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CannotMeetTarget {}

/// Selector error
#[derive(Debug)]
pub enum SelectorError {
    /// miniscript error
    Miniscript(miniscript::Error),
    /// meeting the target is not possible
    CannotMeetTarget(CannotMeetTarget),
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Miniscript(err) => write!(f, "{err}"),
            Self::CannotMeetTarget(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SelectorError {}

impl<'c> Selector<'c> {
    /// Create new input selector.
    ///
    /// # Errors
    ///
    /// - If we are unable to create a change policy from the `params`.
    /// - If the target is unreachable given the total input value.
    pub fn new(
        candidates: &'c InputCandidates,
        params: SelectorParams,
    ) -> Result<Self, SelectorError> {
        let target = params.to_cs_target();
        let change_policy = params
            .to_cs_change_policy()
            .map_err(SelectorError::Miniscript)?;
        let target_outputs = params.target_outputs;
        let change_script = params.change_script;
        if target.value() > candidates.groups().map(|grp| grp.value().to_sat()).sum() {
            return Err(SelectorError::CannotMeetTarget(CannotMeetTarget));
        }
        let mut inner = bdk_coin_select::CoinSelector::new(candidates.coin_select_candidates());
        if candidates.must_select().is_some() {
            inner.select_next();
        }
        Ok(Self {
            candidates,
            target,
            target_outputs,
            change_policy,
            change_script,
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

    /// Select with the provided `algorithm`.
    pub fn select_with_algorithm<F, E>(&mut self, mut algorithm: F) -> Result<(), E>
    where
        F: FnMut(&mut Selector) -> Result<(), E>,
    {
        algorithm(self)
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
        let to_apply = self.candidates.groups().collect::<Vec<_>>();
        Some(Selection {
            inputs: self
                .inner
                .apply_selection(&to_apply)
                .copied()
                .flat_map(InputGroup::inputs)
                .cloned()
                .collect(),
            outputs: {
                let mut outputs = self.target_outputs.clone();
                if maybe_change.is_some() {
                    outputs.push(Output::from((
                        self.change_script.clone(),
                        Amount::from_sat(maybe_change.value),
                    )));
                }
                outputs
            },
        })
    }
}
