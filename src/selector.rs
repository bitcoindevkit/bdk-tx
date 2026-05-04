use bdk_coin_select::{InsufficientFunds, Replace, Target, TargetFee, TargetOutputs};
use bitcoin::{Amount, FeeRate, ScriptBuf, Transaction, Weight};
use miniscript::bitcoin;

use crate::{
    utils::is_standard_script, DefiniteDescriptor, FeeRateExt, InputCandidates, InputGroup,
    MempoolPolicy, Output, ScriptSource, Selection,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug};

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
/// Use [`SelectorParams::builder`] for the validated construction path, or
/// construct directly via the public fields to opt out of standardness checks.
#[derive(Debug)]
pub struct SelectorParams {
    /// Target feerate.
    ///
    /// The actual feerate of the resulting transaction may be higher due to RBF requirements or
    /// rounding.
    pub target_feerate: FeeRate,

    /// Outputs that must be included.
    pub target_outputs: Vec<Output>,

    /// Source of the change output script.
    ///
    /// The satisfaction weight (cost of spending the change output in the future) is derived from
    /// this. For descriptors it is computed automatically; for raw scripts it must be provided.
    pub change_script: ChangeScript,

    /// Dust relay feerate used to calculate the dust threshold for outputs (target and change).
    ///
    /// If `None`, defaults to 3 sat/vB (the Bitcoin Core default for `-dustrelayfee`).
    pub dust_relay_feerate: Option<FeeRate>,

    /// Minimum change value.
    ///
    /// A change value below this is forgone as fee. `None` means only the dust threshold applies.
    pub change_min_value: Option<Amount>,

    /// Long-term feerate for waste optimization when deciding whether to include change.
    ///
    /// `None` means no waste optimization - just enforce `change_min_value` (if specified) and the
    /// dust threshold.
    pub change_longterm_feerate: Option<FeeRate>,

    /// Params for replacing tx(s).
    pub replace: Option<RbfParams>,
}

/// Source of the change output script and its spending cost.
///
/// For a [`DefiniteDescriptor`], the satisfaction weight is derived automatically. For a raw
/// script (e.g. silent payments), the caller may provide it. It can be omitted if the change
/// policy does not require waste calculations.
#[derive(Debug)]
pub enum ChangeScript {
    /// A raw script pubkey.
    Script {
        /// The output script.
        script: ScriptBuf,
        /// The weight of the witness/scriptSig data needed to spend this script in a future
        /// transaction.
        ///
        /// This is the same value as
        /// [`Plan::satisfaction_weight`](miniscript::plan::Plan::satisfaction_weight) and is used
        /// by coin selection to estimate the cost of spending the change output.
        ///
        /// Can be `Weight::ZERO` if `SelectorParams::change_longterm_feerate` is unspecified.
        satisfaction_weight: Weight,
    },
    /// A definite descriptor from which the script and satisfaction weight are both derived.
    Descriptor {
        /// The descriptor.
        descriptor: Box<DefiniteDescriptor>,
        /// Assets available for satisfying the descriptor.
        ///
        /// If provided, the satisfaction weight is computed via [`Plan`](miniscript::plan::Plan)
        /// for a tighter estimate. If `None`, falls back to
        /// [`max_weight_to_satisfy`](DefiniteDescriptor::max_weight_to_satisfy).
        satisfaction_assets: Option<miniscript::plan::Assets>,
    },
}

impl ChangeScript {
    /// Create from a [`DefiniteDescriptor`].
    ///
    /// The satisfaction weight is derived via
    /// [`max_weight_to_satisfy`](DefiniteDescriptor::max_weight_to_satisfy).
    pub fn from_descriptor(descriptor: DefiniteDescriptor) -> Self {
        Self::Descriptor {
            descriptor: Box::new(descriptor),
            satisfaction_assets: None,
        }
    }

    /// Create from a [`DefiniteDescriptor`] with known assets.
    ///
    /// The satisfaction weight is derived via [`Plan`](miniscript::plan::Plan) for a tighter
    /// estimate based on the provided assets.
    pub fn from_descriptor_with_assets(
        descriptor: DefiniteDescriptor,
        assets: miniscript::plan::Assets,
    ) -> Self {
        Self::Descriptor {
            descriptor: Box::new(descriptor),
            satisfaction_assets: Some(assets),
        }
    }

    /// Create from a raw script.
    pub fn from_script(script: ScriptBuf, satisfaction_weight: Weight) -> Self {
        Self::Script {
            script,
            satisfaction_weight,
        }
    }

    /// Convert to a [`ScriptSource`], discarding the satisfaction weight.
    pub fn source(&self) -> ScriptSource {
        match self {
            ChangeScript::Script { script, .. } => ScriptSource::Script(script.clone()),
            ChangeScript::Descriptor { descriptor, .. } => {
                ScriptSource::Descriptor(descriptor.clone())
            }
        }
    }

    fn satisfaction_weight(&self) -> Result<Weight, SelectorError> {
        match &self {
            ChangeScript::Script {
                satisfaction_weight,
                ..
            } => Ok(*satisfaction_weight),
            ChangeScript::Descriptor {
                descriptor,
                satisfaction_assets,
            } => match satisfaction_assets {
                Some(assets) => descriptor
                    .clone()
                    .plan(assets)
                    .map(|p| Weight::from_wu_usize(p.satisfaction_weight()))
                    .map_err(|_| SelectorError::InsufficientAssets),
                None => descriptor
                    .max_weight_to_satisfy()
                    .map_err(SelectorError::Miniscript),
            },
        }
    }
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
            incremental_relay_feerate: FeeRate::from_sat_per_vb(1).expect("valid fee rate"),
        }
    }

    /// To coin select `Replace` params.
    pub fn to_cs_replace(&self) -> Replace {
        Replace {
            fee: self.original_txs.iter().map(|otx| otx.fee.to_sat()).sum(),
            incremental_relay_feerate: self.incremental_relay_feerate.into_cs_feerate(),
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
        target_feerate: FeeRate,
        target_outputs: Vec<Output>,
        change_script: ChangeScript,
    ) -> Self {
        Self {
            target_feerate,
            target_outputs,
            change_script,
            change_min_value: None,
            change_longterm_feerate: None,
            replace: None,
            dust_relay_feerate: None,
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
                rate: self.target_feerate.max(feerate_lb).into_cs_feerate(),
                replace: self.replace.as_ref().map(|r| r.to_cs_replace()),
            },
            outputs: TargetOutputs::fund_outputs(
                self.target_outputs
                    .iter()
                    .map(|o| (o.txout().weight().to_wu(), o.value.to_sat())),
            ),
        }
    }

    /// Compute the [`bdk_coin_select::ChangePolicy`] from the current params.
    ///
    /// # Errors
    ///
    /// Returns [`SelectorError::InsufficientAssets`] if the provided assets cannot satisfy the
    /// change descriptor.
    ///
    /// Returns [`SelectorError::Miniscript`] if the change descriptor is inherently unsatisfiable.
    pub fn to_cs_change_policy(&self) -> Result<bdk_coin_select::ChangePolicy, SelectorError> {
        let change_script = self.change_script.source().script();
        let min_non_dust = self.dust_relay_feerate.map_or_else(
            || change_script.minimal_non_dust(),
            |r| change_script.minimal_non_dust_custom(r),
        );

        let change_weights = bdk_coin_select::DrainWeights {
            output_weight: {
                let temp_txout = bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: change_script,
                };
                temp_txout.weight().to_wu()
            },
            // This code assumes that the change spend transaction is segwit.
            spend_weight: bitcoin::TxIn::default().segwit_weight().to_wu()
                + self.change_script.satisfaction_weight()?.to_wu(),
            n_outputs: 1,
        };

        let min_value = min_non_dust
            .max(self.change_min_value.unwrap_or(Amount::ZERO))
            .to_sat();

        Ok(
            if let Some(longterm_feerate) = self.change_longterm_feerate {
                bdk_coin_select::ChangePolicy::min_value_and_waste(
                    change_weights,
                    min_value,
                    self.target_feerate.into_cs_feerate(),
                    longterm_feerate.into_cs_feerate(),
                )
            } else {
                bdk_coin_select::ChangePolicy::min_value(change_weights, min_value)
            },
        )
    }

    /// Run output-side standardness checks against `policy`.
    ///
    /// Covers dust thresholds, the `OP_RETURN` zero-value rule, the aggregate
    /// `OP_RETURN` `scriptPubKey` cap, and standard output script types.
    /// Mirrors the output-only part of Bitcoin Core's `IsStandardTx`;
    /// post-selection checks live in [`MempoolPolicy::check_post_selection`].
    ///
    /// Called automatically by [`SelectorParamsBuilder::build`] and
    /// [`SelectorParamsBuilder::build_with_policy`].
    pub fn check_standardness(&self, policy: &MempoolPolicy) -> Result<(), SelectorParamsError> {
        let dust_feerate = self.dust_relay_feerate.unwrap_or(policy.dust_relay_feerate);
        let mut op_return_total_bytes: usize = 0;

        for output in &self.target_outputs {
            let spk = output.script_pubkey();

            if spk.is_op_return() {
                if output.value > Amount::ZERO {
                    return Err(SelectorParamsError::OpReturnWithValue);
                }

                // Aggregate cap across all OP_RETURN outputs, matching
                // Bitcoin Core v30's `-datacarriersize`.
                op_return_total_bytes = op_return_total_bytes.saturating_add(spk.len());

                continue;
            }

            if !is_standard_script(&spk) {
                return Err(SelectorParamsError::NonStandardScriptType);
            }

            let required = spk.minimal_non_dust_custom(dust_feerate);
            if output.value < required {
                return Err(SelectorParamsError::DustOutput {
                    actual: output.value,
                    required,
                });
            }
        }

        if op_return_total_bytes > policy.max_op_return_aggregate_bytes {
            return Err(SelectorParamsError::OpReturnTooLarge {
                actual: op_return_total_bytes,
                max: policy.max_op_return_aggregate_bytes,
            });
        }

        Ok(())
    }

    /// Start a builder.
    ///
    /// The two required fields are taken eagerly so the builder cannot be
    /// constructed in an incomplete state. Outputs and optional fields are
    /// added with chained setters, and the builder terminates with one of
    /// [`build`](SelectorParamsBuilder::build),
    /// [`build_with_policy`](SelectorParamsBuilder::build_with_policy), or
    /// [`build_unchecked`](SelectorParamsBuilder::build_unchecked).
    pub fn builder(target_feerate: FeeRate, change_script: ChangeScript) -> SelectorParamsBuilder {
        SelectorParamsBuilder {
            target_feerate,
            target_outputs: Vec::new(),
            change_script,
            dust_relay_feerate: None,
            change_min_value: None,
            change_longterm_feerate: None,
            replace: None,
        }
    }
}

/// Builder for [`SelectorParams`].
///
/// Three terminal methods are provided. They differ only in which policy (if
/// any) the output side is validated against; the resulting `SelectorParams`
/// shape is the same in every case.
///
/// - [`build`](Self::build) — validate against [`MempoolPolicy::default`].
/// - [`build_with_policy`](Self::build_with_policy) — validate against a
///   caller-supplied policy. Use this when the target node runs non-default
///   relay settings or you want to pin to a specific Core release.
/// - [`build_unchecked`](Self::build_unchecked) — skip validation entirely.
///   Used to deliberately produce non-standard transactions.
#[derive(Debug)]
#[must_use]
pub struct SelectorParamsBuilder {
    target_feerate: FeeRate,
    target_outputs: Vec<Output>,
    change_script: ChangeScript,
    dust_relay_feerate: Option<FeeRate>,
    change_min_value: Option<Amount>,
    change_longterm_feerate: Option<FeeRate>,
    replace: Option<RbfParams>,
}

impl SelectorParamsBuilder {
    /// Add a single target output.
    pub fn add_output(mut self, output: impl Into<Output>) -> Self {
        self.target_outputs.push(output.into());
        self
    }

    /// Add multiple target outputs.
    pub fn add_outputs<I>(mut self, outputs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Output>,
    {
        self.target_outputs
            .extend(outputs.into_iter().map(Into::into));
        self
    }

    /// Override the target feerate.
    pub fn target_feerate(mut self, feerate: FeeRate) -> Self {
        self.target_feerate = feerate;
        self
    }

    /// Override the change script source.
    pub fn change_script(mut self, change_script: ChangeScript) -> Self {
        self.change_script = change_script;
        self
    }

    /// Override the dust relay feerate used to compute dust thresholds for
    /// all outputs (target and change).
    ///
    /// When unset, the threshold derives from the policy supplied to
    /// `build_with_policy` (or [`MempoolPolicy::default`] for `build`).
    pub fn dust_relay_feerate(mut self, feerate: FeeRate) -> Self {
        self.dust_relay_feerate = Some(feerate);
        self
    }

    /// Set a minimum change value.
    pub fn change_min_value(mut self, value: Amount) -> Self {
        self.change_min_value = Some(value);
        self
    }

    /// Enable waste-optimized change decisions using the given long-term feerate.
    pub fn change_longterm_feerate(mut self, feerate: FeeRate) -> Self {
        self.change_longterm_feerate = Some(feerate);
        self
    }

    /// Configure this transaction as a replacement (BIP 125) for the given
    /// original transactions.
    pub fn replace(mut self, replace: RbfParams) -> Self {
        self.replace = Some(replace);
        self
    }

    /// Validate against [`MempoolPolicy::default`] and produce a
    /// [`SelectorParams`].
    pub fn build(self) -> Result<SelectorParams, SelectorParamsError> {
        self.build_with_policy(&MempoolPolicy::default())
    }

    /// Validate against a caller-supplied policy.
    ///
    /// Output-side standardness checks (dust, `OP_RETURN`, standard script
    /// types) are evaluated against `policy`. The dust feerate used by the
    /// change-policy computation also defaults to `policy.dust_relay_feerate`
    /// unless explicitly overridden via [`Self::dust_relay_feerate`].
    pub fn build_with_policy(
        mut self,
        policy: &MempoolPolicy,
    ) -> Result<SelectorParams, SelectorParamsError> {
        if self.dust_relay_feerate.is_none() {
            self.dust_relay_feerate = Some(policy.dust_relay_feerate);
        }
        let params = self.into_params();
        params.check_standardness(policy)?;
        Ok(params)
    }

    /// Skip all validation.
    ///
    /// Use this to deliberately construct non-standard transactions. Pairs
    /// with [`Selection::create_psbt_unchecked`].
    pub fn build_unchecked(self) -> SelectorParams {
        self.into_params()
    }

    fn into_params(self) -> SelectorParams {
        SelectorParams {
            target_feerate: self.target_feerate,
            target_outputs: self.target_outputs,
            change_script: self.change_script,
            dust_relay_feerate: self.dust_relay_feerate,
            change_min_value: self.change_min_value,
            change_longterm_feerate: self.change_longterm_feerate,
            replace: self.replace,
        }
    }
}

/// Errors when building `SelectorParams`.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectorParamsError {
    /// Output value is below dust threshold
    DustOutput {
        /// Actual output value.
        actual: Amount,
        /// Required minimum value.
        required: Amount,
    },
    /// The combined size of all `OP_RETURN` outputs exceeds the aggregate cap.
    OpReturnTooLarge {
        /// Total bytes across all OP_RETURN.
        actual: usize,
        /// Maximum allowed aggregate size
        max: usize,
    },
    /// OP_RETURN output has value greater than zero
    OpReturnWithValue,
    /// An output uses a non-standard script type.
    NonStandardScriptType,
}

impl core::fmt::Display for SelectorParamsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DustOutput { actual, required } => {
                write!(
                    f,
                    "output value {actual} is below the dust threshold of {required}"
                )
            }
            Self::OpReturnTooLarge { actual, max } => {
                write!(
                    f,
                    "aggregate OP_RETURN scriptPubKey size is {actual} bytes, which exceeds the configured limit of {max} bytes"

                )
            }
            Self::OpReturnWithValue => {
                write!(f, "OP_RETURN output must have zero value")
            }
            Self::NonStandardScriptType => {
                write!(f, "an output uses a non-standard script type")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SelectorParamsError {}

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
    /// Miniscript error (e.g. the change descriptor is inherently unsatisfiable).
    Miniscript(miniscript::Error),
    /// Meeting the target is not possible with the input candidates.
    CannotMeetTarget(CannotMeetTarget),
    /// The provided assets cannot satisfy the change descriptor.
    InsufficientAssets,
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Miniscript(err) => write!(f, "{err}"),
            Self::CannotMeetTarget(err) => write!(f, "{err}"),
            Self::InsufficientAssets => {
                write!(f, "provided assets cannot satisfy the change descriptor")
            }
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
        let change_policy = params.to_cs_change_policy()?;
        let target_outputs = params.target_outputs;
        let change_script = params.change_script.source();
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
    pub fn cs_change_policy(&self) -> bdk_coin_select::ChangePolicy {
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
