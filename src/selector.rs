use bdk_coin_select::{
    metrics::LowestFee, Drain, NoBnbSolution, Replace, SelectError, Target, TargetFee,
    TargetOutputs,
};
use bitcoin::{policy::MAX_STANDARD_TX_WEIGHT, Amount, FeeRate, ScriptBuf, Transaction, Weight};
use miniscript::bitcoin;

use crate::{
    DefiniteDescriptor, FeeRateExt, Input, InputCandidates, InputGroup, Output, ScriptSource,
    Selection,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug};

/// A coin selector
#[derive(Debug, Clone)]
pub struct Selector<'c> {
    candidates: &'c InputCandidates,
    target_outputs: Vec<Output>,
    change_policy: bdk_coin_select::ChangePolicy,
    change_script: ScriptSource,
    /// Dust relay feerate [`LowestFee`] uses to judge change as dust.
    dust_relay_feerate: bdk_coin_select::FeeRate,
    /// Change decided by [`Selector::run_lowest_fee_bnb`], after enforcing `change_min_value`.
    ///
    /// Cleared whenever the selection may change, so it never applies to a different selection.
    drain: Option<Drain>,
    /// Dust threshold or `change_min_value`, whichever is larger.
    min_change_value: u64,
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

    /// Dust relay feerate used to calculate the dust threshold for change outputs.
    ///
    /// If `None`, defaults to 3 sat/vB (the Bitcoin Core default for `-dustrelayfee`).
    pub change_dust_relay_feerate: Option<FeeRate>,

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

    /// Maximum allowed weight of the transaction.
    ///
    /// Defaults to the standard relay limit ([`MAX_STANDARD_TX_WEIGHT`], 400,000 WU).
    pub max_weight: Weight,
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
    /// Original txs that are to be replaced.
    pub original_txs: Vec<OriginalTxStats>,
    /// Sum of fees from evicted descendants.
    pub descendant_fee: Amount,
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
    pub fn new<I>(tx_to_replace: I, descendant_fee: Amount) -> Self
    where
        I: IntoIterator,
        I::Item: Into<OriginalTxStats>,
    {
        Self {
            original_txs: tx_to_replace.into_iter().map(Into::into).collect(),
            descendant_fee,
            incremental_relay_feerate: FeeRate::from_sat_per_vb(1).expect("valid fee rate"),
        }
    }

    /// To coin select `Replace` params.
    pub fn to_cs_replace(&self) -> Replace {
        Replace {
            fee: self
                .original_txs
                .iter()
                .map(|otx| otx.fee.to_sat())
                .sum::<u64>()
                + self.descendant_fee.to_sat(),
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
    /// Construct params from the required fields.
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
            change_dust_relay_feerate: None,
            max_weight: Weight::from_wu(u64::from(MAX_STANDARD_TX_WEIGHT)),
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
                ..TargetFee::ZERO
            },
            outputs: TargetOutputs::fund_outputs(
                self.target_outputs
                    .iter()
                    .map(|o| (o.txout().weight().to_wu(), o.value.to_sat())),
            ),
            max_weight: Some(self.max_weight.to_wu()),
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

        let min_value = self.min_change_value(&change_script);

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

    /// Smallest change value worth creating: the dust threshold or `change_min_value`, whichever
    /// is larger. Excludes any waste-based threshold.
    fn min_change_value(&self, change_script: &ScriptBuf) -> u64 {
        let min_non_dust = self.change_dust_relay_feerate.map_or_else(
            || change_script.minimal_non_dust(),
            |r| change_script.minimal_non_dust_custom(r),
        );
        min_non_dust
            .max(self.change_min_value.unwrap_or(Amount::ZERO))
            .to_sat()
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
    /// Miniscript error (e.g. the change descriptor is inherently unsatisfiable).
    Miniscript(miniscript::Error),
    /// Meeting the target is not possible with the input candidates.
    CannotMeetTarget(CannotMeetTarget),
    /// The provided assets cannot satisfy the change descriptor.
    InsufficientAssets,
    /// Input candidates have absolute timelocks of mixed units (some height-based, others
    /// time-based).
    ///
    /// Such a set is unbuildable since `nLockTime` is a single field on a transaction.
    /// Filter the [`InputCandidates`] down to a single-unit subset before constructing the
    /// [`Selector`].
    LockTypeMismatch,
    /// The selection exceeds the maximum allowed transaction weight.
    MaxWeightExceeded,
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Miniscript(err) => write!(f, "{err}"),
            Self::CannotMeetTarget(err) => write!(f, "{err}"),
            Self::InsufficientAssets => {
                write!(f, "provided assets cannot satisfy the change descriptor")
            }
            Self::LockTypeMismatch => {
                write!(f, "input candidates have absolute timelocks of mixed units")
            }
            Self::MaxWeightExceeded => write!(
                f,
                "selection exceeds the maximum allowed transaction weight"
            ),
        }
    }
}

impl From<SelectError> for SelectorError {
    fn from(e: SelectError) -> Self {
        match e {
            SelectError::InsufficientFunds(_) => Self::CannotMeetTarget(CannotMeetTarget),
            SelectError::MaxWeightExceeded => Self::MaxWeightExceeded,
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

        let change_script = params.change_script.source();
        let min_change_value = params.min_change_value(&change_script.script());

        let dust_relay_feerate = params
            .change_dust_relay_feerate
            .unwrap_or(FeeRate::DUST)
            .into_cs_feerate();

        let target_outputs = params.target_outputs;

        if target.value() > candidates.groups().map(|grp| grp.value().to_sat()).sum() {
            return Err(SelectorError::CannotMeetTarget(CannotMeetTarget));
        }

        // Verify that all inputs agree on absolute timelock unit (height vs time).
        // Downstream stages (create_psbt, apply_anti_fee_sniping) rely on this invariant.
        let mut unit: Option<bitcoin::absolute::LockTime> = None;
        for lt in candidates.inputs().filter_map(Input::absolute_timelock) {
            match unit {
                Some(existing_unit) => {
                    if !existing_unit.is_same_unit(lt) {
                        return Err(SelectorError::LockTypeMismatch);
                    }
                }
                None => unit = Some(lt),
            }
        }

        let mut inner =
            bdk_coin_select::CoinSelector::new(candidates.coin_select_candidates(), target);
        if candidates.must_select().is_some() {
            inner.select_next();
        }
        Ok(Self {
            candidates,
            target_outputs,
            change_policy,
            change_script,
            dust_relay_feerate,
            drain: None,
            min_change_value,
            inner,
        })
    }

    /// Get the inner coin selector.
    pub fn inner(&self) -> &bdk_coin_select::CoinSelector<'c> {
        &self.inner
    }

    /// Get a mutable reference to the inner coin selector.
    ///
    /// Discards any change decided by a previous search, since the selection may be modified.
    pub fn inner_mut(&mut self) -> &mut bdk_coin_select::CoinSelector<'c> {
        self.drain = None;
        &mut self.inner
    }

    /// Coin selection target.
    pub fn target(&self) -> Target {
        self.inner.target()
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
        self.drain = None;
        self.inner.select_all();
    }

    /// Select in order until target is met.
    pub fn select_until_target_met(&mut self) -> Result<(), SelectorError> {
        self.drain = None;
        self.inner.select_until_target_met()?;
        Ok(())
    }

    /// Whether we added the change output to the selection.
    ///
    /// Return `None` if target is not met yet.
    pub fn has_change(&self) -> Option<bool> {
        if !self.inner.is_funded() {
            return None;
        }
        Some(self.effective_drain().is_some())
    }

    /// The change for the current selection.
    ///
    /// Uses the change decided by the last metric-driven search if it is still valid, otherwise
    /// falls back to the change policy.
    fn effective_drain(&self) -> Drain {
        self.drain
            .unwrap_or_else(|| self.inner.drain(self.change_policy))
    }

    /// Estimated weight of the transaction.
    pub fn weight(&self) -> Weight {
        Weight::from_wu(self.inner.weight(self.effective_drain().weights))
    }

    /// Maximum allowed transaction weight, if any.
    pub fn max_weight(&self) -> Option<Weight> {
        self.inner.target().max_weight.map(Weight::from_wu)
    }

    /// Run branch and bound with [`LowestFee`], keeping the change decision it makes.
    ///
    /// # Errors
    ///
    /// Returns [`NoBnbSolution::MaxWeightExceeded`] if the best selection only fits
    /// [`SelectorParams::max_weight`] by dropping change that is worth keeping.
    pub fn run_lowest_fee_bnb(
        &mut self,
        long_term_feerate: FeeRate,
        max_rounds: usize,
    ) -> Result<(), NoBnbSolution> {
        self.drain = None;

        let metric = LowestFee {
            long_term_feerate: long_term_feerate.into_cs_feerate(),
            dust_relay_feerate: self.dust_relay_feerate,
            drain_weights: self.change_policy.drain_weights,
        };
        let (_, mut drain) = self.inner.run_bnb(metric, max_rounds)?;

        // LowestFee drops change that would exceed `max_weight` and pays it as fee instead.
        if drain.is_none()
            && self.inner.drain(self.change_policy).is_some()
            && !self
                .inner
                .is_within_max_weight(self.change_policy.drain_weights)
        {
            return Err(NoBnbSolution::MaxWeightExceeded);
        }

        // LowestFee doesn't know `change_min_value`, so enforce it here.
        if drain.is_some() && drain.value <= self.min_change_value {
            drain = Drain::NONE;
        }

        self.drain = Some(drain);
        Ok(())
    }

    /// Try get final selection.
    ///
    /// # Errors
    ///
    /// - [`SelectorError::CannotMeetTarget`] if the target is not met yet.
    /// - [`SelectorError::MaxWeightExceeded`] if the estimated transaction weight exceeds [`SelectorParams::max_weight`].
    pub fn try_finalize(&self) -> Result<Selection, SelectorError> {
        let drain = self.effective_drain();

        if !self.inner.is_within_max_weight(drain.weights) {
            return Err(SelectorError::MaxWeightExceeded);
        }

        if !self.inner.is_funded() {
            return Err(SelectorError::CannotMeetTarget(CannotMeetTarget));
        }
        let to_apply = self.candidates.groups().collect::<Vec<_>>();
        let inputs = self
            .inner
            .apply_selection(&to_apply)
            .copied()
            .flat_map(InputGroup::inputs)
            .cloned()
            .collect();
        let mut outputs = self.target_outputs.clone();
        if drain.is_some() {
            outputs.push(Output::from((
                self.change_script.clone(),
                Amount::from_sat(drain.value),
            )));
        }

        Ok(Selection::new(inputs, outputs))
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use crate::*;
    use bitcoin::{
        absolute, key::Secp256k1, secp256k1::SecretKey, transaction, Amount, FeeRate, PrivateKey,
        ScriptBuf, Transaction, TxIn, TxOut, Weight,
    };
    use miniscript::{plan::Assets, DescriptorPublicKey};
    use std::string::ToString;

    fn setup_cltv_input(cltv: absolute::LockTime) -> anyhow::Result<Input> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1_u8; 32])?;
        let public_key = PrivateKey::new(secret_key, bitcoin::Network::Regtest).public_key(&secp);
        let desc_str = format!("wsh(and_v(v:pk({public_key}),after({cltv})))");
        let desc_pk: DescriptorPublicKey = public_key.to_string().parse()?;
        let (desc, _) = Descriptor::parse_descriptor(&secp, &desc_str)?;
        let plan = desc
            .at_derivation_index(0)?
            .plan(&Assets::new().add(desc_pk).after(cltv))
            .expect("locktime asset must satisfy descriptor");
        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.at_derivation_index(0)?.script_pubkey(),
                value: Amount::ONE_BTC,
            }],
        };
        Ok(Input::from_prev_tx(plan, prev_tx, 0, None)?)
    }

    #[test]
    fn test_selector_rejects_mixed_absolute_locktime_units() -> anyhow::Result<()> {
        let height_locked_input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let time_locked_input = setup_cltv_input(absolute::LockTime::from_consensus(500_000_001))?;
        let candidates = InputCandidates::new([], [height_locked_input, time_locked_input]);
        let params = SelectorParams::new(
            FeeRate::ZERO,
            vec![],
            ChangeScript::from_script(ScriptBuf::new(), Weight::ZERO),
        );
        assert!(matches!(
            Selector::new(&candidates, params),
            Err(SelectorError::LockTypeMismatch)
        ));
        Ok(())
    }

    #[test]
    fn lowest_fee_bnb_errors_instead_of_burning_change() -> anyhow::Result<()> {
        let input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let spk = input.prev_txout().script_pubkey.clone();
        let candidates = InputCandidates::new([], [input]);
        let make_params = || {
            SelectorParams::new(
                FeeRate::from_sat_per_vb_u32(2),
                vec![Output::with_script(spk.clone(), Amount::from_sat(10_000))],
                ChangeScript::from_script(spk.clone(), Weight::ZERO),
            )
        };

        // Weight of the transaction with no change.
        let without_change = {
            let mut selector = Selector::new(&candidates, make_params())?;
            selector.select_all();
            selector.inner().weight(bdk_coin_select::DrainWeights::NONE)
        };

        // The changeless transaction fits, but the change output does not. Dropping change here
        // would pay almost the whole 1 BTC input as fee.
        let mut params = make_params();
        params.max_weight = Weight::from_wu(without_change);

        let err = candidates
            .into_selection(
                selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb_u32(1), 100_000),
                params,
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                IntoSelectionError::SelectionAlgorithm(
                    bdk_coin_select::NoBnbSolution::MaxWeightExceeded
                )
            ),
            "expected MaxWeightExceeded, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn lowest_fee_bnb_keeps_change_that_fits_max_weight() -> anyhow::Result<()> {
        let input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let spk = input.prev_txout().script_pubkey.clone();
        let candidates = InputCandidates::new([], [input]);
        let make_params = || {
            SelectorParams::new(
                FeeRate::from_sat_per_vb_u32(2),
                vec![Output::with_script(spk.clone(), Amount::from_sat(10_000))],
                ChangeScript::from_script(spk.clone(), Weight::ZERO),
            )
        };

        // Cap exactly at the weight with change.
        let with_change = {
            let mut selector = Selector::new(&candidates, make_params())?;
            selector.select_all();
            selector
                .inner()
                .weight(selector.cs_change_policy().drain_weights)
        };
        let mut params = make_params();
        params.max_weight = Weight::from_wu(with_change);

        let selection = candidates.into_selection(
            selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb_u32(1), 100_000),
            params,
        )?;
        assert_eq!(selection.outputs().len(), 2, "change must be kept");
        Ok(())
    }
    #[test]
    fn into_selection_errors_when_max_weight_exceeded() -> anyhow::Result<()> {
        let input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let recipient_spk = input.prev_txout().script_pubkey.clone();
        let candidates = InputCandidates::new([], [input]);

        let mut params = SelectorParams::new(
            FeeRate::from_sat_per_vb_u32(2),
            vec![Output::with_script(recipient_spk, Amount::from_sat(10_000))],
            ChangeScript::from_script(ScriptBuf::new(), Weight::ZERO),
        );
        params.max_weight = Weight::from_wu(100);

        let err = candidates
            .into_selection(|selector| selector.select_until_target_met(), params)
            .unwrap_err();

        assert!(
            matches!(
                err,
                IntoSelectionError::SelectionAlgorithm(SelectorError::MaxWeightExceeded)
            ),
            "expected MaxWeightExceeded, got {err:?}"
        );

        Ok(())
    }

    #[test]
    fn max_weight_is_none_when_target_has_no_cap() -> anyhow::Result<()> {
        let input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let spk = input.prev_txout().script_pubkey.clone();
        let candidates = InputCandidates::new([], [input]);
        let params = SelectorParams::new(
            FeeRate::from_sat_per_vb_u32(2),
            vec![Output::with_script(spk.clone(), Amount::from_sat(10_000))],
            ChangeScript::from_script(spk, Weight::ZERO),
        );
        let mut selector = Selector::new(&candidates, params)?;

        let mut target = selector.target();
        target.max_weight = None;
        let uncapped = selector.inner().with_target(target);
        *selector.inner_mut() = uncapped;

        assert_eq!(selector.max_weight(), None);
        selector.select_all();
        assert!(selector.try_finalize().is_ok());
        Ok(())
    }

    #[test]
    fn try_finalize_checks_weight_with_change() -> anyhow::Result<()> {
        let input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let spk = input.prev_txout().script_pubkey.clone();
        let candidates = InputCandidates::new([], [input]);
        let make_params = || {
            SelectorParams::new(
                FeeRate::from_sat_per_vb_u32(2),
                vec![Output::with_script(spk.clone(), Amount::from_sat(10_000))],
                ChangeScript::from_script(spk.clone(), Weight::ZERO),
            )
        };

        // The changeless transaction fits, but the change output does not.
        let without_change = {
            let mut selector = Selector::new(&candidates, make_params())?;
            selector.select_all();
            selector.inner().weight(bdk_coin_select::DrainWeights::NONE)
        };
        let mut params = make_params();
        params.max_weight = Weight::from_wu(without_change);

        let mut selector = Selector::new(&candidates, params)?;
        selector.select_until_target_met()?;
        assert!(matches!(
            selector.try_finalize(),
            Err(SelectorError::MaxWeightExceeded)
        ));
        Ok(())
    }

    #[test]
    fn lowest_fee_bnb_drops_change_below_change_min_value() -> anyhow::Result<()> {
        let input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let spk = input.prev_txout().script_pubkey.clone();
        let candidates = InputCandidates::new([], [input]);

        // About 19,000 sats of change, below `change_min_value`.
        let mut params = SelectorParams::new(
            FeeRate::from_sat_per_vb_u32(2),
            vec![Output::with_script(
                spk.clone(),
                Amount::ONE_BTC - Amount::from_sat(20_000),
            )],
            ChangeScript::from_script(spk, Weight::ZERO),
        );
        params.change_min_value = Some(Amount::from_sat(50_000));

        let selection = candidates.into_selection(
            selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb_u32(1), 100_000),
            params,
        )?;
        assert_eq!(
            selection.outputs().len(),
            1,
            "change below change_min_value must be dropped"
        );
        Ok(())
    }
}
