use bdk_coin_select::{Replace, Target, TargetFee, TargetOutputs};
use bitcoin::{Amount, FeeRate, ScriptBuf, Transaction, Weight};
use miniscript::bitcoin;

use crate::{DefiniteDescriptor, FeeRateExt, Output, ScriptSource};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

/// Context handed to a selection algorithm.
///
/// This is pure data describing the resolved coin-selection target and the parameters an algorithm
/// needs to make change/waste decisions.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SelectionContext {
    /// The resolved coin-selection target (recipient value, weight and feerate).
    pub target: Target,
    /// The change policy derived from the params, used to decide whether to add a change output.
    pub change_policy: bdk_coin_select::ChangePolicy,
    /// Long-term feerate used for waste calculations, e.g. by metrics such as
    /// [`LowestFee`](bdk_coin_select::metrics::LowestFee).
    ///
    /// Resolved from [`SelectionParams::longterm_feerate`]; when that is `None` it defaults to the
    /// target feerate (i.e. "assume future conditions match the present").
    pub longterm_feerate: bdk_coin_select::FeeRate,
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
pub struct SelectionParams {
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

    /// Long-term feerate used for waste optimization across the whole selection - both the change
    /// policy and metrics such as [`LowestFee`](bdk_coin_select::metrics::LowestFee).
    ///
    /// Represents the feerate at which the resulting coins are expected to be spent in the future.
    /// `None` means "assume it matches `target_feerate`", the neutral default when no estimate is
    /// available.
    pub longterm_feerate: Option<FeeRate>,

    /// Params for replacing tx(s).
    pub replace: Option<RbfParams>,
}

/// Source of the change output script and its spending cost.
///
/// For a [`DefiniteDescriptor`], the satisfaction weight is derived automatically. For a raw
/// script (e.g. silent payments), the caller must provide it: the change policy is always
/// waste-aware, so an accurate spend cost is needed to decide whether a change output is worth it.
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
        /// This always feeds the waste calculation, so it should reflect the real spend cost; a
        /// `Weight::ZERO` here will skew the change/no-change decision.
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

    fn satisfaction_weight(&self) -> Result<Weight, ChangePolicyError> {
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
                    .map_err(|_| ChangePolicyError::InsufficientAssets),
                None => descriptor
                    .max_weight_to_satisfy()
                    .map_err(ChangePolicyError::Miniscript),
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

impl SelectionParams {
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
            longterm_feerate: None,
            replace: None,
            change_dust_relay_feerate: None,
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
    /// Returns [`ChangePolicyError::InsufficientAssets`] if the provided assets cannot satisfy the
    /// change descriptor.
    ///
    /// Returns [`ChangePolicyError::Miniscript`] if the change descriptor is inherently
    /// unsatisfiable.
    pub fn to_cs_change_policy(&self) -> Result<bdk_coin_select::ChangePolicy, ChangePolicyError> {
        let change_script = self.change_script.source().script();
        let min_non_dust = self.change_dust_relay_feerate.map_or_else(
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

        // The change policy is always waste-aware. When no long-term feerate is configured we fall
        // back to the target feerate, i.e. "assume the change will be spent under today's
        // conditions". Note this does not collapse to a plain dust threshold: the change output
        // still has to clear its own lifetime cost (creation now plus spending later).
        Ok(bdk_coin_select::ChangePolicy::min_value_and_waste(
            change_weights,
            min_value,
            self.target_feerate.into_cs_feerate(),
            self.longterm_feerate
                .unwrap_or(self.target_feerate)
                .into_cs_feerate(),
        ))
    }
}

/// Error building the change policy from [`SelectionParams`].
///
/// Returned by [`SelectionParams::to_cs_change_policy`]; every variant stems from the change
/// descriptor being unsatisfiable with the available assets.
#[derive(Debug)]
pub enum ChangePolicyError {
    /// Miniscript error (e.g. the change descriptor is inherently unsatisfiable).
    Miniscript(miniscript::Error),
    /// The provided assets cannot satisfy the change descriptor.
    InsufficientAssets,
}

impl fmt::Display for ChangePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Miniscript(err) => write!(f, "{err}"),
            Self::InsufficientAssets => {
                write!(f, "provided assets cannot satisfy the change descriptor")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChangePolicyError {}

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
    fn test_selection_rejects_mixed_absolute_locktime_units() -> anyhow::Result<()> {
        let height_locked_input = setup_cltv_input(absolute::LockTime::from_consensus(10_000))?;
        let time_locked_input = setup_cltv_input(absolute::LockTime::from_consensus(500_000_001))?;
        let candidates = InputCandidates::new([], [height_locked_input, time_locked_input]);
        let params = SelectionParams::new(
            FeeRate::ZERO,
            vec![],
            ChangeScript::from_script(ScriptBuf::new(), Weight::ZERO),
        );
        let result = candidates.into_selection(
            |_cs, _cx| Result::<(), core::convert::Infallible>::Ok(()),
            params,
        );
        assert!(matches!(result, Err(IntoSelectionError::LockTypeMismatch)));
        Ok(())
    }
}
