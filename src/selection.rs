use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use bdk_coin_select::FeeRate;
use bitcoin::{absolute, transaction, Sequence};
use miniscript::bitcoin;
use miniscript::psbt::PsbtExt;

use crate::{Finalizer, Input, Output};

const FALLBACK_SEQUENCE: bitcoin::Sequence = bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF;

pub(crate) fn cs_feerate(feerate: bitcoin::FeeRate) -> bdk_coin_select::FeeRate {
    FeeRate::from_sat_per_wu(feerate.to_sat_per_kwu() as f32 / 1000.0)
}

/// Final selection of inputs and outputs.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Inputs in this selection.
    pub inputs: Vec<Input>,
    /// Outputs in this selection.
    pub outputs: Vec<Output>,
}

/// Parameters for creating a psbt.
#[derive(Debug, Clone)]
pub struct PsbtParams {
    /// Use a specific [`transaction::Version`].
    pub version: transaction::Version,

    /// Fallback tx locktime.
    ///
    /// The locktime to use if no input specifies a required absolute locktime.
    ///
    /// It is best practice to set this to the latest block height to avoid fee sniping.
    pub fallback_locktime: absolute::LockTime,

    /// [`Sequence`] value to use by default if not provided by the input.
    pub fallback_sequence: Sequence,

    /// Whether to require the full tx, aka [`non_witness_utxo`] for segwit v0 inputs,
    /// default is `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,

    /// Sighash type to be used for each input.
    ///
    /// This option only applies to [`Input`]s that include a plan, as otherwise the given PSBT
    /// input can be expected to set a specific sighash type. Defaults to `None` which will not
    /// set an explicit sighash type for any input. (In that case the sighash will typically
    /// cover all of the outputs).
    pub sighash_type: Option<bitcoin::psbt::PsbtSighashType>,
}

impl Default for PsbtParams {
    fn default() -> Self {
        Self {
            version: transaction::Version::TWO,
            fallback_locktime: absolute::LockTime::ZERO,
            fallback_sequence: FALLBACK_SEQUENCE,
            mandate_full_tx_for_segwit_v0: true,
            sighash_type: None,
        }
    }
}

/// Occurs when creating a psbt fails.
#[derive(Debug)]
pub enum CreatePsbtError {
    /// Attempted to mix locktime types.
    LockTypeMismatch,
    /// Missing tx for legacy input.
    MissingFullTxForLegacyInput(Input),
    /// Missing tx for segwit v0 input.
    MissingFullTxForSegwitV0Input(Input),
    /// Psbt error.
    Psbt(bitcoin::psbt::Error),
    /// Update psbt output with descriptor error.
    OutputUpdate(miniscript::psbt::OutputUpdateError),
}

impl core::fmt::Display for CreatePsbtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CreatePsbtError::LockTypeMismatch => write!(f, "cannot mix locktime units"),
            CreatePsbtError::MissingFullTxForLegacyInput(input) => write!(
                f,
                "legacy input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            CreatePsbtError::MissingFullTxForSegwitV0Input(input) => write!(
                f,
                "segwit v0 input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            CreatePsbtError::Psbt(error) => Display::fmt(&error, f),
            CreatePsbtError::OutputUpdate(output_update_error) => {
                Display::fmt(&output_update_error, f)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreatePsbtError {}

impl Selection {
    /// Returns none if there is a mismatch of units in `locktimes`.
    fn _accumulate_max_locktime(
        locktimes: impl IntoIterator<Item = absolute::LockTime>,
    ) -> Option<absolute::LockTime> {
        let mut acc = Option::<absolute::LockTime>::None;
        for locktime in locktimes {
            match &mut acc {
                Some(acc) => {
                    if !acc.is_same_unit(locktime) {
                        return None;
                    }
                    if acc.is_implied_by(locktime) {
                        *acc = locktime;
                    }
                }
                acc => *acc = Some(locktime),
            };
        }
        acc
    }

    /// Create psbt.
    pub fn create_psbt(&self, params: PsbtParams) -> Result<bitcoin::Psbt, CreatePsbtError> {
        let mut psbt = bitcoin::Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: params.version,
            lock_time: Self::_accumulate_max_locktime(
                self.inputs
                    .iter()
                    .filter_map(|input| input.absolute_timelock())
                    .chain([params.fallback_locktime]),
            )
            .ok_or(CreatePsbtError::LockTypeMismatch)?,
            input: self
                .inputs
                .iter()
                .map(|input| bitcoin::TxIn {
                    previous_output: input.prev_outpoint(),
                    sequence: input.sequence().unwrap_or(params.fallback_sequence),
                    ..Default::default()
                })
                .collect(),
            output: self.outputs.iter().map(|output| output.txout()).collect(),
        })
        .map_err(CreatePsbtError::Psbt)?;

        for (plan_input, psbt_input) in self.inputs.iter().zip(psbt.inputs.iter_mut()) {
            if let Some(finalized_psbt_input) = plan_input.psbt_input() {
                *psbt_input = finalized_psbt_input.clone();
                continue;
            }
            if let Some(plan) = plan_input.plan() {
                plan.update_psbt_input(psbt_input);

                let witness_version = plan.witness_version();
                if witness_version.is_some() {
                    psbt_input.witness_utxo = Some(plan_input.prev_txout().clone());
                }
                // We are allowed to have full tx for segwit inputs. Might as well include it.
                // If the caller does not wish to include the full tx in Segwit V0 inputs, they should not
                // include it in `crate::Input`.
                psbt_input.non_witness_utxo = plan_input.prev_tx().cloned();
                if psbt_input.non_witness_utxo.is_none() {
                    if witness_version.is_none() {
                        return Err(CreatePsbtError::MissingFullTxForLegacyInput(
                            plan_input.clone(),
                        ));
                    }
                    if params.mandate_full_tx_for_segwit_v0
                        && witness_version == Some(bitcoin::WitnessVersion::V0)
                    {
                        return Err(CreatePsbtError::MissingFullTxForSegwitV0Input(
                            plan_input.clone(),
                        ));
                    }
                }

                psbt_input.sighash_type = params.sighash_type;

                continue;
            }
            unreachable!("input candidate must either have finalized psbt input or plan");
        }
        for (output_index, output) in self.outputs.iter().enumerate() {
            if let Some(desc) = output.descriptor() {
                psbt.update_output_with_descriptor(output_index, desc)
                    .map_err(CreatePsbtError::OutputUpdate)?;
            }
        }

        Ok(psbt)
    }

    /// Into psbt finalizer.
    pub fn into_finalizer(self) -> Finalizer {
        Finalizer::new(
            self.inputs
                .iter()
                .filter_map(|input| Some((input.prev_outpoint(), input.plan().cloned()?))),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::{absolute, secp256k1::Secp256k1, transaction, Amount, Transaction, TxIn, TxOut};
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};

    #[test]
    fn test_fallback_locktime() -> anyhow::Result<()> {
        let abs_locktime = absolute::LockTime::from_consensus(100_000);
        let secp = Secp256k1::new();
        let pk = "032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3";
        let desc_str = format!("wsh(and_v(v:pk({pk}),after({abs_locktime})))");
        let desc_pk: DescriptorPublicKey = pk.parse()?;
        let (desc, _) = Descriptor::parse_descriptor(&secp, &desc_str)?;
        let plan = desc
            .at_derivation_index(0)?
            .plan(&Assets::new().add(desc_pk).after(abs_locktime))
            .unwrap();
        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.at_derivation_index(0)?.script_pubkey(),
                value: Amount::ONE_BTC,
            }],
        };
        let input = Input::from_prev_tx(plan, prev_tx, 0, None)?;

        let selection = Selection {
            inputs: vec![input],
            outputs: vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        };

        struct TestCase {
            name: &'static str,
            psbt_params: PsbtParams,
            exp_locktime: u32,
        }

        let cases = vec![
            TestCase {
                name: "no fallback locktime, use plan locktime",
                psbt_params: PsbtParams::default(),
                exp_locktime: 100_000,
            },
            TestCase {
                name: "larger fallback locktime is used",
                psbt_params: PsbtParams {
                    fallback_locktime: absolute::LockTime::from_consensus(100_100),
                    ..Default::default()
                },
                exp_locktime: 100_100,
            },
            TestCase {
                name: "smaller fallback locktime is ignored",
                psbt_params: PsbtParams {
                    fallback_locktime: absolute::LockTime::from_consensus(99_900),
                    ..Default::default()
                },
                exp_locktime: 100_000,
            },
        ];

        for test in cases {
            let psbt = selection.create_psbt(test.psbt_params)?;
            assert_eq!(
                psbt.unsigned_tx.lock_time.to_consensus_u32(),
                test.exp_locktime,
                "Test failed {}",
                test.name,
            );
        }

        Ok(())
    }
}
