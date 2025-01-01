use bitcoin::{
    absolute, transaction, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxOut, Weight,
};
use miniscript::plan::Plan;

use crate::{DataProvider, Finalizer, Updater};

/// Transaction builder
#[derive(Debug, Clone, Default)]
pub struct Builder {
    recipients: Vec<(ScriptBuf, Amount)>,
    utxos: Vec<PlannedUtxo>,
    drain_to: Option<(ScriptBuf, Amount)>,
    /* TODO: to have feature-parity with `bdk_wallet` */
    // drain_wallet: bool,
    // fee_policy: Option<FeePolicy>,
    // unspendable: HashSet<OutPoint>,
    // manually_selected_only: bool,
    // sighash: Option<psbt::PsbtSighashType>,
    // ordering: TxOrdering,
    // locktime: Option<absolute::LockTime>,
    // sequence: Option<Sequence>,
    // version: Option<Version>,
    // change_policy: ChangeSpendPolicy,
    // only_witness_utxo: bool,
    // add_global_xpubs: bool,
    // include_output_redeem_witness_script: bool,
    // bumping_fee: Option<PreviousFee>,
    // allow_dust: bool,
}

/// Planned utxo
#[derive(Debug, Clone)]
pub struct PlannedUtxo {
    pub plan: Plan,
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

impl Builder {
    /// New
    pub fn new() -> Self {
        Self::default()
    }

    /// Add recipient
    pub fn add_recipient(&mut self, script: ScriptBuf, amount: Amount) -> &mut Self {
        self.recipients.push((script, amount));
        self
    }

    /// Get the target amounts based on the weight + value of all recipients
    ///
    /// This is used for passing target values to a coin selection implementation.
    pub fn target_outputs(&self) -> impl Iterator<Item = (Weight, Amount)> + '_ {
        self.recipients
            .iter()
            .cloned()
            .map(|(script_pubkey, value)| {
                let txout = TxOut {
                    value,
                    script_pubkey,
                };
                (txout.weight(), value)
            })
    }

    /// Set the drain script
    pub fn drain_to(&mut self, script: ScriptBuf, amount: Amount) -> &mut Self {
        self.drain_to = Some((script, amount));
        self
    }

    /// Add utxos which will be used to fund the inputs
    pub fn add_utxos<I>(&mut self, utxos: I) -> &mut Self
    where
        I: IntoIterator,
        I::Item: Into<PlannedUtxo>,
    {
        self.utxos.extend(utxos.into_iter().map(Into::into));
        self
    }

    /// Build a [`Psbt`] with the given data provider
    pub fn build_tx<D>(self, provider: &D) -> Result<(Psbt, Finalizer), String>
    where
        D: DataProvider,
    {
        // set outputs
        let mut output = self
            .recipients
            .into_iter()
            .map(|(script_pubkey, value)| TxOut {
                value,
                script_pubkey,
            })
            .collect::<Vec<_>>();

        if let Some((spk, value)) = self.drain_to {
            // Note: It would be nice if the drain value could grow/shrink to
            // meet the target feerate. For now we rely on `bdk_coin_select` to
            // determine the drain value
            output.push(TxOut {
                value,
                script_pubkey: spk,
            });
        }

        // set inputs
        let input = self
            .utxos
            .iter()
            .map(|PlannedUtxo { plan, outpoint, .. }| bitcoin::TxIn {
                previous_output: *outpoint,
                sequence: plan
                    .relative_timelock
                    .map(|lt| lt.to_sequence())
                    .unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
                ..Default::default()
            })
            .collect();

        let unsigned_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        // check, validate
        let total_inputs: Amount = self.utxos.iter().map(|p| p.txout.value).sum();
        let total_outputs: Amount = unsigned_tx.output.iter().map(|txo| txo.value).sum();
        if total_inputs > total_outputs * 2 {
            let excess = total_inputs - total_outputs;
            let total_sat_wu: Weight = self
                .utxos
                .iter()
                .map(|p| Weight::from_wu_usize(p.plan.satisfaction_weight()))
                .sum();
            let est_wu = unsigned_tx.weight() + total_sat_wu;
            let computed = excess / est_wu;
            return Err(format!(
                "absurd feerate: {} sat/vb",
                computed.to_sat_per_vb_ceil()
            ));
        }

        // update psbt
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("failed to create Psbt");
        let mut updater = Updater::new();
        for plan_utxo in self.utxos {
            updater.map.insert(plan_utxo.outpoint, plan_utxo);
        }
        updater.update_psbt(&mut psbt, provider);

        Ok((psbt, updater.into()))
    }
}

#[allow(unused)]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_build_tx() {}
}
