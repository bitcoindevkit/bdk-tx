#![allow(unused)]

use std::str::FromStr;

use bdk_coin_select::{
    metrics::LowestFee, ChangePolicy, CoinSelector, Drain, DrainWeights, Target, TargetFee,
    TargetOutputs,
};
use bdk_wallet::{test_utils::*, KeychainKind::*, Wallet};
use bitcoin::{absolute, bip32, relative, secp256k1::Secp256k1, Amount};
use miniscript::{plan::Assets, ForEachKey};

use bdk_transaction::PlannedUtxo;

const XPRV: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
const DERIV: &str = "86h/1h/0h";
const FEERATE: f32 = 2.0;

fn main() -> anyhow::Result<()> {
    let xprv = bip32::Xpriv::from_str(XPRV)?;
    let desc = format!("tr({}/{}/0/*)", XPRV, DERIV);
    let change_desc = format!("tr({}/{}/1/*)", XPRV, DERIV);
    let (mut wallet, _) = get_funded_wallet(&desc, &change_desc);

    let addr = wallet.peek_address(External, 0);

    println!("Address: {}", addr);

    let mut builder = bdk_transaction::Builder::new();

    // Add recipients
    let recip = addr.script_pubkey();
    let amt = Amount::from_sat(10_000);
    builder.add_recipient(recip.clone(), amt);

    // Select coins:
    //
    // 1) get assets
    // 2) get planned utxos
    // 3) fund target outputs
    // 4) apply selection
    // 5) decide change
    let assets = wallet.assets();
    let plan_utxos = wallet.planned_utxos(&assets);
    let target = TargetOutputs::fund_outputs(
        builder
            .target_outputs()
            .map(|(weight, value)| (weight.to_wu() as u32, value.to_sat())),
    );
    let (selection, drain) = select_coins(&plan_utxos, target);
    if drain.is_some() {
        builder.drain_to(
            wallet.next_unused_address(Internal).script_pubkey(),
            Amount::from_sat(drain.value),
        );
    }

    // Fund the inputs
    builder.add_utxos(selection);

    let (mut psbt, finalizer) = builder.build_tx(&wallet).unwrap();

    let fee = psbt.fee().expect("failed to calculate fee");

    // Sign + finalize
    if let Err((_, e)) = psbt.sign(&xprv, &Secp256k1::new()) {
        eprintln!("error while signing: {:?}", e);
    }
    dbg!(finalizer.finalize(&mut psbt).is_finalized());

    let tx = psbt.extract_tx()?;
    let feerate = fee / tx.weight();

    dbg!(feerate.to_sat_per_kwu());

    Ok(())
}

/// Run coin selection from the available candidates and target outputs.
///
/// Note for simplicity we make some assumptions such as:
///
/// - change policy including minimum drain value
/// - target feerate
/// - Bnb metric (lowest fee) and 10 sat/vb long-term feerate
fn select_coins(utxos: &[PlannedUtxo], outputs: TargetOutputs) -> (Vec<PlannedUtxo>, Drain) {
    use bdk_coin_select::Candidate;
    use bdk_coin_select::FeeRate;
    let candidates = utxos
        .iter()
        .map(|p| Candidate {
            value: p.txout.value.to_sat(),
            weight: p.plan.satisfaction_weight() as u32,
            input_count: 1,
            is_segwit: p.plan.witness_version().is_some(),
        })
        .collect::<Vec<_>>();

    let mut selector = CoinSelector::new(&candidates);

    let min_value = 1000;
    let target = Target {
        fee: TargetFee {
            rate: FeeRate::from_sat_per_vb(FEERATE),
            ..Default::default()
        },
        outputs,
    };
    let change_policy = ChangePolicy {
        min_value,
        drain_weights: DrainWeights::TR_KEYSPEND,
    };
    let metric = LowestFee {
        target,
        long_term_feerate: FeeRate::from_sat_per_vb(10.0),
        change_policy,
    };
    if selector.run_bnb(metric, 500).is_err() {
        selector
            .select_until_target_met(target)
            .expect("failed to select coins");
    }

    let selection = selector.apply_selection(utxos).cloned().collect();

    let drain = selector.drain(target, change_policy);

    (selection, drain)
}

// ========== Extra helpers ========== //

trait WalletExt {
    fn assets(&self) -> Assets;
    fn planned_utxos(&self, spend_assets: &Assets) -> Vec<PlannedUtxo>;
}

impl WalletExt for Wallet {
    fn planned_utxos(&self, spend_assets: &Assets) -> Vec<PlannedUtxo> {
        let mut ret = vec![];

        let cur_height = self.latest_checkpoint().height();
        let abs_lt = absolute::LockTime::from_consensus(cur_height);
        let unspent = self.list_unspent().collect::<Vec<_>>();

        for utxo in unspent {
            let desc = self.public_descriptor(utxo.keychain);
            let def_desc = desc.at_derivation_index(utxo.derivation_index).unwrap();
            let conf_height = utxo
                .chain_position
                .confirmation_height_upper_bound()
                .unwrap_or(cur_height);
            let n_confs: u16 = cur_height
                .saturating_sub(conf_height)
                .try_into()
                .unwrap_or(u16::MAX);
            let rel_lt = relative::LockTime::from_height(n_confs);

            let mut assets = Assets::new();
            assets.extend(spend_assets);
            assets = assets.after(abs_lt);
            assets = assets.older(rel_lt);

            if let Ok(plan) = def_desc.plan(&assets) {
                let candidate = PlannedUtxo {
                    plan,
                    outpoint: utxo.outpoint,
                    txout: utxo.txout,
                };
                ret.push(candidate);
            }
        }

        ret
    }

    fn assets(&self) -> Assets {
        let mut pks = vec![];
        for (_, desc) in self.keychains() {
            desc.for_each_key(|k| {
                pks.push(k.clone());
                true
            });
        }
        Assets::new().add(pks)
    }
}

trait AssetsExt {
    fn extend(&mut self, other: &Self);
}

impl AssetsExt for Assets {
    fn extend(&mut self, other: &Self) {
        self.keys.extend(other.keys.clone());
        self.sha256_preimages.extend(other.sha256_preimages.clone());
        self.hash256_preimages
            .extend(other.hash256_preimages.clone());
        self.ripemd160_preimages
            .extend(other.ripemd160_preimages.clone());
        self.hash160_preimages
            .extend(other.hash160_preimages.clone());

        self.absolute_timelock = other.absolute_timelock.or(self.absolute_timelock);
        self.relative_timelock = other.relative_timelock.or(self.relative_timelock);
    }
}
