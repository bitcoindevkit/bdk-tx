use crate::{CreatePsbtError, Input};
use alloc::vec::Vec;
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction::Version,
    Sequence, Transaction, WitnessVersion,
};

use rand_core::{OsRng, RngCore};

/// Applies BIP326 anti‐fee‐sniping
pub fn apply_anti_fee_sniping(
    tx: &mut Transaction,
    inputs: &[Input],
    current_height: absolute::Height,
    rbf_enabled: bool,
) -> Result<(), CreatePsbtError> {
    const MAX_SEQUENCE_VALUE: u32 = 65_535;
    const USE_NLOCKTIME_PROBABILITY: u32 = 2;
    const MIN_SEQUENCE_VALUE: u32 = 1;
    const FURTHER_BACK_PROBABILITY: u32 = 10;
    const MAX_RANDOM_OFFSET: u32 = 99;

    let mut rng = OsRng;

    if tx.version < Version::TWO {
        return Err(CreatePsbtError::UnsupportedVersion(tx.version));
    }

    let taproot_inputs: Vec<usize> = (0..tx.input.len())
        .filter(|&idx| {
            // Check if this input is taproot using the corresponding Input data
            inputs
                .get(idx)
                .and_then(|input| input.plan())
                .and_then(|plan| plan.witness_version())
                .map(|version| version == WitnessVersion::V1)
                .unwrap_or(false)
        })
        .collect();

    // Check always‐locktime conditions
    let must_use_locktime = inputs.iter().any(|input| {
        let confirmation = input.confirmations(current_height);
        confirmation == 0
            || confirmation > MAX_SEQUENCE_VALUE
            || !matches!(
                input.plan().and_then(|plan| plan.witness_version()),
                Some(WitnessVersion::V1)
            )
    });

    let use_locktime = !rbf_enabled
        || must_use_locktime
        || taproot_inputs.is_empty()
        || random_probability(&mut rng, USE_NLOCKTIME_PROBABILITY);

    if use_locktime {
        // Use nLockTime
        let mut locktime = current_height.to_consensus_u32();

        if random_probability(&mut rng, FURTHER_BACK_PROBABILITY) {
            let random_offset = random_range(&mut rng, MAX_RANDOM_OFFSET);
            locktime = locktime.saturating_sub(random_offset);
        }

        let new_locktime = LockTime::from_height(locktime)
            .map_err(|_| CreatePsbtError::InvalidHeight(locktime))?;

        tx.lock_time = new_locktime;
    } else {
        // Use Sequence
        tx.lock_time = LockTime::ZERO;
        let input_index = random_range(&mut rng, taproot_inputs.len() as u32) as usize;
        let confirmation = inputs[input_index].confirmations(current_height);

        let mut sequence_value = confirmation;
        if random_probability(&mut rng, FURTHER_BACK_PROBABILITY) {
            let random_offset = random_range(&mut rng, MAX_RANDOM_OFFSET);
            sequence_value = sequence_value
                .saturating_sub(random_offset)
                .max(MIN_SEQUENCE_VALUE);
        }

        tx.input[input_index].sequence = Sequence(sequence_value);
    }

    Ok(())
}

fn random_probability(rng: &mut OsRng, probability: u32) -> bool {
    let rand_val = rng.next_u32();
    rand_val % probability == 0
}

fn random_range(rng: &mut OsRng, max: u32) -> u32 {
    rng.next_u32() % max
}
