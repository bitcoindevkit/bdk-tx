use crate::Input;
use bitcoin::{
    absolute::{self, LockTime},
    transaction::Version,
    Sequence, Transaction, WitnessVersion,
};
use std::vec::Vec;

use rand_core::{OsRng, RngCore};

/// Applies BIP326 anti‐fee‐sniping
pub fn apply_anti_fee_sniping(
    tx: &mut Transaction,
    inputs: &[Input],
    current_height: absolute::Height,
    rbf_enabled: bool,
) {
    const MAX_SEQUENCE_VALUE: u32 = 65_535;
    const USE_NLOCKTIME_PROBABILITY: f64 = 0.5;
    const MIN_SEQUENCE_VALUE: u32 = 1;
    const FURTHER_BACK_PROBABILITY: f64 = 0.1;
    const MAX_RANDOM_OFFSET: u32 = 99;

    tx.version = Version::TWO;

    let taproot_inputs: Vec<_> = inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| {
            matches!(
                input.plan().and_then(|plan| plan.witness_version()),
                Some(WitnessVersion::V1)
            )
        })
        .collect();

    // Initialize all nsequence to indicate the requested RBF state
    for input in &mut tx.input {
        input.sequence = if rbf_enabled {
            Sequence(0xFFFFFFFF - 2) // 2^32 - 3
        } else {
            Sequence(0xFFFFFFFF - 1) // 2^32 - 2
        }
    }
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
        || random_probability(USE_NLOCKTIME_PROBABILITY);

    if use_locktime {
        // Use nLockTime
        let mut locktime = current_height.to_consensus_u32();

        if random_probability(FURTHER_BACK_PROBABILITY) {
            let random_offset = random_range(0, MAX_RANDOM_OFFSET);
            locktime = locktime.saturating_sub(random_offset);
        }

        tx.lock_time = LockTime::from_height(locktime).unwrap();
    } else {
        // Use Sequence
        tx.lock_time = LockTime::ZERO;

        let input_index = random_range(0, taproot_inputs.len() as u32) as usize;

        let (idx, input) = &taproot_inputs[input_index];

        let confirmation = input.confirmations(current_height);

        let mut sequence_value = confirmation;

        if random_probability(FURTHER_BACK_PROBABILITY) {
            let random_offset = random_range(0, MAX_RANDOM_OFFSET);
            sequence_value = sequence_value
                .saturating_sub(random_offset)
                .max(MIN_SEQUENCE_VALUE);
        }

        tx.input[*idx].sequence = Sequence(sequence_value);
    }
}

fn random_probability(probability: f64) -> bool {
    debug_assert!(
        (0.0..=1.0).contains(&probability),
        "Probability must be between 0.0 and 1.0"
    );

    let mut rng = OsRng;
    let rand_val = rng.next_u32() as f64;
    let max_u32 = u32::MAX as f64;
    (rand_val / max_u32) < probability
}

fn random_range(min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    let mut rng = OsRng;
    let range = max.saturating_sub(min);
    let threshold = u32::MAX.saturating_sub(u32::MAX % range);
    let min_val = min + (rng.next_u32() % (max - min));
    let mut r;

    loop {
        r = rng.next_u32();
        if r < threshold {
            break;
        }
    }
    min_val.saturating_add(r % range)
}
