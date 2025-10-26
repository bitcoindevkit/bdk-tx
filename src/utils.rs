use crate::{CreatePsbtError, Input};
use alloc::vec::Vec;
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    secp256k1::rand::Rng,
    transaction::Version,
    Sequence, Transaction,
};

use rand_core::{OsRng, RngCore};

/// Applies BIP326 anti-fee-sniping protection to a transaction.
///
/// Anti-fee-sniping makes transaction replay attacks less profitable by setting
/// either nLockTime or nSequence to indicate the transaction should only be valid
/// at or after the current block height. This discourages miners from attempting
/// to reorganize recent blocks to claim fees from transactions.
///
/// # Strategy
/// The function randomly chooses between two approaches:
/// - **nLockTime**: Sets the transaction's lock time to approximately the current height
/// - **nSequence**: Sets one Taproot input's sequence to approximately its confirmation depth
///
/// Random offsets (0-99 blocks) are applied with 10% probability to avoid creating
/// a unique fingerprint that could identify transactions from this wallet.
///
/// # Parameters
/// - `tx`: The transaction to modify
/// - `inputs`: The inputs associated with the transaction
/// - `current_height`: The current blockchain height (used as the base for time locks)
/// - `rbf_enabled`: Whether Replace-By-Fee is enabled (affects strategy selection)
///
/// # Errors
/// Returns an error if:
/// - Transaction version is less than 2 [`CreatePsbtError::UnsupportedVersion`]
///
/// # Example
/// ```
/// # use bdk_tx::{apply_anti_fee_sniping, Input};
/// # use miniscript::bitcoin::{
/// #     absolute::{Height, LockTime}, transaction::Version, Transaction, TxIn, TxOut, ScriptBuf, Amount
/// # };
/// 
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let inputs: Vec<Input> = vec![];
///     let mut tx = Transaction {
///         version: Version::TWO,
///         lock_time: LockTime::from_height(800_000)?,
///         input: vec![/* corresponding TxIns */],
///         output: vec![/* your outputs */],
///     };
///     let current_height = Height::from_consensus(800_000)?;
///     apply_anti_fee_sniping(&mut tx, &inputs, current_height, true)?;
///     // tx now has anti-fee-sniping protection applied
///     Ok(())
/// }
/// ```
///
/// # See Also
/// [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki)
pub fn apply_anti_fee_sniping(
    tx: &mut Transaction,
    inputs: &[Input],
    current_height: absolute::Height,
    rbf_enabled: bool,
) -> Result<(), CreatePsbtError> {
    const MAX_RELATIVE_HEIGHT: u32 = 65_535;
    const USE_NLOCKTIME_PROBABILITY: u32 = 2;
    const MIN_SEQUENCE_VALUE: u32 = 1;
    const FURTHER_BACK_PROBABILITY: u32 = 10;
    const MAX_RANDOM_OFFSET: u32 = 100;

    let mut rng = OsRng;

    if tx.version < Version::TWO {
        return Err(CreatePsbtError::UnsupportedVersion(tx.version));
    }

    // vector of input_index and associated Input ref.
    let taproot_inputs: Vec<(usize, &Input)> = tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(vin, txin)| {
            let input = inputs
                .iter()
                .find(|input| input.prev_outpoint() == txin.previous_output)?;
            if input.prev_txout().script_pubkey.is_p2tr() {
                Some((vin, input))
            } else {
                None
            }
        })
        .collect();

    // Check always‐locktime conditions
    let must_use_locktime = inputs.iter().any(|input| {
        let confirmation = input.confirmations(current_height);
        confirmation == 0
            || confirmation > MAX_RELATIVE_HEIGHT
            || !input.prev_txout().script_pubkey.is_p2tr()
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

        let new_locktime = LockTime::from_height(locktime).expect("must be valid Height");

        tx.lock_time = new_locktime;
    } else {
        // Use Sequence
        tx.lock_time = LockTime::ZERO;
        let random_index = random_range(&mut rng, taproot_inputs.len() as u32);
        let (input_index, input) = taproot_inputs[random_index as usize];
        let confirmation = input.confirmations(current_height);

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

/// Returns true with probability 1/n.
fn random_probability(rng: &mut OsRng, probability: u32) -> bool {
    rng.gen_range(0..probability) == 0
}

// Return a random value in the range [0, end].
fn random_range(rng: &mut OsRng, end: u32) -> u32 {
    let max = u32::MAX;
    let max_multiple = max - (max % end);

    loop {
        let n = rng.next_u32();
        if n < max_multiple {
            return n % end;
        }
    }
}
