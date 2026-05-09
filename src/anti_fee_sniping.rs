use crate::Input;
use alloc::vec::Vec;
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction::Version,
    Sequence, Transaction,
};
#[cfg(feature = "std")]
use rand::Rng;
use rand_core::RngCore;

/// Error returned by [`apply_anti_fee_sniping`].
#[derive(Debug, Clone)]
pub enum AntiFeeSnipingError {
    /// Transaction `version` must be >= 2 for AFS to use relative locktimes.
    UnsupportedVersion(Version),
}

impl core::fmt::Display for AntiFeeSnipingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(
                f,
                "anti-fee-sniping requires tx.version >= 2 (got {version})"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AntiFeeSnipingError {}

/// Applies BIP326 anti-fee-sniping protection to a transaction.
///
/// Anti-fee-sniping makes transaction replay attacks less profitable by setting
/// either nLockTime or nSequence to indicate the transaction should only be valid
/// at or after the current block height. This discourages miners from attempting
/// to reorganize recent blocks to claim fees from transactions. It must be called
/// **before** the PSBT is signed.
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
/// - `rng`: Random number generator implementing `RngCore`
///
/// # Errors
/// [`AntiFeeSnipingError::UnsupportedVersion`] if `tx.version < 2`.
///
/// # Example
/// ```ignore
/// # use bdk_tx::{apply_anti_fee_sniping, Input};
/// # use miniscript::bitcoin::{
/// #     absolute::{Height, LockTime}, transaction::Version, Transaction,
/// # };
/// # use rand_core::OsRng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let inputs: Vec<Input> = vec![];
///     let mut tx = Transaction {
///         version: Version::TWO,
///         lock_time: LockTime::from_height(800_000)?,
///         input: vec![/* corresponding TxIns */],
///         output: vec![/* your outputs */],
///     };
///     let tip_height = Height::from_consensus(800_000)?;
///     apply_anti_fee_sniping(&mut tx, &inputs, tip_height, &mut OsRng)?;
///     # Ok(())
/// }
/// ```
///
/// # See Also
/// [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki)
pub fn apply_anti_fee_sniping(
    tx: &mut Transaction,
    inputs: &[Input],
    tip_height: absolute::Height,
    rng: &mut impl RngCore,
) -> Result<(), AntiFeeSnipingError> {
    const MAX_RELATIVE_HEIGHT: u32 = 65_535;
    const FIFTY_PERCENT_PROBABILITY_RANGE: u32 = 2;
    const MIN_SEQUENCE_VALUE: u32 = 1;
    const TEN_PERCENT_PROBABILITY_RANGE: u32 = 10;
    const MAX_RANDOM_OFFSET: u32 = 100;

    if tx.version < Version::TWO {
        return Err(AntiFeeSnipingError::UnsupportedVersion(tx.version));
    }

    let rbf_enabled = tx.is_explicitly_rbf();

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

    // Conditions that force nLockTime (vs nSequence).
    let must_use_locktime = inputs.iter().any(|input| {
        let confirmation = input.confirmations(tip_height);
        confirmation == 0
            || confirmation > MAX_RELATIVE_HEIGHT
            || !input.prev_txout().script_pubkey.is_p2tr()
    });

    let use_locktime = !rbf_enabled
        || must_use_locktime
        || taproot_inputs.is_empty()
        || random_probability(rng, FIFTY_PERCENT_PROBABILITY_RANGE);

    if use_locktime {
        // Use nLockTime
        let mut locktime = tip_height.to_consensus_u32();

        if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
            let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
            locktime = locktime.saturating_sub(random_offset);
        }

        let new_locktime = LockTime::from_height(locktime).expect("must be valid Height");

        tx.lock_time = new_locktime;
    } else {
        // Use Sequence
        tx.lock_time = LockTime::ZERO;
        let random_index = random_range(rng, taproot_inputs.len() as u32);
        let (input_index, input) = taproot_inputs[random_index as usize];
        let confirmation = input.confirmations(tip_height);

        let mut sequence_value = confirmation;
        if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
            let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
            sequence_value = sequence_value
                .saturating_sub(random_offset)
                .max(MIN_SEQUENCE_VALUE);
        }

        tx.input[input_index].sequence = Sequence(sequence_value);
    }

    Ok(())
}

/// Returns true with probability 1/n.
#[cfg(feature = "std")]
fn random_probability(rng: &mut impl RngCore, n: u32) -> bool {
    rng.gen_bool(1.0 / n as f64)
}

/// Returns true with probability 1/n.
///
/// This `no-std` implementation avoids depending on the full `rand` crate,
/// keeping the dependency tree minimal while supporting `no-std` environments
/// through `rand_core` alone.
#[cfg(not(feature = "std"))]
fn random_probability(rng: &mut impl RngCore, n: u32) -> bool {
    random_range(rng, n) == 0
}

/// Returns a random value in the range [0, n).
#[cfg(feature = "std")]
fn random_range(rng: &mut impl RngCore, n: u32) -> u32 {
    rng.gen_range(0..n)
}

/// Returns a random value in the range [0, n) using unbiased sampling.
///
/// This `no-std` implementation uses rejection sampling to ensure uniform
/// distribution and avoid modulo bias, without depending on the full `rand` crate.
/// This keeps the dependency tree minimal while supporting `no-std` environments
/// through `rand_core` alone.
#[cfg(not(feature = "std"))]
fn random_range(rng: &mut impl RngCore, n: u32) -> u32 {
    let threshold = n.wrapping_neg() % n;

    loop {
        let value = rng.next_u32();
        if value >= threshold {
            return value % n;
        }
    }
}
