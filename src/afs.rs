use crate::{
    no_std_rand::{random_probability, random_range},
    TxTemplate,
};
use alloc::vec::Vec;
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction::Version,
    Sequence,
};
use rand_core::RngCore;

/// Error returned by `apply_anti_fee_sniping`.
#[derive(Debug, Clone, PartialEq)]
pub enum AntiFeeSnipingError {
    /// Transaction `version` must be >= 2 for AFS to use relative locktimes.
    UnsupportedVersion(Version),
    /// AFS only supports height-based locktimes. The transaction's locktime is
    /// time-based (MTP), which can originate from either `TxTemplateParams::min_locktime`
    /// or an input's time-based CLTV requirement.
    UnsupportedLockTime(absolute::LockTime),
}

impl core::fmt::Display for AntiFeeSnipingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(
                f,
                "anti-fee-sniping requires tx.version >= 2 (got {version})"
            ),
            Self::UnsupportedLockTime(locktime) => write!(
                f,
                "anti-fee-sniping requires a height-based tx locktime (got time-based {locktime}); \
                 check `min_locktime` and any input CLTV requirements"
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
/// - `tip_height`: The current blockchain height (used as the base for time locks)
/// - `rng`: Random number generator implementing `RngCore`
///
/// # Behavior with existing locktime constraints
///
/// If `tx.lock_time` is already a block height greater than the AFS target
/// (e.g., because an input's CLTV pins the transaction to a future height),
/// this function leaves `tx.lock_time` untouched and returns `Ok(())`. The
/// existing CLTV already prevents inclusion before `tip_height + 1`, so AFS
/// is implicitly satisfied.
///
/// # Errors
/// - [`AntiFeeSnipingError::UnsupportedVersion`] if `tx.version < 2`.
/// - [`AntiFeeSnipingError::UnsupportedLockTime`] if `tx.lock_time` is time-based
///   (either from `TxTemplateParams::min_locktime` or an input's time-based CLTV).
///
/// # See Also
/// [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki)
pub(crate) fn apply_anti_fee_sniping(
    mut template: TxTemplate,
    tip_height: absolute::Height,
    rng: &mut impl RngCore,
) -> Result<TxTemplate, AntiFeeSnipingError> {
    const MAX_RELATIVE_HEIGHT: u32 = 65_535;
    const FIFTY_PERCENT_PROBABILITY_RANGE: u32 = 2;
    const MIN_SEQUENCE_VALUE: u32 = 1;
    const TEN_PERCENT_PROBABILITY_RANGE: u32 = 10;
    const MAX_RANDOM_OFFSET: u32 = 100;

    if template.version() < Version::TWO {
        return Err(AntiFeeSnipingError::UnsupportedVersion(template.version()));
    }

    if !template.lock_time().is_block_height() {
        return Err(AntiFeeSnipingError::UnsupportedLockTime(
            template.lock_time(),
        ));
    }

    // A tx signals RBF if at least one input has `nSequence < 0xfffffffe`.
    let fallback = template.fallback_sequence();
    let rbf_enabled = template
        .inputs()
        .iter()
        .any(|input| input.sequence().unwrap_or(fallback).is_rbf());

    // Indices of taproot inputs without a relative timelock — candidates for the nSequence path.
    let taproot_inputs: Vec<usize> = template
        .inputs()
        .iter()
        .enumerate()
        .filter_map(|(i, input)| {
            (input.prev_txout().script_pubkey.is_p2tr() && input.relative_timelock().is_none())
                .then_some(i)
        })
        .collect();

    // Conditions that force nLockTime (vs nSequence).
    let must_use_locktime = taproot_inputs.is_empty()
        || template.inputs().iter().any(|input| {
            let confirmation = input.confirmations(tip_height);
            confirmation == 0 || confirmation > MAX_RELATIVE_HEIGHT
        });
    let use_locktime = !rbf_enabled
        || must_use_locktime
        || random_probability(rng, FIFTY_PERCENT_PROBABILITY_RANGE);

    if use_locktime {
        let mut afs_height = tip_height.to_consensus_u32();
        if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
            let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
            afs_height = afs_height.saturating_sub(random_offset);
        }
        let afs_locktime = LockTime::from_height(afs_height).expect("must be valid Height");

        // Only apply if it's a bump (i.e. doesn't regress an input's CLTV requirement).
        if template.lock_time().is_implied_by(afs_locktime) {
            template = template
                .set_locktime(afs_locktime)
                .expect("AFS picks a value ≥ current lock_time (same height-based unit)");
        }
    } else {
        let random_index = random_range(rng, taproot_inputs.len() as u32) as usize;
        let input_index = taproot_inputs[random_index];
        let outpoint = template.inputs()[input_index].prev_outpoint();
        let confirmation = template.inputs()[input_index].confirmations(tip_height);

        let mut sequence_value = confirmation;
        if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
            let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
            sequence_value = sequence_value
                .saturating_sub(random_offset)
                .max(MIN_SEQUENCE_VALUE);
        }

        template
            .input_mut(outpoint)
            .expect("taproot input index resolved above")
            .set_sequence(Sequence(sequence_value))
            .expect("AFS only picks inputs without timelock constraints");
    }

    Ok(template)
}
