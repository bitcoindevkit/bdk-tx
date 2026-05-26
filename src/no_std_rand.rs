use rand_core::RngCore;

/// Returns true with probability 1/n.
pub(crate) fn random_probability(rng: &mut impl RngCore, n: u32) -> bool {
    random_range(rng, n) == 0
}

/// Returns a random value in the range [0, n) using unbiased rejection sampling.
pub(crate) fn random_range(rng: &mut impl RngCore, n: u32) -> u32 {
    let threshold = n.wrapping_neg() % n;

    loop {
        let value = rng.next_u32();
        if value >= threshold {
            return value % n;
        }
    }
}

/// Fisher-Yates in-place shuffle using unbiased rejection sampling.
pub(crate) fn fisher_yates_shuffle<T>(slice: &mut [T], rng: &mut impl RngCore) {
    for i in (1..slice.len()).rev() {
        // Unbiased index in [0, i+1) via rejection sampling.
        let j = random_range(rng, (i + 1) as u32) as usize;
        slice.swap(i, j);
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use rand_core::OsRng;

    #[test]
    fn test_fisher_yates_shuffle_preserves_multiset() {
        let original: Vec<u32> = (0..32).collect();
        let mut shuffled = original.clone();
        fisher_yates_shuffle(&mut shuffled, &mut OsRng);
        shuffled.sort();
        assert_eq!(shuffled, original);
    }
}
