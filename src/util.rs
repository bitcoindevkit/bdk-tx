use rand_core::RngCore;

/// The Knuth shuffling algorithm based on the original [Fisher-Yates method](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle)
#[allow(unused)]
pub(crate) fn shuffle_slice<T>(list: &mut [T], rng: &mut impl RngCore) {
    if list.is_empty() {
        return;
    }
    let mut current_index = list.len() - 1;
    while current_index > 0 {
        let random_index = rng.next_u32() as usize % (current_index + 1);
        list.swap(current_index, random_index);
        current_index -= 1;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    #[test]
    fn test_shuffle_slice_empty_vec() {
        let mut test: Vec<u8> = vec![];
        shuffle_slice(&mut test, &mut thread_rng());
    }

    #[test]
    fn test_shuffle_slice_single_vec() {
        let mut test: Vec<u8> = vec![0];
        shuffle_slice(&mut test, &mut thread_rng());
    }

    #[test]
    fn test_shuffle_slice_duple_vec() {
        let seed = [0; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut test: Vec<u8> = vec![0, 1];
        shuffle_slice(&mut test, &mut rng);
        assert_eq!(test, &[0, 1]);
        let seed = [6; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut test: Vec<u8> = vec![0, 1];
        shuffle_slice(&mut test, &mut rng);
        assert_eq!(test, &[1, 0]);
    }

    #[test]
    fn test_shuffle_slice_multi_vec() {
        let seed = [0; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut test: Vec<u8> = vec![0, 1, 2, 4, 5];
        shuffle_slice(&mut test, &mut rng);
        assert_eq!(test, &[2, 1, 0, 4, 5]);
        let seed = [25; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut test: Vec<u8> = vec![0, 1, 2, 4, 5];
        shuffle_slice(&mut test, &mut rng);
        assert_eq!(test, &[0, 4, 1, 2, 5]);
    }
}
