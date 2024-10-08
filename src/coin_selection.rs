// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Legacy coin selection module ported from `bdk_wallet`
//!
//! This module provides the trait [`CoinSelectionAlgorithm`] that can be implemented to
//! define custom coin selection algorithms.
//!
//! [`DefaultCoinSelectionAlgorithm`] aliases the coin selection algorithm that will
//! be used if it is not explicitly set.

use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt::{self, Formatter};

use bdk_chain::bitcoin::{self, OutPoint};
use bitcoin::{consensus::encode::serialize, Amount, FeeRate, Script, TxIn, Weight};
use rand_core::RngCore;

use crate::util;
use crate::CandidateUtxo;

/// Default coin selection algorithm used by [`TxBuilder`](crate::TxBuilder) if not
/// overridden
pub type DefaultCoinSelectionAlgorithm = BranchAndBoundCoinSelection<SingleRandomDraw>;

/// Wallet's UTXO set is not enough to cover recipient's requested plus fee.
///
/// This is thrown by [`CoinSelectionAlgorithm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsufficientFunds {
    /// Sats needed for some transaction
    pub needed: u64,
    /// Sats available for spending
    pub available: u64,
}

impl fmt::Display for InsufficientFunds {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Insufficient funds: {} sat available of {} sat needed",
            self.available, self.needed
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsufficientFunds {}

#[derive(Debug)]
/// Remaining amount after performing coin selection
pub enum Excess {
    /// It's not possible to create spendable output from excess using the current drain output
    NoChange {
        /// Threshold to consider amount as dust for this particular change script_pubkey
        dust_threshold: u64,
        /// Exceeding amount of current selection over outgoing value and fee costs
        remaining_amount: u64,
        /// The calculated fee for the drain TxOut with the selected script_pubkey
        change_fee: u64,
    },
    /// It's possible to create spendable output from excess using the current drain output
    Change {
        /// Effective amount available to create change after deducting the change output fee
        amount: u64,
        /// The deducted change output fee
        fee: u64,
    },
}

/// Result of a successful coin selection
#[derive(Debug)]
pub struct Selection {
    /// List of outputs selected for use as inputs
    pub selected: Vec<CandidateUtxo>,
    /// Total fee amount for the selected utxos in satoshis
    pub fee_amount: u64,
    /// Remaining amount after deducing fees and outgoing outputs
    pub excess: Excess,
}

impl Selection {
    /// The total value of the inputs selected.
    pub fn selected_amount(&self) -> u64 {
        self.selected
            .iter()
            .map(|u| u.txout().expect("candidate must have txout").value.to_sat())
            .sum()
    }

    /// The total value of the inputs selected.
    pub fn selected_coins(&self) -> Vec<OutPoint> {
        self.selected.iter().map(|u| u.outpoint).collect()
    }
}

/// Trait to check if a value is below the dust limit.
/// We are performing dust value calculation for a given script public key using rust-bitcoin to
/// keep it compatible with network dust rate
// we implement this trait to make sure we don't mess up the comparison with off-by-one like a <
// instead of a <= etc.
pub trait IsDust {
    /// Check whether or not a value is below dust limit
    fn is_dust(&self, script: &Script) -> bool;
}

impl IsDust for Amount {
    fn is_dust(&self, script: &Script) -> bool {
        *self < script.minimal_non_dust()
    }
}

impl IsDust for u64 {
    fn is_dust(&self, script: &Script) -> bool {
        Amount::from_sat(*self).is_dust(script)
    }
}

/// Trait for generalized coin selection algorithms
///
/// This trait can be implemented to enable using a customized coin selection algorithm
/// when creating transactions.
pub trait CoinSelectionAlgorithm: core::fmt::Debug + Default + Clone {
    /// Attempt to find a selection of candidates sufficient to meet the target amount at the given feerate.
    /// TODO: describe parameters
    fn coin_select<R: RngCore>(
        &self,
        required_utxos: Vec<CandidateUtxo>,
        optional_utxos: Vec<CandidateUtxo>,
        fee_rate: FeeRate,
        target_amount: u64,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<Selection, InsufficientFunds>;
}

/// Simple and dumb coin selection
///
/// This coin selection algorithm sorts the available UTXOs by value and then picks them starting
/// from the largest ones until the required amount is reached.
#[derive(Debug, Default, Clone, Copy)]
pub struct LargestFirstCoinSelection;

impl CoinSelectionAlgorithm for LargestFirstCoinSelection {
    fn coin_select<R: RngCore>(
        &self,
        required_utxos: Vec<CandidateUtxo>,
        mut optional_utxos: Vec<CandidateUtxo>,
        fee_rate: FeeRate,
        target_amount: u64,
        drain_script: &Script,
        _: &mut R,
    ) -> Result<Selection, InsufficientFunds> {
        // We put the "required UTXOs" first and make sure the optional UTXOs are sorted,
        // initially smallest to largest, before being reversed with `.rev()`.
        let utxos = {
            optional_utxos
                .sort_unstable_by_key(|utxo| utxo.txout().expect("must have txout").value);
            required_utxos
                .into_iter()
                .map(|utxo| (true, utxo))
                .chain(optional_utxos.into_iter().rev().map(|utxo| (false, utxo)))
        };

        select_sorted_utxos(utxos, fee_rate, target_amount, drain_script)
    }
}

/// OldestFirstCoinSelection always picks the utxo with the smallest blockheight to add to the selected coins next
///
/// This coin selection algorithm sorts the available UTXOs by blockheight and then picks them starting
/// from the oldest ones until the required amount is reached.
#[derive(Debug, Default, Clone, Copy)]
pub struct OldestFirstCoinSelection;

impl CoinSelectionAlgorithm for OldestFirstCoinSelection {
    fn coin_select<R: RngCore>(
        &self,
        required_utxos: Vec<CandidateUtxo>,
        mut optional_utxos: Vec<CandidateUtxo>,
        fee_rate: FeeRate,
        target_amount: u64,
        drain_script: &Script,
        _: &mut R,
    ) -> Result<Selection, InsufficientFunds> {
        // We put the "required UTXOs" first and make sure the optional UTXOs are sorted from
        // oldest to newest according to blocktime
        // Foreign utxos will have lowest priority to be selected
        let utxos = {
            optional_utxos.sort_unstable_by_key(|utxo| utxo.confirmation_time);

            required_utxos
                .into_iter()
                .map(|utxo| (true, utxo))
                .chain(optional_utxos.into_iter().map(|utxo| (false, utxo)))
        };

        select_sorted_utxos(utxos, fee_rate, target_amount, drain_script)
    }
}

/// Decide if change can be created
///
/// - `remaining_amount`: the amount in which the selected coins exceed the target amount
/// - `fee_rate`: required fee rate for the current selection
/// - `drain_script`: script to consider change creation
pub fn decide_change(remaining_amount: u64, fee_rate: FeeRate, drain_script: &Script) -> Excess {
    // drain_output_len = size(len(script_pubkey)) + len(script_pubkey) + size(output_value)
    let drain_output_len = serialize(drain_script).len() + 8usize;
    let change_fee =
        (fee_rate * Weight::from_vb(drain_output_len as u64).expect("overflow occurred")).to_sat();
    let drain_val = remaining_amount.saturating_sub(change_fee);

    if drain_val.is_dust(drain_script) {
        let dust_threshold = drain_script.minimal_non_dust().to_sat();
        Excess::NoChange {
            dust_threshold,
            change_fee,
            remaining_amount,
        }
    } else {
        Excess::Change {
            amount: drain_val,
            fee: change_fee,
        }
    }
}

fn select_sorted_utxos(
    utxos: impl Iterator<Item = (bool, CandidateUtxo)>,
    fee_rate: FeeRate,
    target_amount: u64,
    drain_script: &Script,
) -> Result<Selection, InsufficientFunds> {
    let mut selected_amount = 0;
    let mut fee_amount = 0;
    let selected = utxos
        .scan(
            (&mut selected_amount, &mut fee_amount),
            |(selected_amount, fee_amount), (must_use, utxo)| {
                if must_use || **selected_amount < target_amount + **fee_amount {
                    **fee_amount += (fee_rate
                        * (TxIn::default()
                            .segwit_weight()
                            .checked_add(utxo.satisfaction_weight)
                            .expect("`Weight` addition should not cause an integer overflow")))
                    .to_sat();
                    **selected_amount += utxo.txout().expect("must have txout").value.to_sat();
                    Some(utxo)
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    let amount_needed_with_fees = target_amount + fee_amount;
    if selected_amount < amount_needed_with_fees {
        return Err(InsufficientFunds {
            needed: amount_needed_with_fees,
            available: selected_amount,
        });
    }

    let remaining_amount = selected_amount - amount_needed_with_fees;

    let excess = decide_change(remaining_amount, fee_rate, drain_script);

    Ok(Selection {
        selected,
        fee_amount,
        excess,
    })
}

#[derive(Debug, Clone)]
/// Adds fee information to a UTXO.
struct EffectiveUtxo {
    utxo: CandidateUtxo,
    // Amount of fees for spending a certain utxo, calculated using a certain FeeRate
    fee: u64,
    // The effective value of the UTXO, i.e., the utxo value minus the fee for spending it
    effective_value: i64,
}

impl EffectiveUtxo {
    /// Create new effective utxo from a candidate and feerate
    fn new(utxo: CandidateUtxo, fee_rate: FeeRate) -> Self {
        let fee = (fee_rate
            * (TxIn::default()
                .segwit_weight()
                .checked_add(utxo.satisfaction_weight)
                .expect("`Weight` addition should not cause an integer overflow")))
        .to_sat();
        let effective_value =
            utxo.txout().expect("must have txout").value.to_sat() as i64 - fee as i64;
        EffectiveUtxo {
            utxo,
            fee,
            effective_value,
        }
    }

    /// Get the TxOut of this UTXO
    fn txout(&self) -> bitcoin::TxOut {
        self.utxo.txout().expect("candidate must have txout")
    }
}

/// Branch and bound coin selection
///
/// Code adapted from Bitcoin Core's implementation and from Mark Erhardt Master's Thesis: <http://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf>
#[derive(Debug, Clone)]
pub struct BranchAndBoundCoinSelection<Cs = SingleRandomDraw> {
    size_of_change: u64,
    fallback_algorithm: Cs,
}

/// Error returned by branch and bound coin selection.
#[derive(Debug)]
enum BnbError {
    /// Branch and bound coin selection tries to avoid needing a change by finding the right inputs for
    /// the desired outputs plus fee, if there is not such combination this error is thrown
    NoExactMatch,
    /// Branch and bound coin selection possible attempts with sufficiently big UTXO set could grow
    /// exponentially, thus a limit is set, and when hit, this error is thrown
    TotalTriesExceeded,
}

impl<Cs: Default> Default for BranchAndBoundCoinSelection<Cs> {
    fn default() -> Self {
        Self {
            // P2WPKH cost of change -> value (8 bytes) + script len (1 bytes) + script (22 bytes)
            size_of_change: 8 + 1 + 22,
            fallback_algorithm: Cs::default(),
        }
    }
}

impl<Cs> BranchAndBoundCoinSelection<Cs> {
    /// Create new instance with a target `size_of_change` and `fallback_algorithm`.
    pub fn new(size_of_change: u64, fallback_algorithm: Cs) -> Self {
        Self {
            size_of_change,
            fallback_algorithm,
        }
    }
}

const BNB_TOTAL_TRIES: usize = 100_000;

impl<Cs: CoinSelectionAlgorithm> CoinSelectionAlgorithm for BranchAndBoundCoinSelection<Cs> {
    fn coin_select<R: RngCore>(
        &self,
        required_utxos: Vec<CandidateUtxo>,
        optional_utxos: Vec<CandidateUtxo>,
        fee_rate: FeeRate,
        target_amount: u64,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<Selection, InsufficientFunds> {
        // Mapping every (UTXO, usize) to an output group
        let required_eff: Vec<EffectiveUtxo> = required_utxos
            .iter()
            .map(|u| EffectiveUtxo::new(u.clone(), fee_rate))
            .collect();

        // Mapping every (UTXO, usize) to an output group, filtering UTXOs with a negative
        // effective value
        let optional_eff: Vec<EffectiveUtxo> = optional_utxos
            .iter()
            .map(|u| EffectiveUtxo::new(u.clone(), fee_rate))
            .filter(|u| u.effective_value.is_positive())
            .collect();

        let curr_value = required_eff
            .iter()
            .fold(0, |acc, x| acc + x.effective_value);

        let curr_available_value = optional_eff
            .iter()
            .fold(0, |acc, x| acc + x.effective_value);

        let cost_of_change =
            (Weight::from_vb(self.size_of_change).expect("overflow occurred") * fee_rate).to_sat();

        // `curr_value` and `curr_available_value` are both the sum of *effective_values* of
        // the UTXOs. For the optional UTXOs (curr_available_value) we filter out UTXOs with
        // negative effective value, so it will always be positive.
        //
        // Since we are required to spend the required UTXOs (curr_value) we have to consider
        // all their effective values, even when negative, which means that curr_value could
        // be negative as well.
        //
        // If the sum of curr_value and curr_available_value is negative or lower than our target,
        // we can immediately exit with an error, as it's guaranteed we will never find a solution
        // if we actually run the BnB.
        let total_value: Result<u64, _> = (curr_available_value + curr_value).try_into();
        match total_value {
            Ok(v) if v >= target_amount => {}
            _ => {
                // Assume we spend all the UTXOs we can (all the required + all the optional with
                // positive effective value), sum their value and their fee cost.
                let (utxo_fees, utxo_value) = required_eff.iter().chain(optional_eff.iter()).fold(
                    (0, 0),
                    |(mut fees, mut value), utxo| {
                        fees += utxo.fee;
                        value += utxo.txout().value.to_sat();

                        (fees, value)
                    },
                );

                // Add to the target the fee cost of the UTXOs
                return Err(InsufficientFunds {
                    needed: target_amount + utxo_fees,
                    available: utxo_value,
                });
            }
        }

        let signed_target_amount = target_amount
            .try_into()
            .expect("Bitcoin amount to fit into i64");

        if curr_value > signed_target_amount {
            // remaining_amount can't be negative as that would mean the
            // selection wasn't successful
            // target_amount = amount_needed + (fee_amount - vin_fees)
            let remaining_amount = (curr_value - signed_target_amount) as u64;

            let excess = decide_change(remaining_amount, fee_rate, drain_script);

            return Ok(calculate_cs_result(vec![], required_eff, excess));
        }

        match self.bnb(
            required_eff,
            optional_eff,
            curr_value,
            curr_available_value,
            signed_target_amount,
            cost_of_change,
            drain_script,
            fee_rate,
        ) {
            Ok(r) => Ok(r),
            Err(_) => self.fallback_algorithm.coin_select(
                required_utxos,
                optional_utxos,
                fee_rate,
                target_amount,
                drain_script,
                rand,
            ),
        }
    }
}

impl<Cs> BranchAndBoundCoinSelection<Cs> {
    // TODO: make this more Rust-onic :)
    // (And perhaps refactor with less arguments?)
    #[allow(clippy::too_many_arguments)]
    fn bnb(
        &self,
        required_utxos: Vec<EffectiveUtxo>,
        mut optional_utxos: Vec<EffectiveUtxo>,
        mut curr_value: i64,
        mut curr_available_value: i64,
        target_amount: i64,
        cost_of_change: u64,
        drain_script: &Script,
        fee_rate: FeeRate,
    ) -> Result<Selection, BnbError> {
        // current_selection[i] will contain true if we are using optional_utxos[i],
        // false otherwise. Note that current_selection.len() could be less than
        // optional_utxos.len(), it just means that we still haven't decided if we should keep
        // certain optional_utxos or not.
        let mut current_selection: Vec<bool> = Vec::with_capacity(optional_utxos.len());

        // Sort the utxo_pool
        optional_utxos.sort_by_key(|a| a.effective_value);
        optional_utxos.reverse();

        // Contains the best selection we found
        let mut best_selection = Vec::new();
        let mut best_selection_value = None;

        // Depth First search loop for choosing the UTXOs
        for _ in 0..BNB_TOTAL_TRIES {
            // Conditions for starting a backtrack
            let mut backtrack = false;
            // Cannot possibly reach target with the amount remaining in the curr_available_value,
            // or the selected value is out of range.
            // Go back and try other branch
            if curr_value + curr_available_value < target_amount
                || curr_value > target_amount + cost_of_change as i64
            {
                backtrack = true;
            } else if curr_value >= target_amount {
                // Selected value is within range, there's no point in going forward. Start
                // backtracking
                backtrack = true;

                // If we found a solution better than the previous one, or if there wasn't previous
                // solution, update the best solution
                if best_selection_value.is_none() || curr_value < best_selection_value.unwrap() {
                    best_selection.clone_from(&current_selection);
                    best_selection_value = Some(curr_value);
                }

                // If we found a perfect match, break here
                if curr_value == target_amount {
                    break;
                }
            }

            // Backtracking, moving backwards
            if backtrack {
                // Walk backwards to find the last included UTXO that still needs to have its omission branch traversed.
                while let Some(false) = current_selection.last() {
                    current_selection.pop();
                    curr_available_value += optional_utxos[current_selection.len()].effective_value;
                }

                if current_selection.last_mut().is_none() {
                    // We have walked back to the first utxo and no branch is untraversed. All solutions searched
                    // If best selection is empty, then there's no exact match
                    if best_selection.is_empty() {
                        return Err(BnbError::NoExactMatch);
                    }
                    break;
                }

                if let Some(c) = current_selection.last_mut() {
                    // Output was included on previous iterations, try excluding now.
                    *c = false;
                }

                let utxo = &optional_utxos[current_selection.len() - 1];
                curr_value -= utxo.effective_value;
            } else {
                // Moving forwards, continuing down this branch
                let utxo = &optional_utxos[current_selection.len()];

                // Remove this utxo from the curr_available_value utxo amount
                curr_available_value -= utxo.effective_value;

                // Inclusion branch first (Largest First Exploration)
                current_selection.push(true);
                curr_value += utxo.effective_value;
            }
        }

        // Check for solution
        if best_selection.is_empty() {
            return Err(BnbError::TotalTriesExceeded);
        }

        // Set output set
        let selected_utxos = optional_utxos
            .into_iter()
            .zip(best_selection)
            .filter_map(|(optional, is_in_best)| if is_in_best { Some(optional) } else { None })
            .collect::<Vec<EffectiveUtxo>>();

        let selected_amount = best_selection_value.unwrap();

        // remaining_amount can't be negative as that would mean the
        // selection wasn't successful
        // target_amount = amount_needed + (fee_amount - vin_fees)
        let remaining_amount = (selected_amount - target_amount) as u64;

        let excess = decide_change(remaining_amount, fee_rate, drain_script);

        Ok(calculate_cs_result(selected_utxos, required_utxos, excess))
    }
}

/// Pull UTXOs at random until we have enough to meet the target.
#[derive(Debug, Clone, Copy, Default)]
pub struct SingleRandomDraw;

impl CoinSelectionAlgorithm for SingleRandomDraw {
    fn coin_select<R: RngCore>(
        &self,
        required_utxos: Vec<CandidateUtxo>,
        mut optional_utxos: Vec<CandidateUtxo>,
        fee_rate: FeeRate,
        target_amount: u64,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<Selection, InsufficientFunds> {
        // We put the required UTXOs first and then the randomize optional UTXOs to take as needed
        let utxos = {
            util::shuffle_slice(&mut optional_utxos, rand);

            required_utxos
                .into_iter()
                .map(|utxo| (true, utxo))
                .chain(optional_utxos.into_iter().map(|utxo| (false, utxo)))
        };

        // select required UTXOs and then random optional UTXOs.
        select_sorted_utxos(utxos, fee_rate, target_amount, drain_script)
    }
}

fn calculate_cs_result(
    mut selected_utxos: Vec<EffectiveUtxo>,
    mut required_utxos: Vec<EffectiveUtxo>,
    excess: Excess,
) -> Selection {
    selected_utxos.append(&mut required_utxos);
    let fee_amount = selected_utxos.iter().map(|u| u.fee).sum::<u64>();
    let selected = selected_utxos
        .into_iter()
        .map(|u| u.utxo)
        .collect::<Vec<_>>();

    Selection {
        selected,
        fee_amount,
        excess,
    }
}

#[cfg(test)]
mod test {
    use alloc::boxed::Box;
    use core::str::FromStr;
    use rand::rngs::StdRng;

    use bdk_chain::ConfirmationTime;
    use bitcoin::{psbt, Address, Amount, Network, OutPoint, ScriptBuf, TxIn, TxOut};

    use super::*;

    use rand::prelude::SliceRandom;
    use rand::{thread_rng, Rng, SeedableRng};

    // signature len (1WU) + signature and sighash (72WU)
    // + pubkey len (1WU) + pubkey (33WU)
    const P2WPKH_SATISFACTION_SIZE: usize = 1 + 72 + 1 + 33;

    const FEE_AMOUNT: u64 = 50;

    fn utxo(value: u64, index: u32, confirmation_time: ConfirmationTime) -> CandidateUtxo {
        assert!(index < 10);
        let outpoint = OutPoint::from_str(&format!(
            "000000000000000000000000000000000000000000000000000000000000000{}:0",
            index
        ))
        .unwrap();
        CandidateUtxo {
            satisfaction_weight: Weight::from_wu_usize(P2WPKH_SATISFACTION_SIZE),
            outpoint,
            sequence: None,
            confirmation_time: Some(confirmation_time),
            txout: Some(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }),
            psbt_input: Box::new(psbt::Input::default()),
        }
    }

    fn get_test_utxos() -> Vec<CandidateUtxo> {
        vec![
            utxo(100_000, 0, ConfirmationTime::Unconfirmed { last_seen: 0 }),
            utxo(
                FEE_AMOUNT - 40,
                1,
                ConfirmationTime::Unconfirmed { last_seen: 0 },
            ),
            utxo(200_000, 2, ConfirmationTime::Unconfirmed { last_seen: 0 }),
        ]
    }

    fn get_oldest_first_test_utxos() -> Vec<CandidateUtxo> {
        // ensure utxos are from different tx
        let utxo1 = utxo(
            120_000,
            1,
            ConfirmationTime::Confirmed {
                height: 1,
                time: 1231006505,
            },
        );
        let utxo2 = utxo(
            80_000,
            2,
            ConfirmationTime::Confirmed {
                height: 2,
                time: 1231006505,
            },
        );
        let utxo3 = utxo(
            300_000,
            3,
            ConfirmationTime::Confirmed {
                height: 3,
                time: 1231006505,
            },
        );
        vec![utxo1, utxo2, utxo3]
    }

    fn generate_random_utxos(rng: &mut StdRng, utxos_number: usize) -> Vec<CandidateUtxo> {
        let mut res = Vec::new();
        for i in 0..utxos_number {
            res.push(CandidateUtxo {
                satisfaction_weight: Weight::from_wu_usize(P2WPKH_SATISFACTION_SIZE),
                outpoint: OutPoint::from_str(&format!(
                    "ebd9813ecebc57ff8f30797de7c205e3c7498ca950ea4341ee51a685ff2fa30a:{}",
                    i
                ))
                .unwrap(),
                sequence: None,
                confirmation_time: None,
                txout: Some(TxOut {
                    value: Amount::from_sat(rng.gen_range(0..200000000)),
                    script_pubkey: ScriptBuf::new(),
                }),
                psbt_input: Box::new(psbt::Input::default()),
            });
        }
        res
    }

    fn generate_same_value_utxos(utxos_value: u64, utxos_number: usize) -> Vec<CandidateUtxo> {
        (0..utxos_number)
            .map(|i| CandidateUtxo {
                satisfaction_weight: Weight::from_wu_usize(P2WPKH_SATISFACTION_SIZE),
                outpoint: OutPoint::from_str(&format!(
                    "ebd9813ecebc57ff8f30797de7c205e3c7498ca950ea4341ee51a685ff2fa30a:{}",
                    i
                ))
                .unwrap(),
                sequence: None,
                confirmation_time: None,
                txout: Some(TxOut {
                    value: Amount::from_sat(utxos_value),
                    script_pubkey: ScriptBuf::new(),
                }),
                psbt_input: Box::new(psbt::Input::default()),
            })
            .collect()
    }

    fn sum_random_utxos(mut rng: &mut StdRng, utxos: &mut Vec<CandidateUtxo>) -> u64 {
        let utxos_picked_len = rng.gen_range(2..utxos.len() / 2);
        utxos.shuffle(&mut rng);
        utxos[..utxos_picked_len]
            .iter()
            .map(|u| u.txout().unwrap().value.to_sat())
            .sum()
    }

    fn calc_target_amount(utxos: &[CandidateUtxo], fee_rate: FeeRate) -> u64 {
        utxos
            .iter()
            .cloned()
            .map(|utxo| u64::try_from(EffectiveUtxo::new(utxo, fee_rate).effective_value).unwrap())
            .sum()
    }

    #[test]
    fn test_is_dust() {
        let script_p2pkh = Address::from_str("1GNgwA8JfG7Kc8akJ8opdNWJUihqUztfPe")
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();
        assert!(script_p2pkh.is_p2pkh());
        assert!(545.is_dust(&script_p2pkh));
        assert!(!546.is_dust(&script_p2pkh));

        let script_p2wpkh = Address::from_str("bc1qxlh2mnc0yqwas76gqq665qkggee5m98t8yskd8")
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();
        assert!(script_p2wpkh.is_p2wpkh());
        assert!(293.is_dust(&script_p2wpkh));
        assert!(!294.is_dust(&script_p2wpkh));
    }

    #[test]
    fn test_largest_first_coin_selection_success() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 250_000 + FEE_AMOUNT;

        let result = LargestFirstCoinSelection
            .coin_select(
                utxos,
                vec![],
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.selected_amount(), 300_010);
        assert_eq!(result.fee_amount, 204)
    }

    #[test]
    fn test_largest_first_coin_selection_use_all() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 20_000 + FEE_AMOUNT;

        let result = LargestFirstCoinSelection
            .coin_select(
                utxos,
                vec![],
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.selected_amount(), 300_010);
        assert_eq!(result.fee_amount, 204);
    }

    #[test]
    fn test_largest_first_coin_selection_use_only_necessary() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 20_000 + FEE_AMOUNT;

        let result = LargestFirstCoinSelection
            .coin_select(
                vec![],
                utxos,
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected_amount(), 200_000);
        assert_eq!(result.fee_amount, 68);
    }

    #[test]
    fn test_largest_first_coin_selection_insufficient_funds() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 500_000 + FEE_AMOUNT;

        let result = LargestFirstCoinSelection.coin_select(
            vec![],
            utxos,
            FeeRate::from_sat_per_vb_unchecked(1),
            target_amount,
            &drain_script,
            &mut thread_rng(),
        );
        assert!(matches!(result, Err(InsufficientFunds { .. })));
    }

    #[test]
    fn test_largest_first_coin_selection_insufficient_funds_high_fees() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 250_000 + FEE_AMOUNT;

        let result = LargestFirstCoinSelection.coin_select(
            vec![],
            utxos,
            FeeRate::from_sat_per_vb_unchecked(1000),
            target_amount,
            &drain_script,
            &mut thread_rng(),
        );
        assert!(matches!(result, Err(InsufficientFunds { .. })));
    }

    #[test]
    fn test_oldest_first_coin_selection_success() {
        let utxos = get_oldest_first_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 180_000 + FEE_AMOUNT;

        let result = OldestFirstCoinSelection
            .coin_select(
                vec![],
                utxos,
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.selected_amount(), 200_000);
        assert_eq!(result.fee_amount, 136)
    }

    #[test]
    fn test_oldest_first_coin_selection_use_all() {
        let utxos = get_oldest_first_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 20_000 + FEE_AMOUNT;

        let result = OldestFirstCoinSelection
            .coin_select(
                utxos,
                vec![],
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.selected_amount(), 500_000);
        assert_eq!(result.fee_amount, 204);
    }

    #[test]
    fn test_oldest_first_coin_selection_use_only_necessary() {
        let utxos = get_oldest_first_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 20_000 + FEE_AMOUNT;

        let result = OldestFirstCoinSelection
            .coin_select(
                vec![],
                utxos,
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected_amount(), 120_000);
        assert_eq!(result.fee_amount, 68);
    }

    #[test]
    fn test_oldest_first_coin_selection_insufficient_funds() {
        let utxos = get_oldest_first_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 600_000 + FEE_AMOUNT;

        let result = OldestFirstCoinSelection.coin_select(
            vec![],
            utxos,
            FeeRate::from_sat_per_vb_unchecked(1),
            target_amount,
            &drain_script,
            &mut thread_rng(),
        );
        assert!(matches!(result, Err(InsufficientFunds { .. })));
    }

    #[test]
    fn test_oldest_first_coin_selection_insufficient_funds_high_fees() {
        let utxos = get_oldest_first_test_utxos();

        let target_amount: u64 = utxos
            .iter()
            .map(|utxo| utxo.txout().unwrap().value.to_sat())
            .sum::<u64>()
            - 50;
        let drain_script = ScriptBuf::default();

        let result = OldestFirstCoinSelection.coin_select(
            vec![],
            utxos,
            FeeRate::from_sat_per_vb_unchecked(1000),
            target_amount,
            &drain_script,
            &mut thread_rng(),
        );
        assert!(matches!(result, Err(InsufficientFunds { .. })));
    }

    #[test]
    fn test_bnb_coin_selection_success() {
        // In this case bnb won't find a suitable match and single random draw will
        // select three outputs
        let utxos = generate_same_value_utxos(100_000, 20);
        let drain_script = ScriptBuf::default();
        let target_amount = 250_000 + FEE_AMOUNT;

        let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default()
            .coin_select(
                vec![],
                utxos,
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.selected_amount(), 300_000);
        assert_eq!(result.fee_amount, 204);
    }

    #[test]
    fn test_bnb_coin_selection_required_are_enough() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 20_000 + FEE_AMOUNT;

        let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default()
            .coin_select(
                utxos.clone(),
                utxos,
                FeeRate::from_sat_per_vb_unchecked(1),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.selected_amount(), 300_010);
        assert_eq!(result.fee_amount, 204);
    }

    #[test]
    fn test_bnb_coin_selection_optional_are_enough() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let fee_rate = FeeRate::BROADCAST_MIN;
        // first and third utxo's effective value
        let target_amount = calc_target_amount(&[utxos[0].clone(), utxos[2].clone()], fee_rate);

        let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default()
            .coin_select(
                vec![],
                utxos,
                fee_rate,
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.selected_amount(), 300000);
        assert_eq!(result.fee_amount, 136);
    }

    #[test]
    fn test_single_random_draw_function_success() {
        let seed = [0; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut utxos = generate_random_utxos(&mut rng, 300);
        let target_amount = sum_random_utxos(&mut rng, &mut utxos) + FEE_AMOUNT;
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
        let drain_script = ScriptBuf::default();

        let result = SingleRandomDraw.coin_select(
            vec![],
            utxos,
            fee_rate,
            target_amount,
            &drain_script,
            &mut thread_rng(),
        );

        assert!(matches!(result, Ok(Selection { selected, fee_amount, .. })
            if selected.iter().map(|u| u.txout().unwrap().value.to_sat()).sum::<u64>() > target_amount
            && fee_amount == ((selected.len() * 68) as u64)
        ));
    }

    #[test]
    fn test_single_random_draw_function_error() {
        let seed = [0; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        // 100_000, 10, 200_000
        let utxos = get_test_utxos();
        let target_amount = 300_000 + FEE_AMOUNT;
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
        let drain_script = ScriptBuf::default();

        let result = SingleRandomDraw.coin_select(
            vec![],
            utxos,
            fee_rate,
            target_amount,
            &drain_script,
            &mut rng,
        );

        assert!(matches!(result, Err(InsufficientFunds {needed, available})
                if needed == 300_254 && available == 300_010));
    }

    #[test]
    fn test_bnb_coin_selection_required_not_enough() {
        let utxos = get_test_utxos();

        let required = vec![utxos[0].clone()];
        let mut optional = utxos[1..].to_vec();
        optional.push(utxo(
            500_000,
            3,
            ConfirmationTime::Unconfirmed { last_seen: 0 },
        ));

        // Defensive assertions, for sanity and in case someone changes the test utxos vector.
        let amount: u64 = required
            .iter()
            .map(|u| u.txout().unwrap().value.to_sat())
            .sum();
        assert_eq!(amount, 100_000);
        let amount: u64 = optional
            .iter()
            .map(|u| u.txout().unwrap().value.to_sat())
            .sum();
        assert!(amount > 150_000);
        let drain_script = ScriptBuf::default();

        let fee_rate = FeeRate::BROADCAST_MIN;
        // first and third utxo's effective value
        let target_amount = calc_target_amount(&[utxos[0].clone(), utxos[2].clone()], fee_rate);

        let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default()
            .coin_select(
                required,
                optional,
                fee_rate,
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.selected_amount(), 300_000);
        assert_eq!(result.fee_amount, 136);
    }

    #[test]
    fn test_bnb_coin_selection_insufficient_funds() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 500_000 + FEE_AMOUNT;

        let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default().coin_select(
            vec![],
            utxos,
            FeeRate::from_sat_per_vb_unchecked(1),
            target_amount,
            &drain_script,
            &mut thread_rng(),
        );

        assert!(matches!(result, Err(InsufficientFunds { .. })));
    }

    #[test]
    fn test_bnb_coin_selection_insufficient_funds_high_fees() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 250_000 + FEE_AMOUNT;

        let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default().coin_select(
            vec![],
            utxos,
            FeeRate::from_sat_per_vb_unchecked(1000),
            target_amount,
            &drain_script,
            &mut thread_rng(),
        );
        assert!(matches!(result, Err(InsufficientFunds { .. })));
    }

    #[test]
    fn test_bnb_coin_selection_check_fee_rate() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let fee_rate = FeeRate::BROADCAST_MIN;
        // first utxo's effective value
        let target_amount = calc_target_amount(&utxos[0..1], fee_rate);

        let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default()
            .coin_select(
                vec![],
                utxos,
                fee_rate,
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected_amount(), 100_000);
        let input_weight =
            TxIn::default().segwit_weight().to_wu() + P2WPKH_SATISFACTION_SIZE as u64;
        // the final fee rate should be exactly the same as the fee rate given
        let result_feerate = Amount::from_sat(result.fee_amount) / Weight::from_wu(input_weight);
        assert_eq!(result_feerate, fee_rate);
    }

    #[test]
    fn test_bnb_coin_selection_exact_match() {
        let seed = [0; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        for _i in 0..200 {
            let mut optional_utxos = generate_random_utxos(&mut rng, 16);
            let target_amount = sum_random_utxos(&mut rng, &mut optional_utxos);
            let drain_script = ScriptBuf::default();
            let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default()
                .coin_select(
                    vec![],
                    optional_utxos,
                    FeeRate::ZERO,
                    target_amount,
                    &drain_script,
                    &mut thread_rng(),
                )
                .unwrap();
            assert_eq!(result.selected_amount(), target_amount);
        }
    }

    #[test]
    fn test_bnb_function_no_exact_match() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
        let utxos: Vec<EffectiveUtxo> = get_test_utxos()
            .into_iter()
            .map(|u| EffectiveUtxo::new(u, fee_rate))
            .collect();

        let curr_available_value = utxos.iter().fold(0, |acc, x| acc + x.effective_value);

        let size_of_change = 31;
        let cost_of_change = (Weight::from_vb_unchecked(size_of_change) * fee_rate).to_sat();

        let drain_script = ScriptBuf::default();
        let target_amount = 20_000 + FEE_AMOUNT;
        let result = BranchAndBoundCoinSelection::new(size_of_change, SingleRandomDraw).bnb(
            vec![],
            utxos,
            0,
            curr_available_value,
            target_amount as i64,
            cost_of_change,
            &drain_script,
            fee_rate,
        );
        assert!(matches!(result, Err(BnbError::NoExactMatch)));
    }

    #[test]
    fn test_bnb_function_tries_exceeded() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
        let utxos: Vec<EffectiveUtxo> = generate_same_value_utxos(100_000, 100_000)
            .into_iter()
            .map(|u| EffectiveUtxo::new(u, fee_rate))
            .collect();

        let curr_available_value = utxos.iter().fold(0, |acc, x| acc + x.effective_value);

        let size_of_change = 31;
        let cost_of_change = (Weight::from_vb_unchecked(size_of_change) * fee_rate).to_sat();
        let target_amount = 20_000 + FEE_AMOUNT;

        let drain_script = ScriptBuf::default();

        let result = BranchAndBoundCoinSelection::new(size_of_change, SingleRandomDraw).bnb(
            vec![],
            utxos,
            0,
            curr_available_value,
            target_amount as i64,
            cost_of_change,
            &drain_script,
            fee_rate,
        );
        assert!(matches!(result, Err(BnbError::TotalTriesExceeded)));
    }

    // The match won't be exact but still in the range
    #[test]
    fn test_bnb_function_almost_exact_match_with_fees() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
        let size_of_change = 31;
        let cost_of_change = (Weight::from_vb_unchecked(size_of_change) * fee_rate).to_sat();

        let utxos: Vec<_> = generate_same_value_utxos(50_000, 10)
            .into_iter()
            .map(|u| EffectiveUtxo::new(u, fee_rate))
            .collect();

        let curr_value = 0;

        let curr_available_value = utxos.iter().fold(0, |acc, x| acc + x.effective_value);

        // 2*(value of 1 utxo)  - 2*(1 utxo fees with 1.0sat/vbyte fee rate) -
        // cost_of_change + 5.
        let target_amount = 2 * 50_000 - 2 * 67 - cost_of_change as i64 + 5;

        let drain_script = ScriptBuf::default();

        let result = BranchAndBoundCoinSelection::new(size_of_change, SingleRandomDraw)
            .bnb(
                vec![],
                utxos,
                curr_value,
                curr_available_value,
                target_amount,
                cost_of_change,
                &drain_script,
                fee_rate,
            )
            .unwrap();
        assert_eq!(result.selected_amount(), 100_000);
        assert_eq!(result.fee_amount, 136);
    }

    // TODO: bnb() function should be optimized, and this test should be done with more utxos
    #[test]
    fn test_bnb_function_exact_match_more_utxos() {
        let seed = [0; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let fee_rate = FeeRate::ZERO;

        for _ in 0..200 {
            let optional_utxos: Vec<_> = generate_random_utxos(&mut rng, 40)
                .into_iter()
                .map(|u| EffectiveUtxo::new(u, fee_rate))
                .collect();

            let curr_value = 0;

            let curr_available_value = optional_utxos
                .iter()
                .fold(0, |acc, x| acc + x.effective_value);

            let target_amount =
                optional_utxos[3].effective_value + optional_utxos[23].effective_value;

            let drain_script = ScriptBuf::default();

            let result = BranchAndBoundCoinSelection::<SingleRandomDraw>::default()
                .bnb(
                    vec![],
                    optional_utxos,
                    curr_value,
                    curr_available_value,
                    target_amount,
                    0,
                    &drain_script,
                    fee_rate,
                )
                .unwrap();
            assert_eq!(result.selected_amount(), target_amount as u64);
        }
    }

    #[test]
    fn test_bnb_exclude_negative_effective_value() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();

        let selection = BranchAndBoundCoinSelection::<SingleRandomDraw>::default().coin_select(
            vec![],
            utxos,
            FeeRate::from_sat_per_vb_unchecked(10),
            500_000,
            &drain_script,
            &mut thread_rng(),
        );

        assert!(matches!(
            selection,
            Err(InsufficientFunds {
                available: 300_000,
                ..
            })
        ));
    }

    #[test]
    fn test_bnb_include_negative_effective_value_when_required() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();

        let (required, optional) = utxos.into_iter().partition(
            |u| matches!(u, CandidateUtxo { txout: Some(txout), .. } if txout.value.to_sat() < 1000),
        );

        let selection = BranchAndBoundCoinSelection::<SingleRandomDraw>::default().coin_select(
            required,
            optional,
            FeeRate::from_sat_per_vb_unchecked(10),
            500_000,
            &drain_script,
            &mut thread_rng(),
        );

        assert!(matches!(
            selection,
            Err(InsufficientFunds {
                available: 300_010,
                ..
            })
        ));
    }

    #[test]
    fn test_bnb_sum_of_effective_value_negative() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();

        let selection = BranchAndBoundCoinSelection::<SingleRandomDraw>::default().coin_select(
            utxos,
            vec![],
            FeeRate::from_sat_per_vb_unchecked(10_000),
            500_000,
            &drain_script,
            &mut thread_rng(),
        );

        assert!(matches!(
            selection,
            Err(InsufficientFunds {
                available: 300_010,
                ..
            })
        ));
    }

    #[test]
    fn test_bnb_fallback_algorithm() {
        // utxo value
        // 120k + 80k + 300k
        let optional_utxos = get_oldest_first_test_utxos();
        let feerate = FeeRate::BROADCAST_MIN;
        let target_amount = 190_000;
        let drain_script = ScriptBuf::new();
        // bnb won't find exact match and should select oldest first
        let bnb_with_oldest_first =
            BranchAndBoundCoinSelection::new(8 + 1 + 22, OldestFirstCoinSelection);
        let res = bnb_with_oldest_first
            .coin_select(
                vec![],
                optional_utxos,
                feerate,
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();
        assert_eq!(res.selected_amount(), 200_000);
    }

    #[test]
    fn test_deterministic_coin_selection_picks_same_utxos() {
        enum CoinSelectionAlgo {
            BranchAndBound,
            OldestFirst,
            LargestFirst,
        }

        struct TestCase<'a> {
            name: &'a str,
            coin_selection_algo: CoinSelectionAlgo,
            exp_vouts: &'a [u32],
        }

        let test_cases = [
            TestCase {
                name: "branch and bound",
                coin_selection_algo: CoinSelectionAlgo::BranchAndBound,
                // note: we expect these to be sorted largest first, which indicates
                // BnB succeeded with no fallback
                exp_vouts: &[29, 28, 27],
            },
            TestCase {
                name: "oldest first",
                coin_selection_algo: CoinSelectionAlgo::OldestFirst,
                exp_vouts: &[0, 1, 2],
            },
            TestCase {
                name: "largest first",
                coin_selection_algo: CoinSelectionAlgo::LargestFirst,
                exp_vouts: &[29, 28, 27],
            },
        ];

        let optional = generate_same_value_utxos(100_000, 30);
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
        let target_amount = calc_target_amount(&optional[0..3], fee_rate);
        assert_eq!(target_amount, 299_796);
        let drain_script = ScriptBuf::default();

        for tc in test_cases {
            let optional = optional.clone();

            let result = match tc.coin_selection_algo {
                CoinSelectionAlgo::BranchAndBound => {
                    BranchAndBoundCoinSelection::<SingleRandomDraw>::default().coin_select(
                        vec![],
                        optional,
                        fee_rate,
                        target_amount,
                        &drain_script,
                        &mut thread_rng(),
                    )
                }
                CoinSelectionAlgo::OldestFirst => OldestFirstCoinSelection.coin_select(
                    vec![],
                    optional,
                    fee_rate,
                    target_amount,
                    &drain_script,
                    &mut thread_rng(),
                ),
                CoinSelectionAlgo::LargestFirst => LargestFirstCoinSelection.coin_select(
                    vec![],
                    optional,
                    fee_rate,
                    target_amount,
                    &drain_script,
                    &mut thread_rng(),
                ),
            };

            assert!(result.is_ok(), "coin_select failed {}", tc.name);
            let result = result.unwrap();
            assert!(matches!(result.excess, Excess::NoChange { .. },));
            assert_eq!(
                result.selected.len(),
                3,
                "wrong selected len for {}",
                tc.name
            );
            assert_eq!(
                result.selected_amount(),
                300_000,
                "wrong selected amount for {}",
                tc.name
            );
            assert_eq!(result.fee_amount, 204, "wrong fee amount for {}", tc.name);
            let vouts = result
                .selected
                .iter()
                .map(|utxo| utxo.outpoint.vout)
                .collect::<Vec<u32>>();
            assert_eq!(vouts, tc.exp_vouts, "wrong selected vouts for {}", tc.name);
        }
    }
}
