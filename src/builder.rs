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

//! Transaction builder
//!
//! ## Example
//!
//! ```
//! # use std::str::FromStr;
//! # use bitcoin::*;
//! # use bdk_wallet::*;
//! # use bdk_wallet::doctest_wallet;
//! # use bdk_wallet::ChangeSet;
//! # use bdk_wallet::error::CreateTxError;
//! # use anyhow::Error;
//! # let to_address = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap().assume_checked();
//! # let mut wallet = doctest_wallet!();
//! // create a TxBuilder from a wallet
//! let mut tx_builder = wallet.tx_builder();
//!
//! tx_builder
//!     // Create a transaction with one output to `to_address` of 50_000 satoshi
//!     .add_recipient(to_address.script_pubkey(), Amount::from_sat(50_000))
//!     // With a custom fee rate of 5.0 satoshi/vbyte
//!     .fee_rate(FeeRate::from_sat_per_vb(5).expect("valid feerate"))
//!     // Only spend non-change outputs
//!     .do_not_spend_change();
//! let psbt = tx_builder.build_tx()?;
//! # Ok::<(), anyhow::Error>(())
//! ```
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;
use core::mem;

use bdk_chain::bitcoin::{
    absolute, psbt, script::PushBytes, transaction::Version, Amount, FeeRate, OutPoint, Psbt,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight,
};
use bdk_chain::collections::{BTreeMap, HashSet};
use bdk_chain::miniscript::plan::Assets;
use bdk_chain::ConfirmationTime;
use rand_core::RngCore;

use crate::coin_selection::CoinSelectionAlgorithm;
use crate::util;
use crate::CreateTx;
// use crate::coin_selection::CoinSelectionAlgorithm;

/// A transaction builder
///
/// A `TxBuilder` is created by calling [`new`](TxBuilder::new). After initializing the builder,
/// you set options on it until finally calling `build_tx` to consume the builder and generate
/// the transaction.
///
/// Each option setting method on `TxBuilder` takes and returns `&mut self` so you can chain calls
/// as in the following example:
///
/// ```rust,no_run
/// # use bdk_wallet::*;
/// # use bdk_transaction::TxOrdering;
/// # use bitcoin::*;
/// # use core::str::FromStr;
/// # use bdk_wallet::ChangeSet;
/// # use bdk_wallet::error::CreateTxError;
/// # use anyhow::Error;
/// # let mut wallet = doctest_wallet!();
/// # let addr1 = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap().assume_checked();
/// # let addr2 = addr1.clone();
/// // chaining
/// let psbt1 = {
///     let mut builder = wallet.tx_builder();
///     builder
///         .ordering(TxOrdering::Untouched)
///         .add_recipient(addr1.script_pubkey(), Amount::from_sat(50_000))
///         .add_recipient(addr2.script_pubkey(), Amount::from_sat(50_000))
///         .build_tx()?
/// };
///
/// // non-chaining
/// let psbt2 = {
///     let mut builder = wallet.tx_builder();
///     builder.ordering(TxOrdering::Untouched);
///     for addr in &[addr1, addr2] {
///         builder.add_recipient(addr.script_pubkey(), Amount::from_sat(50_000));
///     }
///     builder.build_tx()?
/// };
///
/// assert_eq!(psbt1.unsigned_tx.output[..2], psbt2.unsigned_tx.output[..2]);
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Debug)]
pub struct TxBuilder<'a, Cs, T> {
    /// Tx params
    pub(crate) params: TxParams,
    /// Coin selection algorithm
    pub(crate) coin_selection: Cs,
    /// Transaction creator
    pub(crate) creator: Rc<RefCell<&'a mut T>>,
}

/// The parameters for transaction creation sans coin selection algorithm.
//TODO: TxParams should eventually be exposed publicly.
#[derive(Default, Debug)]
pub struct TxParams {
    pub(crate) assets: Assets,
    pub(crate) recipients: Vec<(ScriptBuf, Amount)>,
    pub(crate) drain_wallet: bool,
    pub(crate) drain_to: Option<ScriptBuf>,
    pub(crate) fee_policy: Option<FeePolicy>,
    pub(crate) internal_policy_path: Option<BTreeMap<String, Vec<usize>>>,
    pub(crate) external_policy_path: Option<BTreeMap<String, Vec<usize>>>,
    pub(crate) utxos: Vec<OutPoint>, // candidates that can be looked up by outpoint
    pub(crate) candidates: Vec<CandidateUtxo>, // foreign utxos
    pub(crate) unspendable: HashSet<OutPoint>,
    pub(crate) manually_selected_only: bool,
    pub(crate) sighash: Option<psbt::PsbtSighashType>,
    pub(crate) ordering: TxOrdering,
    pub(crate) locktime: Option<absolute::LockTime>,
    pub(crate) sequence: Option<Sequence>,
    pub(crate) version: Option<Version>,
    pub(crate) change_policy: ChangeSpendPolicy,
    pub(crate) only_witness_utxo: bool,
    pub(crate) add_global_xpubs: bool,
    pub(crate) include_output_redeem_witness_script: bool,
    pub(crate) bumping_fee: Option<PreviousFee>,
    pub(crate) current_height: Option<absolute::LockTime>,
    pub(crate) allow_dust: bool,
}

/// A UTXO with its satisfaction weight. This is used primarily when
/// adding foreign UTXOs to a [`TxBuilder`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CandidateUtxo {
    /// Outpoint
    pub outpoint: OutPoint,
    /// Satisfaction weight
    pub satisfaction_weight: Weight,
    /// TxOut (may be None if this is a foreign utxo)
    pub txout: Option<TxOut>,
    /// Sequence
    pub sequence: Option<Sequence>,
    /// Confirmation time
    pub confirmation_time: Option<ConfirmationTime>,
    /// Psbt input
    pub psbt_input: Box<psbt::Input>,
}

impl Default for CandidateUtxo {
    fn default() -> Self {
        Self {
            outpoint: OutPoint::null(),
            satisfaction_weight: Weight::ZERO,
            sequence: None,
            confirmation_time: None,
            txout: None,
            psbt_input: Box::new(psbt::Input::default()),
        }
    }
}

impl PartialOrd for CandidateUtxo {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CandidateUtxo {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.partial_cmp(other).expect("OutPoint is Ord")
    }
}

impl CandidateUtxo {
    /// Get the TxOut from this candidate.
    pub fn txout(&self) -> Option<TxOut> {
        if self.txout.is_some() {
            return self.txout.clone();
        }

        let witness_utxo = &self.psbt_input.witness_utxo;
        let non_witness_utxo = &self.psbt_input.non_witness_utxo;

        match (witness_utxo, non_witness_utxo) {
            (Some(_), _) => witness_utxo.clone(),
            (_, Some(_)) => non_witness_utxo
                .as_ref()
                .map(|tx| tx.output[self.outpoint.vout as usize].clone()),
            _ => None,
        }
    }
}

/// Previous fee.
#[derive(Clone, Copy, Debug)]
pub struct PreviousFee {
    /// Absolute
    pub absolute: Amount,
    /// FeeRate
    pub rate: FeeRate,
}

/// Fee policy.
#[derive(Debug, Clone, Copy)]
pub enum FeePolicy {
    /// FeeRate
    FeeRate(FeeRate),
    /// Amount
    FeeAmount(Amount),
}

impl Default for FeePolicy {
    fn default() -> Self {
        FeePolicy::FeeRate(FeeRate::BROADCAST_MIN)
    }
}

// impl getters for `TxParams` that can be cloned or copied
macro_rules! impl_get_field_clone {
    ($($field:ident, $ret:ty,)*) => {
        paste::paste! {
            $(
                impl TxParams {
                    #[doc = "Get `" $field "` parameter"]
                    pub fn $field(&self) -> $ret {
                        self.$field.clone()
                    }
                }
            )*
        }
    }
}
macro_rules! impl_get_field {
    ($($field:ident, $ret:ty,)*) => {
        paste::paste! {
            $(
                impl TxParams {
                    #[doc = "Get `" $field "` parameter"]
                    pub fn $field(&self) -> $ret {
                        self.$field
                    }
                }
            )*
        }
    }
}
#[rustfmt::skip]
impl_get_field_clone!(
    recipients, Vec<(ScriptBuf, Amount)>,
    drain_to, Option<ScriptBuf>,
    fee_policy, Option<FeePolicy>,
    internal_policy_path, Option<BTreeMap<String, Vec<usize>>>,
    external_policy_path, Option<BTreeMap<String, Vec<usize>>>,
    utxos, Vec<OutPoint>,
    candidates, Vec<CandidateUtxo>,
    unspendable, HashSet<OutPoint>,
    sighash, Option<psbt::PsbtSighashType>,
    ordering, TxOrdering,
    locktime, Option<absolute::LockTime>,
    sequence, Option<Sequence>,
    version, Option<Version>,
    change_policy, ChangeSpendPolicy,
    bumping_fee, Option<PreviousFee>,
    current_height, Option<absolute::LockTime>,
);
#[rustfmt::skip]
impl_get_field!(
    drain_wallet, bool,
    manually_selected_only, bool,
    only_witness_utxo, bool,
    add_global_xpubs, bool,
    include_output_redeem_witness_script, bool,
    allow_dust, bool,
);

impl TxParams {
    /// Get [`Assets`] parameter.
    pub fn assets(&self) -> &Assets {
        &self.assets
    }
}

/// Implemented on [`Assets`] so that one instance can be extended from a reference
/// of the same type.
// TODO: try upstream some form of this to rust-miniscript
pub trait AssetsExt {
    /// Extend `self` with the contents of `other`.
    fn extend(&mut self, other: &Self);
    /// Is empty
    fn is_empty(&self) -> bool;
}

impl AssetsExt for Assets {
    /// Extends `self` with the contents of `other`. Note that if set,
    /// this preferentially uses the timelock value of `other`.
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

    /// Whether this [`Assets`] is empty.
    fn is_empty(&self) -> bool {
        self.keys.is_empty()
            && self.sha256_preimages.is_empty()
            && self.hash256_preimages.is_empty()
            && self.ripemd160_preimages.is_empty()
            && self.hash160_preimages.is_empty()
            && self.absolute_timelock.is_none()
            && self.relative_timelock.is_none()
    }
}

impl<'a, Cs: CoinSelectionAlgorithm, T> TxBuilder<'a, Cs, T> {
    /// New from selector and tx creator.
    pub fn new(coin_selection: Cs, creator: &'a mut T) -> Self {
        Self {
            params: TxParams::default(),
            coin_selection,
            creator: Rc::new(RefCell::new(creator)),
        }
    }
}

impl<'a, Cs, T> TxBuilder<'a, Cs, T> {
    /// Set candidate UTXOs
    pub fn set_candidates(
        &mut self,
        candidates: impl IntoIterator<Item = CandidateUtxo>,
    ) -> &mut Self {
        self.params.candidates.extend(candidates);
        self
    }

    /// Set previous fee.
    pub fn set_previous_fee(&mut self, previous_fee: PreviousFee) -> &mut Self {
        self.params.bumping_fee = Some(previous_fee);
        self
    }

    /// Add [`Assets`].
    pub fn add_assets(&mut self, assets: &Assets) -> &mut Self {
        self.params.assets.extend(assets);
        self
    }

    /// Set a custom fee rate.
    ///
    /// This method sets the mining fee paid by the transaction as a rate on its size.
    /// This means that the total fee paid is equal to `fee_rate` times the size
    /// of the transaction. Default is 1 sat/vB in accordance with Bitcoin Core's default
    /// relay policy.
    ///
    /// Note that this is really a minimum feerate -- it's possible to
    /// overshoot it slightly since adding a change output to drain the remaining
    /// excess might not be viable.
    pub fn fee_rate(&mut self, fee_rate: FeeRate) -> &mut Self {
        self.params.fee_policy = Some(FeePolicy::FeeRate(fee_rate));
        self
    }

    /// Set an absolute fee
    /// The fee_absolute method refers to the absolute transaction fee in [`Amount`].
    /// If anyone sets both the `fee_absolute` method and the `fee_rate` method,
    /// the `FeePolicy` enum will be set by whichever method was called last,
    /// as the [`FeeRate`] and `FeeAmount` are mutually exclusive.
    ///
    /// Note that this is really a minimum absolute fee -- it's possible to
    /// overshoot it slightly since adding a change output to drain the remaining
    /// excess might not be viable.
    pub fn fee_absolute(&mut self, fee_amount: Amount) -> &mut Self {
        self.params.fee_policy = Some(FeePolicy::FeeAmount(fee_amount));
        self
    }

    /// Set the policy path to use while creating the transaction for a given keychain.
    ///
    /// This method accepts a map where the key is the policy node id and the value
    /// is the list of the indexes of the items that are intended to be satisfied from
    /// the policy node (see the [policy module][0] for details).
    ///
    /// ## Example
    ///
    /// An example of when the policy path is needed is the following descriptor:
    /// `wsh(thresh(2,pk(A),sj:and_v(v:pk(B),n:older(6)),snj:and_v(v:pk(C),after(630000))))`,
    /// derived from the miniscript policy `thresh(2,pk(A),and(pk(B),older(6)),and(pk(C),after(630000)))`.
    /// It declares three descriptor fragments, and at the top level it uses `thresh()` to
    /// ensure that at least two of them are satisfied. The individual fragments are:
    ///
    /// 1. `pk(A)`
    /// 2. `and(pk(B),older(6))`
    /// 3. `and(pk(C),after(630000))`
    ///
    /// When those conditions are combined in pairs, it's clear that the transaction needs to be created
    /// differently depending on how the user intends to satisfy the policy afterwards:
    ///
    /// * If fragments `1` and `2` are used, the transaction will need to use a specific
    ///   `n_sequence` in order to spend an `OP_CSV` branch.
    /// * If fragments `1` and `3` are used, the transaction will need to use a specific `locktime`
    ///   in order to spend an `OP_CLTV` branch.
    /// * If fragments `2` and `3` are used, the transaction will need both.
    ///
    /// When the spending policy is represented as a tree, every node is assigned a
    /// unique identifier that can be used in the policy path to specify which of the node's
    /// children the user intends to satisfy: for instance, assuming the `thresh()` root
    /// node of this example has an id of `aabbccdd`, the policy path map would look like:
    ///
    /// `{ "aabbccdd" => [0, 1] }`
    ///
    /// where the key is the node's id, and the value is a list of the children that should be
    /// used, in no particular order.
    ///
    /// If a particularly complex descriptor has multiple ambiguous thresholds in its structure,
    /// multiple entries can be added to the map, one for each node that requires an explicit path.
    ///
    /// ```
    /// # use std::str::FromStr;
    /// # use std::collections::BTreeMap;
    /// # use bitcoin::*;
    /// # use bdk_wallet::*;
    /// # let to_address =
    /// Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt")
    ///     .unwrap()
    ///     .assume_checked();
    /// # let mut wallet = doctest_wallet!();
    /// let mut path = BTreeMap::new();
    /// path.insert("aabbccdd".to_string(), vec![0, 1]);
    ///
    /// let builder = wallet
    ///     .tx_builder()
    ///     .add_recipient(to_address.script_pubkey(), Amount::from_sat(50_000))
    ///     .external_policy_path(path);
    ///
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    /// [0]: https://docs.rs/bdk_wallet/latest/bdk_wallet/descriptor/policy/index.html
    pub fn external_policy_path(&mut self, policy_path: BTreeMap<String, Vec<usize>>) -> &mut Self {
        self.params.external_policy_path = Some(policy_path);
        self
    }

    /// Set the internal policy path to use while creating the transaction.
    ///
    /// See also [`external_policy_path`](Self::external_policy_path).
    pub fn internal_policy_path(&mut self, policy_path: BTreeMap<String, Vec<usize>>) -> &mut Self {
        self.params.internal_policy_path = Some(policy_path);
        self
    }

    /// Add the list of outpoints to the internal list of UTXOs that **must** be spent.
    ///
    /// If an error occurs while adding any of the UTXOs then none of them are added and the error is returned.
    ///
    /// These have priority over the "unspendable" utxos, meaning that if a utxo is present both in
    /// the "utxos" and the "unspendable" list, it will be spent.
    pub fn add_utxos(&mut self, outpoints: &[OutPoint]) -> Result<&mut Self, AddUtxoError> {
        self.params.utxos.extend(outpoints);
        Ok(self)
    }

    /// Add a utxo to the internal list of utxos that **must** be spent
    ///
    /// These have priority over the "unspendable" utxos, meaning that if a utxo is present both in
    /// the "utxos" and the "unspendable" list, it will be spent.
    pub fn add_utxo(&mut self, outpoint: OutPoint) -> Result<&mut Self, AddUtxoError> {
        self.add_utxos(&[outpoint])
    }

    /// Add a foreign UTXO i.e. a UTXO not owned by this wallet.
    ///
    /// At a minimum to add a foreign UTXO we need:
    ///
    /// 1. `outpoint`: To add it to the raw transaction.
    /// 2. `psbt_input`: To know the value.
    /// 3. `satisfaction_weight`: To know how much weight/vbytes the input will add to the transaction for fee calculation.
    ///
    /// There are several security concerns about adding foreign UTXOs that application
    /// developers should consider. First, how do you know the value of the input is correct? If a
    /// `non_witness_utxo` is provided in the `psbt_input` then this method implicitly verifies the
    /// value by checking it against the transaction. If only a `witness_utxo` is provided then this
    /// method doesn't verify the value but just takes it as a given -- it is up to you to check
    /// that whoever sent you the `input_psbt` was not lying!
    ///
    /// Secondly, you must somehow provide `satisfaction_weight` of the input. Depending on your
    /// application it may be important that this be known precisely. If not, a malicious
    /// counterparty may fool you into putting in a value that is too low, giving the transaction a
    /// lower than expected feerate. They could also fool you into putting a value that is too high
    /// causing you to pay a fee that is too high. The party who is broadcasting the transaction can
    /// of course check the real input weight matches the expected weight prior to broadcasting.
    ///
    /// To guarantee the `max_weight_to_satisfy` is correct, you can require the party providing the
    /// `psbt_input` provide a miniscript descriptor for the input so you can check it against the
    /// `script_pubkey` and then ask it for the [`max_weight_to_satisfy`].
    ///
    /// This is an **EXPERIMENTAL** feature, API and other major changes are expected.
    ///
    /// In order to use [`Wallet::calculate_fee`] or [`Wallet::calculate_fee_rate`] for a transaction
    /// created with foreign UTXO(s) you must manually insert the corresponding TxOut(s) into the tx
    /// graph using the `Wallet::insert_txout` function.
    ///
    /// # Errors
    ///
    /// This method returns errors in the following circumstances:
    ///
    /// 1. The `psbt_input` does not contain a `witness_utxo` or `non_witness_utxo`.
    /// 2. The data in `non_witness_utxo` does not match what is in `outpoint`.
    ///
    /// Note unless you set [`only_witness_utxo`] any non-taproot `psbt_input` you pass to this
    /// method must have `non_witness_utxo` set otherwise you will get an error when `build_tx`
    /// is called.
    ///
    /// [`only_witness_utxo`]: Self::only_witness_utxo
    /// [`max_weight_to_satisfy`]: bdk_chain::miniscript::Descriptor::max_weight_to_satisfy
    /// [`Wallet::calculate_fee`]: https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.Wallet.html#method.calculate_fee
    /// [`Wallet::calculate_fee_rate`]: https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.Wallet.html#method.calculate_fee_rate
    pub fn add_foreign_utxo(
        &mut self,
        outpoint: OutPoint,
        psbt_input: psbt::Input,
        satisfaction_weight: Weight,
    ) -> Result<&mut Self, AddForeignUtxoError> {
        self.add_foreign_utxo_with_sequence(
            outpoint,
            psbt_input,
            satisfaction_weight,
            Sequence::MAX,
        )
    }

    /// Same as [add_foreign_utxo](TxBuilder::add_foreign_utxo) but allows to set the nSequence value.
    pub fn add_foreign_utxo_with_sequence(
        &mut self,
        outpoint: OutPoint,
        psbt_input: psbt::Input,
        satisfaction_weight: Weight,
        sequence: Sequence,
    ) -> Result<&mut Self, AddForeignUtxoError> {
        if psbt_input.witness_utxo.is_none() {
            match psbt_input.non_witness_utxo.as_ref() {
                Some(tx) => {
                    if tx.compute_txid() != outpoint.txid {
                        return Err(AddForeignUtxoError::InvalidTxid {
                            input_txid: tx.compute_txid(),
                            foreign_utxo: outpoint,
                        });
                    }
                    if tx.output.len() <= outpoint.vout as usize {
                        return Err(AddForeignUtxoError::InvalidOutpoint(outpoint));
                    }
                }
                None => {
                    return Err(AddForeignUtxoError::MissingUtxo);
                }
            }
        }

        self.params.candidates.push(CandidateUtxo {
            satisfaction_weight,
            outpoint,
            sequence: Some(sequence),
            confirmation_time: None,
            txout: None,
            psbt_input: Box::new(psbt_input),
        });

        Ok(self)
    }

    /// Only spend utxos added by [`add_utxo`].
    ///
    /// The wallet will **not** add additional utxos to the transaction even if they are needed to
    /// make the transaction valid.
    ///
    /// [`add_utxo`]: Self::add_utxo
    pub fn manually_selected_only(&mut self) -> &mut Self {
        self.params.manually_selected_only = true;
        self
    }

    /// Replace the internal list of unspendable utxos with a new list
    ///
    /// It's important to note that the "must-be-spent" utxos added with [`TxBuilder::add_utxo`]
    /// have priority over these. See the docs of the two linked methods for more details.
    pub fn unspendable(&mut self, unspendable: Vec<OutPoint>) -> &mut Self {
        self.params.unspendable = unspendable.into_iter().collect();
        self
    }

    /// Add a utxo to the internal list of unspendable utxos
    ///
    /// It's important to note that the "must-be-spent" utxos added with [`TxBuilder::add_utxo`]
    /// have priority over this. See the docs of the two linked methods for more details.
    pub fn add_unspendable(&mut self, unspendable: OutPoint) -> &mut Self {
        self.params.unspendable.insert(unspendable);
        self
    }

    /// Sign with a specific sig hash
    ///
    /// **Use this option very carefully**
    pub fn sighash(&mut self, sighash: psbt::PsbtSighashType) -> &mut Self {
        self.params.sighash = Some(sighash);
        self
    }

    /// Choose the ordering for inputs and outputs of the transaction
    pub fn ordering(&mut self, ordering: TxOrdering) -> &mut Self {
        self.params.ordering = ordering;
        self
    }

    /// Use a specific nLockTime while creating the transaction
    ///
    /// This can cause conflicts if the wallet's descriptors contain an "after" (OP_CLTV) operator.
    pub fn nlocktime(&mut self, locktime: absolute::LockTime) -> &mut Self {
        self.params.locktime = Some(locktime);
        self
    }

    /// Build a transaction with a specific version
    ///
    /// The `version` should always be greater than `0` and greater than `1` if the wallet's
    /// descriptors contain an "older" (OP_CSV) operator.
    pub fn version(&mut self, version: i32) -> &mut Self {
        self.params.version = Some(Version(version));
        self
    }

    /// Do not spend change outputs
    ///
    /// This effectively adds all the change outputs to the "unspendable" list. See
    /// [`TxBuilder::unspendable`]. This method assumes the presence of an internal
    /// keychain, otherwise it has no effect.
    pub fn do_not_spend_change(&mut self) -> &mut Self {
        self.params.change_policy = ChangeSpendPolicy::ChangeForbidden;
        self
    }

    /// Only spend change outputs
    ///
    /// This effectively adds all the non-change outputs to the "unspendable" list. See
    /// [`TxBuilder::unspendable`]. This method assumes the presence of an internal
    /// keychain, otherwise it has no effect.
    pub fn only_spend_change(&mut self) -> &mut Self {
        self.params.change_policy = ChangeSpendPolicy::OnlyChange;
        self
    }

    /// Set a specific [`ChangeSpendPolicy`]. See [`TxBuilder::do_not_spend_change`] and
    /// [`TxBuilder::only_spend_change`] for some shortcuts. This method assumes the presence
    /// of an internal keychain, otherwise it has no effect.
    pub fn change_policy(&mut self, change_policy: ChangeSpendPolicy) -> &mut Self {
        self.params.change_policy = change_policy;
        self
    }

    /// Only Fill-in the [`psbt::Input::witness_utxo`] field when spending from SegWit descriptors.
    ///
    /// This reduces the size of the PSBT, but some signers might reject them due to the lack of
    /// the `non_witness_utxo`.
    ///
    /// [`psbt::Input::witness_utxo`]: bdk_chain::bitcoin::psbt::Input::witness_utxo
    pub fn only_witness_utxo(&mut self) -> &mut Self {
        self.params.only_witness_utxo = true;
        self
    }

    /// Fill-in the [`psbt::Output::redeem_script`][0] and [`psbt::Output::witness_script`][1]
    /// fields.
    ///
    /// This is useful for signers which always require it, like ColdCard hardware wallets.
    ///
    /// [0]: bdk_chain::bitcoin::psbt::Output::redeem_script
    /// [1]: bdk_chain::bitcoin::psbt::Output::witness_script
    pub fn include_output_redeem_witness_script(&mut self) -> &mut Self {
        self.params.include_output_redeem_witness_script = true;
        self
    }

    /// Fill-in the `PSBT_GLOBAL_XPUB` field with the extended keys contained in both the external
    /// and internal descriptors
    ///
    /// This is useful for offline signers that take part to a multisig. Some hardware wallets like
    /// BitBox and ColdCard are known to require this.
    pub fn add_global_xpubs(&mut self) -> &mut Self {
        self.params.add_global_xpubs = true;
        self
    }

    /// Spend all the available inputs. This respects filters like [`TxBuilder::unspendable`] and the change policy.
    pub fn drain_wallet(&mut self) -> &mut Self {
        self.params.drain_wallet = true;
        self
    }

    /// Choose the coin selection algorithm
    ///
    /// Overrides the [`CoinSelectionAlgorithm`].
    ///
    /// Note that this function consumes the builder and returns it so it is usually best to put
    /// this as the first call on the builder.
    pub fn coin_selection<A: CoinSelectionAlgorithm>(
        self,
        coin_selection: A,
    ) -> TxBuilder<'a, A, T> {
        TxBuilder {
            params: self.params,
            coin_selection,
            creator: self.creator,
        }
    }

    /// Set an exact nSequence value
    ///
    /// This can cause conflicts if the wallet's descriptors contain an
    /// "older" (OP_CSV) operator and the given `nsequence` is lower than the CSV value.
    pub fn set_exact_sequence(&mut self, nsequence: Sequence) -> &mut Self {
        self.params.sequence = Some(nsequence);
        self
    }

    /// Set the current blockchain height.
    ///
    /// This will be used to:
    /// 1. Set the nLockTime for preventing fee sniping.
    ///    **Note**: This will be ignored if you manually specify a nlocktime using [`TxBuilder::nlocktime`].
    /// 2. Decide whether coinbase outputs are mature or not. If the coinbase outputs are not
    ///    mature at `current_height`, we ignore them in the coin selection.
    ///    If you want to create a transaction that spends immature coinbase inputs, manually
    ///    add them using [`TxBuilder::add_utxos`].
    ///
    /// In both cases, if you don't provide a current height, we use the last sync height.
    pub fn current_height(&mut self, height: u32) -> &mut Self {
        self.params.current_height =
            Some(absolute::LockTime::from_height(height).expect("Invalid height"));
        self
    }

    /// Set whether or not the dust limit is checked.
    ///
    /// **Note**: by avoiding a dust limit check you may end up with a transaction that is non-standard.
    pub fn allow_dust(&mut self, allow_dust: bool) -> &mut Self {
        self.params.allow_dust = allow_dust;
        self
    }

    /// Replace the recipients already added with a new list
    pub fn set_recipients(&mut self, recipients: Vec<(ScriptBuf, Amount)>) -> &mut Self {
        self.params.recipients = recipients;
        self
    }

    /// Add a recipient to the internal list
    pub fn add_recipient(&mut self, script_pubkey: ScriptBuf, amount: Amount) -> &mut Self {
        self.params.recipients.push((script_pubkey, amount));
        self
    }

    /// Add data as an output, using OP_RETURN
    pub fn add_data<B: AsRef<PushBytes>>(&mut self, data: &B) -> &mut Self {
        let script = ScriptBuf::new_op_return(data);
        self.add_recipient(script, Amount::ZERO);
        self
    }

    /// Sets the address to *drain* excess coins to.
    ///
    /// Usually, when there are excess coins they are sent to a change address generated by the
    /// wallet. This option replaces the usual change address with an arbitrary `script_pubkey` of
    /// your choosing. Just as with a change output, if the drain output is not needed (the excess
    /// coins are too small) it will not be included in the resulting transaction. The only
    /// difference is that it is valid to use `drain_to` without setting any ordinary recipients
    /// with [`add_recipient`] (but it is perfectly fine to add recipients as well).
    ///
    /// If you choose not to set any recipients, you should provide the utxos that the
    /// transaction should spend via [`add_utxos`].
    ///
    /// # Example
    ///
    /// `drain_to` is very useful for draining all the coins in a wallet with [`drain_wallet`] to a
    /// single address.
    ///
    /// ```
    /// # use std::str::FromStr;
    /// # use bitcoin::*;
    /// # use bdk_wallet::*;
    /// # use bdk_wallet::ChangeSet;
    /// # use bdk_wallet::error::CreateTxError;
    /// # use anyhow::Error;
    /// # let to_address =
    /// Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt")
    ///     .unwrap()
    ///     .assume_checked();
    /// # let mut wallet = doctest_wallet!();
    /// let mut tx_builder = wallet.tx_builder();
    ///
    /// tx_builder
    ///     // Spend all outputs in this wallet.
    ///     .drain_wallet()
    ///     // Send the excess (which is all the coins minus the fee) to this address.
    ///     .set_drain_to(to_address.script_pubkey())
    ///     .fee_rate(FeeRate::from_sat_per_vb(5).expect("valid feerate"));
    /// let psbt = tx_builder.build_tx()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    ///
    /// [`add_recipient`]: Self::add_recipient
    /// [`add_utxos`]: Self::add_utxos
    /// [`drain_wallet`]: Self::drain_wallet
    pub fn set_drain_to(&mut self, script_pubkey: ScriptBuf) -> &mut Self {
        self.params.drain_to = Some(script_pubkey);
        self
    }
}

impl<'a, Cs, T> TxBuilder<'a, Cs, T> {
    /// Finish building the transaction.
    ///
    /// The provided random number generator `rng` can be used to shuffle inputs and outputs
    /// as well as for some coin selection algorithms such as single random draw.
    pub fn build_tx_with_aux_rand(&mut self, rng: &mut impl RngCore) -> Result<Psbt, T::Error>
    where
        Cs: CoinSelectionAlgorithm,
        T: CreateTx,
    {
        let params = mem::take(&mut self.params);
        self.creator
            .borrow_mut()
            .create_tx(params, self.coin_selection.clone(), rng)
    }
}

#[derive(Debug)]
/// Error returned from [`TxBuilder::add_utxo`] and [`TxBuilder::add_utxos`]
pub enum AddUtxoError {
    /// Happens when the [`CreateTx`] implementor cannot look up a UTXO by outpoint.
    UnknownUtxo(OutPoint),
}

impl fmt::Display for AddUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUtxo(outpoint) => write!(
                f,
                "UTXO not found in the internal database for txid: {} with vout: {}",
                outpoint.txid, outpoint.vout
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddUtxoError {}

#[derive(Debug)]
/// Error returned from [`TxBuilder::add_foreign_utxo`].
pub enum AddForeignUtxoError {
    /// Foreign utxo outpoint txid does not match PSBT input txid
    InvalidTxid {
        /// PSBT input txid
        input_txid: Txid,
        /// Foreign UTXO outpoint
        foreign_utxo: OutPoint,
    },
    /// Requested outpoint doesn't exist in the tx (vout greater than available outputs)
    InvalidOutpoint(OutPoint),
    /// Foreign utxo missing witness_utxo or non_witness_utxo
    MissingUtxo,
}

impl fmt::Display for AddForeignUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTxid {
                input_txid,
                foreign_utxo,
            } => write!(
                f,
                "Foreign UTXO outpoint txid: {} does not match PSBT input txid: {}",
                foreign_utxo.txid, input_txid,
            ),
            Self::InvalidOutpoint(outpoint) => write!(
                f,
                "Requested outpoint doesn't exist for txid: {} with vout: {}",
                outpoint.txid, outpoint.vout,
            ),
            Self::MissingUtxo => write!(f, "Foreign utxo missing witness_utxo or non_witness_utxo"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddForeignUtxoError {}

type TxSort<T> = dyn Fn(&T, &T) -> core::cmp::Ordering;

/// Ordering of the transaction's inputs and outputs
#[derive(Clone, Default)]
pub enum TxOrdering {
    /// Randomized (default)
    #[default]
    Shuffle,
    /// Unchanged
    Untouched,
    /// Provide custom comparison functions for sorting
    Custom {
        /// Transaction inputs sort function
        input_sort: Arc<TxSort<TxIn>>,
        /// Transaction outputs sort function
        output_sort: Arc<TxSort<TxOut>>,
    },
}

impl core::fmt::Debug for TxOrdering {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            TxOrdering::Shuffle => write!(f, "Shuffle"),
            TxOrdering::Untouched => write!(f, "Untouched"),
            TxOrdering::Custom { .. } => write!(f, "Custom"),
        }
    }
}

impl TxOrdering {
    /// Sort transaction inputs and outputs by [`TxOrdering`] variant.
    ///
    /// Uses the thread-local random number generator (rng).
    #[cfg(feature = "std")]
    pub fn sort_tx(&self, tx: &mut Transaction) {
        self.sort_tx_with_aux_rand(tx, &mut bdk_chain::bitcoin::key::rand::thread_rng())
    }

    /// Sort transaction inputs and outputs by [`TxOrdering`] variant.
    ///
    /// Uses a provided random number generator (rng).
    pub fn sort_tx_with_aux_rand(&self, tx: &mut Transaction, rng: &mut impl RngCore) {
        match self {
            TxOrdering::Untouched => {}
            TxOrdering::Shuffle => {
                util::shuffle_slice(&mut tx.input, rng);
                util::shuffle_slice(&mut tx.output, rng);
            }
            TxOrdering::Custom {
                input_sort,
                output_sort,
            } => {
                tx.input.sort_unstable_by(|a, b| input_sort(a, b));
                tx.output.sort_unstable_by(|a, b| output_sort(a, b));
            }
        }
    }
}

/// Policy regarding the use of change outputs when creating a transaction
#[derive(Default, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Clone, Copy)]
pub enum ChangeSpendPolicy {
    /// Use both change and non-change outputs (default)
    #[default]
    ChangeAllowed,
    /// Only use change outputs (see [`TxBuilder::only_spend_change`])
    OnlyChange,
    /// Only use non-change outputs (see [`TxBuilder::do_not_spend_change`])
    ChangeForbidden,
}

#[cfg(test)]
mod test {
    const ORDERING_TEST_TX: &str = "0200000003c26f3eb7932f7acddc5ddd26602b77e7516079b03090a16e2c2f54\
                                    85d1fd600f0100000000ffffffffc26f3eb7932f7acddc5ddd26602b77e75160\
                                    79b03090a16e2c2f5485d1fd600f0000000000ffffffff571fb3e02278217852\
                                    dd5d299947e2b7354a639adc32ec1fa7b82cfb5dec530e0500000000ffffffff\
                                    03e80300000000000002aaeee80300000000000001aa200300000000000001ff\
                                    00000000";
    macro_rules! ordering_test_tx {
        () => {
            consensus::deserialize::<Transaction>(&Vec::<u8>::from_hex(ORDERING_TEST_TX).unwrap())
                .unwrap()
        };
    }

    use super::*;
    use alloc::vec;

    use bdk_chain::bitcoin::consensus;
    use bdk_chain::bitcoin::hex::FromHex;
    use bdk_chain::bitcoin::TxOut;

    #[test]
    fn test_output_ordering_untouched() {
        let original_tx = ordering_test_tx!();
        let mut tx = original_tx.clone();

        TxOrdering::Untouched.sort_tx(&mut tx);

        assert_eq!(original_tx, tx);
    }

    #[test]
    fn test_output_ordering_shuffle() {
        let original_tx = ordering_test_tx!();
        let mut tx = original_tx.clone();

        (0..40)
            .find(|_| {
                TxOrdering::Shuffle.sort_tx(&mut tx);
                original_tx.input != tx.input
            })
            .expect("it should have moved the inputs at least once");

        let mut tx = original_tx.clone();
        (0..40)
            .find(|_| {
                TxOrdering::Shuffle.sort_tx(&mut tx);
                original_tx.output != tx.output
            })
            .expect("it should have moved the outputs at least once");
    }

    #[test]
    fn test_output_ordering_custom_but_bip69() {
        use core::str::FromStr;

        let original_tx = ordering_test_tx!();
        let mut tx = original_tx;

        let bip69_txin_cmp = |tx_a: &TxIn, tx_b: &TxIn| {
            let project_outpoint = |t: &TxIn| (t.previous_output.txid, t.previous_output.vout);
            project_outpoint(tx_a).cmp(&project_outpoint(tx_b))
        };

        let bip69_txout_cmp = |tx_a: &TxOut, tx_b: &TxOut| {
            let project_utxo = |t: &TxOut| (t.value, t.script_pubkey.clone());
            project_utxo(tx_a).cmp(&project_utxo(tx_b))
        };

        let custom_bip69_ordering = TxOrdering::Custom {
            input_sort: Arc::new(bip69_txin_cmp),
            output_sort: Arc::new(bip69_txout_cmp),
        };

        custom_bip69_ordering.sort_tx(&mut tx);

        assert_eq!(
            tx.input[0].previous_output,
            OutPoint::from_str(
                "0e53ec5dfb2cb8a71fec32dc9a634a35b7e24799295ddd5278217822e0b31f57:5"
            )
            .unwrap()
        );
        assert_eq!(
            tx.input[1].previous_output,
            OutPoint::from_str(
                "0f60fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2:0"
            )
            .unwrap()
        );
        assert_eq!(
            tx.input[2].previous_output,
            OutPoint::from_str(
                "0f60fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2:1"
            )
            .unwrap()
        );

        assert_eq!(tx.output[0].value.to_sat(), 800);
        assert_eq!(tx.output[1].script_pubkey, ScriptBuf::from(vec![0xAA]));
        assert_eq!(
            tx.output[2].script_pubkey,
            ScriptBuf::from(vec![0xAA, 0xEE])
        );
    }

    #[test]
    fn test_output_ordering_custom_with_sha256() {
        use bdk_chain::bitcoin::hashes::{sha256, Hash};

        let original_tx = ordering_test_tx!();
        let mut tx_1 = original_tx.clone();
        let mut tx_2 = original_tx.clone();
        let shared_secret = "secret_tweak";

        let hash_txin_with_shared_secret_seed = Arc::new(|tx_a: &TxIn, tx_b: &TxIn| {
            let secret_digest_from_txin = |txin: &TxIn| {
                sha256::Hash::hash(
                    &[
                        &txin.previous_output.txid.to_raw_hash()[..],
                        &txin.previous_output.vout.to_be_bytes(),
                        shared_secret.as_bytes(),
                    ]
                    .concat(),
                )
            };
            secret_digest_from_txin(tx_a).cmp(&secret_digest_from_txin(tx_b))
        });

        let hash_txout_with_shared_secret_seed = Arc::new(|tx_a: &TxOut, tx_b: &TxOut| {
            let secret_digest_from_txout = |txin: &TxOut| {
                sha256::Hash::hash(
                    &[
                        &txin.value.to_sat().to_be_bytes(),
                        &txin.script_pubkey.clone().into_bytes()[..],
                        shared_secret.as_bytes(),
                    ]
                    .concat(),
                )
            };
            secret_digest_from_txout(tx_a).cmp(&secret_digest_from_txout(tx_b))
        });

        let custom_ordering_from_salted_sha256_1 = TxOrdering::Custom {
            input_sort: hash_txin_with_shared_secret_seed.clone(),
            output_sort: hash_txout_with_shared_secret_seed.clone(),
        };

        let custom_ordering_from_salted_sha256_2 = TxOrdering::Custom {
            input_sort: hash_txin_with_shared_secret_seed,
            output_sort: hash_txout_with_shared_secret_seed,
        };

        custom_ordering_from_salted_sha256_1.sort_tx(&mut tx_1);
        custom_ordering_from_salted_sha256_2.sort_tx(&mut tx_2);

        // Check the ordering is consistent between calls
        assert_eq!(tx_1, tx_2);
        // Check transaction order has changed
        assert_ne!(tx_1, original_tx);
        assert_ne!(tx_2, original_tx);
    }
}
