//! `bdk_wallet_tx` -- a bridge between [`bdk_wallet`] and [`bdk_tx`].
//!
//! `bdk_wallet` is the stable, batteries-included wallet; `bdk_tx` is a fast-moving,
//! low-level transaction-building library. This crate depends on **both** and exposes their
//! integration as an extension trait, [`WalletTxExt`], implemented for [`bdk_wallet::Wallet`]. That
//! keeps `bdk_tx`'s pre-stable types out of `bdk_wallet`'s public API: neither base crate depends
//! on the other, and every breaking `bdk_tx` release is absorbed here rather than forcing a
//! `bdk_wallet` major.
//!
//! PSBT building is a three-stage pipeline:
//!
//! 1. [`candidates`](WalletTxExt::candidates) / [`candidates_with`](WalletTxExt::candidates_with) /
//!    [`rbf_candidates`](WalletTxExt::rbf_candidates) -> a [`CandidateSet`].
//! 2. [`select`](WalletTxExt::select) -> a [`bdk_tx::TxTemplate`] (shape it: version, locktime,
//!    anti-fee-sniping, input/output ordering).
//! 3. Emit the PSBT directly with [`bdk_tx::TxTemplate::build_psbt`] -> `(Psbt, Finalizer)`,
//!    optionally filling global xpubs from the wallet via
//!    [`add_global_xpubs`](WalletTxExt::add_global_xpubs).
//!
//! # Anti-fee-sniping and MTP
//!
//! `select` returns an **unshuffled** template with **no** anti-fee-sniping. Apply it yourself with
//! `template.apply_anti_fee_sniping(tip_height, rng)` before emitting the PSBT, and
//! shuffle outputs (`template.shuffle_outputs(rng)`) for change-output privacy. Note that
//! `bdk_wallet` checkpoints carry no median-time-past: a per-input [`ConfirmationStatus`] takes its
//! `prev_mtp` from the optional [`CandidateParams::fetch_mtp`] oracle (never a fabricated value),
//! and is left `None` when no oracle is supplied -- so `bdk_tx` reports time-based
//! relative-timelock spendability as "unknown" only then.

#![warn(missing_docs)]

mod candidates;
mod error;
mod params;

pub use candidates::*;
pub use error::*;
pub use params::*;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bdk_tx::{
    bdk_coin_select::CoinSelector, selection_algorithm_lowest_fee_bnb,
    selection_algorithm_single_random_draw, ChangeScript, ConfirmationStatus, Input,
    InputCandidates, OriginalTxStats, Output, RbfParams, SelectionContext, SelectionParams,
    TxTemplate,
};
use bdk_wallet::chain::{Anchor, ChainPosition, ConfirmationBlockTime, FullTxOut};
use bdk_wallet::{AddressInfo, KeychainKind, Wallet};
use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::{absolute, relative, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Txid};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey};
use miniscript::plan::Assets;
use miniscript::{Descriptor, ForEachKey};

use error::map_into_tx_template_error;
use params::merge_assets_secrets;

/// Extension trait that drives [`bdk_tx`]'s multi-stage transaction building from a
/// [`bdk_wallet::Wallet`].
///
/// See the [crate-level docs](crate) for the three-stage pipeline.
pub trait WalletTxExt {
    /// **Stage 1.** Resolve the wallet's spendable [`CandidateSet`] for `opts`.
    ///
    /// Plans manually-selected UTXOs, gathers and filters the wallet's spendable coins, and -- when
    /// [`opts.replace`](CandidateParams::replace) is non-empty -- sets up the Replace-By-Fee
    /// context. The returned [`CandidateSet`] is an owned snapshot suitable for
    /// [`select`](Self::select).
    ///
    /// This is the single stage-1 primitive; [`candidates`](Self::candidates) and
    /// [`rbf_candidates`](Self::rbf_candidates) are convenience wrappers over it.
    fn candidates_with(&self, opts: &CandidateParams) -> Result<CandidateSet, CandidatesError>;

    /// **Stage 1.** Resolve the wallet's spendable [`CandidateSet`] with default options.
    fn candidates(&self) -> Result<CandidateSet, CandidatesError> {
        self.candidates_with(&CandidateParams::default())
    }

    /// **Stage 1.** Resolve a Replace-By-Fee [`CandidateSet`] replacing the given `txids`.
    ///
    /// Shortcut for [`candidates_with`](Self::candidates_with) with a [`CandidateParams`] whose
    /// [`replace`](CandidateParams::replace) list is `txids`. The replacement conflicts with these
    /// txs (forcing their wallet-owned inputs) and must beat their fee; see
    /// [`replace`](CandidateParams::replace) for how a replaced tx's foreign inputs are handled.
    fn rbf_candidates(&self, txids: &[Txid]) -> Result<CandidateSet, CandidatesError> {
        self.candidates_with(&CandidateParams {
            replace: txids.to_vec(),
            ..Default::default()
        })
    }

    /// **Stage 2.** Run coin selection over a resolved [`CandidateSet`], returning a [`TxTemplate`]
    /// that pays the given recipients.
    ///
    /// The returned template is **unshuffled** with **no** anti-fee-sniping; shape it (version,
    /// locktime, anti-fee-sniping, ordering) before emitting the PSBT with
    /// [`bdk_tx::TxTemplate::build_psbt`].
    ///
    /// This is a pure read -- it does **not** mutate the wallet. When no [`ChangeScript`] is
    /// supplied via [`SelectParams`] and the selection produces a change output, the auto-derived
    /// change [`AddressInfo`] is returned (otherwise `None`). It is **peeked, not reserved** --
    /// [`reserve_change`](Self::reserve_change) it to keep a later selection from reusing that
    /// change address; otherwise no wallet state is touched:
    ///
    /// ```rust,ignore
    /// let (template, change) = wallet.select(&coins, params, &mut rng)?;
    /// if let Some(c) = &change {
    ///     wallet.reserve_change(c);   // reveal + mark used; then persist the staged change set
    /// }
    /// ```
    ///
    /// `coins` is borrowed, so the same (expensive-to-build) [`CandidateSet`] can be selected over
    /// repeatedly with different [`SelectParams`]. The RNG is consumed only by
    /// [`SelectionStrategy::SingleRandomDraw`]; other strategies ignore it.
    fn select(
        &self,
        coins: &CandidateSet,
        params: SelectParams,
        rng: &mut impl RngCore,
    ) -> Result<(TxTemplate, Option<AddressInfo>), SelectError>;

    /// Reserve the change [`AddressInfo`] from a [`select`](Self::select), so a later
    /// [`select`](Self::select) won't reuse that change address.
    ///
    /// It **reveals** the address (so the wallet tracks the change output) and **marks it used**
    /// (so it isn't handed out again).
    ///
    /// # Persistence
    ///
    /// Revealing stages a change set; **you must persist it** (e.g. via [`Wallet::take_staged`]),
    /// or the reservation is lost on restart and the wallet won't detect the change output when it
    /// syncs.
    ///
    /// # When to use
    ///
    /// Reserve when several candidate transactions might each be broadcast and you don't want them
    /// to share a change address: reserve up front, before you know which go out, then release any
    /// you don't use with [`Wallet::unmark_used`] (`change.keychain` / `change.index`). Reserve
    /// nothing and the wallet stays untouched -- the peeked address is reused next time.
    fn reserve_change(&mut self, change: &AddressInfo);

    /// Fill in the PSBT's global xpubs from the wallet's descriptors.
    ///
    /// Optional helper for **stage 3**: after emitting a PSBT from the [`select`](Self::select)
    /// template via [`bdk_tx::TxTemplate::build_psbt`], call this to add the
    /// [`global xpubs`](bitcoin::Psbt::xpub) (the only emission step that needs the wallet).
    ///
    /// # Errors
    ///
    /// [`MissingKeyOrigin`] if an extended key in a descriptor is neither a master key (depth 0)
    /// nor carries an explicit origin.
    fn add_global_xpubs(&self, psbt: &mut Psbt) -> Result<(), MissingKeyOrigin>;
}

impl WalletTxExt for Wallet {
    fn candidates_with(&self, opts: &CandidateParams) -> Result<CandidateSet, CandidatesError> {
        build_candidates(self, opts)
    }

    fn select(
        &self,
        coins: &CandidateSet,
        mut params: SelectParams,
        rng: &mut impl RngCore,
    ) -> Result<(TxTemplate, Option<AddressInfo>), SelectError> {
        // A sweep (`SweepAll` / `SweepEffective`) selects candidates and sends the remainder to
        // change, so it may have no recipients. Any other strategy requires at least one recipient
        // -- guarding against accidentally draining the whole wallet by passing empty recipients.
        let sweep = matches!(
            params.coin_selection,
            SelectionStrategy::SweepAll | SelectionStrategy::SweepEffective
        );
        if params.recipients.is_empty() && !sweep {
            return Err(SelectError::NoRecipients);
        }

        // Resolve change: the caller's script, or *peek* the next unused internal address without
        // revealing it. Revelation is deferred until after the template is built -- see below.
        let (change_info, change_script) = peek_change_info(self, params.change_script.take());
        let target_outputs = target_outputs(self, &params.recipients);

        // `coins` is borrowed so callers can re-select on the same snapshot; clone the parts
        // `into_tx_template` consumes. (The clone goes away once `bdk_tx` selection borrows.)
        let (input_candidates, rbf) = (coins.candidates.clone(), coins.rbf.clone());

        // `longterm_feerate` is a selection-wide waste parameter (it also drives the change
        // policy), so it applies to every strategy -- not just `LowestFee`.
        let select_params = SelectionParams {
            replace: rbf,
            longterm_feerate: params.longterm_feerate,
            ..SelectionParams::new(params.feerate, target_outputs, change_script)
        };

        let template = match params.coin_selection {
            SelectionStrategy::SweepAll => input_candidates
                .into_tx_template(
                    |cs: &mut CoinSelector, _cx: SelectionContext| {
                        cs.select_all();
                        Ok::<(), core::convert::Infallible>(())
                    },
                    select_params,
                )
                .map_err(|e| map_into_tx_template_error(e, |never| match never {}))?,
            SelectionStrategy::SweepEffective => input_candidates
                .into_tx_template(
                    |cs: &mut CoinSelector, cx: SelectionContext| {
                        cs.select_all_effective(cx.target.fee.rate);
                        Ok::<(), core::convert::Infallible>(())
                    },
                    select_params,
                )
                .map_err(|e| map_into_tx_template_error(e, |never| match never {}))?,
            SelectionStrategy::SingleRandomDraw => input_candidates
                .into_tx_template(selection_algorithm_single_random_draw(rng), select_params)
                .map_err(|e| {
                    map_into_tx_template_error(e, |e| SelectError::CannotMeetTarget {
                        missing: e.missing,
                    })
                })?,
            SelectionStrategy::LowestFee { max_rounds } => input_candidates
                .into_tx_template(
                    selection_algorithm_lowest_fee_bnb(max_rounds),
                    select_params,
                )
                .map_err(|e| map_into_tx_template_error(e, SelectError::Bnb))?,
        };

        // The sole change/drain output fell below the dust threshold and was dropped to fees,
        // leaving no outputs (a no-recipient sweep of dust).
        if template.outputs().is_empty() {
            return Err(SelectError::ChangeBelowDust);
        }

        // Surface the auto-derived change address, but *only* if it actually ended up in the
        // template's outputs. A caller-supplied change script, or a selection that produced no
        // change (exact-amount / sweep), yields `None`.
        let change = change_info.filter(|info| {
            let spk = info.address.script_pubkey();
            template.outputs().iter().any(|o| o.script_pubkey() == spk)
        });

        Ok((template, change))
    }

    fn reserve_change(&mut self, change: &AddressInfo) {
        // `change.keychain` is already mapped: `reveal_addresses_to` maps it too (idempotent), and
        // `mark_used` does *not* map -- so feeding it the mapped keychain is what makes this
        // correct on single-descriptor wallets.
        let _ = self.reveal_addresses_to(change.keychain, change.index);
        self.mark_used(change.keychain, change.index);
    }

    fn add_global_xpubs(&self, psbt: &mut Psbt) -> Result<(), MissingKeyOrigin> {
        // Resolve every key origin first, so a `MissingKeyOrigin` leaves the PSBT untouched rather
        // than partially populated.
        let mut entries = Vec::new();
        for (_, desc) in self.spk_index().keychains() {
            for xpub in extended_keys(desc) {
                let origin = match xpub.origin.clone() {
                    Some(origin) => origin,
                    // A depth-0 key is its own master, so its fingerprint is the root.
                    None if xpub.xkey.depth == 0 => {
                        (xpub.xkey.fingerprint(), DerivationPath::default())
                    }
                    _ => return Err(MissingKeyOrigin { xpub: xpub.xkey }),
                };
                entries.push((xpub.xkey, origin));
            }
        }
        psbt.xpub.extend(entries);
        Ok(())
    }
}

/// Peek at the change script for a selection **without** revealing/mutating wallet state.
///
/// Returns the resolved [`ChangeScript`], plus the change [`AddressInfo`] when it was auto-derived
/// (so the caller can reveal/track it later, if the selection ends up used). A caller-supplied
/// script is passed through with `None`. The auto-derived script is the next unused change address:
/// the first revealed-but-unused one, or the next index to reveal if there is none.
///
/// The peek goes through the *mapped* change keychain (single-descriptor wallets fall back to the
/// external one), so the returned `AddressInfo.keychain` is mapped too -- safe to feed to
/// `Wallet::mark_used` / `unmark_used`, which do not map it themselves.
fn peek_change_info(
    wallet: &Wallet,
    override_script: Option<ChangeScript>,
) -> (Option<AddressInfo>, ChangeScript) {
    match override_script {
        Some(cs) => (None, cs),
        None => {
            // Replicate the (private) `Wallet::map_keychain` rule: a single-descriptor wallet has
            // no internal keychain, so change falls back to the external one.
            let keychain = if wallet.spk_index().keychains().count() == 1 {
                KeychainKind::External
            } else {
                KeychainKind::Internal
            };
            // These accessors map the keychain internally too, so passing the mapped one is fine.
            let info = wallet
                .list_unused_addresses(keychain)
                .next()
                .unwrap_or_else(|| {
                    let index = wallet.next_derivation_index(keychain);
                    wallet.peek_address(keychain, index)
                });
            let descriptor = wallet
                .public_descriptor(keychain)
                .at_derivation_index(info.index)
                .expect("derivation index from the wallet is valid");
            (Some(info), ChangeScript::from_descriptor(descriptor))
        }
    }
}

/// Maps a chain position to tx confirmation status, if `pos` is the confirmed variant.
///
/// `prev_mtp` comes from the caller's [`mtp`](MtpOracle) oracle, queried with the input's
/// confirmation block (`bdk_wallet` retains no median-time-past, so we never fabricate one). It is
/// `None` when no oracle is supplied or the oracle has no value for that block, leaving time-based
/// relative-timelock spendability "unknown". Returns `None` if the confirmation height is not a
/// valid absolute height.
fn status_from_position(
    pos: ChainPosition<ConfirmationBlockTime>,
    mtp: Option<&MtpOracle>,
) -> Option<ConfirmationStatus> {
    if let ChainPosition::Confirmed { anchor, .. } = pos {
        let conf_height = anchor.confirmation_height_upper_bound();
        let height = absolute::Height::from_consensus(conf_height).ok()?;
        let prev_mtp = mtp.and_then(|f| f(anchor.block_id));
        Some(ConfirmationStatus { height, prev_mtp })
    } else {
        None
    }
}

/// Extended keys of a descriptor (replicates `bdk_wallet`'s private `get_extended_keys`).
fn extended_keys(desc: &Descriptor<DescriptorPublicKey>) -> Vec<DescriptorXKey<Xpub>> {
    let mut answer = Vec::new();
    desc.for_each_key(|pk| {
        // Expand multipath keys into their single-path xpubs (as `parse_params` does), so a
        // multi-xpub descriptor isn't silently dropped from the global-xpub set.
        for single in pk.clone().into_single_keys() {
            if let DescriptorPublicKey::XPub(xpub) = single {
                answer.push(xpub);
            }
        }
        true
    });
    answer
}

/// Parse the common params used during candidate construction: the spend assets and the map of
/// indexed tx outputs.
fn parse_params(
    wallet: &Wallet,
    opts: &CandidateParams,
) -> (Assets, HashMap<OutPoint, FullTxOut<ConfirmationBlockTime>>) {
    // The caller's `opts.assets` are authoritative. Copy in its keys/preimages and carry its
    // timelocks over verbatim. If the caller supplied no signing keys, assume all wallet keys are
    // available so wallet-controlled outputs can still be planned.
    let mut assets = Assets::new();
    merge_assets_secrets(&mut assets, &opts.assets);
    assets.absolute_timelock = opts.assets.absolute_timelock;
    assets.relative_timelock = opts.assets.relative_timelock;
    if assets.keys.is_empty() {
        let mut pks = vec![];
        for (_, desc) in wallet.spk_index().keychains() {
            desc.for_each_key(|k| {
                pks.extend(k.clone().into_single_keys());
                true
            });
        }
        merge_assets_secrets(&mut assets, &Assets::new().add(pks));
    }

    let txouts = wallet
        .tx_graph()
        .filter_chain_txouts(
            wallet.local_chain(),
            wallet.latest_checkpoint().block_id(),
            opts.canonical_params.clone(),
            wallet.spk_index().outpoints().iter().cloned(),
        )
        .map(|(_, txo)| (txo.outpoint, txo))
        .collect();

    (assets, txouts)
}

/// Map the recipients to target [`Output`]s, deriving a descriptor for wallet-owned scripts.
fn target_outputs(wallet: &Wallet, recipients: &[(ScriptBuf, Amount)]) -> Vec<Output> {
    recipients
        .iter()
        .cloned()
        .map(
            |(script, value)| match wallet.spk_index().index_of_spk(script.clone()) {
                Some(&(keychain, index)) => {
                    let descriptor = wallet
                        .public_descriptor(keychain)
                        .at_derivation_index(index)
                        .expect("should be valid derivation index");
                    Output::with_descriptor(descriptor, value)
                }
                None => Output::with_script(script, value),
            },
        )
        .collect()
}

/// Resolve a [`CandidateSet`] from `opts`, handling both the normal and Replace-By-Fee paths.
fn build_candidates(
    wallet: &Wallet,
    opts: &CandidateParams,
) -> Result<CandidateSet, CandidatesError> {
    let (assets, mut txouts) = parse_params(wallet, opts);

    // Per-block MTP oracle (if any); queried per input to fill `prev_mtp`, and for the tip below.
    let mtp = opts.fetch_mtp.as_deref();

    // Height axis for spendability -- coinbase maturity and height-based CLTV/CSV timelocks, in
    // both `plan_input` and the post-planning filter. (Time-based locks use `tip_mtp`, at the tip.)
    let at_height = opts.maturity_height.unwrap_or_else(|| {
        absolute::Height::from_consensus(wallet.latest_checkpoint().height())
            .expect("a chain tip height is a valid absolute height")
    });
    let eval_height = at_height.to_consensus_u32();

    let is_rbf = !opts.replace.is_empty();

    let mut rbf_must_spend: Vec<Input> = vec![];
    let mut to_replace: HashSet<Txid> = HashSet::new();
    let mut rbf_params: Option<RbfParams> = None;
    if is_rbf {
        // Build the set of replaced txids, dropping any tx that is a coinbase or whose ancestors
        // are also being replaced (replacing an ancestor invalidates the descendant).
        let candidate_replace: HashSet<Txid> = opts.replace.iter().copied().collect();
        let mut direct_conflicts: HashSet<Txid> = HashSet::new();
        let mut replace_outpoints: Vec<OutPoint> = vec![];
        for &txid in opts.replace.iter() {
            let tx = wallet
                .tx_graph()
                .get_tx(txid)
                .ok_or(CandidatesError::MissingTransaction(txid))?;
            // A descendant is covered (skip it) only by an ancestor that is *genuinely* replaced --
            // i.e. in the replace list and not a coinbase (coinbases are skipped, so they cover
            // nothing).
            let has_replaced_ancestor = wallet
                .tx_graph()
                .walk_ancestors(Arc::clone(&tx), |_, ancestor| {
                    Some((ancestor.compute_txid(), ancestor.is_coinbase()))
                })
                .any(|(atxid, is_coinbase)| !is_coinbase && candidate_replace.contains(&atxid));
            if tx.is_coinbase() || has_replaced_ancestor {
                continue;
            }
            if direct_conflicts.insert(txid) {
                // The wallet must control at least one of the tx's inputs, otherwise it can't build
                // a replacement that double-spends (and therefore evicts) it.
                if !tx
                    .input
                    .iter()
                    .any(|txin| txouts.contains_key(&txin.previous_output))
                {
                    return Err(CandidatesError::CannotReplace(txid));
                }
                replace_outpoints.extend(tx.input.iter().map(|txin| txin.previous_output));
            }
        }

        // The must-spend inputs are the wallet-owned inputs of the (sanitized) replaced txs.
        for outpoint in &replace_outpoints {
            if opts.must_spend.contains(outpoint) {
                continue;
            }
            let Some(txo) = txouts.get(outpoint) else {
                continue;
            };
            let input = plan_input(wallet, txo, &assets, eval_height, mtp)
                .ok_or(CandidatesError::Plan(*outpoint))?;
            rbf_must_spend.push(input);
        }

        // Replaced txs and their descendants are excluded from coin selection.
        let descendants: HashSet<Txid> = direct_conflicts
            .iter()
            .flat_map(|&txid| {
                wallet
                    .tx_graph()
                    .walk_descendants(txid, |_, txid| Some(txid))
            })
            .filter(|txid| !direct_conflicts.contains(txid))
            .collect();
        to_replace = direct_conflicts
            .iter()
            .chain(descendants.iter())
            .copied()
            .collect();

        // Drop the replaced set's own outputs from the considered UTXOs: the replacement evicts
        // those txs, so their outputs won't exist (selecting one then yields `CannotSpend`).
        txouts.retain(|outpoint, _| !to_replace.contains(&outpoint.txid));

        let original_txs: Vec<OriginalTxStats> = direct_conflicts
            .iter()
            .map(|&txid| -> Result<_, CandidatesError> {
                let tx = wallet
                    .tx_graph()
                    .get_tx(txid)
                    .ok_or(CandidatesError::MissingTransaction(txid))?;
                let fee = wallet
                    .calculate_fee(&tx)
                    .map_err(CandidatesError::PreviousFee)?;
                Ok(OriginalTxStats {
                    weight: tx.weight(),
                    fee,
                })
            })
            .collect::<Result<_, _>>()?;

        // Sum fees from all descendants (each assumed to be in the mempool, so evicted too).
        let mut descendant_fee = Amount::ZERO;
        for &txid in descendants.iter() {
            let tx = wallet
                .tx_graph()
                .get_tx(txid)
                .ok_or(CandidatesError::MissingTransaction(txid))?;
            descendant_fee += wallet
                .calculate_fee(&tx)
                .map_err(CandidatesError::PreviousFee)?;
        }

        rbf_params = Some(RbfParams {
            original_txs,
            descendant_fee,
            incremental_relay_feerate: FeeRate::BROADCAST_MIN,
        });
    }

    // Combine the RBF-derived must-spend inputs with the user-supplied ones.
    let mut must_spend = rbf_must_spend;
    for &outpoint in &opts.must_spend {
        let txo = txouts
            .get(&outpoint)
            .ok_or(CandidatesError::CannotSpend(outpoint))?;
        // A spent coin can't be spent again -- unless the only thing spending it is a tx we're
        // replacing, which the replacement evicts (freeing the coin).
        if let Some((_, spender)) = &txo.spent_by {
            if !to_replace.contains(spender) {
                return Err(CandidatesError::CannotSpend(outpoint));
            }
        }
        let input = plan_input(wallet, txo, &assets, eval_height, mtp)
            .ok_or(CandidatesError::Plan(outpoint))?;
        must_spend.push(input);
    }

    let may_spend: Vec<Input> = if opts.manually_selected_only {
        vec![]
    } else {
        txouts
            .into_values()
            .filter(|txo| {
                // Skip manually-selected (added separately as must-spend) and locked outputs.
                if opts.must_spend.contains(&txo.outpoint)
                    || wallet.is_outpoint_locked(txo.outpoint)
                {
                    return false;
                }
                // A spent coin is unavailable -- unless the only tx spending it is one we're
                // replacing (the replacement evicts it, freeing the coin).
                if let Some((_, spender)) = &txo.spent_by {
                    if !to_replace.contains(spender) {
                        return false;
                    }
                }
                // In the RBF case, only spend confirmed outputs (the replaced set's outputs were
                // already removed from `txouts` above).
                !is_rbf || txo.chain_position.is_confirmed()
            })
            .flat_map(|txo| plan_input(wallet, &txo, &assets, eval_height, mtp))
            .collect()
    };

    // Build the candidate set, then drop immature / time-locked *optional* candidates unless
    // allowed. `InputCandidates::filter` never drops must-select inputs, so manually-selected coins
    // are spent regardless of maturity or timelocks.
    let mut candidates = InputCandidates::new(must_spend, may_spend);
    if !opts.allow_immature || !opts.allow_timelocked {
        // Tip MTP for time-based locks at spend time (each input's `prev_mtp` was filled during
        // planning via `fetch_mtp`). Height-based locks need neither, so absent values only leave
        // time-based locks unresolved (`None` -> conservatively excluded).
        let tip_mtp = opts.tip_mtp;
        candidates = candidates.filter(|input| {
            if !opts.allow_immature && input.is_immature(at_height) {
                return false;
            }
            if !opts.allow_timelocked && input.is_timelocked(at_height, tip_mtp).unwrap_or(true) {
                return false;
            }
            true
        });
    }

    // Wallet-owned UTXOs the replacement strips from the canonical view.
    let replaced_unspent = if is_rbf {
        wallet
            .list_unspent()
            .filter(|utxo| to_replace.contains(&utxo.outpoint.txid))
            .collect()
    } else {
        Vec::new()
    };

    Ok(CandidateSet {
        candidates,
        rbf: rbf_params,
        replaced: to_replace,
        replaced_unspent,
    })
}

/// Build a planned [`Input`] that spends `txo`, or `None` if it can't be planned with the
/// available assets (not wallet-owned, or insufficient keys/preimages).
fn plan_input(
    wallet: &Wallet,
    txo: &FullTxOut<ConfirmationBlockTime>,
    spend_assets: &Assets,
    eval_height: u32,
    mtp: Option<&MtpOracle>,
) -> Option<Input> {
    let op = txo.outpoint;
    let txid = op.txid;

    // Pin timelocks to `eval_height` (the maturity/evaluation height, defaulting to the chain tip)
    // so a coin spendable as of that height actually plans -- matching the post-planning filter.
    // Afford the output with as many assets as we can; the plan uses only the ones needed.
    let abs_locktime = spend_assets
        .absolute_timelock
        .unwrap_or(absolute::LockTime::from_consensus(eval_height));

    let rel_locktime = spend_assets.relative_timelock.unwrap_or_else(|| {
        let age = match txo.chain_position.confirmation_height_upper_bound() {
            Some(conf_height) => eval_height
                .saturating_add(1)
                .saturating_sub(conf_height)
                .try_into()
                .unwrap_or(u16::MAX),
            None => 0,
        };
        relative::LockTime::from_height(age)
    });

    // Keep the caller's keys/preimages, but pin the timelocks to the values derived above.
    let mut assets = Assets::new();
    merge_assets_secrets(&mut assets, spend_assets);
    let assets = assets.after(abs_locktime).older(rel_locktime);

    // Plan the spend (None if the outpoint isn't indexed or the assets are insufficient).
    let indexer = wallet.spk_index();
    let ((keychain, index), _) = indexer.txout(op)?;
    let plan = indexer
        .get_descriptor(keychain)?
        .at_derivation_index(index)
        .expect("must be valid derivation index")
        .plan(&assets)
        .ok()?;

    let tx = wallet.tx_graph().get_tx(txid)?;
    let tx_status = status_from_position(txo.chain_position, mtp);

    Input::from_prev_tx(plan, tx, op.vout as usize, tx_status).ok()
}
