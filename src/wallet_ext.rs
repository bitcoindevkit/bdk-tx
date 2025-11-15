use crate::{
    CanonicalUnspents, ExtractReplacementsError, Input, InputCandidates,
    OriginalTxHasNoInputsAvailable, RbfParams, TxStatus, TxWithStatus,
};

use alloc::{fmt, sync::Arc, vec::Vec};
use std::collections::HashSet;

use bdk_wallet::{
    chain::{keychain_txout::KeychainTxOutIndex, ChainPosition},
    KeychainKind, Wallet, WalletTx,
};
use miniscript::{
    bitcoin::{
        absolute::{Height, LockTime, Time},
        OutPoint, Transaction, Txid,
    },
    plan::{Assets, Plan},
    ForEachKey,
};

/// Errors that can occur during Replace-By-Fee (RBF) transaction preparation.
#[derive(Debug)]
pub enum RbfError {
    /// Transaction has descendants that must be explicitly included for replacement.
    ///
    /// When attempting to replace a transaction, any child transactions that spend
    /// its outputs must also be included in the replacement set to maintain
    /// blockchain validity.
    HasDescendants(Vec<Txid>),
    /// Failed to find input of transaction we are intending to replace.
    ///
    /// This occurs when the required input from the original transaction
    /// cannot be located in the wallet's UTXO set.
    MissingInput,
    /// Error from canonical unspents extraction.
    ///
    /// Failed to extract replacement candidates from the canonical unspent set.
    ExtractReplacements(ExtractReplacementsError),
    /// Original transaction has no input available for replacement
    NoInputsAvailable(OriginalTxHasNoInputsAvailable),
}

impl fmt::Display for RbfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HasDescendants(txids) => write!(
                f,
                "Transaction has descendants that must be explicitly included: {txids:?}"
            ),
            Self::MissingInput => {
                write!(f, "Failed to find input of tx we are intending to replace")
            }
            Self::ExtractReplacements(err) => write!(f, "Extract replacements error: {err}"),
            Self::NoInputsAvailable(err) => {
                write!(f, "No input available: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RbfError {}

impl From<OriginalTxHasNoInputsAvailable> for RbfError {
    fn from(err: OriginalTxHasNoInputsAvailable) -> Self {
        Self::NoInputsAvailable(err)
    }
}

impl From<ExtractReplacementsError> for RbfError {
    fn from(err: ExtractReplacementsError) -> Self {
        Self::ExtractReplacements(err)
    }
}

/// Extension trait for `bdk_wallet::Wallet` to provide coin selection methods.
///
/// This trait adds functionality for general coin selection and Replace-By-Fee (RBF)
/// transaction preparation, handling the complexities of UTXO selection and
/// transaction dependency validation.
pub trait WalletExt {
    /// Returns `InputCandidates` for general coin selection.
    fn all_candidates(&self) -> InputCandidates;

    /// Returns `InputCandidates` for Replace-By-Fee (RBF) transactions.
    ///
    /// The caller must explicitly include the `Txid`s of all transactions
    /// to replace and the current blockchain tip height for locktime validation.
    ///
    /// Returns an [`RbfError`] if validation failed or required input is unavailable.
    fn rbf_candidates(
        &self,
        replace: impl IntoIterator<Item = Txid>,
        tip_height: Height,
        include_descendants: bool,
    ) -> Result<(InputCandidates, RbfParams), RbfError>;
}

fn build_assets(tip_height: u32, index: &KeychainTxOutIndex<KeychainKind>) -> Assets {
    Assets::new()
        .after(LockTime::from_height(tip_height).expect("must be valid height"))
        .add({
            let mut pks = vec![];
            for (_, desc) in index.keychains() {
                desc.for_each_key(|k| {
                    pks.extend(k.clone().into_single_keys());
                    true
                });
            }
            pks
        })
}

fn canonical_txs<'a, I>(txs: I) -> impl Iterator<Item = TxWithStatus<Arc<Transaction>>> + 'a
where
    I: Iterator<Item = WalletTx<'a>> + 'a,
{
    txs.map(|c_tx| {
        let tx: Arc<Transaction> = c_tx.tx_node.tx;
        let tx_status = match c_tx.chain_position {
            ChainPosition::Confirmed { anchor, .. } => Some(TxStatus {
                height: Height::from_consensus(anchor.block_id.height).expect("valid height"),
                time: Time::from_consensus(anchor.confirmation_time as _).expect("valid time"),
            }),
            ChainPosition::Unconfirmed { .. } => None,
        };
        (tx, tx_status)
    })
}

fn plan_of_output(
    index: &KeychainTxOutIndex<KeychainKind>,
    outpoint: OutPoint,
    assets: &Assets,
) -> Option<Plan> {
    let ((k, i), _txout) = index.txout(outpoint)?;
    let desc = index.get_descriptor(k)?.at_derivation_index(i).ok()?;
    let plan = desc.plan(assets).ok()?;
    Some(plan)
}

impl WalletExt for Wallet {
    fn all_candidates(&self) -> InputCandidates {
        let tip_height = self.local_chain().tip().block_id().height;
        let index = self.spk_index();
        let assets = build_assets(tip_height, index);

        let canonical_txs = canonical_txs(self.transactions());
        let canonical_utxos = CanonicalUnspents::new(canonical_txs);

        let can_select = canonical_utxos.try_get_unspents(
            index
                .outpoints()
                .iter()
                .filter_map(|(_, op)| Some((*op, plan_of_output(index, *op, &assets)?))),
        );

        InputCandidates::new([], can_select)
    }

    fn rbf_candidates(
        &self,
        replace: impl IntoIterator<Item = Txid>,
        tip_height: Height,
        include_descendants: bool,
    ) -> Result<(InputCandidates, RbfParams), RbfError> {
        let index = self.spk_index();
        let chain_tip_height = self.local_chain().tip().block_id().height;
        let assets = build_assets(chain_tip_height, index);

        let mut replace_set: HashSet<Txid> = replace.into_iter().collect();

        // Check for descendants that spend outputs from transactions being replaced
        let descendants: Vec<Txid> = self
            .transactions()
            .filter(|tx| {
                let spends_from_target = tx
                    .tx_node
                    .tx
                    .input
                    .iter()
                    .any(|input| replace_set.contains(&input.previous_output.txid));

                let not_in_replace_set = !replace_set.contains(&tx.tx_node.txid);

                spends_from_target && not_in_replace_set
            })
            .map(|tx| tx.tx_node.txid)
            .collect();

        if !descendants.is_empty() {
            if include_descendants {
                replace_set.extend(descendants);
            } else {
                return Err(RbfError::HasDescendants(descendants));
            }
        }

        let canonical_txs = canonical_txs(self.transactions());
        let mut canonical_utxos = CanonicalUnspents::new(canonical_txs);

        let rbf_set = canonical_utxos.extract_replacements(replace_set)?;
        let must_select = rbf_set
            .must_select_largest_input_of_each_original_tx(&canonical_utxos)?
            .into_iter()
            .map(|op| canonical_utxos.try_get_unspent(op, plan_of_output(index, op, &assets)?))
            .collect::<Option<Vec<Input>>>()
            .ok_or(RbfError::MissingInput)?;

        let can_select = index.outpoints().iter().filter_map(|(_, op)| {
            canonical_utxos.try_get_unspent(*op, plan_of_output(index, *op, &assets)?)
        });

        // Create input candidates with RBF-specific filtering
        let input_candidates = InputCandidates::new(must_select, can_select)
            .filter(rbf_set.candidate_filter(tip_height));
        let rbf_params = rbf_set.selector_rbf_params();

        Ok((input_candidates, rbf_params))
    }
}
