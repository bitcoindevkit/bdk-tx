// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::Signer;
//     use alloc::string::String;
//
//     use bitcoin::{
//         secp256k1::{self, Secp256k1},
//         Txid,
//     };
//     use miniscript::{
//         descriptor::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, KeyMap},
//         plan::Assets,
//         ForEachKey,
//     };
//
//     use bdk_chain::{
//         bdk_core, keychain_txout::KeychainTxOutIndex, local_chain::LocalChain, IndexedTxGraph,
//         TxGraph,
//     };
//     use bdk_core::{CheckPoint, ConfirmationBlockTime};
//
//     const XPRV: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
//     const WIF: &str = "cU6BxEezV8FnkEPBCaFtc4WNuUKmgFaAu6sJErB154GXgMUjhgWe";
//     const SPK: &str = "00143f027073e6f341c481f55b7baae81dda5e6a9fba";
//
//     fn get_single_sig_tr_xprv() -> Vec<String> {
//         (0..2)
//             .map(|i| format!("tr({XPRV}/86h/1h/0h/{i}/*)"))
//             .collect()
//     }
//
//     fn get_single_sig_cltv_timestamp() -> String {
//         format!("wsh(and_v(v:pk({WIF}),after(1735877503)))")
//     }
//
//     type KeychainTxGraph = IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<usize>>;
//
//     #[derive(Debug)]
//     struct TestProvider {
//         assets: Assets,
//         signer: Signer,
//         secp: Secp256k1<secp256k1::All>,
//         chain: LocalChain,
//         graph: KeychainTxGraph,
//     }
//
//     // impl DataProvider for TestProvider {
//     //     fn get_tx(&self, txid: Txid) -> Option<Transaction> {
//     //         self.graph
//     //             .graph()
//     //             .get_tx(txid)
//     //             .map(|tx| tx.as_ref().clone())
//     //     }
//     //
//     //     // fn get_descriptor_for_txout(
//     //     //     &self,
//     //     //     txout: &TxOut,
//     //     // ) -> Option<Descriptor<DefiniteDescriptorKey>> {
//     //     //     let indexer = &self.graph.index;
//     //     //
//     //     //     let (keychain, index) = indexer.index_of_spk(txout.script_pubkey.clone())?;
//     //     //     let desc = indexer.get_descriptor(*keychain)?;
//     //     //
//     //     //     desc.at_derivation_index(*index).ok()
//     //     // }
//     // }
//
//     impl TestProvider {
//         /// Set max absolute timelock
//         fn after(mut self, lt: absolute::LockTime) -> Self {
//             self.assets = self.assets.after(lt);
//             self
//         }
//
//         /// Get a reference to the tx graph
//         fn graph(&self) -> &TxGraph {
//             self.graph.graph()
//         }
//
//         /// Get a reference to the indexer
//         fn index(&self) -> &KeychainTxOutIndex<usize> {
//             &self.graph.index
//         }
//
//         /// Get the script pubkey at the specified `index` from the first keychain
//         /// (by Ord).
//         fn spk_at_index(&self, index: u32) -> Option<ScriptBuf> {
//             let keychain = self.graph.index.keychains().next().unwrap().0;
//             self.graph.index.spk_at_index(keychain, index)
//         }
//
//         /// Get next unused internal script pubkey
//         fn next_internal_spk(&mut self) -> ScriptBuf {
//             let keychain = self.graph.index.keychains().last().unwrap().0;
//             let ((_, spk), _) = self.graph.index.next_unused_spk(keychain).unwrap();
//             spk
//         }
//
//         /// Get balance
//         fn balance(&self) -> bdk_chain::Balance {
//             let chain = &self.chain;
//             let chain_tip = chain.tip().block_id();
//
//             let outpoints = self.graph.index.outpoints().clone();
//             let graph = self.graph.graph();
//             graph.balance(chain, chain_tip, outpoints, |_, _| true)
//         }
//
//         /// Get a list of planned utxos sorted largest first
//         fn planned_utxos(&self) -> Vec<Input> {
//             let chain = &self.chain;
//             let chain_tip = chain.tip().block_id();
//             let op = self.index().outpoints().clone();
//
//             let mut utxos = vec![];
//
//             for (indexed, txo) in self.graph().filter_chain_unspents(chain, chain_tip, op) {
//                 let (keychain, index) = indexed;
//                 let desc = self.index().get_descriptor(keychain).unwrap();
//                 let def = desc.at_derivation_index(index).unwrap();
//                 if let Ok(plan) = def.plan(&self.assets) {
//                     utxos.push(PlanInput {
//                         plan,
//                         outpoint: txo.outpoint,
//                         txout: txo.txout,
//                         residing_tx: None,
//                     });
//                 }
//             }
//
//             utxos.sort_by_key(|p| p.txout.value);
//             utxos.reverse();
//
//             utxos
//         }
//
//         /// Attempt to create all the required signatures for this psbt
//         fn sign(&self, psbt: &mut Psbt) {
//             let _ = psbt.sign(&self.signer, &self.secp);
//         }
//     }
//
//     macro_rules! block_id {
//         ( $height:expr, $hash:expr ) => {
//             bdk_chain::BlockId {
//                 height: $height,
//                 hash: $hash,
//             }
//         };
//     }
//
//     fn new_tx(lt: u32) -> Transaction {
//         Transaction {
//             version: transaction::Version(2),
//             lock_time: absolute::LockTime::from_consensus(lt),
//             input: vec![TxIn::default()],
//             output: vec![],
//         }
//     }
//
//     fn parse_descriptor(s: &str) -> (Descriptor<DescriptorPublicKey>, KeyMap) {
//         <Descriptor<DescriptorPublicKey>>::parse_descriptor(&Secp256k1::new(), s).unwrap()
//     }
//
//     /// Initialize a [`TestProvider`] with the given `descriptors`.
//     ///
//     /// The returned object contains a local chain at height 1000 and an indexed tx graph
//     /// with 10 x 1Msat utxos.
//     fn init_graph(descriptors: &[String]) -> TestProvider {
//         use bitcoin::{constants, hashes::Hash, Network};
//
//         let mut keys = vec![];
//         let mut keymap = KeyMap::new();
//
//         let mut index = KeychainTxOutIndex::new(10);
//         for (keychain, desc_str) in descriptors.iter().enumerate() {
//             let (desc, km) = parse_descriptor(desc_str);
//             desc.for_each_key(|k| {
//                 keys.push(k.clone());
//                 true
//             });
//             keymap.extend(km);
//             index.insert_descriptor(keychain, desc).unwrap();
//         }
//
//         let mut graph = KeychainTxGraph::new(index);
//
//         let genesis_hash = constants::genesis_block(Network::Regtest).block_hash();
//         let mut cp = CheckPoint::new(block_id!(0, genesis_hash));
//
//         for height in 1..11 {
//             let ((_, script_pubkey), _) = graph.index.reveal_next_spk(0).unwrap();
//
//             let tx = Transaction {
//                 output: vec![TxOut {
//                     value: Amount::from_btc(0.01).unwrap(),
//                     script_pubkey,
//                 }],
//                 ..new_tx(height)
//             };
//             let txid = tx.compute_txid();
//             let _ = graph.insert_tx(tx);
//
//             let block_id = block_id!(height, Hash::hash(height.to_be_bytes().as_slice()));
//             let anchor = ConfirmationBlockTime {
//                 block_id,
//                 confirmation_time: height as u64,
//             };
//             let _ = graph.insert_anchor(txid, anchor);
//
//             cp = cp.insert(block_id);
//         }
//
//         let tip = block_id!(1000, Hash::hash(b"Z"));
//         cp = cp.insert(tip);
//         let chain = LocalChain::from_tip(cp).unwrap();
//
//         let assets = Assets::new().add(keys);
//
//         TestProvider {
//             assets,
//             signer: Signer(keymap),
//             secp: Secp256k1::new(),
//             chain,
//             graph,
//         }
//     }
//
//     #[test]
//     fn test_build_tx_finalize() {
//         let mut graph = init_graph(&get_single_sig_tr_xprv());
//         assert_eq!(graph.balance().total().to_btc(), 0.1);
//
//         let recip = ScriptBuf::from_hex(SPK).unwrap();
//         let mut builder = Builder::new();
//         builder.add_output(recip, Amount::from_sat(2_500_000));
//
//         let selection = graph.planned_utxos().into_iter().take(3);
//         builder.add_inputs(selection);
//         builder.add_change_output(graph.next_internal_spk(), Amount::from_sat(499_500));
//
//         let (mut psbt, finalizer) = builder.build_tx().unwrap();
//         assert_eq!(psbt.unsigned_tx.input.len(), 3);
//         assert_eq!(psbt.unsigned_tx.output.len(), 2);
//
//         graph.sign(&mut psbt);
//         assert!(finalizer.finalize(&mut psbt).is_finalized());
//     }
//
//     #[test]
//     fn test_build_tx_insane_fee() {
//         let mut graph = init_graph(&get_single_sig_tr_xprv());
//
//         let recip = ScriptBuf::from_hex(SPK).unwrap();
//         let mut builder = Builder::new();
//         builder.add_output(recip, Amount::from_btc(0.01).unwrap());
//
//         let selection = graph
//             .planned_utxos()
//             .into_iter()
//             .take(3)
//             .collect::<Vec<_>>();
//         assert_eq!(
//             selection
//                 .iter()
//                 .map(|p| p.txout.value)
//                 .sum::<Amount>()
//                 .to_btc(),
//             0.03
//         );
//         builder.add_inputs(selection);
//
//         let err = builder.build_tx().unwrap_err();
//         assert!(matches!(err, Error::InsaneFee(..)));
//     }
//
//     #[test]
//     fn test_build_tx_negative_fee() {
//         let mut graph = init_graph(&get_single_sig_tr_xprv());
//
//         let recip = ScriptBuf::from_hex(SPK).unwrap();
//
//         let mut builder = Builder::new();
//         builder.add_output(recip, Amount::from_btc(0.02).unwrap());
//         builder.add_inputs(graph.planned_utxos().into_iter().take(1));
//
//         let err = builder.build_tx().unwrap_err();
//         assert!(matches!(err, Error::NegativeFee(..)));
//     }
//
//     #[test]
//     fn test_build_tx_add_data() {
//         let mut graph = init_graph(&get_single_sig_tr_xprv());
//
//         let mut builder = Builder::new();
//         builder.add_inputs(graph.planned_utxos().into_iter().take(1));
//         builder.add_output(graph.next_internal_spk(), Amount::from_sat(999_000));
//         builder.add_data(b"satoshi nakamoto").unwrap();
//
//         let psbt = builder.build_tx().unwrap().0;
//         assert!(psbt
//             .unsigned_tx
//             .output
//             .iter()
//             .any(|txo| txo.script_pubkey.is_op_return()));
//
//         // try to add more than 80 bytes of data
//         let data = [0x90; 81];
//         builder = Builder::new();
//         assert!(matches!(
//             builder.add_data(data),
//             Err(Error::MaxOpReturnRelay)
//         ));
//
//         // try to add more than 1 op return
//         let data = [0x90; 80];
//         builder = Builder::new();
//         builder.add_data(data).unwrap();
//         assert!(matches!(
//             builder.add_data(data),
//             Err(Error::TooManyOpReturn)
//         ));
//     }
//
//     #[test]
//     fn test_build_tx_version() {
//         use transaction::Version;
//         let mut graph = init_graph(&get_single_sig_tr_xprv());
//
//         // test default tx version (2)
//         let mut builder = Builder::new();
//         let recip = graph.spk_at_index(0).unwrap();
//         let utxo = graph.planned_utxos().first().unwrap().clone();
//         let amt = utxo.txout.value - Amount::from_sat(256);
//         builder.add_input(utxo.clone());
//         builder.add_output(recip.clone(), amt);
//
//         let psbt = builder.build_tx().unwrap().0;
//         assert_eq!(psbt.unsigned_tx.version, Version::TWO);
//
//         // allow any potentially non-standard version
//         builder = Builder::new();
//         builder.version(Version(3));
//         builder.add_input(utxo);
//         builder.add_output(recip, amt);
//
//         let psbt = builder.build_tx().unwrap().0;
//         assert_eq!(psbt.unsigned_tx.version, Version(3));
//     }
//
//     #[test]
//     fn test_timestamp_timelock() {
//         #[derive(Clone)]
//         struct InOut {
//             input: PlanInput,
//             output: (ScriptBuf, Amount),
//         }
//         fn check_locktime(graph: &mut TestProvider, in_out: InOut, lt: u32, exp_lt: Option<u32>) {
//             let InOut {
//                 input,
//                 output: (recip, amount),
//             } = in_out;
//
//             let mut builder = Builder::new();
//             builder.add_output(recip, amount);
//             builder.add_input(input);
//             builder.locktime(absolute::LockTime::from_consensus(lt));
//
//             let res = builder.build_tx();
//
//             match res {
//                 Ok((mut psbt, finalizer)) => {
//                     assert_eq!(
//                         psbt.unsigned_tx.lock_time.to_consensus_u32(),
//                         exp_lt.unwrap()
//                     );
//                     graph.sign(&mut psbt);
//                     assert!(finalizer.finalize(&mut psbt).is_finalized());
//                 }
//                 Err(e) => {
//                     assert!(exp_lt.is_none());
//                     if absolute::LockTime::from_consensus(lt).is_block_height() {
//                         assert!(matches!(e, Error::LockTypeMismatch));
//                     } else if lt < 1735877503 {
//                         assert!(matches!(e, Error::LockTimeCltv { .. }));
//                     }
//                 }
//             }
//         }
//
//         // initial state
//         let mut graph = init_graph(&[get_single_sig_cltv_timestamp()]);
//         let mut t = 1735877503;
//         let locktime = absolute::LockTime::from_consensus(t);
//
//         // supply the assets needed to create plans
//         graph = graph.after(locktime);
//
//         let in_out = InOut {
//             input: graph.planned_utxos().first().unwrap().clone(),
//             output: (ScriptBuf::from_hex(SPK).unwrap(), Amount::from_sat(999_000)),
//         };
//
//         // Test: tx should use the planned locktime
//         check_locktime(&mut graph, in_out.clone(), t, Some(t));
//
//         // Test: requesting a lower timelock should error
//         check_locktime(
//             &mut graph,
//             in_out.clone(),
//             absolute::LOCK_TIME_THRESHOLD,
//             None,
//         );
//
//         // Test: tx may use a custom locktime
//         t += 1;
//         check_locktime(&mut graph, in_out.clone(), t, Some(t));
//
//         // Test: error if lock type mismatch
//         check_locktime(&mut graph, in_out, 100, None);
//     }
//
//     #[test]
//     fn test_build_zero_fee_tx() {
//         let mut graph = init_graph(&get_single_sig_tr_xprv());
//
//         let recip = ScriptBuf::from_hex(SPK).unwrap();
//         let utxos = graph.planned_utxos();
//
//         // case: 1-in/1-out
//         let mut builder = Builder::new();
//         builder.add_inputs(utxos.iter().take(1).cloned());
//         builder.add_output(recip.clone(), Amount::from_sat(1_000_000));
//         let psbt = builder.build_tx().unwrap().0;
//         assert_eq!(psbt.unsigned_tx.output.len(), 1);
//         assert_eq!(psbt.unsigned_tx.output[0].value.to_btc(), 0.01);
//
//         // case: 1-in/2-out
//         let mut builder = Builder::new();
//         builder.add_inputs(utxos.iter().take(1).cloned());
//         builder.add_output(recip, Amount::from_sat(500_000));
//         builder.add_change_output(graph.next_internal_spk(), Amount::from_sat(500_000));
//         builder.check_fee(Some(Amount::ZERO), Some(FeeRate::from_sat_per_kwu(0)));
//
//         let psbt = builder.build_tx().unwrap().0;
//         assert_eq!(psbt.unsigned_tx.output.len(), 2);
//         assert!(psbt
//             .unsigned_tx
//             .output
//             .iter()
//             .all(|txo| txo.value.to_sat() == 500_000));
//     }
// }
