/// Shared test utilities for `bdk-tx` tests.
///
/// Provides helper functions for creating test inputs, outputs, and transactions
/// used across multiple test modules.
use bitcoin::{
    absolute::{self, Time},
    opcodes::all::OP_RETURN,
    script::Builder,
    secp256k1::Secp256k1,
    transaction, Amount, ScriptBuf, Transaction, TxIn, TxOut,
};
use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};

use crate::{ConfirmationStatus, Input, Output, Selection};
use alloc::vec::Vec;

pub(crate) const TEST_DESCRIPTOR: &str = "tr([83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*)";
pub(crate) const TEST_DESCRIPTOR_PK: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";

/// Create a standard Taproot test input confirmed at the given height.
pub(crate) fn setup_test_input(confirmation_height: u32) -> anyhow::Result<Input> {
    let secp = Secp256k1::new();
    let desc = Descriptor::parse_descriptor(&secp, TEST_DESCRIPTOR)
        .unwrap()
        .0;
    let def_desc = desc.at_derivation_index(0).unwrap();
    let script_pubkey = def_desc.script_pubkey();
    let desc_pk: DescriptorPublicKey = TEST_DESCRIPTOR_PK.parse()?;
    let assets = Assets::new().add(desc_pk);
    let plan = def_desc.plan(&assets).expect("failed to create plan");

    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            script_pubkey,
            value: Amount::from_sat(10_000),
        }],
    };

    let status = ConfirmationStatus {
        height: absolute::Height::from_consensus(confirmation_height)?,
        prev_mtp: Some(Time::from_consensus(500_000_000)?),
    };

    let input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;
    Ok(input)
}

/// Create a simple output with the given script and value.
pub(crate) fn create_output(script: ScriptBuf, value: u64) -> Output {
    Output::with_script(script, Amount::from_sat(value))
}

/// Create a standard P2TR output script (empty, for test purposes).
pub(crate) fn p2tr_script() -> ScriptBuf {
    let secp = Secp256k1::new();
    let desc = Descriptor::parse_descriptor(&secp, TEST_DESCRIPTOR)
        .unwrap()
        .0;
    desc.at_derivation_index(0).unwrap().script_pubkey()
}

/// Create an OP_RETURN script with the given data.
pub(crate) fn op_return_script(data: &[u8]) -> ScriptBuf {
    let push_bytes = bitcoin::script::PushBytesBuf::try_from(data.to_vec())
        .expect("data must be valid push bytes");

    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push_bytes)
        .into_script()
}

/// Create an OP_RETURN script with arbitrary-sized data
pub(crate) fn op_return_script_large(data: &[u8]) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(data.len() + 6);
    bytes.push(bitcoin::opcodes::all::OP_RETURN.to_u8());

    // Choose the minimal push opcode for the length.
    match data.len() {
        0..=75 => {
            bytes.push(data.len() as u8);
        }
        76..=255 => {
            bytes.push(0x4c); // OP_PUSHDATA1
            bytes.push(data.len() as u8);
        }
        256..=65_535 => {
            bytes.push(0x4d); // OP_PUSHDATA2
            bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        _ => {
            bytes.push(0x4e); // OP_PUSHDATA4
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        }
    }

    bytes.extend_from_slice(data);
    ScriptBuf::from_bytes(bytes)
}

/// Create a non-standard script for testing.
pub(crate) fn non_standard_script() -> ScriptBuf {
    Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_NOP)
        .push_opcode(bitcoin::opcodes::all::OP_NOP)
        .into_script()
}

/// Build a test transaction and Selection from the given inputs and outputs.
pub(crate) fn build_selection_with_tx(
    inputs: &[Input],
    outputs: &[Output],
) -> (Selection, Transaction) {
    let selection = Selection {
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|input| TxIn {
                previous_output: input.prev_outpoint(),
                ..Default::default()
            })
            .collect(),
        output: outputs.iter().map(|output| output.txout()).collect(),
    };

    (selection, tx)
}
