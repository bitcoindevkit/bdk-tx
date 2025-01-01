#![allow(unused)]

use bdk_wallet::{KeychainKind::*, Wallet};
use bitcoin::Network;

const DESC: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
const NETWORK: Network = Network::Signet;

fn main() -> anyhow::Result<()> {
    let mut wallet = Wallet::create_single(DESC)
        .network(NETWORK)
        .create_wallet_no_persist()?;

    println!("Address: {}", wallet.next_unused_address(External));

    Ok(())
}
