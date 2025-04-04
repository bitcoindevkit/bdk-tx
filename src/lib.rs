//! `bdk_tx`

#![warn(missing_docs)]
#![no_std]

extern crate alloc;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

mod coin_control; // TODO: Move into `bdk_coin_control`.
mod finalizer;
mod input; // TODO: Move into `bdk_tx_core`.
mod input_candidates;
mod output; // TODO: Move into `bdk_tx_core`.
mod rbf;
mod selection;
mod selector;
mod signer;

pub use coin_control::*;
pub use finalizer::*;
pub use input::*;
pub use input_candidates::*;
pub use miniscript;
pub use miniscript::bitcoin;
use miniscript::{DefiniteDescriptorKey, Descriptor};
pub use output::*;
pub use rbf::*;
pub use selection::*;
pub use selector::*;
pub use signer::*;

pub(crate) mod collections {
    #![allow(unused)]

    #[cfg(feature = "std")]
    pub use std::collections::*;

    #[cfg(not(feature = "std"))]
    pub type HashMap<K, V> = alloc::collections::BTreeMap<K, V>;
    pub use alloc::collections::*;
}

/// Definite descriptor.
pub type DefiniteDescriptor = Descriptor<DefiniteDescriptorKey>;
