//! `bdk_tx`

#![warn(missing_docs)]
#![no_std]

extern crate alloc;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

mod create_psbt;
mod create_selection;
mod finalizer;
mod input;
mod input_candidates;
mod output;
mod signer;

pub use create_psbt::*;
pub use create_selection::*;
pub use finalizer::*;
pub use input::*;
pub use input_candidates::*;
pub use miniscript;
pub use miniscript::bitcoin;
use miniscript::{DefiniteDescriptorKey, Descriptor};
pub use output::*;
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
