//! `bdk_tx`
#![warn(missing_docs)]
#![no_std]

extern crate alloc;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

mod canonical_unspents;
mod finalizer;
mod input;
mod input_candidates;
mod output;
mod rbf;
mod selection;
mod selector;
mod signer;

pub use canonical_unspents::*;
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

#[cfg(feature = "std")]
pub(crate) mod collections {
    #![allow(unused)]
    pub use std::collections::*;
}

#[cfg(not(feature = "std"))]
pub(crate) mod collections {
    #![allow(unused)]
    pub type HashMap<K, V> = alloc::collections::BTreeMap<K, V>;
    pub type HashSet<T> = alloc::collections::BTreeSet<T>;
    pub use alloc::collections::*;
}

/// Definite descriptor.
pub type DefiniteDescriptor = Descriptor<DefiniteDescriptorKey>;
