//! `bdk_tx`

#![warn(missing_docs)]
#![no_std]

extern crate alloc;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

mod builder;
mod updater;

pub use builder::*;
pub use updater::*;

pub(crate) mod collections {
    #![allow(unused)]

    #[cfg(feature = "std")]
    pub use std::collections::*;

    #[cfg(not(feature = "std"))]
    pub type HashMap<K, V> = alloc::collections::BTreeMap<K, V>;
    pub use alloc::collections::*;
}
