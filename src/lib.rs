#![cfg_attr(not(feature = "std"), no_std, feature(error_in_core))]
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod error;
pub mod executor;
pub mod types;
pub mod util;
