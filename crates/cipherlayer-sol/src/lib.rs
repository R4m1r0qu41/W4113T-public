//! Solana chain support (ADR-016, ADR-015 phase c).
//!
//! This crate is the read/build/broadcast adapter only. It never touches key
//! material — ed25519 signing lives behind `cipherlayer-vault`.

pub mod adapter;

pub use adapter::{SolAdapter, SolBuildInput, SolTxStatus, SolUnsignedMessage};
