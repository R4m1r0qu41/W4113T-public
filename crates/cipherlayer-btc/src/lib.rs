//! Bitcoin chain adapter (ADR-017, ADR-015 phase d). No signing authority —
//! the vault signs (secp256k1, BIP-143); this crate only builds unsigned
//! transactions and broadcasts already-signed bytes.

pub mod adapter;

pub use adapter::{
    BtcAdapter, BtcBuildInput, BtcTxStatus, BtcUnsignedTx, BtcUtxo, REGTEST_GENESIS_HASH,
};
