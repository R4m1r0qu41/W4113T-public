//! The `ChainAdapter` boundary (ADR-015).
//!
//! Adapters own address parsing/validation, transaction building, fee
//! estimation, broadcast, and chain-identity verification for one chain
//! family. They do NOT own policy, risk, approval limits, the signing state
//! machine, or key material — signing stays behind `cipherlayer-vault`: an
//! adapter hands over an unsigned payload and receives signed bytes, never
//! a key.
//!
//! The surface is split read/write (Arrow's observe/settle lesson):
//! `ChainObserver` is the read-only query side, `ChainBroadcaster` the
//! build/broadcast side. Types are per-chain associated types — there is
//! deliberately no universal transaction struct.
//!
//! The registry's `network_class` development-only signing gate
//! (`ChainRegistry::ensure_signing_allowed`) is orthogonal to this trait and
//! applies to every adapter unchanged.

use cipherlayer_types::ChainId;
use std::future::Future;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// The connected node does not identify as the expected chain. Adapters
    /// must fail closed on this before building or broadcasting anything.
    #[error("chain identity mismatch: node reports chain {actual}, expected {expected} — refusing to act")]
    ChainIdentityMismatch { expected: ChainId, actual: String },
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("rpc error: {0}")]
    Rpc(String),
}

/// Read/observe surface: chain-identity verification and transaction status.
/// Implementations hold no signing authority.
pub trait ChainObserver {
    /// Per-chain transaction status observation (confirmation semantics are
    /// chain-specific: block inclusion, commitment level, confirmation depth).
    type TxStatus;

    /// Ask the connected node for its chain identity and compare it to
    /// `expected`. `Err(AdapterError::ChainIdentityMismatch)` on any mismatch
    /// — never proceed on a node that answers for the wrong chain.
    fn verify_chain_identity(
        &self,
        expected: ChainId,
    ) -> impl Future<Output = Result<(), AdapterError>> + Send;

    /// Look up the status of a previously broadcast transaction by its
    /// chain-native reference (e.g. an EVM tx hash).
    fn transaction_status(
        &self,
        tx_ref: &str,
    ) -> impl Future<Output = Result<Self::TxStatus, AdapterError>> + Send;
}

/// Build/broadcast surface. The adapter builds an *unsigned* transaction
/// (filling chain-specific fields such as nonce and fees) and broadcasts
/// *already-signed* bytes produced by the vault. It never sees key material.
pub trait ChainBroadcaster: ChainObserver {
    /// Chain-native address type.
    type Address;
    /// Caller-supplied fields for building a transaction.
    type BuildInput;
    /// Fully specified unsigned transaction, ready for the vault to sign.
    type UnsignedTx;

    /// Strict, per-chain address parsing/validation.
    fn parse_address(&self, s: &str) -> Result<Self::Address, AdapterError>;

    /// Fill in the chain-specific fields (nonce, fee estimation, gas) to
    /// produce an unsigned transaction.
    fn build_unsigned(
        &self,
        input: &Self::BuildInput,
    ) -> impl Future<Output = Result<Self::UnsignedTx, AdapterError>> + Send;

    /// Broadcast signed bytes; returns the chain-native transaction reference.
    fn broadcast(
        &self,
        raw_signed: &[u8],
    ) -> impl Future<Output = Result<String, AdapterError>> + Send;
}
