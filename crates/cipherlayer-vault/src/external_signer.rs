//! Real external-signer path (ADR-005 amendment, ADR-011, CL-WAL-010).
//!
//! This is the *first real key* path in the family — everywhere else the
//! only signer is the MOCKED `TestSigner` bound to public Anvil dev keys.
//! It is deliberately a **separate signing authority** from the `Vault`: it
//! does NOT go through `Vault::authorize_and_sign` and does NOT weaken that
//! path's development-chain-only gate. The Vault stays dev-only and mocked;
//! this adapter is the parallel, human-gated, real-testnet path.
//!
//! Key-handling invariants (enforced in code, not just documented):
//! - the private key is **never stored** on any struct here — it is read
//!   from the environment (`CIPHERLAYER_EXTERNAL_SIGNER_KEY`) only at the
//!   instant of signing, used, and dropped;
//! - the key is verified to derive to an operator-declared `expected_address`
//!   before it is used to sign anything — a wrong key signs nothing;
//! - key material never appears in `Debug`, logs, errors, or argv (signing is
//!   done in-process via alloy, never by shelling a key onto a command line);
//! - **single permitted chain, hardcoded per config**: each `ExternalSignerConfig`
//!   permits exactly one chain id (Sepolia via `::sepolia()`, or real Ethereum
//!   mainnet via `::mainnet()` — ADR-020, operator directive 2026-07-17, a
//!   deliberate, narrow exception, not a loosening: a Sepolia-configured
//!   signer still cannot sign on mainnet and there is no "any chain" mode).
//!   Development chains route to the mocked `TestSigner`, not here;
//! - signing requires an explicit `UserAuthorization` carrying an
//!   acknowledged approval, mirroring the lifecycle harness's approval phrase.
//!
//! Intended key source: an operator loader like
//! `tools/metamask-lifecycle-harness/load-cipherlayer-test-key.zsh`
//! (adapted from Arrow's `load-*-key.zsh`), which verifies derivation and
//! exports the env var for the current shell only.

use crate::{SignedTransaction, TxParams, UserAuthorization, VaultError};
use alloy::consensus::TxEnvelope;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use cipherlayer_types::{Address, ChainId};

/// The env var the operator's key loader exports. Read at sign time only.
pub const EXTERNAL_SIGNER_KEY_ENV: &str = "CIPHERLAYER_EXTERNAL_SIGNER_KEY";

/// Sepolia — the original external-signer chain (ADR-011).
pub const SEPOLIA_CHAIN_ID: u64 = 11155111;
/// Real Ethereum mainnet — permitted only via `ExternalSignerConfig::mainnet`
/// (ADR-020, operator directive 2026-07-17). A signer configured for Sepolia
/// still refuses this chain id, and vice versa: each config permits exactly
/// one chain.
pub const MAINNET_CHAIN_ID: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ExternalSignerError {
    #[error("no external signer key present: export {EXTERNAL_SIGNER_KEY_ENV} via the operator key loader")]
    NoKey,
    #[error("external signer refuses chain {0}: this config only permits chain {1}")]
    ChainNotPermitted(u64, u64),
    #[error("the supplied key derives to {derived}, not the declared operator address {expected}; the key was not used")]
    AddressMismatch { derived: Address, expected: Address },
    #[error("external signing requires an explicitly acknowledged user authorization")]
    NotAuthorized,
    #[error("key material is malformed (length/charset) — refusing; the key was not printed")]
    MalformedKey,
    #[error("signer error: {0}")]
    Signer(String),
}

impl From<ExternalSignerError> for VaultError {
    fn from(e: ExternalSignerError) -> Self {
        VaultError::Signer(e.to_string())
    }
}

/// Config for a real external signer. Holds only non-secret material: the
/// operator's expected address and the permitted testnet. The key is never
/// held here.
#[derive(Debug, Clone)]
pub struct ExternalSignerConfig {
    /// The address the runtime key must derive to (declared by the operator,
    /// e.g. via the key loader). A guard against pasting the wrong key.
    pub expected_address: Address,
    /// The only chain id this signer will sign on. Defaults to Sepolia.
    pub permitted_chain_id: u64,
}

impl ExternalSignerConfig {
    pub fn sepolia(expected_address: Address) -> Self {
        Self {
            expected_address,
            permitted_chain_id: SEPOLIA_CHAIN_ID,
        }
    }

    /// Real Ethereum mainnet (ADR-020). Real money; every other guard in this
    /// module (key never persisted, address-derivation check, required
    /// `UserAuthorization`) applies identically — the only thing that changes
    /// is which single chain id this config permits.
    pub fn mainnet(expected_address: Address) -> Self {
        Self {
            expected_address,
            permitted_chain_id: MAINNET_CHAIN_ID,
        }
    }
}

/// A real external signer whose key lives in the operator's environment, not
/// in this process's persistent state. `Debug` deliberately carries no key.
#[derive(Debug, Clone)]
pub struct LocalKeyExternalSigner {
    config: ExternalSignerConfig,
}

/// Trait for an external signing authority (real wallets, hardware, or the
/// runtime-key path here). Distinct from the Vault: an external signer holds
/// its own key and vouches for its own address; the wallet delegates, it does
/// not custody.
pub trait ExternalSignerAdapter {
    fn describe(&self) -> String;
    /// The address this signer will sign as (no key access implied).
    fn address(&self) -> Address;
}

impl LocalKeyExternalSigner {
    pub fn new(config: ExternalSignerConfig) -> Self {
        Self { config }
    }

    /// Load and validate the runtime key into an alloy signer, verifying it
    /// derives to the declared address. The returned signer holds the key;
    /// callers must use it and drop it promptly. The raw key string is
    /// overwritten before this returns.
    fn load_verified_signer(&self) -> Result<PrivateKeySigner, ExternalSignerError> {
        let mut raw =
            std::env::var(EXTERNAL_SIGNER_KEY_ENV).map_err(|_| ExternalSignerError::NoKey)?;
        let cleaned = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
        if cleaned.len() != 64 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
            raw.replace_range(.., &"0".repeat(raw.len()));
            return Err(ExternalSignerError::MalformedKey);
        }
        let signer: PrivateKeySigner = format!("0x{cleaned}")
            .parse()
            .map_err(|e| ExternalSignerError::Signer(format!("{e}")))?;
        // Overwrite the source string; the parsed signer now holds the key.
        raw.replace_range(.., &"0".repeat(raw.len()));

        let derived = signer.address();
        if derived != self.config.expected_address {
            return Err(ExternalSignerError::AddressMismatch {
                derived,
                expected: self.config.expected_address,
            });
        }
        Ok(signer)
    }

    /// Sign a transaction on the permitted testnet. Every guard is checked
    /// before the key is even loaded, except address derivation (which needs
    /// the key). Returns the signed, broadcastable artifact — this method
    /// does not broadcast.
    pub async fn sign(
        &self,
        chain_id: ChainId,
        tx: &TxParams,
        authorization: &UserAuthorization,
    ) -> Result<SignedTransaction, ExternalSignerError> {
        if chain_id.0 != self.config.permitted_chain_id {
            return Err(ExternalSignerError::ChainNotPermitted(
                chain_id.0,
                self.config.permitted_chain_id,
            ));
        }
        if !authorization.escalation_acknowledged {
            return Err(ExternalSignerError::NotAuthorized);
        }
        let signer = self.load_verified_signer()?;

        let mut request = TransactionRequest::default()
            .with_from(self.config.expected_address)
            .with_value(tx.value)
            .with_input(tx.data.clone())
            .with_nonce(tx.nonce)
            .with_gas_limit(tx.gas_limit)
            .with_gas_price(tx.gas_price_wei)
            .with_chain_id(chain_id.0);
        request = match tx.to {
            Some(to) => request.with_to(to),
            None => request.with_deploy_code(tx.data.clone()),
        };

        let wallet = EthereumWallet::from(signer);
        let envelope: TxEnvelope = request
            .build(&wallet)
            .await
            .map_err(|e| ExternalSignerError::Signer(e.to_string()))?;
        // `wallet` (and the key it holds) drops at end of scope.
        let raw = envelope.encoded_2718();
        let tx_hash = format!("{}", envelope.tx_hash());
        Ok(SignedTransaction { raw, tx_hash })
    }
}

impl ExternalSignerAdapter for LocalKeyExternalSigner {
    fn describe(&self) -> String {
        format!(
            "local-key external signer (runtime key, testnet {} only, address {})",
            self.config.permitted_chain_id, self.config.expected_address
        )
    }
    fn address(&self) -> Address {
        self.config.expected_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfirmationSurface, ANVIL_DEV_KEYS};
    use cipherlayer_types::U256;

    // Anvil dev key 0 is public and worthless; it derives to this address.
    // We use it only to exercise the derivation/guard logic offline — signing
    // is pure cryptography, no network, no value.
    const DEV0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn authz(ack: bool) -> UserAuthorization {
        UserAuthorization {
            decided_at: chrono::Utc::now(),
            surface: ConfirmationSurface::CliPrompt,
            escalation_acknowledged: ack,
        }
    }

    fn tx() -> TxParams {
        TxParams {
            to: Some(Address::from_slice(&[2u8; 20])),
            value: U256::ZERO,
            data: vec![],
            nonce: 0,
            gas_limit: 21_000,
            gas_price_wei: 1_000_000_000,
        }
    }

    fn signer_for(addr: &str) -> LocalKeyExternalSigner {
        LocalKeyExternalSigner::new(ExternalSignerConfig::sepolia(addr.parse().unwrap()))
    }

    // These tests mutate a process-global env var; keep them serial by not
    // sharing the var's expected value across concurrent cases (each sets it
    // immediately before use). Rust runs tests in threads, so we guard with a
    // mutex.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the lock intentionally serializes global env access
    async fn refuses_without_key() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var(EXTERNAL_SIGNER_KEY_ENV);
        let s = signer_for(DEV0_ADDR);
        assert!(matches!(
            s.sign(ChainId(SEPOLIA_CHAIN_ID), &tx(), &authz(true)).await,
            Err(ExternalSignerError::NoKey)
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the lock intentionally serializes global env access
    async fn refuses_non_testnet_chain_before_touching_key() {
        let _g = ENV_LOCK.lock().unwrap();
        // Even on a development chain, this path refuses — dev routes to TestSigner.
        let s = signer_for(DEV0_ADDR);
        assert!(matches!(
            s.sign(ChainId(31337), &tx(), &authz(true)).await,
            Err(ExternalSignerError::ChainNotPermitted(
                31337,
                SEPOLIA_CHAIN_ID
            ))
        ));
        // A Sepolia-configured signer still refuses mainnet (ADR-020: each
        // config permits exactly one chain — no "any chain" mode).
        assert!(matches!(
            s.sign(ChainId(1), &tx(), &authz(true)).await,
            Err(ExternalSignerError::ChainNotPermitted(1, SEPOLIA_CHAIN_ID))
        ));
    }

    /// ADR-020: a `::mainnet()` config is the mirror image — it signs on
    /// chain 1 and refuses everything else, including Sepolia. No config
    /// ever permits both.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the lock intentionally serializes global env access
    async fn mainnet_config_permits_only_mainnet() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(EXTERNAL_SIGNER_KEY_ENV, ANVIL_DEV_KEYS[0]);
        let s =
            LocalKeyExternalSigner::new(ExternalSignerConfig::mainnet(DEV0_ADDR.parse().unwrap()));
        assert!(matches!(
            s.sign(ChainId(SEPOLIA_CHAIN_ID), &tx(), &authz(true)).await,
            Err(ExternalSignerError::ChainNotPermitted(
                SEPOLIA_CHAIN_ID,
                MAINNET_CHAIN_ID
            ))
        ));
        assert!(matches!(
            s.sign(ChainId(31337), &tx(), &authz(true)).await,
            Err(ExternalSignerError::ChainNotPermitted(
                31337,
                MAINNET_CHAIN_ID
            ))
        ));
        let signed = s
            .sign(ChainId(MAINNET_CHAIN_ID), &tx(), &authz(true))
            .await
            .expect("signs with matching key and chain id on mainnet");
        assert!(signed.tx_hash.starts_with("0x"));
        std::env::remove_var(EXTERNAL_SIGNER_KEY_ENV);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the lock intentionally serializes global env access
    async fn refuses_without_acknowledged_authorization() {
        let _g = ENV_LOCK.lock().unwrap();
        let s = signer_for(DEV0_ADDR);
        assert!(matches!(
            s.sign(ChainId(SEPOLIA_CHAIN_ID), &tx(), &authz(false))
                .await,
            Err(ExternalSignerError::NotAuthorized)
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the lock intentionally serializes global env access
    async fn refuses_key_deriving_to_wrong_address() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(EXTERNAL_SIGNER_KEY_ENV, ANVIL_DEV_KEYS[0]);
        // Declared address is dev key 1's, but the env key is dev key 0's.
        let wrong = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        let s = signer_for(wrong);
        let err = s
            .sign(ChainId(SEPOLIA_CHAIN_ID), &tx(), &authz(true))
            .await
            .unwrap_err();
        assert!(matches!(err, ExternalSignerError::AddressMismatch { .. }));
        std::env::remove_var(EXTERNAL_SIGNER_KEY_ENV);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the lock intentionally serializes global env access
    async fn signs_when_key_matches_on_sepolia() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(EXTERNAL_SIGNER_KEY_ENV, ANVIL_DEV_KEYS[0]);
        let s = signer_for(DEV0_ADDR);
        let signed = s
            .sign(ChainId(SEPOLIA_CHAIN_ID), &tx(), &authz(true))
            .await
            .expect("signs with matching key on sepolia");
        assert!(signed.tx_hash.starts_with("0x"));
        assert!(!signed.raw.is_empty());
        std::env::remove_var(EXTERNAL_SIGNER_KEY_ENV);
    }

    #[test]
    fn describe_and_debug_carry_no_key() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(EXTERNAL_SIGNER_KEY_ENV, ANVIL_DEV_KEYS[0]);
        let s = signer_for(DEV0_ADDR);
        let text = format!("{} {:?}", s.describe(), s);
        for k in ANVIL_DEV_KEYS {
            assert!(!text.to_lowercase().contains(&k[2..]));
        }
        std::env::remove_var(EXTERNAL_SIGNER_KEY_ENV);
    }
}
