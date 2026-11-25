//! The Vault (Zone D): the only component that may authorize a signature.
//!
//! Boundaries — labeled per BP §4.12 and documented in
//! docs/security/prototype-limitations.md:
//! - process isolation is available (ADR-004 addendum): `cipherlayer-vaultd`
//!   hosts this Vault behind the pinned signing-request.v1 IPC (see `ipc`);
//!   in-process use remains the CLI default.
//! - MOCKED custody: the only signer is `TestSigner`, restricted to
//!   well-known, publicly documented Anvil development keys (ADR-005).
//!   Real keys are rejected.
//! - there is no secure storage; nothing persists.
//!
//! What IS enforced, for real, in code:
//! - locked vault refuses to sign;
//! - capabilities must be valid, unexpired, unrevoked, and cover the account,
//!   chain, target contract, and value;
//! - the policy verdict must be Allow, or Escalate with an explicitly
//!   acknowledged escalation; Deny cannot be signed, ever;
//! - only `Development`-class chains may sign in this milestone;
//! - key material never leaves this crate: no accessor, no serialization,
//!   and `Debug` output is redacted.

use alloy::consensus::TxEnvelope;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder};
use alloy::primitives::B256;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer as AlloySigner;
use chrono::{DateTime, Utc};
use cipherlayer_policy::Verdict;
use cipherlayer_types::{Address, ChainId, NetworkClass, U256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod btc;
pub mod external_signer;
pub mod ipc;
pub mod sol;
pub mod sol_external_signer;
pub use btc::{
    BtcCapability, BtcCapabilityError, BtcSignedTransaction, BtcTestSigner, BtcVault,
    BtcVaultError, BtcVaultSigningRequest,
};
pub use external_signer::{
    ExternalSignerAdapter, ExternalSignerConfig, ExternalSignerError, LocalKeyExternalSigner,
};
pub use ipc::{VaultBackend, VaultClient, VaultIpcError, WireSigningRequest, WireSigningResponse};
pub use sol::{
    SolCapability, SolCapabilityError, SolSignedTransaction, SolTestSigner, SolVault,
    SolVaultError, SolVaultSigningRequest,
};
pub use sol_external_signer::{
    SolApprovalTicket, SolApprovedFacts, SolExternalSignerConfig, SolExternalSignerError,
    SolExternalSigningCeremony, SolSignedArtifact, ValidatedSolSign,
};

/// The 10 well-known Anvil development private keys (mnemonic:
/// "test test ... junk"). These are public knowledge and worthless by design.
/// TestSigner accepts ONLY these keys.
pub const ANVIL_DEV_KEYS: [&str; 10] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
];

// ---------------------------------------------------------------------------
// Capabilities (schema wallet-capability.v1 $defs/capability_grant)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScope {
    ReadOnly,
    SignTransactions,
    SignMessages,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub capability_id: Uuid,
    pub subject: String,
    pub account: Address,
    pub chain_id: ChainId,
    pub scope: CapabilityScope,
    #[serde(default)]
    pub contracts: Option<Vec<Address>>,
    #[serde(default)]
    pub max_value_wei_per_tx: Option<U256>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
    pub requires_user_confirmation: bool,
}

impl Capability {
    /// Narrow signing capability for the local CLI user.
    pub fn signing(subject: &str, account: Address, chain_id: ChainId, ttl_minutes: i64) -> Self {
        let now = Utc::now();
        Capability {
            capability_id: cipherlayer_types::new_id(),
            subject: subject.to_string(),
            account,
            chain_id,
            scope: CapabilityScope::SignTransactions,
            contracts: None,
            max_value_wei_per_tx: None,
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(ttl_minutes),
            revoked_at: None,
            requires_user_confirmation: true,
        }
    }

    /// Narrow message-signing capability (`typed_data`/`personal_message`,
    /// v0.4) — same shape as `signing()` but scoped `SignMessages`, so a
    /// transaction-signing grant can never be reused to authorize a message
    /// signature or vice versa (`validate_for_signing`/
    /// `validate_for_message_signing` each check the scope they expect).
    pub fn messages(subject: &str, account: Address, chain_id: ChainId, ttl_minutes: i64) -> Self {
        let now = Utc::now();
        Capability {
            capability_id: cipherlayer_types::new_id(),
            subject: subject.to_string(),
            account,
            chain_id,
            scope: CapabilityScope::SignMessages,
            contracts: None,
            max_value_wei_per_tx: None,
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(ttl_minutes),
            revoked_at: None,
            requires_user_confirmation: true,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("capability {0} has expired")]
    Expired(Uuid),
    #[error("capability {0} was revoked")]
    Revoked(Uuid),
    #[error("capability does not cover account {0}")]
    WrongAccount(Address),
    #[error("capability does not cover chain {0}")]
    WrongChain(ChainId),
    #[error("capability scope {0:?} does not permit transaction signing")]
    WrongScope(CapabilityScope),
    #[error("capability does not cover target contract {0}")]
    TargetNotCovered(Address),
    #[error("value {value} exceeds the capability's per-transaction cap {cap}")]
    ValueExceedsCap { value: U256, cap: U256 },
}

impl Capability {
    pub fn validate_for_signing(
        &self,
        now: DateTime<Utc>,
        account: Address,
        chain_id: ChainId,
        target: Option<Address>,
        value: U256,
    ) -> Result<(), CapabilityError> {
        if self.revoked_at.is_some() {
            return Err(CapabilityError::Revoked(self.capability_id));
        }
        if now >= self.expires_at {
            return Err(CapabilityError::Expired(self.capability_id));
        }
        if self.account != account {
            return Err(CapabilityError::WrongAccount(account));
        }
        if self.chain_id != chain_id {
            return Err(CapabilityError::WrongChain(chain_id));
        }
        if self.scope != CapabilityScope::SignTransactions {
            return Err(CapabilityError::WrongScope(self.scope));
        }
        if let (Some(allowed), Some(t)) = (&self.contracts, target) {
            if !allowed.contains(&t) {
                return Err(CapabilityError::TargetNotCovered(t));
            }
        }
        if let Some(cap) = self.max_value_wei_per_tx {
            if value > cap {
                return Err(CapabilityError::ValueExceedsCap { value, cap });
            }
        }
        Ok(())
    }

    /// Message-signing counterpart of `validate_for_signing`: no target
    /// contract or value to check (a signature is not a value transfer), but
    /// revocation/expiry/account/chain/scope are checked identically. Scope
    /// must be `SignMessages` — a transaction-signing capability does not
    /// carry authority to produce a message signature.
    pub fn validate_for_message_signing(
        &self,
        now: DateTime<Utc>,
        account: Address,
        chain_id: ChainId,
    ) -> Result<(), CapabilityError> {
        if self.revoked_at.is_some() {
            return Err(CapabilityError::Revoked(self.capability_id));
        }
        if now >= self.expires_at {
            return Err(CapabilityError::Expired(self.capability_id));
        }
        if self.account != account {
            return Err(CapabilityError::WrongAccount(account));
        }
        if self.chain_id != chain_id {
            return Err(CapabilityError::WrongChain(chain_id));
        }
        if self.scope != CapabilityScope::SignMessages {
            return Err(CapabilityError::WrongScope(self.scope));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// User authorization (schema signing-request.v1 user_authorization)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationSurface {
    /// Ordinary terminal prompt — spoofable, honestly labeled (T-12).
    CliPrompt,
    /// Deferred: W2 trusted surface.
    DesktopTrustedSurface,
    /// Deferred: hardware confirmation.
    HardwareDevice,
}

/// Only an approved decision can be represented; rejections terminate the
/// pipeline before a signing request exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAuthorization {
    pub decided_at: DateTime<Utc>,
    pub surface: ConfirmationSurface,
    pub escalation_acknowledged: bool,
}

// ---------------------------------------------------------------------------
// Signing request / signed artifact
// ---------------------------------------------------------------------------

/// Transaction parameters the pipeline fills before signing.
#[derive(Debug, Clone)]
pub struct TxParams {
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price_wei: u128,
}

/// v0.4: a signature-only payload — no on-chain transaction, so no `TxParams`
/// applies. The Vault re-derives what it signs from these raw inputs rather
/// than trusting a caller-supplied digest (the same "never blind-sign a hash"
/// discipline that keeps `eth_sign` forbidden): `TypedData` is independently
/// re-parsed via `cipherlayer_evm::typed_data::parse_typed_data`, and
/// `PersonalMessage` is hashed via the standard EIP-191 personal-message
/// prefix (`alloy::signers::Signer::sign_message`), never a pre-hashed value.
#[derive(Debug, Clone)]
pub enum MessagePayload {
    TypedData { typed_data_json: String },
    PersonalMessage { message: Vec<u8> },
}

/// The only message that can ask the Vault to sign (future IPC wire format).
/// `tx` is meaningful only when `message_payload` is `None` (kind =
/// `evm_transaction`); when `message_payload` is `Some(..)`, `tx` is an
/// unused placeholder (kept non-`Option` to avoid touching every
/// transaction-signing call site for an unrelated feature).
#[derive(Debug, Clone)]
pub struct VaultSigningRequest {
    pub signing_request_id: Uuid,
    pub request_id: Uuid,
    pub account: Address,
    pub chain_id: ChainId,
    pub network_class: NetworkClass,
    pub capability: Capability,
    pub policy_verdict: Verdict,
    pub user_authorization: UserAuthorization,
    pub tx: TxParams,
    pub message_payload: Option<MessagePayload>,
}

#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub raw: Vec<u8>,
    pub tx_hash: String,
}

/// A raw ECDSA signature (`r`, `s`, `v`) over a typed-data or personal-sign
/// digest. 65 bytes: `r`(32) || `s`(32) || `v`(1) — the same layout
/// `eth_signTypedData_v4`/`personal_sign` return to callers.
#[derive(Debug, Clone)]
pub struct MessageSignature {
    pub signature: [u8; 65],
}

impl MessageSignature {
    pub fn to_hex(&self) -> String {
        format!("0x{}", alloy::hex::encode(self.signature))
    }
}

/// What signing produced: a broadcastable transaction, or a raw signature —
/// never both, never neither.
#[derive(Debug, Clone)]
pub enum SignOutcome {
    Transaction(SignedTransaction),
    Message(MessageSignature),
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault is locked — emergency or explicit lock is in effect")]
    Locked,
    #[error("capability check failed: {0}")]
    Capability(#[from] CapabilityError),
    #[error("policy verdict {0:?} cannot be signed: a deny is final and cannot be overridden")]
    PolicyDenied(Verdict),
    #[error(
        "policy verdict was Escalate but the escalation was not explicitly acknowledged at review"
    )]
    EscalationNotAcknowledged,
    #[error("signing on {0:?}-class chains is refused in this prototype (development chains only, ADR-005/006)")]
    NonDevelopmentChain(NetworkClass),
    #[error("account {requested} does not match the vault signer {actual}")]
    AccountMismatch { requested: Address, actual: Address },
    #[error("MOCKED test signer accepts only well-known Anvil development keys; refusing what may be a real key")]
    RealKeyForbidden,
    #[error("signer error: {0}")]
    Signer(String),
    #[error("signature payload is malformed and cannot be independently re-derived: {0}")]
    InvalidPayload(String),
}

// ---------------------------------------------------------------------------
// Test signer — MOCKED custody. Keys never leave this struct.
// ---------------------------------------------------------------------------

/// MOCKED: in-memory signer for well-known Anvil dev keys only. This is not a
/// custody mechanism; it exists so the pipeline can produce real ECDSA
/// signatures on a worthless local chain.
pub struct TestSigner {
    inner: PrivateKeySigner,
}

impl std::fmt::Debug for TestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material is never printed.
        f.debug_struct("TestSigner")
            .field("address", &self.inner.address())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl TestSigner {
    /// Accepts only the 10 public Anvil development keys (ADR-005).
    pub fn from_dev_key(hex_key: &str) -> Result<Self, VaultError> {
        let normalized = hex_key.trim().to_lowercase();
        let with_prefix = if normalized.starts_with("0x") {
            normalized
        } else {
            format!("0x{normalized}")
        };
        if !ANVIL_DEV_KEYS.contains(&with_prefix.as_str()) {
            return Err(VaultError::RealKeyForbidden);
        }
        let inner: PrivateKeySigner = with_prefix
            .parse()
            .map_err(|e| VaultError::Signer(format!("{e}")))?;
        Ok(Self { inner })
    }

    pub fn address(&self) -> Address {
        self.inner.address()
    }
}

// ---------------------------------------------------------------------------
// Secure storage & external signers — interface stubs (theoretical)
// ---------------------------------------------------------------------------

/// THEORETICAL: secure storage interface. No implementation exists in
/// milestone 1; hardware/OS-keychain backends are W2+ work.
pub trait SecureStorage {
    fn store(&mut self, key_ref: &str, sealed: &[u8]) -> Result<(), VaultError>;
    fn load(&self, key_ref: &str) -> Result<Vec<u8>, VaultError>;
}

/// THEORETICAL: adapter interface for hardware wallets. No implementation in
/// milestone 1.
pub trait HardwareSignerAdapter {
    fn describe(&self) -> String;
}

// ---------------------------------------------------------------------------
// The Vault
// ---------------------------------------------------------------------------

pub struct Vault {
    signer: TestSigner,
    locked: bool,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("signer", &self.signer)
            .field("locked", &self.locked)
            .finish()
    }
}

impl Vault {
    pub fn new(signer: TestSigner) -> Self {
        Self {
            signer,
            locked: false,
        }
    }

    pub fn address(&self) -> Address {
        self.signer.address()
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Emergency / explicit lock. Takes effect immediately, including for
    /// requests already authorized but not yet signed (AC-H).
    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// The single signing gate. Every precondition is re-checked here even if
    /// the pipeline already checked it — the Vault trusts nothing upstream.
    /// Branches on `req.message_payload`: `None` signs an EVM transaction
    /// exactly as before; `Some(..)` signs a typed-data/personal-message
    /// digest that this method independently re-derives (never a caller-
    /// supplied hash — the same "never blind-sign" discipline that keeps
    /// `eth_sign` forbidden).
    pub async fn authorize_and_sign(
        &self,
        req: &VaultSigningRequest,
    ) -> Result<SignOutcome, VaultError> {
        if self.locked {
            return Err(VaultError::Locked);
        }
        // Deterministic policy outcome is final: deny can never be signed.
        match req.policy_verdict {
            Verdict::Allow => {}
            Verdict::Escalate => {
                if !req.user_authorization.escalation_acknowledged {
                    return Err(VaultError::EscalationNotAcknowledged);
                }
            }
            Verdict::Deny => return Err(VaultError::PolicyDenied(req.policy_verdict)),
        }
        // Milestone-1 gate: development chains only (worthless value by design).
        if req.network_class != NetworkClass::Development {
            return Err(VaultError::NonDevelopmentChain(req.network_class));
        }
        if req.account != self.signer.address() {
            return Err(VaultError::AccountMismatch {
                requested: req.account,
                actual: self.signer.address(),
            });
        }

        let Some(payload) = &req.message_payload else {
            req.capability.validate_for_signing(
                Utc::now(),
                req.account,
                req.chain_id,
                req.tx.to,
                req.tx.value,
            )?;

            let mut tx = TransactionRequest::default()
                .with_from(req.account)
                .with_value(req.tx.value)
                .with_input(req.tx.data.clone())
                .with_nonce(req.tx.nonce)
                .with_gas_limit(req.tx.gas_limit)
                .with_gas_price(req.tx.gas_price_wei)
                .with_chain_id(req.chain_id.0);
            tx = match req.tx.to {
                Some(to) => tx.with_to(to),
                None => tx.with_deploy_code(req.tx.data.clone()),
            };

            let wallet = EthereumWallet::from(self.signer.inner.clone());
            let envelope: TxEnvelope = tx
                .build(&wallet)
                .await
                .map_err(|e| VaultError::Signer(e.to_string()))?;
            let raw = envelope.encoded_2718();
            let tx_hash = format!("{}", envelope.tx_hash());
            return Ok(SignOutcome::Transaction(SignedTransaction { raw, tx_hash }));
        };

        req.capability
            .validate_for_message_signing(Utc::now(), req.account, req.chain_id)?;

        let signature = match payload {
            MessagePayload::TypedData { typed_data_json } => {
                let parsed = cipherlayer_evm::typed_data::parse_typed_data(typed_data_json)
                    .map_err(|e| VaultError::InvalidPayload(e.to_string()))?;
                self.signer
                    .inner
                    .sign_hash(&B256::from(parsed.signing_hash))
                    .await
                    .map_err(|e| VaultError::Signer(e.to_string()))?
            }
            MessagePayload::PersonalMessage { message } => self
                .signer
                .inner
                .sign_message(message)
                .await
                .map_err(|e| VaultError::Signer(e.to_string()))?,
        };
        Ok(SignOutcome::Message(MessageSignature {
            signature: signature.as_bytes(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> TestSigner {
        TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap()
    }

    fn base_request(vault: &Vault) -> VaultSigningRequest {
        VaultSigningRequest {
            signing_request_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            account: vault.address(),
            chain_id: ChainId(31337),
            network_class: NetworkClass::Development,
            capability: Capability::signing("cli:test", vault.address(), ChainId(31337), 60),
            policy_verdict: Verdict::Allow,
            user_authorization: UserAuthorization {
                decided_at: Utc::now(),
                surface: ConfirmationSurface::CliPrompt,
                escalation_acknowledged: false,
            },
            tx: TxParams {
                to: Some(Address::from_slice(&[2u8; 20])),
                value: U256::ZERO,
                data: vec![],
                nonce: 0,
                gas_limit: 21_000,
                gas_price_wei: 1_000_000_000,
            },
            message_payload: None,
        }
    }

    #[test]
    fn refuses_non_anvil_keys() {
        // A random (non-dev) key must be refused even though it is syntactically valid.
        let err = TestSigner::from_dev_key(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap_err();
        assert!(matches!(err, VaultError::RealKeyForbidden));
    }

    #[test]
    fn debug_output_redacts_key_material() {
        let vault = Vault::new(signer());
        let dbg = format!("{vault:?}");
        assert!(dbg.contains("<redacted>"));
        // No Anvil dev key (with or without 0x) may appear in debug output.
        for k in ANVIL_DEV_KEYS {
            assert!(!dbg.to_lowercase().contains(&k[2..]));
        }
    }

    #[tokio::test]
    async fn locked_vault_refuses_signing() {
        let mut vault = Vault::new(signer());
        vault.lock();
        let req = base_request(&vault);
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::Locked
        ));
        vault.unlock();
        assert!(vault.authorize_and_sign(&req).await.is_ok());
    }

    #[tokio::test]
    async fn deny_verdict_can_never_be_signed() {
        let vault = Vault::new(signer());
        let mut req = base_request(&vault);
        req.policy_verdict = Verdict::Deny;
        // Even with an "acknowledged" user authorization, deny is final.
        req.user_authorization.escalation_acknowledged = true;
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::PolicyDenied(_)
        ));
    }

    #[tokio::test]
    async fn escalation_requires_acknowledgement() {
        let vault = Vault::new(signer());
        let mut req = base_request(&vault);
        req.policy_verdict = Verdict::Escalate;
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::EscalationNotAcknowledged
        ));
        req.user_authorization.escalation_acknowledged = true;
        assert!(vault.authorize_and_sign(&req).await.is_ok());
    }

    #[tokio::test]
    async fn non_development_chain_refused() {
        let vault = Vault::new(signer());
        let mut req = base_request(&vault);
        req.network_class = NetworkClass::Mainnet;
        req.chain_id = ChainId(1);
        req.capability = Capability::signing("cli:test", vault.address(), ChainId(1), 60);
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::NonDevelopmentChain(NetworkClass::Mainnet)
        ));
    }

    #[tokio::test]
    async fn expired_capability_rejected() {
        let vault = Vault::new(signer());
        let mut req = base_request(&vault);
        req.capability.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::Capability(CapabilityError::Expired(_))
        ));
    }

    #[tokio::test]
    async fn capability_scope_and_target_checks() {
        let vault = Vault::new(signer());
        let mut req = base_request(&vault);
        req.capability.scope = CapabilityScope::ReadOnly;
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::Capability(CapabilityError::WrongScope(_))
        ));

        let mut req2 = base_request(&vault);
        req2.capability.contracts = Some(vec![Address::from_slice(&[9u8; 20])]);
        assert!(matches!(
            vault.authorize_and_sign(&req2).await.unwrap_err(),
            VaultError::Capability(CapabilityError::TargetNotCovered(_))
        ));
    }

    #[tokio::test]
    async fn account_mismatch_rejected() {
        let vault = Vault::new(signer());
        let mut req = base_request(&vault);
        let other = Address::from_slice(&[7u8; 20]);
        req.account = other;
        req.capability = Capability::signing("cli:test", other, ChainId(31337), 60);
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::AccountMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn signs_a_real_transaction_envelope() {
        let vault = Vault::new(signer());
        let req = base_request(&vault);
        let outcome = vault.authorize_and_sign(&req).await.unwrap();
        let SignOutcome::Transaction(signed) = outcome else {
            panic!("expected a transaction outcome");
        };
        assert!(!signed.raw.is_empty());
        assert!(signed.tx_hash.starts_with("0x"));
    }

    // -- v0.4: typed-data / personal-message signing --------------------

    fn typed_data_json(chain_id: u64) -> String {
        serde_json::json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "chainId", "type": "uint256" }
                ],
                "Mail": [{ "name": "contents", "type": "string" }]
            },
            "primaryType": "Mail",
            "domain": { "name": "Test", "chainId": chain_id },
            "message": { "contents": "hello" }
        })
        .to_string()
    }

    fn message_request(vault: &Vault, payload: MessagePayload) -> VaultSigningRequest {
        let mut req = base_request(vault);
        req.capability = Capability::messages("cli:test", vault.address(), ChainId(31337), 60);
        req.message_payload = Some(payload);
        req
    }

    #[tokio::test]
    async fn signs_typed_data_and_produces_a_real_signature() {
        let vault = Vault::new(signer());
        let req = message_request(
            &vault,
            MessagePayload::TypedData {
                typed_data_json: typed_data_json(31337),
            },
        );
        let outcome = vault.authorize_and_sign(&req).await.unwrap();
        let SignOutcome::Message(sig) = outcome else {
            panic!("expected a message outcome");
        };
        assert_eq!(sig.signature.len(), 65);
        assert!(sig.to_hex().starts_with("0x"));
        assert_eq!(sig.to_hex().len(), 2 + 65 * 2);
    }

    #[tokio::test]
    async fn signs_personal_message_via_eip191() {
        let vault = Vault::new(signer());
        let req = message_request(
            &vault,
            MessagePayload::PersonalMessage {
                message: b"hello wallet".to_vec(),
            },
        );
        let outcome = vault.authorize_and_sign(&req).await.unwrap();
        assert!(matches!(outcome, SignOutcome::Message(_)));
    }

    /// A transaction-signing capability must not authorize a message
    /// signature — the scopes are disjoint by construction.
    #[test]
    fn tx_capability_cannot_authorize_message_signing() {
        let vault = Vault::new(signer());
        let cap = Capability::signing("cli:test", vault.address(), ChainId(31337), 60);
        assert!(matches!(
            cap.validate_for_message_signing(Utc::now(), vault.address(), ChainId(31337)),
            Err(CapabilityError::WrongScope(_))
        ));
    }

    /// Malformed typed-data JSON is refused at the Vault, never blind-signed
    /// as an opaque hash — the Vault re-derives the digest itself.
    #[tokio::test]
    async fn malformed_typed_data_is_refused_not_blind_signed() {
        let vault = Vault::new(signer());
        let req = message_request(
            &vault,
            MessagePayload::TypedData {
                typed_data_json: "{ not valid".into(),
            },
        );
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::InvalidPayload(_)
        ));
    }

    /// Deny is final for message signing too — same as for transactions.
    #[tokio::test]
    async fn deny_verdict_blocks_message_signing_too() {
        let vault = Vault::new(signer());
        let mut req = message_request(
            &vault,
            MessagePayload::PersonalMessage {
                message: b"login".to_vec(),
            },
        );
        req.policy_verdict = Verdict::Deny;
        assert!(matches!(
            vault.authorize_and_sign(&req).await.unwrap_err(),
            VaultError::PolicyDenied(_)
        ));
    }
}
