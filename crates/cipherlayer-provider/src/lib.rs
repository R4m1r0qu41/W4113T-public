//! Provider broker (Zone C): the transaction-request envelope, its fail-closed
//! validation, and the dapp/caller permission model.
//!
//! Trust rules enforced here (TB1):
//! - caller identity is mandatory — identity-less envelopes are rejected;
//! - chain must exist in the registry and match the request scope;
//! - payload fields are typed and size-capped;
//! - permissions are scoped (caller, chain, access), always expire, and are
//!   checked on every request.

use chrono::{DateTime, Duration, Utc};
use cipherlayer_chain::ChainRegistry;
use cipherlayer_types::{AccessClass, Address, CallerIdentity, ChainId, U256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Hard caps (T-22): calldata ≤ 128 KiB hex-decoded, whole envelope ≤ 256 KiB JSON.
pub const MAX_CALLDATA_BYTES: usize = 128 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
/// Hard cap on a `personal_message` payload, hex-decoded. Generous headroom
/// for the largest realistic SIWE/off-chain-order message while still
/// bounding worst-case parse/display cost — same discipline as calldata.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// v0.4 (additive): what kind of signing payload the envelope carries.
/// `EvmTransaction` is the default (absent `kind` on the wire = v0.3-shaped
/// clients, unchanged behavior). `TypedData`/`PersonalMessage` are
/// consequence-bearing signature requests — they traverse the same
/// decode→policy→review→vault pipeline as a transaction, never a bypass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    #[default]
    EvmTransaction,
    TypedData,
    PersonalMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopePayload {
    pub from: String,
    /// `None` = contract creation (`kind: evm_transaction`) or not applicable
    /// (`kind: typed_data` / `personal_message`).
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub value_wei: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub gas_limit: Option<String>,
    #[serde(default)]
    pub nonce: Option<u64>,
    /// v0.4 (additive): defaults to `evm_transaction` when absent, so v0.3
    /// clients that never send `kind` are unaffected.
    #[serde(default)]
    pub kind: PayloadKind,
    /// v0.4: the full `eth_signTypedData_v4` JSON payload. Required iff
    /// `kind == typed_data`.
    #[serde(default)]
    pub typed_data_json: Option<String>,
    /// v0.4: the `personal_sign` message, `0x`-hex encoded (the raw bytes may
    /// not be valid UTF-8). Required iff `kind == personal_message`.
    #[serde(default)]
    pub message_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequestEnvelope {
    pub schema_version: String,
    pub request_id: Uuid,
    pub received_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    pub caller: CallerIdentity,
    pub chain_id: ChainId,
    pub access: AccessClass,
    pub payload: EnvelopePayload,
}

impl TransactionRequestEnvelope {
    pub fn new(
        caller: CallerIdentity,
        chain_id: ChainId,
        access: AccessClass,
        payload: EnvelopePayload,
    ) -> Self {
        Self {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            request_id: cipherlayer_types::new_id(),
            received_at: Utc::now(),
            protocol_version: None,
            caller,
            chain_id,
            access,
            payload,
        }
    }
}

/// Typed, validated view of the payload — produced only by `validate`.
/// `to`/`value`/`data`/`gas_limit`/`nonce` are meaningful for
/// `kind == EvmTransaction` only; `typed_data_json`/`message` are meaningful
/// for their respective kinds only. Kept as one flat struct (rather than a
/// payload enum) so the existing `evm_transaction` call sites are untouched.
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub gas_limit: Option<U256>,
    pub nonce: Option<u64>,
    pub kind: PayloadKind,
    /// Present iff `kind == TypedData`. Format-checked by `validate` (parses
    /// as `cipherlayer_evm::typed_data`); the actual classification/hash is
    /// computed downstream (pipeline `Decoded` step), mirroring how
    /// `decode_calldata` runs downstream of `validate` for transactions.
    pub typed_data_json: Option<String>,
    /// Present iff `kind == PersonalMessage`. Raw message bytes.
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("caller identity missing: envelopes must carry a non-empty origin or app_id")]
    MissingCallerIdentity,
    #[error("unknown chain id {0}")]
    UnknownChain(ChainId),
    /// CL-WAL-015: this pipeline decodes, scores and signs EVM payloads only.
    /// A non-EVM registry id (Solana/Bitcoin, 900000-band) must never flow
    /// through EVM decode/risk/policy toward an EVM signature; non-EVM
    /// evidence is `unknown`, and signing for those families lives behind the
    /// family-specific vault ceremonies (ADR-016/017/021).
    #[error("chain {0} belongs to the {1:?} chain family: refused by the EVM pipeline (chain family gate; evidence is unknown, never low risk)")]
    UnsupportedChainFamily(ChainId, cipherlayer_chain::ChainFamily),
    #[error("invalid `{field}` address: {reason}")]
    InvalidAddress { field: &'static str, reason: String },
    #[error("invalid `{field}` value: {reason}")]
    InvalidValue { field: &'static str, reason: String },
    #[error("calldata exceeds {MAX_CALLDATA_BYTES} bytes")]
    CalldataTooLarge,
    #[error("envelope exceeds {MAX_ENVELOPE_BYTES} bytes")]
    EnvelopeTooLarge,
    #[error("envelope is not valid JSON for schema transaction-request-envelope.v1: {0}")]
    Malformed(String),
    #[error(
        "payload.typed_data_json is required and must be well-formed for kind=typed_data: {0}"
    )]
    InvalidTypedData(String),
    #[error("payload.message_hex is required and must be 0x-prefixed hex for kind=personal_message: {0}")]
    InvalidMessage(String),
    #[error("personal_message exceeds {MAX_MESSAGE_BYTES} bytes")]
    MessageTooLarge,
}

/// Parse a raw JSON envelope with the size cap applied before anything else.
pub fn parse_envelope(raw_json: &str) -> Result<TransactionRequestEnvelope, ValidationError> {
    if raw_json.len() > MAX_ENVELOPE_BYTES {
        return Err(ValidationError::EnvelopeTooLarge);
    }
    serde_json::from_str(raw_json).map_err(|e| ValidationError::Malformed(e.to_string()))
}

/// Fail-closed validation (RECEIVED → VALIDATED gate).
pub fn validate(
    envelope: &TransactionRequestEnvelope,
    registry: &ChainRegistry,
) -> Result<ValidatedRequest, ValidationError> {
    if !envelope.caller.is_identified() {
        return Err(ValidationError::MissingCallerIdentity);
    }
    let entry = registry
        .get(envelope.chain_id)
        .map_err(|_| ValidationError::UnknownChain(envelope.chain_id))?;
    // Deterministic family gate, evaluated before any address parsing or RPC.
    if entry.chain_family != cipherlayer_chain::ChainFamily::Evm {
        return Err(ValidationError::UnsupportedChainFamily(
            envelope.chain_id,
            entry.chain_family,
        ));
    }

    let from = cipherlayer_evm::parse_address(&envelope.payload.from).map_err(|e| {
        ValidationError::InvalidAddress {
            field: "from",
            reason: e.to_string(),
        }
    })?;
    let to = match &envelope.payload.to {
        Some(s) => Some(cipherlayer_evm::parse_address(s).map_err(|e| {
            ValidationError::InvalidAddress {
                field: "to",
                reason: e.to_string(),
            }
        })?),
        None => None,
    };
    let value = match &envelope.payload.value_wei {
        Some(v) => U256::from_str_radix(v, 10).map_err(|e| ValidationError::InvalidValue {
            field: "value_wei",
            reason: e.to_string(),
        })?,
        None => U256::ZERO,
    };
    let data = match &envelope.payload.data {
        Some(d) => {
            let stripped = d
                .strip_prefix("0x")
                .ok_or_else(|| ValidationError::InvalidValue {
                    field: "data",
                    reason: "must be 0x-prefixed hex".into(),
                })?;
            let bytes = hex::decode(stripped).map_err(|e| ValidationError::InvalidValue {
                field: "data",
                reason: e.to_string(),
            })?;
            if bytes.len() > MAX_CALLDATA_BYTES {
                return Err(ValidationError::CalldataTooLarge);
            }
            bytes
        }
        None => Vec::new(),
    };
    let gas_limit = match &envelope.payload.gas_limit {
        Some(g) => {
            Some(
                U256::from_str_radix(g, 10).map_err(|e| ValidationError::InvalidValue {
                    field: "gas_limit",
                    reason: e.to_string(),
                })?,
            )
        }
        None => None,
    };

    // v0.4: signature-payload kinds are format-checked here (fail closed on
    // malformed input, same discipline as `data` above); the actual
    // classification/hash computation happens downstream at the pipeline's
    // Decoded step, mirroring `decode_calldata`.
    let (typed_data_json, message) = match envelope.payload.kind {
        PayloadKind::EvmTransaction => (None, None),
        PayloadKind::TypedData => {
            let raw = envelope.payload.typed_data_json.as_deref().ok_or_else(|| {
                ValidationError::InvalidTypedData(
                    "typed_data_json is required for kind=typed_data".into(),
                )
            })?;
            cipherlayer_evm::typed_data::parse_typed_data(raw)
                .map_err(|e| ValidationError::InvalidTypedData(e.to_string()))?;
            (Some(raw.to_string()), None)
        }
        PayloadKind::PersonalMessage => {
            let raw = envelope.payload.message_hex.as_deref().ok_or_else(|| {
                ValidationError::InvalidMessage(
                    "message_hex is required for kind=personal_message".into(),
                )
            })?;
            let stripped = raw
                .strip_prefix("0x")
                .ok_or_else(|| ValidationError::InvalidMessage("must be 0x-prefixed hex".into()))?;
            let bytes = hex::decode(stripped)
                .map_err(|e| ValidationError::InvalidMessage(e.to_string()))?;
            if bytes.len() > MAX_MESSAGE_BYTES {
                return Err(ValidationError::MessageTooLarge);
            }
            (None, Some(bytes))
        }
    };

    Ok(ValidatedRequest {
        from,
        to,
        value,
        data,
        gas_limit,
        nonce: envelope.payload.nonce,
        kind: envelope.payload.kind,
        typed_data_json,
        message,
    })
}

// ---------------------------------------------------------------------------
// Signing response (schema signing-response.v1) — the wallet's answer on the
// browser-connect wire. Never contains key material.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefusalReason {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResponse {
    pub schema_version: String,
    pub signing_response_id: Uuid,
    /// `None` = the request was refused before a Vault signing request ever
    /// existed (validation/permission/policy refusal) — schema v1.1 semantics.
    pub signing_request_id: Option<Uuid>,
    pub request_id: Uuid,
    pub responded_at: DateTime<Utc>,
    /// Lifecycle state at response time (SCREAMING_SNAKE_CASE on the wire).
    pub state: cipherlayer_types::state::LifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// v1.3 (additive): the raw signature (`0x` + 130 hex chars, r/s/v) for
    /// `typed_data`/`personal_message` requests. `None` for `evm_transaction`
    /// requests (which carry `tx_hash` instead) and for any refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    pub refusal_reasons: Vec<RefusalReason>,
    /// Audit-log sequence of the last event for this request.
    pub audit_head_sequence: u64,
    /// v1.2 (additive, optional): display-only pipeline evidence so a
    /// browser shell can show *why* the wallet decided what it decided
    /// (decoded intent, simulation outcome, risk level + detector findings,
    /// policy verdict/reasons). Pure annotation: it carries no authority,
    /// nothing consumes it wallet-side, and the confirmation decision stays
    /// on the wallet's trusted surface regardless of what a consumer renders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_evidence: Option<ReviewEvidence>,
}

/// Display-only evidence summary (strings/enum names only — no addresses of
/// authority, no key material, no override hooks). See `SigningResponse::
/// review_evidence`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewEvidence {
    /// Decoded action kind (+ function signature when known).
    pub decoded_action: String,
    /// Intent decoding confidence (Exact/Partial/Unknown).
    pub intent_confidence: String,
    /// Simulation outcome + standing-limitation count; `None` = simulation
    /// never ran (refused earlier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation: Option<String>,
    /// Aggregated risk level; UNKNOWN is spelled out, never softened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// Individual detector findings (scam-guard et al.).
    #[serde(default)]
    pub risk_findings: Vec<RiskFindingSummary>,
    /// Detectors that were configured but unavailable (absence is evidence).
    #[serde(default)]
    pub detectors_unavailable: Vec<String>,
    /// Policy verdict (Allow/Escalate/Deny); `None` = policy never ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_verdict: Option<String>,
    /// Policy reasons, `CODE: detail`.
    #[serde(default)]
    pub policy_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFindingSummary {
    pub detector: String,
    pub risk_level: String,
    pub reason_codes: Vec<String>,
    pub explanation: String,
}

// ---------------------------------------------------------------------------
// Wallet capability advertisement (schema wallet-capability.v1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCapability {
    pub schema_version: String,
    pub advertised_at: DateTime<Utc>,
    pub protocol_versions: Vec<String>,
    pub chains: Vec<u64>,
    /// Supported request methods; unlisted methods are rejected, not ignored.
    pub methods: Vec<String>,
    pub signer_kinds: Vec<String>,
}

impl WalletCapability {
    /// Milestone-truthful advertisement: one dev chain, transaction signing
    /// only, test signer only.
    pub fn current(registry: &ChainRegistry) -> Self {
        WalletCapability {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            advertised_at: Utc::now(),
            protocol_versions: vec!["0.1".into(), "0.3".into(), "0.4".into()],
            // The capability wire surface is EIP-1193-shaped, so only
            // EVM-family chain ids belong on it: the reserved 900000-band
            // internal ids (Solana/Bitcoin registry keys) must never leave
            // the registry (ADR-016 §3, ADR-021).
            chains: registry
                .entries()
                .iter()
                .filter(|e| e.chain_family == cipherlayer_chain::ChainFamily::Evm)
                .map(|e| e.chain_id.0)
                .collect(),
            methods: vec![
                "host_attest".into(),
                "connect_request".into(),
                "transaction_request".into(),
                "permission_revoke".into(),
                "capability_query".into(),
                // v0.4: transaction_request now also carries payload.kind
                // typed_data / personal_message (additive; see the protocol
                // doc). rpc_query is a new, separate read-only wire message.
                "rpc_query".into(),
            ],
            signer_kinds: vec!["test".into()],
        }
    }
}

// ---------------------------------------------------------------------------
// Permissions (schema dapp-permission.v1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub schema_version: String,
    pub permission_id: Uuid,
    pub caller_key: String,
    pub chain_id: ChainId,
    pub access: AccessClass,
    pub accounts: Vec<Address>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Permission {
    pub fn status(&self, now: DateTime<Utc>) -> PermissionStatus {
        if self.revoked_at.is_some() {
            PermissionStatus::Revoked
        } else if now >= self.expires_at {
            PermissionStatus::Expired
        } else {
            PermissionStatus::Active
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    #[error("no permission for caller `{caller}` on chain {chain} with {access:?} access")]
    NotGranted {
        caller: String,
        chain: ChainId,
        access: AccessClass,
    },
    #[error("permission {0} for caller `{1}` has expired")]
    Expired(Uuid, String),
    #[error("permission {0} was revoked")]
    Revoked(Uuid),
    #[error("account {0} is not covered by the permission")]
    AccountNotCovered(Address),
}

/// Permission store with optional JSON-file persistence (W1-remainder item,
/// implemented). The file is plain JSON — grants are not secrets (they name
/// public accounts and scopes) and the wallet re-validates status on every
/// check; tampering with the file can at most *revoke* effective access
/// early or extend a caller_key's window until the next legitimate save,
/// and every grant/revoke remains hash-chained in the audit log.
#[derive(Debug, Default)]
pub struct PermissionStore {
    permissions: Vec<Permission>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PermissionFile {
    schema_version: String,
    permissions: Vec<Permission>,
}

#[derive(Debug, thiserror::Error)]
pub enum PermissionStoreError {
    #[error("permission store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("permission store file is not valid: {0}")]
    Corrupt(String),
}

impl PermissionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file; a missing file is an empty store (first run).
    /// A corrupt file is an error, never silently treated as empty.
    pub fn load_from(path: &std::path::Path) -> Result<Self, PermissionStoreError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        let file: PermissionFile =
            serde_json::from_str(&raw).map_err(|e| PermissionStoreError::Corrupt(e.to_string()))?;
        Ok(Self {
            permissions: file.permissions,
        })
    }

    /// Atomic: writes to a same-directory temp file, then renames over the
    /// target, so a crash mid-write can never leave a truncated store (a
    /// corrupt store is a hard error on load, which would otherwise trade a
    /// crash for an outage).
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), PermissionStoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = PermissionFile {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            permissions: self.permissions.clone(),
        };
        let json = serde_json::to_string_pretty(&file).expect("permissions serialize");
        // Per-process temp name: the designed-for writers are the daemon plus
        // a concurrent CLI invocation, and a shared temp path would let their
        // interleaved writes be renamed into place as a garbled store.
        let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// An active grant covering (caller, chain, access, account), if any.
    pub fn find_active(
        &self,
        caller: &CallerIdentity,
        chain_id: ChainId,
        access: AccessClass,
        account: Address,
    ) -> Option<&Permission> {
        let key = caller.key();
        let now = Utc::now();
        self.permissions.iter().find(|p| {
            p.caller_key == key
                && p.chain_id == chain_id
                && p.access == access
                && p.accounts.contains(&account)
                && p.status(now) == PermissionStatus::Active
        })
    }

    /// v0.4: does this caller hold *any* active grant on `chain_id`,
    /// regardless of access class or account? Used for the `rpc_query`
    /// read-only proxy — read-only-class grants suffice (a signing grant
    /// implies at least as much access, so it suffices too), and the query
    /// itself is not scoped to one specific account the way a signing
    /// request is.
    pub fn has_any_active(&self, caller: &CallerIdentity, chain_id: ChainId) -> bool {
        let key = caller.key();
        let now = Utc::now();
        self.permissions.iter().any(|p| {
            p.caller_key == key
                && p.chain_id == chain_id
                && p.status(now) == PermissionStatus::Active
        })
    }

    pub fn grant(
        &mut self,
        caller: &CallerIdentity,
        chain_id: ChainId,
        access: AccessClass,
        accounts: Vec<Address>,
        ttl: Duration,
    ) -> Permission {
        let now = Utc::now();
        let p = Permission {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            permission_id: cipherlayer_types::new_id(),
            caller_key: caller.key(),
            chain_id,
            access,
            accounts,
            granted_at: now,
            expires_at: now + ttl,
            revoked_at: None,
        };
        self.permissions.push(p.clone());
        p
    }

    pub fn revoke(&mut self, permission_id: Uuid) -> bool {
        let now = Utc::now();
        let mut found = false;
        for p in &mut self.permissions {
            if p.permission_id == permission_id && p.revoked_at.is_none() {
                p.revoked_at = Some(now);
                found = true;
            }
        }
        found
    }

    pub fn list(&self) -> &[Permission] {
        &self.permissions
    }

    /// PERMISSION_CHECKED gate: an active grant must cover caller+chain+access+account.
    pub fn check(
        &self,
        caller: &CallerIdentity,
        chain_id: ChainId,
        access: AccessClass,
        account: Address,
    ) -> Result<&Permission, PermissionError> {
        let key = caller.key();
        let now = Utc::now();
        let candidates: Vec<&Permission> = self
            .permissions
            .iter()
            .filter(|p| p.caller_key == key && p.chain_id == chain_id && p.access == access)
            .collect();
        if candidates.is_empty() {
            return Err(PermissionError::NotGranted {
                caller: key,
                chain: chain_id,
                access,
            });
        }
        // Prefer an active grant; otherwise report the most specific failure.
        for p in &candidates {
            if p.status(now) == PermissionStatus::Active {
                if p.accounts.contains(&account) {
                    return Ok(p);
                }
                return Err(PermissionError::AccountNotCovered(account));
            }
        }
        let p = candidates[0];
        match p.status(now) {
            PermissionStatus::Revoked => Err(PermissionError::Revoked(p.permission_id)),
            _ => Err(PermissionError::Expired(p.permission_id, key)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherlayer_types::CallerKind;

    fn cli_caller() -> CallerIdentity {
        CallerIdentity {
            kind: CallerKind::Cli,
            origin: None,
            app_id: Some("cli:test".into()),
            capsule_id: None,
        }
    }

    fn anon_caller() -> CallerIdentity {
        CallerIdentity {
            kind: CallerKind::Dapp,
            origin: None,
            app_id: None,
            capsule_id: None,
        }
    }

    fn payload() -> EnvelopePayload {
        EnvelopePayload {
            from: "0x00000000000000000000000000000000000000aa".into(),
            to: Some("0x00000000000000000000000000000000000000bb".into()),
            value_wei: Some("0".into()),
            data: Some("0x".into()),
            gas_limit: None,
            nonce: None,
            kind: PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        }
    }

    #[test]
    fn identityless_envelope_rejected() {
        let env = TransactionRequestEnvelope::new(
            anon_caller(),
            ChainId(31337),
            AccessClass::Signing,
            payload(),
        );
        let err = validate(&env, &ChainRegistry::builtin()).unwrap_err();
        assert!(matches!(err, ValidationError::MissingCallerIdentity));
    }

    #[test]
    fn unknown_chain_rejected() {
        let env = TransactionRequestEnvelope::new(
            cli_caller(),
            ChainId(999999),
            AccessClass::Signing,
            payload(),
        );
        assert!(matches!(
            validate(&env, &ChainRegistry::builtin()).unwrap_err(),
            ValidationError::UnknownChain(_)
        ));
    }

    #[test]
    fn non_evm_family_rejected_before_address_parsing() {
        // Every non-EVM registry entry is refused with the family error, even
        // when the payload is otherwise a valid EVM envelope.
        let registry = ChainRegistry::builtin();
        let non_evm: Vec<_> = registry
            .entries()
            .iter()
            .filter(|e| e.chain_family != cipherlayer_chain::ChainFamily::Evm)
            .collect();
        assert!(!non_evm.is_empty());
        for e in non_evm {
            let env = TransactionRequestEnvelope::new(
                cli_caller(),
                e.chain_id,
                AccessClass::Signing,
                payload(),
            );
            assert!(matches!(
                validate(&env, &registry).unwrap_err(),
                ValidationError::UnsupportedChainFamily(id, fam)
                    if id == e.chain_id && fam == e.chain_family
            ));
        }
    }

    #[test]
    fn bad_hex_and_oversize_rejected() {
        let mut p = payload();
        p.data = Some("0xzz".into());
        let env =
            TransactionRequestEnvelope::new(cli_caller(), ChainId(31337), AccessClass::Signing, p);
        assert!(validate(&env, &ChainRegistry::builtin()).is_err());

        let mut p2 = payload();
        p2.data = Some(format!("0x{}", "00".repeat(MAX_CALLDATA_BYTES + 1)));
        let env2 =
            TransactionRequestEnvelope::new(cli_caller(), ChainId(31337), AccessClass::Signing, p2);
        assert!(matches!(
            validate(&env2, &ChainRegistry::builtin()).unwrap_err(),
            ValidationError::CalldataTooLarge
        ));
    }

    #[test]
    fn malformed_json_rejected() {
        assert!(parse_envelope("{not json").is_err());
        let oversized = format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_ENVELOPE_BYTES));
        assert!(matches!(
            parse_envelope(&oversized).unwrap_err(),
            ValidationError::EnvelopeTooLarge
        ));
    }

    #[test]
    fn permission_lifecycle() {
        let mut store = PermissionStore::new();
        let caller = cli_caller();
        let account = Address::from_slice(&[0xaa; 20]);
        // Not granted yet.
        assert!(matches!(
            store.check(&caller, ChainId(31337), AccessClass::Signing, account),
            Err(PermissionError::NotGranted { .. })
        ));
        // Granted.
        let p = store.grant(
            &caller,
            ChainId(31337),
            AccessClass::Signing,
            vec![account],
            Duration::hours(1),
        );
        assert!(store
            .check(&caller, ChainId(31337), AccessClass::Signing, account)
            .is_ok());
        // Wrong account.
        let other = Address::from_slice(&[0xbb; 20]);
        assert!(matches!(
            store.check(&caller, ChainId(31337), AccessClass::Signing, other),
            Err(PermissionError::AccountNotCovered(_))
        ));
        // Revoked.
        assert!(store.revoke(p.permission_id));
        assert!(matches!(
            store.check(&caller, ChainId(31337), AccessClass::Signing, account),
            Err(PermissionError::Revoked(_))
        ));
    }

    #[test]
    fn permission_store_persists_and_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permissions.json");
        let caller = cli_caller();
        let account = Address::from_slice(&[0xaa; 20]);

        let mut store = PermissionStore::new();
        let p = store.grant(
            &caller,
            ChainId(31337),
            AccessClass::Signing,
            vec![account],
            Duration::hours(1),
        );
        store.save_to(&path).unwrap();

        let reloaded = PermissionStore::load_from(&path).unwrap();
        assert!(reloaded
            .check(&caller, ChainId(31337), AccessClass::Signing, account)
            .is_ok());
        assert!(reloaded
            .find_active(&caller, ChainId(31337), AccessClass::Signing, account)
            .is_some());

        // Revocation persists too.
        let mut reloaded = reloaded;
        assert!(reloaded.revoke(p.permission_id));
        reloaded.save_to(&path).unwrap();
        let again = PermissionStore::load_from(&path).unwrap();
        assert!(matches!(
            again.check(&caller, ChainId(31337), AccessClass::Signing, account),
            Err(PermissionError::Revoked(_))
        ));
    }

    #[test]
    fn missing_file_is_empty_but_corrupt_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert!(PermissionStore::load_from(&missing)
            .unwrap()
            .list()
            .is_empty());

        let corrupt = dir.path().join("corrupt.json");
        std::fs::write(&corrupt, "{ not json").unwrap();
        assert!(matches!(
            PermissionStore::load_from(&corrupt),
            Err(PermissionStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn save_is_atomic_no_temp_residue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permissions.json");
        let caller = cli_caller();
        let account = Address::from_slice(&[0xaa; 20]);
        let mut store = PermissionStore::new();
        store.grant(
            &caller,
            ChainId(31337),
            AccessClass::Signing,
            vec![account],
            Duration::hours(1),
        );
        store.save_to(&path).unwrap();
        // The temp file must not survive a successful save, and the target
        // must be a complete, loadable store.
        assert!(!path
            .with_extension(format!("json.tmp.{}", std::process::id()))
            .exists());
        assert!(PermissionStore::load_from(&path)
            .unwrap()
            .check(&caller, ChainId(31337), AccessClass::Signing, account)
            .is_ok());
    }

    /// Security regression (2026-07-16 review finding): a process that keeps
    /// the store in memory and later saves a stale copy would resurrect a
    /// grant revoked on disk by another process. The required discipline is
    /// reload-before-mutate-or-save (what the CLI does per invocation and
    /// what `connect serve` now does per request); this test pins the
    /// disk-is-source-of-truth semantics that discipline relies on.
    #[test]
    fn stale_copy_reloaded_before_save_cannot_resurrect_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permissions.json");
        let caller = cli_caller();
        let account = Address::from_slice(&[0xaa; 20]);

        // Process A grants and persists, then holds its copy in memory.
        let mut process_a = PermissionStore::new();
        let p = process_a.grant(
            &caller,
            ChainId(31337),
            AccessClass::Signing,
            vec![account],
            Duration::hours(1),
        );
        process_a.save_to(&path).unwrap();

        // Process B (the CLI) revokes on disk.
        let mut process_b = PermissionStore::load_from(&path).unwrap();
        assert!(process_b.revoke(p.permission_id));
        process_b.save_to(&path).unwrap();

        // Process A follows the reload discipline before its next save:
        // the revocation must survive A's save.
        process_a = PermissionStore::load_from(&path).unwrap();
        process_a.save_to(&path).unwrap();
        let final_state = PermissionStore::load_from(&path).unwrap();
        assert!(matches!(
            final_state.check(&caller, ChainId(31337), AccessClass::Signing, account),
            Err(PermissionError::Revoked(_))
        ));
    }

    /// v0.4: `has_any_active` (the `rpc_query` gate) is satisfied by a
    /// read-only grant, by a signing grant, and by neither once revoked —
    /// but is chain-scoped (a grant on another chain does not count).
    #[test]
    fn has_any_active_covers_either_access_class_but_not_other_chains() {
        let mut store = PermissionStore::new();
        let caller = cli_caller();
        let account = Address::from_slice(&[0xaa; 20]);
        assert!(!store.has_any_active(&caller, ChainId(31337)));

        let p = store.grant(
            &caller,
            ChainId(31337),
            AccessClass::ReadOnly,
            vec![account],
            Duration::hours(1),
        );
        assert!(store.has_any_active(&caller, ChainId(31337)));
        assert!(!store.has_any_active(&caller, ChainId(1)));

        assert!(store.revoke(p.permission_id));
        assert!(!store.has_any_active(&caller, ChainId(31337)));

        store.grant(
            &caller,
            ChainId(31337),
            AccessClass::Signing,
            vec![account],
            Duration::hours(1),
        );
        assert!(store.has_any_active(&caller, ChainId(31337)));
    }

    #[test]
    fn expired_permission_rejected() {
        let mut store = PermissionStore::new();
        let caller = cli_caller();
        let account = Address::from_slice(&[0xaa; 20]);
        store.grant(
            &caller,
            ChainId(31337),
            AccessClass::Signing,
            vec![account],
            Duration::seconds(-1), // already expired
        );
        assert!(matches!(
            store.check(&caller, ChainId(31337), AccessClass::Signing, account),
            Err(PermissionError::Expired(_, _))
        ));
    }

    /// v1.2 compatibility: a pre-v1.2 signing-response (no review_evidence)
    /// still deserializes, and the field is omitted on the wire when absent —
    /// additive-minor discipline for the browser-connect contract.
    #[test]
    fn signing_response_review_evidence_is_optional_and_additive() {
        let old_wire = serde_json::json!({
            "schema_version": "1.0",
            "signing_response_id": "018f0000-0000-7000-8000-000000000001",
            "signing_request_id": null,
            "request_id": "018f0000-0000-7000-8000-000000000002",
            "responded_at": "2026-07-09T00:00:00Z",
            "state": "POLICY_DENIED",
            "refusal_reasons": [],
            "audit_head_sequence": 3
        });
        let parsed: SigningResponse = serde_json::from_value(old_wire).unwrap();
        assert!(parsed.review_evidence.is_none());
        let round = serde_json::to_value(&parsed).unwrap();
        assert!(round.get("review_evidence").is_none());
    }
}
