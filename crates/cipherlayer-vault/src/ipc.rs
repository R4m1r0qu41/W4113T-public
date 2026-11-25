//! Vault IPC (ADR-004 W2): the wire format and client for the Vault as a
//! separate OS process (`cipherlayer-vaultd`).
//!
//! The request wire format IS the pinned `schemas/signing-request.v1.json` —
//! written from day one as the future IPC format, so this module is a
//! transport change, not a redesign. Two pipeline-side facts the daemon
//! cannot look up across the process boundary (the policy verdict and the
//! chain's network class) travel in the schema's `ext` field; the daemon
//! still refuses anything but allow / acknowledged-escalate, exactly like
//! the in-process Vault.
//!
//! The response is `schemas/vault-signing-response.v1.json`: the signed
//! artifact or a coded refusal. Key material never appears on the wire in
//! either direction.

use crate::{
    Capability, ConfirmationSurface, MessagePayload, MessageSignature, SignOutcome,
    SignedTransaction, TxParams, UserAuthorization, VaultError, VaultSigningRequest,
};
use chrono::{DateTime, Utc};
use cipherlayer_policy::Verdict;
use cipherlayer_types::{Address, ChainId, NetworkClass, U256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const WIRE_SCHEMA_VERSION: &str = "1.0";

// ---------------------------------------------------------------------------
// Request (signing-request.v1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireUserAuthorization {
    /// Schema const: only approved authorizations exist at this point.
    pub decision: String,
    pub decided_at: DateTime<Utc>,
    pub surface: ConfirmationSurface,
    pub escalation_acknowledged: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTx {
    pub to: Option<Address>,
    pub value: U256,
    pub data_hex: String,
    pub nonce: u64,
    pub gas_limit: u64,
    /// Decimal string: tagged-enum deserialization cannot carry u128, and the
    /// pinned schemas already put wei quantities on the wire as strings.
    pub gas_price_wei: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePayload {
    /// `evm_transaction` | `typed_data` | `personal_message` (v0.4).
    pub kind: String,
    /// Present iff `kind == evm_transaction`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<WireTx>,
    /// Present iff `kind == typed_data`: the full EIP-712 JSON payload. The
    /// Vault re-parses and re-hashes it independently — never a
    /// caller-supplied hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_data_json: Option<String>,
    /// Present iff `kind == personal_message`: the raw message, hex-encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_hex: Option<String>,
}

/// Deterministic evidence for the Vault-side confirmation surface: only what
/// the pipeline derived (decoded intent, simulation, risk, policy). No
/// advisory text, no caller-controlled styling — strings are rendered
/// verbatim inside system-owned chrome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireDisplayEvidence {
    pub intent: String,
    pub chain: String,
    pub simulation: String,
    pub risk: String,
    pub policy_reasons: Vec<String>,
}

/// Pipeline facts the daemon cannot re-derive across the boundary. The daemon
/// treats them exactly as the in-process Vault treats its parameters: a claim
/// to validate against its own rules, never a bypass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireExt {
    pub policy_verdict: Verdict,
    pub network_class: NetworkClass,
    /// Present on confirm_and_sign requests: what the surface must show.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<WireDisplayEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSigningRequest {
    pub schema_version: String,
    pub signing_request_id: Uuid,
    pub request_id: Uuid,
    pub intent_id: Uuid,
    pub decision_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub account: Address,
    pub chain_id: ChainId,
    pub capability: Capability,
    /// v1.2: nullable. `null` = the caller holds no user decision and asks
    /// the Vault-side surface to obtain one (confirm_and_sign only);
    /// pre-authorized sign_request requires it present.
    pub user_authorization: Option<WireUserAuthorization>,
    pub payload: WirePayload,
    pub ext: WireExt,
}

impl WireSigningRequest {
    pub fn from_request(req: &VaultSigningRequest, intent_id: Uuid, decision_id: Uuid) -> Self {
        WireSigningRequest {
            schema_version: WIRE_SCHEMA_VERSION.into(),
            signing_request_id: req.signing_request_id,
            request_id: req.request_id,
            intent_id,
            decision_id,
            created_at: Utc::now(),
            account: req.account,
            chain_id: req.chain_id,
            capability: req.capability.clone(),
            user_authorization: Some(WireUserAuthorization {
                decision: "approved".into(),
                decided_at: req.user_authorization.decided_at,
                surface: req.user_authorization.surface,
                escalation_acknowledged: Some(req.user_authorization.escalation_acknowledged),
            }),
            payload: WirePayload {
                kind: "evm_transaction".into(),
                transaction: Some(WireTx {
                    to: req.tx.to,
                    value: req.tx.value,
                    data_hex: format!("0x{}", alloy::hex::encode(&req.tx.data)),
                    nonce: req.tx.nonce,
                    gas_limit: req.tx.gas_limit,
                    gas_price_wei: req.tx.gas_price_wei.to_string(),
                }),
                typed_data_json: None,
                message_hex: None,
            },
            ext: WireExt {
                policy_verdict: req.policy_verdict,
                network_class: req.network_class,
                display: None,
            },
        }
    }

    /// v0.4: a `typed_data`/`personal_message` signing request. `req.tx` is
    /// ignored (unused placeholder for non-transaction payloads); the wire
    /// carries the raw payload so the Vault can independently re-derive what
    /// it signs, never a pre-computed hash.
    pub fn from_message_request(
        req: &VaultSigningRequest,
        payload: &MessagePayload,
        intent_id: Uuid,
        decision_id: Uuid,
    ) -> Self {
        let mut wire = Self::from_request(req, intent_id, decision_id);
        wire.payload = match payload {
            MessagePayload::TypedData { typed_data_json } => WirePayload {
                kind: "typed_data".into(),
                transaction: None,
                typed_data_json: Some(typed_data_json.clone()),
                message_hex: None,
            },
            MessagePayload::PersonalMessage { message } => WirePayload {
                kind: "personal_message".into(),
                transaction: None,
                typed_data_json: None,
                message_hex: Some(format!("0x{}", alloy::hex::encode(message))),
            },
        };
        wire
    }

    /// A confirm_and_sign request: no user decision yet — the Vault-side
    /// surface must obtain it. `req.user_authorization` is ignored and
    /// stripped; `display` is what the surface will render.
    pub fn for_confirmation(
        req: &VaultSigningRequest,
        intent_id: Uuid,
        decision_id: Uuid,
        display: WireDisplayEvidence,
    ) -> Self {
        let mut wire = Self::from_request(req, intent_id, decision_id);
        wire.user_authorization = None;
        wire.ext.display = Some(display);
        wire
    }

    /// Daemon-side mapping back to the request the Vault validates. Refuses
    /// unknown schema versions and payload kinds rather than guessing.
    pub fn into_request(self) -> Result<VaultSigningRequest, String> {
        if !self.schema_version.starts_with("1.") {
            return Err(format!(
                "unsupported signing-request schema version {}",
                self.schema_version
            ));
        }
        let Some(user_authorization) = self.user_authorization else {
            return Err(
                "user_authorization is null — only confirm_and_sign may omit it, and the \
                 surface must supply it before signing"
                    .into(),
            );
        };
        if user_authorization.decision != "approved" {
            return Err("user_authorization.decision must be \"approved\"".into());
        }
        let user_authorization = UserAuthorization {
            decided_at: user_authorization.decided_at,
            surface: user_authorization.surface,
            escalation_acknowledged: user_authorization.escalation_acknowledged.unwrap_or(false),
        };
        // `tx`/`message_payload` placeholder for whichever kind this is not.
        let placeholder_tx = TxParams {
            to: None,
            value: cipherlayer_types::U256::ZERO,
            data: Vec::new(),
            nonce: 0,
            gas_limit: 0,
            gas_price_wei: 0,
        };
        match self.payload.kind.as_str() {
            "evm_transaction" => {
                let tx = self
                    .payload
                    .transaction
                    .ok_or_else(|| "payload.transaction is required for kind=evm_transaction".to_string())?;
                let data = alloy::hex::decode(tx.data_hex.trim_start_matches("0x"))
                    .map_err(|e| format!("bad data_hex: {e}"))?;
                let gas_price_wei: u128 = tx
                    .gas_price_wei
                    .parse()
                    .map_err(|e| format!("bad gas_price_wei: {e}"))?;
                Ok(VaultSigningRequest {
                    signing_request_id: self.signing_request_id,
                    request_id: self.request_id,
                    account: self.account,
                    chain_id: self.chain_id,
                    network_class: self.ext.network_class,
                    capability: self.capability,
                    policy_verdict: self.ext.policy_verdict,
                    user_authorization,
                    tx: TxParams {
                        to: tx.to,
                        value: tx.value,
                        data,
                        nonce: tx.nonce,
                        gas_limit: tx.gas_limit,
                        gas_price_wei,
                    },
                    message_payload: None,
                })
            }
            "typed_data" => {
                let typed_data_json = self
                    .payload
                    .typed_data_json
                    .ok_or_else(|| "payload.typed_data_json is required for kind=typed_data".to_string())?;
                Ok(VaultSigningRequest {
                    signing_request_id: self.signing_request_id,
                    request_id: self.request_id,
                    account: self.account,
                    chain_id: self.chain_id,
                    network_class: self.ext.network_class,
                    capability: self.capability,
                    policy_verdict: self.ext.policy_verdict,
                    user_authorization,
                    tx: placeholder_tx,
                    message_payload: Some(MessagePayload::TypedData { typed_data_json }),
                })
            }
            "personal_message" => {
                let message_hex = self.payload.message_hex.ok_or_else(|| {
                    "payload.message_hex is required for kind=personal_message".to_string()
                })?;
                let message = alloy::hex::decode(message_hex.trim_start_matches("0x"))
                    .map_err(|e| format!("bad message_hex: {e}"))?;
                Ok(VaultSigningRequest {
                    signing_request_id: self.signing_request_id,
                    request_id: self.request_id,
                    account: self.account,
                    chain_id: self.chain_id,
                    network_class: self.ext.network_class,
                    capability: self.capability,
                    policy_verdict: self.ext.policy_verdict,
                    user_authorization,
                    tx: placeholder_tx,
                    message_payload: Some(MessagePayload::PersonalMessage { message }),
                })
            }
            other => Err(format!(
                "unsupported payload kind {other:?} (evm_transaction | typed_data | personal_message)"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Response (vault-signing-response.v1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WireSignState {
    Signed,
    Refused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRefusal {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSigningResponse {
    pub schema_version: String,
    pub signing_request_id: Uuid,
    pub responded_at: DateTime<Utc>,
    pub state: WireSignState,
    pub raw_tx_hex: Option<String>,
    pub tx_hash: Option<String>,
    /// v0.4 (additive): present iff a `typed_data`/`personal_message`
    /// signature was produced (`raw_tx_hex`/`tx_hash` stay `None` for those).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    pub refusal: Option<WireRefusal>,
}

impl WireSigningResponse {
    pub fn signed(signing_request_id: Uuid, signed: &SignedTransaction) -> Self {
        WireSigningResponse {
            schema_version: WIRE_SCHEMA_VERSION.into(),
            signing_request_id,
            responded_at: Utc::now(),
            state: WireSignState::Signed,
            raw_tx_hex: Some(format!("0x{}", alloy::hex::encode(&signed.raw))),
            tx_hash: Some(signed.tx_hash.clone()),
            signature_hex: None,
            refusal: None,
        }
    }

    pub fn signed_message(signing_request_id: Uuid, sig: &MessageSignature) -> Self {
        WireSigningResponse {
            schema_version: WIRE_SCHEMA_VERSION.into(),
            signing_request_id,
            responded_at: Utc::now(),
            state: WireSignState::Signed,
            raw_tx_hex: None,
            tx_hash: None,
            signature_hex: Some(sig.to_hex()),
            refusal: None,
        }
    }

    /// Dispatch helper: builds the right wire shape for whichever outcome
    /// signing produced.
    pub fn from_outcome(signing_request_id: Uuid, outcome: &SignOutcome) -> Self {
        match outcome {
            SignOutcome::Transaction(tx) => Self::signed(signing_request_id, tx),
            SignOutcome::Message(sig) => Self::signed_message(signing_request_id, sig),
        }
    }

    pub fn refused(signing_request_id: Uuid, err: &VaultError) -> Self {
        WireSigningResponse {
            schema_version: WIRE_SCHEMA_VERSION.into(),
            signing_request_id,
            responded_at: Utc::now(),
            state: WireSignState::Refused,
            raw_tx_hex: None,
            tx_hash: None,
            signature_hex: None,
            refusal: Some(WireRefusal {
                code: refusal_code(err).into(),
                detail: err.to_string(),
            }),
        }
    }
}

/// Stable VLT-* refusal codes for the wire (the signing-response.v1 contract
/// already reserves the VLT prefix for Vault refusals).
pub fn refusal_code(err: &VaultError) -> &'static str {
    match err {
        VaultError::Locked => "VLT-LCK-001",
        VaultError::Capability(_) => "VLT-CAP-001",
        VaultError::PolicyDenied(_) => "VLT-POL-001",
        VaultError::EscalationNotAcknowledged => "VLT-POL-002",
        VaultError::NonDevelopmentChain(_) => "VLT-CHN-001",
        VaultError::AccountMismatch { .. } => "VLT-ACC-001",
        VaultError::RealKeyForbidden => "VLT-KEY-001",
        VaultError::Signer(_) => "VLT-SIG-001",
        VaultError::InvalidPayload(_) => "VLT-MSG-001",
    }
}

// ---------------------------------------------------------------------------
// Daemon protocol envelope (JSON-lines over the same-user Unix socket)
// ---------------------------------------------------------------------------

/// Everything the daemon accepts. Deny-by-default: any other message is a
/// protocol error, mirroring the wallet's unknown-method invariant.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case")]
pub enum VaultRequest {
    Status,
    Lock,
    Unlock,
    SignRequest {
        payload: Box<WireSigningRequest>,
    },
    /// Sign only after the Vault-side confirmation surface obtains a user
    /// decision (trusted-confirmation-surface.md requirement 3). The payload
    /// must carry `user_authorization: null` and `ext.display`.
    ConfirmAndSign {
        payload: Box<WireSigningRequest>,
    },
    /// ADR-021 phase 1 (vault-sol-signing.v1): present the operator-entered
    /// facts on vaultd's own terminal and require the chain-labeled approval
    /// phrase THERE — the phrase never travels this wire. Response is an
    /// approval nonce with a ~90 s expiry, or a coded refusal.
    SolApproveFacts {
        cluster_chain_id: u64,
        facts: WireSolFacts,
    },
    /// ADR-021 phase 2: sign the adapter-built message against the pending
    /// approval. vaultd independently re-decodes the message, enforces the
    /// fee rule, and prompts for the key on its own terminal (echo off) —
    /// the key never travels this wire in either direction.
    SolSign {
        nonce: Uuid,
        /// Hex-encoded `Message::serialize()` bytes.
        message_hex: String,
        /// Authoritative fee for THIS message; null = unknown (refused on
        /// mainnet — unknown is not evidence).
        final_fee_lamports: Option<u64>,
    },
}

/// The operator-approved facts for a Solana external-signer ceremony
/// (vault-sol-signing.v1). Wire mirror of `SolApprovedFacts` — no secret
/// material by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSolFacts {
    pub from_pubkey: String,
    pub to_pubkey: String,
    pub lamports: u64,
    #[serde(default)]
    pub fee_estimate_lamports: Option<u64>,
}

/// Map a ceremony error to its wire refusal code (vault-sol-signing.v1).
/// Codes are stable contract; detail strings are advisory.
pub fn sol_refusal_code(err: &crate::SolExternalSignerError) -> &'static str {
    use crate::SolExternalSignerError as E;
    match err {
        E::ClusterNotPermitted(..) => "VLT-SOL-001",
        E::PhraseMismatch => "VLT-SOL-002",
        E::InvalidFacts(_) => "VLT-SOL-003",
        E::MainnetFeeUnknown | E::FeeExceedsApproved { .. } => "VLT-SOL-004",
        E::NoApprovalPending | E::NonceMismatch | E::ApprovalExpired => "VLT-SOL-005",
        E::UnsignableMessage(_) => "VLT-SOL-006",
        E::ApprovedFactsMismatch(_) => "VLT-SOL-007",
        E::MalformedKey | E::AddressMismatch { .. } => "VLT-SOL-008",
        E::Signer(_) => "VLT-SOL-009",
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case")]
pub enum VaultResponse {
    Status {
        address: Address,
        locked: bool,
        signer_kind: String,
    },
    LockResponse {
        locked: bool,
    },
    SignResponse {
        payload: Box<WireSigningResponse>,
    },
    /// ADR-021 phase 1 success: the approval ticket. The console must present
    /// this nonce in phase 2 within the expiry window.
    SolApproveResponse {
        nonce: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
        cluster_name: String,
    },
    /// ADR-021 phase 2 success: public key, base58 signature, and the
    /// hex-encoded broadcastable transaction. Never key material.
    SolSignResponse {
        pubkey: String,
        signature: String,
        raw_hex: String,
    },
    Error {
        code: String,
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VaultIpcError {
    #[error("vault socket {0} is not connectable: {1}")]
    Connect(String, String),
    #[error("vault socket {0} refused: {1} (the vault socket must be owner-only)")]
    InsecureSocket(String, String),
    #[error("vault daemon protocol error: {0}")]
    Protocol(String),
    #[error("vault daemon refused: {code}: {detail}")]
    Refused { code: String, detail: String },
}

/// Client for the vault daemon. One connection per call: a JSON line out, a
/// JSON line back — the narrowest IPC that can carry the pinned schema.
#[derive(Debug)]
pub struct VaultClient {
    socket_path: std::path::PathBuf,
}

impl VaultClient {
    /// Refuses group- or world-accessible sockets/directories outright, the
    /// same discipline as the browser broker's same-user socket checks.
    pub fn connect_checked(
        socket_path: impl Into<std::path::PathBuf>,
    ) -> Result<Self, VaultIpcError> {
        let socket_path = socket_path.into();
        let display = socket_path.display().to_string();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(&socket_path)
                .map_err(|e| VaultIpcError::Connect(display.clone(), e.to_string()))?;
            if meta.mode() & 0o077 != 0 {
                return Err(VaultIpcError::InsecureSocket(
                    display,
                    format!(
                        "socket mode {:o} is group/world accessible",
                        meta.mode() & 0o777
                    ),
                ));
            }
            if let Some(dir) = socket_path.parent() {
                let dmeta = std::fs::metadata(dir)
                    .map_err(|e| VaultIpcError::Connect(display.clone(), e.to_string()))?;
                if dmeta.mode() & 0o077 != 0 {
                    return Err(VaultIpcError::InsecureSocket(
                        display,
                        format!(
                            "socket directory mode {:o} is group/world accessible",
                            dmeta.mode() & 0o777
                        ),
                    ));
                }
            }
        }
        Ok(Self { socket_path })
    }

    async fn round_trip(&self, req: &VaultRequest) -> Result<VaultResponse, VaultIpcError> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let display = self.socket_path.display().to_string();
        let stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| VaultIpcError::Connect(display, e.to_string()))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut line =
            serde_json::to_string(req).map_err(|e| VaultIpcError::Protocol(e.to_string()))?;
        line.push('\n');
        write_half
            .write_all(line.as_bytes())
            .await
            .map_err(|e| VaultIpcError::Protocol(e.to_string()))?;
        let mut reader = BufReader::new(read_half);
        let mut reply = String::new();
        reader
            .read_line(&mut reply)
            .await
            .map_err(|e| VaultIpcError::Protocol(e.to_string()))?;
        let resp: VaultResponse = serde_json::from_str(reply.trim())
            .map_err(|e| VaultIpcError::Protocol(format!("bad daemon reply: {e}")))?;
        if let VaultResponse::Error { code, detail } = resp {
            return Err(VaultIpcError::Refused { code, detail });
        }
        Ok(resp)
    }

    /// ADR-021 phase 1: send the facts; the approval phrase is typed on the
    /// vaultd terminal, never through this client.
    pub async fn sol_approve_facts(
        &self,
        cluster_chain_id: u64,
        facts: WireSolFacts,
    ) -> Result<(Uuid, chrono::DateTime<chrono::Utc>, String), VaultIpcError> {
        match self
            .round_trip(&VaultRequest::SolApproveFacts {
                cluster_chain_id,
                facts,
            })
            .await?
        {
            VaultResponse::SolApproveResponse {
                nonce,
                expires_at,
                cluster_name,
            } => Ok((nonce, expires_at, cluster_name)),
            other => Err(VaultIpcError::Protocol(format!(
                "unexpected reply to sol_approve_facts: {other:?}"
            ))),
        }
    }

    /// ADR-021 phase 2: sign against the pending approval. The key is pasted
    /// on the vaultd terminal; this client only ever receives the public key
    /// and the signed artifact.
    pub async fn sol_sign(
        &self,
        nonce: Uuid,
        serialized_message: &[u8],
        final_fee_lamports: Option<u64>,
    ) -> Result<(String, String, Vec<u8>), VaultIpcError> {
        match self
            .round_trip(&VaultRequest::SolSign {
                nonce,
                message_hex: alloy::hex::encode(serialized_message),
                final_fee_lamports,
            })
            .await?
        {
            VaultResponse::SolSignResponse {
                pubkey,
                signature,
                raw_hex,
            } => {
                let raw = alloy::hex::decode(raw_hex.trim_start_matches("0x"))
                    .map_err(|e| VaultIpcError::Protocol(format!("bad raw_hex in reply: {e}")))?;
                Ok((pubkey, signature, raw))
            }
            other => Err(VaultIpcError::Protocol(format!(
                "unexpected reply to sol_sign: {other:?}"
            ))),
        }
    }

    pub async fn status(&self) -> Result<(Address, bool), VaultIpcError> {
        match self.round_trip(&VaultRequest::Status).await? {
            VaultResponse::Status {
                address, locked, ..
            } => Ok((address, locked)),
            other => Err(VaultIpcError::Protocol(format!(
                "unexpected reply to status: {other:?}"
            ))),
        }
    }

    pub async fn set_locked(&self, locked: bool) -> Result<bool, VaultIpcError> {
        let msg = if locked {
            VaultRequest::Lock
        } else {
            VaultRequest::Unlock
        };
        match self.round_trip(&msg).await? {
            VaultResponse::LockResponse { locked } => Ok(locked),
            other => Err(VaultIpcError::Protocol(format!(
                "unexpected reply to lock/unlock: {other:?}"
            ))),
        }
    }

    /// Remote counterpart of `Vault::authorize_and_sign`. The daemon
    /// re-validates everything; a refusal comes back as a coded response,
    /// never a signature.
    pub async fn authorize_and_sign(
        &self,
        req: &VaultSigningRequest,
        intent_id: Uuid,
        decision_id: Uuid,
    ) -> Result<WireSigningResponse, VaultIpcError> {
        let wire = match &req.message_payload {
            None => WireSigningRequest::from_request(req, intent_id, decision_id),
            Some(payload) => {
                WireSigningRequest::from_message_request(req, payload, intent_id, decision_id)
            }
        };
        match self
            .round_trip(&VaultRequest::SignRequest {
                payload: Box::new(wire),
            })
            .await?
        {
            VaultResponse::SignResponse { payload } => Ok(*payload),
            other => Err(VaultIpcError::Protocol(format!(
                "unexpected reply to sign_request: {other:?}"
            ))),
        }
    }

    /// Ask the daemon to render its confirmation surface and, only on an
    /// approved decision, sign. `req.user_authorization` is ignored — the
    /// decision is made on the Vault side.
    pub async fn confirm_and_sign(
        &self,
        req: &VaultSigningRequest,
        intent_id: Uuid,
        decision_id: Uuid,
        display: WireDisplayEvidence,
    ) -> Result<WireSigningResponse, VaultIpcError> {
        // v0.4 honest limitation: the Vault-side confirmation surface only
        // renders transaction evidence today. Message-signing requests must
        // use the direct `authorize_and_sign` review path (the pipeline
        // enforces this before ever reaching here) — refuse rather than
        // render a wrong/misleading surface.
        if req.message_payload.is_some() {
            return Err(VaultIpcError::Protocol(
                "confirm_and_sign (vault-side surface) does not support typed_data/personal_message payloads in this revision — use the direct review path".into(),
            ));
        }
        let wire = WireSigningRequest::for_confirmation(req, intent_id, decision_id, display);
        match self
            .round_trip(&VaultRequest::ConfirmAndSign {
                payload: Box::new(wire),
            })
            .await?
        {
            VaultResponse::SignResponse { payload } => Ok(*payload),
            other => Err(VaultIpcError::Protocol(format!(
                "unexpected reply to confirm_and_sign: {other:?}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Backend: one signing surface, in-process or across the ADR-004 boundary
// ---------------------------------------------------------------------------

/// Outcome of a Vault-side confirmation: the human decided. Anything that is
/// not one of these two (surface unavailable, vault refusal) is an error.
#[derive(Debug)]
pub enum SurfaceOutcome {
    Signed(SignedTransaction),
    /// The human rejected at the surface (VLT-USR-001) — a normal outcome,
    /// not a failure.
    Rejected {
        detail: String,
    },
}

/// The pipeline's vault handle. `InProcess` is the milestone-1 arrangement
/// (interface isolation only); `Remote` talks to `cipherlayer-vaultd` so key
/// material lives in a separate OS process. Both refuse identically — the
/// daemon hosts the same `Vault`.
#[derive(Debug)]
pub enum VaultBackend {
    InProcess(crate::Vault),
    Remote {
        client: VaultClient,
        /// Signer address, fetched from the daemon at connect time.
        address: Address,
    },
}

impl VaultBackend {
    /// Connect to a vault daemon and cache its signer address.
    pub async fn remote(socket_path: impl Into<std::path::PathBuf>) -> Result<Self, VaultIpcError> {
        let client = VaultClient::connect_checked(socket_path)?;
        let (address, _locked) = client.status().await?;
        Ok(VaultBackend::Remote { client, address })
    }

    pub fn address(&self) -> Address {
        match self {
            VaultBackend::InProcess(v) => v.address(),
            VaultBackend::Remote { address, .. } => *address,
        }
    }

    /// Honest provenance label for audit events.
    pub fn signer_kind(&self) -> &'static str {
        match self {
            VaultBackend::InProcess(_) => "test (MOCKED custody, Anvil dev key, in-process)",
            VaultBackend::Remote { .. } => {
                "test (MOCKED custody, Anvil dev key, cipherlayer-vaultd process)"
            }
        }
    }

    /// In-process emergency lock (AC-H). A remote vault is locked against the
    /// daemon itself (`VaultClient::set_locked`); returns whether this call
    /// applied.
    pub fn lock(&mut self) -> bool {
        match self {
            VaultBackend::InProcess(v) => {
                v.lock();
                true
            }
            VaultBackend::Remote { .. } => false,
        }
    }

    /// The single signing gate, whichever side of the boundary the Vault is
    /// on. Refusals come back as `code: detail` strings for the audit log.
    /// Returns `SignOutcome::Transaction` for `evm_transaction` requests and
    /// `SignOutcome::Message` for `typed_data`/`personal_message` requests
    /// (`req.message_payload.is_some()`).
    pub async fn authorize_and_sign(
        &self,
        req: &VaultSigningRequest,
        intent_id: Uuid,
        decision_id: Uuid,
    ) -> Result<SignOutcome, String> {
        match self {
            VaultBackend::InProcess(v) => v
                .authorize_and_sign(req)
                .await
                .map_err(|e| format!("{}: {e}", refusal_code(&e))),
            VaultBackend::Remote { client, .. } => {
                let resp = client
                    .authorize_and_sign(req, intent_id, decision_id)
                    .await
                    .map_err(|e| e.to_string())?;
                match resp.state {
                    WireSignState::Signed => {
                        if let Some(sig_hex) = &resp.signature_hex {
                            let bytes = alloy::hex::decode(sig_hex.trim_start_matches("0x"))
                                .map_err(|e| format!("bad signature_hex from daemon: {e}"))?;
                            let signature: [u8; 65] = bytes
                                .try_into()
                                .map_err(|_| "daemon signature_hex is not 65 bytes".to_string())?;
                            return Ok(SignOutcome::Message(MessageSignature { signature }));
                        }
                        let raw_hex = resp.raw_tx_hex.ok_or("daemon reply missing raw_tx_hex")?;
                        let raw = alloy::hex::decode(raw_hex.trim_start_matches("0x"))
                            .map_err(|e| format!("bad raw_tx_hex from daemon: {e}"))?;
                        let tx_hash = resp.tx_hash.ok_or("daemon reply missing tx_hash")?;
                        Ok(SignOutcome::Transaction(SignedTransaction { raw, tx_hash }))
                    }
                    WireSignState::Refused => {
                        let r = resp.refusal.unwrap_or_else(|| WireRefusal {
                            code: "VLT-SIG-001".into(),
                            detail: "refused without a reason (daemon bug)".into(),
                        });
                        Err(format!("{}: {}", r.code, r.detail))
                    }
                }
            }
        }
    }

    /// Delegate USER_REVIEW to the Vault-side confirmation surface, then sign
    /// (trusted-confirmation-surface.md). Only meaningful across the process
    /// boundary: in-process there is no Vault-side surface to trust.
    pub async fn confirm_and_sign(
        &self,
        req: &VaultSigningRequest,
        intent_id: Uuid,
        decision_id: Uuid,
        display: WireDisplayEvidence,
    ) -> Result<SurfaceOutcome, String> {
        let client = match self {
            VaultBackend::InProcess(_) => {
                return Err("vault-surface confirmation requires the vault daemon \
                     (set CIPHERLAYER_VAULT_SOCKET and run cipherlayer-vaultd)"
                    .into())
            }
            VaultBackend::Remote { client, .. } => client,
        };
        let resp = client
            .confirm_and_sign(req, intent_id, decision_id, display)
            .await
            .map_err(|e| e.to_string())?;
        match resp.state {
            WireSignState::Signed => {
                let raw_hex = resp.raw_tx_hex.ok_or("daemon reply missing raw_tx_hex")?;
                let raw = alloy::hex::decode(raw_hex.trim_start_matches("0x"))
                    .map_err(|e| format!("bad raw_tx_hex from daemon: {e}"))?;
                let tx_hash = resp.tx_hash.ok_or("daemon reply missing tx_hash")?;
                Ok(SurfaceOutcome::Signed(SignedTransaction { raw, tx_hash }))
            }
            WireSignState::Refused => {
                let r = resp.refusal.unwrap_or_else(|| WireRefusal {
                    code: "VLT-SIG-001".into(),
                    detail: "refused without a reason (daemon bug)".into(),
                });
                if r.code == "VLT-USR-001" {
                    Ok(SurfaceOutcome::Rejected { detail: r.detail })
                } else {
                    Err(format!("{}: {}", r.code, r.detail))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, TestSigner, Vault, ANVIL_DEV_KEYS};

    fn sample_request(account: Address) -> VaultSigningRequest {
        VaultSigningRequest {
            signing_request_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            account,
            chain_id: ChainId(31337),
            network_class: NetworkClass::Development,
            capability: Capability::signing("cli:test", account, ChainId(31337), 60),
            policy_verdict: Verdict::Allow,
            user_authorization: UserAuthorization {
                decided_at: Utc::now(),
                surface: ConfirmationSurface::CliPrompt,
                escalation_acknowledged: false,
            },
            tx: TxParams {
                to: Some(Address::from_slice(&[2u8; 20])),
                value: U256::from(7u64),
                data: vec![0xde, 0xad],
                nonce: 3,
                gas_limit: 21_000,
                gas_price_wei: 1_000_000_000,
            },
            message_payload: None,
        }
    }

    #[test]
    fn wire_round_trip_preserves_everything_the_vault_checks() {
        let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
        let account = signer.address();
        let req = sample_request(account);
        let wire = WireSigningRequest::from_request(&req, Uuid::new_v4(), Uuid::new_v4());
        let json = serde_json::to_string(&wire).unwrap();
        let parsed: WireSigningRequest = serde_json::from_str(&json).unwrap();
        let back = parsed.into_request().unwrap();
        assert_eq!(back.signing_request_id, req.signing_request_id);
        assert_eq!(back.account, req.account);
        assert_eq!(back.chain_id, req.chain_id);
        assert_eq!(back.network_class, req.network_class);
        assert_eq!(back.policy_verdict, req.policy_verdict);
        assert_eq!(back.tx.to, req.tx.to);
        assert_eq!(back.tx.value, req.tx.value);
        assert_eq!(back.tx.data, req.tx.data);
        assert_eq!(back.tx.nonce, req.tx.nonce);
        assert_eq!(back.tx.gas_limit, req.tx.gas_limit);
        assert_eq!(back.tx.gas_price_wei, req.tx.gas_price_wei);
        assert_eq!(back.capability.capability_id, req.capability.capability_id);
    }

    #[tokio::test]
    async fn round_tripped_request_still_signs_and_still_refuses() {
        let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
        let vault = Vault::new(signer);
        let req = sample_request(vault.address());
        let wire = WireSigningRequest::from_request(&req, Uuid::new_v4(), Uuid::new_v4());
        let back =
            serde_json::from_str::<WireSigningRequest>(&serde_json::to_string(&wire).unwrap())
                .unwrap()
                .into_request()
                .unwrap();
        assert!(vault.authorize_and_sign(&back).await.is_ok());

        // A deny verdict survives the wire and is still refused.
        let mut denied = sample_request(vault.address());
        denied.policy_verdict = Verdict::Deny;
        let wire = WireSigningRequest::from_request(&denied, Uuid::new_v4(), Uuid::new_v4());
        let back = wire.into_request().unwrap();
        let err = vault.authorize_and_sign(&back).await.unwrap_err();
        assert_eq!(refusal_code(&err), "VLT-POL-001");
    }

    #[test]
    fn unknown_schema_version_and_payload_kind_are_refused() {
        let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
        let req = sample_request(signer.address());
        let mut wire = WireSigningRequest::from_request(&req, Uuid::new_v4(), Uuid::new_v4());
        wire.schema_version = "2.0".into();
        assert!(wire.clone().into_request().is_err());
        wire.schema_version = WIRE_SCHEMA_VERSION.into();
        // A kind claiming typed_data but missing the required field is still
        // refused, not silently treated as some other kind.
        wire.payload.kind = "typed_data".into();
        assert!(wire.clone().into_request().is_err());
        // A genuinely unsupported kind is refused outright.
        wire.payload.kind = "bogus_kind".into();
        assert!(wire.into_request().is_err());
    }

    /// v0.4: a typed_data wire request round-trips into a `VaultSigningRequest`
    /// with `message_payload` populated and `tx` unused, and the Vault signs
    /// it end-to-end via the wire path exactly as it does in-process.
    #[tokio::test]
    async fn typed_data_wire_round_trip_signs_end_to_end() {
        let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
        let vault = Vault::new(signer);
        let mut req = sample_request(vault.address());
        req.capability = Capability::messages("cli:test", vault.address(), ChainId(31337), 60);
        let typed_data = serde_json::json!({
            "types": {
                "EIP712Domain": [{ "name": "chainId", "type": "uint256" }],
                "Mail": [{ "name": "contents", "type": "string" }]
            },
            "primaryType": "Mail",
            "domain": { "chainId": 31337 },
            "message": { "contents": "hi" }
        })
        .to_string();
        let payload = MessagePayload::TypedData {
            typed_data_json: typed_data,
        };
        let wire = WireSigningRequest::from_message_request(
            &req,
            &payload,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        assert_eq!(wire.payload.kind, "typed_data");
        assert!(wire.payload.transaction.is_none());
        let json = serde_json::to_string(&wire).unwrap();
        let parsed: WireSigningRequest = serde_json::from_str(&json).unwrap();
        let back = parsed.into_request().unwrap();
        assert!(back.message_payload.is_some());

        let outcome = vault.authorize_and_sign(&back).await.unwrap();
        let SignOutcome::Message(sig) = outcome else {
            panic!("expected a message outcome");
        };
        assert_eq!(sig.signature.len(), 65);
    }

    /// personal_message wire round-trip, same shape as the typed_data test.
    #[tokio::test]
    async fn personal_message_wire_round_trip_signs_end_to_end() {
        let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
        let vault = Vault::new(signer);
        let mut req = sample_request(vault.address());
        req.capability = Capability::messages("cli:test", vault.address(), ChainId(31337), 60);
        let payload = MessagePayload::PersonalMessage {
            message: b"sign in to example.org".to_vec(),
        };
        let wire = WireSigningRequest::from_message_request(
            &req,
            &payload,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        assert_eq!(wire.payload.kind, "personal_message");
        let back =
            serde_json::from_str::<WireSigningRequest>(&serde_json::to_string(&wire).unwrap())
                .unwrap()
                .into_request()
                .unwrap();
        let outcome = vault.authorize_and_sign(&back).await.unwrap();
        assert!(matches!(outcome, SignOutcome::Message(_)));
        let response = WireSigningResponse::from_outcome(back.signing_request_id, &outcome);
        assert!(response.signature_hex.is_some());
        assert!(response.raw_tx_hex.is_none());
        assert!(response.tx_hash.is_none());
    }

    #[test]
    fn response_never_contains_key_material() {
        let signed = SignedTransaction {
            raw: vec![1, 2, 3],
            tx_hash: "0xabc".into(),
        };
        let resp = WireSigningResponse::signed(Uuid::new_v4(), &signed);
        let json = serde_json::to_string(&resp).unwrap();
        for k in ANVIL_DEV_KEYS {
            assert!(!json.to_lowercase().contains(&k[2..]));
        }
        assert_eq!(resp.state, WireSignState::Signed);
        assert_eq!(resp.raw_tx_hex.as_deref(), Some("0x010203"));
    }
}
