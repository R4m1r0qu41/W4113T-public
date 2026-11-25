//! Shared deterministic types for the CipherLayer trust spine.
//!
//! This crate contains no business logic and no I/O. It owns the vocabulary
//! every other crate speaks — identifiers, security-relevant enums, and the
//! signing state machine — so that no crate can express an unsafe concept
//! (e.g., an out-of-order pipeline or a stringly-typed chain id).

pub mod state;

pub use alloy::primitives::{Address, B256, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wire schema version emitted by this build (schemas/*.v1.json, minor 0).
pub const SCHEMA_VERSION: &str = "1.0";

/// EVM chain identifier. Always typed, never a bare integer in signatures-adjacent code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(pub u64);

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Safety class of a network. Drives the milestone-1 signing gate:
/// only `Development` chains may sign (ADR-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkClass {
    Development,
    Testnet,
    Mainnet,
}

/// Declared access class of a request. Signing requests traverse the full pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessClass {
    ReadOnly,
    Signing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerKind {
    Dapp,
    Cli,
    Desktop,
    Agent,
    Unknown,
}

/// Mandatory caller identity (TB1). An identity with neither origin nor
/// app_id is invalid and must be rejected at RECEIVED.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerIdentity {
    pub kind: CallerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_id: Option<String>,
}

impl CallerIdentity {
    pub fn is_identified(&self) -> bool {
        self.origin.as_deref().is_some_and(|s| !s.trim().is_empty())
            || self.app_id.as_deref().is_some_and(|s| !s.trim().is_empty())
    }

    /// Stable key for permission lookups.
    ///
    /// For dapp callers the `capsule_id` is part of the key when present, so a
    /// grant is scoped to the capsule and not merely to the origin
    /// (`dapp-capsules.md`: permissions are capsule-scoped, and a new capsule
    /// generation orphans prior grants). This is the confused-deputy defense
    /// (T-19): two capsules of the same origin, or the same origin after a
    /// "reset capsule", never share a grant. Non-dapp callers (CLI/app) key by
    /// origin/app_id as before.
    pub fn key(&self) -> String {
        let id = self
            .origin
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or(self.app_id.as_deref())
            .unwrap_or("<unidentified>");
        match (&self.kind, self.capsule_id.as_deref()) {
            (CallerKind::Dapp, Some(capsule)) if !capsule.trim().is_empty() => {
                format!("dapp:{id}#{capsule}")
            }
            _ => format!("{:?}:{id}", self.kind).to_lowercase(),
        }
    }
}

/// Risk levels per the FPL contract plus aggregate-only members.
/// `Unknown` must never be treated as `Low` (CL-FPL-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
    Conflicting,
}

impl RiskLevel {
    /// Severity rank for confident levels; `None` for unknown/conflicting,
    /// which are not comparable and must take the restrictive path.
    pub fn severity(self) -> Option<u8> {
        match self {
            RiskLevel::Low => Some(0),
            RiskLevel::Medium => Some(1),
            RiskLevel::High => Some(2),
            RiskLevel::Critical => Some(3),
            RiskLevel::Unknown | RiskLevel::Conflicting => None,
        }
    }
}

/// Decoder confidence in a classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Exact,
    High,
    Partial,
    Unknown,
}

/// Custody/authority classification (CL-LEG-003). Surfaces must label these
/// plainly; a token representation never proves an off-chain legal right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyContext {
    SelfCustody,
    ExternalCustody,
    SmartAccount,
    Multisig,
    Delegated,
    SessionKey,
    WatchOnly,
    Unknown,
}

/// Provenance stamp carried by every derived artifact (intent, decision, bundle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub producer: String,
    pub producer_version: String,
}

impl Provenance {
    pub fn of(producer: &str) -> Self {
        Self {
            producer: producer.to_string(),
            producer_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// RFC 3339 UTC timestamp helper.
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// New stable identifier.
pub fn new_id() -> Uuid {
    Uuid::new_v4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_requires_origin_or_app_id() {
        let anon = CallerIdentity {
            kind: CallerKind::Dapp,
            origin: None,
            app_id: None,
            capsule_id: None,
        };
        assert!(!anon.is_identified());
        let blank = CallerIdentity {
            kind: CallerKind::Dapp,
            origin: Some("   ".into()),
            app_id: None,
            capsule_id: None,
        };
        assert!(!blank.is_identified());
        let ok = CallerIdentity {
            kind: CallerKind::Cli,
            origin: None,
            app_id: Some("cli:local-user".into()),
            capsule_id: None,
        };
        assert!(ok.is_identified());
    }

    #[test]
    fn dapp_permission_key_is_capsule_scoped() {
        let dapp = |capsule: Option<&str>| CallerIdentity {
            kind: CallerKind::Dapp,
            origin: Some("https://x.example".into()),
            app_id: None,
            capsule_id: capsule.map(String::from),
        };
        // Two capsules of the same origin never share a key (T-19 defense).
        assert_ne!(dapp(Some("cap-1")).key(), dapp(Some("cap-2")).key());
        // A new capsule generation (reset capsule) orphans the prior grant.
        assert_ne!(dapp(Some("x#gen1")).key(), dapp(Some("x#gen2")).key());
        // Origin still participates.
        assert!(dapp(Some("cap-1")).key().contains("https://x.example"));
        // Non-dapp callers are unaffected (CLI keys by app_id).
        let cli = CallerIdentity {
            kind: CallerKind::Cli,
            origin: None,
            app_id: Some("cli:local-user".into()),
            capsule_id: None,
        };
        assert_eq!(cli.key(), "cli:cli:local-user");
    }

    #[test]
    fn unknown_risk_has_no_severity() {
        assert_eq!(RiskLevel::Unknown.severity(), None);
        assert_eq!(RiskLevel::Conflicting.severity(), None);
        assert!(RiskLevel::Critical.severity() > RiskLevel::Low.severity());
    }

    #[test]
    fn chain_id_serde_is_transparent() {
        let c: ChainId = serde_json::from_str("31337").unwrap();
        assert_eq!(c, ChainId(31337));
        assert_eq!(serde_json::to_string(&c).unwrap(), "31337");
    }
}
