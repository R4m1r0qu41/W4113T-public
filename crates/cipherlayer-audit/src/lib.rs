//! Append-only, hash-chained audit log (schema audit-event.v1, ADR-007).
//!
//! Integrity model — stated honestly:
//! - each event carries `prev_hash` and `event_hash` (SHA-256 over the
//!   canonical serialization of sequence, occurred_at, kind, request_id,
//!   payload, prev_hash);
//! - `verify()` detects in-place edits and mid-chain breaks;
//! - it does NOT detect a full-suffix rewrite or tail truncation by an
//!   attacker with file write access — that requires an externally stored
//!   head hash, which milestone 1 does not implement. This is tamper
//!   EVIDENCE, not immutability, and must never be described otherwise.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const GENESIS_TAG: &str = "cipherlayer-audit-genesis-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    ConnectionRequested,
    PermissionGranted,
    PermissionDenied,
    PermissionRevoked,
    RequestReceived,
    RequestValidated,
    PermissionChecked,
    IntentDecoded,
    SimulationCompleted,
    SimulationFailed,
    RiskEvaluated,
    PolicyEvaluated,
    UserDecision,
    SignatureCreated,
    SigningFailed,
    BroadcastCompleted,
    BroadcastFailed,
    StateTransition,
    IllegalTransitionAttempted,
    VaultLocked,
    VaultUnlocked,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: String,
    pub event_id: Uuid,
    pub sequence: u64,
    pub occurred_at: DateTime<Utc>,
    pub kind: EventKind,
    pub request_id: Option<Uuid>,
    pub payload: serde_json::Value,
    pub prev_hash: String,
    pub event_hash: String,
}

/// Canonical hash input: field order is fixed by this struct's declaration
/// order (serde_json preserves it). Changing this struct is a breaking change
/// to the chain format and requires a schema major bump.
#[derive(Serialize)]
struct HashInput<'a> {
    sequence: u64,
    occurred_at: &'a DateTime<Utc>,
    kind: &'a EventKind,
    request_id: &'a Option<Uuid>,
    payload: &'a serde_json::Value,
    prev_hash: &'a str,
}

fn genesis_hash() -> String {
    hex::encode(Sha256::digest(GENESIS_TAG.as_bytes()))
}

fn compute_hash(
    sequence: u64,
    occurred_at: &DateTime<Utc>,
    kind: &EventKind,
    request_id: &Option<Uuid>,
    payload: &serde_json::Value,
    prev_hash: &str,
) -> String {
    let input = HashInput {
        sequence,
        occurred_at,
        kind,
        request_id,
        payload,
        prev_hash,
    };
    let canonical = serde_json::to_vec(&input).expect("hash input is always serializable");
    hex::encode(Sha256::digest(&canonical))
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit log line {0} is not valid JSON: {1}")]
    Corrupt(u64, String),
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub total_events: u64,
    pub valid: bool,
    /// Sequence number of the first event whose hash chain fails.
    pub first_invalid_sequence: Option<u64>,
    pub message: String,
}

/// Append-only JSONL audit log.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_all(&self) -> Result<Vec<AuditEvent>, AuditError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&self.path)?;
        let mut events = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let ev: AuditEvent = serde_json::from_str(line)
                .map_err(|e| AuditError::Corrupt(i as u64, e.to_string()))?;
            events.push(ev);
        }
        Ok(events)
    }

    /// Append one event, chaining it to the current head.
    pub fn append(
        &self,
        kind: EventKind,
        request_id: Option<Uuid>,
        payload: serde_json::Value,
    ) -> Result<AuditEvent, AuditError> {
        let existing = self.read_all()?;
        let (sequence, prev_hash) = match existing.last() {
            Some(last) => (last.sequence + 1, last.event_hash.clone()),
            None => (0, genesis_hash()),
        };
        let occurred_at = Utc::now();
        let event_hash = compute_hash(
            sequence,
            &occurred_at,
            &kind,
            &request_id,
            &payload,
            &prev_hash,
        );
        let event = AuditEvent {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            event_id: cipherlayer_types::new_id(),
            sequence,
            occurred_at,
            kind,
            request_id,
            payload,
            prev_hash,
            event_hash,
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut line = serde_json::to_string(&event).expect("event serializes");
        line.push('\n');
        file.write_all(line.as_bytes())?;
        Ok(event)
    }

    /// Recompute the whole chain and report the first divergence.
    pub fn verify(&self) -> Result<VerifyReport, AuditError> {
        let events = self.read_all()?;
        let mut expected_prev = genesis_hash();
        for (i, ev) in events.iter().enumerate() {
            let seq_ok = ev.sequence == i as u64;
            let prev_ok = ev.prev_hash == expected_prev;
            let hash_ok = compute_hash(
                ev.sequence,
                &ev.occurred_at,
                &ev.kind,
                &ev.request_id,
                &ev.payload,
                &ev.prev_hash,
            ) == ev.event_hash;
            if !(seq_ok && prev_ok && hash_ok) {
                return Ok(VerifyReport {
                    total_events: events.len() as u64,
                    valid: false,
                    first_invalid_sequence: Some(ev.sequence),
                    message: format!(
                        "chain diverges at sequence {} (sequence_ok={seq_ok}, prev_hash_ok={prev_ok}, event_hash_ok={hash_ok}). \
                         Note: a full-suffix rewrite or tail truncation is NOT detectable without an external head anchor.",
                        ev.sequence
                    ),
                });
            }
            expected_prev = ev.event_hash.clone();
        }
        Ok(VerifyReport {
            total_events: events.len() as u64,
            valid: true,
            first_invalid_sequence: None,
            message: format!(
                "hash chain valid over {} event(s). Tamper-evident, not immutable: \
                 truncation/suffix-rewrite detection requires an external head anchor (not implemented).",
                events.len()
            ),
        })
    }

    pub fn events_for_request(&self, request_id: Uuid) -> Result<Vec<AuditEvent>, AuditError> {
        Ok(self
            .read_all()?
            .into_iter()
            .filter(|e| e.request_id == Some(request_id))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> (tempfile::TempDir, AuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        (dir, log)
    }

    #[test]
    fn chain_builds_and_verifies() {
        let (_d, log) = temp_log();
        let rid = Uuid::new_v4();
        log.append(
            EventKind::RequestReceived,
            Some(rid),
            serde_json::json!({"a":1}),
        )
        .unwrap();
        log.append(
            EventKind::RequestValidated,
            Some(rid),
            serde_json::json!({}),
        )
        .unwrap();
        log.append(
            EventKind::PolicyEvaluated,
            Some(rid),
            serde_json::json!({"verdict":"deny"}),
        )
        .unwrap();
        let report = log.verify().unwrap();
        assert!(report.valid, "{}", report.message);
        assert_eq!(report.total_events, 3);
        assert_eq!(log.events_for_request(rid).unwrap().len(), 3);
    }

    #[test]
    fn in_place_tampering_is_detected() {
        let (_d, log) = temp_log();
        for i in 0..5u64 {
            log.append(
                EventKind::StateTransition,
                None,
                serde_json::json!({ "i": i }),
            )
            .unwrap();
        }
        // Tamper with event #2's payload without recomputing hashes.
        let content = fs::read_to_string(log.path()).unwrap();
        let tampered: String = content
            .lines()
            .map(|l| {
                if l.contains("\"i\":2") {
                    l.replace("\"i\":2", "\"i\":99")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(log.path(), tampered).unwrap();
        let report = log.verify().unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_sequence, Some(2));
    }

    #[test]
    fn broken_prev_link_is_detected() {
        let (_d, log) = temp_log();
        log.append(EventKind::RequestReceived, None, serde_json::json!({}))
            .unwrap();
        log.append(EventKind::RequestValidated, None, serde_json::json!({}))
            .unwrap();
        // Remove the first line: sequence and prev-link both break.
        let content = fs::read_to_string(log.path()).unwrap();
        let without_first: String = content.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(log.path(), without_first).unwrap();
        let report = log.verify().unwrap();
        assert!(!report.valid);
    }

    #[test]
    fn empty_log_is_valid() {
        let (_d, log) = temp_log();
        let report = log.verify().unwrap();
        assert!(report.valid);
        assert_eq!(report.total_events, 0);
    }

    #[test]
    fn verify_message_states_limitations() {
        let (_d, log) = temp_log();
        log.append(EventKind::RequestReceived, None, serde_json::json!({}))
            .unwrap();
        let report = log.verify().unwrap();
        assert!(report.message.contains("not immutable"));
    }
}
