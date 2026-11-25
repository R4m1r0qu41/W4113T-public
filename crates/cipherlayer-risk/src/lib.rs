//! FPL / Scam Guard detector **consumer** (ADR-009). This crate is not a fraud
//! detector: it defines the consumer side of the pinned detector contract
//! (imports/scam-guard/, contract v0.1) — a `Detector` trait, output
//! normalization, and conflict-preserving aggregation.
//!
//! Contract obligations enforced here:
//! - findings are preserved verbatim, never dropped or rewritten;
//! - `unknown` aggregates to `unknown`, never to `low` (CL-FPL-003);
//! - material disagreement between confident detectors becomes `conflicting`
//!   with both sides visible;
//! - risk output is advisory: nothing in this crate can authorize anything.

use chrono::{DateTime, Utc};
use cipherlayer_intent::TransactionIntent;
use cipherlayer_types::{Provenance, RiskLevel};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DETECTOR_CONTRACT_VERSION: &str = "0.1.0";
pub const DEFAULT_FPL_BIN: &str = "scam-guard";
pub const FPL_MODE_ENV: &str = "CIPHERLAYER_FPL_MODE";
pub const FPL_BIN_ENV: &str = "CIPHERLAYER_FPL_BIN";
pub const FPL_TIMEOUT_MS_ENV: &str = "CIPHERLAYER_FPL_TIMEOUT_MS";
const DEFAULT_FPL_TIMEOUT_MS: u64 = 2_000;
const MAX_FPL_INPUT_BYTES: usize = 256 * 1024;
const MAX_FPL_OUTPUT_BYTES: usize = 1024 * 1024;

/// Confidence at or above which a finding participates in severity
/// aggregation. Below-threshold findings remain visible but do not set the
/// overall level (they can still keep it from being "low-and-quiet": an
/// aggregate with only low-confidence findings is `unknown`).
pub const CONFIDENT_THRESHOLD: f64 = 0.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Domain,
    Url,
    Address,
    Contract,
    TransactionIntent,
    MessageText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub kind: SubjectKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSourceClass {
    LocalHeuristic,
    LocalDataset,
    RemoteFeed,
    ModelAssisted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorProvenance {
    pub data_source_class: DataSourceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_version: Option<String>,
    /// true = produced by a labeled mock detector; consumers must surface this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mock: Option<bool>,
}

/// One finding — mirrors the pinned `detector-output.v1.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorOutput {
    pub schema_version: String,
    pub output_id: Uuid,
    pub detector: DetectorInfo,
    pub evaluated_at: DateTime<Utc>,
    pub subject: Subject,
    pub risk_level: RiskLevel,
    pub confidence: f64,
    pub reason_codes: Vec<String>,
    pub explanation: String,
    pub provenance: DetectorProvenance,
}

/// A detector examines an intent and returns zero or more findings.
pub trait Detector {
    fn name(&self) -> &str;
    fn evaluate(&self, intent: &TransactionIntent) -> Vec<DetectorOutput>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub finding_a: Uuid,
    pub finding_b: Uuid,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProvenance {
    pub producer: String,
    pub producer_version: String,
    pub detector_contract_version: String,
}

/// Aggregate — mirrors `risk-evidence-bundle.v1.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvidenceBundle {
    pub schema_version: String,
    pub bundle_id: Uuid,
    pub request_id: Uuid,
    pub aggregated_at: DateTime<Utc>,
    pub overall_level: RiskLevel,
    pub overall_rationale: String,
    pub findings: Vec<DetectorOutput>,
    pub conflicts: Vec<Conflict>,
    pub detectors_unavailable: Vec<String>,
    pub provenance: BundleProvenance,
}

/// Conflict rule: two confident findings disagree materially when their
/// severities differ by ≥ 2 ranks (e.g. low vs high).
const MATERIAL_DISAGREEMENT: u8 = 2;

pub fn aggregate(
    request_id: Uuid,
    findings: Vec<DetectorOutput>,
    detectors_unavailable: Vec<String>,
) -> RiskEvidenceBundle {
    let confident: Vec<&DetectorOutput> = findings
        .iter()
        .filter(|f| f.confidence >= CONFIDENT_THRESHOLD && f.risk_level.severity().is_some())
        .collect();

    let mut conflicts = Vec::new();
    for (i, a) in confident.iter().enumerate() {
        for b in confident.iter().skip(i + 1) {
            let (sa, sb) = (
                a.risk_level.severity().expect("filtered"),
                b.risk_level.severity().expect("filtered"),
            );
            if sa.abs_diff(sb) >= MATERIAL_DISAGREEMENT {
                conflicts.push(Conflict {
                    finding_a: a.output_id,
                    finding_b: b.output_id,
                    description: format!(
                        "{} reports {:?} while {} reports {:?} for the same request",
                        a.detector.name, a.risk_level, b.detector.name, b.risk_level
                    ),
                });
            }
        }
    }

    let overall_level = if !conflicts.is_empty() {
        RiskLevel::Conflicting
    } else if confident.is_empty() {
        // No evidence, or only unknown / low-confidence evidence: the honest
        // answer is unknown — never low (CL-FPL-003).
        RiskLevel::Unknown
    } else {
        let max = confident
            .iter()
            .map(|f| f.risk_level.severity().expect("filtered"))
            .max()
            .expect("non-empty");
        match max {
            0 => RiskLevel::Low,
            1 => RiskLevel::Medium,
            2 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    };

    let overall_rationale = if findings.is_empty() {
        "No detector produced evidence for this request; risk is unknown, not low.".to_string()
    } else {
        let parts: Vec<String> = findings
            .iter()
            .map(|f| {
                format!(
                    "{} ({:?}, confidence {:.2}{}): [{}] {}",
                    f.detector.name,
                    f.risk_level,
                    f.confidence,
                    if f.provenance.mock == Some(true) {
                        ", MOCK"
                    } else {
                        ""
                    },
                    f.reason_codes.join(","),
                    f.explanation
                )
            })
            .collect();
        parts.join(" | ")
    };

    let p = Provenance::of("cipherlayer-risk");
    RiskEvidenceBundle {
        schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
        bundle_id: cipherlayer_types::new_id(),
        request_id,
        aggregated_at: Utc::now(),
        overall_level,
        overall_rationale,
        findings,
        conflicts,
        detectors_unavailable,
        provenance: BundleProvenance {
            producer: p.producer,
            producer_version: p.producer_version,
            detector_contract_version: DETECTOR_CONTRACT_VERSION.into(),
        },
    }
}

// ---------------------------------------------------------------------------
// MOCKED: the only detector in milestone 1. It demonstrates the contract
// (reason codes, confidence, unknown handling) and detects nothing real.
// Every finding it emits carries provenance.mock = true and SG-MOCK-001.
// ---------------------------------------------------------------------------

pub struct MockDetector;

impl MockDetector {
    fn base(&self, intent: &TransactionIntent) -> (Subject, DetectorInfo, DetectorProvenance) {
        (
            Subject {
                kind: SubjectKind::TransactionIntent,
                value: intent.intent_id.to_string(),
                chain_id: Some(intent.chain_id.0),
            },
            DetectorInfo {
                name: "mock-detector".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            DetectorProvenance {
                data_source_class: DataSourceClass::LocalHeuristic,
                dataset_version: None,
                mock: Some(true),
            },
        )
    }

    fn finding(
        &self,
        intent: &TransactionIntent,
        risk_level: RiskLevel,
        confidence: f64,
        reason_codes: Vec<String>,
        explanation: String,
    ) -> DetectorOutput {
        let (subject, detector, provenance) = self.base(intent);
        DetectorOutput {
            schema_version: "1.0".into(),
            output_id: cipherlayer_types::new_id(),
            detector,
            evaluated_at: Utc::now(),
            subject,
            risk_level,
            confidence,
            reason_codes,
            explanation,
            provenance,
        }
    }
}

impl Detector for MockDetector {
    fn name(&self) -> &str {
        "mock-detector"
    }

    fn evaluate(&self, intent: &TransactionIntent) -> Vec<DetectorOutput> {
        use cipherlayer_evm::ActionKind;
        let mut out = Vec::new();
        if intent.is_unlimited_approval() {
            out.push(self.finding(
                intent,
                RiskLevel::High,
                0.9,
                vec!["SG-ALLOW-001".into(), "SG-MOCK-001".into()],
                "Unlimited token allowance requested (mock finding for contract demonstration)."
                    .into(),
            ));
        }
        match intent.decoded_action.kind {
            ActionKind::Unknown => out.push(self.finding(
                intent,
                RiskLevel::Unknown,
                1.0,
                vec!["SG-UNK-001".into(), "SG-MOCK-001".into()],
                "Calldata could not be classified; insufficient evidence to assess risk.".into(),
            )),
            ActionKind::Permit => out.push(self.finding(
                intent,
                RiskLevel::Medium,
                0.7,
                vec!["SG-ALLOW-002".into(), "SG-MOCK-001".into()],
                "Permit-style allowance-by-signature detected (mock finding).".into(),
            )),
            _ => {}
        }
        out
    }
}

// ---------------------------------------------------------------------------
// FPL CLI adapter — the first *real* detector consumer (contract v0.1).
// ---------------------------------------------------------------------------

/// Invokes the sibling Scam Guard product as a subprocess over the pinned
/// wire contract: the decoded intent goes to `scam-guard --json check intent -`
/// on stdin, findings come back as detector-output.v1 instances. No sibling
/// code is linked (family invariant). The managed `scam-guard` executable is
/// the default; `CIPHERLAYER_FPL_BIN` may point to an explicitly managed
/// installation. `CIPHERLAYER_FPL_MODE=mock` is test/demo-only and must never
/// become a production default.
///
/// Failure posture: if the binary is missing, fails, or returns malformed
/// output, the detector reports itself *unavailable* — the aggregate then
/// carries `detectors_unavailable`, which keeps the overall level from
/// reading as a quiet `low`. Detection failure is never silent safety.
pub struct FplCliDetector {
    bin: std::path::PathBuf,
    timeout: std::time::Duration,
}

impl FplCliDetector {
    /// Resolve the managed detector executable. A missing binary is an
    /// unavailable detector, not permission to substitute mock evidence.
    pub fn from_env() -> Self {
        let bin = std::env::var(FPL_BIN_ENV).unwrap_or_else(|_| DEFAULT_FPL_BIN.into());
        let timeout_ms = std::env::var(FPL_TIMEOUT_MS_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| (100..=30_000).contains(value))
            .unwrap_or(DEFAULT_FPL_TIMEOUT_MS);
        Self {
            bin: std::path::PathBuf::from(bin),
            timeout: std::time::Duration::from_millis(timeout_ms),
        }
    }

    pub fn mock_mode_requested() -> bool {
        std::env::var(FPL_MODE_ENV).as_deref() == Ok("mock")
    }

    fn run(&self, intent: &TransactionIntent) -> Result<Vec<DetectorOutput>, String> {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let payload = serde_json::to_vec(intent).map_err(|e| e.to_string())?;
        if payload.len() > MAX_FPL_INPUT_BYTES {
            return Err(format!(
                "refusing {}-byte detector input; maximum is {MAX_FPL_INPUT_BYTES} bytes",
                payload.len()
            ));
        }
        let mut child = Command::new(&self.bin)
            .args(["--json", "check", "intent", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot spawn {}: {e}", self.bin.display()))?;
        // The write happens on a thread: a child that never reads stdin would
        // otherwise block the pipe write past the pipe buffer and dodge the
        // timeout below entirely.
        let mut stdin = child.stdin.take().ok_or("no stdin")?;
        let stdin_writer = std::thread::spawn(move || -> Result<(), String> {
            stdin.write_all(&payload).map_err(|e| e.to_string())
        });
        let mut stdout = child.stdout.take().ok_or("no detector stdout")?;
        let stdout_reader = std::thread::spawn(move || -> Result<Vec<u8>, String> {
            let mut output = Vec::new();
            let mut bounded = (&mut stdout).take((MAX_FPL_OUTPUT_BYTES + 1) as u64);
            bounded
                .read_to_end(&mut output)
                .map_err(|e| e.to_string())?;
            Ok(output)
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(status) => break status,
                None if started.elapsed() >= self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdin_writer.join();
                    let _ = stdout_reader.join();
                    return Err(format!(
                        "scam-guard timed out after {} ms",
                        self.timeout.as_millis()
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        stdin_writer
            .join()
            .map_err(|_| "detector stdin writer panicked".to_string())?
            .map_err(|e| format!("cannot write detector input: {e}"))?;
        let stdout = stdout_reader
            .join()
            .map_err(|_| "detector stdout reader panicked".to_string())??;
        if stdout.len() > MAX_FPL_OUTPUT_BYTES {
            return Err(format!(
                "scam-guard output exceeded {MAX_FPL_OUTPUT_BYTES} bytes"
            ));
        }
        if !status.success() {
            return Err(format!("scam-guard exited with {status}"));
        }
        let assessment: serde_json::Value =
            serde_json::from_slice(&stdout).map_err(|e| format!("malformed output: {e}"))?;
        let raw_findings = assessment
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .ok_or("detector output has no findings array")?;
        let findings: Vec<DetectorOutput> = raw_findings
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("findings do not match detector-output.v1: {e}"))?;
        validate_findings(raw_findings, &findings)?;
        Ok(findings)
    }

    /// Evaluate, separating findings from unavailability so the pipeline can
    /// pass the failure into `detectors_unavailable` honestly.
    pub fn try_evaluate(&self, intent: &TransactionIntent) -> Result<Vec<DetectorOutput>, String> {
        self.run(intent)
    }
}

fn pinned_reason_codes() -> &'static std::collections::BTreeSet<String> {
    static CODES: std::sync::OnceLock<std::collections::BTreeSet<String>> =
        std::sync::OnceLock::new();
    CODES.get_or_init(|| {
        let registry: serde_json::Value = serde_json::from_str(include_str!(
            "../../../imports/scam-guard/reason-codes-registry.v1.json"
        ))
        .expect("pinned Scam Guard reason-code registry is valid JSON");
        registry["codes"]
            .as_array()
            .expect("pinned Scam Guard registry has codes")
            .iter()
            .filter_map(|code| code["code"].as_str().map(str::to_owned))
            .collect()
    })
}

fn validate_findings(
    raw_findings: &[serde_json::Value],
    findings: &[DetectorOutput],
) -> Result<(), String> {
    const ALLOWED_KEYS: [&str; 11] = [
        "schema_version",
        "output_id",
        "detector",
        "evaluated_at",
        "subject",
        "risk_level",
        "confidence",
        "reason_codes",
        "explanation",
        "provenance",
        "ext",
    ];
    let known_codes = pinned_reason_codes();
    for (raw, finding) in raw_findings.iter().zip(findings) {
        let object = raw.as_object().ok_or("detector finding is not an object")?;
        if let Some(key) = object
            .keys()
            .find(|key| !ALLOWED_KEYS.contains(&key.as_str()))
        {
            return Err(format!("detector finding contains unpinned field `{key}`"));
        }
        if !finding.schema_version.starts_with("1.")
            || finding.detector.name.trim().is_empty()
            || finding.detector.version.trim().is_empty()
            || finding.subject.value.trim().is_empty()
            || finding.explanation.trim().is_empty()
            || !finding.confidence.is_finite()
            || !(0.0..=1.0).contains(&finding.confidence)
            || finding.reason_codes.is_empty()
        {
            return Err("detector finding violates required v1 contract constraints".into());
        }
        if let Some(code) = finding
            .reason_codes
            .iter()
            .find(|code| !known_codes.contains(*code))
        {
            return Err(format!(
                "detector emitted unregistered pinned reason code `{code}`"
            ));
        }
    }
    Ok(())
}

impl Detector for FplCliDetector {
    fn name(&self) -> &str {
        "scam-guard-cli"
    }

    fn evaluate(&self, intent: &TransactionIntent) -> Vec<DetectorOutput> {
        self.run(intent).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherlayer_types::{Address, ChainId, U256};

    fn intent_for(data: &[u8]) -> TransactionIntent {
        let to = Address::from_slice(&[9u8; 20]);
        let decoded = cipherlayer_evm::decode_calldata(Some(to), U256::ZERO, data);
        TransactionIntent::from_decoded(
            cipherlayer_types::new_id(),
            ChainId(31337),
            serde_json::Value::Null,
            Address::from_slice(&[1u8; 20]),
            U256::ZERO,
            decoded,
        )
    }

    fn output(level: RiskLevel, confidence: f64) -> DetectorOutput {
        DetectorOutput {
            schema_version: "1.0".into(),
            output_id: cipherlayer_types::new_id(),
            detector: DetectorInfo {
                name: "t".into(),
                version: "0".into(),
            },
            evaluated_at: Utc::now(),
            subject: Subject {
                kind: SubjectKind::TransactionIntent,
                value: "x".into(),
                chain_id: None,
            },
            risk_level: level,
            confidence,
            reason_codes: vec!["SG-MOCK-001".into()],
            explanation: "t".into(),
            provenance: DetectorProvenance {
                data_source_class: DataSourceClass::LocalHeuristic,
                dataset_version: None,
                mock: Some(true),
            },
        }
    }

    #[test]
    fn empty_findings_aggregate_to_unknown() {
        let b = aggregate(cipherlayer_types::new_id(), vec![], vec![]);
        assert_eq!(b.overall_level, RiskLevel::Unknown);
        assert!(b.overall_rationale.contains("not low"));
    }

    #[test]
    fn unknown_findings_never_become_low() {
        let b = aggregate(
            cipherlayer_types::new_id(),
            vec![output(RiskLevel::Unknown, 1.0)],
            vec![],
        );
        assert_eq!(b.overall_level, RiskLevel::Unknown);
    }

    #[test]
    fn low_confidence_findings_do_not_set_severity() {
        let b = aggregate(
            cipherlayer_types::new_id(),
            vec![output(RiskLevel::Low, 0.1)],
            vec![],
        );
        assert_eq!(b.overall_level, RiskLevel::Unknown);
        assert_eq!(
            b.findings.len(),
            1,
            "finding preserved even below threshold"
        );
    }

    #[test]
    fn max_severity_wins_without_conflict() {
        let b = aggregate(
            cipherlayer_types::new_id(),
            vec![output(RiskLevel::Medium, 0.9), output(RiskLevel::High, 0.8)],
            vec![],
        );
        assert_eq!(b.overall_level, RiskLevel::High);
        assert!(b.conflicts.is_empty());
    }

    #[test]
    fn material_disagreement_is_conflicting_with_both_sides_visible() {
        let b = aggregate(
            cipherlayer_types::new_id(),
            vec![
                output(RiskLevel::Low, 0.9),
                output(RiskLevel::Critical, 0.9),
            ],
            vec![],
        );
        assert_eq!(b.overall_level, RiskLevel::Conflicting);
        assert_eq!(b.conflicts.len(), 1);
        assert_eq!(b.findings.len(), 2);
    }

    #[test]
    fn aggregation_is_order_independent() {
        let f1 = output(RiskLevel::Medium, 0.9);
        let f2 = output(RiskLevel::High, 0.8);
        let a = aggregate(
            cipherlayer_types::new_id(),
            vec![f1.clone(), f2.clone()],
            vec![],
        );
        let b = aggregate(cipherlayer_types::new_id(), vec![f2, f1], vec![]);
        assert_eq!(a.overall_level, b.overall_level);
    }

    #[test]
    fn mock_detector_flags_unlimited_approval_and_labels_itself() {
        let mut data = cipherlayer_evm::SELECTOR_APPROVE.to_vec();
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&[2u8; 20]);
        data.extend_from_slice(&U256::MAX.to_be_bytes::<32>());
        let intent = intent_for(&data);
        let findings = MockDetector.evaluate(&intent);
        assert!(findings
            .iter()
            .any(|f| f.reason_codes.contains(&"SG-ALLOW-001".to_string())));
        assert!(findings.iter().all(|f| f.provenance.mock == Some(true)));
    }

    #[test]
    fn mock_detector_reports_unknown_for_unclassified() {
        let intent = intent_for(&[0xde, 0xad, 0xbe, 0xef]);
        let findings = MockDetector.evaluate(&intent);
        let b = aggregate(intent.request_id, findings, vec![]);
        assert_eq!(b.overall_level, RiskLevel::Unknown);
    }

    #[test]
    fn subprocess_contract_rejects_unknown_reason_codes_and_extra_fields() {
        let mut finding = serde_json::to_value(output(RiskLevel::High, 0.9)).unwrap();
        finding["provenance"]["mock"] = serde_json::Value::Bool(false);
        let parsed: DetectorOutput = serde_json::from_value(finding.clone()).unwrap();
        assert!(validate_findings(&[finding.clone()], &[parsed]).is_ok());

        finding["reason_codes"] = serde_json::json!(["SG-NOT-999"]);
        let parsed: DetectorOutput = serde_json::from_value(finding.clone()).unwrap();
        assert!(validate_findings(&[finding], &[parsed]).is_err());

        let mut finding = serde_json::to_value(output(RiskLevel::High, 0.9)).unwrap();
        finding["unexpected"] = serde_json::json!(true);
        let parsed: DetectorOutput = serde_json::from_value(finding.clone()).unwrap();
        assert!(validate_findings(&[finding], &[parsed]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_timeout_is_reported_as_detector_failure() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "cipherlayer-fpl-timeout-{}",
            cipherlayer_types::new_id()
        ));
        std::fs::write(&path, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();

        let detector = FplCliDetector {
            bin: path.clone(),
            timeout: std::time::Duration::from_millis(50),
        };
        let result = detector.try_evaluate(&intent_for(&[]));
        let _ = std::fs::remove_file(path);
        assert!(
            matches!(&result, Err(message) if message.contains("timed out")),
            "unexpected detector result: {result:?}"
        );
    }

    /// A detector that never reads stdin must not defeat the timeout: with a
    /// payload larger than the OS pipe buffer, the stdin write itself blocks
    /// and has to be governed by the same deadline as the child.
    #[cfg(unix)]
    #[test]
    fn subprocess_ignoring_stdin_still_times_out() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "cipherlayer-fpl-stdin-{}",
            cipherlayer_types::new_id()
        ));
        std::fs::write(&path, "#!/bin/sh\nsleep 60\n").unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();

        let detector = FplCliDetector {
            bin: path.clone(),
            timeout: std::time::Duration::from_millis(200),
        };
        // ~100 KiB of calldata serializes well past the ~64 KiB pipe buffer
        // while staying under MAX_FPL_INPUT_BYTES.
        let result = detector.try_evaluate(&intent_for(&vec![0xABu8; 100 * 1024]));
        let _ = std::fs::remove_file(path);
        assert!(
            matches!(&result, Err(message) if message.contains("timed out")),
            "unexpected detector result: {result:?}"
        );
    }
}
