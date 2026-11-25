//! Deterministic policy engine (schemas policy.v1, policy-decision.v1).
//!
//! Invariants enforced by construction:
//! - evaluation is a pure function of (policy, intent, evidence): same inputs,
//!   same decision — no clock, no randomness, no network, no AI input;
//! - unlimited ERC-20 approvals can be denied or escalated, never silently
//!   allowed (`UnlimitedApprovalAction` has no `Allow` member — CL-POL-002);
//! - unknown decoded actions / missing simulation take a restrictive path
//!   (`UnknownBehavior` has no `Allow` member — CL-POL-004);
//! - risk evidence can escalate but never authorize; a denial cannot be
//!   downgraded by anything in this crate's API (CL-POL-005).

use cipherlayer_evm::ActionKind;
use cipherlayer_intent::TransactionIntent;
use cipherlayer_types::{Address, Confidence, Provenance, RiskLevel, U256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// -- Policy document ---------------------------------------------------------

/// Action for unlimited approvals. `Allow` is intentionally not a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlimitedApprovalAction {
    Deny,
    Escalate,
}

/// Behavior for unknown/undecodable actions. `Allow` is intentionally not a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownBehavior {
    Deny,
    Escalate,
}

/// Time-boxed "soft override" for unlimited approvals (operator decision
/// AC-005, 2026-07-04): while the window is active, unlimited approvals are
/// ESCALATED (explicit extra confirmation) instead of the default action.
/// The window is bounded to 720 hours (30 days) and must be refreshed after
/// expiry. There is still no silent-allow path. Reminder notifications and
/// periodic unlimited-approval summaries (6/12/18/24h) are W2 UI scope; the
/// audit log already records every escalated approval for those reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlimitedApprovalOverride {
    pub enabled_at: chrono::DateTime<chrono::Utc>,
    /// Must lie within (enabled_at, enabled_at + 720h].
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Maximum soft-override window: 720 hours = 30 days (AC-005).
pub const MAX_OVERRIDE_HOURS: i64 = 720;

impl UnlimitedApprovalOverride {
    /// Deterministic activity check: evaluated against the intent's creation
    /// time, not the wall clock, so identical inputs yield identical decisions.
    pub fn is_active_at(&self, at: chrono::DateTime<chrono::Utc>) -> bool {
        at >= self.enabled_at && at < self.expires_at
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.expires_at <= self.enabled_at {
            return Err(PolicyError::InvalidPolicy(
                "unlimited_approval_override: expires_at must be after enabled_at".into(),
            ));
        }
        if self.expires_at - self.enabled_at > chrono::Duration::hours(MAX_OVERRIDE_HOURS) {
            return Err(PolicyError::InvalidPolicy(format!(
                "unlimited_approval_override window exceeds the {MAX_OVERRIDE_HOURS}h (30 day) maximum — refresh instead of extending"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRules {
    #[serde(default)]
    pub allowed_chain_ids: Option<Vec<u64>>,
    #[serde(default)]
    pub contract_allowlist: Option<Vec<Address>>,
    #[serde(default)]
    pub contract_denylist: Vec<Address>,
    #[serde(default)]
    pub function_denylist: Vec<String>,
    #[serde(default)]
    pub max_value_wei_per_tx: Option<U256>,
    #[serde(default)]
    pub max_gas_limit: Option<U256>,
    pub unlimited_approval_action: UnlimitedApprovalAction,
    /// AC-005 soft override: while active, unlimited approvals escalate
    /// instead of the default action. Bounded, expiring, refresh-required.
    #[serde(default)]
    pub unlimited_approval_override: Option<UnlimitedApprovalOverride>,
    #[serde(default)]
    pub approval_amount_escalation_threshold_wei: Option<U256>,
    pub unknown_action_behavior: UnknownBehavior,
    /// Confident risk at/above this level escalates. Unknown/conflicting always escalate.
    pub risk_escalation_at: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: String,
    pub policy_id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub rules: PolicyRules,
}

impl Policy {
    /// Default development policy: dev chain only, unlimited approvals denied,
    /// unknown escalates, high risk escalates.
    pub fn default_dev() -> Self {
        Policy {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            policy_id: cipherlayer_types::new_id(),
            name: "default-dev".into(),
            created_at: chrono::Utc::now(),
            rules: PolicyRules {
                allowed_chain_ids: Some(vec![31337]),
                contract_allowlist: None,
                contract_denylist: vec![],
                function_denylist: vec![],
                max_value_wei_per_tx: Some(U256::from(10u128.pow(21))), // 1000 dev ETH
                max_gas_limit: Some(U256::from(10_000_000u64)),
                unlimited_approval_action: UnlimitedApprovalAction::Deny,
                unlimited_approval_override: None,
                approval_amount_escalation_threshold_wei: Some(U256::from(10u128.pow(24))),
                unknown_action_behavior: UnknownBehavior::Escalate,
                risk_escalation_at: RiskLevel::High,
            },
        }
    }

    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        let policy: Policy =
            serde_json::from_str(json).map_err(|e| PolicyError::InvalidPolicy(e.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Structural validation beyond serde (window bounds, etc.).
    pub fn validate(&self) -> Result<(), PolicyError> {
        if let Some(ov) = &self.rules.unlimited_approval_override {
            ov.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy document: {0}")]
    InvalidPolicy(String),
}

// -- Evaluation inputs --------------------------------------------------------

/// Simulation availability as the policy engine sees it. `Unavailable` means
/// simulation was not run (e.g. `tx evaluate --no-sim`); the pipeline itself
/// terminates on SimulationError before policy in the signing path.
/// `NotApplicable` (v0.4, additive) is a distinct, honest state for requests
/// simulation was never meant to cover at all — `typed_data`/`personal_message`
/// signing produces no on-chain state change to simulate. It is deliberately
/// excluded from the "missing evidence" restrictive path below
/// (`Unavailable`/`SimulationError` still are): the difference is "evaluated
/// and out of scope" vs. "should have run and didn't", matching the schema's
/// null/absent convention rather than laundering one into the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationStatus {
    Success,
    Revert,
    SimulationError,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Clone, Copy)]
pub struct EvaluationEvidence {
    pub simulation: SimulationStatus,
    pub risk: Option<RiskLevel>,
}

// -- Decision -----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Escalate,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reason {
    pub code: String,
    pub rule: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceConsidered {
    pub intent_confidence: Confidence,
    pub simulation: SimulationStatus,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub schema_version: String,
    pub decision_id: Uuid,
    pub request_id: Uuid,
    pub intent_id: Uuid,
    pub policy_id: Uuid,
    pub verdict: Verdict,
    pub reasons: Vec<Reason>,
    pub evidence_considered: EvidenceConsidered,
    pub provenance: Provenance,
}

// -- Engine -------------------------------------------------------------------

/// Deterministic evaluation. All rules are checked; reasons accumulate; the
/// verdict is the most severe outcome across rules.
pub fn evaluate(
    policy: &Policy,
    intent: &TransactionIntent,
    evidence: EvaluationEvidence,
) -> PolicyDecision {
    let mut reasons: Vec<Reason> = Vec::new();
    let mut verdict = Verdict::Allow;
    let bump = |v: Verdict, verdict: &mut Verdict| {
        if v > *verdict {
            *verdict = v;
        }
    };
    let r = &policy.rules;

    // 1. Chain restriction.
    if let Some(chains) = &r.allowed_chain_ids {
        if !chains.contains(&intent.chain_id.0) {
            bump(Verdict::Deny, &mut verdict);
            reasons.push(Reason {
                code: "POL-CHAIN-001".into(),
                rule: "allowed_chain_ids".into(),
                detail: format!(
                    "chain {} is not in the allowed set {:?}",
                    intent.chain_id, chains
                ),
            });
        }
    }

    // 1.5. Typed-data domain chain-id mismatch (v0.4): a definite mismatch
    // between the EIP-712 domain's declared chainId and the session/envelope
    // chain is a cross-chain replay pattern (same family as AC-D) — fail
    // closed. `None` (domain omitted chainId, legal per EIP-712) is not a
    // mismatch and is not flagged here.
    if intent.domain_chain_id_matches == Some(false) {
        bump(Verdict::Deny, &mut verdict);
        reasons.push(Reason {
            code: "POL-CHAIN-002".into(),
            rule: "domain_chain_id_matches".into(),
            detail: format!(
                "typed-data domain chainId does not match the session chain {} — refusing to sign across chains",
                intent.chain_id
            ),
        });
    }

    // 2. Contract deny/allow lists — evaluated against the interaction target.
    let target: Option<Address> = intent
        .raw
        .get("to")
        .and_then(|v| v.as_str())
        .and_then(|s| cipherlayer_evm::parse_address(s).ok());
    if let Some(t) = target {
        if r.contract_denylist.contains(&t) {
            bump(Verdict::Deny, &mut verdict);
            reasons.push(Reason {
                code: "POL-DENY-001".into(),
                rule: "contract_denylist".into(),
                detail: format!("target contract {t} is denylisted"),
            });
        }
        if let Some(allow) = &r.contract_allowlist {
            if !allow.contains(&t) {
                bump(Verdict::Deny, &mut verdict);
                reasons.push(Reason {
                    code: "POL-ALW-001".into(),
                    rule: "contract_allowlist".into(),
                    detail: format!("target contract {t} is not on the allowlist"),
                });
            }
        }
    } else if r.contract_allowlist.is_some()
        && intent.decoded_action.kind != ActionKind::ContractCreation
    {
        // Allowlist configured but target unresolvable: restrictive path.
        bump(Verdict::Deny, &mut verdict);
        reasons.push(Reason {
            code: "POL-ALW-002".into(),
            rule: "contract_allowlist".into(),
            detail: "allowlist is configured but the interaction target could not be resolved"
                .into(),
        });
    }

    // 3. Function denylist.
    if let Some(sel) = &intent.decoded_action.function_selector {
        if r.function_denylist
            .iter()
            .any(|d| d.eq_ignore_ascii_case(sel))
        {
            bump(Verdict::Deny, &mut verdict);
            reasons.push(Reason {
                code: "POL-FUN-001".into(),
                rule: "function_denylist".into(),
                detail: format!("function selector {sel} is denylisted"),
            });
        }
    }

    // 4. Approval rules (CL-POL-002 / AC-005).
    if let Some(allowance) = &intent.allowance {
        match allowance.kind {
            cipherlayer_evm::AllowanceKind::Unlimited => {
                let spender = intent
                    .spender
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "<unresolved spender>".into());
                let override_active = r
                    .unlimited_approval_override
                    .as_ref()
                    .is_some_and(|ov| ov.is_active_at(intent.created_at));
                if override_active {
                    // AC-005 soft override: escalate (explicit confirmation),
                    // never silent allow, while the bounded window is active.
                    let ov = r.unlimited_approval_override.as_ref().expect("checked");
                    bump(Verdict::Escalate, &mut verdict);
                    reasons.push(Reason {
                        code: "POL-APR-004".into(),
                        rule: "unlimited_approval_override".into(),
                        detail: format!(
                            "unlimited token allowance to {spender} is ESCALATED under a time-boxed soft override active until {} — explicit confirmation required; override must be refreshed after expiry",
                            ov.expires_at.to_rfc3339()
                        ),
                    });
                } else {
                    let (v, action) = match r.unlimited_approval_action {
                        UnlimitedApprovalAction::Deny => (Verdict::Deny, "denied"),
                        UnlimitedApprovalAction::Escalate => (Verdict::Escalate, "escalated"),
                    };
                    bump(v, &mut verdict);
                    let expired_note = if r.unlimited_approval_override.is_some() {
                        " (a soft override exists but is not active for this request — refresh it to use it)"
                    } else {
                        ""
                    };
                    reasons.push(Reason {
                        code: "POL-APR-001".into(),
                        rule: "unlimited_approval_action".into(),
                        detail: format!(
                            "unlimited token allowance to {spender} is {action} by policy (silent allow is not possible){expired_note}"
                        ),
                    });
                }
            }
            cipherlayer_evm::AllowanceKind::Exact => {
                if let (Some(threshold), Some(amount)) =
                    (r.approval_amount_escalation_threshold_wei, allowance.amount)
                {
                    if amount > threshold {
                        bump(Verdict::Escalate, &mut verdict);
                        reasons.push(Reason {
                            code: "POL-APR-002".into(),
                            rule: "approval_amount_escalation_threshold_wei".into(),
                            detail: format!(
                                "bounded allowance {amount} exceeds the escalation threshold {threshold}"
                            ),
                        });
                    }
                }
            }
            cipherlayer_evm::AllowanceKind::Unknown => {
                bump(Verdict::Escalate, &mut verdict);
                reasons.push(Reason {
                    code: "POL-APR-003".into(),
                    rule: "allowance_unknown".into(),
                    detail: "an approval was detected but its amount could not be resolved".into(),
                });
            }
        }
    }

    // 5. Value / gas limits.
    if let Some(max) = r.max_value_wei_per_tx {
        let value = intent
            .raw
            .get("value_wei")
            .and_then(|v| v.as_str())
            .and_then(|s| U256::from_str_radix(s, 10).ok())
            .unwrap_or(U256::ZERO);
        if value > max {
            bump(Verdict::Deny, &mut verdict);
            reasons.push(Reason {
                code: "POL-LIM-001".into(),
                rule: "max_value_wei_per_tx".into(),
                detail: format!("value {value} wei exceeds the per-transaction limit {max}"),
            });
        }
    }
    if let (Some(max_gas), Some(gas)) = (
        r.max_gas_limit,
        intent.gas.as_ref().and_then(|g| g.limit.or(g.estimated)),
    ) {
        if gas > max_gas {
            bump(Verdict::Escalate, &mut verdict);
            reasons.push(Reason {
                code: "POL-LIM-002".into(),
                rule: "max_gas_limit".into(),
                detail: format!("gas {gas} exceeds the policy gas ceiling {max_gas}"),
            });
        }
    }

    // 6. Unknown decoded action / simulation gaps (CL-POL-004): restrictive path.
    let action_unknown = intent.decoded_action.kind == ActionKind::Unknown
        || intent.confidence == Confidence::Unknown;
    let sim_missing = matches!(
        evidence.simulation,
        SimulationStatus::SimulationError | SimulationStatus::Unavailable
    );
    if action_unknown || sim_missing {
        let (v, what) = match r.unknown_action_behavior {
            UnknownBehavior::Deny => (Verdict::Deny, "denied"),
            UnknownBehavior::Escalate => (Verdict::Escalate, "escalated"),
        };
        bump(v, &mut verdict);
        reasons.push(Reason {
            code: "POL-UNK-001".into(),
            rule: "unknown_action_behavior".into(),
            detail: format!(
                "{} — request is {what}, never silently allowed",
                match (action_unknown, sim_missing) {
                    (true, true) => "decoded action is unknown and simulation evidence is missing",
                    (true, false) => "decoded action is unknown",
                    _ => "simulation evidence is missing or failed",
                }
            ),
        });
    }
    if evidence.simulation == SimulationStatus::Revert {
        bump(Verdict::Escalate, &mut verdict);
        reasons.push(Reason {
            code: "POL-SIM-001".into(),
            rule: "simulation_revert".into(),
            detail: "simulation predicts this transaction reverts".into(),
        });
    }

    // 7. Risk evidence: escalates, never authorizes (CL-POL-005).
    match evidence.risk {
        None => {
            bump(Verdict::Escalate, &mut verdict);
            reasons.push(Reason {
                code: "POL-RSK-002".into(),
                rule: "risk_evidence".into(),
                detail: "no risk evidence available — treated as unknown, not low".into(),
            });
        }
        Some(level) => match level.severity() {
            None => {
                bump(Verdict::Escalate, &mut verdict);
                reasons.push(Reason {
                    code: "POL-RSK-002".into(),
                    rule: "risk_evidence".into(),
                    detail: format!("risk evidence is {level:?} — escalated, never treated as low"),
                });
            }
            Some(sev) => {
                let threshold = policy
                    .rules
                    .risk_escalation_at
                    .severity()
                    .unwrap_or(2 /* High if misconfigured */);
                if sev >= threshold {
                    bump(Verdict::Escalate, &mut verdict);
                    reasons.push(Reason {
                        code: "POL-RSK-001".into(),
                        rule: "risk_escalation_at".into(),
                        detail: format!(
                            "confident risk level {level:?} is at/above the escalation threshold"
                        ),
                    });
                }
            }
        },
    }

    if reasons.is_empty() {
        reasons.push(Reason {
            code: "POL-OK-001".into(),
            rule: "default".into(),
            detail: "no policy rule was violated".into(),
        });
    }

    PolicyDecision {
        schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
        decision_id: cipherlayer_types::new_id(),
        request_id: intent.request_id,
        intent_id: intent.intent_id,
        policy_id: policy.policy_id,
        verdict,
        reasons,
        evidence_considered: EvidenceConsidered {
            intent_confidence: intent.confidence,
            simulation: evidence.simulation,
            risk: evidence
                .risk
                .map(|r| format!("{r:?}").to_lowercase())
                .unwrap_or_else(|| "unavailable".into()),
        },
        provenance: Provenance::of("cipherlayer-policy"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherlayer_evm::{decode_calldata, SELECTOR_APPROVE};
    use cipherlayer_types::ChainId;

    fn addr(n: u8) -> Address {
        Address::from_slice(&[n; 20])
    }

    fn approve_intent(amount: U256, chain: u64) -> TransactionIntent {
        let mut d = SELECTOR_APPROVE.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(addr(2).as_slice());
        d.extend_from_slice(&amount.to_be_bytes::<32>());
        let decoded = decode_calldata(Some(addr(9)), U256::ZERO, &d);
        TransactionIntent::from_decoded(
            cipherlayer_types::new_id(),
            ChainId(chain),
            serde_json::json!({"to": format!("{}", addr(9)), "value_wei": "0"}),
            addr(1),
            U256::ZERO,
            decoded,
        )
    }

    fn ok_evidence() -> EvaluationEvidence {
        EvaluationEvidence {
            simulation: SimulationStatus::Success,
            risk: Some(RiskLevel::Low),
        }
    }

    #[test]
    fn unlimited_approval_denied_by_default() {
        let d = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::MAX, 31337),
            ok_evidence(),
        );
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d.reasons.iter().any(|r| r.code == "POL-APR-001"));
    }

    #[test]
    fn unlimited_approval_can_escalate_but_never_allow() {
        let mut p = Policy::default_dev();
        p.rules.unlimited_approval_action = UnlimitedApprovalAction::Escalate;
        let d = evaluate(&p, &approve_intent(U256::MAX, 31337), ok_evidence());
        assert_eq!(d.verdict, Verdict::Escalate);
        // "allow" is unrepresentable: deserializing it must fail.
        assert!(serde_json::from_str::<UnlimitedApprovalAction>("\"allow\"").is_err());
    }

    #[test]
    fn exact_approval_allowed_with_reasons() {
        let d = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(100u64), 31337),
            ok_evidence(),
        );
        assert_eq!(d.verdict, Verdict::Allow);
        assert!(!d.reasons.is_empty());
    }

    #[test]
    fn wrong_chain_denied() {
        let d = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(1u64), 1),
            ok_evidence(),
        );
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d.reasons.iter().any(|r| r.code == "POL-CHAIN-001"));
    }

    #[test]
    fn unknown_action_never_silently_allowed() {
        let decoded = decode_calldata(Some(addr(9)), U256::ZERO, &[0xde, 0xad, 0xbe, 0xef]);
        let intent = TransactionIntent::from_decoded(
            cipherlayer_types::new_id(),
            ChainId(31337),
            serde_json::json!({"to": format!("{}", addr(9))}),
            addr(1),
            U256::ZERO,
            decoded,
        );
        let d = evaluate(&Policy::default_dev(), &intent, ok_evidence());
        assert_ne!(d.verdict, Verdict::Allow);
        assert!(d.reasons.iter().any(|r| r.code == "POL-UNK-001"));
    }

    #[test]
    fn missing_simulation_takes_restrictive_path() {
        let d = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(1u64), 31337),
            EvaluationEvidence {
                simulation: SimulationStatus::Unavailable,
                risk: Some(RiskLevel::Low),
            },
        );
        assert_ne!(d.verdict, Verdict::Allow);
    }

    #[test]
    fn unknown_or_missing_risk_escalates() {
        for risk in [None, Some(RiskLevel::Unknown), Some(RiskLevel::Conflicting)] {
            let d = evaluate(
                &Policy::default_dev(),
                &approve_intent(U256::from(1u64), 31337),
                EvaluationEvidence {
                    simulation: SimulationStatus::Success,
                    risk,
                },
            );
            assert_eq!(d.verdict, Verdict::Escalate, "risk={risk:?}");
            assert!(d.reasons.iter().any(|r| r.code == "POL-RSK-002"));
        }
    }

    #[test]
    fn high_risk_escalates_low_does_not() {
        let d = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(1u64), 31337),
            EvaluationEvidence {
                simulation: SimulationStatus::Success,
                risk: Some(RiskLevel::High),
            },
        );
        assert_eq!(d.verdict, Verdict::Escalate);
        let d2 = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(1u64), 31337),
            ok_evidence(),
        );
        assert_eq!(d2.verdict, Verdict::Allow);
    }

    #[test]
    fn denylist_and_value_limit_deny() {
        let mut p = Policy::default_dev();
        p.rules.contract_denylist = vec![addr(9)];
        let d = evaluate(&p, &approve_intent(U256::from(1u64), 31337), ok_evidence());
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d.reasons.iter().any(|r| r.code == "POL-DENY-001"));
    }

    #[test]
    fn evaluation_is_deterministic() {
        let p = Policy::default_dev();
        let i = approve_intent(U256::MAX, 31337);
        let a = evaluate(&p, &i, ok_evidence());
        let b = evaluate(&p, &i, ok_evidence());
        assert_eq!(a.verdict, b.verdict);
        assert_eq!(
            a.reasons.iter().map(|r| &r.code).collect::<Vec<_>>(),
            b.reasons.iter().map(|r| &r.code).collect::<Vec<_>>()
        );
    }

    #[test]
    fn set_approval_for_all_grant_hits_unlimited_rules() {
        // Blanket operator grants are unlimited-class authority (CL-EVM-007).
        let mut d = cipherlayer_evm::SELECTOR_SET_APPROVAL_FOR_ALL.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(addr(2).as_slice());
        let mut flag = [0u8; 32];
        flag[31] = 1;
        d.extend_from_slice(&flag);
        let decoded = decode_calldata(Some(addr(9)), U256::ZERO, &d);
        let intent = TransactionIntent::from_decoded(
            cipherlayer_types::new_id(),
            ChainId(31337),
            serde_json::json!({"to": format!("{}", addr(9)), "value_wei": "0"}),
            addr(1),
            U256::ZERO,
            decoded,
        );
        let verdict = evaluate(&Policy::default_dev(), &intent, ok_evidence());
        assert_eq!(verdict.verdict, Verdict::Deny);
        assert!(verdict.reasons.iter().any(|r| r.code == "POL-APR-001"));

        // Revocation (false) is not treated as unlimited.
        let mut d2 = cipherlayer_evm::SELECTOR_SET_APPROVAL_FOR_ALL.to_vec();
        d2.extend_from_slice(&[0u8; 12]);
        d2.extend_from_slice(addr(2).as_slice());
        d2.extend_from_slice(&[0u8; 32]);
        let decoded2 = decode_calldata(Some(addr(9)), U256::ZERO, &d2);
        let intent2 = TransactionIntent::from_decoded(
            cipherlayer_types::new_id(),
            ChainId(31337),
            serde_json::json!({"to": format!("{}", addr(9)), "value_wei": "0"}),
            addr(1),
            U256::ZERO,
            decoded2,
        );
        let verdict2 = evaluate(&Policy::default_dev(), &intent2, ok_evidence());
        assert_eq!(verdict2.verdict, Verdict::Allow);
    }

    #[test]
    fn soft_override_escalates_unlimited_while_active() {
        let mut p = Policy::default_dev();
        let now = chrono::Utc::now();
        p.rules.unlimited_approval_override = Some(UnlimitedApprovalOverride {
            enabled_at: now - chrono::Duration::hours(1),
            expires_at: now + chrono::Duration::hours(23),
            reason: Some("testing automated strategy".into()),
        });
        let d = evaluate(&p, &approve_intent(U256::MAX, 31337), ok_evidence());
        assert_eq!(d.verdict, Verdict::Escalate);
        assert!(d.reasons.iter().any(|r| r.code == "POL-APR-004"));
        // Never silent allow, even under an active override.
        assert_ne!(d.verdict, Verdict::Allow);
    }

    #[test]
    fn expired_soft_override_falls_back_to_default_deny() {
        let mut p = Policy::default_dev();
        let now = chrono::Utc::now();
        p.rules.unlimited_approval_override = Some(UnlimitedApprovalOverride {
            enabled_at: now - chrono::Duration::hours(48),
            expires_at: now - chrono::Duration::hours(24),
            reason: None,
        });
        let d = evaluate(&p, &approve_intent(U256::MAX, 31337), ok_evidence());
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d
            .reasons
            .iter()
            .any(|r| r.code == "POL-APR-001" && r.detail.contains("refresh")));
    }

    #[test]
    fn soft_override_window_bounded_to_720_hours() {
        let now = chrono::Utc::now();
        let too_long = UnlimitedApprovalOverride {
            enabled_at: now,
            expires_at: now + chrono::Duration::hours(MAX_OVERRIDE_HOURS + 1),
            reason: None,
        };
        let mut p = Policy::default_dev();
        p.rules.unlimited_approval_override = Some(too_long);
        assert!(p.validate().is_err());
        // And a policy file with an oversized window is rejected on load.
        let s = serde_json::to_string(&p).unwrap();
        assert!(Policy::from_json(&s).is_err());

        let inverted = UnlimitedApprovalOverride {
            enabled_at: now,
            expires_at: now - chrono::Duration::hours(1),
            reason: None,
        };
        p.rules.unlimited_approval_override = Some(inverted);
        assert!(p.validate().is_err());

        let ok = UnlimitedApprovalOverride {
            enabled_at: now,
            expires_at: now + chrono::Duration::hours(MAX_OVERRIDE_HOURS),
            reason: None,
        };
        p.rules.unlimited_approval_override = Some(ok);
        assert!(p.validate().is_ok());
    }

    /// v0.4: a typed-data domain claiming a different chain than the session
    /// is denied outright (POL-CHAIN-002), regardless of everything else
    /// about the request.
    #[test]
    fn domain_chain_id_mismatch_is_denied() {
        let intent =
            approve_intent(U256::from(1u64), 31337).with_domain_chain_id_matches(Some(false));
        let d = evaluate(&Policy::default_dev(), &intent, ok_evidence());
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d.reasons.iter().any(|r| r.code == "POL-CHAIN-002"));
    }

    /// A domain that omits chainId (`None`) is not a mismatch.
    #[test]
    fn missing_domain_chain_id_is_not_denied() {
        let intent = approve_intent(U256::from(1u64), 31337).with_domain_chain_id_matches(None);
        let d = evaluate(&Policy::default_dev(), &intent, ok_evidence());
        assert!(!d.reasons.iter().any(|r| r.code == "POL-CHAIN-002"));
    }

    /// v0.4: `NotApplicable` simulation (signature-only requests) does not,
    /// by itself, trip the restrictive unknown/missing-simulation path —
    /// unlike `Unavailable`, which still does. A known, bounded approval with
    /// N/A simulation is allowed exactly as it would be with a successful one.
    #[test]
    fn simulation_not_applicable_does_not_force_unknown_escalation() {
        let d = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(100u64), 31337),
            EvaluationEvidence {
                simulation: SimulationStatus::NotApplicable,
                risk: Some(RiskLevel::Low),
            },
        );
        assert!(!d.reasons.iter().any(|r| r.code == "POL-UNK-001"));

        // Unavailable, by contrast, still takes the restrictive path.
        let d2 = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(100u64), 31337),
            EvaluationEvidence {
                simulation: SimulationStatus::Unavailable,
                risk: Some(RiskLevel::Low),
            },
        );
        assert!(d2.reasons.iter().any(|r| r.code == "POL-UNK-001"));
    }

    #[test]
    fn policy_json_round_trip_and_rejects_unknown_fields() {
        let p = Policy::default_dev();
        let s = serde_json::to_string(&p).unwrap();
        let back = Policy::from_json(&s).unwrap();
        assert_eq!(back.name, "default-dev");
        assert!(Policy::from_json("{\"schema_version\":\"1.0\",\"bogus\":1}").is_err());
    }
}
