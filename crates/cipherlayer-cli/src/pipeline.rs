//! The signing pipeline: orchestrates validate → permission → decode →
//! simulate → risk → policy → user review → vault → broadcast, with the
//! state machine enforcing order and the audit log recording every step.
//!
//! This module wires the trust-spine crates together; it introduces no
//! security decisions of its own. Anything that looks like a decision here
//! (e.g. the confirmation prompt) is explicitly presentation: the deciding
//! checks are re-validated inside `cipherlayer-vault`.

use cipherlayer_audit::{AuditLog, EventKind};
use cipherlayer_chain::adapter::{ChainBroadcaster, ChainObserver};
use cipherlayer_chain::ChainRegistry;
use cipherlayer_evm::adapter::{EvmAdapter, EvmBuildInput, EvmTxStatus};
use cipherlayer_intent::TransactionIntent;
use cipherlayer_policy::{EvaluationEvidence, Policy, PolicyDecision, SimulationStatus, Verdict};
use cipherlayer_provider::{
    validate, PayloadKind, PermissionStore, TransactionRequestEnvelope, ValidatedRequest,
};
use cipherlayer_risk::{aggregate, Detector, MockDetector, RiskEvidenceBundle};
use cipherlayer_simulation::{
    AnvilSimulator, SimOutcome, SimTx, SimulationProvider, SimulationResult,
};
use cipherlayer_types::state::{Lifecycle, LifecycleState};
use cipherlayer_types::{AccessClass, U256};
use cipherlayer_vault::{
    Capability, ConfirmationSurface, MessagePayload, SignOutcome, TxParams, UserAuthorization,
    Vault, VaultBackend, VaultSigningRequest,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("audit log error: {0}")]
    Audit(#[from] cipherlayer_audit::AuditError),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("internal state error: {0}")]
    State(String),
}

/// How USER_REVIEW is answered. `AssumeYes` is the CLI `--yes` flag — an
/// explicit, logged confirmation supplied up front (required for signing
/// commands per CL-WAL-007); `Interactive` prompts on stdin; `Reject` is
/// used by tests and non-interactive refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMode {
    Interactive,
    AssumeYes,
    Reject,
    /// USER_REVIEW delegated to the Vault-side confirmation surface
    /// (trusted-confirmation-surface.md): the decision is made by the vault
    /// daemon in system-owned chrome, never in this process. Requires a
    /// remote vault (CIPHERLAYER_VAULT_SOCKET).
    VaultSurface,
}

pub struct PipelineOutcome {
    pub final_state: LifecycleState,
    pub request_id: uuid::Uuid,
    /// `None` until a Vault signing request was actually constructed.
    pub signing_request_id: Option<uuid::Uuid>,
    pub intent: Option<TransactionIntent>,
    pub simulation: Option<SimulationResult>,
    pub risk: Option<RiskEvidenceBundle>,
    pub decision: Option<PolicyDecision>,
    pub tx_hash: Option<String>,
    /// v0.4: the raw signature for `typed_data`/`personal_message` requests
    /// (`0x` + 130 hex chars). `None` for `evm_transaction` requests (which
    /// carry `tx_hash` instead) and for any non-signed outcome.
    pub signature_hex: Option<String>,
    pub notes: Vec<String>,
}

pub struct Pipeline {
    pub registry: ChainRegistry,
    pub policy: Policy,
    pub audit: AuditLog,
    pub permissions: PermissionStore,
    pub vault: VaultBackend,
    pub rpc_url: String,
}

impl Pipeline {
    pub fn new(policy: Policy, audit: AuditLog, vault: Vault, rpc_url: &str) -> Self {
        Self::with_backend(policy, audit, VaultBackend::InProcess(vault), rpc_url)
    }

    /// Construct against an explicit vault backend — the ADR-004 process
    /// split: pass `VaultBackend::remote(..)` to keep key material in the
    /// `cipherlayer-vaultd` process instead of this one.
    pub fn with_backend(
        policy: Policy,
        audit: AuditLog,
        vault: VaultBackend,
        rpc_url: &str,
    ) -> Self {
        Self {
            registry: ChainRegistry::builtin(),
            policy,
            audit,
            permissions: PermissionStore::new(),
            vault,
            rpc_url: rpc_url.to_string(),
        }
    }

    fn audit_step(
        &self,
        kind: EventKind,
        lifecycle: &Lifecycle,
        payload: serde_json::Value,
    ) -> Result<(), PipelineError> {
        let mut payload = payload;
        payload["state"] = json!(lifecycle.state());
        self.audit
            .append(kind, Some(lifecycle.request_id()), payload)?;
        Ok(())
    }

    fn advance(&self, lifecycle: &mut Lifecycle, to: LifecycleState) -> Result<(), PipelineError> {
        if let Err(e) = lifecycle.advance(to) {
            // A rejected transition is itself auditable evidence (T-25).
            let _ = self.audit.append(
                EventKind::IllegalTransitionAttempted,
                Some(lifecycle.request_id()),
                json!({"from": e.from, "to": e.to}),
            );
            return Err(PipelineError::State(e.to_string()));
        }
        Ok(())
    }

    /// Run the full signing pipeline for one envelope.
    pub async fn process(
        &mut self,
        envelope: TransactionRequestEnvelope,
        review: ReviewMode,
    ) -> Result<PipelineOutcome, PipelineError> {
        let mut lifecycle = Lifecycle::start(envelope.request_id);
        let mut notes: Vec<String> = Vec::new();
        self.audit_step(
            EventKind::RequestReceived,
            &lifecycle,
            json!({"caller": envelope.caller, "chain_id": envelope.chain_id, "access": envelope.access, "payload": envelope.payload}),
        )?;

        // 1. VALIDATED — fail closed.
        let validated: ValidatedRequest = match validate(&envelope, &self.registry) {
            Ok(v) => v,
            Err(e) => {
                self.advance(&mut lifecycle, LifecycleState::Rejected)?;
                self.audit_step(
                    EventKind::Failure,
                    &lifecycle,
                    json!({"phase": "validation", "error": e.to_string()}),
                )?;
                return Ok(self.terminated(lifecycle, vec![e.to_string()]));
            }
        };
        self.advance(&mut lifecycle, LifecycleState::Validated)?;
        self.audit_step(EventKind::RequestValidated, &lifecycle, json!({}))?;

        // 2. PERMISSION_CHECKED.
        match self.permissions.check(
            &envelope.caller,
            envelope.chain_id,
            envelope.access,
            validated.from,
        ) {
            Ok(p) => {
                self.advance(&mut lifecycle, LifecycleState::PermissionChecked)?;
                self.audit_step(
                    EventKind::PermissionChecked,
                    &lifecycle,
                    json!({"permission_id": p.permission_id}),
                )?;
            }
            Err(e) => {
                let terminal = match &e {
                    cipherlayer_provider::PermissionError::Expired(_, _) => LifecycleState::Expired,
                    _ => LifecycleState::Rejected,
                };
                self.advance(&mut lifecycle, terminal)?;
                self.audit_step(
                    EventKind::PermissionDenied,
                    &lifecycle,
                    json!({"error": e.to_string()}),
                )?;
                return Ok(self.terminated(lifecycle, vec![e.to_string()]));
            }
        }
        if envelope.access == AccessClass::ReadOnly {
            // Read-only requests stop here in milestone 1 (no read routing yet).
            notes.push("read-only request: no signing pipeline stages executed".into());
        }

        // 3. DECODED (deterministic; unknown is a legal answer, not an error).
        // v0.4: typed_data/personal_message decode into the same `Decoded`
        // shape calldata does (ActionKind::Permit/TypedDataSign/PersonalSign),
        // so the intent/policy pipeline below (steps 5-7) is unchanged
        // regardless of payload kind.
        let decoded = match validated.kind {
            PayloadKind::EvmTransaction => {
                cipherlayer_evm::decode_calldata(validated.to, validated.value, &validated.data)
            }
            PayloadKind::TypedData => {
                // Re-parsed here (validate() already format-checked it at
                // RECEIVED→VALIDATED) — mirrors decode_calldata running
                // downstream of validate() for transactions.
                match cipherlayer_evm::typed_data::parse_typed_data(
                    validated.typed_data_json.as_deref().unwrap_or_default(),
                ) {
                    Ok(parsed) => parsed.to_decoded(),
                    Err(e) => {
                        self.advance(&mut lifecycle, LifecycleState::Rejected)?;
                        self.audit_step(
                            EventKind::Failure,
                            &lifecycle,
                            json!({"phase": "typed-data-decode", "error": e.to_string()}),
                        )?;
                        return Ok(self.terminated(lifecycle, vec![e.to_string()]));
                    }
                }
            }
            PayloadKind::PersonalMessage => cipherlayer_evm::decode_personal_message(
                validated.message.as_deref().unwrap_or_default(),
            ),
        };
        // Domain chainId vs. session/envelope chain (typed_data only) — feeds
        // POL-CHAIN-002 below. `None` for everything else, or when the domain
        // omitted chainId (legal per EIP-712, never treated as a match).
        let domain_chain_id_matches = if validated.kind == PayloadKind::TypedData {
            cipherlayer_evm::typed_data::parse_typed_data(
                validated.typed_data_json.as_deref().unwrap_or_default(),
            )
            .ok()
            .and_then(|p| p.domain.chain_id_matches(envelope.chain_id))
        } else {
            None
        };
        let mut intent = TransactionIntent::from_decoded(
            envelope.request_id,
            envelope.chain_id,
            serde_json::to_value(&envelope.payload).unwrap_or(serde_json::Value::Null),
            validated.from,
            validated.value,
            decoded,
        )
        .with_domain_chain_id_matches(domain_chain_id_matches);
        self.advance(&mut lifecycle, LifecycleState::Decoded)?;
        self.audit_step(
            EventKind::IntentDecoded,
            &lifecycle,
            serde_json::to_value(&intent).unwrap_or_default(),
        )?;

        // 3.5 CHAIN IDENTITY (T-09, evm_transaction only): the node behind
        // rpc_url must actually be the chain the envelope names. Everything
        // downstream — simulation evidence, nonce/gas fill, broadcast —
        // comes from this endpoint, so a mismatch poisons the evidence
        // chain; fail closed before producing any of it. Unreachable/
        // unparseable is equally a refusal, never a pass. typed_data/
        // personal_message never touch chain RPC (no broadcast, no
        // simulation) — their session-chain check is `domain_chain_id_matches`
        // above (POL-CHAIN-002), evaluated against the envelope's own
        // chain_id, not a live node.
        if validated.kind == PayloadKind::EvmTransaction {
            let adapter = EvmAdapter::new(&self.rpc_url);
            if let Err(e) = adapter.verify_chain_identity(envelope.chain_id).await {
                self.advance(&mut lifecycle, LifecycleState::Blocked)?;
                self.audit_step(
                    EventKind::Failure,
                    &lifecycle,
                    json!({"phase": "chain-identity", "error": e.to_string()}),
                )?;
                return Ok(PipelineOutcome {
                    final_state: lifecycle.state(),
                    request_id: lifecycle.request_id(),
                    signing_request_id: None,
                    intent: Some(intent),
                    simulation: None,
                    risk: None,
                    decision: None,
                    tx_hash: None,
                    signature_hex: None,
                    notes: vec![format!("chain identity verification failed: {e}")],
                });
            }
        }

        // 4. SIMULATED / SIMULATION_FAILED (evm_transaction only). Simulation
        // is N/A for signature-only requests — never faked; recorded honestly
        // as `SimulationStatus::NotApplicable` in the policy evidence below
        // (the schema's null/absent convention: "evaluated and out of scope",
        // never conflated with "should have run and didn't", which is what
        // `Unavailable` still means and still restricts on).
        let simulation: Option<SimulationResult> = if validated.kind == PayloadKind::EvmTransaction
        {
            let simulator = AnvilSimulator::new(&self.rpc_url);
            let sim_tx = SimTx {
                from: validated.from,
                to: validated.to,
                value: validated.value,
                data: validated.data.clone(),
                gas_limit: validated.gas_limit.map(|g| g.to::<u64>()),
            };
            let sim = simulator
                .simulate(envelope.request_id, &intent, &sim_tx)
                .await;
            intent.simulation_evidence_id = Some(sim.simulation_id);
            if sim.outcome == SimOutcome::SimulationError {
                self.advance(&mut lifecycle, LifecycleState::SimulationFailed)?;
                self.audit_step(
                    EventKind::SimulationFailed,
                    &lifecycle,
                    serde_json::to_value(&sim).unwrap_or_default(),
                )?;
                return Ok(PipelineOutcome {
                    final_state: lifecycle.state(),
                    request_id: lifecycle.request_id(),
                    signing_request_id: None,
                    intent: Some(intent),
                    simulation: Some(sim),
                    risk: None,
                    decision: None,
                    tx_hash: None,
                    signature_hex: None,
                    notes: vec![
                        "simulation failed — prototype refuses to proceed without simulation evidence"
                            .into(),
                    ],
                });
            }
            self.advance(&mut lifecycle, LifecycleState::Simulated)?;
            self.audit_step(
                EventKind::SimulationCompleted,
                &lifecycle,
                serde_json::to_value(&sim).unwrap_or_default(),
            )?;
            Some(sim)
        } else {
            self.advance(&mut lifecycle, LifecycleState::Simulated)?;
            self.audit_step(
                EventKind::SimulationCompleted,
                &lifecycle,
                json!({"outcome": "not_applicable", "note": "signature-only request — no on-chain transaction to simulate"}),
            )?;
            None
        };

        // 5. RISK_EVALUATED (advisory). The managed `scam-guard` executable
        // is the default detector. Failure is recorded as unavailable, never
        // replaced with mock evidence or treated as a quiet all-clear. MOCKED
        // mode is explicit and exists only for test/demo harnesses.
        let (findings, unavailable) = if cipherlayer_risk::FplCliDetector::mock_mode_requested() {
            (MockDetector.evaluate(&intent), vec![])
        } else {
            match cipherlayer_risk::FplCliDetector::from_env().try_evaluate(&intent) {
                Ok(f) => (f, vec![]),
                Err(e) => (vec![], vec![format!("scam-guard-cli: {e}")]),
            }
        };
        let risk = aggregate(envelope.request_id, findings, unavailable);
        intent.risk_evidence_id = Some(risk.bundle_id);
        self.advance(&mut lifecycle, LifecycleState::RiskEvaluated)?;
        self.audit_step(
            EventKind::RiskEvaluated,
            &lifecycle,
            serde_json::to_value(&risk).unwrap_or_default(),
        )?;

        // 6. POLICY_EVALUATED (deterministic).
        let evidence = EvaluationEvidence {
            simulation: match &simulation {
                Some(s) => match s.outcome {
                    SimOutcome::Success => SimulationStatus::Success,
                    SimOutcome::Revert => SimulationStatus::Revert,
                    SimOutcome::SimulationError => SimulationStatus::SimulationError,
                },
                None => SimulationStatus::NotApplicable,
            },
            risk: Some(risk.overall_level),
        };
        let decision = cipherlayer_policy::evaluate(&self.policy, &intent, evidence);
        self.advance(&mut lifecycle, LifecycleState::PolicyEvaluated)?;
        self.audit_step(
            EventKind::PolicyEvaluated,
            &lifecycle,
            serde_json::to_value(&decision).unwrap_or_default(),
        )?;

        if decision.verdict == Verdict::Deny {
            self.advance(&mut lifecycle, LifecycleState::PolicyDenied)?;
            self.audit_step(
                EventKind::Failure,
                &lifecycle,
                json!({"phase": "policy", "reasons": decision.reasons}),
            )?;
            return Ok(PipelineOutcome {
                final_state: lifecycle.state(),
                request_id: lifecycle.request_id(),
                signing_request_id: None,
                intent: Some(intent),
                simulation,
                risk: Some(risk),
                decision: Some(decision),
                tx_hash: None,
                signature_hex: None,
                notes: vec!["policy denied — a deterministic denial cannot be overridden".into()],
            });
        }

        // 7. USER_REVIEW — explicit confirmation, never skipped. Local modes
        // decide here (spoofable CLI prompt, T-12); VaultSurface defers the
        // decision to the Vault-side surface after preflight, below.
        self.advance(&mut lifecycle, LifecycleState::UserReview)?;
        let escalated = decision.verdict == Verdict::Escalate;
        let local_approved = match review {
            ReviewMode::AssumeYes => {
                notes.push(
                    "confirmation supplied via explicit --yes flag (logged as user decision)"
                        .into(),
                );
                Some(true)
            }
            ReviewMode::Reject => Some(false),
            ReviewMode::Interactive => Some(prompt_confirmation(escalated)),
            ReviewMode::VaultSurface => None,
        };
        if let Some(approved) = local_approved {
            self.audit_step(
                EventKind::UserDecision,
                &lifecycle,
                json!({"approved": approved, "escalation_acknowledged": approved && escalated, "surface": "cli_prompt", "surface_note": "MOCKED trusted surface: terminal prompts are spoofable (T-12)"}),
            )?;
            if !approved {
                self.advance(&mut lifecycle, LifecycleState::Rejected)?;
                return Ok(PipelineOutcome {
                    final_state: lifecycle.state(),
                    request_id: lifecycle.request_id(),
                    signing_request_id: None,
                    intent: Some(intent),
                    simulation,
                    risk: Some(risk),
                    decision: Some(decision),
                    tx_hash: None,
                    signature_hex: None,
                    notes: vec!["rejected at user review".into()],
                });
            }
            self.advance(&mut lifecycle, LifecycleState::Authorized)?;
        }

        let chain_entry = self
            .registry
            .get(envelope.chain_id)
            .map_err(|e| PipelineError::State(e.to_string()))?;

        // v0.4: typed_data/personal_message signing has no on-chain tx, no
        // nonce/gas, and no broadcast — it terminates at SIGNED. This is a
        // legitimate resting final_state: the state machine's
        // Signed->Broadcast|BroadcastFailed edges are simply never taken here.
        if validated.kind != PayloadKind::EvmTransaction {
            if review == ReviewMode::VaultSurface {
                // v0.4 honest limitation: the Vault-side confirmation surface
                // only renders transaction evidence today (WireDisplayEvidence
                // is tx-shaped). Fail closed rather than render a wrong or
                // misleading surface.
                self.advance(&mut lifecycle, LifecycleState::Blocked)?;
                self.audit_step(
                    EventKind::Failure,
                    &lifecycle,
                    json!({"phase": "vault-surface", "error": "message-signing payloads are not supported by the vault-side confirmation surface in this revision", "note": "fail closed"}),
                )?;
                return Ok(PipelineOutcome {
                    final_state: lifecycle.state(),
                    request_id: lifecycle.request_id(),
                    signing_request_id: None,
                    intent: Some(intent),
                    simulation,
                    risk: Some(risk),
                    decision: Some(decision),
                    tx_hash: None,
                    signature_hex: None,
                    notes: vec!["vault-side confirmation surface does not support typed_data/personal_message in this revision — use the direct review path (--yes/interactive)".into()],
                });
            }
            let signing_request_id = cipherlayer_types::new_id();
            let message_payload = match validated.kind {
                PayloadKind::TypedData => MessagePayload::TypedData {
                    typed_data_json: validated.typed_data_json.clone().unwrap_or_default(),
                },
                PayloadKind::PersonalMessage => MessagePayload::PersonalMessage {
                    message: validated.message.clone().unwrap_or_default(),
                },
                PayloadKind::EvmTransaction => unreachable!("handled by the branch above"),
            };
            let signing_request = VaultSigningRequest {
                signing_request_id,
                request_id: envelope.request_id,
                account: validated.from,
                chain_id: envelope.chain_id,
                network_class: chain_entry.network_class,
                capability: Capability::messages(
                    &envelope.caller.key(),
                    validated.from,
                    envelope.chain_id,
                    60,
                ),
                policy_verdict: decision.verdict,
                user_authorization: UserAuthorization {
                    decided_at: cipherlayer_types::now(),
                    surface: ConfirmationSurface::CliPrompt,
                    escalation_acknowledged: escalated,
                },
                tx: TxParams {
                    to: None,
                    value: U256::ZERO,
                    data: Vec::new(),
                    nonce: 0,
                    gas_limit: 0,
                    gas_price_wei: 0,
                },
                message_payload: Some(message_payload),
            };
            let sig = match self
                .vault
                .authorize_and_sign(&signing_request, intent.intent_id, decision.decision_id)
                .await
            {
                Ok(SignOutcome::Message(sig)) => sig,
                Ok(SignOutcome::Transaction(_)) => {
                    return Err(PipelineError::State(
                        "internal: vault returned a transaction outcome for a message-signing request"
                            .into(),
                    ));
                }
                Err(e) => {
                    self.advance(&mut lifecycle, LifecycleState::SigningFailed)?;
                    self.audit_step(
                        EventKind::SigningFailed,
                        &lifecycle,
                        json!({"error": e.to_string()}),
                    )?;
                    return Ok(PipelineOutcome {
                        final_state: lifecycle.state(),
                        request_id: lifecycle.request_id(),
                        signing_request_id: Some(signing_request_id),
                        intent: Some(intent),
                        simulation,
                        risk: Some(risk),
                        decision: Some(decision),
                        tx_hash: None,
                        signature_hex: None,
                        notes: vec![format!("vault refused to sign: {e}")],
                    });
                }
            };
            self.advance(&mut lifecycle, LifecycleState::Signed)?;
            self.audit_step(
                EventKind::SignatureCreated,
                &lifecycle,
                json!({"signature_hex": sig.to_hex(), "signer": format!("{}", self.vault.address()), "signer_kind": self.vault.signer_kind()}),
            )?;
            return Ok(PipelineOutcome {
                final_state: lifecycle.state(),
                request_id: lifecycle.request_id(),
                signing_request_id: Some(signing_request_id),
                intent: Some(intent),
                simulation,
                risk: Some(risk),
                decision: Some(decision),
                tx_hash: None,
                signature_hex: Some(sig.to_hex()),
                notes,
            });
        }

        // 8. SIGNED / SIGNING_FAILED — the Vault re-checks everything.
        let simulation = simulation.expect("evm_transaction path always simulates above");
        let (nonce, gas_limit, gas_price) = self
            .fill_tx_params(&validated)
            .await
            .map_err(PipelineError::Rpc)?;
        let signing_request_id = cipherlayer_types::new_id();
        let signing_request = VaultSigningRequest {
            signing_request_id,
            request_id: envelope.request_id,
            account: validated.from,
            chain_id: envelope.chain_id,
            network_class: chain_entry.network_class,
            capability: Capability::signing(
                &envelope.caller.key(),
                validated.from,
                envelope.chain_id,
                60,
            ),
            policy_verdict: decision.verdict,
            user_authorization: UserAuthorization {
                decided_at: cipherlayer_types::now(),
                surface: ConfirmationSurface::CliPrompt,
                escalation_acknowledged: escalated,
            },
            tx: TxParams {
                to: validated.to,
                value: validated.value,
                data: validated.data.clone(),
                nonce,
                gas_limit,
                gas_price_wei: gas_price,
            },
            message_payload: None,
        };
        let sign_result = if review == ReviewMode::VaultSurface {
            // The Vault-side surface decides; whatever it displays comes only
            // from the deterministic pipeline evidence assembled here.
            let display = cipherlayer_vault::ipc::WireDisplayEvidence {
                intent: format!(
                    "{:?}{}",
                    intent.decoded_action.kind,
                    intent
                        .decoded_action
                        .function_signature
                        .as_deref()
                        .map(|s| format!(" ({s})"))
                        .unwrap_or_default()
                ),
                chain: format!("{} ({})", chain_entry.name, envelope.chain_id.0),
                simulation: format!(
                    "{:?} ({} standing limitations)",
                    simulation.outcome,
                    simulation.limitations.len()
                ),
                risk: match risk.overall_level {
                    cipherlayer_types::RiskLevel::Unknown => {
                        "UNKNOWN — no evidence; never treated as low".to_string()
                    }
                    other => format!("{other:?}"),
                },
                policy_reasons: decision
                    .reasons
                    .iter()
                    .map(|r| format!("{}: {}", r.code, r.detail))
                    .collect(),
            };
            match self
                .vault
                .confirm_and_sign(
                    &signing_request,
                    intent.intent_id,
                    decision.decision_id,
                    display,
                )
                .await
            {
                Ok(cipherlayer_vault::ipc::SurfaceOutcome::Signed(s)) => {
                    self.audit_step(
                        EventKind::UserDecision,
                        &lifecycle,
                        json!({"approved": true, "escalation_acknowledged": escalated, "surface": "desktop_trusted_surface", "surface_note": "decision obtained by the Vault-side surface (cipherlayer-vaultd)"}),
                    )?;
                    self.advance(&mut lifecycle, LifecycleState::Authorized)?;
                    Ok(SignOutcome::Transaction(s))
                }
                Ok(cipherlayer_vault::ipc::SurfaceOutcome::Rejected { detail }) => {
                    self.audit_step(
                        EventKind::UserDecision,
                        &lifecycle,
                        json!({"approved": false, "surface": "desktop_trusted_surface", "detail": detail}),
                    )?;
                    self.advance(&mut lifecycle, LifecycleState::Rejected)?;
                    return Ok(PipelineOutcome {
                        final_state: lifecycle.state(),
                        request_id: lifecycle.request_id(),
                        signing_request_id: Some(signing_request_id),
                        intent: Some(intent),
                        simulation: Some(simulation),
                        risk: Some(risk),
                        decision: Some(decision),
                        tx_hash: None,
                        signature_hex: None,
                        notes: vec![format!(
                            "rejected at the vault confirmation surface: {detail}"
                        )],
                    });
                }
                Err(e) => {
                    // No user decision exists — fail closed (Blocked), never
                    // SigningFailed, which would imply an authorized attempt.
                    self.audit_step(
                        EventKind::Failure,
                        &lifecycle,
                        json!({"phase": "vault-surface", "error": e, "note": "surface unavailable or refused integrity — fail closed"}),
                    )?;
                    self.advance(&mut lifecycle, LifecycleState::Blocked)?;
                    return Ok(PipelineOutcome {
                        final_state: lifecycle.state(),
                        request_id: lifecycle.request_id(),
                        signing_request_id: Some(signing_request_id),
                        intent: Some(intent),
                        simulation: Some(simulation),
                        risk: Some(risk),
                        decision: Some(decision),
                        tx_hash: None,
                        signature_hex: None,
                        notes: vec![format!("confirmation surface fail-closed: {e}")],
                    });
                }
            }
        } else {
            self.vault
                .authorize_and_sign(&signing_request, intent.intent_id, decision.decision_id)
                .await
        };
        let signed = match sign_result {
            Ok(SignOutcome::Transaction(s)) => s,
            Ok(SignOutcome::Message(_)) => {
                return Err(PipelineError::State(
                    "internal: vault returned a message outcome for a transaction-signing request"
                        .into(),
                ));
            }
            Err(e) => {
                self.advance(&mut lifecycle, LifecycleState::SigningFailed)?;
                self.audit_step(
                    EventKind::SigningFailed,
                    &lifecycle,
                    json!({"error": e.to_string()}),
                )?;
                return Ok(PipelineOutcome {
                    final_state: lifecycle.state(),
                    request_id: lifecycle.request_id(),
                    signing_request_id: Some(signing_request_id),
                    intent: Some(intent),
                    simulation: Some(simulation),
                    risk: Some(risk),
                    decision: Some(decision),
                    tx_hash: None,
                    signature_hex: None,
                    notes: vec![format!("vault refused to sign: {e}")],
                });
            }
        };
        self.advance(&mut lifecycle, LifecycleState::Signed)?;
        self.audit_step(
            EventKind::SignatureCreated,
            &lifecycle,
            json!({"tx_hash": signed.tx_hash, "signer": format!("{}", self.vault.address()), "signer_kind": self.vault.signer_kind()}),
        )?;

        // 9. BROADCAST / CONFIRMED.
        match self.broadcast_and_confirm(&signed.raw).await {
            Ok(block) => {
                self.advance(&mut lifecycle, LifecycleState::Broadcast)?;
                self.audit_step(
                    EventKind::BroadcastCompleted,
                    &lifecycle,
                    json!({"tx_hash": signed.tx_hash, "block_number": block}),
                )?;
                self.advance(&mut lifecycle, LifecycleState::Confirmed)?;
                self.audit_step(
                    EventKind::StateTransition,
                    &lifecycle,
                    json!({"note": "receipt observed", "block_number": block}),
                )?;
                Ok(PipelineOutcome {
                    final_state: lifecycle.state(),
                    request_id: lifecycle.request_id(),
                    signing_request_id: Some(signing_request_id),
                    intent: Some(intent),
                    simulation: Some(simulation),
                    risk: Some(risk),
                    decision: Some(decision),
                    tx_hash: Some(signed.tx_hash),
                    signature_hex: None,
                    notes,
                })
            }
            Err(e) => {
                // Failure may occur at submission or while waiting for a receipt.
                if lifecycle.state() == LifecycleState::Signed {
                    self.advance(&mut lifecycle, LifecycleState::BroadcastFailed)?;
                }
                self.audit_step(EventKind::BroadcastFailed, &lifecycle, json!({"error": e}))?;
                Ok(PipelineOutcome {
                    final_state: lifecycle.state(),
                    request_id: lifecycle.request_id(),
                    signing_request_id: Some(signing_request_id),
                    intent: Some(intent),
                    simulation: Some(simulation),
                    risk: Some(risk),
                    decision: Some(decision),
                    tx_hash: Some(signed.tx_hash),
                    signature_hex: None,
                    notes: vec![format!("broadcast failed: {e}")],
                })
            }
        }
    }

    /// Build the browser-connect wire answer (signing-response.v1) for an
    /// outcome. Refusal reasons come from policy reasons on POLICY_DENIED and
    /// from pipeline notes otherwise; the audit head lets the consumer
    /// reference the hash-chained trail.
    pub fn to_signing_response(
        &self,
        outcome: &PipelineOutcome,
    ) -> Result<cipherlayer_provider::SigningResponse, PipelineError> {
        let audit_head_sequence = self
            .audit
            .events_for_request(outcome.request_id)?
            .last()
            .map(|e| e.sequence)
            .unwrap_or(0);
        let refusal_reasons = if outcome.final_state == LifecycleState::PolicyDenied {
            outcome
                .decision
                .as_ref()
                .map(|d| {
                    d.reasons
                        .iter()
                        .map(|r| cipherlayer_provider::RefusalReason {
                            code: r.code.clone(),
                            detail: r.detail.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else if outcome.final_state == LifecycleState::Confirmed
            || outcome.final_state == LifecycleState::Signed
        {
            // Confirmed = a broadcast transaction reached the chain; Signed
            // with no tx_hash and a signature_hex present = a v0.4
            // typed_data/personal_message request succeeded (it has no
            // broadcast step — SIGNED is its terminal success state).
            Vec::new()
        } else {
            outcome
                .notes
                .iter()
                .map(|n| cipherlayer_provider::RefusalReason {
                    code: format!("STATE-{:?}", outcome.final_state).to_uppercase(),
                    detail: n.clone(),
                })
                .collect()
        };
        Ok(cipherlayer_provider::SigningResponse {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            signing_response_id: cipherlayer_types::new_id(),
            signing_request_id: outcome.signing_request_id,
            request_id: outcome.request_id,
            responded_at: cipherlayer_types::now(),
            state: outcome.final_state,
            tx_hash: outcome.tx_hash.clone(),
            signature_hex: outcome.signature_hex.clone(),
            refusal_reasons,
            audit_head_sequence,
            review_evidence: Self::review_evidence(outcome),
        })
    }

    /// Display-only evidence summary for the browser-connect wire (schema
    /// signing-response v1.2, additive). Strings only, assembled from the
    /// same deterministic pipeline artifacts the trusted surface displays;
    /// nothing here is consumed by any decision path.
    fn review_evidence(outcome: &PipelineOutcome) -> Option<cipherlayer_provider::ReviewEvidence> {
        let intent = outcome.intent.as_ref()?;
        Some(cipherlayer_provider::ReviewEvidence {
            decoded_action: format!(
                "{:?}{}",
                intent.decoded_action.kind,
                intent
                    .decoded_action
                    .function_signature
                    .as_deref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            ),
            intent_confidence: format!("{:?}", intent.confidence),
            simulation: outcome.simulation.as_ref().map(|s| {
                format!(
                    "{:?} ({} standing limitations)",
                    s.outcome,
                    s.limitations.len()
                )
            }),
            risk_level: outcome.risk.as_ref().map(|r| match r.overall_level {
                cipherlayer_types::RiskLevel::Unknown => {
                    "UNKNOWN — no evidence; never treated as low".to_string()
                }
                other => format!("{other:?}"),
            }),
            risk_findings: outcome
                .risk
                .as_ref()
                .map(|r| {
                    r.findings
                        .iter()
                        .map(|f| cipherlayer_provider::RiskFindingSummary {
                            detector: f.detector.name.clone(),
                            risk_level: format!("{:?}", f.risk_level),
                            reason_codes: f.reason_codes.clone(),
                            explanation: f.explanation.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            detectors_unavailable: outcome
                .risk
                .as_ref()
                .map(|r| r.detectors_unavailable.clone())
                .unwrap_or_default(),
            policy_verdict: outcome
                .decision
                .as_ref()
                .map(|d| format!("{:?}", d.verdict)),
            policy_reasons: outcome
                .decision
                .as_ref()
                .map(|d| {
                    d.reasons
                        .iter()
                        .map(|r| format!("{}: {}", r.code, r.detail))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    fn terminated(&self, lifecycle: Lifecycle, notes: Vec<String>) -> PipelineOutcome {
        PipelineOutcome {
            final_state: lifecycle.state(),
            request_id: lifecycle.request_id(),
            signing_request_id: None,
            intent: None,
            simulation: None,
            risk: None,
            decision: None,
            tx_hash: None,
            signature_hex: None,
            notes,
        }
    }

    /// Fill nonce/gas/fee via the chain adapter (ADR-015 boundary): the
    /// adapter builds unsigned params; signing stays in the vault.
    async fn fill_tx_params(
        &self,
        validated: &ValidatedRequest,
    ) -> Result<(u64, u64, u128), String> {
        let adapter = EvmAdapter::new(&self.rpc_url);
        let unsigned = adapter
            .build_unsigned(&EvmBuildInput {
                from: validated.from,
                to: validated.to,
                value: validated.value,
                data: validated.data.clone(),
                nonce: validated.nonce,
                gas_limit: validated.gas_limit.map(|g| g.to::<u64>()),
            })
            .await
            .map_err(|e| e.to_string())?;
        Ok((unsigned.nonce, unsigned.gas_limit, unsigned.gas_price_wei))
    }

    async fn broadcast_and_confirm(&self, raw: &[u8]) -> Result<u64, String> {
        let adapter = EvmAdapter::new(&self.rpc_url);
        let tx_hash = adapter.broadcast(raw).await.map_err(|e| e.to_string())?;
        for _ in 0..40 {
            match adapter
                .transaction_status(&tx_hash)
                .await
                .map_err(|e| e.to_string())?
            {
                EvmTxStatus::Confirmed { block_number } => return Ok(block_number),
                EvmTxStatus::Reverted => {
                    return Err("transaction reverted on-chain (status 0x0)".into())
                }
                EvmTxStatus::Pending => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err("no receipt within polling window".into())
    }
}

/// Interactive confirmation. Presentation only: the Vault re-validates the
/// authorization; and this terminal prompt is a MOCKED trusted surface (T-12).
fn prompt_confirmation(escalated: bool) -> bool {
    use std::io::Write;
    if escalated {
        println!("⚠ policy verdict: ESCALATE — additional explicit confirmation required.");
    }
    print!("Type 'yes' to authorize signing (anything else rejects): ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    line.trim() == "yes"
}

/// Helper for signing-capable commands: grant the local CLI caller a scoped,
/// expiring signing permission (auditable).
pub fn grant_cli_permission(
    pipeline: &mut Pipeline,
    caller: &cipherlayer_types::CallerIdentity,
    chain_id: cipherlayer_types::ChainId,
    account: cipherlayer_types::Address,
) -> Result<(), PipelineError> {
    let p = pipeline.permissions.grant(
        caller,
        chain_id,
        AccessClass::Signing,
        vec![account],
        chrono::Duration::hours(1),
    );
    pipeline.audit.append(
        cipherlayer_audit::EventKind::PermissionGranted,
        None,
        serde_json::to_value(&p).unwrap_or_default(),
    )?;
    Ok(())
}

/// Like `grant_cli_permission`, but idempotent across invocations now that
/// grants persist: reuses an existing active grant instead of stacking a new
/// one per CLI run.
pub fn ensure_cli_permission(
    pipeline: &mut Pipeline,
    caller: &cipherlayer_types::CallerIdentity,
    chain_id: cipherlayer_types::ChainId,
    account: cipherlayer_types::Address,
) -> Result<(), PipelineError> {
    if pipeline
        .permissions
        .find_active(caller, chain_id, AccessClass::Signing, account)
        .is_some()
    {
        return Ok(());
    }
    grant_cli_permission(pipeline, caller, chain_id, account)
}

/// Format a wei amount as a decimal token amount (18 decimals) for display.
pub fn format_units18(v: U256) -> String {
    let base = U256::from(10u64).pow(U256::from(18u64));
    let whole = v / base;
    let frac = (v % base) / U256::from(10u64).pow(U256::from(14u64));
    format!("{whole}.{frac:04}")
}
