//! Security regression tests (BP §15): each test encodes one hard invariant.
//! A failure here is a release blocker by definition. These run without a
//! chain — they exercise the deterministic layers directly.

use cipherlayer_chain::ChainRegistry;
use cipherlayer_policy::{evaluate, EvaluationEvidence, Policy, SimulationStatus, Verdict};
use cipherlayer_provider::{
    parse_envelope, validate, EnvelopePayload, TransactionRequestEnvelope, ValidationError,
    MAX_ENVELOPE_BYTES,
};
use cipherlayer_risk::aggregate;
use cipherlayer_types::state::{Lifecycle, LifecycleState};
use cipherlayer_types::{
    AccessClass, Address, CallerIdentity, CallerKind, ChainId, NetworkClass, RiskLevel, U256,
};
use cipherlayer_vault::{
    Capability, ConfirmationSurface, TestSigner, TxParams, UserAuthorization, Vault, VaultError,
    VaultSigningRequest, ANVIL_DEV_KEYS,
};

fn addr(n: u8) -> Address {
    Address::from_slice(&[n; 20])
}

fn cli_caller() -> CallerIdentity {
    CallerIdentity {
        kind: CallerKind::Cli,
        origin: None,
        app_id: Some("cli:test".into()),
        capsule_id: None,
    }
}

fn approve_intent(amount: U256, chain: u64) -> cipherlayer_intent::TransactionIntent {
    let mut d = cipherlayer_evm::SELECTOR_APPROVE.to_vec();
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(addr(2).as_slice());
    d.extend_from_slice(&amount.to_be_bytes::<32>());
    let decoded = cipherlayer_evm::decode_calldata(Some(addr(9)), U256::ZERO, &d);
    cipherlayer_intent::TransactionIntent::from_decoded(
        cipherlayer_types::new_id(),
        ChainId(chain),
        serde_json::json!({"to": format!("{}", addr(9)), "value_wei": "0"}),
        addr(1),
        U256::ZERO,
        decoded,
    )
}

fn good_evidence() -> EvaluationEvidence {
    EvaluationEvidence {
        simulation: SimulationStatus::Success,
        risk: Some(RiskLevel::Low),
    }
}

/// Build a `TransactionIntent` from an `eth_signTypedData_v4` JSON payload,
/// the same way a typed-data signing request would reach the policy engine:
/// parse + classify (`cipherlayer_evm::typed_data`), project into the
/// existing `Decoded` shape, then build the intent exactly as calldata
/// decoding does (`TransactionIntent::from_decoded`) — no separate policy
/// path for typed data (CL-EVM-003/004).
fn typed_data_intent(json: &str, chain: u64) -> cipherlayer_intent::TransactionIntent {
    let parsed = cipherlayer_evm::typed_data::parse_typed_data(json)
        .expect("well-formed typed data must parse");
    cipherlayer_intent::TransactionIntent::from_decoded(
        cipherlayer_types::new_id(),
        ChainId(chain),
        serde_json::json!({ "typed_data": true }),
        addr(1),
        U256::ZERO,
        parsed.to_decoded(),
    )
}

fn eip2612_permit_json(token: Address, spender: Address, value: U256, chain_id: u64) -> String {
    serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [
                { "name": "owner", "type": "address" },
                { "name": "spender", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "nonce", "type": "uint256" },
                { "name": "deadline", "type": "uint256" }
            ]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "TestToken",
            "version": "1",
            "chainId": chain_id,
            "verifyingContract": format!("{token}")
        },
        "message": {
            "owner": format!("{}", addr(1)),
            "spender": format!("{spender}"),
            "value": value.to_string(),
            "nonce": "0",
            "deadline": "0"
        }
    })
    .to_string()
}

/// Malformed or oversized provider requests are rejected at RECEIVED.
#[test]
fn malformed_envelope_rejected() {
    assert!(parse_envelope("{ not json").is_err());
    assert!(parse_envelope("{\"schema_version\":\"1.0\"}").is_err()); // missing required fields
    let oversized = format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_ENVELOPE_BYTES));
    assert!(matches!(
        parse_envelope(&oversized).unwrap_err(),
        ValidationError::EnvelopeTooLarge
    ));
}

/// Dapp identity cannot be omitted (TB1).
#[test]
fn missing_dapp_identity_rejected() {
    let env = TransactionRequestEnvelope::new(
        CallerIdentity {
            kind: CallerKind::Dapp,
            origin: Some("".into()),
            app_id: None,
            capsule_id: None,
        },
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{}", addr(1)),
            to: Some(format!("{}", addr(2))),
            value_wei: Some("0".into()),
            data: Some("0x".into()),
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        },
    );
    assert!(matches!(
        validate(&env, &ChainRegistry::builtin()).unwrap_err(),
        ValidationError::MissingCallerIdentity
    ));
}

/// Chain mismatch is rejected: unknown chains fail validation; known-but-
/// unpermitted chains fail policy; non-development chains fail the Vault gate.
#[tokio::test]
async fn wrong_chain_rejected_at_every_layer() {
    // Unknown chain: validation.
    let env = TransactionRequestEnvelope::new(
        cli_caller(),
        ChainId(424242),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{}", addr(1)),
            to: Some(format!("{}", addr(2))),
            value_wei: Some("0".into()),
            data: Some("0x".into()),
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        },
    );
    assert!(validate(&env, &ChainRegistry::builtin()).is_err());

    // Known but non-allowed chain: policy.
    let d = evaluate(
        &Policy::default_dev(),
        &approve_intent(U256::from(1u64), 1),
        good_evidence(),
    );
    assert_eq!(d.verdict, Verdict::Deny);

    // Non-development chain: Vault refuses even a policy-allowed request.
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let vault = Vault::new(signer);
    let req = VaultSigningRequest {
        signing_request_id: cipherlayer_types::new_id(),
        request_id: cipherlayer_types::new_id(),
        account: vault.address(),
        chain_id: ChainId(1),
        network_class: NetworkClass::Mainnet,
        capability: Capability::signing("cli:test", vault.address(), ChainId(1), 60),
        policy_verdict: Verdict::Allow,
        user_authorization: UserAuthorization {
            decided_at: cipherlayer_types::now(),
            surface: ConfirmationSurface::CliPrompt,
            escalation_acknowledged: false,
        },
        tx: TxParams {
            to: Some(addr(2)),
            value: U256::ZERO,
            data: vec![],
            nonce: 0,
            gas_limit: 21_000,
            gas_price_wei: 1_000_000_000,
        },
        message_payload: None,
    };
    assert!(matches!(
        vault.authorize_and_sign(&req).await.unwrap_err(),
        VaultError::NonDevelopmentChain(_)
    ));
}

/// Policy cannot be bypassed by missing/undecoded fields: unknown decoding
/// takes the restrictive path, never silent allow.
#[test]
fn policy_not_bypassed_by_missing_fields() {
    let decoded =
        cipherlayer_evm::decode_calldata(Some(addr(9)), U256::ZERO, &[0xde, 0xad, 0xbe, 0xef]);
    let intent = cipherlayer_intent::TransactionIntent::from_decoded(
        cipherlayer_types::new_id(),
        ChainId(31337),
        serde_json::json!({"to": format!("{}", addr(9))}),
        addr(1),
        U256::ZERO,
        decoded,
    );
    let d = evaluate(&Policy::default_dev(), &intent, good_evidence());
    assert_ne!(d.verdict, Verdict::Allow);

    // Missing simulation evidence is also restrictive.
    let d2 = evaluate(
        &Policy::default_dev(),
        &approve_intent(U256::from(1u64), 31337),
        EvaluationEvidence {
            simulation: SimulationStatus::Unavailable,
            risk: Some(RiskLevel::Low),
        },
    );
    assert_ne!(d2.verdict, Verdict::Allow);
}

/// AI/risk explanation cannot override a deterministic denial: (a) the best
/// possible risk evidence does not change a policy deny; (b) the Vault
/// refuses a deny verdict even with an acknowledged user authorization.
#[tokio::test]
async fn risk_cannot_override_policy_denial() {
    let intent = approve_intent(U256::MAX, 31337); // unlimited approval → deny
    let best_possible_risk = EvaluationEvidence {
        simulation: SimulationStatus::Success,
        risk: Some(RiskLevel::Low),
    };
    let d = evaluate(&Policy::default_dev(), &intent, best_possible_risk);
    assert_eq!(d.verdict, Verdict::Deny);

    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let vault = Vault::new(signer);
    let req = VaultSigningRequest {
        signing_request_id: cipherlayer_types::new_id(),
        request_id: cipherlayer_types::new_id(),
        account: vault.address(),
        chain_id: ChainId(31337),
        network_class: NetworkClass::Development,
        capability: Capability::signing("cli:test", vault.address(), ChainId(31337), 60),
        policy_verdict: Verdict::Deny,
        user_authorization: UserAuthorization {
            decided_at: cipherlayer_types::now(),
            surface: ConfirmationSurface::CliPrompt,
            escalation_acknowledged: true,
        },
        tx: TxParams {
            to: Some(addr(2)),
            value: U256::ZERO,
            data: vec![],
            nonce: 0,
            gas_limit: 21_000,
            gas_price_wei: 1_000_000_000,
        },
        message_payload: None,
    };
    assert!(matches!(
        vault.authorize_and_sign(&req).await.unwrap_err(),
        VaultError::PolicyDenied(_)
    ));
}

/// Provider/browser-facing surfaces cannot invoke private-key export: no such
/// API exists (compile-time), and runtime representations redact key material.
#[test]
fn no_private_key_export_surface() {
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let vault = Vault::new(signer);
    let dbg = format!("{vault:?}");
    assert!(dbg.contains("<redacted>"));
    for k in ANVIL_DEV_KEYS {
        assert!(
            !dbg.to_lowercase().contains(&k[2..].to_lowercase()),
            "debug output leaked key material"
        );
    }
    // The signer refuses anything that isn't a public Anvil dev key, so this
    // surface cannot be repurposed as real custody.
    assert!(TestSigner::from_dev_key(
        "0x2222222222222222222222222222222222222222222222222222222222222222"
    )
    .is_err());
}

/// Unknown risk does not become "low risk" by default — at aggregation and at policy.
#[test]
fn unknown_risk_not_low() {
    let bundle = aggregate(
        cipherlayer_types::new_id(),
        vec![],
        vec!["offline-detector".into()],
    );
    assert_eq!(bundle.overall_level, RiskLevel::Unknown);
    assert_ne!(bundle.overall_level, RiskLevel::Low);

    for risk in [Some(RiskLevel::Unknown), Some(RiskLevel::Conflicting), None] {
        let d = evaluate(
            &Policy::default_dev(),
            &approve_intent(U256::from(1u64), 31337),
            EvaluationEvidence {
                simulation: SimulationStatus::Success,
                risk,
            },
        );
        assert_ne!(
            d.verdict,
            Verdict::Allow,
            "risk {risk:?} must not pass silently"
        );
    }
}

/// AC-C (the permit harvest): an EIP-2612 `permit` typed-data signature
/// granting an unlimited allowance must be classified as unlimited-approval
/// authority — the same as an on-chain `approve(spender, 2^256-1)` — and
/// denied by the same default policy rule, never treated as a harmless
/// "login" signature.
#[test]
fn typed_data_unlimited_permit_denied_by_default_policy() {
    let token = addr(9);
    let spender = addr(2);
    let json = eip2612_permit_json(token, spender, U256::MAX, 31337);
    let intent = typed_data_intent(&json, 31337);
    assert!(intent.is_unlimited_approval());
    let d = evaluate(&Policy::default_dev(), &intent, good_evidence());
    assert_eq!(d.verdict, Verdict::Deny);
    assert!(d.reasons.iter().any(|r| r.code == "POL-APR-001"));
}

/// A bounded-value EIP-2612 permit is allowed, exactly like a bounded
/// `approve` — typed-data classification does not over-restrict.
#[test]
fn typed_data_bounded_permit_allowed() {
    let json = eip2612_permit_json(addr(9), addr(2), U256::from(100u64), 31337);
    let intent = typed_data_intent(&json, 31337);
    assert!(!intent.is_unlimited_approval());
    let d = evaluate(&Policy::default_dev(), &intent, good_evidence());
    assert_eq!(d.verdict, Verdict::Allow);
}

/// A permit's domain names a `verifyingContract` different from the token
/// the user believes they're approving: the domain must be surfaced (never
/// hidden or silently substituted) so the caller can compare it themselves.
#[test]
fn typed_data_permit_to_unexpected_verifying_contract_domain_surfaced() {
    let actual_contract = addr(0xAB);
    let expected_token = addr(9);
    let json = eip2612_permit_json(actual_contract, addr(2), U256::MAX, 31337);
    let parsed = cipherlayer_evm::typed_data::parse_typed_data(&json).unwrap();
    assert_eq!(parsed.domain.verifying_contract, Some(actual_contract));
    assert_ne!(parsed.domain.verifying_contract, Some(expected_token));
    let intent = typed_data_intent(&json, 31337);
    assert_eq!(intent.allowance.unwrap().token, Some(actual_contract));
}

/// AC-D applied to typed data: a domain `chainId` that does not match the
/// session/expected chain must be detectable by the caller — exposed as
/// data on the parsed result, never silently accepted as a match.
#[test]
fn typed_data_chain_id_mismatch_detectable_by_caller() {
    let json = eip2612_permit_json(addr(9), addr(2), U256::from(1u64), 1 /* mainnet */);
    let parsed = cipherlayer_evm::typed_data::parse_typed_data(&json).unwrap();
    assert_eq!(
        parsed.domain.chain_id_matches(ChainId(31337)),
        Some(false),
        "mainnet domain must not match the dev-chain session"
    );
}

/// Cyclic or otherwise malicious type definitions are rejected with a typed
/// error — never a panic, never a best-guess hash reaching the signer.
#[test]
fn typed_data_cyclic_type_definition_rejected_never_panics() {
    let json = serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "A": [{ "name": "b", "type": "B" }],
            "B": [{ "name": "a", "type": "A" }]
        },
        "primaryType": "A",
        "domain": {},
        "message": { "b": { "a": {} } }
    })
    .to_string();
    let err = cipherlayer_evm::typed_data::parse_typed_data(&json).unwrap_err();
    assert!(matches!(
        err,
        cipherlayer_evm::typed_data::TypedDataError::CyclicTypeDefinition(_)
    ));
}

/// AC-C, the undecodable half: typed data that does not match a recognized
/// permit shape classifies as `unknown` at `Confidence::Unknown`, which
/// takes policy's restrictive unknown-action path — never a quiet "Sign".
#[test]
fn typed_data_unclassified_signature_escalates_never_silently_allowed() {
    let json = serde_json::json!({
        "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }],
            "Vote": [
                { "name": "proposalId", "type": "uint256" },
                { "name": "support", "type": "bool" }
            ]
        },
        "primaryType": "Vote",
        "domain": { "name": "Governance" },
        "message": { "proposalId": "1", "support": true }
    })
    .to_string();
    let intent = typed_data_intent(&json, 31337);
    assert_eq!(intent.confidence, cipherlayer_types::Confidence::Unknown);
    let d = evaluate(&Policy::default_dev(), &intent, good_evidence());
    assert_ne!(d.verdict, Verdict::Allow);
    assert!(d.reasons.iter().any(|r| r.code == "POL-UNK-001"));
}

/// Unlimited ERC-20 approvals are blocked by the default policy, and the
/// policy language cannot even express a silent allow for them.
#[test]
fn unlimited_approval_blocked() {
    let d = evaluate(
        &Policy::default_dev(),
        &approve_intent(U256::MAX, 31337),
        good_evidence(),
    );
    assert_eq!(d.verdict, Verdict::Deny);
    assert!(d.reasons.iter().any(|r| r.code == "POL-APR-001"));
    assert!(
        serde_json::from_str::<cipherlayer_policy::UnlimitedApprovalAction>("\"allow\"").is_err()
    );
}

/// The signing state machine cannot skip required states.
#[test]
fn state_machine_no_skip() {
    let mut lc = Lifecycle::start(cipherlayer_types::new_id());
    // Straight to signing: impossible.
    assert!(lc.advance(LifecycleState::Signed).is_err());
    assert!(lc.advance(LifecycleState::Authorized).is_err());
    // Skipping simulation/risk after decode: impossible.
    lc.advance(LifecycleState::Validated).unwrap();
    lc.advance(LifecycleState::PermissionChecked).unwrap();
    lc.advance(LifecycleState::Decoded).unwrap();
    assert!(lc.advance(LifecycleState::UserReview).is_err());
    assert!(lc.advance(LifecycleState::PolicyEvaluated).is_err());
}

/// In-place audit tampering is detected by verification.
#[test]
fn tampered_audit_log_detected() {
    let dir = tempfile::tempdir().unwrap();
    let log = cipherlayer_audit::AuditLog::open(dir.path().join("a.jsonl")).unwrap();
    for i in 0..4u64 {
        log.append(
            cipherlayer_audit::EventKind::StateTransition,
            None,
            serde_json::json!({ "i": i }),
        )
        .unwrap();
    }
    let content = std::fs::read_to_string(log.path()).unwrap();
    let tampered = content.replace("\"i\":1", "\"i\":41");
    std::fs::write(log.path(), tampered).unwrap();
    let report = log.verify().unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_invalid_sequence, Some(1));
}

/// Expired capabilities and locked vaults refuse signing (Vault gate).
#[tokio::test]
async fn expired_capability_and_locked_vault_refused() {
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let mut vault = Vault::new(signer);
    let mut req = VaultSigningRequest {
        signing_request_id: cipherlayer_types::new_id(),
        request_id: cipherlayer_types::new_id(),
        account: vault.address(),
        chain_id: ChainId(31337),
        network_class: NetworkClass::Development,
        capability: Capability::signing("cli:test", vault.address(), ChainId(31337), 60),
        policy_verdict: Verdict::Allow,
        user_authorization: UserAuthorization {
            decided_at: cipherlayer_types::now(),
            surface: ConfirmationSurface::CliPrompt,
            escalation_acknowledged: false,
        },
        tx: TxParams {
            to: Some(addr(2)),
            value: U256::ZERO,
            data: vec![],
            nonce: 0,
            gas_limit: 21_000,
            gas_price_wei: 1_000_000_000,
        },
        message_payload: None,
    };
    req.capability.expires_at = cipherlayer_types::now() - chrono::Duration::seconds(1);
    assert!(matches!(
        vault.authorize_and_sign(&req).await.unwrap_err(),
        VaultError::Capability(_)
    ));

    req.capability = Capability::signing("cli:test", vault.address(), ChainId(31337), 60);
    vault.lock();
    assert!(matches!(
        vault.authorize_and_sign(&req).await.unwrap_err(),
        VaultError::Locked
    ));
}

/// T-09 at the pipeline level: a node that reports a different chain than the
/// envelope names is refused BEFORE simulation — no evidence is produced from
/// a wrong-chain endpoint, and the request lands in BLOCKED (fail closed).
/// Self-contained: the "node" is an in-test mock answering only eth_chainId.
#[tokio::test]
async fn wrong_chain_node_blocked_before_simulation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Mock JSON-RPC node claiming Ethereum mainnet (0x1).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"jsonrpc":"2.0","id":0,"result":"0x1"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let audit = cipherlayer_audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let vault = Vault::new(signer);
    let account = vault.address();
    let mut pipeline =
        cipherlayer_cli::pipeline::Pipeline::new(Policy::default_dev(), audit, vault, &rpc_url);
    cipherlayer_cli::pipeline::grant_cli_permission(
        &mut pipeline,
        &cli_caller(),
        ChainId(31337),
        account,
    )
    .unwrap();

    // Envelope names the Anvil dev chain (31337); the node claims mainnet.
    let env = TransactionRequestEnvelope::new(
        cli_caller(),
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{account}"),
            to: Some(format!("{}", addr(2))),
            value_wei: Some("1".into()),
            data: Some("0x".into()),
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        },
    );
    let out = pipeline
        .process(env, cipherlayer_cli::pipeline::ReviewMode::AssumeYes)
        .await
        .unwrap();

    assert_eq!(out.final_state, LifecycleState::Blocked);
    assert!(out.simulation.is_none(), "no simulation evidence may exist");
    assert!(out.tx_hash.is_none());
    assert!(out
        .notes
        .iter()
        .any(|n| n.contains("chain identity verification failed")));
}

// ---------------------------------------------------------------------------
// v0.4 end-to-end: typed_data / personal_message over the REAL pipeline
// (validate -> decode -> risk -> policy -> review -> vault), closing AC-C for
// real (not just at the policy-engine level — see the already-existing
// typed_data_* tests above, which prove classification/policy wiring but not
// the wire-format/pipeline/vault closure). No Anvil is required: signature
// payloads never touch chain RPC (no chain-identity check, no simulation —
// N/A by design; see pipeline.rs step 4).
// ---------------------------------------------------------------------------

/// Build a fresh in-memory pipeline with a signing grant for `account` on the
/// dev chain, exactly the setup a real `connect_request` would produce.
fn fresh_signing_pipeline() -> (
    cipherlayer_cli::pipeline::Pipeline,
    Address,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let audit = cipherlayer_audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let vault = Vault::new(signer);
    let account = vault.address();
    let mut pipeline = cipherlayer_cli::pipeline::Pipeline::new(
        Policy::default_dev(),
        audit,
        vault,
        // Deliberately unreachable: typed_data/personal_message never call it.
        "http://127.0.0.1:1",
    );
    cipherlayer_cli::pipeline::grant_cli_permission(
        &mut pipeline,
        &cli_caller(),
        ChainId(31337),
        account,
    )
    .unwrap();
    (pipeline, account, dir)
}

fn typed_data_envelope(from: Address, typed_data_json: String) -> TransactionRequestEnvelope {
    TransactionRequestEnvelope::new(
        cli_caller(),
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{from}"),
            to: None,
            value_wei: None,
            data: None,
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::TypedData,
            typed_data_json: Some(typed_data_json),
            message_hex: None,
        },
    )
}

fn personal_message_envelope(from: Address, message: &[u8]) -> TransactionRequestEnvelope {
    TransactionRequestEnvelope::new(
        cli_caller(),
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{from}"),
            to: None,
            value_wei: None,
            data: None,
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::PersonalMessage,
            typed_data_json: None,
            message_hex: Some(format!("0x{}", hex::encode(message))),
        },
    )
}

/// AC-C, end to end: an unlimited EIP-2612 permit submitted as a real
/// `typed_data` request over the socket-shaped envelope, run through the
/// FULL pipeline, is DENIED — POL-APR-001, the same rule a raw `approve`
/// hits — and never reaches the vault (no signature_hex, no signing_request).
#[tokio::test]
async fn typed_data_unlimited_permit_denied_end_to_end_over_the_pipeline() {
    let (mut pipeline, account, _dir) = fresh_signing_pipeline();
    let json = eip2612_permit_json(addr(9), addr(2), U256::MAX, 31337);
    let env = typed_data_envelope(account, json);
    let out = pipeline
        .process(env, cipherlayer_cli::pipeline::ReviewMode::AssumeYes)
        .await
        .unwrap();

    assert_eq!(out.final_state, LifecycleState::PolicyDenied);
    assert!(
        out.signature_hex.is_none(),
        "a denied permit must never be signed"
    );
    assert!(
        out.signing_request_id.is_none(),
        "no vault request may exist for a denial"
    );
    let decision = out.decision.as_ref().expect("decision present");
    assert!(decision.reasons.iter().any(|r| r.code == "POL-APR-001"));

    // The browser-connect wire answer reflects the same denial + reasons.
    let response = pipeline.to_signing_response(&out).unwrap();
    assert_eq!(response.state, LifecycleState::PolicyDenied);
    assert!(response
        .refusal_reasons
        .iter()
        .any(|r| r.code == "POL-APR-001"));
    assert!(response.signature_hex.is_none());
}

/// AC-C, the undecodable half, end to end: typed data that doesn't match a
/// recognized permit shape escalates (POL-UNK-001) rather than a quiet
/// "Sign" — and, because escalation is not denial, an explicit acknowledged
/// confirmation (--yes) can still carry it through to a real signature. The
/// escalation reason is preserved in the record either way.
#[tokio::test]
async fn typed_data_unknown_escalates_end_to_end_over_the_pipeline() {
    let (mut pipeline, account, _dir) = fresh_signing_pipeline();
    let json = serde_json::json!({
        "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }],
            "Vote": [
                { "name": "proposalId", "type": "uint256" },
                { "name": "support", "type": "bool" }
            ]
        },
        "primaryType": "Vote",
        "domain": { "name": "Governance" },
        "message": { "proposalId": "1", "support": true }
    })
    .to_string();

    // Reject mode: escalation never becomes a quiet allow — no acknowledgement, no signature.
    let env_reject = typed_data_envelope(account, json.clone());
    let out_reject = pipeline
        .process(env_reject, cipherlayer_cli::pipeline::ReviewMode::Reject)
        .await
        .unwrap();
    assert_eq!(out_reject.final_state, LifecycleState::Rejected);
    assert!(out_reject.signature_hex.is_none());
    assert!(out_reject
        .decision
        .as_ref()
        .unwrap()
        .reasons
        .iter()
        .any(|r| r.code == "POL-UNK-001"));

    // Explicit --yes acknowledgement: escalation carries through to a real signature.
    let env_yes = typed_data_envelope(account, json);
    let out_yes = pipeline
        .process(env_yes, cipherlayer_cli::pipeline::ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out_yes.final_state, LifecycleState::Signed);
    let decision = out_yes.decision.as_ref().unwrap();
    assert_eq!(decision.verdict, Verdict::Escalate);
    assert!(decision.reasons.iter().any(|r| r.code == "POL-UNK-001"));
    let sig = out_yes.signature_hex.as_ref().expect("signature present");
    assert!(sig.starts_with("0x"));
    assert_eq!(sig.len(), 2 + 65 * 2, "65-byte r/s/v signature");
}

/// personal_sign, end to end: deterministic UTF-8-or-hex display, always
/// requires review (Reject truly refuses; AssumeYes truly signs), and the
/// signature roundtrips as a real 65-byte ECDSA signature — never a raw
/// `eth_sign` blind-hash (that stays forbidden; the Vault only ever hashes
/// message bytes it derives itself via EIP-191, never a caller-supplied hash).
#[tokio::test]
async fn personal_sign_requires_review_and_roundtrips_end_to_end() {
    let (mut pipeline, account, _dir) = fresh_signing_pipeline();
    let message = b"Sign in to example.org\nNonce: abc123".to_vec();

    // Review required: an explicit rejection must refuse, not sign.
    let env_reject = personal_message_envelope(account, &message);
    let out_reject = pipeline
        .process(env_reject, cipherlayer_cli::pipeline::ReviewMode::Reject)
        .await
        .unwrap();
    assert_eq!(out_reject.final_state, LifecycleState::Rejected);
    assert!(out_reject.signature_hex.is_none());

    // Approved: signs and roundtrips; valid UTF-8 is shown as readable text.
    let env_yes = personal_message_envelope(account, &message);
    let out_yes = pipeline
        .process(env_yes, cipherlayer_cli::pipeline::ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out_yes.final_state, LifecycleState::Signed);
    let sig = out_yes.signature_hex.as_ref().expect("signature present");
    assert!(sig.starts_with("0x"));
    assert_eq!(sig.len(), 2 + 65 * 2);
    let intent = out_yes.intent.as_ref().unwrap();
    assert_eq!(
        intent.decoded_action.kind,
        cipherlayer_evm::ActionKind::PersonalSign
    );
    assert_eq!(
        intent.decoded_action.function_signature.as_deref(),
        Some("Sign in to example.org\nNonce: abc123"),
        "valid UTF-8 must be shown as readable text, not hex"
    );

    // Non-UTF-8 bytes: shown as hex, never mangled or silently dropped.
    let binary = vec![0xffu8, 0x00, 0xfe, 0x01];
    let env_binary = personal_message_envelope(account, &binary);
    let out_binary = pipeline
        .process(env_binary, cipherlayer_cli::pipeline::ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out_binary.final_state, LifecycleState::Signed);
    let intent_binary = out_binary.intent.as_ref().unwrap();
    assert_eq!(
        intent_binary.decoded_action.function_signature.as_deref(),
        Some("0xff00fe01"),
        "non-UTF-8 message bytes must be shown as hex, never mangled"
    );

    // The browser-connect wire answer carries the signature and no tx_hash.
    let response = pipeline.to_signing_response(&out_yes).unwrap();
    assert_eq!(response.state, LifecycleState::Signed);
    assert!(response.tx_hash.is_none());
    assert!(response.signature_hex.is_some());
    assert!(response.refusal_reasons.is_empty());
}

/// A typed-data domain claiming a different chain than the session is denied
/// outright (POL-CHAIN-002) end to end — the same cross-chain-replay
/// discipline as AC-D, applied to signature requests.
#[tokio::test]
async fn typed_data_domain_chain_mismatch_denied_end_to_end() {
    let (mut pipeline, account, _dir) = fresh_signing_pipeline();
    // Domain says mainnet (1); the session/envelope is the dev chain (31337).
    let json = eip2612_permit_json(addr(9), addr(2), U256::from(1u64), 1);
    let env = typed_data_envelope(account, json);
    let out = pipeline
        .process(env, cipherlayer_cli::pipeline::ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out.final_state, LifecycleState::PolicyDenied);
    assert!(out
        .decision
        .as_ref()
        .unwrap()
        .reasons
        .iter()
        .any(|r| r.code == "POL-CHAIN-002"));
    assert!(out.signature_hex.is_none());
}

/// v0.3-shaped clients keep working unchanged: a wire envelope with no
/// `kind`/`typed_data_json`/`message_hex` keys at all (exactly what a v0.3
/// browser broker sends today) still parses and validates as
/// `evm_transaction` — protocol-doc rule 6, additive-only.
#[test]
fn v03_shaped_envelope_without_kind_field_still_parses_as_evm_transaction() {
    let raw = format!(
        r#"{{
          "schema_version": "1.0",
          "request_id": "0193b5a4-0000-7000-8000-0000000000aa",
          "received_at": "2026-07-05T12:00:00Z",
          "protocol_version": "0.3",
          "caller": {{ "kind": "dapp", "origin": "https://old-dapp.example", "capsule_id": "c1" }},
          "chain_id": 31337,
          "access": "signing",
          "payload": {{ "from": "{}", "to": "{}", "value_wei": "0", "data": "0x" }}
        }}"#,
        addr(1),
        addr(2)
    );
    let env = parse_envelope(&raw).expect("v0.3-shaped envelope must still parse");
    assert_eq!(
        env.payload.kind,
        cipherlayer_provider::PayloadKind::EvmTransaction
    );
    assert!(env.payload.typed_data_json.is_none());
    assert!(env.payload.message_hex.is_none());
    validate(&env, &ChainRegistry::builtin()).expect("must still validate");
}

/// Recipient aliases are presentation convenience, never authority: only an
/// exact label may resolve, and the authoritative address remains available
/// for the preflight/signing path.
#[test]
fn recipient_alias_resolves_exactly_to_the_vetted_address() {
    use cipherlayer_cli::console::{resolve_evm_address_ref, AddressAlias};

    let aliases = vec![AddressAlias {
        label: "Test Target".into(),
        address: "0x1111111111111111111111111111111111111111".into(),
    }];
    let resolved = resolve_evm_address_ref("test target", &aliases, "recipient")
        .expect("exact case-insensitive alias must resolve");
    assert_eq!(resolved.address, addr(0x11));
    assert_eq!(resolved.label.as_deref(), Some("Test Target"));
    assert!(
        resolve_evm_address_ref("Test", &aliases, "recipient").is_err(),
        "partial/fuzzy alias matches could redirect funds"
    );
}

/// An alias label reaches the terminal directly beside the authoritative
/// resolved address the operator is told to verify before signing (T-11).
/// A label carrying terminal control/escape bytes — however it got into the
/// address book — must never be able to corrupt or hide that address on
/// screen.
#[test]
fn alias_label_control_bytes_are_stripped_before_display() {
    use cipherlayer_cli::console::sanitize_display_label;

    let hostile = "Treasury\x1b[2K\x1b[1A\x1b[2Kdrain-to-attacker";
    let shown = sanitize_display_label(hostile);
    assert!(
        !shown.contains('\x1b'),
        "no raw escape byte may reach the terminal: {shown:?}"
    );
}

/// A duplicated human label is safe only when every copy names the same
/// address. Conflicting duplicates must fail closed before preflight.
#[test]
fn conflicting_recipient_aliases_refuse_closed() {
    use cipherlayer_cli::console::{resolve_evm_address_ref, AddressAlias};

    let aliases = vec![
        AddressAlias {
            label: "Treasury".into(),
            address: "0x1111111111111111111111111111111111111111".into(),
        },
        AddressAlias {
            label: "treasury".into(),
            address: "0x2222222222222222222222222222222222222222".into(),
        },
    ];
    let err = resolve_evm_address_ref("TREASURY", &aliases, "recipient")
        .expect_err("conflicting duplicate aliases must not choose an address");
    assert!(err.contains("ambiguous"), "{err}");
}

// ---------------------------------------------------------------------------
// CL-WAL-015: the shared (EVM) pipeline must refuse every non-EVM chain
// family, deterministically and before any RPC. A Solana/Bitcoin registry id
// (900000-band) must never flow through EVM decode/risk/policy/review toward
// an EVM signature, and must never read as low risk: non-EVM evidence is
// `unknown`, and the only non-EVM signing entry points are the family-specific
// vault ceremonies (ADR-016/017/021), not this pipeline.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_evm_chain_families_are_refused_by_the_shared_pipeline() {
    use cipherlayer_chain::ChainFamily;
    use cipherlayer_provider::PayloadKind;

    let non_evm: Vec<ChainId> = ChainRegistry::builtin()
        .entries()
        .iter()
        .filter(|e| e.chain_family != ChainFamily::Evm)
        .map(|e| e.chain_id)
        .collect();
    assert!(
        non_evm.len() >= 2,
        "registry should carry Solana and Bitcoin entries"
    );

    for chain in non_evm {
        for kind in [
            PayloadKind::EvmTransaction,
            PayloadKind::TypedData,
            PayloadKind::PersonalMessage,
        ] {
            let (mut pipeline, account, dir) = fresh_signing_pipeline();
            // A signing grant exists for this exact chain id, so the
            // permission layer cannot be what refuses it.
            cipherlayer_cli::pipeline::grant_cli_permission(
                &mut pipeline,
                &cli_caller(),
                chain,
                account,
            )
            .unwrap();
            let mut env = match kind {
                PayloadKind::TypedData => typed_data_envelope(
                    account,
                    eip2612_permit_json(addr(9), addr(2), U256::from(1u8), 31337),
                ),
                PayloadKind::PersonalMessage => personal_message_envelope(account, b"hello"),
                PayloadKind::EvmTransaction => TransactionRequestEnvelope::new(
                    cli_caller(),
                    chain,
                    AccessClass::Signing,
                    EnvelopePayload {
                        from: format!("{account}"),
                        to: Some(format!("{}", addr(2))),
                        value_wei: Some("1".into()),
                        data: Some("0x".into()),
                        gas_limit: None,
                        nonce: None,
                        kind: PayloadKind::EvmTransaction,
                        typed_data_json: None,
                        message_hex: None,
                    },
                ),
            };
            env.chain_id = chain;
            let request_id = env.request_id;
            let out = pipeline
                .process(env, cipherlayer_cli::pipeline::ReviewMode::AssumeYes)
                .await
                .unwrap();

            let label = format!("chain {chain:?} kind {kind:?}");
            assert!(
                matches!(
                    out.final_state,
                    LifecycleState::Rejected | LifecycleState::Blocked
                ),
                "{label}: expected a terminal refusal, got {:?}",
                out.final_state
            );
            assert!(out.signing_request_id.is_none(), "{label}: vault reached");
            assert!(out.signature_hex.is_none(), "{label}: signed");
            assert!(out.tx_hash.is_none(), "{label}: broadcast");
            assert!(out.simulation.is_none(), "{label}: simulation evidence");
            assert!(out.risk.is_none(), "{label}: risk evidence");
            assert!(out.decision.is_none(), "{label}: policy decision reached");
            assert!(
                out.notes.iter().any(|n| n.contains("chain family")),
                "{label}: refusal must name the chain-family gate, got {:?}",
                out.notes
            );
            let events = pipeline.audit.events_for_request(request_id).unwrap();
            assert!(
                events
                    .iter()
                    .any(|e| format!("{:?}", e.kind).contains("Failure")),
                "{label}: refusal must be audited"
            );
            drop(dir);
        }
    }
}
