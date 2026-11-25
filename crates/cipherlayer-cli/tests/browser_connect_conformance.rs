//! Browser-connect contract conformance harness (browser gate criterion 3).
//!
//! Plays the role of a browser broker: builds wire-format JSON exactly as a
//! browser would send it (raw strings, not shared Rust constructors), drives
//! the wallet pipeline, and checks the signing-response answers against the
//! exported contract (exports/browser-connect-v0.1). This is a test harness,
//! not product code — the browser repo stays implementation-free.
//!
//! Offline cases always run; end-to-end cases are gated on
//! CIPHERLAYER_INTEGRATION=1 + a local Anvil (make anvil-up).

use cipherlayer_audit::AuditLog;
use cipherlayer_cli::demo;
use cipherlayer_cli::pipeline::{Pipeline, ReviewMode};
use cipherlayer_policy::Policy;
use cipherlayer_provider::{parse_envelope, validate, WalletCapability};
use cipherlayer_types::state::LifecycleState;
use cipherlayer_types::{AccessClass, Address, CallerIdentity, CallerKind, ChainId, U256};
use cipherlayer_vault::{TestSigner, Vault, ANVIL_DEV_KEYS};

fn rpc_url() -> String {
    std::env::var("CIPHERLAYER_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into())
}

fn integration_enabled() -> bool {
    if std::env::var("CIPHERLAYER_INTEGRATION").as_deref() == Ok("1") {
        true
    } else {
        eprintln!("SKIPPED: set CIPHERLAYER_INTEGRATION=1 (make test-integration) to run");
        false
    }
}

/// Raw wire JSON as a browser broker would emit it.
fn wire_envelope(request_id: &str, from: &str, to: &str, data: &str) -> String {
    format!(
        r#"{{
          "schema_version": "1.0",
          "request_id": "{request_id}",
          "received_at": "2026-07-05T12:00:00Z",
          "protocol_version": "0.1",
          "caller": {{
            "kind": "dapp",
            "origin": "https://sample-dapp.example",
            "capsule_id": "capsule-0001"
          }},
          "chain_id": 31337,
          "access": "signing",
          "payload": {{
            "from": "{from}",
            "to": "{to}",
            "value_wei": "0",
            "data": "{data}"
          }}
        }}"#
    )
}

fn dapp_caller() -> CallerIdentity {
    CallerIdentity {
        kind: CallerKind::Dapp,
        origin: Some("https://sample-dapp.example".into()),
        app_id: None,
        capsule_id: Some("capsule-0001".into()),
    }
}

fn fresh_pipeline() -> (Pipeline, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let pipeline = Pipeline::new(Policy::default_dev(), audit, Vault::new(signer), &rpc_url());
    (pipeline, dir)
}

// ---------------------------------------------------------------------------
// Offline conformance (always runs)
// ---------------------------------------------------------------------------

/// Wire-format envelopes parse and validate exactly as the schema promises;
/// broken identity fails closed.
#[test]
fn wire_envelope_parses_and_identity_is_enforced() {
    let raw = wire_envelope(
        "0193b5a4-0000-7000-8000-000000000001",
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "0x00000000000000000000000000000000000000bb",
        "0x",
    );
    let env = parse_envelope(&raw).expect("browser wire format must parse");
    assert_eq!(env.protocol_version.as_deref(), Some("0.1"));
    assert_eq!(env.caller.capsule_id.as_deref(), Some("capsule-0001"));
    validate(&env, &cipherlayer_chain::ChainRegistry::builtin()).expect("must validate");

    // Same envelope with the identity stripped must fail closed.
    let anonymized = raw.replace(
        r#""origin": "https://sample-dapp.example","#,
        r#""origin": "","#,
    );
    let env2 = parse_envelope(&anonymized).expect("parses");
    assert!(validate(&env2, &cipherlayer_chain::ChainRegistry::builtin()).is_err());
}

/// The capability advertisement answers capability_query truthfully:
/// versioned protocol, dev chain present, unlisted methods absent.
#[test]
fn capability_advertisement_matches_contract() {
    let cap = WalletCapability::current(&cipherlayer_chain::ChainRegistry::builtin());
    let json = serde_json::to_value(&cap).unwrap();
    assert_eq!(json["schema_version"], "1.0");
    assert!(cap.protocol_versions.contains(&"0.1".to_string()));
    assert!(cap.chains.contains(&31337));
    assert!(cap.methods.contains(&"transaction_request".to_string()));
    assert!(!cap.methods.contains(&"eth_exportPrivateKey".to_string()));
    assert_eq!(cap.signer_kinds, vec!["test".to_string()]);
}

/// Security regression (ADR-016 §3 / ADR-021): the reserved 900000-band
/// internal registry ids (non-EVM chains) must never serialize onto the
/// EIP-1193-shaped capability surface. Removing the EVM-family filter in
/// `WalletCapability::current` re-opens this leak — this test is what fails.
#[test]
fn capability_never_lists_reserved_band_chain_ids() {
    let cap = WalletCapability::current(&cipherlayer_chain::ChainRegistry::builtin());
    for id in cap.chains {
        assert!(
            !(900_000..=999_999).contains(&id),
            "reserved-band internal id {id} leaked onto the capability wire surface"
        );
    }
    // The registry genuinely contains reserved-band entries (this test is
    // vacuous otherwise): Solana local/devnet/mainnet-beta + Bitcoin regtest.
    let registry = cipherlayer_chain::ChainRegistry::builtin();
    for id in [900_001, 900_002, 900_003, 900_004] {
        assert!(
            registry.get(cipherlayer_types::ChainId(id)).is_ok(),
            "expected reserved-band registry entry {id} is missing"
        );
    }
}

// ---------------------------------------------------------------------------
// End-to-end conformance (Anvil)
// ---------------------------------------------------------------------------

/// Denial path: unlimited approval from a permitted dapp yields a
/// POLICY_DENIED signing-response with machine-readable refusal reasons,
/// a null signing_request_id (no Vault request ever existed), and an audit
/// head reference.
#[tokio::test]
async fn denial_produces_conformant_signing_response() {
    if !integration_enabled() {
        return;
    }
    let (mut pipeline, _dir) = fresh_pipeline();
    let account = pipeline.vault.address();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(rpc_url().parse().unwrap());
    let token = demo::deploy(
        &provider,
        account,
        demo::creation_bytecode(demo::TOKEN_ARTIFACT).unwrap(),
    )
    .await
    .unwrap();

    // connect_request equivalent: grant the dapp a scoped signing permission.
    pipeline.permissions.grant(
        &dapp_caller(),
        ChainId(31337),
        AccessClass::Signing,
        vec![account],
        chrono::Duration::hours(1),
    );

    let raw = wire_envelope(
        &cipherlayer_types::new_id().to_string(),
        &format!("{account}"),
        &format!("{token}"),
        &demo::approve_calldata(Address::from_slice(&[7u8; 20]), U256::MAX),
    );
    let env = parse_envelope(&raw).unwrap();
    let outcome = pipeline.process(env, ReviewMode::AssumeYes).await.unwrap();
    let response = pipeline.to_signing_response(&outcome).unwrap();

    assert_eq!(response.state, LifecycleState::PolicyDenied);
    assert_eq!(response.signing_request_id, None);
    assert!(response.tx_hash.is_none());
    assert!(response
        .refusal_reasons
        .iter()
        .any(|r| r.code == "POL-APR-001"));
    assert!(response.audit_head_sequence > 0);

    // v1.2 display evidence: a denial carries the deterministic pipeline
    // evidence (verdict Deny + reasons), for display only — the refusal
    // itself is already final regardless of what any consumer renders.
    let evidence = response.review_evidence.as_ref().expect("evidence present");
    assert_eq!(evidence.policy_verdict.as_deref(), Some("Deny"));
    assert!(evidence
        .policy_reasons
        .iter()
        .any(|r| r.starts_with("POL-APR-001")));
    assert!(evidence.risk_level.is_some());

    // Wire shape: serializes with SCREAMING_SNAKE_CASE state and null request id.
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["state"], "POLICY_DENIED");
    assert!(json["signing_request_id"].is_null());
}

/// Happy path: exact approval yields a CONFIRMED signing-response carrying
/// the tx hash, the Vault signing_request_id, and the audit head.
#[tokio::test]
async fn confirmation_produces_conformant_signing_response() {
    if !integration_enabled() {
        return;
    }
    let (mut pipeline, _dir) = fresh_pipeline();
    let account = pipeline.vault.address();
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(rpc_url().parse().unwrap());
    let token = demo::deploy(
        &provider,
        account,
        demo::creation_bytecode(demo::TOKEN_ARTIFACT).unwrap(),
    )
    .await
    .unwrap();
    pipeline.permissions.grant(
        &dapp_caller(),
        ChainId(31337),
        AccessClass::Signing,
        vec![account],
        chrono::Duration::hours(1),
    );

    let raw = wire_envelope(
        &cipherlayer_types::new_id().to_string(),
        &format!("{account}"),
        &format!("{token}"),
        &demo::approve_calldata(Address::from_slice(&[7u8; 20]), U256::from(42u64)),
    );
    let env = parse_envelope(&raw).unwrap();
    let outcome = pipeline.process(env, ReviewMode::AssumeYes).await.unwrap();
    let response = pipeline.to_signing_response(&outcome).unwrap();

    assert_eq!(response.state, LifecycleState::Confirmed);
    assert!(response.signing_request_id.is_some());
    assert!(response.tx_hash.as_deref().unwrap_or("").starts_with("0x"));
    assert!(response.refusal_reasons.is_empty());
    // v1.2 display evidence travels with the confirmation too.
    let evidence = response.review_evidence.as_ref().expect("evidence present");
    assert!(evidence.simulation.is_some());
    assert!(evidence.risk_level.is_some());
    assert_ne!(evidence.policy_verdict.as_deref(), Some("Deny"));
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["state"], "CONFIRMED");
}

/// Expiry path: an expired grant yields EXPIRED with reasons, never a signature.
#[tokio::test]
async fn expiry_produces_conformant_signing_response() {
    if !integration_enabled() {
        return;
    }
    let (mut pipeline, _dir) = fresh_pipeline();
    let account = pipeline.vault.address();
    pipeline.permissions.grant(
        &dapp_caller(),
        ChainId(31337),
        AccessClass::Signing,
        vec![account],
        chrono::Duration::seconds(-1),
    );
    let raw = wire_envelope(
        &cipherlayer_types::new_id().to_string(),
        &format!("{account}"),
        "0x00000000000000000000000000000000000000bb",
        "0x",
    );
    let env = parse_envelope(&raw).unwrap();
    let outcome = pipeline.process(env, ReviewMode::AssumeYes).await.unwrap();
    let response = pipeline.to_signing_response(&outcome).unwrap();
    assert_eq!(response.state, LifecycleState::Expired);
    assert_eq!(response.signing_request_id, None);
    assert!(response.tx_hash.is_none());
    assert!(!response.refusal_reasons.is_empty());
}
