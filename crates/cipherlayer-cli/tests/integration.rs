//! Integration tests against a live local Anvil chain (BP §15).
//!
//! Guarded: they run only when CIPHERLAYER_INTEGRATION=1 (set by
//! `make test-integration`) and print SKIPPED otherwise, so a plain
//! `cargo test` never reports false green for suites that did not run.
//! Requires `make anvil-up` (chain-id 31337 on port 8545, or
//! CIPHERLAYER_RPC_URL).

use cipherlayer_audit::AuditLog;
use cipherlayer_cli::demo;
use cipherlayer_cli::pipeline::{grant_cli_permission, Pipeline, ReviewMode};
use cipherlayer_policy::Policy;
use cipherlayer_provider::{EnvelopePayload, TransactionRequestEnvelope};
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

fn caller() -> CallerIdentity {
    CallerIdentity {
        kind: CallerKind::Cli,
        origin: None,
        app_id: Some("cli:integration-test".into()),
        capsule_id: None,
    }
}

struct TestCtx {
    pipeline: Pipeline,
    _dir: tempfile::TempDir,
}

fn fresh_pipeline() -> TestCtx {
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let vault = Vault::new(signer);
    let pipeline = Pipeline::new(Policy::default_dev(), audit, vault, &rpc_url());
    TestCtx {
        pipeline,
        _dir: dir,
    }
}

async fn deploy_token(account: Address) -> Address {
    let provider =
        alloy::providers::ProviderBuilder::new().connect_http(rpc_url().parse().unwrap());
    demo::deploy(
        &provider,
        account,
        demo::creation_bytecode(demo::TOKEN_ARTIFACT).unwrap(),
    )
    .await
    .expect("token deployment (is Anvil up? make anvil-up)")
}

/// Anvil lifecycle + sample deployment + the complete vertical slice:
/// unlimited approval blocked, exact approval confirmed end-to-end, on-chain
/// allowance verified, audit chain valid.
#[tokio::test]
async fn vertical_slice_demo_end_to_end() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    let report = demo::run(&mut ctx.pipeline).await.expect("demo must pass");
    assert!(report.audit_valid);
    assert!(report.audit_events >= 20, "expected a full lifecycle trail");
    assert_eq!(
        report.onchain_allowance,
        U256::from(100u64) * U256::from(10u64).pow(U256::from(18u64))
    );

    // The confirmed request's lifecycle is reconstructable from the audit log.
    let events = ctx
        .pipeline
        .audit
        .events_for_request(report.confirmed_request)
        .unwrap();
    let kinds: Vec<String> = events.iter().map(|e| format!("{:?}", e.kind)).collect();
    for expected in [
        "RequestReceived",
        "RequestValidated",
        "PermissionChecked",
        "IntentDecoded",
        "SimulationCompleted",
        "RiskEvaluated",
        "PolicyEvaluated",
        "UserDecision",
        "SignatureCreated",
        "BroadcastCompleted",
    ] {
        assert!(
            kinds.iter().any(|k| k == expected),
            "missing audit event {expected}"
        );
    }
}

/// Wrong-chain request: permission is scoped to 31337; a mainnet envelope is rejected.
#[tokio::test]
async fn wrong_chain_request_rejected() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    let account = ctx.pipeline.vault.address();
    grant_cli_permission(&mut ctx.pipeline, &caller(), ChainId(31337), account).unwrap();
    let mut env = demo::envelope(
        &caller(),
        account,
        Address::from_slice(&[9u8; 20]),
        "0x".into(),
    );
    env.chain_id = ChainId(1); // known chain, not covered by the grant
    let out = ctx
        .pipeline
        .process(env, ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out.final_state, LifecycleState::Rejected);
}

/// Unauthorized dapp: identified caller without any grant is rejected at
/// PERMISSION_CHECKED, and the denial is audited.
#[tokio::test]
async fn unauthorized_dapp_rejected() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    let account = ctx.pipeline.vault.address();
    let dapp = CallerIdentity {
        kind: CallerKind::Dapp,
        origin: Some("https://not-granted.example".into()),
        app_id: None,
        capsule_id: None,
    };
    let env = demo::envelope(&dapp, account, Address::from_slice(&[9u8; 20]), "0x".into());
    let rid = env.request_id;
    let out = ctx
        .pipeline
        .process(env, ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out.final_state, LifecycleState::Rejected);
    let events = ctx.pipeline.audit.events_for_request(rid).unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e.kind, cipherlayer_audit::EventKind::PermissionDenied)));
}

/// Expired permission terminates in EXPIRED.
#[tokio::test]
async fn expired_permission_rejected() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    let account = ctx.pipeline.vault.address();
    ctx.pipeline.permissions.grant(
        &caller(),
        ChainId(31337),
        AccessClass::Signing,
        vec![account],
        chrono::Duration::seconds(-1),
    );
    let env = demo::envelope(
        &caller(),
        account,
        Address::from_slice(&[9u8; 20]),
        "0x".into(),
    );
    let out = ctx
        .pipeline
        .process(env, ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out.final_state, LifecycleState::Expired);
}

/// Simulation failure (node cannot execute: sender has no funds) terminates
/// in SIMULATION_FAILED and never reaches signing.
#[tokio::test]
async fn simulation_failure_blocks_pipeline() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    // An account with no balance tries to send 1 ETH.
    let broke = Address::from_slice(&[0x42; 20]);
    ctx.pipeline.permissions.grant(
        &caller(),
        ChainId(31337),
        AccessClass::Signing,
        vec![broke],
        chrono::Duration::hours(1),
    );
    let env = TransactionRequestEnvelope::new(
        caller(),
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{broke}"),
            to: Some(format!("{}", Address::from_slice(&[0x43; 20]))),
            value_wei: Some("1000000000000000000".into()),
            data: Some("0x".into()),
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        },
    );
    let out = ctx
        .pipeline
        .process(env, ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out.final_state, LifecycleState::SimulationFailed);
    assert!(
        out.tx_hash.is_none(),
        "nothing may be signed after simulation failure"
    );
}

/// Locked signer: pipeline reaches the Vault and is refused (SIGNING_FAILED).
#[tokio::test]
async fn locked_signer_fails_at_vault() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    let account = ctx.pipeline.vault.address();
    let token = deploy_token(account).await;
    grant_cli_permission(&mut ctx.pipeline, &caller(), ChainId(31337), account).unwrap();
    ctx.pipeline.vault.lock();
    let env = demo::envelope(
        &caller(),
        account,
        token,
        demo::approve_calldata(Address::from_slice(&[7u8; 20]), U256::from(10u64)),
    );
    let out = ctx
        .pipeline
        .process(env, ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out.final_state, LifecycleState::SigningFailed);
    assert!(out.tx_hash.is_none());
}

/// Broadcast failure: an under-gassed transaction simulates as a revert
/// (escalated, honestly surfaced) and fails at broadcast confirmation.
#[tokio::test]
async fn undergassed_transaction_fails_at_broadcast() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    let account = ctx.pipeline.vault.address();
    let token = deploy_token(account).await;
    grant_cli_permission(&mut ctx.pipeline, &caller(), ChainId(31337), account).unwrap();
    let mut env = demo::envelope(
        &caller(),
        account,
        token,
        demo::approve_calldata(Address::from_slice(&[7u8; 20]), U256::from(10u64)),
    );
    // Enough for intrinsic gas, not enough to execute the approve.
    env.payload.gas_limit = Some("26000".into());
    let out = ctx
        .pipeline
        .process(env, ReviewMode::AssumeYes)
        .await
        .unwrap();
    assert_eq!(out.final_state, LifecycleState::BroadcastFailed);
}

/// User rejection at review terminates in REJECTED with no signature.
#[tokio::test]
async fn user_rejection_terminates_without_signature() {
    if !integration_enabled() {
        return;
    }
    let mut ctx = fresh_pipeline();
    let account = ctx.pipeline.vault.address();
    let token = deploy_token(account).await;
    grant_cli_permission(&mut ctx.pipeline, &caller(), ChainId(31337), account).unwrap();
    let env = demo::envelope(
        &caller(),
        account,
        token,
        demo::approve_calldata(Address::from_slice(&[7u8; 20]), U256::from(10u64)),
    );
    let out = ctx.pipeline.process(env, ReviewMode::Reject).await.unwrap();
    assert_eq!(out.final_state, LifecycleState::Rejected);
    assert!(out.tx_hash.is_none());
}
