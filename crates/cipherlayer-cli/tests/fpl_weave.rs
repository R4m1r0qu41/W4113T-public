//! FPL weave test: the pipeline's risk step consumes real Scam Guard
//! findings over the pinned contract (subprocess, no linked sibling code).
//!
//! Gated on both CIPHERLAYER_INTEGRATION=1 (needs Anvil) and
//! CIPHERLAYER_FPL_BIN (needs a built scam-guard binary) — the root
//! system-test.sh sets both.

use cipherlayer_audit::AuditLog;
use cipherlayer_cli::pipeline::{ensure_cli_permission, Pipeline, ReviewMode};
use cipherlayer_policy::Policy;
use cipherlayer_provider::{EnvelopePayload, TransactionRequestEnvelope};
use cipherlayer_types::{AccessClass, CallerIdentity, CallerKind, ChainId};
use cipherlayer_vault::{TestSigner, Vault, ANVIL_DEV_KEYS};

#[tokio::test]
async fn risk_step_carries_real_scam_guard_findings() {
    if std::env::var("CIPHERLAYER_INTEGRATION").as_deref() != Ok("1") {
        eprintln!("SKIPPED: set CIPHERLAYER_INTEGRATION=1");
        return;
    }
    let Ok(bin) = std::env::var("CIPHERLAYER_FPL_BIN") else {
        eprintln!("SKIPPED: set CIPHERLAYER_FPL_BIN to a scam-guard binary");
        return;
    };
    assert!(
        std::path::Path::new(&bin).exists(),
        "CIPHERLAYER_FPL_BIN points at a missing file"
    );

    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
    let rpc = std::env::var("CIPHERLAYER_RPC_URL").unwrap_or("http://127.0.0.1:8545".into());
    let mut pipeline = Pipeline::new(Policy::default_dev(), audit, Vault::new(signer), &rpc);
    let caller = CallerIdentity {
        kind: CallerKind::Cli,
        origin: None,
        app_id: Some("cli:fpl-weave-test".into()),
        capsule_id: None,
    };
    let account = pipeline.vault.address();
    ensure_cli_permission(&mut pipeline, &caller, ChainId(31337), account).unwrap();

    // Unlimited approve → scam-guard must flag SG-ALLOW-001, policy must deny.
    let env = TransactionRequestEnvelope::new(
        caller,
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{account}"),
            to: Some("0x00000000000000000000000000000000000000cc".into()),
            value_wei: Some("0".into()),
            data: Some(format!(
                "0x095ea7b3{:0>64}{}",
                "07".repeat(20),
                "f".repeat(64)
            )),
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        },
    );
    let out = pipeline.process(env, ReviewMode::AssumeYes).await.unwrap();
    let risk = out.risk.expect("risk bundle present");

    let fpl_finding = risk
        .findings
        .iter()
        .find(|f| f.detector.name == "intent-allowance")
        .expect("real scam-guard finding present, not the mock");
    assert!(fpl_finding
        .reason_codes
        .contains(&"SG-ALLOW-001".to_string()));
    assert_ne!(
        fpl_finding.provenance.mock,
        Some(true),
        "must not be a mock"
    );
    assert!(risk.detectors_unavailable.is_empty());
    assert_eq!(
        format!("{:?}", out.final_state),
        "PolicyDenied",
        "policy still decides; findings only inform"
    );
}
