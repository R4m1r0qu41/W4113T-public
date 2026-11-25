//! Solana ceremony security regressions at the REAL IPC boundary
//! (AGENTS.md process requirement; external re-audit, 2026-07-20).
//!
//! The 2026-07-19 unit tests called the daemon's handlers in-process and
//! missed that the LOCK REQUEST itself never dropped the pending approval —
//! lock → unlock → sign resurrected it. These tests drive the actual
//! `cipherlayer-vaultd` daemon over its Unix socket with the actual
//! `VaultClient` the console uses, so the wire, the handler dispatch, and
//! the gates are all exercised as deployed. No tty is ever reached: every
//! asserted path refuses before any terminal prompt.

use cipherlayer_vault::ipc::WireSolFacts;
use cipherlayer_vault::{
    SolApprovedFacts, SolExternalSignerConfig, SolExternalSigningCeremony, TestSigner, Vault,
    VaultClient, VaultIpcError, ANVIL_DEV_KEYS,
};
use cipherlayer_vaultd::Daemon;
use std::path::PathBuf;
use std::time::Duration;

fn facts() -> WireSolFacts {
    WireSolFacts {
        from_pubkey: "587DciffbmfqQKNDK1XLvfCGfndMKfxnpwWk2t8qWK9U".into(),
        to_pubkey: "AbZmoJqS2KrxVsEo3wi5CMHjpJCBrdovgcu1xH9KGpHE".into(),
        lamports: 1_000_000,
        fee_estimate_lamports: Some(5_000),
    }
}

fn daemon() -> Daemon {
    let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).expect("anvil dev key loads");
    Daemon::new(Vault::new(signer))
}

/// A daemon holding a live devnet approval, created engine-side (the same
/// phase-1 outcome the tty would produce), installed through the explicitly
/// feature-gated test seam — everything AFTER this point travels the real
/// wire. Default/production vaultd builds do not expose this helper.
fn daemon_with_approval() -> (Daemon, uuid::Uuid) {
    let mut d = daemon();
    let config = SolExternalSignerConfig::devnet();
    let phrase = config.approval_phrase;
    let chain_id = config.cluster_chain_id;
    let mut ceremony = SolExternalSigningCeremony::new(config);
    let f = facts();
    let ticket = ceremony
        .approve_facts(
            chain_id,
            SolApprovedFacts {
                from_pubkey: f.from_pubkey,
                to_pubkey: f.to_pubkey,
                lamports: f.lamports,
                fee_estimate_lamports: f.fee_estimate_lamports,
            },
            phrase,
            chrono::Utc::now(),
        )
        .expect("phase 1 approves");
    d.install_sol_ceremony(ceremony);
    (d, ticket.nonce)
}

/// Serve the daemon on a fresh owner-only socket; returns a checked client.
/// The TempDir must outlive the test (dropping it removes the socket).
async fn serve(mut d: Daemon) -> (tempfile::TempDir, VaultClient) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock: PathBuf = dir.path().join("vaultd").join("vault.sock");
    let sock_for_daemon = sock.clone();
    tokio::spawn(async move {
        let _ = d.run(&sock_for_daemon).await;
    });
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let client = VaultClient::connect_checked(&sock).expect("socket is owner-only and present");
    (dir, client)
}

fn refusal_code(err: VaultIpcError) -> String {
    match err {
        VaultIpcError::Refused { code, .. } => code,
        other => panic!("expected a coded refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn sol_sign_with_no_ceremony_refuses_over_ipc() {
    let (_dir, client) = serve(daemon()).await;
    let err = client
        .sol_sign(uuid::Uuid::new_v4(), &[0u8], Some(5_000))
        .await
        .expect_err("no approval exists — must refuse");
    assert_eq!(refusal_code(err), "VLT-SOL-005");
}

#[tokio::test]
async fn locked_vault_refuses_sol_sign_over_ipc() {
    let (d, nonce) = daemon_with_approval();
    let (_dir, client) = serve(d).await;
    assert!(client.set_locked(true).await.expect("lock round-trips"));
    let err = client
        .sol_sign(nonce, &[0u8], Some(5_000))
        .await
        .expect_err("locked vault must refuse");
    assert_eq!(refusal_code(err), "VLT-SOL-010");
}

/// The re-audit's resurrection scenario, end to end over the wire:
/// approve → lock → unlock → sign must find NOTHING pending. The lock
/// request alone must have killed the approval; no Solana request ever
/// arrives while locked. Without the fix the approval survives, the sign
/// attempt validates against it, and the refusal code differs — this
/// assertion discriminates without ever risking a key prompt (the message
/// bytes are not a decodable Solana message).
#[tokio::test]
async fn lock_unlock_does_not_resurrect_the_approval_over_ipc() {
    let (d, nonce) = daemon_with_approval();
    let (_dir, client) = serve(d).await;
    assert!(client.set_locked(true).await.expect("lock round-trips"));
    assert!(!client.set_locked(false).await.expect("unlock round-trips"));
    let err = client
        .sol_sign(nonce, &[0u8], Some(5_000))
        .await
        .expect_err("the approval died with the lock — must refuse");
    assert_eq!(refusal_code(err), "VLT-SOL-005");
}
