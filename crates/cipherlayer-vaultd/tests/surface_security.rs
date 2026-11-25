//! Security regression tests for the Vault-side confirmation surface
//! (trusted-confirmation-surface.md; ADR-012 tier v1).
//!
//! Real daemon binary, real socket. The dialog itself is bypassed with the
//! explicit CIPHERLAYER_CONFIRM_AUTO hook (the same discipline as the
//! transport's --yes); the fail-closed and never-confirmable paths are the
//! ones under test and do NOT depend on the hook.

use cipherlayer_policy::Verdict;
use cipherlayer_types::{Address, ChainId, NetworkClass, U256};
use cipherlayer_vault::ipc::{VaultClient, WireDisplayEvidence, WireSignState};
use cipherlayer_vault::{
    Capability, ConfirmationSurface, TxParams, UserAuthorization, VaultSigningRequest,
};
use std::process::{Child, Command};
use std::time::Duration;
use uuid::Uuid;

const DEV0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

struct DaemonGuard {
    child: Child,
    socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the daemon with a controlled surface environment.
/// `auto`: Some("approve"/"reject") sets the test hook; None removes it so
/// the real fail-closed path (phrase file check) runs.
/// `phrase_file`: Some(path) points the daemon at that phrase file.
fn spawn_daemon(auto: Option<&str>, phrase_file: Option<&std::path::Path>) -> DaemonGuard {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("vault.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cipherlayer-vaultd"));
    cmd.arg(&socket).env_remove("CIPHERLAYER_TEST_SIGNER_KEY");
    match auto {
        Some(v) => cmd.env("CIPHERLAYER_CONFIRM_AUTO", v),
        None => cmd.env_remove("CIPHERLAYER_CONFIRM_AUTO"),
    };
    match phrase_file {
        Some(p) => cmd.env("CIPHERLAYER_CONFIRM_PHRASE_FILE", p),
        None => cmd.env(
            "CIPHERLAYER_CONFIRM_PHRASE_FILE",
            dir.path().join("no-such-phrase"),
        ),
    };
    let child = cmd.spawn().unwrap();
    let guard = DaemonGuard {
        child,
        socket,
        _dir: dir,
    };
    for _ in 0..100 {
        if guard.socket.exists() {
            return guard;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not bind its socket in time");
}

fn base_request(account: Address, verdict: Verdict) -> VaultSigningRequest {
    VaultSigningRequest {
        signing_request_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        account,
        chain_id: ChainId(31337),
        network_class: NetworkClass::Development,
        capability: Capability::signing("cli:test", account, ChainId(31337), 60),
        policy_verdict: verdict,
        user_authorization: UserAuthorization {
            decided_at: chrono::Utc::now(),
            surface: ConfirmationSurface::DesktopTrustedSurface,
            escalation_acknowledged: false,
        },
        tx: TxParams {
            to: Some(Address::from_slice(&[2u8; 20])),
            value: U256::ZERO,
            data: vec![],
            nonce: 0,
            gas_limit: 21_000,
            gas_price_wei: 1_000_000_000,
        },
        message_payload: None,
    }
}

fn display() -> WireDisplayEvidence {
    WireDisplayEvidence {
        intent: "NativeTransfer".into(),
        chain: "Anvil (local development) (31337)".into(),
        simulation: "Success (3 standing limitations)".into(),
        risk: "UNKNOWN — no evidence; never treated as low".into(),
        policy_reasons: vec!["POL-RSK-002: risk evidence is Unknown".into()],
    }
}

fn dev0() -> Address {
    DEV0.parse().unwrap()
}

#[tokio::test]
async fn approved_surface_decision_signs() {
    let daemon = spawn_daemon(Some("approve"), None);
    let c = VaultClient::connect_checked(&daemon.socket).unwrap();
    let req = base_request(dev0(), Verdict::Allow);
    let resp = c
        .confirm_and_sign(&req, Uuid::new_v4(), Uuid::new_v4(), display())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Signed);
    assert!(resp.tx_hash.unwrap().starts_with("0x"));
}

#[tokio::test]
async fn rejected_surface_decision_is_vlt_usr_001_and_no_signature() {
    let daemon = spawn_daemon(Some("reject"), None);
    let c = VaultClient::connect_checked(&daemon.socket).unwrap();
    let req = base_request(dev0(), Verdict::Allow);
    let resp = c
        .confirm_and_sign(&req, Uuid::new_v4(), Uuid::new_v4(), display())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert!(resp.raw_tx_hex.is_none());
    assert_eq!(resp.refusal.unwrap().code, "VLT-USR-001");
}

#[tokio::test]
async fn deny_verdict_is_never_rendered_for_confirmation() {
    // Even with the auto-hook set to approve, a deny must be refused BEFORE
    // any surface interaction (requirement 7: deny is never confirmable).
    let daemon = spawn_daemon(Some("approve"), None);
    let c = VaultClient::connect_checked(&daemon.socket).unwrap();
    let req = base_request(dev0(), Verdict::Deny);
    let resp = c
        .confirm_and_sign(&req, Uuid::new_v4(), Uuid::new_v4(), display())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert_eq!(resp.refusal.unwrap().code, "VLT-POL-001");
}

#[tokio::test]
async fn escalate_approved_via_surface_signs_with_acknowledgement() {
    let daemon = spawn_daemon(Some("approve"), None);
    let c = VaultClient::connect_checked(&daemon.socket).unwrap();
    let req = base_request(dev0(), Verdict::Escalate);
    let resp = c
        .confirm_and_sign(&req, Uuid::new_v4(), Uuid::new_v4(), display())
        .await
        .unwrap();
    // The daemon constructs the authorization with the escalation
    // acknowledged flag; the vault would refuse otherwise.
    assert_eq!(resp.state, WireSignState::Signed);
}

#[tokio::test]
async fn missing_phrase_file_fails_closed_without_the_hook() {
    // No auto hook, no phrase file: the surface must refuse to confirm at
    // all (VLT-SUR-001) — it cannot prove genuineness. Never a dialog, never
    // a signature. (On non-macOS the platform check fails closed the same
    // way, so this test is portable.)
    let daemon = spawn_daemon(None, None);
    let c = VaultClient::connect_checked(&daemon.socket).unwrap();
    let req = base_request(dev0(), Verdict::Allow);
    let resp = c
        .confirm_and_sign(&req, Uuid::new_v4(), Uuid::new_v4(), display())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    let refusal = resp.refusal.unwrap();
    assert_eq!(refusal.code, "VLT-SUR-001");
    assert!(refusal.detail.contains("fail closed"));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn group_readable_phrase_file_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let phrase = dir.path().join("confirm-phrase");
    std::fs::write(&phrase, "correct horse battery staple\n").unwrap();
    std::fs::set_permissions(&phrase, std::fs::Permissions::from_mode(0o644)).unwrap();

    let daemon = spawn_daemon(None, Some(&phrase));
    let c = VaultClient::connect_checked(&daemon.socket).unwrap();
    let req = base_request(dev0(), Verdict::Allow);
    let resp = c
        .confirm_and_sign(&req, Uuid::new_v4(), Uuid::new_v4(), display())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    let refusal = resp.refusal.unwrap();
    assert_eq!(refusal.code, "VLT-SUR-001");
    assert!(refusal.detail.contains("group/world accessible"));
}

#[tokio::test]
async fn confirm_and_sign_with_preauthorized_request_is_refused() {
    // A caller must not be able to smuggle its own authorization through the
    // confirm path: user_authorization must be null.
    use cipherlayer_vault::WireSigningRequest;
    let daemon = spawn_daemon(Some("approve"), None);
    let req = base_request(dev0(), Verdict::Allow);
    let mut wire = WireSigningRequest::from_request(&req, Uuid::new_v4(), Uuid::new_v4());
    wire.ext.display = Some(display());
    // Deliberately leave user_authorization set (pre-authorized).
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(&daemon.socket).unwrap();
    let msg = serde_json::json!({"message": "confirm_and_sign", "payload": wire});
    let mut line = serde_json::to_string(&msg).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    assert!(reply.contains("\"error\""), "{reply}");
    assert!(reply.contains("user_authorization: null"), "{reply}");
}

#[tokio::test]
async fn confirm_and_sign_without_display_evidence_is_refused() {
    // A surface with nothing deterministic to show must not render.
    let daemon = spawn_daemon(Some("approve"), None);
    let req = base_request(dev0(), Verdict::Allow);
    use cipherlayer_vault::WireSigningRequest;
    let mut wire = WireSigningRequest::from_request(&req, Uuid::new_v4(), Uuid::new_v4());
    wire.user_authorization = None; // correct
    wire.ext.display = None; // missing evidence
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(&daemon.socket).unwrap();
    let msg = serde_json::json!({"message": "confirm_and_sign", "payload": wire});
    let mut line = serde_json::to_string(&msg).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    assert!(reply.contains("\"error\""), "{reply}");
    assert!(reply.contains("display"), "{reply}");
}
