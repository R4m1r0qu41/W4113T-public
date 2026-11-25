//! Security regression tests for the vault process boundary (ADR-004 W2).
//!
//! Every test spawns the REAL daemon binary and talks to it over the REAL
//! Unix socket with the pinned wire format — no in-process shortcuts. The
//! invariants proven in-process by the vault crate's own tests are re-proven
//! here across the process boundary: what the Vault refuses in-process it
//! must refuse identically over IPC.

use cipherlayer_policy::Verdict;
use cipherlayer_types::{Address, ChainId, NetworkClass, U256};
use cipherlayer_vault::ipc::{VaultClient, VaultIpcError, WireSignState};
use cipherlayer_vault::{
    Capability, ConfirmationSurface, TxParams, UserAuthorization, VaultSigningRequest,
    ANVIL_DEV_KEYS,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::Duration;
use uuid::Uuid;

/// Anvil dev account #0 — the address ANVIL_DEV_KEYS[0] derives to.
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

fn spawn_daemon() -> DaemonGuard {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("vault.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_cipherlayer-vaultd"))
        .arg(&socket)
        .env_remove("CIPHERLAYER_TEST_SIGNER_KEY")
        .spawn()
        .unwrap();
    // The guard kills + reaps the child on every path, including the
    // bind-timeout panic below.
    let guard = DaemonGuard {
        child,
        socket,
        _dir: dir,
    };
    // Wait for the socket to appear (the daemon binds before serving).
    for _ in 0..100 {
        if guard.socket.exists() {
            return guard;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not bind its socket in time");
}

fn dev0_address() -> Address {
    DEV0.parse().unwrap()
}

fn base_request(account: Address) -> VaultSigningRequest {
    VaultSigningRequest {
        signing_request_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        account,
        chain_id: ChainId(31337),
        network_class: NetworkClass::Development,
        capability: Capability::signing("cli:test", account, ChainId(31337), 60),
        policy_verdict: Verdict::Allow,
        user_authorization: UserAuthorization {
            decided_at: chrono::Utc::now(),
            surface: ConfirmationSurface::CliPrompt,
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

async fn client(guard: &DaemonGuard) -> VaultClient {
    VaultClient::connect_checked(&guard.socket).unwrap()
}

#[tokio::test]
async fn signs_a_valid_request_over_the_boundary() {
    let daemon = spawn_daemon();
    let c = client(&daemon).await;
    let (address, locked) = c.status().await.unwrap();
    assert_eq!(address, dev0_address());
    assert!(!locked);

    let req = base_request(address);
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Signed);
    assert_eq!(resp.signing_request_id, req.signing_request_id);
    let raw = resp.raw_tx_hex.unwrap();
    assert!(raw.starts_with("0x") && raw.len() > 2);
    assert!(resp.tx_hash.unwrap().starts_with("0x"));
    // The signed artifact is not the key: no dev key appears anywhere.
    for k in ANVIL_DEV_KEYS {
        assert!(!raw.to_lowercase().contains(&k[2..]));
    }
}

#[tokio::test]
async fn locked_daemon_refuses_and_unlock_restores() {
    let daemon = spawn_daemon();
    let c = client(&daemon).await;
    assert!(c.set_locked(true).await.unwrap());
    let req = base_request(dev0_address());
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert_eq!(resp.refusal.unwrap().code, "VLT-LCK-001");
    assert!(resp.raw_tx_hex.is_none());

    assert!(!c.set_locked(false).await.unwrap());
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Signed);
}

#[tokio::test]
async fn deny_verdict_refused_over_the_boundary() {
    let daemon = spawn_daemon();
    let c = client(&daemon).await;
    let mut req = base_request(dev0_address());
    req.policy_verdict = Verdict::Deny;
    req.user_authorization.escalation_acknowledged = true; // still final
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert_eq!(resp.refusal.unwrap().code, "VLT-POL-001");
}

#[tokio::test]
async fn unacknowledged_escalation_refused_over_the_boundary() {
    let daemon = spawn_daemon();
    let c = client(&daemon).await;
    let mut req = base_request(dev0_address());
    req.policy_verdict = Verdict::Escalate;
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert_eq!(resp.refusal.unwrap().code, "VLT-POL-002");
}

#[tokio::test]
async fn non_development_chain_refused_over_the_boundary() {
    let daemon = spawn_daemon();
    let c = client(&daemon).await;
    let mut req = base_request(dev0_address());
    req.chain_id = ChainId(1);
    req.network_class = NetworkClass::Mainnet;
    req.capability = Capability::signing("cli:test", dev0_address(), ChainId(1), 60);
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert_eq!(resp.refusal.unwrap().code, "VLT-CHN-001");
}

#[tokio::test]
async fn expired_capability_refused_over_the_boundary() {
    let daemon = spawn_daemon();
    let c = client(&daemon).await;
    let mut req = base_request(dev0_address());
    req.capability.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert_eq!(resp.refusal.unwrap().code, "VLT-CAP-001");
}

#[tokio::test]
async fn account_mismatch_refused_over_the_boundary() {
    let daemon = spawn_daemon();
    let c = client(&daemon).await;
    let other = Address::from_slice(&[7u8; 20]);
    let mut req = base_request(other);
    req.capability = Capability::signing("cli:test", other, ChainId(31337), 60);
    let resp = c
        .authorize_and_sign(&req, Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(resp.state, WireSignState::Refused);
    assert_eq!(resp.refusal.unwrap().code, "VLT-ACC-001");
}

#[tokio::test]
async fn unknown_message_and_malformed_json_are_coded_errors() {
    let daemon = spawn_daemon();
    // Raw socket talk: bypass the client to prove the daemon itself rejects.
    let mut stream = UnixStream::connect(&daemon.socket).unwrap();
    stream
        .write_all(b"{\"message\":\"export_keys\"}\nnot json at all\n")
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(
        line.contains("\"error\""),
        "unknown message must error: {line}"
    );
    assert!(line.contains("malformed_or_unsupported"));
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("malformed_or_unsupported"), "{line}");
}

#[tokio::test]
async fn client_refuses_group_or_world_accessible_socket() {
    let daemon = spawn_daemon();
    // Sabotage: loosen the socket permissions, client must refuse.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&daemon.socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    let err = VaultClient::connect_checked(&daemon.socket).unwrap_err();
    assert!(matches!(err, VaultIpcError::InsecureSocket(..)));
}

#[tokio::test]
async fn daemon_refuses_to_start_with_a_non_dev_key() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("vault.sock");
    let out = Command::new(env!("CARGO_BIN_EXE_cipherlayer-vaultd"))
        .arg(&socket)
        .env(
            "CIPHERLAYER_TEST_SIGNER_KEY",
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!socket.exists(), "no socket may exist for a refused key");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing"), "stderr: {stderr}");
}
