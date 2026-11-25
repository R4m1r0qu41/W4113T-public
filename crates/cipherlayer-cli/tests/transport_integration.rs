//! Protocol v0.3 transport integration test (gate criterion 3, transport
//! half): spawns the real `connect serve` binary and speaks JSON-lines over
//! the Unix socket exactly as a browser broker would — separate process,
//! separate address space, wire contract only.
//!
//! Requires Anvil: CIPHERLAYER_INTEGRATION=1 (make test-integration).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn integration_enabled() -> bool {
    if std::env::var("CIPHERLAYER_INTEGRATION").as_deref() == Ok("1") {
        true
    } else {
        eprintln!("SKIPPED: set CIPHERLAYER_INTEGRATION=1 (make test-integration) to run");
        false
    }
}

struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const HOST_TOKEN: &str = "test-host-token-0123456789abcdef";

fn spawn_server(dir: &std::path::Path) -> (Server, std::path::PathBuf) {
    let socket = dir.join("sock/browser-connect.sock");
    // The Server Drop guard kills + waits; the panic path below leaks the
    // child intentionally only if the guard was never constructed.
    #[allow(clippy::zombie_processes)]
    let child = Command::new(env!("CARGO_BIN_EXE_cipherlayer-cli"))
        .args(["connect", "serve", "--yes"])
        .arg("--socket")
        .arg(&socket)
        .env("CIPHERLAYER_PERMISSIONS_FILE", dir.join("permissions.json"))
        .env("CIPHERLAYER_AUDIT_LOG", dir.join("audit.jsonl"))
        .env("CIPHERLAYER_CONNECT_HOST_TOKEN", HOST_TOKEN)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve spawns");
    let server = Server { child };
    for _ in 0..100 {
        if socket.exists() {
            return (server, socket);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("socket never appeared at {}", socket.display());
}

fn round_trip(stream: &mut BufReader<UnixStream>, req: serde_json::Value) -> serde_json::Value {
    let mut line = req.to_string();
    line.push('\n');
    stream.get_mut().write_all(line.as_bytes()).unwrap();
    let mut reply = String::new();
    stream.read_line(&mut reply).unwrap();
    serde_json::from_str(&reply).expect("wallet replies with JSON")
}

/// One connection, whole contract: capability → connect → confirmed transfer
/// → denied unlimited approval → revoke → refusal. A real process boundary —
/// the closest thing to a browser the wallet has met so far.
#[test]
fn browser_connect_transport_end_to_end() {
    if !integration_enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (_server, socket) = spawn_server(dir.path());

    // Socket must not be group/world-accessible (v0.2 peer-auth model).
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "socket must be 0600");

    let mut stream = BufReader::new(UnixStream::connect(&socket).unwrap());
    let account = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    let cap = round_trip(
        &mut stream,
        serde_json::json!({"message": "capability_query"}),
    );
    assert_eq!(cap["message"], "capability");
    // v0.4: additive rev (typed_data/personal_message payload kinds,
    // rpc_query) — the transport's live protocol_version advances, while
    // "0.3" (and "0.1") stay listed in the capability advertisement's
    // protocol_versions[] and v0.3-shaped envelopes keep working unchanged
    // (see the forged-envelope case below, which still declares "0.3").
    assert_eq!(cap["protocol_version"], "0.4");

    // v0.3: capsule operations are refused until the connection attests.
    let premature = round_trip(
        &mut stream,
        serde_json::json!({
            "message": "connect_request", "origin": "https://transport-test.example",
            "capsule_id": "capsule-t1", "chain_id": 31337, "access": "signing",
            "accounts": [account], "ttl_hours": 1
        }),
    );
    assert_eq!(premature["message"], "error");
    assert_eq!(premature["code"], "attestation_required");

    // A wrong token does not attest.
    let bad = round_trip(
        &mut stream,
        serde_json::json!({"message": "host_attest", "token": "not-the-token"}),
    );
    assert_eq!(bad["message"], "attest_response");
    assert_eq!(bad["attested"], false);

    // The launch token attests the host connection.
    let good = round_trip(
        &mut stream,
        serde_json::json!({"message": "host_attest", "token": HOST_TOKEN}),
    );
    assert_eq!(good["attested"], true);

    let grant = round_trip(
        &mut stream,
        serde_json::json!({
            "message": "connect_request", "origin": "https://transport-test.example",
            "capsule_id": "capsule-t1", "chain_id": 31337, "access": "signing",
            "accounts": [account], "ttl_hours": 1
        }),
    );
    assert_eq!(grant["message"], "connect_response");
    let permission_id = grant["payload"]["permission_id"]
        .as_str()
        .unwrap()
        .to_string();

    let envelope = |data: &str, to: &str| {
        serde_json::json!({
            "message": "transaction_request",
            "envelope": {
                "schema_version": "1.0",
                "request_id": uuid::Uuid::new_v4(),
                "received_at": chrono::Utc::now(),
                "protocol_version": "0.2",
                "caller": {"kind": "dapp", "origin": "https://transport-test.example", "capsule_id": "capsule-t1"},
                "chain_id": 31337, "access": "signing",
                "payload": {"from": account, "to": to, "value_wei": "0", "data": data}
            }
        })
    };

    let ok = round_trip(
        &mut stream,
        envelope("0x", "0x00000000000000000000000000000000000000bb"),
    );
    assert_eq!(ok["message"], "signing_response");
    assert_eq!(ok["payload"]["state"], "CONFIRMED");
    assert!(ok["payload"]["tx_hash"].as_str().unwrap().starts_with("0x"));

    let unlimited = format!("0x095ea7b3{:0>64}{}", "07".repeat(20), "f".repeat(64));
    let denied = round_trip(
        &mut stream,
        envelope(&unlimited, "0x00000000000000000000000000000000000000cc"),
    );
    assert_eq!(denied["payload"]["state"], "POLICY_DENIED");
    assert!(denied["payload"]["signing_request_id"].is_null());

    // Revoke reply is flat: {message, permission_id, revoked}.
    let revoke = round_trip(
        &mut stream,
        serde_json::json!({"message": "permission_revoke", "permission_id": permission_id}),
    );
    assert_eq!(revoke["message"], "revoke_response");
    assert_eq!(revoke["revoked"], true);
    let again = round_trip(
        &mut stream,
        serde_json::json!({"message": "permission_revoke", "permission_id": permission_id}),
    );
    assert_eq!(again["revoked"], false, "second revoke is a no-op");

    let refused = round_trip(
        &mut stream,
        envelope("0x", "0x00000000000000000000000000000000000000bb"),
    );
    assert_eq!(refused["payload"]["state"], "REJECTED");

    // Deny-by-default on the transport itself.
    let unknown = round_trip(
        &mut stream,
        serde_json::json!({"message": "eth_exportPrivateKey"}),
    );
    assert_eq!(unknown["message"], "error");
}

/// ADR-B002 finding 2 (transport concurrency), closed: a second, independent
/// connection must be served — and get its response — while a first
/// connection is still open. Pre-fix, the server did not call `accept()`
/// again until the previous `serve_connection` call returned, i.e. until
/// that peer disconnected; a single capsule holding its session open (the
/// normal case — a dapp keeps its connection for the whole page lifetime)
/// meant no other capsule could even connect. The check: hold connection A
/// open (never drop it before B's round trip completes), do B's round trip
/// on a background thread, and require it to complete within a bounded
/// timeout — pre-fix this would hang until A closed (or the test's overall
/// timeout), not until B's own request completed.
#[test]
fn second_connection_is_served_while_first_stays_open() {
    if !integration_enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (_server, socket) = spawn_server(dir.path());
    let account = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    // Connection A: attest, connect, and then just... stay open (like a
    // dapp capsule holding its session for the page's lifetime). Deliberately
    // not dropped until after B's check completes.
    let mut conn_a = BufReader::new(UnixStream::connect(&socket).unwrap());
    let attested = round_trip(
        &mut conn_a,
        serde_json::json!({"message": "host_attest", "token": HOST_TOKEN}),
    );
    assert_eq!(attested["attested"], true);
    let grant = round_trip(
        &mut conn_a,
        serde_json::json!({
            "message": "connect_request", "origin": "https://capsule-a.example",
            "capsule_id": "capsule-a", "chain_id": 31337, "access": "signing",
            "accounts": [account], "ttl_hours": 1
        }),
    );
    assert_eq!(grant["message"], "connect_response");

    // Connection B: a wholly separate socket, opened while A is still open.
    // Its round trip runs on a background thread so the main thread can
    // bound how long it's willing to wait.
    let socket_b = socket.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut conn_b = BufReader::new(UnixStream::connect(&socket_b).unwrap());
        let cap = round_trip(
            &mut conn_b,
            serde_json::json!({"message": "capability_query"}),
        );
        let _ = tx.send(cap);
    });

    let cap = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("connection B must be served promptly while A stays open — the transport must handle concurrent connections (ADR-B002 finding 2)");
    assert_eq!(cap["message"], "capability");

    // A is still usable afterward — confirms this isn't just B "winning" a
    // race that starved A; both connections are genuinely concurrent.
    let still_a = round_trip(
        &mut conn_a,
        serde_json::json!({"message": "capability_query"}),
    );
    assert_eq!(still_a["message"], "capability");
}

/// C-1 (capsule_id integrity, ADR-B002 finding 1 / ADR-013): a second peer
/// that never presented the host token cannot forge the attested host's
/// capsule id to ride its grant. At v0.2 this succeeded; v0.3 refuses it.
#[test]
fn unattested_peer_cannot_forge_capsule_identity() {
    if !integration_enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (_server, socket) = spawn_server(dir.path());
    let account = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    // Host connection: attest, then establish a signing grant for capsule-A.
    let mut host = BufReader::new(UnixStream::connect(&socket).unwrap());
    let attested = round_trip(
        &mut host,
        serde_json::json!({"message": "host_attest", "token": HOST_TOKEN}),
    );
    assert_eq!(attested["attested"], true);
    let grant = round_trip(
        &mut host,
        serde_json::json!({
            "message": "connect_request", "origin": "https://victim-dapp.example",
            "capsule_id": "victim-capsule", "chain_id": 31337, "access": "signing",
            "accounts": [account], "ttl_hours": 1
        }),
    );
    assert_eq!(grant["message"], "connect_response");
    // The transport serves connections sequentially (ADR-B002 finding 2), so
    // close the host connection before the attacker opens one. The grant
    // persists (permissions.json), so the forge attempt is still meaningful.
    drop(host);

    // Attacker: a SEPARATE connection with no attestation, forging the
    // victim's exact origin + capsule_id in the envelope.
    let mut attacker = BufReader::new(UnixStream::connect(&socket).unwrap());
    let forged = round_trip(
        &mut attacker,
        serde_json::json!({
            "message": "transaction_request",
            "envelope": {
                "schema_version": "1.0",
                "request_id": uuid::Uuid::new_v4(),
                "received_at": chrono::Utc::now(),
                "protocol_version": "0.3",
                "caller": {"kind": "dapp", "origin": "https://victim-dapp.example", "capsule_id": "victim-capsule"},
                "chain_id": 31337, "access": "signing",
                "payload": {"from": account, "to": "0x00000000000000000000000000000000000000bb", "value_wei": "0", "data": "0x"}
            }
        }),
    );
    assert_eq!(forged["message"], "error");
    assert_eq!(
        forged["code"], "attestation_required",
        "an un-attested peer must not be able to submit a capsule-bearing envelope at all"
    );
}
