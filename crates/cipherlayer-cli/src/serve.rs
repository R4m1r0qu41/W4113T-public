//! Browser-connect transport (protocol v0.3): a local Unix-domain-socket
//! JSON-lines server exposing the browser-connect message set to a
//! same-user broker process.
//!
//! Peer authentication: the socket lives in a 0700 directory, so only the
//! same OS user can connect (the transport is never reachable by web content
//! or other users). v0.3 adds **host attestation** (ADR-013): a connection
//! must present the launch token (`host_attest`) before it may assert any
//! capsule identity, so a peer that is not the launched host cannot forge a
//! capsule id to ride another's grant (C-1). Honest residual: a same-user
//! attacker who can read the token is local malware (T-14, accepted).
//!
//! **Concurrency (ADR-B002 finding 2, closed):** each accepted connection is
//! served on its own task, so one capsule holding a long-lived session (or
//! stuck in a slow signing request) can no longer prevent another capsule
//! from even opening a connection — the pre-concurrency transport's actual limitation
//! (it did not `accept()` again until the previous connection closed). The
//! shared pipeline state (permissions store, audit log, the single vault/
//! nonce space) is still correctly serialized behind one async mutex —
//! required for correctness, not an oversight — while the read-only chain
//! registry is shared lock-free so a capability query never waits on an
//! unrelated capsule's signing request.
//!
//! The server carries zero authority of its own: every request runs through
//! the same validate → permission → decode → simulate → risk → policy →
//! review → vault pipeline as the CLI, and USER_REVIEW stays on this
//! process's terminal unless the operator passed the explicit, logged
//! auto-approval flag (tests/harness only).

use crate::pipeline::{Pipeline, PipelineError, ReviewMode};
use cipherlayer_chain::adapter::ChainObserver;
use cipherlayer_chain::ChainRegistry;
use cipherlayer_evm::adapter::EvmAdapter;
use cipherlayer_provider::{parse_envelope, WalletCapability};
use cipherlayer_types::{AccessClass, CallerIdentity, CallerKind, ChainId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex as AsyncMutex;

pub const PROTOCOL_VERSION: &str = "0.4";

/// v0.4 read-only RPC proxy (`rpc_query`): a STRICT hardcoded whitelist.
/// Every method here is a pure chain-state read with no signing consequence
/// — it cannot move funds, change permissions, or produce a signature (see
/// ADR-019 and the browser repo's dapp-compat-matrix.md §2, which is exactly
/// this list). Anything else is refused with the transport's existing
/// unsupported-method error, never forwarded — this list is not
/// caller-extensible.
pub const RPC_QUERY_WHITELIST: &[&str] = &[
    "eth_call",
    "eth_estimateGas",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_gasPrice",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "net_version",
];

/// Bound on the serialized `params` array (T-22 discipline applied to reads
/// too — a request is capped well before it, but this is a tighter,
/// read-path-specific bound since legitimate `params` for these methods are
/// always small: an address, a call object, a tx hash).
pub const MAX_RPC_PARAMS_BYTES: usize = 16 * 1024;
/// Bound on the serialized RPC result. `eth_call` can return arbitrary
/// contract output; this caps worst-case memory/wire cost without touching
/// the RPC manager's own timeout/retry behavior.
pub const MAX_RPC_RESULT_BYTES: usize = 256 * 1024;

/// Wire messages the transport accepts (deny-by-default: anything else is a
/// protocol error, mirroring the wallet's unknown-method invariant).
#[derive(Debug, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)] // variant names are the wire message names
enum Request {
    CapabilityQuery,
    /// v0.3: the connecting peer proves it is the trusted browser host by
    /// presenting the launch-time attestation token. Only an attested
    /// connection may assert capsule identity (closes C-1 / T-19 forgery for
    /// any peer that is not the launched host).
    HostAttest {
        token: String,
    },
    ConnectRequest {
        origin: String,
        capsule_id: String,
        chain_id: u64,
        access: AccessClass,
        accounts: Vec<String>,
        ttl_hours: i64,
    },
    TransactionRequest {
        envelope: serde_json::Value,
    },
    PermissionRevoke {
        permission_id: uuid::Uuid,
    },
    /// v0.4: read-only JSON-RPC proxy. Whitelist-only (`RPC_QUERY_WHITELIST`);
    /// requires an active permission grant (read-only class suffices) for
    /// this capsule on `chain_id`. Capsule-bearing (asserts `origin`/
    /// `capsule_id`), so it requires host attestation like `connect_request`/
    /// `transaction_request`.
    RpcQuery {
        origin: String,
        capsule_id: String,
        chain_id: u64,
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    },
}

/// Per-connection state. `attested` gates every capsule-bearing operation.
#[derive(Default)]
struct ConnState {
    attested: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "message", rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)] // variant names are the wire message names
enum Response {
    Capability {
        protocol_version: String,
        payload: WalletCapability,
    },
    ConnectResponse {
        payload: cipherlayer_provider::Permission,
    },
    SigningResponse {
        payload: cipherlayer_provider::SigningResponse,
    },
    RevokeResponse {
        permission_id: uuid::Uuid,
        revoked: bool,
    },
    RpcQueryResponse {
        result: serde_json::Value,
    },
    AttestResponse {
        attested: bool,
        protocol_version: String,
    },
    Error {
        code: String,
        detail: String,
    },
}

fn err(code: &str, detail: impl ToString) -> Response {
    Response::Error {
        code: code.into(),
        detail: detail.to_string(),
    }
}

/// Length-checked, difference-OR comparison so a wrong token cannot be
/// narrowed by response timing. Not a substitute for a real MAC — the token
/// is a launch secret, not a network-exposed credential.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Resolve the v0.3 host-attestation token. Preference order:
///  1. `CIPHERLAYER_CONNECT_HOST_TOKEN` (env; never written to disk — the
///     preferred channel for the wallet to hand the token to the host it
///     launches);
///  2. `<socket-dir>/connect-host-token` (0600 file; generated if absent so a
///     standalone `connect serve` is usable, and readable only by the user).
///
/// Honest bound: the token distinguishes the launched host from any other
/// peer, but a same-user attacker who can read the env/file defeats it — that
/// is local malware (threat T-14), accepted for the prototype. The gain over
/// v0.2 is that a peer which is *not* the host (web content, a
/// reduced-privilege helper) can no longer forge a capsule id.
pub fn resolve_host_token(socket_path: &Path) -> std::io::Result<String> {
    if let Ok(t) = std::env::var("CIPHERLAYER_CONNECT_HOST_TOKEN") {
        if !t.trim().is_empty() {
            return Ok(t);
        }
    }
    let token_path = socket_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("connect-host-token");
    if let Ok(existing) = std::fs::read_to_string(&token_path) {
        if !existing.trim().is_empty() {
            return Ok(existing.trim().to_string());
        }
    }
    // Generate: two v4 UUIDs = ~244 bits of randomness, hex-only.
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::write(&token_path, &token)?;
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(token)
}

/// Disk is the source of truth for permissions across processes: a CLI
/// `permissions revoke` in another process must take effect here without a
/// daemon restart — and, worse, a stale in-memory copy would re-persist
/// (resurrect) the revoked grant on this process's next save. Reload before
/// every permission-consuming or -mutating step. Residual: a same-user writer
/// racing the load→save window (microseconds) — T-14 local-malware class,
/// accepted like the rest of the same-user surface.
fn reload_permissions(
    pl: &mut Pipeline,
    path: &Path,
) -> Result<(), cipherlayer_provider::PermissionStoreError> {
    pl.permissions = cipherlayer_provider::PermissionStore::load_from(path)?;
    Ok(())
}

fn dapp_caller(origin: &str, capsule_id: &str) -> CallerIdentity {
    CallerIdentity {
        kind: CallerKind::Dapp,
        origin: Some(origin.to_string()),
        app_id: None,
        capsule_id: Some(capsule_id.to_string()),
    }
}

/// Cheap to clone: every field is either `Copy`, small, or an `Arc`. `run`
/// clones one per accepted connection so each can be served on its own task.
#[derive(Clone)]
pub struct ConnectServer {
    pipeline: Arc<AsyncMutex<Pipeline>>,
    /// Read-only and immutable after construction (`ChainRegistry::builtin()`
    /// never changes at runtime), so it is shared without a lock — a
    /// capability query or chain lookup never waits on another capsule's
    /// in-flight signing request, which the mutex-guarded pipeline alone
    /// would not give us.
    registry: Arc<ChainRegistry>,
    review: ReviewMode,
    permissions_path: PathBuf,
    /// v0.3 host-attestation token. A connection must present this before it
    /// may assert capsule identity. See `resolve_host_token`.
    host_token: String,
}

impl ConnectServer {
    pub fn new(
        pipeline: Pipeline,
        review: ReviewMode,
        permissions_path: PathBuf,
        host_token: String,
    ) -> Self {
        let registry = Arc::new(pipeline.registry.clone());
        Self {
            pipeline: Arc::new(AsyncMutex::new(pipeline)),
            registry,
            review,
            permissions_path,
            host_token,
        }
    }

    async fn handle(&self, line: &str, conn: &mut ConnState) -> Response {
        // Envelope size cap applies to the whole line before any parsing.
        if line.len() > cipherlayer_provider::MAX_ENVELOPE_BYTES {
            return err("size_cap_exceeded", "request exceeds envelope size cap");
        }
        let request: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return err("malformed_or_unsupported", e),
        };
        // Capsule-bearing operations require an attested host connection
        // (v0.3). capability_query and host_attest are the only messages a
        // fresh connection may send.
        let needs_attestation = matches!(
            request,
            Request::ConnectRequest { .. }
                | Request::TransactionRequest { .. }
                | Request::PermissionRevoke { .. }
                | Request::RpcQuery { .. }
        );
        if needs_attestation && !conn.attested {
            return err(
                "attestation_required",
                "present host_attest with the launch token before asserting capsule identity (protocol v0.3)",
            );
        }
        match request {
            // Lock-free: never waits on another capsule's in-flight request.
            Request::CapabilityQuery => Response::Capability {
                protocol_version: PROTOCOL_VERSION.into(),
                payload: WalletCapability::current(&self.registry),
            },
            Request::HostAttest { token } => {
                // Constant-time-ish compare: equal length + byte diff-OR, so a
                // wrong token cannot be probed by timing the length.
                let ok = constant_time_eq(token.as_bytes(), self.host_token.as_bytes());
                if ok {
                    conn.attested = true;
                }
                Response::AttestResponse {
                    attested: ok,
                    protocol_version: PROTOCOL_VERSION.into(),
                }
            }
            Request::ConnectRequest {
                origin,
                capsule_id,
                chain_id,
                access,
                accounts,
                ttl_hours,
            } => {
                if origin.is_empty() || capsule_id.is_empty() {
                    return err(
                        "identity_required",
                        "origin and capsule_id must be non-empty",
                    );
                }
                if !(1..=24 * 30).contains(&ttl_hours) {
                    return err("invalid_ttl", "ttl_hours must be within 1..=720");
                }
                if self.registry.get(ChainId(chain_id)).is_err() {
                    return err("unknown_chain", format!("chain id {chain_id}"));
                }
                let mut parsed = Vec::with_capacity(accounts.len());
                for a in &accounts {
                    match cipherlayer_evm::parse_address(a) {
                        Ok(addr) => parsed.push(addr),
                        Err(e) => return err("invalid_account", e),
                    }
                }
                if parsed.is_empty() {
                    return err("invalid_account", "at least one account is required");
                }
                let caller = dapp_caller(&origin, &capsule_id);
                // Permission grant/lookup + its persistence and audit record
                // are one atomic step from other capsules' point of view.
                let mut pl = self.pipeline.lock().await;
                if let Err(e) = reload_permissions(&mut pl, &self.permissions_path) {
                    return err("store_error", e);
                }
                let grant = match pl.permissions.find_active(
                    &caller,
                    ChainId(chain_id),
                    access,
                    parsed[0],
                ) {
                    // Idempotent reconnect: reuse the covering active grant.
                    Some(existing) if parsed.iter().all(|a| existing.accounts.contains(a)) => {
                        existing.clone()
                    }
                    _ => {
                        let g = pl.permissions.grant(
                            &caller,
                            ChainId(chain_id),
                            access,
                            parsed,
                            chrono::Duration::hours(ttl_hours),
                        );
                        if let Err(e) = pl.permissions.save_to(&self.permissions_path) {
                            return err("store_error", e);
                        }
                        let _ = pl.audit.append(
                            cipherlayer_audit::EventKind::PermissionGranted,
                            None,
                            json!({"permission_id": g.permission_id, "caller_key": g.caller_key,
                                   "transport": "unix-socket", "protocol_version": PROTOCOL_VERSION}),
                        );
                        g
                    }
                };
                Response::ConnectResponse { payload: grant }
            }
            Request::TransactionRequest { envelope } => {
                let raw = envelope.to_string();
                let env = match parse_envelope(&raw) {
                    Ok(e) => e,
                    Err(e) => return err("invalid_envelope", e),
                };
                // Held for the whole pipeline run (validate through vault
                // sign/broadcast, including USER_REVIEW): nonce assignment,
                // vault lock state, and audit ordering are correctness
                // requirements with a single account/nonce space, not just a
                // convenience lock — two capsules cannot safely prepare
                // transactions for the same account concurrently. Another
                // capsule's capability_query is unaffected (lock-free above);
                // another capsule's own connect/transaction/revoke will wait,
                // same as one human operator can only review one request at
                // a time regardless of how many sockets are open.
                let mut pl = self.pipeline.lock().await;
                if let Err(e) = reload_permissions(&mut pl, &self.permissions_path) {
                    return err("store_error", e);
                }
                match pl.process(env, self.review).await {
                    Ok(outcome) => match pl.to_signing_response(&outcome) {
                        Ok(payload) => Response::SigningResponse { payload },
                        Err(e) => err("internal", e),
                    },
                    Err(PipelineError::Rpc(e)) => err("rpc_unavailable", e),
                    Err(e) => err("internal", e),
                }
            }
            Request::PermissionRevoke { permission_id } => {
                let mut pl = self.pipeline.lock().await;
                if let Err(e) = reload_permissions(&mut pl, &self.permissions_path) {
                    return err("store_error", e);
                }
                let revoked = pl.permissions.revoke(permission_id);
                if revoked {
                    if let Err(e) = pl.permissions.save_to(&self.permissions_path) {
                        return err("store_error", e);
                    }
                    let _ = pl.audit.append(
                        cipherlayer_audit::EventKind::PermissionRevoked,
                        None,
                        json!({"permission_id": permission_id, "transport": "unix-socket"}),
                    );
                }
                Response::RevokeResponse {
                    permission_id,
                    revoked,
                }
            }
            Request::RpcQuery {
                origin,
                capsule_id,
                chain_id,
                method,
                params,
            } => {
                self.handle_rpc_query(&origin, &capsule_id, chain_id, &method, params)
                    .await
            }
        }
    }

    /// v0.4 read-only RPC proxy. Whitelist-only, size-bounded both ways,
    /// requires an active permission grant (read-only class suffices), and
    /// executes only against `self.rpc_url` — never a caller-supplied
    /// endpoint — whose chain identity is verified against the requested
    /// `chain_id` before anything is served (T-09 applied to reads: data is
    /// never returned under a chain label the endpoint didn't prove).
    ///
    /// **No per-query audit event.** These are read-only chain-state lookups
    /// with no signing consequence (never a signature, never a fund
    /// movement, never a permission change) — a dapp/wagmi client can poll
    /// `eth_blockNumber`/`eth_call` many times a second, and logging every
    /// one would flood the hash-chained audit log with routine traffic that
    /// has no forensic value (nothing to investigate: the whitelist already
    /// bounds what could have happened). The audit log's job is decision
    /// provenance for consequence-bearing events (grants, signatures,
    /// denials); connection-level enforcement (attestation, permission,
    /// whitelist, size caps) is still applied on every call even though it
    /// is not separately logged per-call.
    async fn handle_rpc_query(
        &self,
        origin: &str,
        capsule_id: &str,
        chain_id: u64,
        method: &str,
        params: serde_json::Value,
    ) -> Response {
        if !RPC_QUERY_WHITELIST.contains(&method) {
            return err(
                "malformed_or_unsupported",
                format!("rpc_query method {method:?} is not on the whitelist"),
            );
        }
        if origin.is_empty() || capsule_id.is_empty() {
            return err(
                "identity_required",
                "origin and capsule_id must be non-empty",
            );
        }
        let params_len = serde_json::to_string(&params).map(|s| s.len()).unwrap_or(0);
        if params_len > MAX_RPC_PARAMS_BYTES {
            return err("size_cap_exceeded", "rpc_query params exceed the size cap");
        }
        if self.registry.get(ChainId(chain_id)).is_err() {
            return err("unknown_chain", format!("chain id {chain_id}"));
        }
        let caller = dapp_caller(origin, capsule_id);
        let rpc_url = {
            let mut pl = self.pipeline.lock().await;
            if let Err(e) = reload_permissions(&mut pl, &self.permissions_path) {
                return err("store_error", e);
            }
            if !pl.permissions.has_any_active(&caller, ChainId(chain_id)) {
                return err(
                    "permission_required",
                    "no active grant for this capsule on the requested chain",
                );
            }
            pl.rpc_url.clone()
        };
        let adapter = EvmAdapter::new(&rpc_url);
        // T-09 discipline applied to reads (2026-07-17 verification finding):
        // the proxy has one configured endpoint, so without this check a
        // query for chain 1 would return dev-node data labeled as mainnet.
        // Verify the endpoint actually is the requested chain before serving
        // anything — one eth_chainId roundtrip per query, honest cost. A
        // definite mismatch is `chain_mismatch`; an unreachable endpoint
        // stays `rpc_unavailable` (nothing was mislabeled, nothing served).
        if let Err(e) = adapter.verify_chain_identity(ChainId(chain_id)).await {
            return match e {
                cipherlayer_chain::adapter::AdapterError::ChainIdentityMismatch { .. } => err(
                    "chain_mismatch",
                    format!("rpc endpoint does not serve chain {chain_id}: {e}"),
                ),
                other => err("rpc_unavailable", other),
            };
        }
        let params_for_call = if params.is_null() {
            serde_json::Value::Array(vec![])
        } else {
            params
        };
        match adapter.raw_rpc_call(method, params_for_call).await {
            Ok(result) => {
                let result_len = serde_json::to_string(&result).map(|s| s.len()).unwrap_or(0);
                if result_len > MAX_RPC_RESULT_BYTES {
                    return err("size_cap_exceeded", "rpc_query result exceeds the size cap");
                }
                Response::RpcQueryResponse { result }
            }
            Err(e) => err("rpc_unavailable", e),
        }
    }

    async fn serve_connection(&self, stream: UnixStream) -> std::io::Result<()> {
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();
        // Attestation is per-connection: a fresh connection starts un-attested
        // and must present the host token before any capsule operation.
        let mut conn = ConnState::default();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = self.handle(&line, &mut conn).await;
            let mut out = serde_json::to_string(&response).expect("responses serialize");
            out.push('\n');
            write_half.write_all(out.as_bytes()).await?;
        }
        Ok(())
    }

    /// Bind the socket (0700 parent dir = same-user peer auth) and serve
    /// connections concurrently — one task per accepted connection — until
    /// the process is terminated.
    pub async fn run(&self, socket_path: &Path) -> std::io::Result<()> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }
        let listener = UnixListener::bind(socket_path)?;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        let token_hint = if std::env::var("CIPHERLAYER_CONNECT_HOST_TOKEN").is_ok() {
            "host token: from CIPHERLAYER_CONNECT_HOST_TOKEN".to_string()
        } else {
            format!(
                "host token: {}/connect-host-token (0600)",
                socket_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .display()
            )
        };
        eprintln!(
            "browser-connect transport listening on {} (protocol {PROTOCOL_VERSION}, review mode {:?}); {token_hint} — the host must host_attest before asserting capsule identity",
            socket_path.display(),
            self.review
        );
        loop {
            let (stream, _addr) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.serve_connection(stream).await {
                    eprintln!("connection error: {e}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherlayer_policy::Policy;
    use cipherlayer_vault::{TestSigner, Vault, ANVIL_DEV_KEYS};

    const TOKEN: &str = "test-token-for-serve-unit-tests";

    fn server() -> (ConnectServer, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let audit = cipherlayer_audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).unwrap();
        // Deliberately unreachable RPC: every test below is refused before
        // any RPC call is ever attempted (whitelist / size cap / attestation
        // / permission gates all fire first) — no Anvil required.
        let pipeline = Pipeline::new(
            Policy::default_dev(),
            audit,
            Vault::new(signer),
            "http://127.0.0.1:1",
        );
        let s = ConnectServer::new(
            pipeline,
            ReviewMode::AssumeYes,
            dir.path().join("permissions.json"),
            TOKEN.to_string(),
        );
        (s, dir)
    }

    async fn attested_conn(server: &ConnectServer) -> ConnState {
        let mut conn = ConnState::default();
        let resp = server
            .handle(
                &serde_json::json!({"message": "host_attest", "token": TOKEN}).to_string(),
                &mut conn,
            )
            .await;
        assert!(matches!(
            resp,
            Response::AttestResponse { attested: true, .. }
        ));
        assert!(conn.attested);
        conn
    }

    /// The whitelist is exactly the eight methods the compat matrix and
    /// ADR-019 name — no more, no less.
    #[test]
    fn whitelist_is_exactly_the_eight_read_only_methods() {
        assert_eq!(
            RPC_QUERY_WHITELIST,
            &[
                "eth_call",
                "eth_estimateGas",
                "eth_blockNumber",
                "eth_getBalance",
                "eth_gasPrice",
                "eth_getTransactionByHash",
                "eth_getTransactionReceipt",
                "net_version",
            ]
        );
        // Never any signing/write/wallet-management method, regardless of
        // future edits to the list above.
        for forbidden in [
            "eth_sendTransaction",
            "eth_sendRawTransaction",
            "eth_sign",
            "eth_signTypedData_v4",
            "personal_sign",
            "eth_exportPrivateKey",
            "wallet_switchEthereumChain",
            "wallet_addEthereumChain",
        ] {
            assert!(!RPC_QUERY_WHITELIST.contains(&forbidden));
        }
    }

    /// An un-attested connection cannot submit `rpc_query` — it is
    /// capsule-bearing (carries origin/capsule_id) exactly like
    /// connect_request/transaction_request.
    #[tokio::test]
    async fn rpc_query_requires_attestation() {
        let (server, _dir) = server();
        let mut conn = ConnState::default();
        let resp = server
            .handle(
                &serde_json::json!({
                    "message": "rpc_query", "origin": "https://dapp.example",
                    "capsule_id": "c1", "chain_id": 31337, "method": "eth_blockNumber",
                    "params": []
                })
                .to_string(),
                &mut conn,
            )
            .await;
        assert!(matches!(resp, Response::Error { code, .. } if code == "attestation_required"));
    }

    /// A method off the whitelist is refused outright — never forwarded to
    /// the RPC manager (the unreachable rpc_url in `server()` proves this:
    /// if it were forwarded, the test would fail on a connection error
    /// instead of the expected coded refusal).
    #[tokio::test]
    async fn off_whitelist_method_is_refused_not_forwarded() {
        let (server, _dir) = server();
        let mut conn = attested_conn(&server).await;
        for method in [
            "eth_sendRawTransaction",
            "eth_sign",
            "wallet_switchEthereumChain",
        ] {
            let resp = server
                .handle(
                    &serde_json::json!({
                        "message": "rpc_query", "origin": "https://dapp.example",
                        "capsule_id": "c1", "chain_id": 31337, "method": method, "params": []
                    })
                    .to_string(),
                    &mut conn,
                )
                .await;
            assert!(
                matches!(&resp, Response::Error { code, .. } if code == "malformed_or_unsupported"),
                "method {method} must be refused, got {resp:?}"
            );
        }
    }

    /// An oversized `params` array is refused before ever reaching the
    /// permission check or the RPC manager.
    #[tokio::test]
    async fn oversized_params_refused() {
        let (server, _dir) = server();
        let mut conn = attested_conn(&server).await;
        let huge = "x".repeat(MAX_RPC_PARAMS_BYTES + 1);
        let resp = server
            .handle(
                &serde_json::json!({
                    "message": "rpc_query", "origin": "https://dapp.example",
                    "capsule_id": "c1", "chain_id": 31337, "method": "eth_call",
                    "params": [huge]
                })
                .to_string(),
                &mut conn,
            )
            .await;
        assert!(matches!(resp, Response::Error { code, .. } if code == "size_cap_exceeded"));
    }

    /// A whitelisted method on a known chain, but with no permission grant
    /// for this capsule, is refused before any RPC call is attempted.
    #[tokio::test]
    async fn rpc_query_without_a_grant_is_refused() {
        let (server, _dir) = server();
        let mut conn = attested_conn(&server).await;
        let resp = server
            .handle(
                &serde_json::json!({
                    "message": "rpc_query", "origin": "https://dapp.example",
                    "capsule_id": "c1", "chain_id": 31337, "method": "eth_blockNumber",
                    "params": []
                })
                .to_string(),
                &mut conn,
            )
            .await;
        assert!(matches!(resp, Response::Error { code, .. } if code == "permission_required"));
    }

    /// A read-only grant suffices — a signing grant is not required for
    /// rpc_query. This still hits the (unreachable) RPC endpoint, so the
    /// assertion is on getting *past* the permission gate (an rpc_unavailable
    /// error, not permission_required), proving read-only class is accepted.
    #[tokio::test]
    async fn read_only_grant_suffices_for_rpc_query() {
        let (server, dir) = server();
        let mut conn = attested_conn(&server).await;
        {
            let mut pl = server.pipeline.lock().await;
            let caller = dapp_caller("https://dapp.example", "c1");
            pl.permissions.grant(
                &caller,
                ChainId(31337),
                AccessClass::ReadOnly,
                vec![cipherlayer_types::Address::from_slice(&[0xaa; 20])],
                chrono::Duration::hours(1),
            );
            pl.permissions
                .save_to(&dir.path().join("permissions.json"))
                .unwrap();
        }
        let resp = server
            .handle(
                &serde_json::json!({
                    "message": "rpc_query", "origin": "https://dapp.example",
                    "capsule_id": "c1", "chain_id": 31337, "method": "eth_blockNumber",
                    "params": []
                })
                .to_string(),
                &mut conn,
            )
            .await;
        // Past the permission gate: refused only because the RPC endpoint is
        // unreachable, never because of the (satisfied) permission check.
        assert!(matches!(resp, Response::Error { code, .. } if code == "rpc_unavailable"));
    }

    /// v0.4 capability advertisement lists rpc_query and protocol 0.4, while
    /// keeping 0.1/0.3 for backward compatibility (browser-wallet-protocol.md
    /// design rule 6: additive changes bump minor, old versions keep working).
    #[tokio::test]
    async fn capability_query_advertises_v04_and_rpc_query() {
        let (server, _dir) = server();
        let mut conn = ConnState::default();
        let resp = server
            .handle(
                &serde_json::json!({"message": "capability_query"}).to_string(),
                &mut conn,
            )
            .await;
        let Response::Capability {
            protocol_version,
            payload,
        } = resp
        else {
            panic!("expected a capability response, got {resp:?}");
        };
        assert_eq!(protocol_version, "0.4");
        assert!(payload.protocol_versions.contains(&"0.3".to_string()));
        assert!(payload.methods.contains(&"rpc_query".to_string()));
    }
}
