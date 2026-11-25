//! cipherlayer-vaultd — the Vault as its own OS process (ADR-004 W2).
//!
//! Deliberately minimal: no web rendering, no pipeline, no policy engine, no
//! chain RPC — just the `cipherlayer-vault` crate behind a narrow JSON-lines
//! IPC on a same-user Unix socket (0700 dir / 0600 socket, the same
//! OS-enforced peer-auth model as the browser-connect transport). Everything
//! the in-process Vault refuses, this process refuses identically: the wire
//! format is the pinned signing-request.v1 schema and the daemon re-validates
//! every precondition itself — a well-formed request is necessary, never
//! sufficient.
//!
//! MOCKED custody unchanged (ADR-005): only well-known Anvil dev keys are
//! accepted; a real key refuses to load. Key material never leaves the
//! process, never appears on the wire, and is never logged.
//!
//! This is a library target so the daemon can be exercised over its REAL
//! Unix-socket boundary from integration tests (external re-audit,
//! 2026-07-20: the lock/unlock approval lifecycle escaped unit tests that
//! called handlers in-process); the `cipherlayer-vaultd` binary is a thin
//! `main` around [`Daemon`].

use cipherlayer_vault::ipc::{
    sol_refusal_code, VaultRequest, VaultResponse, WireRefusal, WireSignState, WireSigningResponse,
    WireSolFacts, WireUserAuthorization,
};
use cipherlayer_vault::{
    ConfirmationSurface, SolExternalSignerConfig, SolExternalSigningCeremony, Vault,
};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

mod sol_ceremony;
mod surface;

/// Whole-line size cap, applied before any parsing (same discipline as the
/// browser-connect transport).
const MAX_LINE_BYTES: usize = 64 * 1024;

fn err(code: &str, detail: impl ToString) -> VaultResponse {
    VaultResponse::Error {
        code: code.into(),
        detail: detail.to_string(),
    }
}

pub struct Daemon {
    vault: Vault,
    /// ADR-021: at most one Solana ceremony (and so at most one pending
    /// approval) exists at a time; a request for a different cluster drops
    /// it (nothing to wipe — the engine never holds key material).
    sol_ceremony: Option<SolExternalSigningCeremony>,
}

impl Daemon {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            sol_ceremony: None,
        }
    }

    /// Test-only seam for IPC boundary regressions: install a ceremony with
    /// a live engine-side approval before exercising the real socket. The
    /// default/production library API does not contain this phase-1 bypass.
    #[cfg(any(test, feature = "test-seams"))]
    #[doc(hidden)]
    pub fn install_sol_ceremony(&mut self, ceremony: SolExternalSigningCeremony) {
        self.sol_ceremony = Some(ceremony);
    }

    async fn handle(&mut self, line: &str) -> VaultResponse {
        if line.len() > MAX_LINE_BYTES {
            return err("size_cap_exceeded", "request exceeds line size cap");
        }
        let request: VaultRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return err("malformed_or_unsupported", e),
        };
        match request {
            VaultRequest::Status => VaultResponse::Status {
                address: self.vault.address(),
                locked: self.vault.is_locked(),
                signer_kind: "test (MOCKED custody, Anvil dev key)".into(),
            },
            VaultRequest::Lock => {
                self.vault.lock();
                // Lock means STOP, not pause (external re-audit, 2026-07-20):
                // the pending Solana approval dies WITH the lock, not lazily
                // on the next Solana request — lock → unlock → sign must
                // never resurrect an approval.
                self.invalidate_sol_approval();
                VaultResponse::LockResponse { locked: true }
            }
            VaultRequest::Unlock => {
                self.vault.unlock();
                VaultResponse::LockResponse { locked: false }
            }
            VaultRequest::SignRequest { payload } => {
                let signing_request_id = payload.signing_request_id;
                let req = match payload.into_request() {
                    Ok(r) => r,
                    Err(e) => return err("invalid_signing_request", e),
                };
                let response = match self.vault.authorize_and_sign(&req).await {
                    Ok(outcome) => WireSigningResponse::from_outcome(signing_request_id, &outcome),
                    Err(e) => WireSigningResponse::refused(signing_request_id, &e),
                };
                VaultResponse::SignResponse {
                    payload: Box::new(response),
                }
            }
            VaultRequest::ConfirmAndSign { payload } => self.confirm_and_sign(*payload).await,
            VaultRequest::SolApproveFacts {
                cluster_chain_id,
                facts,
            } => self.sol_approve_facts(cluster_chain_id, facts),
            VaultRequest::SolSign {
                nonce,
                message_hex,
                final_fee_lamports,
            } => self.sol_sign(nonce, &message_hex, final_fee_lamports),
        }
    }

    /// Drop any pending Solana approval. Shared by the lock handler and the
    /// lock gate below so "approval invalidated" has exactly one meaning.
    fn invalidate_sol_approval(&mut self) {
        if let Some(c) = &mut self.sol_ceremony {
            c.reset();
        }
    }

    /// The vault's operator lock covers the Solana ceremony too (external
    /// audit, 2026-07-19): a locked vault refuses phase 1 and phase 2 before
    /// any terminal prompt. The approval itself is already dropped by the
    /// lock handler; this gate re-drops defensively in case the vault was
    /// locked by any path that bypassed the IPC handler.
    fn sol_lock_gate(&mut self) -> Option<VaultResponse> {
        if self.vault.is_locked() {
            self.invalidate_sol_approval();
            return Some(err(
                "VLT-SOL-010",
                "vault is locked — the Solana ceremony refuses while locked; any pending \
                 approval was dropped (unlock, then re-run the full ceremony)",
            ));
        }
        None
    }

    /// ADR-021 phase 1: select the single-cluster config, render the facts
    /// on vaultd's own terminal, require the chain-labeled phrase there.
    fn sol_approve_facts(&mut self, cluster_chain_id: u64, facts: WireSolFacts) -> VaultResponse {
        if let Some(refusal) = self.sol_lock_gate() {
            return refusal;
        }
        let config = match cluster_chain_id {
            cipherlayer_chain::SOLANA_DEVNET_CHAIN_ID => SolExternalSignerConfig::devnet(),
            cipherlayer_chain::SOLANA_MAINNET_CHAIN_ID => SolExternalSignerConfig::mainnet(),
            other => {
                return err(
                    "VLT-SOL-001",
                    format!("cluster {other} is not a Solana external-signer cluster"),
                )
            }
        };
        // A different in-flight cluster (or any previous approval) is dropped:
        // single in-flight ceremony, no resurrection.
        let ceremony = match &mut self.sol_ceremony {
            Some(c) if c.config().cluster_chain_id == cluster_chain_id => c,
            _ => {
                self.sol_ceremony = Some(SolExternalSigningCeremony::new(config.clone()));
                self.sol_ceremony.as_mut().expect("just set")
            }
        };
        let prompt = sol_ceremony::render_facts(
            config.cluster_name,
            config.expected_genesis_hash,
            &facts,
            config.approval_phrase,
            config.is_mainnet,
        );
        let typed = match sol_ceremony::prompt_visible(&prompt) {
            Ok(t) => t,
            Err(sol_ceremony::TtyUnavailable(detail)) => {
                return err("VLT-SUR-001", format!("fail closed: {detail}"));
            }
        };
        let engine_facts = cipherlayer_vault::SolApprovedFacts {
            from_pubkey: facts.from_pubkey,
            to_pubkey: facts.to_pubkey,
            lamports: facts.lamports,
            fee_estimate_lamports: facts.fee_estimate_lamports,
        };
        match ceremony.approve_facts(cluster_chain_id, engine_facts, &typed, chrono::Utc::now()) {
            Ok(ticket) => VaultResponse::SolApproveResponse {
                nonce: ticket.nonce,
                expires_at: ticket.expires_at,
                cluster_name: config.cluster_name.to_string(),
            },
            Err(e) => {
                sol_ceremony::echo_refusal(&e);
                err(sol_refusal_code(&e), e.to_string())
            }
        }
    }

    /// ADR-021 phase 2: re-decode, enforce the fee rule, and only then read
    /// the key on the vaultd terminal. The engine wipes the key input on
    /// every path; on any refusal the approval is already consumed.
    fn sol_sign(
        &mut self,
        nonce: uuid::Uuid,
        message_hex: &str,
        final_fee_lamports: Option<u64>,
    ) -> VaultResponse {
        if let Some(refusal) = self.sol_lock_gate() {
            return refusal;
        }
        let Some(ceremony) = &mut self.sol_ceremony else {
            return err("VLT-SOL-005", "no approval is pending — run phase 1 first");
        };
        let message = match alloy::hex::decode(message_hex.trim_start_matches("0x")) {
            Ok(m) => m,
            Err(e) => {
                // ANY phase-2 attempt consumes the approval — including one
                // that dies at hex decode (external audit, 2026-07-19: a
                // malformed attempt must not leave the approval live).
                ceremony.reset();
                return err(
                    "VLT-SOL-006",
                    format!("message_hex does not decode: {e} — the approval was consumed"),
                );
            }
        };
        let cluster_name = ceremony.config().cluster_name;
        // ADR-021 §2: validate (nonce, expiry, independent re-decode,
        // facts-match, fee rule) and consume the approval FIRST — the key is
        // never requested for a ceremony that will be refused, so a real
        // mainnet key never enters memory for a doomed attempt.
        let validated = match ceremony.validate_and_consume(
            nonce,
            &message,
            final_fee_lamports,
            chrono::Utc::now(),
        ) {
            Ok(v) => v,
            Err(e) => {
                sol_ceremony::echo_refusal(&e);
                return err(sol_refusal_code(&e), e.to_string());
            }
        };
        // Only now — after every gate passed — is the key read on the tty.
        let mut key = match sol_ceremony::prompt_secret(&sol_ceremony::key_prompt(cluster_name)) {
            Ok(k) => k,
            Err(sol_ceremony::TtyUnavailable(detail)) => {
                return err("VLT-SUR-001", format!("fail closed: {detail}"));
            }
        };
        let result =
            cipherlayer_vault::SolExternalSigningCeremony::sign_validated(&validated, &mut key);
        key.zeroize(); // engine already wiped; belt-and-suspenders
        match result {
            Ok(signed) => VaultResponse::SolSignResponse {
                pubkey: signed.pubkey,
                signature: signed.signature,
                raw_hex: alloy::hex::encode(&signed.raw),
            },
            Err(e) => {
                sol_ceremony::echo_refusal(&e);
                err(sol_refusal_code(&e), e.to_string())
            }
        }
    }

    /// USER_REVIEW on the Vault side (trusted-confirmation-surface.md):
    /// render the deterministic evidence in system-owned chrome, obtain the
    /// human decision here, and only then sign. Every refusal is coded;
    /// every surface failure fails closed.
    async fn confirm_and_sign(
        &mut self,
        mut wire: cipherlayer_vault::WireSigningRequest,
    ) -> VaultResponse {
        let signing_request_id = wire.signing_request_id;
        let refuse = |code: &str, detail: String| VaultResponse::SignResponse {
            payload: Box::new(WireSigningResponse {
                schema_version: cipherlayer_vault::ipc::WIRE_SCHEMA_VERSION.into(),
                signing_request_id,
                responded_at: chrono::Utc::now(),
                state: WireSignState::Refused,
                raw_tx_hex: None,
                tx_hash: None,
                signature_hex: None,
                refusal: Some(WireRefusal {
                    code: code.into(),
                    detail,
                }),
            }),
        };
        if wire.user_authorization.is_some() {
            return err(
                "invalid_signing_request",
                "confirm_and_sign requires user_authorization: null — the decision is made here",
            );
        }
        // v0.4 honest limitation: this surface only renders transaction
        // evidence today (see `WireDisplayEvidence`); message-signing
        // requests must use the direct authorize_and_sign review path.
        if wire.payload.kind != "evm_transaction" {
            return err(
                "unsupported_payload_kind",
                format!(
                    "confirm_and_sign (vault-side surface) does not support kind={:?} in this revision",
                    wire.payload.kind
                ),
            );
        }
        let Some(display) = wire.ext.display.clone() else {
            return err(
                "invalid_signing_request",
                "confirm_and_sign requires ext.display evidence to render",
            );
        };
        // A deny is never rendered as confirmable (requirement 7).
        if wire.ext.policy_verdict == cipherlayer_policy::Verdict::Deny {
            return refuse(
                "VLT-POL-001",
                "policy verdict deny is final — not rendered for confirmation".into(),
            );
        }
        let escalated = wire.ext.policy_verdict == cipherlayer_policy::Verdict::Escalate;

        // Deterministic evidence text: from the request and pipeline evidence
        // only. Unknown risk stays visible; escalation is called out.
        let Some(tx) = &wire.payload.transaction else {
            return err(
                "invalid_signing_request",
                "kind=evm_transaction requires payload.transaction",
            );
        };
        let body = format!(
            "intent:      {}\nchain:       {}\naccount:     {}\nto:          {}\nvalue (wei): {}\nsimulation:  {}\nrisk:        {}\npolicy:      {:?}\n{}",
            display.intent,
            display.chain,
            wire.account,
            tx.to.map(|a| a.to_string())
                .unwrap_or_else(|| "(contract creation)".into()),
            tx.value,
            display.simulation,
            display.risk,
            wire.ext.policy_verdict,
            display
                .policy_reasons
                .iter()
                .map(|r| format!("  - {r}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );

        let decision = match surface::confirm(&body, escalated) {
            Ok(d) => d,
            Err(surface::SurfaceUnavailable(detail)) => {
                return refuse("VLT-SUR-001", format!("fail closed: {detail}"));
            }
        };
        match decision {
            surface::Decision::Rejected { detail } => refuse("VLT-USR-001", detail),
            surface::Decision::Approved { auto } => {
                wire.user_authorization = Some(WireUserAuthorization {
                    decision: "approved".into(),
                    decided_at: chrono::Utc::now(),
                    surface: ConfirmationSurface::DesktopTrustedSurface,
                    escalation_acknowledged: Some(escalated),
                });
                if auto {
                    eprintln!(
                        "confirm_and_sign {signing_request_id}: approved via \
                         CIPHERLAYER_CONFIRM_AUTO (test hook, not a human decision)"
                    );
                }
                let req = match wire.into_request() {
                    Ok(r) => r,
                    Err(e) => return err("invalid_signing_request", e),
                };
                let response = match self.vault.authorize_and_sign(&req).await {
                    Ok(outcome) => WireSigningResponse::from_outcome(signing_request_id, &outcome),
                    Err(e) => WireSigningResponse::refused(signing_request_id, &e),
                };
                VaultResponse::SignResponse {
                    payload: Box::new(response),
                }
            }
        }
    }

    async fn serve_connection(&mut self, stream: UnixStream) -> std::io::Result<()> {
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = self.handle(&line).await;
            let mut out = serde_json::to_string(&response).expect("responses serialize");
            out.push('\n');
            write_half.write_all(out.as_bytes()).await?;
        }
        Ok(())
    }

    pub async fn run(&mut self, socket_path: &Path) -> std::io::Result<()> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }
        let listener = UnixListener::bind(socket_path)?;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        eprintln!(
            "vaultd listening on {} (signer {}, MOCKED custody — Anvil dev keys only)",
            socket_path.display(),
            self.vault.address()
        );
        loop {
            let (stream, _addr) = listener.accept().await?;
            if let Err(e) = self.serve_connection(stream).await {
                eprintln!("connection error: {e}");
            }
        }
    }
}

#[cfg(test)]
mod sol_gate_tests {
    //! Security regressions for the Solana ceremony's daemon-level gates
    //! (external audit, 2026-07-19). These exercise the handlers directly —
    //! every path here refuses BEFORE any tty prompt, so no terminal is
    //! needed and the gates are proven independent of the human channel.
    //! The same lifecycle is also exercised over the REAL Unix-socket IPC in
    //! `crates/cipherlayer-cli/tests/sol_ipc_security.rs` (re-audit,
    //! 2026-07-20).

    use super::*;
    use cipherlayer_vault::{SolApprovedFacts, TestSigner, ANVIL_DEV_KEYS};

    fn daemon() -> Daemon {
        let signer = TestSigner::from_dev_key(ANVIL_DEV_KEYS[0]).expect("anvil dev key loads");
        Daemon::new(Vault::new(signer))
    }

    fn facts() -> WireSolFacts {
        WireSolFacts {
            from_pubkey: "587DciffbmfqQKNDK1XLvfCGfndMKfxnpwWk2t8qWK9U".into(),
            to_pubkey: "AbZmoJqS2KrxVsEo3wi5CMHjpJCBrdovgcu1xH9KGpHE".into(),
            lamports: 1_000_000,
            fee_estimate_lamports: Some(5_000),
        }
    }

    /// Build a daemon whose ceremony holds a live approval, without any tty:
    /// the engine's phase 1 is called directly with the correct phrase.
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

    fn error_code(resp: &VaultResponse) -> &str {
        match resp {
            VaultResponse::Error { code, .. } => code,
            other => panic!("expected an error response, got {other:?}"),
        }
    }

    async fn lock_request(d: &mut Daemon) {
        let resp = d.handle(r#"{"message":"lock"}"#).await;
        assert!(
            matches!(resp, VaultResponse::LockResponse { locked: true }),
            "lock must succeed, got {resp:?}"
        );
    }

    #[test]
    fn locked_vault_refuses_phase_1_before_any_prompt() {
        let mut d = daemon();
        d.vault.lock();
        let resp = d.sol_approve_facts(cipherlayer_chain::SOLANA_DEVNET_CHAIN_ID, facts());
        assert_eq!(error_code(&resp), "VLT-SOL-010");
    }

    #[test]
    fn locked_vault_refuses_phase_2_and_drops_the_pending_approval() {
        let (mut d, nonce) = daemon_with_approval();
        d.vault.lock();
        let resp = d.sol_sign(nonce, "00", Some(5_000));
        assert_eq!(error_code(&resp), "VLT-SOL-010");
        // Unlocking does not resurrect the approval: it was dropped.
        d.vault.unlock();
        let resp = d.sol_sign(nonce, "00", Some(5_000));
        assert_eq!(error_code(&resp), "VLT-SOL-005");
    }

    /// External re-audit, 2026-07-20: the LOCK REQUEST itself must drop the
    /// approval — not merely a Solana request arriving while still locked.
    /// lock → unlock → sign with no intervening Solana traffic must find
    /// nothing pending.
    #[tokio::test]
    async fn lock_request_alone_kills_the_approval_no_resurrection_after_unlock() {
        let (mut d, nonce) = daemon_with_approval();
        lock_request(&mut d).await;
        let resp = d.handle(r#"{"message":"unlock"}"#).await;
        assert!(matches!(
            resp,
            VaultResponse::LockResponse { locked: false }
        ));
        // Unlocked vault, no Solana request ever hit the lock gate: the
        // approval must still be gone. (Without the fix this passed the gate,
        // validated against the resurrected approval, and reached the key
        // prompt.)
        let resp = d.sol_sign(nonce, "00", Some(5_000));
        assert_eq!(error_code(&resp), "VLT-SOL-005");
    }

    #[test]
    fn malformed_message_hex_consumes_the_approval() {
        let (mut d, nonce) = daemon_with_approval();
        let resp = d.sol_sign(nonce, "zz-not-hex", Some(5_000));
        assert_eq!(error_code(&resp), "VLT-SOL-006");
        // The approval must be gone: a follow-up attempt has nothing to use.
        let resp = d.sol_sign(nonce, "00", Some(5_000));
        assert_eq!(error_code(&resp), "VLT-SOL-005");
    }
}
