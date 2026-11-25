# ADR-004 — Vault Process Boundary

**Status:** Accepted; process split **implemented** 2026-07-07 (see Addendum) · **Date:** 2026-07-03

## Context

Both scopes require the Vault to be a separate, narrowly scoped component: separate process, minimal codebase, no web rendering, narrow IPC, capability-based requests, hardware-backed storage where available (BS §6.4; US §3.1). A real OS-process split only pays off once there is a second process (desktop UI at W2); in a CLI-only milestone, the honest statement is that the boundary is architectural, not yet physical.

## Decision

- Target architecture: the Vault runs as a **separate OS process** with a narrow, schema-validated IPC surface (signing-request/response schemas), introduced at W2 alongside the desktop shell.
- Milestone 1: the Vault is the `cipherlayer-vault` crate behind a strict trait boundary (`Signer`, `Vault`), with capability validation, lock state, and authorization checks enforced in code. This is labeled **MOCKED (process isolation)** in code and in `docs/security/prototype-limitations.md`.
- Nothing outside the crate can reach key material: keys are private fields, never serialized, never logged, no accessor APIs. The compiler enforces the interface; it does not enforce memory isolation.

## Alternatives considered

1. **Separate process now** — rejected for milestone 1: adds IPC machinery with exactly one caller (CLI) and no adversarial co-resident code yet; would slow the vertical slice without changing the real trust posture of a single-binary CLI.
2. **In-process forever** — rejected: renderer-adjacent processes (desktop/browser) must never share an address space with keys.
3. **OS keychain / secure enclave now** — deferred: worth doing at W2+; interface stub exists (`SecureStorage` trait).

## Consequences

- The signing-request/response schemas are written now as the future IPC wire format, so the process split is a transport change, not a redesign.
- Until the split, a memory-unsafe bug anywhere in the CLI binary is a key-compromise bug. Acceptable only because the only keys allowed are worthless, publicly known Anvil dev keys (enforced + documented).

## Security implications

Honest labeling: prototype provides *interface* isolation, not *process* isolation. All prototype-limitations language and the security-claims register reflect this.

## Revisit conditions

W2 desktop work (must implement the process split before any GUI signing); availability of hardware-backed storage; independent security review findings.

## Addendum — process split implemented (2026-07-07)

The W2 split now exists, sequenced ahead of the desktop shell because the browser MVP gate's criterion 2 and the ADR-B002 engine selection (Tauri + separate Vault process) both assume it.

- **`cipherlayer-vaultd`** — a minimal daemon binary hosting the same `Vault` behind a JSON-lines IPC on a same-user Unix socket (0700 directory / 0600 socket — the identical OS-enforced peer-auth model as the browser-connect v0.2 transport). Deny-by-default messages: `status`, `lock`, `unlock`, `sign_request`. Test keys only (ADR-005): a non-Anvil key refuses to start.
- **Wire format** — the pinned `signing-request.v1` schema, exactly as this ADR planned ("a transport change, not a redesign"). Two pipeline facts the daemon cannot re-derive (policy verdict, network class) travel in the schema's `ext` field and are validated, never trusted. The response is the new pinned `vault-signing-response.v1`: signed artifact or a `VLT-*` coded refusal. Key material appears on the wire in neither direction.
- **Consumption** — `VaultBackend::{InProcess, Remote}`: the CLI default remains in-process; `CIPHERLAYER_VAULT_SOCKET` routes signing through the daemon. Audit events carry the honest provenance (`…, cipherlayer-vaultd process`).
- **Proven** — the vault crate's in-process refusal invariants are re-proven across the boundary by `cipherlayer-vaultd/tests/ipc_security.rs` (real binary, real socket): locked, deny, unacknowledged escalation, non-dev chain, expired capability, account mismatch, unknown message, malformed JSON, group/world-accessible socket refusal, real-key startup refusal.

Still open from the original decision: hardware-backed / OS-keychain storage (the `SecureStorage` stub remains theoretical) and, of course, real custody — ADR-005's test-key gate is unchanged.
