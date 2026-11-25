# ADR-021 — Solana External Signer (devnet + mainnet-beta), Behind the Vault Process Boundary

**Status:** Accepted (2026-07-18 — implemented: engine + vaultd ceremony + IPC contract + console dispatcher + litesvm e2e, all gates green; devnet ceremony gate **passed live 2026-07-19**; first external adversarial audit returned four findings, all fixed same day — see §6 Amendment; the re-audit of those fixes found two remaining high-severity gaps (approval resurrection through lock/unlock; state-machine bypass) plus a TLS/independence medium — all fixed, see §7 Amendment; the focused post-commit re-audit **passed 2026-07-20 at `8ca5b23` with no mainnet-blocking findings**) · **Date:** 2026-07-18 (amended 2026-07-19, 2026-07-20) · Amends ADR-016 (§Revisit: key material outside the vault) and discharges ADR-020 §6 (Solana explicitly out of scope there). Companion to ADR-011/ADR-020 (the EVM external-signer authority).

## Context

ADR-016 built the Solana adapter under a hard stop: *"any need for key material outside the vault"* requires its own ADR before any code. ADR-020 §6 reaffirmed it: a mainnet Solana path "is a separate, larger piece of work and gets its own ADR." The operator has now directed that work (2026-07-17 handoff, priority 1): a human-gated Solana signing ceremony for devnet and mainnet-beta, mirroring the proven EVM external-signer pattern.

Two review inputs shaped this ADR beyond the EVM precedent:

- An external adversarial review (Codex, 2026-07-18) rejected the first design — which mirrored ADR-020's key path (no-echo console prompt + process env var) — on the ground that it places key material inside the CLI/presentation process, conflicting with the trust-boundary rule that signing happens only behind the vault. The operator accepted that finding.
- The same review rejected a fee-display fallback ("~5000 lamports when the RPC returns null") as evidence, per the "unknown stays unknown" invariant, and required that mainnet RPC endpoints be explicitly configured, never defaulted.

The EVM path (ADR-020) is therefore **not** the boundary precedent here — it is recorded below as debt.

## Decision

### 1. The hard-stop lift, worded narrowly

ADR-016's "no key material outside the vault" is lifted **only** for a runtime-key ed25519 signing authority that lives **inside the vault process boundary**: signing logic in `cipherlayer-vault` (new `sol_external_signer` module), secret entry and human approval hosted by `cipherlayer-vaultd`. Nothing else moves:

- `SolVault`/`SolTestSigner` (dev-only, litesvm) is untouched.
- `ChainRegistry::ensure_signing_allowed` (Development-only vault custody gate) is untouched.
- `cipherlayer-sol` remains key-free (its own crate invariant).
- The CLI/console never sees the key in any form: it receives only the declared public key and the signed artifact.

### 2. Process boundary and ceremony shape (two-phase, key-lifetime-minimal)

vaultd's existing human channel is the macOS system dialog (ADR-012). A private key must not transit an `osascript` child process and its stdout pipe, so secret entry uses **vaultd's own controlling terminal** (`/dev/tty`, termios echo off), fail-closed if vaultd has no tty. The ceremony is two IPC phases (new contract `vault-sol-signing.v1`), driven by the console over the vaultd socket:

- **Phase 1 — approve facts.** Console sends the operator-entered facts: cluster, from-pubkey (declared), to-pubkey, lamports, and the pre-approval fee estimate. vaultd renders them on its terminal and requires the chain-labeled approval phrase (`SEND-CIPHERLAYER-SOLANA-MAINNET` / `SEND-CIPHERLAYER-SOLANA-DEVNET`) typed on the **vaultd** terminal — the wallet-side surface, not the browser, not the CLI. On approval vaultd records `{facts, fee_estimate, nonce, expires_at}` (single in-flight approval, ~90 s expiry — the blockhash lifetime bound).
- **Build after approval.** The console builds the unsigned message with a **fresh blockhash** (`SolAdapter::build_unsigned`) and queries the **authoritative fee for that final message**.
- **Phase 2 — sign.** Console sends `{nonce, unsigned message bytes, final fee}`. vaultd verifies the nonce/expiry, **independently re-decodes the message** and refuses any deviation from the approved facts (fee payer = declared pubkey, `num_required_signatures == 1`, exactly one system-program `Transfer`, decoded `(to, lamports)` equal to the approval — `ApprovedFactsMismatch` otherwise), and enforces the fee rule (§4). Only then does it prompt for the key on `/dev/tty` (no echo), parse, derive, and refuse unless the derived pubkey equals the declared one — then sign, wipe, and return `{pubkey, signature, signed tx bytes}`. The key exists in memory for a single call: paste → derive-check → sign → drop.

The signature is bound to operator-approved **facts**, not to a byte blob; the blockhash is the only field the operator never vouches for, and it cannot redirect funds. Blockhash expiry never triggers silent re-signing: a failed or expired broadcast requires the full ceremony again, and the console's timeout message warns against re-running until an explorer confirms the transaction is absent (Solana transactions carry no chain id and no replay-window nonce; the double-send risk is real).

Zeroization: the tty input buffer and the decoded base58 bytes are overwritten after parse; `solana-keypair`'s `Keypair` zeroizes its secret on drop (verified: `ed25519_dalek::SigningKey` with the default-on `zeroize` feature). Residuals (allocator copies, kernel tty buffers) are same-user-attacker surface, T-14 class, recorded in the threat model (T-27).

### 3. Extend, don't loosen (ADR-020 conditions, restated for Solana)

- Two hardcoded constructors, `devnet()` / `mainnet()`, each permitting exactly one cluster; no "any cluster" mode. Internal chain ids 900003 (devnet) / 900004 (mainnet-beta) in ADR-016's reserved band — and per ADR-016, these ids **never appear on a browser-facing wire**: the browser capability surface was filtered to EVM-family entries in this ADR's chunk 1 (wallet commit `98cf7b1`, fixing the pre-existing 900001/900002 leak, guarded by a band-absence regression test). The 900003/900004 ids appear only on the same-user vault IPC (`vault-sol-signing.v1`) and in the console's chain-family dispatcher.
- Cluster identity is the **pinned genesis hash** (mainnet `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`, devnet `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`), baked into the constructor and re-verified live (`SolAdapter::verify_chain_identity`, fail closed) immediately before phase 1 and again before broadcast. Blockhash-based cluster separation is incidental and never relied upon; the same keypair is valid on both clusters, which is exactly why the phrase names the cluster and approvals expire.
- The console's Solana ceremony gate admits exactly `{900003, 900004}`; the local validator (900001) stays on the mocked `SolVault` path.
- **Mainnet RPC is explicit-only**: `CIPHERLAYER_SOLANA_MAINNET_RPC` must be set or the mainnet ceremony refuses to start — no public fallback. Devnet resolves `CIPHERLAYER_SOLANA_DEVNET_RPC` → `https://api.devnet.solana.com`.
- No single flag or env var can silently enable mainnet: constructor, registry entry, console permitted-set literal, approval phrase, and the explicit RPC requirement are each a deliberate source edit or operator action.
- Scope: **system transfers only** (one `Transfer` instruction, nothing else decodes as signable), mirroring the dev vault's decoder — which is refactored into a shared helper so this module and `SolVault` cannot drift.

### 4. Fee evidence stays honest

`getFeeForMessage` returning null is **unknown**, and unknown is not evidence:

- Preflight (pre-approval) shows an authoritative fee query result for a provisional message, labeled as an estimate; on mainnet a null here already refuses the ceremony.
- Phase 2 carries the authoritative fee for the **final** message. Mainnet: null → refuse signing. Devnet: may proceed displaying `fee: unknown`.
- If the final fee exceeds the estimate the operator approved, vaultd refuses the nonce; the ceremony re-runs with the new number. Approved facts never silently change.

### 5. EVM key path recorded as debt

ADR-020's key mechanics (key via `CIPHERLAYER_EXTERNAL_SIGNER_KEY` in the CLI process, no-echo console prompt, loader script) violate the boundary this ADR establishes. They remain functional and sanctioned by ADR-020, but are **debt, not precedent**: no new signing family may copy them, and a follow-up ADR should move the EVM external signer behind the same vaultd two-phase ceremony. Until then the difference is documented in `prototype-limitations.md`.

### 6. Amendment (2026-07-19) — external-audit fixes

The first adversarial audit (Codex) confirmed the devnet ceremony and the engine but blocked mainnet on four defects. All four are fixed; the fixes are part of this ADR's contract:

1. **Cluster identity is bound through broadcast (ATK5).** Solana transactions carry no chain id, so a Byzantine primary RPC can attest the pinned genesis while handing out another cluster's blockhash — turning a devnet-phrased approval into a mainnet-valid transaction. The ceremony now (a) re-verifies the pinned genesis on the primary immediately before broadcast (as §3 always required), and (b) requires an **independent cross-check provider** that must attest both the pinned genesis and the *final message's blockhash* (`isBlockhashValid`) immediately before broadcast. Mainnet: `CIPHERLAYER_SOLANA_MAINNET_RPC_CROSSCHECK` is mandatory and must resolve to a **different hostname** than the primary (normalized: scheme/userinfo/port/path/query/case stripped — a cosmetically dressed-up same-host URL refuses; an unparseable URL refuses) — no single provider is trusted alone; an unavailable or non-boolean answer refuses, closed. The resolution, verdict, and balance-preflight decisions are pure functions with unit tests on every refusal branch (`resolve_sol_crosscheck` / `crosscheck_verdict` / `sol_balance_preflight`). Devnet: `CIPHERLAYER_SOLANA_DEVNET_RPC_CROSSCHECK` is optional; its absence is an accepted single-provider residual (worthless funds), stated in the threat model. Residual: two colluding providers defeat the cross-check; recorded in T-27.
2. **The ceremony sits under the mandatory controls.** The vault operator lock now gates both phases (refusal `VLT-SOL-010`, checked before any terminal prompt) and locking drops any pending approval — lock means STOP, not pause. The console ceremony refuses to start without a writable audit log (CL-AUD-001); a failed `SignatureCreated` append aborts *before* broadcast; broadcast failures, on-chain failures, and confirmation-window timeouts each get an audit record.
3. **Key zeroization is complete.** The vaultd key prompt no longer reads through `BufReader` (whose internal heap buffer held key bytes and dropped unwiped, contradicting §2's claim); it reads unbuffered, byte-at-a-time from the tty fd into a `Zeroizing` accumulator, and the staging byte is wiped.
4. **Single-use covers malformed input.** A phase-2 attempt whose `message_hex` fails to decode now consumes the approval like every other attempt — a malformed attempt cannot leave the approval live. Daemon-level security regressions cover the lock gate (both phases), approval-drop-on-lock, and malformed-input consumption; adapter tests pin `isBlockhashValid` fail-closed semantics.

The audit also surfaced a preflight gap proven live in the devnet gate: the console now refuses before phase 1 when `lamports + fee estimate > balance` (fee-unknown: the amount alone must be strictly below balance, stated honestly).

### 7. Amendment (2026-07-20) — re-audit fixes

The follow-up adversarial re-audit confirmed the §6 closures for findings 1, 3, and 4 but found finding 2's closure incomplete in two ways, plus a medium. All are fixed and part of this ADR's contract:

1. **Lock invalidates the approval eagerly, not lazily.** The §6 fix dropped a pending approval only when a *Solana request arrived while the vault was locked*; the lock request itself left it standing, so lock → unlock → sign resurrected the approved nonce. The lock handler now clears the pending Solana approval the moment the lock request is processed, through a single shared `invalidate_sol_approval()` used by both the lock handler and the (now defensive) per-request lock gate. Regression coverage runs at two levels: in-process handler tests, and **boundary-level tests that drive the real `cipherlayer-vaultd` daemon over its Unix socket with the real `VaultClient`** (`crates/cipherlayer-cli/tests/sol_ipc_security.rs` — the daemon is a library target for exactly this reason). The resurrection test was verified to fail with the fix removed.
2. **The ceremony is a first-class signing lifecycle.** The console's Solana path previously never entered `cipherlayer-types::state` — a bypass of the hard invariant that the signing state machine may not be skipped, and of CL-AUD-001's full-lifecycle audit. The ceremony now runs one `Lifecycle` under one request id: RECEIVED → VALIDATED → PERMISSION_CHECKED (recorded explicitly as operator-direct, no delegated grant) → DECODED → SIMULATED → RISK_EVALUATED → POLICY_EVALUATED (fee honesty + balance preflight, deny → POLICY_DENIED) → USER_REVIEW (vaultd tty) → AUTHORIZED → SIGNED → BROADCAST → CONFIRMED, with every transition validated against the shared table and audited, and every refusal branch landing in the correct terminal state. Simulation and risk evidence are **entered and recorded as `unknown`** — no Solana simulator/risk evaluator is wired — and therefore the non-denied policy result is always **escalate**, never allow; the chain-labeled vaultd approval is the explicit escalation acknowledgement. BROADCAST is audited **at acceptance, before confirmation polling**, so a crash while polling cannot leave the audit implying the signed transaction was never submitted; a confirmation-window timeout leaves the lifecycle honestly at BROADCAST with the timeout recorded. Pre-broadcast audit-append failures fail the ceremony closed; post-broadcast failures warn (the transaction is already out).
3. **TLS + administrative independence.** Non-loopback RPC URLs (primary and cross-check, both clusters) must be `https://` — a cleartext hop can rewrite the very attestations the ceremony's gates rest on; loopback (local validator) is exempt. URL authorities are parsed structurally: only the exact `localhost` name or an actual loopback IP receives the local cleartext exemption; DNS names that merely resemble loopback do not. Refusal is closed and unit-tested (`require_sol_rpc_tls`). The hostname-inequality check remains a *necessary, not sufficient* independence test: two hostnames can share an operator or infrastructure. **Operational requirement (documented, not machine-checkable): the mainnet primary and cross-check endpoints must be administratively independent providers** — different companies, not two subdomains or two products of one vendor. Residual recorded in T-27.

## Consequences

- New: `cipherlayer-vault::sol_external_signer` (pure signing logic, unit-testable with injected key strings), vaultd terminal ceremony + `VaultRequest::{SolApproveFacts, SolSign}` wire arms, `schemas/vault-sol-signing.v1.json`, registry entries 900003/900004 with `expected_genesis_hash` (schema minor bump, compatibility-tested), console ceremony under menu 9's new chain-family dispatcher, litesvm e2e for the signer path.
- Removed from the design (relative to the reviewed draft): key env var, `keytool sol-pubkey`, loader script — no key ingestion mechanism exists outside vaultd.
- Real SOL becomes reachable from this codebase under the same class of controls that made ADR-020 acceptable, plus a stronger boundary than ADR-020 itself: the presentation process cannot leak what it never holds.
- Threat model gains T-27 (runtime ed25519 key exposure, scoped to the vaultd process); T-09's row gains the genesis-pin re-verification note. Requirements matrix gains CL-WAL-011.
- Live gating: operator devnet ceremony (worthless faucet key) first; independent adversarial audit before any mainnet use; mainnet ceremony only after both, small balance, explicit RPC.

## Alternatives considered

1. **Mirror ADR-020's env/console key path (EVM parity).** Rejected by external review and operator decision: puts key material in the presentation process; env vars inherit into child processes; "clear the env var" is not a wipe.
2. **Key entry via the macOS dialog (`with hidden answer`).** Rejected: the key would transit the `osascript` child process and its stdout pipe — a wider exposure than the tty read it replaces.
3. **vaultd builds the message itself.** Rejected: vaultd deliberately has no chain RPC; the adapter stays the only message builder, and the facts-binding check makes the builder untrusted anyway.
4. **`id.json` file ingestion.** Rejected: a file-shaped format invites keys-on-disk workflows; the paste-at-ceremony-time convention stands. Key format is the base58-encoded 64-byte keypair string (Phantom/Solflare export shape).
5. **A single-phase ceremony (approve and sign in one call, vaultd holds the key across the approval).** Rejected: maximizes key residence time for no benefit; the two-phase shape holds the key only for the sign call itself.

## Revisit

- Any non-transfer instruction (SPL tokens, versioned transactions, priority fees, durable nonces): new ADR.
- Vault-held Solana custody (true custody, not runtime-key relay): own ADR + audit, per ADR-020's precedent.
- Hardware/keychain key backends; moving the EVM family behind this boundary (§5).
