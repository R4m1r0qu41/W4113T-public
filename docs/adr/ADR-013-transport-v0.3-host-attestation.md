# ADR-013 — Browser-Connect Transport v0.3: Host Attestation

**Status:** Accepted (implemented) · **Date:** 2026-07-07 · **Decider:** operator · Closes browser threat-extension **C-1** (capsule_id integrity) for non-host peers; follows ADR-B002 (browser repo) which named this as a pre-MVP prerequisite. Extends the v0.2 transport (`serve.rs`).

## Context

The browser-connect transport (v0.2) carries `capsule_id` as a plaintext bearer string inside each envelope's `caller`, and the wallet keys permission grants by `dapp:{origin}#{capsule_id}`. The capsule-isolation experiment (browser repo, ADR-B002 finding 1) measured the consequence: **any local process that reaches the socket can put another capsule's id in an envelope and inherit that capsule's grant** — a confused-deputy / identity-forgery gap (wallet threats T-18/T-19). Permission *scoping* is correctly enforced wallet-side; capsule *identity* is not authenticated.

ADR-B002 concluded the gap must be closed by **either** protocol-level per-peer/capsule attestation **or** the Tauri host process vouching for each WebView's identity (the host is trusted; the page is not), and made it a blocking prerequisite for any multi-capsule shell. No Tauri host exists yet, so this ADR builds the transport-level half now, and defines the contract the future host will authenticate against.

## Decision

Introduce **host attestation** in transport v0.3:

- The `connect serve` process holds a **launch token**. Source, in order: `CIPHERLAYER_CONNECT_HOST_TOKEN` (env — preferred, never written to disk; the channel by which the wallet hands the token to the host it launches), else `<socket-dir>/connect-host-token` (0600 file, generated if absent so a standalone daemon is usable).
- A new message `host_attest { token }` marks the **connection** attested iff the token matches (length-checked, difference-OR compare). Attestation is per-connection state, not global.
- Every **capsule-bearing** operation — `connect_request`, `transaction_request`, `permission_revoke` — is refused on an un-attested connection with `error { code: "attestation_required" }`. `capability_query` and `host_attest` are the only messages a fresh connection may send.
- `PROTOCOL_VERSION` → `0.3`; the capability advertisement lists `0.3` and the `host_attest` method.

A rogue local process that never presents the token therefore **cannot submit a capsule-bearing envelope at all**, so it cannot forge another capsule's id to ride its grant. The legitimate host attests once, then multiplexes capsules it vouches for; pages never speak the protocol directly and never choose their own capsule id.

## What this closes, and what it does not (honest bound)

- **Closes:** capsule forgery by any peer that is **not** the launched host — web content (which cannot read the token and cannot reach the socket except through the host), and reduced-privilege or other-user helpers. This is the architecturally meaningful boundary and the one the capsule-isolation experiment exercised. `unattested_peer_cannot_forge_capsule_identity` proves it over the real socket.
- **Does NOT close:** a **same-user attacker who can read the env var or the 0600 token file** can attest and impersonate the host. That is local malware at the user's own privilege — wallet threat **T-14**, already `accepted-P` for the prototype (only worthless Anvil dev keys exist, ADR-005). The token is a *launch secret*, not a network credential; it raises the bar from "any same-user process" (v0.2) to "a same-user process that can also read the token," and defines the seam where OS-level per-capsule isolation (the engine's job, ADR-B002) provides defence in depth.

No claim of cryptographic peer authentication is made. A future v0.4 could bind attestation to OS peer credentials or a per-connection challenge; that is not required to close C-1 for non-host peers.

## Alternatives considered

1. **Wallet-minted capsule handles** (wallet issues unguessable capsule ids instead of pages choosing strings) — rejected for now: it complicates grant persistence (grants are keyed by a stable capsule identity across restarts) without closing the same-user-read residual, and host attestation already denies the non-host peer outright.
2. **OS peer credentials (SO_PEERCRED/getpeereid)** — insufficient alone: all peers are the same user, so uid/pid cannot distinguish the host from a rogue same-user process.
3. **Do nothing until the Tauri host exists** — rejected: the transport contract the host must speak should exist and be tested first, and C-1 blocks the MVP either way.

## Consequences

- Every browser-connect consumer must `host_attest` before capsule operations. Updated: wallet `transport_integration.rs` (+ a dedicated forge-refused test), browser `broker-core` (`attest`/`attest_from_env`), and the `provider-harness` and `capsule-isolation` harnesses (the latter's "known v0.2 gap" measurement now asserts the gap is **closed**).
- Threat model rows T-18/T-19 move forward (same-user peer forgery closed; same-user-read residual named). Browser C-1 disposition moves from "open, blocking" to "closed for non-host peers; residual = T-14."
- Transport concurrency (ADR-B002 finding 2) was a separate, since-closed pre-MVP item — see the transport-concurrency addendum below.

## Addendum — transport concurrency (2026-07-08)

The transport now serves connections concurrently (one task per accepted connection, `Arc<Mutex<Pipeline>>` for correctness-critical state, a lock-free `Arc<ChainRegistry>` for read-only queries). Host attestation is unaffected: it remains per-connection state (`ConnState`), and each concurrently-served connection still attests independently before asserting capsule identity. See the wallet's transport-concurrency commit for detail; ADR-B002 finding 2 is closed.

## Revisit

If OS-level peer attestation becomes worthwhile (v0.4); when the Tauri host lands (it becomes the attesting party and this contract is its authentication point); if the same-user-read residual must be closed before real keys (then: OS keychain-gated token or per-capsule process isolation).
