# ADR-007 — Local-First Audit Log

**Status:** Accepted · **Date:** 2026-07-03

## Context

The audit layer must record the full signing lifecycle — requested intent, decoded intent, simulation, risk, policy outcome, user decision, signature, broadcast, failures, revocations — and is the institutional wedge (US §6). The prompt forbids claiming immutability without a real integrity mechanism and asks for tamper-evident chaining if practical, with limitations described (BP §6.2; conflict AC-006 vs US "immutable audit logs").

## Decision

- **Format:** append-only JSON Lines file, one structured `AuditEvent` per line, schema-versioned (`audit-event.v1.json`).
- **Integrity:** each event carries `sequence`, `prev_hash`, and `event_hash` = SHA-256 over a canonical serialization of (sequence, timestamp, kind, payload, prev_hash). Genesis uses a fixed tag. `cipherlayer-cli audit verify` recomputes the chain and reports the first divergence.
- **Storage:** local file (`CIPHERLAYER_AUDIT_LOG`, default `./data/audit-log.jsonl`). No cloud, no external anchoring in milestone 1 — **local-first** per privacy architecture (BS §15).
- **Claim discipline:** described everywhere as *tamper-evident*, never *immutable*. Documented limitation: an attacker with file write access can rewrite the entire chain from any point; truncation of the tail is detectable only against an externally stored head hash (not yet implemented).

## Alternatives considered

1. **SQLite ledger** — richer queries, but hides the bytes; JSONL is inspectable with standard tools and diff-able, which suits an evidence artifact.
2. **Merkle tree + periodic external anchor** (e.g., posting the root on-chain) — right long-term answer for the legal-grade layer; deferred, extension point documented.
3. **No chaining (plain log)** — rejected: cheap to add chaining now; the verify command is itself a demo-able differentiator.

## Consequences

- Every pipeline step emits exactly one event kind; the CLI can reconstruct a request's lifecycle by `request_id`.
- Log rotation/compaction is out of scope; file grows unbounded (acceptable for prototype).

## Security implications

Tamper-evidence ≠ tamper-proofness; register entry SC-07 states exactly what `audit verify` does and does not prove. Audit events never contain key material or full raw signatures beyond what a broadcast transaction reveals anyway.

## Revisit conditions

Legal-grade phase (W5): external anchoring, retention policy, export formats, evidence-preservation requirements.
