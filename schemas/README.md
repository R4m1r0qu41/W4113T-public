# Schemas — versioned wire contracts

These JSON Schemas (draft 2020-12) are the source of truth for every cross-boundary message. Rust types in `crates/` mirror them; when they disagree, the schema wins and the code is the bug.

## Common conventions (apply to every schema here)

- **Versioning:** filename carries the major version (`*.v1.json`); each instance carries `schema_version` (`"1.0"`-style). Additive, optional-field changes bump the minor version in place. Breaking changes create a new file (`*.v2.json`) plus a migration note here — old versions are never edited retroactively.
- **Stable identifiers:** every entity has a stable string ID (`request_id`, `intent_id`, `event_id`, …), UUID-format, assigned once, never reused.
- **Timestamps:** RFC 3339 UTC (`date-time`), field names end in `_at`.
- **Provenance:** messages derived from analysis (intent, simulation, risk, decision) carry a `provenance` object naming the producer and its version.
- **Unknown/null semantics:** `null` means *evaluated and unknown*; an **absent optional field** means *not evaluated*. Consumers must treat both restrictively and must never map unknown to a permissive value. Enums that can face novel input include an explicit `"unknown"` member.
- **Extension rule:** objects set `additionalProperties: false`; forward-compatible extension happens through the optional `ext` object (namespaced keys, e.g. `"cl.experiment/foo"`), never by sneaking untyped fields into the core.
- **Typed security values:** addresses are `0x`-40-hex strings (EIP-55 checksum not enforced at schema level; enforced in code), chain IDs are integers ≥ 1, amounts are **quantity strings** — decimal digits or `0x`-prefixed hex, arbitrary precision, never floats (the Rust implementation emits hex, accepts both), hashes are `0x`-64-hex.

## Index

| Schema | Purpose | Producer → Consumer |
|---|---|---|
| `wallet-capability.v1.json` | what the wallet supports (chains, methods, protocol) | wallet → browser/dapp |
| `dapp-permission.v1.json` | connection grant: scope, accounts, chain, expiry | wallet ↔ browser |
| `transaction-request-envelope.v1.json` | inbound request with mandatory caller identity; v1.1 (v0.4) adds payload.kind (evm_transaction/typed_data/personal_message) | dapp/browser/CLI → provider broker |
| `rpc-query.v1.json` | read-only JSON-RPC proxy (whitelist-only), v0.4 | dapp/browser → provider broker → chain RPC |
| `transaction-intent.v1.json` | canonical decoded intent + evidence references | decoder → policy/user/audit |
| `simulation-result.v1.json` | normalized simulation evidence with provenance & limitations | simulator → policy/user |
| `policy.v1.json` | machine-readable policy document | operator → policy engine |
| `policy-decision.v1.json` | deterministic decision + reason codes | policy engine → pipeline/audit |
| `detector-output.v1.json` | **pinned** from scam-guard (`../imports/scam-guard/`) — do not edit there | detector → risk aggregator |
| `risk-evidence-bundle.v1.json` | aggregated, conflict-preserving risk evidence | risk aggregator → policy/user |
| `signing-request.v1.json` | authorization-bearing request to the Vault (future IPC wire format) | pipeline → Vault |
| `signing-response.v1.json` | signature / refusal with terminal state | Vault → pipeline → caller |
| `audit-event.v1.json` | hash-chained lifecycle event | all components → audit log |
| `chain-registry-entry.v1.json` | chain identity + safety metadata | registry file |
| `rpc-profile.v1.json` | endpoint class + privacy notes | registry file |
| `agent-authorization.v1.json` | bounded agent capability (execution deferred) | operator → future agent runtime |

Cross-repo contracts are pinned under `../imports/scam-guard/` (`PIN.json` provenance) and published to siblings from `../exports/` (Arrow/Tarquin convention, register AC-001).
