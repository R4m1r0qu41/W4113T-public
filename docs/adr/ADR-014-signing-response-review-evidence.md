# ADR-014 — Signing-Response Review Evidence (schema v1.2, additive)

**Status:** Accepted · **Date:** 2026-07-09 · **Context:** Browser MVP shell (browser ADR-B003) needs to display *why* the wallet decided — decoded intent, simulation outcome, risk findings (incl. scam-guard), policy verdict/reasons — per browser-wallet protocol design rule 5 ("responses carry decision provenance so the browser can display *why*, without being able to alter *what*").

## Decision

Add an **optional, display-only** `review_evidence` object to `signing-response.v1` (additive minor bump, v1.2):

- `decoded_action`, `intent_confidence`, `simulation`, `risk_level`, `risk_findings[]` (detector / level / reason codes / explanation), `detectors_unavailable[]`, `policy_verdict`, `policy_reasons[]`.
- Assembled in `Pipeline::to_signing_response` from the same deterministic pipeline artifacts the trusted surface displays. Strings only. `risk_level: Unknown` is spelled out ("UNKNOWN — no evidence; never treated as low"), never softened.
- **No authority:** nothing wallet-side consumes the field; it cannot approve, override a denial, or downgrade risk. USER_REVIEW stays on the wallet-owned surface (`cipherlayer-vaultd`, ADR-012) regardless of what a consumer renders. Consumers rendering it must not present it as a confirmation surface (browser AGENTS #6 already binds the browser repo).
- Timing: the evidence arrives **with the terminal response** (after the trusted-surface decision), not before USER_REVIEW. Pre-decision evidence streaming is an explicit v0.4 open item in the protocol doc — deliberately deferred so the transport keeps its one-request/one-response shape.

## Consequences

- Schema `schemas/signing-response.v1.json` v1.2; export bundle `exports/browser-connect-v0.1/` refreshed (protocol doc updated to v0.3 reality: host_attest, concurrency, vault-confirm surface) and browser `imports/wallet/` re-pinned.
- Tests: provider unit test proves the field is optional/additive (old wire still parses, absent field omitted); browser-connect conformance tests assert a denial carries `policy_verdict: Deny` + POL codes and a confirmation carries simulation/risk evidence.
- Requirements matrix CL-PRV-003 updated.

## Alternatives considered

Carrying evidence in the schema's `ext` bag (rejected: untyped, invites drift); a two-phase evidence→decision protocol (rejected for now: real design work, tracked as the v0.4 pre-decision streaming item).
