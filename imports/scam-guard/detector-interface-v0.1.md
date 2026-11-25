# Detector Integration Contract — v0.1

**Status:** normative for consumers · **Owner:** scam-guard repository · **Date:** 2026-07-03

This is the versioned interface through which any consumer (CipherLayer Wallet risk center, CipherLayer Browser checks, future platform integrations) consumes Fraud Prevention Layer detectors. It is derived strictly from the unified stack scope (§3.2, §7); it does not commit to any particular detection technique or data source.

## 1. Model

A **detector** is a named component that examines a subject and returns zero or more **findings**. A finding is one `detector-output.v1.json` instance.

Subjects (v0.1): `domain`, `url`, `address` (EVM), `contract` (address + chain), `transaction_intent` (consumer-decoded intent), `message_text`. A detector declares which subject kinds it accepts.

## 2. Output requirements (normative)

Every finding MUST carry:

- `risk_level`: `low | medium | high | critical | unknown` — detector-local assessment. `unknown` is a legal, expected answer; consumers MUST NOT map it to `low`.
- `confidence`: number in [0,1] — how sure the detector is of its own finding.
- `reason_codes`: ≥ 1 code from the Reason Code registry (`schemas/reason-codes.v1.json`). Codes are stable, machine-readable, and defensible — a platform must be able to justify an action by citing them.
- `explanation`: human-readable, composed from the reason codes; never a verdict without reasons.
- `provenance`: detector name, version, evaluation timestamp, and data-source class (`local_heuristic | local_dataset | remote_feed | model_assisted`). `model_assisted` findings are advisory-grade by definition and MUST be marked so.
- explicit `subject` echo (what exactly was evaluated).

## 3. Consumer obligations (normative)

1. Preserve findings verbatim in any aggregate; never drop or rewrite them.
2. Aggregate `unknown` as `unknown` — absence of evidence is not evidence of safety.
3. Represent material disagreement between confident detectors as `conflicting`, with both findings visible.
4. Never present any finding or aggregate as a guarantee, and never use "safe" as an unqualified label.
5. Never allow a finding (or its absence) to *authorize* anything — findings inform deterministic consumer-side policy; they do not replace it.
6. Display or log detector provenance with the finding.

## 4. Versioning & distribution

- Contract version: `0.1.0`. Instances carry `schema_version`.
- Additive optional fields bump minor; breaking changes create `detector-output.v2.json` + migration note.
- **Distribution (family convention, per operator decision 2026-07-04 / wallet register AC-001):** this repository publishes release artifacts under `exports/` (versioned files + `SHA256SUMS`). Consumers pin them under `imports/scam-guard/` in their own repo: a `PIN.json` (Arrow/Tarquin format: `pin_schema_version`, `source_repo`, per-artifact `version`, `source_commit`, `source_path`, `sha256`, `pinned_at`, `purpose`) plus read-only copies of the pinned artifacts. A package/registry distribution is intended to replace copy-pinning; until then the commit hash + checksum is the pin.
- Update procedure: consumer re-copies from `exports/` at a chosen scam-guard commit, updates `PIN.json` (commit, hashes, date), runs its contract-conformance tests, notes the bump in its changelog/ADR if semantics changed. Pinned copies are never edited in place.

## 5. Reason Code registry

`schemas/reason-codes.v1.json` seeds the registry with codes required by the wallet consumer's first milestone (allowance/approval mechanics, domain lookalikes, drainer patterns, unknown/insufficient-data). Codes are namespaced `SG-<AREA>-<NNN>`, never reused, never renumbered; deprecation is a flag, not a deletion.

## 6. Explicit non-commitments (v0.1)

This contract does not define: detector discovery/registration protocol, transport (in-process vs service), rate limits, dataset formats, platform adapter APIs, or any specific detection technique. Those belong to the future FPL specification (see `docs/requirements-placeholder.md`).
