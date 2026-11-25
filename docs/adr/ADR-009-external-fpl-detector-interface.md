# ADR-009 — External FPL Detector Interface

**Status:** Accepted · **Date:** 2026-07-03

## Context

The Fraud Prevention Layer (Scam Guard) is a sibling product and external dependency (US §7). The Stack's risk engine is a *consumer* of FPL's detector interface — risk score, confidence, machine-readable Reason Codes, explainable rationale, no opaque AI-only verdicts (US §3.2). No standalone FPL specification exists locally, so the prompt (§2.4, §19) prescribes: define a versioned adapter boundary and a requirements placeholder without inventing product requirements; provide a mock detector; do not rebuild FPL.

## Decision

- **Ownership:** the detector contract is owned and versioned by the `scam-guard` repository (`contracts/detector-interface-v0.1.md` + `schemas/detector-output.v1.json` + `schemas/reason-codes.v1.json`).
- **Consumption:** the wallet pins a read-only copy under `imports/scam-guard/` with `PIN.json` provenance (source repo, version, commit hash, sha256 checksum, update procedure — Arrow/Tarquin format, operator decision 2026-07-04). `cipherlayer-risk` implements the consumer side: a `Detector` trait, output normalization, aggregation into a `RiskEvidenceBundle`.
- **Semantics fixed at v0.1:** risk levels `low | medium | high | critical | unknown | conflicting`; confidence in [0,1]; every finding carries ≥1 Reason Code from the registry (`SG-` prefix) plus provenance; aggregation never drops evidence, and **unknown/missing detector output aggregates to `unknown`, never to `low`**; conflicting detectors aggregate to `conflicting` with both sides visible.
- **Mock:** `MockDetector` (labeled) provides deterministic evidence for tests/demo (e.g., flags unlimited approvals with `SG-ALLOW-001`).

## Alternatives considered

1. **Define the contract in the wallet repo** — rejected: inverts the mandated dependency direction (scam-guard → wallet).
2. **Skip the risk layer until FPL exists** — rejected: the pipeline's `RISK_EVALUATED` state and the unknown/conflict semantics are architectural now; retrofitting honesty semantics later is exactly the failure mode BP §4.18 warns about.
3. **Runtime path import from `../scam-guard/`** — rejected (prompt §2.6): no filesystem coupling; pinned copies with checksums instead.

## Consequences

- Two copies of the contract exist (owner exports/ + consumer imports/); drift is detectable via recorded checksum and version.
- The full FPL detector engine (phishing feeds, drainer patterns, platform adapters) remains **deferred** and out of this repo permanently.

## Security implications

Risk evidence is advisory input to the deterministic policy engine — it can escalate but never authorize; a detector (or its absence) can never downgrade a policy denial. Regression-tested.

## Revisit conditions

First real Scam Guard detector implementation; contract v0.2; a package-registry distribution replacing copy-vendoring.
