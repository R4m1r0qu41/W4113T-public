# Security Policy — CipherLayer Wallet

## Status

**Prototype. Not audited. Not for real funds.**

This repository is a security-conscious prototype of a wallet trust core. It has had **no independent security review**. The Vault signer is a test signer (mocked boundary); secure storage is not implemented; the audit log is tamper-evident but not immutable. The complete honest list is in [`docs/security/prototype-limitations.md`](docs/security/prototype-limitations.md), and every user-facing security statement is governed by [`docs/security/security-claims-register.md`](docs/security/security-claims-register.md).

## Rules this codebase enforces on itself

- Private keys never exist in presentation/renderer code; signing only behind the `cipherlayer-vault` interface.
- Deterministic validation for all security-critical decisions; AI/heuristics are advisory only and cannot override a denial.
- Default unlimited ERC-20 approval handling: **block** (escalation requires explicit policy).
- Simulation results are evidence, never guarantees, and carry provenance + freshness.
- Unknown or conflicting risk evidence is surfaced, never collapsed to "safe".
- Local chains / test keys by default; no real funds during prototype development.
- Mocked security boundaries are labeled in code and docs.

## Reporting a vulnerability

This is a private, pre-release repository with no public deployment. Report issues directly to the repository owner (operator). Include: affected component/crate, trust boundary crossed, reproduction steps, impact, and suggested mitigation. Do not open public issues for security reports if this repository ever becomes public.

## Scope of interest

Highest-value reports, in order:
1. Any path by which presentation code, a provider request, or a future plugin/browser surface can reach key material or trigger signing without crossing the Vault authorization boundary.
2. Policy-engine bypass (including via missing/undecoded fields, malformed envelopes, or state-machine skips).
3. Approval/permit detection gaps that would misclassify an unlimited or dangerous approval.
4. Audit-log chain forgery or silent truncation that `audit verify` does not detect.
5. Chain-identity confusion (wrong chain accepted, chain ID spoofing).

## Dependencies

Dependencies are pinned via `Cargo.lock` (committed). `make audit` runs `cargo audit` when installed; `make sbom` produces a CycloneDX SBOM when `cargo-cyclonedx` is installed. Both are documented, optional developer tooling — absence of findings is not a security claim.
