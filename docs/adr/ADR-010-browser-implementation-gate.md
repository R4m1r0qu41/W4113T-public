# ADR-010 — Browser Implementation Gate

**Status:** Accepted · **Date:** 2026-07-03

**Amended by:** browser ADR-B003 (accepted 2026-07-07), which opened the gate for the Tauri/system-WebView local/dev-chain MVP shell under its recorded compensating control. Browser implementation still lives in the browser repository, never in this one.

## Context

The browser is the wallet's most powerful integration surface and its most expensive, highest-risk build (BS §2, §13). The Unified Scope gates browser work behind Wallet MVP (W2 "Wallet MVP proven → unlock browser", US §12); the prompt forbids a Chromium fork and any browser implementation focus before the gate (BP §3, §7).

## Decision

Browser **implementation** (any shell code, provider injection, rendering integration) is blocked until all gate criteria hold:

1. Wallet vertical slice is stable: validate → decode → simulate → risk → policy → authorize → sign → broadcast → audit, with passing unit/integration/security-regression suites.
2. The Vault process boundary is real (ADR-004 process split done), not in-process.
3. The browser-connect/provider contract (`schemas/` + `docs/architecture/browser-wallet-protocol.md`) is versioned and has survived at least one consumer exercise (e.g., a test harness driving it end-to-end).
4. Desktop wallet UI (W2) demonstrates the trusted-confirmation flow outside the CLI.
5. Threat-model extension for the browser (in the browser repo) is reviewed.
6. Operator explicitly opens the gate.

Until then the browser repo contains only: documentation (trust zones, capsule model, broker, confirmation-surface requirements, protocol, compatibility test plan, engine comparison, threat extension, Web2 competency requirements, this gate's checklist mirror), contracts pinned from the wallet (imports/wallet/PIN.json), and — after criteria 1–3 — *narrow* compatibility experiments (e.g., a provider-injection harness), never a shell build.

The full checklist lives at `browser/docs/architecture/browser-mvp-gate.md` and is the operative copy.

## Alternatives considered

1. **Time-based gate** — rejected: the gate is about trust-core stability, not calendar time.
2. **Extension-first PoC now** — rejected for milestone 1; explicitly allowed as the *first* post-gate experiment (cheapest credible harness, BS §8.1).

## Consequences

Browser ambitions cannot dilute the wallet trust core; browser design work proceeds on paper against versioned contracts.

## Security implications

Prevents the historical failure mode (heavy browser, weak wallet) and keeps keys away from any renderer until the Vault is process-isolated.

## Revisit conditions

Gate review upon W2 completion; any operator instruction to change the gate (record superseding ADR).
