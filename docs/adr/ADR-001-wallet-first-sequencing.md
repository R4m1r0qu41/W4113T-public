# ADR-001 — Wallet-First Sequencing

**Status:** Accepted (locked by product decision) · **Date:** 2026-07-03

## Context

Both source scopes describe a wallet **and** a browser sharing one trust spine (Vault + risk interface). The Unified Scope §11 locks the sequencing decision: build the wallet before the browser, for four stated reasons — the Vault is the trust anchor and must exist before consumers; value ships sooner; parallel development historically yields a feature-poor wallet next to a heavy browser; wallet-first fixes the module boundaries the browser then integrates. The build prompt §3 restates this as a governing product decision.

## Decision

Implement the wallet trust spine first: Vault interface, transaction-intent model, decoder, simulation adapter, policy engine, audit log, and CLI — all in the `wallet` repository. The `browser` repository receives only architecture documents, interfaces, threat models, and (later) narrow compatibility experiments until the Wallet MVP gate (ADR-010) is met.

## Alternatives considered

1. **Browser-first** — rejected: the browser is a consumer of a trust core that would not exist; highest-cost surface (Chromium maintenance) before any validated value.
2. **Parallel tracks** — rejected: reproduces the divergence risk the merge was designed to eliminate (two teams deciding the highest-risk module independently).
3. **Extension-first proof** (BS §8.1) — deferred, not rejected: a cheap compatibility harness remains an option *after* the provider contract stabilizes.

## Consequences

- First credible product is a CLI-driven signing pipeline on a local chain, not a GUI.
- The browser repo stays documentation-only this milestone; its roadmap is gated, not scheduled.
- The provider/browser-connect contract must be published from the wallet repo early so browser design can proceed on paper.

## Security implications

Positive: the minimal trusted computing base is designed and tested without renderer/attack-surface pressure. Risk: interfaces designed without a live consumer may need revision — mitigated by versioned schemas with explicit compatibility strategy.

## Revisit conditions

Only if the operator explicitly reverses the locked decision, or if wallet-phase learnings invalidate the browser integration model (record a superseding ADR).
