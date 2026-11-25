# ADR-002 — Independent Repositories Rather Than a Monorepo

**Status:** Accepted · **Date:** 2026-07-03

## Context

The product family has three components with different owners, lifecycles, and trust postures: the wallet trust core, the browser (a consumer, gated), and Scam Guard/FPL (a sibling product also licensable outside the stack). The build prompt §2 mandates three independent Git repositories under an organizational parent that is itself not a repository. (Prompt title of ADR-002 says "two repositories"; the operative instructions define three — recorded in the conflicts register.)

## Decision

Three independent Git repositories — `wallet/`, `browser/`, `scam-guard/` — under the non-versioned container `~/Dev/CipherLayer/`. No monorepo, no shared fourth repo, no parent `.git`. Cross-repo contracts travel as **versioned pinned artifacts** — producer `exports/` (+SHA256SUMS), consumer `imports/<sibling>/` with `PIN.json` (source, version, commit hash, checksum, update procedure; Arrow/Tarquin convention, operator decision 2026-07-04) — never as relative-path imports. Browser architecture and gate documents live in the browser repository (conflict AC-002).

## Alternatives considered

1. **Monorepo** — rejected: couples release lifecycles; makes it easy to blur the Vault boundary and to "borrow" wallet internals from browser code; complicates a future standalone Scam Guard licensing path.
2. **Monorepo with enforced workspace boundaries** — workable technically, rejected because FPL is explicitly a separate *product*, not a module.
3. **Fourth `shared/` repo** — rejected for milestone 1 (prompt §2.7): no real versioned cross-project artifact exists yet.

## Consequences

- Some duplication (each repo has its own README/AGENTS/gitignore/licensing) — accepted cost.
- Schema changes propagate by explicit vendoring with provenance, which is slower but auditable.
- A future package registry / git-tag release flow should replace copy-pinning (documented in each PIN.json).

## Security implications

Repo boundaries reinforce trust boundaries: browser code physically cannot import Vault internals; Scam Guard cannot grow dependencies on wallet secrets. Supply-chain review scope per repo stays small.

## Revisit conditions

If a real shared artifact emerges (e.g., a published `cipherlayer-contracts` crate/package), document owner/versioning/release/compat/security first (prompt §2.7) and record a new ADR.
