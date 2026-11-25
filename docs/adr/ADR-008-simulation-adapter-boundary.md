# ADR-008 — Simulation Adapter Boundary

**Status:** Accepted · **Date:** 2026-07-03

## Context

Simulation must run before signing and report balance changes, approvals, reverts, and gas — while remaining evidence, not a guarantee (BS §6.6; BP §4.9). Sources vary (local fork, RPC `eth_call`, trace APIs, third-party services) and can disagree; conflicting results must be representable (BP §6.2).

## Decision

- A provider-neutral trait `SimulationProvider` in `cipherlayer-simulation`, returning a **normalized `SimulationResult`** (schema `simulation-result.v1.json`) carrying: outcome (success/revert/failed-to-simulate), balance diffs, allowance diffs, gas used, revert reason, **provider provenance, block context, timestamp/freshness, and an explicit limitations list**.
- Milestone-1 implementation: **AnvilSimulator** — against the local Anvil chain, using `evm_snapshot` → impersonated execution (`anvil_impersonateAccount` + `eth_sendTransaction`) → state diff reads (balances/allowances of interest) → `evm_revert`. This yields real EVM state transitions, not estimates.
- Simulation failure is a first-class pipeline state (`SIMULATION_FAILED`) — the pipeline never silently proceeds past it, and a failed simulation can never be presented as a successful one.
- Multi-provider comparison and conflict surfacing: type-level support (`SimulationEvidence` holds N results and a `conflicts` marker), implementation deferred.

## Alternatives considered

1. **`eth_call` + `eth_estimateGas` only** — cheaper but blind to state diffs (allowance/balance changes); rejected as primary, viable as a future lightweight provider.
2. **Third-party simulation API** (Tenderly-style) — network + privacy dependency; deferred as optional adapter per BS §6.6.
3. **In-process REVM fork** — attractive later (no RPC round-trips); deferred to keep milestone-1 dependency surface small.

## Consequences

- Simulation requires a running Anvil node; integration tests and demo manage one via `make anvil-up`.
- Because execution happens on the same node that will broadcast, prototype "simulation vs execution divergence" is minimal — which is *unrepresentative* of mainnet reality; the normalized result's limitations field says so explicitly.

## Security implications

Simulation-mismatch is threat T-11; provenance + freshness + limitations fields keep the evidence honest. The simulator holds no signing authority (Zone E rule).

## Revisit conditions

Adding any remote provider (privacy review required); mainnet/testnet enablement; conflicting-provider aggregation implementation.
