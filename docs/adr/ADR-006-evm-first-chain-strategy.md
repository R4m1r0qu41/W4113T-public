# ADR-006 — EVM First-Chain Strategy

**Status:** Accepted · **Date:** 2026-07-03

**Amended by:** ADR-015 (multi-chain adapter gate; non-EVM chains and EVM L2s) with ADR-016 (Solana) and ADR-017 (Bitcoin).

## Context

US §4.3 warns against "the multi-chain monster"; US §13/§16 answer the first-chain question with "Ethereum"; BS §8.6 recommends one EVM chain initially, expansion only via adapters. The prototype must not touch real funds (BP §4.14).

## Decision

- **Chain family:** Ethereum/EVM semantics only for milestone 1.
- **Execution target:** local **Anvil** chain, chain-id **31337**, as the sole default. Ethereum mainnet (1) and Sepolia (11155111) exist in the chain registry as metadata with `network_class` markers (`mainnet` / `testnet` / `development`) — the registry refuses signing defaults to anything not `development` in this milestone.
- **Extension path:** additional chains are registry entries + adapter implementations behind the `cipherlayer-chain` / `cipherlayer-evm` boundaries; non-EVM chains (Solana, Bitcoin, Cosmos) are **deferred** and require a new ADR each.

## Alternatives considered

1. **Sepolia testnet first** — rejected as default: external RPC dependency, faucet friction, non-reproducible tests; kept as a registry entry.
2. **Multi-EVM at MVP** — rejected: multiplies decoding/simulation edge cases before the pipeline is trustworthy on one chain.
3. **Hardhat node** — rejected: Foundry/Anvil already installed, faster, has snapshot/impersonation RPCs the simulation adapter uses.

## Consequences

- Chain-ID validation is strict and testable (wrong-chain requests are a security regression test).
- All balance/allowance semantics are exercised against real EVM state transitions locally.

## Security implications

Chain-identity confusion is a first-class threat (threat model T-09); a single-chain default with an explicit `development`-only signing gate minimizes it during prototyping.

## Revisit conditions

Wallet MVP gate passage (public-testnet enablement decision); first institutional requirement naming a specific L2; any non-EVM demand.
