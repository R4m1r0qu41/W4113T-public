# ADR-016 — Solana Adapter (ADR-015 phase c)

**Status:** Accepted · **Date:** 2026-07-10

> Operator accepted 2026-10-13. Implemented while still marked Proposed; the shared-pipeline evidence concern is closed by the chain-family gate (CL-WAL-015).

## Context

ADR-015 opened the multi-chain gate and requires a per-chain ADR before any
non-EVM adapter merges. Solana is phase (c): local infrastructure exists
(Agave 3.1.15 with `solana-test-validator`; an Anchor localnet harness at
`~/Dev/solana-lab/test_project`), and the crate choices are already
proven there.

Solana differs from EVM in three ways that matter to CipherLayer's
invariants: it has **no numeric chain id** (network identity is the genesis
hash), it signs with **ed25519** (not secp256k1/ECDSA), and its transaction
model is message + recent blockhash, not nonce + gas.

## Decision

1. **Crates** (versions proven in solana-lab): `solana-keypair` 3.0,
   `solana-signer` 3.0, `solana-message` 3.0, `solana-transaction` 3.0 for
   message construction and signing types; `litesvm` 0.10 for in-process
   tests; `solana-rpc-client` 3.x for RPC transport. No monolithic
   `solana-sdk` dependency.
2. **Adapter crate.** `cipherlayer-sol` implements
   `ChainObserver`/`ChainBroadcaster` from `cipherlayer-chain::adapter`:
   address (base58 pubkey) parsing, unsigned system-transfer message
   building (fetching the recent blockhash), broadcast of already-signed
   bytes, and status by signature. It never touches key material.
3. **Chain identity = genesis hash.** The registry keeps its internal u64
   `ChainId` as the lookup key; non-EVM entries claim the reserved band
   **900000–999999** (900001 = Solana local test validator, Development
   class). A band, not "≥900000": real EVM chain ids also live above it
   (Sepolia is 11155111), so only the bounded range is internal. The entry
   records the *expected genesis hash* where known; the local validator's
   genesis hash is not stable across resets, so the Development entry
   verifies reachability + cluster sanity instead, and any future
   testnet/mainnet metadata entry must pin its well-known genesis hash
   (mainnet `5eykt4...`, devnet `EtWTRA...`) and fail closed on mismatch
   (T-09).
4. **ed25519 signing lives behind the vault.** A Solana signer is added to
   `cipherlayer-vault` behind the same `network_class` development-only
   gate, capability checks, and authorization re-validation as the EVM
   signer. Test keys only (generated or `~/.config/solana/id.json` style
   dev keys); key material never appears in the adapter, CLI, or logs.
5. **Evidence stays honest.** Intent decoding, simulation, and risk are
   EVM-only today. Solana requests must surface `unknown` for every
   evidence dimension they cannot produce — never a silent "low risk"
   (ADR-015 restated). Full pipeline integration is follow-up work, not
   part of this ADR's scope.
6. **Units.** Amounts render as lamports with an explicit unit + chain
   badge (ADR-015 security implication); 1 SOL = 10^9 lamports
   (`native_decimals: 9`).

## Alternatives considered

1. **Monolithic `solana-sdk`** — rejected: deprecated direction upstream;
   the split crates are smaller, and solana-lab already validates them.
2. **Hand-rolled JSON-RPC (Arrow style)** — rejected for the signing path
   per ADR-015; acceptable only for read-only observers.
3. **Reusing EVM `ChainId` semantics for Solana clusters** — rejected:
   inventing fake numeric ids that look like EVM chain ids invites
   confusion; the reserved 900000–999999 ids are clearly internal and never appear
   on any wire.

## Consequences

- `cipherlayer-types` gains nothing: `ChainId` stays u64; the genesis-hash
  identity lives in the registry entry and adapter.
- Requirements matrix CL-WAL-003 gains a phase (c) note; wrong-cluster and
  wrong-network-class regression tests are mandatory before merge.
- The vault grows a second signature scheme; its refusal paths (locked,
  expired capability, non-development network) must be tested for the
  Solana signer independently.

## Security implications

Genesis-hash verification replaces chain-id verification as the T-09
control. Base58 address validation is strict (length + decode). Fee/unit
confusion (lamports vs wei) is mitigated by explicit unit labels. The
ed25519 signer is gated identically to ECDSA — no path may sign for a
non-Development registry entry.

## Revisit conditions

Solana testnet/devnet enablement (requires pinned genesis hashes and the
MVP gate review); versioned transactions / priority fees beyond simple
transfers; any need for key material outside the vault (hard stop).
