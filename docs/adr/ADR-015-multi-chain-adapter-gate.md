# ADR-015 — Multi-Chain Adapter Gate (Bitcoin · Solana · Tezos · EVM L2s)

**Status:** Accepted · **Date:** 2026-07-10

> Operator accepted 2026-10-13. Phases (a)–(d) shipped while this ADR was still marked Proposed (adapter trait, EVM L2s, Solana, Bitcoin); phase (e) Tezos is pending and needs its own ADR.

## Context

ADR-006 locked milestone 1 to EVM/Anvil and deferred non-EVM chains, each behind its own ADR. The operator has now explicitly requested the "full chain stack": Bitcoin, Solana, Tezos, and EVM L2s. AGENTS.md forbids multi-chain code without an explicit ADR — this is that ADR, opening the gate as a *program* decision: it defines the adapter boundary, sequencing, and the invariants every chain adapter must satisfy. Each non-EVM chain still gets a short per-chain ADR (ADR-016+) recording its concrete client library, local test network, and signing scheme before its adapter merges.

## Decision

1. **Adapter boundary.** A new trait, `ChainAdapter`, lives in `cipherlayer-chain` (which already owns the registry and the `network_class` signing gate). `cipherlayer-evm` becomes the first adapter implementation. Adapters own: address parsing/validation, transaction building, fee estimation, broadcast, and chain-identity verification. Adapters do **not** own: policy, risk, approval limits, or the signing state machine — those stay deterministic and chain-agnostic in their existing crates.
2. **Signing stays in the vault.** Each chain's signature scheme (secp256k1/ECDSA, ed25519, Schnorr/taproot, tz1/ed25519) is added behind the `cipherlayer-vault` interface. No adapter, CLI, or presentation path ever touches key material (unchanged invariant).
3. **Development-network-only gate extends per chain.** The registry's `network_class` gate applies uniformly: Bitcoin regtest / local pruned node, `solana-test-validator`, Tezos sandbox (flextesa or equivalent), Anvil-forked L2s. Mainnets/testnets are registry metadata only, exactly as ADR-006 established for EVM.
4. **Sequencing.** (a) `ChainAdapter` trait + EVM adapter refactor (no behaviour change, existing tests green); (b) EVM L2s — registry entries + Anvil-fork profiles, cheapest win since they reuse the EVM adapter. Each L2 appears twice in the registry: the real chain as Mainnet-class identity metadata (signing refused), and a Development-class Anvil-fork entry whose chain id is **remapped** to a local id (31338+, via `anvil --fork-url … --chain-id <dev id>`). The remap is a security decision: the real L2 chain id can never satisfy the development signing gate, and the pipeline's pre-simulation chain-identity check refuses a fork entry whose node still reports the upstream id; (c) Solana (local infra exists at `~/Dev/solana-lab`); (d) Bitcoin (local pruned node exists); (e) Tezos last (least local prior art).
5. **Per-chain tooling** (client crates, exact local-node wiring) is recorded in the per-chain ADRs. A prior-art survey of the Arrow repo (2026-07-10) fixes the starting points:

   | Chain | Client crates (signing path) | Local test infra | Prior art |
   |---|---|---|---|
   | EVM + L2s | `alloy` (already in use) | Anvil 1.7.1; L2s as Anvil-fork registry profiles | Arrow collapses L2s to "EVM lib + chain-config shell" (`arrow-origin-{arb,base}` are config-only over `arrow-origin-evm`) — copy that |
   | Solana | split `solana-{keypair,signer,message,transaction}` 3.x + `litesvm` for in-process tests | Agave 3.1.15 + `solana-test-validator` installed; Anchor localnet harness in `~/Dev/solana-lab/test_project` | Arrow's `arrow-origin-sol` (commitment-based finality, `getGenesisHash` network binding) is read-only; crate choices come from solana-lab |
   | Bitcoin | `rust-bitcoin` + `bitcoincore-rpc` | bitcoind v31 installed; pruned-mainnet (rpcport 28335) and signet nodes configured with launchers in `Arrow/tools/lifecycle-tests/`; regtest for signing tests | Arrow's `arrow-origin-btc` (per-chain `ObservedUtxo`, depth-based finality) is read-only |
   | Tezos | greenfield — no Arrow prior art, no local tooling installed (`octez-client`/flextesa absent); per-chain ADR must choose crates and install sandbox first | none yet | none |

   Design lessons adopted from Arrow's adapter layer (`arrow-adapter/src/traits.rs`): split observe (read) from settle (write) traits with per-chain associated observation types — no lowest-common-denominator transaction struct; layer pure mapping between RPC I/O and domain events so signing logic never entangles with RPC; fail closed on network/chain-id mismatch before acting. Deliberate divergences: use real SDKs on the signing path (Arrow's hand-rolled JSON-RPC suits observers only), and make the trait `async` on the existing runtime (no per-call runtimes).

## Alternatives considered

1. **Stay EVM-only, add chains on demand** — rejected: operator direction is explicit, and the adapter refactor is cheaper now than after more EVM-coupled features accrete.
2. **One mega-ADR fixing all tooling today** — rejected: crate choices per chain deserve their own evidence and revisit conditions; this ADR opens the gate and fixes the boundary only.
3. **Separate crate per chain importing a shared trait crate** — accepted in spirit: adapters land as `cipherlayer-<chain>` crates depending on `cipherlayer-chain`, mirroring `cipherlayer-evm`.

## Consequences

- Requirements matrix gains a multi-chain section; each adapter lands with wrong-chain / wrong-network-class security regression tests (T-09 extends to every chain family).
- Intent decoding, simulation, and risk currently assume EVM semantics; non-EVM adapters must surface `unknown` for any evidence dimension they cannot produce — never a silent "low risk" (existing invariant, restated because it bites hardest here).
- CLI/console gains a chain selector; presentation only.

## Security implications

Multi-chain multiplies chain-identity confusion (T-09), address-format spoofing, and fee-unit confusion (wei vs lamports vs sats vs mutez). Mitigations: adapters must render amounts with explicit unit + chain badge; address validation is per-adapter and strict; the state machine and audit log record `chain_id` on every transition.

## Revisit conditions

Any chain requiring a remote-only test network; any adapter needing key material outside the vault boundary (hard stop, redesign); MVP gate review.
