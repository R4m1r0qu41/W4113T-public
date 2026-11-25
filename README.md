# CipherLayer Wallet (W4113T)

**Never sign blind.** A modular, self-custody wallet trust core: transaction requests are validated, decoded, simulated, risk-evaluated, policy-checked, explicitly authorized, signed through a separated Vault interface, broadcast on a local EVM chain, and reconstructed from an auditable event trail.

**Status: prototype.** No component in this repository is production-ready or security-audited. All development targets local chains (Anvil) and test keys. **Do not use real funds or real keys.** See [`docs/security/prototype-limitations.md`](docs/security/prototype-limitations.md) for the honest list of what is real and what is mocked.

This is the **primary implementation repository** of the CipherLayer Web3 Stack (wallet-first, per ADR-001). The sibling repositories are [`../browser/`](../browser/) (integration surface, gated behind Wallet MVP) and [`../scam-guard/`](../scam-guard/) (external fraud-detection dependency, consumed through a versioned detector interface).

## What works today (vertical slice)

A CLI-driven end-to-end signing pipeline on a local Anvil chain:

1. Anvil starts; a sample ERC-20 token and spender contract are deployed.
2. A transaction request (envelope) is received and validated.
3. Calldata is decoded (ERC-20 `approve`/`transfer`, permit detection) into a versioned **transaction intent**.
4. The transaction is **simulated** on Anvil (snapshot → execute → diff → revert); balance and allowance changes are normalized.
5. The **risk adapter** runs the pinned Scam Guard detector as a bounded subprocess by default (ADR-018) and returns structured evidence with reason codes; detector failure surfaces as `detectors_unavailable`, never a quiet all-clear.
6. The **policy engine** produces a deterministic, reasoned decision — unlimited ERC-20 approvals are blocked/escalated by default.
7. On explicit authorization, the **Vault** — now its own OS process (`cipherlayer-vaultd`, ADR-004) with a trusted confirmation surface (ADR-012); test keys only — signs; the transaction is broadcast.
8. Every step is written to a hash-chained, append-only **audit log** the CLI can inspect and verify.

Landed beyond the slice: the browser-connect transport at **protocol v0.3** (host-attested, concurrent Unix socket — ADR-013; signing-response v1.2 `review_evidence`, ADR-014) that the browser shell consumes; a real **MetaMask external-signer** lifecycle verified on Sepolia (ADR-011, CL-WAL-010); a **mainnet external-signer exception** for EVM (ADR-020) and a **Solana external signer** behind the vault process boundary — devnet gate passed live, mainnet gate passed after external re-audit (ADR-021, CL-WAL-011); the **multi-chain adapter program** (ADR-015) with EVM-L2 registry entries, a Solana adapter (ADR-016), and a Bitcoin P2WPKH adapter (ADR-017); **recipient aliases** for the console send flow (case-insensitive, fail-closed on ambiguity); and a **presentation-only desktop prototype** (`apps/desktop` — no keys, no authority).

## Quick start

Prerequisites: Rust (stable, ≥1.85), [Foundry](https://getfoundry.sh) (`anvil`, `forge`, `cast`), GNU Make.

```bash
make bootstrap      # check prerequisites, build workspace
make test           # unit tests (no network, no chain)
make anvil-up       # start local Anvil chain (port 8545)
make test-integration  # integration tests against Anvil
make demo           # full vertical-slice demonstration
make anvil-down
```

Inspect the lifecycle after a demo:

```bash
cargo run -p cipherlayer-cli -- audit inspect
cargo run -p cipherlayer-cli -- audit verify
```

All commands: `make help` or see [`Makefile`](Makefile). CLI reference: `cargo run -p cipherlayer-cli -- --help`.

### Interactive console (W4113T)

```bash
make console
```

launches the oldschool interactive operator console — a menu over status, chains, decode, policy, audit, permissions, vault lock, and the Sepolia external-signer flow. For an even shorter invocation, add an alias to your own shell rc (not set up for you — this repo never touches files outside itself):

```bash
alias w4113t='cargo run -q --manifest-path /path/to/wallet/Cargo.toml -p cipherlayer-cli -- console'
```

## Repository layout

```text
crates/
  cipherlayer-types/       shared deterministic types (no business logic)
  cipherlayer-vault/       signer abstraction, test signers, lock state, capability checks  [test keys only]
  cipherlayer-vaultd/      Vault OS process — pinned IPC, trusted confirmation surface (ADR-004/ADR-012)
  cipherlayer-policy/      machine-readable policy, deterministic evaluation, reason codes
  cipherlayer-chain/       chain registry, RPC profiles, chain-identity safety metadata, ChainAdapter boundary (ADR-015)
  cipherlayer-evm/         calldata decoding, approval/permit detection, EVM validation
  cipherlayer-sol/         Solana adapter + ed25519 signing (ADR-016)
  cipherlayer-btc/         Bitcoin adapter + P2WPKH signing (ADR-017)
  cipherlayer-intent/      canonical versioned transaction-intent model
  cipherlayer-simulation/  provider-neutral simulation adapter + Anvil implementation
  cipherlayer-risk/        detector consumer interface — managed Scam Guard execution (ADR-018); mock detector for tests
  cipherlayer-audit/       append-only, hash-chained audit event log (tamper-evident, not immutable)
  cipherlayer-provider/    wallet-provider request envelope, permission scopes, routing
  cipherlayer-cli/         command-line interface and demo driver
schemas/                   versioned JSON Schemas (source of truth for wire formats)
fixtures/                  sample contracts (Foundry project), test vectors
docs/                      architecture, threat model, requirements, ADRs, security, legal
scripts/                   anvil lifecycle, demo, docs checks
tests/                     cross-crate integration & security regression tests (in cipherlayer-cli/tests)
apps/desktop/              presentation-only desktop prototype — no key material, no policy authority
```

## Trust model in one paragraph

The **Vault** is the only component that may authorize a signature; everything else receives capabilities, never keys. Presentation code (CLI today, desktop later, browser much later) never holds key material. Security-critical decisions (policy, chain identity, approval limits) are deterministic; AI/heuristic components may only explain or flag. Simulation is evidence, not a guarantee. Unknown or conflicting risk evidence stays visible — it is never collapsed into a binary "safe/unsafe". See [`docs/architecture/trust-boundaries.md`](docs/architecture/trust-boundaries.md).

## Component status labels

Per [`docs/security/prototype-limitations.md`](docs/security/prototype-limitations.md), every major component is labeled **production-ready / prototype / experimental / mocked / deferred / theoretical**. Today nothing is production-ready; the Vault signer and secure storage are **mocked**; the pipeline, policy engine, decoder, simulation adapter, and audit log are **prototype**.

## Documentation map

- [`docs/requirements/requirements-matrix.md`](docs/requirements/requirements-matrix.md) — requirement IDs, ownership, phase, status
- [`docs/requirements/ambiguities-and-conflicts.md`](docs/requirements/ambiguities-and-conflicts.md) — contradiction register
- [`docs/adr/`](docs/adr/) — Architecture Decision Records (ADR-001…ADR-018)
- [`docs/architecture/`](docs/architecture/) — system overview, trust boundaries, data flow, signing state machine, browser-wallet protocol
- [`docs/threat-model/`](docs/threat-model/) — STRIDE threat model and abuse cases
- [`docs/security/`](docs/security/) — security-claims register, prototype limitations
- [`docs/legal/`](docs/legal/) — legal and regulatory issues register
- [`docs/roadmap/`](docs/roadmap/) — implementation roadmap and gates

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Contributions require a DCO `Signed-off-by` line; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
