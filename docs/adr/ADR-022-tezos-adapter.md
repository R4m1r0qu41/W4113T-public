# ADR-022 — Tezos Adapter (ADR-015 phase e)

**Status:** Proposed · **Date:** 2026-10-13 · **Decider:** operator (open: crate choice, §2) · Requirements row: CL-WAL-014

## Context

ADR-015 phase (e). Bitcoin (ADR-017) and Solana (ADR-016/021) shipped; Tezos is
greenfield: there is no Arrow prior art, no registry entry, no crate and **no local tooling**.
Checked on the development machine on 2026-10-13 (macOS, arm64): `docker`, `octez-client`,
`octez-node`, `tezos-sandbox`/Flextesa and `opam` are all absent.

Tezos differs from EVM, Solana and Bitcoin in ways that matter to the vault:

- Accounts are account-based with a per-account **counter**; the first operation from an
  implicit account (`tz1…`/`tz2…`/`tz3…`) must be preceded by a **reveal** of its public key.
- An operation is a binary-forged byte string whose signing input is
  `blake2b-256(0x03 ‖ forged_bytes)` (the `0x03` generic-operation watermark). The signed
  bytes include `branch` (a recent block hash that expires), so a signature is only valid
  for a short window and for one chain.
- Fee, gas limit and storage limit are all chosen by the builder, not refunded. Overpaying
  is a real loss, as with Bitcoin fees.
- Chain identity is a Base58 `chain_id` (`Net…`) derived from the genesis block hash;
  there is no numeric chain id.
- Units are mutez (6 decimals, symbol `XTZ`).

## Decision

1. **Scope: transfers only, `tz1` (ed25519) only, development network only.** One
   implicit-account → implicit-account transfer, optionally preceded by one reveal in the
   same batch. No contract calls, delegation, staking, FA tokens, smart rollups, `tz2`/`tz3`
   keys or batches beyond reveal + transfer. Each is a later ADR. `tz1` keeps the signing
   scheme identical to the existing ed25519 `SolVault` path.
2. **Crates (operator decision required).** ADR-015 forbids hand-rolled consensus code on the
   signing path; operation forging is consensus-critical.

   | Option | What | Facts checked 2026-10-13 | Assessment |
   |---|---|---|---|
   | A. `tezos_crypto_rs` + `tezos_data_encoding` | Address, key, hash and operation encoding from the `trilitech/tezedge` fork | `tezos_crypto_rs` 0.6.0, MIT, MSRV 1.64, 6 versions, **last release 2024-07-02** | Real SDK, but no release in 15 months; wide dependency tree. Needs `cargo audit`/`cargo deny` review and a pin. **Recommended**, with the exit condition below |
   | B. RustCrypto parts (`ed25519-dalek`, `blake2`, a Base58Check crate) + node-side forging | Vault only hashes, signs and *independently decodes* the forged bytes the node returns | Small tree, all actively maintained | Avoids an aging SDK. Needs a hand-written **decoder** for the reveal and transaction operations; the decoder is the security check and must be tested against vectors from a real node |
   | C. Octez `octez-client` as a subprocess signer | Node tooling signs | — | **Rejected**: key material would live in a tool outside the vault boundary (hard-stop invariant), as ADR-017 §Alternatives 1 |

   Recommendation: A for decoding and address handling, node-side `forge/operations` for
   building (untrusted input), with the vault re-decoding the exact bytes it is about to sign
   (the ADR-021 §2 pattern). **Exit condition:** if A's dependency tree fails `cargo audit`
   or the crate is flagged unmaintained, fall back to B without changing the vault interface.
3. **Adapter crate `cipherlayer-tez`** implements `ChainObserver`/`ChainBroadcaster`:
   network-strict `tz1` parsing, unsigned operation building from node-provided
   counter/branch/protocol, broadcast of signed bytes (`injection/operation`), status by
   operation hash. No key material, no signing.
4. **Chain identity = `chain_id` + genesis block hash.** Registry reserves internal id
   **900003** (band 900000–999999, ADR-016) for "Tezos sandbox (local development)",
   Development class, `native_symbol` `XTZ`, `native_decimals` 6 (mutez); `ChainFamily::Tezos`
   is added as an additive schema v1.2 change to `schemas/chain-registry-entry.v1.json`.
   `verify_chain_identity` compares `/chains/main/chain_id` **and** the hash of block 0 with
   pinned values and **fails closed** on mismatch or unreachable node (T-09). The pinned
   values are obtained by running the sandbox once and recording them with the ceremony
   evidence; they are never typed from memory. Mainnet and testnets get no signable entries.
5. **Signing stays in the vault.** A `TezVault` signs `blake2b-256(0x03 ‖ bytes)` with the
   same gates as the other schemes: lock, verdict finality, Development-only network class,
   capability re-validation. The mutez cap is decoded from the operation bytes themselves,
   never from a caller-declared amount; ephemeral test keys, no import path, Debug-redacted.
   External-signer ceremonies for Tezos would need their own ADR, as for Solana (ADR-021).
6. **Fee discipline.** `fee`, `gas_limit`, `storage_limit` and a mutez `max_fee` are
   **required** builder inputs with no defaults; the cap is enforced before building and
   re-derived from the decoded bytes in the vault. Branch must come from a block no older
   than a fixed bound, re-fetched after approval, as the Solana blockhash.
7. **Evidence stays honest.** Intent, simulation and risk for Tezos are `unknown`; the shared
   EVM pipeline already refuses non-EVM families (`UnsupportedChainFamily`, CL-WAL-015), so
   `ChainFamily::Tezos` is refused there from day one. The only signing path is a
   family-specific ceremony that records `unknown` evidence and escalates.

## Tooling that must be installed before any code

| Need | Candidate | Source | Note |
|---|---|---|---|
| Container runtime | Docker (or a compatible runtime) | docker.com | Required by both container sandboxes below. Absent today |
| Local sandbox | **Flextesa**, image `oxheadalpha/flextesa:latest`, `oxfordbox`-style script, port 20000, `block_time` configurable, manual baking | docs.tezos.com/developing/sandbox | Matches ADR-015 §3 ("flextesa or equivalent"). Image tag must be pinned by digest; the docs page example names an older protocol script, so confirm the current script name |
| Alternative sandbox | Tezbox, `ghcr.io/tez-capital/tezbox:tezos-v22.1`, RPC on 8732 | docs.tezos.com/developing/sandbox | Needs a local Octez client. The page's version text is inconsistent (v22.1 tag vs "Octez 19.1"), so verify at install time |
| Client / RPC debugging | `octez-client` (+ `octez-node` if not using a container) | octez.tezos.com/docs/introduction/howtoget.html | Docs list a Homebrew formula for macOS that compiles Octez; the exact tap and arm64 behaviour were **not** verified here. Inside the Flextesa image the client is preinstalled, so a host install is optional |
| Rust crates | `tezos_crypto_rs`, `tezos_data_encoding` (option A) or `ed25519-dalek`, `blake2`, a Base58Check crate (option B) | crates.io | Pin exact versions; run `cargo audit` and review the lockfile diff in the same commit as the first use |

Install order: Docker → pin and pull the Flextesa image → record chain id and block-0 hash →
vendor the crates. Nothing is installed by this ADR; the operator installs the container
runtime and approves the image digest.

## Alternatives considered

1. **Ship no Tezos support** — remains valid; this ADR only authorises design and tooling
   setup. Code starts after the operator accepts it and the sandbox exists.
2. **Tezos via a general multi-chain SDK** — rejected: adds a large generic surface to the
   signing path for one chain.

## Consequences

- CL-WAL-014 moves from `deferred` to `partial` only when the adapter crate lands; this ADR
  alone changes nothing in the status legend.
- Mandatory regression tests before merge: wrong chain id, wrong genesis hash, expired
  branch, fee above `max_fee`, amount above the vault cap (decoded from bytes), tampered
  forged bytes refused by the vault's re-decode, locked vault, non-Development class, and
  the shared-pipeline refusal for `ChainFamily::Tezos`.
- Amounts render as mutez with explicit unit and chain badge.

## Security implications

Pinned chain identity (T-09) replaces the numeric chain id. Node-forged bytes are untrusted:
the vault signs only what it independently decodes and matches against the approved facts.
The branch expiry and the reveal requirement are replay and ordering concerns the builder
must handle, not the user.

## Revisit conditions

Operator picks crate option A or B; first Flextesa run records the pinned values; any
contract-call, delegation, `tz2`/`tz3` or external-signer scope; any testnet enablement.
