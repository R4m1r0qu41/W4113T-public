# ADR-017 — Bitcoin Adapter (ADR-015 phase d)

**Status:** Accepted · **Date:** 2026-07-10

> Operator accepted 2026-10-13. Implemented while still marked Proposed; the shared-pipeline evidence concern is closed by the chain-family gate (CL-WAL-015).

## Context

ADR-015 phase (d). Local infrastructure exists: Bitcoin Core v31 with
configured pruned-mainnet and signet nodes (launchers in
`Arrow/tools/lifecycle-tests/`); **regtest** is the signing test network.
Arrow's `arrow-origin-btc` provides read-only prior art (per-chain
`ObservedUtxo`, depth-based finality) but no signing path.

Bitcoin differs from EVM in ways that matter here: it is UTXO-based (no
accounts, no nonce), network identity is carried by address prefixes,
network magic, and the genesis block hash (no numeric chain id), fees are
sats/vB chosen by the builder (fee overpayment is a real loss, not a
refunded gas limit), and signing is per-input over a taproot/segwit
sighash.

## Decision

1. **Crates.** `rust-bitcoin` (`bitcoin` crate) for transaction types,
   address parsing, and consensus encoding — real SDKs on the signing path
   per ADR-015; no hand-rolled consensus code. Node RPC is raw JSON-RPC
   over `reqwest` rather than `bitcoincore-rpc`: the latter's blocking
   client does not compose with the RPITIT `Send` async adapter traits,
   and the RPC surface is three methods (`getblockhash`,
   `getrawtransaction`, `sendrawtransaction`); hand-rolled transport is
   acceptable, hand-rolled consensus is not.
2. **Adapter crate.** `cipherlayer-btc` implements
   `ChainObserver`/`ChainBroadcaster`: network-strict address parsing
   (a mainnet address is a hard error on regtest and vice versa — never a
   silent re-interpretation), unsigned transaction building from
   node-provided UTXOs with explicit fee and change, broadcast of raw
   signed bytes, and status by txid with confirmation depth. No key
   material.
3. **Chain identity = genesis block hash + network.** Registry reserves
   internal id **900002** (band 900000–999999 per ADR-016) for "Bitcoin
   regtest (local development)", Development class, `native_symbol` "BTC",
   `native_decimals` 8 (sats). `verify_chain_identity` fetches the genesis
   block hash (`getblockhash 0`): regtest's is a well-known constant
   (`0f9188f1...`) and is pinned — mainnet/signet/testnet genesis hashes
   must fail closed (T-09). Pruned-mainnet and signet nodes are observation
   infrastructure only and get no signable registry entries.
4. **Signing stays in the vault.** A Bitcoin test signer (secp256k1 over
   BIP-341 taproot key-path or BIP-143 segwit-v0 sighash — whichever
   `rust-bitcoin`'s signing utilities make simplest and safest) is added
   behind `cipherlayer-vault` with the same gates as ECDSA/ed25519: lock,
   verdict finality, Development-only network class, capability
   re-validation. The sat value cap is decoded from the transaction
   outputs themselves, never from a caller-declared amount. Ephemeral test
   keys only; no import path; Debug-redacted.
5. **Fee discipline.** The unsigned builder computes fee = inputs − outputs
   explicitly and refuses to build when the implied fee exceeds a hard cap.
   The cap (`max_fee`) is a **required** field on every build input — there
   is no default and no way to omit it — and the guard is enforced twice:
   before building and re-derived from the built transaction. Absurd-fee is
   a loss path, not a UX nit.
6. **Evidence stays honest.** Intent/simulation/risk are EVM-only; Bitcoin
   requests surface `unknown` for evidence they cannot produce (ADR-015).
   Pipeline integration is follow-up, as with Solana.

## Alternatives considered

1. **Descriptor-wallet signing inside Bitcoin Core** (node signs) —
   rejected: keys would live in the node process, outside the vault
   boundary (hard-stop invariant).
2. **Hand-rolled JSON-RPC** — rejected on the signing path per ADR-015.
3. **PSBT round-trip through the node** — deferred: full PSBT workflow is
   the right long-term shape for hardware custody, but the prototype's
   vault-internal signer doesn't need it yet; revisit at custody review.

## Consequences

- Requirements matrix CL-WAL-003 gains a phase (d) note; wrong-network
  address, wrong-genesis-hash, and fee-cap regression tests are mandatory.
- Amounts render as sats with explicit unit + chain badge (wei/lamports/
  sats confusion is T-09-adjacent, ADR-015 security implication).
- The vault grows a third scheme; its refusal paths are tested
  independently, mirroring ADR-016.

## Security implications

Genesis-hash pinning replaces chain-id verification (T-09). Network-strict
address parsing prevents mainnet-address-on-regtest confusion — and the
reverse, which would burn real funds if a regtest flow were ever pointed
at mainnet. The explicit fee computation guards against fee-drain
transactions that are structurally valid but economically destructive.

## Revisit conditions

Signet/testnet enablement (MVP gate review); PSBT/hardware custody work;
multi-input coin selection beyond the simple builder; any need for key
material outside the vault (hard stop).
