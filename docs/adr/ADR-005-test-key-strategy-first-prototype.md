# ADR-005 — External-Wallet / Test-Key Strategy for the First Prototype

**Status:** Accepted · **Date:** 2026-07-03

**Amended by:** ADR-020 (EVM external-signer mainnet exception) and ADR-021 (Solana external signer, devnet and mainnet-beta): deliberate, gated exceptions to the test-key-only default.

## Context

BS §7.4 recommends prioritizing hardware and external open-source wallet integrations and delaying a native seed-phrase wallet until the Vault is independently audited. The build prompt (§4.13–14) requires prototype defaults of local chains, testnets, watch-only accounts, external wallets, hardware wallets, or test keys, and forbids real funds.

## Decision

Milestone 1 signing uses a **TestSigner**: an in-memory secp256k1 key restricted to well-known Anvil development keys on chain-id 31337. Guardrails:

- The CLI refuses signing paths when the target chain is not a local development chain (chain-id allowlist in the chain registry marked `development`).
- `ExternalSignerAdapter` and `HardwareSignerAdapter` exist as typed interface stubs (**theoretical**), so the Vault API is signer-agnostic from day one.
- Watch-only accounts are representable in the account model but not the demo path.
- No seed-phrase generation, storage, or recovery code exists anywhere in the repo.

## Amendment (2026-07-05, operator decision AC-004)

The first *real* signer integration (W1-remainder) is a **MetaMask-compatible external-signer adapter** — the operator has MetaMask installed and ready for real tests, mirroring how the Arrow project ran its lifecycle tests. Real-network tests adopt Arrow's harness discipline (`~/Dev/Arrow/tools/lifecycle-harness` as the reference pattern): environment-driven scrubbed scripts committed, operator-specific copies gitignored; an **originator/observer split** (spend-capable path human-gated with an explicit approval phrase; observer path read-only and automatable); testnet/small-value first. This amends the alternatives ranking below — the external bridge is now scheduled, not rejected; the TestSigner remains the default for local development and CI.

### Progress (2026-07-05, same day)

`tools/metamask-lifecycle-harness/` implements the discipline above as a standalone dapp-side test page (not yet wired into `ExternalSignerAdapter`): EIP-6963 discovery refuses any provider that doesn't self-identify as MetaMask, every chain but Sepolia is refused, and sending requires both an on-page approval phrase and MetaMask's own popup confirmation — no automation may click the latter. `verify-artifact.sh` is the observer half: it independently re-derives the chain id from the RPC (never trusting the page's report) before writing an evidence artifact under `docs/test/evidence/`.

**First live run completed same day.** The operator ran the full originator flow: connected MetaMask, confirmed Sepolia, sent a real 10-wei transfer, approved both the on-page phrase and MetaMask's own popup. Tx hash `0xfcae624b…b2c8734`. Independently verified by the observer script against a fresh RPC (not the page's report): status success, block 11212415, chain id 11155111 confirmed. Artifact: `docs/test/evidence/metamask-sepolia-lifecycle-fcae624b456f.json`. (Incidental finding: the previously-assumed default public RPC `rpc.sepolia.org` is decommissioned — 404 from a bare Apache server — and was replaced with `ethereum-sepolia-rpc.publicnode.com`.)

This proves the mechanics of driving a real external wallet through the standard injected-provider protocol end-to-end on a live network; it does not yet prove `ExternalSignerAdapter` integration — see the harness README's "what this does and does not prove."

## Alternatives considered

1. **External wallet bridge (e.g., WalletConnect) now** — rejected: large protocol surface, network dependency, and a real-key pathway before any review.
2. **Hardware wallet now** — rejected for milestone 1: device dependency in CI/demo; adapter interface preserved.
3. **Native encrypted keystore** — rejected: creates real key custody before audit; explicitly against BS §7.4.

## Consequences

- The demo is fully reproducible offline with zero value at risk.
- Signature-flow realism is preserved (real ECDSA over real transactions on a real EVM chain), so swapping in an external signer later changes the adapter, not the pipeline.

## Security implications

Zero real-fund exposure by construction. The residual risk is *illusory security*: contributors must not mistake TestSigner for a custody solution — labeled MOCKED in code, CLI output, and prototype-limitations.

## Revisit conditions

Independent Vault review; W2 desktop signing (requires at least external-signer adapter completion); any request to touch a public testnet with faucet funds (needs explicit operator sign-off).
