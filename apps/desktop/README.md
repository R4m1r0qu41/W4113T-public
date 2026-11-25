# Desktop wallet prototype

This directory contains the first wallet desktop UI code. It is deliberately
presentation-only: no private keys, seed material, signing libraries, or policy
decisions live here. The UI is designed to be embedded by a future Tauri shell
and to communicate with the Rust trust spine only through wallet-owned IPC and
versioned contracts.

Current status:

- `index.html` plus `src/` is a static, local-first desktop prototype.
- It renders wallet status, chain/RPC state, policy/risk evidence, a transaction
  review surface, and audit entries from a local fixture model.
- The landing view is **Assets**: a unified, cross-chain holdings view (every
  chain adapter this repo ships — EVM/Anvil/Sepolia/L2s, Solana, Bitcoin) with
  network-class (Development/Testnet/Mainnet), chain, and token/NFT filters,
  per the UX-first sequencing decision recorded in the roadmap's "W2 —
  Desktop wallet UI" section ("see and act on everything I own" JTBD).
  Fixture data only — not yet wired to live chain/adapter state.
- The signing controls are non-authoritative. Real USER_REVIEW remains in
  `cipherlayer-vaultd` via `confirm_and_sign`.
- It labels mocked custody and prototype boundaries in the surface.

Run locally:

```sh
open apps/desktop/index.html
```

No dev server is required for the current prototype.

Boundary rules:

1. Desktop UI may render evidence and operator choices.
2. Desktop UI must never hold key material or instantiate a signer.
3. Desktop UI must never make policy decisions or convert a denial into an
   approval.
4. Desktop UI must route final confirmation to the Vault-owned surface.
5. Browser/dapp provider injection remains out of scope for this repo.

Next implementation step is a Tauri host that reads status/evidence from the
wallet process and invokes the existing `cipherlayer-vaultd` confirmation path.
