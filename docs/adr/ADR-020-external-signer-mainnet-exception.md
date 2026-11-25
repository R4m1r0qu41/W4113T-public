# ADR-020 — External-Signer Mainnet Exception

**Status:** Accepted · **Date:** 2026-07-17 · Amends ADR-011 (external-signer transport) and the `permitted_chain_id` scope of `crates/cipherlayer-vault/src/external_signer.rs`.

## Context

ADR-011 built the headless external-signer path and deliberately hardcoded it to Sepolia only — `external_signer.rs` states plainly "**testnet only**: this adapter refuses every chain except the configured testnet," and its own test (`refuses_non_testnet_chain_before_touching_key`) asserts chain id 1 is refused with the comment "Mainnet is likewise refused; no mainnet path exists." AGENTS.md's binding invariant is the same: *"Test environments by default... Never wire real funds, mainnet RPC defaults, or real key material into code, fixtures, or docs examples."*

The operator has now explicitly directed a mainnet run: a small-balance test wallet they already hold, funded with an amount they have stated they are willing to lose, used to prove the external-signer pipeline against real Ethereum mainnet (operator directive, 2026-07-17). This is exactly the kind of deliberate, informed override those invariants are written to require rather than forbid outright — AGENTS.md's own phrasing is "never wire... by default," not "never permit."

## Decision

1. **Extend, don't loosen.** `ExternalSignerConfig` gains a second, equally-hardcoded constructor, `ExternalSignerConfig::mainnet(expected_address)`, alongside the existing `::sepolia()`. Each constructor still permits exactly **one** chain id — a Sepolia-configured signer still cannot sign on mainnet and vice versa. No config permits both; there is no "any chain" mode. The existing address-derivation guard, the never-persisted key discipline, and the required `UserAuthorization` acknowledgement are unchanged and apply identically to both.
2. **The console's Sepolia-only gate becomes a small permitted set** (`{SEPOLIA_CHAIN_ID, MAINNET_CHAIN_ID}`), not an "any chain" gate — every other registry entry (Anvil, L2 mainnets/forks) remains refused by the external-signer flow exactly as before.
3. **The approval phrase is chain-specific** (`SEND-CIPHERLAYER-SEPOLIA` vs. `SEND-CIPHERLAYER-MAINNET`), so an operator's muscle memory from testnet runs cannot accidentally authorize a real-money mainnet send — the phrase itself names the stakes.
4. **RPC resolution mirrors the Sepolia pattern**: `CIPHERLAYER_MAINNET_RPC` (operator-supplied), else a public fallback (`https://ethereum-rpc.publicnode.com`), then the on-chain identity is re-verified against the live RPC before signing — the existing belt-and-suspenders check, unchanged in mechanism.
5. **The registry's mainnet `ChainEntry` (chain id 1) gets a populated `RpcProfile`**, replacing the empty `rpc_profiles: vec![]` placeholder. Its `notes` field is corrected — signing was never truly "refused in this prototype" as a blanket statement; it is refused by `Vault::authorize_and_sign`'s development-only gate (`ensure_signing_allowed`, unchanged, still hard-refuses chain 1) and now deliberately permitted only through this separate external-signer authority.
6. **Solana is explicitly out of scope for this ADR.** ADR-016 treats any key material outside the vault as a hard stop requiring its own ADR; no Solana external-signer code exists yet (no trait, no runtime-key pattern). A mainnet Solana path is a separate, larger piece of work and gets its own ADR when undertaken.

## Consequences

- `Vault::authorize_and_sign`'s development-only signing gate is **untouched** — this ADR does not weaken vault custody in any way; it only widens the pre-existing, separate, human-gated external-signer authority that was always designed to bypass the vault (ADR-011 §3: "a legitimate second `ExternalSignerAdapter` implementation... independent of the browser transport").
- Real money is now reachable from this codebase for the first time. The mitigations are the same ones that made the Sepolia path safe to build: key never persisted (env-var-at-sign-time only, zeroed after use), address-derivation guard (wrong key signs nothing), full preflight display before any signature, an explicit and chain-labeled approval phrase, and live on-chain identity re-verification immediately before signing.
- Every mainnet-enabling change is a small, explicit source edit (new constructor, extended permitted-set literal, populated RPC profile) — consistent with ADR-011's original design property that no single flag or env var can silently enable mainnet; each surface must be deliberately touched.
- This ADR does not open any gate for Vault-held mainnet custody, browser-repo integration, or Solana. Those remain separately gated (browser MVP gate, ADR-016 hard stop).

## Revisit

If the operator ever wants the *vault itself* to hold a real mainnet key (true custody, not external-signer relay), that is a different, larger decision requiring its own ADR and a dedicated hardening/audit pass — not a natural extension of this one.
