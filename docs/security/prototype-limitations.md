# Prototype Limitations — What Is Real and What Is Not

**Version:** 0.1 · This file is the honest ledger required by BP §4.12/§16. If a limitation is missing here, that is a documentation bug — report it.

## Component status

| Component | Status | What that means here |
|---|---|---|
| Signing state machine (`cipherlayer-types::state`) | **prototype** | Real transition enforcement + tests; not formally verified |
| Provider envelope & permission model | **prototype** | Validation + identity requirements real; grants persisted to a local JSON file (not secret material; status re-validated on every use); live local transport = same-user Unix socket (`connect serve`), **protocol v0.3 host attestation** (ADR-013): capsule ops require the launch token, a non-host peer is refused — residual is a same-user attacker who can read the token (T-14); connections served concurrently (one task per connection; permission/audit/vault state correctly serialized, capability queries lock-free) |
| EVM decoder (approve/transfer/transferFrom, increaseAllowance, setApprovalForAll, ERC-721 safeTransferFrom, permit shapes) | **prototype** | Deterministic; ERC-20/721 selector collisions surfaced in unresolved_fields; everything else labeled unknown |
| Transaction intent (v1) | **prototype** | Versioned schema + Rust types; proxy-awareness fields reserved, unpopulated |
| Anvil simulation adapter | **prototype** | Real state-diff simulation on a local node; single provider; no multi-provider conflict detection yet |
| Risk layer (`cipherlayer-risk`) | **prototype** | Aggregation/unknown/conflict semantics real and tested. Managed `scam-guard` subprocess is the default (or `CIPHERLAYER_FPL_BIN`); missing, timed-out, oversized, or invalid output becomes `detectors_unavailable` and restrictive `unknown`. `CIPHERLAYER_FPL_MODE=mock` is explicit test/demo-only and labels findings. Offline Scam Guard coverage remains narrow and is not a guarantee. |
| Policy engine | **prototype** | Deterministic rules + reason codes real; rule set minimal (chain, deny/allowlist, limits, unlimited-approval, unknown-handling) |
| Vault | **prototype (custody MOCKED)** | (1) Process isolation implemented (ADR-004 addendum): `cipherlayer-vaultd` hosts the Vault behind a same-user Unix-socket IPC on the pinned signing-request.v1 wire format; the CLI defaults to in-process and opts in via `CIPHERLAYER_VAULT_SOCKET`. (2) Custody remains MOCKED: the only signer is a TestSigner holding well-known Anvil dev keys in memory (ADR-005). There is **no secure storage**, no hardware backing, no encryption at rest (nothing persisted) |
| External / hardware signer adapters | **partial prototype / theoretical** | Two runtime-key external signers exist, both human-gated: EVM (`LocalKeyExternalSigner`, ADR-020 — Sepolia + Ethereum mainnet by deliberate exception; key loaded in the CLI process, recorded as debt in ADR-021 §5) and Solana (`SolExternalSigningCeremony`, ADR-021 — devnet + mainnet-beta; key entered on the vaultd terminal, never in the CLI process). Neither is custody, a hardware wallet, or a browser/MetaMask native-messaging bridge. Hardware signer and OS-keychain-backed adapters remain theoretical |
| Audit log | **prototype** | Real append-only hash chaining + verification; **not immutable**; no external anchoring; unbounded file growth |
| Chain registry / RPC profiles | **prototype** | Local Anvil default; mainnet/Sepolia entries are metadata only; signing gated to `development` class |
| CLI | **prototype** | Real driver of the full pipeline; its confirmation prompt is an ordinary terminal prompt — **spoofable**, not a trusted surface. The `assets` unified-view menu item reads live native EVM balances (display only, `unavailable` on failure, never zero, mainnet and non-EVM never queried); every other holding it shows is a fixture labeled `(fixture)` |
| Trusted confirmation surface | **prototype tier v1** | `cipherlayer-vaultd` can render USER_REVIEW through a macOS system dialog with a user-selected secret phrase and fail-closed checks (ADR-012). SEP/biometric binding and occlusion detection are not implemented |
| Desktop app | **prototype scaffold** | `apps/desktop` contains a static/Tauri-ready wallet UI prototype. It renders evidence and status only; it has no key handling, signer, policy authority, or live IPC wiring yet. Its landing "Assets" unified view shows fixture holdings, labeled as such in the view itself — not live chain/adapter balances |
| Browser integration | **prototype contract / gated product** | Wallet-side browser-connect transport is protocol v0.3 with host attestation and concurrency; browser product shell remains gated by ADR-010 and operator approval |
| Agent runtime, session keys, MEV, multi-chain, mobile, plugins, NFT/DAO modules | **deferred** | Schemas/extension points at most |

## Hard limitations to keep in mind

1. **No real security for real keys.** The prototype must never hold anything but Anvil's publicly known dev keys. It provides *decision-quality* safety (decode/simulate/policy/audit), not custody safety.
2. **Custody is still mocked.** The process split exists, but the default signer is still an in-memory Anvil dev key unless the operator deliberately uses a separate testnet external-signer flow. No native custody, secure storage, or hardware-backed key path exists.
3. **Terminal confirmation is not a trusted surface.** Anything controlling the terminal can spoof the prompt (T-12). Use `cipherlayer-vaultd` plus `--vault-confirm` for the tier-v1 Vault-owned confirmation surface.
4. **Simulation happens on the same local node that executes.** Ideal fidelity locally — and unrepresentative of mainnet divergence risk; do not extrapolate reliability claims.
5. **The mock detector detects nothing real.** Risk output demonstrates the *interface contract* (reason codes, confidence, unknown/conflict), not fraud detection.
6. **Audit tamper-evidence is local-only.** An attacker with file access can rewrite the suffix or truncate the tail undetected absent an external head anchor (ADR-007).
7. **No updates, no distribution, no recovery.** There is no update channel, no installer, no backup/recovery mechanism — and deliberately no native key custody to need one.
8. **DoS hardening is minimal.** Size caps and basic rate limiting only.
9. **Dependency trust.** alloy + tokio + serde et al. are pinned but not vendored/reviewed line-by-line; `cargo audit`/SBOM are optional developer tools, not CI gates yet. **Accepted advisories (2026-11-01):** RUSTSEC-2026-0391/0403/0398 (`zstd` 0.13.3 / `zstd-safe` 7.2.4) are ignored in `.cargo/audit.toml` — transitive via `solana-account-decoder` 3.1.14 with no compatible fix, and the wallet never requests zstd-encoded Solana account data; remove when a stable `solana-*` >= 4 is adopted. **Open, not accepted:** RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5, constant-time timing issues) is on the vault signing path via `alloy-signer-local` → `k256` 0.13 and has no compatible fix; it keeps `cargo audit` failing until the operator decides or alloy moves to `k256` 0.14.
10. **No independent review.** Nothing here has been security-audited. "Tested" means the repository's own test suite passes.

## Gate conditions before any real key / real fund

Hardware-backed or external-wallet signer path; independent security review; signed release pipeline; SEP/biometric confirmation tier or equivalent; the `accepted-P` rows of the threat model re-dispositioned. Until then, the dev-chain-only Vault custody gate stays in code, and real-network signing happens only through the separate, human-gated external-signer authorities (EVM Sepolia/mainnet, ADR-020; Solana devnet/mainnet-beta behind the vaultd process boundary, ADR-021) — each single-chain-hardcoded, chain-labeled-phrase-gated, key never persisted.
