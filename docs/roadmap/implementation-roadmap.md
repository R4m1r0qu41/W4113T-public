# Implementation Roadmap — CipherLayer Wallet

**Version:** 0.1 · Follows the unified roadmap (US §12) with gates; wallet-first is locked (ADR-001). Dates are deliberately absent — gates are capability-based.

## Milestone 1 (this milestone) — Trust-spine vertical slice ✅

Scope delivered: repo family established; requirements matrix + conflicts register; ADR-001...014; threat model + abuse cases; versioned schemas; Rust workspace (types, vault, vaultd, policy, chain, evm, intent, simulation, risk, audit, provider, cli); signing state machine; deterministic policy with unlimited-approval default-deny; Anvil simulation adapter; hash-chained audit log; CLI vertical slice + demo on Anvil; vaultd process boundary; trusted confirmation tier v1; browser-connect protocol v0.3; static desktop UI scaffold; unit/integration/security-regression tests; browser + scam-guard repos populated with contracts/docs.

Explicitly not in milestone 1: production GUI shell, native custody, hardware-backed storage, hardware signer, mainnet/default real-fund path, full FPL detector engine in this repo, browser product shell.

## W1 (remainder) — Wallet core hardening

- ~~**MetaMask-compatible external-signer adapter first**~~ ✅ done 2026-07-06 (operator decision AC-004; ADR-011): real `ExternalSignerAdapter`, Arrow-style lifecycle harness, verified Sepolia send via the operator console
- ~~EIP-712 full typed-data parsing~~ ✅ parser done 2026-07-16 (`cipherlayer-evm::typed_data`: encodeType/encodeData/hashStruct/domain separator, bounded against cyclic/deep type graphs, EIP-2612 + DAI-style permit classification feeding the existing default-deny policy; **library level** — a production typed-data request path needs the browser-connect contract rev, see CL-EVM-003; domain fidelity for unclassified typed data is crate-level API pending an additive schema bump — see requirements matrix CL-EVM-004); ~~broader selector library~~ ✅ done 2026-07-05 (`setApprovalForAll`, `increaseAllowance`, ERC-721 `safeTransferFrom`; ERC-1155 batch ops still open)
- ~~Permission persistence + `permissions` CLI completeness~~ ✅ done 2026-07-05 (data/permissions.json + list/revoke, audited)
- ~~Fuzz/property tests in CI for envelope, calldata, state machine~~ ✅ done 2026-07-16 (local `make ci` gate added 2026-07-05; remote CI done 2026-07-07 — GitHub Actions `make ci` + Anvil integration job + nightly family invariants; proptest, stable toolchain, default 256 cases: envelope parser property tests added `crates/cipherlayer-provider/tests/envelope_proptest.rs` — arbitrary JSON near-misses never panic, well-formed envelopes roundtrip; calldata decoder and signing-state-machine property tests already existed and stay green — `cipherlayer-evm::lib` / `cipherlayer-types::state` `prop_tests`)
- ~~Browser-connect conformance harness (gate criterion 3)~~ done 2026-07-05; upgraded through protocol v0.3 host attestation and concurrent transport tests (wire-format envelopes to pipeline to signing-response incl. denial/expiry paths)
- ~~cargo-audit + SBOM as CI gates~~ ✅ done 2026-07-16 (`make audit` / `make sbom` targets; GitHub Actions `audit` and `sbom` jobs, both kept out of the offline `make ci` gate — advisory-DB fetch and crates.io installs need network; SBOM uploaded as a workflow artifact from `target/sbom/`)
- ~~EVM mainnet external-signer exception~~ ✅ done 2026-07-17 (ADR-020, operator directive): second single-chain-hardcoded `ExternalSignerConfig` constructor, chain-labeled approval phrase, no address auto-fill default
- ~~Solana external signer (devnet + mainnet-beta) behind the vault process boundary~~ ✅ done (ADR-021, CL-WAL-011): two-phase approve/sign ceremony hosted by `cipherlayer-vaultd` on its own tty; devnet gate passed live 2026-07-19; external-audit and re-audit findings closed; mainnet gate passed 2026-07-20 with no blocking findings
- ~~Recipient aliases for the console send flow~~ ✅ done: exact case-insensitive, whitespace-normalized EVM alias resolution; literal addresses take precedence, ambiguous labels fail closed
- **Gate to W2:** core signs reliably on local chain across the expanded decode set; security regression suite green in CI

## W2 — Desktop wallet UI (Wallet MVP gate)

- ~~Vault process split first~~ done in `cipherlayer-vaultd` (ADR-004 addendum); GUI signing must use that boundary
- Desktop shell decision ADR (Tauri vs Electron trade-off per BP §6.3; preliminary lean Tauri, AC-009)
- Wire `apps/desktop` to wallet-owned IPC without key material or policy authority in the UI (presentation-only prototype landed 2026-07-11; IPC wiring still open)
- **UX-first sequencing (operator directive, 2026-08-20):** infrastructure (CLI integration, cross-chain sending) proved the system works; UX now leads further chain/wallet integration instead of following it. First surface, ~~unified view~~ done 2026-08-20: `apps/desktop`'s landing view is a cross-chain/cross-asset holdings screen (every adapter this repo ships — EVM/Anvil/Sepolia/L2s, Solana, Bitcoin) with network-class (development/testnet/mainnet) and chain/type filters built in from the start so the view stays legible as holdings grow, not bolted on after; the operator console gained an equivalent `assets` menu item reading the same real `ChainRegistry` for chain identity. Both surfaces show fixture holdings only, labeled as such — not wired to live adapter balances yet. Frictionless network switching and state legibility (translating raw chain data into what it means for the holder) remain open, building on this filter foundation; a "one pane over many external wallets" surface (Phantom/MetaMask/etc. aggregation) is a later, separate extension
- Dashboard: accounts, hot/warm/cold labels, network, assets ~~(unified view, fixture data)~~ done above, NFT gallery ~~(fixture data)~~ done above, spam quarantine, tx composer, decoded intent, simulation, risk evidence, policy result, confirmation, audit trail (BP §6.3)
- Trusted-confirmation tier v1 exists (ADR-012); SEP-backed / biometric binding remains the next tier
- Custody-clarity labels in UI (CL-LEG-008 review)
- Unlimited-approval override reminders + periodic summaries (CL-POL-008, 6/12/18/24h cadence)
- UI priorities driven by the resolved persona (UQ-001): power users/developers with institutional sight — vault tiers (cold/warm/hot), network profiles, CLI parity, spam handling — with newcomer-grade defaults
- **Wallet MVP gate (US §12):** desktop wallet proves the thesis → unlocks browser implementation per ADR-010 checklist

## W3 — Mobile (parallel with B1 once W2 stable) — deferred

Full wallet, not companion; stability benchmarks against large NFT/spam/multi-chain accounts (US §4.2). Requires its own threat-model extension.

## B1/B2 — Browser (in `../browser/`, post-gate)

Cheapest credible shell/compatibility harness first (no Chromium fork); provider injection; dapp detection; per-site permissions; interception → wallet pipeline; FPL wired in. Acceptance: BS §22 flow end-to-end. Operative gate checklist: `browser/docs/architecture/browser-mvp-gate.md`.

## W5/B3 — Legal-grade & institutional

Policy engine extensions (roles, approval workflows, jurisdictional profiles); audit export/anchoring (ADR-007 revisit); multisig governance; compliance reporting; institutional pilot gate.

## Later (each requires a new ADR)

~~Additional EVM chains via adapters → Solana/Bitcoin adapters~~ ✅ done 2026-07-10 under the ADR-015 adapter-gate program (EVM-L2 registry entries, Solana ADR-016, Bitcoin ADR-017; Tezos still open); MPC; plugin runtime + marketplace (hard boundary: no Vault access); agent runtime (authority ladder, session keys); MEV routing options (never "protection" as absolute); NFT studio; DAO legal graph.

## Standing constraints across all phases

Wallet-first until gate · no real funds until the prototype-limitations gate conditions clear · deferred scope needs an ADR · every phase updates requirements matrix, threat model, claims register.
