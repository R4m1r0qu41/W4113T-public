# ADR-003 — Rust Trust Core, TypeScript Presentation Layers

**Status:** Accepted · **Date:** 2026-07-03

## Context

The Unified Scope §13 assigns "policy broker, transaction decoding, security-critical services" to Rust and the frontend/IPC layer to TypeScript. The trust core (Vault, policy, intent, simulation, audit, provider broker) needs memory safety, strong typing for security-critical values, a mature crypto/EVM ecosystem (alloy, k256), and a path to a minimal, formally specifiable component. Presentation layers (desktop UI, later browser chrome) need web-technology velocity.

## Decision

- **Rust** for everything inside or adjacent to the trust boundary: all `crates/cipherlayer-*` including the CLI.
- **TypeScript** for future presentation surfaces (desktop UI at W2, browser chrome later), communicating with the Rust core only through the versioned schemas in `schemas/` — never holding keys, never making policy decisions.
- The EVM/RPC layer uses the **alloy** crate family (the maintained successor to ethers-rs) rather than hand-rolled RLP/secp256k1, to avoid bespoke cryptographic plumbing.

## Alternatives considered

1. **TypeScript everywhere** — rejected: weaker guarantees for security-critical values; drags Node into the trusted computing base.
2. **Rust everywhere including UI** — rejected for later phases: slows UI iteration without shrinking the *trusted* surface (UI is untrusted by design).
3. **Hand-rolled minimal EVM plumbing** (raw JSON-RPC + k256 + custom RLP) — smaller dependency tree but re-implements cryptographic serialization; rejected per "use open-source dependencies where practical" (BS §22) — alloy is standard, pinned, and auditable.

## Consequences

- Workspace-wide `Cargo.lock` pins the dependency tree; alloy adds a sizable but standard tree (recorded in SBOM).
- Desktop-shell choice: **operator confirmed Tauri as the working default** (AC-009 decision, 2026-07-04 — "keep Tauri, update to Electron later as appropriate"). The W2 webview-consistency evaluation still runs before code; Electron remains the recorded fallback if it fails.

## Security implications

Typed `Address`/`U256`/`ChainId` throughout the core removes classes of string-confusion bugs. Alloy becomes a critical supply-chain dependency: version pinned, updates reviewed.

## Revisit conditions

Desktop-shell ADR at W2; if alloy's maintenance posture changes; if formal specification of the Vault requires narrowing the dependency tree.
