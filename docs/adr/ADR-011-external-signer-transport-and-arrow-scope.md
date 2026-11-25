# ADR-011 — External-Signer Transport (Native Messaging) and Arrow's Scope in It

**Status:** Accepted (evaluation + direction) · **Date:** 2026-07-06 · Follows the first live MetaMask/Sepolia test (ADR-005 amendment) and answers: how does a real external signer talk to the wallet, and does the Arrow protocol belong in that path?

**Amended by:** ADR-020 (mainnet exception for the EVM external signer); ADR-021 discharges the Solana half.

## Context

The MetaMask lifecycle harness proved the *mechanics* of driving a real external wallet, but as a standalone dapp page — the browser held the provider, and nothing connected it to `cipherlayer-vault`. Two questions block a real `ExternalSignerAdapter`:

1. **Transport:** how does a browser-resident signer (MetaMask) reach the wallet's Rust core, given the wallet is a separate process (ADR-004 direction) and the browser is untrusted (ADR-010)?
2. **Arrow:** the operator asked whether Arrow (`~/Dev/Arrow`) could be wired "as a native-messaging bridge within its scope."

## Evaluation: is Arrow the bridge?

**No — and forcing it would violate Arrow's own charter.** Arrow is a *stateful event-coordination standard*: its README states plainly "Arrow does not move assets. Arrow standardizes and routes verified events," and its canonical object is an `ArrowEvent` (`Class:Origin:State:Action:Finality:Confidence`) describing *what happened*. Its transport envelope (`arrow-transport::TransportEnvelope`) wraps a *completed, DID-signed event* for routing between coordinating nodes — it is not a request/response RPC for *soliciting* a signature.

A signing bridge needs the opposite shape: a **request** (`transaction-request-envelope.v1`) travels browser → wallet, a **response** (`signing-response.v1`) travels back, before anything has happened on-chain. That is the browser-connect contract this repo already owns (protocol v0.2). Routing it as Arrow events would mean inventing "please sign this" and "here is your signature" as Arrow Actions — pretending a pending solicitation is a verified past event. That inverts Class/State semantics and couples a live spend path to an event bus. Rejected.

**Where Arrow *does* fit — downstream, in its real scope.** Once a signature confirms on a real chain, that is exactly an Arrow event: an `ETH`-origin, `TRANSFER`/`CLOSE`-class, `FN` (final) event with `C` confidence. Arrow's own lifecycle harness already does this (`arrow-registry-test lifecycle run` derives an Arrow event from a real tx hash). So Arrow is an **optional observer/coordination sink**, not the request transport: after the wallet's audit log records a confirmed external-signer transaction, an adapter *may* emit an Arrow `ETH` event for cross-domain coordination. This keeps Arrow within "routes verified events," reuses the existing lifecycle-harness pattern, and stays fully optional (the wallet's own hash-chained audit log remains the primary record). Tarquin/Orlog are further downstream still (legal `LEG`-origin events from Orlog artifacts via Tarquin) and have no role in the signing path.

## Decision

1. **Transport = Chrome/Firefox Native Messaging**, carrying the existing **browser-connect contract** (not Arrow). A small native-messaging host (stdio JSON framing per the browser Native Messaging API) bridges the browser extension to the wallet's `connect serve` transport. This is the natural sibling of the v0.2 Unix-socket transport already built: same message set, different framing (length-prefixed stdio instead of a socket). It lives in the **browser** repo (the untrusted side owns the extension and host manifest); the wallet exposes only the already-published contract.
2. **Arrow integration = optional downstream event emission**, observer-role only, reusing the lifecycle-harness pattern, gated behind an explicit flag. Never on the request path. Deferred until the external-signer adapter lands; recorded here so the scope is fixed. **Operator note (2026-07-06):** the desired shape is a native Arrow *independent verification adapter* embedded in the browser or wallet — it watches confirmed transactions and derives/checks Arrow `ETH` events on its own authority (its own verification regime), giving the family a second, independent confirmation path beyond the wallet's audit log. This is squarely Arrow's observer role and is the intended first Arrow integration; it consumes Arrow's published crates and adds no signing authority.
3. **The real `ExternalSignerAdapter` (ADR-005, CL-WAL-010) does not wait on native messaging.** A headless external-signer path — key supplied at runtime by the operator (à la Arrow's `load-*-key.zsh`), used to sign, never persisted — is a legitimate second `ExternalSignerAdapter` implementation for real-network testing, independent of the browser transport. See ADR-005 and the adapter module docs for the key-handling invariants.

## Consequences

- The browser-connect contract is reaffirmed as the one signing-path interface; native messaging is a *framing* of it, not a new protocol.
- Arrow, Tarquin, Orlog stay in their own scope; the family's dependency direction is not bent to make a signing bridge out of an event standard.
- Two `ExternalSignerAdapter` implementations are now scoped: (a) headless runtime-key (this session), (b) browser/MetaMask over native messaging (follow-on, browser repo).
- The Native Messaging host is browser-repo work behind the browser MVP gate; it does not open that gate.

## Revisit

If Arrow gains a request/response solicitation model (it has none today), or if the Native Messaging framing proves unable to carry the contract without modification.
