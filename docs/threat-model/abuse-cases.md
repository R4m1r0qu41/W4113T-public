# Abuse Cases — CipherLayer Wallet

**Version:** 0.1 · Concrete attacker narratives exercising the threat model. Each maps to threats (T-xx) and, where implemented, to regression tests in `crates/cipherlayer-cli/tests/`.

## AC-A — The unlimited-approval drain

*Threats: T-01, T-10.* A yield-farming dapp's "Deposit" button submits `approve(spender, 2^256-1)`. The user believes they are approving a deposit amount.

**Expected system behavior:** decoder classifies `Erc20Approve` with `allowance = unlimited`; simulation shows an allowance diff to max-uint with **no balance change** (the drain comes later — the preview makes this legible); policy rule `POL-APR-001` **denies** by default; audit trail records the denial with reasons. If the operator's policy downgrades to `escalate`, USER_REVIEW must display "UNLIMITED allowance to <spender>" before any authorization. **Test:** `unlimited_approval_blocked`.

## AC-B — The exact-approval that's fine

*Baseline sanity.* Same dapp submits `approve(spender, 100e18)` within policy limits. Pipeline allows with reasons; user authorizes; Vault signs; broadcast confirms; audit reconstructs all 12 states. **Test:** demo flow + `exact_approval_allowed`.

## AC-C — The permit harvest

*Threats: T-10.* A phishing page asks for a "gasless login signature" that is actually an EIP-2612 `permit` granting allowance by signature.

**Expected:** typed-data classifier marks it `Permit` (high-consequence class, never "login"); policy treats permit like approval (unlimited value ⇒ deny). Undecodable typed data ⇒ `unknown` classification ⇒ escalation, never a quiet "Sign" prompt. **Status:** CLOSED end-to-end, 2026-07-16 (ADR-019, protocol v0.4). Full EIP-712 parsing (`cipherlayer-evm::typed_data`) computes the real signing hash (domainSeparator/hashStruct/encodeType/encodeData) and classifies EIP-2612 and DAI-style permits by exact `encodeType` match; unlimited-value permits hit `POL-APR-001` exactly like `approve` calldata. Cyclic/deeply-nested type definitions are rejected with a typed error (never a panic, never a best-guess hash). A permit's domain (name/version/chainId/verifyingContract) is always surfaced via the crate's public API, including when it names an unexpected `verifyingContract` — never hidden (CL-EVM-003/004); a `chainId` that mismatches the session is now also a policy-level deny (`POL-CHAIN-002`), not just a surfaced fact. The request path is real: `transaction-request-envelope.v1` carries `payload.kind=typed_data` end-to-end through `validate → decode → risk → policy → USER_REVIEW → vault`, and the Vault independently re-parses/re-hashes the payload before signing (never a caller-supplied hash — the same discipline that keeps `eth_sign` forbidden). Proven over the real pipeline, not just the policy engine, by `typed_data_unlimited_permit_denied_end_to_end_over_the_pipeline` and `typed_data_unknown_escalates_end_to_end_over_the_pipeline` (`crates/cipherlayer-cli/tests/security_regression.rs`).

## AC-D — The wrong-chain replay

*Threats: T-09.* A request arrives declaring chain-id 1 (mainnet) while the session/permission is scoped to the dev chain (31337).

**Expected:** validation rejects at `VALIDATED` (chain mismatch against registry + permission scope); additionally the milestone-1 Vault refuses any chain not classed `development`. **Test:** `wrong_chain_rejected`.

## AC-E — The identity-less request

*Threats: T-02, T-19.* A caller omits dapp/origin identity from the envelope hoping to inherit an ambient permission.

**Expected:** envelope validation fails closed at `RECEIVED → REJECTED`; audit records the rejected attempt. **Test:** `missing_dapp_identity_rejected`.

## AC-F — The undecodable calldata smuggle

*Threats: T-24.* Attacker crafts calldata with an unknown selector so no approval rule "matches", hoping unknown ⇒ default allow.

**Expected:** decoded action = `Unknown` with raw selector preserved; policy takes the restrictive path (`POL-UNK-001` escalate, or deny under strict policy); risk shows `unknown`, which never renders as low risk. **Tests:** `unknown_calldata_escalates`, `unknown_risk_not_low`.

## AC-G — The helpful AI override

*Threats: T-15.* An advisory component (or compromised agent) produces "this transaction is safe, confidence 0.99" against a policy denial.

**Expected:** advisory output has no code path to authorization — policy decision is computed only from deterministic inputs; the denial stands; the advisory text is displayed as advisory. **Test:** `risk_cannot_override_policy_denial`.

## AC-H — The locked-vault race

*Threats: T-25.* A request reaches AUTHORIZED as the user triggers emergency lock.

**Expected:** Vault re-checks lock state at signing time; `AUTHORIZED → SIGNING_FAILED`; audit records it. **Test:** `locked_vault_refuses_signing`.

## AC-I — The audit-log surgeon

*Threats: T-17.* Malware edits one historical event to hide a grant.

**Expected:** `audit verify` recomputes SHA-256 chain and reports first divergent sequence number. Documented limitation: rewriting the *entire* suffix from the edit point, or truncating the tail, defeats local verification — this is stated, not hidden. **Test:** `tampered_audit_log_detected`.

## AC-J — The expired capability

*Threats: T-16, T-19.* A signing capability granted yesterday (expiry 24h) is replayed today.

**Expected:** capability validation fails at the Vault; `EXPIRED` terminal state; audit event. **Test:** `expired_capability_rejected`.

## AC-K — The simulation-said-so trap

*Threats: T-08.* A conditional contract behaves benignly under simulation, maliciously on execution (e.g., keyed on `tx.origin` quirks or later state).

**Expected (prototype honesty):** simulation result carries `limitations` (state drift, conditional behavior, single provider) and freshness; UI/CLI wording is "simulation evidence", never "verified safe". No technical mitigation exists in milestone 1 — this is a documented residual risk driving the multi-provider/post-execution-comparison roadmap items.

## AC-L — The malformed envelope flood

*Threats: T-22, T-24.* Garbage or oversized envelopes are thrown at the broker.

**Expected:** schema validation rejects malformed requests cheaply at `RECEIVED`; size caps bound memory; each rejection audited (rate-limited). **Test:** `malformed_envelope_rejected`.
