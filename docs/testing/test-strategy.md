# Test Strategy — CipherLayer Wallet

**Version:** 0.1 · One documented command per suite (BP §14). Tests are the executable form of the security invariants — a failing security regression test is a release blocker by definition.

## Commands

| Suite | Command | Needs chain? |
|---|---|---|
| Unit | `make test` (`cargo test --workspace --lib --bins`) | No |
| Integration + security regression | `make anvil-up && make test-integration` | Yes (local Anvil) |
| Lint/format | `make lint` / `make fmt` | No |
| Full demo | `make demo` | Yes |
| Docs presence/links | `make docs-check` | No |

Integration tests are guarded by `CIPHERLAYER_INTEGRATION=1` (set by the make target) and skip gracefully with a notice when Anvil is unreachable, so `cargo test` never reports false green for suites that didn't run — skipped suites print `SKIPPED`.

## Unit tests (no I/O)

Per BP §15: schema validation (serde round-trips + required-field rejection) · chain-ID validation · capability validation (expiry, scope, subject) · policy rules (each rule allow/deny/escalate + reason codes) · unlimited-approval detection (max-uint, threshold edge, bounded) · calldata decoding (approve/transfer/transferFrom/permit/unknown selectors, truncated calldata) · state transitions (exhaustive legal/illegal table, terminal absorption) · audit-event chaining (build, verify, tamper detection) · risk aggregation (unknown stays unknown; conflict representation; ordering independence).

## Integration tests (Anvil)

Anvil lifecycle (connect, chain-id check) · sample token + spender deployment · **exact approval end-to-end happy path** (all 12 states, audit reconstruction) · **unlimited approval denied** · wrong-chain request rejected · unauthorized dapp rejected · expired capability rejected · simulation failure path (reverting tx → SIMULATION_FAILED, no signing) · signer locked (SIGNING_FAILED) · broadcast failure (invalid nonce injection → BROADCAST_FAILED).

## Security regression tests (invariants encoded)

| Test | Invariant (BP §15) |
|---|---|
| `renderer_cannot_reach_signer` | no public API path from presentation/provider surface to raw signer ops; vault exposes no key export (compile-time + runtime probe) |
| `malformed_envelope_rejected` | malformed/oversized IPC or provider requests rejected at RECEIVED |
| `missing_dapp_identity_rejected` | dapp identity cannot be omitted |
| `wrong_chain_rejected` | chain mismatch is rejected |
| `policy_not_bypassed_by_missing_fields` | undecoded/missing fields take the restrictive path |
| `risk_cannot_override_policy_denial` | AI/risk explanation cannot override a deterministic denial |
| `no_private_key_export_surface` | provider/browser-facing interfaces cannot invoke key export (no such method exists; probe asserts) |
| `unknown_risk_not_low` | unknown risk never renders/aggregates as low |
| `unlimited_approval_blocked` | default policy blocks unlimited ERC-20 approvals |
| `locked_vault_refuses_signing`, `expired_capability_rejected` | vault gate conditions |
| `state_machine_no_skip` | signing unreachable without full pipeline |
| `tampered_audit_log_detected` | in-place audit edits detected by verify |

## Property-based / fuzz testing

Milestone 1: property tests (proptest) for state-machine closure (random transition sequences never reach SIGNED without the required prefix) and decoder robustness (arbitrary bytes never panic; non-matching selectors always yield Unknown). Roadmap (W1): cargo-fuzz targets for envelope JSON, calldata, and audit-line parsing in CI.

## Coverage philosophy

Coverage percentage is not a goal; **invariant coverage is**. Every threat-model row marked `mitigated-P` must cite at least one test; every abuse case that claims a test must have it. Reviewers check that mapping, not a number.
