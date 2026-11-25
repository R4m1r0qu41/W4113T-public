# ADR-012 — Trusted Confirmation-Surface Tier (v1)

**Status:** Accepted (tier v1 implemented) · **Date:** 2026-07-07 · **Decider:** operator · Implements `../architecture/trusted-confirmation-surface.md`; satisfies browser MVP gate criterion 4 on the wallet side. Follows ADR-004 (the process split this surface renders from).

## Context

`trusted-confirmation-surface.md` requires that a human authorizes signatures on a **wallet-owned, non-web, spoofing-resistant** surface, rendered by the Vault-side process (post ADR-004), and requires the spoofing-resistance tier to be *selected at W2 with an ADR* including a red-team exercise. UQ-003 (2026-07-04) directs: on macOS prefer the strongest tier first — Secure Enclave (SEP) / biometric binding on Apple silicon — degrading through OS window treatment, a consistent visual identifier, a user-selected secret phrase, an optional secure attention sequence, and hardware-wallet confirmation for the highest tier.

SEP/biometric binding requires a signed, entitled app bundle (LocalAuthentication, code signing, provisioning) — a substantially larger build than the current headless daemon. The confirmation surface is on the critical path for the browser gate now.

## Decision

Adopt, as **tier v1**, an OS-owned confirmation surface + secret-phrase marker, rendered by `cipherlayer-vaultd`:

- **System-owned chrome, no web content.** The surface is a macOS system dialog (`osascript`/`display dialog`) drawn by the OS, not by any renderer-hosting process. No HTML, no theme, no plugin, no dapp markup can draw into or restyle it (requirements 1–3).
- **User-selected secret phrase.** Read from `data/vaultd/confirm-phrase` (override `CIPHERLAYER_CONFIRM_PHRASE_FILE`), owner-only (0600) — the daemon refuses a group/world-readable phrase file. Shown on every genuine surface; a spoofer that cannot read the vault-user-only file cannot reproduce the marker (requirement 5, phrase tier).
- **Deterministic content only.** The dialog body is built by the daemon from the signing request and the pipeline's `ext.display` evidence (decoded intent, chain, account, to, value, simulation summary, risk with unknowns visible, policy reason codes). No advisory/AI text, no caller-supplied markup (requirements 4, 8).
- **Escalation is explicit.** A policy `escalate` verdict renders a distinct dialog requiring the operator to type `ESCALATE`; a `deny` is refused before any surface is shown and is never confirmable (requirement 7).
- **Fail closed.** Missing / unreadable / group-or-world-readable phrase file, unsupported platform, dialog launch error, timeout (120 s), or dismissal all resolve to refusal (`VLT-SUR-001`) or rejection (`VLT-USR-001`) — never approval (requirement 10).
- **Auditable.** Each decision emits a `UserDecision` audit event carrying `surface: desktop_trusted_surface` (requirement 9).

The Vault still re-validates every precondition after the decision — the surface obtains authorization; it does not bypass capability/lock/chain/policy checks.

### Wire mechanics

A new daemon message `confirm_and_sign` carries the signing request with `user_authorization: null` (signing-request schema v1.2 makes it nullable, legal only on this message) and `ext.display`. The daemon renders, obtains the decision, stamps the authorization with `desktop_trusted_surface`, and only then signs. Pipeline `ReviewMode::VaultSurface` (CLI `--vault-confirm`, requires `CIPHERLAYER_VAULT_SOCKET`) routes USER_REVIEW here.

`CIPHERLAYER_CONFIRM_AUTO=approve|reject` bypasses the dialog for tests/harnesses only — loud on stderr, and recorded in the decision detail; never a silent default.

## Alternatives considered

1. **SEP/biometric now** — the target tier (kept as the next increment). Rejected for v1 only on cost/sequencing: needs an app bundle + entitlements before anything can be demonstrated, and would block the gate.
2. **Native Rust GUI window (egui/iced)** — more visual control (persistent anti-spoof identifier), but pulls a large GUI dependency tree into the trust-critical daemon and is still not SEP-backed. Deferred; revisit with the SEP work.
3. **Keep the CLI terminal prompt** — rejected: it is the acknowledged spoofable surface (T-12) this ADR exists to replace.

## Red-team exercise (required before "trusted" may appear in any claim)

Per the acceptance-evidence requirement. Results 2026-07-07, this build:

| # | Attack | Result |
|---|---|---|
| RT-1 | A test page / rogue process draws its own `display dialog` mimicking the surface, without the phrase. | Distinguishable: the genuine surface always shows the user's secret phrase on its first line; the spoof cannot (it cannot read the 0600 phrase file). The documented marker is the tell. |
| RT-2 | A non-vault-user process attempts to read the phrase to reproduce the marker. | Prevented by OS file permissions: `confirm-phrase` is 0600 (verified group/world bits = 0). |
| RT-3 | The phrase file is tampered to be group/world-readable (marker no longer secret). | Fail closed: the daemon refuses with `VLT-SUR-001` ("phrase file is group/world accessible") and renders no surface — a leaked marker disables confirmation rather than degrading it. Reproduced live and in `surface_security.rs::group_readable_phrase_file_fails_closed`. |
| RT-4 | Caller smuggles a pre-filled `user_authorization` through `confirm_and_sign` to skip the human. | Refused: `confirm_and_sign` requires `user_authorization: null` (`surface_security.rs::confirm_and_sign_with_preauthorized_request_is_refused`). |
| RT-5 | Caller sends `confirm_and_sign` with no `ext.display` (nothing deterministic to show). | Refused before rendering (`…without_display_evidence_is_refused`). |
| RT-6 | A `deny` verdict is routed to the surface hoping the human clicks Approve. | Refused before any dialog: deny is never rendered (`deny_verdict_is_never_rendered_for_confirmation`). |

**Known residual (honest):** the phrase marker resists spoofers who cannot read the file, but not an attacker who has already achieved same-user code execution AND read the phrase — that adversary can reproduce the marker. Closing this is exactly what the SEP/biometric tier is for (a marker the attacker cannot extract). Occlusion detection (a spoof window drawn *over* the genuine one) is **not** implemented at v1; the system-dialog focus behavior is the only mitigation. Both are recorded as open items for the next tier. Until then, no user-facing wording may call this "unspoofable" — see the claims-register row.

## Consequences

- Browser MVP gate criterion 4 is satisfied on the wallet side: the confirmation flow is demonstrated outside the CLI, rendered by the Vault process, meeting requirements 1–4 and 6–10 fully and requirement 5 at the OS-chrome + secret-phrase tiers.
- `signing-request` schema is now v1.2 (nullable `user_authorization`); `vault-signing-response` adds `VLT-USR-001` / `VLT-SUR-001`. Affected claims-register row: SC-11 (new).
- macOS-only at v1; other platforms fail closed (no silent lower-assurance fallback).
- The SEP/biometric tier, a persistent visual identifier, and occlusion detection remain open, tracked here and in the requirements matrix.

## Revisit

When the SEP/biometric tier is built (app bundle + entitlements); if macOS dialog behavior changes; if occlusion attacks prove practical; on independent security review.
