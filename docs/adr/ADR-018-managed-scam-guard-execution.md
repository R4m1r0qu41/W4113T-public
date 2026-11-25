# ADR-018 - Managed Scam Guard Execution

**Status:** Accepted  
**Date:** 2026-07-11

## Context

ADR-009 established Scam Guard as an external, pinned-contract dependency. The
initial wallet adapter only ran the real detector when `CIPHERLAYER_FPL_BIN`
was set and otherwise substituted labeled mock findings. It also had no
subprocess deadline or output cap, and pinned a reason-code schema where the
operative registry instance was required.

## Decision

- The managed `scam-guard` executable is the default detector command.
  `CIPHERLAYER_FPL_BIN` selects an operator-managed installation.
- `CIPHERLAYER_FPL_MODE=mock` is an explicit test/demo-only escape hatch; it
  is never a fallback for a missing or failed real detector.
- The adapter caps input at 256 KiB, output at 1 MiB, and terminates the child
  after a bounded configurable timeout (2 seconds default, 100-30,000 ms).
- Findings are checked against the pinned v1 field surface and the pinned
  operative Reason Code registry before aggregation. Invalid output is
  detector unavailability, which aggregates to `unknown`.
- The integration remains a subprocess over the published contract. The wallet
  does not link or import Scam Guard implementation code.

## Consequences

An unavailable or malformed detector never silently becomes a mock
all-clear; it produces restrictive risk evidence. A hung detector adds up
to the timeout (2 s default) of pipeline latency before being killed.
Packaging must ship or install the `scam-guard` executable alongside the
wallet before a production release. This ADR does not make risk findings an
authorization mechanism: deterministic policy and the Vault retain authority.
