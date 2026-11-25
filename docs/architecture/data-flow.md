# Data Flow — CipherLayer Wallet

**Version:** 0.1 · Flows shown are implemented in the milestone-1 vertical slice unless marked deferred.

## Transaction-signing flow (end to end)

```mermaid
sequenceDiagram
    participant R as Requester (CLI / dapp via envelope)
    participant P as Provider broker
    participant D as EVM decoder
    participant S as Simulation (Anvil)
    participant K as Risk (FPL consumer)
    participant Y as Policy engine
    participant U as User
    participant V as Vault
    participant C as Chain (Anvil)
    participant A as Audit log

    R->>P: transaction-request-envelope.v1
    P->>A: RequestReceived
    P->>P: validate (identity, chain, permission scope)
    P->>A: RequestValidated / PermissionChecked
    P->>D: raw tx request
    D->>D: decode calldata (approve/transfer/permit/unknown)
    D->>A: IntentDecoded
    D->>S: intent + raw tx
    S->>C: snapshot → impersonated exec → diff → revert
    S->>A: SimulationCompleted (or SimulationFailed)
    S->>K: intent + simulation evidence
    K->>K: detectors → normalized evidence (unknown stays unknown)
    K->>A: RiskEvaluated
    K->>Y: intent + evidence bundle
    Y->>Y: deterministic rules → decision + reason codes
    Y->>A: PolicyEvaluated
    alt policy = deny
        Y-->>R: POLICY_DENIED (terminal)
    else allow / escalate
        Y->>U: decoded intent + simulation + risk + policy reasons
        U->>A: UserDecision (approve/reject)
        alt approved
            U->>V: authorization + capability
            V->>V: check lock, capability, chain class
            V->>A: SignatureCreated (or SigningFailed)
            V->>C: broadcast signed tx
            C->>A: BroadcastCompleted / BroadcastFailed
            C-->>R: receipt
        else rejected
            U-->>R: REJECTED (terminal)
        end
    end
```

## Simulation flow (detail)

```mermaid
flowchart LR
    IN["intent + raw tx"] --> SNAP["evm_snapshot"]
    SNAP --> PRE["read pre-state:<br/>balances, allowances of interest"]
    PRE --> IMP["anvil_impersonateAccount(sender)"]
    IMP --> EXEC["eth_sendTransaction"]
    EXEC -->|success| POST["read post-state"]
    EXEC -->|revert| REV["capture revert reason"]
    POST --> DIFF["normalize diffs:<br/>balance Δ, allowance Δ, gas"]
    REV --> NORM
    DIFF --> NORM["SimulationResult v1:<br/>outcome, diffs, gas,<br/>provider provenance, block, freshness,<br/>limitations[]"]
    NORM --> REVERT["evm_revert(snapshot)"]
```

The result is **evidence with provenance, never a guarantee**; the `limitations` list is always non-empty (state drift, conditional contract behavior, single-provider view).

## Permission flow

```mermaid
sequenceDiagram
    participant Dapp as Dapp / caller
    participant P as Provider broker
    participant U as User
    participant A as Audit log

    Dapp->>P: connection request (identity, chain, scope: read-only | signing)
    P->>A: ConnectionRequested
    P->>U: disclose accounts, chain, scope, expiry
    U->>P: grant / deny (scoped, expiring)
    P->>A: PermissionGranted / PermissionDenied
    Note over P: later requests checked against grant:<br/>expired ⇒ re-prompt · out-of-scope ⇒ reject
    U->>P: revoke (CLI permissions revoke)
    P->>A: PermissionRevoked
```

## Policy-decision flow

```mermaid
flowchart TB
    START["intent + simulation + risk evidence"] --> CHAIN{"chain allowed?"}
    CHAIN -->|no| DENY["DENY · POL-CHAIN-001"]
    CHAIN -->|yes| DENYLIST{"contract denylisted?"}
    DENYLIST -->|yes| DENY2["DENY · POL-DENY-001"]
    DENYLIST -->|no| APPROVAL{"is approval?"}
    APPROVAL -->|"unlimited"| UNL["default DENY · POL-APR-001<br/>(policy may set escalate, never silent allow)"]
    APPROVAL -->|"bounded"| LIMITS
    APPROVAL -->|"not an approval"| LIMITS{"value / gas within limits?"}
    LIMITS -->|no| ESC["ESCALATE or DENY · POL-LIM-00x"]
    LIMITS -->|yes| UNKNOWN{"decoded action unknown<br/>or simulation failed?"}
    UNKNOWN -->|yes| ESC2["ESCALATE · POL-UNK-001<br/>(never silent allow)"]
    UNKNOWN -->|no| RISKQ{"risk ≥ escalation threshold<br/>or conflicting/unknown?"}
    RISKQ -->|yes| ESC3["ESCALATE · POL-RSK-00x"]
    RISKQ -->|no| ALLOW["ALLOW (with reasons)"]
```

Deny short-circuits are terminal; escalation requires explicit user confirmation at USER_REVIEW; **no path authorizes without the deterministic engine**.

## Audit trail

Every step above appends one hash-chained event (`audit-event.v1`): `RequestReceived → RequestValidated → PermissionChecked → IntentDecoded → SimulationCompleted|SimulationFailed → RiskEvaluated → PolicyEvaluated → UserDecision → SignatureCreated|SigningFailed → BroadcastCompleted|BroadcastFailed`, plus `ConnectionRequested/PermissionGranted/PermissionRevoked` and terminal failures. `audit inspect --request <id>` reconstructs a lifecycle; `audit verify` recomputes the hash chain.
