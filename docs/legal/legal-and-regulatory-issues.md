# Legal and Regulatory Issues Register

**Version:** 0.1 · **Status:** engineering-maintained issue register, **not legal advice**; formal counsel review is an open item. The operator's regulatory background is a product wedge (US §6, §14), which raises — not lowers — the bar for accuracy here.

## Operator positions recorded (US §16) and their caveats

| Question (BS §14) | Operator answer | Engineering caveat recorded |
|---|---|---|
| Does any feature create custody or intermediary status? | **No** | Defensible today: prototype holds only worthless test keys and never routes user funds. Must be re-analyzed before: native key custody, external-signer relay, any fee on transactions, session-key issuance, or hosted services. |
| Does personalized AI analysis become regulated advice? | **No** | Holds while output is transaction *explanation* and generic risk evidence. Personalized portfolio recommendations, "you should buy/sell", or fee-linked routing suggestions would reopen the question (investment-adviser characterization). |
| What security claims are defensible? | "Antivirus-type disclaimer, best effort, no guarantees" | Recorded as posture, but BP §18 governs: disclaimers do not cure functionally misleading claims. Every claim is individually registered in `../security/security-claims-register.md` with prohibited overstatements. |

## Issue register

| ID | Issue | Trigger | Risk | Current posture | Required before status change |
|---|---|---|---|---|---|
| LEG-01 | Custody classification | native seed storage, hosted signing, recovery services | custodian/VASP status, licensing | No custody exists (test keys, local chain) | formal analysis per target jurisdiction |
| LEG-02 | Money-transmitter / intermediary status | routing user transactions, fees tied to transfers | licensing, penalties | No routing of value; local broadcast of user-authorized txs only | counsel review at testnet/mainnet enablement |
| LEG-03 | Investment-adviser characterization | personalized recommendations, paid signals | registration obligations | Explanations + deterministic policy only; no recommendations | product review of any advisory feature |
| LEG-04 | Broker/exchange characterization | integrated swap routing, order handling, MEV routing fees | securities/commodities regimes | Deferred scope; nothing implemented | ADR + counsel before any swap/routing feature |
| LEG-05 | Security-representation liability | marketing "blocks scams/drains" | consumer-protection, negligence claims on missed detection | Claims register discipline; risk output shows confidence and unknowns | legal sign-off per claim; jurisdiction matrix |
| LEG-06 | Sanctions / screening obligations | mainnet operation, hosted services, screening adapters | sanctions exposure either way (screening wrongly or not at all) | Not applicable on local dev chain; "adapters where lawful" (BS §6.7) deferred | counsel design review before any screening feature |
| LEG-07 | Privacy regulation (GDPR et al.) | telemetry, sync, hosted anything | data-protection obligations | Local-first, zero telemetry; RPC-leakage disclosure documented | DPIA if any cloud/sync feature is added |
| LEG-08 | Custody-clarity representations | UI labels of custody states | user confusion → liability | Typed custody vocabulary in data model (CL-LEG-003); plain-language surfacing at W2 | UX + legal review of labels at W2 |
| LEG-09 | Token ≠ legal right | any DAO/tokenized-structure visualization (deferred) | implying tokens confer off-chain rights | Principle encoded: representations must distinguish technical control, economic interest, governance, legal rights (BS §6.15) | counsel review of visualization semantics (Phase 8) |
| LEG-10 | Jurisdiction scope | distribution | divergent regimes (US, MX, EU cited in BS §14) | Undetermined; no distribution exists | jurisdiction matrix before public release |
| LEG-11 | License & warranty terms | publishing the repo | warranty/liability defaults | Apache-2.0 + DCO, family-wide (operator decision 2026-07-16, UQ-004 resolved) | counsel review of Apache-2.0 warranty disclaimer before public release |
| LEG-12 | Export/cryptography restrictions | distribution of signing software | export-control regimes | Standard open-source crypto deps; no distribution yet | check at release |

## Software-encoded distinctions (CL-LEG-003)

The type system distinguishes, and user surfaces must plainly label: self-custody · external custody · smart-account authority · multisignature authority · delegated authority · session key · approval · allowance · bridge deposit · staking · wrapping · watch-only. The wallet tells the user in plain language when they are signing, granting an allowance, connecting, delegating, bridging, or changing custody (US §4.5) — implemented in data model now, in UI at W2.

## Standing rule

Any feature touching LEG-01…LEG-06 triggers: ADR + this register update + operator/counsel review **before** implementation, not after.
