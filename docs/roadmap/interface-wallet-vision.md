# The Interface Wallet — CipherLayer as a clean layer over other wallets

**Status:** operator product-vision note, recorded 2026-07-17. Not scoped, not scheduled — recorded so the thesis doesn't live only in one session's chat log. Candidate for a future ADR when any piece of it is picked up.

## The thesis (operator, 2026-07-17)

The external-signer test (MetaMask holds the key, CipherLayer is the
interface) is not just a test harness — it's a product shape:

> "What if you could place the wallet as an interface on top of other
> wallets? That way you have a clean-looking wallet, CLI-compatible, Web3-
> browser-compatible, integrated, personally customizable — a wallet
> without all the noise (e.g. OKX, Binance are full of noisy non-useful
> options). Same with custodial wallets: not your keys, but if you can
> sign on that wallet, there should be a way to external-sign and bolt
> CipherLayer onto it too."

CipherLayer's trust spine (decode → simulate → risk → policy → review →
audit) is key-agnostic by construction — ADR-011 already split "who holds
the key" from "who reviews the decision." That split generalizes:

| Key holder | CipherLayer's role | Status |
|---|---|---|
| CipherLayer vault (dev keys) | full custody + review | built (dev-only) |
| Operator-pasted runtime key | review + relay signing | built (Sepolia + mainnet, ADR-020) |
| MetaMask / browser wallets | review in front, wallet signs | harness proven; native-messaging adapter deferred (ADR-011) |
| Exchange/custodial accounts (OKX, Binance, …) | review in front, custodian signs via their API/flow | idea only — this note |
| Hardware wallets | review in front, device signs | natural fit, unscoped |

## Why it's differentiated

- Every wallet above ships its own noisy UI and its own (usually absent)
  risk analysis. CipherLayer's pipeline + evidence panel + deterministic
  policy is the part none of them have — and it doesn't need the keys to
  deliver it.
- One consistent, customizable, minimal interface across N backends beats
  N noisy interfaces; the trust spine stays identical regardless of who
  custodies.
- The audit log becomes a unified record of the user's *decisions* across
  all their wallets, not just one.

## Honest constraints (to face when scoping)

- Custodial "bolt-on" depends entirely on what each custodian exposes
  (APIs, transaction-review hooks, withdrawal allow-lists). Some will have
  no clean signing hook at all; this is per-custodian integration work.
- CipherLayer-in-front can *advise and refuse to relay*, but a user can
  always bypass it by going to the underlying wallet directly — the
  security claim must stay honest: decision support, not enforcement,
  unless the backend can be scoped to only accept CipherLayer-relayed
  requests.
- Each new backend is a new external-signer authority needing its own
  ADR-011/ADR-020-style scope decision (which chains, which ceremonies).

## Nearest concrete steps (when picked up)

1. The already-deferred MetaMask native-messaging adapter (ADR-011) is the
   first real instance of this pattern beyond the paste-key flow.
2. `ExternalSignerAdapter` today is EVM/alloy-specific and paste-key-shaped;
   a backend-agnostic signing-authority trait (request out → signature
   back, any transport) would be the architectural seam.
3. Survey 2–3 custodial APIs (e.g. exchange withdrawal/signing APIs) for
   whether a review-in-front integration is even possible per-custodian.
