# Live bait assets — operator-donated trash/spam NFTs as test fodder

**Status:** idea, recorded 2026-07-17 (operator directive). Not implemented. Sandboxing rules below are binding before anything moves.

## The idea

The operator holds worthless NFTs and received spam NFTs and is willing to
commit them to the project as expendable live test assets ("if they get lost
it is fine"). Two uses:

1. **Bait / canary assets.** Any transaction the pipeline classifies as
   *very high risk* could first be exercised against a trash NFT instead of
   anything of value — a live-fire rehearsal: if the drain attempt is real,
   the attacker gets a spam NFT and we get a full audit-logged capture of the
   attack shape.
2. **Spam-NFT corpus.** The spam NFTs themselves are real, in-the-wild
   hostile artifacts (lure names, malicious collection links, wash-trade
   patterns). They are exactly the evidence class scam-guard's adversarial
   corpus currently synthesizes — real specimens would ground it
   (`datasets/adversarial-corpus`, FPL detection-floor discipline).

## Sandboxing rules (binding, per wallet AGENTS.md)

- **Dedicated burner account only.** The bait assets live on a fresh keypair
  used for nothing else — never the vault's dev keys, never any account that
  also holds anything of value, never an account reused for identity.
- **No mainnet path from the pipeline.** The wallet's default chain stays
  Anvil/testnets; any mainnet interaction with these assets goes through the
  operator-driven external-signer flow (ADR-011) exactly like the Sepolia
  work — the wallet itself never holds a mainnet-capable hot key for this.
- **Fork, don't touch.** The primary way to use the bait NFTs in tests is an
  Anvil **mainnet fork** of the block where they exist: `anvil --fork-url …`
  gives every suite the real contracts + real spam assets with zero live
  risk. Live-mainnet bait use is a deliberate, operator-confirmed act each
  time, never automated.
- **Spam NFTs are hostile input.** Their metadata/URLs are attacker-authored:
  never fetch their `tokenURI` from wallet/browser code outside a sandboxed,
  offline capture step; strings from them enter scam-guard as *subjects*,
  never as anything executed or rendered in trusted chrome.
- **No value creep.** If any bait asset ever appreciates or a bait account
  accumulates anything of value, it exits the program (transfer out or
  abandon) — the whole point is that total loss is acceptable.

## Next steps (when picked up)

1. Operator inventories the assets (chain, contract, token id) into a small
   `datasets/`-style manifest — that list is itself useful corpus data.
2. Capture spam-NFT metadata offline into scam-guard's adversarial corpus as
   real specimens (new corpus entries, hostile class).
3. ERC-721/1155 decode support (W1 leftover) is a prerequisite for the
   wallet to reason about NFT transfers at intent level.
4. A "rehearse against bait first" flow is a policy/UX design question
   (very-high-risk ⇒ offer dry-run against bait) — needs an ADR before any
   implementation; it must never weaken the deny path (a rehearsal is in
   addition to policy, never instead of it).
