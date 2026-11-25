# W4113T operator console — guide

The console is presentation only: it renders state and routes to the same
trust-spine crates the non-interactive CLI uses. It makes no security
decisions of its own. Launch with `make console` (alias: `make W4113T`).

Every prompt accepts blank to go back. Unrecognized input always prints a
reason — if nothing happened, that is a bug, report it.

## Menu

- 1 status — vault, chain, audit detail (the vault signer is a MOCKED
  Anvil dev key, worthless by design; unrelated to the external signer).
- 2 aliases — saved EVM addresses with labels. Every label is available as
  a transfer recipient; selecting a numbered entry also pre-fills the signer
  key-load step in 9. Paste an address to add it. Only address+label are
  stored (`data/signer-aliases.json`, retained for compatibility) — never key
  material. Labels resolve by exact case-insensitive match; an ambiguous
  duplicate refuses rather than choosing an address.
- 3 chains — registry view. Enter a number to set the session-active
  chain (marked with a dot). Chain-bound flows refuse to run when the
  active chain does not match.
- 4 decode — paste calldata, get the decoded intent.
- 5 policy — view the active policy JSON.
- 6 audit — verify the hash chain or inspect recent events.
- 7 permissions — list grants, revoke by id.
- 8 vault — lock / unlock the (mocked) vault.
- 9 external-signer — a chain-family dispatcher: EVM (Sepolia / Ethereum
  mainnet) lifecycle when the active chain is one of those, or the Solana
  (devnet / mainnet-beta) vaultd-hosted ceremony when the active chain is a
  Solana cluster (both below).
- a assets — unified view: every chain this repo ships an adapter for, every
  held asset, filterable by network class (all/development/testnet/mainnet).
  Chain identity and network class come from the same `ChainRegistry` 3
  reads; holdings are demo fixture data, clearly labeled, not live balances.
- h help — this guide. Also: ?, /help, /guide.

## External-signer lifecycle (Sepolia)

Step by step:

1. (optional) 2 — select or paste your signing address, and manage recipient
   aliases.
2. 9 — the flow refuses immediately unless the active chain is Sepolia.
3. l — load a key. Confirm the declared address (blank = the address
   selected in 2), then paste the private key; input is not echoed, the
   key is verified to derive the declared address, and lives only in this
   process for this session. Also: l <0xaddress> in one go.
4. s — send. Guided mode prompts for recipient and amount. One-go mode:

       s <recipient-or-alias> a <wei>

   Fields may appear in either order; multi-word aliases stay together on
   one side of `a <wei>`; whatever you omit is prompted. Examples: `s` ·
   `s 0xAbC… a 10` · `s Test Target a 10` · `s a 10` (self-send, 10 wei).
5. Preflight prints from/to/value/nonce/gas/balance and the chain id as
   reported by the RPC itself (config is never trusted for chain identity).
   When a recipient alias is used, the label and authoritative resolved
   address are both shown; verify the address, not only the label. Then, and
   only then, you type the approval phrase to sign and broadcast. The phrase
   is deliberately a separate step after the preview — it cannot be supplied
   inline.
6. The tx is audited before broadcast, the receipt is polled, and the
   observer verification command is printed
   (tools/metamask-lifecycle-harness/verify-artifact.sh <tx-hash>).

## Solana external-signer ceremony (devnet / mainnet-beta, ADR-021)

Requires **cipherlayer-vaultd running in its own terminal** — it hosts the
approval phrase and key prompts on its own tty. The key is NEVER entered in
the console; this process cannot leak what it never holds.

1. 3 — switch the active chain to Solana devnet or Solana mainnet-beta.
2. 9 — the Solana ceremony starts. It resolves the RPC (mainnet is
   explicit-only: `CIPHERLAYER_SOLANA_MAINNET_RPC` must be set, no public
   fallback; devnet falls back to api.devnet.solana.com) and re-verifies the
   cluster's pinned genesis hash live before anything else.
3. Enter the facts in the console (all public): sender pubkey, recipient
   pubkey, amount in lamports. A preflight prints from/to/amount (with the
   SOL equivalent)/fee-estimate/balance/cluster.
4. **Switch to the vaultd terminal:** it displays the same facts and asks
   for the chain-labeled approval phrase there
   (`SEND-CIPHERLAYER-SOLANA-DEVNET` / `-MAINNET`). Approval is valid ~90s.
5. The console builds the final message with a fresh blockhash and its
   authoritative fee, then hands off to vaultd again, which asks for the
   private key on its terminal (input hidden), verifies it derives to the
   approved sender, signs, and wipes it.
6. The signature is audited before broadcast, the transaction is broadcast,
   and confirmation is polled; the explorer link is printed. On a broadcast
   without confirmation, DO NOT re-run until an explorer shows the signature
   absent — Solana transactions carry no replay-window nonce.

Fee honesty (ADR-021 §4): a cluster that returns no fee is shown as
`unknown`, never a guessed number. On mainnet, unknown refuses; a final fee
above the approved estimate refuses (re-run with the new number). Devnet may
proceed on unknown.

## Environment

- CIPHERLAYER_QUICKNODE_SEPOLIA_URL — premium Sepolia RPC (URL never printed).
- CIPHERLAYER_SEPOLIA_RPC — plain Sepolia RPC override.
- CIPHERLAYER_SIGNER_ALIASES — alias file path (default data/signer-aliases.json).
- CIPHERLAYER_VAULT_STATE — mocked-vault lock state file.
- NO_COLOR — disable all styling.
- CIPHERLAYER_MAINNET_RPC — Ethereum mainnet RPC (ADR-020; public fallback
  is used when unset — URL never printed if it embeds a token).
- CIPHERLAYER_SOLANA_MAINNET_RPC — Solana mainnet-beta RPC (ADR-021;
  REQUIRED for the mainnet ceremony, no public fallback — URL never printed).
- CIPHERLAYER_SOLANA_MAINNET_RPC_CROSSCHECK — independent second mainnet
  provider (ADR-021 §6; REQUIRED, must differ from the primary). Re-attests
  the pinned genesis and the final message's blockhash immediately before
  broadcast; unavailable or unknown answers refuse, closed. The hostname
  check only catches same-host dressing — the primary and cross-check must
  be **administratively independent providers** (different companies, not
  two subdomains of one vendor); that part is on the operator (ADR-021 §7).
- All non-loopback Solana RPC URLs (primary and cross-check, both clusters)
  must be https:// — cleartext refuses, closed (ADR-021 §7). Loopback
  (local validator) is exempt.
- CIPHERLAYER_SOLANA_DEVNET_RPC — Solana devnet RPC override (falls back to
  api.devnet.solana.com when unset).
- CIPHERLAYER_SOLANA_DEVNET_RPC_CROSSCHECK — optional devnet cross-check
  provider (same role as the mainnet one; absence is an accepted
  single-provider residual on devnet).
- CIPHERLAYER_VAULT_SOCKET — vaultd IPC socket (default data/vaultd/vault.sock);
  the Solana ceremony connects here for the terminal-hosted phrase and key.

## Known limitations

- **No line editing or arrow-key navigation.** The console is plain
  stdin/stdout by design (minimal-dependency posture — no TUI framework,
  no raw-mode terminal handling). Arrow keys emit escape sequences that
  land as literal input; use your terminal's paste and backspace instead.
  Flagged by the operator 2026-07-17; a readline-style input layer is a
  candidate refinement if console use grows.
- **Approval phrases are exact-match** (hyphens included). A mismatch now
  says so and lets you retry; a blank entry cancels.
- **Design rule (operator, 2026-07-17): nothing exits without an
  explanation.** Every refusal, cancellation, or fall-through must say what
  happened and how to proceed. Silent returns are bugs — report them.
