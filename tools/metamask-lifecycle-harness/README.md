# MetaMask Lifecycle Harness — First Real External-Signer Test

**Requirement:** CL-WAL-010 · **Decision:** ADR-005 amendment (2026-07-05, operator decision AC-004) · **Reference pattern:** `~/Dev/Arrow/tools/lifecycle-harness` (Arrow's on-chain lifecycle test discipline, adapted here)

This is the first *real* signer integration test in the family: everywhere else, "signing" means the MOCKED `TestSigner` on Anvil with well-known dev keys (ADR-005). Here, a real installed MetaMask extension holds the key and is the only component that authorizes a signature — mirroring the Vault's own core invariant, but for an external signer instead of the in-process one.

**This harness never touches key material.** No private key, seed phrase, or mnemonic appears anywhere in this directory, in any script, or in any file this harness writes. MetaMask holds the key; the harness only *requests* signatures through the standard injected-provider protocol (EIP-1193/EIP-6963), exactly as any dapp would.

## The originator / observer split (Arrow discipline, adapted)

| Role | What it does | Surface |
|---|---|---|
| **Originator** | Spend-capable. Connects to MetaMask, previews the transaction, requires the operator to type an approval phrase *here*, then requires the operator to approve *again* inside MetaMask's own popup. | A real browser, human at the keyboard. **Never** automated — no script or agent clicks the MetaMask confirmation button. |
| **Observer** | Read-only. Polls a public Sepolia RPC for the transaction receipt and writes a verified evidence artifact. | Safe to automate (`verify-artifact.sh`), carries zero spend authority. |

If browser automation (e.g. Claude-in-Chrome) is used to drive this page, it may click *this page's* buttons (connect, preview, send-request) up through requesting the transaction — but the actual MetaMask extension popup that appears afterward must be approved by the human operator, never by automation. This mirrors Arrow's rule verbatim: "a spend key must not flow through an automated relay."

## Safety properties enforced in code

- **MetaMask only.** Uses EIP-6963 (`eip6963:requestProvider`/`announceProvider`) to find the provider that specifically announces as MetaMask, even with multiple wallet extensions installed. Falls back to `window.ethereum` only if it self-identifies via `isMetaMask`. No silent fallback to any other wallet.
- **Sepolia only.** The chain id is checked before preview and re-checked before send; every other chain is refused. There is no mainnet code path in this file.
- **Two-gate approval.** The Send button stays disabled until the exact phrase `SEND-METAMASK-SEPOLIA-LIFECYCLE` is typed on this page — and MetaMask's own popup is the second, non-bypassable gate.
- **Minimal value.** Defaults to sending 1 wei to the connected account itself (a self-send), so no third-party recipient or amount beyond dust is required for the test to be meaningful. Both fields are operator-editable at runtime; nothing operator-specific is baked into committed files.

## Running it

```bash
# 1. Serve the harness (binds 127.0.0.1 only — never reachable off-host):
./serve.sh
# 2. Open http://127.0.0.1:8931/index.html in the browser where MetaMask is installed.
# 3. Ensure MetaMask has some Sepolia test ETH (a faucet, e.g. sepoliafaucet.com,
#    if not — the harness will show a normal MetaMask "insufficient funds" error
#    otherwise, which is a legitimate and safe way to discover this).
# 4. Click through steps 1-5 on the page. Approve the connection and the
#    transaction inside MetaMask when its popup appears.
# 5. Once step 5 shows a receipt, independently verify from the CLI:
./verify-artifact.sh 0x<the tx hash from the page>
```

`verify-artifact.sh` re-derives the chain id from the RPC itself and refuses to write an artifact if it isn't Sepolia — it does not trust the page's own report of the network.

## Environment

- `CIPHERLAYER_MM_HARNESS_PORT` — local port for `serve.sh` (default `8931`).
- `CIPHERLAYER_SEPOLIA_RPC` — RPC for `verify-artifact.sh` (default `https://ethereum-sepolia-rpc.publicnode.com`; `rpc.sepolia.org` was tried first and found decommissioned — 404 from a bare Apache server — during the first live run).

## Evidence

Verified artifacts land in `docs/test/evidence/metamask-sepolia-lifecycle-<hash-prefix>.json`, schema `cipherlayer-metamask-lifecycle.v1`. These are real Sepolia transactions (worthless testnet value) — not covered by any wallet security claim beyond "an external signer can be driven through the standard injected-provider protocol."

### First live run (2026-07-06)

Completed end-to-end by the operator: MetaMask discovered via EIP-6963, connected, confirmed already on Sepolia, previewed a 10-wei transfer to an operator-chosen recipient, approved via the on-page phrase and MetaMask's own popup, and returned a real tx hash. Independently verified against a fresh RPC (`ethereum-sepolia-rpc.publicnode.com`, not the page's own report): **status success, block 11212415, chain id 11155111 confirmed**. Artifact: `docs/test/evidence/metamask-sepolia-lifecycle-fcae624b456f.json`.

## What this does and does not prove

**Proves:** the family can drive a real, independent, unmodified external wallet (MetaMask) through the standard dapp-signing protocol, with two independent human-visible confirmation gates and no key material ever touching CipherLayer code.

**Does not prove:** integration with the CipherLayer Vault pipeline itself — this harness is a standalone dapp page, deliberately outside `cipherlayer-vault`'s `ExternalSignerAdapter` trait (still `THEORETICAL`, no implementation). Wiring a real `ExternalSignerAdapter` impl that calls into a browser session (via the browser repo's broker, or a future native-messaging bridge) is follow-on work once this harness has demonstrated the mechanics work end-to-end.
