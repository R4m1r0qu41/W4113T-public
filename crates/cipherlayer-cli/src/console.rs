//! The W411T operator console — an interactive, oldschool-CLI front end over
//! the wallet's capabilities. Presentation only: it renders state and routes
//! to the same trust-spine crates the non-interactive CLI uses; it makes no
//! security decisions of its own (the terminal is a spoofable surface, T-12).
//!
//! No TUI framework: plain stdin/stdout + ANSI, matching the family's
//! minimal-dependency posture. Colour degrades to plain text when NO_COLOR is
//! set or output is not a TTY.

use cipherlayer_audit::AuditLog;
use cipherlayer_chain::adapter::ChainObserver;
use cipherlayer_chain::ChainRegistry;
use cipherlayer_policy::Policy;
use cipherlayer_provider::PermissionStore;
use cipherlayer_types::{Address, NetworkClass};
use cipherlayer_vault::{
    external_signer::EXTERNAL_SIGNER_KEY_ENV, TestSigner, Vault, ANVIL_DEV_KEYS,
};
use std::io::{self, Write};
use std::path::PathBuf;

/// Fixture holdings for the console's unified `assets` view (menu `a`).
/// Presentation only, like the rest of this console — never balances read
/// from a chain. Mirrors `apps/desktop`'s fixture set so the CLI and desktop
/// unified views tell the same demo story from the same source chains.
enum DemoAssetKind {
    Token,
    Nft,
}

struct DemoAsset {
    kind: DemoAssetKind,
    symbol: &'static str,
    name: &'static str,
    /// Amount for a token, collection name for an NFT.
    detail: &'static str,
}

// Reconciled by hand against `apps/desktop/src/app.js`'s fixture on every
// change — same chains, same per-chain holdings, same counts (8 chains / 13
// tokens / 7 NFTs total). Kept as two hardcoded copies rather than one
// shared source: Rust and browser JS, no existing shared-fixture channel,
// and duplicating ~40 lines of demo data beats standing up a build-time
// codegen step for a fixture that only needs to compile-check identical.
/// Which RPC (if any) the assets view may read a live native balance from.
/// Development chains use the console's own RPC; Sepolia uses the same env
/// order as the external signer. Mainnet-class chains are never queried by
/// default, and non-EVM families are not wired (CL-WAL-013).
fn live_balance_rpc(entry: &cipherlayer_chain::ChainEntry, dev_rpc: &str) -> Option<String> {
    use cipherlayer_chain::ChainFamily;
    if entry.chain_family != ChainFamily::Evm {
        return None;
    }
    if entry.chain_id.0 == 31337 {
        return Some(dev_rpc.to_string());
    }
    if entry.chain_id.0 == cipherlayer_vault::external_signer::SEPOLIA_CHAIN_ID {
        return Some(
            std::env::var("CIPHERLAYER_QUICKNODE_SEPOLIA_URL")
                .or_else(|_| std::env::var("CIPHERLAYER_SEPOLIA_RPC"))
                .unwrap_or_else(|_| "https://ethereum-sepolia-rpc.publicnode.com".to_string()),
        );
    }
    None
}

/// Read-only `eth_getBalance`, bounded by a timeout. Display only: the
/// node's chain identity is not verified here, so a hostile node can show a
/// wrong number labeled live. The result must never feed policy or signing.
async fn fetch_native_balance(
    rpc: &str,
    address: cipherlayer_types::Address,
) -> Result<cipherlayer_types::U256, String> {
    use alloy::providers::{Provider, ProviderBuilder};
    let url = rpc.parse().map_err(|_| "unparseable rpc url".to_string())?;
    let provider = ProviderBuilder::new().connect_http(url);
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.get_balance(address),
    )
    .await
    {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(_)) => Err("rpc error".to_string()),
        Err(_) => Err("timeout".to_string()),
    }
}

/// `wei`-style integer to a decimal string, up to 6 fractional digits,
/// trailing zeros trimmed.
fn format_units_trimmed(v: cipherlayer_types::U256, decimals: u8) -> String {
    let digits = v.to_string();
    let d = decimals as usize;
    let padded = if digits.len() <= d {
        format!("{}{}", "0".repeat(d + 1 - digits.len()), digits)
    } else {
        digits
    };
    let (int, frac) = padded.split_at(padded.len() - d);
    let frac: String = frac.chars().take(6).collect();
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int.to_string()
    } else {
        format!("{int}.{frac}")
    }
}

/// Live balance label. A failed fetch is "unavailable", never zero.
fn format_live_native(
    result: Result<cipherlayer_types::U256, String>,
    decimals: u8,
    symbol: &str,
) -> String {
    match result {
        Ok(v) => format!("{} {symbol} (live)", format_units_trimmed(v, decimals)),
        Err(why) => format!("unavailable ({why}) — not zero"),
    }
}

fn demo_assets_for(chain_id: u64) -> &'static [DemoAsset] {
    use DemoAssetKind::{Nft, Token};
    match chain_id {
        31337 => &[
            DemoAsset {
                kind: Token,
                symbol: "ETH",
                name: "Ether (native)",
                detail: "10.0 ETH",
            },
            DemoAsset {
                kind: Token,
                symbol: "TT",
                name: "Sample ERC-20 (demo)",
                detail: "500 TT",
            },
            DemoAsset {
                kind: Nft,
                symbol: "SC",
                name: "Sample Collectible #1",
                detail: "Demo Collectibles",
            },
        ],
        900002 => &[DemoAsset {
            kind: Token,
            symbol: "BTC",
            name: "Bitcoin (regtest, native)",
            detail: "2.50000000 BTC",
        }],
        cipherlayer_vault::external_signer::SEPOLIA_CHAIN_ID => &[
            DemoAsset {
                kind: Token,
                symbol: "ETH",
                name: "Ether (native)",
                detail: "0.42 ETH",
            },
            DemoAsset {
                kind: Token,
                symbol: "USDC",
                name: "USD Coin (test)",
                detail: "120.00 USDC",
            },
            DemoAsset {
                kind: Nft,
                symbol: "TB",
                name: "Testnet Badge #7",
                detail: "Faucet Badges",
            },
        ],
        cipherlayer_chain::SOLANA_DEVNET_CHAIN_ID => &[
            DemoAsset {
                kind: Token,
                symbol: "SOL",
                name: "Solana (native, devnet)",
                detail: "5.0 SOL",
            },
            DemoAsset {
                kind: Token,
                symbol: "USDC",
                name: "USD Coin (devnet)",
                detail: "50.00 USDC",
            },
        ],
        42161 => &[
            DemoAsset {
                kind: Token,
                symbol: "ETH",
                name: "Ether (native)",
                detail: "0.081 ETH",
            },
            DemoAsset {
                kind: Token,
                symbol: "ARB",
                name: "Arbitrum",
                detail: "64.2 ARB",
            },
            DemoAsset {
                kind: Nft,
                symbol: "AO",
                name: "Arbitrum Odyssey #214",
                detail: "Arbitrum Odyssey",
            },
            DemoAsset {
                kind: Nft,
                symbol: "AO",
                name: "Arbitrum Odyssey #891",
                detail: "Arbitrum Odyssey",
            },
        ],
        8453 => &[
            DemoAsset {
                kind: Token,
                symbol: "ETH",
                name: "Ether (native)",
                detail: "0.015 ETH",
            },
            DemoAsset {
                kind: Nft,
                symbol: "BN",
                name: "demo.base.eth",
                detail: "Basenames",
            },
        ],
        10 => &[
            DemoAsset {
                kind: Token,
                symbol: "ETH",
                name: "Ether (native)",
                detail: "0.003 ETH",
            },
            DemoAsset {
                kind: Token,
                symbol: "OP",
                name: "Optimism",
                detail: "18.9 OP",
            },
        ],
        cipherlayer_chain::SOLANA_MAINNET_CHAIN_ID => &[
            DemoAsset {
                kind: Token,
                symbol: "SOL",
                name: "Solana (native)",
                detail: "1.24 SOL",
            },
            DemoAsset {
                kind: Nft,
                symbol: "ML",
                name: "Mad Lads #4021",
                detail: "Mad Lads",
            },
            DemoAsset {
                kind: Nft,
                symbol: "TN",
                name: "Tensorians #118",
                detail: "Tensorians",
            },
        ],
        _ => &[],
    }
}

/// A saved EVM (address, label) pair. The same address book is usable for a
/// signing address or a transfer recipient; it never contains key material.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct AddressAlias {
    pub label: String,
    pub address: String,
}

/// A direct address or an exact address-book resolution. The address remains
/// authoritative; `label` is presentation-only metadata shown beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAddressRef {
    pub address: Address,
    pub label: Option<String>,
}

fn normalized_alias_label(label: &str) -> String {
    label
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Strip ASCII control/escape bytes (e.g. terminal cursor-movement or
/// line-erase sequences) before a label reaches the terminal. Labels are
/// otherwise unrestricted in character content and are printed directly
/// beside the authoritative resolved address the operator is told to verify
/// before signing (T-11) — an unsanitized label could visually corrupt or
/// hide that address (code-review finding, 2026-08-20).
pub fn sanitize_display_label(label: &str) -> String {
    label.chars().filter(|c| !c.is_control()).collect()
}

/// Resolve an EVM address reference without fuzzy matching. A literal address
/// always wins. Aliases are exact (case-insensitive, whitespace-normalized),
/// and duplicate labels that point at different addresses refuse closed.
pub fn resolve_evm_address_ref(
    input: &str,
    aliases: &[AddressAlias],
    role: &str,
) -> Result<ResolvedAddressRef, String> {
    let input = input.trim();
    if let Ok(address) = cipherlayer_evm::parse_address(input) {
        return Ok(ResolvedAddressRef {
            address,
            label: None,
        });
    }
    // A 0x-prefixed token is always a literal-address attempt, never an
    // alias lookup — even when malformed. Falling through to the alias
    // table here would let a saved label that happens to resemble a
    // truncated/mistyped address silently resolve to a different address
    // instead of failing closed (code-review finding, 2026-08-20).
    if input
        .as_bytes()
        .get(0..2)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"0x"))
    {
        return Err(format!("\"{input}\" is not a valid EVM {role} address."));
    }

    let wanted = normalized_alias_label(input);
    let matches = aliases
        .iter()
        .filter(|alias| normalized_alias_label(&alias.label) == wanted)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(if aliases.is_empty() {
            format!(
                "\"{input}\" is not a valid EVM {role} address, and no address aliases are saved yet — add one in aliases (2)."
            )
        } else {
            format!(
                "\"{input}\" is not a valid EVM {role} address and matches no saved alias. Saved aliases: {}.",
                aliases
                    .iter()
                    .map(|alias| alias.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        });
    }

    let parsed = matches
        .iter()
        .map(|alias| {
            cipherlayer_evm::parse_address(&alias.address).map_err(|e| {
                format!(
                    "saved alias \"{}\" contains an invalid EVM address ({e}) — fix the address book before sending.",
                    alias.label
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let address = parsed[0];
    if parsed.iter().any(|candidate| *candidate != address) {
        return Err(format!(
            "saved alias \"{input}\" is ambiguous: it maps to multiple addresses — rename or remove the duplicate entries before sending."
        ));
    }

    Ok(ResolvedAddressRef {
        address,
        label: Some(matches[0].label.trim().to_string()),
    })
}

/// Fields the operator supplied inline with the send verb; anything left
/// `None` is collected step-by-step by prompts.
#[derive(Debug, Default, PartialEq)]
struct SendCommand {
    to: Option<String>,
    value_wei: Option<String>,
}

/// Parse the dual-mode send input: `s`/`send` alone (guided, every field
/// prompted) or one-go `s <recipient-or-alias> a <wei>` in either field order.
/// Multi-word aliases stay one contiguous field. Every rejection says why —
/// nothing falls through silently.
fn parse_send_command(input: &str) -> Result<SendCommand, String> {
    let mut tokens = input.split_whitespace();
    let verb = tokens.next().unwrap_or("");
    if verb != "s" && verb != "send" {
        return Err(format!(
            "\"{input}\" not recognized — type 's' for step-by-step, 's <recipient-or-alias> a <wei>' for one-go, or leave blank to go back."
        ));
    }
    let mut cmd = SendCommand::default();
    let mut recipient_parts = Vec::new();
    let mut recipient_after_amount = None;
    while let Some(tok) = tokens.next() {
        if tok == "a" || tok == "amount" {
            let Some(wei) = tokens.next() else {
                return Err("'a' needs a value: a <wei>.".into());
            };
            if !wei.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("amount must be plain wei digits, got \"{wei}\"."));
            }
            if cmd.value_wei.is_some() {
                return Err("amount given twice.".into());
            }
            cmd.value_wei = Some(wei.to_string());
        } else {
            let after_amount = cmd.value_wei.is_some();
            match recipient_after_amount {
                Some(side) if side != after_amount => {
                    return Err(
                        "recipient alias must be one contiguous field before or after `a <wei>`."
                            .into(),
                    );
                }
                None => recipient_after_amount = Some(after_amount),
                _ => {}
            }
            recipient_parts.push(tok);
        }
    }
    if recipient_parts.len() > 1
        && recipient_parts
            .iter()
            .any(|part| part.starts_with("0x") || part.starts_with("0X"))
    {
        return Err(
            "a literal 0x recipient must be one token; use a saved alias for a name with spaces."
                .into(),
        );
    }
    if !recipient_parts.is_empty() {
        cmd.to = Some(recipient_parts.join(" "));
    }
    Ok(cmd)
}

// --- Solana ceremony decision logic (ADR-021 §6) -------------------------
// Pure functions so every refusal branch is unit-testable: the ceremony
// body only plumbs RPC results through these.

/// Parsed RPC host, normalized for the cross-check independence test. URL
/// parsing is structural: string prefixes and hand-split authorities can
/// mistake a DNS name that resembles a loopback address for a local IP.
/// Two URLs on the same host are the same provider no matter how the rest of
/// the URL is dressed up (trailing slash, api key, case — external re-audit
/// finding, 2026-07-19).
fn rpc_host(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    match parsed.host()? {
        url::Host::Domain(host) => {
            // A trailing-dot FQDN (`host.`) is the same host as `host` —
            // normalize so it cannot pose as an independent provider.
            Some(host.trim_end_matches('.').to_ascii_lowercase())
        }
        url::Host::Ipv4(ip) => Some(ip.to_string()),
        // An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is the same host as
        // plain IPv4 `a.b.c.d` — normalize so it cannot pose as an
        // independent cross-check provider (code-review finding, 2026-08-20).
        url::Host::Ipv6(ip) => Some(
            ip.to_ipv4_mapped()
                .map(|v4| v4.to_string())
                .unwrap_or_else(|| ip.to_string()),
        ),
    }
}

/// TLS is required for any non-loopback RPC endpoint (external re-audit,
/// 2026-07-20): a cleartext hop can rewrite the very attestations — genesis
/// hash, blockhash validity, fee, balance — that the ceremony's gates rest
/// on, making the cross-check theater. Loopback (a local validator) is
/// exempt: it never leaves the machine.
fn require_sol_rpc_tls(url: &str, role: &str) -> Result<(), String> {
    let trimmed = url.trim();
    let parsed = url::Url::parse(trimmed)
        .map_err(|_| format!("could not parse the {role} RPC URL — refusing, closed."))?;
    let host = parsed.host().ok_or_else(|| {
        format!("could not extract a hostname from the {role} RPC URL — refusing, closed.")
    })?;
    // A real loopback ADDRESS only — never a string prefix. A name such as
    // `127.evil.com` remains `Host::Domain`, so it cannot inherit the local
    // cleartext exemption. Bracketed IPv6 is parsed as `Host::Ipv6`, making
    // the `::1` check real rather than dead string-splitting code.
    let loopback = match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    if parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(format!(
            "the {role} RPC URL is not https:// or an http:// loopback endpoint — insecure \
             RPC cannot carry identity attestations (ADR-021 §6). Use an https endpoint."
        ))
    }
}

/// Resolve the pre-broadcast cross-check endpoint (ADR-021 §6). Mainnet:
/// required, and it must be a DIFFERENT HOST from the primary — no single
/// provider is trusted alone. Devnet: optional (absent = accepted
/// single-provider residual), but if set it must still be independent.
/// Anything unparseable refuses, closed.
fn resolve_sol_crosscheck(
    is_mainnet: bool,
    primary_rpc: &str,
    env_value: Option<&str>,
) -> Result<Option<String>, String> {
    let candidate = env_value.map(str::trim).filter(|v| !v.is_empty());
    let Some(candidate) = candidate else {
        return if is_mainnet {
            Err(
                "CIPHERLAYER_SOLANA_MAINNET_RPC_CROSSCHECK is not set. Mainnet requires an \
                 independent second RPC provider to attest cluster identity and the final \
                 blockhash before broadcast (ADR-021 §6) — no single provider is trusted alone."
                    .into(),
            )
        } else {
            Ok(None)
        };
    };
    match (rpc_host(primary_rpc), rpc_host(candidate)) {
        (Some(p), Some(c)) if p != c => {
            require_sol_rpc_tls(candidate, "cross-check")?;
            Ok(Some(candidate.to_string()))
        }
        (Some(_), Some(_)) => Err(
            "the cross-check RPC is on the same host as the primary — independence is the \
             point (ADR-021 §6). Configure a different provider."
                .into(),
        ),
        _ => Err(
            "could not extract a hostname from an RPC URL — refusing the cross-check \
             configuration, closed."
                .into(),
        ),
    }
}

/// Map the cross-check attestation outcome to a verdict: only an explicit
/// `true` from the independent provider proceeds. `false` is a possible
/// cross-cluster blockhash; unavailable is a refusal, never a pass. Returns
/// the audit status slug alongside the operator-facing reason.
fn crosscheck_verdict(attests: Result<bool, String>) -> Result<(), (&'static str, String)> {
    match attests {
        Ok(true) => Ok(()),
        Ok(false) => Err((
            "aborted_pre_broadcast_crosscheck_blockhash",
            "the independent provider does not know this blockhash — possible \
             cross-cluster blockhash from a hostile primary (ADR-021 §6)."
                .into(),
        )),
        Err(e) => Err((
            "aborted_pre_broadcast_crosscheck_unavailable",
            format!(
                "the cross-check provider could not attest ({e}) — an unavailable check \
                 is a refusal, not a pass."
            ),
        )),
    }
}

/// The sender pays the fee from the same account: `lamports + fee` must fit
/// the balance. Fee unknown (devnet-only path): the amount alone must be
/// strictly below the balance, stated honestly (the live devnet gate burned
/// a ceremony on exactly this — external audit, 2026-07-19).
fn sol_balance_preflight(balance: u64, lamports: u64, fee: Option<u64>) -> Result<(), String> {
    let required = lamports
        .checked_add(fee.unwrap_or(0))
        .ok_or_else(|| "amount plus fee overflows — refusing.".to_string())?;
    if balance < required {
        return Err(format!(
            "balance {balance} lamports cannot cover {lamports} + fee {} — the sender pays \
             the fee from the same account. Reduce the amount.",
            match fee {
                Some(f) => f.to_string(),
                None => "(unknown — amount alone already exceeds balance)".to_string(),
            }
        ));
    }
    if fee.is_none() && balance == lamports {
        return Err(
            "sending the exact balance with an unknown fee cannot succeed — the fee has \
             nowhere to come from."
                .into(),
        );
    }
    Ok(())
}

/// Deterministic Solana policy result for this prototype. Missing simulation
/// and risk engines are recorded as `unknown`, so a financially valid request
/// may only escalate to the vault-side human ceremony — it must never become
/// an implicit allow. Concrete fee/balance failures remain hard denials.
fn sol_policy_verdict(
    is_mainnet: bool,
    balance: u64,
    lamports: u64,
    fee: Option<u64>,
) -> Result<&'static str, String> {
    if is_mainnet && fee.is_none() {
        return Err(
            "the cluster returned no fee for this message and this is mainnet — unknown is not \
             evidence (ADR-021 §4)."
                .into(),
        );
    }
    sol_balance_preflight(balance, lamports, fee)?;
    Ok("escalate")
}

/// One Solana ceremony's signing lifecycle + audit trail (external re-audit,
/// 2026-07-20): the ceremony is a first-class lifecycle in
/// `cipherlayer-types::state` — every transition is validated against the
/// shared table and audited under ONE request id (AGENTS.md hard invariant;
/// CL-AUD-001), exactly like the pipeline. Pre-broadcast, an audit append
/// failure fails the ceremony closed; post-broadcast the caller uses
/// [`SolTrace::step_warn`] because the transaction is already out and a
/// missing record must warn, not pretend the send didn't happen.
struct SolTrace<'a> {
    audit: &'a AuditLog,
    lifecycle: cipherlayer_types::state::Lifecycle,
}

impl<'a> SolTrace<'a> {
    fn start(audit: &'a AuditLog) -> Self {
        Self {
            audit,
            lifecycle: cipherlayer_types::state::Lifecycle::start(uuid::Uuid::new_v4()),
        }
    }

    fn request_id(&self) -> uuid::Uuid {
        self.lifecycle.request_id()
    }

    /// Append an audit event at the CURRENT state (no transition).
    fn record(
        &self,
        kind: cipherlayer_audit::EventKind,
        mut payload: serde_json::Value,
    ) -> Result<(), String> {
        payload["state"] = serde_json::json!(self.lifecycle.state());
        self.audit
            .append(kind, Some(self.lifecycle.request_id()), payload)
            .map(|_| ())
            .map_err(|e| format!("audit append failed ({e}) — refusing (CL-AUD-001)"))
    }

    /// Advance the lifecycle and audit the step. `Err` means the ceremony
    /// must refuse: either the transition is illegal (audited as such — a
    /// bug, never silently absorbed) or the audit log cannot be written.
    fn step(
        &mut self,
        to: cipherlayer_types::state::LifecycleState,
        kind: cipherlayer_audit::EventKind,
        payload: serde_json::Value,
    ) -> Result<(), String> {
        let from = self.lifecycle.state();
        if let Err(e) = self.lifecycle.advance(to) {
            let _ = self.record(
                cipherlayer_audit::EventKind::IllegalTransitionAttempted,
                serde_json::json!({"from": from, "to": to, "error": e.to_string()}),
            );
            return Err(format!("internal lifecycle violation: {e} — refusing"));
        }
        self.record(kind, payload)
    }

    /// Post-broadcast variant: the transition/audit outcome cannot change
    /// what already happened on chain, so failures are surfaced as a
    /// warning string instead of aborting.
    #[must_use]
    fn step_warn(
        &mut self,
        to: cipherlayer_types::state::LifecycleState,
        kind: cipherlayer_audit::EventKind,
        payload: serde_json::Value,
    ) -> Option<String> {
        self.step(to, kind, payload).err()
    }
}

// --- styling -------------------------------------------------------------

struct Style {
    on: bool,
}
impl Style {
    fn detect() -> Self {
        let on = std::env::var("NO_COLOR").is_err()
            && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(false);
        Style { on }
    }
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    fn amber(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    /// Selectable keys (menu numbers, one-letter verbs): bold cyan.
    fn key(&self, s: &str) -> String {
        self.wrap("1;36", s)
    }
}

// The banner: W4113T — WALLET in leetspeak (W-4-1-1-3-T = W-A-L-L-E-T),
// the wallet's codename. Six glyphs: W, 4, 1, 1, 3, T, all from the ANSI
// Shadow figlet font so the "4" matches the rest (its own glyph, not a
// hand-edited one). The box-drawing ╗╝║ edges give the back-outline look.
const BANNER: &str = r#"
██╗    ██╗ ██╗  ██╗  ██╗  ██╗ ██████╗  ████████╗
██║    ██║ ██║  ██║ ███║ ███║ ╚════██╗ ╚══██╔══╝
██║ █╗ ██║ ███████║ ╚██║ ╚██║  █████╔╝    ██║
██║███╗██║ ╚════██║  ██║  ██║  ╚═══██╗    ██║
╚███╔███╔╝      ██║  ██║  ██║ ██████╔╝    ██║
 ╚══╝╚══╝       ╚═╝  ╚═╝  ╚═╝ ╚═════╝     ╚═╝
"#;

/// Render width of the operator-terminal grid (rules, frames, separators).
const WIDTH: usize = 64;

pub struct Console {
    rpc_url: String,
    audit_path: PathBuf,
    policy: Policy,
    permissions_path: PathBuf,
    style: Style,
    registry: ChainRegistry,
    // Address chosen from the signer-alias picker (menu option 2); pre-fills
    // the "declared address" step of the external-signer key load. Holds no
    // key material — just an address the operator already vetted.
    pending_signer_addr: Option<String>,
    // Session-active chain (switch via menu 3). Chain-bound flows (the
    // external signer) must match it or refuse. Defaults to Sepolia, the
    // only chain the external signer supports.
    active_chain: cipherlayer_types::ChainId,
}

impl Console {
    pub fn new(
        rpc_url: String,
        audit_path: PathBuf,
        policy: Policy,
        permissions_path: PathBuf,
    ) -> Self {
        Self {
            rpc_url,
            audit_path,
            policy,
            permissions_path,
            style: Style::detect(),
            registry: ChainRegistry::builtin(),
            pending_signer_addr: None,
            active_chain: cipherlayer_types::ChainId(
                cipherlayer_vault::external_signer::SEPOLIA_CHAIN_ID,
            ),
        }
    }

    fn aliases_path(&self) -> PathBuf {
        PathBuf::from(
            std::env::var("CIPHERLAYER_SIGNER_ALIASES")
                .unwrap_or_else(|_| "./data/signer-aliases.json".into()),
        )
    }

    fn load_aliases(&self) -> Vec<AddressAlias> {
        std::fs::read_to_string(self.aliases_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_aliases(&self, aliases: &[AddressAlias]) -> Result<(), String> {
        let p = self.aliases_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(aliases).map_err(|e| e.to_string())?;
        std::fs::write(&p, json).map_err(|e| e.to_string())
    }

    fn build_vault(&self) -> Result<Vault, String> {
        let key = std::env::var("CIPHERLAYER_TEST_SIGNER_KEY")
            .unwrap_or_else(|_| ANVIL_DEV_KEYS[0].to_string());
        let signer = TestSigner::from_dev_key(&key).map_err(|e| e.to_string())?;
        let mut vault = Vault::new(signer);
        if self.read_locked() {
            vault.lock();
        }
        Ok(vault)
    }

    fn vault_state_path(&self) -> PathBuf {
        PathBuf::from(
            std::env::var("CIPHERLAYER_VAULT_STATE")
                .unwrap_or_else(|_| "./data/vault-state.json".into()),
        )
    }
    fn read_locked(&self) -> bool {
        std::fs::read_to_string(self.vault_state_path())
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v["locked"].as_bool())
            .unwrap_or(false)
    }
    fn write_locked(&self, locked: bool) -> Result<(), String> {
        let p = self.vault_state_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&p, serde_json::json!({ "locked": locked }).to_string())
            .map_err(|e| e.to_string())
    }

    fn permissions(&self) -> PermissionStore {
        PermissionStore::load_from(&self.permissions_path).unwrap_or_default()
    }

    fn rule(&self, width: usize) -> String {
        self.style.dim(&"─".repeat(width))
    }

    /// "vault" → "V A U L T": spaced-uppercase operator-terminal label.
    fn spaced(text: &str) -> String {
        let mut out = String::new();
        for (i, c) in text.chars().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.extend(c.to_uppercase());
        }
        out
    }

    /// Thin box-drawing section header: `┌─ T I T L E ──────────`.
    fn section(&self, title: &str) {
        let t = Self::spaced(title);
        let fill = WIDTH.saturating_sub(t.chars().count() + 4);
        println!(
            "{}",
            self.style.dim(&format!("┌─ {t} {}", "─".repeat(fill)))
        );
    }

    /// Dotted separator: `· · · · · ·`.
    fn dots(&self) -> String {
        self.style
            .dim("· ".repeat(WIDTH / 2).trim_end().to_string().as_str())
    }

    /// One-line context strip at the top of each screen:
    /// chain · network class · signer mode · policy.
    fn context_strip(&self) {
        let s = &self.style;
        let (chain_name, class) = match self.registry.get(self.active_chain) {
            Ok(e) => (
                e.name.clone(),
                format!("{:?}", e.network_class).to_lowercase(),
            ),
            Err(_) => ("unknown".into(), "unknown".into()),
        };
        // Non-development network classes get the red accent; the text itself
        // always carries the meaning (T-12: styling alone conveys nothing).
        let class_badge = if class == "development" {
            s.dim(&class)
        } else {
            s.red(&class)
        };
        let signer_mode = if std::env::var(EXTERNAL_SIGNER_KEY_ENV).is_ok() {
            s.amber("ext-key")
        } else if self.pending_signer_addr.is_some() {
            s.amber("ext-selected")
        } else {
            format!("test-key {}", s.red("MOCKED"))
        };
        println!(
            "{} {} ({}) {class_badge} {} {} {signer_mode} {} {} {}",
            s.dim("CHAIN"),
            chain_name,
            self.active_chain.0,
            s.dim("·"),
            s.dim("SIGNER"),
            s.dim("·"),
            s.dim("POLICY"),
            self.policy.name
        );
    }

    fn splash(&self) {
        let s = &self.style;
        print!("{}", s.cyan(BANNER));
        println!(
            "  {}   {} {}",
            s.bold("CipherLayer Wallet"),
            s.dim(&format!("W4113T · {} ·", Self::spaced("operator console"))),
            s.red("PROTOTYPE")
        );
        println!(
            "  {}",
            s.red("test keys · local/dev chains · MOCKED custody · not a confirmation surface")
        );
        println!("{}", self.rule(WIDTH));
    }

    /// Live status strip shown above the menu each loop.
    fn status_strip(&self) {
        let s = &self.style;
        let (signer, locked) = match self.build_vault() {
            Ok(v) => (format!("{}", v.address()), v.is_locked()),
            Err(e) => (format!("<{e}>"), false),
        };
        let lock_badge = if locked {
            s.red("LOCKED")
        } else {
            s.green("unlocked")
        };
        let audit_badge = match AuditLog::open(&self.audit_path).and_then(|a| a.verify()) {
            Ok(r) => format!(
                "{} events · chain {}",
                r.total_events,
                if r.valid {
                    s.green("valid")
                } else {
                    s.red("INVALID")
                }
            ),
            Err(_) => s.dim("no log yet").to_string(),
        };
        let perms = self.permissions();
        let active = perms
            .list()
            .iter()
            .filter(|p| {
                matches!(
                    p.status(chrono::Utc::now()),
                    cipherlayer_provider::PermissionStatus::Active
                )
            })
            .count();
        // External-signer line reflects every stage: nothing → address
        // selected (menu 2) → key loaded and verified (menu 9).
        let ext = if std::env::var(EXTERNAL_SIGNER_KEY_ENV).is_ok() {
            let from = std::env::var("CIPHERLAYER_EXTERNAL_SIGNER_FROM").unwrap_or_default();
            format!("{} {}", s.green("key LOADED"), s.amber(&from))
        } else if let Some(a) = &self.pending_signer_addr {
            format!(
                "{} {}",
                s.amber(&format!("selected {a}")),
                s.dim("— key not loaded yet (9 → l)")
            )
        } else {
            s.dim("none").to_string()
        };
        let chain_badge = match self.registry.get(self.active_chain) {
            Ok(e) => format!(
                "{} ({}) {}",
                s.amber(&e.name),
                self.active_chain.0,
                s.dim(&format!("{:?}", e.network_class).to_lowercase())
            ),
            Err(_) => s.red(&format!("unknown chain {}", self.active_chain.0)),
        };
        // Left-column labels: spaced uppercase, dim; padded before wrapping
        // so the ANSI codes do not break the grid alignment.
        let lbl = |name: &str| s.dim(&format!("{:<12}", Self::spaced(name)));
        self.section("session");
        println!(
            "  {} {lock_badge}   signer {}",
            lbl("vault"),
            s.dim(&signer)
        );
        println!("  {} {chain_badge}", lbl("chain"));
        println!("  {} {audit_badge}", lbl("audit"));
        println!(
            "  {} {active} active grant(s)   rpc {}",
            lbl("perms"),
            s.dim(&self.rpc_url)
        );
        println!("  {} {ext}", lbl("signer"));
        println!("{}", self.dots());
    }

    fn menu(&self) {
        let s = &self.style;
        let item = |n: &str, label: &str, hint: &str| {
            println!(
                "  {}  {} {}",
                s.key(n),
                s.dim(&format!("{:<22}", label.to_uppercase())),
                s.dim(hint)
            );
        };
        item("1", "status", "vault, chain, audit detail");
        item("2", "aliases", "saved EVM sender / recipient addresses");
        item("3", "chains", "registry · switch active chain");
        item("4", "decode", "calldata → intent");
        item("5", "policy", "view / offline test");
        item("6", "audit", "inspect / verify chain");
        item("7", "permissions", "list / revoke grants");
        item("8", "vault", "lock / unlock");
        item(
            "9",
            "external-signer",
            "Sepolia / mainnet real-key lifecycle",
        );
        item("a", "assets", "unified view · every chain, every asset");
        println!("{}", self.dots());
        item("h", "help", "guide (also /help, /guide)");
        item("q", "quit", "");
        println!("{}", self.rule(WIDTH));
    }

    fn prompt(&self, label: &str) -> io::Result<String> {
        print!("{} ", self.style.cyan(&format!("{label}›")));
        io::stdout().flush()?;
        let mut line = String::new();
        let n = io::stdin().read_line(&mut line)?;
        if n == 0 {
            return Ok("q".into()); // EOF → quit
        }
        Ok(line.trim().to_string())
    }

    pub async fn run(&mut self) -> io::Result<()> {
        self.splash();
        loop {
            println!();
            self.status_strip();
            self.menu();
            let choice = self.prompt("select")?;
            println!();
            // Each screen opens with the context strip and a framed title.
            let title = match choice.as_str() {
                "1" => Some("status"),
                "2" => Some("aliases"),
                "3" => Some("chains"),
                "4" => Some("decode"),
                "5" => Some("policy"),
                "6" => Some("audit"),
                "7" => Some("permissions"),
                "8" => Some("vault"),
                "9" => Some("external-signer"),
                "a" => Some("assets"),
                "h" | "help" | "?" | "/help" | "/guide" => Some("help"),
                _ => None,
            };
            if let Some(t) = title {
                self.context_strip();
                self.section(t);
            }
            match choice.as_str() {
                "1" => self.show_status(),
                "2" => self.do_signer_aliases()?,
                "3" => self.do_chains()?,
                "4" => self.do_decode()?,
                "5" => self.do_policy()?,
                "6" => self.do_audit()?,
                "7" => self.do_permissions()?,
                "8" => self.do_vault()?,
                "9" => self.do_external_signer().await?,
                "a" => self.do_assets().await?,
                "h" | "help" | "?" | "/help" | "/guide" => self.show_help(),
                "q" | "quit" | "exit" => {
                    println!("  {}", self.style.dim("session closed."));
                    return Ok(());
                }
                "" => {}
                other => println!("  {}", self.style.red(&format!("unknown option: {other}"))),
            }
        }
    }

    // --- actions ---------------------------------------------------------

    fn show_status(&self) {
        let s = &self.style;
        match self.build_vault() {
            Ok(v) => {
                println!(
                    "  signer   {}  {}",
                    v.address(),
                    s.dim("[MOCKED: Anvil dev key]")
                );
                println!(
                    "  {}",
                    s.dim("kind=test custody=self(dev-key) — worthless by design")
                );
                println!(
                    "  vault    {}",
                    if v.is_locked() {
                        s.red("LOCKED")
                    } else {
                        s.green("unlocked")
                    }
                );
            }
            Err(e) => println!("  {}", s.red(&e)),
        }
        println!("  rpc      {}", self.rpc_url);
        match AuditLog::open(&self.audit_path).and_then(|a| a.verify()) {
            Ok(r) => println!(
                "  audit    {} events at {} ({})",
                r.total_events,
                self.audit_path.display(),
                if r.valid {
                    s.green("valid")
                } else {
                    s.red("INVALID")
                }
            ),
            Err(e) => println!("  audit    {}", s.dim(&format!("{e}"))),
        }
    }

    /// EVM address book (menu option 2). Every saved alias is available as a
    /// transfer recipient; selecting one also pre-fills the external-signer
    /// address. The file contains labels + public addresses, never keys.
    fn do_signer_aliases(&mut self) -> io::Result<()> {
        let s = &self.style;
        let aliases = self.load_aliases();
        if aliases.is_empty() {
            println!("  {}", s.dim("no saved aliases yet."));
        } else {
            for (i, a) in aliases.iter().enumerate() {
                println!(
                    "  {}  {:<16} {}",
                    s.bold(&(i + 1).to_string()),
                    a.label,
                    s.dim(&a.address)
                );
            }
        }
        if let Some(addr) = &self.pending_signer_addr {
            println!("  {}", s.dim(&format!("(currently selected: {addr})")));
        }
        println!(
            "  {}",
            s.dim("saved labels can be typed as recipients; selection here is only for the sender default")
        );
        let choice = self.prompt("[number]=use saved · or paste an address · blank=back")?;
        let choice = choice.trim();
        if choice.is_empty() {
            return Ok(());
        }
        // A bare number selects a saved alias.
        if let Ok(n) = choice.parse::<usize>() {
            return match n.checked_sub(1).and_then(|i| aliases.get(i)) {
                Some(a) => {
                    self.pending_signer_addr = Some(a.address.clone());
                    println!(
                        "  {}",
                        s.green(&format!(
                            "selected {} ({}) — used as the default next time you load a key in external-signer",
                            a.label, a.address
                        ))
                    );
                    Ok(())
                }
                _ => {
                    println!(
                        "  {}",
                        s.dim(&format!("no alias #{n} — {} saved.", aliases.len()))
                    );
                    Ok(())
                }
            };
        }
        // Otherwise treat it as an address: use it now, and offer to save it.
        let parsed_choice = match cipherlayer_evm::parse_address(choice) {
            Ok(address) => address,
            Err(e) => {
                println!(
                    "  {}",
                    s.dim(&format!(
                        "\"{choice}\" not recognized as a number or address ({e})."
                    ))
                );
                return Ok(());
            }
        };
        self.pending_signer_addr = Some(choice.to_string());
        println!(
            "  {}",
            s.green(&format!(
                "using {choice} as the default next time you load a key in external-signer."
            ))
        );
        let save = self.prompt("save this address as an alias? [y]es / blank=no")?;
        if save.trim() == "y" || save.trim() == "yes" {
            let label = self
                .prompt("label")?
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if label.is_empty() {
                println!("  {}", s.red("alias label cannot be blank."));
                return Ok(());
            }
            if label
                .split_whitespace()
                .any(|part| part.eq_ignore_ascii_case("a") || part.eq_ignore_ascii_case("amount"))
            {
                println!(
                    "  {}",
                    s.red("alias labels cannot contain the standalone word `a` or `amount`; those words mark the value field in one-go sends.")
                );
                return Ok(());
            }
            if label.chars().any(|c| c.is_control()) {
                println!(
                    "  {}",
                    s.red("alias labels cannot contain control characters — they are shown beside the authoritative address you verify before signing.")
                );
                return Ok(());
            }
            let mut aliases = aliases;
            let same_label = aliases
                .iter()
                .filter(|alias| {
                    normalized_alias_label(&alias.label) == normalized_alias_label(&label)
                })
                .collect::<Vec<_>>();
            if !same_label.is_empty() {
                let same_address = same_label.iter().all(|alias| {
                    cipherlayer_evm::parse_address(&alias.address)
                        .map(|address| address == parsed_choice)
                        .unwrap_or(false)
                });
                println!(
                    "  {}",
                    if same_address {
                        s.dim(&format!("{label} already names {choice}; nothing added."))
                    } else {
                        s.red(&format!(
                            "alias {label} already maps to another address — choose a unique label."
                        ))
                    }
                );
                return Ok(());
            }
            aliases.push(AddressAlias {
                label: label.clone(),
                address: choice.to_string(),
            });
            if let Err(e) = self.save_aliases(&aliases) {
                println!("  {}", s.red(&format!("could not save: {e}")));
                return Ok(());
            }
            println!("  {}", s.green(&format!("saved {label} ({choice})")));
        }
        Ok(())
    }

    /// Unified view (menu `a`; UX-first sequencing, roadmap "W2 — Desktop
    /// wallet UI"): every chain this repo ships an adapter for, every held
    /// asset, filterable by the SAME
    /// `NetworkClass` the real `ChainRegistry` and signing gate use — so
    /// switching the filter switches the exact concept the trust core
    /// already reasons about, not a second invented taxonomy. Holdings are
    /// demo fixture data (labeled as such below); chain identity/network
    /// class come from the real registry, same source `do_chains` reads.
    async fn do_assets(&mut self) -> io::Result<()> {
        let s = &self.style;
        let mut filter: Option<NetworkClass> = None;
        // CL-WAL-013: native EVM balances are read live for ONE public
        // address the operator supplies (read-only; no key, no signing).
        // Tokens/NFTs stay labeled fixtures. A failed fetch is shown as
        // unavailable, never as zero.
        let default_addr = self.pending_signer_addr.clone().unwrap_or_default();
        let entered = self.prompt(&format!(
            "public EVM address for live native balances (blank = {})",
            if default_addr.is_empty() {
                "fixtures only"
            } else {
                "saved signer address"
            }
        ))?;
        let live_addr = match entered.trim() {
            "" if default_addr.is_empty() => None,
            "" => Some(default_addr),
            other => Some(other.to_string()),
        };
        let mut live: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
        if let Some(addr) = &live_addr {
            match cipherlayer_evm::parse_address(addr) {
                Err(e) => println!(
                    "  {}",
                    s.red(&format!("not a valid EVM address, fixtures only: {e}"))
                ),
                Ok(parsed) => {
                    for e in self.registry.entries() {
                        let Some(url) = live_balance_rpc(e, &self.rpc_url) else {
                            continue;
                        };
                        let fetched = fetch_native_balance(&url, parsed).await;
                        live.insert(
                            e.chain_id.0,
                            format_live_native(fetched, e.native_decimals, &e.native_symbol),
                        );
                    }
                }
            }
        }
        loop {
            // The chain set shown here is exactly demo_assets_for's non-empty
            // arms — Ethereum mainnet, the Anvil-fork L2 dev-twins, and the
            // Solana local test validator have no fixture entry there and so
            // never appear. One list, not a second hardcoded allowlist kept
            // in sync by hand against the match statement below.
            let chains: Vec<_> = self
                .registry
                .entries()
                .iter()
                .filter(|e| !demo_assets_for(e.chain_id.0).is_empty())
                .filter(|e| filter.is_none_or(|f| f == e.network_class))
                .collect();

            println!(
                "  {}",
                s.dim("every chain, every asset — native EVM balances live where an address and RPC are available; all other holdings are demo fixtures")
            );
            if chains.is_empty() {
                println!("  {}", s.dim("no chains match this filter."));
            }
            let plural =
                |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
            let (mut total_tokens, mut total_nfts) = (0usize, 0usize);
            for e in &chains {
                let assets = demo_assets_for(e.chain_id.0);
                let tokens: Vec<_> = assets
                    .iter()
                    .filter(|a| matches!(a.kind, DemoAssetKind::Token))
                    .collect();
                let nfts: Vec<_> = assets
                    .iter()
                    .filter(|a| matches!(a.kind, DemoAssetKind::Nft))
                    .collect();
                total_tokens += tokens.len();
                total_nfts += nfts.len();
                println!(
                    "  {}  {:<12} {}",
                    s.bold(&e.name),
                    format!("{:?}", e.network_class).to_lowercase(),
                    plural(assets.len(), "asset")
                );
                for t in &tokens {
                    match live.get(&e.chain_id.0) {
                        Some(v) if t.name.ends_with("(native)") => {
                            println!("      {:<6} {:<28} {}", t.symbol, t.name, s.green(v));
                        }
                        _ => println!(
                            "      {:<6} {:<28} {} {}",
                            t.symbol,
                            t.name,
                            t.detail,
                            s.dim("(fixture)")
                        ),
                    }
                }
                for n in &nfts {
                    println!("      {:<6} {:<28} ({})", n.symbol, n.name, n.detail);
                }
            }
            println!(
                "  {}",
                s.dim(&format!(
                    "{} · {} · {}",
                    plural(chains.len(), "chain"),
                    plural(total_tokens, "token"),
                    plural(total_nfts, "NFT"),
                ))
            );
            let choice =
                self.prompt("[a]ll / [d]evelopment / [t]estnet / [m]ainnet / blank=back")?;
            match choice.trim() {
                "a" | "all" => filter = None,
                "d" | "dev" | "development" => filter = Some(NetworkClass::Development),
                "t" | "testnet" => filter = Some(NetworkClass::Testnet),
                "m" | "mainnet" => filter = Some(NetworkClass::Mainnet),
                "" => return Ok(()),
                other => println!("  {}", s.red(&format!("unknown option: {other}"))),
            }
            println!();
        }
    }

    /// Chain registry view + active-chain switch (menu 3). The active chain
    /// gates chain-bound flows: the external signer refuses to run unless the
    /// active chain matches what it supports AND what the RPC itself reports.
    fn do_chains(&mut self) -> io::Result<()> {
        let s = &self.style;
        for (i, e) in self.registry.entries().iter().enumerate() {
            let signing = if e.network_class == NetworkClass::Development {
                s.green("signing allowed")
            } else {
                s.dim("signing refused (prototype gate)")
            };
            let marker = if e.chain_id == self.active_chain {
                s.green("●")
            } else {
                " ".to_string()
            };
            println!(
                "  {} {} {:>9}  {:<20} {:<12} {}",
                s.key(&(i + 1).to_string()),
                marker,
                e.chain_id.0,
                s.bold(&e.name),
                format!("{:?}", e.network_class).to_lowercase(),
                signing
            );
            for p in &e.rpc_profiles {
                // Premium profiles carry their URL in an env var, not the
                // registry; resolve it for display without ever printing a token.
                let shown = match (p.url.is_empty(), &p.auth_env_var) {
                    (true, Some(var)) => {
                        if std::env::var(var).is_ok() {
                            s.green(&format!("configured via {var}"))
                        } else {
                            s.dim(&format!("unset — export {var}"))
                        }
                    }
                    _ => s.dim(&p.url),
                };
                println!("               {} {}", s.dim(&p.profile_id), shown);
            }
        }
        println!("  {}", s.dim("● = active chain for this session"));
        let choice = self.prompt("[number]=set active chain / blank=back")?;
        let choice = choice.trim();
        if choice.is_empty() {
            return Ok(());
        }
        let picked = choice
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| self.registry.entries().get(i))
            .map(|e| (e.chain_id, e.name.clone()));
        match picked {
            Some((id, name)) => {
                // Chain switch invalidates the session key (2026-07-17
                // verification finding): without this, a key loaded under the
                // Sepolia ceremony silently survives into a mainnet run,
                // skipping every mainnet-specific load protection (ADR-020).
                // The key must be re-pasted under the ceremony that names the
                // stakes of the chain it will sign on.
                if id != self.active_chain && std::env::var(EXTERNAL_SIGNER_KEY_ENV).is_ok() {
                    std::env::remove_var(EXTERNAL_SIGNER_KEY_ENV);
                    std::env::remove_var("CIPHERLAYER_EXTERNAL_SIGNER_FROM");
                    println!(
                        "  {}",
                        s.amber(
                            "session signing key cleared (chain switch) — reload it in external-signer (9)."
                        )
                    );
                }
                self.active_chain = id;
                println!(
                    "  {}",
                    s.green(&format!("active chain set to {name} ({})", id.0))
                );
                if id.0 != cipherlayer_vault::external_signer::SEPOLIA_CHAIN_ID
                    && id.0 != cipherlayer_vault::external_signer::MAINNET_CHAIN_ID
                    && id.0 != cipherlayer_chain::SOLANA_DEVNET_CHAIN_ID
                    && id.0 != cipherlayer_chain::SOLANA_MAINNET_CHAIN_ID
                {
                    println!(
                        "  {}",
                        s.dim("note: the external signer (9) permits only Sepolia, Ethereum mainnet, Solana devnet, or Solana mainnet-beta, and will refuse on this chain.")
                    );
                }
            }
            None => println!(
                "  {}",
                s.red(&format!(
                    "\"{choice}\" is not a listed number — enter 1-{}, or blank to go back.",
                    self.registry.entries().len()
                ))
            ),
        }
        Ok(())
    }

    fn do_decode(&self) -> io::Result<()> {
        let to = self.prompt("to (0x.. or blank=creation)")?;
        let data = self.prompt("data (0x..)")?;
        let value = self.prompt("value wei (blank=0)")?;
        let to_addr = if to.is_empty() {
            None
        } else {
            match cipherlayer_evm::parse_address(&to) {
                Ok(a) => Some(a),
                Err(e) => {
                    println!("  {}", self.style.red(&e.to_string()));
                    return Ok(());
                }
            }
        };
        let bytes = hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
        let value = cipherlayer_types::U256::from_str_radix(
            if value.is_empty() { "0" } else { &value },
            10,
        )
        .unwrap_or(cipherlayer_types::U256::ZERO);
        let decoded = cipherlayer_evm::decode_calldata(to_addr, value, &bytes);
        println!(
            "  {} {:?}  confidence {:?}",
            self.style.bold("action"),
            decoded.kind,
            decoded.confidence
        );
        if let Some(a) = &decoded.allowance {
            println!("  allowance {:?} amount={:?}", a.kind, a.amount);
        }
        if !decoded.unresolved_fields.is_empty() {
            println!(
                "  {} {:?}",
                self.style.amber("unresolved"),
                decoded.unresolved_fields
            );
        }
        Ok(())
    }

    fn do_policy(&self) -> io::Result<()> {
        let s = &self.style;
        println!("  {}", s.bold("active policy"));
        match serde_json::to_string_pretty(&self.policy) {
            Ok(j) => {
                for line in j.lines().take(40) {
                    println!("  {}", s.dim(line));
                }
            }
            Err(e) => println!("  {}", s.red(&e.to_string())),
        }
        Ok(())
    }

    fn do_audit(&self) -> io::Result<()> {
        let s = &self.style;
        let sub = self.prompt("[v]erify / [i]nspect")?;
        let audit = match AuditLog::open(&self.audit_path) {
            Ok(a) => a,
            Err(e) => {
                println!("  {}", s.dim(&format!("{e}")));
                return Ok(());
            }
        };
        match sub.as_str() {
            "i" | "inspect" => match audit.read_all() {
                Ok(events) => {
                    for e in events.iter().rev().take(12) {
                        println!(
                            "  {:>4}  {:<22} {}",
                            e.sequence,
                            format!("{:?}", e.kind),
                            s.dim(&e.occurred_at.to_rfc3339())
                        );
                    }
                }
                Err(e) => println!("  {}", s.red(&e.to_string())),
            },
            _ => match audit.verify() {
                Ok(r) => println!(
                    "  {} events, chain {}",
                    r.total_events,
                    if r.valid {
                        s.green("valid")
                    } else {
                        s.red("INVALID")
                    }
                ),
                Err(e) => println!("  {}", s.red(&e.to_string())),
            },
        }
        Ok(())
    }

    fn do_permissions(&self) -> io::Result<()> {
        let s = &self.style;
        let mut store = self.permissions();
        if store.list().is_empty() {
            println!("  {}", s.dim("no grants on file"));
            return Ok(());
        }
        for p in store.list() {
            println!(
                "  {}  caller={} chain={} access={:?} {}",
                p.permission_id,
                s.dim(&p.caller_key),
                p.chain_id.0,
                p.access,
                match p.status(chrono::Utc::now()) {
                    cipherlayer_provider::PermissionStatus::Active => s.green("active"),
                    cipherlayer_provider::PermissionStatus::Expired => s.amber("expired"),
                    cipherlayer_provider::PermissionStatus::Revoked => s.red("revoked"),
                }
            );
        }
        let id = self.prompt("revoke id (blank=skip)")?;
        if !id.is_empty() {
            match uuid::Uuid::parse_str(&id) {
                Ok(uuid) if store.revoke(uuid) => {
                    store
                        .save_to(&self.permissions_path)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    println!("  {}", s.green(&format!("revoked {uuid} (persisted)")));
                }
                Ok(uuid) => println!("  {}", s.amber(&format!("no active grant {uuid}"))),
                Err(e) => println!("  {}", s.red(&e.to_string())),
            }
        }
        Ok(())
    }

    fn do_vault(&self) -> io::Result<()> {
        let s = &self.style;
        let locked = self.read_locked();
        println!(
            "  vault is {}",
            if locked {
                s.red("LOCKED")
            } else {
                s.green("unlocked")
            }
        );
        let action = self.prompt("[l]ock / [u]nlock / blank=skip")?;
        match action.as_str() {
            "l" | "lock" => {
                self.write_locked(true).map_err(io::Error::other)?;
                println!("  {}", s.red("vault locked (persisted)"));
            }
            "u" | "unlock" => {
                self.write_locked(false).map_err(io::Error::other)?;
                println!("  {}", s.green("vault unlocked (persisted)"));
            }
            _ => {}
        }
        Ok(())
    }

    /// Interactive, in-process key load: paste a key, verify it derives to a
    /// declared address, and set it for THIS process only (no cross-shell
    /// magic — a child process cannot export into its parent shell, so this
    /// is the honest alternative: same masking technique as the zsh loader
    /// (`stty -echo`/`stty echo` on the controlling tty), same verify-before-
    /// accept invariant, same "key never printed" discipline).
    /// Resolve an operator-supplied signer reference through the same exact,
    /// fail-closed address book used for recipients.
    fn resolve_signer_ref(&self, input: &str) -> Result<String, String> {
        let aliases = self.load_aliases();
        resolve_evm_address_ref(input, &aliases, "signer")
            .map(|resolved| resolved.address.to_string())
    }

    fn load_key_interactive(
        &self,
        inline_addr: Option<&str>,
        is_mainnet: bool,
    ) -> io::Result<bool> {
        let s = &self.style;
        // Mainnet gets no *hardcoded* habit-default — but an address the
        // operator explicitly picked this session (the alias picker, menu 2)
        // is a deliberate choice and IS offered, confirm-with-Enter
        // (operator feedback 2026-07-17). Sepolia keeps its convenience
        // default. The address-derivation guard below stays fail-closed
        // either way.
        let default_addr = if is_mainnet {
            self.pending_signer_addr.clone()
        } else {
            Some(
                self.pending_signer_addr
                    .clone()
                    .unwrap_or_else(|| "0x7cD33930465A2258B89A25B59A1ACd5aa033932E".to_string()),
            )
        };
        let addr_input = match inline_addr {
            Some(a) => a.to_string(),
            None => match &default_addr {
                Some(d) => self.prompt(&format!("declared address (Enter = {d})"))?,
                None => self.prompt(
                    "declared mainnet address or alias (required — pick one in aliases (2) to pre-load it)",
                )?,
            },
        };
        let expected_str = if addr_input.is_empty() {
            match &default_addr {
                Some(d) => d.clone(),
                None => {
                    println!(
                        "  {}",
                        s.red(
                            "a mainnet address is required — nothing was loaded, back to the menu."
                        )
                    );
                    return Ok(false);
                }
            }
        } else {
            match self.resolve_signer_ref(&addr_input) {
                Ok(a) => a,
                Err(msg) => {
                    println!("  {}", s.red(&msg));
                    return Ok(false);
                }
            }
        };
        let expected = match cipherlayer_evm::parse_address(&expected_str) {
            Ok(a) => a,
            Err(e) => {
                println!("  {}", s.red(&e.to_string()));
                return Ok(false);
            }
        };

        print!(
            "  paste {} private key, then press Enter: ",
            if is_mainnet {
                "MAINNET (real funds)"
            } else {
                "Sepolia test"
            }
        );
        io::stdout().flush()?;
        #[cfg(unix)]
        let _ = std::process::Command::new("stty").arg("-echo").status();
        let mut raw = String::new();
        let read_result = io::stdin().read_line(&mut raw);
        #[cfg(unix)]
        let _ = std::process::Command::new("stty").arg("echo").status();
        println!(); // newline the terminal didn't echo for us
        read_result?;

        let cleaned = raw
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_string();
        raw.replace_range(.., &"0".repeat(raw.len()));
        if cleaned.len() != 64 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
            println!(
                "  {}",
                s.red("invalid key (length/charset). The key was not printed or used.")
            );
            return Ok(false);
        }
        let signer: alloy::signers::local::PrivateKeySigner = match format!("0x{cleaned}").parse() {
            Ok(k) => k,
            Err(e) => {
                println!("  {}", s.red(&format!("could not parse key: {e}")));
                return Ok(false);
            }
        };
        let derived = signer.address();
        if derived != expected {
            println!(
                "  {}",
                s.red(&format!(
                    "MISMATCH: derived {derived}, expected {expected}. The key was not used."
                ))
            );
            return Ok(false);
        }
        std::env::set_var(EXTERNAL_SIGNER_KEY_ENV, format!("0x{cleaned}"));
        std::env::set_var("CIPHERLAYER_EXTERNAL_SIGNER_FROM", format!("{derived}"));
        println!(
            "  {}",
            s.green(&format!(
                "key verified and loaded for this session ({derived})."
            ))
        );
        println!(
            "  {}",
            s.dim("(session-only: this does not persist to your shell or to disk; reload each time you restart the console)")
        );
        Ok(true)
    }

    /// Print the operator guide (docs/console-guide.md, embedded at build
    /// time so the printed text and the checked-in doc cannot drift).
    fn show_help(&self) {
        let s = &self.style;
        for line in include_str!("../../../docs/console-guide.md").lines() {
            if let Some(h) = line.strip_prefix('#') {
                println!("  {}", s.key(h.trim_start_matches('#').trim()));
            } else {
                println!("  {line}");
            }
        }
    }

    /// External-signer status + the Sepolia/mainnet lifecycle send flow
    /// (CL-WAL-010, ADR-020). Same discipline on both chains: chain
    /// re-verified from the RPC itself, full preview, explicit chain-labeled
    /// approval phrase, audited.
    async fn do_external_signer(&self) -> io::Result<()> {
        use alloy::providers::{Provider, ProviderBuilder};
        use cipherlayer_vault::external_signer::{MAINNET_CHAIN_ID, SEPOLIA_CHAIN_ID};
        use cipherlayer_vault::{
            ConfirmationSurface, ExternalSignerConfig, LocalKeyExternalSigner, TxParams,
            UserAuthorization,
        };

        // ADR-021: menu 9 is a chain-family dispatcher. The Solana clusters
        // route to the vaultd-hosted ceremony; the EVM ceremony below is
        // unchanged (its console-side key path is recorded debt, ADR-021 §5).
        if self.active_chain.0 == cipherlayer_chain::SOLANA_DEVNET_CHAIN_ID
            || self.active_chain.0 == cipherlayer_chain::SOLANA_MAINNET_CHAIN_ID
        {
            return self.do_external_signer_sol().await;
        }

        let s = &self.style;
        println!(
            "  {}",
            s.bold("external signer (real-key, Sepolia or Ethereum mainnet)")
        );
        println!(
            "  {}",
            s.dim(
                "separate authority from the (dev-only, mocked) Vault; testnet or real \
                 mainnet only, human-gated (ADR-011/ADR-020)."
            )
        );
        // The active chain (menu 3) must be Sepolia or mainnet before
        // anything else — deterministic gate, checked again against the RPC
        // below. No other registry entry is reachable from this flow.
        let is_mainnet = self.active_chain.0 == MAINNET_CHAIN_ID;
        let is_sepolia = self.active_chain.0 == SEPOLIA_CHAIN_ID;
        if !is_mainnet && !is_sepolia {
            let name = self
                .registry
                .get(self.active_chain)
                .map(|e| e.name.clone())
                .unwrap_or_else(|_| "unknown".into());
            println!(
                "  {}",
                s.red(&format!(
                    "REFUSED: active chain is {name} ({}) — the external signer permits only \
                     Sepolia ({SEPOLIA_CHAIN_ID}) or Ethereum mainnet ({MAINNET_CHAIN_ID}). \
                     Switch it in chains (3).",
                    self.active_chain.0
                ))
            );
            return Ok(());
        }
        let chain_name = if is_mainnet {
            "Ethereum mainnet"
        } else {
            "Sepolia"
        };
        let approval_phrase = if is_mainnet {
            "SEND-CIPHERLAYER-MAINNET"
        } else {
            "SEND-CIPHERLAYER-SEPOLIA"
        };
        if is_mainnet {
            println!(
                "  {}",
                s.red("⚠ REAL ETHEREUM MAINNET — REAL FUNDS, IRREVERSIBLE (ADR-020) ⚠")
            );
        }
        if std::env::var(EXTERNAL_SIGNER_KEY_ENV).is_err() {
            println!("  {}", s.dim("no runtime key loaded."));
            let choice = self.prompt("[l]oad a key now (or 'l <address>') / blank=back")?;
            let choice = choice.trim();
            if choice.is_empty() {
                return Ok(());
            }
            // Accept "l" alone, or "l <address>" inline (a natural thing to
            // paste) — previously any other text silently fell through to
            // "back" with no message, which read as a hang.
            let mut parts = choice.splitn(2, char::is_whitespace);
            let verb = parts.next().unwrap_or("");
            let inline_addr = parts.next().map(str::trim).filter(|s| !s.is_empty());
            if verb != "l" && verb != "load" {
                println!(
                    "  {}",
                    s.dim(&format!(
                        "\"{choice}\" not recognized — type 'l' to load a key, or leave blank to go back."
                    ))
                );
                return Ok(());
            }
            if !self.load_key_interactive(inline_addr, is_mainnet)? {
                return Ok(());
            }
        }
        let Ok(from_str) = std::env::var("CIPHERLAYER_EXTERNAL_SIGNER_FROM") else {
            println!(
                "  {}",
                s.red("CIPHERLAYER_EXTERNAL_SIGNER_FROM is not set (the loader exports it).")
            );
            return Ok(());
        };
        let from = match cipherlayer_evm::parse_address(&from_str) {
            Ok(a) => a,
            Err(e) => {
                println!(
                    "  {}",
                    s.red(&format!("bad CIPHERLAYER_EXTERNAL_SIGNER_FROM: {e}"))
                );
                return Ok(());
            }
        };
        println!("  key loaded for {}", s.amber(&from_str));

        // RPC preference: operator's premium endpoint, else the public
        // default. A premium URL may embed a token — label it without ever
        // printing it.
        let (rpc, rpc_label) = if is_mainnet {
            match std::env::var("CIPHERLAYER_MAINNET_RPC") {
                Ok(u) => (
                    u,
                    "operator-configured mainnet rpc (from env, url not shown)".to_string(),
                ),
                Err(_) => (
                    "https://ethereum-rpc.publicnode.com".to_string(),
                    "https://ethereum-rpc.publicnode.com (public default)".to_string(),
                ),
            }
        } else {
            match std::env::var("CIPHERLAYER_QUICKNODE_SEPOLIA_URL") {
                Ok(u) => (u, "quicknode (from env, url not shown)".to_string()),
                Err(_) => match std::env::var("CIPHERLAYER_SEPOLIA_RPC") {
                    Ok(u) => {
                        let label = u.clone();
                        (u, label)
                    }
                    Err(_) => (
                        "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
                        "https://ethereum-sepolia-rpc.publicnode.com (public default)".to_string(),
                    ),
                },
            }
        };
        println!("  rpc      {}", s.dim(&rpc_label));

        println!(
            "  {}",
            s.dim("step-by-step: type 's' and follow the prompts · one-go: s <recipient-or-alias> a <wei>")
        );
        let action = self.prompt("send / blank=back")?;
        let action = action.trim();
        if action.is_empty() {
            return Ok(());
        }
        let cmd = match parse_send_command(action) {
            Ok(c) => c,
            Err(msg) => {
                println!("  {}", s.red(&msg));
                return Ok(());
            }
        };

        let url = match rpc.parse() {
            Ok(u) => u,
            Err(e) => {
                println!("  {}", s.red(&format!("bad rpc url: {e}")));
                return Ok(());
            }
        };
        let provider = ProviderBuilder::new().connect_http(url);

        // Never trust config: the RPC itself must report Sepolia. Same
        // adapter check the pipeline enforces (ADR-015).
        let adapter = cipherlayer_evm::adapter::EvmAdapter::new(&rpc);
        match adapter.verify_chain_identity(self.active_chain).await {
            Ok(()) => {}
            Err(cipherlayer_chain::adapter::AdapterError::ChainIdentityMismatch {
                actual, ..
            }) => {
                println!(
                    "  {}",
                    s.red(&format!(
                        "REFUSED: rpc reports chain {actual}, not the active chain {chain_name} ({}).",
                        self.active_chain.0
                    ))
                );
                return Ok(());
            }
            Err(e) => {
                println!("  {}", s.red(&format!("rpc unreachable: {e}")));
                return Ok(());
            }
        }

        let to_input = match cmd.to {
            Some(addr) => addr,
            None => self.prompt("recipient address or alias (blank = self-send)")?,
        };
        let resolved_to = if to_input.is_empty() {
            ResolvedAddressRef {
                address: from,
                label: None,
            }
        } else {
            match resolve_evm_address_ref(&to_input, &self.load_aliases(), "recipient") {
                Ok(resolved) => resolved,
                Err(message) => {
                    println!("  {}", s.red(&message));
                    return Ok(());
                }
            }
        };
        let to = resolved_to.address;
        let value_input = match cmd.value_wei {
            Some(v) => v,
            None => self.prompt("value wei (blank = 1)")?,
        };
        let value = cipherlayer_types::U256::from_str_radix(
            if value_input.is_empty() {
                "1"
            } else {
                &value_input
            },
            10,
        )
        .unwrap_or(cipherlayer_types::U256::from(1u64));

        let (Ok(nonce), Ok(gas_price), Ok(balance)) = (
            provider.get_transaction_count(from).await,
            provider.get_gas_price().await,
            provider.get_balance(from).await,
        ) else {
            println!(
                "  {}",
                s.red("failed to fetch nonce/gas/balance from the rpc.")
            );
            return Ok(());
        };
        let gas_limit: u64 = 21_000; // native transfer

        println!();
        println!("  {}", s.bold(&format!("{chain_name} lifecycle preflight")));
        if is_mainnet {
            println!(
                "  {}",
                s.red("  ⚠ REAL FUNDS — this cannot be undone once broadcast ⚠")
            );
        }
        println!("    from      {from}");
        println!(
            "    to        {to}{}",
            if to == from { " (self)" } else { "" }
        );
        if let Some(label) = &resolved_to.label {
            println!(
                "    to alias  {} (resolved locally; verify address above)",
                sanitize_display_label(label)
            );
        }
        println!("    value     {value} wei");
        println!("    nonce     {nonce}");
        println!("    gas       {gas_limit} @ {gas_price} wei");
        println!("    balance   {balance} wei");
        println!("    chain     {} (verified from rpc)", self.active_chain.0);
        println!();
        println!(
            "  Type {} to sign and broadcast this REAL {} transaction:",
            s.amber(approval_phrase),
            if is_mainnet { "MAINNET" } else { "testnet" }
        );
        // Distinguish a typo from a cancel (2026-07-17 operator feedback:
        // two real mainnet attempts died on a one-letter phrase typo with
        // only "cancelled" as feedback). Blank cancels; a wrong phrase says
        // so and lets the operator retry — the gate stays exact-match.
        loop {
            let approval = self.prompt("approve (blank = cancel)")?;
            if approval.is_empty() {
                println!("  {}", s.dim("cancelled before signing."));
                return Ok(());
            }
            if approval == approval_phrase {
                break;
            }
            println!(
                "  {}",
                s.amber(&format!(
                    "phrase mismatch — type {approval_phrase} exactly (hyphens included), or leave blank to cancel."
                ))
            );
        }

        let signer_config = if is_mainnet {
            ExternalSignerConfig::mainnet(from)
        } else {
            ExternalSignerConfig::sepolia(from)
        };
        let signer = LocalKeyExternalSigner::new(signer_config);
        let authz = UserAuthorization {
            decided_at: chrono::Utc::now(),
            surface: ConfirmationSurface::CliPrompt,
            escalation_acknowledged: true, // the phrase above IS the acknowledgement
        };
        let tx = TxParams {
            to: Some(to),
            value,
            data: vec![],
            nonce,
            gas_limit,
            gas_price_wei: gas_price,
        };
        let signed = match signer.sign(self.active_chain, &tx, &authz).await {
            Ok(x) => x,
            Err(e) => {
                println!("  {}", s.red(&format!("signing refused: {e}")));
                return Ok(());
            }
        };
        println!("  signed. tx hash {}", s.bold(&signed.tx_hash));

        // Audit before broadcast — the record exists even if broadcast fails.
        if let Ok(audit) = AuditLog::open(&self.audit_path) {
            let _ = audit.append(
                cipherlayer_audit::EventKind::SignatureCreated,
                None,
                serde_json::json!({
                    "signer": "external:local-key", "chain_id": self.active_chain.0,
                    "from": format!("{from}"), "to": format!("{to}"),
                    "value_wei": value.to_string(), "tx_hash": signed.tx_hash,
                    "rpc": rpc_label,
                }),
            );
        }

        let raw_hex = format!("0x{}", hex::encode(&signed.raw));
        let sent: Result<String, _> = provider
            .raw_request("eth_sendRawTransaction".into(), (raw_hex,))
            .await;
        match sent {
            Ok(h) => println!("  broadcast accepted: {}", s.green(&h)),
            Err(e) => {
                println!("  {}", s.red(&format!("broadcast failed: {e}")));
                return Ok(());
            }
        }

        println!("  {}", s.dim("polling for receipt (up to ~2 min)..."));
        for _ in 0..40 {
            let receipt: Result<serde_json::Value, _> = provider
                .raw_request(
                    "eth_getTransactionReceipt".into(),
                    (signed.tx_hash.clone(),),
                )
                .await;
            if let Ok(r) = receipt {
                if !r.is_null() {
                    let status = if r["status"] == "0x1" {
                        s.green("success")
                    } else {
                        s.red("reverted")
                    };
                    let block = u64::from_str_radix(
                        r["blockNumber"]
                            .as_str()
                            .unwrap_or("0x0")
                            .trim_start_matches("0x"),
                        16,
                    )
                    .unwrap_or(0);
                    println!("  confirmed: block {block}, status {status}");
                    if let Ok(audit) = AuditLog::open(&self.audit_path) {
                        let _ = audit.append(
                            cipherlayer_audit::EventKind::BroadcastCompleted,
                            None,
                            serde_json::json!({
                                "signer": "external:local-key", "chain_id": self.active_chain.0,
                                "tx_hash": signed.tx_hash, "block": block,
                            }),
                        );
                    }
                    if is_mainnet {
                        println!(
                            "  {}",
                            s.dim(&format!(
                                "verify: https://etherscan.io/tx/{}",
                                signed.tx_hash
                            ))
                        );
                    } else {
                        println!(
                            "  {}",
                            s.dim(&format!(
                                "observer verification: tools/metamask-lifecycle-harness/verify-artifact.sh {}",
                                signed.tx_hash
                            ))
                        );
                    }
                    return Ok(());
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        println!(
            "  {}",
            s.amber("no receipt yet — check a block explorer; the tx may still confirm.")
        );
        Ok(())
    }

    /// ADR-021: the Solana external-signer ceremony — console side. This
    /// method orchestrates only the NON-SECRET steps: RPC resolution,
    /// genesis re-verification, fact collection, message building, fee
    /// queries, broadcast, and audit. The approval phrase and the private
    /// key are entered on the **vaultd terminal**, never here — this
    /// process cannot leak what it never holds.
    async fn do_external_signer_sol(&self) -> io::Result<()> {
        use cipherlayer_chain::adapter::{ChainBroadcaster, ChainObserver};
        use cipherlayer_sol::{SolAdapter, SolBuildInput, SolTxStatus};
        use cipherlayer_vault::ipc::WireSolFacts;
        use cipherlayer_vault::VaultClient;

        let s = &self.style;
        let is_mainnet = self.active_chain.0 == cipherlayer_chain::SOLANA_MAINNET_CHAIN_ID;
        let cluster_name = if is_mainnet {
            "Solana mainnet-beta"
        } else {
            "Solana devnet"
        };
        println!(
            "  {}",
            s.bold(&format!(
                "external signer — {cluster_name} (vaultd-hosted ceremony, ADR-021)"
            ))
        );
        println!(
            "  {}",
            s.dim(
                "the approval phrase and the private key are entered on the VAULTD terminal, \
                 not here; this console never sees the key."
            )
        );
        if is_mainnet {
            println!(
                "  {}",
                s.red("⚠ REAL SOLANA MAINNET — REAL FUNDS, IRREVERSIBLE (ADR-021) ⚠")
            );
        }

        use cipherlayer_audit::EventKind;
        use cipherlayer_types::state::LifecycleState;
        use serde_json::json;

        // The audit log is lifecycle evidence, not decoration (CL-AUD-001):
        // if it cannot be written, the ceremony refuses to start. Opened
        // FIRST so every gate below — including configuration refusals — is
        // recorded under the ceremony's lifecycle (external re-audit,
        // 2026-07-20).
        let audit = match AuditLog::open(&self.audit_path) {
            Ok(a) => a,
            Err(e) => {
                println!(
                    "  {}",
                    s.red(&format!(
                        "REFUSED: audit log unavailable ({e}) — the ceremony requires \
                         lifecycle evidence (CL-AUD-001) and will not run without it."
                    ))
                );
                return Ok(());
            }
        };
        // The ceremony is a signing lifecycle (cipherlayer-types::state):
        // one request id, every transition validated + audited. RECEIVED now.
        let mut trace = SolTrace::start(&audit);
        if let Err(e) = trace.record(
            EventKind::RequestReceived,
            json!({
                "signer": "external:sol-vaultd", "cluster": cluster_name,
                "chain_id": self.active_chain.0, "kind": "sol_system_transfer",
            }),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }
        println!(
            "  request  {}",
            s.dim(&format!("lifecycle {}", trace.request_id()))
        );

        // RPC resolution. Mainnet is explicit-only: no public fallback.
        let (rpc, rpc_label) = if is_mainnet {
            match std::env::var("CIPHERLAYER_SOLANA_MAINNET_RPC") {
                Ok(u) if !u.trim().is_empty() => (
                    u,
                    "operator-configured mainnet rpc (from env, url not shown)".to_string(),
                ),
                _ => {
                    println!(
                        "  {}",
                        s.red(
                            "REFUSED: CIPHERLAYER_SOLANA_MAINNET_RPC is not set. Mainnet RPC is \
                             explicit-only (ADR-021 §3) — there is no public fallback. Export it \
                             and re-enter this menu."
                        )
                    );
                    let _ = trace.step(
                        LifecycleState::Rejected,
                        EventKind::Failure,
                        json!({"stage": "rpc-resolution", "reason": "mainnet rpc not configured"}),
                    );
                    return Ok(());
                }
            }
        } else {
            match std::env::var("CIPHERLAYER_SOLANA_DEVNET_RPC") {
                Ok(u) if !u.trim().is_empty() => (
                    u,
                    "operator-configured devnet rpc (from env, url not shown)".to_string(),
                ),
                _ => (
                    "https://api.devnet.solana.com".to_string(),
                    "https://api.devnet.solana.com (public default)".to_string(),
                ),
            }
        };
        // TLS gate (external re-audit, 2026-07-20): a cleartext primary can
        // rewrite every attestation the ceremony rests on. Loopback (local
        // validator) is exempt.
        if let Err(reason) = require_sol_rpc_tls(&rpc, "primary") {
            println!("  {}", s.red(&format!("REFUSED: {reason}")));
            let _ = trace.step(
                LifecycleState::Rejected,
                EventKind::Failure,
                json!({"stage": "rpc-resolution", "reason": reason}),
            );
            return Ok(());
        }
        println!("  rpc      {}", s.dim(&rpc_label));

        // Independent cross-check endpoint (ADR-021 amendment, external
        // audit 2026-07-19 / ATK5): Solana transactions carry no chain id,
        // so a Byzantine primary could attest the pinned genesis while
        // handing out another cluster's blockhash. Before broadcast, a
        // SECOND provider must independently attest the genesis and the
        // final message's blockhash. Mainnet: required, and it must differ
        // from the primary. Devnet: optional — absent is an accepted,
        // documented single-provider residual.
        let crosscheck_env = if is_mainnet {
            std::env::var("CIPHERLAYER_SOLANA_MAINNET_RPC_CROSSCHECK").ok()
        } else {
            std::env::var("CIPHERLAYER_SOLANA_DEVNET_RPC_CROSSCHECK").ok()
        };
        let crosscheck_rpc: Option<String> =
            match resolve_sol_crosscheck(is_mainnet, &rpc, crosscheck_env.as_deref()) {
                Ok(cc) => cc,
                Err(reason) => {
                    println!("  {}", s.red(&format!("REFUSED: {reason}")));
                    let _ = trace.step(
                        LifecycleState::Rejected,
                        EventKind::Failure,
                        json!({"stage": "crosscheck-resolution", "reason": reason}),
                    );
                    return Ok(());
                }
            };
        match &crosscheck_rpc {
            Some(_) => println!(
                "  {}",
                s.dim("cross-check rpc configured (independent provider, url not shown)")
            ),
            None => println!(
                "  {}",
                s.dim(
                    "cross-check rpc not set — single-provider mode (devnet-only residual, \
                     ADR-021 amendment)"
                )
            ),
        }

        // Pinned genesis identity, re-verified live before anything else
        // (ADR-016 §3 / ADR-021 §3 — never trust config for cluster identity).
        let pinned: solana_hash::Hash = if is_mainnet {
            cipherlayer_chain::SOLANA_MAINNET_GENESIS
                .parse()
                .expect("pinned genesis parses")
        } else {
            cipherlayer_chain::SOLANA_DEVNET_GENESIS
                .parse()
                .expect("pinned genesis parses")
        };
        let adapter = SolAdapter::new(&rpc, Some(pinned));
        match adapter.verify_chain_identity(self.active_chain).await {
            Ok(()) => println!("  genesis  {}", s.green("verified against the pinned hash")),
            Err(cipherlayer_chain::adapter::AdapterError::ChainIdentityMismatch {
                actual, ..
            }) => {
                println!(
                    "  {}",
                    s.red(&format!(
                        "REFUSED: rpc reports genesis {actual}, not the pinned {cluster_name} \
                         genesis. Wrong cluster or hostile endpoint — nothing was sent."
                    ))
                );
                let _ = trace.step(
                    LifecycleState::Rejected,
                    EventKind::Failure,
                    json!({"stage": "chain-identity", "actual_genesis": actual.to_string()}),
                );
                return Ok(());
            }
            Err(e) => {
                println!("  {}", s.red(&format!("rpc unreachable: {e}")));
                let _ = trace.step(
                    LifecycleState::Rejected,
                    EventKind::Failure,
                    json!({"stage": "chain-identity", "error": e.to_string()}),
                );
                return Ok(());
            }
        }

        // vaultd must be up (it hosts the phrase + key prompts on its tty).
        let vault_socket = std::env::var("CIPHERLAYER_VAULT_SOCKET")
            .unwrap_or_else(|_| "./data/vaultd/vault.sock".into());
        let client = match VaultClient::connect_checked(&vault_socket) {
            Ok(c) => c,
            Err(e) => {
                println!(
                    "  {}",
                    s.red(&format!(
                        "vaultd is not reachable ({e}). Start it in its own terminal — \
                         `cargo run -p cipherlayer-vaultd` — it hosts the approval and key \
                         prompts for this ceremony."
                    ))
                );
                let _ = trace.step(
                    LifecycleState::Rejected,
                    EventKind::Failure,
                    json!({"stage": "vaultd-connect", "error": e.to_string()}),
                );
                return Ok(());
            }
        };

        // Facts (all public): sender, recipient, amount. Any malformed fact
        // is a REJECTED lifecycle, audited as such.
        let reject_facts = |trace: &mut SolTrace, reason: &str| {
            println!("  {}", s.red(reason));
            let _ = trace.step(
                LifecycleState::Rejected,
                EventKind::Failure,
                json!({"stage": "facts-validation", "reason": reason}),
            );
        };
        let from_input = self.prompt("sender pubkey (base58)")?;
        let from = match adapter.parse_address(from_input.trim()) {
            Ok(p) => p,
            Err(e) => {
                reject_facts(&mut trace, &e.to_string());
                return Ok(());
            }
        };
        let to_input = self.prompt("recipient pubkey (base58)")?;
        let to = match adapter.parse_address(to_input.trim()) {
            Ok(p) => p,
            Err(e) => {
                reject_facts(&mut trace, &e.to_string());
                return Ok(());
            }
        };
        let lamports_input = self.prompt("amount in lamports (1 SOL = 1_000_000_000)")?;
        let Ok(lamports) = lamports_input.trim().replace('_', "").parse::<u64>() else {
            reject_facts(&mut trace, "amount must be plain lamport digits.");
            return Ok(());
        };
        if lamports == 0 {
            reject_facts(&mut trace, "amount must be non-zero.");
            return Ok(());
        }

        // Everything the lifecycle calls "validated" now holds: audited RPC
        // + cross-check configuration, live genesis identity, reachable
        // vaultd, well-formed facts.
        if let Err(e) = trace.step(
            LifecycleState::Validated,
            EventKind::RequestValidated,
            json!({
                "from": from.to_string(), "to": to.to_string(), "lamports": lamports,
                "rpc": rpc_label, "crosscheck_configured": crosscheck_rpc.is_some(),
            }),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }
        // No delegated grant is in scope: the operator drives this ceremony
        // directly and approves it in person on the vault surface (ADR-021).
        // Recorded explicitly, never silently skipped.
        if let Err(e) = trace.step(
            LifecycleState::PermissionChecked,
            EventKind::PermissionChecked,
            json!({"model": "operator-direct external signer — no delegated grant in scope"}),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }

        // Preflight: provisional message for the authoritative fee estimate,
        // live balance. Lamports always rendered with the SOL equivalent.
        // Query failures are REJECTED lifecycles — evidence that cannot be
        // gathered refuses, closed.
        let reject_query = |trace: &mut SolTrace, stage: &str, error: String| {
            println!("  {}", s.red(&format!("{stage}: {error}")));
            let _ = trace.step(
                LifecycleState::Rejected,
                EventKind::Failure,
                json!({"stage": stage, "error": error}),
            );
        };
        let provisional = match adapter
            .build_unsigned(&SolBuildInput {
                from,
                to,
                lamports,
                recent_blockhash: None,
            })
            .await
        {
            Ok(m) => m,
            Err(e) => {
                reject_query(&mut trace, "could not build message", e.to_string());
                return Ok(());
            }
        };
        let fee_estimate = match adapter.fee_for_message(&provisional.message).await {
            Ok(f) => f,
            Err(e) => {
                reject_query(&mut trace, "fee query failed", e.to_string());
                return Ok(());
            }
        };
        let balance = match adapter.balance_lamports(&from).await {
            Ok(b) => b,
            Err(e) => {
                reject_query(&mut trace, "balance query failed", e.to_string());
                return Ok(());
            }
        };

        // DECODED: the intent is a fully-constructed system transfer.
        if let Err(e) = trace.step(
            LifecycleState::Decoded,
            EventKind::IntentDecoded,
            json!({
                "intent": "sol_system_transfer",
                "from": from.to_string(), "to": to.to_string(), "lamports": lamports,
            }),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }
        // SIMULATED / RISK_EVALUATED: no Solana simulator or risk evaluator
        // is wired in this revision. Unknown stays unknown (AGENTS.md hard
        // invariant) — the states are entered and audited with the honest
        // evidence value, never skipped and never defaulted to "ok"/"low".
        if let Err(e) = trace.step(
            LifecycleState::Simulated,
            EventKind::SimulationCompleted,
            json!({"simulation": "unknown — no Solana simulation wired (recorded honestly)"}),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }
        if let Err(e) = trace.step(
            LifecycleState::RiskEvaluated,
            EventKind::RiskEvaluated,
            json!({"risk": "unknown — no Solana risk evaluator wired (unknown never downgrades)"}),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }

        // POLICY_EVALUATED: the ceremony's deterministic gates — fee honesty
        // (ADR-021 §4: mainnet refuses on unknown) and the balance preflight
        // (external audit, 2026-07-19: a full-balance send left nothing for
        // the fee and burned a ceremony). Deny is terminal: POLICY_DENIED.
        // Otherwise the unknown simulation/risk evidence forces escalation
        // to the vault-side human ceremony; it never becomes an allow.
        let policy_result = sol_policy_verdict(is_mainnet, balance, lamports, fee_estimate);
        if let Err(e) = trace.step(
            LifecycleState::PolicyEvaluated,
            EventKind::PolicyEvaluated,
            json!({
                "gates": ["fee-honesty (ADR-021 §4)", "balance-preflight"],
                "fee_estimate_lamports": fee_estimate, "balance_lamports": balance,
                "verdict": policy_result.as_ref().copied().unwrap_or("deny"),
                "unknown_evidence_rule": "simulation/risk unknown requires trusted human escalation",
            }),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }
        if let Err(reason) = policy_result {
            println!("  {}", s.red(&format!("REFUSED: {reason}")));
            let _ = trace.step(
                LifecycleState::PolicyDenied,
                EventKind::Failure,
                json!({"stage": "policy", "reason": reason}),
            );
            return Ok(());
        }

        println!();
        println!(
            "  {}",
            s.bold(&format!("{cluster_name} ceremony preflight"))
        );
        if is_mainnet {
            println!(
                "  {}",
                s.red("  ⚠ REAL FUNDS — this cannot be undone once broadcast ⚠")
            );
        }
        println!("    from      {from}");
        println!(
            "    to        {to}{}",
            if to == from { " (self)" } else { "" }
        );
        println!(
            "    amount    {lamports} lamports ({} SOL)",
            lamports as f64 / 1e9
        );
        match fee_estimate {
            Some(f) => println!("    fee       {f} lamports (pre-approval estimate)"),
            None => println!("    fee       unknown (devnet may proceed; shown honestly)"),
        }
        println!(
            "    balance   {balance} lamports ({} SOL)",
            balance as f64 / 1e9
        );
        println!("    cluster   {cluster_name} (genesis verified from rpc)");
        println!();
        println!(
            "  {}",
            s.amber(
                "→ switch to the VAULTD terminal now: it will display these facts and ask for \
                 the approval phrase there."
            )
        );

        // USER_REVIEW: the human decision happens on vaultd's trusted tty —
        // the same facts, the chain-labeled phrase, presence at the terminal.
        if let Err(e) = trace.step(
            LifecycleState::UserReview,
            EventKind::StateTransition,
            json!({
                "surface": "vaultd trusted tty (ADR-021)",
                "status": "escalated for review — chain-labeled approval phrase required",
            }),
        ) {
            println!("  {}", s.red(&format!("REFUSED: {e}")));
            return Ok(());
        }

        // Phase 1: facts to vaultd; the phrase is typed on ITS terminal.
        let facts = WireSolFacts {
            from_pubkey: from.to_string(),
            to_pubkey: to.to_string(),
            lamports,
            fee_estimate_lamports: fee_estimate,
        };
        let nonce = match client.sol_approve_facts(self.active_chain.0, facts).await {
            Ok((nonce, expires_at, _)) => {
                println!(
                    "  {}",
                    s.green(&format!(
                        "facts approved on the vault surface (valid until {})",
                        expires_at.format("%H:%M:%S")
                    ))
                );
                if let Err(e) = trace.step(
                    LifecycleState::Authorized,
                    EventKind::UserDecision,
                    json!({
                        "decision": "approved", "surface": "vaultd trusted tty (ADR-021)",
                        "approval_nonce": nonce, "expires_at": expires_at,
                    }),
                ) {
                    println!("  {}", s.red(&format!("REFUSED: {e}")));
                    return Ok(());
                }
                nonce
            }
            Err(e) => {
                println!("  {}", s.red(&format!("approval did not complete: {e}")));
                let _ = trace.step(
                    LifecycleState::Rejected,
                    EventKind::UserDecision,
                    json!({"decision": "not approved", "error": e.to_string()}),
                );
                return Ok(());
            }
        };

        // Build the FINAL message with a fresh blockhash, after approval
        // (ADR-021 §2), and its authoritative fee.
        let unsigned = match adapter
            .build_unsigned(&SolBuildInput {
                from,
                to,
                lamports,
                recent_blockhash: None,
            })
            .await
        {
            Ok(m) => m,
            Err(e) => {
                println!(
                    "  {}",
                    s.red(&format!("could not build final message: {e}"))
                );
                let _ = trace.step(
                    LifecycleState::SigningFailed,
                    EventKind::SigningFailed,
                    json!({"stage": "final-message-build", "error": e.to_string(),
                           "note": "refused before the key prompt — nothing was signed"}),
                );
                return Ok(());
            }
        };
        let final_fee = match adapter.fee_for_message(&unsigned.message).await {
            Ok(f) => f,
            Err(e) => {
                println!("  {}", s.red(&format!("final fee query failed: {e}")));
                let _ = trace.step(
                    LifecycleState::SigningFailed,
                    EventKind::SigningFailed,
                    json!({"stage": "final-fee-query", "error": e.to_string(),
                           "note": "refused before the key prompt — nothing was signed"}),
                );
                return Ok(());
            }
        };
        if final_fee != fee_estimate {
            println!(
                "  {}",
                s.amber(&format!(
                    "note: final fee {:?} differs from the estimate {:?} — vaultd will refuse \
                     if it exceeds what you approved.",
                    final_fee, fee_estimate
                ))
            );
        }
        // Re-check the balance against the FINAL fee before asking for the
        // key: a doomed broadcast should never get a signature. (Balance as
        // queried at preflight; the approval simply expires unused.)
        if let Err(reason) = sol_balance_preflight(balance, lamports, final_fee) {
            println!(
                "  {}",
                s.red(&format!(
                    "REFUSED before the key prompt: {reason} (final fee, preflight balance) — \
                     nothing was signed; let the approval expire."
                ))
            );
            let _ = trace.step(
                LifecycleState::SigningFailed,
                EventKind::SigningFailed,
                json!({"stage": "final-fee-balance-preflight", "reason": reason,
                       "note": "refused before the key prompt — nothing was signed"}),
            );
            return Ok(());
        }
        println!(
            "  {}",
            s.amber(
                "→ back to the VAULTD terminal: it will ask for the private key there (hidden)."
            )
        );

        // Phase 2: sign at vaultd. Key never transits this process.
        let (pubkey, signature, raw) = match client
            .sol_sign(nonce, &unsigned.serialize(), final_fee)
            .await
        {
            Ok(x) => x,
            Err(e) => {
                println!("  {}", s.red(&format!("signing did not complete: {e}")));
                println!(
                    "  {}",
                    s.dim("the approval was consumed — a retry is a full ceremony re-run.")
                );
                let _ = trace.step(
                    LifecycleState::SigningFailed,
                    EventKind::SigningFailed,
                    json!({"stage": "vaultd-sign", "error": e.to_string(),
                           "note": "the approval was consumed"}),
                );
                return Ok(());
            }
        };
        println!(
            "  signed by {} — sig {}",
            s.amber(&pubkey),
            s.bold(&signature)
        );

        // SIGNED, audited before broadcast — no record, no broadcast
        // (CL-AUD-001). The signed artifact is discarded on refusal; the
        // approval is already consumed, so nothing can be sent later either.
        if let Err(e) = trace.step(
            LifecycleState::Signed,
            EventKind::SignatureCreated,
            json!({
                "signer": "external:sol-vaultd", "cluster": cluster_name,
                "chain_id": self.active_chain.0,
                "from": pubkey, "to": to.to_string(),
                "lamports": lamports, "signature": signature,
                "rpc": rpc_label,
            }),
        ) {
            println!(
                "  {}",
                s.red(&format!(
                    "REFUSED: could not record the signature ({e}) — aborting BEFORE \
                     broadcast (CL-AUD-001). Nothing was sent; the signed bytes are \
                     discarded and the approval is spent."
                ))
            );
            return Ok(());
        }

        // Pre-broadcast identity gate (ADR-021 §3 + amendment): the primary
        // must STILL attest the pinned genesis, and — when a cross-check
        // provider is configured (always, on mainnet) — the independent
        // endpoint must attest both the genesis and THIS message's
        // blockhash. A cross-cluster blockhash fails here, closed.
        if let Err(e) = adapter.verify_chain_identity(self.active_chain).await {
            println!(
                "  {}",
                s.red(&format!(
                    "REFUSED pre-broadcast: the primary rpc no longer attests the pinned \
                     genesis ({e}) — nothing was broadcast."
                ))
            );
            let _ = trace.step(
                LifecycleState::BroadcastFailed,
                EventKind::Failure,
                json!({
                    "signer": "external:sol-vaultd", "cluster": cluster_name,
                    "signature": signature,
                    "status": "aborted_pre_broadcast_identity", "error": e.to_string(),
                }),
            );
            return Ok(());
        }
        if let Some(cc) = &crosscheck_rpc {
            let cc_adapter = SolAdapter::new(cc, Some(pinned));
            let attests = match cc_adapter.verify_chain_identity(self.active_chain).await {
                Ok(()) => cc_adapter
                    .is_blockhash_valid(&unsigned.message.recent_blockhash)
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            match crosscheck_verdict(attests) {
                Ok(()) => println!(
                    "  {}",
                    s.green("cross-check: independent provider attests genesis + blockhash")
                ),
                Err((status, reason)) => {
                    println!(
                        "  {}",
                        s.red(&format!(
                            "REFUSED pre-broadcast: {reason} Nothing was broadcast."
                        ))
                    );
                    let _ = trace.step(
                        LifecycleState::BroadcastFailed,
                        EventKind::Failure,
                        json!({
                            "signer": "external:sol-vaultd", "cluster": cluster_name,
                            "signature": signature,
                            "status": status,
                        }),
                    );
                    return Ok(());
                }
            }
        }

        let tx_sig = match adapter.broadcast(&raw).await {
            Ok(sig) => {
                println!("  broadcast accepted: {}", s.green(&sig));
                // BROADCAST recorded at ACCEPTANCE, before confirmation
                // polling (external re-audit, 2026-07-20): a crash while
                // polling must never leave the audit implying the signed
                // transaction was never submitted.
                if let Some(w) = trace.step_warn(
                    LifecycleState::Broadcast,
                    EventKind::BroadcastCompleted,
                    json!({
                        "signer": "external:sol-vaultd", "cluster": cluster_name,
                        "chain_id": self.active_chain.0,
                        "signature": sig, "status": "accepted_awaiting_confirmation",
                    }),
                ) {
                    println!("  {}", s.red(&format!("⚠ {w}")));
                }
                sig
            }
            Err(e) => {
                println!("  {}", s.red(&format!("broadcast failed: {e}")));
                if let Some(w) = trace.step_warn(
                    LifecycleState::BroadcastFailed,
                    EventKind::BroadcastFailed,
                    json!({
                        "signer": "external:sol-vaultd", "cluster": cluster_name,
                        "chain_id": self.active_chain.0,
                        "signature": signature, "error": e.to_string(),
                    }),
                ) {
                    println!("  {}", s.red(&format!("⚠ {w}")));
                }
                println!(
                    "  {}",
                    s.amber(
                        "⚠ do NOT re-run the ceremony until an explorer confirms this signature \
                         is absent — Solana transactions carry no replay-window nonce and a \
                         double-send is a real risk (ADR-021 §2)."
                    )
                );
                return Ok(());
            }
        };

        println!("  {}", s.dim("polling for confirmation (up to ~90s)..."));
        let explorer = if is_mainnet {
            format!("https://explorer.solana.com/tx/{tx_sig}")
        } else {
            format!("https://explorer.solana.com/tx/{tx_sig}?cluster=devnet")
        };
        for _ in 0..30 {
            match adapter.transaction_status(&tx_sig).await {
                Ok(SolTxStatus::Confirmed { slot }) | Ok(SolTxStatus::Finalized { slot }) => {
                    println!("  confirmed: slot {slot}, status {}", s.green("success"));
                    if let Some(w) = trace.step_warn(
                        LifecycleState::Confirmed,
                        EventKind::StateTransition,
                        json!({
                            "note": "confirmation observed",
                            "signer": "external:sol-vaultd", "cluster": cluster_name,
                            "chain_id": self.active_chain.0,
                            "signature": tx_sig, "slot": slot,
                        }),
                    ) {
                        println!("  {}", s.red(&format!("⚠ {w}")));
                    }
                    println!("  {}", s.dim(&format!("verify: {explorer}")));
                    return Ok(());
                }
                Ok(SolTxStatus::Failed { slot }) => {
                    println!(
                        "  {}",
                        s.red(&format!("transaction failed on-chain at slot {slot}"))
                    );
                    if let Some(w) = trace.step_warn(
                        LifecycleState::BroadcastFailed,
                        EventKind::BroadcastFailed,
                        json!({
                            "signer": "external:sol-vaultd", "cluster": cluster_name,
                            "chain_id": self.active_chain.0,
                            "signature": tx_sig, "slot": slot,
                            "status": "failed_on_chain",
                        }),
                    ) {
                        println!("  {}", s.red(&format!("⚠ {w}")));
                    }
                    println!("  {}", s.dim(&format!("details: {explorer}")));
                    return Ok(());
                }
                _ => {}
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        // No terminal transition: the outcome is genuinely undetermined —
        // the lifecycle honestly remains at BROADCAST (the transaction may
        // still land) and the timeout itself is recorded.
        if let Err(w) = trace.record(
            EventKind::Failure,
            json!({
                "signer": "external:sol-vaultd", "cluster": cluster_name,
                "chain_id": self.active_chain.0,
                "signature": tx_sig,
                "status": "unconfirmed_after_poll_window",
            }),
        ) {
            println!("  {}", s.red(&format!("⚠ {w}")));
        }
        println!(
            "  {}",
            s.amber(&format!(
                "no confirmation yet. ⚠ do NOT re-run the ceremony until {explorer} confirms \
                 this signature is absent — a blockhash may still land it (ADR-021 §2)."
            ))
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_alone_is_fully_guided() {
        assert_eq!(parse_send_command("s").unwrap(), SendCommand::default());
        assert_eq!(parse_send_command("send").unwrap(), SendCommand::default());
    }

    #[test]
    fn one_go_recipient_and_amount() {
        let c = parse_send_command("s 0xAbC123 a 10").unwrap();
        assert_eq!(c.to.as_deref(), Some("0xAbC123"));
        assert_eq!(c.value_wei.as_deref(), Some("10"));
    }

    #[test]
    fn one_go_multi_word_recipient_alias() {
        let c = parse_send_command("s Test Target a 500000000000").unwrap();
        assert_eq!(c.to.as_deref(), Some("Test Target"));
        assert_eq!(c.value_wei.as_deref(), Some("500000000000"));

        let c = parse_send_command("send amount 5 Test Target").unwrap();
        assert_eq!(c.to.as_deref(), Some("Test Target"));
        assert_eq!(c.value_wei.as_deref(), Some("5"));
    }

    #[test]
    fn fields_accepted_in_any_order() {
        let c = parse_send_command("send amount 5 0xAbC123").unwrap();
        assert_eq!(c.to.as_deref(), Some("0xAbC123"));
        assert_eq!(c.value_wei.as_deref(), Some("5"));
    }

    #[test]
    fn partial_one_go_leaves_rest_for_prompts() {
        let c = parse_send_command("s 0xAbC123").unwrap();
        assert_eq!(c.to.as_deref(), Some("0xAbC123"));
        assert_eq!(c.value_wei, None);
        let c = parse_send_command("s a 7").unwrap();
        assert_eq!(c.to, None);
        assert_eq!(c.value_wei.as_deref(), Some("7"));
    }

    #[test]
    fn rejections_always_carry_a_reason() {
        for bad in [
            "x",
            "load",
            "s a",
            "s a ten",
            "s 0xA 0xB",
            "s Test a 1 Target",
            "s a 1 a 2",
        ] {
            let err = parse_send_command(bad).unwrap_err();
            assert!(!err.is_empty(), "{bad} must explain its rejection");
        }
    }

    #[test]
    fn recipient_alias_resolution_is_exact_and_case_insensitive() {
        let aliases = vec![AddressAlias {
            label: "Test   Target".into(),
            address: "0x1111111111111111111111111111111111111111".into(),
        }];
        let resolved = resolve_evm_address_ref("test target", &aliases, "recipient").unwrap();
        assert_eq!(
            resolved.address,
            cipherlayer_evm::parse_address("0x1111111111111111111111111111111111111111").unwrap()
        );
        assert_eq!(resolved.label.as_deref(), Some("Test   Target"));
        assert!(resolve_evm_address_ref("Test", &aliases, "recipient").is_err());
    }

    #[test]
    fn malformed_0x_literal_never_falls_through_to_alias_lookup() {
        // A malformed/truncated 0x-prefixed token must fail closed as an
        // invalid address, even if a saved alias label happens to look like
        // it — never silently resolve to a planted alias (code-review
        // finding, 2026-08-20).
        let aliases = vec![AddressAlias {
            label: "0x11111111111111111111111111111111111".into(), // one hex digit short
            address: "0x2222222222222222222222222222222222222222".into(),
        }];
        let err = resolve_evm_address_ref(
            "0x11111111111111111111111111111111111",
            &aliases,
            "recipient",
        )
        .unwrap_err();
        assert!(err.contains("not a valid EVM"), "{err}");
    }

    #[test]
    fn sanitize_display_label_strips_control_bytes() {
        // A label carrying terminal escape/cursor-movement bytes must not
        // reach the operator's screen intact — it is printed directly
        // beside the authoritative address the operator verifies before
        // signing (T-11; code-review finding, 2026-08-20).
        assert_eq!(
            sanitize_display_label("Treasury\x1b[2K\x1b[1A\x1b[2Kevil"),
            "Treasury[2K[1A[2Kevil"
        );
        assert_eq!(sanitize_display_label("Treasury"), "Treasury");
        assert_eq!(sanitize_display_label("Trea\nsury\t"), "Treasury");
    }

    #[test]
    fn duplicate_aliases_refuse_if_they_disagree() {
        let aliases = vec![
            AddressAlias {
                label: "Target".into(),
                address: "0x1111111111111111111111111111111111111111".into(),
            },
            AddressAlias {
                label: "target".into(),
                address: "0x2222222222222222222222222222222222222222".into(),
            },
        ];
        let err = resolve_evm_address_ref("TARGET", &aliases, "recipient").unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn duplicate_aliases_to_the_same_address_remain_deterministic() {
        let aliases = vec![
            AddressAlias {
                label: "Target".into(),
                address: "0x1111111111111111111111111111111111111111".into(),
            },
            AddressAlias {
                label: "target".into(),
                address: "0x1111111111111111111111111111111111111111".into(),
            },
        ];
        let resolved = resolve_evm_address_ref("TARGET", &aliases, "recipient").unwrap();
        assert_eq!(
            resolved.address,
            cipherlayer_evm::parse_address("0x1111111111111111111111111111111111111111").unwrap()
        );
    }

    // --- Solana ceremony decision logic (ADR-021 §6 security regressions) --

    #[test]
    fn rpc_host_normalizes_dress_up() {
        for (url, host) in [
            ("https://rpc.example.com", "rpc.example.com"),
            ("https://RPC.Example.com/", "rpc.example.com"),
            ("https://rpc.example.com/v1?key=abc", "rpc.example.com"),
            ("https://user:pw@rpc.example.com:8899/x", "rpc.example.com"),
            // Trailing-dot FQDN is the same host, not an independent one.
            ("https://rpc.example.com./v1", "rpc.example.com"),
            ("http://127.0.0.1:8899", "127.0.0.1"),
            ("http://[::1]:8899", "::1"),
        ] {
            assert_eq!(rpc_host(url).as_deref(), Some(host), "{url}");
        }
        assert_eq!(rpc_host(""), None);
        assert_eq!(rpc_host("https://"), None);
        assert_eq!(rpc_host("rpc.example.com:8899"), None);
    }

    #[test]
    fn rpc_host_normalizes_ipv4_mapped_ipv6() {
        // ::ffff:a.b.c.d is the same host as plain IPv4 a.b.c.d — a hostile
        // primary must not be able to pose as an "independent" cross-check
        // provider just by wrapping its address in IPv6-mapped notation
        // (code-review finding, 2026-08-20).
        assert_eq!(
            rpc_host("https://198.51.100.7"),
            rpc_host("https://[::ffff:198.51.100.7]")
        );
        assert!(
            resolve_sol_crosscheck(
                true,
                "https://198.51.100.7",
                Some("https://[::ffff:198.51.100.7]")
            )
            .is_err(),
            "IPv4-mapped IPv6 dressing must not count as an independent provider"
        );
    }

    #[test]
    fn mainnet_crosscheck_is_mandatory() {
        for absent in [None, Some(""), Some("   ")] {
            assert!(
                resolve_sol_crosscheck(true, "https://a.example.com", absent).is_err(),
                "mainnet must refuse without a cross-check ({absent:?})"
            );
        }
    }

    #[test]
    fn same_host_crosscheck_refuses_no_matter_the_dressing() {
        // The re-audit's exact scenario: cosmetic URL differences must not
        // count as independence.
        for dressed in [
            "https://a.example.com",
            "https://a.example.com/",
            "https://A.EXAMPLE.COM",
            "https://a.example.com/?apikey=zzz",
            "https://user@a.example.com:443/path",
        ] {
            assert!(
                resolve_sol_crosscheck(true, "https://a.example.com/v1", Some(dressed)).is_err(),
                "{dressed} is the same provider as the primary"
            );
            assert!(
                resolve_sol_crosscheck(false, "https://a.example.com/v1", Some(dressed)).is_err(),
                "devnet with a same-host cross-check is a loud misconfig, not a pass"
            );
        }
    }

    #[test]
    fn distinct_host_crosscheck_resolves() {
        let cc = resolve_sol_crosscheck(
            true,
            "https://a.example.com",
            Some("https://b.example.com/v2?key=k"),
        )
        .unwrap();
        assert_eq!(cc.as_deref(), Some("https://b.example.com/v2?key=k"));
    }

    #[test]
    fn devnet_without_crosscheck_is_single_provider_mode() {
        assert_eq!(
            resolve_sol_crosscheck(false, "https://api.devnet.solana.com", None).unwrap(),
            None
        );
    }

    #[test]
    fn unparseable_crosscheck_refuses_closed() {
        assert!(resolve_sol_crosscheck(true, "https://a.example.com", Some("://")).is_err());
    }

    #[test]
    fn crosscheck_verdict_only_explicit_true_proceeds() {
        assert!(crosscheck_verdict(Ok(true)).is_ok());
        let (status, _) = crosscheck_verdict(Ok(false)).unwrap_err();
        assert_eq!(status, "aborted_pre_broadcast_crosscheck_blockhash");
        let (status, reason) = crosscheck_verdict(Err("timeout".into())).unwrap_err();
        assert_eq!(status, "aborted_pre_broadcast_crosscheck_unavailable");
        assert!(reason.contains("timeout"));
    }

    #[test]
    fn balance_preflight_covers_fee_and_overflow() {
        // The live devnet-gate failure: full balance + fee cannot fit.
        assert!(sol_balance_preflight(1_000_000_000, 1_000_000_000, Some(5_000)).is_err());
        // Amount + known fee exactly fits: allowed.
        assert!(sol_balance_preflight(1_000_005_000, 1_000_000_000, Some(5_000)).is_ok());
        // Unknown fee: exact-balance send refuses; strictly-below passes.
        assert!(sol_balance_preflight(1_000_000_000, 1_000_000_000, None).is_err());
        assert!(sol_balance_preflight(1_000_000_000, 999_999_999, None).is_ok());
        // Overflow is a refusal, not a wrap.
        assert!(sol_balance_preflight(u64::MAX, u64::MAX, Some(1)).is_err());
    }

    #[test]
    fn live_balance_failure_is_unavailable_never_zero() {
        let err = format_live_native(Err("timeout".into()), 18, "ETH");
        assert!(err.contains("unavailable"));
        assert!(!err.contains("0 ETH"));
        let zero = format_live_native(Ok(cipherlayer_types::U256::ZERO), 18, "ETH");
        assert_eq!(zero, "0 ETH (live)");
        let one_and_half = cipherlayer_types::U256::from(1_500_000_000_000_000_000u64);
        assert_eq!(
            format_live_native(Ok(one_and_half), 18, "ETH"),
            "1.5 ETH (live)"
        );
        assert_eq!(
            format_units_trimmed(cipherlayer_types::U256::from(1u64), 18),
            "0"
        );
    }

    #[tokio::test]
    async fn unreachable_rpc_yields_error_not_a_balance() {
        let r = fetch_native_balance("http://127.0.0.1:1", cipherlayer_types::Address::ZERO).await;
        assert!(r.is_err());
    }

    #[test]
    fn live_balance_rpc_never_selects_mainnet_or_non_evm() {
        let reg = ChainRegistry::builtin();
        for e in reg.entries() {
            let rpc = live_balance_rpc(e, "http://127.0.0.1:8545");
            if e.chain_family != cipherlayer_chain::ChainFamily::Evm
                || e.network_class == NetworkClass::Mainnet
            {
                assert!(rpc.is_none(), "{} must not be queried", e.name);
            }
        }
        let dev = reg.get(cipherlayer_types::ChainId(31337)).unwrap();
        assert_eq!(
            live_balance_rpc(dev, "http://127.0.0.1:8545").as_deref(),
            Some("http://127.0.0.1:8545")
        );
    }

    #[test]
    fn unknown_sol_evidence_escalates_never_allows() {
        assert_eq!(
            sol_policy_verdict(false, 1_000_000, 100_000, Some(5_000)).unwrap(),
            "escalate"
        );
        assert_eq!(
            sol_policy_verdict(false, 1_000_000, 100_000, None).unwrap(),
            "escalate"
        );
        assert!(sol_policy_verdict(true, 1_000_000, 100_000, None).is_err());
        assert!(sol_policy_verdict(true, 100_000, 100_000, Some(5_000)).is_err());
    }

    // --- TLS gate + lifecycle discipline (external re-audit, 2026-07-20) --

    #[test]
    fn non_loopback_rpc_requires_https() {
        assert!(require_sol_rpc_tls("https://rpc.example.com", "primary").is_ok());
        assert!(require_sol_rpc_tls("HTTPS://rpc.example.com/path", "primary").is_ok());
        assert!(require_sol_rpc_tls("http://rpc.example.com", "primary").is_err());
        assert!(require_sol_rpc_tls("ws://rpc.example.com", "primary").is_err());
        // Loopback (local validator) is exempt — it never leaves the machine.
        assert!(require_sol_rpc_tls("http://127.0.0.1:8899", "primary").is_ok());
        assert!(require_sol_rpc_tls("http://localhost:8899", "primary").is_ok());
        assert!(require_sol_rpc_tls("http://[::1]:8899", "primary").is_ok());
        // DNS names that merely resemble loopback are remote and must not
        // inherit the cleartext exemption.
        for disguised in [
            "http://127.evil.com:8899",
            "http://127.0.0.1.evil.com:8899",
            "http://localhost.evil.com:8899",
        ] {
            assert!(
                require_sol_rpc_tls(disguised, "primary").is_err(),
                "{disguised} is a DNS name, not a loopback address"
            );
        }
        // A bare or malformed IPv6 authority is not silently repaired.
        assert!(require_sol_rpc_tls("http://::1:8899", "primary").is_err());
        // No extractable host refuses, closed.
        assert!(require_sol_rpc_tls("://", "primary").is_err());
    }

    #[test]
    fn cleartext_crosscheck_refuses_even_on_a_distinct_host() {
        assert!(resolve_sol_crosscheck(
            true,
            "https://a.example.com",
            Some("http://b.example.com")
        )
        .is_err());
    }

    fn temp_audit() -> (tempfile::TempDir, AuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        (dir, log)
    }

    /// The Solana ceremony's full happy path is legal in the shared
    /// transition table, every step lands in the audit log under the ONE
    /// request id, and simulation/risk are present (as unknown), not
    /// skipped.
    #[test]
    fn sol_trace_happy_path_is_legal_and_fully_audited() {
        use cipherlayer_audit::EventKind;
        use cipherlayer_types::state::LifecycleState as L;
        let (_dir, audit) = temp_audit();
        let mut trace = SolTrace::start(&audit);
        trace
            .record(EventKind::RequestReceived, serde_json::json!({}))
            .unwrap();
        for (to, kind) in [
            (L::Validated, EventKind::RequestValidated),
            (L::PermissionChecked, EventKind::PermissionChecked),
            (L::Decoded, EventKind::IntentDecoded),
            (L::Simulated, EventKind::SimulationCompleted),
            (L::RiskEvaluated, EventKind::RiskEvaluated),
            (L::PolicyEvaluated, EventKind::PolicyEvaluated),
            (L::UserReview, EventKind::StateTransition),
            (L::Authorized, EventKind::UserDecision),
            (L::Signed, EventKind::SignatureCreated),
            (L::Broadcast, EventKind::BroadcastCompleted),
            (L::Confirmed, EventKind::StateTransition),
        ] {
            trace
                .step(to, kind, serde_json::json!({"evidence": "unknown"}))
                .unwrap();
        }
        let events = audit.read_all().unwrap();
        assert_eq!(events.len(), 12);
        let rid = trace.request_id();
        assert!(events.iter().all(|e| e.request_id == Some(rid)));
    }

    /// Skipping a mandatory state is impossible: the shared table refuses,
    /// the attempt is audited, and the caller gets a hard error.
    #[test]
    fn sol_trace_cannot_skip_user_review_to_signed() {
        use cipherlayer_audit::EventKind;
        use cipherlayer_types::state::LifecycleState as L;
        let (_dir, audit) = temp_audit();
        let mut trace = SolTrace::start(&audit);
        trace
            .step(
                L::Validated,
                EventKind::RequestValidated,
                serde_json::json!({}),
            )
            .unwrap();
        let err = trace
            .step(
                L::Signed,
                EventKind::SignatureCreated,
                serde_json::json!({}),
            )
            .unwrap_err();
        assert!(err.contains("lifecycle violation"), "{err}");
        let events = audit.read_all().unwrap();
        assert!(matches!(
            events.last().unwrap().kind,
            EventKind::IllegalTransitionAttempted
        ));
    }
}
