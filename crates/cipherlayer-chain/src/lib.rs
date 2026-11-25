//! Chain registry and RPC profiles (schemas: chain-registry-entry.v1, rpc-profile.v1).
//!
//! The registry's `network_class` drives the milestone-1 signing gate:
//! only `Development` chains may sign (ADR-006). Mainnet/testnet entries
//! exist as metadata so chain identity is validated against something real.

pub mod adapter;

use cipherlayer_types::{ChainId, NetworkClass};
use serde::{Deserialize, Serialize};

/// Well-known cluster genesis hashes (ADR-016 §3 / ADR-021). These constants
/// are the single source of the pins: the registry entries and the
/// cipherlayer-sol adapter tests reference them rather than re-typing the
/// strings. The vaultd signer's constructors (ADR-021 step 4, not yet built)
/// must do the same — re-typed literals there would be drift-prone and are a
/// review-rejection criterion.
pub const SOLANA_MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
pub const SOLANA_DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/// Internal registry ids for the fixed-genesis Solana clusters (reserved
/// non-EVM band 900000–999999 — never on any wire).
pub const SOLANA_DEVNET_CHAIN_ID: u64 = 900003;
pub const SOLANA_MAINNET_CHAIN_ID: u64 = 900004;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointClass {
    Local,
    SelfHosted,
    Public,
    Premium,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcProfile {
    pub profile_id: String,
    pub name: String,
    pub url: String,
    pub endpoint_class: EndpointClass,
    /// Mandatory for public/premium endpoints: what using this endpoint reveals (T-21).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_note: Option<String>,
    /// Env var holding credentials; the credential itself never appears in config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_env_var: Option<String>,
}

/// Which protocol family a chain belongs to. Drives wire-surface filtering:
/// only EVM-family entries may appear in EIP-1193-facing contracts (the
/// 900000-band internal ids are registry lookup keys, never wire values —
/// ADR-016, ADR-021).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainFamily {
    #[default]
    Evm,
    Solana,
    Bitcoin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    pub chain_id: ChainId,
    pub name: String,
    pub network_class: NetworkClass,
    /// Additive in schema v1.1; absent means EVM (every pre-v1.1 entry was).
    #[serde(default)]
    pub chain_family: ChainFamily,
    pub native_symbol: String,
    pub native_decimals: u8,
    pub rpc_profiles: Vec<RpcProfile>,
    /// Additive in schema v1.1 (ADR-016 §3: "the entry records the expected
    /// genesis hash where known"). Set for fixed-genesis non-EVM networks
    /// (Solana devnet/mainnet-beta); `None` where identity is a numeric chain
    /// id or the genesis is unstable (local validators reset theirs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_genesis_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("unknown chain id {0}")]
    UnknownChain(ChainId),
    #[error("signing is not allowed on {name} (chain {chain_id}, class {class:?}) in this prototype — development chains only (ADR-006)")]
    SigningNotAllowed {
        chain_id: ChainId,
        name: String,
        class: NetworkClass,
    },
}

#[derive(Debug, Clone)]
pub struct ChainRegistry {
    entries: Vec<ChainEntry>,
}

impl ChainRegistry {
    /// Built-in registry: local Anvil (signing-capable), Ethereum mainnet and
    /// Sepolia as identity metadata only.
    pub fn builtin() -> Self {
        Self {
            entries: vec![
                ChainEntry {
                    chain_id: ChainId(31337),
                    name: "Anvil (local development)".into(),
                    network_class: NetworkClass::Development,
                    chain_family: ChainFamily::Evm,
                    expected_genesis_hash: None,
                    native_symbol: "ETH".into(),
                    native_decimals: 18,
                    rpc_profiles: vec![RpcProfile {
                        profile_id: "anvil-local".into(),
                        name: "Local Anvil node".into(),
                        url: "http://127.0.0.1:8545".into(),
                        endpoint_class: EndpointClass::Local,
                        privacy_note: None,
                        auth_env_var: None,
                    }],
                    notes: Some(
                        "Default development chain. Value here is worthless by design.".into(),
                    ),
                },
                ChainEntry {
                    chain_id: ChainId(11155111),
                    name: "Sepolia".into(),
                    network_class: NetworkClass::Testnet,
                    chain_family: ChainFamily::Evm,
                    expected_genesis_hash: None,
                    native_symbol: "ETH".into(),
                    native_decimals: 18,
                    rpc_profiles: vec![
                        RpcProfile {
                            profile_id: "sepolia-public".into(),
                            name: "Public Sepolia RPC".into(),
                            // rpc.sepolia.org was decommissioned (bare 404) as
                            // of the first live lifecycle run; publicnode is the
                            // working default.
                            url: "https://ethereum-sepolia-rpc.publicnode.com".into(),
                            endpoint_class: EndpointClass::Public,
                            privacy_note: Some(
                                "Public endpoint operators can correlate your addresses with your IP."
                                    .into(),
                            ),
                            auth_env_var: None,
                        },
                        RpcProfile {
                            profile_id: "sepolia-quicknode".into(),
                            name: "QuickNode Sepolia (premium; URL from env)".into(),
                            // The full authenticated URL (which embeds the token)
                            // is never committed — it is read from the env var at
                            // use time. Empty here means "not configured".
                            url: String::new(),
                            endpoint_class: EndpointClass::Premium,
                            privacy_note: Some(
                                "Dedicated endpoint: the provider sees your queries; no shared-pool correlation.".into(),
                            ),
                            auth_env_var: Some("CIPHERLAYER_QUICKNODE_SEPOLIA_URL".into()),
                        },
                    ],
                    notes: Some(
                        "Registry metadata only; signing gated off in this prototype. QuickNode URL supplied via CIPHERLAYER_QUICKNODE_SEPOLIA_URL when configured.".into(),
                    ),
                },
                ChainEntry {
                    chain_id: ChainId(1),
                    name: "Ethereum".into(),
                    network_class: NetworkClass::Mainnet,
                    chain_family: ChainFamily::Evm,
                    expected_genesis_hash: None,
                    native_symbol: "ETH".into(),
                    native_decimals: 18,
                    rpc_profiles: vec![
                        RpcProfile {
                            profile_id: "mainnet-public".into(),
                            name: "Public Ethereum mainnet RPC".into(),
                            url: "https://ethereum-rpc.publicnode.com".into(),
                            endpoint_class: EndpointClass::Public,
                            privacy_note: Some(
                                "Public endpoint operators can correlate your addresses with your IP."
                                    .into(),
                            ),
                            auth_env_var: None,
                        },
                        RpcProfile {
                            profile_id: "mainnet-operator".into(),
                            name: "Operator-supplied mainnet RPC (premium; URL from env)".into(),
                            url: String::new(),
                            endpoint_class: EndpointClass::Premium,
                            privacy_note: Some(
                                "Dedicated endpoint: the provider sees your queries; no shared-pool correlation.".into(),
                            ),
                            auth_env_var: Some("CIPHERLAYER_MAINNET_RPC".into()),
                        },
                    ],
                    notes: Some(
                        "Value on this chain is real. Vault-held signing is refused by the \
                         development-only gate (ensure_signing_allowed, ADR-006), unconditionally. \
                         The separate external-signer authority (ADR-011/ADR-020) may sign here \
                         only via ExternalSignerConfig::mainnet, human-gated, key never persisted."
                            .into(),
                    ),
                },
                // EVM L2s (ADR-015 phase b): each L2 appears twice — the real
                // chain as Mainnet-class identity metadata (signing refused),
                // and a Development-class Anvil-fork entry with a REMAPPED
                // local chain id. The remap is deliberate: the real L2 chain
                // id can never satisfy the development signing gate, and the
                // pipeline's chain-identity check refuses a fork entry whose
                // node still reports the upstream id.
                Self::l2_mainnet(42161, "Arbitrum One"),
                Self::l2_mainnet(8453, "Base"),
                Self::l2_mainnet(10, "OP Mainnet"),
                Self::l2_fork(31338, "Arbitrum One", 42161, 8546),
                Self::l2_fork(31339, "Base", 8453, 8547),
                Self::l2_fork(31340, "OP Mainnet", 10, 8548),
                // Solana (ADR-016, ADR-015 phase c). Solana has no numeric
                // chain id: network identity is the genesis hash, verified by
                // the adapter. The id band 900000-999999 is reserved for
                // internal non-EVM ids — registry lookup keys only, never on
                // any wire.
                ChainEntry {
                    chain_id: ChainId(900001),
                    name: "Solana local test validator (local development)".into(),
                    network_class: NetworkClass::Development,
                    chain_family: ChainFamily::Solana,
                    // The local validator's genesis hash changes on ledger
                    // reset — no stable pin exists (the adapter checks cluster
                    // sanity instead).
                    expected_genesis_hash: None,
                    native_symbol: "SOL".into(),
                    native_decimals: 9,
                    rpc_profiles: vec![RpcProfile {
                        profile_id: "solana-local".into(),
                        name: "Local solana-test-validator".into(),
                        url: "http://127.0.0.1:8899".into(),
                        endpoint_class: EndpointClass::Local,
                        privacy_note: None,
                        auth_env_var: None,
                    }],
                    notes: Some(
                        "The id band 900000-999999 is reserved for internal non-EVM ids; they \
                         never appear on any wire. Chain identity here is the node's genesis hash \
                         (getGenesisHash), not a numeric chain id; the local validator's genesis \
                         hash changes on ledger reset, so the adapter checks cluster sanity \
                         instead of a pinned hash. Value here is worthless by design."
                            .into(),
                    ),
                },
                // Solana devnet + mainnet-beta (ADR-021). Fixed-genesis
                // clusters: identity is the pinned genesis hash, re-verified
                // live by the adapter (fail closed). Vault-held signing is
                // refused by ensure_signing_allowed unconditionally; only the
                // vaultd-hosted external-signer ceremony (ADR-021) may sign,
                // human-gated, key never in the CLI process.
                ChainEntry {
                    chain_id: ChainId(900003),
                    name: "Solana devnet".into(),
                    network_class: NetworkClass::Testnet,
                    chain_family: ChainFamily::Solana,
                    expected_genesis_hash: Some(SOLANA_DEVNET_GENESIS.into()),
                    native_symbol: "SOL".into(),
                    native_decimals: 9,
                    rpc_profiles: vec![
                        RpcProfile {
                            profile_id: "solana-devnet-public".into(),
                            name: "Public Solana devnet RPC".into(),
                            url: "https://api.devnet.solana.com".into(),
                            endpoint_class: EndpointClass::Public,
                            privacy_note: Some(
                                "Public endpoint operators can correlate your addresses with your IP."
                                    .into(),
                            ),
                            auth_env_var: None,
                        },
                        RpcProfile {
                            profile_id: "solana-devnet-operator".into(),
                            name: "Operator-supplied devnet RPC (URL from env)".into(),
                            url: String::new(),
                            endpoint_class: EndpointClass::Premium,
                            privacy_note: Some(
                                "Dedicated endpoint: the provider sees your queries; no shared-pool correlation.".into(),
                            ),
                            auth_env_var: Some("CIPHERLAYER_SOLANA_DEVNET_RPC".into()),
                        },
                    ],
                    notes: Some(
                        "Internal id 900003 (reserved non-EVM band; never on any wire). Identity \
                         is the pinned devnet genesis hash, re-verified live before any ceremony \
                         step. Devnet SOL is worthless by design (faucet-funded)."
                            .into(),
                    ),
                },
                ChainEntry {
                    chain_id: ChainId(900004),
                    name: "Solana mainnet-beta".into(),
                    network_class: NetworkClass::Mainnet,
                    chain_family: ChainFamily::Solana,
                    expected_genesis_hash: Some(SOLANA_MAINNET_GENESIS.into()),
                    native_symbol: "SOL".into(),
                    native_decimals: 9,
                    // Deliberately no public profile: the mainnet ceremony is
                    // explicit-RPC-only (ADR-021 §3) — no default endpoint may
                    // exist for it to fall back to.
                    rpc_profiles: vec![RpcProfile {
                        profile_id: "solana-mainnet-operator".into(),
                        name: "Operator-supplied mainnet-beta RPC (required; URL from env)".into(),
                        url: String::new(),
                        endpoint_class: EndpointClass::Premium,
                        privacy_note: Some(
                            "Dedicated endpoint: the provider sees your queries; no shared-pool correlation.".into(),
                        ),
                        auth_env_var: Some("CIPHERLAYER_SOLANA_MAINNET_RPC".into()),
                    }],
                    notes: Some(
                        "Value on this chain is real. Internal id 900004 (reserved non-EVM band; \
                         never on any wire). Identity is the pinned mainnet-beta genesis hash, \
                         re-verified live before any ceremony step. Vault-held signing refused \
                         unconditionally; only the vaultd external-signer ceremony (ADR-021) may \
                         sign — human-gated, explicit RPC via CIPHERLAYER_SOLANA_MAINNET_RPC \
                         only, key never in the CLI process."
                            .into(),
                    ),
                },
                // Bitcoin (ADR-017, ADR-015 phase d). Bitcoin has no numeric
                // chain id: network identity is the genesis block hash
                // (getblockhash 0), verified by the adapter against a pinned
                // constant. Internal id 900002 sits in the reserved
                // 900000-999999 non-EVM band — a registry lookup key only,
                // never on any wire.
                ChainEntry {
                    chain_id: ChainId(900002),
                    name: "Bitcoin regtest (local development)".into(),
                    network_class: NetworkClass::Development,
                    chain_family: ChainFamily::Bitcoin,
                    // Regtest's genesis constant is pinned by the adapter
                    // itself; the registry adds nothing there.
                    expected_genesis_hash: None,
                    native_symbol: "BTC".into(),
                    native_decimals: 8,
                    rpc_profiles: vec![RpcProfile {
                        profile_id: "bitcoin-regtest".into(),
                        name: "Local Bitcoin Core regtest node".into(),
                        url: "http://127.0.0.1:18443".into(),
                        endpoint_class: EndpointClass::Local,
                        privacy_note: None,
                        auth_env_var: None,
                    }],
                    notes: Some(
                        "The id band 900000-999999 is reserved for internal non-EVM ids; they \
                         never appear on any wire. Chain identity here is the genesis block hash \
                         (getblockhash 0), pinned to the well-known regtest constant by the \
                         adapter; mainnet/signet/testnet genesis hashes fail closed. Value here \
                         is worthless by design."
                            .into(),
                    ),
                },
            ],
        }
    }

    /// Real L2 chain: identity metadata only, signing refused (like Ethereum).
    fn l2_mainnet(chain_id: u64, name: &str) -> ChainEntry {
        ChainEntry {
            chain_id: ChainId(chain_id),
            name: name.into(),
            network_class: NetworkClass::Mainnet,
            chain_family: ChainFamily::Evm,
            expected_genesis_hash: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            rpc_profiles: vec![],
            notes: Some(
                "Value on this chain is real. Signing is refused in this prototype; develop against the local Anvil-fork entry instead.".into(),
            ),
        }
    }

    /// Local Anvil fork of an L2 (ADR-015 phase b): a development chain whose
    /// state is forked from the upstream L2 but whose chain id is remapped so
    /// it can never be confused with the real chain.
    fn l2_fork(dev_chain_id: u64, upstream_name: &str, upstream_id: u64, port: u16) -> ChainEntry {
        ChainEntry {
            chain_id: ChainId(dev_chain_id),
            name: format!("Anvil fork of {upstream_name} (local development)"),
            network_class: NetworkClass::Development,
            chain_family: ChainFamily::Evm,
            expected_genesis_hash: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            rpc_profiles: vec![RpcProfile {
                profile_id: format!("anvil-fork-{dev_chain_id}"),
                name: format!("Local Anvil fork of {upstream_name}"),
                url: format!("http://127.0.0.1:{port}"),
                endpoint_class: EndpointClass::Local,
                privacy_note: None,
                auth_env_var: None,
            }],
            notes: Some(format!(
                "Start with: anvil --fork-url <{upstream_name} rpc> --chain-id {dev_chain_id} --port {port}. \
                 Chain id is remapped from {upstream_id} on purpose: the fork must never report the real L2's id."
            )),
        }
    }

    pub fn entries(&self) -> &[ChainEntry] {
        &self.entries
    }

    pub fn get(&self, chain_id: ChainId) -> Result<&ChainEntry, ChainError> {
        self.entries
            .iter()
            .find(|e| e.chain_id == chain_id)
            .ok_or(ChainError::UnknownChain(chain_id))
    }

    /// Milestone-1 signing gate: development chains only.
    pub fn ensure_signing_allowed(&self, chain_id: ChainId) -> Result<&ChainEntry, ChainError> {
        let entry = self.get(chain_id)?;
        if entry.network_class == NetworkClass::Development {
            Ok(entry)
        } else {
            Err(ChainError::SigningNotAllowed {
                chain_id,
                name: entry.name.clone(),
                class: entry.network_class,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_has_anvil_dev_chain() {
        let r = ChainRegistry::builtin();
        let anvil = r.get(ChainId(31337)).unwrap();
        assert_eq!(anvil.network_class, NetworkClass::Development);
        assert_eq!(anvil.rpc_profiles[0].endpoint_class, EndpointClass::Local);
    }

    #[test]
    fn unknown_chain_is_error() {
        let r = ChainRegistry::builtin();
        assert!(r.get(ChainId(424242)).is_err());
    }

    #[test]
    fn signing_gate_allows_only_development() {
        let r = ChainRegistry::builtin();
        assert!(r.ensure_signing_allowed(ChainId(31337)).is_ok());
        assert!(r.ensure_signing_allowed(ChainId(1)).is_err());
        assert!(r.ensure_signing_allowed(ChainId(11155111)).is_err());
    }

    /// ADR-015 phase (b): L2 mainnets are metadata-only (signing refused);
    /// their Anvil-fork twins are Development-class and signable, and never
    /// share a chain id with the upstream chain.
    #[test]
    fn l2_forks_signable_but_l2_mainnets_refused() {
        let r = ChainRegistry::builtin();
        for mainnet in [42161u64, 8453, 10] {
            assert!(r.ensure_signing_allowed(ChainId(mainnet)).is_err());
        }
        for fork in [31338u64, 31339, 31340] {
            let e = r.ensure_signing_allowed(ChainId(fork)).unwrap();
            assert_eq!(e.network_class, NetworkClass::Development);
            assert_eq!(e.rpc_profiles[0].endpoint_class, EndpointClass::Local);
        }
        // No fork id collides with any real chain id in the registry, and all
        // registry ids are unique.
        let mut ids: Vec<u64> = r.entries().iter().map(|e| e.chain_id.0).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), r.entries().len(), "duplicate chain id");
    }

    /// ADR-016: the Solana local test validator is Development-class and
    /// signable; its reserved internal id (band 900000-999999) collides with
    /// nothing.
    #[test]
    fn solana_local_validator_signable_and_id_reserved() {
        let r = ChainRegistry::builtin();
        let e = r.ensure_signing_allowed(ChainId(900001)).unwrap();
        assert_eq!(e.network_class, NetworkClass::Development);
        assert_eq!(e.native_symbol, "SOL");
        assert_eq!(e.native_decimals, 9);
        assert_eq!(e.rpc_profiles[0].endpoint_class, EndpointClass::Local);
        // Reserved internal band 900000..=999999 (real EVM chain ids also
        // exist above it, e.g. Sepolia): only non-EVM internal ids may sit
        // in the band, and all registry ids stay unique.
        assert!(r
            .entries()
            .iter()
            .all(|e| !(900_000..=999_999).contains(&e.chain_id.0)
                || [
                    ChainId(900001),
                    ChainId(900002),
                    ChainId(SOLANA_DEVNET_CHAIN_ID),
                    ChainId(SOLANA_MAINNET_CHAIN_ID)
                ]
                .contains(&e.chain_id)));
        let mut ids: Vec<u64> = r.entries().iter().map(|e| e.chain_id.0).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), r.entries().len(), "duplicate chain id");
    }

    /// ADR-017: the Bitcoin regtest entry is Development-class and signable;
    /// its reserved internal id (band 900000-999999) collides with nothing.
    #[test]
    fn bitcoin_regtest_signable_and_id_reserved() {
        let r = ChainRegistry::builtin();
        let e = r.ensure_signing_allowed(ChainId(900002)).unwrap();
        assert_eq!(e.network_class, NetworkClass::Development);
        assert_eq!(e.native_symbol, "BTC");
        assert_eq!(e.native_decimals, 8);
        assert_eq!(e.rpc_profiles[0].endpoint_class, EndpointClass::Local);
        assert_eq!(e.rpc_profiles[0].url, "http://127.0.0.1:18443");
        let mut ids: Vec<u64> = r.entries().iter().map(|e| e.chain_id.0).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), r.entries().len(), "duplicate chain id");
    }

    /// ADR-021: the fixed-genesis Solana clusters are metadata + pinned
    /// identity only — vault-held signing refused unconditionally (the
    /// external-signer ceremony is a separate authority that never consults
    /// this gate), pins present and distinct, mainnet has no public fallback
    /// profile (explicit-RPC-only).
    #[test]
    fn solana_clusters_refused_by_vault_gate_and_pinned() {
        let r = ChainRegistry::builtin();
        let devnet = r.get(ChainId(SOLANA_DEVNET_CHAIN_ID)).unwrap();
        let mainnet = r.get(ChainId(SOLANA_MAINNET_CHAIN_ID)).unwrap();
        for e in [devnet, mainnet] {
            assert!(r.ensure_signing_allowed(e.chain_id).is_err());
            assert_eq!(e.chain_family, ChainFamily::Solana);
            assert_eq!(e.native_symbol, "SOL");
            assert_eq!(e.native_decimals, 9);
        }
        assert_eq!(devnet.network_class, NetworkClass::Testnet);
        assert_eq!(mainnet.network_class, NetworkClass::Mainnet);
        assert_eq!(
            devnet.expected_genesis_hash.as_deref(),
            Some(SOLANA_DEVNET_GENESIS)
        );
        assert_eq!(
            mainnet.expected_genesis_hash.as_deref(),
            Some(SOLANA_MAINNET_GENESIS)
        );
        assert_ne!(SOLANA_DEVNET_GENESIS, SOLANA_MAINNET_GENESIS);
        // Explicit-RPC-only mainnet: every profile resolves through an env
        // var; none carries a committed URL.
        assert!(mainnet
            .rpc_profiles
            .iter()
            .all(|p| p.url.is_empty() && p.auth_env_var.is_some()));
    }

    /// Schema v1.1 compatibility: a v1.0-shaped entry (no chain_family, no
    /// expected_genesis_hash) still deserializes, defaulting to the EVM
    /// family — the additive-rev discipline the contract promises.
    #[test]
    fn v1_0_entry_json_still_deserializes() {
        let v1_0 = serde_json::json!({
            "chain_id": 31337,
            "name": "Anvil (local development)",
            "network_class": "development",
            "native_symbol": "ETH",
            "native_decimals": 18,
            "rpc_profiles": []
        });
        let e: ChainEntry = serde_json::from_value(v1_0).unwrap();
        assert_eq!(e.chain_family, ChainFamily::Evm);
        assert!(e.expected_genesis_hash.is_none());
        // And omitted optionals stay omitted on re-serialization (no noisy
        // nulls for old consumers).
        let back = serde_json::to_value(&e).unwrap();
        assert!(back.get("expected_genesis_hash").is_none());
    }

    #[test]
    fn public_profiles_carry_privacy_notes() {
        let r = ChainRegistry::builtin();
        for e in r.entries() {
            for p in &e.rpc_profiles {
                if matches!(
                    p.endpoint_class,
                    EndpointClass::Public | EndpointClass::Premium
                ) {
                    assert!(
                        p.privacy_note.is_some(),
                        "public profile without privacy note"
                    );
                }
            }
        }
    }
}
