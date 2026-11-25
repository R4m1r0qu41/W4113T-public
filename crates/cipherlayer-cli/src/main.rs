//! CipherLayer Wallet CLI — presentation layer over the trust spine.
//!
//! PROTOTYPE. Test keys on local development chains only. The confirmation
//! prompt is an ordinary terminal prompt (MOCKED trusted surface, T-12).

use cipherlayer_audit::AuditLog;
use cipherlayer_chain::ChainRegistry;
use cipherlayer_cli::pipeline::{ensure_cli_permission, Pipeline, ReviewMode};
use cipherlayer_policy::Policy;
use cipherlayer_provider::{EnvelopePayload, TransactionRequestEnvelope};
use cipherlayer_types::{AccessClass, CallerIdentity, CallerKind, ChainId, U256};
use cipherlayer_vault::{TestSigner, Vault, ANVIL_DEV_KEYS};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cipherlayer",
    version,
    about = "CipherLayer Wallet — prototype trust-spine CLI (test keys, local chains only)"
)]
struct Cli {
    /// RPC endpoint (default: $CIPHERLAYER_RPC_URL or http://127.0.0.1:8545)
    #[arg(long, global = true)]
    rpc_url: Option<String>,
    /// Audit log path (default: $CIPHERLAYER_AUDIT_LOG or ./data/audit-log.jsonl)
    #[arg(long, global = true)]
    audit_log: Option<PathBuf>,
    /// Policy JSON file (default: $CIPHERLAYER_POLICY_FILE or built-in default-dev policy)
    #[arg(long, global = true)]
    policy_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show vault, chain, and audit status
    Status,
    /// List known accounts (test signer only in this prototype)
    Accounts,
    /// List chain registry entries
    Chains,
    /// List RPC profiles
    Rpc,
    /// Decode calldata into a transaction intent (no chain access)
    Decode {
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value = "0x")]
        data: String,
        #[arg(long, default_value = "0")]
        value: String,
    },
    /// Policy inspection and offline testing
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Transaction pipeline commands
    Tx {
        #[command(subcommand)]
        cmd: TxCmd,
    },
    /// Audit log inspection and chain verification
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Vault lock state
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    /// Permission inspection and revocation (persisted to data/permissions.json)
    Permissions {
        #[command(subcommand)]
        cmd: PermissionsCmd,
    },
    /// Browser-connect transport (protocol v0.3)
    Connect {
        #[command(subcommand)]
        cmd: ConnectCmd,
    },
    /// Launch the interactive W411T operator console
    Console,
    /// Run the full vertical-slice demonstration on Anvil
    Demo,
}

#[derive(Subcommand)]
enum ConnectCmd {
    /// Serve the browser-connect contract on a local Unix socket
    /// (same-user peer auth via 0700 socket directory)
    Serve {
        /// Socket path (default: $CIPHERLAYER_CONNECT_SOCKET or ./data/browser-connect.sock)
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Auto-approve USER_REVIEW (explicit, logged — harness/tests only)
        #[arg(long)]
        yes: bool,
        /// Delegate USER_REVIEW to the Vault-side confirmation surface
        /// (requires CIPHERLAYER_VAULT_SOCKET + cipherlayer-vaultd)
        #[arg(long, conflicts_with = "yes")]
        vault_confirm: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Show the active policy
    List,
    /// Evaluate a hypothetical transaction offline (no simulation, no signing)
    Test {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "0x")]
        data: String,
        #[arg(long, default_value = "0")]
        value: String,
        #[arg(long, default_value = "31337")]
        chain_id: u64,
    },
}

#[derive(Subcommand)]
enum TxCmd {
    /// Decode + simulate a transaction (no signing)
    Simulate {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "0x")]
        data: String,
        #[arg(long, default_value = "0")]
        value: String,
    },
    /// Full evaluation: decode + simulate + risk + policy (no signing)
    Evaluate {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "0x")]
        data: String,
        #[arg(long, default_value = "0")]
        value: String,
    },
    /// Run the FULL pipeline including signing and broadcast (dev chain only).
    /// Requires explicit confirmation: pass --yes or answer the prompt.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "0x")]
        data: String,
        #[arg(long, default_value = "0")]
        value: String,
        /// Explicit up-front confirmation (logged as the user decision)
        #[arg(long)]
        yes: bool,
        /// Delegate USER_REVIEW to the Vault-side confirmation surface
        /// (requires CIPHERLAYER_VAULT_SOCKET + cipherlayer-vaultd)
        #[arg(long, conflicts_with = "yes")]
        vault_confirm: bool,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Print audit events (optionally for one request)
    Inspect {
        #[arg(long)]
        request: Option<uuid::Uuid>,
    },
    /// Recompute and verify the audit hash chain
    Verify,
}

#[derive(Subcommand)]
enum PermissionsCmd {
    /// List all grants with their status
    List,
    /// Revoke a grant by permission id (audited)
    Revoke {
        #[arg(long)]
        id: uuid::Uuid,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Engage the emergency lock (persisted)
    Lock,
    /// Release the lock
    Unlock,
    /// Show lock state
    Status,
}

fn env_or(cli_val: Option<String>, env: &str, default: &str) -> String {
    cli_val
        .or_else(|| std::env::var(env).ok())
        .unwrap_or_else(|| default.to_string())
}

fn load_policy(path: Option<PathBuf>) -> Result<Policy, String> {
    let path = path.or_else(|| {
        std::env::var("CIPHERLAYER_POLICY_FILE")
            .ok()
            .map(PathBuf::from)
    });
    match path {
        Some(p) => {
            let raw = std::fs::read_to_string(&p)
                .map_err(|e| format!("cannot read policy file {}: {e}", p.display()))?;
            Policy::from_json(&raw).map_err(|e| e.to_string())
        }
        None => Ok(Policy::default_dev()),
    }
}

fn permissions_path() -> PathBuf {
    PathBuf::from(
        std::env::var("CIPHERLAYER_PERMISSIONS_FILE")
            .unwrap_or_else(|_| "./data/permissions.json".into()),
    )
}

fn vault_state_path() -> PathBuf {
    PathBuf::from(
        std::env::var("CIPHERLAYER_VAULT_STATE")
            .unwrap_or_else(|_| "./data/vault-state.json".into()),
    )
}

fn read_locked() -> bool {
    std::fs::read_to_string(vault_state_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["locked"].as_bool())
        .unwrap_or(false)
}

fn write_locked(locked: bool) -> Result<(), String> {
    let p = vault_state_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&p, serde_json::json!({ "locked": locked }).to_string())
        .map_err(|e| e.to_string())
}

fn build_vault() -> Result<Vault, String> {
    // MOCKED custody: only well-known Anvil dev keys are accepted (ADR-005).
    let key = std::env::var("CIPHERLAYER_TEST_SIGNER_KEY")
        .unwrap_or_else(|_| ANVIL_DEV_KEYS[0].to_string());
    let signer = TestSigner::from_dev_key(&key).map_err(|e| e.to_string())?;
    let mut vault = Vault::new(signer);
    if read_locked() {
        vault.lock();
    }
    Ok(vault)
}

/// ADR-004 process split: with CIPHERLAYER_VAULT_SOCKET set, signing happens
/// in the separate `cipherlayer-vaultd` process and this process never
/// constructs a signer. Default remains in-process.
async fn build_vault_backend() -> Result<cipherlayer_vault::VaultBackend, String> {
    match std::env::var("CIPHERLAYER_VAULT_SOCKET") {
        Ok(socket) => {
            let backend = cipherlayer_vault::VaultBackend::remote(&socket)
                .await
                .map_err(|e| e.to_string())?;
            eprintln!("vault: remote via cipherlayer-vaultd at {socket} (process-isolated)");
            Ok(backend)
        }
        Err(_) => Ok(cipherlayer_vault::VaultBackend::InProcess(build_vault()?)),
    }
}

fn cli_caller() -> CallerIdentity {
    CallerIdentity {
        kind: CallerKind::Cli,
        origin: None,
        app_id: Some("cli:local-user".into()),
        capsule_id: None,
    }
}

fn make_envelope(to: &str, data: &str, value: &str) -> TransactionRequestEnvelope {
    // The signer address is the `from`; resolved when the vault is built.
    let from = build_vault()
        .map(|v| format!("{}", v.address()))
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".into());
    TransactionRequestEnvelope::new(
        cli_caller(),
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from,
            to: Some(to.to_string()),
            value_wei: Some(value.to_string()),
            data: Some(data.to_string()),
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        },
    )
}

fn print_outcome_summary(out: &cipherlayer_cli::pipeline::PipelineOutcome) {
    println!("request:      {}", out.request_id);
    if let Some(i) = &out.intent {
        println!(
            "decoded:      {:?} (confidence {:?}), unresolved: {:?}",
            i.decoded_action.kind, i.confidence, i.unresolved_fields
        );
        if let Some(a) = &i.allowance {
            println!("allowance:    {:?} amount={:?}", a.kind, a.amount);
        }
    }
    if let Some(s) = &out.simulation {
        println!(
            "simulation:   {:?} — limitations: {}",
            s.outcome,
            s.limitations.join("; ")
        );
    }
    if let Some(r) = &out.risk {
        println!(
            "risk:         {:?} — {}",
            r.overall_level, r.overall_rationale
        );
    }
    if let Some(d) = &out.decision {
        println!("policy:       {:?}", d.verdict);
        for reason in &d.reasons {
            println!("  [{}] {}", reason.code, reason.detail);
        }
    }
    println!("final state:  {:?}", out.final_state);
    if let Some(h) = &out.tx_hash {
        println!("tx hash:      {h}");
    }
    for n in &out.notes {
        println!("note:         {n}");
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let rpc_url = env_or(
        cli.rpc_url.clone(),
        "CIPHERLAYER_RPC_URL",
        "http://127.0.0.1:8545",
    );
    let audit_path = cli
        .audit_log
        .clone()
        .or_else(|| {
            std::env::var("CIPHERLAYER_AUDIT_LOG")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("./data/audit-log.jsonl"));

    let result = run(cli, rpc_url, audit_path).await;
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli, rpc_url: String, audit_path: PathBuf) -> Result<(), String> {
    match cli.command {
        Command::Status => {
            let vault = build_vault()?;
            println!("CipherLayer Wallet — PROTOTYPE (test keys, local chains only)");
            println!(
                "signer:    {} [MOCKED custody: Anvil dev key]",
                vault.address()
            );
            println!(
                "vault:     {}",
                if vault.is_locked() {
                    "LOCKED"
                } else {
                    "unlocked"
                }
            );
            println!("rpc:       {rpc_url}");
            let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
            let report = audit.verify().map_err(|e| e.to_string())?;
            println!(
                "audit:     {} events at {} (chain {})",
                report.total_events,
                audit_path.display(),
                if report.valid { "valid" } else { "INVALID" }
            );
            Ok(())
        }
        Command::Accounts => {
            let vault = build_vault()?;
            println!("accounts (prototype: single test signer):");
            println!(
                "  {}  kind=test  custody=self_custody(dev-key)  label=[MOCKED custody — Anvil dev key, worthless by design]",
                vault.address()
            );
            Ok(())
        }
        Command::Chains => {
            for e in ChainRegistry::builtin().entries() {
                println!(
                    "{:>10}  {:<28} class={:<12} signing={}",
                    e.chain_id.0,
                    e.name,
                    format!("{:?}", e.network_class).to_lowercase(),
                    if e.network_class == cipherlayer_types::NetworkClass::Development {
                        "allowed"
                    } else {
                        "refused (prototype gate)"
                    }
                );
                if let Some(n) = &e.notes {
                    println!("            {n}");
                }
            }
            Ok(())
        }
        Command::Rpc => {
            for e in ChainRegistry::builtin().entries() {
                for p in &e.rpc_profiles {
                    println!(
                        "{:<16} chain={:<10} class={:<11} {}",
                        p.profile_id,
                        e.chain_id.0,
                        format!("{:?}", p.endpoint_class).to_lowercase(),
                        p.url
                    );
                    if let Some(note) = &p.privacy_note {
                        println!("                 privacy: {note}");
                    }
                }
            }
            Ok(())
        }
        Command::Decode { to, data, value } => {
            let to_addr = match &to {
                Some(t) => Some(cipherlayer_evm::parse_address(t).map_err(|e| e.to_string())?),
                None => None,
            };
            let bytes = hex::decode(data.trim_start_matches("0x")).map_err(|e| e.to_string())?;
            let value = U256::from_str_radix(&value, 10).map_err(|e| e.to_string())?;
            let decoded = cipherlayer_evm::decode_calldata(to_addr, value, &bytes);
            println!(
                "{}",
                serde_json::to_string_pretty(&decoded).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        Command::Policy { cmd } => match cmd {
            PolicyCmd::List => {
                let policy = load_policy(cli.policy_file)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&policy).map_err(|e| e.to_string())?
                );
                Ok(())
            }
            PolicyCmd::Test {
                to,
                data,
                value,
                chain_id,
            } => {
                let policy = load_policy(cli.policy_file)?;
                let to_addr = cipherlayer_evm::parse_address(&to).map_err(|e| e.to_string())?;
                let bytes =
                    hex::decode(data.trim_start_matches("0x")).map_err(|e| e.to_string())?;
                let v = U256::from_str_radix(&value, 10).map_err(|e| e.to_string())?;
                let decoded = cipherlayer_evm::decode_calldata(Some(to_addr), v, &bytes);
                let intent = cipherlayer_intent::TransactionIntent::from_decoded(
                    cipherlayer_types::new_id(),
                    ChainId(chain_id),
                    serde_json::json!({"to": to, "value_wei": value}),
                    build_vault()?.address(),
                    v,
                    decoded,
                );
                let decision = cipherlayer_policy::evaluate(
                    &policy,
                    &intent,
                    cipherlayer_policy::EvaluationEvidence {
                        simulation: cipherlayer_policy::SimulationStatus::Unavailable,
                        risk: None,
                    },
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&decision).map_err(|e| e.to_string())?
                );
                println!("note: offline test — simulation/risk unavailable, which itself takes the restrictive path");
                Ok(())
            }
        },
        Command::Connect { cmd } => match cmd {
            ConnectCmd::Serve {
                socket,
                yes,
                vault_confirm,
            } => {
                let socket = socket
                    .or_else(|| {
                        std::env::var("CIPHERLAYER_CONNECT_SOCKET")
                            .ok()
                            .map(PathBuf::from)
                    })
                    .unwrap_or_else(|| PathBuf::from("./data/browser-connect.sock"));
                let policy = load_policy(cli.policy_file)?;
                let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
                let backend = build_vault_backend().await?;
                let mut pipeline = Pipeline::with_backend(policy, audit, backend, &rpc_url);
                pipeline.permissions =
                    cipherlayer_provider::PermissionStore::load_from(&permissions_path())
                        .map_err(|e| e.to_string())?;
                let review = if vault_confirm {
                    ReviewMode::VaultSurface
                } else if yes {
                    println!(
                        "WARNING: --yes auto-approves USER_REVIEW (harness/tests only; logged)"
                    );
                    ReviewMode::AssumeYes
                } else {
                    ReviewMode::Interactive
                };
                let host_token = cipherlayer_cli::serve::resolve_host_token(&socket)
                    .map_err(|e| e.to_string())?;
                let server = cipherlayer_cli::serve::ConnectServer::new(
                    pipeline,
                    review,
                    permissions_path(),
                    host_token,
                );
                server.run(&socket).await.map_err(|e| e.to_string())
            }
        },
        Command::Tx { cmd } => {
            let policy = load_policy(cli.policy_file)?;
            let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
            let backend = build_vault_backend().await?;
            let mut pipeline = Pipeline::with_backend(policy, audit, backend, &rpc_url);
            pipeline.permissions =
                cipherlayer_provider::PermissionStore::load_from(&permissions_path())
                    .map_err(|e| e.to_string())?;
            let account = pipeline.vault.address();
            ensure_cli_permission(&mut pipeline, &cli_caller(), ChainId(31337), account)
                .map_err(|e| e.to_string())?;
            pipeline
                .permissions
                .save_to(&permissions_path())
                .map_err(|e| e.to_string())?;
            match cmd {
                TxCmd::Simulate { to, data, value } | TxCmd::Evaluate { to, data, value } => {
                    // Evaluate runs the pipeline but always stops at review.
                    let env = make_envelope(&to, &data, &value);
                    let out = pipeline
                        .process(env, ReviewMode::Reject)
                        .await
                        .map_err(|e| e.to_string())?;
                    print_outcome_summary(&out);
                    println!("(no signing was attempted: review answered 'reject' by design)");
                    Ok(())
                }
                TxCmd::Send {
                    to,
                    data,
                    value,
                    yes,
                    vault_confirm,
                } => {
                    let env = make_envelope(&to, &data, &value);
                    let mode = if vault_confirm {
                        ReviewMode::VaultSurface
                    } else if yes {
                        ReviewMode::AssumeYes
                    } else {
                        ReviewMode::Interactive
                    };
                    let out = pipeline
                        .process(env, mode)
                        .await
                        .map_err(|e| e.to_string())?;
                    print_outcome_summary(&out);
                    Ok(())
                }
            }
        }
        Command::Audit { cmd } => {
            let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
            match cmd {
                AuditCmd::Inspect { request } => {
                    let events = match request {
                        Some(r) => audit.events_for_request(r).map_err(|e| e.to_string())?,
                        None => audit.read_all().map_err(|e| e.to_string())?,
                    };
                    for e in events {
                        println!(
                            "#{:<4} {:<28} req={} at {}",
                            e.sequence,
                            format!("{:?}", e.kind),
                            e.request_id
                                .map(|r| r.to_string())
                                .unwrap_or_else(|| "-".into()),
                            e.occurred_at.to_rfc3339()
                        );
                    }
                    Ok(())
                }
                AuditCmd::Verify => {
                    let report = audit.verify().map_err(|e| e.to_string())?;
                    println!("{}", report.message);
                    if !report.valid {
                        return Err(format!(
                            "audit chain INVALID at sequence {:?}",
                            report.first_invalid_sequence
                        ));
                    }
                    Ok(())
                }
            }
        }
        Command::Vault { cmd } => match cmd {
            VaultCmd::Lock => {
                write_locked(true)?;
                let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
                audit
                    .append(
                        cipherlayer_audit::EventKind::VaultLocked,
                        None,
                        serde_json::json!({}),
                    )
                    .map_err(|e| e.to_string())?;
                println!("vault LOCKED (emergency lock persisted)");
                Ok(())
            }
            VaultCmd::Unlock => {
                write_locked(false)?;
                let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
                audit
                    .append(
                        cipherlayer_audit::EventKind::VaultUnlocked,
                        None,
                        serde_json::json!({}),
                    )
                    .map_err(|e| e.to_string())?;
                println!("vault unlocked");
                Ok(())
            }
            VaultCmd::Status => {
                println!(
                    "vault: {}",
                    if read_locked() { "LOCKED" } else { "unlocked" }
                );
                Ok(())
            }
        },
        Command::Permissions { cmd } => {
            let path = permissions_path();
            let mut store = cipherlayer_provider::PermissionStore::load_from(&path)
                .map_err(|e| e.to_string())?;
            match cmd {
                PermissionsCmd::List => {
                    if store.list().is_empty() {
                        println!("no grants recorded ({}).", path.display());
                        return Ok(());
                    }
                    let now = cipherlayer_types::now();
                    for p in store.list() {
                        println!(
                            "{}  caller={:<24} chain={:<7} access={:<9} status={:<8} expires={}",
                            p.permission_id,
                            p.caller_key,
                            p.chain_id.0,
                            format!("{:?}", p.access).to_lowercase(),
                            format!("{:?}", p.status(now)).to_lowercase(),
                            p.expires_at.to_rfc3339()
                        );
                        for a in &p.accounts {
                            println!("    account {a}");
                        }
                    }
                    Ok(())
                }
                PermissionsCmd::Revoke { id } => {
                    if !store.revoke(id) {
                        return Err(format!("no active grant with id {id}"));
                    }
                    store.save_to(&path).map_err(|e| e.to_string())?;
                    let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
                    audit
                        .append(
                            cipherlayer_audit::EventKind::PermissionRevoked,
                            None,
                            serde_json::json!({ "permission_id": id }),
                        )
                        .map_err(|e| e.to_string())?;
                    println!("revoked {id} (persisted, audited)");
                    Ok(())
                }
            }
        }
        Command::Console => {
            let policy = load_policy(cli.policy_file)?;
            let mut console = cipherlayer_cli::console::Console::new(
                rpc_url,
                audit_path,
                policy,
                permissions_path(),
            );
            console.run().await.map_err(|e| e.to_string())
        }
        Command::Demo => {
            let policy = load_policy(cli.policy_file)?;
            let audit = AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
            let backend = build_vault_backend().await?;
            let mut pipeline = Pipeline::with_backend(policy, audit, backend, &rpc_url);
            println!("CipherLayer vertical-slice demo (local Anvil, test keys, MOCKED boundaries labeled)\n");
            let report = cipherlayer_cli::demo::run(&mut pipeline)
                .await
                .map_err(|e| e.to_string())?;
            println!("\n── demo summary ──");
            println!("token:               {}", report.token);
            println!("spender:             {}", report.spender);
            println!(
                "blocked request:     {} (unlimited approval → POLICY_DENIED)",
                report.blocked_request
            );
            println!(
                "confirmed request:   {} (exact approval → CONFIRMED)",
                report.confirmed_request
            );
            println!("confirmed tx:        {}", report.confirmed_tx_hash);
            println!(
                "audit events:        {} (chain valid: {})",
                report.audit_events, report.audit_valid
            );
            println!("\ninspect the lifecycle:");
            println!(
                "  cargo run -p cipherlayer-cli -- audit inspect --request {}",
                report.confirmed_request
            );
            println!("  cargo run -p cipherlayer-cli -- audit verify");
            Ok(())
        }
    }
}
