//! The vertical-slice demonstration (BP §13): deploys fixture contracts on a
//! local Anvil chain, then drives the full pipeline through a blocked
//! unlimited approval and an authorized exact approval, and finally verifies
//! the audit chain.
//!
//! Contract creation bytecode is loaded from committed Foundry artifacts
//! (fixtures/contracts/artifacts/, built from the Solidity sources next to
//! them — see fixtures/contracts/README.md for the rebuild procedure).

use crate::pipeline::{format_units18, grant_cli_permission, Pipeline, ReviewMode};
use alloy::providers::{Provider, ProviderBuilder};
use cipherlayer_provider::{EnvelopePayload, TransactionRequestEnvelope};
use cipherlayer_types::state::LifecycleState;
use cipherlayer_types::{AccessClass, Address, CallerIdentity, CallerKind, ChainId, U256};
use serde_json::json;

pub const TOKEN_ARTIFACT: &str =
    include_str!("../../../fixtures/contracts/artifacts/TestToken.json");
pub const SPENDER_ARTIFACT: &str =
    include_str!("../../../fixtures/contracts/artifacts/TestSpender.json");

#[derive(Debug, thiserror::Error)]
pub enum DemoError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("deployment failed: {0}")]
    Deploy(String),
    #[error("demo expectation failed: {0}")]
    Expectation(String),
    #[error(transparent)]
    Pipeline(#[from] crate::pipeline::PipelineError),
}

pub struct DemoReport {
    pub token: Address,
    pub spender: Address,
    pub blocked_request: uuid::Uuid,
    pub confirmed_request: uuid::Uuid,
    pub confirmed_tx_hash: String,
    pub onchain_allowance: U256,
    pub audit_events: u64,
    pub audit_valid: bool,
}

pub fn creation_bytecode(artifact_json: &str) -> Result<Vec<u8>, DemoError> {
    let v: serde_json::Value = serde_json::from_str(artifact_json)
        .map_err(|e| DemoError::Deploy(format!("bad artifact json: {e}")))?;
    let hex_code = v["bytecode"]
        .as_str()
        .ok_or_else(|| DemoError::Deploy("artifact missing .bytecode".into()))?;
    hex::decode(hex_code.trim_start_matches("0x"))
        .map_err(|e| DemoError::Deploy(format!("bad bytecode hex: {e}")))
}

pub async fn deploy<P: Provider>(
    provider: &P,
    from: Address,
    bytecode: Vec<u8>,
) -> Result<Address, DemoError> {
    // Anvil's dev accounts are unlocked; deployment is test scaffolding, not
    // part of the guarded signing pipeline.
    let tx = json!({
        "from": from,
        "data": format!("0x{}", hex::encode(bytecode)),
        "gas": "0x2dc6c0",
    });
    let tx_hash: String = provider
        .raw_request("eth_sendTransaction".into(), (tx,))
        .await
        .map_err(|e| DemoError::Deploy(e.to_string()))?;
    for _ in 0..40 {
        let receipt: Option<serde_json::Value> = provider
            .raw_request("eth_getTransactionReceipt".into(), (tx_hash.clone(),))
            .await
            .map_err(|e| DemoError::Deploy(e.to_string()))?;
        if let Some(r) = receipt {
            if r["status"] != json!("0x1") {
                return Err(DemoError::Deploy("deployment reverted".into()));
            }
            let addr = r["contractAddress"]
                .as_str()
                .ok_or_else(|| DemoError::Deploy("no contractAddress in receipt".into()))?;
            return cipherlayer_evm::parse_address(addr)
                .map_err(|e| DemoError::Deploy(e.to_string()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(DemoError::Deploy("no deployment receipt".into()))
}

pub fn approve_calldata(spender: Address, amount: U256) -> String {
    let mut d = cipherlayer_evm::SELECTOR_APPROVE.to_vec();
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(spender.as_slice());
    d.extend_from_slice(&amount.to_be_bytes::<32>());
    format!("0x{}", hex::encode(d))
}

pub fn envelope(
    caller: &CallerIdentity,
    from: Address,
    token: Address,
    data: String,
) -> TransactionRequestEnvelope {
    TransactionRequestEnvelope::new(
        caller.clone(),
        ChainId(31337),
        AccessClass::Signing,
        EnvelopePayload {
            from: format!("{from}"),
            to: Some(format!("{token}")),
            value_wei: Some("0".into()),
            data: Some(data),
            gas_limit: None,
            nonce: None,
            kind: cipherlayer_provider::PayloadKind::EvmTransaction,
            typed_data_json: None,
            message_hex: None,
        },
    )
}

pub async fn read_allowance(
    rpc_url: &str,
    token: Address,
    owner: Address,
    spender: Address,
) -> Result<U256, DemoError> {
    let url = rpc_url
        .parse()
        .map_err(|e| DemoError::Rpc(format!("{e}")))?;
    let provider = ProviderBuilder::new().connect_http(url);
    let mut data = vec![0xdd, 0x62, 0xed, 0x3e];
    for a in [owner, spender] {
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(a.as_slice());
    }
    let call = json!({"to": token, "data": format!("0x{}", hex::encode(data))});
    let result: String = provider
        .raw_request("eth_call".into(), (call, "latest"))
        .await
        .map_err(|e| DemoError::Rpc(e.to_string()))?;
    U256::from_str_radix(result.trim_start_matches("0x"), 16)
        .map_err(|e| DemoError::Rpc(e.to_string()))
}

/// Run the complete vertical slice. Prints progress; returns a machine-checkable report.
pub async fn run(pipeline: &mut Pipeline) -> Result<DemoReport, DemoError> {
    let rpc_url = pipeline.rpc_url.clone();
    let url = rpc_url
        .parse()
        .map_err(|e| DemoError::Rpc(format!("bad rpc url: {e}")))?;
    let provider = ProviderBuilder::new().connect_http(url);

    // Step 1-2: chain + signer.
    let chain_id = provider.get_chain_id().await.map_err(|e| {
        DemoError::Rpc(format!(
            "Anvil unreachable at {rpc_url}: {e} — run `make anvil-up`"
        ))
    })?;
    if chain_id != 31337 {
        return Err(DemoError::Expectation(format!(
            "expected Anvil chain 31337, found {chain_id}"
        )));
    }
    let account = pipeline.vault.address();
    println!("✔ Anvil chain 31337 reachable; test signer registered: {account}");
    println!("  [MOCKED] custody: in-memory Anvil dev key — not a custody mechanism (ADR-005)");

    // Step 3: deploy sample ERC-20 + spender.
    let token = deploy(&provider, account, creation_bytecode(TOKEN_ARTIFACT)?).await?;
    let spender = deploy(&provider, account, creation_bytecode(SPENDER_ARTIFACT)?).await?;
    println!("✔ TestToken deployed at {token}");
    println!("✔ TestSpender deployed at {spender}");

    // Permission grant for the CLI caller (auditable).
    let caller = CallerIdentity {
        kind: CallerKind::Cli,
        origin: None,
        app_id: Some("cli:demo".into()),
        capsule_id: None,
    };
    grant_cli_permission(pipeline, &caller, ChainId(31337), account)?;
    println!("✔ scoped signing permission granted to cli:demo (expires in 1h)");

    // Flow A: unlimited approval — must be blocked.
    println!("\n── Flow A: unlimited approval (expected: POLICY_DENIED) ──");
    let env_a = envelope(
        &caller,
        account,
        token,
        approve_calldata(spender, U256::MAX),
    );
    let blocked_request = env_a.request_id;
    let out_a = pipeline.process(env_a, ReviewMode::AssumeYes).await?;
    print_outcome(&out_a);
    if out_a.final_state != LifecycleState::PolicyDenied {
        return Err(DemoError::Expectation(format!(
            "unlimited approval ended in {:?}, expected POLICY_DENIED",
            out_a.final_state
        )));
    }

    // Flow B: exact approval — authorized end to end.
    println!("\n── Flow B: exact approval of 100 CLT (expected: CONFIRMED) ──");
    let amount = U256::from(100u64) * U256::from(10u64).pow(U256::from(18u64));
    let env_b = envelope(&caller, account, token, approve_calldata(spender, amount));
    let confirmed_request = env_b.request_id;
    let out_b = pipeline.process(env_b, ReviewMode::AssumeYes).await?;
    print_outcome(&out_b);
    if out_b.final_state != LifecycleState::Confirmed {
        return Err(DemoError::Expectation(format!(
            "exact approval ended in {:?}, expected CONFIRMED",
            out_b.final_state
        )));
    }

    // Verify the allowance actually landed on chain.
    let onchain_allowance = read_allowance(&rpc_url, token, account, spender).await?;
    if onchain_allowance != amount {
        return Err(DemoError::Expectation(format!(
            "on-chain allowance {onchain_allowance} != approved {amount}"
        )));
    }
    println!(
        "✔ on-chain allowance verified: {} CLT for spender {spender}",
        format_units18(onchain_allowance)
    );

    // Audit chain verification.
    let report = pipeline
        .audit
        .verify()
        .map_err(crate::pipeline::PipelineError::Audit)?;
    println!("\n✔ audit: {}", report.message);

    Ok(DemoReport {
        token,
        spender,
        blocked_request,
        confirmed_request,
        confirmed_tx_hash: out_b.tx_hash.unwrap_or_default(),
        onchain_allowance,
        audit_events: report.total_events,
        audit_valid: report.valid,
    })
}

fn print_outcome(out: &crate::pipeline::PipelineOutcome) {
    if let Some(intent) = &out.intent {
        println!(
            "  decoded: {:?} (confidence {:?}){}",
            intent.decoded_action.kind,
            intent.confidence,
            intent
                .allowance
                .as_ref()
                .map(|a| format!(", allowance: {:?}", a.kind))
                .unwrap_or_default()
        );
    }
    if let Some(sim) = &out.simulation {
        println!(
            "  simulation: {:?} (evidence, not a guarantee)",
            sim.outcome
        );
        for a in &sim.allowance_changes {
            println!(
                "    allowance {} -> {} (owner {}, spender {})",
                a.before.map(|v| v.to_string()).unwrap_or("?".into()),
                a.after.map(|v| v.to_string()).unwrap_or("?".into()),
                a.owner,
                a.spender
            );
        }
    }
    if let Some(risk) = &out.risk {
        println!(
            "  risk: {:?} — {}",
            risk.overall_level, risk.overall_rationale
        );
    }
    if let Some(d) = &out.decision {
        println!("  policy: {:?}", d.verdict);
        for r in &d.reasons {
            println!("    [{}] {}", r.code, r.detail);
        }
    }
    println!("  final state: {:?}", out.final_state);
    if let Some(h) = &out.tx_hash {
        println!("  tx: {h}");
    }
    for n in &out.notes {
        println!("  note: {n}");
    }
}
