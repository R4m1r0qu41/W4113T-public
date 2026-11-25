//! Provider-neutral transaction simulation (schema simulation-result.v1, ADR-008).
//!
//! Milestone-1 implementation: `AnvilSimulator` executes the transaction on
//! the local Anvil node inside a snapshot (evm_snapshot → impersonated
//! execution → state-diff reads → evm_revert), yielding real EVM state
//! transitions rather than estimates.
//!
//! Honesty rules enforced here:
//! - every result carries provider provenance, block context, and a
//!   NON-EMPTY limitations list — simulation is evidence, never a guarantee;
//! - a failed simulation is a first-class outcome (`SimulationError`), never
//!   silently skipped;
//! - this crate holds no signing authority (Zone E).

use alloy::providers::{Provider, ProviderBuilder};
use chrono::{DateTime, Utc};
use cipherlayer_evm::ActionKind;
use cipherlayer_intent::TransactionIntent;
use cipherlayer_types::{Address, U256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimOutcome {
    Success,
    Revert,
    SimulationError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub kind: String,
    pub endpoint_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContext {
    pub block_number: Option<u64>,
    pub chain_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceChange {
    pub asset: String,
    pub holder: Address,
    pub before: Option<U256>,
    pub after: Option<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowanceChange {
    pub token: Address,
    pub owner: Address,
    pub spender: Address,
    pub before: Option<U256>,
    pub after: Option<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub schema_version: String,
    pub simulation_id: Uuid,
    pub request_id: Uuid,
    pub simulated_at: DateTime<Utc>,
    pub provider: ProviderInfo,
    pub block_context: Option<BlockContext>,
    pub outcome: SimOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    pub balance_changes: Vec<BalanceChange>,
    pub allowance_changes: Vec<AllowanceChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<U256>,
    /// Mandatory, non-empty (schema-enforced): why this evidence may diverge
    /// from execution.
    pub limitations: Vec<String>,
}

/// Standing limitations attached to every AnvilSimulator result.
fn standing_limitations() -> Vec<String> {
    vec![
        "state-drift: chain state may change between simulation and execution".into(),
        "conditional-contract-behavior: contracts can behave differently at execution time".into(),
        "single-provider: one local node's view; no cross-provider comparison".into(),
    ]
}

/// The transaction fields the simulator needs (already validated upstream).
#[derive(Debug, Clone)]
pub struct SimTx {
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub gas_limit: Option<u64>,
}

/// Provider-neutral simulation interface. Future providers (RPC eth_call,
/// third-party services, in-process forks) implement the same contract and
/// must fill provenance + limitations honestly.
pub trait SimulationProvider {
    fn simulate(
        &self,
        request_id: Uuid,
        intent: &TransactionIntent,
        tx: &SimTx,
    ) -> impl std::future::Future<Output = SimulationResult> + Send;
}

// ---------------------------------------------------------------------------
// Anvil implementation
// ---------------------------------------------------------------------------

const SELECTOR_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
const SELECTOR_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e]; // allowance(address,address)

pub struct AnvilSimulator {
    rpc_url: String,
}

impl AnvilSimulator {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
        }
    }

    fn provider_info(&self, version: Option<String>) -> ProviderInfo {
        ProviderInfo {
            name: "anvil-local".into(),
            kind: "local_node".into(),
            endpoint_class: "local".into(),
            version,
        }
    }

    fn error_result(&self, request_id: Uuid, detail: String) -> SimulationResult {
        let mut limitations = standing_limitations();
        limitations.push(format!("simulation-error: {detail}"));
        SimulationResult {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            simulation_id: cipherlayer_types::new_id(),
            request_id,
            simulated_at: Utc::now(),
            provider: self.provider_info(None),
            block_context: None,
            outcome: SimOutcome::SimulationError,
            revert_reason: None,
            balance_changes: vec![],
            allowance_changes: vec![],
            gas_used: None,
            limitations,
        }
    }

    async fn run(
        &self,
        request_id: Uuid,
        intent: &TransactionIntent,
        tx: &SimTx,
    ) -> Result<SimulationResult, String> {
        let url = self
            .rpc_url
            .parse()
            .map_err(|e| format!("bad rpc url: {e}"))?;
        let provider = ProviderBuilder::new().connect_http(url);

        let client_version: Option<String> = provider
            .raw_request::<_, String>("web3_clientVersion".into(), ())
            .await
            .ok();
        let chain_id = provider.get_chain_id().await.map_err(|e| e.to_string())?;
        let block_number = provider
            .get_block_number()
            .await
            .map_err(|e| e.to_string())?;

        // Parties whose native balances we observe.
        let mut holders: Vec<Address> = vec![tx.from];
        if let Some(r) = intent.recipient {
            if !holders.contains(&r) {
                holders.push(r);
            }
        }
        // Token observation set: for ERC-20 interactions the token is the call target.
        let token: Option<Address> = match intent.decoded_action.kind {
            ActionKind::Erc20Approve
            | ActionKind::Erc20Transfer
            | ActionKind::Erc20TransferFrom
            | ActionKind::Permit => tx.to,
            _ => None,
        };
        let allowance_pair: Option<(Address, Address)> =
            intent.spender.map(|spender| (tx.from, spender));

        let snapshot: String = provider
            .raw_request("evm_snapshot".into(), ())
            .await
            .map_err(|e| format!("evm_snapshot failed: {e}"))?;

        // Everything from here on must revert the snapshot, including errors.
        let result = self
            .execute_and_diff(
                &provider,
                request_id,
                tx,
                token,
                allowance_pair,
                &holders,
                chain_id,
                block_number,
                client_version.clone(),
            )
            .await;

        let _: bool = provider
            .raw_request("evm_revert".into(), (snapshot,))
            .await
            .map_err(|e| format!("evm_revert failed: {e}"))?;

        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_and_diff<P: Provider>(
        &self,
        provider: &P,
        request_id: Uuid,
        tx: &SimTx,
        token: Option<Address>,
        allowance_pair: Option<(Address, Address)>,
        holders: &[Address],
        chain_id: u64,
        block_number: u64,
        client_version: Option<String>,
    ) -> Result<SimulationResult, String> {
        // Pre-state.
        let mut native_before = Vec::new();
        for h in holders {
            let b = provider.get_balance(*h).await.map_err(|e| e.to_string())?;
            native_before.push((*h, b));
        }
        let mut token_before = Vec::new();
        if let Some(tok) = token {
            for h in holders {
                if let Some(b) = self.erc20_balance(provider, tok, *h).await {
                    token_before.push((tok, *h, b));
                }
            }
        }
        let allowance_before = match (token, allowance_pair) {
            (Some(tok), Some((owner, spender))) => self
                .erc20_allowance(provider, tok, owner, spender)
                .await
                .map(|v| (tok, owner, spender, v)),
            _ => None,
        };

        // Impersonated execution.
        let _: () = provider
            .raw_request("anvil_impersonateAccount".into(), (tx.from,))
            .await
            .map_err(|e| format!("impersonation failed: {e}"))?;

        let mut tx_obj = json!({
            "from": tx.from,
            "value": format!("0x{:x}", tx.value),
            "data": format!("0x{}", hex::encode(&tx.data)),
        });
        if let Some(to) = tx.to {
            tx_obj["to"] = json!(to);
        }
        if let Some(gas) = tx.gas_limit {
            tx_obj["gas"] = json!(format!("0x{gas:x}"));
        }

        let send_result: Result<String, _> = provider
            .raw_request("eth_sendTransaction".into(), (tx_obj,))
            .await;

        let _: () = provider
            .raw_request("anvil_stopImpersonatingAccount".into(), (tx.from,))
            .await
            .unwrap_or(());

        let (outcome, revert_reason, gas_used) = match send_result {
            Ok(tx_hash) => {
                // Anvil automines; poll briefly for the receipt.
                let mut receipt: Option<serde_json::Value> = None;
                for _ in 0..20 {
                    let r: Option<serde_json::Value> = provider
                        .raw_request("eth_getTransactionReceipt".into(), (tx_hash.clone(),))
                        .await
                        .map_err(|e| e.to_string())?;
                    if r.is_some() {
                        receipt = r;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                match receipt {
                    Some(r) => {
                        let status_ok = r["status"] == json!("0x1");
                        let gas = r["gasUsed"].as_str().and_then(|s| {
                            U256::from_str_radix(s.trim_start_matches("0x"), 16).ok()
                        });
                        if status_ok {
                            (SimOutcome::Success, None, gas)
                        } else {
                            (
                                SimOutcome::Revert,
                                Some("transaction reverted (status 0x0)".into()),
                                gas,
                            )
                        }
                    }
                    None => (
                        SimOutcome::SimulationError,
                        Some("no receipt within polling window".into()),
                        None,
                    ),
                }
            }
            Err(e) => {
                // Node-side rejection with a revert message is still evidence.
                let msg = e.to_string();
                if msg.contains("revert") {
                    (SimOutcome::Revert, Some(msg), None)
                } else {
                    (SimOutcome::SimulationError, Some(msg), None)
                }
            }
        };

        // Post-state.
        let mut balance_changes = Vec::new();
        for (h, before) in &native_before {
            let after = provider.get_balance(*h).await.ok();
            balance_changes.push(BalanceChange {
                asset: "native".into(),
                holder: *h,
                before: Some(*before),
                after,
            });
        }
        for (tok, h, before) in &token_before {
            let after = self.erc20_balance(provider, *tok, *h).await;
            balance_changes.push(BalanceChange {
                asset: format!("{tok}"),
                holder: *h,
                before: Some(*before),
                after,
            });
        }
        let mut allowance_changes = Vec::new();
        if let Some((tok, owner, spender, before)) = allowance_before {
            let after = self.erc20_allowance(provider, tok, owner, spender).await;
            allowance_changes.push(AllowanceChange {
                token: tok,
                owner,
                spender,
                before: Some(before),
                after,
            });
        }

        Ok(SimulationResult {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            simulation_id: cipherlayer_types::new_id(),
            request_id,
            simulated_at: Utc::now(),
            provider: self.provider_info(client_version),
            block_context: Some(BlockContext {
                block_number: Some(block_number),
                chain_id: Some(chain_id),
            }),
            outcome,
            revert_reason,
            balance_changes,
            allowance_changes,
            gas_used,
            limitations: standing_limitations(),
        })
    }

    async fn erc20_balance<P: Provider>(
        &self,
        provider: &P,
        token: Address,
        holder: Address,
    ) -> Option<U256> {
        let mut data = SELECTOR_BALANCE_OF.to_vec();
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(holder.as_slice());
        self.eth_call_u256(provider, token, data).await
    }

    async fn erc20_allowance<P: Provider>(
        &self,
        provider: &P,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> Option<U256> {
        let mut data = SELECTOR_ALLOWANCE.to_vec();
        for a in [owner, spender] {
            data.extend_from_slice(&[0u8; 12]);
            data.extend_from_slice(a.as_slice());
        }
        self.eth_call_u256(provider, token, data).await
    }

    async fn eth_call_u256<P: Provider>(
        &self,
        provider: &P,
        to: Address,
        data: Vec<u8>,
    ) -> Option<U256> {
        let call = json!({
            "to": to,
            "data": format!("0x{}", hex::encode(&data)),
        });
        let result: String = provider
            .raw_request("eth_call".into(), (call, "latest"))
            .await
            .ok()?;
        let stripped = result.strip_prefix("0x")?;
        if stripped.len() != 64 {
            return None;
        }
        U256::from_str_radix(stripped, 16).ok()
    }
}

impl SimulationProvider for AnvilSimulator {
    async fn simulate(
        &self,
        request_id: Uuid,
        intent: &TransactionIntent,
        tx: &SimTx,
    ) -> SimulationResult {
        match self.run(request_id, intent, tx).await {
            Ok(result) => result,
            Err(detail) => self.error_result(request_id, detail),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_results_are_first_class_and_carry_limitations() {
        let sim = AnvilSimulator::new("http://127.0.0.1:1"); // nothing listens here
        let r = sim.error_result(cipherlayer_types::new_id(), "unreachable".into());
        assert_eq!(r.outcome, SimOutcome::SimulationError);
        assert!(!r.limitations.is_empty());
        assert!(r.limitations.iter().any(|l| l.contains("simulation-error")));
    }

    #[test]
    fn standing_limitations_never_empty() {
        assert!(!standing_limitations().is_empty());
    }

    #[test]
    fn result_serde_round_trip() {
        let sim = AnvilSimulator::new("http://127.0.0.1:1");
        let r = sim.error_result(cipherlayer_types::new_id(), "x".into());
        let s = serde_json::to_string(&r).unwrap();
        let back: SimulationResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.outcome, SimOutcome::SimulationError);
    }
}
