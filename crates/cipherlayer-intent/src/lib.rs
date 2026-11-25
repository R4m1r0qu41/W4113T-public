//! Canonical, versioned transaction intent (schema transaction-intent.v1).
//!
//! The intent is the pipeline's single legible artifact: raw request,
//! deterministic decoding, evidence references, unresolved fields, confidence,
//! and provenance. It never loses information — what could not be resolved is
//! listed, not dropped.

use chrono::{DateTime, Utc};
use cipherlayer_evm::{ActionKind, Decoded, DecodedAllowance};
use cipherlayer_types::{Address, ChainId, Confidence, CustodyContext, Provenance, U256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedActionSummary {
    pub kind: ActionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeDirection {
    Debit,
    Credit,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetChange {
    /// "native" or token contract address (0x…).
    pub asset: String,
    pub holder: Address,
    pub direction: ChangeDirection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<U256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<U256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated: Option<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionIntent {
    pub schema_version: String,
    pub intent_id: Uuid,
    pub request_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub chain_id: ChainId,
    /// Verbatim copy of the envelope payload this intent was decoded from.
    pub raw: serde_json::Value,
    pub decoded_action: DecodedActionSummary,
    pub asset_changes: Vec<AssetChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spender: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowance: Option<DecodedAllowance>,
    /// v1.1 (additive): for `typed_data` signing requests, whether the
    /// EIP-712 domain's declared `chainId` matches the session/envelope
    /// chain (`cipherlayer_evm::typed_data::TypedDataDomain::chain_id_matches`).
    /// `None` = not evaluated (not a typed-data request, or the domain
    /// omitted `chainId` — legal per EIP-712, never treated as a match).
    /// `Some(false)` feeds a dedicated policy deny rule (POL-CHAIN-002).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_chain_id_matches: Option<bool>,
    pub custody_context: CustodyContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<GasInfo>,
    /// Reference to simulation evidence; `None` = not (yet) available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation_evidence_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_evidence_id: Option<Uuid>,
    pub unresolved_fields: Vec<String>,
    pub confidence: Confidence,
    pub provenance: Provenance,
}

impl TransactionIntent {
    /// Build an intent from a validated envelope payload and its deterministic decoding.
    pub fn from_decoded(
        request_id: Uuid,
        chain_id: ChainId,
        raw_payload: serde_json::Value,
        from: Address,
        value: U256,
        decoded: Decoded,
    ) -> Self {
        let mut asset_changes = Vec::new();
        match decoded.kind {
            ActionKind::NativeTransfer => {
                asset_changes.push(AssetChange {
                    asset: "native".into(),
                    holder: from,
                    direction: ChangeDirection::Debit,
                    amount: Some(value),
                });
                if let Some(r) = decoded.recipient {
                    asset_changes.push(AssetChange {
                        asset: "native".into(),
                        holder: r,
                        direction: ChangeDirection::Credit,
                        amount: Some(value),
                    });
                }
            }
            ActionKind::Erc20Transfer | ActionKind::Erc20TransferFrom => {
                if let (Some(token), Some(r)) = (
                    decoded
                        .allowance
                        .as_ref()
                        .and_then(|a| a.token)
                        .or_else(|| {
                            raw_payload
                                .get("to")
                                .and_then(|v| v.as_str())
                                .and_then(|s| cipherlayer_evm::parse_address(s).ok())
                        }),
                    decoded.recipient,
                ) {
                    asset_changes.push(AssetChange {
                        asset: format!("{token}"),
                        holder: r,
                        direction: ChangeDirection::Credit,
                        amount: decoded.amount,
                    });
                }
            }
            _ => {}
        }

        TransactionIntent {
            schema_version: cipherlayer_types::SCHEMA_VERSION.into(),
            intent_id: cipherlayer_types::new_id(),
            request_id,
            created_at: Utc::now(),
            chain_id,
            raw: raw_payload,
            decoded_action: DecodedActionSummary {
                kind: decoded.kind,
                function_selector: decoded.selector.clone(),
                function_signature: decoded.function_signature.clone(),
            },
            asset_changes,
            spender: decoded.spender,
            recipient: decoded.recipient,
            allowance: decoded.allowance,
            domain_chain_id_matches: None,
            // MOCKED: milestone 1 always signs with the local test signer,
            // which is honest-labeled self-custody of a worthless dev key.
            custody_context: CustodyContext::SelfCustody,
            gas: None,
            simulation_evidence_id: None,
            risk_evidence_id: None,
            unresolved_fields: decoded.unresolved_fields,
            confidence: decoded.confidence,
            provenance: Provenance::of("cipherlayer-intent"),
        }
    }

    /// Set after construction by the typed-data decode step (pipeline), which
    /// alone knows both the parsed domain and the session/envelope chain.
    pub fn with_domain_chain_id_matches(mut self, matches: Option<bool>) -> Self {
        self.domain_chain_id_matches = matches;
        self
    }

    pub fn is_unlimited_approval(&self) -> bool {
        self.allowance
            .as_ref()
            .is_some_and(|a| a.kind == cipherlayer_evm::AllowanceKind::Unlimited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherlayer_evm::{decode_calldata, SELECTOR_APPROVE};

    fn addr(n: u8) -> Address {
        Address::from_slice(&[n; 20])
    }

    fn approve(spender: Address, amount: U256) -> Vec<u8> {
        let mut d = SELECTOR_APPROVE.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(spender.as_slice());
        d.extend_from_slice(&amount.to_be_bytes::<32>());
        d
    }

    #[test]
    fn intent_preserves_unresolved_and_flags_unlimited() {
        let decoded = decode_calldata(Some(addr(9)), U256::ZERO, &approve(addr(2), U256::MAX));
        let intent = TransactionIntent::from_decoded(
            uuid::Uuid::new_v4(),
            ChainId(31337),
            serde_json::json!({"to": format!("{}", addr(9))}),
            addr(1),
            U256::ZERO,
            decoded,
        );
        assert!(intent.is_unlimited_approval());
        assert_eq!(intent.schema_version, "1.0");
        assert_eq!(intent.decoded_action.kind, ActionKind::Erc20Approve);
    }

    #[test]
    fn unknown_decoding_yields_unknown_confidence() {
        let decoded = decode_calldata(Some(addr(9)), U256::ZERO, &[0xde, 0xad, 0xbe, 0xef]);
        let intent = TransactionIntent::from_decoded(
            uuid::Uuid::new_v4(),
            ChainId(31337),
            serde_json::Value::Null,
            addr(1),
            U256::ZERO,
            decoded,
        );
        assert_eq!(intent.confidence, Confidence::Unknown);
        assert!(!intent.unresolved_fields.is_empty());
        assert!(!intent.is_unlimited_approval());
    }

    #[test]
    fn serde_round_trip() {
        let decoded = decode_calldata(Some(addr(9)), U256::from(5u64), &[]);
        let intent = TransactionIntent::from_decoded(
            uuid::Uuid::new_v4(),
            ChainId(31337),
            serde_json::Value::Null,
            addr(1),
            U256::from(5u64),
            decoded,
        );
        let s = serde_json::to_string(&intent).unwrap();
        let back: TransactionIntent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.intent_id, intent.intent_id);
        assert_eq!(back.asset_changes.len(), 2);
    }
}
