//! `ChainAdapter` implementation for EVM chains (ADR-015 phase a).
//!
//! First adapter behind the `cipherlayer-chain` boundary: address parsing,
//! unsigned-transaction building (nonce/gas/fee fill), broadcast, and
//! chain-identity verification against the connected node. No signing
//! authority — the vault signs; this adapter only builds unsigned params and
//! broadcasts already-signed bytes.

use alloy::providers::{Provider, ProviderBuilder};
use cipherlayer_chain::adapter::{AdapterError, ChainBroadcaster, ChainObserver};
use cipherlayer_types::{Address, ChainId, U256};

/// EVM adapter over a single JSON-RPC endpoint.
pub struct EvmAdapter {
    rpc_url: String,
}

impl EvmAdapter {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
        }
    }

    fn provider(&self) -> Result<impl Provider, AdapterError> {
        let url = self
            .rpc_url
            .parse()
            .map_err(|e| AdapterError::Rpc(format!("bad rpc url: {e}")))?;
        Ok(ProviderBuilder::new().connect_http(url))
    }

    /// Generic read-only JSON-RPC passthrough for the browser-connect
    /// `rpc_query` proxy (protocol v0.4). Callers are responsible for
    /// whitelisting `method` before calling this — this adapter forwards
    /// whatever it is given, exactly like `build_unsigned`/`broadcast` trust
    /// their callers for the fields they fill. No signing authority is
    /// reachable through this path: it only ever returns a JSON-RPC result.
    pub async fn raw_rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        let provider = self.provider()?;
        provider
            .raw_request(method.to_string().into(), params)
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))
    }
}

/// Status of a broadcast EVM transaction (receipt semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmTxStatus {
    /// No receipt yet.
    Pending,
    /// Receipt with status 0x1.
    Confirmed { block_number: u64 },
    /// Receipt with a non-success status.
    Reverted,
}

/// Caller-supplied fields for building an EVM transaction. Optional fields
/// are filled from the node (nonce, gas estimation) when absent.
#[derive(Debug, Clone)]
pub struct EvmBuildInput {
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub nonce: Option<u64>,
    pub gas_limit: Option<u64>,
}

/// Fully specified unsigned EVM transaction, ready for the vault to sign.
#[derive(Debug, Clone)]
pub struct EvmUnsignedTx {
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price_wei: u128,
}

impl ChainObserver for EvmAdapter {
    type TxStatus = EvmTxStatus;

    async fn verify_chain_identity(&self, expected: ChainId) -> Result<(), AdapterError> {
        let provider = self.provider()?;
        let chain_hex: String = provider
            .raw_request("eth_chainId".into(), ())
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        let actual = u64::from_str_radix(chain_hex.trim_start_matches("0x"), 16).map_err(|e| {
            AdapterError::Rpc(format!("unparseable eth_chainId {chain_hex:?}: {e}"))
        })?;
        if actual != expected.0 {
            return Err(AdapterError::ChainIdentityMismatch {
                expected,
                actual: actual.to_string(),
            });
        }
        Ok(())
    }

    async fn transaction_status(&self, tx_ref: &str) -> Result<EvmTxStatus, AdapterError> {
        let provider = self.provider()?;
        let receipt: Option<serde_json::Value> = provider
            .raw_request("eth_getTransactionReceipt".into(), (tx_ref.to_string(),))
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        match receipt {
            None => Ok(EvmTxStatus::Pending),
            Some(r) => {
                if r["status"] != serde_json::json!("0x1") {
                    return Ok(EvmTxStatus::Reverted);
                }
                let block_number = r["blockNumber"]
                    .as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                Ok(EvmTxStatus::Confirmed { block_number })
            }
        }
    }
}

impl ChainBroadcaster for EvmAdapter {
    type Address = Address;
    type BuildInput = EvmBuildInput;
    type UnsignedTx = EvmUnsignedTx;

    fn parse_address(&self, s: &str) -> Result<Address, AdapterError> {
        crate::parse_address(s).map_err(|e| AdapterError::InvalidAddress(e.to_string()))
    }

    async fn build_unsigned(&self, input: &EvmBuildInput) -> Result<EvmUnsignedTx, AdapterError> {
        let provider = self.provider()?;
        let nonce = match input.nonce {
            Some(n) => n,
            None => provider
                .get_transaction_count(input.from)
                .await
                .map_err(|e| AdapterError::Rpc(e.to_string()))?,
        };
        let gas_limit = match input.gas_limit {
            Some(g) => g,
            None => {
                let mut call = serde_json::json!({
                    "from": input.from,
                    "value": format!("0x{:x}", input.value),
                    "data": format!("0x{}", hex::encode(&input.data)),
                });
                if let Some(to) = input.to {
                    call["to"] = serde_json::json!(to);
                }
                let est: String = provider
                    .raw_request("eth_estimateGas".into(), (call,))
                    .await
                    .map_err(|e| AdapterError::Rpc(e.to_string()))?;
                u64::from_str_radix(est.trim_start_matches("0x"), 16)
                    .map_err(|e| AdapterError::Rpc(e.to_string()))?
                    .saturating_mul(12)
                    / 10
            }
        };
        let gas_price_wei = provider
            .get_gas_price()
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        Ok(EvmUnsignedTx {
            to: input.to,
            value: input.value,
            data: input.data.clone(),
            nonce,
            gas_limit,
            gas_price_wei,
        })
    }

    async fn broadcast(&self, raw_signed: &[u8]) -> Result<String, AdapterError> {
        let provider = self.provider()?;
        provider
            .raw_request(
                "eth_sendRawTransaction".into(),
                (format!("0x{}", hex::encode(raw_signed)),),
            )
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal JSON-RPC mock: answers each method from a fixed table,
    /// one HTTP request per connection.
    async fn mock_rpc(responses: Vec<(&'static str, serde_json::Value)>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let responses = responses.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // Read until we have the full body (Content-Length).
                    loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf);
                        if let Some(hdr_end) = text.find("\r\n\r\n") {
                            let content_length = text
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if buf.len() >= hdr_end + 4 + content_length {
                                break;
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&buf);
                    let body = &text[text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0)..];
                    let req: serde_json::Value = serde_json::from_str(body).unwrap();
                    let method = req["method"].as_str().unwrap_or("").to_string();
                    let result = responses
                        .iter()
                        .find(|(m, _)| *m == method)
                        .map(|(_, r)| r.clone())
                        .unwrap_or(serde_json::Value::Null);
                    let resp_body = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": req["id"],
                        "result": result,
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn chain_identity_match_passes() {
        let url = mock_rpc(vec![("eth_chainId", serde_json::json!("0x7a69"))]).await;
        let adapter = EvmAdapter::new(&url);
        adapter
            .verify_chain_identity(ChainId(31337))
            .await
            .expect("matching chain id must verify");
    }

    #[tokio::test]
    async fn chain_identity_mismatch_fails_closed() {
        // Node claims mainnet while we expect the Anvil dev chain: refuse.
        let url = mock_rpc(vec![("eth_chainId", serde_json::json!("0x1"))]).await;
        let adapter = EvmAdapter::new(&url);
        let err = adapter
            .verify_chain_identity(ChainId(31337))
            .await
            .expect_err("wrong chain id must fail closed");
        match err {
            AdapterError::ChainIdentityMismatch { expected, actual } => {
                assert_eq!(expected, ChainId(31337));
                assert_eq!(actual, "1");
            }
            other => panic!("expected ChainIdentityMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unparseable_chain_id_is_an_error_not_a_pass() {
        let url = mock_rpc(vec![("eth_chainId", serde_json::json!("0xzz"))]).await;
        let adapter = EvmAdapter::new(&url);
        assert!(adapter.verify_chain_identity(ChainId(31337)).await.is_err());
    }

    #[tokio::test]
    async fn build_unsigned_fills_nonce_gas_and_price_from_node() {
        let url = mock_rpc(vec![
            ("eth_getTransactionCount", serde_json::json!("0x5")),
            ("eth_estimateGas", serde_json::json!("0x5208")), // 21000
            ("eth_gasPrice", serde_json::json!("0x3b9aca00")), // 1 gwei
        ])
        .await;
        let adapter = EvmAdapter::new(&url);
        let input = EvmBuildInput {
            from: Address::from_slice(&[1u8; 20]),
            to: Some(Address::from_slice(&[2u8; 20])),
            value: U256::from(1u64),
            data: vec![],
            nonce: None,
            gas_limit: None,
        };
        let tx = adapter.build_unsigned(&input).await.unwrap();
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.gas_limit, 21000 * 12 / 10); // 1.2x estimate headroom
        assert_eq!(tx.gas_price_wei, 1_000_000_000);
        assert_eq!(tx.to, input.to);
    }

    #[tokio::test]
    async fn build_unsigned_respects_caller_supplied_nonce_and_gas() {
        // Only eth_gasPrice should be needed.
        let url = mock_rpc(vec![("eth_gasPrice", serde_json::json!("0x1"))]).await;
        let adapter = EvmAdapter::new(&url);
        let input = EvmBuildInput {
            from: Address::from_slice(&[1u8; 20]),
            to: None,
            value: U256::ZERO,
            data: vec![0xde, 0xad],
            nonce: Some(9),
            gas_limit: Some(400_000),
        };
        let tx = adapter.build_unsigned(&input).await.unwrap();
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.gas_limit, 400_000);
        assert_eq!(tx.gas_price_wei, 1);
    }

    #[tokio::test]
    async fn transaction_status_maps_receipt_states() {
        let adapter = EvmAdapter::new(
            &mock_rpc(vec![(
                "eth_getTransactionReceipt",
                serde_json::json!({"status": "0x1", "blockNumber": "0x10"}),
            )])
            .await,
        );
        assert_eq!(
            adapter.transaction_status("0xabc").await.unwrap(),
            EvmTxStatus::Confirmed { block_number: 16 }
        );

        let adapter = EvmAdapter::new(
            &mock_rpc(vec![(
                "eth_getTransactionReceipt",
                serde_json::json!({"status": "0x0", "blockNumber": "0x10"}),
            )])
            .await,
        );
        assert_eq!(
            adapter.transaction_status("0xabc").await.unwrap(),
            EvmTxStatus::Reverted
        );

        let adapter = EvmAdapter::new(
            &mock_rpc(vec![("eth_getTransactionReceipt", serde_json::Value::Null)]).await,
        );
        assert_eq!(
            adapter.transaction_status("0xabc").await.unwrap(),
            EvmTxStatus::Pending
        );
    }

    #[tokio::test]
    async fn broadcast_returns_tx_hash() {
        let url = mock_rpc(vec![(
            "eth_sendRawTransaction",
            serde_json::json!("0xhash"),
        )])
        .await;
        let adapter = EvmAdapter::new(&url);
        assert_eq!(adapter.broadcast(&[0x01, 0x02]).await.unwrap(), "0xhash");
    }

    #[tokio::test]
    async fn parse_address_enforces_evm_format_via_trait() {
        // Exercise the trait surface generically, as a multi-chain caller would.
        fn parse<A: ChainBroadcaster>(a: &A, s: &str) -> Result<A::Address, AdapterError> {
            a.parse_address(s)
        }
        let adapter = EvmAdapter::new("http://127.0.0.1:1");
        assert!(parse(&adapter, "0x0000000000000000000000000000000000000001").is_ok());
        assert!(matches!(
            parse(&adapter, "not-an-address"),
            Err(AdapterError::InvalidAddress(_))
        ));
    }
}
