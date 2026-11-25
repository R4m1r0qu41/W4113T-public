//! `ChainAdapter` implementation for Solana (ADR-016, ADR-015 phase c).
//!
//! Solana has no numeric chain id: network identity is the genesis hash
//! (`getGenesisHash`), so that is what `verify_chain_identity` checks. The
//! registry's internal `ChainId` (900001 = local test validator) is a lookup
//! key only and never appears on any wire.
//!
//! No signing authority — the vault signs (ed25519); this adapter only builds
//! unsigned messages and broadcasts already-signed bytes.

use cipherlayer_chain::adapter::{AdapterError, ChainBroadcaster, ChainObserver};
use cipherlayer_types::ChainId;
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::request::RpcRequest;
use solana_signature::Signature;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::TransactionConfirmationStatus;
use std::str::FromStr;

/// Solana adapter over a single JSON-RPC endpoint.
///
/// `expected_genesis_hash` pins the cluster identity where it is stable
/// (testnet/mainnet metadata entries). The local test validator's genesis
/// hash changes on every ledger reset, so the Development entry passes
/// `None` and `verify_chain_identity` checks reachability + cluster sanity
/// (a well-formed genesis hash) instead (ADR-016 §3).
pub struct SolAdapter {
    rpc_url: String,
    expected_genesis_hash: Option<Hash>,
}

impl SolAdapter {
    pub fn new(rpc_url: &str, expected_genesis_hash: Option<Hash>) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            expected_genesis_hash,
        }
    }

    fn client(&self) -> RpcClient {
        RpcClient::new(self.rpc_url.clone())
    }

    /// Native balance in lamports.
    pub async fn balance_lamports(&self, pubkey: &Pubkey) -> Result<u64, AdapterError> {
        self.client()
            .get_balance(pubkey)
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))
    }

    /// Authoritative `getFeeForMessage` result for exactly this message.
    /// `Ok(None)` is an honest "the cluster does not know" (a null value) —
    /// it is never coerced to a default number, because unknown is not
    /// evidence (ADR-021 §4). The mainnet ceremony refuses on `None`; devnet
    /// may proceed displaying `fee: unknown`.
    pub async fn fee_for_message(&self, message: &Message) -> Result<Option<u64>, AdapterError> {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(message.serialize());
        let resp: serde_json::Value = self
            .client()
            .send(
                RpcRequest::GetFeeForMessage,
                serde_json::json!([encoded, { "commitment": "confirmed" }]),
            )
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        match &resp["value"] {
            serde_json::Value::Null => Ok(None),
            v => v.as_u64().map(Some).ok_or_else(|| {
                AdapterError::Rpc(format!("unexpected getFeeForMessage value: {v}"))
            }),
        }
    }

    /// `isBlockhashValid` for exactly this blockhash, on THIS endpoint.
    /// Used as the pre-broadcast cross-check (ADR-021 amendment, external
    /// audit 2026-07-19): a blockhash smuggled in from another cluster is
    /// not valid on an independent endpoint of the intended cluster, so a
    /// second provider answering `false` fails the ceremony closed. Any
    /// non-boolean response is an error, never coerced.
    pub async fn is_blockhash_valid(&self, blockhash: &Hash) -> Result<bool, AdapterError> {
        let resp: serde_json::Value = self
            .client()
            .send(
                RpcRequest::IsBlockhashValid,
                serde_json::json!([blockhash.to_string(), { "commitment": "processed" }]),
            )
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        resp["value"].as_bool().ok_or_else(|| {
            AdapterError::Rpc(format!(
                "unexpected isBlockhashValid value: {}",
                resp["value"]
            ))
        })
    }
}

/// Status of a broadcast Solana transaction (commitment-level semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolTxStatus {
    /// Signature not known to the node yet.
    Pending,
    /// Processed by the queried node only; may still be dropped.
    Processed { slot: u64 },
    /// Voted on by a supermajority of the cluster.
    Confirmed { slot: u64 },
    /// Rooted; will not be rolled back.
    Finalized { slot: u64 },
    /// Included but the transaction itself failed.
    Failed { slot: u64 },
}

/// Caller-supplied fields for building a system transfer. The recent
/// blockhash is fetched from the node when absent.
#[derive(Debug, Clone)]
pub struct SolBuildInput {
    pub from: Pubkey,
    pub to: Pubkey,
    pub lamports: u64,
    pub recent_blockhash: Option<Hash>,
}

/// Fully specified unsigned Solana message, ready for the vault to sign.
/// Amounts are lamports (1 SOL = 10^9 lamports) — never render without the
/// unit label (ADR-015 security implication).
#[derive(Debug, Clone)]
pub struct SolUnsignedMessage {
    pub message: Message,
}

impl SolUnsignedMessage {
    /// Canonical serialized form handed to the vault for signing.
    pub fn serialize(&self) -> Vec<u8> {
        self.message.serialize()
    }
}

impl ChainObserver for SolAdapter {
    type TxStatus = SolTxStatus;

    async fn verify_chain_identity(&self, expected: ChainId) -> Result<(), AdapterError> {
        // Chain identity on Solana IS the genesis hash (ADR-016 §3).
        let reported: String = self
            .client()
            .send(RpcRequest::GetGenesisHash, serde_json::Value::Null)
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        // Cluster sanity: the response must be a well-formed 32-byte base58
        // hash. Anything else is not a Solana cluster — fail closed.
        let genesis = Hash::from_str(&reported)
            .map_err(|e| AdapterError::Rpc(format!("malformed genesis hash {reported:?}: {e}")))?;
        if let Some(pinned) = self.expected_genesis_hash {
            if genesis != pinned {
                return Err(AdapterError::ChainIdentityMismatch {
                    expected,
                    actual: reported,
                });
            }
        }
        Ok(())
    }

    async fn transaction_status(&self, tx_ref: &str) -> Result<SolTxStatus, AdapterError> {
        let sig = Signature::from_str(tx_ref)
            .map_err(|e| AdapterError::Rpc(format!("invalid transaction signature: {e}")))?;
        let statuses = self
            .client()
            .get_signature_statuses(&[sig])
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        match statuses.value.into_iter().next().flatten() {
            // Unknown signature: pending (possibly dropped), never success.
            None => Ok(SolTxStatus::Pending),
            Some(st) => {
                if st.err.is_some() {
                    return Ok(SolTxStatus::Failed { slot: st.slot });
                }
                match st.confirmation_status {
                    Some(TransactionConfirmationStatus::Processed) => {
                        Ok(SolTxStatus::Processed { slot: st.slot })
                    }
                    Some(TransactionConfirmationStatus::Confirmed) => {
                        Ok(SolTxStatus::Confirmed { slot: st.slot })
                    }
                    Some(TransactionConfirmationStatus::Finalized) => {
                        Ok(SolTxStatus::Finalized { slot: st.slot })
                    }
                    // Absent commitment level: refuse to guess.
                    None => Err(AdapterError::Rpc(
                        "node returned a status without a confirmation level — refusing to guess"
                            .into(),
                    )),
                }
            }
        }
    }
}

impl ChainBroadcaster for SolAdapter {
    type Address = Pubkey;
    type BuildInput = SolBuildInput;
    type UnsignedTx = SolUnsignedMessage;

    fn parse_address(&self, s: &str) -> Result<Pubkey, AdapterError> {
        // Strict base58 pubkey validation (decode + 32-byte length).
        Pubkey::from_str(s).map_err(|e| AdapterError::InvalidAddress(format!("{s:?}: {e}")))
    }

    async fn build_unsigned(
        &self,
        input: &SolBuildInput,
    ) -> Result<SolUnsignedMessage, AdapterError> {
        let recent_blockhash = match input.recent_blockhash {
            Some(h) => h,
            None => self
                .client()
                .get_latest_blockhash()
                .await
                .map_err(|e| AdapterError::Rpc(e.to_string()))?,
        };
        let ix =
            solana_system_interface::instruction::transfer(&input.from, &input.to, input.lamports);
        let message = Message::new_with_blockhash(&[ix], Some(&input.from), &recent_blockhash);
        Ok(SolUnsignedMessage { message })
    }

    async fn broadcast(&self, raw_signed: &[u8]) -> Result<String, AdapterError> {
        // The bytes must be a well-formed signed transaction; garbage fails
        // here rather than at the node.
        let tx: Transaction = bincode::deserialize(raw_signed)
            .map_err(|e| AdapterError::Rpc(format!("not a signed Solana transaction: {e}")))?;
        let sig = self
            .client()
            .send_transaction(&tx)
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?;
        Ok(sig.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal JSON-RPC mock: answers each method from a fixed table,
    /// one HTTP request per connection (same pattern as cipherlayer-evm).
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

    /// The canonical pins (ADR-016 §3, ADR-021) — referenced from
    /// cipherlayer-chain, never re-typed here, so the registry pin and the
    /// adapter tests cannot drift.
    const MAINNET_GENESIS: &str = cipherlayer_chain::SOLANA_MAINNET_GENESIS;
    const DEVNET_GENESIS: &str = cipherlayer_chain::SOLANA_DEVNET_GENESIS;

    const LOCAL_CHAIN: ChainId = ChainId(900001);

    fn keypair() -> solana_keypair::Keypair {
        solana_keypair::Keypair::new()
    }

    fn pubkey(kp: &solana_keypair::Keypair) -> Pubkey {
        solana_signer::Signer::pubkey(kp)
    }

    // -- chain identity (T-09) ---------------------------------------------

    #[tokio::test]
    async fn identity_without_pin_accepts_well_formed_genesis_hash() {
        // Development local-validator entry: no pinned hash, so a well-formed
        // genesis hash response is reachability + cluster sanity.
        let url = mock_rpc(vec![("getGenesisHash", serde_json::json!(DEVNET_GENESIS))]).await;
        let adapter = SolAdapter::new(&url, None);
        adapter
            .verify_chain_identity(LOCAL_CHAIN)
            .await
            .expect("well-formed genesis hash must verify when no pin is configured");
    }

    #[tokio::test]
    async fn identity_pin_match_passes() {
        let url = mock_rpc(vec![("getGenesisHash", serde_json::json!(DEVNET_GENESIS))]).await;
        let adapter = SolAdapter::new(&url, Some(Hash::from_str(DEVNET_GENESIS).unwrap()));
        adapter
            .verify_chain_identity(LOCAL_CHAIN)
            .await
            .expect("matching genesis hash must verify");
    }

    #[tokio::test]
    async fn identity_pin_mismatch_fails_closed() {
        // Node reports mainnet-beta while we expect the devnet hash: refuse.
        let url = mock_rpc(vec![("getGenesisHash", serde_json::json!(MAINNET_GENESIS))]).await;
        let adapter = SolAdapter::new(&url, Some(Hash::from_str(DEVNET_GENESIS).unwrap()));
        let err = adapter
            .verify_chain_identity(LOCAL_CHAIN)
            .await
            .expect_err("wrong genesis hash must fail closed");
        match err {
            AdapterError::ChainIdentityMismatch { expected, actual } => {
                assert_eq!(expected, LOCAL_CHAIN);
                assert_eq!(actual, MAINNET_GENESIS);
            }
            other => panic!("expected ChainIdentityMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_genesis_hash_is_an_error_not_a_pass() {
        // Not a 32-byte base58 hash: not a Solana cluster, even without a pin.
        let url = mock_rpc(vec![("getGenesisHash", serde_json::json!("not-base58!"))]).await;
        let adapter = SolAdapter::new(&url, None);
        assert!(adapter.verify_chain_identity(LOCAL_CHAIN).await.is_err());
    }

    #[tokio::test]
    async fn unreachable_node_is_an_error() {
        let adapter = SolAdapter::new("http://127.0.0.1:1", None);
        assert!(adapter.verify_chain_identity(LOCAL_CHAIN).await.is_err());
    }

    // -- transaction status ---------------------------------------------

    fn status_response(value: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "context": { "slot": 100 }, "value": [value] })
    }

    async fn status_of(value: serde_json::Value) -> Result<SolTxStatus, AdapterError> {
        let url = mock_rpc(vec![("getSignatureStatuses", status_response(value))]).await;
        let adapter = SolAdapter::new(&url, None);
        let sig = Signature::default().to_string();
        adapter.transaction_status(&sig).await
    }

    #[tokio::test]
    async fn status_not_found_is_pending() {
        assert_eq!(
            status_of(serde_json::Value::Null).await.unwrap(),
            SolTxStatus::Pending
        );
    }

    #[tokio::test]
    async fn status_maps_commitment_levels() {
        for (level, expected) in [
            ("processed", SolTxStatus::Processed { slot: 7 }),
            ("confirmed", SolTxStatus::Confirmed { slot: 7 }),
            ("finalized", SolTxStatus::Finalized { slot: 7 }),
        ] {
            let v = serde_json::json!({
                "slot": 7, "confirmations": 1, "status": { "Ok": null },
                "err": null, "confirmationStatus": level,
            });
            assert_eq!(status_of(v).await.unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn status_with_err_is_failed_even_if_finalized() {
        let v = serde_json::json!({
            "slot": 9, "confirmations": null,
            "status": { "Err": "AccountNotFound" },
            "err": "AccountNotFound",
            "confirmationStatus": "finalized",
        });
        assert_eq!(status_of(v).await.unwrap(), SolTxStatus::Failed { slot: 9 });
    }

    #[tokio::test]
    async fn status_without_commitment_level_is_an_error_not_a_pass() {
        let v = serde_json::json!({
            "slot": 9, "confirmations": 1, "status": { "Ok": null },
            "err": null, "confirmationStatus": null,
        });
        assert!(status_of(v).await.is_err());
    }

    #[tokio::test]
    async fn status_rejects_garbage_signature_reference() {
        let adapter = SolAdapter::new("http://127.0.0.1:1", None);
        assert!(adapter.transaction_status("not-a-signature").await.is_err());
    }

    // -- build / broadcast ---------------------------------------------

    #[tokio::test]
    async fn build_unsigned_fetches_blockhash_from_node() {
        let url = mock_rpc(vec![(
            "getLatestBlockhash",
            serde_json::json!({
                "context": { "slot": 1 },
                "value": { "blockhash": DEVNET_GENESIS, "lastValidBlockHeight": 100 },
            }),
        )])
        .await;
        let adapter = SolAdapter::new(&url, None);
        let (from, to) = (pubkey(&keypair()), pubkey(&keypair()));
        let unsigned = adapter
            .build_unsigned(&SolBuildInput {
                from,
                to,
                lamports: 42,
                recent_blockhash: None,
            })
            .await
            .unwrap();
        assert_eq!(
            unsigned.message.recent_blockhash,
            Hash::from_str(DEVNET_GENESIS).unwrap()
        );
        // Fee payer (first account key, the only required signer) is `from`.
        assert_eq!(unsigned.message.account_keys[0], from);
        assert_eq!(unsigned.message.header.num_required_signatures, 1);
    }

    #[tokio::test]
    async fn build_unsigned_respects_caller_supplied_blockhash() {
        // No RPC should be needed: the URL points nowhere.
        let adapter = SolAdapter::new("http://127.0.0.1:1", None);
        let hash = Hash::from_str(MAINNET_GENESIS).unwrap();
        let unsigned = adapter
            .build_unsigned(&SolBuildInput {
                from: pubkey(&keypair()),
                to: pubkey(&keypair()),
                lamports: 1,
                recent_blockhash: Some(hash),
            })
            .await
            .unwrap();
        assert_eq!(unsigned.message.recent_blockhash, hash);
    }

    #[tokio::test]
    async fn broadcast_returns_signature() {
        let kp = keypair();
        let to = pubkey(&keypair());
        let ix = solana_system_interface::instruction::transfer(&pubkey(&kp), &to, 5);
        let message = Message::new_with_blockhash(
            &[ix],
            Some(&pubkey(&kp)),
            &Hash::from_str(DEVNET_GENESIS).unwrap(),
        );
        let mut tx = Transaction::new_unsigned(message);
        let blockhash = tx.message.recent_blockhash;
        tx.try_sign(&[&kp], blockhash).unwrap();
        let expected_sig = tx.signatures[0].to_string();

        let url = mock_rpc(vec![(
            "sendTransaction",
            serde_json::json!(expected_sig.clone()),
        )])
        .await;
        let adapter = SolAdapter::new(&url, None);
        let raw = bincode::serialize(&tx).unwrap();
        assert_eq!(adapter.broadcast(&raw).await.unwrap(), expected_sig);
    }

    #[tokio::test]
    async fn broadcast_rejects_garbage_bytes() {
        let adapter = SolAdapter::new("http://127.0.0.1:1", None);
        let err = adapter.broadcast(&[0xde, 0xad, 0xbe, 0xef]).await;
        assert!(matches!(err, Err(AdapterError::Rpc(_))));
    }

    // -- address parsing ---------------------------------------------

    #[test]
    fn parse_address_accepts_valid_base58_pubkey() {
        let adapter = SolAdapter::new("http://127.0.0.1:1", None);
        let kp = keypair();
        assert_eq!(
            adapter.parse_address(&pubkey(&kp).to_string()).unwrap(),
            pubkey(&kp)
        );
    }

    #[test]
    fn parse_address_rejects_garbage_and_wrong_length() {
        let adapter = SolAdapter::new("http://127.0.0.1:1", None);
        for bad in [
            "",
            "not-an-address",
            "O0Il",                                       // non-base58 alphabet
            "abc",                                        // too short
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147",     // truncated (< 32 bytes)
            "0x0000000000000000000000000000000000000001", // EVM address, wrong chain family
        ] {
            assert!(
                matches!(
                    adapter.parse_address(bad),
                    Err(AdapterError::InvalidAddress(_))
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    // --- ADR-021 helpers: balance + honest fee ----------------------------

    fn any_message() -> Message {
        let kp = keypair();
        let to = pubkey(&keypair());
        let ix = solana_system_interface::instruction::transfer(&pubkey(&kp), &to, 5);
        Message::new(&[ix], Some(&pubkey(&kp)))
    }

    #[tokio::test]
    async fn balance_lamports_reads_the_node() {
        let url = mock_rpc(vec![(
            "getBalance",
            serde_json::json!({"context": {"slot": 1}, "value": 123_456u64}),
        )])
        .await;
        let adapter = SolAdapter::new(&url, None);
        let who = pubkey(&keypair());
        assert_eq!(adapter.balance_lamports(&who).await.unwrap(), 123_456);
    }

    #[tokio::test]
    async fn fee_for_message_returns_the_authoritative_number() {
        let url = mock_rpc(vec![(
            "getFeeForMessage",
            serde_json::json!({"context": {"slot": 1}, "value": 5_000u64}),
        )])
        .await;
        let adapter = SolAdapter::new(&url, None);
        assert_eq!(
            adapter.fee_for_message(&any_message()).await.unwrap(),
            Some(5_000)
        );
    }

    /// ADR-021 §4: a null fee is an honest `None` — never an error dressed
    /// as a number, never a default. The refuse-on-mainnet policy lives in
    /// the ceremony, not here.
    #[tokio::test]
    async fn fee_for_message_null_is_none_not_a_default() {
        let url = mock_rpc(vec![(
            "getFeeForMessage",
            serde_json::json!({"context": {"slot": 1}, "value": null}),
        )])
        .await;
        let adapter = SolAdapter::new(&url, None);
        assert_eq!(adapter.fee_for_message(&any_message()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn fee_for_message_garbage_value_is_an_error_not_a_guess() {
        let url = mock_rpc(vec![(
            "getFeeForMessage",
            serde_json::json!({"context": {"slot": 1}, "value": "five thousand"}),
        )])
        .await;
        let adapter = SolAdapter::new(&url, None);
        assert!(adapter.fee_for_message(&any_message()).await.is_err());
    }

    // -- isBlockhashValid (pre-broadcast cross-check, ADR-021 amendment) --

    #[tokio::test]
    async fn blockhash_valid_true_and_false_pass_through() {
        let hash = Hash::from_str(DEVNET_GENESIS).unwrap();
        for expected in [true, false] {
            let url = mock_rpc(vec![(
                "isBlockhashValid",
                serde_json::json!({"context": {"slot": 1}, "value": expected}),
            )])
            .await;
            let adapter = SolAdapter::new(&url, None);
            assert_eq!(adapter.is_blockhash_valid(&hash).await.unwrap(), expected);
        }
    }

    /// A cross-check that cannot answer is a refusal, not a pass: null or
    /// garbage never coerces to `true` (the fail-closed direction).
    #[tokio::test]
    async fn blockhash_valid_non_boolean_is_an_error_not_a_pass() {
        let hash = Hash::from_str(DEVNET_GENESIS).unwrap();
        for value in [serde_json::json!(null), serde_json::json!("yes")] {
            let url = mock_rpc(vec![(
                "isBlockhashValid",
                serde_json::json!({"context": {"slot": 1}, "value": value}),
            )])
            .await;
            let adapter = SolAdapter::new(&url, None);
            assert!(adapter.is_blockhash_valid(&hash).await.is_err());
        }
    }
}
