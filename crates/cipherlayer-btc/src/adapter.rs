//! `ChainAdapter` implementation for Bitcoin (ADR-017, ADR-015 phase d).
//!
//! Bitcoin has no numeric chain id: network identity is the genesis block
//! hash (`getblockhash 0`), so that is what `verify_chain_identity` checks —
//! pinned, never inferred. The registry's internal `ChainId` (900002 =
//! regtest) is a lookup key only and never appears on any wire.
//!
//! Node access is raw JSON-RPC over HTTP (Bitcoin Core's native protocol):
//! `bitcoincore-rpc`'s blocking client does not compose with the RPITIT
//! async adapter traits, and the surface here is four methods. ALL consensus
//! types, addresses, and encoding come from the `bitcoin` crate — no
//! hand-rolled consensus code (ADR-017 §1).
//!
//! No signing authority — the vault signs; this adapter only builds unsigned
//! transactions and broadcasts already-signed bytes.

use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use cipherlayer_chain::adapter::{AdapterError, ChainBroadcaster, ChainObserver};
use cipherlayer_types::ChainId;
use std::str::FromStr;

/// Regtest genesis block hash — a fixed, well-known constant (unlike the
/// Solana local validator's genesis hash, which changes on ledger reset).
/// Pinned for the Development registry entry (ADR-017 §3, T-09).
pub const REGTEST_GENESIS_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Bitcoin adapter over a single Bitcoin Core JSON-RPC endpoint.
///
/// `network` makes address parsing strict: a mainnet address is a hard error
/// on regtest and vice versa (ADR-017 §2). `expected_genesis` pins the chain
/// identity; there is no unpinned mode — every network's genesis hash is a
/// known constant.
pub struct BtcAdapter {
    rpc_url: String,
    network: Network,
    expected_genesis: BlockHash,
    /// Bitcoin Core userpass auth (`rpcuser`/`rpcpassword` or cookie-file
    /// contents split on `:`). `None` for unauthenticated test doubles.
    auth: Option<(String, String)>,
}

impl BtcAdapter {
    pub fn new(
        rpc_url: &str,
        network: Network,
        expected_genesis: BlockHash,
        auth: Option<(String, String)>,
    ) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            network,
            expected_genesis,
            auth,
        }
    }

    /// Regtest adapter with the pinned regtest genesis hash.
    pub fn regtest(rpc_url: &str, auth: Option<(String, String)>) -> Self {
        Self::new(
            rpc_url,
            Network::Regtest,
            BlockHash::from_str(REGTEST_GENESIS_HASH).expect("pinned constant is a valid hash"),
            auth,
        )
    }

    /// One Bitcoin Core JSON-RPC call. A JSON-RPC `error` member is an `Err`,
    /// never a value.
    async fn rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        let mut req = reqwest::Client::new()
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "1.0",
                "id": "cipherlayer-btc",
                "method": method,
                "params": params,
            }));
        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }
        let body: serde_json::Value = req
            .send()
            .await
            .map_err(|e| AdapterError::Rpc(e.to_string()))?
            .json()
            .await
            .map_err(|e| AdapterError::Rpc(format!("malformed JSON-RPC response: {e}")))?;
        if !body["error"].is_null() {
            return Err(AdapterError::Rpc(format!(
                "{method} failed: {}",
                body["error"]
            )));
        }
        Ok(body["result"].clone())
    }
}

/// Status of a broadcast Bitcoin transaction (confirmation-depth semantics).
///
/// An unknown txid is an `AdapterError::Rpc`, not a status: without
/// `-txindex`, `getrawtransaction` cannot distinguish "never seen" from
/// "confirmed but unindexed", so guessing `Pending` could mask a settled
/// spend. Never silently confirmed either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtcTxStatus {
    /// In the mempool (0 confirmations); may still be dropped or replaced.
    Pending,
    /// Included in a block at the given confirmation depth (>= 1).
    Confirmed { depth: u64, block_hash: String },
}

/// A spendable output the transaction consumes. Values are sats — never
/// render without the unit label (ADR-015 security implication).
#[derive(Debug, Clone)]
pub struct BtcUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
}

/// Caller-supplied fields for building a single-recipient spend with change.
/// The fee is explicit (sats, chosen by the builder from a rate), and
/// `max_fee` is the hard absurd-fee cap: fee overpayment on Bitcoin is a
/// real loss, not a refunded gas limit (ADR-017 §5).
#[derive(Debug, Clone)]
pub struct BtcBuildInput {
    pub utxos: Vec<BtcUtxo>,
    pub to: Address,
    pub amount: Amount,
    /// Change goes back to the sender, explicitly.
    pub change_address: Address,
    pub fee: Amount,
    /// Hard cap: building refuses (fails closed) if `fee` exceeds this.
    pub max_fee: Amount,
}

/// Fully specified unsigned transaction, ready for the vault to sign. Carries
/// the prevouts because BIP-143 sighashes commit to the spent value and
/// script — the vault re-derives everything from these, trusting no declared
/// amount.
#[derive(Debug, Clone)]
pub struct BtcUnsignedTx {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
}

impl BtcUnsignedTx {
    /// Canonical consensus-serialized form handed to the vault for signing.
    pub fn serialize(&self) -> Vec<u8> {
        encode::serialize(&self.tx)
    }
}

impl ChainObserver for BtcAdapter {
    type TxStatus = BtcTxStatus;

    async fn verify_chain_identity(&self, expected: ChainId) -> Result<(), AdapterError> {
        // Chain identity on Bitcoin IS the genesis block hash (ADR-017 §3).
        let result = self.rpc("getblockhash", serde_json::json!([0])).await?;
        let reported = result
            .as_str()
            .ok_or_else(|| AdapterError::Rpc(format!("non-string genesis hash: {result}")))?;
        // The response must be a well-formed block hash. Anything else is not
        // a Bitcoin node — fail closed, never a pass.
        let genesis = BlockHash::from_str(reported)
            .map_err(|e| AdapterError::Rpc(format!("malformed genesis hash {reported:?}: {e}")))?;
        if genesis != self.expected_genesis {
            return Err(AdapterError::ChainIdentityMismatch {
                expected,
                actual: reported.to_string(),
            });
        }
        Ok(())
    }

    async fn transaction_status(&self, tx_ref: &str) -> Result<BtcTxStatus, AdapterError> {
        let txid = Txid::from_str(tx_ref)
            .map_err(|e| AdapterError::Rpc(format!("invalid txid {tx_ref:?}: {e}")))?;
        // Verbose getrawtransaction: mempool transactions come back without a
        // "confirmations" field; confirmed ones carry depth + block hash.
        // An unknown txid is a JSON-RPC error, surfaced as Err by rpc().
        let result = self
            .rpc(
                "getrawtransaction",
                serde_json::json!([txid.to_string(), true]),
            )
            .await?;
        match result["confirmations"].as_u64() {
            None | Some(0) => Ok(BtcTxStatus::Pending),
            Some(depth) => {
                let block_hash = result["blockhash"]
                    .as_str()
                    .ok_or_else(|| {
                        AdapterError::Rpc(
                            "confirmed transaction without a block hash — refusing to guess".into(),
                        )
                    })?
                    .to_string();
                Ok(BtcTxStatus::Confirmed { depth, block_hash })
            }
        }
    }
}

impl ChainBroadcaster for BtcAdapter {
    type Address = Address;
    type BuildInput = BtcBuildInput;
    type UnsignedTx = BtcUnsignedTx;

    fn parse_address(&self, s: &str) -> Result<Address, AdapterError> {
        // Network-strict: a mainnet address on regtest (or vice versa) is a
        // hard error, never a silent re-interpretation (ADR-017 §2).
        let unchecked: Address<NetworkUnchecked> = s
            .parse()
            .map_err(|e| AdapterError::InvalidAddress(format!("{s:?}: {e}")))?;
        unchecked.require_network(self.network).map_err(|e| {
            AdapterError::InvalidAddress(format!("{s:?} is not a {:?} address: {e}", self.network))
        })
    }

    async fn build_unsigned(&self, input: &BtcBuildInput) -> Result<BtcUnsignedTx, AdapterError> {
        if input.utxos.is_empty() {
            return Err(AdapterError::Rpc("no UTXOs supplied".into()));
        }
        // Absurd-fee guard first: refuse before any arithmetic can hide it.
        if input.fee > input.max_fee {
            return Err(AdapterError::Rpc(format!(
                "fee {} exceeds the hard fee cap {} — refusing to build (ADR-017 §5)",
                input.fee, input.max_fee
            )));
        }
        let total_in = input
            .utxos
            .iter()
            .try_fold(Amount::ZERO, |acc, u| acc.checked_add(u.value))
            .ok_or_else(|| AdapterError::Rpc("input value overflows".into()))?;
        let spent = input
            .amount
            .checked_add(input.fee)
            .ok_or_else(|| AdapterError::Rpc("amount + fee overflows".into()))?;
        let change = total_in.checked_sub(spent).ok_or_else(|| {
            AdapterError::Rpc(format!(
                "insufficient inputs: {total_in} < {} + {} fee",
                input.amount, input.fee
            ))
        })?;
        let mut output = vec![TxOut {
            value: input.amount,
            script_pubkey: input.to.script_pubkey(),
        }];
        // Explicit change back to the sender; a zero change output is omitted
        // (it would be unspendable noise), which leaves the fee unchanged.
        if change > Amount::ZERO {
            output.push(TxOut {
                value: change,
                script_pubkey: input.change_address.script_pubkey(),
            });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: input
                .utxos
                .iter()
                .map(|u| TxIn {
                    previous_output: u.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output,
        };
        // Re-derive fee = inputs − outputs from the built transaction and
        // check it against the cap again: the invariant must hold on what is
        // actually handed to the vault, not on intermediate arithmetic.
        let total_out = tx
            .output
            .iter()
            .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))
            .ok_or_else(|| AdapterError::Rpc("output value overflows".into()))?;
        let implied_fee = total_in
            .checked_sub(total_out)
            .ok_or_else(|| AdapterError::Rpc("outputs exceed inputs".into()))?;
        if implied_fee != input.fee || implied_fee > input.max_fee {
            return Err(AdapterError::Rpc(format!(
                "implied fee {implied_fee} does not satisfy fee {} / cap {} — refusing to build",
                input.fee, input.max_fee
            )));
        }
        Ok(BtcUnsignedTx {
            tx,
            prevouts: input
                .utxos
                .iter()
                .map(|u| TxOut {
                    value: u.value,
                    script_pubkey: u.script_pubkey.clone(),
                })
                .collect(),
        })
    }

    async fn broadcast(&self, raw_signed: &[u8]) -> Result<String, AdapterError> {
        // The bytes must be a well-formed signed transaction; garbage fails
        // here rather than at the node.
        let tx: Transaction = encode::deserialize(raw_signed)
            .map_err(|e| AdapterError::Rpc(format!("not a signed Bitcoin transaction: {e}")))?;
        let result = self
            .rpc(
                "sendrawtransaction",
                serde_json::json!([hex::encode(encode::serialize(&tx))]),
            )
            .await?;
        let txid = result
            .as_str()
            .ok_or_else(|| AdapterError::Rpc(format!("non-string txid: {result}")))?;
        Ok(txid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    /// Minimal JSON-RPC mock: answers each method from a fixed table,
    /// one HTTP request per connection (same pattern as cipherlayer-sol).
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
                    // Bitcoin Core semantics: unknown method/txid is a
                    // JSON-RPC error object, not null.
                    let (result, error) = responses
                        .iter()
                        .find(|(m, _)| *m == method)
                        .map(|(_, r)| (r.clone(), serde_json::Value::Null))
                        .unwrap_or((
                            serde_json::Value::Null,
                            serde_json::json!({ "code": -5, "message": "not found" }),
                        ));
                    let resp_body = serde_json::json!({
                        "id": req["id"],
                        "result": result,
                        "error": error,
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

    /// Mainnet genesis block hash (well known).
    const MAINNET_GENESIS: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    const BTC_REGTEST: ChainId = ChainId(900002);

    fn regtest_key_address() -> (bitcoin::key::CompressedPublicKey, Address) {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());
        let cpk = bitcoin::key::CompressedPublicKey(pk);
        let addr = Address::p2wpkh(&cpk, Network::Regtest);
        (cpk, addr)
    }

    fn utxo(vout: u32, sats: u64, script: ScriptBuf) -> BtcUtxo {
        BtcUtxo {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout,
            },
            value: Amount::from_sat(sats),
            script_pubkey: script,
        }
    }

    // -- chain identity (T-09) ---------------------------------------------

    #[tokio::test]
    async fn identity_regtest_genesis_passes() {
        let url = mock_rpc(vec![(
            "getblockhash",
            serde_json::json!(REGTEST_GENESIS_HASH),
        )])
        .await;
        let adapter = BtcAdapter::regtest(&url, None);
        adapter
            .verify_chain_identity(BTC_REGTEST)
            .await
            .expect("pinned regtest genesis hash must verify");
    }

    #[tokio::test]
    async fn identity_mainnet_genesis_fails_closed() {
        // Node reports the mainnet genesis while we expect regtest: refuse.
        let url = mock_rpc(vec![("getblockhash", serde_json::json!(MAINNET_GENESIS))]).await;
        let adapter = BtcAdapter::regtest(&url, None);
        let err = adapter
            .verify_chain_identity(BTC_REGTEST)
            .await
            .expect_err("wrong genesis hash must fail closed");
        match err {
            AdapterError::ChainIdentityMismatch { expected, actual } => {
                assert_eq!(expected, BTC_REGTEST);
                assert_eq!(actual, MAINNET_GENESIS);
            }
            other => panic!("expected ChainIdentityMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn identity_garbage_hash_is_an_error_not_a_pass() {
        let url = mock_rpc(vec![("getblockhash", serde_json::json!("not-a-hash"))]).await;
        let adapter = BtcAdapter::regtest(&url, None);
        assert!(adapter.verify_chain_identity(BTC_REGTEST).await.is_err());
    }

    #[tokio::test]
    async fn identity_unreachable_node_is_an_error() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        assert!(adapter.verify_chain_identity(BTC_REGTEST).await.is_err());
    }

    // -- address parsing (network-strict) -----------------------------------

    #[test]
    fn parse_address_accepts_regtest_address() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        let (_, addr) = regtest_key_address();
        assert_eq!(adapter.parse_address(&addr.to_string()).unwrap(), addr);
    }

    #[test]
    fn parse_address_rejects_mainnet_address_on_regtest() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        // The (unspendable) mainnet genesis coinbase address.
        let mainnet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        assert!(matches!(
            adapter.parse_address(mainnet),
            Err(AdapterError::InvalidAddress(_))
        ));
    }

    #[test]
    fn parse_address_rejects_regtest_address_on_mainnet() {
        // The reverse direction would burn real funds if a regtest flow were
        // ever pointed at mainnet (ADR-017 security implications).
        let adapter = BtcAdapter::new(
            "http://127.0.0.1:1",
            Network::Bitcoin,
            BlockHash::from_str(MAINNET_GENESIS).unwrap(),
            None,
        );
        let (_, regtest_addr) = regtest_key_address();
        assert!(matches!(
            adapter.parse_address(&regtest_addr.to_string()),
            Err(AdapterError::InvalidAddress(_))
        ));
    }

    #[test]
    fn parse_address_rejects_garbage() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        for bad in [
            "",
            "not-an-address",
            "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", // bad checksum
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

    // -- build_unsigned: fee math, fee cap, change ---------------------------

    fn build_input(in_sats: u64, amount: u64, fee: u64, max_fee: u64) -> BtcBuildInput {
        let (_, from) = regtest_key_address();
        let (_, to) = regtest_key_address();
        BtcBuildInput {
            utxos: vec![utxo(0, in_sats, from.script_pubkey())],
            to,
            amount: Amount::from_sat(amount),
            change_address: from,
            fee: Amount::from_sat(fee),
            max_fee: Amount::from_sat(max_fee),
        }
    }

    #[tokio::test]
    async fn build_unsigned_pays_recipient_with_explicit_change() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        let input = build_input(100_000, 60_000, 500, 1_000);
        let unsigned = adapter.build_unsigned(&input).await.unwrap();
        assert_eq!(unsigned.tx.output.len(), 2);
        assert_eq!(unsigned.tx.output[0].value, Amount::from_sat(60_000));
        assert_eq!(
            unsigned.tx.output[0].script_pubkey,
            input.to.script_pubkey()
        );
        // Change = inputs − amount − fee, back to the sender.
        assert_eq!(unsigned.tx.output[1].value, Amount::from_sat(39_500));
        assert_eq!(
            unsigned.tx.output[1].script_pubkey,
            input.change_address.script_pubkey()
        );
        // fee = inputs − outputs, exactly as requested.
        let total_out: Amount = unsigned.tx.output.iter().map(|o| o.value).sum();
        assert_eq!(Amount::from_sat(100_000) - total_out, Amount::from_sat(500));
        // Prevouts travel with the unsigned tx for the vault's sighash.
        assert_eq!(unsigned.prevouts.len(), 1);
        assert_eq!(unsigned.prevouts[0].value, Amount::from_sat(100_000));
    }

    #[tokio::test]
    async fn build_unsigned_omits_zero_change() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        let unsigned = adapter
            .build_unsigned(&build_input(100_000, 99_500, 500, 1_000))
            .await
            .unwrap();
        assert_eq!(unsigned.tx.output.len(), 1);
        assert_eq!(unsigned.tx.output[0].value, Amount::from_sat(99_500));
    }

    #[tokio::test]
    async fn build_unsigned_refuses_fee_over_hard_cap() {
        // Absurd-fee guard (ADR-017 §5): fee overpayment is a loss path.
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        let err = adapter
            .build_unsigned(&build_input(100_000, 60_000, 1_001, 1_000))
            .await
            .expect_err("fee above the hard cap must fail closed");
        assert!(err.to_string().contains("fee cap"), "{err}");
    }

    #[tokio::test]
    async fn build_unsigned_refuses_insufficient_inputs() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        assert!(adapter
            .build_unsigned(&build_input(100, 60_000, 500, 1_000))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn build_unsigned_refuses_empty_utxo_set() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        let mut input = build_input(100_000, 60_000, 500, 1_000);
        input.utxos.clear();
        assert!(adapter.build_unsigned(&input).await.is_err());
    }

    // -- broadcast -----------------------------------------------------------

    #[tokio::test]
    async fn broadcast_returns_txid() {
        let adapter_local = BtcAdapter::regtest("http://127.0.0.1:1", None);
        let unsigned = adapter_local
            .build_unsigned(&build_input(100_000, 60_000, 500, 1_000))
            .await
            .unwrap();
        let expected_txid = unsigned.tx.compute_txid().to_string();
        let url = mock_rpc(vec![(
            "sendrawtransaction",
            serde_json::json!(expected_txid.clone()),
        )])
        .await;
        let adapter = BtcAdapter::regtest(&url, None);
        assert_eq!(
            adapter.broadcast(&unsigned.serialize()).await.unwrap(),
            expected_txid
        );
    }

    #[tokio::test]
    async fn broadcast_rejects_garbage_bytes() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        let err = adapter.broadcast(&[0xde, 0xad, 0xbe, 0xef]).await;
        assert!(matches!(err, Err(AdapterError::Rpc(_))));
    }

    // -- transaction status ---------------------------------------------

    async fn status_of(result: serde_json::Value) -> Result<BtcTxStatus, AdapterError> {
        let url = mock_rpc(vec![("getrawtransaction", result)]).await;
        let adapter = BtcAdapter::regtest(&url, None);
        adapter
            .transaction_status(&Txid::all_zeros().to_string())
            .await
    }

    #[tokio::test]
    async fn status_mempool_is_pending() {
        // Mempool transactions come back without a confirmations field.
        let v = serde_json::json!({ "txid": Txid::all_zeros().to_string(), "hex": "00" });
        assert_eq!(status_of(v).await.unwrap(), BtcTxStatus::Pending);
    }

    #[tokio::test]
    async fn status_confirmed_carries_depth_and_block() {
        let v = serde_json::json!({
            "txid": Txid::all_zeros().to_string(),
            "confirmations": 3,
            "blockhash": REGTEST_GENESIS_HASH,
        });
        assert_eq!(
            status_of(v).await.unwrap(),
            BtcTxStatus::Confirmed {
                depth: 3,
                block_hash: REGTEST_GENESIS_HASH.to_string()
            }
        );
    }

    #[tokio::test]
    async fn status_unknown_txid_is_an_error_never_confirmed() {
        // The mock answers unknown methods with Bitcoin Core's -5 error, so
        // an empty table simulates an unknown txid.
        let url = mock_rpc(vec![]).await;
        let adapter = BtcAdapter::regtest(&url, None);
        let err = adapter
            .transaction_status(&Txid::all_zeros().to_string())
            .await;
        assert!(matches!(err, Err(AdapterError::Rpc(_))));
    }

    #[tokio::test]
    async fn status_rejects_garbage_txid_reference() {
        let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
        assert!(adapter.transaction_status("not-a-txid").await.is_err());
    }
}
