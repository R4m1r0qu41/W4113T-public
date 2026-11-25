//! End-to-end (ADR-017): adapter builds the unsigned transaction, the vault
//! signs it (secp256k1 over BIP-143, behind the vault boundary — the adapter
//! never sees a key), and the signature is verified by independently
//! recomputing the sighash from the signed bytes. No live node needed: the
//! whole P2WPKH witness (signature + pubkey vs. the spent script_pubkey) is
//! checkable standalone with rust-bitcoin.

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash as _;
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid};
use chrono::Utc;
use cipherlayer_btc::{BtcAdapter, BtcBuildInput, BtcUtxo};
use cipherlayer_chain::adapter::ChainBroadcaster;
use cipherlayer_policy::Verdict;
use cipherlayer_types::{ChainId, NetworkClass};
use cipherlayer_vault::btc::{BtcCapability, BtcTestSigner, BtcVault, BtcVaultSigningRequest};
use cipherlayer_vault::{ConfirmationSurface, UserAuthorization};
use uuid::Uuid;

const BTC_REGTEST: ChainId = ChainId(900002);
const SPEND_SATS: u64 = 60_000; // 0.0006 BTC
const FEE_SATS: u64 = 500;

#[tokio::test]
async fn build_sign_verify_p2wpkh_spend() {
    let vault = BtcVault::new(BtcTestSigner::ephemeral());
    let from = vault.address_regtest();
    let to = BtcTestSigner::ephemeral().address_regtest();

    // 1. Adapter builds the unsigned transaction (no RPC: UTXOs supplied).
    let adapter = BtcAdapter::regtest("http://127.0.0.1:1", None);
    let input = BtcBuildInput {
        utxos: vec![BtcUtxo {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            value: Amount::from_sat(100_000),
            script_pubkey: from.script_pubkey(),
        }],
        to: to.clone(),
        amount: Amount::from_sat(SPEND_SATS),
        change_address: from.clone(),
        fee: Amount::from_sat(FEE_SATS),
        max_fee: Amount::from_sat(1_000),
    };
    let unsigned = adapter.build_unsigned(&input).await.unwrap();

    // 2. Vault authorizes and signs the serialized transaction.
    let signed = vault
        .authorize_and_sign(&BtcVaultSigningRequest {
            signing_request_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            account: from.to_string(),
            chain_id: BTC_REGTEST,
            network_class: NetworkClass::Development,
            capability: BtcCapability::signing("cli:test", &from.to_string(), BTC_REGTEST, 60),
            policy_verdict: Verdict::Allow,
            user_authorization: UserAuthorization {
                decided_at: Utc::now(),
                surface: ConfirmationSurface::CliPrompt,
                escalation_acknowledged: false,
            },
            serialized_tx: unsigned.serialize(),
            prevouts: unsigned.prevouts.clone(),
        })
        .unwrap();

    // 3. The signed bytes are the same transaction (txid unchanged — witness
    //    data is not part of the txid) and every input's BIP-143 signature
    //    verifies against the independently recomputed sighash, with the
    //    witness pubkey hashing to the spent P2WPKH script.
    let tx: Transaction = encode::deserialize(&signed.raw).unwrap();
    assert_eq!(tx.compute_txid(), unsigned.tx.compute_txid());
    assert_eq!(tx.compute_txid().to_string(), signed.txid);
    assert_eq!(tx.output[0].value, Amount::from_sat(SPEND_SATS));
    assert_eq!(tx.output[0].script_pubkey, to.script_pubkey());

    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(&tx);
    for (i, prevout) in unsigned.prevouts.iter().enumerate() {
        let witness = &tx.input[i].witness;
        assert_eq!(witness.len(), 2, "P2WPKH witness is [signature, pubkey]");
        let sig = bitcoin::ecdsa::Signature::from_slice(&witness[0]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_slice(&witness[1]).unwrap();
        let sighash = cache
            .p2wpkh_signature_hash(i, &prevout.script_pubkey, prevout.value, sig.sighash_type)
            .unwrap();
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &sig.signature,
            &pk,
        )
        .expect("BIP-143 signature must verify");
        assert_eq!(
            Address::p2wpkh(&CompressedPublicKey(pk), Network::Regtest).script_pubkey(),
            prevout.script_pubkey,
            "witness pubkey must match the spent P2WPKH script"
        );
    }
}
