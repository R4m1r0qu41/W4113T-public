//! Bitcoin secp256k1 signing (ADR-017). Mirrors the ECDSA/ed25519 vaults:
//! same lock semantics, policy-verdict finality, development-only network
//! gate, and capability re-validation — the Vault trusts nothing upstream.
//!
//! Boundaries, labeled per BP §4.12:
//! - MOCKED custody: `BtcTestSigner` holds an ephemeral, test-generated
//!   secp256k1 key. There is no secure storage; nothing persists.
//! - Key material never leaves this module: no accessor, no serialization,
//!   no import path, and `Debug` output is redacted.
//!
//! The vault signs a P2WPKH (segwit v0, BIP-143) spend built by the adapter
//! (`cipherlayer-btc`); the adapter never sees a key. P2WPKH was chosen over
//! taproot key-path: rust-bitcoin's `p2wpkh_signature_hash` +
//! `Witness::p2wpkh` need no key tweaking, which is the smallest surface for
//! a signing mistake. Only spends of the vault's own P2WPKH outputs are
//! signable: any input it cannot fully attribute to itself fails closed, and
//! the capability's sat value cap is enforced against the non-change outputs
//! decoded from the transaction itself, never a caller-declared amount.
//! Because BIP-143 sighashes are computed here, over the very transaction and
//! prevouts the vault just validated, the signed digest cannot diverge from
//! the validated content — and each produced signature is verified against
//! that digest before release.

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash as _;
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Address, Amount, Network, ScriptBuf, Transaction, TxOut, Witness};
use chrono::{DateTime, Utc};
use cipherlayer_policy::Verdict;
use cipherlayer_types::{ChainId, NetworkClass};
use uuid::Uuid;

use crate::{CapabilityScope, UserAuthorization};

// ---------------------------------------------------------------------------
// Capability (Bitcoin flavor: bech32 account, sats value cap)
// ---------------------------------------------------------------------------

/// Signing capability scoped to a Bitcoin account (address string) and chain.
/// Mirrors `Capability` (wallet-capability.v1) with sats as the value unit —
/// 1 BTC = 10^8 sats.
#[derive(Debug, Clone)]
pub struct BtcCapability {
    pub capability_id: Uuid,
    pub subject: String,
    /// Address string (bech32 for P2WPKH) the capability covers.
    pub account: String,
    pub chain_id: ChainId,
    pub scope: CapabilityScope,
    pub max_sats_per_tx: Option<u64>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub requires_user_confirmation: bool,
}

impl BtcCapability {
    /// Narrow signing capability for the local CLI user.
    pub fn signing(subject: &str, account: &str, chain_id: ChainId, ttl_minutes: i64) -> Self {
        let now = Utc::now();
        BtcCapability {
            capability_id: cipherlayer_types::new_id(),
            subject: subject.to_string(),
            account: account.to_string(),
            chain_id,
            scope: CapabilityScope::SignTransactions,
            max_sats_per_tx: None,
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(ttl_minutes),
            revoked_at: None,
            requires_user_confirmation: true,
        }
    }

    pub fn validate_for_signing(
        &self,
        now: DateTime<Utc>,
        account: &str,
        chain_id: ChainId,
        sats: u64,
    ) -> Result<(), BtcCapabilityError> {
        if self.revoked_at.is_some() {
            return Err(BtcCapabilityError::Revoked(self.capability_id));
        }
        if now >= self.expires_at {
            return Err(BtcCapabilityError::Expired(self.capability_id));
        }
        if self.account != account {
            return Err(BtcCapabilityError::WrongAccount(account.to_string()));
        }
        if self.chain_id != chain_id {
            return Err(BtcCapabilityError::WrongChain(chain_id));
        }
        if self.scope != CapabilityScope::SignTransactions {
            return Err(BtcCapabilityError::WrongScope(self.scope));
        }
        if let Some(cap) = self.max_sats_per_tx {
            if sats > cap {
                return Err(BtcCapabilityError::ValueExceedsCap { sats, cap });
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BtcCapabilityError {
    #[error("capability {0} has expired")]
    Expired(Uuid),
    #[error("capability {0} was revoked")]
    Revoked(Uuid),
    #[error("capability does not cover account {0}")]
    WrongAccount(String),
    #[error("capability does not cover chain {0}")]
    WrongChain(ChainId),
    #[error("capability scope {0:?} does not permit transaction signing")]
    WrongScope(CapabilityScope),
    #[error("value {sats} sats exceeds the capability's per-transaction cap {cap} sats")]
    ValueExceedsCap { sats: u64, cap: u64 },
}

// ---------------------------------------------------------------------------
// Signing request / signed artifact
// ---------------------------------------------------------------------------

/// The only message that can ask the Vault for a Bitcoin signature. The
/// transaction content is the consensus-serialized unsigned transaction the
/// adapter built plus its prevouts (BIP-143 commits to spent value and
/// script); the vault re-derives the spend amount from the outputs rather
/// than trusting a declared value.
#[derive(Debug, Clone)]
pub struct BtcVaultSigningRequest {
    pub signing_request_id: Uuid,
    pub request_id: Uuid,
    /// Address string expected to sign (the vault's P2WPKH address).
    pub account: String,
    pub chain_id: ChainId,
    pub network_class: NetworkClass,
    pub capability: BtcCapability,
    pub policy_verdict: Verdict,
    pub user_authorization: UserAuthorization,
    /// `BtcUnsignedTx::serialize()` output from the adapter.
    pub serialized_tx: Vec<u8>,
    /// The outputs being spent, in input order (value + script_pubkey).
    pub prevouts: Vec<TxOut>,
}

#[derive(Debug, Clone)]
pub struct BtcSignedTransaction {
    /// Consensus-serialized signed transaction, ready to broadcast.
    pub raw: Vec<u8>,
    /// Hex txid (the chain-native tx reference).
    pub txid: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BtcVaultError {
    #[error("vault is locked — emergency or explicit lock is in effect")]
    Locked,
    #[error("capability check failed: {0}")]
    Capability(#[from] BtcCapabilityError),
    #[error("policy verdict {0:?} cannot be signed: a deny is final and cannot be overridden")]
    PolicyDenied(Verdict),
    #[error(
        "policy verdict was Escalate but the escalation was not explicitly acknowledged at review"
    )]
    EscalationNotAcknowledged,
    #[error("signing on {0:?}-class chains is refused in this prototype (development chains only, ADR-005/006)")]
    NonDevelopmentChain(NetworkClass),
    #[error("account {requested} does not match the vault signer {actual}")]
    AccountMismatch { requested: String, actual: String },
    #[error("refusing to sign: {0}")]
    UnsignableTransaction(String),
    #[error("signer error: {0}")]
    Signer(String),
}

// ---------------------------------------------------------------------------
// Test signer — MOCKED custody. Keys never leave this struct.
// ---------------------------------------------------------------------------

/// MOCKED: in-memory secp256k1 signer over an ephemeral test key. This is
/// not a custody mechanism; it exists so the pipeline can produce real
/// BIP-143 signatures on a worthless local regtest chain (ADR-017). There is
/// deliberately no key-import path.
pub struct BtcTestSigner {
    secp: Secp256k1<All>,
    secret: SecretKey,
    pubkey: CompressedPublicKey,
}

impl std::fmt::Debug for BtcTestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material is never printed.
        f.debug_struct("BtcTestSigner")
            .field("pubkey", &self.pubkey)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl BtcTestSigner {
    /// Freshly generated ephemeral test key (nothing persists).
    pub fn ephemeral() -> Self {
        let secp = Secp256k1::new();
        let (secret, pubkey) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());
        Self {
            secp,
            secret,
            pubkey: CompressedPublicKey(pubkey),
        }
    }

    /// Regtest P2WPKH address — the only thing this signer ever exposes.
    pub fn address_regtest(&self) -> Address {
        Address::p2wpkh(&self.pubkey, Network::Regtest)
    }
}

// ---------------------------------------------------------------------------
// The Bitcoin vault
// ---------------------------------------------------------------------------

pub struct BtcVault {
    signer: BtcTestSigner,
    locked: bool,
}

impl std::fmt::Debug for BtcVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcVault")
            .field("signer", &self.signer)
            .field("locked", &self.locked)
            .finish()
    }
}

impl BtcVault {
    pub fn new(signer: BtcTestSigner) -> Self {
        Self {
            signer,
            locked: false,
        }
    }

    pub fn address_regtest(&self) -> Address {
        self.signer.address_regtest()
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Emergency / explicit lock. Takes effect immediately, including for
    /// requests already authorized but not yet signed (AC-H).
    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// The single Bitcoin signing gate. Every precondition is re-checked here
    /// even if the pipeline already checked it — the Vault trusts nothing
    /// upstream.
    pub fn authorize_and_sign(
        &self,
        req: &BtcVaultSigningRequest,
    ) -> Result<BtcSignedTransaction, BtcVaultError> {
        if self.locked {
            return Err(BtcVaultError::Locked);
        }
        // Deterministic policy outcome is final: deny can never be signed.
        match req.policy_verdict {
            Verdict::Allow => {}
            Verdict::Escalate => {
                if !req.user_authorization.escalation_acknowledged {
                    return Err(BtcVaultError::EscalationNotAcknowledged);
                }
            }
            Verdict::Deny => return Err(BtcVaultError::PolicyDenied(req.policy_verdict)),
        }
        // Milestone-1 gate: development chains only (worthless value by design).
        if req.network_class != NetworkClass::Development {
            return Err(BtcVaultError::NonDevelopmentChain(req.network_class));
        }
        let mut tx: Transaction = encode::deserialize(&req.serialized_tx).map_err(|e| {
            BtcVaultError::UnsignableTransaction(format!(
                "not a well-formed Bitcoin transaction: {e}"
            ))
        })?;
        let vault_script = self.signer.address_regtest().script_pubkey();
        // Every input must spend one of the vault's own P2WPKH outputs — never
        // lend a signature to someone else's input, and never sign an input
        // whose prevout (which BIP-143 commits to) is missing or already
        // carries signature data we did not produce.
        if req.prevouts.len() != tx.input.len() {
            return Err(BtcVaultError::UnsignableTransaction(format!(
                "{} prevouts for {} inputs",
                req.prevouts.len(),
                tx.input.len()
            )));
        }
        for (i, (txin, prevout)) in tx.input.iter().zip(&req.prevouts).enumerate() {
            if prevout.script_pubkey != vault_script {
                return Err(BtcVaultError::UnsignableTransaction(format!(
                    "input {i} does not spend the vault's own P2WPKH output"
                )));
            }
            if !txin.script_sig.is_empty() || !txin.witness.is_empty() {
                return Err(BtcVaultError::UnsignableTransaction(format!(
                    "input {i} already carries signature data"
                )));
            }
        }
        // Value is decoded from the transaction itself — a declared amount
        // could lie. The spend amount is the sum of non-change outputs (an
        // output back to the vault's own script is change, not a spend).
        let sats = spend_sats(&tx, &vault_script)?;
        req.capability
            .validate_for_signing(Utc::now(), &req.account, req.chain_id, sats)?;
        let signer_address = self.signer.address_regtest().to_string();
        if req.account != signer_address {
            return Err(BtcVaultError::AccountMismatch {
                requested: req.account.clone(),
                actual: signer_address,
            });
        }

        // BIP-143 sighash per input, computed over the transaction and
        // prevouts validated above — the signed digest is derived here, in
        // place, so it cannot correspond to anything else.
        let sighash_type = EcdsaSighashType::All;
        let mut witnesses = Vec::with_capacity(tx.input.len());
        {
            let mut cache = SighashCache::new(&tx);
            for (i, prevout) in req.prevouts.iter().enumerate() {
                let sighash = cache
                    .p2wpkh_signature_hash(i, &prevout.script_pubkey, prevout.value, sighash_type)
                    .map_err(|e| BtcVaultError::Signer(e.to_string()))?;
                let digest = Message::from_digest(sighash.to_byte_array());
                let signature = self.signer.secp.sign_ecdsa(&digest, &self.signer.secret);
                // Self-check before release: the signature must verify
                // against the digest we just computed and the vault's key.
                self.signer
                    .secp
                    .verify_ecdsa(&digest, &signature, &self.signer.pubkey.0)
                    .map_err(|e| {
                        BtcVaultError::Signer(format!("produced signature failed self-check: {e}"))
                    })?;
                witnesses.push(Witness::p2wpkh(
                    &bitcoin::ecdsa::Signature {
                        signature,
                        sighash_type,
                    },
                    &self.signer.pubkey.0,
                ));
            }
        }
        for (txin, witness) in tx.input.iter_mut().zip(witnesses) {
            txin.witness = witness;
        }
        Ok(BtcSignedTransaction {
            raw: encode::serialize(&tx),
            txid: tx.compute_txid().to_string(),
        })
    }
}

/// Total sats sent to scripts other than the vault's own (i.e. the spend,
/// excluding change). Fully decodable by construction — `Transaction` outputs
/// are typed — but the sum still fails closed on overflow.
fn spend_sats(tx: &Transaction, vault_script: &ScriptBuf) -> Result<u64, BtcVaultError> {
    let mut total = Amount::ZERO;
    for out in &tx.output {
        if out.script_pubkey != *vault_script {
            total = total.checked_add(out.value).ok_or_else(|| {
                BtcVaultError::UnsignableTransaction("output sats total overflows".into())
            })?;
        }
    }
    Ok(total.to_sat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfirmationSurface;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Sequence, TxIn, Txid};

    const BTC_REGTEST: ChainId = ChainId(900002);
    const SPEND_SATS: u64 = 60_000;

    fn vault() -> BtcVault {
        BtcVault::new(BtcTestSigner::ephemeral())
    }

    fn other_address() -> Address {
        BtcTestSigner::ephemeral().address_regtest()
    }

    /// One 100_000-sat vault-owned input, SPEND_SATS to a stranger, change
    /// minus a 500-sat fee back to `from`.
    fn spend_from(from: &Address) -> (Vec<u8>, Vec<TxOut>) {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "1111111111111111111111111111111111111111111111111111111111111111",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(SPEND_SATS),
                    script_pubkey: other_address().script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(100_000 - SPEND_SATS - 500),
                    script_pubkey: from.script_pubkey(),
                },
            ],
        };
        let prevouts = vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: from.script_pubkey(),
        }];
        (encode::serialize(&tx), prevouts)
    }

    use std::str::FromStr;

    fn base_request(vault: &BtcVault) -> BtcVaultSigningRequest {
        let account = vault.address_regtest();
        let (serialized_tx, prevouts) = spend_from(&account);
        BtcVaultSigningRequest {
            signing_request_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            account: account.to_string(),
            chain_id: BTC_REGTEST,
            network_class: NetworkClass::Development,
            capability: BtcCapability::signing("cli:test", &account.to_string(), BTC_REGTEST, 60),
            policy_verdict: Verdict::Allow,
            user_authorization: UserAuthorization {
                decided_at: Utc::now(),
                surface: ConfirmationSurface::CliPrompt,
                escalation_acknowledged: false,
            },
            serialized_tx,
            prevouts,
        }
    }

    #[test]
    fn signs_a_verifiable_bitcoin_transaction() {
        let vault = vault();
        let req = base_request(&vault);
        let signed = vault.authorize_and_sign(&req).unwrap();
        assert!(!signed.raw.is_empty());
        // The signed bytes are a well-formed transaction whose BIP-143
        // signature verifies against the recomputed sighash.
        let tx: Transaction = encode::deserialize(&signed.raw).unwrap();
        assert_eq!(tx.compute_txid().to_string(), signed.txid);
        let secp = Secp256k1::new();
        let mut cache = SighashCache::new(&tx);
        for (i, prevout) in req.prevouts.iter().enumerate() {
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
            .expect("signature must verify");
            // The witness pubkey is the vault's key (matches the prevout).
            assert_eq!(
                Address::p2wpkh(&CompressedPublicKey(pk), Network::Regtest).script_pubkey(),
                prevout.script_pubkey
            );
        }
    }

    #[test]
    fn debug_output_redacts_key_material() {
        let vault = vault();
        let dbg = format!("{vault:?}");
        assert!(dbg.contains("<redacted>"));
        // The hex secret key must never appear in debug output.
        assert!(!dbg.contains(&vault.signer.secret.display_secret().to_string()));
    }

    #[test]
    fn locked_vault_refuses_signing() {
        let mut vault = vault();
        vault.lock();
        let req = base_request(&vault);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::Locked
        ));
        vault.unlock();
        assert!(vault.authorize_and_sign(&req).is_ok());
    }

    #[test]
    fn deny_verdict_can_never_be_signed() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.policy_verdict = Verdict::Deny;
        // Even with an "acknowledged" user authorization, deny is final.
        req.user_authorization.escalation_acknowledged = true;
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::PolicyDenied(_)
        ));
    }

    #[test]
    fn escalation_requires_acknowledgement() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.policy_verdict = Verdict::Escalate;
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::EscalationNotAcknowledged
        ));
        req.user_authorization.escalation_acknowledged = true;
        assert!(vault.authorize_and_sign(&req).is_ok());
    }

    #[test]
    fn non_development_chain_refused() {
        // A hypothetical Bitcoin mainnet registry entry must be refused by
        // class, exactly like EVM mainnet (T-09 / ADR-017).
        let vault = vault();
        let mut req = base_request(&vault);
        req.network_class = NetworkClass::Mainnet;
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::NonDevelopmentChain(NetworkClass::Mainnet)
        ));
    }

    #[test]
    fn expired_capability_rejected() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.capability.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::Capability(BtcCapabilityError::Expired(_))
        ));
    }

    #[test]
    fn capability_chain_scope_and_value_checks() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.capability.chain_id = ChainId(31337);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::Capability(BtcCapabilityError::WrongChain(_))
        ));

        let mut req2 = base_request(&vault);
        req2.capability.scope = CapabilityScope::ReadOnly;
        assert!(matches!(
            vault.authorize_and_sign(&req2).unwrap_err(),
            BtcVaultError::Capability(BtcCapabilityError::WrongScope(_))
        ));

        // The cap is enforced against the sats decoded from the transaction's
        // non-change outputs (SPEND_SATS), not any declared amount — change
        // back to the vault does not count against it.
        let mut req3 = base_request(&vault);
        req3.capability.max_sats_per_tx = Some(SPEND_SATS - 1);
        assert!(matches!(
            vault.authorize_and_sign(&req3).unwrap_err(),
            BtcVaultError::Capability(BtcCapabilityError::ValueExceedsCap {
                sats: SPEND_SATS,
                cap: _
            })
        ));
        let mut req4 = base_request(&vault);
        req4.capability.max_sats_per_tx = Some(SPEND_SATS);
        assert!(vault.authorize_and_sign(&req4).is_ok());
    }

    #[test]
    fn account_mismatch_rejected() {
        let vault = vault();
        let other = other_address();
        let mut req = base_request(&vault);
        req.account = other.to_string();
        req.capability = BtcCapability::signing("cli:test", &other.to_string(), BTC_REGTEST, 60);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::AccountMismatch { .. }
        ));
    }

    #[test]
    fn refuses_inputs_that_are_not_the_vaults_own() {
        // Request/capability name the vault's account, but the transaction
        // spends someone else's output: refuse to lend the signature.
        let vault = vault();
        let mut req = base_request(&vault);
        let (serialized_tx, prevouts) = spend_from(&other_address());
        req.serialized_tx = serialized_tx;
        req.prevouts = prevouts;
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::UnsignableTransaction(_)
        ));
    }

    #[test]
    fn refuses_prevout_count_mismatch_and_garbage() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.prevouts.clear();
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            BtcVaultError::UnsignableTransaction(_)
        ));

        // Garbage bytes are not a transaction at all — refuse anything the
        // vault cannot fully decode.
        let mut req2 = base_request(&vault);
        req2.serialized_tx = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(matches!(
            vault.authorize_and_sign(&req2).unwrap_err(),
            BtcVaultError::UnsignableTransaction(_)
        ));
    }
}
