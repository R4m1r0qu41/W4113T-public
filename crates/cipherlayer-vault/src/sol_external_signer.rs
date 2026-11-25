//! ADR-021: the Solana runtime-key external signer — **inside** the vault
//! process boundary.
//!
//! This module is the pure signing logic; `cipherlayer-vaultd` hosts the
//! human ceremony around it (facts + approval phrase + key paste on vaultd's
//! own `/dev/tty`). The CLI/console never constructs this type and never
//! sees the key in any form: it receives only the declared public key and
//! the signed artifact over the vault IPC (`vault-sol-signing.v1`).
//!
//! Two-phase, key-lifetime-minimal ceremony:
//! - **Phase 1** (`approve_facts`): the operator-entered facts (cluster,
//!   from, to, lamports, fee estimate) are approved with the chain-labeled
//!   phrase. A single in-flight approval is recorded with a nonce and a
//!   ~90 s expiry (the blockhash lifetime bound).
//! - **Phase 2** (`sign`): given the nonce and the adapter-built message,
//!   the module **independently re-decodes** the message and refuses any
//!   deviation from the approved facts; only then is the key parsed
//!   (base58 64-byte keypair, the Phantom/Solflare export shape),
//!   derivation-checked against the declared pubkey, used once, and wiped.
//!
//! Key-handling invariants (enforced in code):
//! - the key exists in memory for a single call: paste → derive-check →
//!   sign → drop; the input `String` and the decoded 64-byte buffer are
//!   zeroized before `sign` returns, success or failure;
//! - key material never appears in `Debug`, errors, or any return value
//!   (`MalformedKey` is a fixed string — the input is never echoed);
//! - each config permits exactly one cluster (devnet or mainnet-beta),
//!   pinned by genesis hash **referenced from `cipherlayer_chain`** — the
//!   single source; re-typed literals are a review-rejection criterion;
//! - approvals are single-use: any phase-2 attempt, successful or not,
//!   consumes the pending approval — a failed ceremony re-runs in full;
//! - fee evidence stays honest ("unknown stays unknown"): on mainnet a
//!   missing fee — estimate or final — refuses; a final fee above the
//!   approved estimate refuses (`FeeExceedsApproved`), never silently
//!   proceeds. Devnet may proceed on an unknown fee, displayed as such.

use chrono::{DateTime, Duration, Utc};
use cipherlayer_chain::{
    SOLANA_DEVNET_CHAIN_ID, SOLANA_DEVNET_GENESIS, SOLANA_MAINNET_CHAIN_ID, SOLANA_MAINNET_GENESIS,
};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer as _;
use solana_transaction::Transaction;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::sol::decode_system_transfers;

/// Chain-labeled approval phrases, typed on the vaultd terminal. The phrase
/// names the stakes: devnet muscle memory cannot authorize mainnet.
pub const SOLANA_DEVNET_APPROVAL_PHRASE: &str = "SEND-CIPHERLAYER-SOLANA-DEVNET";
pub const SOLANA_MAINNET_APPROVAL_PHRASE: &str = "SEND-CIPHERLAYER-SOLANA-MAINNET";

/// Approval lifetime — bounded by the blockhash validity window; an expired
/// approval means a full ceremony re-run, never a silent re-sign.
pub const APPROVAL_TTL_SECONDS: i64 = 90;

/// Config for one cluster. Two hardcoded constructors, each permitting
/// exactly one cluster; there is no "any cluster" mode (ADR-020 discipline
/// restated for Solana, ADR-021 §3).
#[derive(Debug, Clone)]
pub struct SolExternalSignerConfig {
    pub cluster_chain_id: u64,
    pub cluster_name: &'static str,
    /// Pinned genesis hash — referenced from `cipherlayer_chain`, never
    /// re-typed. vaultd/console re-verify it live against the RPC; this copy
    /// travels with the config so the ceremony can display it.
    pub expected_genesis_hash: &'static str,
    pub approval_phrase: &'static str,
    /// Mainnet tightens the fee rules: unknown fees refuse.
    pub is_mainnet: bool,
}

impl SolExternalSignerConfig {
    pub fn devnet() -> Self {
        Self {
            cluster_chain_id: SOLANA_DEVNET_CHAIN_ID,
            cluster_name: "Solana devnet",
            expected_genesis_hash: SOLANA_DEVNET_GENESIS,
            approval_phrase: SOLANA_DEVNET_APPROVAL_PHRASE,
            is_mainnet: false,
        }
    }

    /// Real SOL. Every other guard applies identically; what changes is the
    /// single permitted cluster, the phrase that names it, and the strict
    /// fee rule.
    pub fn mainnet() -> Self {
        Self {
            cluster_chain_id: SOLANA_MAINNET_CHAIN_ID,
            cluster_name: "Solana mainnet-beta",
            expected_genesis_hash: SOLANA_MAINNET_GENESIS,
            approval_phrase: SOLANA_MAINNET_APPROVAL_PHRASE,
            is_mainnet: true,
        }
    }
}

/// The facts the operator approves in phase 1. The signature is bound to
/// these — not to a byte blob; the blockhash is the only message field the
/// operator never vouches for, and it cannot redirect funds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolApprovedFacts {
    /// Base58 pubkey the key must derive to (fee payer, sender).
    pub from_pubkey: String,
    /// Base58 recipient.
    pub to_pubkey: String,
    pub lamports: u64,
    /// Authoritative pre-approval fee estimate (`getFeeForMessage`);
    /// `None` = unknown. Mainnet refuses to approve on unknown.
    pub fee_estimate_lamports: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SolApprovalTicket {
    pub nonce: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// What phase 2 returns to the console: public key, signature, and the
/// broadcastable artifact. Never key material.
#[derive(Debug, Clone)]
pub struct SolSignedArtifact {
    pub pubkey: String,
    pub signature: String,
    /// Bincode-serialized signed transaction, ready to broadcast.
    pub raw: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SolExternalSignerError {
    #[error("this signer refuses cluster {0}: this config only permits cluster {1}")]
    ClusterNotPermitted(u64, u64),
    #[error("approval phrase did not match — the ceremony was not approved")]
    PhraseMismatch,
    #[error("facts are invalid: {0}")]
    InvalidFacts(String),
    #[error("fee is unknown and this is mainnet — unknown is not evidence; refusing (ADR-021 §4)")]
    MainnetFeeUnknown,
    #[error("no approval is pending — run phase 1 (approve facts) first")]
    NoApprovalPending,
    #[error("the pending approval does not match this nonce — full ceremony re-run required")]
    NonceMismatch,
    #[error(
        "the approval expired ({APPROVAL_TTL_SECONDS}s bound) — full ceremony re-run required"
    )]
    ApprovalExpired,
    #[error("refusing to sign: {0}")]
    UnsignableMessage(String),
    #[error("message deviates from the approved facts: {0} — nothing was signed")]
    ApprovedFactsMismatch(String),
    #[error("final fee {final_fee} lamports exceeds the approved estimate {approved_estimate} — re-run the ceremony with the new number")]
    FeeExceedsApproved {
        final_fee: u64,
        approved_estimate: u64,
    },
    #[error("key material is malformed (length/charset) — refusing; the key was not printed")]
    MalformedKey,
    #[error("the supplied key derives to {derived}, not the declared address {expected}; the key was not used")]
    AddressMismatch { derived: String, expected: String },
    #[error("signer error: {0}")]
    Signer(String),
}

#[derive(Debug)]
struct PendingApproval {
    facts: SolApprovedFacts,
    nonce: Uuid,
    expires_at: DateTime<Utc>,
}

/// The two-phase ceremony engine. Hosting-agnostic: vaultd drives it from
/// its terminal; tests drive it with injected strings. Holds **no key
/// material ever** — the key enters and leaves inside a single `sign` call.
#[derive(Debug)]
pub struct SolExternalSigningCeremony {
    config: SolExternalSignerConfig,
    pending: Option<PendingApproval>,
}

impl SolExternalSigningCeremony {
    pub fn new(config: SolExternalSignerConfig) -> Self {
        Self {
            config,
            pending: None,
        }
    }

    pub fn config(&self) -> &SolExternalSignerConfig {
        &self.config
    }

    /// Drop any pending approval (cluster change, ceremony abort, vaultd
    /// shutdown). There is deliberately no way to resurrect one.
    pub fn reset(&mut self) {
        self.pending = None;
    }

    /// Phase 1 — approve facts. Starting a new approval always voids any
    /// previous one (single in-flight). The typed phrase must match the
    /// config's chain-labeled phrase exactly.
    pub fn approve_facts(
        &mut self,
        cluster_chain_id: u64,
        facts: SolApprovedFacts,
        typed_phrase: &str,
        now: DateTime<Utc>,
    ) -> Result<SolApprovalTicket, SolExternalSignerError> {
        // Any new attempt voids the previous approval, even if this one fails.
        self.pending = None;
        if cluster_chain_id != self.config.cluster_chain_id {
            return Err(SolExternalSignerError::ClusterNotPermitted(
                cluster_chain_id,
                self.config.cluster_chain_id,
            ));
        }
        if facts.from_pubkey.parse::<solana_pubkey::Pubkey>().is_err() {
            return Err(SolExternalSignerError::InvalidFacts(
                "from_pubkey is not a valid base58 pubkey".into(),
            ));
        }
        if facts.to_pubkey.parse::<solana_pubkey::Pubkey>().is_err() {
            return Err(SolExternalSignerError::InvalidFacts(
                "to_pubkey is not a valid base58 pubkey".into(),
            ));
        }
        if facts.lamports == 0 {
            return Err(SolExternalSignerError::InvalidFacts(
                "lamports must be non-zero".into(),
            ));
        }
        if self.config.is_mainnet && facts.fee_estimate_lamports.is_none() {
            return Err(SolExternalSignerError::MainnetFeeUnknown);
        }
        if typed_phrase.trim() != self.config.approval_phrase {
            return Err(SolExternalSignerError::PhraseMismatch);
        }
        let ticket = SolApprovalTicket {
            nonce: cipherlayer_types::new_id(),
            expires_at: now + Duration::seconds(APPROVAL_TTL_SECONDS),
        };
        self.pending = Some(PendingApproval {
            facts,
            nonce: ticket.nonce,
            expires_at: ticket.expires_at,
        });
        Ok(ticket)
    }

    /// Phase 2, part A — validate and consume the approval, WITHOUT touching
    /// a key. Everything an untrusted message could get wrong is checked
    /// here (ADR-021 §2: "vaultd verifies the nonce/expiry, independently
    /// re-decodes the message and refuses any deviation... enforces the fee
    /// rule. **Only then does it prompt for the key.**"). This method takes
    /// NO key argument by construction — the key cannot be involved in
    /// validation, and the host must not read it until this returns `Ok`.
    ///
    /// Single-use: the pending approval is consumed on ANY call (success or
    /// failure) — a failed ceremony re-runs in full.
    pub fn validate_and_consume(
        &mut self,
        nonce: Uuid,
        serialized_message: &[u8],
        final_fee_lamports: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<ValidatedSolSign, SolExternalSignerError> {
        // Single-use: taken (consumed) before any check can fail.
        let pending = self
            .pending
            .take()
            .ok_or(SolExternalSignerError::NoApprovalPending)?;
        if pending.nonce != nonce {
            return Err(SolExternalSignerError::NonceMismatch);
        }
        if now >= pending.expires_at {
            return Err(SolExternalSignerError::ApprovalExpired);
        }
        let facts = &pending.facts;

        let message: Message = bincode::deserialize(serialized_message).map_err(|e| {
            SolExternalSignerError::UnsignableMessage(format!(
                "not a well-formed Solana message: {e}"
            ))
        })?;
        if message.header.num_required_signatures != 1 {
            return Err(SolExternalSignerError::UnsignableMessage(format!(
                "message requires {} signatures; exactly 1 is signable",
                message.header.num_required_signatures
            )));
        }
        let fee_payer = message
            .account_keys
            .first()
            .map(|k| k.to_string())
            .unwrap_or_default();
        if fee_payer != facts.from_pubkey {
            return Err(SolExternalSignerError::ApprovedFactsMismatch(format!(
                "fee payer is {fee_payer}, approved sender is {}",
                facts.from_pubkey
            )));
        }
        let transfers =
            decode_system_transfers(&message).map_err(SolExternalSignerError::UnsignableMessage)?;
        if transfers.len() != 1 {
            return Err(SolExternalSignerError::UnsignableMessage(format!(
                "{} system transfers in message; exactly 1 is signable (ADR-021 scope)",
                transfers.len()
            )));
        }
        let t = &transfers[0];
        if t.to != facts.to_pubkey {
            return Err(SolExternalSignerError::ApprovedFactsMismatch(format!(
                "recipient is {}, approved recipient is {}",
                t.to, facts.to_pubkey
            )));
        }
        if t.lamports != facts.lamports {
            return Err(SolExternalSignerError::ApprovedFactsMismatch(format!(
                "amount is {} lamports, approved amount is {}",
                t.lamports, facts.lamports
            )));
        }

        // Fee rule (ADR-021 §4): unknown is not evidence on mainnet; a fee
        // above the approved estimate never proceeds silently.
        match (final_fee_lamports, facts.fee_estimate_lamports) {
            (None, _) if self.config.is_mainnet => {
                return Err(SolExternalSignerError::MainnetFeeUnknown)
            }
            (Some(f), Some(est)) if f > est => {
                return Err(SolExternalSignerError::FeeExceedsApproved {
                    final_fee: f,
                    approved_estimate: est,
                });
            }
            _ => {}
        }

        Ok(ValidatedSolSign {
            message,
            expected_from: facts.from_pubkey.clone(),
        })
    }

    /// Phase 2, part B — sign a validated message with the operator's key.
    /// Called only after `validate_and_consume` returns `Ok` (the key is
    /// read from the vaultd terminal in between, so it never enters memory
    /// for a ceremony that will be refused). The key input is wiped before
    /// this returns, success or failure. Associated function (no ceremony
    /// state): the validation already consumed the approval.
    pub fn sign_validated(
        validated: &ValidatedSolSign,
        key_input: &mut String,
    ) -> Result<SolSignedArtifact, SolExternalSignerError> {
        let result = Self::sign_validated_inner(validated, key_input);
        key_input.zeroize();
        result
    }

    fn sign_validated_inner(
        validated: &ValidatedSolSign,
        key_input: &str,
    ) -> Result<SolSignedArtifact, SolExternalSignerError> {
        let keypair = parse_keypair(key_input)?;
        let derived = keypair.pubkey().to_string();
        if derived != validated.expected_from {
            return Err(SolExternalSignerError::AddressMismatch {
                derived,
                expected: validated.expected_from.clone(),
            });
        }
        let message = validated.message.clone();
        let recent_blockhash =
            solana_message::Hash::new_from_array(message.recent_blockhash.to_bytes());
        let mut tx = Transaction::new_unsigned(message);
        tx.try_sign(&[&keypair], recent_blockhash)
            .map_err(|e| SolExternalSignerError::Signer(e.to_string()))?;
        // `keypair` (ed25519_dalek::SigningKey, zeroize-on-drop) drops at end
        // of scope.
        let signature = tx.signatures[0].to_string();
        let raw =
            bincode::serialize(&tx).map_err(|e| SolExternalSignerError::Signer(e.to_string()))?;
        Ok(SolSignedArtifact {
            pubkey: derived,
            signature,
            raw,
        })
    }

    /// Convenience all-in-one (validate → sign) for in-process callers that
    /// already hold the key (tests, the litesvm e2e). The host path
    /// (vaultd) does NOT use this — it calls `validate_and_consume` first
    /// and only reads the key on success (ADR-021 §2). The key input is
    /// wiped on every path.
    pub fn sign(
        &mut self,
        nonce: Uuid,
        serialized_message: &[u8],
        final_fee_lamports: Option<u64>,
        key_input: &mut String,
        now: DateTime<Utc>,
    ) -> Result<SolSignedArtifact, SolExternalSignerError> {
        match self.validate_and_consume(nonce, serialized_message, final_fee_lamports, now) {
            Ok(validated) => Self::sign_validated(&validated, key_input),
            Err(e) => {
                // The key was never used, but this method owns wiping its arg.
                key_input.zeroize();
                Err(e)
            }
        }
    }
}

/// A message that has passed every non-key validation gate and consumed its
/// approval. Opaque to the host: it carries the vetted message and the
/// public key the operator's key must derive to — no secret material.
#[derive(Debug, Clone)]
pub struct ValidatedSolSign {
    message: Message,
    expected_from: String,
}

/// Parse the base58-encoded 64-byte keypair string (Phantom/Solflare export
/// shape) through an owned, wiped buffer. The error carries a fixed message
/// — never any part of the input.
fn parse_keypair(key_input: &str) -> Result<Keypair, SolExternalSignerError> {
    let trimmed = key_input.trim();
    let mut buf = [0u8; 64];
    let decoded = five8::decode_64(trimmed, &mut buf);
    let result = match decoded {
        Ok(()) => Keypair::try_from(&buf[..]).map_err(|_| SolExternalSignerError::MalformedKey),
        Err(_) => Err(SolExternalSignerError::MalformedKey),
    };
    buf.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_pubkey::Pubkey;

    fn keypair() -> Keypair {
        Keypair::new()
    }

    fn key_string(kp: &Keypair) -> String {
        kp.to_base58_string()
    }

    fn facts_for(kp: &Keypair, to: &Pubkey, lamports: u64, fee: Option<u64>) -> SolApprovedFacts {
        SolApprovedFacts {
            from_pubkey: kp.pubkey().to_string(),
            to_pubkey: to.to_string(),
            lamports,
            fee_estimate_lamports: fee,
        }
    }

    fn transfer_message(from: &Pubkey, to: &Pubkey, lamports: u64) -> Vec<u8> {
        let ix = solana_system_interface::instruction::transfer(from, to, lamports);
        Message::new(&[ix], Some(from)).serialize()
    }

    fn approved(
        ceremony: &mut SolExternalSigningCeremony,
        facts: SolApprovedFacts,
    ) -> SolApprovalTicket {
        let cluster = ceremony.config().cluster_chain_id;
        let phrase = ceremony.config().approval_phrase;
        ceremony
            .approve_facts(cluster, facts, phrase, Utc::now())
            .expect("facts approve")
    }

    // --- phase 1 gates ----------------------------------------------------

    #[test]
    fn wrong_cluster_refused_before_anything_else() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::mainnet());
        // A mainnet ceremony refuses the devnet cluster id — and vice versa.
        let err = c
            .approve_facts(
                SOLANA_DEVNET_CHAIN_ID,
                facts_for(&kp, &to, 1_000, Some(5_000)),
                SOLANA_MAINNET_APPROVAL_PHRASE,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            SolExternalSignerError::ClusterNotPermitted(id, permitted)
                if id == SOLANA_DEVNET_CHAIN_ID && permitted == SOLANA_MAINNET_CHAIN_ID
        ));

        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        // The dev local validator (900001) is NOT this path either.
        let err = c
            .approve_facts(
                900_001,
                facts_for(&kp, &to, 1_000, None),
                SOLANA_DEVNET_APPROVAL_PHRASE,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            SolExternalSignerError::ClusterNotPermitted(900_001, _)
        ));
    }

    #[test]
    fn wrong_phrase_never_approves() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        for wrong in [
            "SEND-CIPHERLAYER-SOLANA-MAINET",  // typo
            "SEND-CIPHERLAYER-SOLANA-MAINNET", // other cluster's phrase
            "send-cipherlayer-solana-devnet",  // case
            "",                                // blank
        ] {
            let err = c
                .approve_facts(
                    SOLANA_DEVNET_CHAIN_ID,
                    facts_for(&kp, &to, 1_000, None),
                    wrong,
                    Utc::now(),
                )
                .unwrap_err();
            assert!(matches!(err, SolExternalSignerError::PhraseMismatch));
            // And nothing is pending afterwards.
            let mut key = key_string(&kp);
            assert!(matches!(
                c.sign(Uuid::new_v4(), &[], None, &mut key, Utc::now()),
                Err(SolExternalSignerError::NoApprovalPending)
            ));
        }
    }

    #[test]
    fn mainnet_refuses_unknown_fee_estimate_at_approval() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::mainnet());
        let err = c
            .approve_facts(
                SOLANA_MAINNET_CHAIN_ID,
                facts_for(&kp, &to, 1_000, None),
                SOLANA_MAINNET_APPROVAL_PHRASE,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, SolExternalSignerError::MainnetFeeUnknown));
    }

    #[test]
    fn garbage_facts_refused() {
        let kp = keypair();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let bad = SolApprovedFacts {
            from_pubkey: "not-base58!!".into(),
            to_pubkey: kp.pubkey().to_string(),
            lamports: 1,
            fee_estimate_lamports: None,
        };
        assert!(matches!(
            c.approve_facts(
                SOLANA_DEVNET_CHAIN_ID,
                bad,
                SOLANA_DEVNET_APPROVAL_PHRASE,
                Utc::now()
            ),
            Err(SolExternalSignerError::InvalidFacts(_))
        ));
        let zero = SolApprovedFacts {
            from_pubkey: kp.pubkey().to_string(),
            to_pubkey: kp.pubkey().to_string(),
            lamports: 0,
            fee_estimate_lamports: None,
        };
        assert!(matches!(
            c.approve_facts(
                SOLANA_DEVNET_CHAIN_ID,
                zero,
                SOLANA_DEVNET_APPROVAL_PHRASE,
                Utc::now()
            ),
            Err(SolExternalSignerError::InvalidFacts(_))
        ));
    }

    // --- phase 2 gates ----------------------------------------------------

    #[test]
    fn sign_without_approval_refused_and_nonce_must_match() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(Uuid::new_v4(), &[], None, &mut key, Utc::now()),
            Err(SolExternalSignerError::NoApprovalPending)
        ));

        let facts = facts_for(&kp, &to, 1_000, None);
        let _ticket = approved(&mut c, facts.clone());
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let mut key = key_string(&kp);
        // Wrong nonce refuses AND consumes the approval (single-use).
        assert!(matches!(
            c.sign(Uuid::new_v4(), &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::NonceMismatch)
        ));
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(Uuid::new_v4(), &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::NoApprovalPending)
        ));
    }

    #[test]
    fn expired_approval_refused() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let mut key = key_string(&kp);
        let late = Utc::now() + Duration::seconds(APPROVAL_TTL_SECONDS + 1);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, None, &mut key, late),
            Err(SolExternalSignerError::ApprovalExpired)
        ));
    }

    #[test]
    fn message_deviating_from_facts_is_refused() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let other = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());

        // Wrong recipient.
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&kp.pubkey(), &other, 1_000);
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::ApprovedFactsMismatch(_))
        ));

        // Wrong amount.
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&kp.pubkey(), &to, 2_000);
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::ApprovedFactsMismatch(_))
        ));

        // Wrong fee payer: message spends from someone else entirely.
        let stranger = keypair();
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&stranger.pubkey(), &to, 1_000);
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::ApprovedFactsMismatch(_))
        ));
    }

    #[test]
    fn non_transfer_multi_transfer_and_garbage_messages_refused() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());

        // Garbage bytes.
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &[0xde, 0xad], None, &mut key, Utc::now()),
            Err(SolExternalSignerError::UnsignableMessage(_))
        ));

        // Non-transfer instruction (create_account).
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let ix = solana_system_interface::instruction::create_account(
            &kp.pubkey(),
            &to,
            1_000,
            0,
            &solana_system_interface::program::ID,
        );
        let msg = Message::new(&[ix], Some(&kp.pubkey())).serialize();
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::UnsignableMessage(_))
        ));

        // Two transfers: individually fine, jointly out of ADR-021 scope.
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let ix1 = solana_system_interface::instruction::transfer(&kp.pubkey(), &to, 500);
        let ix2 = solana_system_interface::instruction::transfer(&kp.pubkey(), &to, 500);
        let msg = Message::new(&[ix1, ix2], Some(&kp.pubkey())).serialize();
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::UnsignableMessage(_))
        ));
    }

    #[test]
    fn fee_rules_mainnet_null_refuses_and_excess_refuses() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::mainnet());

        // Final fee unknown on mainnet → refuse (even with an approved estimate).
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, Some(5_000)));
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::MainnetFeeUnknown)
        ));

        // Final fee above the approved estimate → refuse with both numbers.
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, Some(5_000)));
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(ticket.nonce, &msg, Some(6_000), &mut key, Utc::now()),
            Err(SolExternalSignerError::FeeExceedsApproved {
                final_fee: 6_000,
                approved_estimate: 5_000
            })
        ));
    }

    #[test]
    fn devnet_may_proceed_on_unknown_fee() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let mut key = key_string(&kp);
        let signed = c
            .sign(ticket.nonce, &msg, None, &mut key, Utc::now())
            .expect("devnet signs with fee unknown");
        assert_eq!(signed.pubkey, kp.pubkey().to_string());
    }

    // --- key handling -----------------------------------------------------

    #[test]
    fn malformed_key_refused_and_error_never_echoes_input() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        for bad in ["", "hello", "0x1234", "!!!not-base58!!!"] {
            let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
            let msg = transfer_message(&kp.pubkey(), &to, 1_000);
            let mut key = bad.to_string();
            let err = c
                .sign(ticket.nonce, &msg, None, &mut key, Utc::now())
                .unwrap_err();
            assert!(matches!(err, SolExternalSignerError::MalformedKey));
            if !bad.is_empty() {
                assert!(
                    !err.to_string().contains(bad),
                    "error text must never echo key input"
                );
            }
            // The input buffer was wiped even on failure.
            assert!(key.is_empty(), "key input must be wiped on every path");
        }
    }

    #[test]
    fn wrong_derivation_refused_and_key_wiped() {
        let kp = keypair();
        let wrong = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let mut key = key_string(&wrong);
        let err = c
            .sign(ticket.nonce, &msg, None, &mut key, Utc::now())
            .unwrap_err();
        assert!(matches!(
            err,
            SolExternalSignerError::AddressMismatch { .. }
        ));
        assert!(key.is_empty());
    }

    #[test]
    fn key_input_wiped_on_success_too() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let mut key = key_string(&kp);
        c.sign(ticket.nonce, &msg, None, &mut key, Utc::now())
            .expect("signs");
        assert!(key.is_empty());
    }

    // --- happy paths ------------------------------------------------------

    #[test]
    fn happy_path_signs_a_verifiable_transaction_devnet_and_mainnet() {
        for config in [
            SolExternalSignerConfig::devnet(),
            SolExternalSignerConfig::mainnet(),
        ] {
            let kp = keypair();
            let to = Keypair::new().pubkey();
            let mut c = SolExternalSigningCeremony::new(config);
            let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, Some(5_000)));
            let msg = transfer_message(&kp.pubkey(), &to, 1_000);
            let mut key = key_string(&kp);
            let signed = c
                .sign(ticket.nonce, &msg, Some(5_000), &mut key, Utc::now())
                .expect("signs");
            assert_eq!(signed.pubkey, kp.pubkey().to_string());
            let tx: Transaction = bincode::deserialize(&signed.raw).unwrap();
            tx.verify().expect("ed25519 signature must verify");
            assert_eq!(tx.signatures[0].to_string(), signed.signature);
            // Approval was consumed by the successful sign.
            let ticket_gone = Uuid::new_v4();
            let mut key = key_string(&kp);
            assert!(matches!(
                c.sign(ticket_gone, &msg, None, &mut key, Utc::now()),
                Err(SolExternalSignerError::NoApprovalPending)
            ));
        }
    }

    #[test]
    fn second_approval_replaces_the_first() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let first = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let _second = approved(&mut c, facts_for(&kp, &to, 2_000, None));
        // The first ticket's nonce is dead.
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let mut key = key_string(&kp);
        assert!(matches!(
            c.sign(first.nonce, &msg, None, &mut key, Utc::now()),
            Err(SolExternalSignerError::NonceMismatch)
        ));
    }

    /// ADR-021 §2 ordering, proven structurally: validation takes NO key
    /// argument, so a doomed ceremony (bad facts / expired / wrong fee) is
    /// refused before any key could be involved — the vaultd host reads the
    /// key only after this returns Ok. A refused validation still consumes
    /// the approval (single-use).
    #[test]
    fn validation_needs_no_key_and_a_refusal_consumes_the_approval() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::mainnet());

        // Facts approved for `to`, but the message pays a different recipient.
        let other = Keypair::new().pubkey();
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, Some(5_000)));
        let msg = transfer_message(&kp.pubkey(), &other, 1_000);
        let err = c
            .validate_and_consume(ticket.nonce, &msg, Some(5_000), Utc::now())
            .unwrap_err();
        assert!(matches!(
            err,
            SolExternalSignerError::ApprovedFactsMismatch(_)
        ));
        // The approval was consumed by that failed validation — no key was
        // ever read, and a retry needs a fresh approval.
        let good = transfer_message(&kp.pubkey(), &to, 1_000);
        assert!(matches!(
            c.validate_and_consume(ticket.nonce, &good, Some(5_000), Utc::now()),
            Err(SolExternalSignerError::NoApprovalPending)
        ));
    }

    /// The two-step host path (validate → read key → sign_validated) produces
    /// the same verifiable signature as the all-in-one `sign`.
    #[test]
    fn validate_then_sign_validated_matches_all_in_one() {
        let kp = keypair();
        let to = Keypair::new().pubkey();
        let mut c = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
        let ticket = approved(&mut c, facts_for(&kp, &to, 1_000, None));
        let msg = transfer_message(&kp.pubkey(), &to, 1_000);
        let validated = c
            .validate_and_consume(ticket.nonce, &msg, None, Utc::now())
            .expect("validates");
        let mut key = key_string(&kp);
        let signed = SolExternalSigningCeremony::sign_validated(&validated, &mut key)
            .expect("signs the validated message");
        assert!(key.is_empty(), "key wiped by sign_validated");
        assert_eq!(signed.pubkey, kp.pubkey().to_string());
        let tx: Transaction = bincode::deserialize(&signed.raw).unwrap();
        tx.verify().expect("signature verifies");
    }

    #[test]
    fn debug_output_carries_no_key_and_genesis_pins_are_referenced() {
        let c = SolExternalSigningCeremony::new(SolExternalSignerConfig::mainnet());
        let dbg = format!("{c:?}");
        assert!(!dbg.to_lowercase().contains("secret"));
        // The pins come from cipherlayer-chain — the single source.
        assert_eq!(
            SolExternalSignerConfig::mainnet().expected_genesis_hash,
            cipherlayer_chain::SOLANA_MAINNET_GENESIS
        );
        assert_eq!(
            SolExternalSignerConfig::devnet().expected_genesis_hash,
            cipherlayer_chain::SOLANA_DEVNET_GENESIS
        );
    }
}
