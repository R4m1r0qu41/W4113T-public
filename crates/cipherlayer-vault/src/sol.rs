//! Solana ed25519 signing (ADR-016). Mirrors the ECDSA `Vault`: same lock
//! semantics, policy-verdict finality, development-only network gate, and
//! capability re-validation — the Vault trusts nothing upstream.
//!
//! Boundaries, labeled per BP §4.12:
//! - MOCKED custody: `SolTestSigner` holds an ephemeral, test-generated
//!   ed25519 keypair. There is no secure storage; nothing persists.
//! - Key material never leaves this module: no accessor, no serialization,
//!   and `Debug` output is redacted.
//!
//! The vault signs a *serialized message* built by the adapter
//! (`cipherlayer-sol`); the adapter never sees a key. Only system-program
//! transfers are signable: any other instruction fails closed, and the
//! capability's value cap is enforced against the lamports decoded from the
//! message itself, never against a caller-declared amount.

use chrono::{DateTime, Utc};
use cipherlayer_policy::Verdict;
use cipherlayer_types::{ChainId, NetworkClass};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer as _;
use solana_system_interface::instruction::SystemInstruction;
use solana_transaction::Transaction;
use uuid::Uuid;

use crate::{CapabilityScope, UserAuthorization};

// ---------------------------------------------------------------------------
// Capability (Solana flavor: base58 account, lamports value cap)
// ---------------------------------------------------------------------------

/// Signing capability scoped to a Solana account (base58 pubkey) and chain.
/// Mirrors `Capability` (wallet-capability.v1) with lamports as the value
/// unit — 1 SOL = 10^9 lamports.
#[derive(Debug, Clone)]
pub struct SolCapability {
    pub capability_id: Uuid,
    pub subject: String,
    /// Base58 pubkey the capability covers.
    pub account: String,
    pub chain_id: ChainId,
    pub scope: CapabilityScope,
    pub max_lamports_per_tx: Option<u64>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub requires_user_confirmation: bool,
}

impl SolCapability {
    /// Narrow signing capability for the local CLI user.
    pub fn signing(subject: &str, account: &str, chain_id: ChainId, ttl_minutes: i64) -> Self {
        let now = Utc::now();
        SolCapability {
            capability_id: cipherlayer_types::new_id(),
            subject: subject.to_string(),
            account: account.to_string(),
            chain_id,
            scope: CapabilityScope::SignTransactions,
            max_lamports_per_tx: None,
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
        lamports: u64,
    ) -> Result<(), SolCapabilityError> {
        if self.revoked_at.is_some() {
            return Err(SolCapabilityError::Revoked(self.capability_id));
        }
        if now >= self.expires_at {
            return Err(SolCapabilityError::Expired(self.capability_id));
        }
        if self.account != account {
            return Err(SolCapabilityError::WrongAccount(account.to_string()));
        }
        if self.chain_id != chain_id {
            return Err(SolCapabilityError::WrongChain(chain_id));
        }
        if self.scope != CapabilityScope::SignTransactions {
            return Err(SolCapabilityError::WrongScope(self.scope));
        }
        if let Some(cap) = self.max_lamports_per_tx {
            if lamports > cap {
                return Err(SolCapabilityError::ValueExceedsCap { lamports, cap });
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SolCapabilityError {
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
    #[error(
        "value {lamports} lamports exceeds the capability's per-transaction cap {cap} lamports"
    )]
    ValueExceedsCap { lamports: u64, cap: u64 },
}

// ---------------------------------------------------------------------------
// Signing request / signed artifact
// ---------------------------------------------------------------------------

/// The only message that can ask the Vault for a Solana signature. The
/// transaction content is the serialized message the adapter built; the
/// vault re-derives the transfer amount from it rather than trusting a
/// declared value.
#[derive(Debug, Clone)]
pub struct SolVaultSigningRequest {
    pub signing_request_id: Uuid,
    pub request_id: Uuid,
    /// Base58 pubkey expected to sign (fee payer).
    pub account: String,
    pub chain_id: ChainId,
    pub network_class: NetworkClass,
    pub capability: SolCapability,
    pub policy_verdict: Verdict,
    pub user_authorization: UserAuthorization,
    /// `Message::serialize()` output from the adapter.
    pub serialized_message: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SolSignedTransaction {
    /// Bincode-serialized signed transaction, ready to broadcast.
    pub raw: Vec<u8>,
    /// Base58 transaction signature (the chain-native tx reference).
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SolVaultError {
    #[error("vault is locked — emergency or explicit lock is in effect")]
    Locked,
    #[error("capability check failed: {0}")]
    Capability(#[from] SolCapabilityError),
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
    UnsignableMessage(String),
    #[error("signer error: {0}")]
    Signer(String),
}

// ---------------------------------------------------------------------------
// Test signer — MOCKED custody. Keys never leave this struct.
// ---------------------------------------------------------------------------

/// MOCKED: in-memory ed25519 signer over an ephemeral test keypair. This is
/// not a custody mechanism; it exists so the pipeline can produce real
/// ed25519 signatures on a worthless local validator (ADR-016).
pub struct SolTestSigner {
    keypair: Keypair,
}

impl std::fmt::Debug for SolTestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material is never printed.
        f.debug_struct("SolTestSigner")
            .field("pubkey", &self.keypair.pubkey())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SolTestSigner {
    /// Freshly generated ephemeral test keypair (nothing persists).
    pub fn ephemeral() -> Self {
        Self {
            keypair: Keypair::new(),
        }
    }

    /// Base58 public key — the only thing this signer ever exposes.
    pub fn pubkey_base58(&self) -> String {
        self.keypair.pubkey().to_string()
    }
}

// ---------------------------------------------------------------------------
// The Solana vault
// ---------------------------------------------------------------------------

pub struct SolVault {
    signer: SolTestSigner,
    locked: bool,
}

impl std::fmt::Debug for SolVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolVault")
            .field("signer", &self.signer)
            .field("locked", &self.locked)
            .finish()
    }
}

impl SolVault {
    pub fn new(signer: SolTestSigner) -> Self {
        Self {
            signer,
            locked: false,
        }
    }

    pub fn pubkey_base58(&self) -> String {
        self.signer.pubkey_base58()
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

    /// The single Solana signing gate. Every precondition is re-checked here
    /// even if the pipeline already checked it — the Vault trusts nothing
    /// upstream.
    pub fn authorize_and_sign(
        &self,
        req: &SolVaultSigningRequest,
    ) -> Result<SolSignedTransaction, SolVaultError> {
        if self.locked {
            return Err(SolVaultError::Locked);
        }
        // Deterministic policy outcome is final: deny can never be signed.
        match req.policy_verdict {
            Verdict::Allow => {}
            Verdict::Escalate => {
                if !req.user_authorization.escalation_acknowledged {
                    return Err(SolVaultError::EscalationNotAcknowledged);
                }
            }
            Verdict::Deny => return Err(SolVaultError::PolicyDenied(req.policy_verdict)),
        }
        // Milestone-1 gate: development chains only (worthless value by design).
        if req.network_class != NetworkClass::Development {
            return Err(SolVaultError::NonDevelopmentChain(req.network_class));
        }
        let message: Message = bincode::deserialize(&req.serialized_message).map_err(|e| {
            SolVaultError::UnsignableMessage(format!("not a well-formed Solana message: {e}"))
        })?;
        // Value is decoded from the message itself — a declared amount could
        // lie. Non-transfer instructions fail closed.
        let lamports = transfer_lamports(&message)?;
        req.capability
            .validate_for_signing(Utc::now(), &req.account, req.chain_id, lamports)?;
        let signer_pubkey = self.signer.pubkey_base58();
        if req.account != signer_pubkey {
            return Err(SolVaultError::AccountMismatch {
                requested: req.account.clone(),
                actual: signer_pubkey,
            });
        }
        // The fee payer (first required signer) must be the vault's key —
        // never lend a signature to a message that spends from someone else.
        if message.account_keys.first().map(|k| k.to_string()) != Some(signer_pubkey) {
            return Err(SolVaultError::UnsignableMessage(
                "message fee payer is not the vault signer".into(),
            ));
        }

        // Byte-copy the blockhash: `Hash` is only `Copy` under some feature
        // unions, and the message is moved into the transaction next.
        let recent_blockhash =
            solana_message::Hash::new_from_array(message.recent_blockhash.to_bytes());
        let mut tx = Transaction::new_unsigned(message);
        tx.try_sign(&[&self.signer.keypair], recent_blockhash)
            .map_err(|e| SolVaultError::Signer(e.to_string()))?;
        let signature = tx.signatures[0].to_string();
        let raw = bincode::serialize(&tx).map_err(|e| SolVaultError::Signer(e.to_string()))?;
        Ok(SolSignedTransaction { raw, signature })
    }
}

/// One decoded system-program `Transfer`: the recipient (base58) and amount.
/// Shared between `SolVault` (dev custody) and the ADR-021 external signer so
/// the two decode paths cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSolTransfer {
    pub to: String,
    pub lamports: u64,
}

/// Decode every instruction of `message` as a system-program `Transfer`, or
/// refuse. Any instruction that is anything else makes the message
/// unsignable — fail closed, never "probably fine". Returns the transfers in
/// instruction order; policy over the list (sum vs. exactly-one) belongs to
/// the caller.
pub(crate) fn decode_system_transfers(
    message: &Message,
) -> Result<Vec<DecodedSolTransfer>, String> {
    let mut transfers = Vec::with_capacity(message.instructions.len());
    for (i, ix) in message.instructions.iter().enumerate() {
        let program_id = message
            .account_keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| format!("instruction {i} references a program id out of bounds"))?;
        if *program_id != solana_system_interface::program::ID {
            return Err(format!(
                "instruction {i} targets program {program_id}; only system transfers are signable"
            ));
        }
        match bincode::deserialize::<SystemInstruction>(&ix.data) {
            Ok(SystemInstruction::Transfer { lamports }) => {
                // Transfer account order is [from, to]; indices point into
                // account_keys.
                let to_index = *ix
                    .accounts
                    .get(1)
                    .ok_or_else(|| format!("instruction {i} transfer has no recipient account"))?;
                let to = message
                    .account_keys
                    .get(to_index as usize)
                    .ok_or_else(|| format!("instruction {i} recipient index is out of bounds"))?
                    .to_string();
                transfers.push(DecodedSolTransfer { to, lamports });
            }
            _ => {
                return Err(format!("instruction {i} is not a system transfer"));
            }
        }
    }
    Ok(transfers)
}

/// Total lamports moved by the message's system-program transfer
/// instructions (the dev vault's policy: sum across instructions, enforced
/// against the capability cap).
fn transfer_lamports(message: &Message) -> Result<u64, SolVaultError> {
    let transfers = decode_system_transfers(message).map_err(SolVaultError::UnsignableMessage)?;
    let mut total: u64 = 0;
    for t in &transfers {
        total = total
            .checked_add(t.lamports)
            .ok_or_else(|| SolVaultError::UnsignableMessage("lamports total overflows".into()))?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfirmationSurface;
    use solana_pubkey::Pubkey;

    const SOL_LOCAL: ChainId = ChainId(900001);

    fn vault() -> SolVault {
        SolVault::new(SolTestSigner::ephemeral())
    }

    fn transfer_message(from_base58: &str, lamports: u64) -> Vec<u8> {
        let from: Pubkey = from_base58.parse().unwrap();
        let to = Keypair::new().pubkey();
        let ix = solana_system_interface::instruction::transfer(&from, &to, lamports);
        Message::new(&[ix], Some(&from)).serialize()
    }

    fn base_request(vault: &SolVault) -> SolVaultSigningRequest {
        let account = vault.pubkey_base58();
        SolVaultSigningRequest {
            signing_request_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            account: account.clone(),
            chain_id: SOL_LOCAL,
            network_class: NetworkClass::Development,
            capability: SolCapability::signing("cli:test", &account, SOL_LOCAL, 60),
            policy_verdict: Verdict::Allow,
            user_authorization: UserAuthorization {
                decided_at: Utc::now(),
                surface: ConfirmationSurface::CliPrompt,
                escalation_acknowledged: false,
            },
            serialized_message: transfer_message(&account, 1_000),
        }
    }

    #[test]
    fn signs_a_verifiable_solana_transaction() {
        let vault = vault();
        let req = base_request(&vault);
        let signed = vault.authorize_and_sign(&req).unwrap();
        assert!(!signed.raw.is_empty());
        // The signed bytes are a well-formed transaction whose ed25519
        // signature verifies against the message.
        let tx: Transaction = bincode::deserialize(&signed.raw).unwrap();
        tx.verify().expect("signature must verify");
        assert_eq!(tx.signatures[0].to_string(), signed.signature);
    }

    #[test]
    fn debug_output_redacts_key_material() {
        let vault = vault();
        let dbg = format!("{vault:?}");
        assert!(dbg.contains("<redacted>"));
        // The base58 secret key must never appear in debug output.
        assert!(!dbg.contains(&vault.signer.keypair.to_base58_string()));
    }

    #[test]
    fn locked_vault_refuses_signing() {
        let mut vault = vault();
        vault.lock();
        let req = base_request(&vault);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::Locked
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
            SolVaultError::PolicyDenied(_)
        ));
    }

    #[test]
    fn escalation_requires_acknowledgement() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.policy_verdict = Verdict::Escalate;
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::EscalationNotAcknowledged
        ));
        req.user_authorization.escalation_acknowledged = true;
        assert!(vault.authorize_and_sign(&req).is_ok());
    }

    #[test]
    fn non_development_chain_refused() {
        // A hypothetical Solana mainnet registry entry must be refused by
        // class, exactly like EVM mainnet (T-09 / ADR-016).
        let vault = vault();
        let mut req = base_request(&vault);
        req.network_class = NetworkClass::Mainnet;
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::NonDevelopmentChain(NetworkClass::Mainnet)
        ));
    }

    #[test]
    fn expired_capability_rejected() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.capability.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::Capability(SolCapabilityError::Expired(_))
        ));
    }

    #[test]
    fn capability_chain_scope_and_value_checks() {
        let vault = vault();
        let mut req = base_request(&vault);
        req.capability.chain_id = ChainId(31337);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::Capability(SolCapabilityError::WrongChain(_))
        ));

        let mut req2 = base_request(&vault);
        req2.capability.scope = CapabilityScope::ReadOnly;
        assert!(matches!(
            vault.authorize_and_sign(&req2).unwrap_err(),
            SolVaultError::Capability(SolCapabilityError::WrongScope(_))
        ));

        // The cap is enforced against lamports decoded from the message
        // (1_000), not any declared amount.
        let mut req3 = base_request(&vault);
        req3.capability.max_lamports_per_tx = Some(999);
        assert!(matches!(
            vault.authorize_and_sign(&req3).unwrap_err(),
            SolVaultError::Capability(SolCapabilityError::ValueExceedsCap {
                lamports: 1_000,
                cap: 999
            })
        ));
    }

    #[test]
    fn account_mismatch_rejected() {
        let vault = vault();
        let other = Keypair::new().pubkey().to_string();
        let mut req = base_request(&vault);
        req.account = other.clone();
        req.capability = SolCapability::signing("cli:test", &other, SOL_LOCAL, 60);
        req.serialized_message = transfer_message(&other, 1_000);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::AccountMismatch { .. }
        ));
    }

    #[test]
    fn fee_payer_must_be_the_vault_signer() {
        // Request/capability name the vault's account, but the message
        // spends from someone else: refuse to lend the signature.
        let vault = vault();
        let mut req = base_request(&vault);
        req.serialized_message = transfer_message(&Keypair::new().pubkey().to_string(), 1_000);
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::UnsignableMessage(_)
        ));
    }

    #[test]
    fn non_transfer_instructions_fail_closed() {
        let vault = vault();
        let mut req = base_request(&vault);
        let from: Pubkey = vault.pubkey_base58().parse().unwrap();
        // A system-program instruction that is NOT a transfer.
        let ix = solana_system_interface::instruction::create_account(
            &from,
            &Keypair::new().pubkey(),
            1,
            0,
            &solana_system_interface::program::ID,
        );
        req.serialized_message = Message::new(&[ix], Some(&from)).serialize();
        assert!(matches!(
            vault.authorize_and_sign(&req).unwrap_err(),
            SolVaultError::UnsignableMessage(_)
        ));

        // Garbage bytes are not a message at all.
        let mut req2 = base_request(&vault);
        req2.serialized_message = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(matches!(
            vault.authorize_and_sign(&req2).unwrap_err(),
            SolVaultError::UnsignableMessage(_)
        ));
    }
}
