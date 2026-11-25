//! End-to-end (ADR-016): adapter builds the unsigned message, the vault
//! signs it (ed25519, behind the vault boundary — the adapter never sees a
//! key), and the signed bytes execute in an in-process SVM.

use chrono::Utc;
use cipherlayer_chain::adapter::ChainBroadcaster;
use cipherlayer_policy::Verdict;
use cipherlayer_sol::{SolAdapter, SolBuildInput};
use cipherlayer_types::{ChainId, NetworkClass};
use cipherlayer_vault::sol::{SolCapability, SolTestSigner, SolVault, SolVaultSigningRequest};
use cipherlayer_vault::{ConfirmationSurface, UserAuthorization};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use uuid::Uuid;

const SOL_LOCAL: ChainId = ChainId(900001);
const TRANSFER_LAMPORTS: u64 = 1_000_000; // 0.001 SOL

#[tokio::test]
async fn build_sign_execute_transfers_lamports() {
    let mut svm = LiteSVM::new();
    let vault = SolVault::new(SolTestSigner::ephemeral());
    let from = vault.pubkey_base58();
    let to = Keypair::new().pubkey();
    svm.airdrop(&from.parse().unwrap(), 1_000_000_000).unwrap();

    // 1. Adapter builds the unsigned message (no RPC: blockhash supplied).
    let adapter = SolAdapter::new("http://127.0.0.1:1", None);
    let unsigned = adapter
        .build_unsigned(&SolBuildInput {
            from: from.parse().unwrap(),
            to,
            lamports: TRANSFER_LAMPORTS,
            recent_blockhash: Some(svm.latest_blockhash()),
        })
        .await
        .unwrap();

    // 2. Vault authorizes and signs the serialized message.
    let signed = vault
        .authorize_and_sign(&SolVaultSigningRequest {
            signing_request_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            account: from.clone(),
            chain_id: SOL_LOCAL,
            network_class: NetworkClass::Development,
            capability: SolCapability::signing("cli:test", &from, SOL_LOCAL, 60),
            policy_verdict: Verdict::Allow,
            user_authorization: UserAuthorization {
                decided_at: Utc::now(),
                surface: ConfirmationSurface::CliPrompt,
                escalation_acknowledged: false,
            },
            serialized_message: unsigned.serialize(),
        })
        .unwrap();

    // 3. The signed bytes execute in the SVM and move exactly the lamports.
    let tx: Transaction = bincode::deserialize(&signed.raw).unwrap();
    let before = svm.get_balance(&from.parse().unwrap()).unwrap();
    svm.send_transaction(tx).expect("transfer must execute");
    assert_eq!(svm.get_balance(&to).unwrap(), TRANSFER_LAMPORTS);
    let after = svm.get_balance(&from.parse().unwrap()).unwrap();
    // Sender paid the transfer plus a fee.
    assert!(after <= before - TRANSFER_LAMPORTS);
}

/// ADR-021 e2e: the runtime-key external-signer ceremony (facts approval →
/// adapter-built message → independent re-decode → key derive-guard →
/// sign → wipe) produces bytes that execute in a real SVM and move exactly
/// the approved lamports. The adapter never sees the key; the ceremony
/// engine holds it for a single call.
#[tokio::test]
async fn external_signer_ceremony_build_sign_execute() {
    use cipherlayer_vault::{
        SolApprovedFacts, SolExternalSignerConfig, SolExternalSigningCeremony,
    };

    let mut svm = LiteSVM::new();
    let operator_key = Keypair::new();
    let from = operator_key.pubkey();
    let to = Keypair::new().pubkey();
    svm.airdrop(&from, 1_000_000_000).unwrap();

    // Phase 1: approve the facts with the chain-labeled phrase (devnet
    // config — the pinned-genesis identity check is the console's live RPC
    // step, out of scope in-process).
    let mut ceremony = SolExternalSigningCeremony::new(SolExternalSignerConfig::devnet());
    let facts = SolApprovedFacts {
        from_pubkey: from.to_string(),
        to_pubkey: to.to_string(),
        lamports: TRANSFER_LAMPORTS,
        fee_estimate_lamports: Some(5_000),
    };
    let ticket = ceremony
        .approve_facts(
            cipherlayer_chain::SOLANA_DEVNET_CHAIN_ID,
            facts,
            cipherlayer_vault::sol_external_signer::SOLANA_DEVNET_APPROVAL_PHRASE,
            Utc::now(),
        )
        .expect("facts approve");

    // Build AFTER approval with a fresh blockhash (ADR-021 §2).
    let adapter = SolAdapter::new("http://127.0.0.1:1", None);
    let unsigned = adapter
        .build_unsigned(&SolBuildInput {
            from,
            to,
            lamports: TRANSFER_LAMPORTS,
            recent_blockhash: Some(svm.latest_blockhash()),
        })
        .await
        .unwrap();

    // Phase 2: key enters for a single call and is wiped.
    let mut key = operator_key.to_base58_string();
    let signed = ceremony
        .sign(
            ticket.nonce,
            &unsigned.serialize(),
            Some(5_000),
            &mut key,
            Utc::now(),
        )
        .expect("ceremony signs");
    assert!(key.is_empty(), "key input wiped after signing");
    assert_eq!(signed.pubkey, from.to_string());

    // The signed bytes execute and move exactly the approved lamports.
    let tx: Transaction = bincode::deserialize(&signed.raw).unwrap();
    let before = svm.get_balance(&from).unwrap();
    svm.send_transaction(tx).expect("transfer must execute");
    assert_eq!(svm.get_balance(&to).unwrap(), TRANSFER_LAMPORTS);
    assert!(svm.get_balance(&from).unwrap() <= before - TRANSFER_LAMPORTS);
}
