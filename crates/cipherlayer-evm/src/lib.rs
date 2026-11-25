//! Deterministic EVM calldata decoding and approval/permit detection.
//!
//! Coverage is deliberately narrow: ERC-20 approve / transfer / transferFrom /
//! increaseAllowance, EIP-2612 permit, ERC-721/1155 setApprovalForAll, and the
//! ERC-721 safeTransferFrom variants (CL-EVM-001/002/007). Everything else
//! decodes to `Unknown` with the raw selector preserved — the decoder never
//! guesses (CL-EVM-005), and consumers must treat `Unknown` restrictively.

pub mod adapter;
pub mod typed_data;

use cipherlayer_types::{Address, Confidence, U256};
use serde::{Deserialize, Serialize};

pub const SELECTOR_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
pub const SELECTOR_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
pub const SELECTOR_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom(address,address,uint256)
pub const SELECTOR_PERMIT: [u8; 4] = [0xd5, 0x05, 0xac, 0xcf]; // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
pub const SELECTOR_SET_APPROVAL_FOR_ALL: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65]; // setApprovalForAll(address,bool) — ERC-721/1155
pub const SELECTOR_INCREASE_ALLOWANCE: [u8; 4] = [0x39, 0x50, 0x93, 0x51]; // increaseAllowance(address,uint256) — OZ extension
pub const SELECTOR_SAFE_TRANSFER_FROM: [u8; 4] = [0x42, 0x84, 0x2e, 0x0e]; // safeTransferFrom(address,address,uint256) — ERC-721
pub const SELECTOR_SAFE_TRANSFER_FROM_DATA: [u8; 4] = [0xb8, 0x8d, 0x4f, 0xde]; // safeTransferFrom(address,address,uint256,bytes) — ERC-721

// Known selector collisions, stated honestly: ERC-721 `approve(address,uint256)`
// and `transferFrom(address,address,uint256)` share selectors with their ERC-20
// namesakes (identical signatures). Without contract introspection the decoder
// cannot tell tokenId from amount; the intent records the ERC-20 reading and
// the collision in `unresolved_fields`, and simulation evidence disambiguates
// (an ERC-721 shows no allowance/balance-amount diffs).

/// An allowance counts as "unlimited" when it is at or above 2^255 (or exactly
/// U256::MAX). Bounded-but-huge approvals are handled separately by the policy
/// escalation threshold — this constant only captures "effectively unbounded".
pub fn is_unlimited_amount(amount: U256) -> bool {
    amount == U256::MAX || amount >= (U256::from(1u8) << 255)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    NativeTransfer,
    Erc20Transfer,
    Erc20TransferFrom,
    Erc20Approve,
    /// OZ `increaseAllowance` — approval-family; resulting total is unresolved.
    Erc20IncreaseAllowance,
    /// ERC-721 `safeTransferFrom` variants.
    Erc721Transfer,
    /// ERC-721/1155 `setApprovalForAll` — blanket operator grant/revocation.
    SetApprovalForAll,
    Permit,
    ContractCall,
    ContractCreation,
    TypedDataSign,
    PersonalSign,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowanceKind {
    Exact,
    Unlimited,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedAllowance {
    pub kind: AllowanceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<U256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Address>,
}

/// Result of deterministic calldata decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decoded {
    pub kind: ActionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spender: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<U256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowance: Option<DecodedAllowance>,
    /// Field names the decoder could not resolve — surfaced, never hidden.
    pub unresolved_fields: Vec<String>,
    pub confidence: Confidence,
}

impl Decoded {
    fn unknown(selector: Option<[u8; 4]>, unresolved: &str) -> Self {
        Decoded {
            kind: ActionKind::Unknown,
            selector: selector.map(|s| format!("0x{}", hex::encode(s))),
            function_signature: None,
            spender: None,
            recipient: None,
            amount: None,
            allowance: None,
            unresolved_fields: vec![unresolved.to_string()],
            confidence: Confidence::Unknown,
        }
    }
}

fn word(data: &[u8], index: usize) -> Option<&[u8]> {
    let start = 4 + index * 32;
    data.get(start..start + 32)
}

fn word_address(data: &[u8], index: usize) -> Option<Address> {
    let w = word(data, index)?;
    // ABI-encoded addresses are left-padded with 12 zero bytes; nonzero
    // padding means this is not a well-formed address argument.
    if w[..12].iter().any(|b| *b != 0) {
        return None;
    }
    Some(Address::from_slice(&w[12..]))
}

fn word_u256(data: &[u8], index: usize) -> Option<U256> {
    word(data, index).map(U256::from_be_slice)
}

/// Decode an EVM transaction's calldata deterministically.
///
/// `to == None` means contract creation. Undecodable input yields
/// `ActionKind::Unknown`, never a guess.
pub fn decode_calldata(to: Option<Address>, value: U256, data: &[u8]) -> Decoded {
    if to.is_none() {
        return Decoded {
            kind: ActionKind::ContractCreation,
            selector: None,
            function_signature: None,
            spender: None,
            recipient: None,
            amount: None,
            allowance: None,
            unresolved_fields: vec!["deployed_code_behavior".into()],
            confidence: Confidence::High,
        };
    }
    if data.is_empty() {
        return Decoded {
            kind: ActionKind::NativeTransfer,
            selector: None,
            function_signature: None,
            spender: None,
            recipient: to,
            amount: Some(value),
            allowance: None,
            unresolved_fields: vec![],
            confidence: Confidence::Exact,
        };
    }
    if data.len() < 4 {
        return Decoded::unknown(None, "calldata_shorter_than_selector");
    }
    let selector: [u8; 4] = data[..4].try_into().expect("length checked");
    let args_ok = |n: usize| data.len() == 4 + 32 * n;

    match selector {
        SELECTOR_APPROVE => {
            if !args_ok(2) {
                return Decoded::unknown(Some(selector), "truncated_or_padded_approve_calldata");
            }
            match (word_address(data, 0), word_u256(data, 1)) {
                (Some(spender), Some(amount)) => Decoded {
                    kind: ActionKind::Erc20Approve,
                    selector: Some(format!("0x{}", hex::encode(selector))),
                    function_signature: Some("approve(address,uint256)".into()),
                    spender: Some(spender),
                    recipient: None,
                    amount: Some(amount),
                    allowance: Some(DecodedAllowance {
                        kind: if is_unlimited_amount(amount) {
                            AllowanceKind::Unlimited
                        } else {
                            AllowanceKind::Exact
                        },
                        amount: Some(amount),
                        token: to,
                    }),
                    // ERC-721 approve(address,uint256) shares this selector;
                    // without introspection the uint256 could be a tokenId.
                    unresolved_fields: vec!["erc721_approve_selector_collision".into()],
                    confidence: Confidence::Exact,
                },
                _ => Decoded::unknown(Some(selector), "malformed_approve_arguments"),
            }
        }
        SELECTOR_TRANSFER => {
            if !args_ok(2) {
                return Decoded::unknown(Some(selector), "truncated_or_padded_transfer_calldata");
            }
            match (word_address(data, 0), word_u256(data, 1)) {
                (Some(recipient), Some(amount)) => Decoded {
                    kind: ActionKind::Erc20Transfer,
                    selector: Some(format!("0x{}", hex::encode(selector))),
                    function_signature: Some("transfer(address,uint256)".into()),
                    spender: None,
                    recipient: Some(recipient),
                    amount: Some(amount),
                    allowance: None,
                    unresolved_fields: vec![],
                    confidence: Confidence::Exact,
                },
                _ => Decoded::unknown(Some(selector), "malformed_transfer_arguments"),
            }
        }
        SELECTOR_TRANSFER_FROM => {
            if !args_ok(3) {
                return Decoded::unknown(
                    Some(selector),
                    "truncated_or_padded_transfer_from_calldata",
                );
            }
            match (
                word_address(data, 0),
                word_address(data, 1),
                word_u256(data, 2),
            ) {
                (Some(_from), Some(recipient), Some(amount)) => Decoded {
                    kind: ActionKind::Erc20TransferFrom,
                    selector: Some(format!("0x{}", hex::encode(selector))),
                    function_signature: Some("transferFrom(address,address,uint256)".into()),
                    spender: None,
                    recipient: Some(recipient),
                    amount: Some(amount),
                    allowance: None,
                    // ERC-721 transferFrom shares this selector (uint256 may be a tokenId).
                    unresolved_fields: vec!["erc721_transfer_from_selector_collision".into()],
                    confidence: Confidence::Exact,
                },
                _ => Decoded::unknown(Some(selector), "malformed_transfer_from_arguments"),
            }
        }
        SELECTOR_PERMIT => {
            if !args_ok(7) {
                return Decoded::unknown(Some(selector), "truncated_or_padded_permit_calldata");
            }
            match (word_address(data, 1), word_u256(data, 2)) {
                (Some(spender), Some(amount)) => Decoded {
                    kind: ActionKind::Permit,
                    selector: Some(format!("0x{}", hex::encode(selector))),
                    function_signature: Some(
                        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)".into(),
                    ),
                    spender: Some(spender),
                    recipient: None,
                    amount: Some(amount),
                    allowance: Some(DecodedAllowance {
                        kind: if is_unlimited_amount(amount) {
                            AllowanceKind::Unlimited
                        } else {
                            AllowanceKind::Exact
                        },
                        amount: Some(amount),
                        token: to,
                    }),
                    unresolved_fields: vec!["permit_deadline_and_signature_validity".into()],
                    confidence: Confidence::High,
                },
                _ => Decoded::unknown(Some(selector), "malformed_permit_arguments"),
            }
        }
        SELECTOR_SET_APPROVAL_FOR_ALL => {
            if !args_ok(2) {
                return Decoded::unknown(
                    Some(selector),
                    "truncated_or_padded_set_approval_for_all",
                );
            }
            let operator = word_address(data, 0);
            let flag_word = word_u256(data, 1);
            match (operator, flag_word) {
                (Some(operator), Some(flag)) if flag <= U256::from(1u8) => {
                    let granted = flag == U256::from(1u8);
                    Decoded {
                        kind: ActionKind::SetApprovalForAll,
                        selector: Some(format!("0x{}", hex::encode(selector))),
                        function_signature: Some("setApprovalForAll(address,bool)".into()),
                        spender: Some(operator),
                        recipient: None,
                        amount: None,
                        allowance: Some(DecodedAllowance {
                            // Granting operator status over ALL tokens of the
                            // collection is unlimited-class authority; the
                            // unlimited-approval policy rules apply. false =
                            // revocation, represented as an exact-zero grant.
                            kind: if granted {
                                AllowanceKind::Unlimited
                            } else {
                                AllowanceKind::Exact
                            },
                            amount: if granted { None } else { Some(U256::ZERO) },
                            token: to,
                        }),
                        unresolved_fields: vec![],
                        confidence: Confidence::Exact,
                    }
                }
                _ => Decoded::unknown(Some(selector), "malformed_set_approval_for_all_arguments"),
            }
        }
        SELECTOR_INCREASE_ALLOWANCE => {
            if !args_ok(2) {
                return Decoded::unknown(Some(selector), "truncated_or_padded_increase_allowance");
            }
            match (word_address(data, 0), word_u256(data, 1)) {
                (Some(spender), Some(amount)) => Decoded {
                    kind: ActionKind::Erc20IncreaseAllowance,
                    selector: Some(format!("0x{}", hex::encode(selector))),
                    function_signature: Some("increaseAllowance(address,uint256)".into()),
                    spender: Some(spender),
                    recipient: None,
                    amount: Some(amount),
                    allowance: Some(DecodedAllowance {
                        kind: if is_unlimited_amount(amount) {
                            AllowanceKind::Unlimited
                        } else {
                            AllowanceKind::Exact
                        },
                        amount: Some(amount),
                        token: to,
                    }),
                    // The increase is relative; the resulting total depends on
                    // the current on-chain allowance (simulation shows it).
                    unresolved_fields: vec!["resulting_total_allowance".into()],
                    confidence: Confidence::Exact,
                },
                _ => Decoded::unknown(Some(selector), "malformed_increase_allowance_arguments"),
            }
        }
        SELECTOR_SAFE_TRANSFER_FROM | SELECTOR_SAFE_TRANSFER_FROM_DATA => {
            // 3 fixed words; the bytes variant appends dynamic data.
            if data.len() < 4 + 32 * 3 {
                return Decoded::unknown(Some(selector), "truncated_safe_transfer_from");
            }
            match (word_address(data, 0), word_address(data, 1)) {
                (Some(_from), Some(recipient)) => Decoded {
                    kind: ActionKind::Erc721Transfer,
                    selector: Some(format!("0x{}", hex::encode(selector))),
                    function_signature: Some(if selector == SELECTOR_SAFE_TRANSFER_FROM {
                        "safeTransferFrom(address,address,uint256)".into()
                    } else {
                        "safeTransferFrom(address,address,uint256,bytes)".into()
                    }),
                    spender: None,
                    recipient: Some(recipient),
                    // The third word is a tokenId, not an amount — deliberately
                    // not surfaced as `amount` to avoid value confusion.
                    amount: None,
                    allowance: None,
                    unresolved_fields: vec!["token_id_and_collection_metadata".into()],
                    confidence: Confidence::Exact,
                },
                _ => Decoded::unknown(Some(selector), "malformed_safe_transfer_from_arguments"),
            }
        }
        _ => Decoded::unknown(Some(selector), "unrecognized_function_selector"),
    }
}

/// Deterministic classification of a `personal_sign` message. Unlike calldata
/// or typed-data, a personal-sign payload is always fully decodable — there
/// is no selector to fail to recognize — so this always returns
/// `Confidence::High`: the message the user reviews is exactly the bytes that
/// will be signed (via the EIP-191 `personal_sign` hash), never a guess.
/// Valid UTF-8 is shown as text (`function_signature`); otherwise the raw
/// hex is preserved instead (never silently dropped or mangled).
pub fn decode_personal_message(message: &[u8]) -> Decoded {
    let display = match std::str::from_utf8(message) {
        Ok(text) => text.to_string(),
        Err(_) => format!("0x{}", hex::encode(message)),
    };
    Decoded {
        kind: ActionKind::PersonalSign,
        selector: None,
        function_signature: Some(display),
        spender: None,
        recipient: None,
        amount: None,
        allowance: None,
        unresolved_fields: vec![],
        confidence: Confidence::High,
    }
}

/// Parse and validate a 0x-prefixed EVM address string.
pub fn parse_address(s: &str) -> Result<Address, AddressError> {
    let stripped = s.strip_prefix("0x").ok_or(AddressError::MissingPrefix)?;
    if stripped.len() != 40 {
        return Err(AddressError::WrongLength(stripped.len()));
    }
    let bytes = hex::decode(stripped).map_err(|_| AddressError::InvalidHex)?;
    Ok(Address::from_slice(&bytes))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("address must start with 0x")]
    MissingPrefix,
    #[error("address must be 40 hex chars, got {0}")]
    WrongLength(usize),
    #[error("address contains non-hex characters")]
    InvalidHex,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::from_slice(&[n; 20])
    }

    fn approve_calldata(spender: Address, amount: U256) -> Vec<u8> {
        let mut d = SELECTOR_APPROVE.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(spender.as_slice());
        d.extend_from_slice(&amount.to_be_bytes::<32>());
        d
    }

    #[test]
    fn decodes_exact_approve() {
        let d = decode_calldata(
            Some(addr(9)),
            U256::ZERO,
            &approve_calldata(addr(2), U256::from(100u64)),
        );
        assert_eq!(d.kind, ActionKind::Erc20Approve);
        assert_eq!(d.spender, Some(addr(2)));
        let a = d.allowance.unwrap();
        assert_eq!(a.kind, AllowanceKind::Exact);
        assert_eq!(a.token, Some(addr(9)));
        assert_eq!(d.confidence, Confidence::Exact);
    }

    #[test]
    fn detects_unlimited_approve_max() {
        let d = decode_calldata(
            Some(addr(9)),
            U256::ZERO,
            &approve_calldata(addr(2), U256::MAX),
        );
        assert_eq!(d.allowance.unwrap().kind, AllowanceKind::Unlimited);
    }

    #[test]
    fn detects_unlimited_approve_2_255() {
        let big = U256::from(1u8) << 255;
        let d = decode_calldata(Some(addr(9)), U256::ZERO, &approve_calldata(addr(2), big));
        assert_eq!(d.allowance.unwrap().kind, AllowanceKind::Unlimited);
        // Just below the threshold is exact, handled by policy thresholds instead.
        let below = (U256::from(1u8) << 255) - U256::from(1u8);
        let d2 = decode_calldata(Some(addr(9)), U256::ZERO, &approve_calldata(addr(2), below));
        assert_eq!(d2.allowance.unwrap().kind, AllowanceKind::Exact);
    }

    #[test]
    fn decodes_transfer_and_transfer_from() {
        let mut t = SELECTOR_TRANSFER.to_vec();
        t.extend_from_slice(&[0u8; 12]);
        t.extend_from_slice(addr(3).as_slice());
        t.extend_from_slice(&U256::from(5u64).to_be_bytes::<32>());
        let d = decode_calldata(Some(addr(9)), U256::ZERO, &t);
        assert_eq!(d.kind, ActionKind::Erc20Transfer);
        assert_eq!(d.recipient, Some(addr(3)));

        let mut tf = SELECTOR_TRANSFER_FROM.to_vec();
        for a in [addr(1), addr(4)] {
            tf.extend_from_slice(&[0u8; 12]);
            tf.extend_from_slice(a.as_slice());
        }
        tf.extend_from_slice(&U256::from(7u64).to_be_bytes::<32>());
        let d = decode_calldata(Some(addr(9)), U256::ZERO, &tf);
        assert_eq!(d.kind, ActionKind::Erc20TransferFrom);
        assert_eq!(d.recipient, Some(addr(4)));
    }

    #[test]
    fn permit_detected_as_high_consequence() {
        let mut p = SELECTOR_PERMIT.to_vec();
        // owner, spender
        for a in [addr(1), addr(2)] {
            p.extend_from_slice(&[0u8; 12]);
            p.extend_from_slice(a.as_slice());
        }
        // value = MAX, deadline, v, r, s
        p.extend_from_slice(&U256::MAX.to_be_bytes::<32>());
        p.extend_from_slice(&[0u8; 32 * 4]);
        let d = decode_calldata(Some(addr(9)), U256::ZERO, &p);
        assert_eq!(d.kind, ActionKind::Permit);
        assert_eq!(d.allowance.as_ref().unwrap().kind, AllowanceKind::Unlimited);
        assert!(!d.unresolved_fields.is_empty());
    }

    fn set_approval_for_all_calldata(operator: Address, granted: bool) -> Vec<u8> {
        let mut d = SELECTOR_SET_APPROVAL_FOR_ALL.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(operator.as_slice());
        let mut flag = [0u8; 32];
        if granted {
            flag[31] = 1;
        }
        d.extend_from_slice(&flag);
        d
    }

    #[test]
    fn set_approval_for_all_grant_is_unlimited_class() {
        let d = decode_calldata(
            Some(addr(9)),
            U256::ZERO,
            &set_approval_for_all_calldata(addr(2), true),
        );
        assert_eq!(d.kind, ActionKind::SetApprovalForAll);
        assert_eq!(d.spender, Some(addr(2)));
        let a = d.allowance.unwrap();
        assert_eq!(a.kind, AllowanceKind::Unlimited);
        assert_eq!(a.token, Some(addr(9)));
    }

    #[test]
    fn set_approval_for_all_revocation_is_exact_zero() {
        let d = decode_calldata(
            Some(addr(9)),
            U256::ZERO,
            &set_approval_for_all_calldata(addr(2), false),
        );
        assert_eq!(d.kind, ActionKind::SetApprovalForAll);
        let a = d.allowance.unwrap();
        assert_eq!(a.kind, AllowanceKind::Exact);
        assert_eq!(a.amount, Some(U256::ZERO));
    }

    #[test]
    fn set_approval_for_all_nonboolean_flag_is_unknown() {
        let mut d = SELECTOR_SET_APPROVAL_FOR_ALL.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(addr(2).as_slice());
        d.extend_from_slice(&U256::from(7u64).to_be_bytes::<32>()); // not 0/1
        let out = decode_calldata(Some(addr(9)), U256::ZERO, &d);
        assert_eq!(out.kind, ActionKind::Unknown);
    }

    #[test]
    fn increase_allowance_notes_relative_semantics() {
        let mut d = SELECTOR_INCREASE_ALLOWANCE.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(addr(2).as_slice());
        d.extend_from_slice(&U256::from(500u64).to_be_bytes::<32>());
        let out = decode_calldata(Some(addr(9)), U256::ZERO, &d);
        assert_eq!(out.kind, ActionKind::Erc20IncreaseAllowance);
        assert!(out
            .unresolved_fields
            .contains(&"resulting_total_allowance".to_string()));
        assert_eq!(out.allowance.unwrap().kind, AllowanceKind::Exact);
    }

    #[test]
    fn erc721_safe_transfer_from_decodes_without_amount_confusion() {
        for (sel, extra_words) in [
            (SELECTOR_SAFE_TRANSFER_FROM, 1),
            (SELECTOR_SAFE_TRANSFER_FROM_DATA, 3),
        ] {
            let mut d = sel.to_vec();
            for a in [addr(1), addr(4)] {
                d.extend_from_slice(&[0u8; 12]);
                d.extend_from_slice(a.as_slice());
            }
            d.extend_from_slice(&U256::from(1234u64).to_be_bytes::<32>()); // tokenId
            d.extend_from_slice(&vec![0u8; 32 * (extra_words - 1)]);
            let out = decode_calldata(Some(addr(9)), U256::ZERO, &d);
            assert_eq!(out.kind, ActionKind::Erc721Transfer);
            assert_eq!(out.recipient, Some(addr(4)));
            assert_eq!(out.amount, None, "tokenId must not masquerade as an amount");
        }
    }

    #[test]
    fn selector_collisions_are_surfaced() {
        let d = decode_calldata(
            Some(addr(9)),
            U256::ZERO,
            &approve_calldata(addr(2), U256::from(1u64)),
        );
        assert!(d
            .unresolved_fields
            .iter()
            .any(|f| f.contains("selector_collision")));
    }

    #[test]
    fn unknown_selector_never_guesses() {
        let d = decode_calldata(Some(addr(9)), U256::ZERO, &[0xde, 0xad, 0xbe, 0xef, 0x01]);
        assert_eq!(d.kind, ActionKind::Unknown);
        assert_eq!(d.selector.as_deref(), Some("0xdeadbeef"));
        assert_eq!(d.confidence, Confidence::Unknown);
        assert!(!d.unresolved_fields.is_empty());
    }

    #[test]
    fn truncated_approve_is_unknown() {
        let mut d = SELECTOR_APPROVE.to_vec();
        d.extend_from_slice(&[0u8; 40]); // not 64 bytes of args
        let out = decode_calldata(Some(addr(9)), U256::ZERO, &d);
        assert_eq!(out.kind, ActionKind::Unknown);
    }

    #[test]
    fn nonzero_address_padding_rejected() {
        let mut d = SELECTOR_APPROVE.to_vec();
        d.extend_from_slice(&[0xffu8; 32]); // garbage "address" word
        d.extend_from_slice(&U256::from(1u8).to_be_bytes::<32>());
        let out = decode_calldata(Some(addr(9)), U256::ZERO, &d);
        assert_eq!(out.kind, ActionKind::Unknown);
    }

    #[test]
    fn native_transfer_and_creation() {
        let d = decode_calldata(Some(addr(5)), U256::from(1000u64), &[]);
        assert_eq!(d.kind, ActionKind::NativeTransfer);
        assert_eq!(d.recipient, Some(addr(5)));
        let c = decode_calldata(None, U256::ZERO, &[0x60, 0x80]);
        assert_eq!(c.kind, ActionKind::ContractCreation);
    }

    #[test]
    fn parse_address_validates() {
        assert!(parse_address("0x0000000000000000000000000000000000000001").is_ok());
        assert_eq!(parse_address("0001"), Err(AddressError::MissingPrefix));
        assert_eq!(parse_address("0x01"), Err(AddressError::WrongLength(2)));
        assert_eq!(
            parse_address("0xzz00000000000000000000000000000000000001"),
            Err(AddressError::InvalidHex)
        );
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Arbitrary bytes never panic the decoder, and anything that doesn't
        /// match a known selector+shape is Unknown/NativeTransfer/Creation.
        #[test]
        fn decoder_total_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let to = Some(cipherlayer_types::Address::from_slice(&[7u8; 20]));
            let d = decode_calldata(to, U256::ZERO, &data);
            if !data.is_empty() && data.len() >= 4 {
                let known = [
                    SELECTOR_APPROVE,
                    SELECTOR_TRANSFER,
                    SELECTOR_TRANSFER_FROM,
                    SELECTOR_PERMIT,
                    SELECTOR_SET_APPROVAL_FOR_ALL,
                    SELECTOR_INCREASE_ALLOWANCE,
                    SELECTOR_SAFE_TRANSFER_FROM,
                    SELECTOR_SAFE_TRANSFER_FROM_DATA,
                ]
                .iter().any(|s| data[..4] == s[..]);
                if !known {
                    prop_assert_eq!(d.kind, ActionKind::Unknown);
                }
            }
        }
    }
}
