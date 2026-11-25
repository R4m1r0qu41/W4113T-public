//! Deterministic EIP-712 typed-data parsing (`eth_signTypedData_v4`),
//! CL-EVM-003/CL-EVM-004.
//!
//! Wraps `alloy_dyn_abi`'s EIP-712 resolver — the same encodeType/encodeData/
//! hashStruct/domain-separator implementation used by Foundry and reth — with
//! two things it does not provide on its own:
//!
//! - **Bounded input.** A payload byte-size cap and an independent, iterative
//!   (non-recursive) walk of the declared `types` graph that rejects cyclic
//!   or excessively deep type definitions *before* anything is handed to the
//!   resolver. This is belt-and-suspenders against a malicious or malformed
//!   `types` map: even if the resolver's own cycle detection is correct, nothing
//!   here trusts a third-party recursive routine to bound its own stack usage
//!   against adversarial input on a signing path.
//! - **Deterministic classification.** EIP-2612 `Permit`, DAI-style `Permit`,
//!   or an honest `unknown typed-data` — matched by exact `encodeType` string,
//!   never by guessing from a field name alone.
//!
//! Every rejection path returns a [`TypedDataError`]; there is no panic and no
//! best-guess hash. `unknown` classification is a first-class result, not an
//! error — undecodable-but-well-formed typed data must still surface its
//! domain and primaryType (see [`ParsedTypedData`]), never a quiet guess.

use std::collections::BTreeMap;

use alloy_dyn_abi::{DynSolValue, Eip712Domain, TypedData as AlloyTypedData};
use cipherlayer_types::{Address, ChainId, Confidence, U256};
use serde::Deserialize;

use crate::{is_unlimited_amount, ActionKind, AllowanceKind, Decoded, DecodedAllowance};

/// Hard bound on the raw typed-data payload. Real `eth_signTypedData_v4`
/// payloads (including deeply nested marketplace orders) run a few KB; this
/// is generous headroom while still bounding worst-case parse/hash cost.
pub const MAX_PAYLOAD_BYTES: usize = 262_144; // 256 KiB

/// Hard bound on how many distinct struct levels a type may reference,
/// checked by our own iterative walk before the resolver ever runs. Cyclic
/// definitions are rejected outright regardless of this bound; this catches
/// deliberately deep *acyclic* chains built to exhaust the stack during type
/// resolution (encodeType/encodeData recurse once per referenced struct).
pub const MAX_TYPE_DEPTH: usize = 32;

/// The canonical EIP-2612 `Permit` `encodeType` string. Matched literally
/// (field names, types, and order) — a struct that merely happens to be
/// named "Permit" with different fields is never force-fit into this class.
pub const EIP2612_PERMIT_ENCODE_TYPE: &str =
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";

/// The canonical DAI-style `Permit` `encodeType` string (`allowed: bool`
/// instead of a `value` amount — a blanket grant/revocation, not a bounded one).
pub const DAI_PERMIT_ENCODE_TYPE: &str =
    "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TypedDataError {
    #[error("typed-data payload is {0} bytes, exceeding the {1}-byte bound")]
    PayloadTooLarge(usize, usize),
    #[error("malformed typed-data JSON: {0}")]
    InvalidJson(String),
    #[error("primaryType {0:?} is not a defined struct type")]
    UnknownPrimaryType(String),
    #[error("type {0:?} references undefined type {1:?}")]
    MissingReferencedType(String, String),
    #[error("cyclic type definition reachable from {0:?}")]
    CyclicTypeDefinition(String),
    #[error("type graph reachable from {0:?} exceeds the {1}-level depth bound")]
    TypeDepthExceeded(String, usize),
    #[error("EIP-712 encoding failed: {0}")]
    Encoding(String),
}

/// EIP-712 signing domain, surfaced honestly and in full regardless of
/// classification outcome — a permit to an unexpected `verifying_contract`,
/// or a `chain_id` that does not match the session, must be visible to the
/// caller, never hidden inside a generic "unknown" result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TypedDataDomain {
    pub name: Option<String>,
    pub version: Option<String>,
    pub chain_id: Option<U256>,
    pub verifying_contract: Option<Address>,
}

impl TypedDataDomain {
    /// Whether the domain's declared `chainId` matches the session/expected
    /// chain. `None` means the domain omitted `chainId` (legal per EIP-712) —
    /// the caller must treat that as "not verifiable", not as a match.
    pub fn chain_id_matches(&self, expected: ChainId) -> Option<bool> {
        self.chain_id.map(|c| c == U256::from(expected.0))
    }
}

impl From<&Eip712Domain> for TypedDataDomain {
    fn from(d: &Eip712Domain) -> Self {
        TypedDataDomain {
            name: d.name.as_ref().map(|s| s.to_string()),
            version: d.version.as_ref().map(|s| s.to_string()),
            chain_id: d.chain_id,
            verifying_contract: d.verifying_contract,
        }
    }
}

/// Deterministic classification of a parsed typed-data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedDataClassification {
    /// EIP-2612 `permit` — feeds the same unlimited-approval policy path as
    /// on-chain `approve`/`permit` calldata (`value == type(uint256).max` or
    /// `>= 2^255` is unlimited-class authority).
    Eip2612Permit {
        owner: Address,
        spender: Address,
        value: U256,
        nonce: U256,
        deadline: U256,
    },
    /// DAI-style `permit` — `allowed: bool` is a blanket grant/revocation,
    /// analogous to `setApprovalForAll` (CL-EVM-007): `true` is unlimited-class.
    DaiPermit {
        holder: Address,
        spender: Address,
        nonce: U256,
        expiry: U256,
        allowed: bool,
    },
    /// Well-formed, hashable typed data that does not match a recognized
    /// permit shape. Never a guess — the domain and primaryType are still
    /// fully available on [`ParsedTypedData`].
    Unknown,
}

/// Result of parsing and hashing an `eth_signTypedData_v4` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTypedData {
    pub primary_type: String,
    pub domain: TypedDataDomain,
    /// `keccak256("\x19\x01" || domainSeparator || hashStruct(message))`.
    pub signing_hash: [u8; 32],
    pub classification: TypedDataClassification,
}

impl ParsedTypedData {
    /// Project into the same `Decoded` shape calldata decoding produces, so
    /// typed-data signatures flow through the existing
    /// `TransactionIntent`/policy pipeline unchanged: permits become
    /// `ActionKind::Permit` with the same unlimited-value `DecodedAllowance`
    /// logic used for `approve`/EIP-2612 calldata (feeding `POL-APR-001`/
    /// `POL-APR-004` in `cipherlayer-policy::evaluate`); anything unclassified
    /// becomes `ActionKind::TypedDataSign` at `Confidence::Unknown`, which
    /// hits the restrictive `POL-UNK-001` path — never a quiet "Sign" prompt
    /// (see `docs/threat-model/abuse-cases.md` AC-C).
    ///
    /// The full [`TypedDataDomain`] (name/version/chainId/verifyingContract)
    /// is deliberately *not* folded into this projection: `Decoded`/
    /// `TransactionIntent` have no field for it without a wire-schema change
    /// (`schemas/transaction-intent.v1.json` is closed — additional
    /// properties are rejected). Callers that need full domain fidelity
    /// (CLI display, permission checks, chain-id comparison) read `self.domain`
    /// directly; see the schema follow-up noted in the module's callers.
    pub fn to_decoded(&self) -> Decoded {
        match &self.classification {
            TypedDataClassification::Eip2612Permit { spender, value, .. } => Decoded {
                kind: ActionKind::Permit,
                selector: None,
                function_signature: Some(EIP2612_PERMIT_ENCODE_TYPE.into()),
                spender: Some(*spender),
                recipient: None,
                amount: Some(*value),
                allowance: Some(DecodedAllowance {
                    kind: if is_unlimited_amount(*value) {
                        AllowanceKind::Unlimited
                    } else {
                        AllowanceKind::Exact
                    },
                    amount: Some(*value),
                    token: self.domain.verifying_contract,
                }),
                unresolved_fields: vec!["typed_data_deadline_and_signature_validity".into()],
                confidence: Confidence::High,
            },
            TypedDataClassification::DaiPermit {
                spender, allowed, ..
            } => Decoded {
                kind: ActionKind::Permit,
                selector: None,
                function_signature: Some(DAI_PERMIT_ENCODE_TYPE.into()),
                spender: Some(*spender),
                recipient: None,
                amount: None,
                allowance: Some(DecodedAllowance {
                    kind: if *allowed {
                        AllowanceKind::Unlimited
                    } else {
                        AllowanceKind::Exact
                    },
                    amount: if *allowed { None } else { Some(U256::ZERO) },
                    token: self.domain.verifying_contract,
                }),
                unresolved_fields: vec!["typed_data_expiry_and_signature_validity".into()],
                confidence: Confidence::High,
            },
            TypedDataClassification::Unknown => Decoded {
                kind: ActionKind::TypedDataSign,
                selector: None,
                function_signature: Some(self.primary_type.clone()),
                spender: None,
                recipient: None,
                amount: None,
                allowance: None,
                unresolved_fields: vec!["typed_data_unclassified_signature".into()],
                confidence: Confidence::Unknown,
            },
        }
    }
}

#[derive(Deserialize)]
struct RawProp {
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Deserialize)]
struct RawTypedData {
    types: BTreeMap<String, Vec<RawProp>>,
    #[serde(rename = "primaryType")]
    primary_type: String,
}

fn root_type_name(ty: &str) -> &str {
    ty.split('[').next().unwrap_or(ty)
}

fn is_basic_solidity_type(name: &str) -> bool {
    match name {
        "address" | "bool" | "string" | "bytes" => true,
        _ => {
            if let Some(rest) = name.strip_prefix("bytes") {
                return rest.parse::<u16>().is_ok_and(|n| (1..=32).contains(&n));
            }
            if let Some(rest) = name.strip_prefix("uint") {
                return is_valid_bit_width(rest);
            }
            if let Some(rest) = name.strip_prefix("int") {
                return is_valid_bit_width(rest);
            }
            false
        }
    }
}

fn is_valid_bit_width(rest: &str) -> bool {
    rest.parse::<u16>()
        .is_ok_and(|n| n > 0 && n <= 256 && n % 8 == 0)
}

/// Iterative (non-recursive) cycle- and depth-bounded walk of the declared
/// type graph, rooted at `primary_type`. Runs before anything is handed to
/// the EIP-712 resolver.
fn validate_type_graph(
    types: &BTreeMap<String, Vec<RawProp>>,
    primary_type: &str,
) -> Result<(), TypedDataError> {
    enum Frame {
        Enter(String),
        Exit,
    }

    let mut work: Vec<Frame> = vec![Frame::Enter(primary_type.to_string())];
    let mut on_path: Vec<String> = Vec::new();
    // Memoized subtree height per struct type (path-independent in a DAG):
    // height = 1 + max(child heights), basic types count 0. Needed so a
    // diamond/shortcut graph — where a deep subtree is first explored via a
    // shallow path — still has its true root-to-leaf depth checked when the
    // explored type is later reached at the bottom of a long chain.
    let mut height: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    while let Some(frame) = work.pop() {
        match frame {
            Frame::Exit => {
                if let Some(name) = on_path.pop() {
                    let h = types
                        .get(&name)
                        .map(|props| {
                            1 + props
                                .iter()
                                .map(|p| height.get(root_type_name(&p.ty)).copied().unwrap_or(0))
                                .max()
                                .unwrap_or(0)
                        })
                        .unwrap_or(0);
                    height.insert(name, h);
                }
            }
            Frame::Enter(name) => {
                let Some(props) = types.get(&name) else {
                    if !is_basic_solidity_type(&name) {
                        return Err(TypedDataError::MissingReferencedType(
                            primary_type.to_string(),
                            name,
                        ));
                    }
                    continue;
                };
                if on_path.contains(&name) {
                    return Err(TypedDataError::CyclicTypeDefinition(name));
                }
                if let Some(h) = height.get(&name) {
                    // Already validated via another path (diamond reference,
                    // e.g. `Mail.from`/`Mail.to` both being `Person`) — no
                    // re-walk, but its memoized subtree height must still fit
                    // under the current path.
                    if on_path.len() + h > MAX_TYPE_DEPTH {
                        return Err(TypedDataError::TypeDepthExceeded(
                            primary_type.to_string(),
                            MAX_TYPE_DEPTH,
                        ));
                    }
                    continue;
                }
                if on_path.len() >= MAX_TYPE_DEPTH {
                    return Err(TypedDataError::TypeDepthExceeded(
                        primary_type.to_string(),
                        MAX_TYPE_DEPTH,
                    ));
                }
                on_path.push(name.clone());
                work.push(Frame::Exit);
                for prop in props {
                    work.push(Frame::Enter(root_type_name(&prop.ty).to_string()));
                }
            }
        }
    }
    Ok(())
}

/// Parse, bound, and hash an `eth_signTypedData_v4` payload.
///
/// Accepts either transport shape: a bare JSON object, or the doubly-encoded
/// JSON string form some RPC transports use for the second `eth_signTypedData_v4`
/// parameter (`"{\"types\":...}"`).
pub fn parse_typed_data(input: &str) -> Result<ParsedTypedData, TypedDataError> {
    if input.len() > MAX_PAYLOAD_BYTES {
        return Err(TypedDataError::PayloadTooLarge(
            input.len(),
            MAX_PAYLOAD_BYTES,
        ));
    }

    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| TypedDataError::InvalidJson(e.to_string()))?;
    let value = match value {
        serde_json::Value::String(s) => {
            serde_json::from_str(&s).map_err(|e| TypedDataError::InvalidJson(e.to_string()))?
        }
        other => other,
    };

    let raw: RawTypedData = serde_json::from_value(value.clone())
        .map_err(|e| TypedDataError::InvalidJson(e.to_string()))?;
    validate_type_graph(&raw.types, &raw.primary_type)?;

    let typed_data: AlloyTypedData =
        serde_json::from_value(value).map_err(|e| TypedDataError::InvalidJson(e.to_string()))?;

    // A bare atomic primaryType (e.g. "uint256") resolves successfully inside
    // the resolver but is not a struct; hashing it would reach an
    // `Option::unwrap()` on the non-struct branch of the resolver's
    // `encode_data`. Reject it as a typed error before that path is
    // reachable — this parser never panics regardless of the resolver's
    // internal assumptions.
    if !typed_data
        .resolver
        .contains_type_name(&typed_data.primary_type)
    {
        return Err(TypedDataError::UnknownPrimaryType(
            typed_data.primary_type.clone(),
        ));
    }

    let signing_hash = typed_data
        .eip712_signing_hash()
        .map_err(|e| TypedDataError::Encoding(e.to_string()))?;

    let domain = TypedDataDomain::from(&typed_data.domain);
    let classification = classify(&typed_data)?;

    Ok(ParsedTypedData {
        primary_type: typed_data.primary_type.clone(),
        domain,
        signing_hash: signing_hash.0,
        classification,
    })
}

fn classify(typed_data: &AlloyTypedData) -> Result<TypedDataClassification, TypedDataError> {
    if typed_data.primary_type != "Permit" {
        return Ok(TypedDataClassification::Unknown);
    }
    let encode_type = typed_data
        .encode_type()
        .map_err(|e| TypedDataError::Encoding(e.to_string()))?;
    if encode_type != EIP2612_PERMIT_ENCODE_TYPE && encode_type != DAI_PERMIT_ENCODE_TYPE {
        return Ok(TypedDataClassification::Unknown);
    }

    let value = typed_data
        .coerce()
        .map_err(|e| TypedDataError::Encoding(e.to_string()))?;
    let Some((_, _, fields)) = value.as_custom_struct() else {
        return Ok(TypedDataClassification::Unknown);
    };
    let [f0, f1, f2, f3, f4] = fields else {
        return Ok(TypedDataClassification::Unknown);
    };

    if encode_type == EIP2612_PERMIT_ENCODE_TYPE {
        return match (
            f0.as_address(),
            f1.as_address(),
            uint_of(f2),
            uint_of(f3),
            uint_of(f4),
        ) {
            (Some(owner), Some(spender), Some(value), Some(nonce), Some(deadline)) => {
                Ok(TypedDataClassification::Eip2612Permit {
                    owner,
                    spender,
                    value,
                    nonce,
                    deadline,
                })
            }
            _ => Err(TypedDataError::Encoding(
                "Permit fields did not match address,address,uint256,uint256,uint256".into(),
            )),
        };
    }

    // DAI_PERMIT_ENCODE_TYPE
    match (
        f0.as_address(),
        f1.as_address(),
        uint_of(f2),
        uint_of(f3),
        f4.as_bool(),
    ) {
        (Some(holder), Some(spender), Some(nonce), Some(expiry), Some(allowed)) => {
            Ok(TypedDataClassification::DaiPermit {
                holder,
                spender,
                nonce,
                expiry,
                allowed,
            })
        }
        _ => Err(TypedDataError::Encoding(
            "DAI-style Permit fields did not match address,address,uint256,uint256,bool".into(),
        )),
    }
}

fn uint_of(v: &DynSolValue) -> Option<U256> {
    v.as_uint().map(|(u, _bits)| u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn addr(hex: &str) -> Address {
        hex.parse().unwrap()
    }

    // -- EIP-712 hash vectors --
    //
    // Honest provenance note: only `known_vector_eip2612_permit_hand_derived`
    // is fully independent — its digest is recomputed in the test with raw
    // keccak256/ABI word-packing, sharing no code with the parser. The three
    // vectors below use ecosystem-shaped payloads (their domains/values are
    // not byte-identical to any published vector), so their hex literals were
    // pinned from this parser's own first output: they are regression pins
    // that freeze today's hash computation against future drift, not
    // independent oracles. Independence for the structural features they
    // cover (nested structs, struct arrays, domain-only) rests on the
    // hand-derived vector plus alloy-dyn-abi's upstream test suite.

    /// The Cow -> Bob "Mail" shape familiar from the EIP-712 ecosystem
    /// (nested custom structs: `Mail` containing two `Person` values).
    /// Regression pin — see the provenance note above.
    #[test]
    fn known_vector_mail_nested_struct() {
        let json = json!({
            "domain": {},
            "types": {
                "EIP712Domain": [],
                "Person": [
                    { "name": "name", "type": "string" },
                    { "name": "wallet", "type": "address" }
                ],
                "Mail": [
                    { "name": "from", "type": "Person" },
                    { "name": "to", "type": "Person" },
                    { "name": "contents", "type": "string" }
                ]
            },
            "primaryType": "Mail",
            "message": {
                "from": { "name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
                "to": { "name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
                "contents": "Hello, Bob!"
            }
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(
            hex::encode(parsed.signing_hash),
            "25c3d40a39e639a4d0b6e4d2ace5e1281e039c88494d97d8d08f99a6ea75d775",
        );
        assert_eq!(parsed.classification, TypedDataClassification::Unknown);
    }

    /// A real-world Seaport (OpenSea) marketplace order: recursive struct
    /// references plus a dynamic array of structs (`OfferItem[]`) — exercises
    /// `encodeData`'s array-of-struct branch, not just scalar fields.
    #[test]
    fn known_vector_seaport_order_nested_array() {
        let json = json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "OrderComponents": [
                    { "name": "offerer", "type": "address" },
                    { "name": "zone", "type": "address" },
                    { "name": "offer", "type": "OfferItem[]" },
                    { "name": "startTime", "type": "uint256" },
                    { "name": "endTime", "type": "uint256" },
                    { "name": "zoneHash", "type": "bytes32" },
                    { "name": "salt", "type": "uint256" },
                    { "name": "conduitKey", "type": "bytes32" },
                    { "name": "counter", "type": "uint256" }
                ],
                "OfferItem": [{ "name": "token", "type": "address" }]
            },
            "primaryType": "OrderComponents",
            "domain": {
                "name": "Seaport",
                "version": "1.1",
                "chainId": "1",
                "verifyingContract": "0x00000000006c3852cbEf3e08E8dF289169EdE581"
            },
            "message": {
                "offerer": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                "offer": [{ "token": "0xA604060890923Ff400e8c6f5290461A83AEDACec" }],
                "startTime": "1658645591",
                "endTime": "1659250386",
                "zone": "0x004C00500000aD104D7DBd00e3ae0A5C00560C00",
                "zoneHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "salt": "16178208897136618",
                "conduitKey": "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000",
                "counter": "0"
            }
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(
            hex::encode(parsed.signing_hash),
            "0b8aa9f3712df0034bc29fe5b24dd88cfdba02c7f499856ab24632e2969709a8",
        );
        assert_eq!(
            parsed.domain.chain_id_matches(ChainId(1)),
            Some(true),
            "domain chain id must be comparable against the session chain"
        );
    }

    /// A domain-only payload (`primaryType == "EIP712Domain"`) is a real,
    /// well-known MetaMask eth-sig-util test vector — exercises the special
    /// 34-byte (no hashStruct) signing-hash branch.
    #[test]
    fn known_vector_domain_only() {
        let json = json!({
            "types": { "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" },
                { "name": "salt", "type": "bytes32" }
            ]},
            "primaryType": "EIP712Domain",
            "domain": {
                "name": "example.metamask.io",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0x0000000000000000000000000000000000000000"
            },
            "message": {}
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(
            hex::encode(parsed.signing_hash),
            "122d1c8ef94b76dad44dcb03fa772361e20855c63311a15d5afe02d1b38f6077",
        );
    }

    /// Independently hand-derived EIP-2612 permit hash: computed here via raw
    /// `keccak256`/ABI word-packing (not via the resolver at all), then
    /// checked against `parse_typed_data`'s output. This proves the wired-up
    /// hash computation is correct without relying on the same library twice.
    #[test]
    fn known_vector_eip2612_permit_hand_derived() {
        use alloy::primitives::{keccak256, B256};

        let owner = addr("0x0000000000000000000000000000000000000001");
        let spender = addr("0x0000000000000000000000000000000000000002");
        let value = U256::MAX;
        let nonce = U256::from(7u64);
        let deadline = U256::from(1_700_000_000u64);
        let token = addr("0x0000000000000000000000000000000000000009");
        let chain_id = 31337u64;

        // -- Independent, hand-rolled derivation (no dyn-abi involved) --
        let domain_typehash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let mut domain_data = Vec::new();
        domain_data.extend_from_slice(domain_typehash.as_slice());
        domain_data.extend_from_slice(keccak256(b"TestToken").as_slice());
        domain_data.extend_from_slice(keccak256(b"1").as_slice());
        domain_data.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
        domain_data.extend_from_slice(&[0u8; 12]);
        domain_data.extend_from_slice(token.as_slice());
        let domain_separator = keccak256(&domain_data);

        let permit_typehash = keccak256(EIP2612_PERMIT_ENCODE_TYPE.as_bytes());
        let mut struct_data = Vec::new();
        struct_data.extend_from_slice(permit_typehash.as_slice());
        struct_data.extend_from_slice(&[0u8; 12]);
        struct_data.extend_from_slice(owner.as_slice());
        struct_data.extend_from_slice(&[0u8; 12]);
        struct_data.extend_from_slice(spender.as_slice());
        struct_data.extend_from_slice(&value.to_be_bytes::<32>());
        struct_data.extend_from_slice(&nonce.to_be_bytes::<32>());
        struct_data.extend_from_slice(&deadline.to_be_bytes::<32>());
        let struct_hash = keccak256(&struct_data);

        let mut digest_input = vec![0x19, 0x01];
        digest_input.extend_from_slice(domain_separator.as_slice());
        digest_input.extend_from_slice(struct_hash.as_slice());
        let expected: B256 = keccak256(&digest_input);

        // -- Parser under test --
        let json = json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Permit": [
                    { "name": "owner", "type": "address" },
                    { "name": "spender", "type": "address" },
                    { "name": "value", "type": "uint256" },
                    { "name": "nonce", "type": "uint256" },
                    { "name": "deadline", "type": "uint256" }
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "TestToken",
                "version": "1",
                "chainId": chain_id,
                "verifyingContract": format!("{token}")
            },
            "message": {
                "owner": format!("{owner}"),
                "spender": format!("{spender}"),
                "value": value.to_string(),
                "nonce": nonce.to_string(),
                "deadline": deadline.to_string()
            }
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(
            parsed.signing_hash, expected.0,
            "hash must match the independently hand-derived digest"
        );
        assert_eq!(
            parsed.classification,
            TypedDataClassification::Eip2612Permit {
                owner,
                spender,
                value,
                nonce,
                deadline
            }
        );
    }

    // -- Classification / policy wiring --

    #[test]
    fn eip2612_unlimited_permit_classifies_as_unlimited_approval() {
        let token = addr("0x0000000000000000000000000000000000000009");
        let spender = addr("0x0000000000000000000000000000000000000002");
        let json = permit_json(
            token,
            addr("0x0000000000000000000000000000000000000001"),
            spender,
            U256::MAX,
        );
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        let decoded = parsed.to_decoded();
        assert_eq!(decoded.kind, ActionKind::Permit);
        assert_eq!(decoded.allowance.unwrap().kind, AllowanceKind::Unlimited);
        assert_eq!(decoded.spender, Some(spender));
    }

    #[test]
    fn eip2612_bounded_permit_classifies_as_exact() {
        let token = addr("0x0000000000000000000000000000000000000009");
        let json = permit_json(
            token,
            addr("0x0000000000000000000000000000000000000001"),
            addr("0x0000000000000000000000000000000000000002"),
            U256::from(1000u64),
        );
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(
            parsed.to_decoded().allowance.unwrap().kind,
            AllowanceKind::Exact
        );
    }

    #[test]
    fn dai_style_permit_allowed_true_is_unlimited_class() {
        let token = addr("0x0000000000000000000000000000000000000009");
        let holder = addr("0x0000000000000000000000000000000000000001");
        let spender = addr("0x0000000000000000000000000000000000000002");
        let json = json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Permit": [
                    { "name": "holder", "type": "address" },
                    { "name": "spender", "type": "address" },
                    { "name": "nonce", "type": "uint256" },
                    { "name": "expiry", "type": "uint256" },
                    { "name": "allowed", "type": "bool" }
                ]
            },
            "primaryType": "Permit",
            "domain": { "name": "Dai Stablecoin", "chainId": 1, "verifyingContract": format!("{token}") },
            "message": {
                "holder": format!("{holder}"),
                "spender": format!("{spender}"),
                "nonce": "0",
                "expiry": "0",
                "allowed": true
            }
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(
            parsed.classification,
            TypedDataClassification::DaiPermit {
                holder,
                spender,
                nonce: U256::ZERO,
                expiry: U256::ZERO,
                allowed: true
            }
        );
        let decoded = parsed.to_decoded();
        assert_eq!(decoded.kind, ActionKind::Permit);
        assert_eq!(decoded.allowance.unwrap().kind, AllowanceKind::Unlimited);
    }

    #[test]
    fn dai_style_permit_revocation_is_not_unlimited() {
        let holder = addr("0x0000000000000000000000000000000000000001");
        let spender = addr("0x0000000000000000000000000000000000000002");
        let json = json!({
            "types": {
                "EIP712Domain": [{ "name": "chainId", "type": "uint256" }],
                "Permit": [
                    { "name": "holder", "type": "address" },
                    { "name": "spender", "type": "address" },
                    { "name": "nonce", "type": "uint256" },
                    { "name": "expiry", "type": "uint256" },
                    { "name": "allowed", "type": "bool" }
                ]
            },
            "primaryType": "Permit",
            "domain": { "chainId": 1 },
            "message": {
                "holder": format!("{holder}"), "spender": format!("{spender}"),
                "nonce": "0", "expiry": "0", "allowed": false
            }
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        let decoded = parsed.to_decoded();
        assert_eq!(decoded.allowance.unwrap().kind, AllowanceKind::Exact);
    }

    /// A permit whose `verifyingContract` differs from the token the caller
    /// expects: the domain must still be surfaced (never hidden or silently
    /// substituted), so the caller can compare it itself.
    #[test]
    fn permit_to_unexpected_verifying_contract_domain_is_surfaced_never_hidden() {
        let actual_contract = addr("0x00000000000000000000000000000000000000ad");
        let expected_token = addr("0x0000000000000000000000000000000000000009");
        let json = permit_json(
            actual_contract,
            addr("0x0000000000000000000000000000000000000001"),
            addr("0x0000000000000000000000000000000000000002"),
            U256::MAX,
        );
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(parsed.domain.verifying_contract, Some(actual_contract));
        assert_ne!(parsed.domain.verifying_contract, Some(expected_token));
        // The Decoded projection's `token` is the domain's *actual* contract,
        // not a guess or the caller's expectation.
        assert_eq!(
            parsed.to_decoded().allowance.unwrap().token,
            Some(actual_contract)
        );
    }

    /// `chainId` in the domain not matching the session/expected chain must
    /// be detectable by the caller — exposed as data, not swallowed.
    #[test]
    fn chain_id_mismatch_is_detectable() {
        let token = addr("0x0000000000000000000000000000000000000009");
        let json = permit_json_with_chain(
            token,
            addr("0x0000000000000000000000000000000000000001"),
            addr("0x0000000000000000000000000000000000000002"),
            U256::from(1u64),
            1, // mainnet
        );
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        // Session/expected is the Anvil dev chain (31337), domain says mainnet.
        assert_eq!(parsed.domain.chain_id_matches(ChainId(31337)), Some(false));
        assert_eq!(parsed.domain.chain_id_matches(ChainId(1)), Some(true));
    }

    /// A domain that omits `chainId` entirely (legal per EIP-712) must not be
    /// silently treated as a match — `None` is honest "not verifiable".
    #[test]
    fn missing_domain_chain_id_is_not_silently_a_match() {
        let json = json!({
            "types": {
                "EIP712Domain": [{ "name": "name", "type": "string" }],
                "Message": [{ "name": "data", "type": "string" }]
            },
            "primaryType": "Message",
            "domain": { "name": "NoChainDomain" },
            "message": { "data": "hi" }
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(parsed.domain.chain_id, None);
        assert_eq!(parsed.domain.chain_id_matches(ChainId(31337)), None);
    }

    /// Undecodable-but-well-formed typed data classifies as unknown, at
    /// `Confidence::Unknown`, so it hits the policy engine's restrictive
    /// unknown-action path — never a quiet "Sign" prompt (AC-C).
    #[test]
    fn unrecognized_struct_is_unknown_confidence_never_a_guess() {
        let json = json!({
            "types": {
                "EIP712Domain": [{ "name": "name", "type": "string" }],
                "Vote": [
                    { "name": "proposalId", "type": "uint256" },
                    { "name": "support", "type": "bool" }
                ]
            },
            "primaryType": "Vote",
            "domain": { "name": "Governance" },
            "message": { "proposalId": "1", "support": true }
        });
        let parsed = parse_typed_data(&json.to_string()).unwrap();
        assert_eq!(parsed.classification, TypedDataClassification::Unknown);
        let decoded = parsed.to_decoded();
        assert_eq!(decoded.kind, ActionKind::TypedDataSign);
        assert_eq!(decoded.confidence, Confidence::Unknown);
        assert_eq!(decoded.function_signature.as_deref(), Some("Vote"));
    }

    // -- Bounded / rejection paths (never a panic, never a best-guess hash) --

    #[test]
    fn cyclic_type_definition_is_rejected_not_panicked() {
        let json = json!({
            "types": {
                "EIP712Domain": [],
                "A": [{ "name": "b", "type": "B" }],
                "B": [{ "name": "c", "type": "C" }],
                "C": [{ "name": "a", "type": "A" }]
            },
            "primaryType": "A",
            "domain": {},
            "message": { "b": { "c": { "a": {} } } }
        });
        let err = parse_typed_data(&json.to_string()).unwrap_err();
        assert!(matches!(err, TypedDataError::CyclicTypeDefinition(_)));
    }

    #[test]
    fn self_referential_type_is_rejected_not_panicked() {
        // Same shape as the well-known "Mail with replyTo: Mail" case: the
        // TYPE is self-referential even though this particular message value
        // does not actually recurse forever.
        let json = json!({
            "types": {
                "EIP712Domain": [],
                "Mail": [
                    { "name": "contents", "type": "string" },
                    { "name": "replyTo", "type": "Mail" }
                ]
            },
            "primaryType": "Mail",
            "domain": {},
            "message": { "contents": "hi", "replyTo": { "contents": "hi2" } }
        });
        let err = parse_typed_data(&json.to_string()).unwrap_err();
        assert!(matches!(err, TypedDataError::CyclicTypeDefinition(_)));
    }

    #[test]
    fn missing_referenced_type_is_rejected_not_panicked() {
        let json = json!({
            "types": {
                "EIP712Domain": [],
                "User": [{ "name": "name", "type": "Nonexistent" }]
            },
            "primaryType": "User",
            "domain": {},
            "message": { "name": {} }
        });
        let err = parse_typed_data(&json.to_string()).unwrap_err();
        assert!(matches!(err, TypedDataError::MissingReferencedType(_, _)));
    }

    #[test]
    fn deeply_nested_acyclic_type_chain_is_depth_bounded() {
        // 200 distinct, non-cyclic struct levels: A0 -> A1 -> ... -> A199.
        // No cycle exists, but resolving it would recurse ~200 levels deep
        // through encodeType/encodeData; our own bound rejects it first.
        let mut types = serde_json::Map::new();
        types.insert("EIP712Domain".into(), json!([]));
        for i in 0..200 {
            let next = format!("A{}", i + 1);
            types.insert(format!("A{i}"), json!([{ "name": "next", "type": next }]));
        }
        types.insert(
            "A200".into(),
            json!([{ "name": "leaf", "type": "uint256" }]),
        );
        let payload = json!({
            "types": types,
            "primaryType": "A0",
            "domain": {},
            "message": {}
        });
        let err = parse_typed_data(&payload.to_string()).unwrap_err();
        assert!(matches!(err, TypedDataError::TypeDepthExceeded(_, _)));
    }

    #[test]
    fn diamond_shortcut_graph_cannot_evade_depth_bound() {
        // Adversarial shape from the 2026-07-16 verification pass: a deep
        // subtree D0->..->D24 is first reached via a shallow shortcut
        // (Primary -> D0), which memoizes it as explored; the long chain
        // C0->..->C19 then reaches D0 at depth ~20. True root-to-leaf depth
        // is ~45 > MAX_TYPE_DEPTH (32), and the memoized-height check must
        // still reject it even though every individual walk stays short.
        let mut types = serde_json::Map::new();
        types.insert("EIP712Domain".into(), json!([]));
        for i in 0..25 {
            let next = format!("D{}", i + 1);
            types.insert(format!("D{i}"), json!([{ "name": "next", "type": next }]));
        }
        types.insert("D25".into(), json!([{ "name": "leaf", "type": "uint256" }]));
        for i in 0..20 {
            let next = format!("C{}", i + 1);
            types.insert(format!("C{i}"), json!([{ "name": "next", "type": next }]));
        }
        types.insert("C20".into(), json!([{ "name": "deep", "type": "D0" }]));
        // Children are walked LIFO, so listing the shortcut last makes the
        // D-subtree get explored (and memoized) first, forcing the rejection
        // through the memoized-height branch rather than a plain deep walk.
        types.insert(
            "Primary".into(),
            json!([
                { "name": "chain", "type": "C0" },
                { "name": "shortcut", "type": "D0" }
            ]),
        );
        let payload = json!({
            "types": types,
            "primaryType": "Primary",
            "domain": {},
            "message": {}
        });
        let err = parse_typed_data(&payload.to_string()).unwrap_err();
        assert!(matches!(err, TypedDataError::TypeDepthExceeded(_, _)));
    }

    #[test]
    fn payload_over_size_bound_is_rejected() {
        let huge = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        let err = parse_typed_data(&huge).unwrap_err();
        assert!(matches!(err, TypedDataError::PayloadTooLarge(_, _)));
    }

    #[test]
    fn bare_atomic_primary_type_is_rejected_not_panicked() {
        // "uint256" resolves successfully as an atomic type inside the
        // resolver but is not a struct — hashing it would otherwise reach an
        // `unwrap()` inside the resolver's non-struct encode_data branch.
        let json = json!({
            "types": { "EIP712Domain": [] },
            "primaryType": "uint256",
            "domain": {},
            "message": {}
        });
        let err = parse_typed_data(&json.to_string()).unwrap_err();
        assert!(matches!(err, TypedDataError::UnknownPrimaryType(_)));
    }

    #[test]
    fn malformed_json_is_a_typed_error_not_a_panic() {
        assert!(matches!(
            parse_typed_data("{ not json").unwrap_err(),
            TypedDataError::InvalidJson(_)
        ));
        assert!(matches!(
            parse_typed_data("{}").unwrap_err(),
            TypedDataError::InvalidJson(_)
        ));
    }

    #[test]
    fn wrong_value_shape_is_rejected_not_panicked() {
        let json = json!({
            "types": {
                "EIP712Domain": [],
                "Permit": [
                    { "name": "owner", "type": "address" },
                    { "name": "spender", "type": "address" },
                    { "name": "value", "type": "uint256" },
                    { "name": "nonce", "type": "uint256" },
                    { "name": "deadline", "type": "uint256" }
                ]
            },
            "primaryType": "Permit",
            "domain": {},
            "message": {
                "owner": "not-an-address",
                "spender": "0x0000000000000000000000000000000000000002",
                "value": "1",
                "nonce": "1",
                "deadline": "1"
            }
        });
        let err = parse_typed_data(&json.to_string()).unwrap_err();
        assert!(matches!(err, TypedDataError::Encoding(_)));
    }

    /// Double-encoded transport shape (the second `eth_signTypedData_v4` RPC
    /// param is conventionally a JSON string) parses identically to the bare
    /// object form.
    #[test]
    fn double_encoded_string_transport_shape_is_accepted() {
        let obj = json!({
            "types": {
                "EIP712Domain": [{ "name": "name", "type": "string" }],
                "Message": [{ "name": "data", "type": "string" }]
            },
            "primaryType": "Message",
            "domain": { "name": "D" },
            "message": { "data": "hi" }
        });
        let bare = parse_typed_data(&obj.to_string()).unwrap();
        let double_encoded = serde_json::to_string(&obj.to_string()).unwrap();
        let wrapped = parse_typed_data(&double_encoded).unwrap();
        assert_eq!(bare.signing_hash, wrapped.signing_hash);
    }

    fn permit_json(
        token: Address,
        owner: Address,
        spender: Address,
        value: U256,
    ) -> serde_json::Value {
        permit_json_with_chain(token, owner, spender, value, 31337)
    }

    fn permit_json_with_chain(
        token: Address,
        owner: Address,
        spender: Address,
        value: U256,
        chain_id: u64,
    ) -> serde_json::Value {
        json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Permit": [
                    { "name": "owner", "type": "address" },
                    { "name": "spender", "type": "address" },
                    { "name": "value", "type": "uint256" },
                    { "name": "nonce", "type": "uint256" },
                    { "name": "deadline", "type": "uint256" }
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "TestToken",
                "version": "1",
                "chainId": chain_id,
                "verifyingContract": format!("{token}")
            },
            "message": {
                "owner": format!("{owner}"),
                "spender": format!("{spender}"),
                "value": value.to_string(),
                "nonce": "0",
                "deadline": "0"
            }
        })
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Arbitrary bytes-as-text never panic the parser: every input is
        /// either a bounded, typed `Err` or a successful, hashable parse.
        #[test]
        fn parser_total_on_arbitrary_text(s in ".{0,2048}") {
            let _ = parse_typed_data(&s);
        }

        /// A well-formed but arbitrarily deep, non-cyclic chain of struct
        /// references is always bounded — never a stack overflow, always a
        /// typed `TypeDepthExceeded` once past `MAX_TYPE_DEPTH`.
        #[test]
        fn arbitrarily_deep_acyclic_chain_is_always_bounded(depth in 1usize..300) {
            let mut types = serde_json::Map::new();
            types.insert("EIP712Domain".into(), serde_json::json!([]));
            for i in 0..depth {
                let next = format!("A{}", i + 1);
                types.insert(
                    format!("A{i}"),
                    serde_json::json!([{ "name": "next", "type": next }]),
                );
            }
            types.insert(
                format!("A{depth}"),
                serde_json::json!([{ "name": "leaf", "type": "uint256" }]),
            );
            // A properly-shaped, `depth`-deep nested message so a
            // within-bound chain doesn't fail on an unrelated "wrong value
            // shape" error instead of exercising the depth bound itself.
            let mut message = serde_json::json!({ "leaf": "0" });
            for _ in 0..depth {
                message = serde_json::json!({ "next": message });
            }
            let payload = serde_json::json!({
                "types": types,
                "primaryType": "A0",
                "domain": {},
                "message": message
            });
            let result = parse_typed_data(&payload.to_string());
            // The chain has `depth + 1` distinct struct nodes (A0..=A{depth});
            // the bound allows at most MAX_TYPE_DEPTH nodes on the path.
            if depth + 1 > MAX_TYPE_DEPTH {
                // Bounded one way or another — either our own depth check or
                // (for very large depths) serde_json's own nesting guard on
                // the message JSON trips first. Both are typed errors, never
                // a panic; which one fires first is an implementation detail.
                prop_assert!(result.is_err());
            } else {
                prop_assert!(result.is_ok());
            }
        }
    }
}
