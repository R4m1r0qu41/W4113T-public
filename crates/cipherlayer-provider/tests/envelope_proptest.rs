//! Property tests for the transaction-request envelope (W1-remainder:
//! fuzz/property tests in CI). New file, additive only — does not touch
//! `crates/cipherlayer-provider/src/lib.rs` (in-flight elsewhere).
//!
//! Two properties, both against the public `parse_envelope` API:
//! - arbitrary JSON near-miss inputs (structurally JSON but not a valid
//!   envelope, or not JSON at all) never panic the parser — worst case is a
//!   typed `ValidationError`, never a crash;
//! - a well-formed envelope always roundtrips through JSON unchanged.
//!
//! Default proptest case count (256), CI-sane.

use chrono::{TimeZone, Utc};
use cipherlayer_provider::{parse_envelope, EnvelopePayload, TransactionRequestEnvelope};
use cipherlayer_types::{AccessClass, CallerIdentity, CallerKind, ChainId};
use proptest::prelude::*;

fn arb_caller_kind() -> impl Strategy<Value = CallerKind> {
    prop_oneof![
        Just(CallerKind::Dapp),
        Just(CallerKind::Cli),
        Just(CallerKind::Desktop),
        Just(CallerKind::Agent),
        Just(CallerKind::Unknown),
    ]
}

fn arb_access() -> impl Strategy<Value = AccessClass> {
    prop_oneof![Just(AccessClass::ReadOnly), Just(AccessClass::Signing)]
}

fn arb_opt_string() -> impl Strategy<Value = Option<String>> {
    proptest::option::of("[a-zA-Z0-9_.:-]{0,16}")
}

fn arb_hex_addr() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), 20).prop_map(|b| format!("0x{}", hex::encode(b)))
}

fn arb_hex_data() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), 0..64).prop_map(|b| format!("0x{}", hex::encode(b)))
}

/// A well-formed envelope, built entirely through the public constructor and
/// public field types — no assumption about internal representation.
///
/// Grouped into nested sub-tuples (each well under any reasonable
/// tuple-strategy arity limit) rather than one flat tuple, purely to keep
/// this robust regardless of proptest's exact tuple-impl ceiling.
fn arb_envelope() -> impl Strategy<Value = TransactionRequestEnvelope> {
    let caller_group = (
        arb_caller_kind(),
        arb_opt_string(), // origin
        arb_opt_string(), // app_id
        arb_opt_string(), // capsule_id
    );
    let meta_group = (
        any::<u64>(), // chain_id
        arb_access(),
        0i64..4_102_444_800i64, // received_at seconds: 1970-01-01 .. 2100-01-01
    );
    let payload_group = (
        arb_hex_addr(),                       // from
        proptest::option::of(arb_hex_addr()), // to
        proptest::option::of("[0-9]{1,20}"),  // value_wei
        proptest::option::of(arb_hex_data()), // data
        proptest::option::of("[0-9]{1,10}"),  // gas_limit
        proptest::option::of(any::<u64>()),   // nonce
    );

    (caller_group, meta_group, payload_group).prop_map(
        |(
            (kind, origin, app_id, capsule_id),
            (chain_id, access, secs),
            (from, to, value_wei, data, gas_limit, nonce),
        )| {
            let caller = CallerIdentity {
                kind,
                origin,
                app_id,
                capsule_id,
            };
            let payload = EnvelopePayload {
                from,
                to,
                value_wei,
                data,
                gas_limit,
                nonce,
                kind: cipherlayer_provider::PayloadKind::EvmTransaction,
                typed_data_json: None,
                message_hex: None,
            };
            let mut env =
                TransactionRequestEnvelope::new(caller, ChainId(chain_id), access, payload);
            env.received_at = Utc.timestamp_opt(secs, 0).single().unwrap();
            env
        },
    )
}

/// Bounded recursive arbitrary JSON value — deliberately not shaped like an
/// envelope, to exercise near-miss structures (wrong types, missing/extra
/// keys, nested garbage) rather than only well-formed inputs.
fn arb_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        "[a-zA-Z0-9_ .:/-]{0,24}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
            proptest::collection::vec(("[a-zA-Z_]{1,8}", inner), 0..4).prop_map(|pairs| {
                let map: serde_json::Map<String, serde_json::Value> = pairs.into_iter().collect();
                serde_json::Value::Object(map)
            }),
        ]
    })
}

proptest! {
    /// Arbitrary JSON near-miss structures never panic `parse_envelope`; the
    /// worst outcome is a typed `ValidationError`.
    #[test]
    fn parse_never_panics_on_arbitrary_json(value in arb_json()) {
        let raw = value.to_string();
        let _ = parse_envelope(&raw);
    }

    /// Arbitrary byte soup (not necessarily valid JSON, not necessarily
    /// valid UTF-8) never panics `parse_envelope` either.
    #[test]
    fn parse_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        let _ = parse_envelope(&raw);
    }

    /// A well-formed envelope always survives a JSON roundtrip unchanged.
    #[test]
    fn valid_envelope_roundtrips(env in arb_envelope()) {
        let json = serde_json::to_string(&env).expect("serialize");
        let parsed = parse_envelope(&json).expect("a well-formed envelope must parse");

        prop_assert_eq!(parsed.schema_version, env.schema_version);
        prop_assert_eq!(parsed.request_id, env.request_id);
        prop_assert_eq!(parsed.received_at, env.received_at);
        prop_assert_eq!(parsed.protocol_version, env.protocol_version);
        prop_assert_eq!(parsed.caller.kind, env.caller.kind);
        prop_assert_eq!(parsed.caller.origin, env.caller.origin);
        prop_assert_eq!(parsed.caller.app_id, env.caller.app_id);
        prop_assert_eq!(parsed.caller.capsule_id, env.caller.capsule_id);
        prop_assert_eq!(parsed.chain_id, env.chain_id);
        prop_assert_eq!(parsed.access, env.access);
        prop_assert_eq!(parsed.payload.from, env.payload.from);
        prop_assert_eq!(parsed.payload.to, env.payload.to);
        prop_assert_eq!(parsed.payload.value_wei, env.payload.value_wei);
        prop_assert_eq!(parsed.payload.data, env.payload.data);
        prop_assert_eq!(parsed.payload.gas_limit, env.payload.gas_limit);
        prop_assert_eq!(parsed.payload.nonce, env.payload.nonce);
    }
}
