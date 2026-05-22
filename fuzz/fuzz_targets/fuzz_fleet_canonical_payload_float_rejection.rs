#![no_main]

//! Fuzz harness for
//! `frankenengine_node::control_plane::fleet_transport::canonical_fleet_convergence_receipt_payload`
//! at `crates/franken-node/src/control_plane/fleet_transport.rs:117`.
//!
//! Background. The canonicalizer is the float-rejecting variant of
//! `connector::canonical_serializer::canonical_bytes` that fleet
//! convergence receipts use as their signed-payload preimage. Two
//! production paths consume the output:
//!
//!   - `sign_fleet_convergence_receipt_payload` (line 126) hashes the
//!     canonical bytes and feeds them to Ed25519 — a non-determinism
//!     bug in the canonicalizer would let an attacker land receipts
//!     whose recomputed hash diverges across nodes.
//!
//!   - The integration test
//!     `fleet_payload_bytes_match_shared_streaming_encoder_after_float_preflight`
//!     (shipped under ea511675) pins that — when no `f64` numbers
//!     reach the encoder — the canonicalizer's output is
//!     byte-identical to `canonical_bytes(&value)`. The fuzz harness
//!     here exercises that invariant across the full random-input
//!     space.
//!
//! Existing fuzz coverage of this function: **zero**.
//!
//! Four invariants pinned per call:
//!
//!   (A) **INV-FLEET-CANONICAL-PANIC-FREE**: arbitrary `serde_json::
//!       Value` shaped from fuzz input MUST NOT panic the
//!       canonicalizer.
//!
//!   (B) **INV-FLEET-CANONICAL-NAN-REJECT**: any non-finite `f64` in
//!       the input tree MUST cause `canonical_fleet_convergence_
//!       receipt_payload` to return `Err`. Since `serde_json::Value`
//!       only constructs `Number` via `Number::from_f64` (which rejects
//!       non-finite values), a Value containing NaN/Inf is structurally
//!       unreachable through the public API; the harness asserts the
//!       integer-only happy path instead — every successful canonicalize
//!       MUST be byte-equal to the shared `canonical_bytes`.
//!
//!   (C) **INV-FLEET-CANONICAL-DETERMINISM**: invoking the function
//!       twice on the same Value produces byte-identical output.
//!
//!   (D) **INV-FLEET-CANONICAL-PARITY**: when the canonicalizer
//!       succeeds (no f64 in tree), its output MUST equal
//!       `canonical_bytes(&value)` byte-for-byte. Catches a regression
//!       where the float-preflight introduces a side effect that
//!       changes the encoded bytes.

use arbitrary::Arbitrary;
use frankenengine_node::connector::canonical_serializer::canonical_bytes;
use frankenengine_node::control_plane::fleet_transport::canonical_fleet_convergence_receipt_payload;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

const MAX_BYTES: usize = 8 * 1024;
const MAX_DEPTH: usize = 4;
const MAX_BRANCH: usize = 8;

#[derive(Debug, Arbitrary)]
enum FuzzValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    String(String),
    Array(Vec<FuzzValue>),
    Object(Vec<(String, FuzzValue)>),
}

#[derive(Debug, Arbitrary)]
struct FleetCanonicalFuzzCase {
    value: FuzzValue,
}

fuzz_target!(|case: FleetCanonicalFuzzCase| {
    let value = build_value(&case.value, MAX_DEPTH);

    // ── (A) Panic-freedom: call itself is the assertion ─────────────
    let first = canonical_fleet_convergence_receipt_payload(&value);

    // The integer-only happy path MUST succeed because Value::Number
    // can only carry finite values (serde_json::Number::from_f64
    // rejects NaN/Inf at construction). Any Err here would indicate a
    // bug in the canonicalizer rejecting valid input.
    let bytes = match first {
        Ok(bytes) => bytes,
        Err(_) => {
            // Float rejection is the documented Err path; if it fires on
            // an integer-only tree, that's a regression. But since
            // build_value below never produces f64, an Err here would
            // panic the harness — which is the desired observability.
            panic!(
                "INV-FLEET-CANONICAL-NAN-REJECT violated: canonicalizer rejected \
                 an integer-only payload"
            );
        }
    };

    if bytes.len() > MAX_BYTES {
        // Skip oversized payloads to keep the fuzz loop fast; the prior
        // assertions already covered the panic-free + Ok contract.
        return;
    }

    // ── (C) Determinism: call again, expect byte-identical output ────
    let second =
        canonical_fleet_convergence_receipt_payload(&value).expect("second call must also succeed");
    assert_eq!(
        bytes, second,
        "INV-FLEET-CANONICAL-DETERMINISM violated: identical input produced \
         different canonical bytes"
    );

    // ── (D) Parity with canonical_bytes ─────────────────────────────
    let shared = canonical_bytes(&value);
    assert_eq!(
        bytes, shared,
        "INV-FLEET-CANONICAL-PARITY violated: fleet canonicalizer diverged \
         from shared canonical_bytes on integer-only input — the float-preflight \
         layer introduced a side effect that changes the encoded bytes"
    );
});

fn build_value(node: &FuzzValue, depth_budget: usize) -> Value {
    match node {
        FuzzValue::Null => Value::Null,
        FuzzValue::Bool(b) => Value::Bool(*b),
        FuzzValue::Int(n) => Value::Number((*n).into()),
        FuzzValue::Uint(n) => Value::Number((*n).into()),
        FuzzValue::String(s) => Value::String(bounded(s, 256)),
        FuzzValue::Array(items) if depth_budget > 0 => Value::Array(
            items
                .iter()
                .take(MAX_BRANCH)
                .map(|child| build_value(child, depth_budget - 1))
                .collect(),
        ),
        FuzzValue::Object(entries) if depth_budget > 0 => {
            let mut map = Map::new();
            for (key, child) in entries.iter().take(MAX_BRANCH) {
                let bounded_key = bounded(key, 64);
                map.insert(bounded_key, build_value(child, depth_budget - 1));
            }
            Value::Object(map)
        }
        // Depth budget exhausted on a container → degrade to null so the
        // tree always terminates; this keeps the fuzz input from
        // exhausting the stack on deeply-nested arbitrary structures.
        FuzzValue::Array(_) | FuzzValue::Object(_) => Value::Null,
    }
}

fn bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}
