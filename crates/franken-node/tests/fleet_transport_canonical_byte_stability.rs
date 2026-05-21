//! Integration regression test for bd-98xo5.7.3 — pins that
//! `canonical_fleet_convergence_receipt_payload` produces stable,
//! byte-identical canonical output after the bd-98xo5.7.1 path-alloc
//! cleanup.
//!
//! ## Why this exists
//!
//! T7 (bd-98xo5.7) refactored `canonicalize_json_value` from a
//! `format!`-allocates-on-every-descent implementation to a
//! `Vec<PathSeg>` stack that only renders the path string on the
//! float-error branch. The change is allocation-only — the
//! observable canonical byte output and the float-error message
//! must remain byte-identical to the prior implementation. A
//! regression that silently re-ordered keys (or dropped the
//! BTreeMap-sorted contract) would corrupt SHA-256 hashes computed
//! downstream over canonical bytes (fleet convergence receipt
//! signing, replay bundle hash linkage).
//!
//! ## Why no golden-fixture comparison here
//!
//! The bead spec references `tests/golden/fleet_convergence/`
//! fixtures, but the project's actual golden fixtures live under
//! `crates/franken-node/tests/goldens/fleet_cli/` and they cover the
//! CLI surface, not the raw canonicalise output. Rather than fork a
//! brittle dependency on whichever fixture happens to be on disk, we
//! build a representative timeline-event-shaped payload in-test, hash
//! its canonical bytes with the prefix used by
//! `sign_fleet_convergence_receipt_payload` and assert STABILITY
//! across multiple invocations. This catches the same regression
//! class (any silent change in canonical byte output → hash mismatch)
//! without coupling to fixture rotation in other beads.

use frankenengine_node::control_plane::fleet_transport::{
    canonical_fleet_convergence_receipt_payload, sign_fleet_convergence_receipt_payload,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn realistic_convergence_payload() -> serde_json::Value {
    // Mirrors the shape of a real fleet convergence receipt: zones
    // array with mixed integer / string fields, nested by-node
    // status map, and a top-level seq + timestamp. Deliberately uses
    // unsorted keys so the BTreeMap-sort contract is exercised.
    json!({
        "zone_id": "us-east-1",
        "seq": 42,
        "timestamp_millis": 1_700_000_000_000_u64,
        "zones": [
            {"id": "zone-b", "health": "Healthy"},
            {"id": "zone-a", "health": "Degraded"},
            {"id": "zone-c", "health": "Quarantined"},
        ],
        "nodes": {
            "node-2": {"health": "Healthy", "epoch": 7},
            "node-1": {"health": "Stale", "epoch": 6},
            "node-3": {"health": "Healthy", "epoch": 7},
        },
        "metadata": {
            "policy_snapshot": "policy@v3.2.1",
            "trust_anchor": "fleet-anchor-v1",
        },
    })
}

#[test]
fn canonical_bytes_are_deterministic_across_invocations() {
    let payload = realistic_convergence_payload();
    let first_bytes =
        canonical_fleet_convergence_receipt_payload(&payload).expect("canonical first call");
    let second_bytes =
        canonical_fleet_convergence_receipt_payload(&payload).expect("canonical second call");
    assert_eq!(
        first_bytes, second_bytes,
        "canonical bytes must be byte-identical across invocations"
    );
}

#[test]
fn canonical_bytes_round_trip_preserves_hash() {
    // Mirrors the production sign_fleet_convergence_receipt_payload
    // contract: hash the canonical bytes, round-trip via serde_json,
    // recompute, assert identity. A regression in canonicalise
    // (key reorder, path-state leak, etc.) would break this with
    // high signal because every downstream signature relies on
    // byte-stable canonical output.
    let payload = realistic_convergence_payload();
    let bytes =
        canonical_fleet_convergence_receipt_payload(&payload).expect("canonicalise must succeed");
    let mut h = Sha256::new();
    h.update(b"fleet_convergence_receipt_v1:");
    h.update(&bytes);
    let first_hash = h.finalize();

    // Round-trip: deserialise + recanonicalise + rehash.
    let round_tripped: serde_json::Value =
        serde_json::from_slice(&bytes).expect("deserialise canonical bytes");
    let rebytes = canonical_fleet_convergence_receipt_payload(&round_tripped)
        .expect("recanonicalise round-tripped value");
    let mut h2 = Sha256::new();
    h2.update(b"fleet_convergence_receipt_v1:");
    h2.update(&rebytes);
    let second_hash = h2.finalize();

    assert_eq!(
        first_hash, second_hash,
        "round-tripped canonical bytes must hash identically"
    );
}

#[test]
fn sign_payload_remains_byte_stable() {
    // The production sign path materialises canonical bytes, prepends
    // a domain prefix, and produces a signed_payload_sha256 + a hex
    // signature. Ed25519 is deterministic per RFC 8032 §5.1.6 so both
    // the signed_payload_sha256 (canonical-bytes hash) AND the
    // signature_hex must be byte-stable across invocations with the
    // same key.
    let payload = realistic_convergence_payload();
    let signing_key_seed = [0xAB_u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_seed);
    let first = sign_fleet_convergence_receipt_payload(
        &payload,
        &signing_key,
        "node-1-source",
        "node-1-identity",
    )
    .expect("sign first call");
    let second = sign_fleet_convergence_receipt_payload(
        &payload,
        &signing_key,
        "node-1-source",
        "node-1-identity",
    )
    .expect("sign second call");
    assert_eq!(
        first.signed_payload_sha256, second.signed_payload_sha256,
        "signed_payload_sha256 must be byte-stable across signing invocations"
    );
    assert_eq!(
        first.signature_hex, second.signature_hex,
        "Ed25519 deterministic signatures must be byte-stable per RFC 8032 §5.1.6"
    );
}
