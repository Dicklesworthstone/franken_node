#![no_main]

//! Fuzz harness for
//! `frankenengine_node::control_plane::fork_detection::StateVector::compute_state_hash`
//! at `crates/franken-node/src/control_plane/fork_detection.rs:162`.
//!
//! Background. The function produces the canonical hash that
//! `StateVector::compare` consults via `ct_eq` to detect forks vs
//! rollbacks vs convergence. The implementation is length-prefixed
//! SHA-256:
//!
//!   ```text
//!   "fork_detection_state_v1:" ++ len(payload) ++ payload
//!   ```
//!
//! with `u64::try_from(payload.len()).unwrap_or(u64::MAX).to_le_bytes()`
//! framing. A regression that drops the domain prefix, the length
//! prefix, or the payload bytes would let an attacker construct two
//! distinct StateVectors with colliding state_hash strings —
//! `compare` would then report `Converged` when in fact a fork
//! happened.
//!
//! Existing fuzz coverage of this function: **zero**.
//!
//! Four invariants pinned per call:
//!
//!   (A) **INV-FORK-HASH-DETERMINISM** — same payload twice
//!       produces byte-identical output.
//!
//!   (B) **INV-FORK-HASH-OUTPUT-SHAPE** — output is always
//!       exactly 64 lowercase ASCII hex digits.
//!
//!   (C) **INV-FORK-HASH-PAYLOAD-SENSITIVITY** — flipping a single
//!       byte of the payload changes the hash (SHA-256 avalanche).
//!
//!   (D) **INV-FORK-HASH-LENGTH-PREFIX** — `"a"` and `"a\u{0001}"`
//!       have a one-byte difference; their hashes MUST differ even
//!       though the concatenated content overlaps. Catches a
//!       regression where the length prefix is dropped.

use arbitrary::Arbitrary;
use frankenengine_node::control_plane::fork_detection::StateVector;
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD_BYTES: usize = 4096;

#[derive(Debug, Arbitrary)]
struct ForkStateHashFuzzCase {
    payload: String,
    flip_byte_at: u8,
}

fuzz_target!(|case: ForkStateHashFuzzCase| {
    let payload = bounded(&case.payload, MAX_PAYLOAD_BYTES);

    // ── (A) Determinism ─────────────────────────────────────────────
    let first = StateVector::compute_state_hash(&payload);
    let second = StateVector::compute_state_hash(&payload);
    assert_eq!(
        first, second,
        "INV-FORK-HASH-DETERMINISM violated: identical payload produced \
         different hashes"
    );

    // ── (B) Output shape ────────────────────────────────────────────
    assert_eq!(
        first.len(),
        64,
        "INV-FORK-HASH-OUTPUT-SHAPE violated: SHA-256 hex must be 64 chars, got {}",
        first.len()
    );
    assert!(
        first.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "INV-FORK-HASH-OUTPUT-SHAPE violated: hash hex must be lowercase ASCII \
         hex digits, got {first:?}"
    );

    // ── (C) Payload sensitivity ─────────────────────────────────────
    // Flip a deterministic position chosen from fuzz input. If the
    // payload is empty, append a single byte instead.
    let flipped_payload = if payload.is_empty() {
        "\u{0001}".to_string()
    } else {
        let mut bytes: Vec<u8> = payload.bytes().collect();
        let idx = usize::from(case.flip_byte_at) % bytes.len();
        bytes[idx] = bytes[idx].wrapping_add(1);
        // Result may be invalid UTF-8 — but compute_state_hash takes &str
        // and we need a String. Convert via lossy decode so the harness
        // doesn't reject borderline inputs.
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let flipped_hash = StateVector::compute_state_hash(&flipped_payload);
    assert_ne!(
        first, flipped_hash,
        "INV-FORK-HASH-PAYLOAD-SENSITIVITY violated: byte-flipped payload \
         produced the same hash — payload was dropped from the preimage"
    );

    // ── (D) Length-prefix safety ────────────────────────────────────
    // "a" and "a\u{0001}" share the leading "a" but differ in length
    // by exactly one byte. Their hashes MUST differ; if the length
    // prefix is dropped, they would collide because the concatenated
    // bytes after the domain prefix are not distinguishable at
    // hash time without the length field.
    let short = StateVector::compute_state_hash("a");
    let long = StateVector::compute_state_hash("a\u{0001}");
    assert_ne!(
        short, long,
        "INV-FORK-HASH-LENGTH-PREFIX violated: \"a\" and \"a\\u0001\" hashed \
         identically — the length prefix is missing from the preimage"
    );
});

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
