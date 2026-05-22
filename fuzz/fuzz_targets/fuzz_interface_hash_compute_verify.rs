#![no_main]

//! Fuzz harness for
//! `frankenengine_node::security::interface_hash::{compute_hash, verify_hash}`
//! at `crates/franken-node/src/security/interface_hash.rs:22` and
//! `:33`. The compute/verify pair backs every connector-admission
//! interface check — a hash collision or a verify-accepts-on-mismatch
//! regression would let an attacker bind a forged payload to a
//! trusted domain identifier.
//!
//! `compute_hash` uses the `secure_hash!` proc-macro from
//! `franken-security-macros` which emits length-prefixed
//! domain-separated SHA-256: `"interface_hash_v1:" ++ len(domain)
//! ++ domain ++ len(data) ++ data` little-endian-framed. `verify_hash`
//! is constant-time via
//! `crate::security::constant_time::ct_eq` over the lowercased hex
//! strings.
//!
//! Existing fuzz coverage of these functions: **zero**. The harness
//! pins six production invariants per call:
//!
//!   (A) **INV-IH-DETERMINISM** — `compute_hash(d, data)` invoked
//!       twice produces byte-identical InterfaceHash structs.
//!
//!   (B) **INV-IH-OUTPUT-SHAPE** — `compute_hash().hash_hex` is
//!       always exactly 64 lowercase ASCII hex digits, and
//!       `data_len` matches `data.len()`. Catches a truncated or
//!       uppercase output regression.
//!
//!   (C) **INV-IH-ROUNDTRIP** — `verify_hash(compute_hash(d, data),
//!       d, data) == Ok(())`. The compute/verify cycle MUST close.
//!
//!   (D) **INV-IH-DOMAIN-SEP** — `verify_hash(compute_hash("a",
//!       data), "b", data)` MUST return `Err(DomainMismatch)`.
//!       Catches a regression that drops the domain field from
//!       the preimage OR drops the domain-equality short-circuit
//!       at `interface_hash.rs:39-41`.
//!
//!   (E) **INV-IH-DATA-SENSITIVITY** — `verify_hash(compute_hash(
//!       d, data1), d, data2)` for `data1 != data2` MUST return
//!       `Err(_)`. Catches a regression that drops `data` from the
//!       preimage (SHA-256 avalanche makes the hash differ
//!       structurally; the assertion catches a wiring bug).
//!
//!   (F) **INV-IH-LENGTH-PREFIX** — `compute_hash("ab", b"cd...")`
//!       MUST produce a different hash than `compute_hash("a",
//!       b"bcd...")` even though the concatenated bytes match.
//!       Catches a regression that drops the length prefix on
//!       domain or data.

use arbitrary::Arbitrary;
use frankenengine_node::security::interface_hash::{
    compute_hash, verify_hash, InterfaceHash, RejectionCode,
};
use libfuzzer_sys::fuzz_target;

const MAX_DOMAIN_BYTES: usize = 256;
const MAX_DATA_BYTES: usize = 4096;

#[derive(Debug, Arbitrary)]
struct InterfaceHashFuzzCase {
    domain_a: String,
    domain_b: String,
    data_a: Vec<u8>,
    data_b: Vec<u8>,
}

fuzz_target!(|case: InterfaceHashFuzzCase| {
    let domain_a = bounded_str(&case.domain_a, MAX_DOMAIN_BYTES);
    let domain_b = bounded_str(&case.domain_b, MAX_DOMAIN_BYTES);
    let data_a = bounded_bytes(case.data_a, MAX_DATA_BYTES);
    let data_b = bounded_bytes(case.data_b, MAX_DATA_BYTES);

    // ── (A) Determinism ─────────────────────────────────────────────
    let first = compute_hash(&domain_a, &data_a);
    let second = compute_hash(&domain_a, &data_a);
    assert_eq!(
        first, second,
        "INV-IH-DETERMINISM violated: identical inputs produced different InterfaceHash"
    );

    // ── (B) Output shape ────────────────────────────────────────────
    assert_eq!(
        first.hash_hex.len(),
        64,
        "INV-IH-OUTPUT-SHAPE violated: hash_hex must be 64 chars, got {}",
        first.hash_hex.len()
    );
    assert!(
        first.hash_hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "INV-IH-OUTPUT-SHAPE violated: hash_hex must be lowercase ASCII hex, got {:?}",
        first.hash_hex,
    );
    assert_eq!(
        first.data_len,
        data_a.len(),
        "INV-IH-OUTPUT-SHAPE violated: data_len must match input data.len()"
    );
    assert_eq!(
        first.domain,
        domain_a,
        "INV-IH-OUTPUT-SHAPE violated: returned domain must equal input domain"
    );

    // ── (C) Roundtrip ──────────────────────────────────────────────
    let roundtrip = verify_hash(&first, &domain_a, &data_a);
    assert!(
        roundtrip.is_ok(),
        "INV-IH-ROUNDTRIP violated: verify_hash rejected a freshly-computed hash: {:?}",
        roundtrip
    );

    // ── (D) Domain separation ──────────────────────────────────────
    if domain_a != domain_b {
        let cross_domain = verify_hash(&first, &domain_b, &data_a);
        assert_eq!(
            cross_domain,
            Err(RejectionCode::DomainMismatch),
            "INV-IH-DOMAIN-SEP violated: verify_hash accepted a domain swap \
             from {domain_a:?} to {domain_b:?}, got {cross_domain:?}",
        );
    }

    // ── (E) Data sensitivity ───────────────────────────────────────
    if data_a != data_b {
        let cross_data = verify_hash(&first, &domain_a, &data_b);
        assert!(
            cross_data.is_err(),
            "INV-IH-DATA-SENSITIVITY violated: verify_hash accepted a data swap \
             on domain {domain_a:?}; original data_len={} swapped data_len={}",
            data_a.len(),
            data_b.len(),
        );
    }

    // ── (F) Length-prefix safety ───────────────────────────────────
    // ("ab", b"cd_payload") and ("a", b"bcd_payload") have identical concatenated
    // bytes if you drop the length prefix on domain. The length prefix MUST
    // distinguish them.
    let split_a = compute_hash("ab", b"cd_payload");
    let split_b = compute_hash("a", b"bcd_payload");
    assert_ne!(
        split_a.hash_hex, split_b.hash_hex,
        "INV-IH-LENGTH-PREFIX violated: (\"ab\", b\"cd_payload\") collided with \
         (\"a\", b\"bcd_payload\") — the length prefix on domain was dropped"
    );
});

#[allow(dead_code)]
fn _force_link_interface_hash_type(_: &InterfaceHash) {}

fn bounded_str(s: &str, max_bytes: usize) -> String {
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

fn bounded_bytes(mut v: Vec<u8>, max_bytes: usize) -> Vec<u8> {
    if v.len() > max_bytes {
        v.truncate(max_bytes);
    }
    v
}
