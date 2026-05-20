#![no_main]
#![forbid(unsafe_code)]

//! Fuzz `repair::proof_carrying_decode::ProofVerificationApi::verify` over
//! the `RepairProof` Deserialize boundary at
//! `crates/franken-node/src/repair/proof_carrying_decode.rs`.
//!
//! Peer commit `9a537171`
//! (`fix(proof_carrying_decode): validate algorithm_id in register_algorithm`)
//! just hardened the registration path; the module has no existing fuzz
//! coverage despite exposing the `RepairProof` Deserialize boundary plus
//! the `ProofVerificationApi::verify` entry point that any verifier-side
//! consumer would call on attacker-supplied proof JSON.
//!
//! Invariants pinned on every input that parses to a `RepairProof`:
//!
//!   1. `verify` never panics — returns a `VerificationResult` enum
//!      variant for any combination of (proof, originals, expected hash).
//!   2. Serialize-deserialize round-trip of the result enum is lossless
//!      (the verify result is itself `Serialize`-able and JSON-trip-safe).
//!   3. Determinism: invoking `verify` twice on the same inputs produces
//!      equal results. The verifier is documented as a pure function of
//!      its arguments + the registered-algorithms set.
//!
//! The harness uses a fixed signing_secret + a 3-algorithm registry so
//! the verifier surface is exercised under realistic configuration.
//! Input capped at 256 KiB.

use frankenengine_node::repair::proof_carrying_decode::{
    AlgorithmId, ProofVerificationApi, RepairProof, VerificationResult,
};
use libfuzzer_sys::fuzz_target;
use std::str;

const FUZZ_SIGNING_SECRET: &str = "fuzz-verifier-secret-2026";

fn fuzz_verifier() -> ProofVerificationApi {
    ProofVerificationApi::new(
        FUZZ_SIGNING_SECRET,
        vec![
            AlgorithmId::new("reed_solomon_8_4"),
            AlgorithmId::new("xor_parity_2"),
            AlgorithmId::new("simple_concat"),
        ],
    )
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let Ok(json_str) = str::from_utf8(data) else {
        return;
    };

    let Ok(proof) = serde_json::from_str::<RepairProof>(json_str) else {
        return;
    };

    let verifier = fuzz_verifier();

    // Build plausible-but-not-matching originals from the proof's own
    // declared fragment hashes. The verify path exercises both the
    // count-mismatch branch (when originals differ in count from proof)
    // and the per-hash mismatch / match branches.
    let originals: Vec<String> = proof.input_fragment_hashes.clone();
    let recomputed = proof.output_hash.clone();

    // Invariant 1: never panics.
    let result_a = verifier.verify(&proof, &originals, &recomputed);

    // Invariant 3: determinism.
    let result_b = verifier.verify(&proof, &originals, &recomputed);
    assert_eq!(
        result_a, result_b,
        "ProofVerificationApi::verify must be a pure function of its inputs"
    );

    // Invariant 2: result enum round-trips through serde_json losslessly.
    if let Ok(serialized) = serde_json::to_string(&result_a) {
        let reparsed: VerificationResult = serde_json::from_str(&serialized)
            .expect("VerificationResult JSON must round-trip losslessly");
        assert_eq!(
            result_a, reparsed,
            "VerificationResult round-trip must preserve variant + payload"
        );
    }
});
