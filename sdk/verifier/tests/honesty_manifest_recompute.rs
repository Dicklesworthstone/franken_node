//! Conformance: the verifier SDK independently re-verifies the committed,
//! Python-generated Honesty Manifest (bd-5r99w.9).
//!
//! This is the load-bearing cross-language check. The manifest + evidence are
//! produced by `scripts/check_claims_manifest.py --update-honesty` (Python,
//! `cryptography`); this test verifies them with `ed25519-dalek` and the SDK's
//! own canonicalization. If Python and Rust disagree by a single byte in the
//! canonical JSON or the signature preimage, `verify_honesty_manifest` fails —
//! so a green run proves the two implementations agree.
//!
//! It also proves tamper-evidence (flip a census count / a manifest value →
//! reject) and pins the README-claim contract so a silent schema change fails.

use std::fs;
use std::path::PathBuf;

use frankenengine_verifier_sdk::honesty_manifest::{
    HONESTY_MANIFEST_HARNESS_KEY_ID, HonestyManifestError, HonestyTrustAnchor,
    harness_public_key_hex, verify_honesty_manifest,
};
use serde_json::Value;

fn repo_path(relative: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/sdk/verifier
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read(relative: &str) -> Vec<u8> {
    let path = repo_path(relative);
    fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} (run `python scripts/check_claims_manifest.py --update-honesty`)",
            path.display()
        )
    })
}

fn manifest_bytes() -> Vec<u8> {
    read("docs/honesty_manifest.json")
}

fn evidence_bytes() -> Vec<u8> {
    read("docs/honesty_manifest_evidence.json")
}

/// The README-headline contract: exactly these claims, with these kinds.
const EXPECTED_CLAIMS: &[(&str, &str)] = &[
    ("integration_tests_run_by_cargo_test", "count"),
    ("inline_tests_behind_inline_lane", "count"),
    ("fuzz_targets_registered", "count"),
    ("validators", "count"),
    ("unsafe_blocks", "exact"),
    ("license", "string"),
    ("replay_verdict_load_bearing", "bool"),
];

#[test]
fn committed_manifest_verifies_under_the_harness_anchor() {
    let verified = verify_honesty_manifest(
        &manifest_bytes(),
        &evidence_bytes(),
        &HonestyTrustAnchor::HarnessDefault,
    )
    .expect("committed honesty manifest must verify (regenerate with --update-honesty if stale)");

    assert_eq!(verified.signer_key_id, HONESTY_MANIFEST_HARNESS_KEY_ID);
    assert_eq!(verified.claim_count, EXPECTED_CLAIMS.len());
    assert!(verified.corpus_digest.starts_with("sha256:"));
    assert!(
        verified
            .event_codes
            .iter()
            .any(|c| c == "FN-VSDK-HONESTY-MANIFEST-PASS"),
        "expected the pass event code"
    );
}

#[test]
fn rust_derived_harness_key_matches_python_signer_key() {
    // Cross-language key agreement: the Rust-derived harness public key must
    // equal the one Python embedded when it signed.
    let manifest: Value = serde_json::from_slice(&manifest_bytes()).expect("parse manifest");
    let embedded = manifest["signature"]["signer_public_key_hex"]
        .as_str()
        .expect("signer_public_key_hex");
    assert_eq!(embedded, harness_public_key_hex());
}

#[test]
fn committed_manifest_pins_the_readme_claim_contract() {
    let manifest: Value = serde_json::from_slice(&manifest_bytes()).expect("parse manifest");
    let claims = manifest["claims"].as_array().expect("claims array");
    let got: Vec<(String, String)> = claims
        .iter()
        .map(|c| {
            (
                c["claim_id"].as_str().unwrap_or_default().to_string(),
                c["kind"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let expected: Vec<(String, String)> = EXPECTED_CLAIMS
        .iter()
        .map(|(id, kind)| ((*id).to_string(), (*kind).to_string()))
        .collect();
    assert_eq!(
        got, expected,
        "Honesty Manifest claim/kind contract drifted — a deliberate change must update this test"
    );
}

#[test]
fn flipping_a_committed_census_count_is_rejected() {
    let mut evidence: Value = serde_json::from_slice(&evidence_bytes()).expect("parse evidence");
    // Bump the first count of the first count-claim that has items.
    let claims = evidence["claims"].as_array_mut().expect("claims");
    let mut mutated = false;
    for claim in claims.iter_mut() {
        if let Some(items) = claim["items"].as_array_mut()
            && let Some(first) = items.first_mut()
        {
            let current = first["count"].as_u64().unwrap_or(0);
            first["count"] = Value::from(current.wrapping_add(1));
            mutated = true;
            break;
        }
    }
    assert!(mutated, "expected at least one census item to mutate");
    let tampered = serde_json::to_vec(&evidence).expect("reserialize");
    let err = verify_honesty_manifest(
        &manifest_bytes(),
        &tampered,
        &HonestyTrustAnchor::HarnessDefault,
    )
    .expect_err("tampered census must be rejected");
    assert!(
        matches!(err, HonestyManifestError::EvidenceDigestMismatch { .. }),
        "expected EvidenceDigestMismatch, got {err:?}"
    );
}

#[test]
fn flipping_a_committed_manifest_value_is_rejected() {
    let mut manifest: Value = serde_json::from_slice(&manifest_bytes()).expect("parse manifest");
    // Flip a count claim's recomputed_value; this is inside the signed payload.
    let claims = manifest["claims"].as_array_mut().expect("claims");
    let claim = claims
        .iter_mut()
        .find(|c| c["kind"] == "count")
        .expect("a count claim");
    let current = claim["recomputed_value"].as_u64().unwrap_or(0);
    claim["recomputed_value"] = Value::from(current.wrapping_add(1));
    let tampered = serde_json::to_vec(&manifest).expect("reserialize");
    let err = verify_honesty_manifest(
        &tampered,
        &evidence_bytes(),
        &HonestyTrustAnchor::HarnessDefault,
    )
    .expect_err("tampered manifest value must be rejected");
    assert!(
        matches!(err, HonestyManifestError::SignatureInvalid),
        "expected SignatureInvalid (value is signed), got {err:?}"
    );
}

#[test]
fn an_operator_anchor_other_than_the_signer_is_rejected() {
    // The committed manifest is signed by the harness key; pinning to a
    // different operator key must fail closed at the signer-key check.
    use ed25519_dalek::SigningKey;
    let foreign = SigningKey::from_bytes(&[3_u8; 32]).verifying_key();
    let err = verify_honesty_manifest(
        &manifest_bytes(),
        &evidence_bytes(),
        &HonestyTrustAnchor::OperatorKey(foreign),
    )
    .expect_err("a foreign operator anchor must be rejected");
    assert!(
        matches!(err, HonestyManifestError::SignerKeyMismatch),
        "expected SignerKeyMismatch, got {err:?}"
    );
}
