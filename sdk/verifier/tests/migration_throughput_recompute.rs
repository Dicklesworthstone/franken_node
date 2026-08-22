//! Conformance: the verifier SDK independently re-verifies the committed,
//! Python-generated live migration-throughput delta (bd-reality-20260820-w0fc6.2).
//!
//! This is the load-bearing cross-language check. The delta + evidence census
//! are produced by `scripts/emit_migration_throughput_delta.py` (Python,
//! `cryptography`); this test verifies them with `ed25519-dalek` and the SDK's
//! own canonicalization, median, basis-point, and splitmix64-bootstrap
//! implementations. If Python and Rust disagree by a single byte in the
//! canonical JSON, the signature preimage, the integer math, or the PRNG
//! stream, `verify_throughput_delta` fails — so a green run proves the two
//! implementations agree end to end.
//!
//! It also proves tamper-evidence (flip a census run / a signed value →
//! reject), pins the fixture-set contract so a silent cohort change fails,
//! and asserts the holdout fixture is present and separately reported.

use std::fs;
use std::path::PathBuf;

use frankenengine_verifier_sdk::migration_throughput::{
    BootstrapCi95, MIGTP_HARNESS_KEY_ID, MigrationThroughputError, SignedThroughputDelta,
    ThroughputTrustAnchor, bootstrap_ci_bp, migtp_harness_public_key_hex, median_u64,
    ratio_bp, splitmix64, verify_throughput_delta,
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
            "read {}: {e} (run `python3 scripts/emit_migration_throughput_delta.py`)",
            path.display()
        )
    })
}

fn delta_bytes() -> Vec<u8> {
    read("artifacts/migration/throughput_delta.json")
}

fn evidence_bytes() -> Vec<u8> {
    read("artifacts/migration/throughput_delta_evidence.json")
}

/// The frozen-cohort contract: exactly these fixtures, with these roles. A
/// deliberate cohort change must update this test.
const EXPECTED_FIXTURES: &[(&str, &str)] = &[
    ("hardened", "cohort"),
    ("holdout-worker-service", "holdout"),
    ("rewrite-shell-commonjs", "cohort"),
    ("risky", "cohort"),
];

#[test]
fn committed_delta_verifies_under_the_harness_anchor() {
    let verified = verify_throughput_delta(
        &delta_bytes(),
        &evidence_bytes(),
        &ThroughputTrustAnchor::HarnessDefault,
    )
    .expect(
        "committed migration-throughput delta must verify (regenerate with \
         scripts/emit_migration_throughput_delta.py if stale)",
    );

    assert_eq!(verified.signer_key_id, MIGTP_HARNESS_KEY_ID);
    assert_eq!(verified.fixture_count, EXPECTED_FIXTURES.len());
    assert!(verified.velocity_ratio_bp >= 30_000, "velocity ratio must meet 3x");
    assert!(
        verified
            .event_codes
            .iter()
            .any(|code| code == "FN-VSDK-MIGTP-DELTA-PASS"),
        "expected the pass event code"
    );
}

#[test]
fn rust_derived_harness_key_matches_python_signer_key() {
    // Cross-language key agreement: the Rust-derived harness public key must
    // equal the one Python embedded when it signed.
    let delta: Value = serde_json::from_slice(&delta_bytes()).expect("parse delta");
    let embedded = delta["signature"]["signer_public_key_hex"]
        .as_str()
        .expect("signer_public_key_hex");
    assert_eq!(embedded, migtp_harness_public_key_hex());
}

#[test]
fn committed_delta_pins_the_fixture_contract() {
    let evidence: Value = serde_json::from_slice(&evidence_bytes()).expect("parse evidence");
    let fixtures = evidence["fixtures"].as_array().expect("fixtures array");
    let mut got: Vec<(String, String)> = fixtures
        .iter()
        .map(|fixture| {
            (
                fixture["fixture_id"].as_str().unwrap_or_default().to_string(),
                fixture["role"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    got.sort();
    let mut expected: Vec<(String, String)> = EXPECTED_FIXTURES
        .iter()
        .map(|(id, role)| ((*id).to_string(), (*role).to_string()))
        .collect();
    expected.sort();
    assert_eq!(
        got, expected,
        "throughput cohort/holdout contract drifted — a deliberate change must update this test"
    );
    // The holdout must carry its own frozen input digests (never a synthetic row).
    let holdout = fixtures
        .iter()
        .find(|fixture| fixture["role"] == "holdout")
        .expect("exactly one holdout");
    let inputs = holdout["input_files"].as_array().expect("input_files");
    assert!(
        inputs.iter().any(|file| file["path"]
            .as_str()
            .is_some_and(|path| path.contains("holdout_worker_service"))),
        "holdout input digests must reference the holdout fixture files"
    );
}

#[test]
fn flipping_a_committed_census_run_is_rejected() {
    let mut evidence: Value = serde_json::from_slice(&evidence_bytes()).expect("parse evidence");
    // Bump the first run's tool_ms; this desyncs the corpus digest and every
    // aggregate recompute.
    let fixtures = evidence["fixtures"].as_array_mut().expect("fixtures");
    let first = fixtures
        .first_mut()
        .expect("at least one fixture");
    let runs = first["runs"].as_array_mut().expect("runs array");
    let run = runs.first_mut().expect("at least one run");
    let current = run["tool_ms"].as_u64().unwrap_or(0);
    run["tool_ms"] = Value::from(current.wrapping_add(1));
    let tampered = serde_json::to_vec(&evidence).expect("reserialize");
    let err = verify_throughput_delta(
        &delta_bytes(),
        &tampered,
        &ThroughputTrustAnchor::HarnessDefault,
    )
    .expect_err("tampered census must be rejected");
    assert!(
        matches!(
            err,
            MigrationThroughputError::CensusRecomputeMismatch { .. }
                | MigrationThroughputError::CorpusDigestMismatch
                | MigrationThroughputError::DeltaRecomputeMismatch { .. }
        ),
        "expected a census/digest recompute failure, got {err:?}"
    );
}

#[test]
fn flipping_a_committed_signed_value_is_rejected() {
    let mut delta: Value = serde_json::from_slice(&delta_bytes()).expect("parse delta");
    // Flip the signed velocity ratio; this is inside the signed payload.
    let current = delta["velocity_ratio_bp"].as_u64().unwrap_or(0);
    delta["velocity_ratio_bp"] = Value::from(current.wrapping_add(1));
    let tampered = serde_json::to_vec(&delta).expect("reserialize");
    let err = verify_throughput_delta(
        &tampered,
        &evidence_bytes(),
        &ThroughputTrustAnchor::HarnessDefault,
    )
    .expect_err("tampered signed value must be rejected");
    assert!(
        matches!(err, MigrationThroughputError::SignatureInvalid)
            || matches!(err, MigrationThroughputError::DeltaRecomputeMismatch { .. }),
        "expected SignatureInvalid or recompute mismatch, got {err:?}"
    );
}

#[test]
fn an_operator_anchor_other_than_the_signer_is_rejected() {
    // The committed delta is signed by the throughput harness key; pinning to
    // a different operator key must fail closed at the signer-key check.
    use ed25519_dalek::SigningKey;
    let foreign = SigningKey::from_bytes(&[7_u8; 32]).verifying_key();
    let err = verify_throughput_delta(
        &delta_bytes(),
        &evidence_bytes(),
        &ThroughputTrustAnchor::OperatorKey(foreign),
    )
    .expect_err("a foreign operator anchor must be rejected");
    assert!(
        matches!(err, MigrationThroughputError::SignerKeyMismatch),
        "expected SignerKeyMismatch, got {err:?}"
    );
}

#[test]
fn a_foreign_key_resign_of_a_tampered_delta_is_rejected_under_the_harness_anchor() {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use sha2::{Digest, Sha256};

    // Tamper the signed payload, then re-sign with a FOREIGN key whose seed
    // is derived the same way as the harness key but from a different
    // preimage. The harness anchor must reject it.
    let mut delta: Value = serde_json::from_slice(&delta_bytes()).expect("parse delta");
    delta["median_tool_ms"] = Value::from(delta["median_tool_ms"].as_u64().unwrap_or(0) + 1);

    let mut unsigned = delta.clone();
    unsigned.as_object_mut().expect("object").remove("signature");
    let canonical =
        serde_json::to_vec(&unsigned).expect("canonical-ish serialization for foreign signing");

    let foreign_seed: [u8; 32] = Sha256::digest(b"foreign-throughput-key").into();
    let foreign = SigningKey::from_bytes(&foreign_seed);
    let mut message = b"frankenengine-verifier-sdk:migration-throughput-signature:v1:".to_vec();
    message.extend_from_slice(&(u64::try_from(canonical.len()).expect("len")).to_le_bytes());
    message.extend_from_slice(&canonical);
    let signature: Signature = foreign.sign(&message);

    delta["signature"] = serde_json::json!({
        "algorithm": "ed25519",
        "signer_key_id": "foreign-key",
        "signer_public_key_hex": hex::encode(foreign.verifying_key().to_bytes()),
        "signature_hex": hex::encode(signature.to_bytes()),
    });
    let resigned = serde_json::to_vec(&delta).expect("reserialize");
    let err = verify_throughput_delta(
        &resigned,
        &evidence_bytes(),
        &ThroughputTrustAnchor::HarnessDefault,
    )
    .expect_err("a foreign re-sign must be rejected under the harness anchor");
    assert!(
        matches!(err, MigrationThroughputError::SignerKeyMismatch),
        "expected SignerKeyMismatch, got {err:?}"
    );
}

#[test]
fn integer_math_matches_the_python_emitter() {
    // Median rules.
    assert_eq!(median_u64(&[5, 1, 3]), 3);
    assert_eq!(median_u64(&[4, 1, 3, 2]), 2);
    assert_eq!(median_u64(&[]), 0);
    // Ratio rounding.
    assert_eq!(ratio_bp(30_000, 10_000), Some(30_000));
    assert_eq!(ratio_bp(1, 3), Some(3_333));
    assert_eq!(ratio_bp(10, 0), None);
    // splitmix64 reference vector (seed 0, first output).
    let (next, out) = splitmix64(0);
    assert_eq!(next, 0x9E37_79B9_7F4A_7C15);
    assert_eq!(out, 0xE220_A839_7B1D_CDAF);
    // Degenerate bootstrap.
    let pairs = [(100_u64, 350_u64); 5];
    let ci = bootstrap_ci_bp(&pairs, 2_000, 42).expect("bootstrap");
    assert_eq!(
        ci,
        BootstrapCi95 {
            resamples: 2_000,
            seed: 42,
            ci95_low_bp: 35_000,
            ci95_high_bp: 35_000,
        }
    );
}

#[test]
fn delta_struct_round_trips_the_committed_bytes() {
    let delta: SignedThroughputDelta =
        serde_json::from_slice(&delta_bytes()).expect("parse committed delta");
    assert_eq!(delta.schema_version, "franken-node/migration-throughput/v1");
    assert_eq!(delta.required_velocity_ratio_bp, 30_000);
    assert_eq!(delta.fixture_ids_holdout.len(), 1);
    assert!(delta.measured_runs >= 1);
    assert!(delta.corpus_digest.starts_with("sha256:"));
}
