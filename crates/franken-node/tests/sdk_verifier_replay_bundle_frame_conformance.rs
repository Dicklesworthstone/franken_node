//! Golden-vector conformance harness for the verifier SDK replay-bundle frame.
//!
//! Coverage matrix:
//! - MUST: canonical replay-bundle bytes remain byte-for-byte stable
//! - MUST: the live verifier accepts the canonical frame and rejects non-canonical framing
//! - MUST: canonical signature tampering fails closed

use std::path::{Path, PathBuf};

use frankenengine_verifier_sdk::bundle::{self, BundleError, ReplayBundle};
use serde::Deserialize;

const FRAME_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/sdk_verifier_replay_bundle_frame_vectors.json");

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct BundleFrameVectors {
    schema_version: String,
    contract: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<BundleFrameVector>,
}

#[derive(Debug, Deserialize)]
struct CoverageRow {
    spec_section: String,
    level: String,
    tested: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputMode {
    ParsedFixtureReserialize,
    RawFixtureBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mutation {
    FlipSignatureLastNibble,
}

#[derive(Debug, Deserialize)]
struct BundleFrameVector {
    name: String,
    source_fixture: String,
    input_mode: InputMode,
    expected: ExpectedVerdict,
    #[serde(default)]
    mutation: Option<Mutation>,
    #[serde(default)]
    expected_error: Option<String>,
    #[serde(default)]
    expected_canonical_bytes_hex: Option<String>,
    #[serde(default)]
    expected_byte_len: Option<usize>,
    #[serde(default)]
    expected_integrity_hash: Option<String>,
    #[serde(default)]
    expected_signature_hex: Option<String>,
}

fn conformance_vectors() -> Result<BundleFrameVectors, String> {
    serde_json::from_str(FRAME_VECTORS_JSON)
        .map_err(|err| format!("sdk verifier replay-bundle frame vectors must parse: {err}"))
}

fn workspace_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read_fixture_bytes(relative: &str) -> Result<Vec<u8>, String> {
    let path = workspace_path(relative);
    std::fs::read(&path).map_err(|err| format!("fixture {} must be readable: {err}", path.display()))
}

fn load_fixture_bundle(relative: &str) -> Result<ReplayBundle, String> {
    let path = workspace_path(relative);
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("fixture {} must be readable as UTF-8 JSON: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("fixture {} must parse as ReplayBundle: {err}", path.display()))
}

fn mutate_bundle(bundle: &mut ReplayBundle, mutation: Mutation) -> Result<(), String> {
    match mutation {
        Mutation::FlipSignatureLastNibble => {
            let current = bundle.signature.signature_hex.clone();
            let (prefix, last) = current
                .split_at(current.len().checked_sub(1).ok_or_else(|| {
                    "signature tamper vector requires non-empty signature_hex".to_string()
                })?);
            let flipped = if last == "0" { "1" } else { "0" };
            bundle.signature.signature_hex = format!("{prefix}{flipped}");
            Ok(())
        }
    }
}

fn bundle_error_name(error: &BundleError) -> &'static str {
    match error {
        BundleError::NonCanonicalEncoding => "NonCanonicalEncoding",
        BundleError::SignatureMismatch { .. } => "SignatureMismatch",
        BundleError::IntegrityMismatch { .. } => "IntegrityMismatch",
        _ => "Other",
    }
}

fn canonical_bytes_for_vector(vector: &BundleFrameVector) -> Result<Vec<u8>, String> {
    let mut bundle = load_fixture_bundle(&vector.source_fixture)?;
    if let Some(mutation) = vector.mutation {
        mutate_bundle(&mut bundle, mutation)?;
    }
    bundle::serialize(&bundle)
        .map_err(|err| format!("{} canonical serialization failed: {err}", vector.name))
}

#[test]
fn sdk_verifier_replay_bundle_frame_vectors_cover_required_contract() -> TestResult {
    let vectors = conformance_vectors()?;
    assert_eq!(
        vectors.schema_version,
        "franken-node/sdk-verifier-replay-bundle-frame-conformance/v1"
    );
    assert_eq!(vectors.contract, "sdk/verifier replay_bundle binary frame");
    assert!(
        !vectors.vectors.is_empty(),
        "frame conformance artifact must publish at least one vector"
    );

    for required in ["VSDK-BUNDLE-6.7", "VSDK-BUNDLE-6.8", "VSDK-BUNDLE-6.12"] {
        assert!(
            vectors
                .coverage
                .iter()
                .any(|row| row.spec_section == required && row.level == "MUST" && row.tested),
            "{required} must be covered by the frame conformance matrix"
        );
    }

    Ok(())
}

#[test]
fn sdk_verifier_replay_bundle_frame_vectors_match_live_bundle_contract() -> TestResult {
    let vectors = conformance_vectors()?;

    for vector in &vectors.vectors {
        match vector.input_mode {
            InputMode::ParsedFixtureReserialize => {
                let canonical_bytes = canonical_bytes_for_vector(vector)?;

                if vector.expected == ExpectedVerdict::Pass {
                    let expected_hex = vector.expected_canonical_bytes_hex.as_ref().ok_or_else(|| {
                        format!("{} must declare expected_canonical_bytes_hex", vector.name)
                    })?;
                    assert_eq!(
                        hex::encode(&canonical_bytes),
                        *expected_hex,
                        "{} canonical bytes drifted from the checked-in golden vector",
                        vector.name
                    );
                    assert_eq!(
                        canonical_bytes.len(),
                        vector.expected_byte_len.ok_or_else(|| {
                            format!("{} must declare expected_byte_len", vector.name)
                        })?,
                        "{} canonical byte length drifted from the checked-in vector",
                        vector.name
                    );

                    let verified = bundle::verify(&canonical_bytes)
                        .map_err(|err| format!("{} canonical bytes must verify: {err}", vector.name))?;
                    assert_eq!(
                        verified.integrity_hash,
                        vector.expected_integrity_hash.as_deref().ok_or_else(|| {
                            format!("{} must declare expected_integrity_hash", vector.name)
                        })?,
                        "{} integrity hash drifted from the checked-in vector",
                        vector.name
                    );
                    assert_eq!(
                        verified.signature.signature_hex,
                        vector.expected_signature_hex.as_deref().ok_or_else(|| {
                            format!("{} must declare expected_signature_hex", vector.name)
                        })?,
                        "{} signature hex drifted from the checked-in vector",
                        vector.name
                    );

                    let reserialized = bundle::serialize(&verified).map_err(|err| {
                        format!("{} verified bundle must reserialize canonically: {err}", vector.name)
                    })?;
                    assert_eq!(
                        reserialized, canonical_bytes,
                        "{} verified bundle must preserve canonical bytes",
                        vector.name
                    );
                } else {
                    let err = bundle::verify(&canonical_bytes)
                        .expect_err(&format!("{} mutated canonical bytes must fail closed", vector.name));
                    let expected_error = vector.expected_error.as_deref().ok_or_else(|| {
                        format!("{} must declare expected_error", vector.name)
                    })?;
                    assert_eq!(
                        bundle_error_name(&err),
                        expected_error,
                        "{} failed with the wrong bundle error",
                        vector.name
                    );
                }
            }
            InputMode::RawFixtureBytes => {
                let raw_bytes = read_fixture_bytes(&vector.source_fixture)?;
                let err = bundle::verify(&raw_bytes)
                    .expect_err(&format!("{} raw fixture bytes must fail closed", vector.name));
                let expected_error = vector.expected_error.as_deref().ok_or_else(|| {
                    format!("{} must declare expected_error", vector.name)
                })?;
                assert_eq!(
                    bundle_error_name(&err),
                    expected_error,
                    "{} failed with the wrong bundle error",
                    vector.name
                );
            }
        }
    }

    Ok(())
}
