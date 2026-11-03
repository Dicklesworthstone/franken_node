//! Protocol interoperability with the exact production run-record and bundle
//! signers. This fixture's execution metadata is synthetic; no native execution
//! or engine-session certification is claimed by these tests.

use std::io::Write;
use std::process::{Command, Stdio};

use ed25519_dalek::VerifyingKey;
use frankenengine_verifier_sdk::incident_bundle::{
    IncidentBundleError, verify_incident_bundle, verify_incident_bundle_with_run_key,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const BUNDLE: &[u8] = include_bytes!("fixtures/run_origin_protocol/producer-run.fnbundle");
const EXPORTER: &str = include_str!("fixtures/run_origin_protocol/bundle-authority.pub");
const RUN_AUTHORITY: &str = include_str!("fixtures/run_origin_protocol/run-authority.pub");

fn key(text: &str) -> VerifyingKey {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(text.trim(), &mut bytes).unwrap();
    VerifyingKey::from_bytes(&bytes).unwrap()
}

#[test]
fn independent_sdk_accepts_exact_producer_protocol_with_distinct_authorities_and_finite_floats() {
    let verified =
        verify_incident_bundle_with_run_key(BUNDLE, &key(EXPORTER), &key(RUN_AUTHORITY)).unwrap();
    assert_eq!(verified.bundle.event_count, 1);
    assert_eq!(verified.bundle.native_capture, None);
    assert_eq!(
        verified.run_origin.receipt_id,
        "run-synthetic-origin-protocol-1"
    );
    assert_eq!(
        verified.run_origin.signer_public_key_hex,
        RUN_AUTHORITY.trim()
    );
    assert_ne!(
        verified.run_origin.signer_public_key_hex,
        verified.bundle.signer_public_key_hex
    );
    let bundle: Value = serde_json::from_slice(BUNDLE).unwrap();
    let raw = bundle["initial_state_snapshot"]["run_origin"]["record_json"]
        .as_str()
        .unwrap();
    assert!(raw.contains("51.248178375505404"));
    assert!(raw.contains("unknown_signed_extension"));
    assert_eq!(
        verified.run_origin.record_sha256,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
    let provenance: Value =
        serde_json::from_str(include_str!("fixtures/run_origin_protocol/PROVENANCE.json")).unwrap();
    assert_eq!(
        provenance["fixture_sha256"],
        hex::encode(Sha256::digest(BUNDLE))
    );
    assert_eq!(
        provenance["original_record_sha256"],
        verified.run_origin.record_sha256
    );
    assert_eq!(provenance["native_execution_performed"], false);
    assert_eq!(provenance["typed_run_receipt_identity_recomputed"], false);
    verify_incident_bundle(BUNDLE, &key(EXPORTER)).unwrap();
    assert_eq!(
        verify_incident_bundle_with_run_key(BUNDLE, &key(EXPORTER), &key(EXPORTER)),
        Err(IncidentBundleError::RunOriginSignatureInvalid),
    );
}

fn executable(run_authority: Option<&str>) -> (bool, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_franken-verifier"));
    command.args([
        "verify",
        "--format",
        "incident-bundle",
        "--trusted-key-hex",
        EXPORTER.trim(),
    ]);
    if let Some(authority) = run_authority {
        command.args(["--trusted-run-key-hex", authority.trim()]);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(BUNDLE).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn executable_returns_original_attribution_only_when_explicit_run_authority_verifies() {
    let (success, strong) = executable(Some(RUN_AUTHORITY));
    assert!(success);
    assert_eq!(strong["scope"], "authenticated_run_incident");
    assert_eq!(
        strong["facts"]["run_origin"]["signer_public_key_hex"],
        RUN_AUTHORITY.trim()
    );
    assert_eq!(
        strong["artifact_sha256"],
        hex::encode(Sha256::digest(BUNDLE))
    );
    let (success, ordinary) = executable(None);
    assert!(success);
    assert_eq!(ordinary["scope"], "authenticated_recorded_incident");
    assert!(ordinary["facts"].get("run_origin").is_none());
    let (success, rejected) = executable(Some(EXPORTER));
    assert!(!success);
    assert_eq!(rejected["error"]["code"], "RUN_ORIGIN_SIGNATURE_INVALID");
    assert!(rejected.get("facts").is_none());
}
