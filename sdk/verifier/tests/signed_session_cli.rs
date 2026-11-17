//! Exercise portable session verification across the actual CLI boundary.
//!
//! Positive inputs are exported by the public SDK from actual verification
//! results. Mutations keep the original trusted anchor and signed transcript,
//! so a structural or cryptographic refusal cannot be replaced by a mock verdict.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

use ed25519_dalek::{SigningKey, VerifyingKey};
use frankenengine_verifier_sdk::{
    MAX_VERIFICATION_SESSION_STEPS, SignedSessionTranscript, VerificationVerdict, VerifierSdk,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BUNDLE: &[u8] = include_bytes!("fixtures/public_api/bundle_canonical.json");
const PRIVATE: &str = "SIGNED-SESSION-PRIVATE-SENTINEL";

fn fixture(verdict: VerificationVerdict) -> (VerifyingKey, SignedSessionTranscript) {
    let sdk = VerifierSdk::with_signing_key(
        "verifier://facade-test",
        SigningKey::from_bytes(&[91_u8; 32]),
    );
    let mut session = sdk.create_session("portable-audit-session").unwrap();
    if verdict != VerificationVerdict::Inconclusive {
        let bundle: frankenengine_verifier_sdk::bundle::ReplayBundle =
            serde_json::from_slice(BUNDLE).unwrap();
        let canonical = frankenengine_verifier_sdk::bundle::serialize(&bundle).unwrap();
        let pass = sdk
            .verify_trust_state(&canonical, &bundle.integrity_hash)
            .unwrap();
        assert_eq!(pass.verdict, VerificationVerdict::Pass);
        sdk.record_session_step(&mut session, &pass).unwrap();
        if verdict == VerificationVerdict::Fail {
            let fail = sdk.verify_migration_artifact(&canonical).unwrap();
            assert_eq!(fail.verdict, VerificationVerdict::Fail);
            sdk.record_session_step(&mut session, &fail).unwrap();
        } else {
            sdk.record_session_step(&mut session, &pass).unwrap();
        }
    }
    assert_eq!(sdk.seal_session(&mut session).unwrap(), verdict);
    let transcript = sdk.export_signed_session(&session).unwrap();
    VerifierSdk::verify_signed_session(&sdk.verifying_key(), &transcript).unwrap();
    (sdk.verifying_key(), transcript)
}

fn invoke(input: &[u8], anchor: &VerifyingKey, extra_args: &[&str]) -> (Output, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_franken-verifier"))
        .args([
            "verify",
            "--format",
            "signed-session",
            "--trusted-key-hex",
            &hex::encode(anchor.as_bytes()),
        ])
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the real verifier CLI");
    let mut stdin = child.stdin.take().unwrap();
    let written = stdin.write_all(input);
    drop(stdin);
    if let Err(error) = written {
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty(), "unexpected diagnostic stream");
    assert!(output.stdout.len() <= 64 * 1024, "unbounded CLI response");
    let response: Value = serde_json::from_slice(&output.stdout).expect("one JSON response");
    assert_eq!(response["schema_version"], "franken-verifier-cli/v1");
    (output, response)
}

fn reject(input: &[u8], anchor: &VerifyingKey, code: &str) {
    let (output, response) = invoke(input, anchor, &[]);
    assert_eq!(output.status.code(), Some(1), "{response}");
    assert_eq!(response["verdict"], "rejected");
    assert_eq!(response["error"]["code"], code, "{response}");
    assert!(response.get("facts").is_none());
    assert!(response.get("scope").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(PRIVATE));
}

#[test]
fn signed_session_cli_authenticates_sdk_exports_without_promoting_workflow_verdicts() {
    for verdict in [
        VerificationVerdict::Pass,
        VerificationVerdict::Fail,
        VerificationVerdict::Inconclusive,
    ] {
        let (anchor, transcript) = fixture(verdict.clone());
        let input = serde_json::to_vec(&transcript).unwrap();
        let (output, response) = invoke(&input, &anchor, &[]);
        assert_eq!(output.status.code(), Some(0), "{response}");
        assert_eq!(response["verdict"], "verified");
        assert_eq!(response["format"], "signed-session");
        assert_eq!(response["scope"], "authenticated_verification_session");
        assert_eq!(
            response["artifact_sha256"],
            hex::encode(Sha256::digest(&input))
        );
        assert_eq!(
            response["facts"],
            json!({
                "session_id": transcript.session_id,
                "verifier_identity": transcript.verifier_identity,
                "created_at": transcript.created_at,
                "final_verdict": verdict,
                "step_count": transcript.steps.len(),
                "transcript_hash": transcript.transcript_hash,
                "signer_public_key_hex": hex::encode(anchor.as_bytes()),
            })
        );
        assert!(response["facts"].get("steps").is_none());
        assert!(response["facts"].get("replay_certified").is_none());
        assert!(response["facts"].get("historical_completeness").is_none());
    }
}

#[test]
fn signed_session_cli_requires_the_callers_anchor_and_a_real_signature() {
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let input = serde_json::to_vec(&transcript).unwrap();
    let foreign = SigningKey::from_bytes(&[92_u8; 32]).verifying_key();
    reject(&input, &foreign, "SIGNER_UNTRUSTED");
    let mut substituted = transcript.clone();
    substituted.signer_public_key_hex = hex::encode(foreign.as_bytes());
    reject(
        &serde_json::to_vec(&substituted).unwrap(),
        &anchor,
        "SIGNER_UNTRUSTED",
    );
    let mut forged = transcript.clone();
    forged.ed25519_signature_hex = "0".repeat(128);
    reject(
        &serde_json::to_vec(&forged).unwrap(),
        &anchor,
        "SIGNATURE_INVALID",
    );
    for signature in [
        String::new(),
        "0".repeat(126),
        "0".repeat(130),
        "g".repeat(128),
        "A".repeat(128),
        PRIVATE.to_owned(),
    ] {
        let mut malformed = transcript.clone();
        malformed.ed25519_signature_hex = signature;
        reject(
            &serde_json::to_vec(&malformed).unwrap(),
            &anchor,
            "SIGNATURE_MALFORMED",
        );
    }
}

#[test]
fn signed_session_cli_rejects_step_reordering_splicing_truncation_and_payload_edits() {
    let (anchor, original) = fixture(VerificationVerdict::Pass);
    assert_eq!(original.steps.len(), 2);
    assert_ne!(
        original.steps[0].step_signature,
        original.steps[1].step_signature
    );
    let (_, other) = fixture(VerificationVerdict::Fail);
    let mut changed = original.clone();
    changed.steps.swap(0, 1);
    let mut cases = vec![changed];
    let mut changed = original.clone();
    changed.steps[1] = other.steps[1].clone();
    cases.push(changed);
    let mut changed = original.clone();
    changed.steps.pop();
    cases.push(changed);
    let mut changed = original.clone();
    changed.steps[1].step_index = 0;
    cases.push(changed);
    let mut changed = original.clone();
    changed.steps[0].artifact_binding_hash = "0".repeat(64);
    cases.push(changed);
    let mut changed = original.clone();
    changed.steps[0].timestamp = PRIVATE.into();
    cases.push(changed);
    let mut changed = original.clone();
    changed.steps[0].step_signature = "0".repeat(64);
    cases.push(changed);
    let mut changed = original.clone();
    changed.session_id = PRIVATE.into();
    cases.push(changed);
    let mut changed = original.clone();
    changed.verifier_identity = format!("verifier://{PRIVATE}");
    cases.push(changed);
    let mut changed = original.clone();
    changed.created_at = PRIVATE.into();
    cases.push(changed);
    let mut changed = original.clone();
    changed.final_verdict = VerificationVerdict::Inconclusive;
    cases.push(changed);
    let mut changed = original;
    changed.transcript_hash = "0".repeat(64);
    cases.push(changed);
    for candidate in cases {
        reject(
            &serde_json::to_vec(&candidate).unwrap(),
            &anchor,
            "EVIDENCE_INVALID",
        );
    }
}

#[test]
fn signed_session_cli_refuses_unsigned_extensions_and_ambiguous_json() {
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let original = serde_json::to_value(&transcript).unwrap();
    let mut extension = original.clone();
    extension["replay_certified"] = json!(true);
    let mut cases = vec![extension];
    let mut extension = original.clone();
    extension["steps"][0]["trusted_runtime_key"] = json!(PRIVATE);
    cases.push(extension);
    let mut missing = original.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("ed25519_signature_hex");
    cases.push(missing);
    let mut null = original.clone();
    null["steps"][0]["artifact_binding_hash"] = Value::Null;
    cases.push(null);
    let mut wrong_type = original.clone();
    wrong_type["steps"][0]["step_index"] = json!("0");
    cases.push(wrong_type);
    let mut unsupported = original;
    unsupported["schema_version"] = json!("vsdk-signed-session-v0.0");
    cases.push(unsupported);
    for candidate in cases {
        reject(
            &serde_json::to_vec(&candidate).unwrap(),
            &anchor,
            "EVIDENCE_INVALID",
        );
    }
    let compact = serde_json::to_string(&transcript).unwrap();
    let duplicate_outer = compact.replacen('{', "{\"session_id\":\"portable-audit-session\",", 1);
    let duplicate_step =
        compact.replacen("\"step_index\":0", "\"step_index\":0,\"step_index\":0", 1);
    assert_ne!(duplicate_step, compact);
    for input in [
        duplicate_outer,
        duplicate_step,
        format!("{compact}{{}}"),
        format!("{{\"private\":\"{PRIVATE}\""),
    ] {
        reject(input.as_bytes(), &anchor, "JSON_INVALID");
    }
}

#[test]
fn signed_session_cli_rejects_unbounded_metadata_and_step_populations() {
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let mut excessive = transcript.clone();
    excessive.steps = (0..=MAX_VERIFICATION_SESSION_STEPS)
        .map(|index| {
            let mut step = transcript.steps[0].clone();
            step.step_index = index;
            step
        })
        .collect();
    reject(
        &serde_json::to_vec(&excessive).unwrap(),
        &anchor,
        "EVIDENCE_INVALID",
    );
    for field in ["session_id", "verifier_identity", "created_at"] {
        let mut excessive = serde_json::to_value(&transcript).unwrap();
        excessive[field] = json!(PRIVATE.repeat(4096));
        reject(
            &serde_json::to_vec(&excessive).unwrap(),
            &anchor,
            "EVIDENCE_INVALID",
        );
    }
}

#[test]
fn signed_session_cli_cannot_borrow_unrelated_authority_options() {
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let input = serde_json::to_vec(&transcript).unwrap();
    let key = hex::encode(anchor.as_bytes());
    let signature = "0".repeat(128);
    for (option, value) in [
        ("--trusted-run-key-hex", key.as_str()),
        ("--trusted-runtime-key-hex", key.as_str()),
        ("--trusted-revocation-key-hex", key.as_str()),
        ("--trusted-provenance-key-hex", key.as_str()),
        ("--evaluation-time", "2026-11-16T00:00:00Z"),
        ("--max-revocation-age-secs", "60"),
        ("--signature-hex", signature.as_str()),
    ] {
        let (output, response) = invoke(&input, &anchor, &[option, value]);
        assert_eq!(output.status.code(), Some(2), "{option}: {response}");
        assert_eq!(response["verdict"], "rejected");
        assert_eq!(response["error"]["code"], "USAGE");
        assert!(response.get("facts").is_none());
    }
}
