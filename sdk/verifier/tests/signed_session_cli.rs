//! Exercise portable session verification across the actual CLI boundary.
//!
//! Positive inputs are exported by the public SDK from actual verification
//! results. Mutations keep the original trusted anchor and signed transcript,
//! so a structural or cryptographic refusal cannot be replaced by a mock verdict.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

use ed25519_dalek::{SigningKey, VerifyingKey};
use frankenengine_verifier_sdk::{
    MAX_SIGNED_SESSION_POLICY_BYTES, MAX_VERIFICATION_SESSION_STEPS,
    SIGNED_SESSION_POLICY_SCHEMA_VERSION, SignedSessionPolicy, SignedSessionStepPolicy,
    SignedSessionTranscript, VerificationOperation, VerificationVerdict, VerifierSdk,
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

fn expected_trust_session_policy() -> SignedSessionPolicy {
    // These expectations come from a trusted fixture and the requested workflow,
    // independently of any candidate transcript.
    let bundle: frankenengine_verifier_sdk::bundle::ReplayBundle =
        serde_json::from_slice(BUNDLE).unwrap();
    SignedSessionPolicy {
        schema_version: SIGNED_SESSION_POLICY_SCHEMA_VERSION.into(),
        session_id: "portable-audit-session".into(),
        verifier_identity: "verifier://facade-test".into(),
        steps: vec![
            SignedSessionStepPolicy {
                operation: VerificationOperation::TrustState,
                artifact_binding_hash: bundle.integrity_hash.clone(),
                verdict: VerificationVerdict::Pass,
            };
            2
        ],
    }
}

struct SessionPolicyFile(std::path::PathBuf);

impl SessionPolicyFile {
    fn new(bytes: &[u8]) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "franken-verifier-session-policy-{}-{nonce}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        Self(path)
    }

    fn argument(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for SessionPolicyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn signed_session_cli_matches_independent_policy_and_commits_its_exact_bytes() {
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let input = serde_json::to_vec(&transcript).unwrap();
    let policy = expected_trust_session_policy();
    let compact = serde_json::to_vec(&policy).unwrap();
    let pretty = serde_json::to_vec_pretty(&policy).unwrap();
    assert_ne!(Sha256::digest(&compact), Sha256::digest(&pretty));
    for bytes in [compact, pretty] {
        let file = SessionPolicyFile::new(&bytes);
        let (output, response) = invoke(
            &input,
            &anchor,
            &["--trusted-session-policy", file.argument()],
        );
        assert_eq!(output.status.code(), Some(0), "{response}");
        assert_eq!(response["scope"], "authenticated_verification_session");
        assert_eq!(response["facts"]["final_verdict"], "pass");
        assert_eq!(
            response["facts"]["trusted_session_policy_sha256"],
            hex::encode(Sha256::digest(&bytes)),
        );
        assert!(response["facts"].get("steps").is_none());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(file.argument()));
    }

    let (anchor, transcript) = fixture(VerificationVerdict::Inconclusive);
    let mut empty = policy;
    empty.steps.clear();
    let file = SessionPolicyFile::new(&serde_json::to_vec(&empty).unwrap());
    let (output, response) = invoke(
        &serde_json::to_vec(&transcript).unwrap(),
        &anchor,
        &["--trusted-session-policy", file.argument()],
    );
    assert_eq!(output.status.code(), Some(0), "{response}");
    assert_eq!(response["facts"]["final_verdict"], "inconclusive");
}

#[test]
fn signed_session_cli_refuses_signed_request_substitution_without_disclosing_policy() {
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let input = serde_json::to_vec(&transcript).unwrap();
    let mut policy = expected_trust_session_policy();
    policy.session_id = PRIVATE.into();
    let file = SessionPolicyFile::new(&serde_json::to_vec(&policy).unwrap());
    let (output, response) = invoke(
        &input,
        &anchor,
        &["--trusted-session-policy", file.argument()],
    );
    assert_eq!(output.status.code(), Some(1), "{response}");
    assert_eq!(response["error"]["code"], "SESSION_POLICY_MISMATCH");
    assert!(response.get("facts").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(PRIVATE));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(file.argument()));

    let mut forged = transcript;
    forged.ed25519_signature_hex = "0".repeat(128);
    let (output, response) = invoke(
        &serde_json::to_vec(&forged).unwrap(),
        &anchor,
        &["--trusted-session-policy", file.argument()],
    );
    assert_eq!(output.status.code(), Some(1), "{response}");
    assert_eq!(response["error"]["code"], "SIGNATURE_INVALID");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(PRIVATE));
}

#[test]
fn signed_session_cli_refuses_invalid_policy_before_consuming_candidate_evidence() {
    let (anchor, _) = fixture(VerificationVerdict::Pass);
    for (bytes, expected_error) in [
        (Vec::new(), "SESSION_POLICY_INVALID"),
        (br#"{"steps":[],"steps":[]}"#.to_vec(), "SESSION_POLICY_INVALID"),
        (vec![b' '; MAX_SIGNED_SESSION_POLICY_BYTES + 1], "SESSION_POLICY_TOO_LARGE"),
    ] {
        let file = SessionPolicyFile::new(&bytes);
        let (output, response) = invoke(
            b"not candidate JSON",
            &anchor,
            &["--trusted-session-policy", file.argument()],
        );
        assert_eq!(output.status.code(), Some(1), "{response}");
        assert_eq!(response["error"]["code"], expected_error);
        assert!(response.get("facts").is_none());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(file.argument()));
    }
    let (output, response) = invoke(
        b"not candidate JSON",
        &anchor,
        &["--trusted-session-policy", env!("CARGO_MANIFEST_DIR")],
    );
    assert_eq!(output.status.code(), Some(1), "{response}");
    assert_eq!(response["error"]["code"], "SESSION_POLICY_IO");
}

#[cfg(target_os = "linux")]
fn invoke_session_client(
    language: &str,
    input: &[u8],
    anchor: &VerifyingKey,
    policy: &SessionPolicyFile,
    verifier: &str,
) -> (Output, Value) {
    const PYTHON: &str = r#"
import json, sys
sys.path.insert(0, sys.argv[1])
from franken_verifier import verify_artifact, VerifierError
try:
    result = verify_artifact(
        sys.stdin.buffer.read(), sys.argv[3], verifier=sys.argv[2],
        format="signed-session", trusted_session_policy_path=sys.argv[4],
    )
except VerifierError as error:
    print(json.dumps({"code": error.code}))
    sys.exit(1)
print(json.dumps(result))
"#;
    const JAVASCRIPT: &str = r#"
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { verifyArtifact, VerifierError } = await import(pathToFileURL(process.argv[1]));
try {
  const result = await verifyArtifact(readFileSync(0), process.argv[3], {
    verifier: process.argv[2], format: "signed-session",
    trustedSessionPolicyPath: process.argv[4],
  });
  process.stdout.write(JSON.stringify(result) + "\n");
} catch (error) {
  if (!(error instanceof VerifierError)) throw error;
  process.stdout.write(JSON.stringify({code: error.code}) + "\n");
  process.exitCode = 1;
}
"#;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = match language {
        "python" => {
            let mut command = Command::new("python3");
            command.args(["-c", PYTHON]).arg(root.join("bindings/python"));
            command
        }
        "javascript" => {
            let mut command = Command::new("node");
            command
                .args(["--input-type=module", "--eval", JAVASCRIPT])
                .arg(root.join("bindings/javascript/franken_verifier.mjs"));
            command
        }
        _ => panic!("unknown client language"),
    };
    let mut child = command
        .arg(verifier)
        .arg(hex::encode(anchor.as_bytes()))
        .arg(policy.argument())
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("language client runtime is a standalone test prerequisite");
    let mut stdin = child.stdin.take().unwrap();
    let written = stdin.write_all(input);
    drop(stdin);
    if let Err(error) = written {
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty(), "{language}: {:?}", output.stderr);
    let response = serde_json::from_slice(&output.stdout).expect("one client JSON response");
    (output, response)
}

#[cfg(target_os = "linux")]
#[test]
fn signed_session_language_clients_use_the_real_verifier_and_independent_policy() {
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let input = serde_json::to_vec(&transcript).unwrap();
    let policy = expected_trust_session_policy();
    for language in ["python", "javascript"] {
        let bytes = serde_json::to_vec_pretty(&policy).unwrap();
        let file = SessionPolicyFile::new(&bytes);
        let (output, response) = invoke_session_client(
            language, &input, &anchor, &file, env!("CARGO_BIN_EXE_franken-verifier"),
        );
        assert_eq!(output.status.code(), Some(0), "{language}: {response}");
        assert_eq!(response["facts"]["final_verdict"], "pass");
        assert_eq!(
            response["facts"]["trusted_session_policy_sha256"],
            hex::encode(Sha256::digest(&bytes)),
        );
        for verdict in [VerificationVerdict::Fail, VerificationVerdict::Inconclusive] {
            let (outcome_anchor, candidate) = fixture(verdict.clone());
            let mut outcome_policy = policy.clone();
            if verdict == VerificationVerdict::Fail {
                let sdk = VerifierSdk::new("verifier://facade-test");
                let bundle: frankenengine_verifier_sdk::bundle::ReplayBundle =
                    serde_json::from_slice(BUNDLE).unwrap();
                let canonical = frankenengine_verifier_sdk::bundle::serialize(&bundle).unwrap();
                let migration = sdk.verify_migration_artifact(&canonical).unwrap();
                outcome_policy.steps[1] = SignedSessionStepPolicy {
                    operation: VerificationOperation::MigrationArtifact,
                    artifact_binding_hash: migration.artifact_binding_hash,
                    verdict: VerificationVerdict::Fail,
                };
            } else {
                outcome_policy.steps.clear();
            }
            let outcome_file =
                SessionPolicyFile::new(&serde_json::to_vec(&outcome_policy).unwrap());
            let (output, response) = invoke_session_client(
                language,
                &serde_json::to_vec(&candidate).unwrap(),
                &outcome_anchor,
                &outcome_file,
                env!("CARGO_BIN_EXE_franken-verifier"),
            );
            assert_eq!(output.status.code(), Some(0), "{language}: {response}");
            assert_eq!(response["facts"]["final_verdict"], serde_json::to_value(verdict).unwrap());
        }
        let mut other = policy.clone();
        other.steps[1].operation = VerificationOperation::MigrationArtifact;
        let file = SessionPolicyFile::new(&serde_json::to_vec(&other).unwrap());
        let (output, response) = invoke_session_client(
            language, &input, &anchor, &file, env!("CARGO_BIN_EXE_franken-verifier"),
        );
        assert_eq!(output.status.code(), Some(1), "{language}: {response}");
        assert_eq!(response["code"], "SESSION_POLICY_MISMATCH");

        // Both bindings reject duplicate decoded names even when spellings differ.
        let ambiguous = serde_json::to_string(&policy).unwrap().replacen(
            "\"steps\":", "\"\\u0073teps\":[],\"steps\":", 1,
        );
        let file = SessionPolicyFile::new(ambiguous.as_bytes());
        let (output, response) = invoke_session_client(
            language, &input, &anchor, &file, env!("CARGO_BIN_EXE_franken-verifier"),
        );
        assert_eq!(output.status.code(), Some(1), "{language}: {response}");
        assert_eq!(response["code"], "SESSION_POLICY_INVALID");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn signed_session_language_clients_reject_policy_replacement_after_their_initial_read() {
    use std::os::unix::fs::PermissionsExt;

    // A deliberately dishonest executable tests only the clients' process
    // protocol checks. It changes whitespace in the policy after the client
    // reads it, then returns a response naming the substituted file's digest.
    let executable = SessionPolicyFile::new(br#"#!/usr/bin/env python3
import hashlib, json, sys
data = sys.stdin.buffer.read()
transcript = json.loads(data)
path = sys.argv[sys.argv.index("--trusted-session-policy") + 1]
with open(path, "ab") as policy:
    policy.write(b"\n")
with open(path, "rb") as policy:
    policy_hash = hashlib.sha256(policy.read()).hexdigest()
facts = {key: transcript[key] for key in (
    "session_id", "verifier_identity", "created_at", "final_verdict",
    "transcript_hash", "signer_public_key_hex",
)}
facts["step_count"] = len(transcript["steps"])
facts["trusted_session_policy_sha256"] = policy_hash
print(json.dumps({
    "schema_version": "franken-verifier-cli/v1", "verdict": "verified",
    "format": "signed-session", "scope": "authenticated_verification_session",
    "artifact_sha256": hashlib.sha256(data).hexdigest(), "facts": facts,
}, separators=(",", ":")))
"#);
    std::fs::set_permissions(&executable.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (anchor, transcript) = fixture(VerificationVerdict::Pass);
    let input = serde_json::to_vec(&transcript).unwrap();
    let bytes = serde_json::to_vec(&expected_trust_session_policy()).unwrap();
    for language in ["python", "javascript"] {
        let policy = SessionPolicyFile::new(&bytes);
        let (output, response) =
            invoke_session_client(language, &input, &anchor, &policy, executable.argument());
        assert_eq!(output.status.code(), Some(1), "{language}: {response}");
        assert_eq!(response["code"], "PROTOCOL_INVALID");
        assert_ne!(std::fs::read(&policy.0).unwrap(), bytes);
    }
}
