#![forbid(unsafe_code)]

//! Offline process boundary for the independent verifier SDK.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ed25519_dalek::VerifyingKey;
use frankenengine_verifier_sdk::bundle::{self, BundleError};
use frankenengine_verifier_sdk::capsule::{self, CapsuleError, CapsuleVerdict, ReplayCapsule};
use frankenengine_verifier_sdk::incident_bundle::{
    CapturedNativeTerminalState, IncidentBundleError, MAX_INCIDENT_BUNDLE_BYTES,
    decode_evidence_json, verify_incident_bundle,
};
use serde_json::{Value, json};

const PROTOCOL: &str = "franken-verifier-cli/v1";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const USAGE: &str = "franken-verifier verify --format incident-bundle|capsule|signed-bundle --trusted-key-hex HEX [--signature-hex HEX] < artifact";

struct Request {
    format: String,
    anchor: VerifyingKey,
    signature: Option<[u8; 64]>,
}

struct Failure {
    code: &'static str,
    message: &'static str,
    exit: u8,
}

fn failure(code: &'static str, message: &'static str) -> Failure {
    Failure { code, message, exit: 1 }
}

fn arguments(args: &[String]) -> Result<Request, Failure> {
    let usage = || Failure { code: "USAGE", message: USAGE, exit: 2 };
    if args.first().map(String::as_str) != Some("verify") {
        return Err(usage());
    }
    let (mut format, mut anchor, mut signature) = (None, None, None);
    let mut options = args[1..].chunks_exact(2);
    for option in &mut options {
        let slot = match option[0].as_str() {
            "--format" => &mut format,
            "--trusted-key-hex" => &mut anchor,
            "--signature-hex" => &mut signature,
            _ => return Err(usage()),
        };
        if slot.replace(option[1].clone()).is_some() {
            return Err(usage());
        }
    }
    if !options.remainder().is_empty() {
        return Err(usage());
    }
    let format = format.ok_or_else(usage)?;
    if !matches!(format.as_str(), "incident-bundle" | "capsule" | "signed-bundle") {
        return Err(failure("UNSUPPORTED_FORMAT", "unsupported evidence format"));
    }
    let mut key = [0_u8; 32];
    hex::decode_to_slice(anchor.ok_or_else(usage)?, &mut key)
        .map_err(|_| failure("ANCHOR_INVALID", "expected a 32-byte hexadecimal public key"))?;
    let anchor = VerifyingKey::from_bytes(&key)
        .map_err(|_| failure("ANCHOR_INVALID", "invalid Ed25519 public key"))?;
    let signature = match (format.as_str(), signature) {
        ("signed-bundle", Some(text)) => {
            let mut bytes = [0_u8; 64];
            hex::decode_to_slice(text, &mut bytes)
                .map_err(|_| failure("SIGNATURE_MALFORMED", "expected a 64-byte detached signature"))?;
            Some(bytes)
        }
        ("signed-bundle", None) | (_, Some(_)) => return Err(usage()),
        (_, None) => None,
    };
    Ok(Request { format, anchor, signature })
}

fn incident_failure(error: &IncidentBundleError) -> Failure {
    let code = match error {
        IncidentBundleError::TooLarge { .. } => "INPUT_TOO_LARGE",
        IncidentBundleError::Json(_) => "JSON_INVALID",
        IncidentBundleError::SignerNotTrusted | IncidentBundleError::SignatureKeySourceUntrusted => "SIGNER_UNTRUSTED",
        IncidentBundleError::SignatureMalformed => "SIGNATURE_MALFORMED",
        IncidentBundleError::SignatureInvalid => "SIGNATURE_INVALID",
        IncidentBundleError::IntegrityMismatch { .. } => "INTEGRITY_MISMATCH",
        IncidentBundleError::DecisionSequenceMismatch { .. } => "DECISION_SEQUENCE_MISMATCH",
        _ => "EVIDENCE_INVALID",
    };
    // Do not echo private evidence, attacker-controlled field names or payloads.
    failure(code, "incident evidence verification failed")
}

fn verify(request: &Request, bytes: &[u8]) -> Result<Value, Failure> {
    match request.format.as_str() {
        "incident-bundle" => {
            let verified = verify_incident_bundle(bytes, &request.anchor)
                .map_err(|error| incident_failure(&error))?;
            let capture = verified.native_capture.map(|capture| {
                let state = match capture.captured_terminal_state {
                    CapturedNativeTerminalState::Completed => "completed",
                    CapturedNativeTerminalState::UncaughtException => "uncaught_exception",
                    CapturedNativeTerminalState::EngineFailure => "engine_failure",
                };
                json!({"payload_sha256": capture.payload_sha256, "payload_bytes": capture.payload_bytes,
                    "captured_terminal_state": state, "host_io_exchange_count": capture.host_io_exchange_count})
            });
            Ok(json!({"scope": "authenticated_recorded_incident", "facts": {
                "bundle_id": verified.bundle_id, "incident_id": verified.incident_id,
                "created_at": verified.created_at, "policy_version": verified.policy_version,
                "event_count": verified.event_count, "integrity_hash": verified.integrity_hash,
                "decision_sequence_hash": verified.decision_sequence_hash,
                "signer_public_key_hex": verified.signer_public_key_hex,
                "signing_identity": verified.signing_identity, "native_capture": capture}}))
        }
        "capsule" => {
            let value = decode_evidence_json(bytes).map_err(|error| incident_failure(&error))?;
            let evidence: ReplayCapsule = serde_json::from_value(value)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid signed capsule schema"))?;
            let result = capsule::replay(&request.anchor, &evidence, "verifier://offline-sdk")
                .map_err(|error| match error {
                    CapsuleError::Ed25519SignatureInvalid | CapsuleError::SignatureInvalid(_) => failure("SIGNATURE_INVALID", "capsule signature does not verify"),
                    CapsuleError::Ed25519SignatureMalformed { .. } => failure("SIGNATURE_MALFORMED", "malformed capsule signature"),
                    _ => failure("EVIDENCE_INVALID", "capsule verification failed"),
                })?;
            if result.verdict != CapsuleVerdict::Pass {
                return Err(failure("CAPSULE_REPLAY_MISMATCH", "capsule content hash differs from its signed expected hash"));
            }
            Ok(json!({"scope": "authenticated_capsule_content", "facts": {
                "capsule_id": result.capsule_id, "expected_hash": result.expected_hash,
                "actual_hash": result.actual_hash, "signer_public_key_hex": hex::encode(request.anchor.as_bytes())}}))
        }
        "signed-bundle" => {
            let evidence = bundle::verify(bytes)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid canonical SDK replay bundle"))?;
            let signature = request.signature.as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            bundle::verify_signed_bundle(&request.anchor, &evidence, signature)
                .map_err(|error| match error {
                    BundleError::Ed25519SignatureInvalid => failure("SIGNATURE_INVALID", "detached signature does not verify"),
                    _ => failure("EVIDENCE_INVALID", "signed SDK bundle verification failed"),
                })?;
            Ok(json!({"scope": "authenticated_sdk_replay_bundle", "facts": {
                "bundle_id": evidence.bundle_id, "incident_id": evidence.incident_id,
                "event_count": evidence.timeline.len(), "integrity_hash": evidence.integrity_hash,
                "signer_public_key_hex": hex::encode(request.anchor.as_bytes())}}))
        }
        _ => Err(failure("UNSUPPORTED_FORMAT", "unsupported evidence format")),
    }
}

fn run(args: &[String], input: &mut impl Read) -> Result<Value, Failure> {
    let request = arguments(args)?;
    let mut bytes = Vec::new();
    input.take(MAX_INCIDENT_BUNDLE_BYTES as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| Failure { code: "INPUT_IO", message: "cannot read evidence from stdin", exit: 2 })?;
    if bytes.len() > MAX_INCIDENT_BUNDLE_BYTES {
        return Err(failure("INPUT_TOO_LARGE", "evidence exceeds the 64 MiB input limit"));
    }
    let mut result = verify(&request, &bytes)?;
    result["schema_version"] = json!(PROTOCOL);
    result["format"] = json!(request.format);
    result["verdict"] = json!("verified");
    Ok(result)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let (response, code) = match run(&args, &mut io::stdin().lock()) {
        Ok(response) => (response, 0),
        Err(error) => (json!({"schema_version": PROTOCOL, "verdict": "rejected",
            "error": {"code": error.code, "message": error.message}}), error.exit),
    };
    let Ok(mut encoded) = serde_json::to_vec(&response) else { return ExitCode::from(2); };
    if encoded.len() > MAX_RESPONSE_BYTES {
        encoded = br#"{"schema_version":"franken-verifier-cli/v1","verdict":"rejected","error":{"code":"RESPONSE_TOO_LARGE","message":"verified metadata exceeds the response limit"}}"#.to_vec();
        if io::stdout().lock().write_all(&encoded).is_err() { return ExitCode::from(2); }
        return ExitCode::from(1);
    }
    encoded.push(b'\n');
    if io::stdout().lock().write_all(&encoded).is_err() { return ExitCode::from(2); }
    ExitCode::from(code)
}
