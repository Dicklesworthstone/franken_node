#![forbid(unsafe_code)]

//! Offline process boundary for the independent verifier SDK.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ed25519_dalek::VerifyingKey;
use frankenengine_verifier_sdk::bundle::{self, BundleError};
use frankenengine_verifier_sdk::capsule::{self, CapsuleError, CapsuleVerdict, ReplayCapsule};
use frankenengine_verifier_sdk::incident_bundle::{
    CapturedNativeTerminalState, IncidentBundleError, MAX_INCIDENT_BUNDLE_BYTES,
    decode_evidence_json, verify_incident_bundle, verify_incident_bundle_with_run_key,
    verify_incident_bundle_with_runtime_keys,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROTOCOL: &str = "franken-verifier-cli/v1";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const USAGE: &str = "franken-verifier verify --format incident-bundle|capsule|signed-bundle --trusted-key-hex HEX [--trusted-run-key-hex HEX [--trusted-runtime-key-hex HEX]] [--signature-hex HEX] < artifact";

#[derive(Debug)]
struct Request {
    format: String,
    anchor: VerifyingKey,
    run_anchor: Option<VerifyingKey>,
    runtime_anchor: Option<VerifyingKey>,
    signature: Option<[u8; 64]>,
}

#[derive(Debug)]
struct Failure {
    code: &'static str,
    message: &'static str,
    exit: u8,
}

fn failure(code: &'static str, message: &'static str) -> Failure {
    Failure {
        code,
        message,
        exit: 1,
    }
}

fn arguments(args: &[String]) -> Result<Request, Failure> {
    let usage = || Failure {
        code: "USAGE",
        message: USAGE,
        exit: 2,
    };
    if args.first().map(String::as_str) != Some("verify") {
        return Err(usage());
    }
    let (mut format, mut anchor, mut run_anchor, mut runtime_anchor, mut signature) =
        (None, None, None, None, None);
    let (options, remainder) = args[1..].as_chunks::<2>();
    for option in options {
        let slot = match option[0].as_str() {
            "--format" => &mut format,
            "--trusted-key-hex" => &mut anchor,
            "--trusted-run-key-hex" => &mut run_anchor,
            "--trusted-runtime-key-hex" => &mut runtime_anchor,
            "--signature-hex" => &mut signature,
            _ => return Err(usage()),
        };
        if slot.replace(option[1].clone()).is_some() {
            return Err(usage());
        }
    }
    if !remainder.is_empty() {
        return Err(usage());
    }
    let format = format.ok_or_else(usage)?;
    if !matches!(
        format.as_str(),
        "incident-bundle" | "capsule" | "signed-bundle"
    ) {
        return Err(failure("UNSUPPORTED_FORMAT", "unsupported evidence format"));
    }
    let mut key = [0_u8; 32];
    hex::decode_to_slice(anchor.ok_or_else(usage)?, &mut key).map_err(|_| {
        failure(
            "ANCHOR_INVALID",
            "expected a 32-byte hexadecimal public key",
        )
    })?;
    let anchor = VerifyingKey::from_bytes(&key)
        .map_err(|_| failure("ANCHOR_INVALID", "invalid Ed25519 public key"))?;
    let run_anchor = match (format.as_str(), run_anchor) {
        ("incident-bundle", Some(text)) => {
            let mut key = [0_u8; 32];
            hex::decode_to_slice(text, &mut key).map_err(|_| {
                failure(
                    "RUN_ANCHOR_INVALID",
                    "expected a 32-byte hexadecimal run public key",
                )
            })?;
            Some(
                VerifyingKey::from_bytes(&key)
                    .map_err(|_| failure("RUN_ANCHOR_INVALID", "invalid Ed25519 run public key"))?,
            )
        }
        (_, Some(_)) => return Err(usage()),
        (_, None) => None,
    };
    let runtime_anchor = match (format.as_str(), run_anchor.as_ref(), runtime_anchor) {
        ("incident-bundle", Some(_), Some(text)) => {
            let mut key = [0_u8; 32];
            hex::decode_to_slice(text, &mut key).map_err(|_| {
                failure(
                    "RUNTIME_ANCHOR_INVALID",
                    "expected a 32-byte hexadecimal product-root public key",
                )
            })?;
            Some(VerifyingKey::from_bytes(&key).map_err(|_| {
                failure(
                    "RUNTIME_ANCHOR_INVALID",
                    "invalid Ed25519 product-root public key",
                )
            })?)
        }
        (_, _, Some(_)) => return Err(usage()),
        (_, _, None) => None,
    };
    let signature = match (format.as_str(), signature) {
        ("signed-bundle", Some(text)) => {
            let mut bytes = [0_u8; 64];
            hex::decode_to_slice(text, &mut bytes).map_err(|_| {
                failure(
                    "SIGNATURE_MALFORMED",
                    "expected a 64-byte detached signature",
                )
            })?;
            Some(bytes)
        }
        ("signed-bundle", None) => {
            return Err(failure(
                "SIGNATURE_MALFORMED",
                "detached signature is required",
            ));
        }
        (_, Some(_)) => return Err(usage()),
        (_, None) => None,
    };
    Ok(Request {
        format,
        anchor,
        run_anchor,
        runtime_anchor,
        signature,
    })
}

fn incident_failure(error: &IncidentBundleError) -> Failure {
    let code = match error {
        IncidentBundleError::TooLarge { .. } => "INPUT_TOO_LARGE",
        IncidentBundleError::Json(_) => "JSON_INVALID",
        IncidentBundleError::SignerNotTrusted
        | IncidentBundleError::SignatureKeySourceUntrusted => "SIGNER_UNTRUSTED",
        IncidentBundleError::SignatureMalformed => "SIGNATURE_MALFORMED",
        IncidentBundleError::SignatureInvalid => "SIGNATURE_INVALID",
        IncidentBundleError::IntegrityMismatch { .. } => "INTEGRITY_MISMATCH",
        IncidentBundleError::DecisionSequenceMismatch { .. } => "DECISION_SEQUENCE_MISMATCH",
        IncidentBundleError::RunOriginMissing => "RUN_ORIGIN_MISSING",
        IncidentBundleError::RunOriginInvalid { .. } => "RUN_ORIGIN_INVALID",
        IncidentBundleError::RunOriginSignatureMalformed => "RUN_ORIGIN_SIGNATURE_MALFORMED",
        IncidentBundleError::RunOriginSignatureInvalid => "RUN_ORIGIN_SIGNATURE_INVALID",
        IncidentBundleError::RuntimeOriginMissing => "RUNTIME_ORIGIN_MISSING",
        IncidentBundleError::RuntimeOriginInvalid { .. } => "RUNTIME_ORIGIN_INVALID",
        IncidentBundleError::RuntimeOriginSignerNotTrusted => "RUNTIME_ORIGIN_SIGNER_UNTRUSTED",
        IncidentBundleError::RuntimeOriginCaptureSignatureInvalid => {
            "RUNTIME_ORIGIN_CAPTURE_SIGNATURE_INVALID"
        }
        IncidentBundleError::RuntimeOriginLedgerSignatureInvalid => {
            "RUNTIME_ORIGIN_LEDGER_SIGNATURE_INVALID"
        }
        _ => "EVIDENCE_INVALID",
    };
    // Do not echo private evidence, attacker-controlled field names or payloads.
    failure(code, "signed evidence verification failed")
}

fn verify(request: &Request, bytes: &[u8]) -> Result<Value, Failure> {
    match request.format.as_str() {
        "incident-bundle" => {
            let (verified, run_origin, runtime_origin) =
                match (&request.run_anchor, &request.runtime_anchor) {
                    (Some(run_anchor), Some(runtime_anchor)) => {
                        let verified = verify_incident_bundle_with_runtime_keys(
                            bytes,
                            &request.anchor,
                            run_anchor,
                            runtime_anchor,
                        )
                        .map_err(|error| incident_failure(&error))?;
                        (
                            verified.bundle,
                            Some(verified.run_origin),
                            Some(verified.runtime_origin),
                        )
                    }
                    (Some(run_anchor), None) => {
                        let verified =
                            verify_incident_bundle_with_run_key(bytes, &request.anchor, run_anchor)
                                .map_err(|error| incident_failure(&error))?;
                        (verified.bundle, Some(verified.run_origin), None)
                    }
                    (None, None) => (
                        verify_incident_bundle(bytes, &request.anchor)
                            .map_err(|error| incident_failure(&error))?,
                        None,
                        None,
                    ),
                    (None, Some(_)) => return Err(failure("USAGE", USAGE)),
                };
            let capture = verified.native_capture.map(|capture| {
                let state = match capture.captured_terminal_state {
                    CapturedNativeTerminalState::Completed => "completed",
                    CapturedNativeTerminalState::UncaughtException => "uncaught_exception",
                    CapturedNativeTerminalState::EngineFailure => "engine_failure",
                };
                json!({"payload_sha256": capture.payload_sha256, "payload_bytes": capture.payload_bytes,
                    "captured_terminal_state": state, "host_io_exchange_count": capture.host_io_exchange_count})
            });
            let mut result = json!({"scope": "authenticated_recorded_incident", "facts": {
                "bundle_id": verified.bundle_id, "incident_id": verified.incident_id,
                "created_at": verified.created_at, "policy_version": verified.policy_version,
                "event_count": verified.event_count, "integrity_hash": verified.integrity_hash,
                "decision_sequence_hash": verified.decision_sequence_hash,
                "signer_public_key_hex": verified.signer_public_key_hex,
                "signing_identity": verified.signing_identity, "native_capture": capture}});
            if let Some(origin) = run_origin {
                result["scope"] = json!("authenticated_run_incident");
                result["facts"]["run_origin"] = json!({
                    "receipt_id": origin.receipt_id, "receipt_hash": origin.receipt_hash,
                    "signer_public_key_hex": origin.signer_public_key_hex,
                    "record_sha256": origin.record_sha256,
                });
            }
            if let Some(origin) = runtime_origin {
                result["scope"] = json!("authenticated_runtime_incident");
                result["facts"]["runtime_origin"] = json!(origin);
            }
            Ok(result)
        }
        "capsule" => {
            let value = decode_evidence_json(bytes).map_err(|error| incident_failure(&error))?;
            let evidence: ReplayCapsule = serde_json::from_value(value)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid signed capsule schema"))?;
            let result = capsule::replay(&request.anchor, &evidence, "verifier://offline-sdk")
                .map_err(|error| match error {
                    CapsuleError::Ed25519SignatureInvalid | CapsuleError::SignatureInvalid(_) => {
                        failure("SIGNATURE_INVALID", "capsule signature does not verify")
                    }
                    CapsuleError::Ed25519SignatureMalformed { .. } => {
                        failure("SIGNATURE_MALFORMED", "malformed capsule signature")
                    }
                    _ => failure("EVIDENCE_INVALID", "capsule verification failed"),
                })?;
            if result.verdict != CapsuleVerdict::Pass {
                return Err(failure(
                    "CAPSULE_REPLAY_MISMATCH",
                    "capsule content hash differs from its signed expected hash",
                ));
            }
            Ok(json!({"scope": "authenticated_capsule_content", "facts": {
                "capsule_id": result.capsule_id, "expected_hash": result.expected_hash,
                "actual_hash": result.actual_hash, "signer_public_key_hex": hex::encode(request.anchor.as_bytes())}}))
        }
        "signed-bundle" => {
            let evidence = bundle::verify(bytes)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid canonical SDK replay bundle"))?;
            let signature = request
                .signature
                .as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            bundle::verify_signed_bundle(&request.anchor, &evidence, signature).map_err(
                |error| match error {
                    BundleError::Ed25519SignatureInvalid => {
                        failure("SIGNATURE_INVALID", "detached signature does not verify")
                    }
                    _ => failure("EVIDENCE_INVALID", "signed SDK bundle verification failed"),
                },
            )?;
            Ok(
                json!({"scope": "authenticated_sdk_replay_bundle", "facts": {
                "bundle_id": evidence.bundle_id, "incident_id": evidence.incident_id,
                "event_count": evidence.timeline.len(), "integrity_hash": evidence.integrity_hash,
                "signer_public_key_hex": hex::encode(request.anchor.as_bytes())}}),
            )
        }
        _ => Err(failure("UNSUPPORTED_FORMAT", "unsupported evidence format")),
    }
}

fn run(args: &[String], input: &mut impl Read) -> Result<Value, Failure> {
    let request = arguments(args)?;
    let mut bytes = Vec::new();
    input
        .take(MAX_INCIDENT_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure {
            code: "INPUT_IO",
            message: "cannot read evidence from stdin",
            exit: 2,
        })?;
    if bytes.len() > MAX_INCIDENT_BUNDLE_BYTES {
        return Err(failure(
            "INPUT_TOO_LARGE",
            "evidence exceeds the 64 MiB input limit",
        ));
    }
    let mut result = verify(&request, &bytes)?;
    result["schema_version"] = json!(PROTOCOL);
    result["format"] = json!(request.format);
    result["verdict"] = json!("verified");
    result["artifact_sha256"] = json!(hex::encode(Sha256::digest(&bytes)));
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
        Err(error) => (
            json!({"schema_version": PROTOCOL, "verdict": "rejected",
                "error": {"code": error.code, "message": error.message}}),
            error.exit,
        ),
    };
    let Ok(mut encoded) = serde_json::to_vec(&response) else {
        return ExitCode::from(2);
    };
    if encoded.len() > MAX_RESPONSE_BYTES {
        encoded = br#"{"schema_version":"franken-verifier-cli/v1","verdict":"rejected","error":{"code":"RESPONSE_TOO_LARGE","message":"verified metadata exceeds the response limit"}}"#.to_vec();
        if io::stdout().lock().write_all(&encoded).is_err() {
            return ExitCode::from(2);
        }
        return ExitCode::from(1);
    }
    encoded.push(b'\n');
    if io::stdout().lock().write_all(&encoded).is_err() {
        return ExitCode::from(2);
    }
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle");
    const ANCHOR: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn args(format: &str, anchor: &str) -> Vec<String> {
        ["verify", "--format", format, "--trusted-key-hex", anchor]
            .map(str::to_owned)
            .to_vec()
    }

    #[test]
    fn cli_authenticates_recorded_evidence_and_binds_the_original_bytes() {
        let verified = run(&args("incident-bundle", ANCHOR), &mut &*FIXTURE).unwrap();
        assert_eq!(verified["facts"]["event_count"], 3);
        assert_eq!(verified["facts"]["signer_public_key_hex"], ANCHOR);
        assert_eq!(verified["scope"], "authenticated_recorded_incident");
        assert_eq!(
            verified["artifact_sha256"],
            hex::encode(Sha256::digest(FIXTURE))
        );
    }

    #[test]
    fn cli_cannot_select_its_anchor_from_the_bundle() {
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]).verifying_key();
        let error = run(
            &args("incident-bundle", &hex::encode(wrong.as_bytes())),
            &mut &*FIXTURE,
        )
        .unwrap_err();
        assert_eq!(error.code, "SIGNER_UNTRUSTED");
    }

    #[test]
    fn explicit_run_authority_cannot_silently_downgrade_to_bundle_authentication() {
        let mut strong = args("incident-bundle", ANCHOR);
        strong.extend(["--trusted-run-key-hex".into(), ANCHOR.into()]);
        assert_eq!(
            run(&strong, &mut &*FIXTURE).unwrap_err().code,
            "RUN_ORIGIN_MISSING"
        );
        strong.extend(["--trusted-run-key-hex".into(), ANCHOR.into()]);
        assert_eq!(arguments(&strong).unwrap_err().code, "USAGE");
        let mut other_format = args("capsule", ANCHOR);
        other_format.extend(["--trusted-run-key-hex".into(), ANCHOR.into()]);
        assert_eq!(arguments(&other_format).unwrap_err().code, "USAGE");
        let mut malformed = args("incident-bundle", ANCHOR);
        malformed.extend(["--trusted-run-key-hex".into(), "not-a-key".into()]);
        assert_eq!(
            arguments(&malformed).unwrap_err().code,
            "RUN_ANCHOR_INVALID"
        );
    }

    #[test]
    fn runtime_authority_requires_run_authority_and_never_falls_back() {
        let mut strong = args("incident-bundle", ANCHOR);
        strong.extend(["--trusted-runtime-key-hex".into(), ANCHOR.into()]);
        assert_eq!(arguments(&strong).unwrap_err().code, "USAGE");
        strong.extend(["--trusted-run-key-hex".into(), ANCHOR.into()]);
        assert_eq!(
            run(&strong, &mut &*FIXTURE).unwrap_err().code,
            "RUN_ORIGIN_MISSING"
        );
        strong.extend(["--trusted-runtime-key-hex".into(), ANCHOR.into()]);
        assert_eq!(arguments(&strong).unwrap_err().code, "USAGE");

        let mut malformed = args("incident-bundle", ANCHOR);
        malformed.extend([
            "--trusted-run-key-hex".into(),
            ANCHOR.into(),
            "--trusted-runtime-key-hex".into(),
            "malformed".into(),
        ]);
        assert_eq!(
            arguments(&malformed).unwrap_err().code,
            "RUNTIME_ANCHOR_INVALID"
        );
        let mut wrong_format = args("capsule", ANCHOR);
        wrong_format.extend(["--trusted-runtime-key-hex".into(), ANCHOR.into()]);
        assert_eq!(arguments(&wrong_format).unwrap_err().code, "USAGE");
    }

    #[test]
    fn unsigned_sdk_integrity_is_never_an_authenticity_verdict() {
        assert_eq!(
            arguments(&args("signed-bundle", ANCHOR)).unwrap_err().code,
            "SIGNATURE_MALFORMED"
        );
    }

    #[test]
    fn duplicate_options_and_unknown_formats_are_not_accepted() {
        let mut duplicate = args("incident-bundle", ANCHOR);
        duplicate.extend(["--format".into(), "capsule".into()]);
        assert_eq!(arguments(&duplicate).unwrap_err().code, "USAGE");
        assert_eq!(
            arguments(&args("auto", ANCHOR)).unwrap_err().code,
            "UNSUPPORTED_FORMAT"
        );
    }

    #[test]
    fn an_unbounded_input_stream_is_cut_off_before_verification() {
        let error = run(&args("incident-bundle", ANCHOR), &mut io::repeat(b' ')).unwrap_err();
        assert_eq!(error.code, "INPUT_TOO_LARGE");
    }
}
