#![forbid(unsafe_code)]

//! Offline process boundary for the independent verifier SDK.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use frankenengine_verifier_sdk::bundle::{self, BundleError};
use frankenengine_verifier_sdk::capsule::{self, CapsuleError, CapsuleVerdict, ReplayCapsule};
use frankenengine_verifier_sdk::counterfactual::{
    CounterfactualReceiptError, verify_counterfactual_receipt,
};
use frankenengine_verifier_sdk::incident_bundle::{
    CapturedNativeTerminalState, IncidentBundleError, MAX_INCIDENT_BUNDLE_BYTES,
    decode_evidence_json, verify_incident_bundle, verify_incident_bundle_with_run_key,
    verify_incident_bundle_with_runtime_keys,
};
use frankenengine_verifier_sdk::publisher_source::{
    MAX_PUBLISHER_SOURCE_INPUT_BYTES, PublisherSourceError, verify_publisher_source_input,
};
use frankenengine_verifier_sdk::resolution::{
    ResolutionReceiptError, verify_signed_resolution_receipt,
};
use frankenengine_verifier_sdk::{
    FN_LTV_HYBRID_SURVIVED_ALGO_DEATH, LongTermVerificationEvidence, LongTermWitnessTrustAnchor,
    VerificationVerdict, VerifierSdk, long_term_verification_audit_events,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROTOCOL: &str = "franken-verifier-cli/v1";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const COUNTERFACTUAL_INPUT_SCHEMA: &str = "franken-verifier/counterfactual-receipt-input/v1";
const LTV_INPUT_SCHEMA: &str = "franken-verifier/ltv-evidence-input/v1";
const LTV_WITNESS_ANCHOR_DOMAIN: &[u8] = b"franken-verifier/ltv-witness-anchor/v1:";
const MAX_LTV_WITNESS_ANCHOR_BYTES: usize = 64 * 1024;
const USAGE: &str = "franken-verifier verify --format incident-bundle|capsule|signed-bundle|resolution-receipt|publisher-source|counterfactual-receipt|ltv-evidence --trusted-key-hex HEX [--trusted-run-key-hex HEX [--trusted-runtime-key-hex HEX]] [--signature-hex HEX] < artifact";

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
        "incident-bundle"
            | "capsule"
            | "signed-bundle"
            | "resolution-receipt"
            | "publisher-source"
            | "counterfactual-receipt"
            | "ltv-evidence"
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
        ("signed-bundle" | "publisher-source" | "counterfactual-receipt", Some(text)) => {
            let mut bytes = [0_u8; 64];
            hex::decode_to_slice(text, &mut bytes).map_err(|_| {
                failure(
                    "SIGNATURE_MALFORMED",
                    "expected a 64-byte detached signature",
                )
            })?;
            Some(bytes)
        }
        ("signed-bundle" | "publisher-source" | "counterfactual-receipt", None) => {
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

fn resolution_failure(error: &ResolutionReceiptError) -> Failure {
    let code = match error {
        ResolutionReceiptError::Json(_) => "JSON_INVALID",
        ResolutionReceiptError::HashMismatch { .. } => "INTEGRITY_MISMATCH",
        ResolutionReceiptError::SignerKeyMismatch { .. } => "SIGNER_UNTRUSTED",
        ResolutionReceiptError::SignatureHex(_)
        | ResolutionReceiptError::SignatureMalformed { .. } => "SIGNATURE_MALFORMED",
        ResolutionReceiptError::SignatureInvalid => "SIGNATURE_INVALID",
        _ => "EVIDENCE_INVALID",
    };
    failure(code, "signed resolution receipt verification failed")
}

fn publisher_source_failure(error: &PublisherSourceError) -> Failure {
    let code = match error {
        PublisherSourceError::InputTooLarge => "INPUT_TOO_LARGE",
        PublisherSourceError::InputJsonInvalid => "JSON_INVALID",
        PublisherSourceError::SignatureInvalid
        | PublisherSourceError::RevocationSignatureInvalid
        | PublisherSourceError::ProvenanceSignatureInvalid => "SIGNATURE_INVALID",
        PublisherSourceError::ArtifactHashMismatch => "INTEGRITY_MISMATCH",
        PublisherSourceError::PublisherRevoked => "PUBLISHER_REVOKED",
        _ => "EVIDENCE_INVALID",
    };
    failure(code, "publisher-signed source verification failed")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CounterfactualInputEnvelope {
    schema_version: String,
    baseline_integrity_hash: String,
    counterfactual_output: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LtvInputEnvelope {
    schema_version: String,
    witness_anchor_base64: String,
    witness_anchor_signature_hex: String,
    evidence: Value,
}

fn ltv_anchor_signing_payload(anchor_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(LTV_WITNESS_ANCHOR_DOMAIN.len() + 8 + anchor_bytes.len());
    payload.extend_from_slice(LTV_WITNESS_ANCHOR_DOMAIN);
    payload.extend_from_slice(&(anchor_bytes.len() as u64).to_le_bytes());
    payload.extend_from_slice(anchor_bytes);
    payload
}

fn counterfactual_failure(error: &CounterfactualReceiptError) -> Failure {
    let code = match error {
        CounterfactualReceiptError::Json(_) => "JSON_INVALID",
        CounterfactualReceiptError::CounterfactualBundleHashMismatch { .. } => "INTEGRITY_MISMATCH",
        CounterfactualReceiptError::Signature(BundleError::Ed25519SignatureInvalid) => {
            "SIGNATURE_INVALID"
        }
        CounterfactualReceiptError::Signature(BundleError::Ed25519SignatureMalformed {
            ..
        }) => "SIGNATURE_MALFORMED",
        _ => "EVIDENCE_INVALID",
    };
    failure(code, "signed counterfactual receipt verification failed")
}

fn verify(request: &Request, bytes: &[u8]) -> Result<Value, Failure> {
    match request.format.as_str() {
        "publisher-source" => {
            let signature = request
                .signature
                .as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            let verified = verify_publisher_source_input(bytes, signature, &request.anchor)
                .map_err(|error| publisher_source_failure(&error))?;
            // These are authenticated publisher statements and captured bytes.
            // The independent reader does not reconstruct the native graph,
            // establish current revocation, or authorize workload execution.
            Ok(json!({
                "scope": "authenticated_publisher_source_content",
                "facts": verified,
            }))
        }
        "resolution-receipt" => {
            let receipt = verify_signed_resolution_receipt(&request.anchor, bytes)
                .map_err(|error| resolution_failure(&error))?;
            // A verified signed rejection is still a rejection of the package.
            // Authenticate the decision without treating it as run authority or
            // exporting candidate paths, source URLs, rationale or evidence refs.
            Ok(
                json!({"scope": "authenticated_resolution_decision", "facts": {
                    "receipt_id": receipt.receipt_id,
                    "crypto_suite": receipt.crypto_suite,
                    "module_graph_hash": receipt.module_graph_hash,
                    "package_name": receipt.package_name,
                    "requested_range": receipt.requested_range,
                    "policy_profile": receipt.policy_profile,
                    "capability_budget_mode": receipt.capability_budget_mode,
                    "decision": receipt.decision,
                    "selected_version": receipt.selected_version,
                    "rejected_alternative_count": receipt.rejected_alternative_count,
                    "canonical_hash": receipt.canonical_hash,
                    "signer_key_id": receipt.signer_key_id,
                    "signer_public_key_hex": hex::encode(request.anchor.as_bytes()),
                }}),
            )
        }
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
        "counterfactual-receipt" => {
            let signature = request
                .signature
                .as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            let value = decode_evidence_json(bytes).map_err(|error| incident_failure(&error))?;
            let envelope: CounterfactualInputEnvelope =
                serde_json::from_value(value).map_err(|_| {
                    failure("EVIDENCE_INVALID", "invalid counterfactual input transport")
                })?;
            if envelope.schema_version != COUNTERFACTUAL_INPUT_SCHEMA
                || envelope.baseline_integrity_hash.len() != 64
                || envelope
                    .baseline_integrity_hash
                    .bytes()
                    .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
            {
                return Err(failure(
                    "EVIDENCE_INVALID",
                    "invalid counterfactual input transport",
                ));
            }
            verify_counterfactual_receipt(
                &json!({ "integrity_hash": &envelope.baseline_integrity_hash }),
                &envelope.counterfactual_output,
                &request.anchor,
                signature,
            )
            .map_err(|error| counterfactual_failure(&error))?;
            let (mode, result_count) = match envelope.counterfactual_output.get("results") {
                Some(Value::Array(items)) => ("sweep", items.len()),
                _ => ("single", 1_usize),
            };
            if result_count == 0 || result_count > 1024 {
                return Err(failure(
                    "EVIDENCE_INVALID",
                    "counterfactual result count out of bounds",
                ));
            }
            Ok(json!({
                "scope": "authenticated_counterfactual_receipt",
                "facts": {
                    "baseline_integrity_hash": envelope.baseline_integrity_hash,
                    "mode": mode,
                    "result_count": result_count,
                    "signer_public_key_hex": hex::encode(request.anchor.as_bytes()),
                }
            }))
        }
        "ltv-evidence" => {
            let value = decode_evidence_json(bytes).map_err(|error| incident_failure(&error))?;
            let envelope: LtvInputEnvelope = serde_json::from_value(value)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid LTV evidence transport"))?;
            if envelope.schema_version != LTV_INPUT_SCHEMA {
                return Err(failure(
                    "EVIDENCE_INVALID",
                    "invalid LTV evidence transport",
                ));
            }
            if envelope.witness_anchor_base64.len() > MAX_LTV_WITNESS_ANCHOR_BYTES.div_ceil(3) * 4 {
                return Err(failure(
                    "INPUT_TOO_LARGE",
                    "witness anchor exceeds its byte bound",
                ));
            }
            let anchor_bytes = STANDARD
                .decode(&envelope.witness_anchor_base64)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid witness anchor base64"))?;
            if anchor_bytes.len() > MAX_LTV_WITNESS_ANCHOR_BYTES
                || STANDARD.encode(&anchor_bytes) != envelope.witness_anchor_base64
            {
                return Err(failure("EVIDENCE_INVALID", "invalid witness anchor base64"));
            }
            if envelope.witness_anchor_signature_hex.len() != 128
                || envelope
                    .witness_anchor_signature_hex
                    .bytes()
                    .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
            {
                return Err(failure(
                    "SIGNATURE_MALFORMED",
                    "expected a lowercase 64-byte witness anchor signature",
                ));
            }
            let mut anchor_sig = [0_u8; 64];
            hex::decode_to_slice(&envelope.witness_anchor_signature_hex, &mut anchor_sig)
                .map_err(|_| failure("SIGNATURE_MALFORMED", "invalid witness anchor signature"))?;
            request
                .anchor
                .verify_strict(
                    &ltv_anchor_signing_payload(&anchor_bytes),
                    &Signature::from_bytes(&anchor_sig),
                )
                .map_err(|_| {
                    failure(
                        "SIGNATURE_INVALID",
                        "witness anchor signature does not verify under the trusted key",
                    )
                })?;
            let anchor_value = decode_evidence_json(&anchor_bytes)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid signed witness anchor JSON"))?;
            let witness_anchor: LongTermWitnessTrustAnchor = serde_json::from_value(anchor_value)
                .map_err(|_| {
                failure("EVIDENCE_INVALID", "invalid signed witness anchor schema")
            })?;
            let evidence: LongTermVerificationEvidence = serde_json::from_value(envelope.evidence)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid LTV evidence schema"))?;
            let bounded_text = |text: &str, max: usize| {
                !text.is_empty()
                    && text.len() <= max
                    && text.trim() == text
                    && !text.chars().any(char::is_control)
            };
            let canonical_hex64 = |text: &str| {
                let hex_body = text.strip_prefix("sha256:").unwrap_or(text);
                hex_body.len() == 64
                    && hex_body
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            };
            if !bounded_text(&evidence.artifact.artifact_id, 256)
                || !canonical_hex64(&evidence.artifact.artifact_hash)
                || !bounded_text(&evidence.artifact.crypto_suite, 128)
                || !bounded_text(&witness_anchor.witness_group_id, 256)
                || !bounded_text(&witness_anchor.witness_policy_id, 256)
            {
                return Err(failure(
                    "EVIDENCE_INVALID",
                    "LTV metadata violates identifier or hash bounds",
                ));
            }
            let sdk = VerifierSdk::new("verifier://offline-sdk");
            let verification = sdk
                .verify_as_of_ltv(&evidence, &witness_anchor)
                .map_err(|_| failure("EVIDENCE_INVALID", "LTV verification failed"))?;
            if verification.verdict != VerificationVerdict::Pass {
                return Err(failure(
                    "LTV_ANTERIORITY_REJECTED",
                    "long-term verification anteriority or witness checks failed",
                ));
            }
            let hybrid_survived = long_term_verification_audit_events(&verification)
                .iter()
                .any(|event| event.event_code == FN_LTV_HYBRID_SURVIVED_ALGO_DEATH);
            Ok(json!({
                "scope": "authenticated_ltv_anteriority",
                "facts": {
                    "artifact_id": evidence.artifact.artifact_id,
                    "artifact_hash": evidence.artifact.artifact_hash,
                    "crypto_suite": evidence.artifact.crypto_suite,
                    "as_of_unix_seconds": evidence.as_of_unix_seconds.to_string(),
                    "claimed_at_unix_seconds": evidence.artifact.claimed_at_unix_seconds.to_string(),
                    "witness_group_id": witness_anchor.witness_group_id,
                    "witness_policy_id": witness_anchor.witness_policy_id,
                    "reattestation_count": evidence.reattestation_chain.attestations.len(),
                    "hybrid_survived_algo_death": hybrid_survived,
                    "signer_public_key_hex": hex::encode(request.anchor.as_bytes()),
                }
            }))
        }
        _ => Err(failure("UNSUPPORTED_FORMAT", "unsupported evidence format")),
    }
}

fn run(args: &[String], input: &mut impl Read) -> Result<Value, Failure> {
    let request = arguments(args)?;
    let input_limit = if request.format == "publisher-source" {
        MAX_PUBLISHER_SOURCE_INPUT_BYTES
    } else {
        MAX_INCIDENT_BUNDLE_BYTES
    };
    let mut bytes = Vec::new();
    input
        .take(input_limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure {
            code: "INPUT_IO",
            message: "cannot read evidence from stdin",
            exit: 2,
        })?;
    if bytes.len() > input_limit {
        return Err(failure(
            "INPUT_TOO_LARGE",
            if request.format == "publisher-source" {
                "publisher source evidence exceeds its bounded input limit"
            } else {
                "evidence exceeds the 64 MiB input limit"
            },
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
    fn resolution_receipts_require_their_own_explicit_format_and_anchor() {
        assert!(arguments(&args("resolution-receipt", ANCHOR)).is_ok());
        for option in [
            "--trusted-run-key-hex",
            "--trusted-runtime-key-hex",
            "--signature-hex",
        ] {
            let mut request = args("resolution-receipt", ANCHOR);
            request.extend([option.to_string(), ANCHOR.to_string()]);
            assert_eq!(arguments(&request).unwrap_err().code, "USAGE");
        }
        assert_eq!(
            run(&args("resolution-receipt", ANCHOR), &mut &*FIXTURE)
                .unwrap_err()
                .code,
            "JSON_INVALID",
        );
    }

    fn publisher_source_cli_fixture(with_authority: bool) -> (Vec<String>, Vec<u8>, Vec<u8>) {
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};

        // Keep the real producer's source capsule unchanged. This test signs
        // a separate registration statement; it does not simulate a registry
        // admission, provenance attestation, or native execution.
        let vectors: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/module_source_capsules.json"
        ))
        .unwrap();
        let capsule = base64::engine::general_purpose::STANDARD
            .decode(
                vectors["vectors"][0]["module_sources"]["capsule_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let mut manifest = json!({
            "schema_version": "franken-node/extension-registration-manifest/v1",
            "name": "source-audit",
            "publisher_id": "independent-publisher",
            "initial_version": {
                "version": "1.0.0",
                "parent_version": null,
                "content_hash": hex::encode(Sha256::digest(&capsule)),
                "registered_at": "2026-11-10T00:00:00Z",
                "compatible_with": [],
            },
            "tags": [],
        });
        if with_authority {
            manifest["schema_version"] = json!("franken-node/extension-registration-manifest/v2");
            manifest["runtime_authority"] = json!({
                "schema_version": "franken-node/artifact-runtime-authority/v1",
                "policy_revision": "source-audit-policy",
                "allowed_capabilities": ["console", "heap_allocate", "vm_dispatch"],
                "allow_process_shape": false,
                "max_instructions": u64::MAX,
                "max_registers": 128,
                "max_call_depth": 32,
                "max_heap_objects": 128,
                "max_total_memory_bytes": u64::MAX,
                "max_console_entries": 8,
                "max_parse_source_bytes": 65536,
                "max_parse_tokens": 4096,
                "max_parse_recursion_depth": 32,
            });
        }
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let signer = SigningKey::from_bytes(&[21_u8; 32]);
        let mut arguments = args(
            "publisher-source",
            &hex::encode(signer.verifying_key().as_bytes()),
        );
        arguments.extend([
            "--signature-hex".to_string(),
            hex::encode(signer.sign(&manifest_bytes).to_bytes()),
        ]);
        let input = serde_json::to_vec(&json!({
            "schema_version": "franken-verifier/publisher-source-input/v1",
            "manifest_base64": base64::engine::general_purpose::STANDARD.encode(&manifest_bytes),
            "capsule_base64": base64::engine::general_purpose::STANDARD.encode(&capsule),
        }))
        .unwrap();
        (arguments, input, capsule)
    }

    #[test]
    fn publisher_source_cli_authenticates_exact_bytes_without_an_execution_claim() {
        for with_authority in [false, true] {
            let (arguments, input, capsule) = publisher_source_cli_fixture(with_authority);
            let verified = run(&arguments, &mut input.as_slice()).unwrap();
            assert_eq!(verified["format"], "publisher-source");
            assert_eq!(verified["scope"], "authenticated_publisher_source_content");
            assert_eq!(verified["verdict"], "verified");
            assert_eq!(
                verified["artifact_sha256"],
                hex::encode(Sha256::digest(&input)),
            );
            let facts = &verified["facts"];
            assert_eq!(facts["package_name"], "source-audit");
            assert_eq!(facts["publisher_id"], "independent-publisher");
            assert_eq!(
                facts["artifact_sha256"],
                format!("sha256:{}", hex::encode(Sha256::digest(&capsule))),
            );
            assert_eq!(facts["capsule"]["graph_hash_recomputed"], false);
            assert_eq!(facts["capsule"]["capsule_bytes"], capsule.len());
            assert!(facts["capsule"]["file_count"].as_u64().unwrap() > 0);
            if with_authority {
                assert_eq!(
                    facts["runtime_authority"]["max_instructions"],
                    u64::MAX.to_string(),
                );
                assert_eq!(
                    facts["runtime_authority"]["max_total_memory_bytes"],
                    u64::MAX.to_string(),
                );
            } else {
                assert!(facts["runtime_authority"].is_null());
            }
            let report = verified.to_string();
            assert!(!report.contains("node_modules"));
            assert!(!report.contains("PRIVATE-SOURCE-SENTINEL"));
            assert!(facts.get("entrypoint").is_none());
            assert!(facts.get("provenance").is_none());
        }
    }

    #[test]
    fn publisher_source_requires_its_detached_signature_and_independent_anchor() {
        assert_eq!(
            arguments(&args("publisher-source", ANCHOR))
                .unwrap_err()
                .code,
            "SIGNATURE_MALFORMED",
        );
        let (mut malformed, input, _) = publisher_source_cli_fixture(false);
        *malformed.last_mut().unwrap() = "invalid-signature".into();
        assert_eq!(
            arguments(&malformed).unwrap_err().code,
            "SIGNATURE_MALFORMED"
        );

        let (mut foreign, _, _) = publisher_source_cli_fixture(false);
        foreign[4] = ANCHOR.to_string();
        assert_eq!(
            run(&foreign, &mut input.as_slice()).unwrap_err().code,
            "SIGNATURE_INVALID",
        );
        for option in ["--trusted-run-key-hex", "--trusted-runtime-key-hex"] {
            let (mut unrelated, _, _) = publisher_source_cli_fixture(false);
            unrelated.extend([option.to_string(), ANCHOR.to_string()]);
            assert_eq!(arguments(&unrelated).unwrap_err().code, "USAGE");
        }
        let (mut duplicate, _, _) = publisher_source_cli_fixture(false);
        duplicate.extend(["--signature-hex".to_string(), "00".repeat(64)]);
        assert_eq!(arguments(&duplicate).unwrap_err().code, "USAGE");
    }

    #[test]
    fn publisher_source_transport_does_not_hide_tampering_or_extra_claims() {
        use base64::Engine as _;

        let (arguments, input, mut capsule) = publisher_source_cli_fixture(false);
        let mut transport: Value = serde_json::from_slice(&input).unwrap();
        *capsule.last_mut().unwrap() ^= 1;
        transport["capsule_base64"] =
            json!(base64::engine::general_purpose::STANDARD.encode(capsule));
        let changed = serde_json::to_vec(&transport).unwrap();
        assert_eq!(
            run(&arguments, &mut changed.as_slice()).unwrap_err().code,
            "INTEGRITY_MISMATCH",
        );

        let mut transport: Value = serde_json::from_slice(&input).unwrap();
        transport["execution_authorized"] = json!(true);
        let extra = serde_json::to_vec(&transport).unwrap();
        assert_eq!(
            run(&arguments, &mut extra.as_slice()).unwrap_err().code,
            "EVIDENCE_INVALID",
        );
        let mut duplicate = br#"{"schema_version":"duplicate","#.to_vec();
        duplicate.extend_from_slice(&input[1..]);
        let refusal = run(&arguments, &mut duplicate.as_slice()).unwrap_err();
        assert_eq!(refusal.code, "JSON_INVALID");
        assert_eq!(
            refusal.message,
            "publisher-signed source verification failed"
        );
    }

    #[test]
    fn publisher_source_stream_uses_its_own_bound_before_decoding() {
        let (arguments, _, _) = publisher_source_cli_fixture(false);
        let mut input = io::repeat(b' ').take(MAX_PUBLISHER_SOURCE_INPUT_BYTES as u64 + 2);
        let refusal = run(&arguments, &mut input).unwrap_err();
        assert_eq!(refusal.code, "INPUT_TOO_LARGE");
        assert_eq!(
            input.limit(),
            1,
            "stop reading at the publisher transport bound"
        );
    }

    #[test]
    fn an_unbounded_input_stream_is_cut_off_before_verification() {
        let error = run(&args("incident-bundle", ANCHOR), &mut io::repeat(b' ')).unwrap_err();
        assert_eq!(error.code, "INPUT_TOO_LARGE");
    }

    #[test]
    fn counterfactual_receipt_cli_verifies_signed_single_and_sweep_receipts_and_rejects_tampering()
    {
        use ed25519_dalek::{Signer, SigningKey};
        let signer = SigningKey::from_bytes(&[0x33; 32]);
        let anchor_hex = hex::encode(signer.verifying_key().as_bytes());
        let bundle_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let output = json!({
            "metadata": { "bundle_hash": bundle_hash },
            "results": [
                { "metadata": { "bundle_hash": bundle_hash } },
                { "metadata": { "bundle_hash": bundle_hash } }
            ]
        });
        let canonical = serde_json::to_vec(&output).unwrap();
        let sig_hex = hex::encode(signer.sign(&canonical).to_bytes());
        let mut cli_args = args("counterfactual-receipt", &anchor_hex);
        cli_args.extend(["--signature-hex".into(), sig_hex]);
        let payload = serde_json::to_vec(&json!({
            "schema_version": COUNTERFACTUAL_INPUT_SCHEMA,
            "baseline_integrity_hash": bundle_hash,
            "counterfactual_output": output,
        }))
        .unwrap();

        let verified = run(&cli_args, &mut payload.as_slice()).unwrap();
        assert_eq!(verified["scope"], "authenticated_counterfactual_receipt");
        assert_eq!(verified["facts"]["mode"], "sweep");
        assert_eq!(verified["facts"]["result_count"], 2);
        assert_eq!(verified["facts"]["baseline_integrity_hash"], bundle_hash);

        // Mismatched baseline hash must fail closed with INTEGRITY_MISMATCH.
        let wrong_baseline = serde_json::to_vec(&json!({
            "schema_version": COUNTERFACTUAL_INPUT_SCHEMA,
            "baseline_integrity_hash": "f".repeat(64),
            "counterfactual_output": output,
        }))
        .unwrap();
        assert_eq!(
            run(&cli_args, &mut wrong_baseline.as_slice())
                .unwrap_err()
                .code,
            "INTEGRITY_MISMATCH"
        );

        // Foreign anchor must fail closed with SIGNATURE_INVALID.
        let mut wrong_anchor = cli_args.clone();
        wrong_anchor[4] = ANCHOR.to_string();
        assert_eq!(
            run(&wrong_anchor, &mut payload.as_slice())
                .unwrap_err()
                .code,
            "SIGNATURE_INVALID"
        );
    }

    #[test]
    fn ltv_evidence_cli_verifies_anteriority_and_rejects_untrusted_or_backdated_witness() {
        use ed25519_dalek::{Signer, SigningKey};
        use frankenengine_verifier_sdk::{
            LongTermEvidenceRequest, LongTermSignerKey, LongTermThresholdConfig,
            LongTermWitnessSigner, build_long_term_verification_evidence,
        };

        let operator_root = SigningKey::from_bytes(&[0x44; 32]);
        let witness_key_1 = SigningKey::from_bytes(&[0x45; 32]);
        let witness_key_2 = SigningKey::from_bytes(&[0x46; 32]);
        let witness_signers = [
            LongTermWitnessSigner {
                key_id: "wkey-1".into(),
                signing_key: witness_key_1.clone(),
            },
            LongTermWitnessSigner {
                key_id: "wkey-2".into(),
                signing_key: witness_key_2.clone(),
            },
        ];
        let evidence = build_long_term_verification_evidence(
            &LongTermEvidenceRequest {
                artifact_id: "release-capsule-1".into(),
                artifact_hash: "a".repeat(64),
                crypto_suite: "ed25519-v1".into(),
                claimed_at_unix_seconds: 1_700_000_100,
                co_marker_hashes: vec!["b".repeat(64)],
                reattestation_appended_marker_hashes: vec!["c".repeat(64)],
                reattested_at_unix_seconds: 1_700_000_200,
                observed_at_unix_seconds: 1_700_000_300,
                as_of_unix_seconds: 1_700_000_500,
                suite_valid_from_unix_seconds: 1_700_000_000,
                witness_group_id: "independent-witness-quorum".into(),
                witness_policy_id: "policy-quorum-2of2".into(),
                witness_threshold: 2,
                trace_id: "trace-ltv-cli".into(),
                timestamp: "2026-11-11T00:00:00Z".into(),
            },
            &witness_signers,
        )
        .unwrap();
        let witness_anchor = LongTermWitnessTrustAnchor {
            witness_group_id: "independent-witness-quorum".into(),
            witness_policy_id: "policy-quorum-2of2".into(),
            threshold_config: LongTermThresholdConfig {
                threshold: 2,
                total_signers: 2,
                signer_keys: vec![
                    LongTermSignerKey {
                        key_id: "wkey-1".into(),
                        public_key_hex: hex::encode(witness_key_1.verifying_key().as_bytes()),
                    },
                    LongTermSignerKey {
                        key_id: "wkey-2".into(),
                        public_key_hex: hex::encode(witness_key_2.verifying_key().as_bytes()),
                    },
                ],
            },
        };
        let anchor_bytes = serde_json::to_vec(&witness_anchor).unwrap();
        let anchor_sig = operator_root
            .sign(&ltv_anchor_signing_payload(&anchor_bytes))
            .to_bytes();
        let cli_args = args(
            "ltv-evidence",
            &hex::encode(operator_root.verifying_key().as_bytes()),
        );
        let payload = serde_json::to_vec(&json!({
            "schema_version": LTV_INPUT_SCHEMA,
            "witness_anchor_base64": STANDARD.encode(&anchor_bytes),
            "witness_anchor_signature_hex": hex::encode(anchor_sig),
            "evidence": evidence,
        }))
        .unwrap();

        let verified = run(&cli_args, &mut payload.as_slice()).unwrap();
        assert_eq!(verified["scope"], "authenticated_ltv_anteriority");
        assert_eq!(verified["facts"]["artifact_id"], "release-capsule-1");
        assert_eq!(verified["facts"]["as_of_unix_seconds"], "1700000500");
        assert_eq!(verified["facts"]["reattestation_count"], 1);

        // Foreign operator root anchor must be rejected with SIGNATURE_INVALID.
        assert_eq!(
            run(&args("ltv-evidence", ANCHOR), &mut payload.as_slice())
                .unwrap_err()
                .code,
            "SIGNATURE_INVALID"
        );

        // Backdated witness (observed_at > as_of) must fail closed with LTV_ANTERIORITY_REJECTED.
        let mut backdated = evidence;
        backdated.as_of_unix_seconds = 1_700_000_250;
        let bad_payload = serde_json::to_vec(&json!({
            "schema_version": LTV_INPUT_SCHEMA,
            "witness_anchor_base64": STANDARD.encode(&anchor_bytes),
            "witness_anchor_signature_hex": hex::encode(anchor_sig),
            "evidence": backdated,
        }))
        .unwrap();
        assert_eq!(
            run(&cli_args, &mut bad_payload.as_slice())
                .unwrap_err()
                .code,
            "LTV_ANTERIORITY_REJECTED"
        );
    }
}
