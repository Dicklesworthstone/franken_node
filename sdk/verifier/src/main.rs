#![forbid(unsafe_code)]

//! Offline process boundary for the independent verifier SDK.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Timelike, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use frankenengine_verifier_sdk::bundle::{self, BundleError};
use frankenengine_verifier_sdk::capsule::{self, CapsuleError, CapsuleVerdict, ReplayCapsule};
use frankenengine_verifier_sdk::counterfactual::{
    CounterfactualIncidentTrust, CounterfactualReceiptError, verify_counterfactual_incident,
    verify_counterfactual_receipt,
};
use frankenengine_verifier_sdk::fleet_quiescence::{
    FleetCoordinatorTrust, FleetQuiescencePolicy, MAX_FLEET_QUIESCENCE_POLICY_BYTES,
    MAX_FLEET_QUIESCENCE_RESPONSE_BYTES, parse_fleet_quiescence_policy, verify_fleet_epoch_commit,
    verify_fleet_quiescence_observations,
};
use frankenengine_verifier_sdk::incident_bundle::{
    CapturedNativeTerminalState, IncidentBundleError, MAX_INCIDENT_BUNDLE_BYTES,
    VerifiedIncidentBundle, VerifiedRunOrigin, VerifiedRuntimeOrigin, decode_evidence_json,
    verify_incident_bundle, verify_incident_bundle_with_run_key,
    verify_incident_bundle_with_runtime_keys,
};
use frankenengine_verifier_sdk::native_session::{
    MAX_NATIVE_SESSION_FORENSICS_V3_BYTES, NativeSessionForensicError,
    verify_native_session_forensics,
};
use frankenengine_verifier_sdk::publisher_source::{
    MAX_PUBLISHER_SOURCE_INPUT_BYTES, MAX_PUBLISHER_SOURCE_TRUST_INPUT_BYTES, PublisherSourceError,
    PublisherSourceExpectedIdentity, PublisherSourceIdentityError, PublisherTrustAnchors,
    verify_publisher_source_input, verify_publisher_source_input_with_expected_identity,
    verify_publisher_source_trust_input,
    verify_publisher_source_trust_input_with_expected_identity,
};
use frankenengine_verifier_sdk::resolution::{
    ResolutionReceiptError, verify_signed_resolution_receipt,
};
use frankenengine_verifier_sdk::{
    FN_LTV_HYBRID_SURVIVED_ALGO_DEATH, LongTermVerificationEvidence, LongTermWitnessTrustAnchor,
    SignedSessionTranscript, VerificationVerdict, VerifierSdk, VerifierSdkError,
    long_term_verification_audit_events,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROTOCOL: &str = "franken-verifier-cli/v1";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const COUNTERFACTUAL_INPUT_SCHEMA: &str = "franken-verifier/counterfactual-receipt-input/v1";
const COUNTERFACTUAL_INCIDENT_INPUT_SCHEMA: &str =
    "franken-verifier/counterfactual-incident-input/v1";
const LTV_INPUT_SCHEMA: &str = "franken-verifier/ltv-evidence-input/v1";
const LTV_WITNESS_ANCHOR_DOMAIN: &[u8] = b"franken-verifier/ltv-witness-anchor/v1:";
const MAX_LTV_WITNESS_ANCHOR_BYTES: usize = 64 * 1024;
const USAGE: &str = "franken-verifier verify --format incident-bundle|native-session-forensics|capsule|signed-bundle|signed-session|resolution-receipt|publisher-source|publisher-source-trust|counterfactual-receipt|counterfactual-incident|ltv-evidence --trusted-key-hex HEX [--trusted-run-key-hex HEX [--trusted-runtime-key-hex HEX]] [--signature-hex HEX] [--trusted-incident-key-hex HEX --expected-baseline-integrity-hash HEX] [--trusted-revocation-key-hex HEX --evaluation-time RFC3339 --max-revocation-age-secs SECONDS [--trusted-provenance-key-hex HEX]] [--expected-manifest-sha256 sha256:HEX [--expected-source-artifact-sha256 sha256:HEX] [--expected-graph-input-hash sha256:HEX]] < artifact; fleet observations: franken-verifier verify --format fleet-quiescence-observations --trusted-fleet-policy FILE < artifact; committed fleet epoch: franken-verifier verify --format fleet-epoch-commit --trusted-fleet-policy FILE --trusted-coordinator-id ID --trusted-coordinator-key-hex HEX < artifact";

#[derive(Debug)]
struct PublisherTrustRequest {
    revocation_authority: VerifyingKey,
    provenance_authority: Option<VerifyingKey>,
    evaluation_time: DateTime<Utc>,
    max_revocation_age_secs: u64,
}

#[derive(Debug)]
struct Request {
    format: String,
    anchor: Option<VerifyingKey>,
    run_anchor: Option<VerifyingKey>,
    runtime_anchor: Option<VerifyingKey>,
    signature: Option<[u8; 64]>,
    counterfactual_incident: Option<CounterfactualIncidentRequest>,
    publisher_trust: Option<PublisherTrustRequest>,
    expected_publisher_identity: Option<PublisherSourceExpectedIdentity>,
    fleet_policy: Option<FleetPolicyRequest>,
}

#[derive(Debug)]
struct CounterfactualIncidentRequest {
    incident_anchor: VerifyingKey,
    expected_baseline_integrity_hash: String,
}

// Redact the caller's enrollment policy: it contains private project and
// participant identities, even though all keys are public keys.
struct FleetPolicyRequest {
    policy: FleetQuiescencePolicy,
    input_sha256: String,
    coordinator: Option<FleetCoordinatorTrust>,
}

impl std::fmt::Debug for FleetPolicyRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FleetPolicyRequest { policy: [redacted] }")
    }
}

fn read_fleet_policy(path: &str) -> Result<FleetPolicyRequest, Failure> {
    let io_error = || {
        failure(
            "FLEET_POLICY_IO",
            "cannot read the trusted fleet policy file",
        )
    };
    // Reject existing FIFOs/devices before open, which could otherwise block.
    // Recheck the opened handle to avoid accepting a replaced non-file.
    if !std::fs::metadata(path).map_err(|_| io_error())?.is_file() {
        return Err(io_error());
    }
    let file = std::fs::File::open(path).map_err(|_| io_error())?;
    if !file.metadata().map_err(|_| io_error())?.is_file() {
        return Err(io_error());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FLEET_QUIESCENCE_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| io_error())?;
    let policy = parse_fleet_quiescence_policy(&bytes)
        .map_err(|error| failure(error.code(), "trusted fleet policy is invalid"))?;
    Ok(FleetPolicyRequest {
        policy,
        input_sha256: hex::encode(Sha256::digest(&bytes)),
        coordinator: None,
    })
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

fn trusted_evaluation_time(text: &str) -> Result<DateTime<Utc>, Failure> {
    let invalid = || {
        failure(
            "EVALUATION_TIME_INVALID",
            "expected non-leap RFC3339 time with at most nine fractional digits",
        )
    };
    let bytes = text.as_bytes();
    if !(20..=35).contains(&bytes.len())
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(invalid());
    }
    let zone_start = if matches!(bytes.last(), Some(b'Z' | b'z')) {
        bytes.len() - 1
    } else {
        bytes.len() - 6
    };
    if zone_start != 19
        && (!(21..=29).contains(&zone_start)
            || bytes[19] != b'.'
            || !bytes[20..zone_start].iter().all(u8::is_ascii_digit))
    {
        return Err(invalid());
    }
    let parsed = DateTime::parse_from_rfc3339(text).map_err(|_| invalid())?;
    if parsed.nanosecond() >= 1_000_000_000 {
        return Err(invalid());
    }
    Ok(parsed.with_timezone(&Utc))
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
    let (mut revocation_anchor, mut provenance_anchor, mut evaluation_time, mut max_age) =
        (None, None, None, None);
    let (mut expected_manifest, mut expected_source_artifact, mut expected_graph) =
        (None, None, None);
    let (mut incident_anchor, mut expected_baseline) = (None, None);
    let mut fleet_policy_path = None;
    let (mut coordinator_id, mut coordinator_key) = (None, None);
    let (options, remainder) = args[1..].as_chunks::<2>();
    for option in options {
        let slot = match option[0].as_str() {
            "--format" => &mut format,
            "--trusted-key-hex" => &mut anchor,
            "--trusted-run-key-hex" => &mut run_anchor,
            "--trusted-runtime-key-hex" => &mut runtime_anchor,
            "--signature-hex" => &mut signature,
            "--trusted-incident-key-hex" => &mut incident_anchor,
            "--expected-baseline-integrity-hash" => &mut expected_baseline,
            "--trusted-revocation-key-hex" => &mut revocation_anchor,
            "--trusted-provenance-key-hex" => &mut provenance_anchor,
            "--evaluation-time" => &mut evaluation_time,
            "--max-revocation-age-secs" => &mut max_age,
            "--expected-manifest-sha256" => &mut expected_manifest,
            "--expected-source-artifact-sha256" => &mut expected_source_artifact,
            "--expected-graph-input-hash" => &mut expected_graph,
            "--trusted-fleet-policy" => &mut fleet_policy_path,
            "--trusted-coordinator-id" => &mut coordinator_id,
            "--trusted-coordinator-key-hex" => &mut coordinator_key,
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
            | "native-session-forensics"
            | "capsule"
            | "signed-bundle"
            | "signed-session"
            | "resolution-receipt"
            | "publisher-source"
            | "publisher-source-trust"
            | "counterfactual-receipt"
            | "counterfactual-incident"
            | "ltv-evidence"
            | "fleet-quiescence-observations"
            | "fleet-epoch-commit"
    ) {
        return Err(failure("UNSUPPORTED_FORMAT", "unsupported evidence format"));
    }
    let (anchor, fleet_policy) = if matches!(
        format.as_str(),
        "fleet-quiescence-observations" | "fleet-epoch-commit"
    ) {
        if anchor.is_some() {
            return Err(usage());
        }
        let coordinator = if format == "fleet-epoch-commit" {
            let identity = coordinator_id.ok_or_else(usage)?;
            let encoded = coordinator_key.ok_or_else(usage)?;
            let invalid = || {
                failure(
                    "FLEET_COORDINATOR_TRUST_INVALID",
                    "expected an independently enrolled coordinator identity and Ed25519 public key",
                )
            };
            let mut bytes = [0_u8; 32];
            hex::decode_to_slice(&encoded, &mut bytes).map_err(|_| invalid())?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())?;
            if key.is_weak()
                || identity.is_empty()
                || identity.len() > 128
                || identity == "."
                || identity.contains("..")
                || !identity
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(invalid());
            }
            Some(FleetCoordinatorTrust {
                coordinator_id: identity,
                coordinator_public_key_hex: hex::encode(key.as_bytes()),
            })
        } else {
            if coordinator_id.is_some() || coordinator_key.is_some() {
                return Err(usage());
            }
            None
        };
        let mut policy = read_fleet_policy(&fleet_policy_path.ok_or_else(usage)?)?;
        policy.coordinator = coordinator;
        (None, Some(policy))
    } else {
        if fleet_policy_path.is_some() || coordinator_id.is_some() || coordinator_key.is_some() {
            return Err(usage());
        }
        let mut key = [0_u8; 32];
        hex::decode_to_slice(anchor.ok_or_else(usage)?, &mut key).map_err(|_| {
            failure(
                "ANCHOR_INVALID",
                "expected a 32-byte hexadecimal public key",
            )
        })?;
        let key = VerifyingKey::from_bytes(&key)
            .map_err(|_| failure("ANCHOR_INVALID", "invalid Ed25519 public key"))?;
        (Some(key), None)
    };
    let run_anchor = match (format.as_str(), run_anchor) {
        ("incident-bundle" | "counterfactual-incident", Some(text)) => {
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
        ("incident-bundle" | "counterfactual-incident", Some(_), Some(text)) => {
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
        (
            "signed-bundle"
            | "publisher-source"
            | "publisher-source-trust"
            | "counterfactual-receipt"
            | "counterfactual-incident",
            Some(text),
        ) => {
            let mut bytes = [0_u8; 64];
            hex::decode_to_slice(text, &mut bytes).map_err(|_| {
                failure(
                    "SIGNATURE_MALFORMED",
                    "expected a 64-byte detached signature",
                )
            })?;
            Some(bytes)
        }
        (
            "signed-bundle"
            | "publisher-source"
            | "publisher-source-trust"
            | "counterfactual-receipt"
            | "counterfactual-incident",
            None,
        ) => {
            return Err(failure(
                "SIGNATURE_MALFORMED",
                "detached signature is required",
            ));
        }
        (_, Some(_)) => return Err(usage()),
        (_, None) => None,
    };
    let counterfactual_incident = if format == "counterfactual-incident" {
        let encoded = incident_anchor.ok_or_else(usage)?;
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(encoded, &mut bytes).map_err(|_| {
            failure(
                "INCIDENT_ANCHOR_INVALID",
                "expected a 32-byte hexadecimal incident public key",
            )
        })?;
        let incident_anchor = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            failure(
                "INCIDENT_ANCHOR_INVALID",
                "invalid Ed25519 incident public key",
            )
        })?;
        let expected_baseline_integrity_hash = expected_baseline.ok_or_else(usage)?;
        if expected_baseline_integrity_hash.len() != 64
            || !expected_baseline_integrity_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(failure(
                "EXPECTED_BASELINE_INVALID",
                "expected baseline must be a lowercase SHA-256 integrity hash",
            ));
        }
        Some(CounterfactualIncidentRequest {
            incident_anchor,
            expected_baseline_integrity_hash,
        })
    } else {
        if incident_anchor.is_some() || expected_baseline.is_some() {
            return Err(usage());
        }
        None
    };
    let publisher_trust = if format == "publisher-source-trust" {
        let parse_authority = |text: &str, code: &'static str| {
            let mut key = [0_u8; 32];
            hex::decode_to_slice(text, &mut key).map_err(|_| {
                failure(code, "expected a 32-byte hexadecimal authority public key")
            })?;
            VerifyingKey::from_bytes(&key)
                .map_err(|_| failure(code, "invalid Ed25519 authority public key"))
        };
        let revocation_authority = parse_authority(
            &revocation_anchor.ok_or_else(usage)?,
            "REVOCATION_ANCHOR_INVALID",
        )?;
        let provenance_authority = provenance_anchor
            .as_deref()
            .map(|text| parse_authority(text, "PROVENANCE_ANCHOR_INVALID"))
            .transpose()?;
        let evaluation_time = trusted_evaluation_time(&evaluation_time.ok_or_else(usage)?)?;
        let max_age = max_age.ok_or_else(usage)?;
        let max_revocation_age_secs = max_age
            .parse::<u64>()
            .ok()
            .filter(|age| *age > 0 && age.to_string() == max_age)
            .ok_or_else(|| {
                failure(
                    "REVOCATION_FRESHNESS_POLICY_INVALID",
                    "expected a canonical positive u64 freshness window in seconds",
                )
            })?;
        Some(PublisherTrustRequest {
            revocation_authority,
            provenance_authority,
            evaluation_time,
            max_revocation_age_secs,
        })
    } else {
        if revocation_anchor.is_some()
            || provenance_anchor.is_some()
            || evaluation_time.is_some()
            || max_age.is_some()
        {
            return Err(usage());
        }
        None
    };
    let expected_publisher_identity = if expected_manifest.is_some()
        || expected_source_artifact.is_some()
        || expected_graph.is_some()
    {
        if !matches!(
            format.as_str(),
            "publisher-source" | "publisher-source-trust"
        ) {
            return Err(failure(
                "EXPECTED_IDENTITY_INVALID",
                "expected publisher identity applies only to publisher-source formats",
            ));
        }
        let expected = PublisherSourceExpectedIdentity {
            manifest_sha256: expected_manifest.ok_or_else(|| {
                failure(
                    "EXPECTED_IDENTITY_INVALID",
                    "expected manifest SHA-256 is required for publisher identity pins",
                )
            })?,
            source_artifact_sha256: expected_source_artifact,
            graph_input_hash: expected_graph,
        };
        expected
            .validate()
            .map_err(|error| publisher_identity_failure(&error))?;
        Some(expected)
    } else {
        None
    };
    Ok(Request {
        format,
        anchor,
        run_anchor,
        runtime_anchor,
        signature,
        counterfactual_incident,
        publisher_trust,
        expected_publisher_identity,
        fleet_policy,
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
        PublisherSourceError::RevocationFreshnessPolicyInvalid => {
            "REVOCATION_FRESHNESS_POLICY_INVALID"
        }
        PublisherSourceError::RevocationListNotYetValid => "REVOCATION_NOT_YET_VALID",
        PublisherSourceError::RevocationListStale => "REVOCATION_STALE",
        _ => "EVIDENCE_INVALID",
    };
    failure(code, "publisher-signed source verification failed")
}

fn publisher_identity_failure(error: &PublisherSourceIdentityError) -> Failure {
    match error {
        PublisherSourceIdentityError::Source(error) => publisher_source_failure(error),
        PublisherSourceIdentityError::ExpectedIdentityInvalid => failure(
            "EXPECTED_IDENTITY_INVALID",
            "expected publisher identity policy is invalid",
        ),
        PublisherSourceIdentityError::ExpectedIdentityMismatch => failure(
            "EXPECTED_IDENTITY_MISMATCH",
            "authenticated publisher source does not match the expected identity",
        ),
    }
}

fn native_session_failure(error: NativeSessionForensicError) -> Failure {
    let code = match error {
        NativeSessionForensicError::InputTooLarge => "INPUT_TOO_LARGE",
        NativeSessionForensicError::JsonInvalid => "JSON_INVALID",
        NativeSessionForensicError::SchemaUnsupported => "SCHEMA_UNSUPPORTED",
        NativeSessionForensicError::IdentityInvalid => "IDENTITY_INVALID",
        NativeSessionForensicError::SignerUntrusted => "SIGNER_UNTRUSTED",
        NativeSessionForensicError::AdmissionHashMismatch => "INTEGRITY_MISMATCH",
        NativeSessionForensicError::SignatureMalformed => "SIGNATURE_MALFORMED",
        NativeSessionForensicError::AdmissionSignatureInvalid
        | NativeSessionForensicError::OutcomeSignatureInvalid
        | NativeSessionForensicError::JournalSignatureInvalid => "SIGNATURE_INVALID",
        NativeSessionForensicError::JournalInvalid => "JOURNAL_INVALID",
        NativeSessionForensicError::SourceCapsuleInvalid => "SOURCE_CAPSULE_INVALID",
        NativeSessionForensicError::ObservationInvalid => "OBSERVATION_INVALID",
    };
    failure(
        code,
        "native-session supervisor evidence verification failed",
    )
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
struct CounterfactualIncidentInputEnvelope {
    schema_version: String,
    baseline_bundle_base64: String,
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

fn incident_verification_response(
    verified: VerifiedIncidentBundle,
    run_origin: Option<VerifiedRunOrigin>,
    runtime_origin: Option<VerifiedRuntimeOrigin>,
) -> Value {
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
    result
}

fn verify(request: &Request, bytes: &[u8]) -> Result<Value, Failure> {
    if request.format == "fleet-epoch-commit" {
        let policy = request.fleet_policy.as_ref().ok_or_else(|| {
            failure(
                "FLEET_POLICY_INVALID",
                "independent fleet policy is required",
            )
        })?;
        let trust = policy.coordinator.as_ref().ok_or_else(|| {
            failure(
                "FLEET_COORDINATOR_TRUST_INVALID",
                "independent coordinator trust is required",
            )
        })?;
        let verified = verify_fleet_epoch_commit(bytes, &policy.policy, trust)
            .map_err(|error| failure(error.code(), "fleet epoch commit verification failed"))?;
        let mut facts = serde_json::to_value(&verified).map_err(|_| {
            failure(
                "OUTPUT_INVALID",
                "cannot encode verified fleet epoch commit",
            )
        })?;
        facts["admitted_sessions"] = json!(verified.admitted_sessions.to_string());
        facts["terminal_sessions"] = json!(verified.terminal_sessions.to_string());
        facts["committed_epoch"] = json!(verified.committed_epoch.to_string());
        facts["trusted_policy_input_sha256"] = json!(policy.input_sha256);
        return Ok(json!({"scope": "authenticated_fleet_epoch_commit", "facts": facts}));
    }
    if request.format == "fleet-quiescence-observations" {
        let policy = request.fleet_policy.as_ref().ok_or_else(|| {
            failure(
                "FLEET_POLICY_INVALID",
                "independent fleet policy is required",
            )
        })?;
        let verified =
            verify_fleet_quiescence_observations(bytes, &policy.policy).map_err(|error| {
                failure(
                    error.code(),
                    "fleet supervisor evidence verification failed",
                )
            })?;
        let mut facts = serde_json::to_value(&verified).map_err(|_| {
            failure(
                "OUTPUT_INVALID",
                "cannot encode verified fleet observations",
            )
        })?;
        // Preserve exact u64 populations across JavaScript consumers. The
        // independent library retains native integer types for Rust callers.
        facts["admitted_sessions"] = json!(verified.admitted_sessions.to_string());
        facts["terminal_sessions"] = json!(verified.terminal_sessions.to_string());
        facts["trusted_policy_input_sha256"] = json!(policy.input_sha256);
        return Ok(json!({"scope": "authenticated_fleet_supervisor_observations", "facts": facts}));
    }
    let trusted_key = request
        .anchor
        .as_ref()
        .ok_or_else(|| failure("ANCHOR_INVALID", "independent public key is required"))?;
    match request.format.as_str() {
        "signed-session" => {
            let value = decode_evidence_json(bytes).map_err(|error| incident_failure(&error))?;
            let transcript: SignedSessionTranscript = serde_json::from_value(value)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid signed session transcript"))?;
            trusted_evaluation_time(&transcript.created_at)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid signed session creation time"))?;
            let anchor = hex::encode(trusted_key.as_bytes());
            if transcript.signer_public_key_hex != anchor {
                return Err(failure(
                    "SIGNER_UNTRUSTED",
                    "session signer differs from the independently trusted key",
                ));
            }
            if transcript.ed25519_signature_hex.len() != 128
                || !transcript
                    .ed25519_signature_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(failure(
                    "SIGNATURE_MALFORMED",
                    "expected a lowercase 64-byte session signature",
                ));
            }
            VerifierSdk::verify_signed_session(trusted_key, &transcript).map_err(|error| {
                match error {
                    VerifierSdkError::Bundle(BundleError::Ed25519SignatureInvalid) => {
                        failure("SIGNATURE_INVALID", "session signature does not verify")
                    }
                    _ => failure("EVIDENCE_INVALID", "signed session verification failed"),
                }
            })?;
            // Authenticate the signer's recorded decisions, without re-executing
            // the steps or claiming independent verification of their keyed tags.
            // Keep per-step artifacts and timestamps out of the public response.
            Ok(
                json!({"scope": "authenticated_verification_session", "facts": {
                    "session_id": transcript.session_id,
                    "verifier_identity": transcript.verifier_identity,
                    "created_at": transcript.created_at,
                    "final_verdict": transcript.final_verdict,
                    "step_count": transcript.steps.len(),
                    "transcript_hash": transcript.transcript_hash,
                    "signer_public_key_hex": anchor,
                }}),
            )
        }
        "native-session-forensics" => {
            let verified = verify_native_session_forensics(bytes, trusted_key)
                .map_err(native_session_failure)?;
            // The result authenticates original supervisor statements only.
            // It contains no private panic text or host-effect request data.
            Ok(json!({"scope": "authenticated_supervisor_observations", "facts": verified}))
        }
        "publisher-source-trust" => {
            let signature = request
                .signature
                .as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            let policy = request.publisher_trust.as_ref().ok_or_else(|| {
                failure(
                    "REVOCATION_FRESHNESS_POLICY_INVALID",
                    "explicit publisher trust policy is required",
                )
            })?;
            let anchors = PublisherTrustAnchors {
                revocation_authority: &policy.revocation_authority,
                provenance_authority: policy.provenance_authority.as_ref(),
                evaluation_time: policy.evaluation_time,
                max_revocation_age_secs: policy.max_revocation_age_secs,
            };
            let verified = match request.expected_publisher_identity.as_ref() {
                Some(expected) => verify_publisher_source_trust_input_with_expected_identity(
                    bytes,
                    signature,
                    trusted_key,
                    &anchors,
                    expected,
                )
                .map_err(|error| publisher_identity_failure(&error)),
                None => {
                    verify_publisher_source_trust_input(bytes, signature, trusted_key, &anchors)
                        .map_err(|error| publisher_source_failure(&error))
                }
            }?;
            Ok(json!({"scope": "authenticated_publisher_source_trust", "facts": verified}))
        }
        "publisher-source" => {
            let signature = request
                .signature
                .as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            let verified = match request.expected_publisher_identity.as_ref() {
                Some(expected) => verify_publisher_source_input_with_expected_identity(
                    bytes,
                    signature,
                    trusted_key,
                    expected,
                )
                .map_err(|error| publisher_identity_failure(&error)),
                None => verify_publisher_source_input(bytes, signature, trusted_key)
                    .map_err(|error| publisher_source_failure(&error)),
            }?;
            // These are authenticated publisher statements and captured bytes.
            // The independent reader does not reconstruct the native graph,
            // establish current revocation, or authorize workload execution.
            Ok(json!({
                "scope": "authenticated_publisher_source_content",
                "facts": verified,
            }))
        }
        "resolution-receipt" => {
            let receipt = verify_signed_resolution_receipt(trusted_key, bytes)
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
                    "signer_public_key_hex": hex::encode(trusted_key.as_bytes()),
                }}),
            )
        }
        "incident-bundle" => {
            let (verified, run_origin, runtime_origin) =
                match (&request.run_anchor, &request.runtime_anchor) {
                    (Some(run_anchor), Some(runtime_anchor)) => {
                        let verified = verify_incident_bundle_with_runtime_keys(
                            bytes,
                            trusted_key,
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
                            verify_incident_bundle_with_run_key(bytes, trusted_key, run_anchor)
                                .map_err(|error| incident_failure(&error))?;
                        (verified.bundle, Some(verified.run_origin), None)
                    }
                    (None, None) => (
                        verify_incident_bundle(bytes, trusted_key)
                            .map_err(|error| incident_failure(&error))?,
                        None,
                        None,
                    ),
                    (None, Some(_)) => return Err(failure("USAGE", USAGE)),
                };
            Ok(incident_verification_response(
                verified,
                run_origin,
                runtime_origin,
            ))
        }
        "capsule" => {
            let value = decode_evidence_json(bytes).map_err(|error| incident_failure(&error))?;
            let evidence: ReplayCapsule = serde_json::from_value(value)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid signed capsule schema"))?;
            let result = capsule::replay(trusted_key, &evidence, "verifier://offline-sdk")
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
                "actual_hash": result.actual_hash, "signer_public_key_hex": hex::encode(trusted_key.as_bytes())}}))
        }
        "signed-bundle" => {
            let evidence = bundle::verify(bytes)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid canonical SDK replay bundle"))?;
            let signature = request
                .signature
                .as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            bundle::verify_signed_bundle(trusted_key, &evidence, signature).map_err(|error| {
                match error {
                    BundleError::Ed25519SignatureInvalid => {
                        failure("SIGNATURE_INVALID", "detached signature does not verify")
                    }
                    _ => failure("EVIDENCE_INVALID", "signed SDK bundle verification failed"),
                }
            })?;
            Ok(
                json!({"scope": "authenticated_sdk_replay_bundle", "facts": {
                "bundle_id": evidence.bundle_id, "incident_id": evidence.incident_id,
                "event_count": evidence.timeline.len(), "integrity_hash": evidence.integrity_hash,
                "signer_public_key_hex": hex::encode(trusted_key.as_bytes())}}),
            )
        }
        "counterfactual-incident" => {
            let policy = request
                .counterfactual_incident
                .as_ref()
                .ok_or_else(|| failure("USAGE", USAGE))?;
            let signature = request
                .signature
                .as_ref()
                .ok_or_else(|| failure("SIGNATURE_MALFORMED", "detached signature is required"))?;
            let value = decode_evidence_json(bytes).map_err(|error| incident_failure(&error))?;
            let envelope: CounterfactualIncidentInputEnvelope = serde_json::from_value(value)
                .map_err(|_| {
                    failure(
                        "EVIDENCE_INVALID",
                        "invalid counterfactual incident transport",
                    )
                })?;
            if envelope.schema_version != COUNTERFACTUAL_INCIDENT_INPUT_SCHEMA
                || envelope.baseline_bundle_base64.is_empty()
                || envelope.baseline_bundle_base64.len() > MAX_INCIDENT_BUNDLE_BYTES.div_ceil(3) * 4
            {
                return Err(failure(
                    "EVIDENCE_INVALID",
                    "invalid counterfactual incident transport",
                ));
            }
            let baseline_bytes = STANDARD
                .decode(&envelope.baseline_bundle_base64)
                .map_err(|_| failure("EVIDENCE_INVALID", "invalid baseline bundle encoding"))?;
            if STANDARD.encode(&baseline_bytes) != envelope.baseline_bundle_base64 {
                return Err(failure(
                    "EVIDENCE_INVALID",
                    "noncanonical baseline bundle encoding",
                ));
            }
            let verified = verify_counterfactual_incident(
                &baseline_bytes,
                &envelope.counterfactual_output,
                signature,
                &CounterfactualIncidentTrust {
                    expected_baseline_integrity_hash: &policy.expected_baseline_integrity_hash,
                    trusted_counterfactual_signer: trusted_key,
                    trusted_bundle_signer: &policy.incident_anchor,
                    trusted_run_signer: request.run_anchor.as_ref(),
                    trusted_product_root: request.runtime_anchor.as_ref(),
                },
            )
            .map_err(|error| {
                failure(error.code(), "counterfactual incident verification failed")
            })?;
            let baseline = incident_verification_response(
                verified.baseline,
                verified.run_origin,
                verified.runtime_origin,
            );
            Ok(json!({
                "scope": "authenticated_counterfactual_incident",
                "facts": {
                    "baseline_integrity_hash": baseline["facts"]["integrity_hash"],
                    "counterfactual_output_sha256": verified.counterfactual_output_sha256,
                    "signer_public_key_hex": verified.counterfactual_signer_public_key_hex,
                    "mode": verified.mode,
                    "result_count": verified.result_count,
                    "baseline_scope": baseline["scope"],
                    "baseline": baseline["facts"],
                    "guest_execution_verified": verified.guest_execution_verified,
                }
            }))
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
                trusted_key,
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
                    "signer_public_key_hex": hex::encode(trusted_key.as_bytes()),
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
            trusted_key
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
                    "trust_policy_sha256": hex::encode(Sha256::digest(&anchor_bytes)),
                    "reattestation_count": evidence.reattestation_chain.attestations.len(),
                    "hybrid_survived_algo_death": hybrid_survived,
                    "signer_public_key_hex": hex::encode(trusted_key.as_bytes()),
                }
            }))
        }
        _ => Err(failure("UNSUPPORTED_FORMAT", "unsupported evidence format")),
    }
}

fn run(args: &[String], input: &mut impl Read) -> Result<Value, Failure> {
    let request = arguments(args)?;
    let input_limit = match request.format.as_str() {
        "fleet-quiescence-observations" | "fleet-epoch-commit" => {
            MAX_FLEET_QUIESCENCE_RESPONSE_BYTES
        }
        "native-session-forensics" => MAX_NATIVE_SESSION_FORENSICS_V3_BYTES,
        "publisher-source" => MAX_PUBLISHER_SOURCE_INPUT_BYTES,
        "publisher-source-trust" => MAX_PUBLISHER_SOURCE_TRUST_INPUT_BYTES,
        _ => MAX_INCIDENT_BUNDLE_BYTES,
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
            if request.format == "native-session-forensics" {
                "native-session forensic evidence exceeds the 96 MiB input limit"
            } else if matches!(
                request.format.as_str(),
                "fleet-quiescence-observations" | "fleet-epoch-commit"
            ) {
                "fleet supervisor evidence exceeds the 8 MiB input limit"
            } else if matches!(
                request.format.as_str(),
                "publisher-source" | "publisher-source-trust"
            ) {
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
    fn cli_fleet_requires_separate_enrollment_and_a_regular_policy_file() {
        let base = ["verify", "--format", "fleet-quiescence-observations"]
            .map(str::to_owned)
            .to_vec();
        assert_eq!(arguments(&base).unwrap_err().code, "USAGE");
        assert_eq!(
            arguments(&args("fleet-quiescence-observations", ANCHOR))
                .unwrap_err()
                .code,
            "USAGE"
        );
        let mut request = args("incident-bundle", ANCHOR);
        request.extend(["--trusted-fleet-policy".into(), "not-read.json".into()]);
        assert_eq!(arguments(&request).unwrap_err().code, "USAGE");
        let mut request = base;
        request.extend([
            "--trusted-fleet-policy".into(),
            env!("CARGO_MANIFEST_DIR").into(),
        ]);
        let error = arguments(&request).unwrap_err();
        assert_eq!(error.code, "FLEET_POLICY_IO");
        assert!(!error.message.contains(env!("CARGO_MANIFEST_DIR")));
    }

    #[test]
    fn cli_fleet_preserves_exact_counts_and_limits_the_authenticated_claim() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/fleet_quiescence_observations.json"
        ))
        .unwrap();
        let policy_bytes = serde_json::to_vec_pretty(&fixture["policy"]).unwrap();
        let input_sha256 = hex::encode(Sha256::digest(&policy_bytes));
        let request = Request {
            format: "fleet-quiescence-observations".into(),
            anchor: None,
            run_anchor: None,
            runtime_anchor: None,
            signature: None,
            counterfactual_incident: None,
            publisher_trust: None,
            expected_publisher_identity: None,
            fleet_policy: Some(FleetPolicyRequest {
                policy: parse_fleet_quiescence_policy(&policy_bytes).unwrap(),
                input_sha256: input_sha256.clone(),
                coordinator: None,
            }),
        };
        let bytes = serde_json::to_vec(&fixture["http_response"]).unwrap();
        let result = verify(&request, &bytes).unwrap();
        assert_eq!(
            result["scope"],
            "authenticated_fleet_supervisor_observations"
        );
        let facts = &result["facts"];
        assert_eq!(facts["trusted_policy_input_sha256"], input_sha256);
        assert_eq!(
            facts["evidence_sha256"],
            hex::encode(Sha256::digest(&bytes))
        );
        assert_eq!(facts["participant_count"], 2);
        assert_eq!(facts["admitted_sessions"], "5");
        assert_eq!(facts["terminal_sessions"], "5");
        assert_eq!(facts["supervisor_signatures_verified"], true);
        assert_eq!(facts["epoch_commit_authenticated"], false);
        assert_eq!(facts["current_quiescence_proven"], false);
        let output = result.to_string();
        assert!(output.len() < MAX_RESPONSE_BYTES);
        assert!(!output.contains("node-a") && !output.contains("hold-east"));
        assert!(!format!("{request:?}").contains("node-a"));
    }

    fn native_session_fixture(outcome: bool) -> (Vec<u8>, String) {
        use ed25519_dalek::{Signer as _, SigningKey};
        use frankenengine_verifier_sdk::native_session::{
            NATIVE_SESSION_FORENSICS_SCHEMA, NativeSessionForensicAdmissionReceipt,
            NativeSessionForensicBundle, NativeSessionForensicOutcome,
        };
        let key = SigningKey::from_bytes(&[71; 32]);
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let key_id = format!("ed25519:{public_key}");
        let nonce = "019a7f53-c180-7001-8001-000000000071";
        let admission_json = json!({
            "session_nonce": nonce, "product_root_key_id": key_id,
            "identity_capture_path": "/removed/evidence/capture.json", "security_epoch": 9,
            "admitted_at": "2026-11-14T12:00:00Z", "project_root": "/removed/project",
            "entrypoint": "/removed/project/main.js", "dependency_ids": ["private dependency"],
            "configured_node_id": null, "fleet_zone_id": null, "fleet_policy_sha256": null,
            "process_spawn_authority_granted": false, "control_scopes": [],
        })
        .to_string();
        let signing_bytes = |domain: &[u8], raw: &str| {
            [domain, &(raw.len() as u64).to_be_bytes(), raw.as_bytes()].concat()
        };
        let digest = hex::encode(Sha256::digest(signing_bytes(
            b"franken-node/native-session-admission/v1\0",
            &admission_json,
        )));
        let admission_payload = format!(
            "{{\"schema_version\":\"franken-node/native-session-admission-receipt/v1\",\"session_nonce\":\"{nonce}\",\"product_root_key_id\":\"{key_id}\",\"admission_sha256\":\"{digest}\"}}"
        );
        let admission_receipt = NativeSessionForensicAdmissionReceipt {
            schema_version: "franken-node/native-session-admission-receipt/v1".into(),
            session_nonce: nonce.into(),
            product_root_key_id: key_id.clone(),
            admission_sha256: digest.clone(),
            signature_hex: hex::encode(
                key.sign(&signing_bytes(
                    b"franken-node/native-session-admission-signature/v1\0",
                    &admission_payload,
                ))
                .to_bytes(),
            ),
        };
        let outcome = outcome.then(|| {
            let observation = json!({
                "observed_at": "2026-11-14T12:00:01Z", "kind": "panicked", "process": "worker_reaped",
                "containment_empty_observed": false, "effects": {"kind":"no_admitted_host_effects"},
                "panic_evidence": {"panic_message":"private panic", "panic_message_bytes":13,
                    "panic_message_sha256":hex::encode(Sha256::digest(b"private panic")), "panic_message_truncated":false,
                    "cleanup_successful":true,"host_effect_wal":[]},
            });
            let payload_json = format!(
                "{{\"schema_version\":\"franken-node/native-session-outcome-receipt/v1\",\"session_nonce\":\"{nonce}\",\"product_root_key_id\":\"{key_id}\",\"admission_sha256\":\"{digest}\",\"outcome\":{observation}}}"
            );
            NativeSessionForensicOutcome {
                signature_hex: hex::encode(
                    key.sign(&signing_bytes(
                        b"franken-node/native-session-outcome-signature/v1\0",
                        &payload_json,
                    ))
                    .to_bytes(),
                ),
                payload_json,
            }
        });
        let bundle = NativeSessionForensicBundle {
            schema_version: NATIVE_SESSION_FORENSICS_SCHEMA.into(),
            admission_json,
            admission_receipt,
            outcome,
            journal_jsonl: None,
            source_capsule_base64: None,
        };
        (serde_json::to_vec(&bundle).unwrap(), public_key)
    }

    #[test]
    fn cli_native_session_forensics_authenticates_pending_and_panic_without_private_details() {
        for outcome in [false, true] {
            let (bytes, key) = native_session_fixture(outcome);
            let verified = run(
                &args("native-session-forensics", &key),
                &mut bytes.as_slice(),
            )
            .unwrap();
            assert_eq!(verified["verdict"], "verified");
            assert_eq!(verified["scope"], "authenticated_supervisor_observations");
            assert_eq!(
                verified["facts"]["outcome_kind"],
                if outcome { "panicked" } else { "pending" }
            );
            assert_eq!(verified["facts"]["replay_certified"], false);
            assert_eq!(verified["facts"]["quiescence_certified"], false);
            assert_eq!(verified["facts"]["historical_completeness"], false);
            assert_eq!(
                verified["artifact_sha256"],
                hex::encode(Sha256::digest(&bytes))
            );
            let summary = verified.to_string();
            assert!(!summary.contains("private panic") && !summary.contains("private dependency"));
        }
    }

    #[test]
    fn cli_native_session_forensics_rejects_wrong_authority_options_and_oversized_input() {
        let (bytes, key) = native_session_fixture(true);
        assert_eq!(
            run(
                &args("native-session-forensics", ANCHOR),
                &mut bytes.as_slice()
            )
            .unwrap_err()
            .code,
            "SIGNER_UNTRUSTED"
        );
        for option in [
            "--signature-hex",
            "--trusted-run-key-hex",
            "--trusted-runtime-key-hex",
        ] {
            let mut request = args("native-session-forensics", &key);
            request.extend([option.to_owned(), key.clone()]);
            assert_eq!(arguments(&request).unwrap_err().code, "USAGE");
        }
        let oversized = vec![b' '; MAX_NATIVE_SESSION_FORENSICS_V3_BYTES + 1];
        let error = run(
            &args("native-session-forensics", &key),
            &mut oversized.as_slice(),
        )
        .unwrap_err();
        assert_eq!(error.code, "INPUT_TOO_LARGE");
        assert!(error.message.contains("96 MiB"));
    }

    #[test]
    fn cli_native_session_v2_authenticates_retained_journal_without_promoting_pending() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use frankenengine_verifier_sdk::native_session::{
            NATIVE_SESSION_FORENSICS_V2_SCHEMA, NativeSessionForensicBundle,
        };
        let (bytes, anchor) = native_session_fixture(false);
        let mut bundle: NativeSessionForensicBundle = serde_json::from_slice(&bytes).unwrap();
        let receipt = &bundle.admission_receipt;
        let payload = json!({
            "schema_version":"franken-node/native-effect-journal-record/v1",
            "session_nonce":receipt.session_nonce,
            "product_root_key_id":receipt.product_root_key_id,
            "admission_sha256":receipt.admission_sha256,
            "event_index":0,"previous_record_sha256":"0".repeat(64),
            "event":{"kind":"header","scope":"host_io_provider_calls","event_cap":2048,"byte_cap":4194304},
        }).to_string();
        let signed = [
            b"franken-node/native-effect-journal-signature/v1\0".as_slice(),
            &(payload.len() as u64).to_be_bytes(),
            payload.as_bytes(),
        ]
        .concat();
        let signature = SigningKey::from_bytes(&[71; 32]).sign(&signed);
        let journal = format!(
            "{}\nprivate torn diagnostic",
            json!({"payload_json":payload,"signature_hex":hex::encode(signature.to_bytes())})
        );
        bundle.schema_version = NATIVE_SESSION_FORENSICS_V2_SCHEMA.into();
        bundle.journal_jsonl = Some(journal);
        let encoded = serde_json::to_vec(&bundle).unwrap();
        let verified = run(
            &args("native-session-forensics", &anchor),
            &mut encoded.as_slice(),
        )
        .unwrap();
        assert_eq!(verified["verdict"], "verified");
        assert_eq!(verified["facts"]["outcome_kind"], "pending");
        assert!(verified["facts"]["completed_provider_calls"].is_null());
        assert_eq!(verified["facts"]["durable_journal"]["record_count"], 1);
        assert_eq!(
            verified["facts"]["durable_journal"]["trailing_partial_record"],
            true
        );
        assert_eq!(
            verified["facts"]["durable_journal"]["historical_completeness"],
            false
        );
        assert!(!verified.to_string().contains("private torn diagnostic"));
        bundle.journal_jsonl.as_mut().unwrap().push('\n');
        let encoded = serde_json::to_vec(&bundle).unwrap();
        assert_eq!(
            run(
                &args("native-session-forensics", &anchor),
                &mut encoded.as_slice()
            )
            .unwrap_err()
            .code,
            "JSON_INVALID"
        );
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
    fn publisher_identity_cli_enforces_release_pins_for_both_source_formats() {
        let (source_args, source_bytes, _) = publisher_source_cli_fixture(true);
        let (trust_args, trust_bytes) = publisher_trust_cli_fixture(true);
        for (request, input) in [(source_args, source_bytes), (trust_args, trust_bytes)] {
            let baseline = run(&request, &mut input.as_slice()).unwrap();
            let facts = if baseline["format"] == "publisher-source-trust" {
                &baseline["facts"]["source"]
            } else {
                &baseline["facts"]
            };
            let pins = [
                (
                    "--expected-manifest-sha256",
                    facts["manifest_sha256"].as_str().unwrap(),
                ),
                (
                    "--expected-source-artifact-sha256",
                    facts["artifact_sha256"].as_str().unwrap(),
                ),
                (
                    "--expected-graph-input-hash",
                    facts["capsule"]["graph_input_hash"].as_str().unwrap(),
                ),
            ];
            let mut pinned = request.clone();
            for (option, value) in pins {
                pinned.extend([option.into(), value.into()]);
            }
            assert_eq!(run(&pinned, &mut input.as_slice()).unwrap(), baseline);
            for (option, _) in pins {
                let mut mismatch = pinned.clone();
                let index = mismatch.iter().position(|item| item == option).unwrap() + 1;
                mismatch[index] = format!("sha256:{}", "0".repeat(64));
                let error = run(&mismatch, &mut input.as_slice()).unwrap_err();
                assert_eq!(error.code, "EXPECTED_IDENTITY_MISMATCH");
                assert!(!error.message.contains("sha256:"));
            }
            let mut manifest_only = request;
            manifest_only.extend([pins[0].0.into(), pins[0].1.into()]);
            assert_eq!(
                run(&manifest_only, &mut input.as_slice()).unwrap(),
                baseline
            );
        }
    }

    #[test]
    fn publisher_identity_cli_rejects_malformed_or_incomplete_pins_before_input() {
        struct Unreadable;
        impl Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("invalid identity policy must precede input")
            }
        }
        let (request, _, _) = publisher_source_cli_fixture(true);
        let pin = format!("sha256:{}", "a".repeat(64));
        for (option, value) in [
            ("--expected-manifest-sha256", ""),
            ("--expected-manifest-sha256", "sha256:123"),
            ("--expected-source-artifact-sha256", pin.as_str()),
            ("--expected-graph-input-hash", pin.as_str()),
        ] {
            let mut invalid = request.clone();
            invalid.extend([option.into(), value.into()]);
            assert_eq!(
                run(&invalid, &mut Unreadable).unwrap_err().code,
                "EXPECTED_IDENTITY_INVALID"
            );
        }
        let mut wrong_format = args("incident-bundle", ANCHOR);
        wrong_format.extend(["--expected-manifest-sha256".into(), pin.clone()]);
        assert_eq!(
            run(&wrong_format, &mut Unreadable).unwrap_err().code,
            "EXPECTED_IDENTITY_INVALID"
        );
        let mut duplicate = request;
        duplicate.extend([
            "--expected-manifest-sha256".into(),
            pin.clone(),
            "--expected-manifest-sha256".into(),
            pin,
        ]);
        assert_eq!(run(&duplicate, &mut Unreadable).unwrap_err().code, "USAGE");
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
    fn publisher_trust_cli_requires_exact_explicit_policy_options() {
        let (mut request, _, _) = publisher_source_cli_fixture(false);
        request[2] = "publisher-source-trust".into();
        request.extend([
            "--trusted-revocation-key-hex".into(),
            ANCHOR.into(),
            "--evaluation-time".into(),
            "2026-11-11T00:30:00Z".into(),
            "--max-revocation-age-secs".into(),
            "3600".into(),
        ]);
        assert!(arguments(&request).is_ok());
        for option in [
            "--trusted-revocation-key-hex",
            "--evaluation-time",
            "--max-revocation-age-secs",
        ] {
            let position = request.iter().position(|arg| arg == option).unwrap();
            let mut missing = request.clone();
            missing.drain(position..position + 2);
            assert_eq!(arguments(&missing).unwrap_err().code, "USAGE");
            let mut duplicate = request.clone();
            duplicate.extend([option.into(), "duplicate".into()]);
            assert_eq!(arguments(&duplicate).unwrap_err().code, "USAGE");
        }
        let max_position = request
            .iter()
            .position(|arg| arg == "--max-revocation-age-secs")
            .unwrap()
            + 1;
        for invalid in ["0", "01", "+1", " 1", "1.5", "18446744073709551616"] {
            request[max_position] = invalid.into();
            assert_eq!(
                arguments(&request).unwrap_err().code,
                "REVOCATION_FRESHNESS_POLICY_INVALID"
            );
        }
        request[max_position] = u64::MAX.to_string();
        assert_eq!(
            arguments(&request)
                .unwrap()
                .publisher_trust
                .unwrap()
                .max_revocation_age_secs,
            u64::MAX
        );
        request[2] = "publisher-source".into();
        assert_eq!(arguments(&request).unwrap_err().code, "USAGE");
    }

    #[test]
    fn publisher_trust_time_parser_never_rounds_or_normalizes_invalid_instants() {
        let expected = trusted_evaluation_time("2026-11-11T00:30:00.123456789Z").unwrap();
        assert_eq!(
            trusted_evaluation_time("2026-11-11T01:30:00.123456789+01:00").unwrap(),
            expected
        );
        assert_eq!(expected.nanosecond(), 123_456_789);
        for invalid in [
            "",
            "2026-11-11",
            "2026-11-11 00:30:00Z",
            "2026-11-11T00:30:00.1234567891Z",
            "2026-11-11T00:30:00.0000000000Z",
            "2026-11-11T00:30:00.Z",
            "2026-11-11T00:30:60Z",
            "2026-02-29T00:30:00Z",
            "2026-11-11T24:00:00Z",
            "2026-11-11T00:30:00Z\n",
        ] {
            assert_eq!(
                trusted_evaluation_time(invalid).unwrap_err().code,
                "EVALUATION_TIME_INVALID",
                "{invalid}"
            );
        }
    }

    fn publisher_trust_cli_fixture(with_provenance: bool) -> (Vec<String>, Vec<u8>) {
        use ed25519_dalek::{Signer, SigningKey};
        use frankenengine_verifier_sdk::publisher_source::{
            PUBLISHER_SOURCE_TRUST_INPUT_SCHEMA, provenance_chain_signing_payload,
            revocation_list_signing_payload,
        };
        let (mut request, input, _) = publisher_source_cli_fixture(true);
        request[2] = "publisher-source-trust".into();
        let mut transport: Value = serde_json::from_slice(&input).unwrap();
        transport["schema_version"] = json!(PUBLISHER_SOURCE_TRUST_INPUT_SCHEMA);
        let revocation_bytes = serde_json::to_vec(&json!({
            "schema_version": "franken-node/publisher-revocation-list/v1",
            "issued_at": "2026-11-11T00:00:00Z",
            "revoked_publisher_ids": [], "revoked_signer_key_ids": [], "revoked_package_versions": [],
        })).unwrap();
        let revocation_signer = SigningKey::from_bytes(&[0x71; 32]);
        transport["revocation_list_base64"] = json!(STANDARD.encode(&revocation_bytes));
        transport["revocation_signature_hex"] = json!(hex::encode(
            revocation_signer
                .sign(&revocation_list_signing_payload(&revocation_bytes))
                .to_bytes()
        ));
        request.extend([
            "--trusted-revocation-key-hex".into(),
            hex::encode(revocation_signer.verifying_key().as_bytes()),
            "--evaluation-time".into(),
            "2026-11-11T00:30:00Z".into(),
            "--max-revocation-age-secs".into(),
            "3600".into(),
        ]);
        if with_provenance {
            let manifest_bytes = STANDARD
                .decode(transport["manifest_base64"].as_str().unwrap())
                .unwrap();
            let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
            let chain_bytes = serde_json::to_vec(&json!({
                "schema_version": "franken-node/publisher-provenance-chain/v1",
                "package_name": manifest["name"], "publisher_id": manifest["publisher_id"],
                "links": [{
                    "version": manifest["initial_version"]["version"], "parent_version": null,
                    "content_hash": manifest["initial_version"]["content_hash"],
                    "manifest_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes))),
                    "previous_link_sha256": null,
                }],
            })).unwrap();
            let signer = SigningKey::from_bytes(&[0x72; 32]);
            transport["provenance"] = json!({
                "chain_base64": STANDARD.encode(&chain_bytes),
                "signature_hex": hex::encode(signer.sign(&provenance_chain_signing_payload(&chain_bytes)).to_bytes()),
            });
            request.extend([
                "--trusted-provenance-key-hex".into(),
                hex::encode(signer.verifying_key().as_bytes()),
            ]);
        }
        (request, serde_json::to_vec(&transport).unwrap())
    }

    #[test]
    fn publisher_trust_cli_authenticates_source_authorities_and_freshness() {
        for with_provenance in [false, true] {
            let (request, input) = publisher_trust_cli_fixture(with_provenance);
            let verified = run(&request, &mut input.as_slice()).unwrap();
            assert_eq!(verified["format"], "publisher-source-trust");
            assert_eq!(verified["scope"], "authenticated_publisher_source_trust");
            assert_eq!(
                verified["artifact_sha256"],
                hex::encode(Sha256::digest(&input))
            );
            let facts = &verified["facts"];
            assert_eq!(facts["source"]["package_name"], "source-audit");
            assert_eq!(facts["source"]["capsule"]["graph_hash_recomputed"], false);
            assert_eq!(facts["revocation_issued_at"], "2026-11-11T00:00:00Z");
            assert_eq!(facts["revocation_evaluated_at"], "2026-11-11T00:30:00Z");
            assert_eq!(facts["max_revocation_age_secs"], "3600");
            assert_eq!(
                facts["provenance_link_count"],
                if with_provenance {
                    json!(1)
                } else {
                    Value::Null
                }
            );
            assert_eq!(
                facts["provenance_authority_public_key_hex"].is_null(),
                !with_provenance
            );
            assert!(!verified.to_string().contains("PRIVATE-SOURCE-SENTINEL"));
        }
        let (request, input) = publisher_trust_cli_fixture(true);
        for option in [
            "--trusted-key-hex",
            "--trusted-revocation-key-hex",
            "--trusted-provenance-key-hex",
        ] {
            let mut foreign = request.clone();
            let position = foreign.iter().position(|arg| arg == option).unwrap();
            foreign[position + 1] = ANCHOR.into();
            assert_eq!(
                run(&foreign, &mut input.as_slice()).unwrap_err().code,
                "SIGNATURE_INVALID"
            );
        }
        let position = request
            .iter()
            .position(|arg| arg == "--evaluation-time")
            .unwrap()
            + 1;
        for (time, expected) in [
            ("2026-11-11T01:00:00Z", "REVOCATION_STALE"),
            ("2026-11-10T23:59:59.999999999Z", "REVOCATION_NOT_YET_VALID"),
        ] {
            let mut timed = request.clone();
            timed[position] = time.into();
            assert_eq!(
                run(&timed, &mut input.as_slice()).unwrap_err().code,
                expected
            );
        }
        let mut fresh = request.clone();
        fresh[position] = "2026-11-11T00:59:59.999999999Z".into();
        assert!(run(&fresh, &mut input.as_slice()).is_ok());
        let mut missing_provenance_anchor = request;
        missing_provenance_anchor.truncate(missing_provenance_anchor.len() - 2);
        assert_eq!(
            run(&missing_provenance_anchor, &mut input.as_slice())
                .unwrap_err()
                .code,
            "EVIDENCE_INVALID"
        );
    }

    #[test]
    fn publisher_trust_cli_stops_stream_at_the_transport_limit() {
        let (request, _) = publisher_trust_cli_fixture(false);
        let mut input = io::repeat(b' ').take(MAX_PUBLISHER_SOURCE_TRUST_INPUT_BYTES as u64 + 2);
        assert_eq!(
            run(&request, &mut input).unwrap_err().code,
            "INPUT_TOO_LARGE"
        );
        assert_eq!(input.limit(), 1);
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
            LongTermCryptoSuiteRecord, LongTermEvidenceRequest, LongTermSignerKey,
            LongTermThresholdConfig, LongTermWitnessSigner, build_long_term_verification_evidence,
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
        let suite_records = vec![LongTermCryptoSuiteRecord {
            crypto_suite: "ed25519-v1".into(),
            valid_from_unix_seconds: 1_700_000_000,
            valid_until_unix_seconds: None,
            compromised_at_unix_seconds: Some(1_700_000_400),
        }];
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
                suite_records: suite_records.clone(),
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
            suite_records,
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
        assert_eq!(
            verified["facts"]["trust_policy_sha256"],
            hex::encode(Sha256::digest(&anchor_bytes))
        );

        // The authentic historical receipt cannot replace the operator's
        // suite policy. No witness or root signature is modified here.
        let mut erased_policy = serde_json::from_slice::<Value>(&payload).unwrap();
        erased_policy["evidence"]["suite_records"][0]
            .as_object_mut()
            .unwrap()
            .remove("compromised_at_unix_seconds");
        assert_eq!(
            run(
                &cli_args,
                &mut serde_json::to_vec(&erased_policy).unwrap().as_slice()
            )
            .unwrap_err()
            .code,
            "LTV_ANTERIORITY_REJECTED"
        );

        // A root-signed legacy anchor still has no independently approved
        // crypto-suite policy. Never fill that missing authority from evidence.
        let mut legacy_anchor = serde_json::to_value(&witness_anchor).unwrap();
        legacy_anchor
            .as_object_mut()
            .unwrap()
            .remove("suite_records");
        let legacy_bytes = serde_json::to_vec(&legacy_anchor).unwrap();
        let mut legacy_payload = serde_json::from_slice::<Value>(&payload).unwrap();
        legacy_payload["witness_anchor_base64"] = json!(STANDARD.encode(&legacy_bytes));
        legacy_payload["witness_anchor_signature_hex"] = json!(hex::encode(
            operator_root
                .sign(&ltv_anchor_signing_payload(&legacy_bytes))
                .to_bytes()
        ));
        assert_eq!(
            run(
                &cli_args,
                &mut serde_json::to_vec(&legacy_payload).unwrap().as_slice()
            )
            .unwrap_err()
            .code,
            "EVIDENCE_INVALID"
        );

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
