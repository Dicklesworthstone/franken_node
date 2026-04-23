use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::verifier_economy::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

const REPLAY_CAPSULE_SCHEMA_VERSION: &str = "vep-replay-capsule-v2";
const FIXTURE_MATRIX: &str = include_str!("fixtures/verifier_economy/vep_coverage_matrix.json");

#[derive(Debug, Serialize)]
struct MatrixRow<'a> {
    requirement_id: &'a str,
    level: &'a str,
    surface: &'a str,
    contract: &'a str,
    fixture: &'a str,
}

fn matrix_rows() -> Vec<MatrixRow<'static>> {
    vec![
        MatrixRow {
            requirement_id: "VEP-REGISTRATION-OK",
            level: "MUST",
            surface: "verifier_registration",
            contract: "VEP-005",
            fixture: "register_valid_ed25519_verifier",
        },
        MatrixRow {
            requirement_id: "VEP-REGISTRATION-INVALID-PUBLIC-KEY",
            level: "MUST",
            surface: "verifier_registration",
            contract: "ERR-VEP-INVALID-PUBLIC-KEY",
            fixture: "register_rejects_malformed_public_key",
        },
        MatrixRow {
            requirement_id: "VEP-REGISTRATION-DUPLICATE",
            level: "MUST",
            surface: "verifier_registration",
            contract: "ERR-VEP-DUPLICATE-SUBMISSION",
            fixture: "register_rejects_duplicate_public_key",
        },
        MatrixRow {
            requirement_id: "VEP-ATTESTATION-OK",
            level: "MUST",
            surface: "attestation_submission",
            contract: "INV-VEP-ATTESTATION|VEP-001",
            fixture: "submit_valid_signed_attestation",
        },
        MatrixRow {
            requirement_id: "VEP-ATTESTATION-SIGNATURE",
            level: "MUST",
            surface: "attestation_submission",
            contract: "INV-VEP-SIGNATURE|ERR-VEP-INVALID-SIGNATURE",
            fixture: "submit_rejects_tampered_signature",
        },
        MatrixRow {
            requirement_id: "VEP-ATTESTATION-UNREGISTERED",
            level: "MUST",
            surface: "attestation_submission",
            contract: "ERR-VEP-UNREGISTERED-VERIFIER",
            fixture: "submit_rejects_unknown_verifier",
        },
        MatrixRow {
            requirement_id: "VEP-ATTESTATION-INCOMPLETE",
            level: "MUST",
            surface: "attestation_submission",
            contract: "ERR-VEP-INCOMPLETE-PAYLOAD",
            fixture: "submit_rejects_empty_statement_or_suite",
        },
        MatrixRow {
            requirement_id: "VEP-ATTESTATION-DUPLICATE",
            level: "MUST",
            surface: "attestation_submission",
            contract: "ERR-VEP-DUPLICATE-SUBMISSION",
            fixture: "submit_rejects_duplicate_trace_fingerprint",
        },
        MatrixRow {
            requirement_id: "VEP-ANTI-GAMING",
            level: "MUST",
            surface: "attestation_submission",
            contract: "ERR-VEP-ANTI-GAMING|VEP-006",
            fixture: "submit_rejects_rate_limit_exhaustion",
        },
        MatrixRow {
            requirement_id: "VEP-REPUTATION",
            level: "MUST",
            surface: "reputation",
            contract: "INV-VEP-REPUTATION|VEP-004",
            fixture: "update_reputation_is_deterministic",
        },
        MatrixRow {
            requirement_id: "VEP-PUBLISH",
            level: "MUST",
            surface: "publishing",
            contract: "INV-VEP-PUBLISH|VEP-002",
            fixture: "review_then_publish_makes_attestation_immutable",
        },
        MatrixRow {
            requirement_id: "VEP-DISPUTE",
            level: "SHOULD",
            surface: "disputes",
            contract: "VEP-003",
            fixture: "file_dispute_emits_stable_event",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-ACCESS",
            level: "MUST",
            surface: "replay_capsule",
            contract: "VEP-007",
            fixture: "register_and_access_valid_replay_capsule",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-MISSING-FIELDS",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-MISSING-FIELDS",
            fixture: "capsule_rejects_missing_capsule_id",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-SCHEMA",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-SCHEMA",
            fixture: "capsule_rejects_wrong_schema_version",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-FRESHNESS",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-FRESHNESS",
            fixture: "capsule_rejects_expired_window",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-BINDING",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-ATTESTATION-BINDING",
            fixture: "capsule_rejects_missing_attestation_binding",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-TRACE",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-TRACE-COMMITMENT",
            fixture: "capsule_rejects_trace_commitment_mismatch",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-INTEGRITY",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-INTEGRITY-HASH",
            fixture: "capsule_rejects_integrity_hash_mismatch",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-SIGNATURE",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-SIGNATURE",
            fixture: "capsule_rejects_signature_mismatch",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-HASH-FORMAT",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-HASH-FORMAT",
            fixture: "capsule_rejects_non_sha256_hash_field",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-VERIFIER-MISMATCH",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-VERIFIER-MISMATCH",
            fixture: "capsule_rejects_attestation_verifier_mismatch",
        },
        MatrixRow {
            requirement_id: "VEP-REPLAY-CLAIM-MISMATCH",
            level: "MUST",
            surface: "replay_capsule",
            contract: "ERR-VEP-CAPSULE-CLAIM-MISMATCH",
            fixture: "capsule_rejects_claim_metadata_mismatch",
        },
        MatrixRow {
            requirement_id: "VEP-CAPACITY-CODE",
            level: "SHOULD",
            surface: "bounded_registries",
            contract: "ERR-VEP-CAPACITY-EXCEEDED",
            fixture: "capacity_error_code_is_exported_for_boundary_harnesses",
        },
    ]
}

fn push_len_prefixed(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(u64::try_from(value.len()).unwrap_or(u64::MAX)).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn sample_sha256(label: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

fn registration(signing_key: &SigningKey) -> VerifierRegistration {
    VerifierRegistration {
        name: "Conformance Verifier".to_string(),
        contact: "vep-conformance@example.invalid".to_string(),
        public_key: public_key_hex(signing_key),
        capabilities: vec![
            VerificationDimension::Compatibility,
            VerificationDimension::Security,
            VerificationDimension::Conformance,
        ],
        tier: VerifierTier::Advanced,
    }
}

fn attestation_signature_payload(submission: &AttestationSubmission) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"verifier_economy_attestation_v1:");
    push_len_prefixed(&mut payload, &submission.verifier_id);
    push_len_prefixed(&mut payload, &submission.claim.dimension.to_string());
    push_len_prefixed(&mut payload, &submission.claim.statement);
    let score_bits = if submission.claim.score.is_finite() {
        submission.claim.score.to_bits()
    } else {
        0_f64.to_bits()
    };
    payload.extend_from_slice(&score_bits.to_le_bytes());
    push_len_prefixed(&mut payload, &submission.evidence.suite_id);
    push_len_prefixed(&mut payload, &submission.evidence.execution_trace_hash);
    payload.extend_from_slice(
        &(u64::try_from(submission.evidence.measurements.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for measurement in &submission.evidence.measurements {
        push_len_prefixed(&mut payload, measurement);
    }
    payload.extend_from_slice(
        &(u64::try_from(submission.evidence.environment.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for (key, value) in &submission.evidence.environment {
        push_len_prefixed(&mut payload, key);
        push_len_prefixed(&mut payload, value);
    }
    push_len_prefixed(&mut payload, &submission.timestamp);
    payload
}

fn sign_submission(submission: &mut AttestationSubmission, signing_key: &SigningKey) {
    submission.signature.algorithm = "ed25519".to_string();
    submission.signature.public_key = public_key_hex(signing_key);
    submission.signature.value = hex::encode(
        signing_key
            .sign(&attestation_signature_payload(submission))
            .to_bytes(),
    );
}

fn make_submission(
    verifier_id: &str,
    signing_key: &SigningKey,
    trace_label: &str,
) -> AttestationSubmission {
    let mut submission = AttestationSubmission {
        verifier_id: verifier_id.to_string(),
        claim: AttestationClaim {
            dimension: VerificationDimension::Conformance,
            statement: "VEP conformance suite preserves verifier outcomes".to_string(),
            score: 0.97,
        },
        evidence: AttestationEvidence {
            suite_id: "vep-conformance-v1".to_string(),
            measurements: vec!["coverage:24/24".to_string()],
            execution_trace_hash: sample_sha256(trace_label),
            environment: BTreeMap::from([
                ("runtime".to_string(), "franken-node".to_string()),
                ("substrate".to_string(), "lockstep".to_string()),
            ]),
        },
        signature: AttestationSignature {
            algorithm: String::new(),
            public_key: String::new(),
            value: String::new(),
        },
        timestamp: "2026-04-23T00:00:00Z".to_string(),
    };
    sign_submission(&mut submission, signing_key);
    submission
}

fn claim_metadata_hash(attestation: &Attestation) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"verifier_economy_replay_claim_v1:");
    push_len_prefixed(&mut payload, &attestation.claim.dimension.to_string());
    push_len_prefixed(&mut payload, &attestation.claim.statement);
    let score_bits = if attestation.claim.score.is_finite() {
        attestation.claim.score.to_bits()
    } else {
        0_f64.to_bits()
    };
    payload.extend_from_slice(&score_bits.to_le_bytes());
    push_len_prefixed(&mut payload, &attestation.evidence.suite_id);
    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

fn normalize_sha256_prefixed(value: &str) -> Option<String> {
    let normalized = value.strip_prefix("sha256:").unwrap_or(value);
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(format!("sha256:{normalized}"))
    } else {
        None
    }
}

fn trace_commitment_pair(left: &str, right: &str) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_trace_commitment_v1:");
    push_len_prefixed(&mut payload, left);
    push_len_prefixed(&mut payload, right);
    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

fn trace_commitment_root(trace_chunk_hashes: &[String]) -> Option<String> {
    if trace_chunk_hashes.is_empty() {
        return None;
    }
    let mut level = trace_chunk_hashes
        .iter()
        .map(|hash| normalize_sha256_prefixed(hash))
        .collect::<Option<Vec<_>>>()?;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index < level.len() {
            let left = &level[index];
            let right = level.get(index + 1).unwrap_or(left);
            next.push(trace_commitment_pair(left, right));
            index += 2;
        }
        level = next;
    }
    level.into_iter().next()
}

#[allow(clippy::too_many_arguments)]
fn capsule_integrity_hash(
    capsule_id: &str,
    schema_version: &str,
    attestation_id: &str,
    verifier_id: &str,
    claim_metadata_hash: &str,
    issued_at: &str,
    expires_at: &str,
    input_state_hash: &str,
    trace_commitment_root: &str,
    output_state_hash: &str,
    expected_result_hash: &str,
) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_signed_capsule_integrity_v2:");
    for field in [
        capsule_id,
        schema_version,
        attestation_id,
        verifier_id,
        claim_metadata_hash,
        issued_at,
        expires_at,
        input_state_hash,
        trace_commitment_root,
        output_state_hash,
        expected_result_hash,
    ] {
        push_len_prefixed(&mut payload, field);
    }
    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

fn capsule_signature_payload(capsule: &ReplayCapsule) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_signed_capsule_signature_v1:");
    for field in [
        &capsule.capsule_id,
        &capsule.schema_version,
        &capsule.attestation_id,
        &capsule.verifier_id,
        &capsule.claim_metadata_hash,
        &capsule.issued_at,
        &capsule.expires_at,
        &capsule.input_state_hash,
        &capsule.trace_commitment_root,
        &capsule.output_state_hash,
        &capsule.expected_result_hash,
        &capsule.integrity_hash,
    ] {
        push_len_prefixed(&mut payload, field);
    }
    payload.extend_from_slice(
        &(u64::try_from(capsule.trace_chunk_hashes.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for hash in &capsule.trace_chunk_hashes {
        push_len_prefixed(&mut payload, hash);
    }
    payload
}

fn refresh_capsule_integrity(capsule: &mut ReplayCapsule) {
    capsule.integrity_hash = capsule_integrity_hash(
        &capsule.capsule_id,
        &capsule.schema_version,
        &capsule.attestation_id,
        &capsule.verifier_id,
        &capsule.claim_metadata_hash,
        &capsule.issued_at,
        &capsule.expires_at,
        &capsule.input_state_hash,
        &capsule.trace_commitment_root,
        &capsule.output_state_hash,
        &capsule.expected_result_hash,
    );
}

fn sign_capsule(capsule: &mut ReplayCapsule, signing_key: &SigningKey) {
    capsule.signature.algorithm = "ed25519".to_string();
    capsule.signature.public_key = public_key_hex(signing_key);
    capsule.signature.value = hex::encode(
        signing_key
            .sign(&capsule_signature_payload(capsule))
            .to_bytes(),
    );
}

fn make_capsule(
    capsule_id: &str,
    verifier_id: &str,
    attestation: &Attestation,
    signing_key: &SigningKey,
) -> ReplayCapsule {
    let trace_chunk_hashes = vec![
        sample_sha256(&format!("{capsule_id}:trace:0")),
        sample_sha256(&format!("{capsule_id}:trace:1")),
        sample_sha256(&format!("{capsule_id}:trace:2")),
    ];
    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let expires_at =
        (now + chrono::Duration::seconds(3600)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut capsule = ReplayCapsule {
        capsule_id: capsule_id.to_string(),
        schema_version: REPLAY_CAPSULE_SCHEMA_VERSION.to_string(),
        attestation_id: attestation.attestation_id.clone(),
        verifier_id: verifier_id.to_string(),
        claim_metadata_hash: claim_metadata_hash(attestation),
        issued_at,
        expires_at,
        input_state_hash: sample_sha256(&format!("{capsule_id}:input")),
        trace_commitment_root: trace_commitment_root(&trace_chunk_hashes)
            .expect("fixture trace commitment root"),
        trace_chunk_hashes,
        output_state_hash: sample_sha256(&format!("{capsule_id}:output")),
        expected_result_hash: sample_sha256(&format!("{capsule_id}:expected")),
        integrity_hash: String::new(),
        signature: AttestationSignature {
            algorithm: String::new(),
            public_key: String::new(),
            value: String::new(),
        },
    };
    refresh_capsule_integrity(&mut capsule);
    sign_capsule(&mut capsule, signing_key);
    capsule
}

fn signed_capsule_after_mutation(
    mut capsule: ReplayCapsule,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut ReplayCapsule),
) -> ReplayCapsule {
    mutate(&mut capsule);
    refresh_capsule_integrity(&mut capsule);
    sign_capsule(&mut capsule, signing_key);
    capsule
}

fn registered_fixture(seed: u8) -> (VerifierEconomyRegistry, SigningKey, Verifier) {
    let signing_key = signing_key(seed);
    let mut registry = VerifierEconomyRegistry::new();
    let verifier = registry
        .register_verifier(registration(&signing_key))
        .expect("fixture verifier registration");
    (registry, signing_key, verifier)
}

fn published_fixture(seed: u8) -> (VerifierEconomyRegistry, SigningKey, Verifier, Attestation) {
    let (mut registry, signing_key, verifier) = registered_fixture(seed);
    let attestation = registry
        .submit_attestation(make_submission(
            &verifier.verifier_id,
            &signing_key,
            "published-fixture",
        ))
        .expect("fixture attestation submission");
    registry
        .review_attestation(&attestation.attestation_id)
        .expect("fixture review");
    registry
        .publish_attestation(&attestation.attestation_id)
        .expect("fixture publish");
    let published = registry
        .get_attestation(&attestation.attestation_id)
        .expect("published attestation")
        .clone();
    (registry, signing_key, verifier, published)
}

fn expect_error_code<T: std::fmt::Debug>(result: VepResult<T>, expected_code: &str) {
    let err = result.expect_err("fixture should fail");
    assert_eq!(err.code, expected_code, "unexpected VEP error: {err}");
}

fn last_event_code(registry: &VerifierEconomyRegistry) -> &str {
    registry
        .events()
        .last()
        .expect("event should be emitted")
        .code
        .as_str()
}

#[test]
fn verifier_economy_coverage_matrix_artifact_is_stable() {
    let actual = serde_json::to_string_pretty(&matrix_rows()).expect("matrix JSON");

    assert_eq!(actual, FIXTURE_MATRIX.trim());
}

#[test]
fn verifier_economy_vep_conformance_matrix_executes_required_fixtures() {
    let mut passed = BTreeSet::new();

    let (registry, primary_key, verifier) = registered_fixture(1);
    assert_eq!(last_event_code(&registry), VEP_005);
    assert_eq!(verifier.public_key, public_key_hex(&primary_key));
    passed.insert("VEP-REGISTRATION-OK");

    let mut invalid_key_registry = VerifierEconomyRegistry::new();
    let mut invalid_registration = registration(&signing_key(2));
    invalid_registration.public_key = "not-ed25519".to_string();
    expect_error_code(
        invalid_key_registry.register_verifier(invalid_registration),
        ERR_VEP_INVALID_PUBLIC_KEY,
    );
    passed.insert("VEP-REGISTRATION-INVALID-PUBLIC-KEY");

    let mut duplicate_registry = VerifierEconomyRegistry::new();
    duplicate_registry
        .register_verifier(registration(&signing_key(3)))
        .expect("first registration");
    expect_error_code(
        duplicate_registry.register_verifier(registration(&signing_key(3))),
        ERR_VEP_DUPLICATE_SUBMISSION,
    );
    passed.insert("VEP-REGISTRATION-DUPLICATE");

    let (mut submit_registry, submit_key, submit_verifier) = registered_fixture(4);
    let attestation = submit_registry
        .submit_attestation(make_submission(
            &submit_verifier.verifier_id,
            &submit_key,
            "attestation-ok",
        ))
        .expect("valid attestation");
    assert_eq!(attestation.state, AttestationState::Submitted);
    assert_eq!(last_event_code(&submit_registry), VEP_001);
    passed.insert("VEP-ATTESTATION-OK");

    let (mut bad_signature_registry, bad_signature_key, bad_signature_verifier) =
        registered_fixture(5);
    let mut bad_signature_submission = make_submission(
        &bad_signature_verifier.verifier_id,
        &bad_signature_key,
        "bad-signature",
    );
    bad_signature_submission.signature.value = "00".repeat(64);
    expect_error_code(
        bad_signature_registry.submit_attestation(bad_signature_submission),
        ERR_VEP_INVALID_SIGNATURE,
    );
    passed.insert("VEP-ATTESTATION-SIGNATURE");

    let mut unregistered_registry = VerifierEconomyRegistry::new();
    expect_error_code(
        unregistered_registry.submit_attestation(make_submission(
            "ver-missing",
            &signing_key(6),
            "unregistered",
        )),
        ERR_VEP_UNREGISTERED_VERIFIER,
    );
    passed.insert("VEP-ATTESTATION-UNREGISTERED");

    let (mut incomplete_registry, incomplete_key, incomplete_verifier) = registered_fixture(7);
    let mut incomplete_submission = make_submission(
        &incomplete_verifier.verifier_id,
        &incomplete_key,
        "incomplete",
    );
    incomplete_submission.claim.statement.clear();
    sign_submission(&mut incomplete_submission, &incomplete_key);
    expect_error_code(
        incomplete_registry.submit_attestation(incomplete_submission),
        ERR_VEP_INCOMPLETE_PAYLOAD,
    );
    passed.insert("VEP-ATTESTATION-INCOMPLETE");

    let (
        mut duplicate_submission_registry,
        duplicate_submission_key,
        duplicate_submission_verifier,
    ) = registered_fixture(8);
    duplicate_submission_registry
        .submit_attestation(make_submission(
            &duplicate_submission_verifier.verifier_id,
            &duplicate_submission_key,
            "duplicate-submission",
        ))
        .expect("first submission");
    expect_error_code(
        duplicate_submission_registry.submit_attestation(make_submission(
            &duplicate_submission_verifier.verifier_id,
            &duplicate_submission_key,
            "duplicate-submission",
        )),
        ERR_VEP_DUPLICATE_SUBMISSION,
    );
    passed.insert("VEP-ATTESTATION-DUPLICATE");

    let (mut anti_gaming_registry, anti_gaming_key, anti_gaming_verifier) = registered_fixture(9);
    let mut anti_gaming_code = String::new();
    for index in 0..=100 {
        let result = anti_gaming_registry.submit_attestation(make_submission(
            &anti_gaming_verifier.verifier_id,
            &anti_gaming_key,
            &format!("anti-gaming-{index}"),
        ));
        if let Err(err) = result {
            anti_gaming_code = err.code;
            break;
        }
    }
    assert_eq!(anti_gaming_code, ERR_VEP_ANTI_GAMING);
    assert_eq!(last_event_code(&anti_gaming_registry), VEP_006);
    passed.insert("VEP-ANTI-GAMING");

    let (mut reputation_registry, _, reputation_verifier) = registered_fixture(10);
    let score = reputation_registry
        .update_reputation(
            &reputation_verifier.verifier_id,
            &ReputationDimensions {
                consistency: 0.9,
                coverage: 0.8,
                accuracy: 0.95,
                longevity: 0.5,
            },
        )
        .expect("reputation update");
    assert_eq!(
        score,
        VerifierEconomyRegistry::compute_reputation(&ReputationDimensions {
            consistency: 0.9,
            coverage: 0.8,
            accuracy: 0.95,
            longevity: 0.5,
        })
    );
    assert_eq!(last_event_code(&reputation_registry), VEP_004);
    passed.insert("VEP-REPUTATION");

    let (publish_registry, _, _, published_attestation) = published_fixture(11);
    assert_eq!(published_attestation.state, AttestationState::Published);
    assert!(published_attestation.immutable);
    assert_eq!(last_event_code(&publish_registry), VEP_002);
    passed.insert("VEP-PUBLISH");

    let (mut dispute_registry, _, dispute_verifier, dispute_attestation) = published_fixture(12);
    dispute_registry
        .file_dispute(
            &dispute_attestation.attestation_id,
            &dispute_verifier.verifier_id,
            "conformance challenge",
            vec!["fixture evidence".to_string()],
        )
        .expect("dispute filed");
    assert_eq!(last_event_code(&dispute_registry), VEP_003);
    passed.insert("VEP-DISPUTE");

    let (mut capsule_registry, capsule_key, capsule_verifier, capsule_attestation) =
        published_fixture(13);
    let capsule = make_capsule(
        "capsule-ok",
        &capsule_verifier.verifier_id,
        &capsule_attestation,
        &capsule_key,
    );
    capsule_registry
        .register_replay_capsule(capsule.clone())
        .expect("capsule registration");
    capsule_registry
        .access_replay_capsule(&capsule.capsule_id)
        .expect("capsule access");
    assert_eq!(last_event_code(&capsule_registry), VEP_007);
    passed.insert("VEP-REPLAY-ACCESS");

    let (_, missing_key, missing_verifier, missing_attestation) = published_fixture(14);
    let mut missing_capsule = make_capsule(
        "capsule-missing-fields",
        &missing_verifier.verifier_id,
        &missing_attestation,
        &missing_key,
    );
    missing_capsule.capsule_id.clear();
    assert_eq!(
        VerifierEconomyRegistry::verify_capsule_integrity(&missing_capsule)
            .expect_err("missing field")
            .code(),
        ERR_VEP_CAPSULE_MISSING_FIELDS
    );
    passed.insert("VEP-REPLAY-MISSING-FIELDS");

    let (_, schema_key, schema_verifier, schema_attestation) = published_fixture(15);
    let schema_capsule = signed_capsule_after_mutation(
        make_capsule(
            "capsule-schema",
            &schema_verifier.verifier_id,
            &schema_attestation,
            &schema_key,
        ),
        &schema_key,
        |capsule| capsule.schema_version = "vep-replay-capsule-v1".to_string(),
    );
    assert_eq!(
        VerifierEconomyRegistry::verify_capsule_integrity(&schema_capsule)
            .expect_err("schema")
            .code(),
        ERR_VEP_CAPSULE_SCHEMA
    );
    passed.insert("VEP-REPLAY-SCHEMA");

    let (_, freshness_key, freshness_verifier, freshness_attestation) = published_fixture(16);
    let expired_capsule = signed_capsule_after_mutation(
        make_capsule(
            "capsule-freshness",
            &freshness_verifier.verifier_id,
            &freshness_attestation,
            &freshness_key,
        ),
        &freshness_key,
        |capsule| {
            capsule.issued_at = "2026-01-01T00:00:00Z".to_string();
            capsule.expires_at = "2026-01-01T00:10:00Z".to_string();
        },
    );
    assert_eq!(
        VerifierEconomyRegistry::verify_capsule_integrity(&expired_capsule)
            .expect_err("freshness")
            .code(),
        ERR_VEP_CAPSULE_FRESHNESS
    );
    passed.insert("VEP-REPLAY-FRESHNESS");

    let (mut binding_registry, binding_key, binding_verifier, binding_attestation) =
        published_fixture(17);
    let binding_capsule = signed_capsule_after_mutation(
        make_capsule(
            "capsule-binding",
            &binding_verifier.verifier_id,
            &binding_attestation,
            &binding_key,
        ),
        &binding_key,
        |capsule| capsule.attestation_id = "att-missing".to_string(),
    );
    expect_error_code(
        binding_registry.register_replay_capsule(binding_capsule),
        ERR_VEP_CAPSULE_ATTESTATION_BINDING,
    );
    passed.insert("VEP-REPLAY-BINDING");

    let (_, trace_key, trace_verifier, trace_attestation) = published_fixture(18);
    let mut trace_capsule = make_capsule(
        "capsule-trace",
        &trace_verifier.verifier_id,
        &trace_attestation,
        &trace_key,
    );
    trace_capsule.trace_commitment_root = sample_sha256("wrong-trace-root");
    assert_eq!(
        VerifierEconomyRegistry::verify_capsule_integrity(&trace_capsule)
            .expect_err("trace commitment")
            .code(),
        ERR_VEP_CAPSULE_TRACE_COMMITMENT
    );
    passed.insert("VEP-REPLAY-TRACE");

    let (_, integrity_key, integrity_verifier, integrity_attestation) = published_fixture(19);
    let mut integrity_capsule = make_capsule(
        "capsule-integrity",
        &integrity_verifier.verifier_id,
        &integrity_attestation,
        &integrity_key,
    );
    integrity_capsule.integrity_hash = sample_sha256("wrong-integrity");
    assert_eq!(
        VerifierEconomyRegistry::verify_capsule_integrity(&integrity_capsule)
            .expect_err("integrity")
            .code(),
        ERR_VEP_CAPSULE_INTEGRITY_HASH
    );
    passed.insert("VEP-REPLAY-INTEGRITY");

    let (mut signature_registry, signature_key, signature_verifier, signature_attestation) =
        published_fixture(20);
    let mut signature_capsule = make_capsule(
        "capsule-signature",
        &signature_verifier.verifier_id,
        &signature_attestation,
        &signature_key,
    );
    signature_capsule.signature.value = "00".repeat(64);
    expect_error_code(
        signature_registry.register_replay_capsule(signature_capsule),
        ERR_VEP_CAPSULE_SIGNATURE,
    );
    passed.insert("VEP-REPLAY-SIGNATURE");

    let (_, hash_key, hash_verifier, hash_attestation) = published_fixture(21);
    let mut hash_capsule = make_capsule(
        "capsule-hash-format",
        &hash_verifier.verifier_id,
        &hash_attestation,
        &hash_key,
    );
    hash_capsule.input_state_hash = "not-a-sha256-hash".to_string();
    assert_eq!(
        VerifierEconomyRegistry::verify_capsule_integrity(&hash_capsule)
            .expect_err("hash format")
            .code(),
        ERR_VEP_CAPSULE_HASH_FORMAT
    );
    passed.insert("VEP-REPLAY-HASH-FORMAT");

    let (mut mismatch_registry, first_key, first_verifier, mismatch_attestation) =
        published_fixture(22);
    let second_key = signing_key(23);
    let second_verifier = mismatch_registry
        .register_verifier(registration(&second_key))
        .expect("second verifier");
    let verifier_mismatch_capsule = make_capsule(
        "capsule-verifier-mismatch",
        &second_verifier.verifier_id,
        &mismatch_attestation,
        &second_key,
    );
    assert_ne!(first_verifier.verifier_id, second_verifier.verifier_id);
    assert_eq!(
        first_key.verifying_key().to_bytes().len(),
        second_key.verifying_key().to_bytes().len()
    );
    expect_error_code(
        mismatch_registry.register_replay_capsule(verifier_mismatch_capsule),
        ERR_VEP_CAPSULE_VERIFIER_MISMATCH,
    );
    passed.insert("VEP-REPLAY-VERIFIER-MISMATCH");

    let (mut claim_registry, claim_key, claim_verifier, claim_attestation) = published_fixture(24);
    let claim_mismatch_capsule = signed_capsule_after_mutation(
        make_capsule(
            "capsule-claim-mismatch",
            &claim_verifier.verifier_id,
            &claim_attestation,
            &claim_key,
        ),
        &claim_key,
        |capsule| capsule.claim_metadata_hash = sample_sha256("wrong-claim-metadata"),
    );
    expect_error_code(
        claim_registry.register_replay_capsule(claim_mismatch_capsule),
        ERR_VEP_CAPSULE_CLAIM_MISMATCH,
    );
    passed.insert("VEP-REPLAY-CLAIM-MISMATCH");

    assert_eq!(ERR_VEP_CAPACITY_EXCEEDED, "ERR-VEP-CAPACITY-EXCEEDED");
    passed.insert("VEP-CAPACITY-CODE");

    for row in matrix_rows() {
        assert!(
            passed.contains(row.requirement_id),
            "missing executed VEP conformance fixture for {} ({})",
            row.requirement_id,
            row.contract
        );
    }

    let rows = matrix_rows();
    let must_total = rows.iter().filter(|row| row.level == "MUST").count();
    let must_passed = rows
        .iter()
        .filter(|row| row.level == "MUST" && passed.contains(row.requirement_id))
        .count();
    assert_eq!(must_passed, must_total, "VEP MUST conformance must be 100%");
}
