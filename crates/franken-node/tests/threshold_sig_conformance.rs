//! Public conformance harness for threshold signature verification.
//!
//! The matrix below pins fail-closed behavior for the API that callers use:
//! `sign`, `verify_threshold`, and `verify_threshold_preparsed`.

use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::security::threshold_sig::{
    FailureReason, PartialSignature, PreparsedThresholdConfig, PublicationArtifact, SignerKey,
    ThresholdConfig, VerificationResult, sign, verify_threshold, verify_threshold_preparsed,
};
use sha2::{Digest, Sha256};
use std::fmt::Debug;

const ARTIFACT_ID: &str = "artifact-alpha";
const CONNECTOR_ID: &str = "connector-main";
const CONTENT_HASH: &str = "7e2d58c96b17c8bfa6e120d77f3b14a67d5c9fbb793214df7db4bb3f79df0e41";
const TRACE_ID: &str = "trace-threshold-conformance";
const TIMESTAMP: &str = "2026-05-22T18:14:00Z";

type TestResult<T = ()> = Result<T, String>;

#[derive(Debug)]
struct QuorumFixture {
    config: ThresholdConfig,
    signing_keys: Vec<SigningKey>,
}

#[derive(Debug)]
struct CoverageRow {
    id: &'static str,
    requirement: &'static str,
}

fn deterministic_signing_key(index: u32) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"threshold_sig_conformance_seed_v1:");
    hasher.update(index.to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn ensure_eq<T>(actual: &T, expected: &T, context: &str) -> TestResult
where
    T: Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{context}: expected {expected:?}, actual {actual:?}"
        ))
    }
}

fn key_id_for_index(index: u32) -> TestResult<String> {
    match index {
        0 => Ok(String::from("signer-0")),
        1 => Ok(String::from("signer-1")),
        2 => Ok(String::from("signer-2")),
        _ => Err(format!("missing static signer id for index {index}")),
    }
}

fn build_fixture(threshold: u32, total_signers: u32) -> TestResult<QuorumFixture> {
    let mut signing_keys = Vec::new();
    let mut signer_keys = Vec::new();

    for index in 0..total_signers {
        let signing_key = deterministic_signing_key(index);
        signer_keys.push(SignerKey {
            key_id: key_id_for_index(index)?,
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        });
        signing_keys.push(signing_key);
    }

    Ok(QuorumFixture {
        config: ThresholdConfig {
            threshold,
            total_signers,
            signer_keys,
        },
        signing_keys,
    })
}

fn sign_for_context(
    fixture: &QuorumFixture,
    signer_index: usize,
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
) -> TestResult<PartialSignature> {
    let signing_key = fixture
        .signing_keys
        .get(signer_index)
        .ok_or_else(|| format!("missing signing key for signer index {signer_index}"))?;
    let signer_key = fixture
        .config
        .signer_keys
        .get(signer_index)
        .ok_or_else(|| format!("missing signer config for signer index {signer_index}"))?;
    Ok(sign(
        signing_key,
        &signer_key.key_id,
        artifact_id,
        connector_id,
        content_hash,
    ))
}

fn signatures_for_indices(
    fixture: &QuorumFixture,
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
    signer_indices: &[usize],
) -> TestResult<Vec<PartialSignature>> {
    signer_indices
        .iter()
        .map(|&index| sign_for_context(fixture, index, artifact_id, connector_id, content_hash))
        .collect()
}

fn artifact(
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
    signatures: Vec<PartialSignature>,
) -> PublicationArtifact {
    PublicationArtifact {
        artifact_id: artifact_id.to_string(),
        connector_id: connector_id.to_string(),
        content_hash: content_hash.to_string(),
        signatures,
    }
}

fn verify_both(
    config: &ThresholdConfig,
    artifact: &PublicationArtifact,
) -> TestResult<(VerificationResult, VerificationResult)> {
    let baseline = verify_threshold(config, artifact, TRACE_ID, TIMESTAMP);
    let prepared = PreparsedThresholdConfig::from_config(config.clone())
        .map_err(|error| format!("fixture threshold config must be valid: {error:?}"))?;
    let preparsed = verify_threshold_preparsed(&prepared, artifact, TRACE_ID, TIMESTAMP);
    ensure_eq(
        &baseline,
        &preparsed,
        "baseline and preparsed verification paths must remain byte-identical",
    )?;
    Ok((baseline, preparsed))
}

fn assert_result(
    result: &VerificationResult,
    verified: bool,
    valid_signatures: u32,
    failure_reason: Option<FailureReason>,
) -> TestResult {
    ensure_eq(&result.verified, &verified, "verified flag")?;
    ensure_eq(
        &result.valid_signatures,
        &valid_signatures,
        "valid signature count",
    )?;
    ensure_eq(&result.threshold, &2, "threshold")?;
    ensure_eq(&result.trace_id.as_str(), &TRACE_ID, "trace id")?;
    ensure_eq(&result.timestamp.as_str(), &TIMESTAMP, "timestamp")?;
    ensure_eq(&result.failure_reason, &failure_reason, "failure reason")
}

fn assert_failure_variant(
    result: &VerificationResult,
    valid_signatures: u32,
    matches_failure: impl FnOnce(&FailureReason) -> bool,
) -> TestResult {
    ensure(!result.verified, "rejected case must not verify")?;
    ensure_eq(
        &result.valid_signatures,
        &valid_signatures,
        "valid signature count",
    )?;
    let failure_reason = result
        .failure_reason
        .as_ref()
        .ok_or_else(|| "rejected conformance case must explain the failure".to_string())?;
    ensure(
        matches_failure(failure_reason),
        format!("unexpected failure reason: {failure_reason:?}"),
    )
}

fn assert_all_requirements_covered(rows: &[CoverageRow]) -> TestResult {
    let required_ids = [
        "TSIG-QUORUM-ADMIT",
        "TSIG-BELOW-THRESHOLD",
        "TSIG-DUPLICATE-REPLAY",
        "TSIG-UNKNOWN-SIGNER",
        "TSIG-MALFORMED-SIGNATURE",
        "TSIG-IDENTITY-BINDING",
        "TSIG-ARTIFACT-REPLAY",
        "TSIG-CONNECTOR-REPLAY",
        "TSIG-LENGTH-PREFIX-SEPARATION",
        "TSIG-DOMAIN-SEPARATION",
        "TSIG-ARTIFACT-ID-FAIL-CLOSED",
        "TSIG-CONNECTOR-ID-FAIL-CLOSED",
        "TSIG-CONFIG-FAIL-CLOSED",
    ];

    for required_id in required_ids {
        let present = rows
            .iter()
            .any(|row| row.id == required_id && !row.requirement.trim().is_empty());
        ensure(present, missing_coverage_message(required_id))?;
    }
    Ok(())
}

fn missing_coverage_message(required_id: &str) -> String {
    format!("missing or empty conformance row {required_id}")
}

#[test]
fn threshold_signature_conformance_matrix_covers_fail_closed_contracts() -> TestResult {
    let fixture = build_fixture(2, 3)?;
    let mut covered = Vec::new();

    let quorum_artifact = artifact(
        ARTIFACT_ID,
        CONNECTOR_ID,
        CONTENT_HASH,
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0, 1])?,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &quorum_artifact)?;
    assert_result(&baseline, true, 2, None)?;
    covered.push(CoverageRow {
        id: "TSIG-QUORUM-ADMIT",
        requirement: "two distinct configured signatures satisfy a 2-of-3 quorum",
    });

    let below_threshold = artifact(
        ARTIFACT_ID,
        CONNECTOR_ID,
        CONTENT_HASH,
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0])?,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &below_threshold)?;
    assert_result(
        &baseline,
        false,
        1,
        Some(FailureReason::BelowThreshold { have: 1, need: 2 }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-BELOW-THRESHOLD",
        requirement: "partial signature sets stay rejected with stable quorum accounting",
    });

    let duplicate_signature =
        sign_for_context(&fixture, 0, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH)?;
    let duplicate_replay = artifact(
        ARTIFACT_ID,
        CONNECTOR_ID,
        CONTENT_HASH,
        vec![duplicate_signature.clone(), duplicate_signature],
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &duplicate_replay)?;
    assert_result(
        &baseline,
        false,
        1,
        Some(FailureReason::DuplicateSigner {
            signer_id: "signer-0".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-DUPLICATE-REPLAY",
        requirement: "replayed partial signatures cannot inflate quorum count",
    });

    let mut unknown_signatures =
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0])?;
    unknown_signatures.push(PartialSignature {
        signer_id: "unknown-signer".to_string(),
        key_id: "unknown-signer".to_string(),
        signature_hex: "00".repeat(64),
    });
    let unknown_signer = artifact(ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, unknown_signatures);
    let (baseline, _preparsed) = verify_both(&fixture.config, &unknown_signer)?;
    assert_result(
        &baseline,
        false,
        1,
        Some(FailureReason::UnknownSigner {
            signer_id: "unknown-signer".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-UNKNOWN-SIGNER",
        requirement: "unknown key identifiers do not contribute to quorum",
    });

    let mut malformed_signatures =
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0])?;
    malformed_signatures.push(PartialSignature {
        signer_id: "signer-1".to_string(),
        key_id: "signer-1".to_string(),
        signature_hex: "ff".repeat(64),
    });
    let malformed_signature = artifact(
        ARTIFACT_ID,
        CONNECTOR_ID,
        CONTENT_HASH,
        malformed_signatures,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &malformed_signature)?;
    assert_result(
        &baseline,
        false,
        1,
        Some(FailureReason::InvalidSignature {
            signer_id: "signer-1".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-MALFORMED-SIGNATURE",
        requirement: "malformed or non-verifying signature bytes fail closed",
    });

    let mut identity_signatures =
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0])?;
    let mut relabeled = sign_for_context(&fixture, 1, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH)?;
    relabeled.signer_id = "signer-0".to_string();
    identity_signatures.push(relabeled);
    let identity_mismatch = artifact(ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, identity_signatures);
    let (baseline, _preparsed) = verify_both(&fixture.config, &identity_mismatch)?;
    assert_result(
        &baseline,
        false,
        1,
        Some(FailureReason::InvalidSignature {
            signer_id: "signer-0".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-IDENTITY-BINDING",
        requirement: "signer_id must be bound to the configured key_id before quorum credit",
    });

    let artifact_replay = artifact(
        "artifact-beta",
        CONNECTOR_ID,
        CONTENT_HASH,
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0, 1])?,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &artifact_replay)?;
    assert_result(
        &baseline,
        false,
        0,
        Some(FailureReason::InvalidSignature {
            signer_id: "signer-0".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-ARTIFACT-REPLAY",
        requirement: "signatures cannot replay across artifact identifiers",
    });

    let connector_replay = artifact(
        ARTIFACT_ID,
        "connector-alt",
        CONTENT_HASH,
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0, 1])?,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &connector_replay)?;
    assert_result(
        &baseline,
        false,
        0,
        Some(FailureReason::InvalidSignature {
            signer_id: "signer-0".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-CONNECTOR-REPLAY",
        requirement: "signatures cannot replay across connector identifiers",
    });

    let length_prefix_replay = artifact(
        "artifact-ab",
        "c",
        CONTENT_HASH,
        signatures_for_indices(&fixture, "artifact-a", "bc", CONTENT_HASH, &[0, 1])?,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &length_prefix_replay)?;
    assert_result(
        &baseline,
        false,
        0,
        Some(FailureReason::InvalidSignature {
            signer_id: "signer-0".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-LENGTH-PREFIX-SEPARATION",
        requirement: "ambiguous concatenations remain distinct through length-prefixed fields",
    });

    let mut raw_message_signatures =
        signatures_for_indices(&fixture, ARTIFACT_ID, CONNECTOR_ID, CONTENT_HASH, &[0])?;
    let raw_signing_key = fixture
        .signing_keys
        .get(1)
        .ok_or_else(|| "missing signer key for raw domain separation case".to_string())?;
    let raw_signature = raw_signing_key.sign(CONTENT_HASH.as_bytes());
    raw_message_signatures.push(PartialSignature {
        signer_id: "signer-1".to_string(),
        key_id: "signer-1".to_string(),
        signature_hex: hex::encode(raw_signature.to_bytes()),
    });
    let raw_message = artifact(
        ARTIFACT_ID,
        CONNECTOR_ID,
        CONTENT_HASH,
        raw_message_signatures,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &raw_message)?;
    assert_result(
        &baseline,
        false,
        1,
        Some(FailureReason::InvalidSignature {
            signer_id: "signer-1".to_string(),
        }),
    )?;
    covered.push(CoverageRow {
        id: "TSIG-DOMAIN-SEPARATION",
        requirement: "raw content-hash signatures are rejected without the signing domain",
    });

    let invalid_artifact_id = artifact(
        "../escape",
        CONNECTOR_ID,
        CONTENT_HASH,
        signatures_for_indices(&fixture, "../escape", CONNECTOR_ID, CONTENT_HASH, &[0, 1])?,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &invalid_artifact_id)?;
    assert_failure_variant(&baseline, 0, |failure| {
        matches!(failure, FailureReason::InvalidArtifactId { .. })
    })?;
    covered.push(CoverageRow {
        id: "TSIG-ARTIFACT-ID-FAIL-CLOSED",
        requirement: "unsafe artifact identifiers are rejected before signature counting",
    });

    let invalid_connector_id = artifact(
        ARTIFACT_ID,
        "/connector-root",
        CONTENT_HASH,
        signatures_for_indices(
            &fixture,
            ARTIFACT_ID,
            "/connector-root",
            CONTENT_HASH,
            &[0, 1],
        )?,
    );
    let (baseline, _preparsed) = verify_both(&fixture.config, &invalid_connector_id)?;
    assert_failure_variant(&baseline, 0, |failure| {
        matches!(failure, FailureReason::InvalidConnectorId { .. })
    })?;
    covered.push(CoverageRow {
        id: "TSIG-CONNECTOR-ID-FAIL-CLOSED",
        requirement: "unsafe connector identifiers are rejected before signature counting",
    });

    let invalid_signer_keys = fixture.config.signer_keys.iter().take(2).cloned().collect();
    let invalid_config = ThresholdConfig {
        threshold: 3,
        total_signers: 2,
        signer_keys: invalid_signer_keys,
    };
    let result = verify_threshold(&invalid_config, &quorum_artifact, TRACE_ID, TIMESTAMP);
    ensure(!result.verified, "invalid config must fail closed")?;
    ensure_eq(
        &result.valid_signatures,
        &0,
        "invalid config signature count",
    )?;
    ensure(
        matches!(
            result.failure_reason,
            Some(FailureReason::ConfigInvalid { .. })
        ),
        "invalid config must return ConfigInvalid",
    )?;
    ensure(
        PreparsedThresholdConfig::from_config(invalid_config).is_err(),
        "invalid config must not build a preparsed verifier",
    )?;
    covered.push(CoverageRow {
        id: "TSIG-CONFIG-FAIL-CLOSED",
        requirement: "invalid threshold configs fail both baseline and preparsed construction",
    });

    assert_all_requirements_covered(&covered)
}
