//! Contract tests for the shared evidence verification spine.
//!
//! The fixture matrix in `artifacts/evidence_verification_spine` is the
//! operator-facing contract. These tests keep the matrix tied to live verifier
//! behavior instead of letting each surface drift into a local definition of
//! "verified".

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    process::Command,
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use frankenengine_node::{
    connector::universal_verifier_sdk as node_vsdk,
    supply_chain::provenance::{
        self as prov, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole,
        ProvenanceAttestation, ProvenanceLevel, VerificationErrorCode, VerificationPolicy,
    },
    tools::evidence_explain::{self, EvidenceArtifactKind},
    vef::evidence_capsule::{EvidenceCapsule, EvidenceVerificationContext, VefEvidence},
};
use frankenengine_verifier_sdk::{SDK_VERSION, capsule as external_capsule};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXTURE_MATRIX_JSON: &str =
    include_str!("../../../artifacts/evidence_verification_spine/bd-hp1hy_fixture_matrix.json");
const EVIDENCE_EXPLAIN_CONTRACT_JSON: &str =
    include_str!("../../../artifacts/evidence_explain/bd-6z0tq_contract.json");

type TestResult = Result<(), String>;

fn sha256_seed(domain: &[u8], value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn provenance_signing_key_for(signer_id: &str) -> SigningKey {
    SigningKey::from_bytes(&sha256_seed(
        b"evidence_spine:provenance_signer:v1:",
        signer_id,
    ))
}

fn provenance_signing_keys(attestation: &ProvenanceAttestation) -> BTreeMap<String, SigningKey> {
    attestation
        .links
        .iter()
        .map(|link| {
            (
                link.signer_id.clone(),
                provenance_signing_key_for(&link.signer_id),
            )
        })
        .collect()
}

fn provenance_policy_for(attestation: &ProvenanceAttestation) -> VerificationPolicy {
    let mut policy = VerificationPolicy::production_default();
    for link in &attestation.links {
        let signing_key = provenance_signing_key_for(&link.signer_id);
        policy.add_trusted_signer_key(link.signer_id.as_str(), &signing_key.verifying_key());
    }
    policy
}

fn base_provenance_attestation() -> Result<ProvenanceAttestation, String> {
    let mut attestation = ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://example.com/franken-node.git".to_string(),
        build_system_identifier: "github-actions".to_string(),
        builder_identity: "builder@example.com".to_string(),
        builder_version: "2026.05".to_string(),
        vcs_commit_sha: "aabbccddeeff00112233445566778899aabbccdd".to_string(),
        build_timestamp_epoch: 1_700_000_100,
        reproducibility_hash: "sha256:reproducible".to_string(),
        input_hash: "sha256:inputs".to_string(),
        output_hash: "sha256:artifact-output".to_string(),
        slsa_level_claim: 3,
        envelope_format: AttestationEnvelopeFormat::InToto,
        links: vec![
            AttestationLink {
                role: ChainLinkRole::Publisher,
                signer_id: "publisher-key".to_string(),
                signer_version: "v1".to_string(),
                signature: String::new(),
                signed_payload_hash: "sha256:artifact-output".to_string(),
                issued_at_epoch: 1_700_000_200,
                expires_at_epoch: 1_700_100_000,
                revoked: false,
            },
            AttestationLink {
                role: ChainLinkRole::BuildSystem,
                signer_id: "build-key".to_string(),
                signer_version: "v1".to_string(),
                signature: String::new(),
                signed_payload_hash: "sha256:artifact-output".to_string(),
                issued_at_epoch: 1_700_000_210,
                expires_at_epoch: 1_700_100_000,
                revoked: false,
            },
            AttestationLink {
                role: ChainLinkRole::SourceVcs,
                signer_id: "vcs-key".to_string(),
                signer_version: "v1".to_string(),
                signature: String::new(),
                signed_payload_hash: "sha256:artifact-output".to_string(),
                issued_at_epoch: 1_700_000_220,
                expires_at_epoch: 1_700_100_000,
                revoked: false,
            },
        ],
        custom_claims: BTreeMap::new(),
    };
    let signing_keys = provenance_signing_keys(&attestation);
    prov::sign_links_in_place(&mut attestation, &signing_keys)
        .map_err(|err| format!("base provenance attestation must sign: {err}"))?;
    Ok(attestation)
}

fn node_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42_u8; 32])
}

fn node_expected_replay_hash(payload: &str, inputs: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"universal_verifier_sdk_replay_v1:");
    hasher.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(payload.as_bytes());
    hasher.update(
        u64::try_from(inputs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (key, value) in inputs {
        hasher.update(u64::try_from(key.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(key.as_bytes());
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn node_replay_capsule() -> node_vsdk::ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();
    let manifest = node_vsdk::CapsuleManifest {
        schema_version: node_vsdk::VSDK_SCHEMA_VERSION.to_string(),
        capsule_id: "node-capsule-spine-001".to_string(),
        description: "Node replay capsule for evidence spine contract".to_string(),
        claim_type: "migration_safety".to_string(),
        input_refs: vec!["artifact_a".to_string(), "artifact_b".to_string()],
        expected_output_hash: node_expected_replay_hash(&payload, &inputs),
        created_at: "2026-05-05T00:00:00Z".to_string(),
        creator_identity: "creator://spine".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut capsule = node_vsdk::ReplayCapsule {
        manifest,
        payload,
        inputs,
        signature: String::new(),
    };
    node_vsdk::sign_capsule(&mut capsule, &node_signing_key());
    capsule
}

fn external_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

fn external_expected_replay_hash(payload: &str, inputs: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_capsule_replay_v1:");
    hasher.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(payload.as_bytes());
    hasher.update(
        u64::try_from(inputs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (key, value) in inputs {
        hasher.update(u64::try_from(key.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(key.as_bytes());
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn external_replay_capsule() -> external_capsule::ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();
    let manifest = external_capsule::CapsuleManifest {
        schema_version: SDK_VERSION.to_string(),
        capsule_id: "external-capsule-spine-001".to_string(),
        description: "External SDK replay capsule for evidence spine contract".to_string(),
        claim_type: "migration_safety".to_string(),
        input_refs: vec!["artifact_a".to_string(), "artifact_b".to_string()],
        expected_output_hash: external_expected_replay_hash(&payload, &inputs),
        created_at: "2026-05-05T00:00:00Z".to_string(),
        creator_identity: "creator://spine".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut capsule = external_capsule::ReplayCapsule {
        manifest,
        payload,
        inputs,
        signature: String::new(),
    };
    external_capsule::sign_capsule(&external_signing_key(), &mut capsule);
    capsule
}

fn evidence_capsule_with_context() -> Result<(EvidenceCapsule, EvidenceVerificationContext), String>
{
    let mut capsule = EvidenceCapsule::new("vef-spine-001".to_string(), 1_700_000_000);
    let mut evidence = VefEvidence {
        receipt_chain_commitment: String::new(),
        proof_id: "proof-spine-001".to_string(),
        proof_type: "receipt_chain".to_string(),
        window_start: 10,
        window_end: 20,
        verified: true,
        policy_constraints: vec!["no-network".to_string()],
    };
    evidence.receipt_chain_commitment = capsule.derive_receipt_chain_commitment(&evidence);
    let trusted_commitment = evidence.receipt_chain_commitment.clone();
    capsule
        .add_evidence(evidence)
        .map_err(|err| format!("evidence capsule must accept reference evidence: {err}"))?;
    capsule
        .seal()
        .map_err(|err| format!("evidence capsule must seal: {err}"))?;
    let context = EvidenceVerificationContext {
        trusted_receipt_chain_commitments: vec![trusted_commitment],
        accepted_proof_types: vec!["receipt_chain".to_string()],
    };
    Ok((capsule, context))
}

fn artifact_cases_for(surface: &str) -> Result<BTreeSet<String>, String> {
    let matrix: Value = serde_json::from_str(FIXTURE_MATRIX_JSON)
        .map_err(|err| format!("fixture matrix must parse: {err}"))?;
    let cases = matrix
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "fixture matrix cases must be an array".to_string())?;
    Ok(cases
        .iter()
        .filter(|case| {
            case.get("surface")
                .and_then(Value::as_str)
                .is_some_and(|actual| actual == surface)
        })
        .filter_map(|case| case.get("case").and_then(Value::as_str).map(str::to_string))
        .collect())
}

fn repo_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|err| format!("repo root canonicalizes: {err}"))
}

fn franken_node_bin() -> Result<PathBuf, String> {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        Ok(PathBuf::from(exe))
    } else {
        Ok(repo_root()?.join("target/debug/franken-node"))
    }
}

fn explain_json_value(
    value: &Value,
    kind: EvidenceArtifactKind,
    label: &str,
) -> Result<evidence_explain::EvidenceExplainReport, String> {
    let bytes = serde_json::to_vec(value).map_err(|err| format!("fixture serializes: {err}"))?;
    Ok(evidence_explain::explain_evidence_bytes(
        &bytes,
        label,
        kind,
        "verifier://spine",
    ))
}

fn issue_is_invalid_signature(issue: &prov::ChainIssue) -> bool {
    matches!(issue.code, VerificationErrorCode::InvalidSignature)
}

fn issue_is_chain_incomplete(issue: &prov::ChainIssue) -> bool {
    matches!(issue.code, VerificationErrorCode::ChainIncomplete)
}

#[test]
fn evidence_spine_fixture_matrix_declares_required_contract() -> TestResult {
    let matrix: Value = serde_json::from_str(FIXTURE_MATRIX_JSON)
        .map_err(|err| format!("fixture matrix must parse: {err}"))?;
    assert_eq!(
        matrix.get("schema_version").and_then(Value::as_str),
        Some("franken-node/evidence-verification-spine/v1")
    );
    assert_eq!(
        matrix.get("contract").and_then(Value::as_str),
        Some("producer-independent evidence verification")
    );

    let required_fields: BTreeSet<_> = [
        "content_digest",
        "signer_key_id",
        "signature_algorithm",
        "chain_parent_binding",
        "producer_independent_verdict",
    ]
    .into_iter()
    .collect();
    let actual_fields: BTreeSet<_> = matrix
        .get("required_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| "required_fields must be an array".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    for surface in [
        "provenance_attestation_chain",
        "node_universal_replay_capsule",
        "external_verifier_sdk_capsule",
        "vef_evidence_capsule",
    ] {
        let cases = artifact_cases_for(surface)?;
        assert!(
            cases.contains("positive"),
            "{surface} must declare a positive case"
        );
        assert!(
            cases.iter().any(|case| case.starts_with("negative_")),
            "{surface} must declare at least one negative case"
        );
    }

    Ok(())
}

#[test]
fn evidence_explain_contract_declares_debug_surface() -> TestResult {
    let contract: Value = serde_json::from_str(EVIDENCE_EXPLAIN_CONTRACT_JSON)
        .map_err(|err| format!("evidence explain contract must parse: {err}"))?;
    assert_eq!(
        contract.get("schema_version").and_then(Value::as_str),
        Some("franken-node/evidence-explain-contract/v1")
    );
    assert_eq!(
        contract.get("command").and_then(Value::as_str),
        Some("franken-node debug evidence")
    );
    let kinds: BTreeSet<_> = contract
        .get("supported_artifact_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "supported_artifact_kinds must be an array".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        kinds,
        [
            "node-replay-capsule",
            "provenance-attestation",
            "vef-evidence-capsule",
        ]
        .into_iter()
        .collect()
    );

    let fields: BTreeSet<_> = contract
        .get("required_step_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| "required_step_fields must be an array".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        fields,
        [
            "check_id",
            "input_artifact",
            "expected_value",
            "observed_value",
            "verdict",
            "recovery_hint",
        ]
        .into_iter()
        .collect()
    );

    Ok(())
}

#[test]
fn evidence_explain_api_inspects_three_spine_artifact_classes() -> TestResult {
    let node_report = explain_json_value(
        &serde_json::to_value(node_replay_capsule()).map_err(|err| err.to_string())?,
        EvidenceArtifactKind::Auto,
        "node-capsule.json",
    )?;
    assert!(node_report.is_pass(), "{node_report:#?}");
    assert_eq!(node_report.artifact_kind, "node-replay-capsule");
    assert!(
        node_report
            .steps
            .iter()
            .any(|step| step.check_id == "EVEX-NODE-REPLAY")
    );

    let attestation = base_provenance_attestation()?;
    let provenance_report = explain_json_value(
        &json!({
            "attestation": attestation,
            "policy": provenance_policy_for(&base_provenance_attestation()?),
            "now_epoch": 1_700_000_400_u64,
            "trace_id": "spine-explain-ok"
        }),
        EvidenceArtifactKind::Auto,
        "provenance.json",
    )?;
    assert!(provenance_report.is_pass(), "{provenance_report:#?}");
    assert_eq!(provenance_report.artifact_kind, "provenance-attestation");
    assert!(
        provenance_report
            .steps
            .iter()
            .any(|step| step.check_id == "EVEX-PROVENANCE-CHAIN")
    );

    let (capsule, context) = evidence_capsule_with_context()?;
    let vef_report = explain_json_value(
        &json!({
            "capsule": capsule,
            "context": context
        }),
        EvidenceArtifactKind::Auto,
        "vef-capsule.json",
    )?;
    assert!(vef_report.is_pass(), "{vef_report:#?}");
    assert_eq!(vef_report.artifact_kind, "vef-evidence-capsule");
    assert!(
        vef_report
            .steps
            .iter()
            .any(|step| step.check_id == "EVEX-VEF-VERIFY")
    );

    let rendered = evidence_explain::render_evidence_explain_human(&vef_report);
    assert!(rendered.contains("evidence_explain artifact=vef-capsule.json"));
    assert!(rendered.contains("check_id=EVEX-VEF-VERIFY"));
    assert!(!rendered.contains("marketing"));

    Ok(())
}

#[test]
fn evidence_explain_negative_fixtures_fail_closed() -> TestResult {
    let mut tampered = node_replay_capsule();
    tampered.payload.push_str("-tampered");
    let tampered_report = explain_json_value(
        &serde_json::to_value(&tampered).map_err(|err| err.to_string())?,
        EvidenceArtifactKind::NodeReplayCapsule,
        "node-tampered.json",
    )?;
    assert!(!tampered_report.is_pass());
    assert!(
        tampered_report
            .steps
            .iter()
            .any(|step| step.check_id == "EVEX-NODE-SIGNATURE" && step.verdict == "fail")
    );
    assert!(
        tampered_report
            .steps
            .iter()
            .all(|step| !step.observed_value.contains(&tampered.signature)),
        "raw signature must not be echoed in explain output"
    );

    let mut swapped_key = node_replay_capsule();
    swapped_key.manifest.metadata.insert(
        "ed25519_public_key".to_string(),
        hex::encode(VerifyingKey::from(&SigningKey::from_bytes(&[99_u8; 32])).to_bytes()),
    );
    let swapped_report = explain_json_value(
        &serde_json::to_value(&swapped_key).map_err(|err| err.to_string())?,
        EvidenceArtifactKind::NodeReplayCapsule,
        "node-swapped-key.json",
    )?;
    assert!(!swapped_report.is_pass());
    assert!(
        swapped_report
            .steps
            .iter()
            .any(|step| step.check_id == "EVEX-NODE-SIGNATURE" && step.verdict == "fail")
    );

    let mut missing_parent = node_replay_capsule();
    missing_parent.manifest.input_refs.pop();
    let missing_parent_report = explain_json_value(
        &serde_json::to_value(&missing_parent).map_err(|err| err.to_string())?,
        EvidenceArtifactKind::NodeReplayCapsule,
        "node-missing-parent.json",
    )?;
    assert!(!missing_parent_report.is_pass());
    assert!(
        missing_parent_report
            .steps
            .iter()
            .any(|step| step.check_id == "EVEX-NODE-REPLAY" && step.verdict == "fail")
    );

    let stale_attestation = base_provenance_attestation()?;
    let stale_report = explain_json_value(
        &json!({
            "attestation": stale_attestation.clone(),
            "policy": provenance_policy_for(&stale_attestation),
            "now_epoch": 1_800_000_000_u64,
            "trace_id": "spine-explain-stale"
        }),
        EvidenceArtifactKind::ProvenanceAttestation,
        "provenance-stale.json",
    )?;
    assert!(!stale_report.is_pass());
    assert!(
        stale_report
            .steps
            .iter()
            .any(|step| step.observed_value.contains("ChainStale"))
    );

    let mut producer_asserted = EvidenceCapsule::new("vef-spine-001".to_string(), 1_700_000_000);
    producer_asserted
        .add_evidence(VefEvidence {
            receipt_chain_commitment: "sha256:".to_string() + &"0".repeat(64),
            proof_id: "proof-spine-001".to_string(),
            proof_type: "receipt_chain".to_string(),
            window_start: 10,
            window_end: 20,
            verified: true,
            policy_constraints: vec!["no-network".to_string()],
        })
        .map_err(|err| err.to_string())?;
    producer_asserted.seal().map_err(|err| err.to_string())?;
    let (_, context) = evidence_capsule_with_context()?;
    let producer_report = explain_json_value(
        &json!({
            "capsule": producer_asserted,
            "context": context
        }),
        EvidenceArtifactKind::VefEvidenceCapsule,
        "vef-producer-asserted.json",
    )?;
    assert!(!producer_report.is_pass());
    assert!(
        producer_report
            .steps
            .iter()
            .any(|step| step.check_id == "EVEX-VEF-VERIFY" && step.verdict == "fail")
    );

    Ok(())
}

#[test]
fn evidence_explain_cli_json_and_malformed_path_contract() -> TestResult {
    let workspace = tempfile::tempdir().map_err(|err| err.to_string())?;
    let capsule_path = workspace.path().join("node-capsule.json");
    fs::write(
        &capsule_path,
        serde_json::to_string_pretty(&node_replay_capsule()).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;

    let output = Command::new(franken_node_bin()?)
        .current_dir(workspace.path())
        .args([
            "debug",
            "evidence",
            "--artifact",
            "node-capsule.json",
            "--kind",
            "node-replay-capsule",
            "--json",
        ])
        .output()
        .map_err(|err| format!("debug evidence command must run: {err}"))?;
    assert!(
        output.status.success(),
        "debug evidence should pass: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).map_err(|err| format!("stdout JSON: {err}"))?;
    assert_eq!(
        report.get("schema_version").and_then(Value::as_str),
        Some("franken-node/evidence-explain/v1")
    );
    assert_eq!(
        report.get("artifact_kind").and_then(Value::as_str),
        Some("node-replay-capsule")
    );
    assert_eq!(
        report.get("overall_verdict").and_then(Value::as_str),
        Some("pass")
    );

    let malformed = Command::new(franken_node_bin()?)
        .current_dir(workspace.path())
        .args(["debug", "evidence", "--artifact", "../bad.json", "--json"])
        .output()
        .map_err(|err| format!("malformed path command must run: {err}"))?;
    assert!(!malformed.status.success());
    let stderr = String::from_utf8_lossy(&malformed.stderr);
    assert!(
        stderr.contains("Path traversal") || stderr.contains("Invalid content path"),
        "stderr should explain path validation failure: {stderr}"
    );

    Ok(())
}

#[test]
fn provenance_surface_rejects_tamper_key_swap_parent_gap_and_producer_claim() -> TestResult {
    let attestation = base_provenance_attestation()?;
    let policy = provenance_policy_for(&attestation);
    let report = prov::verify_attestation_chain(&attestation, &policy, 1_700_000_400, "spine-ok");
    assert!(report.chain_valid);
    assert_eq!(
        report.provenance_level,
        ProvenanceLevel::Level3IndependentReproduced
    );

    let mut tampered = attestation.clone();
    tampered.output_hash = "sha256:tampered-output".to_string();
    let report = prov::verify_attestation_chain(&tampered, &policy, 1_700_000_400, "spine-tamper");
    assert!(
        !report.chain_valid,
        "content digest tamper must fail independently of producer claims"
    );
    assert!(report.issues.iter().any(|issue| {
        issue_is_invalid_signature(issue) && issue.message.contains("signed payload hash")
    }));

    let mut swapped_key = attestation.clone();
    let publisher_link = swapped_key
        .links
        .get_mut(0)
        .ok_or_else(|| "reference attestation must include a publisher link".to_string())?;
    publisher_link.signer_id = "publisher-key-swapped".to_string();
    let swapped_policy = provenance_policy_for(&swapped_key);
    let report = prov::verify_attestation_chain(
        &swapped_key,
        &swapped_policy,
        1_700_000_400,
        "spine-key-swap",
    );
    assert!(!report.chain_valid);
    assert!(report.issues.iter().any(issue_is_invalid_signature));

    let mut missing_parent = attestation.clone();
    missing_parent.links.pop();
    let report =
        prov::verify_attestation_chain(&missing_parent, &policy, 1_700_000_400, "spine-parent-gap");
    assert!(!report.chain_valid);
    assert!(report.issues.iter().any(issue_is_chain_incomplete));

    let mut producer_asserted = attestation.clone();
    producer_asserted
        .custom_claims
        .insert("verified".to_string(), "true".to_string());
    let report = prov::verify_attestation_chain(
        &producer_asserted,
        &policy,
        1_700_000_400,
        "spine-producer-claim",
    );
    assert!(
        !report.chain_valid,
        "producer-set verified=true must not bypass signed payload verification"
    );

    Ok(())
}

#[test]
fn replay_capsule_surfaces_share_signature_and_parent_binding_rejections() -> TestResult {
    let node = node_replay_capsule();
    let node_result = node_vsdk::replay_capsule(&node, "verifier://spine")
        .map_err(|err| format!("node replay capsule should pass: {err}"))?;
    assert_eq!(node_result.verdict, node_vsdk::CapsuleVerdict::Pass);

    let mut node_tampered = node.clone();
    node_tampered.payload.push_str("-tampered");
    assert!(matches!(
        node_vsdk::replay_capsule(&node_tampered, "verifier://spine"),
        Err(node_vsdk::VsdkError::SignatureMismatch { .. })
    ));

    let mut node_key_swapped = node.clone();
    node_key_swapped.manifest.metadata.insert(
        "ed25519_public_key".to_string(),
        hex::encode(VerifyingKey::from(&SigningKey::from_bytes(&[77_u8; 32])).to_bytes()),
    );
    assert!(matches!(
        node_vsdk::replay_capsule(&node_key_swapped, "verifier://spine"),
        Err(node_vsdk::VsdkError::SignatureMismatch { .. })
    ));

    let mut node_missing_parent = node.clone();
    node_missing_parent.manifest.input_refs.pop();
    assert!(matches!(
        node_vsdk::replay_capsule(&node_missing_parent, "verifier://spine"),
        Err(node_vsdk::VsdkError::SignatureMismatch { .. })
            | Err(node_vsdk::VsdkError::ManifestIncomplete(_))
    ));

    let mut node_producer_asserted = node.clone();
    node_producer_asserted
        .manifest
        .metadata
        .insert("verified".to_string(), "true".to_string());
    assert!(matches!(
        node_vsdk::replay_capsule(&node_producer_asserted, "verifier://spine"),
        Err(node_vsdk::VsdkError::SignatureMismatch { .. })
    ));

    let external = external_replay_capsule();
    let verifying_key = VerifyingKey::from(&external_signing_key());
    let external_result = external_capsule::replay(&verifying_key, &external, "verifier://spine")
        .map_err(|err| format!("external replay capsule should pass: {err}"))?;
    assert_eq!(
        external_result.verdict,
        external_capsule::CapsuleVerdict::Pass
    );

    let mut external_tampered = external.clone();
    external_tampered.payload.push_str("-tampered");
    assert!(matches!(
        external_capsule::replay(&verifying_key, &external_tampered, "verifier://spine"),
        Err(external_capsule::CapsuleError::Ed25519SignatureInvalid)
    ));

    let swapped_key = VerifyingKey::from(&SigningKey::from_bytes(&[88_u8; 32]));
    assert!(matches!(
        external_capsule::replay(&swapped_key, &external, "verifier://spine"),
        Err(external_capsule::CapsuleError::Ed25519SignatureInvalid)
    ));

    let mut external_missing_parent = external.clone();
    external_missing_parent.manifest.input_refs.pop();
    assert!(matches!(
        external_capsule::replay(&verifying_key, &external_missing_parent, "verifier://spine"),
        Err(external_capsule::CapsuleError::Ed25519SignatureInvalid)
            | Err(external_capsule::CapsuleError::ManifestIncomplete(_))
    ));

    let mut external_producer_asserted = external.clone();
    external_producer_asserted
        .manifest
        .metadata
        .insert("verified".to_string(), "true".to_string());
    assert!(matches!(
        external_capsule::replay(
            &verifying_key,
            &external_producer_asserted,
            "verifier://spine"
        ),
        Err(external_capsule::CapsuleError::Ed25519SignatureInvalid)
    ));

    Ok(())
}

#[test]
fn vef_evidence_capsule_ignores_producer_verified_flag_without_context_and_commitment() -> TestResult
{
    let (capsule, context) = evidence_capsule_with_context()?;
    let result = capsule.verify_all_with_context(&context);
    assert!(result.valid);
    assert_eq!(result.checked, 1);
    assert_eq!(result.passed, 1);

    let result = capsule.verify_all();
    assert!(!result.valid);
    assert!(
        result
            .failures
            .iter()
            .any(|failure| failure.contains("missing verification context"))
    );

    let mut tampered = EvidenceCapsule::new("vef-spine-001".to_string(), 1_700_000_000);
    let evidence = VefEvidence {
        receipt_chain_commitment: "sha256:".to_string() + &"0".repeat(64),
        proof_id: "proof-spine-001".to_string(),
        proof_type: "receipt_chain".to_string(),
        window_start: 10,
        window_end: 20,
        verified: true,
        policy_constraints: vec!["no-network".to_string()],
    };
    tampered
        .add_evidence(evidence)
        .map_err(|err| format!("tampered evidence must still add before verification: {err}"))?;
    tampered
        .seal()
        .map_err(|err| format!("tampered evidence capsule must seal: {err}"))?;

    let result = tampered.verify_all_with_context(&context);
    assert!(
        !result.valid,
        "producer-set verified=true must not override commitment/context checks"
    );
    assert!(result.failures.iter().any(|failure| {
        failure.contains("commitment mismatch") || failure.contains("untrusted commitment")
    }));

    Ok(())
}
