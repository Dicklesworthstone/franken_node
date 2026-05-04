use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::{
    artifact_signing::{self, KeyId, KeyRing},
    extension_registry::{
        AdmissionKernel, RegistrationRequest, RegistryConfig, SignedExtensionRegistry,
        VersionEntry, canonical_registration_manifest_bytes,
    },
    provenance::{
        self as prov, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole,
        ProvenanceAttestation,
    },
    transparency_verifier as tv,
};
use serde::Deserialize;
use uuid::Uuid;

const VECTORS_JSON: &str =
    include_str!("fixtures/supply_chain_registry_attestation_receipt_vectors.json");
const VECTOR_SCHEMA_VERSION: &str =
    "franken-node/supply-chain-registry-attestation-receipt-conformance/v1";
const FIXED_NOW_EPOCH: u64 = 1_700_000_500;
const FIXED_REGISTERED_AT: &str = "2026-04-26T20:00:00Z";
const FIXED_SIGNED_AT: &str = "2026-04-26T20:01:00Z";
const EXTENSION_NAME: &str = "supply-chain-attestation-conformance";
const PUBLISHER_ID: &str = "pub-001";
const TRACE_PREFIX: &str = "supply-chain-registry-attestation-receipt";

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct VectorSet {
    schema_version: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<ReceiptVector>,
}

#[derive(Debug, Deserialize)]
struct CoverageRow {
    requirement_id: String,
    level: String,
    contract: String,
    tested: bool,
}

#[derive(Debug, Deserialize)]
struct ReceiptVector {
    name: String,
    requirement_id: String,
    level: String,
    mutation: Mutation,
    transparency_required: bool,
    expected: ExpectedOutcome,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mutation {
    Valid,
    TamperedSignature,
    RevokedPublisherLink,
    MissingTransparencyProof,
}

#[derive(Debug, Deserialize)]
struct ExpectedOutcome {
    admitted: bool,
    error_code: Option<String>,
    detail: String,
    manifest_digest: String,
    provenance_level: Option<String>,
    checked_fields: Vec<String>,
    remediation_contains: Option<String>,
    audit_events: Vec<String>,
    extension_registered: bool,
}

fn load_vectors() -> Result<VectorSet, String> {
    serde_json::from_str(VECTORS_JSON)
        .map_err(|err| format!("registry attestation receipt vectors must parse: {err}"))
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42_u8; 32])
}

fn publisher_key_id() -> String {
    KeyId::from_verifying_key(&signing_key().verifying_key()).to_string()
}

fn provenance_signing_keys() -> BTreeMap<String, SigningKey> {
    let key = signing_key();
    BTreeMap::from([(
        PUBLISHER_ID.to_string(),
        SigningKey::from_bytes(&key.to_bytes()),
    )])
}

fn trace_id(name: &str) -> String {
    format!("{TRACE_PREFIX}-{name}")
}

fn fixed_version() -> VersionEntry {
    VersionEntry {
        version: "1.0.0".to_string(),
        parent_version: None,
        content_hash: "c".repeat(64),
        registered_at: FIXED_REGISTERED_AT.to_string(),
        compatible_with: vec!["franken-node>=1.0.0".to_string()],
    }
}

fn base_provenance(now_epoch: u64) -> Result<ProvenanceAttestation, String> {
    let mut attestation = ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://github.com/example/attestation-conformance".to_string(),
        build_system_identifier: "github-actions".to_string(),
        builder_identity: PUBLISHER_ID.to_string(),
        builder_version: "1.0.0".to_string(),
        vcs_commit_sha: "abc123def456".to_string(),
        build_timestamp_epoch: now_epoch.saturating_sub(60),
        reproducibility_hash: "d".repeat(64),
        input_hash: "e".repeat(64),
        output_hash: "f".repeat(64),
        slsa_level_claim: 2,
        envelope_format: AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
        links: vec![AttestationLink {
            role: ChainLinkRole::Publisher,
            signer_id: PUBLISHER_ID.to_string(),
            signer_version: "1.0.0".to_string(),
            signature: String::new(),
            signed_payload_hash: "f".repeat(64),
            issued_at_epoch: now_epoch.saturating_sub(60),
            expires_at_epoch: now_epoch.saturating_add(86_400),
            revoked: false,
        }],
        custom_claims: std::collections::BTreeMap::new(),
    };
    prov::sign_links_in_place(&mut attestation, &provenance_signing_keys())
        .map_err(|err| format!("conformance provenance should sign: {err}"))?;
    Ok(attestation)
}

fn base_request(now_epoch: u64) -> Result<RegistrationRequest, String> {
    let signing_key = signing_key();
    let initial_version = fixed_version();
    let tags = vec!["attestation".to_string(), "conformance".to_string()];
    let manifest_bytes = canonical_registration_manifest_bytes(
        EXTENSION_NAME,
        PUBLISHER_ID,
        &initial_version,
        &tags,
    )
    .map_err(|err| format!("canonical registration manifest: {err}"))?;

    Ok(RegistrationRequest {
        name: EXTENSION_NAME.to_string(),
        description: "Conformance harness request".to_string(),
        publisher_id: PUBLISHER_ID.to_string(),
        signature: frankenengine_node::supply_chain::extension_registry::ExtensionSignature {
            key_id: publisher_key_id(),
            algorithm: "ed25519".to_string(),
            signature_bytes: artifact_signing::sign_bytes(&signing_key, &manifest_bytes),
            signed_at: FIXED_SIGNED_AT.to_string(),
        },
        provenance: base_provenance(now_epoch)?,
        initial_version,
        tags,
        manifest_bytes,
        transparency_proof: None,
    })
}

fn apply_mutation(request: &mut RegistrationRequest, mutation: Mutation) {
    match mutation {
        Mutation::Valid | Mutation::MissingTransparencyProof => {}
        Mutation::TamperedSignature => {
            request.signature.signature_bytes = vec![0xAA; 64];
        }
        Mutation::RevokedPublisherLink => {
            if let Some(link) = request.provenance.links.first_mut() {
                link.revoked = true;
            }
        }
    }
}

fn registry(transparency_required: bool) -> SignedExtensionRegistry {
    let signing_key = signing_key();
    let mut key_ring = KeyRing::new();
    key_ring.add_key(signing_key.verifying_key());
    let mut provenance_policy = prov::VerificationPolicy::development_profile();
    provenance_policy.add_trusted_signer_key(PUBLISHER_ID, &signing_key.verifying_key());

    let mut transparency_policy = tv::TransparencyPolicy {
        required: false,
        pinned_roots: Vec::new(),
    };
    transparency_policy.required = transparency_required;

    SignedExtensionRegistry::new(
        RegistryConfig::default(),
        AdmissionKernel {
            key_ring,
            provenance_policy,
            transparency_policy,
        },
    )
}

fn audit_event_codes(registry: &SignedExtensionRegistry) -> Vec<String> {
    registry
        .audit_log()
        .iter()
        .map(|record| record.event_code.clone())
        .collect()
}

fn assert_hex_digest(digest: &str, vector_name: &str) -> TestResult {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{vector_name}: manifest_digest must be a 64-char lowercase hex digest, got `{digest}`"
        ));
    }
    Ok(())
}

fn execute_vector(vector: &ReceiptVector) -> TestResult {
    let mut request = base_request(FIXED_NOW_EPOCH)?;
    apply_mutation(&mut request, vector.mutation);

    let trace = trace_id(&vector.name);
    let mut registry = registry(vector.transparency_required);
    let result = registry.register(request.clone(), &trace, FIXED_NOW_EPOCH);
    let receipt = registry.admission_receipts().last().ok_or_else(|| {
        format!(
            "{}: registry did not persist an admission receipt",
            vector.name
        )
    })?;

    let mut replay_registry = registry(vector.transparency_required);
    let replay_result = replay_registry.register(request, &trace, FIXED_NOW_EPOCH);
    let replay_receipt = replay_registry.admission_receipts().last().ok_or_else(|| {
        format!(
            "{}: replay registry did not persist an admission receipt",
            vector.name
        )
    })?;

    if result.success != replay_result.success {
        return Err(format!(
            "{}: repeated registration changed success outcome ({} vs {})",
            vector.name, result.success, replay_result.success
        ));
    }
    if receipt.manifest_digest != replay_receipt.manifest_digest {
        return Err(format!(
            "{}: repeated registration changed manifest digest ({} vs {})",
            vector.name, receipt.manifest_digest, replay_receipt.manifest_digest
        ));
    }

    if result.success != vector.expected.admitted {
        return Err(format!(
            "{}: result.success mismatch: expected {} got {}",
            vector.name, vector.expected.admitted, result.success
        ));
    }
    if receipt.admitted != vector.expected.admitted {
        return Err(format!(
            "{}: receipt.admitted mismatch: expected {} got {}",
            vector.name, vector.expected.admitted, receipt.admitted
        ));
    }
    if result.error_code.as_ref() != vector.expected.error_code.as_ref() {
        return Err(format!(
            "{}: error_code mismatch: expected {:?} got {:?}",
            vector.name, vector.expected.error_code, result.error_code
        ));
    }
    if result.detail != vector.expected.detail {
        return Err(format!(
            "{}: detail mismatch: expected `{}` got `{}`",
            vector.name, vector.expected.detail, result.detail
        ));
    }
    if receipt.manifest_digest != vector.expected.manifest_digest {
        return Err(format!(
            "{}: manifest_digest drifted from golden vector: expected `{}` got `{}`",
            vector.name, vector.expected.manifest_digest, receipt.manifest_digest
        ));
    }
    assert_hex_digest(&receipt.manifest_digest, &vector.name)?;

    if receipt.provenance_level.as_ref() != vector.expected.provenance_level.as_ref() {
        return Err(format!(
            "{}: provenance_level mismatch: expected {:?} got {:?}",
            vector.name, vector.expected.provenance_level, receipt.provenance_level
        ));
    }

    if receipt.extension_name != EXTENSION_NAME {
        return Err(format!(
            "{}: receipt extension_name mismatch: expected `{}` got `{}`",
            vector.name, EXTENSION_NAME, receipt.extension_name
        ));
    }
    if receipt.publisher_key_id != publisher_key_id() {
        return Err(format!(
            "{}: publisher_key_id mismatch: expected `{}` got `{}`",
            vector.name,
            publisher_key_id(),
            receipt.publisher_key_id
        ));
    }
    if receipt.trace_id != trace {
        return Err(format!(
            "{}: trace_id mismatch: expected `{}` got `{}`",
            vector.name, trace, receipt.trace_id
        ));
    }

    Uuid::parse_str(&receipt.receipt_id)
        .map_err(|err| format!("{}: receipt_id is not a UUID: {err}", vector.name))?;
    DateTime::parse_from_rfc3339(&receipt.timestamp).map_err(|err| {
        format!(
            "{}: receipt timestamp must be RFC3339, got `{}`: {err}",
            vector.name, receipt.timestamp
        )
    })?;

    let witness = receipt.witness.as_ref();
    let checked_fields = witness
        .map(|value| value.checked_fields.clone())
        .unwrap_or_default();
    if checked_fields != vector.expected.checked_fields {
        return Err(format!(
            "{}: checked_fields mismatch: expected {:?} got {:?}",
            vector.name, vector.expected.checked_fields, checked_fields
        ));
    }

    match (&vector.expected.remediation_contains, witness) {
        (Some(expected_fragment), Some(actual_witness)) => {
            if !actual_witness.remediation.contains(expected_fragment) {
                return Err(format!(
                    "{}: witness remediation `{}` did not contain `{}`",
                    vector.name, actual_witness.remediation, expected_fragment
                ));
            }
        }
        (Some(expected_fragment), None) => {
            return Err(format!(
                "{}: expected remediation containing `{expected_fragment}` but witness was absent",
                vector.name
            ));
        }
        (None, Some(actual_witness)) => {
            return Err(format!(
                "{}: unexpected negative witness for admitted receipt: {:?}",
                vector.name, actual_witness
            ));
        }
        (None, None) => {}
    }

    let audit_events = audit_event_codes(&registry);
    if audit_events != vector.expected.audit_events {
        return Err(format!(
            "{}: audit event sequence mismatch: expected {:?} got {:?}",
            vector.name, vector.expected.audit_events, audit_events
        ));
    }

    if vector.expected.extension_registered {
        if result.extension_id.is_none() {
            return Err(format!(
                "{}: expected extension_id for admitted registration",
                vector.name
            ));
        }
        if registry.list(None).len() != 1 {
            return Err(format!(
                "{}: expected one registered extension, found {}",
                vector.name,
                registry.list(None).len()
            ));
        }
        if registry.query_by_name(EXTENSION_NAME).is_none() {
            return Err(format!(
                "{}: admitted extension was not queryable by name",
                vector.name
            ));
        }
    } else {
        if result.extension_id.is_some() {
            return Err(format!(
                "{}: rejected registration unexpectedly returned an extension_id",
                vector.name
            ));
        }
        if !registry.list(None).is_empty() {
            return Err(format!(
                "{}: rejected registration should not insert an extension",
                vector.name
            ));
        }
    }

    Ok(())
}

#[test]
fn supply_chain_registry_attestation_receipt_vectors_cover_required_contract() -> TestResult {
    let vectors = load_vectors()?;
    if vectors.schema_version != VECTOR_SCHEMA_VERSION {
        return Err(format!(
            "schema_version mismatch: expected `{VECTOR_SCHEMA_VERSION}` got `{}`",
            vectors.schema_version
        ));
    }
    if vectors.coverage.len() != 4 {
        return Err(format!(
            "expected 4 coverage rows for the attestation receipt contract, found {}",
            vectors.coverage.len()
        ));
    }

    let mut coverage_ids = BTreeSet::new();
    for row in &vectors.coverage {
        if row.level != "MUST" {
            return Err(format!(
                "coverage row `{}` must be MUST-level, got `{}`",
                row.requirement_id, row.level
            ));
        }
        if row.contract.trim().is_empty() {
            return Err(format!(
                "coverage row `{}` must document a contract reference",
                row.requirement_id
            ));
        }
        if !row.tested {
            return Err(format!(
                "coverage row `{}` is marked untested",
                row.requirement_id
            ));
        }
        if !coverage_ids.insert(row.requirement_id.clone()) {
            return Err(format!(
                "duplicate coverage requirement_id `{}`",
                row.requirement_id
            ));
        }
    }

    let mut vector_names = BTreeSet::new();
    for vector in &vectors.vectors {
        if vector.level != "MUST" {
            return Err(format!(
                "vector `{}` must be MUST-level, got `{}`",
                vector.name, vector.level
            ));
        }
        if !coverage_ids.contains(&vector.requirement_id) {
            return Err(format!(
                "vector `{}` references unknown requirement_id `{}`",
                vector.name, vector.requirement_id
            ));
        }
        if !vector_names.insert(vector.name.clone()) {
            return Err(format!("duplicate vector name `{}`", vector.name));
        }
    }

    Ok(())
}

#[test]
fn supply_chain_registry_attestation_receipt_conformance() -> TestResult {
    let vectors = load_vectors()?;
    let mut failures = Vec::new();

    for vector in &vectors.vectors {
        if let Err(err) = execute_vector(vector) {
            failures.push(err);
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}
