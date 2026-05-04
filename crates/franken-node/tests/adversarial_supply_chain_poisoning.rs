use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use frankenengine_node::{
    capacity_defaults,
    supply_chain::{
        artifact_signing::{self, KeyId, KeyRing},
        extension_registry::{
            AdmissionKernel, ExtensionSignature, RegistrationRequest, RegistryConfig,
            RegistryResult, SignedExtensionRegistry, VersionEntry,
            canonical_registration_manifest_bytes, event_codes,
        },
        manifest::{
            AttestationRef, BehavioralProfile, CertificationLevel, MANIFEST_SCHEMA_VERSION,
            MAX_DECLARED_NETWORK_ZONES, MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES,
            MAX_MANIFEST_CAPABILITIES, MAX_MANIFEST_FIELD_BYTES, MAX_REPRODUCIBILITY_MARKERS,
            ManifestSchemaError, ManifestSignature, PackageIdentity, ProvenanceEnvelope, RiskTier,
            SignatureScheme, SignedExtensionManifest, ThresholdSignaturePolicy, TrustMetadata,
            validate_signed_manifest,
        },
        provenance::{
            self as prov, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole,
            ProvenanceAttestation, VerificationErrorCode, VerificationPolicy,
        },
        transparency_verifier::TransparencyPolicy,
    },
};

const NOW_EPOCH: u64 = 1_777_000_000;
const SIGNED_AT: &str = "2026-04-26T00:00:00Z";
const TRACE_PREFIX: &str = "trace-adversarial-supply-chain";
const ED25519_SIGNATURE_BYTES: usize = 64;

fn legitimate_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[41_u8; 32])
}

fn attacker_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[99_u8; 32])
}

fn registry_with_trusted_key(verifying_key: VerifyingKey) -> SignedExtensionRegistry {
    registry_with_trusted_key_and_cap(verifying_key, usize::MAX)
}

fn registry_with_trusted_key_and_cap(
    verifying_key: VerifyingKey,
    max_extensions: usize,
) -> SignedExtensionRegistry {
    let mut key_ring = KeyRing::new();
    key_ring.add_key(verifying_key);
    let mut provenance_policy = VerificationPolicy::development_profile();
    provenance_policy.add_trusted_signer_key("pub-001", &verifying_key);
    let mut config = RegistryConfig::default();
    config.max_extensions = max_extensions;
    SignedExtensionRegistry::new(
        config,
        AdmissionKernel {
            key_ring,
            provenance_policy,
            transparency_policy: TransparencyPolicy {
                required: false,
                pinned_roots: vec![],
            },
        },
    )
}

fn valid_version() -> VersionEntry {
    VersionEntry {
        version: "1.2.3".to_string(),
        parent_version: None,
        content_hash: "c".repeat(64),
        registered_at: SIGNED_AT.to_string(),
        compatible_with: vec!["1.x".to_string()],
    }
}

fn provenance_signing_keys(signing_key: &SigningKey) -> BTreeMap<String, SigningKey> {
    BTreeMap::from([(
        "pub-001".to_string(),
        SigningKey::from_bytes(&signing_key.to_bytes()),
    )])
}

fn valid_provenance(signing_key: &SigningKey, now_epoch: u64) -> ProvenanceAttestation {
    let mut attestation = ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://github.com/acme/supply-chain-target".to_string(),
        build_system_identifier: "github-actions".to_string(),
        builder_identity: "pub-001".to_string(),
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
            signer_id: "pub-001".to_string(),
            signer_version: "1.0.0".to_string(),
            signature: String::new(),
            signed_payload_hash: "f".repeat(64),
            issued_at_epoch: now_epoch.saturating_sub(60),
            expires_at_epoch: now_epoch.saturating_add(86_400),
            revoked: false,
        }],
        custom_claims: BTreeMap::from([(
            "dependency_graph".to_string(),
            "npm:trusted-core@1.0.0".to_string(),
        )]),
    };
    prov::sign_links_in_place(&mut attestation, &provenance_signing_keys(signing_key))
        .expect("baseline provenance should sign");
    attestation
}

fn valid_request(name: &str, signing_key: &SigningKey, now_epoch: u64) -> RegistrationRequest {
    let initial_version = valid_version();
    let tags = vec!["stable".to_string(), "supply-chain-attested".to_string()];
    let manifest_bytes =
        canonical_registration_manifest_bytes(name, "pub-001", &initial_version, &tags)
            .expect("registration manifest should canonicalize");

    RegistrationRequest {
        name: name.to_string(),
        description: format!("Adversarial harness fixture: {name}"),
        publisher_id: "pub-001".to_string(),
        signature: ExtensionSignature {
            key_id: KeyId::from_verifying_key(&signing_key.verifying_key()).to_string(),
            algorithm: "ed25519".to_string(),
            signature_bytes: artifact_signing::sign_bytes(signing_key, &manifest_bytes),
            signed_at: SIGNED_AT.to_string(),
        },
        provenance: valid_provenance(signing_key, now_epoch),
        initial_version,
        tags,
        manifest_bytes,
        transparency_proof: None,
    }
}

fn manifest_cap(name: &str) -> frankenengine_extension_host::Capability {
    serde_json::from_value(serde_json::json!(name)).expect("manifest capability should parse")
}

fn valid_signed_manifest() -> SignedExtensionManifest {
    SignedExtensionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        package: PackageIdentity {
            name: "adversarial-extension".to_string(),
            version: "1.2.3".to_string(),
            publisher: "publisher@example.com".to_string(),
            author: "author@example.com".to_string(),
        },
        entrypoint: "dist/main.js".to_string(),
        capabilities: vec![manifest_cap("fs_read"), manifest_cap("net_client")],
        behavioral_profile: BehavioralProfile {
            risk_tier: RiskTier::Medium,
            summary: "Adversarial supply-chain manifest fixture".to_string(),
            declared_network_zones: vec!["prod-us-east".to_string()],
        },
        minimum_runtime_version: "0.1.0".to_string(),
        provenance: ProvenanceEnvelope {
            build_system: "github-actions".to_string(),
            source_repository: "https://example.com/acme/extensions".to_string(),
            source_revision: "abcdef1234567890".to_string(),
            reproducibility_markers: vec!["reproducible-build=true".to_string()],
            attestation_chain: vec![AttestationRef {
                id: "att-01".to_string(),
                attestation_type: "slsa".to_string(),
                digest: "sha256:0123456789abcdef".to_string(),
            }],
        },
        trust: TrustMetadata {
            certification_level: CertificationLevel::Verified,
            revocation_status_pointer: "revocation://extensions/adversarial".to_string(),
            trust_card_reference: "trust-card://adversarial@1.2.3".to_string(),
        },
        signature: ManifestSignature {
            scheme: SignatureScheme::ThresholdEd25519,
            publisher_key_id: "key-publisher-01".to_string(),
            signature: "QUJDREU=".to_string(),
            threshold: Some(ThresholdSignaturePolicy {
                threshold: 2,
                total_signers: 3,
                signer_key_ids: vec![
                    "key-a".to_string(),
                    "key-b".to_string(),
                    "key-c".to_string(),
                ],
            }),
            signed_at: SIGNED_AT.to_string(),
        },
    }
}

fn assert_fail_closed(
    registry: &SignedExtensionRegistry,
    result: &RegistryResult,
    expected_code: &str,
) {
    assert!(!result.success, "poisoned registration must fail closed");
    assert_eq!(result.error_code.as_deref(), Some(expected_code));
    assert!(
        registry.list(None).is_empty(),
        "poisoned request must not be admitted into the registry"
    );

    let receipt = registry
        .admission_receipts()
        .last()
        .expect("failed admissions must emit a receipt");
    assert!(!receipt.admitted, "receipt must record a rejection");
    let witness = receipt
        .witness
        .as_ref()
        .expect("failed admissions must include a negative witness");
    assert_eq!(witness.rejection_code, expected_code);
}

fn assert_rejected_before_admission(
    registry: &SignedExtensionRegistry,
    result: &RegistryResult,
    expected_code: &str,
    expected_field: &str,
) {
    assert!(!result.success, "oversized registration must fail closed");
    assert_eq!(result.error_code.as_deref(), Some(expected_code));
    assert!(
        registry.list(None).is_empty(),
        "oversized request must not be admitted into the registry"
    );
    assert!(
        registry.admission_receipts().is_empty(),
        "oversized request must fail before admission hashing or signature verification"
    );
    let audit = registry
        .audit_log()
        .last()
        .expect("pre-admission rejection must emit an audit record");
    assert_eq!(audit.event_code, expected_code);
    assert_eq!(audit.details["field"], expected_field);
}

fn assert_manifest_collection_too_large(
    error: ManifestSchemaError,
    expected_field: &str,
    expected_max: usize,
) {
    assert_eq!(error.code(), "EMS_COLLECTION_TOO_LARGE");
    assert!(matches!(
        error,
        ManifestSchemaError::CollectionTooLarge { ref field, max, .. }
            if field == expected_field && max == expected_max
    ));
}

fn oversized_compatibility_markers() -> Vec<String> {
    (0..33).map(|index| format!("runtime-{index}")).collect()
}

#[test]
fn adversarial_supply_chain_baseline_request_is_admitted() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());

    let result = registry.register(
        valid_request("supply-chain-target", &signing_key, NOW_EPOCH),
        &format!("{TRACE_PREFIX}-baseline"),
        NOW_EPOCH,
    );

    assert!(result.success, "baseline request must be admitted");
    assert_eq!(registry.list(None).len(), 1);
}

#[test]
fn adversarial_supply_chain_rejects_new_extension_when_registry_at_capacity() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key_and_cap(signing_key.verifying_key(), 1);

    let admitted = registry.register(
        valid_request("supply-chain-existing", &signing_key, NOW_EPOCH),
        &format!("{TRACE_PREFIX}-capacity-setup"),
        NOW_EPOCH,
    );
    assert!(admitted.success, "setup request must be admitted");

    let rejected = registry.register(
        valid_request("supply-chain-overflow", &signing_key, NOW_EPOCH),
        &format!("{TRACE_PREFIX}-capacity-overflow"),
        NOW_EPOCH,
    );

    assert!(!rejected.success, "capacity overflow must fail closed");
    assert_eq!(
        rejected.error_code.as_deref(),
        Some(event_codes::SER_ERR_REGISTRY_CAPACITY)
    );
    assert!(rejected.detail.contains("registry is at capacity"));
    assert_eq!(
        registry.list(None).len(),
        1,
        "capacity rejection must not grow the registry"
    );
    assert_eq!(registry.admission_receipts().len(), 2);
    assert!(
        registry
            .admission_receipts()
            .iter()
            .all(|receipt| receipt.admitted)
    );

    let audit = registry
        .audit_log()
        .last()
        .expect("capacity rejection must emit an audit record");
    assert_eq!(audit.event_code, event_codes::SER_ERR_REGISTRY_CAPACITY);
    assert_eq!(audit.details["name"], "supply-chain-overflow");
    assert_eq!(audit.details["current"].as_u64(), Some(1));
    assert_eq!(audit.details["max_allowed"].as_u64(), Some(1));
}

#[test]
fn adversarial_supply_chain_duplicate_name_precedes_registry_capacity_error() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key_and_cap(signing_key.verifying_key(), 1);

    let admitted = registry.register(
        valid_request("supply-chain-existing", &signing_key, NOW_EPOCH),
        &format!("{TRACE_PREFIX}-duplicate-capacity-setup"),
        NOW_EPOCH,
    );
    assert!(admitted.success, "setup request must be admitted");

    let duplicate = registry.register(
        valid_request("supply-chain-existing", &signing_key, NOW_EPOCH),
        &format!("{TRACE_PREFIX}-duplicate-at-capacity"),
        NOW_EPOCH,
    );

    assert!(!duplicate.success, "duplicate name must fail closed");
    assert_eq!(
        duplicate.error_code.as_deref(),
        Some(event_codes::SER_ERR_DUPLICATE_NAME)
    );
    assert_eq!(
        registry.list(None).len(),
        1,
        "duplicate rejection must not grow the registry"
    );
    assert_eq!(registry.admission_receipts().len(), 2);
    let audit = registry
        .audit_log()
        .last()
        .expect("duplicate rejection must emit an audit record");
    assert_eq!(audit.event_code, event_codes::SER_ERR_DUPLICATE_NAME);
    assert_eq!(audit.details["name"], "supply-chain-existing");
}

#[test]
fn adversarial_supply_chain_rejects_oversized_signature_before_admission() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);
    request.signature.signature_bytes = vec![0xAA; ED25519_SIGNATURE_BYTES + 1];

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-oversized-signature"),
        NOW_EPOCH,
    );

    assert_rejected_before_admission(
        &registry,
        &result,
        event_codes::SER_ERR_INVALID_SIGNATURE,
        "signature.signature_bytes",
    );
    assert!(result.detail.contains("exactly 64 bytes"));
}

#[test]
fn adversarial_supply_chain_rejects_oversized_manifest_before_admission() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);
    request.manifest_bytes = vec![b'a'; capacity_defaults::base::LARGE + 1];

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-oversized-manifest"),
        NOW_EPOCH,
    );

    assert_rejected_before_admission(
        &registry,
        &result,
        event_codes::SER_ERR_INVALID_INPUT,
        "manifest_bytes",
    );
    assert!(result.detail.contains("Manifest bytes too large"));
}

#[test]
fn adversarial_supply_chain_rejects_oversized_initial_version_before_admission() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);
    request.initial_version.version = "1".repeat(129);

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-oversized-initial-version"),
        NOW_EPOCH,
    );

    assert_rejected_before_admission(
        &registry,
        &result,
        event_codes::SER_ERR_INVALID_INPUT,
        "initial_version.version",
    );
    assert!(result.detail.contains("Version too long"));
}

#[test]
fn adversarial_supply_chain_rejects_invalid_initial_version_hash_before_admission() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);
    request.initial_version.content_hash = "g".repeat(64);

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-invalid-initial-version-hash"),
        NOW_EPOCH,
    );

    assert_rejected_before_admission(
        &registry,
        &result,
        event_codes::SER_ERR_INVALID_INPUT,
        "initial_version.content_hash",
    );
    assert!(result.detail.contains("64 hex characters"));
}

#[test]
fn adversarial_supply_chain_rejects_oversized_initial_compatibility_before_admission() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);
    request.initial_version.compatible_with = oversized_compatibility_markers();

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-oversized-initial-compatibility"),
        NOW_EPOCH,
    );

    assert_rejected_before_admission(
        &registry,
        &result,
        event_codes::SER_ERR_INVALID_INPUT,
        "initial_version.compatible_with",
    );
    assert!(result.detail.contains("Too many compatibility markers"));
}

#[test]
fn adversarial_supply_chain_rejects_oversized_added_version_compatibility_without_lineage_growth() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());

    let result = registry.register(
        valid_request("supply-chain-target", &signing_key, NOW_EPOCH),
        &format!("{TRACE_PREFIX}-add-version-setup"),
        NOW_EPOCH,
    );
    assert!(result.success, "baseline registration must succeed");
    let extension_id = result.extension_id.expect("extension id");

    let mut version = valid_version();
    version.version = "1.2.4".to_string();
    version.parent_version = Some("1.2.3".to_string());
    version.compatible_with = oversized_compatibility_markers();

    let result = registry.add_version(
        &extension_id,
        version,
        &format!("{TRACE_PREFIX}-oversized-added-compatibility"),
    );

    assert!(!result.success, "oversized version metadata must fail");
    assert_eq!(
        result.error_code.as_deref(),
        Some(event_codes::SER_ERR_INVALID_INPUT)
    );
    assert!(result.detail.contains("Too many compatibility markers"));
    assert_eq!(
        registry
            .version_lineage(&extension_id)
            .expect("extension remains registered")
            .len(),
        1,
        "rejected version metadata must not grow lineage"
    );
    let audit = registry
        .audit_log()
        .last()
        .expect("append rejection must emit an audit record");
    assert_eq!(audit.event_code, event_codes::SER_ERR_INVALID_INPUT);
    assert_eq!(audit.details["field"], "version.compatible_with");
}

#[test]
fn adversarial_signed_manifest_rejects_oversized_provenance_vectors_before_projection() {
    let mut manifest = valid_signed_manifest();
    manifest.provenance.attestation_chain = vec![
        AttestationRef {
            id: "att-oversized".to_string(),
            attestation_type: "slsa".to_string(),
            digest: "sha256:0123456789abcdef".to_string(),
        };
        MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES + 1
    ];

    let error = validate_signed_manifest(&manifest)
        .expect_err("oversized attestation chain must fail closed");

    assert_manifest_collection_too_large(
        error,
        "provenance.attestation_chain",
        MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES,
    );

    let mut manifest = valid_signed_manifest();
    manifest.provenance.reproducibility_markers = (0..=MAX_REPRODUCIBILITY_MARKERS)
        .map(|idx| format!("marker-{idx}"))
        .collect();

    let error = validate_signed_manifest(&manifest)
        .expect_err("oversized reproducibility markers must fail closed");

    assert_manifest_collection_too_large(
        error,
        "provenance.reproducibility_markers",
        MAX_REPRODUCIBILITY_MARKERS,
    );
}

#[test]
fn adversarial_signed_manifest_rejects_oversized_profile_and_capability_vectors() {
    let mut manifest = valid_signed_manifest();
    manifest.behavioral_profile.declared_network_zones = (0..=MAX_DECLARED_NETWORK_ZONES)
        .map(|idx| format!("zone-{idx}"))
        .collect();

    let error = validate_signed_manifest(&manifest).expect_err("oversized zones must fail closed");

    assert_manifest_collection_too_large(
        error,
        "behavioral_profile.declared_network_zones",
        MAX_DECLARED_NETWORK_ZONES,
    );

    let mut manifest = valid_signed_manifest();
    manifest.capabilities = vec![manifest_cap("fs_read"); MAX_MANIFEST_CAPABILITIES + 1];

    let error =
        validate_signed_manifest(&manifest).expect_err("oversized capabilities must fail closed");

    assert_manifest_collection_too_large(error, "capabilities", MAX_MANIFEST_CAPABILITIES);
}

#[test]
fn adversarial_signed_manifest_rejects_control_chars_and_huge_vector_fields() {
    let mut manifest = valid_signed_manifest();
    manifest.behavioral_profile.declared_network_zones = vec!["prod\nshadow".to_string()];

    let error = validate_signed_manifest(&manifest).expect_err("control chars must fail closed");

    assert_eq!(error.code(), "EMS_INVALID_FIELD");
    assert!(matches!(
        error,
        ManifestSchemaError::InvalidField { ref field, .. }
            if field == "behavioral_profile.declared_network_zones[0]"
    ));

    let mut manifest = valid_signed_manifest();
    manifest.provenance.reproducibility_markers = vec!["m".repeat(MAX_MANIFEST_FIELD_BYTES + 1)];

    let error = validate_signed_manifest(&manifest).expect_err("huge marker must fail closed");

    assert_eq!(error.code(), "EMS_INVALID_FIELD");
    assert!(matches!(
        error,
        ManifestSchemaError::InvalidField { ref field, .. }
            if field == "provenance.reproducibility_markers[0]"
    ));
}

#[test]
fn adversarial_supply_chain_rejects_oversized_provenance_custom_claim_count_before_projection() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);

    request.provenance.custom_claims.clear();
    for index in 0..=capacity_defaults::base::SMALL {
        request
            .provenance
            .custom_claims
            .insert(format!("claim_{index:03}"), "bounded".to_string());
    }

    let signing_error = prov::sign_links_in_place(
        &mut request.provenance,
        &provenance_signing_keys(&signing_key),
    )
    .expect_err("oversized custom claim count must fail before signing");
    assert_eq!(
        signing_error.code,
        VerificationErrorCode::AttestationCapacityExceeded
    );

    let canonical_error = prov::canonical_attestation_json(&request.provenance)
        .expect_err("oversized custom claim count must fail before canonical attestation JSON");
    assert_eq!(
        canonical_error.code,
        VerificationErrorCode::AttestationCapacityExceeded
    );

    let mut policy = VerificationPolicy::development_profile();
    policy.add_trusted_signer_key("pub-001", &signing_key.verifying_key());
    let report = prov::verify_attestation_chain(
        &request.provenance,
        &policy,
        NOW_EPOCH,
        &format!("{TRACE_PREFIX}-custom-claims-count"),
    );
    assert!(!report.chain_valid);
    assert!(report.issues.iter().any(|issue| {
        issue.code == VerificationErrorCode::AttestationCapacityExceeded
            && issue.message.contains("custom claims count")
    }));

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-custom-claims-count"),
        NOW_EPOCH,
    );
    assert_fail_closed(
        &registry,
        &result,
        event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID,
    );
}

#[test]
fn adversarial_supply_chain_rejects_provenance_custom_claim_total_bytes_before_projection() {
    let signing_key = legitimate_signing_key();
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);

    request.provenance.custom_claims.clear();
    let claims_needed = (capacity_defaults::base::LARGE / capacity_defaults::base::MEDIUM) + 2;
    for index in 0..claims_needed {
        request.provenance.custom_claims.insert(
            format!("claim_{index:03}"),
            "x".repeat(capacity_defaults::base::MEDIUM),
        );
    }

    let signing_error = prov::sign_links_in_place(
        &mut request.provenance,
        &provenance_signing_keys(&signing_key),
    )
    .expect_err("oversized custom claim total must fail before signing");
    assert_eq!(
        signing_error.code,
        VerificationErrorCode::AttestationCapacityExceeded
    );
    assert!(signing_error.message.contains("canonical JSON"));

    let mut policy = VerificationPolicy::development_profile();
    policy.add_trusted_signer_key("pub-001", &signing_key.verifying_key());
    let report = prov::verify_attestation_chain(
        &request.provenance,
        &policy,
        NOW_EPOCH,
        &format!("{TRACE_PREFIX}-custom-claims-total"),
    );
    assert!(!report.chain_valid);
    assert!(report.issues.iter().any(|issue| {
        issue.code == VerificationErrorCode::AttestationCapacityExceeded
            && issue.message.contains("canonical JSON")
    }));
}

#[test]
fn adversarial_supply_chain_rejects_oversized_provenance_link_count_before_projection() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);

    let cloned_link = request
        .provenance
        .links
        .first()
        .expect("valid provenance includes publisher link")
        .clone();
    while request.provenance.links.len() <= ChainLinkRole::expected_order().len() {
        request.provenance.links.push(cloned_link.clone());
    }

    let signing_error = prov::sign_links_in_place(
        &mut request.provenance,
        &provenance_signing_keys(&signing_key),
    )
    .expect_err("oversized provenance link count must fail before signing");
    assert_eq!(
        signing_error.code,
        VerificationErrorCode::AttestationCapacityExceeded
    );
    assert!(signing_error.message.contains("attestation links count"));

    let canonical_error = prov::canonical_attestation_json(&request.provenance)
        .expect_err("oversized provenance link count must fail before canonical JSON");
    assert_eq!(
        canonical_error.code,
        VerificationErrorCode::AttestationCapacityExceeded
    );

    let mut policy = VerificationPolicy::development_profile();
    policy.add_trusted_signer_key("pub-001", &signing_key.verifying_key());
    let report = prov::verify_attestation_chain(
        &request.provenance,
        &policy,
        NOW_EPOCH,
        &format!("{TRACE_PREFIX}-link-count"),
    );
    assert!(!report.chain_valid);
    assert!(report.issues.iter().any(|issue| {
        issue.code == VerificationErrorCode::AttestationCapacityExceeded
            && issue.message.contains("attestation links count")
    }));
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.code == VerificationErrorCode::InvalidSignature)
    );

    let result = registry.register(request, &format!("{TRACE_PREFIX}-link-count"), NOW_EPOCH);
    assert_fail_closed(
        &registry,
        &result,
        event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID,
    );
}

#[test]
fn adversarial_supply_chain_rejects_dependency_injection_after_signing() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);

    request.provenance.custom_claims.insert(
        "dependency_graph".to_string(),
        "npm:trusted-core@1.0.0,npm:evil-miner@9.9.9".to_string(),
    );

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-dependency-injection"),
        NOW_EPOCH,
    );

    assert_fail_closed(
        &registry,
        &result,
        event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID,
    );
}

#[test]
fn adversarial_supply_chain_rejects_backdated_attestation_after_signing() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);

    let stale_epoch = NOW_EPOCH.saturating_sub(400 * 24 * 60 * 60);
    request.provenance.build_timestamp_epoch = stale_epoch;
    for link in &mut request.provenance.links {
        link.issued_at_epoch = stale_epoch;
        link.expires_at_epoch = stale_epoch.saturating_add(60);
    }

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-backdated-attestation"),
        NOW_EPOCH,
    );

    assert_fail_closed(
        &registry,
        &result,
        event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID,
    );
}

#[test]
fn adversarial_supply_chain_rejects_output_hash_poisoning_without_resigning() {
    let signing_key = legitimate_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);

    request.provenance.output_hash = "0".repeat(64);

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-output-hash-poisoning"),
        NOW_EPOCH,
    );

    assert_fail_closed(
        &registry,
        &result,
        event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID,
    );
}

#[test]
fn adversarial_supply_chain_rejects_attacker_resigned_manifest() {
    let signing_key = legitimate_signing_key();
    let attacker_key = attacker_signing_key();
    let mut registry = registry_with_trusted_key(signing_key.verifying_key());
    let mut request = valid_request("supply-chain-target", &signing_key, NOW_EPOCH);

    request.signature.key_id = KeyId::from_verifying_key(&attacker_key.verifying_key()).to_string();
    request.signature.signature_bytes =
        artifact_signing::sign_bytes(&attacker_key, &request.manifest_bytes);

    let result = registry.register(
        request,
        &format!("{TRACE_PREFIX}-attacker-resigned-manifest"),
        NOW_EPOCH,
    );

    assert_fail_closed(&registry, &result, event_codes::SER_ERR_KEY_NOT_FOUND);
}
