use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use frankenengine_node::supply_chain::{
    artifact_signing::{self, KeyId, KeyRing},
    extension_registry::{
        AdmissionKernel, ExtensionSignature, RegistrationRequest, RegistryConfig, RegistryResult,
        SignedExtensionRegistry, VersionEntry, canonical_registration_manifest_bytes, event_codes,
    },
    provenance::{
        self as prov, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole,
        ProvenanceAttestation, VerificationPolicy,
    },
    transparency_verifier::TransparencyPolicy,
};

const NOW_EPOCH: u64 = 1_777_000_000;
const SIGNED_AT: &str = "2026-04-26T00:00:00Z";
const TRACE_PREFIX: &str = "trace-adversarial-supply-chain";

fn legitimate_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[41_u8; 32])
}

fn attacker_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[99_u8; 32])
}

fn registry_with_trusted_key(verifying_key: VerifyingKey) -> SignedExtensionRegistry {
    let mut key_ring = KeyRing::new();
    key_ring.add_key(verifying_key);
    let mut provenance_policy = VerificationPolicy::development_profile();
    provenance_policy.add_trusted_signer_key("pub-001", &verifying_key);
    SignedExtensionRegistry::new(
        RegistryConfig::default(),
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
