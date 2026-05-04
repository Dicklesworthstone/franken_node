use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::artifact_signing::{self, KeyId, KeyRing};
use frankenengine_node::supply_chain::extension_registry::{
    AdmissionKernel, ExtensionSignature, RegistrationRequest, RegistryConfig, SignedExtension,
    SignedExtensionRegistry, VersionEntry,
};
use frankenengine_node::supply_chain::provenance::{
    self, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole, ProvenanceAttestation,
    VerificationPolicy,
};
use frankenengine_node::supply_chain::transparency_verifier::TransparencyPolicy;
use frankenengine_verifier_sdk::bundle::{BundleError, verify_ed25519_signature};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct PublishedRegistryEntry {
    entry: SignedExtension,
    manifest_bytes: Vec<u8>,
    public_key: ed25519_dalek::VerifyingKey,
}

#[test]
fn sdk_independently_verifies_franken_node_registry_signature() -> TestResult {
    let published = publish_signed_registry_entry()?;
    let key_id = KeyId::from_verifying_key(&published.public_key);

    assert_eq!(published.entry.signature.algorithm, "ed25519");
    assert_eq!(published.entry.signature.key_id, key_id.to_string());

    verify_ed25519_signature(
        &published.public_key,
        &published.manifest_bytes,
        &published.entry.signature.signature_bytes,
    )?;

    let mut mutated_manifest = published.manifest_bytes.clone();
    if let Some(first_byte) = mutated_manifest.first_mut() {
        *first_byte ^= 0x01;
    }

    let Err(error) = verify_ed25519_signature(
        &published.public_key,
        &mutated_manifest,
        &published.entry.signature.signature_bytes,
    ) else {
        return Err("mutated registry manifest unexpectedly verified".into());
    };
    assert_eq!(error, BundleError::Ed25519SignatureInvalid);

    Ok(())
}

fn publish_signed_registry_entry() -> TestResult<PublishedRegistryEntry> {
    let now_epoch = 1_700_000_400;
    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let mut registry = registry_with_publisher_key(verifying_key);
    let request = registration_request(&signing_key, now_epoch)?;
    let manifest_bytes = request.manifest_bytes.clone();
    let registered_key_id = request.signature.key_id.clone();

    let result = registry.register(request, "trace-sdk-independent-registry-verify", now_epoch);
    if !result.success {
        return Err(format!("registry admission failed: {}", result.detail).into());
    }
    let extension_id = result
        .extension_id
        .ok_or("registry admission succeeded without extension id")?;
    let entry = registry
        .query(&extension_id)
        .ok_or("registered extension missing from registry")?
        .clone();
    let public_key = registry
        .admission_kernel()
        .key_ring
        .get_key(&KeyId(registered_key_id))
        .copied()
        .ok_or("registered publisher key missing from key ring")?;

    Ok(PublishedRegistryEntry {
        entry,
        manifest_bytes,
        public_key,
    })
}

fn registry_with_publisher_key(
    verifying_key: ed25519_dalek::VerifyingKey,
) -> SignedExtensionRegistry {
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
                pinned_roots: Vec::new(),
            },
        },
    )
}

fn registration_request(
    signing_key: &SigningKey,
    now_epoch: u64,
) -> TestResult<RegistrationRequest> {
    let manifest_bytes = b"manifest:chain-verify-registry:sha256:registry-entry-fixture".to_vec();
    let signature_bytes = artifact_signing::sign_bytes(signing_key, &manifest_bytes);
    let key_id = KeyId::from_verifying_key(&signing_key.verifying_key());

    Ok(RegistrationRequest {
        name: "chain-verify-registry".to_string(),
        description: "SDK verifier independent registry signature fixture".to_string(),
        publisher_id: "pub-001".to_string(),
        signature: ExtensionSignature {
            key_id: key_id.to_string(),
            algorithm: "ed25519".to_string(),
            signature_bytes,
            signed_at: "2023-11-14T22:13:20Z".to_string(),
        },
        provenance: provenance_attestation(signing_key, now_epoch)?,
        initial_version: VersionEntry {
            version: "1.0.0".to_string(),
            parent_version: None,
            content_hash: "c".repeat(64),
            registered_at: "2023-11-14T22:13:20Z".to_string(),
            compatible_with: vec!["franken-node".to_string()],
        },
        tags: vec!["sdk-verifier".to_string(), "registry".to_string()],
        manifest_bytes,
        transparency_proof: None,
    })
}

fn provenance_signing_keys(signing_key: &SigningKey) -> BTreeMap<String, SigningKey> {
    BTreeMap::from([(
        "pub-001".to_string(),
        SigningKey::from_bytes(&signing_key.to_bytes()),
    )])
}

fn provenance_attestation(
    signing_key: &SigningKey,
    now_epoch: u64,
) -> TestResult<ProvenanceAttestation> {
    let mut attestation = ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://example.invalid/franken-node/extensions.git".to_string(),
        build_system_identifier: "franken-node-registry-fixture".to_string(),
        builder_identity: "pub-001".to_string(),
        builder_version: "1.0.0".to_string(),
        vcs_commit_sha: "abc123def4567890abc123def4567890abc123def".to_string(),
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
        custom_claims: Default::default(),
    };
    provenance::sign_links_in_place(&mut attestation, &provenance_signing_keys(signing_key))?;
    Ok(attestation)
}
