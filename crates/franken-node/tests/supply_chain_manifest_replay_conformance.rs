use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::{
    artifact_signing::{self, KeyId, KeyRing},
    extension_registry::{
        AdmissionKernel, ExtensionSignature, RegistrationRequest, RegistryConfig,
        SignedExtensionRegistry, VersionEntry, canonical_registration_manifest_bytes, event_codes,
    },
    provenance::{
        self as prov, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole,
        ProvenanceAttestation,
    },
    transparency_verifier::TransparencyPolicy,
};

const NOW_EPOCH: u64 = 1_777_100_500;
const PUBLISHER_ID: &str = "pub-replay-conformance";
const SIGNED_AT: &str = "2026-04-26T21:00:00Z";
const EXTENSION_NAME: &str = "supply-chain-manifest-replay-conformance";

type TestResult<T = ()> = Result<T, String>;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[73_u8; 32])
}

fn provenance_keyring() -> BTreeMap<String, SigningKey> {
    let key = signing_key();
    BTreeMap::from([(
        PUBLISHER_ID.to_string(),
        SigningKey::from_bytes(&key.to_bytes()),
    )])
}

fn registry() -> SignedExtensionRegistry {
    let key = signing_key();
    let mut key_ring = KeyRing::new();
    key_ring.add_key(key.verifying_key());

    let mut provenance_policy = prov::VerificationPolicy::development_profile();
    provenance_policy.add_trusted_signer_key(PUBLISHER_ID, &key.verifying_key());

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

fn version_entry() -> VersionEntry {
    VersionEntry {
        version: "1.0.0".to_string(),
        parent_version: None,
        content_hash: "c".repeat(64),
        registered_at: SIGNED_AT.to_string(),
        compatible_with: vec!["franken-node>=1.0.0".to_string()],
    }
}

fn provenance() -> TestResult<ProvenanceAttestation> {
    let mut attestation = ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://github.com/example/replay-conformance".to_string(),
        build_system_identifier: "github-actions".to_string(),
        builder_identity: PUBLISHER_ID.to_string(),
        builder_version: "1.0.0".to_string(),
        vcs_commit_sha: "abc123def456".to_string(),
        build_timestamp_epoch: NOW_EPOCH.saturating_sub(60),
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
            issued_at_epoch: NOW_EPOCH.saturating_sub(60),
            expires_at_epoch: NOW_EPOCH.saturating_add(86_400),
            revoked: false,
        }],
        custom_claims: BTreeMap::new(),
    };
    prov::sign_links_in_place(&mut attestation, &provenance_keyring())
        .map_err(|err| format!("provenance fixture signing failed: {err}"))?;
    Ok(attestation)
}

fn registration_request() -> TestResult<RegistrationRequest> {
    let key = signing_key();
    let initial_version = version_entry();
    let tags = vec!["stable".to_string(), "operator-reviewed".to_string()];
    let manifest_bytes = canonical_registration_manifest_bytes(
        EXTENSION_NAME,
        PUBLISHER_ID,
        &initial_version,
        &tags,
    )
    .map_err(|err| format!("canonical registration manifest failed: {err}"))?;

    Ok(RegistrationRequest {
        name: EXTENSION_NAME.to_string(),
        description: "Supply-chain manifest replay conformance fixture".to_string(),
        publisher_id: PUBLISHER_ID.to_string(),
        signature: ExtensionSignature {
            key_id: KeyId::from_verifying_key(&key.verifying_key()).to_string(),
            algorithm: "ed25519".to_string(),
            signature_bytes: artifact_signing::sign_bytes(&key, &manifest_bytes),
            signed_at: SIGNED_AT.to_string(),
        },
        provenance: provenance()?,
        initial_version,
        tags,
        manifest_bytes,
        transparency_proof: None,
    })
}

#[test]
fn signed_manifest_replay_with_mutated_tags_fails_closed() -> TestResult {
    let mut request = registration_request()?;
    request.tags.push("post-signing-capability".to_string());

    let mut registry = registry();
    let result = registry.register(request, "trace-r105-manifest-replay", NOW_EPOCH);

    if result.success {
        return Err("post-signing request mutation was admitted".to_string());
    }
    if result.error_code.as_deref() != Some(event_codes::SER_ERR_INVALID_INPUT) {
        return Err(format!(
            "expected invalid-input rejection, got {:?}",
            result.error_code
        ));
    }
    if !result
        .detail
        .contains("registration request field `tags` diverges")
    {
        return Err(format!(
            "rejection detail did not identify tag divergence: {}",
            result.detail
        ));
    }
    if result.extension_id.is_some() {
        return Err("replayed request returned an extension id".to_string());
    }
    if !registry.list(None).is_empty() {
        return Err("replayed request mutated the extension registry".to_string());
    }
    if registry.query_by_name(EXTENSION_NAME).is_some() {
        return Err("replayed request became queryable by extension name".to_string());
    }

    let receipt = registry
        .admission_receipts()
        .first()
        .ok_or_else(|| "admission evaluation receipt was not persisted".to_string())?;
    if !receipt.admitted {
        return Err("kernel receipt should record that signed bytes verified".to_string());
    }

    let events: Vec<&str> = registry
        .audit_log()
        .iter()
        .map(|record| record.event_code.as_str())
        .collect();
    if !events.contains(&event_codes::SER_ADMISSION_EVALUATED) {
        return Err("audit log omitted admission evaluation event".to_string());
    }
    if !events.contains(&event_codes::SER_ERR_INVALID_INPUT) {
        return Err("audit log omitted final invalid-input rejection".to_string());
    }

    Ok(())
}
