#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::{
    artifact_signing::{self, KeyId, KeyRing},
    extension_registry::{
        AdmissionKernel, EXTENSION_REGISTRATION_MANIFEST_SCHEMA, ExtensionRegistrationManifest,
        ExtensionSignature, ExtensionStatus, RegistrationRequest, RegistryConfig,
        SignedExtensionRegistry, VersionEntry, canonical_registration_manifest_bytes, event_codes,
    },
    provenance as prov, transparency_verifier as tv,
};
use libfuzzer_sys::fuzz_target;

const NOW_EPOCH: u64 = 1_700_000_000;
const MAX_RAW_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_TEXT_CHARS: usize = 128;
const MAX_TAGS: usize = 8;

fuzz_target!(|case: ExtensionRegistrationManifestCase| {
    fuzz_raw_manifest_deserialization(&case.raw_manifest);
    fuzz_structured_registration(case);
});

fn fuzz_raw_manifest_deserialization(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_MANIFEST_BYTES {
        return;
    }

    let _ = serde_json::from_slice::<serde_json::Value>(bytes);
    if let Ok(manifest) = serde_json::from_slice::<ExtensionRegistrationManifest>(bytes) {
        json_roundtrip(&manifest);
        if manifest.schema_version == EXTENSION_REGISTRATION_MANIFEST_SCHEMA {
            let _ = canonical_registration_manifest_bytes(
                &manifest.name,
                &manifest.publisher_id,
                &manifest.initial_version,
                &manifest.tags,
            );
        }
    }
}

fn fuzz_structured_registration(case: ExtensionRegistrationManifestCase) {
    let signing_key = signing_key_from_seed(case.signing_seed);
    let verifying_key = signing_key.verifying_key();
    let trusted_key_id = KeyId::from_verifying_key(&verifying_key).to_string();
    let mut key_ring = KeyRing::new();
    key_ring.add_key(verifying_key);
    let mut provenance_policy = prov::VerificationPolicy::development_profile();
    provenance_policy.add_trusted_signer_key("publisher-fuzz", &verifying_key);
    let kernel = AdmissionKernel {
        key_ring,
        provenance_policy,
        transparency_policy: tv::TransparencyPolicy {
            required: false,
            pinned_roots: vec![],
        },
    };
    let mut registry = SignedExtensionRegistry::new(RegistryConfig::default(), kernel);

    let name = format!("fuzz-ext-{}", bounded_segment(&case.name, "name"));
    let publisher_id = format!(
        "publisher-{}",
        bounded_segment(&case.publisher_id, "publisher")
    );
    let initial_version = version_entry(&case);
    let tags = tags_from_case(&case.tags);
    let canonical_manifest =
        canonical_registration_manifest_bytes(&name, &publisher_id, &initial_version, &tags)
            .expect("generated canonical manifest must serialize");
    let manifest_shape = manifest_bytes_for_case(
        case.manifest_mode,
        &case,
        &canonical_manifest,
        &name,
        &publisher_id,
        &initial_version,
        &tags,
    );

    if manifest_shape.manifest_bytes.len() > MAX_RAW_MANIFEST_BYTES {
        return;
    }

    let signature_bytes = signature_for_case(
        case.signature_mode,
        &signing_key,
        &canonical_manifest,
        &manifest_shape.manifest_bytes,
        &case.raw_signature,
    );
    let key_id = match case.key_id_mode {
        KeyIdMode::Trusted => trusted_key_id,
        KeyIdMode::Unknown => {
            let unknown_key = signing_key_from_seed(case.signing_seed.wrapping_add(1));
            KeyId::from_verifying_key(&unknown_key.verifying_key()).to_string()
        }
    };
    let provenance = provenance_for_case(case.provenance_mode, NOW_EPOCH, &signing_key);
    let request = RegistrationRequest {
        name: name.clone(),
        description: bounded_text(&case.description, "fuzz extension"),
        publisher_id: publisher_id.clone(),
        signature: ExtensionSignature {
            key_id,
            algorithm: match case.signature_mode {
                SignatureMode::UnsupportedAlgorithm => "rsa_pkcs1".to_string(),
                _ => "ed25519".to_string(),
            },
            signature_bytes,
            signed_at: "2026-04-23T00:00:00Z".to_string(),
        },
        provenance,
        initial_version: initial_version.clone(),
        tags: tags.clone(),
        manifest_bytes: manifest_shape.manifest_bytes,
        transparency_proof: None,
    };

    let result = registry.register(
        request,
        &bounded_text(&case.trace_id, "trace-fuzz"),
        NOW_EPOCH,
    );
    assert!(
        registry.admission_receipts().len() <= 1,
        "single registration must store at most one admission receipt"
    );

    let expected_success = manifest_shape.matches_request
        && matches!(
            case.signature_mode,
            SignatureMode::SignManifestBytes | SignatureMode::SignCanonicalBytes
        )
        && matches!(case.key_id_mode, KeyIdMode::Trusted)
        && matches!(case.provenance_mode, ProvenanceMode::Valid);

    if expected_success {
        assert!(
            result.success,
            "valid canonical admission failed: {result:?}"
        );
        let extension = registry
            .query_by_name(&name)
            .expect("successful admission must persist active extension");
        assert_eq!(extension.status, ExtensionStatus::Active);
        assert_eq!(extension.publisher_id, publisher_id);
        assert_eq!(extension.versions, vec![initial_version]);
        assert_eq!(extension.tags, tags);
    } else if manifest_shape.must_fail_closed {
        assert!(
            !result.success,
            "malformed or divergent signed manifest must fail closed"
        );
        if admission_can_reach_manifest_parser(
            case.signature_mode,
            case.key_id_mode,
            case.provenance_mode,
        ) {
            assert_eq!(
                result.error_code.as_deref(),
                Some(event_codes::SER_ERR_INVALID_INPUT),
                "manifest parser/divergence failure must be reported as invalid input"
            );
        }
        assert!(
            registry.query_by_name(&name).is_none(),
            "failed manifest admission must not mutate registry state"
        );
    }

    assert!(registry.list(None).len() <= 1);
}

fn admission_can_reach_manifest_parser(
    signature_mode: SignatureMode,
    key_id_mode: KeyIdMode,
    provenance_mode: ProvenanceMode,
) -> bool {
    matches!(signature_mode, SignatureMode::SignManifestBytes)
        && matches!(key_id_mode, KeyIdMode::Trusted)
        && matches!(provenance_mode, ProvenanceMode::Valid)
}

fn manifest_bytes_for_case(
    mode: ManifestMode,
    case: &ExtensionRegistrationManifestCase,
    canonical_manifest: &[u8],
    name: &str,
    publisher_id: &str,
    initial_version: &VersionEntry,
    tags: &[String],
) -> ManifestBytes {
    match mode {
        ManifestMode::Canonical => ManifestBytes {
            manifest_bytes: canonical_manifest.to_vec(),
            matches_request: true,
            must_fail_closed: false,
        },
        ManifestMode::DivergentName => ManifestBytes {
            manifest_bytes: canonical_registration_manifest_bytes(
                "fuzz-ext-signed-different-name",
                publisher_id,
                initial_version,
                tags,
            )
            .expect("divergent name manifest must serialize"),
            matches_request: false,
            must_fail_closed: true,
        },
        ManifestMode::DivergentPublisher => ManifestBytes {
            manifest_bytes: canonical_registration_manifest_bytes(
                name,
                "publisher-signed-different",
                initial_version,
                tags,
            )
            .expect("divergent publisher manifest must serialize"),
            matches_request: false,
            must_fail_closed: true,
        },
        ManifestMode::DivergentVersion => {
            let mut divergent = initial_version.clone();
            divergent.version = "9.9.9".to_string();
            ManifestBytes {
                manifest_bytes: canonical_registration_manifest_bytes(
                    name,
                    publisher_id,
                    &divergent,
                    tags,
                )
                .expect("divergent version manifest must serialize"),
                matches_request: false,
                must_fail_closed: true,
            }
        }
        ManifestMode::DivergentTags => {
            let mut divergent_tags = tags.to_vec();
            divergent_tags.push("signed-only".to_string());
            ManifestBytes {
                manifest_bytes: canonical_registration_manifest_bytes(
                    name,
                    publisher_id,
                    initial_version,
                    &divergent_tags,
                )
                .expect("divergent tags manifest must serialize"),
                matches_request: false,
                must_fail_closed: true,
            }
        }
        ManifestMode::WrongSchema => ManifestBytes {
            manifest_bytes: serde_json::to_vec(&serde_json::json!({
                "schema_version": "franken-node/extension-registration-manifest/v0",
                "name": name,
                "publisher_id": publisher_id,
                "initial_version": initial_version,
                "tags": tags,
            }))
            .expect("wrong schema JSON must serialize"),
            matches_request: false,
            must_fail_closed: true,
        },
        ManifestMode::UnknownField => ManifestBytes {
            manifest_bytes: serde_json::to_vec(&serde_json::json!({
                "schema_version": EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
                "name": name,
                "publisher_id": publisher_id,
                "initial_version": initial_version,
                "tags": tags,
                "shadow_publisher_id": "attacker",
            }))
            .expect("unknown field JSON must serialize"),
            matches_request: false,
            must_fail_closed: true,
        },
        ManifestMode::CorruptCanonical => {
            let mut bytes = canonical_manifest.to_vec();
            if bytes.is_empty() {
                bytes.push(0xff);
            } else {
                let index = usize::from(case.byte_selector) % bytes.len();
                if let Some(byte) = bytes.get_mut(index) {
                    *byte ^= 0x80;
                }
            }
            ManifestBytes {
                manifest_bytes: bytes,
                matches_request: false,
                must_fail_closed: true,
            }
        }
        ManifestMode::RawBytes => ManifestBytes {
            manifest_bytes: case
                .raw_manifest
                .iter()
                .copied()
                .take(MAX_RAW_MANIFEST_BYTES)
                .collect(),
            matches_request: false,
            must_fail_closed: false,
        },
    }
}

fn signature_for_case(
    mode: SignatureMode,
    signing_key: &SigningKey,
    canonical_manifest: &[u8],
    manifest_bytes: &[u8],
    raw_signature: &[u8],
) -> Vec<u8> {
    match mode {
        SignatureMode::SignManifestBytes | SignatureMode::UnsupportedAlgorithm => {
            artifact_signing::sign_bytes(signing_key, manifest_bytes)
        }
        SignatureMode::SignCanonicalBytes => {
            artifact_signing::sign_bytes(signing_key, canonical_manifest)
        }
        SignatureMode::RawSignature => raw_signature.iter().copied().take(128).collect(),
        SignatureMode::SameLengthGarbage => vec![0xA5; 64],
    }
}

fn provenance_signing_keys(signing_key: &SigningKey) -> BTreeMap<String, SigningKey> {
    BTreeMap::from([(
        "publisher-fuzz".to_string(),
        SigningKey::from_bytes(&signing_key.to_bytes()),
    )])
}

fn provenance_for_case(
    mode: ProvenanceMode,
    now_epoch: u64,
    signing_key: &SigningKey,
) -> prov::ProvenanceAttestation {
    let mut attestation = prov::ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://github.com/franken/fuzz-extension".to_string(),
        build_system_identifier: "fuzz-build".to_string(),
        builder_identity: "publisher-fuzz".to_string(),
        builder_version: "1.0.0".to_string(),
        vcs_commit_sha: "a".repeat(64),
        build_timestamp_epoch: now_epoch.saturating_sub(60),
        reproducibility_hash: "b".repeat(64),
        input_hash: "c".repeat(64),
        output_hash: "d".repeat(64),
        slsa_level_claim: 2,
        envelope_format: prov::AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
        links: vec![prov::AttestationLink {
            role: prov::ChainLinkRole::Publisher,
            signer_id: "publisher-fuzz".to_string(),
            signer_version: "1.0.0".to_string(),
            signature: String::new(),
            signed_payload_hash: "d".repeat(64),
            issued_at_epoch: now_epoch.saturating_sub(60),
            expires_at_epoch: now_epoch.saturating_add(86_400),
            revoked: false,
        }],
        custom_claims: BTreeMap::new(),
    };

    match mode {
        ProvenanceMode::Valid => {}
        ProvenanceMode::MissingLink => attestation.links.clear(),
        ProvenanceMode::ExpiredLink => {
            if let Some(link) = attestation.links.first_mut() {
                link.expires_at_epoch = now_epoch.saturating_sub(1);
            }
        }
        ProvenanceMode::RevokedLink => {
            if let Some(link) = attestation.links.first_mut() {
                link.revoked = true;
            }
        }
        ProvenanceMode::OutputHashMismatch => {
            if let Some(link) = attestation.links.first_mut() {
                link.signed_payload_hash = "e".repeat(64);
            }
        }
    }

    let _ = prov::sign_links_in_place(&mut attestation, &provenance_signing_keys(signing_key));
    attestation
}

fn version_entry(case: &ExtensionRegistrationManifestCase) -> VersionEntry {
    VersionEntry {
        version: format!(
            "{}.{}.{}",
            case.version_major % 8,
            case.version_minor % 64,
            case.version_patch % 128
        ),
        parent_version: None,
        content_hash: hex::encode(case.content_hash),
        registered_at: "2026-04-23T00:00:00Z".to_string(),
        compatible_with: Vec::new(),
    }
}

fn tags_from_case(tags: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for (index, tag) in tags.iter().take(MAX_TAGS).enumerate() {
        out.push(format!("tag-{index}-{}", bounded_segment(tag, "x")));
    }
    if out.is_empty() {
        out.push("tag-0-default".to_string());
    }
    out
}

fn signing_key_from_seed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn bounded_text(raw: &str, fallback: &str) -> String {
    let mut out = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TEXT_CHARS)
        .collect::<String>();
    if out.is_empty() {
        out.push_str(fallback);
    }
    out
}

fn bounded_segment(raw: &str, fallback: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars().take(MAX_TEXT_CHARS) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            out.push(ch);
        }
    }
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

fn json_roundtrip<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_vec(value).expect("JSON serialization must not fail");
    let decoded: T = serde_json::from_slice(&encoded).expect("own JSON must deserialize");
    assert_eq!(decoded, *value);
}

struct ManifestBytes {
    manifest_bytes: Vec<u8>,
    matches_request: bool,
    must_fail_closed: bool,
}

#[derive(Debug, Arbitrary)]
struct ExtensionRegistrationManifestCase {
    raw_manifest: Vec<u8>,
    raw_signature: Vec<u8>,
    name: String,
    publisher_id: String,
    description: String,
    trace_id: String,
    tags: Vec<String>,
    signing_seed: u8,
    byte_selector: u8,
    version_major: u8,
    version_minor: u8,
    version_patch: u8,
    content_hash: [u8; 32],
    manifest_mode: ManifestMode,
    signature_mode: SignatureMode,
    key_id_mode: KeyIdMode,
    provenance_mode: ProvenanceMode,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ManifestMode {
    Canonical,
    DivergentName,
    DivergentPublisher,
    DivergentVersion,
    DivergentTags,
    WrongSchema,
    UnknownField,
    CorruptCanonical,
    RawBytes,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum SignatureMode {
    SignManifestBytes,
    SignCanonicalBytes,
    RawSignature,
    SameLengthGarbage,
    UnsupportedAlgorithm,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum KeyIdMode {
    Trusted,
    Unknown,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ProvenanceMode {
    Valid,
    MissingLink,
    ExpiredLink,
    RevokedLink,
    OutputHashMismatch,
}
