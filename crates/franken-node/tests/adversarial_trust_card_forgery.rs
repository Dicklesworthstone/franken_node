//! Adversarial harness: trust-card forgery rejection.
//!
//! Constructs a legitimately-signed trust card via `TrustCardRegistry::create`
//! using a registry HMAC key controlled by the test, then exercises three
//! concrete forgery patterns against the public verifier
//! (`verify_card_signature`) and the registry-ingestion path
//! (`TrustCardRegistry::from_snapshot`):
//!
//! 1. Tampered scope claims while keeping the original signature — must reject
//!    with `CardHashMismatch`.
//! 2. Re-signed under an attacker-controlled HMAC key — must reject with
//!    `SignatureInvalid` (hash matches the tampered content but signature does
//!    not validate under the legitimate key).
//! 3. Extended freshness/TTL claim (last_verified_timestamp pushed into the
//!    future + matching audit_history entry) without re-signing — must reject
//!    with `CardHashMismatch`.
//!
//! Bead: bd-2476c.1
//! Pattern reference: tests/adversarial_remote_cap_replay.rs (commit f5858ec5).

use chrono::Utc;
use ed25519_dalek::SigningKey;
#[cfg(feature = "test-support")]
use frankenengine_node::supply_chain::extension_registry::parse_signed_registration_manifest;
use frankenengine_node::supply_chain::{
    artifact_signing::{self, KeyId, KeyRing},
    certification::{EvidenceType, VerifiedEvidenceRef},
    extension_registry::{
        AdmissionKernel, EXTENSION_REGISTRATION_MANIFEST_SCHEMA, ExtensionSignature,
        RegistrationRequest, RegistryConfig, SignedExtensionRegistry, VersionEntry,
        canonical_registration_manifest_bytes, event_codes,
    },
    provenance::{
        self as prov, AttestationEnvelopeFormat, AttestationLink, ChainLinkRole,
        ProvenanceAttestation,
    },
    transparency_verifier as tv,
    trust_card::{
        BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
        DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
        ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard, TrustCardError,
        TrustCardInput, TrustCardRegistry, TrustCardRegistrySnapshot, compute_card_hash,
        verify_card_signature,
    },
};
use hmac::{Hmac, KeyInit, Mac};
use proptest::prelude::*;
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const LEGITIMATE_KEY: &[u8] = b"adversarial-trust-card-forgery-legitimate-registry-key";
const ATTACKER_KEY: &[u8] = b"adversarial-trust-card-forgery-attacker-key-not-trusted";
const NOW_SECS: u64 = 1_777_000_000;
const TRACE_ID: &str = "trace-trust-card-forgery";
const CACHE_TTL_SECS: u64 = 60;
const EXTENSION_PUBLISHER_ID: &str = "pub-001";
const EXTENSION_NOW_EPOCH: u64 = 1_777_000_500;

/// Build the (extension/publisher/policy) input shape the registry signs over.
fn legitimate_input() -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@acme/forgery-target".to_string(),
            version: "2.4.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-acme".to_string(),
            display_name: "Acme Security".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        capability_declarations: vec![CapabilityDeclaration {
            name: "policy.read".to_string(),
            description: "Read-only policy lookups".to_string(),
            risk: CapabilityRisk::Low,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: false,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Read-only static-policy extension".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "slsa-l3".to_string(),
            source_uri: "registry://acme/forgery-target".to_string(),
            artifact_hashes: vec!["sha256:".to_string() + &"a".repeat(64)],
            verified_at: "2026-01-01T00:00:00Z".to_string(),
        },
        reputation_score_basis_points: 950,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![DependencyTrustStatus {
            dependency_id: "npm:lodash@4".to_string(),
            trust_level: "verified".to_string(),
        }],
        last_verified_timestamp: "2026-01-01T00:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Low-risk read-only extension".to_string(),
        },
        evidence_refs: legitimate_evidence_refs(),
    }
}

fn legitimate_evidence_refs() -> Vec<VerifiedEvidenceRef> {
    vec![
        VerifiedEvidenceRef {
            evidence_id: "ev-prov-001".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: NOW_SECS,
            verification_receipt_hash: "a".repeat(64),
        },
        VerifiedEvidenceRef {
            evidence_id: "ev-rep-001".to_string(),
            evidence_type: EvidenceType::ReputationSignal,
            verified_at_epoch: NOW_SECS,
            verification_receipt_hash: "b".repeat(64),
        },
    ]
}

/// Mint a freshly-signed trust card under the legitimate registry key.
fn mint_legitimate_card() -> TrustCard {
    let mut registry = TrustCardRegistry::new(CACHE_TTL_SECS, LEGITIMATE_KEY);
    registry
        .create(legitimate_input(), NOW_SECS, TRACE_ID)
        .expect("legitimate registry must mint a fresh trust card")
}

/// Replicate the private `sign_card_in_place` helper from the trust-card module
/// so the test can synthesize an attacker-signed card without needing the
/// crate-private signing path. Domain separator and HMAC construction are
/// pinned to the production format (`trust_card_registry_sig_v1:`); if the
/// production format ever changes, this helper will need to track it — but the
/// MR (rejection of attacker-key signatures) is independent of that format.
fn forge_signed_card(card: &mut TrustCard, attacker_key: &[u8]) {
    card.card_hash = compute_card_hash(card).expect("recompute card hash for attacker re-sign");
    let mut mac = HmacSha256::new_from_slice(attacker_key).expect("attacker HMAC key");
    mac.update(b"trust_card_registry_sig_v1:");
    mac.update(card.card_hash.as_bytes());
    card.registry_signature = hex::encode(mac.finalize().into_bytes());
}

fn extension_id_matches(actual: &str, expected: &str) -> bool {
    actual.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn extension_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42_u8; 32])
}

fn extension_provenance_signing_keys(sk: &SigningKey) -> BTreeMap<String, SigningKey> {
    BTreeMap::from([(
        EXTENSION_PUBLISHER_ID.to_string(),
        SigningKey::from_bytes(&sk.to_bytes()),
    )])
}

fn extension_provenance(sk: &SigningKey, now_epoch: u64) -> ProvenanceAttestation {
    let mut attestation = ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://github.com/example/ext".to_string(),
        build_system_identifier: "github-actions".to_string(),
        builder_identity: EXTENSION_PUBLISHER_ID.to_string(),
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
            signer_id: EXTENSION_PUBLISHER_ID.to_string(),
            signer_version: "1.0.0".to_string(),
            signature: String::new(),
            signed_payload_hash: "f".repeat(64),
            issued_at_epoch: now_epoch.saturating_sub(60),
            expires_at_epoch: now_epoch.saturating_add(86_400),
            revoked: false,
        }],
        custom_claims: BTreeMap::new(),
    };
    prov::sign_links_in_place(&mut attestation, &extension_provenance_signing_keys(sk))
        .expect("extension provenance fixture should sign");
    attestation
}

fn extension_version() -> VersionEntry {
    VersionEntry {
        version: "1.0.0".to_string(),
        parent_version: None,
        content_hash: "c".repeat(64),
        registered_at: Utc::now().to_rfc3339(),
        compatible_with: Vec::new(),
    }
}

fn extension_registry(sk: &SigningKey) -> SignedExtensionRegistry {
    let verifying_key = sk.verifying_key();
    let mut key_ring = KeyRing::new();
    key_ring.add_key(verifying_key);
    let mut provenance_policy = prov::VerificationPolicy::development_profile();
    provenance_policy.add_trusted_signer_key(EXTENSION_PUBLISHER_ID, &verifying_key);

    SignedExtensionRegistry::new(
        RegistryConfig::default(),
        AdmissionKernel {
            key_ring,
            provenance_policy,
            transparency_policy: tv::TransparencyPolicy {
                required: false,
                pinned_roots: Vec::new(),
            },
        },
    )
}

fn extension_request(name: &str, sk: &SigningKey, now_epoch: u64) -> RegistrationRequest {
    let initial_version = extension_version();
    let tags = vec!["replay".to_string(), "conformance".to_string()];
    let manifest_bytes = canonical_registration_manifest_bytes(
        name,
        EXTENSION_PUBLISHER_ID,
        &initial_version,
        &tags,
    )
    .expect("canonical extension registration manifest");

    RegistrationRequest {
        name: name.to_string(),
        description: format!("Replay-prevention conformance fixture: {name}"),
        publisher_id: EXTENSION_PUBLISHER_ID.to_string(),
        signature: ExtensionSignature {
            key_id: KeyId::from_verifying_key(&sk.verifying_key()).to_string(),
            algorithm: "ed25519".to_string(),
            signature_bytes: artifact_signing::sign_bytes(sk, &manifest_bytes),
            signed_at: Utc::now().to_rfc3339(),
        },
        provenance: extension_provenance(sk, now_epoch),
        initial_version,
        tags,
        manifest_bytes,
        transparency_proof: None,
    }
}

const FUZZ_JSON_BYTES_LIMIT: usize = 4096;

#[derive(Clone, Debug)]
struct RegistrationManifestFuzzCase {
    use_valid_schema: bool,
    schema_fallback: Value,
    use_request_name: bool,
    name_fallback: Value,
    use_request_publisher: bool,
    publisher_fallback: Value,
    use_request_version: bool,
    version_fallback: Value,
    use_request_tags: bool,
    tags_fallback: Value,
    include_embedded_signature: bool,
    embedded_signature: Value,
}

impl RegistrationManifestFuzzCase {
    fn exactly_matches_request(&self) -> bool {
        self.use_valid_schema
            && self.use_request_name
            && self.use_request_publisher
            && self.use_request_version
            && self.use_request_tags
            && !self.include_embedded_signature
    }
}

fn fuzz_text(max_len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(0_u8..=127, 0..=max_len)
        .prop_map(|bytes| String::from_utf8(bytes).expect("ASCII fuzz bytes are UTF-8"))
}

fn fuzz_json_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-1024_i64..=1024).prop_map(|value| Value::Number(value.into())),
        fuzz_text(96).prop_map(Value::String),
    ]
}

fn fuzz_version_value() -> impl Strategy<Value = Value> {
    (
        fuzz_text(32),
        prop::option::of(fuzz_text(32)),
        fuzz_text(96),
        fuzz_text(64),
        prop::collection::vec(fuzz_text(32), 0..=4),
        any::<bool>(),
        fuzz_json_leaf(),
    )
        .prop_map(
            |(
                version,
                parent_version,
                content_hash,
                registered_at,
                compatible_with,
                include_unknown,
                unknown_value,
            )| {
                let mut object = Map::new();
                object.insert("version".to_string(), Value::String(version));
                object.insert(
                    "parent_version".to_string(),
                    parent_version.map_or(Value::Null, Value::String),
                );
                object.insert("content_hash".to_string(), Value::String(content_hash));
                object.insert("registered_at".to_string(), Value::String(registered_at));
                object.insert(
                    "compatible_with".to_string(),
                    Value::Array(
                        compatible_with
                            .into_iter()
                            .map(Value::String)
                            .collect::<Vec<_>>(),
                    ),
                );
                if include_unknown {
                    object.insert("unsigned_version_metadata".to_string(), unknown_value);
                }
                Value::Object(object)
            },
        )
}

fn version_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        fuzz_version_value(),
        fuzz_json_leaf(),
        prop::collection::vec(fuzz_json_leaf(), 0..=4).prop_map(Value::Array),
    ]
}

fn tags_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        prop::collection::vec(fuzz_text(32), 0..=6).prop_map(|tags| {
            Value::Array(tags.into_iter().map(Value::String).collect::<Vec<_>>())
        }),
        prop::collection::vec(fuzz_json_leaf(), 0..=6).prop_map(Value::Array),
        fuzz_json_leaf(),
    ]
}

fn manifest_field_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        fuzz_text(128).prop_map(Value::String),
        fuzz_json_leaf(),
        prop::collection::vec(fuzz_json_leaf(), 0..=4).prop_map(Value::Array),
    ]
}

fn signed_registration_manifest_case() -> impl Strategy<Value = RegistrationManifestFuzzCase> {
    (
        any::<bool>(),
        manifest_field_value(),
        any::<bool>(),
        manifest_field_value(),
        any::<bool>(),
        manifest_field_value(),
        any::<bool>(),
        version_value(),
        any::<bool>(),
        tags_value(),
        any::<bool>(),
        fuzz_json_leaf(),
    )
        .prop_map(
            |(
                use_valid_schema,
                schema_fallback,
                use_request_name,
                name_fallback,
                use_request_publisher,
                publisher_fallback,
                use_request_version,
                version_fallback,
                use_request_tags,
                tags_fallback,
                include_embedded_signature,
                embedded_signature,
            )| RegistrationManifestFuzzCase {
                use_valid_schema,
                schema_fallback,
                use_request_name,
                name_fallback,
                use_request_publisher,
                publisher_fallback,
                use_request_version,
                version_fallback,
                use_request_tags,
                tags_fallback,
                include_embedded_signature,
                embedded_signature,
            },
        )
}

fn exact_registration_manifest_value(request: &RegistrationRequest) -> Value {
    serde_json::json!({
        "schema_version": EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
        "name": &request.name,
        "publisher_id": &request.publisher_id,
        "initial_version": &request.initial_version,
        "tags": &request.tags,
    })
}

fn registration_manifest_value(
    request: &RegistrationRequest,
    case: &RegistrationManifestFuzzCase,
) -> Value {
    let mut object = Map::new();
    object.insert(
        "schema_version".to_string(),
        if case.use_valid_schema {
            Value::String(EXTENSION_REGISTRATION_MANIFEST_SCHEMA.to_string())
        } else {
            case.schema_fallback.clone()
        },
    );
    object.insert(
        "name".to_string(),
        if case.use_request_name {
            Value::String(request.name.clone())
        } else {
            case.name_fallback.clone()
        },
    );
    object.insert(
        "publisher_id".to_string(),
        if case.use_request_publisher {
            Value::String(request.publisher_id.clone())
        } else {
            case.publisher_fallback.clone()
        },
    );
    object.insert(
        "initial_version".to_string(),
        if case.use_request_version {
            serde_json::to_value(&request.initial_version).expect("version serializes")
        } else {
            case.version_fallback.clone()
        },
    );
    object.insert(
        "tags".to_string(),
        if case.use_request_tags {
            serde_json::to_value(&request.tags).expect("tags serialize")
        } else {
            case.tags_fallback.clone()
        },
    );
    if case.include_embedded_signature {
        object.insert("signature".to_string(), case.embedded_signature.clone());
    }
    Value::Object(object)
}

fn register_with_manifest_bytes(
    sk: &SigningKey,
    mut request: RegistrationRequest,
    manifest_bytes: Vec<u8>,
    trace_suffix: &str,
) -> (
    SignedExtensionRegistry,
    frankenengine_node::supply_chain::extension_registry::RegistryResult,
) {
    request.manifest_bytes = manifest_bytes;
    request.signature.signature_bytes = artifact_signing::sign_bytes(sk, &request.manifest_bytes);

    let mut registry = extension_registry(sk);
    let result = registry.register(
        request,
        &format!("{TRACE_ID}-{trace_suffix}"),
        EXTENSION_NOW_EPOCH,
    );
    (registry, result)
}

fn resign_extension_request(sk: &SigningKey, request: &mut RegistrationRequest) {
    request.manifest_bytes = canonical_registration_manifest_bytes(
        &request.name,
        &request.publisher_id,
        &request.initial_version,
        &request.tags,
    )
    .expect("registration manifest serializes");
    request.signature.signature_bytes = artifact_signing::sign_bytes(sk, &request.manifest_bytes);
}

fn assert_invalid_extension_version_request(
    sk: &SigningKey,
    mut request: RegistrationRequest,
    trace_suffix: &str,
    expected_field: &str,
    expected_detail: &str,
) {
    resign_extension_request(sk, &mut request);

    let mut registry = extension_registry(sk);
    let result = registry.register(
        request,
        &format!("{TRACE_ID}-{trace_suffix}"),
        EXTENSION_NOW_EPOCH,
    );

    assert!(!result.success, "invalid version entry must fail closed");
    assert_eq!(
        result.error_code.as_deref(),
        Some(event_codes::SER_ERR_INVALID_INPUT)
    );
    assert!(
        result.detail.contains(expected_detail),
        "rejection detail should contain {expected_detail:?}, got {:?}",
        result.detail
    );
    assert!(
        registry.list(None).is_empty(),
        "invalid version entry must not register an extension"
    );
    assert!(
        registry.admission_receipts().is_empty(),
        "invalid version metadata must fail before signature admission"
    );

    let audit = registry
        .audit_log()
        .last()
        .expect("invalid version entry must emit an audit record");
    assert_eq!(audit.event_code, event_codes::SER_ERR_INVALID_INPUT);
    assert_eq!(audit.details["field"], expected_field);
}

/// Sanity check: a legitimately-minted card must verify under the legitimate
/// key. If this baseline ever fails, every subsequent rejection assertion is
/// meaningless.
#[test]
fn baseline_legitimate_card_verifies() {
    let card = mint_legitimate_card();
    verify_card_signature(&card, LEGITIMATE_KEY)
        .expect("baseline: legitimately-signed card must verify under legitimate key");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 192,
        max_shrink_iters: 1024,
        .. ProptestConfig::default()
    })]

    #[test]
    fn signed_extension_registration_manifest_fuzz_rejects_or_admits_only_exact_request(
        case in signed_registration_manifest_case(),
    ) {
        let signing_key = extension_signing_key();
        let request = extension_request(
            "signed-extension-manifest-fuzz",
            &signing_key,
            EXTENSION_NOW_EPOCH,
        );
        let manifest = registration_manifest_value(&request, &case);
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest value serializes");

        let (registry, result) = register_with_manifest_bytes(
            &signing_key,
            request,
            manifest_bytes,
            "signed-manifest-fuzz-json",
        );

        if case.exactly_matches_request() {
            prop_assert!(
                result.success,
                "exact signed manifest should admit: {:?} {}",
                result.error_code,
                result.detail
            );
            prop_assert_eq!(registry.list(None).len(), 1);
        } else if case.include_embedded_signature {
            prop_assert!(!result.success, "embedded signature envelope must fail closed");
            prop_assert_eq!(
                result.error_code.as_deref(),
                Some(event_codes::SER_ERR_INVALID_INPUT)
            );
            prop_assert!(
                registry.list(None).is_empty(),
                "embedded signature envelope must not register an extension"
            );
        }

        if result.success {
            prop_assert!(
                !case.include_embedded_signature,
                "embedded signature fields must never be admitted"
            );
            prop_assert_eq!(registry.list(None).len(), 1);
        } else {
            prop_assert!(
                registry.list(None).is_empty(),
                "rejected manifest must not mutate the registry"
            );
        }
    }

    #[test]
    fn signed_extension_registration_manifest_byte_fuzz_never_panics_or_partially_admits(
        manifest_bytes in prop::collection::vec(any::<u8>(), 0..=FUZZ_JSON_BYTES_LIMIT),
    ) {
        let signing_key = extension_signing_key();
        let request = extension_request(
            "signed-extension-manifest-byte-fuzz",
            &signing_key,
            EXTENSION_NOW_EPOCH,
        );

        let (registry, result) = register_with_manifest_bytes(
            &signing_key,
            request,
            manifest_bytes,
            "signed-manifest-fuzz-bytes",
        );

        if result.success {
            prop_assert_eq!(
                registry.list(None).len(),
                1,
                "successful fuzzed manifest admission must create exactly one extension"
            );
        } else {
            prop_assert!(
                registry.list(None).is_empty(),
                "failed fuzzed manifest admission must not leave partial registry state"
            );
        }
    }
}

#[cfg(feature = "test-support")]
#[test]
fn signed_extension_registration_manifest_parser_corpus_fails_closed_without_echo() {
    let signing_key = extension_signing_key();
    let request = extension_request(
        "signed-extension-parser-corpus",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );

    let parsed =
        parse_signed_registration_manifest(&request.manifest_bytes).expect("canonical manifest");
    assert_eq!(
        parsed.schema_version,
        EXTENSION_REGISTRATION_MANIFEST_SCHEMA
    );
    assert_eq!(parsed.name, request.name);

    let mut unknown_field = exact_registration_manifest_value(&request);
    unknown_field
        .as_object_mut()
        .expect("manifest object")
        .insert(
            "unexpected".to_string(),
            Value::String("must-not-be-accepted".to_string()),
        );

    let mut wrong_version_shape = exact_registration_manifest_value(&request);
    wrong_version_shape
        .as_object_mut()
        .expect("manifest object")
        .insert(
            "initial_version".to_string(),
            Value::String("1.0.0".to_string()),
        );

    for (label, manifest_bytes) in [
        ("empty", Vec::new()),
        ("literal", b"not-json".to_vec()),
        (
            "unknown-field",
            serde_json::to_vec(&unknown_field).expect("unknown-field seed serializes"),
        ),
        (
            "wrong-version-shape",
            serde_json::to_vec(&wrong_version_shape).expect("wrong-version-shape seed serializes"),
        ),
    ] {
        let err = parse_signed_registration_manifest(&manifest_bytes).expect_err(label);
        assert_eq!(err, "invalid signed extension registration manifest");
        assert!(
            !err.contains(label),
            "parser error must not reflect malformed input label {label}: {err}"
        );
    }

    let mut wrong_schema = exact_registration_manifest_value(&request);
    wrong_schema
        .as_object_mut()
        .expect("manifest object")
        .insert(
            "schema_version".to_string(),
            Value::String("evil\nschema".to_string()),
        );
    let err = parse_signed_registration_manifest(
        &serde_json::to_vec(&wrong_schema).expect("wrong-schema seed serializes"),
    )
    .expect_err("wrong schema");
    assert_eq!(
        err,
        "unsupported signed extension registration manifest schema"
    );
    assert!(
        !err.contains("evil"),
        "schema rejection must not echo attacker-controlled schema"
    );
}

#[test]
fn signed_extension_registration_version_entry_corpus_rejects_before_admission() {
    let signing_key = extension_signing_key();

    let mut max_version_request = extension_request(
        "signed-extension-max-version",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    max_version_request.initial_version.version = "18446744073709551615.0.0".to_string();
    resign_extension_request(&signing_key, &mut max_version_request);
    let mut registry = extension_registry(&signing_key);
    let result = registry.register(
        max_version_request,
        &format!("{TRACE_ID}-max-version"),
        EXTENSION_NOW_EPOCH,
    );
    assert!(
        result.success,
        "u64::MAX major version remains a valid numeric boundary: {:?} {}",
        result.error_code, result.detail
    );
    assert_eq!(registry.list(None).len(), 1);

    for (suffix, version, expected_detail) in [
        ("empty-version", "", "non-empty version"),
        ("partial-version", "1.2", "numeric major.minor.patch"),
        ("extra-component", "1.2.3.4", "numeric major.minor.patch"),
        ("control-character", "1.2.3\n", "numeric major.minor.patch"),
        ("prefix-version", "v1.2.3", "numeric major.minor.patch"),
        ("negative-version", "1.-2.3", "numeric major.minor.patch"),
        ("alpha-version", "1.2.x", "numeric major.minor.patch"),
        (
            "u64-overflow",
            "18446744073709551616.0.0",
            "numeric major.minor.patch",
        ),
    ] {
        let mut request = extension_request(
            &format!("signed-extension-{suffix}"),
            &signing_key,
            EXTENSION_NOW_EPOCH,
        );
        request.initial_version.version = version.to_string();
        assert_invalid_extension_version_request(
            &signing_key,
            request,
            suffix,
            "initial_version.version",
            expected_detail,
        );
    }

    let mut overlong = extension_request(
        "signed-extension-overlong-version",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    overlong.initial_version.version = "1".repeat(129);
    assert_invalid_extension_version_request(
        &signing_key,
        overlong,
        "overlong-version",
        "initial_version.version",
        "Version too long",
    );

    let mut bad_parent = extension_request(
        "signed-extension-bad-parent",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    bad_parent.initial_version.parent_version = Some("1.2.x".to_string());
    assert_invalid_extension_version_request(
        &signing_key,
        bad_parent,
        "bad-parent",
        "initial_version.parent_version",
        "Parent version must use numeric major.minor.patch form",
    );

    let mut bad_hash = extension_request(
        "signed-extension-bad-hash",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    bad_hash.initial_version.content_hash = "g".repeat(64);
    assert_invalid_extension_version_request(
        &signing_key,
        bad_hash,
        "bad-hash",
        "initial_version.content_hash",
        "64 hex characters",
    );

    let mut overlong_registered_at = extension_request(
        "signed-extension-overlong-registered-at",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    overlong_registered_at.initial_version.registered_at = "r".repeat(65);
    assert_invalid_extension_version_request(
        &signing_key,
        overlong_registered_at,
        "overlong-registered-at",
        "initial_version.registered_at",
        "Version registration timestamp too long",
    );

    let mut empty_compatibility = extension_request(
        "signed-extension-empty-compatibility",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    empty_compatibility.initial_version.compatible_with = vec![String::new()];
    assert_invalid_extension_version_request(
        &signing_key,
        empty_compatibility,
        "empty-compatibility",
        "initial_version.compatible_with[0]",
        "Compatibility marker must be non-empty",
    );

    let mut too_many_compatibility = extension_request(
        "signed-extension-too-many-compatibility",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    too_many_compatibility.initial_version.compatible_with =
        (0..33).map(|index| format!("runtime-{index}")).collect();
    assert_invalid_extension_version_request(
        &signing_key,
        too_many_compatibility,
        "too-many-compatibility",
        "initial_version.compatible_with",
        "Too many compatibility markers",
    );
}

#[test]
fn signed_extension_registration_manifest_rejects_embedded_signature_field_after_outer_signature() {
    let signing_key = extension_signing_key();
    let request = extension_request(
        "signed-extension-embedded-signature",
        &signing_key,
        EXTENSION_NOW_EPOCH,
    );
    let mut manifest = exact_registration_manifest_value(&request);
    manifest
        .as_object_mut()
        .expect("manifest must be an object")
        .insert(
            "signature".to_string(),
            serde_json::json!({
                "algorithm": "ed25519",
                "value": "replayed-inner-signature-envelope"
            }),
        );

    let (registry, result) = register_with_manifest_bytes(
        &signing_key,
        request,
        serde_json::to_vec(&manifest).expect("manifest value serializes"),
        "embedded-signature",
    );

    assert!(!result.success, "embedded signature field must fail closed");
    assert_eq!(
        result.error_code.as_deref(),
        Some(event_codes::SER_ERR_INVALID_INPUT)
    );
    assert!(result.extension_id.is_none());
    assert!(
        registry.list(None).is_empty(),
        "embedded signature field must not register an extension"
    );

    let receipt = registry
        .admission_receipts()
        .last()
        .expect("outer signature evaluation must persist a receipt");
    assert!(
        receipt.admitted,
        "outer signature may verify, but embedded signed-manifest data must still be rejected"
    );

    let audit = registry
        .audit_log()
        .last()
        .expect("parser rejection must emit an audit record");
    assert_eq!(audit.event_code, event_codes::SER_ERR_INVALID_INPUT);
    assert_eq!(audit.details["field"], "manifest_bytes");
}

#[test]
fn conformance_replayed_signature_over_canonical_manifest_rejected() {
    let signing_key = extension_signing_key();
    let source_name = "signed-extension-replay-source";
    let target_name = "signed-extension-replay-target";
    let trace_id = Uuid::now_v7().to_string();

    let mut source_registry = extension_registry(&signing_key);
    let source_request = extension_request(source_name, &signing_key, EXTENSION_NOW_EPOCH);
    let replayed_signature = source_request.signature.clone();
    let source_result = source_registry.register(source_request, &trace_id, EXTENSION_NOW_EPOCH);

    assert!(
        source_result.success,
        "baseline signed source manifest must be admitted before replay check: {:?}",
        source_result.error_code
    );
    assert!(
        source_registry.query_by_name(source_name).is_some(),
        "baseline signed source manifest must remain queryable"
    );

    let mut target_request = extension_request(target_name, &signing_key, EXTENSION_NOW_EPOCH);
    target_request.signature = replayed_signature;

    let mut replay_registry = extension_registry(&signing_key);
    let result = replay_registry.register(target_request, &trace_id, EXTENSION_NOW_EPOCH);

    assert!(!result.success, "replayed signature must fail closed");
    assert_eq!(
        result.error_code.as_deref(),
        Some(event_codes::SER_ERR_INVALID_SIGNATURE)
    );
    assert!(
        result.extension_id.is_none(),
        "replayed signature must not return an extension_id"
    );
    assert!(
        replay_registry.list(None).is_empty(),
        "replayed signature must not mutate the registry"
    );
    assert!(
        replay_registry.query_by_name(target_name).is_none(),
        "replayed signature must not make the forged target queryable"
    );

    let receipt = replay_registry
        .admission_receipts()
        .last()
        .expect("replayed signature rejection must persist a receipt");
    assert!(!receipt.admitted);
    assert_eq!(receipt.extension_name, target_name);
    let witness = receipt
        .witness
        .as_ref()
        .expect("replayed signature rejection must carry a negative witness");
    assert_eq!(
        witness.rejection_code,
        event_codes::SER_ERR_INVALID_SIGNATURE
    );
    assert_eq!(
        witness.checked_fields,
        vec![
            "signature.signature_bytes".to_string(),
            "manifest_bytes".to_string(),
        ]
    );

    let audit_events: Vec<_> = replay_registry
        .audit_log()
        .iter()
        .map(|record| record.event_code.as_str())
        .collect();
    assert_eq!(
        audit_events,
        vec![
            event_codes::SER_ADMISSION_EVALUATED,
            event_codes::SER_ERR_INVALID_SIGNATURE,
        ]
    );
}

/// Variant (a): tamper scope claims (capability_declarations + risk score)
/// while keeping the original signature. The card_hash recomputation in the
/// verifier must catch the divergence.
#[test]
fn rejects_tampered_scope_claims_with_original_signature() {
    let mut card = mint_legitimate_card();
    let original_hash = card.card_hash.clone();
    let original_signature = card.registry_signature.clone();

    // Attacker escalates capability surface and risk score in-place.
    card.capability_declarations.push(CapabilityDeclaration {
        name: "filesystem.write".to_string(),
        description: "Forged: arbitrary disk write".to_string(),
        risk: CapabilityRisk::High,
    });
    card.reputation_score_basis_points = 9_500;
    card.behavioral_profile.filesystem_access = true;
    card.behavioral_profile.subprocess_access = true;

    // The attacker leaves card_hash + registry_signature untouched, betting the
    // verifier doesn't recompute the canonical hash.
    assert_eq!(
        card.card_hash, original_hash,
        "attacker preserves stale card_hash to bypass tamper detection"
    );
    assert_eq!(
        card.registry_signature, original_signature,
        "attacker preserves stale registry_signature to bypass tamper detection"
    );

    let err = verify_card_signature(&card, LEGITIMATE_KEY)
        .expect_err("tampered scope claims must be rejected by the verifier");
    assert!(
        matches!(err, TrustCardError::CardHashMismatch(ref ext_id)
            if extension_id_matches(ext_id, &card.extension.extension_id)),
        "expected CardHashMismatch for tampered scope claims, got {err:?}"
    );
}

/// Variant (b): attacker tampers the card AND re-signs with their own key. The
/// card now has internally-consistent (hash, signature) under the attacker
/// key, so the hash check passes — the verifier must catch this at the HMAC
/// step against the legitimate key.
#[test]
fn rejects_re_signed_card_under_attacker_key() {
    let mut card = mint_legitimate_card();

    // Attacker escalates capability surface, then re-signs the tampered card
    // under their own HMAC key.
    card.capability_declarations.push(CapabilityDeclaration {
        name: "subprocess.exec".to_string(),
        description: "Forged: arbitrary subprocess execution".to_string(),
        risk: CapabilityRisk::High,
    });
    card.reputation_score_basis_points = 9_999;
    forge_signed_card(&mut card, ATTACKER_KEY);

    // Sanity: the forged card is internally consistent under the attacker key.
    let recomputed = compute_card_hash(&card).expect("recompute forged card hash");
    assert_eq!(
        card.card_hash, recomputed,
        "attacker-resigned card must have a consistent hash before rejection check"
    );
    verify_card_signature(&card, ATTACKER_KEY).expect(
        "sanity: attacker-resigned card verifies under the ATTACKER key — \
         this is the boundary case the verifier must catch when checked under the legitimate key",
    );

    // The MR: the same forged card MUST be rejected by the legitimate
    // verifier, with a SignatureInvalid (not CardHashMismatch — the hash
    // matches the tampered content; the signature is the part the legitimate
    // key disowns).
    let err = verify_card_signature(&card, LEGITIMATE_KEY)
        .expect_err("re-signed forgery under attacker key must be rejected by legitimate verifier");
    assert!(
        matches!(err, TrustCardError::SignatureInvalid(ref ext_id)
            if extension_id_matches(ext_id, &card.extension.extension_id)),
        "expected SignatureInvalid for attacker-key re-sign, got {err:?}"
    );
}

/// Variant (c): attacker extends the card's freshness/TTL claim by pushing
/// `last_verified_timestamp` (and the matching most-recent audit-history
/// entry) into the future without re-signing. The verifier must detect the
/// canonical-hash divergence even though the attacker only touched
/// freshness-bearing fields.
#[test]
fn rejects_extended_freshness_window_without_resigning() {
    let mut card = mint_legitimate_card();

    // Attacker pushes the freshness window forward by one year.
    card.last_verified_timestamp = "2027-01-01T00:00:00Z".to_string();
    if let Some(latest_audit) = card.audit_history.last_mut() {
        latest_audit.timestamp = "2027-01-01T00:00:00Z".to_string();
    }

    let err = verify_card_signature(&card, LEGITIMATE_KEY).expect_err(
        "extended freshness/TTL claim must be rejected — verifier must hash all signed fields",
    );
    assert!(
        matches!(err, TrustCardError::CardHashMismatch(ref ext_id)
            if extension_id_matches(ext_id, &card.extension.extension_id)),
        "expected CardHashMismatch for extended freshness claim, got {err:?}"
    );
}

/// Registry-ingestion path: a snapshot containing any of the forged variants
/// must fail at `from_snapshot`. This guards the boundary where forged cards
/// could be smuggled in via a poisoned snapshot file rather than discovered
/// in-memory.
#[test]
fn registry_ingestion_rejects_forged_card_in_snapshot() {
    // Build a legitimate registry containing one card, snapshot it, then
    // tamper with the embedded card before re-presenting the snapshot to
    // `from_snapshot`. The snapshot signature itself remains untouched, so the
    // ingestion path must catch the embedded forgery via per-card validation
    // before (or independent of) the snapshot signature check.
    let mut registry = TrustCardRegistry::new(CACHE_TTL_SECS, LEGITIMATE_KEY);
    let card = registry
        .create(legitimate_input(), NOW_SECS, TRACE_ID)
        .expect("legitimate card creation");
    let mut snapshot = registry.snapshot().expect("legitimate snapshot");

    // Tamper the embedded card's scope claims without re-signing the card.
    let history = snapshot
        .cards_by_extension
        .get_mut(&card.extension.extension_id)
        .expect("extension bucket must exist after create");
    let latest = history
        .last_mut()
        .expect("snapshot bucket has at least one card");
    latest.reputation_score_basis_points = 9_999;

    // Ingestion under the legitimate key must reject the snapshot. The exact
    // error variant depends on whether the ingestion path validates per-card
    // hashes or the snapshot signature first; both paths are fail-closed.
    let err = TrustCardRegistry::from_snapshot(snapshot, LEGITIMATE_KEY, NOW_SECS)
        .expect_err("snapshot ingestion must reject embedded forged card");
    let acceptable = matches!(
        err,
        TrustCardError::CardHashMismatch(_)
            | TrustCardError::SignatureInvalid(_)
            | TrustCardError::InvalidSnapshot(_)
    );
    assert!(
        acceptable,
        "expected CardHashMismatch / SignatureInvalid / InvalidSnapshot from \
         from_snapshot for embedded forged card, got {err:?}"
    );
}

/// Cross-card consistency: a card minted under the legitimate key must NOT
/// verify under the attacker key. This is the symmetry partner of variant
/// (b) — keys must not be interchangeable.
#[test]
fn legitimate_card_does_not_verify_under_attacker_key() {
    let card = mint_legitimate_card();
    let err = verify_card_signature(&card, ATTACKER_KEY)
        .expect_err("legitimate card must not verify under attacker key");
    assert!(
        matches!(err, TrustCardError::SignatureInvalid(_)),
        "expected SignatureInvalid for legitimate card under attacker key, got {err:?}"
    );
}

/// Defensive: an empty BTreeMap snapshot signed with the attacker key should
/// fail ingestion under the legitimate key, even though there are no cards to
/// validate per-card. This protects against a future regression where an
/// empty snapshot bypasses signature checks.
#[test]
fn empty_snapshot_signed_by_attacker_key_is_rejected() {
    let attacker_snapshot =
        TrustCardRegistrySnapshot::signed(CACHE_TTL_SECS, BTreeMap::new(), ATTACKER_KEY)
            .expect("attacker can self-sign empty snapshot under their own key");

    let err = TrustCardRegistry::from_snapshot(attacker_snapshot, LEGITIMATE_KEY, NOW_SECS)
        .expect_err("attacker-signed empty snapshot must be rejected by legitimate ingestion");
    assert!(
        matches!(
            err,
            TrustCardError::SignatureInvalid(_) | TrustCardError::InvalidSnapshot(_)
        ),
        "expected SignatureInvalid or InvalidSnapshot for attacker-signed empty snapshot, got {err:?}"
    );
}
