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
use frankenengine_node::supply_chain::{
    artifact_signing::{self, KeyId, KeyRing},
    certification::{EvidenceType, VerifiedEvidenceRef},
    extension_registry::{
        AdmissionKernel, ExtensionSignature, RegistrationRequest, RegistryConfig,
        SignedExtensionRegistry, VersionEntry, canonical_registration_manifest_bytes, event_codes,
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

/// Sanity check: a legitimately-minted card must verify under the legitimate
/// key. If this baseline ever fails, every subsequent rejection assertion is
/// meaningless.
#[test]
fn baseline_legitimate_card_verifies() {
    let card = mint_legitimate_card();
    verify_card_signature(&card, LEGITIMATE_KEY)
        .expect("baseline: legitimately-signed card must verify under legitimate key");
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
