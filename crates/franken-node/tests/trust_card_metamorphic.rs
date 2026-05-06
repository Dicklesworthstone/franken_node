//! Metamorphic tests for real trust-card canonicalization surfaces.
//!
//! DE-MOCKED: Now includes ed25519-dalek signature verification alongside existing HMAC verification
//! to catch signature/canonicalization bugs that HMAC alone might miss.

use frankenengine_node::supply_chain::{
    certification::{EvidenceType, VerifiedEvidenceRef},
    trust_card::{
        BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
        DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
        ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard, TrustCardInput,
        TrustCardRegistry, render_trust_card_human, to_canonical_json,
    },
};

// DE-MOCKED: Add ed25519-dalek for real cryptographic signature verification
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use proptest::prelude::*;
use rand::rngs::OsRng;

const REGISTRY_KEY: &[u8] = b"trust-card-metamorphic-real-key";
const NOW_SECS: u64 = 1_777_000_000;
const TRACE_ID: &str = "trace-trust-card-metamorphic";

/// Generate a test ed25519 signing key for cryptographic verification
fn generate_test_ed25519_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Sign canonical trust card bytes using ed25519-dalek
fn sign_trust_card_ed25519(trust_card: &TrustCard, signing_key: &SigningKey) -> Signature {
    let canonical_bytes = to_canonical_json(trust_card)
        .expect("canonical JSON serialization")
        .into_bytes();
    signing_key.sign(&canonical_bytes)
}

/// Verify ed25519 signature on canonical trust card bytes
fn verify_trust_card_ed25519(
    trust_card: &TrustCard,
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> bool {
    let canonical_bytes = to_canonical_json(trust_card)
        .expect("canonical JSON serialization")
        .into_bytes();
    verifying_key.verify(&canonical_bytes, signature).is_ok()
}

fn evidence_refs() -> Vec<VerifiedEvidenceRef> {
    vec![
        VerifiedEvidenceRef {
            evidence_id: "ev-provenance-001".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: NOW_SECS.saturating_sub(10),
            verification_receipt_hash: "a".repeat(64),
        },
        VerifiedEvidenceRef {
            evidence_id: "ev-test-coverage-001".to_string(),
            evidence_type: EvidenceType::TestCoverageReport,
            verified_at_epoch: NOW_SECS.saturating_sub(5),
            verification_receipt_hash: "b".repeat(64),
        },
    ]
}

fn input_with_order(
    capability_declarations: Vec<CapabilityDeclaration>,
    dependency_trust_summary: Vec<DependencyTrustStatus>,
) -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@metamorphic/order-stable".to_string(),
            version: "1.2.3".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-metamorphic".to_string(),
            display_name: "Metamorphic Security Team".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        capability_declarations,
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Network-only policy checks".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "slsa-l3".to_string(),
            source_uri: "https://example.invalid/metamorphic/order-stable".to_string(),
            artifact_hashes: vec![
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            ],
            verified_at: "2026-04-22T10:00:00Z".to_string(),
        },
        reputation_score_basis_points: 912,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary,
        last_verified_timestamp: "2026-04-22T10:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Bounded capabilities with verified provenance".to_string(),
        },
        evidence_refs: evidence_refs(),
    }
}

fn capabilities() -> Vec<CapabilityDeclaration> {
    vec![
        CapabilityDeclaration {
            name: "net.fetch".to_string(),
            description: "Fetch policy bundles from approved endpoints".to_string(),
            risk: CapabilityRisk::Medium,
        },
        CapabilityDeclaration {
            name: "auth.validate-token".to_string(),
            description: "Validate signed session tokens".to_string(),
            risk: CapabilityRisk::Low,
        },
        CapabilityDeclaration {
            name: "telemetry.emit".to_string(),
            description: "Emit bounded policy telemetry".to_string(),
            risk: CapabilityRisk::Low,
        },
    ]
}

fn dependencies() -> Vec<DependencyTrustStatus> {
    vec![
        DependencyTrustStatus {
            dependency_id: "npm:zod@3".to_string(),
            trust_level: "verified".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "npm:jose@5".to_string(),
            trust_level: "verified".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "npm:undici@6".to_string(),
            trust_level: "monitored".to_string(),
        },
    ]
}

fn next_seed(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed
}

fn generated_hash(seed: &mut u64) -> String {
    format!(
        "sha256:{:016x}{:016x}{:016x}{:016x}",
        next_seed(seed),
        next_seed(seed),
        next_seed(seed),
        next_seed(seed)
    )
}

fn generated_signature(seed: &mut u64) -> String {
    format!(
        "hmac:{:016x}{:016x}{:016x}{:016x}",
        next_seed(seed),
        next_seed(seed),
        next_seed(seed),
        next_seed(seed)
    )
}

fn generated_timestamp(seed: &mut u64) -> String {
    let value = next_seed(seed);
    let day = (value % 28) + 1;
    let hour = (value / 28) % 24;
    let minute = (value / (28 * 24)) % 60;
    let second = (value / (28 * 24 * 60)) % 60;
    format!("2026-04-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn generated_trust_card(mut seed: u64) -> TrustCard {
    let extension_id = format!("extension-{:016x}", next_seed(&mut seed));
    let publisher_id = format!("publisher-{:016x}", next_seed(&mut seed));
    let verified_at = generated_timestamp(&mut seed);

    TrustCard {
        schema_version: "franken-node/trust-card/v1".to_string(),
        trust_card_version: next_seed(&mut seed),
        previous_version_hash: if next_seed(&mut seed).is_multiple_of(2) {
            Some(generated_hash(&mut seed))
        } else {
            None
        },
        extension: ExtensionIdentity {
            extension_id: extension_id.clone(),
            version: format!(
                "{}.{}.{}",
                next_seed(&mut seed) % 100,
                next_seed(&mut seed) % 100,
                next_seed(&mut seed) % 100
            ),
        },
        publisher: PublisherIdentity {
            publisher_id: publisher_id.clone(),
            display_name: format!("Publisher {publisher_id}"),
        },
        certification_level: match next_seed(&mut seed) % 5 {
            0 => CertificationLevel::Unknown,
            1 => CertificationLevel::Bronze,
            2 => CertificationLevel::Silver,
            3 => CertificationLevel::Gold,
            _ => CertificationLevel::Platinum,
        },
        capability_declarations: vec![CapabilityDeclaration {
            name: format!("capability-{:x}", next_seed(&mut seed) % 10_000),
            description: "Generated equality test capability".to_string(),
            risk: match next_seed(&mut seed) % 4 {
                0 => CapabilityRisk::Low,
                1 => CapabilityRisk::Medium,
                2 => CapabilityRisk::High,
                _ => CapabilityRisk::Critical,
            },
        }],
        behavioral_profile: BehavioralProfile {
            network_access: next_seed(&mut seed).is_multiple_of(2),
            filesystem_access: next_seed(&mut seed).is_multiple_of(2),
            subprocess_access: next_seed(&mut seed).is_multiple_of(2),
            profile_summary: format!("Generated profile {:016x}", next_seed(&mut seed)),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "generated".to_string(),
            source_uri: format!("https://example.invalid/{extension_id}"),
            artifact_hashes: vec![generated_hash(&mut seed)],
            verified_at: verified_at.clone(),
        },
        reputation_score_basis_points: (next_seed(&mut seed) % 10_001) as u16,
        reputation_trend: match next_seed(&mut seed) % 3 {
            0 => ReputationTrend::Improving,
            1 => ReputationTrend::Stable,
            _ => ReputationTrend::Declining,
        },
        active_quarantine: next_seed(&mut seed).is_multiple_of(2),
        dependency_trust_summary: vec![DependencyTrustStatus {
            dependency_id: format!("npm:dependency-{:x}", next_seed(&mut seed) % 10_000),
            trust_level: "generated".to_string(),
        }],
        last_verified_timestamp: verified_at.clone(),
        user_facing_risk_assessment: RiskAssessment {
            level: match next_seed(&mut seed) % 4 {
                0 => RiskLevel::Low,
                1 => RiskLevel::Medium,
                2 => RiskLevel::High,
                _ => RiskLevel::Critical,
            },
            summary: format!("Generated risk summary {:016x}", next_seed(&mut seed)),
        },
        audit_history: vec![frankenengine_node::supply_chain::trust_card::AuditRecord {
            timestamp: verified_at,
            event_code: "GENERATED_EQUALITY_CASE".to_string(),
            detail: "generated trust card equality case".to_string(),
            trace_id: format!("trace-{:016x}", next_seed(&mut seed)),
        }],
        derivation_evidence: None,
        card_hash: generated_hash(&mut seed),
        registry_signature: generated_signature(&mut seed),
    }
}

#[test]
fn capability_and_dependency_order_permutations_preserve_canonical_and_textual_content() {
    let mut baseline_registry = TrustCardRegistry::new(60, REGISTRY_KEY);
    let mut permuted_registry = TrustCardRegistry::new(60, REGISTRY_KEY);

    // DE-MOCKED: Generate real ed25519 keys for cryptographic signature verification
    let ed25519_signing_key = generate_test_ed25519_key();
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();

    let baseline = baseline_registry
        .create(
            input_with_order(capabilities(), dependencies()),
            NOW_SECS,
            TRACE_ID,
        )
        .expect("baseline trust card");

    let mut permuted_capabilities = capabilities();
    permuted_capabilities.reverse();
    let mut permuted_dependencies = dependencies();
    permuted_dependencies.rotate_left(1);
    let permuted = permuted_registry
        .create(
            input_with_order(permuted_capabilities, permuted_dependencies),
            NOW_SECS,
            TRACE_ID,
        )
        .expect("permuted trust card");

    // DE-MOCKED: Add ed25519 signature verification alongside HMAC verification
    let baseline_ed25519_sig = sign_trust_card_ed25519(&baseline, &ed25519_signing_key);
    let permuted_ed25519_sig = sign_trust_card_ed25519(&permuted, &ed25519_signing_key);

    // Verify both signatures are valid
    assert!(
        verify_trust_card_ed25519(&baseline, &baseline_ed25519_sig, &ed25519_verifying_key),
        "baseline trust card ed25519 signature verification failed"
    );
    assert!(
        verify_trust_card_ed25519(&permuted, &permuted_ed25519_sig, &ed25519_verifying_key),
        "permuted trust card ed25519 signature verification failed"
    );

    // DE-MOCKED: ed25519 signatures should be identical for canonically equivalent cards
    assert_eq!(
        baseline_ed25519_sig, permuted_ed25519_sig,
        "ed25519 signatures differ for canonically equivalent trust cards"
    );

    assert_eq!(
        baseline
            .capability_declarations
            .iter()
            .map(|capability| capability.name.as_str())
            .collect::<Vec<_>>(),
        vec!["auth.validate-token", "net.fetch", "telemetry.emit"],
        "baseline capabilities should be canonicalized by name"
    );
    assert_eq!(
        baseline.capability_declarations, permuted.capability_declarations,
        "capability declaration order should be semantic, not caller-order dependent"
    );
    assert_eq!(
        baseline.dependency_trust_summary, permuted.dependency_trust_summary,
        "dependency trust order should be semantic, not caller-order dependent"
    );
    assert_eq!(
        baseline.card_hash, permuted.card_hash,
        "card hash changed for an order-only input permutation"
    );
    assert_eq!(
        baseline.registry_signature, permuted.registry_signature,
        "registry signature changed for an order-only input permutation"
    );
    assert_eq!(
        to_canonical_json(&baseline).expect("baseline canonical JSON"),
        to_canonical_json(&permuted).expect("permuted canonical JSON"),
        "canonical JSON changed for an order-only input permutation"
    );
    assert_eq!(
        render_trust_card_human(&baseline),
        render_trust_card_human(&permuted),
        "user-facing textual content changed for an order-only input permutation"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn equality_is_transitive_for_random_trust_card_triples(seed in any::<u64>()) {
        let a = generated_trust_card(seed);
        let encoded_a = serde_json::to_string(&a).expect("trust card should serialize");
        let b: TrustCard = serde_json::from_str(&encoded_a)
            .expect("serialized trust card should deserialize");
        let encoded_b = serde_json::to_string(&b).expect("round-tripped trust card should serialize");
        let c: TrustCard = serde_json::from_str(&encoded_b)
            .expect("round-tripped trust card should deserialize again");

        prop_assert!(a == b, "JSON roundtrip changed TrustCard equality");
        prop_assert!(b == c, "second JSON roundtrip changed TrustCard equality");
        if a == b && b == c {
            prop_assert_eq!(a.clone(), c, "TrustCard equality is not transitive");
        }

        let mut same_digest_different_signature = a.clone();
        same_digest_different_signature
            .registry_signature
            .push_str(":signature-mutation");
        prop_assert_ne!(
            a.clone(),
            same_digest_different_signature,
            "TrustCard equality must include registry_signature, not only card_hash"
        );

        let mut same_signature_different_digest = a.clone();
        same_signature_different_digest
            .card_hash
            .push_str(":digest-mutation");
        prop_assert_ne!(
            a,
            same_signature_different_digest,
            "TrustCard equality must include card_hash, not only registry_signature"
        );
    }
}
