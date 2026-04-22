//! Metamorphic testing for canonical serializer idempotence property
//!
//! Tests the fundamental property: canonicalize(canonicalize(x)) == canonicalize(x)
//!
//! If this property fails, the canonical serializer is not actually producing
//! canonical form, which would break deterministic serialization requirements.

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::trust_card::{
    to_canonical_json, TrustCard, TrustCardInput, ExtensionIdentity, PublisherIdentity,
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, RiskLevel, ProvenanceSummary,
    ReputationTrend, RevocationStatus, RiskAssessment, CertificationLevel,
    DependencyTrustStatus, AuditRecord,
};
use frankenengine_node::supply_chain::certification::{VerifiedEvidenceRef, EvidenceType};
use serde_json::{Value, Map};
use std::collections::BTreeMap;

/// Arbitrary implementation for generating diverse JSON structures to test canonicalization
#[derive(Debug, Clone, Arbitrary)]
enum ArbitraryJsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<ArbitraryJsonValue>),
    Object(Vec<(String, ArbitraryJsonValue)>),
}

impl ArbitraryJsonValue {
    fn to_json_value(self) -> Value {
        match self {
            ArbitraryJsonValue::Null => Value::Null,
            ArbitraryJsonValue::Bool(b) => Value::Bool(b),
            ArbitraryJsonValue::Number(n) => {
                // Ensure finite numbers for valid JSON
                if n.is_finite() {
                    serde_json::Number::from_f64(n).map(Value::Number).unwrap_or(Value::Null)
                } else {
                    Value::Null
                }
            }
            ArbitraryJsonValue::String(s) => Value::String(s),
            ArbitraryJsonValue::Array(items) => {
                Value::Array(items.into_iter().map(|x| x.to_json_value()).collect())
            }
            ArbitraryJsonValue::Object(pairs) => {
                let mut map = Map::new();
                for (key, value) in pairs {
                    map.insert(key, value.to_json_value());
                }
                Value::Object(map)
            }
        }
    }
}

/// Generate arbitrary trust card data for testing
#[derive(Debug, Arbitrary)]
struct ArbitraryTrustCardData {
    extension_id: String,
    version: String,
    publisher_name: String,
    publisher_url: String,
    description: String,
    repository_url: String,
    homepage_url: String,
    risk_level: u8, // 0-4 for RiskLevel variants
    certification_level: u8, // 0-4 for CertificationLevel variants
    trust_card_version: u64,
    reputation_score_basis_points: u16,
    card_hash: String,
    registry_signature: String,
    evidence_count: u8, // 0-5 for number of evidence refs
}

impl ArbitraryTrustCardData {
    fn to_trust_card_input(self) -> TrustCardInput {
        let risk_levels = [
            RiskLevel::VeryLow,
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];

        let evidence_types = [
            EvidenceType::ProvenanceChain,
            EvidenceType::ReputationSignal,
            EvidenceType::SecurityAudit,
            EvidenceType::ComplianceAttestation,
            EvidenceType::IntegrationTest,
        ];

        let evidence_refs: Vec<VerifiedEvidenceRef> = (0..self.evidence_count.min(5))
            .map(|i| VerifiedEvidenceRef {
                evidence_id: format!("evidence-{}-{}", self.extension_id, i),
                evidence_type: evidence_types[i as usize % evidence_types.len()],
                verified_at_epoch: 1000 + i as u64,
                verification_receipt_hash: format!("{:064x}", i as u64),
            })
            .collect();

        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: self.extension_id,
                version: self.version,
            },
            publisher: PublisherIdentity {
                publisher_name: self.publisher_name,
                publisher_url: self.publisher_url,
            },
            certification_level: CertificationLevel::Bronze,
            capability_declarations: vec![CapabilityDeclaration {
                capability_risk: CapabilityRisk {
                    risk_level: risk_levels[self.risk_level as usize % risk_levels.len()],
                    mitigation_summary: "Automated testing and code review".to_string(),
                },
            }],
            behavioral_profile: BehavioralProfile {
                description: self.description,
                repository_url: self.repository_url,
                homepage_url: self.homepage_url,
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: ProvenanceSummary {
                attestation_level: "verified".to_string(),
                source_uri: format!("https://github.com/{}", self.extension_id),
                artifact_hashes: vec![format!("sha256:{:064x}", self.trust_card_version)],
                verified_at: "2026-04-21T16:00:00Z".to_string(),
            },
            reputation_score_basis_points: self.reputation_score_basis_points,
            reputation_trend: ReputationTrend::Stable,
            active_quarantine: false,
            dependency_trust_summary: vec![DependencyTrustStatus {
                dependency_id: "test-dependency".to_string(),
                trust_level: "trusted".to_string(),
            }],
            last_verified_timestamp: "2026-04-21T16:00:00Z".to_string(),
            user_facing_risk_assessment: RiskAssessment {
                overall_risk_score: 2.5,
                risk_factors: vec!["Third-party dependencies".to_string()],
                mitigation_strategies: vec!["Regular security updates".to_string()],
            },
            evidence_refs,
        }
    }

    fn to_trust_card(self) -> TrustCard {
        let certification_levels = [
            CertificationLevel::Unknown,
            CertificationLevel::Bronze,
            CertificationLevel::Silver,
            CertificationLevel::Gold,
            CertificationLevel::Platinum,
        ];

        let input = self.to_trust_card_input();
        TrustCard {
            schema_version: "1.0".to_string(),
            trust_card_version: self.trust_card_version,
            previous_version_hash: None,
            extension: input.extension,
            publisher: input.publisher,
            certification_level: certification_levels[self.certification_level as usize % certification_levels.len()],
            capability_declarations: input.capability_declarations,
            behavioral_profile: input.behavioral_profile,
            revocation_status: input.revocation_status,
            provenance_summary: input.provenance_summary,
            reputation_score_basis_points: self.reputation_score_basis_points,
            reputation_trend: input.reputation_trend,
            active_quarantine: input.active_quarantine,
            dependency_trust_summary: vec![DependencyTrustStatus {
                dependency_id: "test-dependency".to_string(),
                trust_level: "trusted".to_string(),
            }],
            last_verified_timestamp: input.last_verified_timestamp,
            user_facing_risk_assessment: input.user_facing_risk_assessment,
            audit_history: Vec::new(),
            derivation_evidence: None,
            card_hash: self.card_hash,
            registry_signature: self.registry_signature,
        }
    }
}

/// Test the fundamental idempotence property of canonical serialization
#[test]
fn canonical_serializer_idempotence_property() {
    // Use proptest-style testing with a reasonable number of cases
    for i in 0..100 {
        let seed = i as u64;
        let seed_bytes = seed.to_le_bytes().repeat(100);
        let mut unstructured = arbitrary::Unstructured::new(&seed_bytes);

        // Generate arbitrary JSON value
        if let Ok(arbitrary_json) = ArbitraryJsonValue::arbitrary(&mut unstructured) {
            let json_value = arbitrary_json.to_json_value();

            // Test idempotence: canonicalize(canonicalize(x)) == canonicalize(x)
            if let (Ok(first_canonical), Ok(second_canonical)) = (
                to_canonical_json(&json_value),
                to_canonical_json(&json_value).and_then(|s| {
                    let parsed: Value = serde_json::from_str(&s).unwrap();
                    to_canonical_json(&parsed)
                })
            ) {
                assert_eq!(
                    first_canonical,
                    second_canonical,
                    "Canonical serialization idempotence violated for JSON value at seed {}:
                     Original: {:?}
                     First canonicalization: {}
                     Second canonicalization: {}",
                    seed,
                    json_value,
                    first_canonical,
                    second_canonical
                );
            }
        }

        // Generate arbitrary trust card
        if let Ok(arbitrary_card_data) = ArbitraryTrustCardData::arbitrary(&mut unstructured) {
            let trust_card = arbitrary_card_data.to_trust_card();

            // Test idempotence for trust card serialization
            if let (Ok(first_canonical), Ok(second_canonical)) = (
                to_canonical_json(&trust_card),
                to_canonical_json(&trust_card).and_then(|s| {
                    let parsed_card: TrustCard = serde_json::from_str(&s).unwrap();
                    to_canonical_json(&parsed_card)
                })
            ) {
                assert_eq!(
                    first_canonical,
                    second_canonical,
                    "Trust card canonical serialization idempotence violated at seed {}:
                     First canonicalization: {}
                     Second canonicalization: {}",
                    seed,
                    first_canonical,
                    second_canonical
                );
            }
        }
    }
}

/// Test canonical serialization preserves semantic equivalence
#[test]
fn canonical_serialization_preserves_semantics() {
    for i in 0..50 {
        let seed = i as u64;
        let seed_bytes = seed.to_le_bytes().repeat(100);
        let mut unstructured = arbitrary::Unstructured::new(&seed_bytes);

        if let Ok(arbitrary_card_data) = ArbitraryTrustCardData::arbitrary(&mut unstructured) {
            let original_card = arbitrary_card_data.to_trust_card();

            if let Ok(canonical_json) = to_canonical_json(&original_card) {
                // Parse the canonical JSON back to a TrustCard
                if let Ok(recovered_card) = serde_json::from_str::<TrustCard>(&canonical_json) {
                    // The recovered card should be semantically equivalent to the original
                    assert_eq!(original_card.extension.extension_id, recovered_card.extension.extension_id);
                    assert_eq!(original_card.trust_card_version, recovered_card.trust_card_version);
                    assert_eq!(original_card.certification_level, recovered_card.certification_level);
                    assert_eq!(original_card.reputation_score_basis_points, recovered_card.reputation_score_basis_points);
                    assert_eq!(original_card.capability_declarations.len(), recovered_card.capability_declarations.len());

                    // Re-canonicalizing the recovered card should produce identical JSON
                    if let Ok(re_canonical) = to_canonical_json(&recovered_card) {
                        assert_eq!(
                            canonical_json,
                            re_canonical,
                            "Semantic equivalence after round-trip failed at seed {}",
                            seed
                        );
                    }
                }
            }
        }
    }
}

/// Test canonical serialization with pathological JSON structures
#[test]
fn canonical_serialization_handles_edge_cases() {
    let edge_cases = vec![
        // Empty structures
        serde_json::json!({}),
        serde_json::json!([]),

        // Nested structures with key ordering challenges
        serde_json::json!({
            "z": "last",
            "a": "first",
            "m": {"nested_z": 1, "nested_a": 2},
            "b": [{"array_z": 3, "array_a": 4}]
        }),

        // Mixed data types
        serde_json::json!({
            "string": "value",
            "number": 42,
            "bool": true,
            "null": null,
            "array": [1, "two", false, null],
            "object": {"nested": "value"}
        }),

        // Large numbers and edge values
        serde_json::json!({
            "large_int": 9007199254740991i64, // Max safe integer in JSON
            "zero": 0,
            "negative": -123,
            "decimal": 3.14159
        }),

        // Unicode and special characters
        serde_json::json!({
            "unicode": "🔒 secure",
            "emoji_key_🔑": "value",
            "newlines": "line1\nline2",
            "quotes": "He said \"Hello\"",
            "backslash": "path\\to\\file"
        }),
    ];

    for (i, edge_case) in edge_cases.iter().enumerate() {
        if let (Ok(first_canonical), Ok(second_canonical)) = (
            to_canonical_json(edge_case),
            to_canonical_json(edge_case).and_then(|s| {
                let parsed: Value = serde_json::from_str(&s).unwrap();
                to_canonical_json(&parsed)
            })
        ) {
            assert_eq!(
                first_canonical,
                second_canonical,
                "Edge case {} failed idempotence test: {:?}",
                i,
                edge_case
            );
        }
    }
}

/// Test that key ordering is deterministic across multiple serializations
#[test]
fn canonical_serialization_key_ordering_stability() {
    // Create an object with keys that would be in different order if not canonicalized
    let test_object = serde_json::json!({
        "zebra": 1,
        "alpha": 2,
        "omega": 3,
        "beta": 4,
        "nested": {
            "zebra_nested": 5,
            "alpha_nested": 6
        }
    });

    // Serialize multiple times
    let serializations: Vec<String> = (0..10)
        .map(|_| to_canonical_json(&test_object).expect("serialization should succeed"))
        .collect();

    // All serializations should be identical
    for (i, serialization) in serializations.iter().enumerate() {
        assert_eq!(
            serializations[0],
            *serialization,
            "Key ordering not stable across serializations, iteration {} differs",
            i
        );
    }

    // The keys should appear in alphabetical order
    let canonical = &serializations[0];
    assert!(canonical.find("\"alpha\"").unwrap() < canonical.find("\"beta\"").unwrap());
    assert!(canonical.find("\"beta\"").unwrap() < canonical.find("\"omega\"").unwrap());
    assert!(canonical.find("\"omega\"").unwrap() < canonical.find("\"zebra\"").unwrap());

    // Nested keys should also be ordered
    assert!(canonical.find("\"alpha_nested\"").unwrap() < canonical.find("\"zebra_nested\"").unwrap());
}