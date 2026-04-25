//! Metamorphic testing for canonical serializer idempotence property
//!
//! Tests the fundamental property: canonicalize(canonicalize(x)) == canonicalize(x)
//!
//! If this property fails, the canonical serializer is not actually producing
//! canonical form, which would break deterministic serialization requirements.

use arbitrary::Arbitrary;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use frankenengine_node::connector::canonical_serializer::{CanonicalSerializer, TrustObjectType};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    to_canonical_json, BehavioralProfile, CapabilityDeclaration, CapabilityRisk,
    CertificationLevel, DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary,
    PublisherIdentity, ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard,
    TrustCardInput,
};
use proptest::prelude::*;
use serde_json::{Map, Value};

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
                    serde_json::Number::from_f64(n)
                        .map(Value::Number)
                        .unwrap_or(Value::Null)
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
    risk_level: u8,          // 0-4 for RiskLevel variants
    certification_level: u8, // 0-4 for CertificationLevel variants
    trust_card_version: u64,
    reputation_score_basis_points: u16,
    card_hash: String,
    registry_signature: String,
    evidence_count: u8, // 0-5 for number of evidence refs
}

impl ArbitraryTrustCardData {
    fn to_trust_card_input(&self) -> TrustCardInput {
        let risk_levels = [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];
        let capability_risks = [
            CapabilityRisk::Low,
            CapabilityRisk::Medium,
            CapabilityRisk::High,
            CapabilityRisk::Critical,
        ];

        let evidence_types = [
            EvidenceType::ProvenanceChain,
            EvidenceType::ReputationSignal,
            EvidenceType::TestCoverageReport,
            EvidenceType::AuditReport,
            EvidenceType::ManifestAdmission,
            EvidenceType::RevocationCheck,
        ];

        let evidence_refs: Vec<VerifiedEvidenceRef> = (0..self.evidence_count.min(5))
            .map(|i| VerifiedEvidenceRef {
                evidence_id: format!("evidence-{}-{}", self.extension_id, i),
                evidence_type: evidence_types[i as usize % evidence_types.len()].clone(),
                verified_at_epoch: 1000 + i as u64,
                verification_receipt_hash: format!("{:064x}", i as u64),
            })
            .collect();

        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: self.extension_id.clone(),
                version: self.version.clone(),
            },
            publisher: PublisherIdentity {
                publisher_id: self.publisher_url.clone(),
                display_name: self.publisher_name.clone(),
            },
            certification_level: CertificationLevel::Bronze,
            capability_declarations: vec![CapabilityDeclaration {
                name: "network".to_string(),
                description: "Generated canonical serializer fixture capability".to_string(),
                risk: capability_risks[self.risk_level as usize % capability_risks.len()],
            }],
            behavioral_profile: BehavioralProfile {
                network_access: true,
                filesystem_access: false,
                subprocess_access: false,
                profile_summary: format!(
                    "{} repository={} homepage={}",
                    self.description, self.repository_url, self.homepage_url
                ),
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
                level: risk_levels[self.risk_level as usize % risk_levels.len()],
                summary: "Third-party dependencies mitigated by regular security updates"
                    .to_string(),
            },
            evidence_refs,
        }
    }

    fn to_trust_card(&self) -> TrustCard {
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
            certification_level: certification_levels
                [self.certification_level as usize % certification_levels.len()],
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
            card_hash: self.card_hash.clone(),
            registry_signature: self.registry_signature.clone(),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn canonical_hex_and_base64_encoding_round_trip(payload in prop::collection::vec(any::<u8>(), 0..=4096)) {
        let hex_encoded = hex::encode(&payload);
        let hex_decoded = hex::decode(&hex_encoded)
            .map_err(|err| TestCaseError::fail(format!("hex decode failed after encode: {err}")))?;
        prop_assert_eq!(
            hex_decoded.as_slice(),
            payload.as_slice(),
            "hex decode(encode(payload)) changed bytes"
        );

        let base64_encoded = STANDARD.encode(&payload);
        let base64_decoded = STANDARD
            .decode(&base64_encoded)
            .map_err(|err| TestCaseError::fail(format!("base64 decode failed after encode: {err}")))?;
        prop_assert_eq!(
            base64_decoded.as_slice(),
            payload.as_slice(),
            "base64 decode(encode(payload)) changed bytes"
        );
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
                }),
            ) {
                assert_eq!(
                    first_canonical, second_canonical,
                    "Canonical serialization idempotence violated for JSON value at seed {}:
                     Original: {:?}
                     First canonicalization: {}
                     Second canonicalization: {}",
                    seed, json_value, first_canonical, second_canonical
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
                }),
            ) {
                assert_eq!(
                    first_canonical, second_canonical,
                    "Trust card canonical serialization idempotence violated at seed {}:
                     First canonicalization: {}
                     Second canonicalization: {}",
                    seed, first_canonical, second_canonical
                );
            }
        }
    }
}

/// Test object insertion order does not change canonical content.
#[test]
fn canonical_serializer_preserves_content_under_object_insertion_permutation() -> Result<(), String>
{
    let mut forward = Map::new();
    forward.insert(
        "extension".to_string(),
        serde_json::json!({
            "id": "npm:@franken/example",
            "version": "1.2.3",
            "capabilities": ["network", "filesystem"]
        }),
    );
    forward.insert(
        "publisher".to_string(),
        serde_json::json!({
            "display_name": "Franken Example",
            "publisher_id": "https://publisher.example"
        }),
    );
    forward.insert(
        "risk".to_string(),
        serde_json::json!({
            "level": "medium",
            "score_basis_points": 4250
        }),
    );

    let mut reverse = Map::new();
    reverse.insert(
        "risk".to_string(),
        serde_json::json!({
            "score_basis_points": 4250,
            "level": "medium"
        }),
    );
    reverse.insert(
        "publisher".to_string(),
        serde_json::json!({
            "publisher_id": "https://publisher.example",
            "display_name": "Franken Example"
        }),
    );
    reverse.insert(
        "extension".to_string(),
        serde_json::json!({
            "capabilities": ["network", "filesystem"],
            "version": "1.2.3",
            "id": "npm:@franken/example"
        }),
    );

    let forward_canonical =
        to_canonical_json(&Value::Object(forward)).map_err(|error| error.to_string())?;
    let reverse_canonical =
        to_canonical_json(&Value::Object(reverse)).map_err(|error| error.to_string())?;

    if forward_canonical
        .as_bytes()
        .ne(reverse_canonical.as_bytes())
    {
        return Err("canonical JSON changed under object insertion-order permutation".to_string());
    }

    let parsed_forward: Value =
        serde_json::from_str(&forward_canonical).map_err(|error| error.to_string())?;
    let parsed_reverse: Value =
        serde_json::from_str(&reverse_canonical).map_err(|error| error.to_string())?;
    if !std::cmp::PartialEq::eq(&parsed_forward, &parsed_reverse) {
        return Err(
            "canonical content changed after object insertion-order permutation".to_string(),
        );
    }

    Ok(())
}

/// Equivalent JSON texts must collapse to one canonical byte string.
#[test]
fn canonical_serializer_collapses_semantically_equivalent_json_texts() -> Result<(), String> {
    let json_variants = [
        r#"{
            "message": "line\nbreak",
            "path": "\/tmp\/replay",
            "unicode": "franken",
            "items": [1, 2, 3],
            "nested": {"beta": true, "alpha": null}
        }"#,
        r#"{"nested":{"alpha":null,"beta":true},"items":[1,2,3],"unicode":"\u0066\u0072\u0061\u006e\u006b\u0065\u006e","path":"/tmp/replay","message":"line\nbreak"}"#,
        r#"{
            "items" : [ 1 , 2 , 3 ],
            "message" : "line\u000abreak",
            "nested" : { "beta" : true, "alpha" : null },
            "path" : "/tmp/replay",
            "unicode" : "franken"
        }"#,
    ];

    let expected = serde_json::json!({
        "items": [1, 2, 3],
        "message": "line\nbreak",
        "nested": {
            "alpha": null,
            "beta": true,
        },
        "path": "/tmp/replay",
        "unicode": "franken",
    });
    let expected_canonical = to_canonical_json(&expected).map_err(|error| error.to_string())?;

    for json_text in json_variants {
        let parsed: Value = serde_json::from_str(json_text).map_err(|error| error.to_string())?;
        let canonical = to_canonical_json(&parsed).map_err(|error| error.to_string())?;
        assert_eq!(
            canonical, expected_canonical,
            "semantic JSON text equivalence did not preserve canonical bytes"
        );
    }

    Ok(())
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
                    assert_eq!(
                        original_card.extension.extension_id,
                        recovered_card.extension.extension_id
                    );
                    assert_eq!(
                        original_card.trust_card_version,
                        recovered_card.trust_card_version
                    );
                    assert_eq!(
                        original_card.certification_level,
                        recovered_card.certification_level
                    );
                    assert_eq!(
                        original_card.reputation_score_basis_points,
                        recovered_card.reputation_score_basis_points
                    );
                    assert_eq!(
                        original_card.capability_declarations.len(),
                        recovered_card.capability_declarations.len()
                    );

                    // Re-canonicalizing the recovered card should produce identical JSON
                    if let Ok(re_canonical) = to_canonical_json(&recovered_card) {
                        assert_eq!(
                            canonical_json, re_canonical,
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
            }),
        ) {
            assert_eq!(
                first_canonical, second_canonical,
                "Edge case {} failed idempotence test: {:?}",
                i, edge_case
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
            serializations[0], *serialization,
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
    assert!(
        canonical.find("\"alpha_nested\"").unwrap() < canonical.find("\"zebra_nested\"").unwrap()
    );
}

fn connector_payload_pair(seed: u64, object_type: TrustObjectType) -> (String, String) {
    let label = object_type.label();
    let serializer = CanonicalSerializer::with_all_schemas();
    let schema = serializer
        .get_schema(object_type)
        .expect("object type should have a default schema");
    let values = [
        serde_json::json!(format!("{label}-{seed}")),
        serde_json::json!(seed),
        serde_json::json!({
            "right": seed % 17,
            "left": format!("left-{label}"),
            "flags": {
                "enabled": seed % 2 == 0,
                "reviewed": seed % 3 == 0
            }
        }),
        serde_json::json!([
            seed,
            seed.wrapping_mul(3).wrapping_add(1),
            seed ^ 0xa5a5_a5a5_a5a5_a5a5
        ]),
        serde_json::json!(seed % 5),
    ];

    let mut original = Map::new();
    for (field, value) in schema.field_order.iter().zip(values.iter()) {
        original.insert(field.clone(), value.clone());
    }
    let permuted_fields = schema
        .field_order
        .iter()
        .zip(values.iter())
        .rev()
        .map(|(field, value)| {
            format!(
                "{}:{}",
                serde_json::to_string(field).expect("field must serialize"),
                serde_json::to_string(value).expect("value must serialize")
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    (
        serde_json::to_string(&Value::Object(original)).expect("fixture must serialize"),
        format!("{{{permuted_fields}}}"),
    )
}

proptest! {
    #[test]
    fn connector_canonical_serializer_round_trip_and_permutation_metamorphic(seed in 0_u64..1024) {
        for &object_type in TrustObjectType::all() {
            let (original_json, permuted_json) = connector_payload_pair(seed, object_type);

            let mut serializer = CanonicalSerializer::with_all_schemas();
            let original = serializer
                .serialize(object_type, original_json.as_bytes(), "integration-mr-original")
                .map_err(|err| TestCaseError::fail(format!("original serialize failed for {object_type:?}: {err}")))?;

            let mut permuted_serializer = CanonicalSerializer::with_all_schemas();
            let permuted = permuted_serializer
                .serialize(object_type, permuted_json.as_bytes(), "integration-mr-permuted")
                .map_err(|err| TestCaseError::fail(format!("permuted serialize failed for {object_type:?}: {err}")))?;
            prop_assert_eq!(
                &original,
                &permuted,
                "field-order permutation changed canonical bytes for {:?}",
                object_type
            );

            let decoded = permuted_serializer
                .deserialize(object_type, &permuted)
                .map_err(|err| TestCaseError::fail(format!("deserialize failed for {object_type:?}: {err}")))?;
            let mut reencode_serializer = CanonicalSerializer::with_all_schemas();
            let reencoded = reencode_serializer
                .serialize(object_type, &decoded, "integration-mr-reencoded")
                .map_err(|err| TestCaseError::fail(format!("re-serialize failed for {object_type:?}: {err}")))?;
            prop_assert_eq!(
                &permuted,
                &reencoded,
                "deserialize(serialize(x)) did not re-encode stably for {:?}",
                object_type
            );

            let mut round_trip_serializer = CanonicalSerializer::with_all_schemas();
            let round_trip = round_trip_serializer
                .round_trip_canonical(
                    object_type,
                    original_json.as_bytes(),
                    "integration-mr-round-trip",
                )
                .map_err(|err| TestCaseError::fail(format!("round trip failed for {object_type:?}: {err}")))?;
            prop_assert_eq!(
                &original,
                &round_trip,
                "round_trip_canonical disagreed with direct serialization for {:?}",
                object_type
            );
        }
    }
}
