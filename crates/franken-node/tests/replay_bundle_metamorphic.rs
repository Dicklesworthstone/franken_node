//! Metamorphic Testing: Replay Bundle Compose/Decompose Inversion
//!
//! Tests the critical metamorphic relation: export then import should equal original bundle.
//! This verifies that ReplayBundle serialization/deserialization is truly lossless across
//! the full spectrum of possible inputs.
//!
//! Metamorphic Property: read_bundle_from_path(write_bundle_to_path(bundle)) == bundle
//! If this relation fails, it indicates a serialization bug that could cause data loss.

use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleSigningMaterial, generate_replay_bundle,
    read_bundle_from_path_with_trusted_key, sign_replay_bundle, to_canonical_json,
    write_bundle_to_path_with_trusted_key,
};
use proptest::prelude::{ProptestConfig, any};
use rand::distributions::{Alphanumeric, DistString};
use rand::{Rng, RngCore, SeedableRng};
use serde_json::json;
use tempfile::TempDir;

fn metamorphic_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[47_u8; 32])
}

fn metamorphic_trusted_key_id() -> String {
    let signing_key = metamorphic_signing_key();
    frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
        &signing_key.verifying_key(),
    )
    .to_string()
}

fn sign_metamorphic_bundle(bundle: &mut ReplayBundle) {
    let signing_key = metamorphic_signing_key();
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "test",
        signing_identity: "replay-bundle-metamorphic",
    };
    sign_replay_bundle(bundle, &signing_material).expect("sign metamorphic replay bundle");
}

fn write_then_read_bundle(bundle: &ReplayBundle, path: &std::path::Path) -> ReplayBundle {
    let trusted_key_id = metamorphic_trusted_key_id();
    write_bundle_to_path_with_trusted_key(bundle, path, &trusted_key_id)
        .expect("bundle should write successfully");
    read_bundle_from_path_with_trusted_key(path, Some(&trusted_key_id))
        .expect("bundle should read successfully")
}

#[cfg(test)]
mod evidence_backed_roundtrip_metamorphic {
    use super::*;
    use frankenengine_node::tools::replay_bundle::{
        INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
        IncidentEvidencePackage, IncidentSeverity, generate_replay_bundle_from_evidence,
        to_canonical_json,
    };
    use proptest::prelude::*;

    fn evidence_package(rng: &mut impl rand::Rng, case_index: usize) -> IncidentEvidencePackage {
        let evidence_refs = vec![
            format!("evidence/case-{case_index}/collector.json"),
            format!("trust/card-{case_index}/manifest.json"),
            format!("trust-artifacts/case-{case_index}/receipt.json"),
        ];
        let event_count = rng.gen_range(1..30);
        let events = (0..event_count)
            .map(|event_index| {
                let provenance_ref = evidence_refs[rng.gen_range(0..evidence_refs.len())].clone();
                let parent_event_id = if event_index > 0 && rng.gen_bool(0.35) {
                    Some(format!(
                        "evt-{case_index}-{}",
                        rng.gen_range(0..event_index)
                    ))
                } else {
                    None
                };
                IncidentEvidenceEvent {
                    event_id: format!("evt-{case_index}-{event_index}"),
                    timestamp: format!(
                        "2024-04-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                        (case_index % 20) + 1,
                        (event_index / 3600) % 24,
                        (event_index / 60) % 60,
                        event_index % 60,
                        rng.gen_range(0..1000)
                    ),
                    event_type: [
                        EventType::StateChange,
                        EventType::PolicyEval,
                        EventType::ExternalSignal,
                        EventType::OperatorAction,
                    ][rng.gen_range(0..4)],
                    payload: json!({
                        "case": case_index,
                        "event": event_index,
                        "signal": Alphanumeric.sample_string(rng, 12),
                        "score_micros": rng.gen_range(0..=1_000_000)
                    }),
                    provenance_ref,
                    parent_event_id,
                    state_snapshot: (event_index == 0).then(|| {
                        json!({
                            "case": case_index,
                            "seeded": true,
                            "state": rng.gen_range(0..10_000)
                        })
                    }),
                    policy_version: (event_index == 0)
                        .then(|| format!("policy-v{}", rng.gen_range(1..5))),
                }
            })
            .collect();

        IncidentEvidencePackage {
            schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
            incident_id: format!("incident-mr-{case_index}"),
            collected_at: "2024-04-30T00:00:00.000Z".to_string(),
            trace_id: format!("trace-mr-{case_index}"),
            severity: match case_index % 4 {
                0 => IncidentSeverity::Low,
                1 => IncidentSeverity::Medium,
                2 => IncidentSeverity::High,
                _ => IncidentSeverity::Critical,
            },
            incident_type: "metamorphic-roundtrip".to_string(),
            detector: "replay-bundle-metamorphic-test".to_string(),
            policy_version: "policy-v1".to_string(),
            initial_state_snapshot: json!({
                "case": case_index,
                "snapshot": "initial",
                "nonce": rng.next_u64()
            }),
            events,
            evidence_refs,
            metadata: IncidentEvidenceMetadata {
                title: format!("Metamorphic replay bundle case {case_index}"),
                affected_components: vec![
                    format!("component-{}", case_index % 7),
                    format!("component-{}", (case_index + 3) % 11),
                ],
                tags: vec!["metamorphic".to_string(), "roundtrip".to_string()],
            },
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 50,
            ..ProptestConfig::default()
        })]

        #[test]
        fn evidence_backed_replay_bundle_export_import_is_fixed_point(
            seed in any::<u64>(),
            case_index in 0usize..10_000,
        ) {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let temp_dir = TempDir::new().expect("create replay bundle temp directory");
            let package = evidence_package(&mut rng, case_index);
            let mut original = generate_replay_bundle_from_evidence(&package)
                .expect("evidence package should generate a replay bundle");
            sign_metamorphic_bundle(&mut original);

            let first_path = temp_dir.path().join(format!("bundle-{case_index}-first.json"));
            let second_path = temp_dir
                .path()
                .join(format!("bundle-{case_index}-second.json"));

            let imported = write_then_read_bundle(&original, &first_path);
            let reimported = write_then_read_bundle(&imported, &second_path);
            let first_wire = std::fs::read_to_string(&first_path)
                .expect("first replay bundle export should be readable");
            let second_wire = std::fs::read_to_string(&second_path)
                .expect("second replay bundle export should be readable");
            let imported_json = to_canonical_json(&imported).expect("canonicalize imported bundle");
            let reimported_json =
                to_canonical_json(&reimported).expect("canonicalize reimported bundle");

            prop_assert_eq!(
                &original,
                &imported,
                "case {}: first export/import changed the bundle",
                case_index
            );
            prop_assert_eq!(
                &imported,
                &reimported,
                "case {}: export(import(bundle)) was not idempotent",
                case_index
            );
            prop_assert_eq!(
                first_wire,
                second_wire,
                "case {}: export(import(bundle)) changed canonical wire bytes",
                case_index
            );
            prop_assert_eq!(
                imported_json,
                reimported_json,
                "case {}: canonical wire output changed after repeated round-trip",
                case_index
            );
            prop_assert_eq!(
                &imported.evidence_refs,
                &package.evidence_refs,
                "case {}: evidence refs changed during round-trip",
                case_index
            );
            let expected_trust_artifact_refs = vec![
                format!("trust/card-{case_index}/manifest.json"),
                format!("trust-artifacts/case-{case_index}/receipt.json"),
            ];
            prop_assert_eq!(
                &imported.trust_artifact_refs,
                &expected_trust_artifact_refs,
                "case {}: trust artifact refs changed during round-trip",
                case_index
            );
        }
    }
}

/// Generate arbitrary RawEvent for property-based testing
fn arbitrary_raw_event(rng: &mut impl Rng, sequence_base: u64) -> RawEvent {
    let event_types = [
        EventType::StateChange,
        EventType::PolicyEval,
        EventType::ExternalSignal,
        EventType::OperatorAction,
    ];

    let event_type = event_types[rng.gen_range(0..event_types.len())];

    // Generate realistic but random payload based on event type
    let payload = match event_type {
        EventType::StateChange => {
            json!({
                "component": format!("component_{}", rng.gen_range(1..10)),
                "from_state": format!("state_{}", rng.gen_range(1..5)),
                "to_state": format!("state_{}", rng.gen_range(1..5)),
                "trigger": "automated_transition"
            })
        }
        EventType::PolicyEval => {
            let decisions = ["allow", "deny", "defer"];
            json!({
                "policy_id": format!("policy_{}", Alphanumeric.sample_string(rng, 8)),
                "decision": decisions[rng.gen_range(0..3)],
                "confidence_micros": rng.gen_range(0..=1_000_000)
            })
        }
        EventType::ExternalSignal => {
            json!({
                "signal_type": format!("signal_{}", rng.gen_range(1..20)),
                "source": format!("external_system_{}", rng.gen_range(1..5)),
                "payload_size": rng.gen_range(0..10_000)
            })
        }
        EventType::OperatorAction => {
            let actions = ["deploy", "rollback", "scale", "restart"];
            json!({
                "action": actions[rng.gen_range(0..4)],
                "operator": format!("operator_{}", rng.gen_range(1..10)),
                "target": format!("service_{}", rng.gen_range(1..20))
            })
        }
    };

    let causal_parent = if rng.gen_bool(0.3) && sequence_base > 0 {
        Some(rng.gen_range(0..sequence_base))
    } else {
        None
    };

    RawEvent {
        timestamp: format!(
            "2024-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            rng.gen_range(1..13),
            rng.gen_range(1..29),
            rng.gen_range(0..24),
            rng.gen_range(0..60),
            rng.gen_range(0..60),
            rng.gen_range(0..1000)
        ),
        event_type,
        payload,
        causal_parent,
        state_snapshot: None, // Keep simple for metamorphic testing
        policy_version: None,
    }
}

/// Generate an arbitrary ReplayBundle for metamorphic testing
fn arbitrary_replay_bundle(rng: &mut impl Rng) -> ReplayBundle {
    let incident_id = format!("incident_{}", Alphanumeric.sample_string(rng, 16));
    let event_count = rng.gen_range(1..50);

    let mut events = Vec::new();
    let mut sequence_base = rng.gen_range(1000..10_000);

    for _ in 0..event_count {
        events.push(arbitrary_raw_event(rng, sequence_base));
        sequence_base += rng.gen_range(1..10);
    }

    let mut bundle = generate_replay_bundle(&incident_id, &events)
        .expect("Generated events should always produce valid bundle");
    sign_metamorphic_bundle(&mut bundle);
    bundle
}

fn entropy_pattern_name(pattern_index: usize) -> &'static str {
    match pattern_index % 4 {
        0 => "all_zero",
        1 => "all_ff",
        2 => "alternating_00_ff",
        _ => "seeded_random",
    }
}

fn entropy_pattern_bytes(rng: &mut impl RngCore, pattern_index: usize, byte_len: usize) -> Vec<u8> {
    match pattern_index % 4 {
        0 => vec![0x00; byte_len],
        1 => vec![0xff; byte_len],
        2 => (0..byte_len)
            .map(|index| if index % 2 == 0 { 0x00 } else { 0xff })
            .collect(),
        _ => {
            let mut bytes = vec![0x00; byte_len];
            rng.fill_bytes(&mut bytes);
            bytes
        }
    }
}

fn fuzzed_entropy_replay_bundle(seed: u64) -> ReplayBundle {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let event_count = rng.gen_range(5..25);
    let events = (0..event_count)
        .map(|event_index| {
            let pattern_index = if event_index < 4 {
                event_index
            } else {
                rng.gen_range(0..4)
            };
            let byte_len = match event_index {
                0 => 64,
                1 => 65,
                2 => 128,
                3 => rng.gen_range(0..=16),
                _ => rng.gen_range(0..=768),
            };
            let bytes = entropy_pattern_bytes(&mut rng, pattern_index, byte_len);
            let byte_hex = hex::encode(&bytes);
            let prefix_hex = hex::encode(bytes.iter().take(32).copied().collect::<Vec<_>>());

            RawEvent {
                timestamp: format!(
                    "2024-05-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    (event_index % 28) + 1,
                    (event_index / 3600) % 24,
                    (event_index / 60) % 60,
                    event_index % 60,
                    rng.gen_range(0..1000)
                ),
                event_type: [
                    EventType::StateChange,
                    EventType::PolicyEval,
                    EventType::ExternalSignal,
                    EventType::OperatorAction,
                ][pattern_index % 4],
                payload: json!({
                    "case_seed": seed,
                    "event_index": event_index,
                    "entropy_pattern": entropy_pattern_name(pattern_index),
                    "byte_len": bytes.len(),
                    "bytes_hex": byte_hex,
                    "prefix_hex": prefix_hex
                }),
                causal_parent: if event_index > 0 && rng.gen_bool(0.35) {
                    Some(rng.gen_range(1..=event_index) as u64)
                } else {
                    None
                },
                state_snapshot: (event_index == 0).then(|| {
                    json!({
                        "seed": seed,
                        "entropy_pattern": entropy_pattern_name(pattern_index),
                        "byte_len": bytes.len()
                    })
                }),
                policy_version: (event_index == 0)
                    .then(|| format!("entropy-policy-v{}", (seed % 7) + 1)),
            }
        })
        .collect::<Vec<_>>();

    let incident_id = format!("INC-ENTROPY-SERDE-{seed:016x}");
    let mut bundle = generate_replay_bundle(&incident_id, &events)
        .expect("fuzzed entropy events should generate a replay bundle");
    sign_metamorphic_bundle(&mut bundle);
    bundle
}

proptest::proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    #[test]
    fn replay_bundle_deserialize_serialize_symmetry_holds(seed in any::<u64>()) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let original_bundle = arbitrary_replay_bundle(&mut rng);

        let serialized = serde_json::to_string(&original_bundle)
            .expect("generated replay bundle should serialize");
        let deserialized: ReplayBundle = serde_json::from_str(&serialized)
            .expect("serialized replay bundle should deserialize");

        proptest::prop_assert_eq!(
            &original_bundle,
            &deserialized,
            "serde deserialize(serialize(bundle)) changed a valid replay bundle"
        );

        let canonical_serialized = to_canonical_json(&original_bundle)
            .expect("generated replay bundle should canonicalize");
        let canonical_deserialized: ReplayBundle = serde_json::from_str(&canonical_serialized)
            .expect("canonical serialized replay bundle should deserialize");

        proptest::prop_assert_eq!(
            &original_bundle,
            &canonical_deserialized,
            "canonical deserialize(serialize(bundle)) changed a valid replay bundle"
        );
    }

    #[test]
    fn replay_bundle_serde_roundtrip_is_byte_stable_for_fuzzed_entropy(
        seed in any::<u64>(),
    ) {
        let original_bundle = fuzzed_entropy_replay_bundle(seed);
        let first_wire = serde_json::to_vec(&original_bundle)
            .expect("fuzzed entropy replay bundle should serialize");
        let decoded: ReplayBundle = serde_json::from_slice(&first_wire)
            .expect("serialized fuzzed entropy replay bundle should deserialize");
        let second_wire = serde_json::to_vec(&decoded)
            .expect("deserialized fuzzed entropy replay bundle should reserialize");

        proptest::prop_assert_eq!(
            first_wire,
            second_wire,
            "seed {}: serde serialize->deserialize->serialize changed wire bytes",
            seed
        );
    }
}

/// Test the core metamorphic relation: export ∘ import = identity
#[test]
fn metamorphic_replay_bundle_compose_decompose_inversion() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42); // Deterministic for reproducibility
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Test across multiple randomly generated bundles
    for test_case in 0..20 {
        let original_bundle = arbitrary_replay_bundle(&mut rng);
        let bundle_path = temp_dir
            .path()
            .join(format!("test_bundle_{}.rbundle", test_case));

        // MR: export then import should equal original
        // Step 1/2: Export (compose) then import (decompose)
        let recovered_bundle = write_then_read_bundle(&original_bundle, &bundle_path);

        // Step 3: Assert metamorphic relation holds
        assert_eq!(
            original_bundle, recovered_bundle,
            "METAMORPHIC RELATION VIOLATED: Test case {}\n\
             Replay bundle export→import is not the identity function.\n\
             This indicates a serialization bug that could cause data loss.\n\
             Original bundle_id: {}\n\
             Recovered bundle_id: {}",
            test_case, original_bundle.bundle_id, recovered_bundle.bundle_id
        );

        // Additional semantic invariants that must be preserved
        assert_eq!(
            original_bundle.incident_id, recovered_bundle.incident_id,
            "Test case {}: Incident ID changed during round-trip",
            test_case
        );
        assert_eq!(
            original_bundle.manifest.event_count, recovered_bundle.manifest.event_count,
            "Test case {}: Event count changed during round-trip",
            test_case
        );
        assert_eq!(
            original_bundle.timeline.len(),
            recovered_bundle.timeline.len(),
            "Test case {}: Timeline length changed during round-trip",
            test_case
        );
        assert_eq!(
            original_bundle.chunks.len(),
            recovered_bundle.chunks.len(),
            "Test case {}: Chunk count changed during round-trip",
            test_case
        );
    }
}

/// Test metamorphic relation with edge cases that stress serialization boundaries
#[test]
fn metamorphic_replay_bundle_edge_cases() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Edge case 1: Single event bundle
    let single_event = vec![RawEvent {
        timestamp: "2024-01-01T00:00:00.000Z".into(),
        event_type: EventType::StateChange,
        payload: json!({"minimal": true}),
        causal_parent: None,
        state_snapshot: None,
        policy_version: None,
    }];
    let mut single_bundle = generate_replay_bundle("edge_single", &single_event)
        .expect("Single event should generate valid bundle");
    sign_metamorphic_bundle(&mut single_bundle);

    let path = temp_dir.path().join("single.rbundle");
    let recovered = write_then_read_bundle(&single_bundle, &path);
    assert_eq!(
        single_bundle, recovered,
        "Single event bundle failed round-trip"
    );

    // Edge case 2: Empty payload bundle
    let empty_payload = vec![RawEvent {
        timestamp: "2024-12-31T23:59:59.999Z".into(),
        event_type: EventType::PolicyEval,
        payload: json!({}),
        causal_parent: Some(41),
        state_snapshot: None,
        policy_version: None,
    }];
    let mut empty_bundle = generate_replay_bundle("edge_empty", &empty_payload)
        .expect("Empty payload should generate valid bundle");
    sign_metamorphic_bundle(&mut empty_bundle);

    let path2 = temp_dir.path().join("empty.rbundle");
    let recovered2 = write_then_read_bundle(&empty_bundle, &path2);
    assert_eq!(
        empty_bundle, recovered2,
        "Empty payload bundle failed round-trip"
    );

    // Edge case 3: Complex nested payload
    let complex_event = vec![RawEvent {
        timestamp: "2024-06-15T12:30:45.123Z".into(),
        event_type: EventType::ExternalSignal,
        payload: json!({
            "nested": {
                "array": [1, 2, 3, null, "string"],
                "object": {
                    "boolean": true,
                    "number_micros": 3_141_590,
                    "unicode": "🚀 test émojis and àccénts"
                }
            },
            "edge_values": {
                "max_i64": 9223372036854775807i64,
                "zero": 0,
                "empty_string": "",
                "very_long_string": "a".repeat(1000)
            }
        }),
        causal_parent: None,
        state_snapshot: None,
        policy_version: None,
    }];
    let mut complex_bundle = generate_replay_bundle("edge_complex", &complex_event)
        .expect("Complex payload should generate valid bundle");
    sign_metamorphic_bundle(&mut complex_bundle);

    let path3 = temp_dir.path().join("complex.rbundle");
    let recovered3 = write_then_read_bundle(&complex_bundle, &path3);
    assert_eq!(
        complex_bundle, recovered3,
        "Complex payload bundle failed round-trip"
    );
}

/// Test metamorphic invariants under stress conditions
#[test]
fn metamorphic_replay_bundle_stress_test() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Generate a large bundle with many events to test chunking boundary conditions
    let incident_id = "stress_test_bundle";
    let mut events = Vec::new();

    // Create enough events to force multiple chunks
    for i in 0..500 {
        events.push(RawEvent {
            timestamp: format!(
                "2024-01-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                (i % 28) + 1,
                (i % 24),
                (i % 60),
                (i % 60),
                i % 1000
            ),
            event_type: [
                EventType::StateChange,
                EventType::PolicyEval,
                EventType::ExternalSignal,
                EventType::OperatorAction,
            ][i % 4],
            payload: json!({
                "stress_data": "x".repeat(if i < 20 { 600_000 } else { rng.gen_range(10..1000) }),
                "index": i,
                "random": rng.next_u64()
            }),
            causal_parent: if i > 0 && rng.gen_bool(0.5) {
                Some(rng.gen_range(0..i) as u64)
            } else {
                None
            },
            state_snapshot: None,
            policy_version: None,
        });
    }

    let mut stress_bundle = generate_replay_bundle(incident_id, &events)
        .expect("Stress test events should generate valid bundle");
    sign_metamorphic_bundle(&mut stress_bundle);

    assert!(
        stress_bundle.chunks.len() > 1,
        "Stress test should produce multiple chunks, got {}",
        stress_bundle.chunks.len()
    );

    let stress_path = temp_dir.path().join("stress.rbundle");
    let recovered_stress = write_then_read_bundle(&stress_bundle, &stress_path);

    assert_eq!(
        stress_bundle, recovered_stress,
        "CRITICAL: Large bundle failed compose/decompose inversion.\n\
         This could indicate chunking or compression bugs."
    );

    // Verify all events preserved correctly
    assert_eq!(
        stress_bundle.timeline.len(),
        recovered_stress.timeline.len()
    );
    for (i, (orig, recovered)) in stress_bundle
        .timeline
        .iter()
        .zip(recovered_stress.timeline.iter())
        .enumerate()
    {
        assert_eq!(
            orig.timestamp, recovered.timestamp,
            "Event {}: timestamp mismatch",
            i
        );
        assert_eq!(
            orig.payload, recovered.payload,
            "Event {}: payload mismatch",
            i
        );
    }
}
