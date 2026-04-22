//! Metamorphic Testing: Replay Bundle Compose/Decompose Inversion
//!
//! Tests the critical metamorphic relation: export then import should equal original bundle.
//! This verifies that ReplayBundle serialization/deserialization is truly lossless across
//! the full spectrum of possible inputs.
//!
//! Metamorphic Property: read_bundle_from_path(write_bundle_to_path(bundle)) == bundle
//! If this relation fails, it indicates a serialization bug that could cause data loss.

use frankenengine_node::tools::replay_bundle::{
    RawEvent, ReplayBundle, generate_replay_bundle, write_bundle_to_path, read_bundle_from_path,
};
use rand::{Rng, SeedableRng};
use rand::distributions::{Alphanumeric, DistString};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tempfile::TempDir;

/// Generate arbitrary RawEvent for property-based testing
fn arbitrary_raw_event(rng: &mut impl Rng, sequence_base: u64) -> RawEvent {
    let event_types = [
        "network_access",
        "filesystem_operation",
        "process_spawn",
        "secret_access",
        "policy_transition",
        "artifact_promotion",
    ];

    let event_type = event_types[rng.gen_range(0..event_types.len())];
    let timestamp_ms = rng.gen_range(1_600_000_000_000..2_000_000_000_000); // 2020-2033

    // Generate realistic but random payload based on event type
    let payload = match event_type {
        "network_access" => {
            let methods = ["GET", "POST", "PUT"];
            json!({
                "url": format!("https://api.example.com/v{}", rng.gen_range(1..5)),
                "method": methods[rng.gen_range(0..3)],
                "status_code": rng.gen_range(200..599)
            })
        },
        "filesystem_operation" => {
            let operations = ["read", "write", "delete"];
            json!({
                "path": format!("/tmp/test_{}.dat", rng.gen_range(1000..9999)),
                "operation": operations[rng.gen_range(0..3)],
                "size_bytes": rng.gen_range(0..1_000_000)
            })
        },
        "process_spawn" => json!({
            "command": format!("test-process-{}", rng.gen_range(1..100)),
            "args": vec![format!("--flag-{}", rng.gen_range(1..10))],
            "exit_code": rng.gen_range(0..128)
        }),
        "secret_access" => {
            let operations = ["read", "rotate"];
            json!({
                "secret_id": format!("secret_{}", Alphanumeric.sample_string(rng, 16)),
                "operation": operations[rng.gen_range(0..2)]
            })
        },
        "policy_transition" => json!({
            "from_policy": format!("policy_v{}", rng.gen_range(1..10)),
            "to_policy": format!("policy_v{}", rng.gen_range(1..10)),
            "reason": "automated_transition"
        }),
        "artifact_promotion" => {
            let from_stages = ["dev", "staging"];
            let to_stages = ["staging", "production"];
            json!({
                "artifact_id": format!("artifact_{}", Alphanumeric.sample_string(rng, 32)),
                "from_stage": from_stages[rng.gen_range(0..2)],
                "to_stage": to_stages[rng.gen_range(0..2)]
            })
        },
        _ => json!({"unknown": true})
    };

    let causal_parent = if rng.gen_bool(0.3) && sequence_base > 0 {
        Some(rng.gen_range(0..sequence_base))
    } else {
        None
    };

    RawEvent {
        sequence_number: sequence_base + rng.gen_range(1..100),
        timestamp: format!("2024-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            rng.gen_range(1..13), rng.gen_range(1..29),
            rng.gen_range(0..24), rng.gen_range(0..60), rng.gen_range(0..60),
            rng.gen_range(0..1000)),
        event_type: event_type.into(),
        payload,
        causal_parent,
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

    generate_replay_bundle(&incident_id, &events)
        .expect("Generated events should always produce valid bundle")
}

/// Test the core metamorphic relation: export ∘ import = identity
#[test]
fn metamorphic_replay_bundle_compose_decompose_inversion() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42); // Deterministic for reproducibility
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Test across multiple randomly generated bundles
    for test_case in 0..20 {
        let original_bundle = arbitrary_replay_bundle(&mut rng);
        let bundle_path = temp_dir.path().join(format!("test_bundle_{}.rbundle", test_case));

        // MR: export then import should equal original
        // Step 1: Export (compose)
        write_bundle_to_path(&original_bundle, &bundle_path)
            .unwrap_or_else(|e| panic!(
                "Test case {}: Failed to write bundle to {}: {}",
                test_case, bundle_path.display(), e
            ));

        // Step 2: Import (decompose)
        let recovered_bundle = read_bundle_from_path(&bundle_path)
            .unwrap_or_else(|e| panic!(
                "Test case {}: Failed to read bundle from {}: {}",
                test_case, bundle_path.display(), e
            ));

        // Step 3: Assert metamorphic relation holds
        assert_eq!(
            original_bundle, recovered_bundle,
            "METAMORPHIC RELATION VIOLATED: Test case {}\n\
             Replay bundle export→import is not the identity function.\n\
             This indicates a serialization bug that could cause data loss.\n\
             Original bundle_id: {}\n\
             Recovered bundle_id: {}",
            test_case,
            original_bundle.bundle_id,
            recovered_bundle.bundle_id
        );

        // Additional semantic invariants that must be preserved
        assert_eq!(original_bundle.incident_id, recovered_bundle.incident_id,
            "Test case {}: Incident ID changed during round-trip", test_case);
        assert_eq!(original_bundle.manifest.event_count, recovered_bundle.manifest.event_count,
            "Test case {}: Event count changed during round-trip", test_case);
        assert_eq!(original_bundle.timeline.len(), recovered_bundle.timeline.len(),
            "Test case {}: Timeline length changed during round-trip", test_case);
        assert_eq!(original_bundle.chunks.len(), recovered_bundle.chunks.len(),
            "Test case {}: Chunk count changed during round-trip", test_case);
    }
}

/// Test metamorphic relation with edge cases that stress serialization boundaries
#[test]
fn metamorphic_replay_bundle_edge_cases() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Edge case 1: Single event bundle
    let single_event = vec![RawEvent {
        sequence_number: 1,
        timestamp: "2024-01-01T00:00:00.000Z".into(),
        event_type: "network_access".into(),
        payload: json!({"minimal": true}),
        causal_parent: None,
    }];
    let single_bundle = generate_replay_bundle("edge_single", &single_event)
        .expect("Single event should generate valid bundle");

    let path = temp_dir.path().join("single.rbundle");
    write_bundle_to_path(&single_bundle, &path).unwrap();
    let recovered = read_bundle_from_path(&path).unwrap();
    assert_eq!(single_bundle, recovered, "Single event bundle failed round-trip");

    // Edge case 2: Empty payload bundle
    let empty_payload = vec![RawEvent {
        sequence_number: 42,
        timestamp: "2024-12-31T23:59:59.999Z".into(),
        event_type: "policy_transition".into(),
        payload: json!({}),
        causal_parent: Some(41),
    }];
    let empty_bundle = generate_replay_bundle("edge_empty", &empty_payload)
        .expect("Empty payload should generate valid bundle");

    let path2 = temp_dir.path().join("empty.rbundle");
    write_bundle_to_path(&empty_bundle, &path2).unwrap();
    let recovered2 = read_bundle_from_path(&path2).unwrap();
    assert_eq!(empty_bundle, recovered2, "Empty payload bundle failed round-trip");

    // Edge case 3: Complex nested payload
    let complex_event = vec![RawEvent {
        sequence_number: 1000,
        timestamp: "2024-06-15T12:30:45.123Z".into(),
        event_type: "artifact_promotion".into(),
        payload: json!({
            "nested": {
                "array": [1, 2, 3, null, "string"],
                "object": {
                    "boolean": true,
                    "number": 3.14159,
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
    }];
    let complex_bundle = generate_replay_bundle("edge_complex", &complex_event)
        .expect("Complex payload should generate valid bundle");

    let path3 = temp_dir.path().join("complex.rbundle");
    write_bundle_to_path(&complex_bundle, &path3).unwrap();
    let recovered3 = read_bundle_from_path(&path3).unwrap();
    assert_eq!(complex_bundle, recovered3, "Complex payload bundle failed round-trip");
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
            sequence_number: i as u64,
            timestamp: format!("2024-01-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                (i % 28) + 1, (i % 24), (i % 60), (i % 60), i % 1000),
            event_type: format!("stress_event_{}", i % 10),
            payload: json!({
                "stress_data": "x".repeat(rng.gen_range(10..1000)),
                "index": i,
                "random": rng.next_u64()
            }),
            causal_parent: if i > 0 && rng.gen_bool(0.5) {
                Some(rng.gen_range(0..i) as u64)
            } else {
                None
            },
        });
    }

    let stress_bundle = generate_replay_bundle(incident_id, &events)
        .expect("Stress test events should generate valid bundle");

    assert!(stress_bundle.chunks.len() > 1,
        "Stress test should produce multiple chunks, got {}", stress_bundle.chunks.len());

    let stress_path = temp_dir.path().join("stress.rbundle");
    write_bundle_to_path(&stress_bundle, &stress_path)
        .expect("Stress bundle should write successfully");

    let recovered_stress = read_bundle_from_path(&stress_path)
        .expect("Stress bundle should read successfully");

    assert_eq!(stress_bundle, recovered_stress,
        "CRITICAL: Large bundle failed compose/decompose inversion.\n\
         This could indicate chunking or compression bugs.");

    // Verify all events preserved correctly
    assert_eq!(stress_bundle.timeline.len(), recovered_stress.timeline.len());
    for (i, (orig, recovered)) in stress_bundle.timeline.iter()
        .zip(recovered_stress.timeline.iter()).enumerate() {
        assert_eq!(orig.sequence_number, recovered.sequence_number,
            "Event {}: sequence number mismatch", i);
        assert_eq!(orig.payload, recovered.payload,
            "Event {}: payload mismatch", i);
    }
}