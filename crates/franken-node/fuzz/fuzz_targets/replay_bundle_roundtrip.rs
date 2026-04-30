#![no_main]

use frankenengine_node::tools::replay_bundle::{ReplayBundle, to_canonical_json};
use libfuzzer_sys::fuzz_target;
use serde_json;

/// Fuzz harness for replay bundle roundtrip property: parse(write(x)) == x
///
/// Tests that ReplayBundle serialization/deserialization is robust against
/// malformed input and maintains roundtrip consistency.
///
/// Target properties:
/// 1. No panics on malformed input
/// 2. Valid bundles roundtrip exactly: parse(write(x)) == x
/// 3. Canonical serialization is deterministic
/// 4. Error handling is consistent
fuzz_target!(|data: &[u8]| {
    // Bound input size to prevent OOM in fuzzer
    if data.len() > 1_000_000 {  // 1MB limit
        return;
    }

    // Try to decode the fuzzed input as a ReplayBundle
    let parse_result = serde_json::from_slice::<ReplayBundle>(data);

    match parse_result {
        Ok(bundle) => {
            // ROUNDTRIP PROPERTY TEST: parse(write(x)) == x

            // 1. Serialize back to JSON
            let reserialize_result = serde_json::to_vec(&bundle);

            if let Ok(reserialized_bytes) = reserialize_result {
                // 2. Parse the reserialized data
                let reparse_result = serde_json::from_slice::<ReplayBundle>(&reserialized_bytes);

                // 3. Roundtrip must succeed and be identical
                match reparse_result {
                    Ok(reparsed_bundle) => {
                        assert_eq!(
                            bundle, reparsed_bundle,
                            "Roundtrip property violation: parse(write(x)) != x"
                        );
                    }
                    Err(_) => {
                        // If reparse fails, this indicates a serialization issue
                        panic!("Roundtrip failure: successfully parsed input, but failed to reparse serialized output");
                    }
                }

                // 4. Test canonical serialization consistency
                if let Ok(canonical1) = to_canonical_json(&bundle) {
                    if let Ok(canonical2) = to_canonical_json(&bundle) {
                        assert_eq!(
                            canonical1, canonical2,
                            "Canonical serialization should be deterministic"
                        );
                    }
                }
            }

            // STRUCTURAL INVARIANTS for valid bundles

            // Bundle must have valid incident_id
            assert!(
                !bundle.incident_id.trim().is_empty(),
                "Valid bundle must have non-empty incident_id"
            );

            // Timeline events should have consistent sequence numbers
            let mut prev_seq: Option<u64> = None;
            for event in &bundle.timeline {
                if let Some(prev) = prev_seq {
                    // Sequence numbers should be monotonic (allowing gaps)
                    assert!(
                        event.sequence_number > prev,
                        "Timeline sequence numbers must be strictly increasing: {} <= {}",
                        event.sequence_number, prev
                    );
                }
                prev_seq = Some(event.sequence_number);
            }

            // Manifest event_count should match timeline length
            assert_eq!(
                bundle.manifest.event_count,
                bundle.timeline.len(),
                "Manifest event_count must match actual timeline length"
            );

            // Chunk count should be reasonable
            assert!(
                bundle.manifest.chunk_count <= 1000,
                "Chunk count should not exceed safety limit: {}",
                bundle.manifest.chunk_count
            );

        }
        Err(_parse_error) => {
            // Input failed to parse - this is expected for malformed fuzz inputs
            // Just ensure we don't panic and continue
        }
    }

    // ADDITIONAL EDGE CASE TESTING

    // Test empty input
    if data.is_empty() {
        let empty_result = serde_json::from_slice::<ReplayBundle>(b"");
        assert!(empty_result.is_err(), "Empty input should fail to parse");
    }

    // Test null bytes handling
    if data.contains(&0u8) {
        // Inputs with null bytes should either parse or fail gracefully
        let null_result = serde_json::from_slice::<ReplayBundle>(data);
        // Just verify no panic occurs - either Ok or Err is acceptable
        let _ = null_result;
    }
});