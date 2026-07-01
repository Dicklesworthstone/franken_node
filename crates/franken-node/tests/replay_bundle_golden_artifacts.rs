//! Golden artifact tests for replay bundle deterministic output.
//!
//! These tests freeze known-good replay bundle outputs to catch non-determinism,
//! serialization changes, or unintended output modifications.

use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, generate_replay_bundle, to_canonical_json,
};
use regex::Regex;

const CANONICAL_SMALL_FIXTURE_GOLDEN: &str =
    include_str!("golden/replay_bundle/canonical_small_fixture.golden");

/// Create a small deterministic fixture with exactly 5 events for golden testing.
fn golden_fixture_events() -> Vec<RawEvent> {
    vec![
        RawEvent::new(
            "2026-01-15T14:30:00.000100Z",
            EventType::ExternalSignal,
            serde_json::json!({"signal": "anomaly", "severity": "critical", "source": "detector_7"}),
        )
        .with_state_snapshot(serde_json::json!({"epoch": 42, "mode": "strict", "active_policies": 3}))
        .with_policy_version("2.1.0"),

        RawEvent::new(
            "2026-01-15T14:30:00.000200Z",
            EventType::PolicyEval,
            serde_json::json!({"decision": "isolate", "confidence": 95, "rule_id": "R-2847"}),
        )
        .with_causal_parent(1),

        RawEvent::new(
            "2026-01-15T14:30:00.000300Z",
            EventType::OperatorAction,
            serde_json::json!({"action": "override", "operator": "alice", "reason": "false_positive"}),
        )
        .with_causal_parent(2),

        RawEvent::new(
            "2026-01-15T14:30:00.000400Z",
            EventType::PolicyEval,
            serde_json::json!({"decision": "allow", "confidence": 88, "override_applied": true}),
        )
        .with_causal_parent(3),

        RawEvent::new(
            "2026-01-15T14:30:00.000500Z",
            EventType::OperatorAction,
            serde_json::json!({"action": "log", "message": "incident resolved", "case_id": "INC-2026-0115-001"}),
        )
        .with_causal_parent(4),
    ]
}

fn scrub_replay_bundle_golden(actual: &str) -> String {
    let mut scrubbed = actual.to_string();
    for (pattern, replacement) in [
        (
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "[FILTERED_UUID]",
        ),
        (
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?",
            "[FILTERED_TIMESTAMP]",
        ),
        (
            r#""integrity_hash":"[0-9a-f]{64}""#,
            r#""integrity_hash":"[FILTERED_HASH]""#,
        ),
        (
            r#""timeline_hash":"[0-9a-f]{64}""#,
            r#""timeline_hash":"[FILTERED_HASH]""#,
        ),
    ] {
        scrubbed = Regex::new(pattern)
            .expect("golden scrub regex should compile")
            .replace_all(&scrubbed, replacement)
            .into_owned();
    }
    scrubbed
}

#[test]
fn replay_bundle_canonical_json_golden() {
    let events = golden_fixture_events();
    let bundle = generate_replay_bundle("INC-GOLDEN-TEST-001", &events)
        .expect("golden fixture bundle generation should succeed");

    let canonical_json =
        to_canonical_json(&bundle).expect("canonical JSON serialization should succeed");
    let scrubbed_json = scrub_replay_bundle_golden(&canonical_json);

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        let golden_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden/replay_bundle/canonical_small_fixture.golden");
        std::fs::write(&golden_path, &scrubbed_json).expect("write replay-bundle golden");
        return;
    }

    assert_eq!(
        scrubbed_json, CANONICAL_SMALL_FIXTURE_GOLDEN,
        "replay bundle canonical JSON must match the reviewed golden artifact"
    );
}

#[test]
fn replay_bundle_determinism_verification() {
    // Verify that the same inputs always produce identical output
    let events = golden_fixture_events();

    let bundle1 =
        generate_replay_bundle("INC-DETERMINISM-TEST", &events).expect("first bundle generation");
    let bundle2 =
        generate_replay_bundle("INC-DETERMINISM-TEST", &events).expect("second bundle generation");

    let json1 = to_canonical_json(&bundle1).expect("first canonical JSON");
    let json2 = to_canonical_json(&bundle2).expect("second canonical JSON");

    assert_eq!(json1, json2, "replay bundle output must be deterministic");
    assert_eq!(
        bundle1.bundle_id, bundle2.bundle_id,
        "bundle IDs must be identical"
    );
    assert_eq!(
        bundle1.integrity_hash, bundle2.integrity_hash,
        "integrity hashes must match"
    );
}

#[test]
fn replay_bundle_structure_golden() {
    // Test that captures the high-level structure for detecting schema changes
    let events = golden_fixture_events();
    let bundle = generate_replay_bundle("INC-STRUCTURE-TEST", &events)
        .expect("structure test bundle generation");

    // Use insta's JSON snapshot for structured comparison
    insta::assert_json_snapshot!(bundle, {
        ".bundle_id" => "[BUNDLE_ID]",
        ".integrity_hash" => "[INTEGRITY_HASH]",
        ".created_at" => "[CREATED_AT]",
        ".timeline[].timestamp" => "[TIMESTAMP]"
    });
}
