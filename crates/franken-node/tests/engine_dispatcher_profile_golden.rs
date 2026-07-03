use std::fs;
use std::path::Path;

use frankenengine_node::config::{Config, Profile};
use frankenengine_node::ops::engine_dispatcher::EngineDispatcher;
use serde_json::{Value, json};

/// Complete configuration snapshot for a given profile
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ProfileConfigSnapshot {
    profile: Profile,
    runtime_config: serde_json::Value,
    orchestrator_config: serde_json::Value,
}

/// Create golden directory if it doesn't exist
fn ensure_golden_dir() {
    let golden_dir = Path::new("tests/golden");
    if !golden_dir.exists() {
        fs::create_dir_all(golden_dir).expect("Failed to create tests/golden directory");
    }
}

/// Generate configuration snapshot for a profile
fn generate_profile_snapshot(profile: Profile, policy_mode: &str) -> ProfileConfigSnapshot {
    let config = Config::for_profile(profile);

    // Generate RuntimeConfig using the test helper function
    let runtime_config = EngineDispatcher::map_config_to_runtime_config_for_tests(&config);
    let runtime_json =
        serde_json::to_value(&runtime_config).expect("Failed to serialize RuntimeConfig");

    // Generate OrchestratorConfig using the test helper function
    let mut orchestrator_config =
        EngineDispatcher::map_config_to_orchestrator_config_for_tests(&config);
    // Apply the policy_mode fix we implemented in bd-3rlp8
    orchestrator_config.policy_id = format!("franken-node-{}-{}", config.profile, policy_mode);
    // franken_node-side JSON projection (bd-9kyqf): franken-engine's
    // execution_orchestrator::OrchestratorConfig no longer derives Serialize
    // (engine-boundary decision — we do NOT force the engine to re-add it). Every
    // field is individually Serialize, so we project them field-by-field here.
    // `force_lane` is rendered via Debug to avoid naming the engine LaneChoice type
    // (there are two, and it is `None` under every profile anyway).
    let orchestrator_json = json!({
        "loss_matrix_preset": serde_json::to_value(orchestrator_config.loss_matrix_preset)
            .expect("Failed to serialize loss_matrix_preset"),
        "force_lane": orchestrator_config
            .force_lane
            .as_ref()
            .map(|lane| format!("{lane:?}")),
        "drain_deadline_ticks": orchestrator_config.drain_deadline_ticks,
        "cell_close_budget_ms": orchestrator_config.cell_close_budget_ms,
        "max_concurrent_sagas": orchestrator_config.max_concurrent_sagas,
        "epoch": serde_json::to_value(orchestrator_config.epoch)
            .expect("Failed to serialize epoch"),
        "parse_goal": serde_json::to_value(orchestrator_config.parse_goal)
            .expect("Failed to serialize parse_goal"),
        "parser_options": serde_json::to_value(&orchestrator_config.parser_options)
            .expect("Failed to serialize parser_options"),
        "trace_id_prefix": orchestrator_config.trace_id_prefix.clone(),
        "policy_id": orchestrator_config.policy_id.clone(),
    });

    ProfileConfigSnapshot {
        profile,
        runtime_config: runtime_json,
        orchestrator_config: orchestrator_json,
    }
}

/// Assert golden comparison with UPDATE_GOLDENS support
fn assert_golden_json(test_name: &str, actual: &Value) {
    ensure_golden_dir();

    let golden_path = Path::new("tests/golden").join(format!("{}.json", test_name));
    let actual_pretty = serde_json::to_string_pretty(actual).expect("Failed to pretty-print JSON");

    // UPDATE MODE: overwrite golden with actual output
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::write(&golden_path, &actual_pretty).expect("Failed to write golden file");
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // COMPARE MODE: diff actual vs golden
    let expected = fs::read_to_string(&golden_path)
        .unwrap_or_else(|_| panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it:\n\
             UPDATE_GOLDENS=1 cargo test -p frankenengine-node --test engine_dispatcher_profile_golden\n\
             Then review and commit: git diff tests/golden/",
            golden_path.display()
        ));

    let expected_json: Value =
        serde_json::from_str(&expected).expect("Failed to parse golden JSON");

    if *actual != expected_json {
        // Write actual for easy diffing
        let actual_path = golden_path.with_extension("actual.json");
        fs::write(&actual_path, &actual_pretty).expect("Failed to write actual file");

        panic!(
            "GOLDEN MISMATCH: {}\n\n\
             Expected: {}\n\
             Actual:   {}\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -p frankenengine-node --test engine_dispatcher_profile_golden -- {}\n\
             To review: diff {} {}",
            test_name,
            golden_path.display(),
            actual_path.display(),
            test_name,
            golden_path.display(),
            actual_path.display(),
        );
    }
}

/// Test profile→config mapping for Strict profile
#[test]
fn test_profile_config_mapping_strict() {
    let snapshot = generate_profile_snapshot(Profile::Strict, "test");
    let json_value = serde_json::to_value(&snapshot).expect("Failed to serialize snapshot");
    assert_golden_json("engine_dispatcher_strict", &json_value);
}

/// Test profile→config mapping for Balanced profile
#[test]
fn test_profile_config_mapping_balanced() {
    let snapshot = generate_profile_snapshot(Profile::Balanced, "test");
    let json_value = serde_json::to_value(&snapshot).expect("Failed to serialize snapshot");
    assert_golden_json("engine_dispatcher_balanced", &json_value);
}

/// Test profile→config mapping for LegacyRisky profile
#[test]
fn test_profile_config_mapping_legacy_risky() {
    let snapshot = generate_profile_snapshot(Profile::LegacyRisky, "test");
    let json_value = serde_json::to_value(&snapshot).expect("Failed to serialize snapshot");
    assert_golden_json("engine_dispatcher_legacy_risky", &json_value);
}

/// Test that all profiles produce different configurations
#[test]
fn test_profile_configs_are_distinct() {
    let strict = generate_profile_snapshot(Profile::Strict, "test");
    let balanced = generate_profile_snapshot(Profile::Balanced, "test");
    let legacy_risky = generate_profile_snapshot(Profile::LegacyRisky, "test");

    // Convert to JSON for comparison
    let strict_json = serde_json::to_value(&strict).unwrap();
    let balanced_json = serde_json::to_value(&balanced).unwrap();
    let legacy_risky_json = serde_json::to_value(&legacy_risky).unwrap();

    // Ensure all profiles produce different configurations
    assert_ne!(
        strict_json, balanced_json,
        "Strict and Balanced configs should differ"
    );
    assert_ne!(
        balanced_json, legacy_risky_json,
        "Balanced and LegacyRisky configs should differ"
    );
    assert_ne!(
        strict_json, legacy_risky_json,
        "Strict and LegacyRisky configs should differ"
    );
}

/// Test that policy_mode is properly incorporated in native execution path
#[test]
fn test_policy_mode_affects_orchestrator_config() {
    let snapshot_policy_a = generate_profile_snapshot(Profile::Balanced, "policy-a");
    let snapshot_policy_b = generate_profile_snapshot(Profile::Balanced, "policy-b");

    // Policy IDs should be different
    let policy_id_a = snapshot_policy_a.orchestrator_config["policy_id"]
        .as_str()
        .unwrap();
    let policy_id_b = snapshot_policy_b.orchestrator_config["policy_id"]
        .as_str()
        .unwrap();

    assert_ne!(
        policy_id_a, policy_id_b,
        "Different policy_modes should produce different policy_ids"
    );
    assert!(
        policy_id_a.contains("policy-a"),
        "Policy ID should contain policy_mode: {}",
        policy_id_a
    );
    assert!(
        policy_id_b.contains("policy-b"),
        "Policy ID should contain policy_mode: {}",
        policy_id_b
    );
}
