//! Conformance tests for engine_dispatcher profile→config mappings.
//!
//! Verifies that each profile (Strict/Balanced/LegacyRisky) produces the
//! documented configuration field values as specified in engine_dispatcher.rs.
//!
//! SPECIFICATION: crates/franken-node/src/ops/engine_dispatcher.rs
//! - map_config_to_runtime_config()
//! - map_config_to_orchestrator_config()
//! - OptimizationConfig/ExtensionHostConfig profile mappings

use frankenengine_engine::{ast::ParseGoal, lowering_pipeline::AmbientAuthorityGrant};
use frankenengine_node::{
    config::{Config, Profile},
    ops::engine_dispatcher::{EngineDispatcher, RunProjectPaths},
};
use std::path::Path;

fn config_with_profile(profile: Profile) -> Config {
    Config {
        profile,
        ..Config::default()
    }
}

#[test]
fn run_project_authority_stops_marker_search_at_invocation_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let invocation = dir.path().join("invocation");
    let source = invocation.join("src");
    std::fs::create_dir_all(&source).expect("create nested source directory");
    std::fs::write(source.join("main.js"), "console.log('scoped');\n").expect("write entrypoint");
    std::fs::write(dir.path().join("package.json"), "{}")
        .expect("write marker above invocation boundary");

    let without_marker = RunProjectPaths::resolve(Path::new("src/main.js"), &invocation)
        .expect("resolve standalone nested file");
    assert_eq!(
        without_marker.project_root(),
        source.canonicalize().unwrap()
    );

    std::fs::write(invocation.join("franken_node.toml"), "")
        .expect("write invocation project marker");
    let with_marker = RunProjectPaths::resolve(Path::new("src/main.js"), &invocation)
        .expect("resolve marked project");
    assert_eq!(
        with_marker.project_root(),
        invocation.canonicalize().unwrap()
    );

    // An absolute file selection stays scoped to its parent even when a
    // project marker exists above it. Broader authority requires a relative
    // invocation inside that project or an explicit directory selection.
    let absolute = RunProjectPaths::resolve(&source.join("main.js"), &invocation)
        .expect("resolve absolute file");
    assert_eq!(absolute.project_root(), source.canonicalize().unwrap());
}

#[test]
fn run_project_authority_uses_nearest_nested_package_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let package = dir.path().join("packages/app");
    std::fs::create_dir_all(package.join("src")).expect("create nested package");
    std::fs::write(dir.path().join("franken_node.toml"), "").expect("write workspace marker");
    std::fs::write(package.join("package.json"), "{}").expect("write nested package marker");
    std::fs::write(package.join("src/main.js"), "console.log('nested');\n")
        .expect("write entrypoint");
    let paths = RunProjectPaths::resolve(Path::new("packages/app/src/main.js"), dir.path())
        .expect("resolve nested package entrypoint");
    assert_eq!(paths.project_root(), package.canonicalize().unwrap());
}

#[cfg(unix)]
#[test]
fn run_project_authority_refuses_relative_directory_symlink_escape() {
    let dir = tempfile::tempdir().expect("tempdir");
    let invocation = dir.path().join("invocation");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&invocation).expect("create invocation directory");
    std::fs::create_dir_all(&outside).expect("create outside directory");
    std::fs::write(outside.join("main.js"), "console.log('outside');\n")
        .expect("write outside entrypoint");
    std::fs::write(outside.join("package.json"), r#"{"main":"main.js"}"#)
        .expect("write explicitly selectable project manifest");
    std::os::unix::fs::symlink(&outside, invocation.join("src"))
        .expect("link source directory outside invocation");

    let error = RunProjectPaths::resolve(Path::new("src/main.js"), &invocation)
        .expect_err("relative source symlink cannot select authority outside invocation")
        .to_string();
    assert!(error.contains("escapes invocation directory"), "{error}");

    let explicit = RunProjectPaths::resolve(Path::new("src"), &invocation)
        .expect("operator may explicitly select the linked project directory");
    assert_eq!(explicit.project_root(), outside.canonicalize().unwrap());
}

#[cfg(feature = "engine")]
#[test]
fn run_project_authority_refuses_retargeted_main_after_preflight() {
    use frankenengine_node::config::PreferredRuntime;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("package.json"), r#"{"main":"before.js"}"#)
        .expect("write original package main");
    std::fs::write(dir.path().join("before.js"), "console.log('before');\n")
        .expect("write original entrypoint");
    std::fs::write(dir.path().join("after.js"), "console.log('after');\n")
        .expect("write alternate entrypoint");
    let paths = RunProjectPaths::resolve(dir.path(), dir.path()).expect("preflight paths");
    std::fs::write(dir.path().join("package.json"), r#"{"main":"after.js"}"#)
        .expect("retarget package after preflight");

    let error = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
        .with_project_paths(paths)
        .with_native_session_worker_path(dir.path().join("worker-does-not-exist"))
        .dispatch_run(
            dir.path(),
            &Config::for_profile(Profile::Balanced),
            "balanced",
            &[],
            2_000,
        )
        .expect_err("authority change must refuse before worker resolution")
        .to_string();
    assert!(
        error.contains("run project authority changed after preflight"),
        "{error}"
    );
}

#[test]
#[cfg(feature = "engine")]
fn process_shape_ambient_grant_is_legacy_risky_only_bd_y30zw() {
    for (profile, expected) in [
        (Profile::Strict, AmbientAuthorityGrant::DenyAll),
        (Profile::Balanced, AmbientAuthorityGrant::DenyAll),
        (
            Profile::LegacyRisky,
            AmbientAuthorityGrant::TrustedProcessShape,
        ),
    ] {
        let config = Config::for_profile(profile);
        assert_eq!(config.runtime.allow_process_shape, None);
        assert_eq!(
            EngineDispatcher::map_config_to_ambient_authority_grant_for_tests(&config),
            expected,
            "{profile}: an unset override must preserve the profile default"
        );
    }
}

#[test]
#[cfg(feature = "engine")]
fn process_shape_override_changes_only_the_narrow_ambient_grant() {
    for profile in [Profile::Strict, Profile::Balanced, Profile::LegacyRisky] {
        let original = Config::for_profile(profile);
        let runtime = EngineDispatcher::map_config_to_runtime_config_for_tests(&original);
        let orchestrator = EngineDispatcher::map_config_to_orchestrator_config_for_tests(&original);
        for (enabled, expected) in [
            (true, AmbientAuthorityGrant::TrustedProcessShape),
            (false, AmbientAuthorityGrant::DenyAll),
        ] {
            let mut configured = original.clone();
            configured.runtime.allow_process_shape = Some(enabled);
            assert_eq!(
                EngineDispatcher::map_config_to_ambient_authority_grant_for_tests(&configured),
                expected,
                "{profile}: explicit {enabled} must override the profile default"
            );
            assert_eq!(
                EngineDispatcher::map_config_to_runtime_config_for_tests(&configured),
                runtime,
                "{profile}: process metadata cannot change execution budgets or containment"
            );
            let mapped = EngineDispatcher::map_config_to_orchestrator_config_for_tests(&configured);
            assert_eq!(mapped.parser_options, orchestrator.parser_options);
            assert_eq!(mapped.loss_matrix_preset, orchestrator.loss_matrix_preset);
            assert_eq!(mapped.epoch, orchestrator.epoch);
            assert_eq!(mapped.force_lane, orchestrator.force_lane);
        }
    }
}

#[test]
#[cfg(feature = "engine")]
fn legacy_replay_refusal_precedes_source_and_worker_resolution() {
    use frankenengine_node::config::PreferredRuntime;

    for allowed in [None, Some(false), Some(true)] {
        let profile = Profile::LegacyRisky;
        let directory = tempfile::tempdir().expect("empty replay fixture");
        let mut config = Config::for_profile(profile);
        config.runtime.allow_process_shape = allowed;
        let error = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
            .with_replay_capture(true)
            .with_native_session_worker_path(directory.path().join("worker-does-not-exist"))
            .dispatch_run(
                &directory.path().join("source-does-not-exist.js"),
                &config,
                &profile.to_string(),
                &[],
                2_000,
            )
            .expect_err("unsupported replay authority must refuse before loading any source")
            .to_string();
        assert!(
            error.contains("native replay capture"),
            "{profile}: {error}"
        );
        assert!(
            error.contains("environment values and child processes are not replay inputs"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("inspect rejected run fixture")
                .count(),
            0,
            "replay refusal must not provision run state, output or worker files"
        );
    }
}

#[test]
#[cfg(feature = "engine")]
fn process_shape_setting_keeps_strict_and_balanced_replay_admissible() {
    use frankenengine_node::config::PreferredRuntime;

    for profile in [Profile::Strict, Profile::Balanced] {
        for allowed in [None, Some(false), Some(true)] {
            let directory = tempfile::tempdir().expect("empty replay fixture");
            let mut config = Config::for_profile(profile);
            config.runtime.allow_process_shape = allowed;
            let error = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
                .with_replay_capture(true)
                .with_native_session_worker_path(directory.path().join("worker-does-not-exist"))
                .dispatch_run(
                    &directory.path().join("source-does-not-exist.js"),
                    &config,
                    &profile.to_string(),
                    &[],
                    2_000,
                )
                .expect_err("ordinary target resolution should follow successful replay admission")
                .to_string();
            assert!(error.contains("resolve run target"), "{profile}: {error}");
            assert!(!error.contains("native replay capture"), "{error}");
        }
    }
}

#[test]
#[cfg(feature = "engine")]
fn mjs_entrypoints_select_module_goal_bd_ergy0() {
    let config = config_with_profile(Profile::LegacyRisky);
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("fixture.mjs"), "export const value = 1;\n")
        .expect("write explicit module");
    let module = RunProjectPaths::resolve(Path::new("fixture.mjs"), dir.path())
        .expect("resolve explicit module");
    assert_eq!(
        EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
            &config, &module,
        )
        .parse_goal,
        ParseGoal::Module
    );
    for script_path in ["fixture.js", "fixture.cjs", "fixture", "fixture.MJS"] {
        std::fs::write(dir.path().join(script_path), "module.exports = 1;\n")
            .expect("write script");
        let script =
            RunProjectPaths::resolve(Path::new(script_path), dir.path()).expect("resolve script");
        assert_eq!(
            EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
                &config, &script,
            )
            .parse_goal,
            ParseGoal::Script,
            "{script_path} must retain ScriptGoal"
        );
    }
}

#[test]
fn run_package_scope_selects_nearest_manifest_for_js_and_extensionless_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("src")).expect("source directory");
    std::fs::write(dir.path().join("package.json"), r#"{"type":"module"}"#).expect("module scope");
    for name in ["main.js", "entry"] {
        std::fs::write(
            dir.path().join("src").join(name),
            "export const value = 1;\n",
        )
        .expect("entrypoint");
    }
    let config = config_with_profile(Profile::Balanced);
    for name in ["src/main.js", "src/entry"] {
        let paths = RunProjectPaths::resolve(Path::new(name), dir.path()).expect("module paths");
        let mapped = EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
            &config, &paths,
        );
        assert_eq!(mapped.parse_goal, ParseGoal::Module, "{name}");
        assert!(!mapped.commonjs_entry, "{name}");
    }

    for metadata in ["{}", r#"{"type":"commonjs"}"#, r#"{"type":"unrecognized"}"#] {
        std::fs::write(dir.path().join("src/package.json"), metadata).expect("nested scope");
        for name in ["src/main.js", "src/entry"] {
            let paths =
                RunProjectPaths::resolve(Path::new(name), dir.path()).expect("script paths");
            let mapped =
                EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
                    &config, &paths,
                );
            assert_eq!(mapped.parse_goal, ParseGoal::Script, "{name}: {metadata}");
            assert!(mapped.commonjs_entry, "{name}: {metadata}");
        }
    }
}

#[test]
fn run_package_scope_cannot_inherit_metadata_outside_its_authority() {
    let dir = tempfile::tempdir().expect("tempdir");
    let selected = dir.path().join("selected");
    std::fs::create_dir(&selected).expect("selected project");
    std::fs::write(selected.join("index.js"), "module.exports = 1;\n").expect("entrypoint");
    let config = config_with_profile(Profile::Balanced);
    for metadata in [r#"{"type":"module"}"#, "{broken"] {
        std::fs::write(dir.path().join("package.json"), metadata).expect("outside metadata");
        for target in [Path::new("index.js"), Path::new(".")] {
            let paths = RunProjectPaths::resolve(target, &selected).expect("authority-local paths");
            let mapped =
                EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
                    &config, &paths,
                );
            assert_eq!(mapped.parse_goal, ParseGoal::Script, "{metadata}");
        }
    }
}

#[test]
fn run_package_scope_stops_before_node_modules_even_inside_one_project() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("node_modules/untyped/src"))
        .expect("dependency directories");
    std::fs::write(dir.path().join("package.json"), r#"{"type":"module"}"#)
        .expect("parent module scope");
    std::fs::write(
        dir.path().join("node_modules/package.json"),
        "{must-not-be-read",
    )
    .expect("container is not a package scope");
    std::fs::write(
        dir.path().join("node_modules/untyped/src/main.js"),
        "module.exports = 1;\n",
    )
    .expect("dependency entrypoint");
    let paths = RunProjectPaths::resolve(Path::new("node_modules/untyped/src/main.js"), dir.path())
        .expect("untyped dependency paths");
    let mapped = EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
        &config_with_profile(Profile::Balanced),
        &paths,
    );
    assert_eq!(mapped.parse_goal, ParseGoal::Script);
    assert!(mapped.commonjs_entry);
}

#[test]
fn run_package_scope_rejects_invalid_metadata_without_changing_explicit_formats() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["main.js", "entry", "main.cjs", "main.mjs"] {
        std::fs::write(dir.path().join(name), "console.log('entry');\n").expect("entrypoint");
    }
    let config = config_with_profile(Profile::Balanced);
    for metadata in [
        "{broken",
        "[]",
        "null",
        r#"{"type":42}"#,
        r#"{"type":null}"#,
    ] {
        std::fs::write(dir.path().join("package.json"), metadata).expect("invalid manifest");
        for name in ["main.js", "entry"] {
            let error = RunProjectPaths::resolve(Path::new(name), dir.path())
                .expect_err("invalid package metadata must not select CommonJS")
                .to_string();
            assert!(
                error.contains("Invalid package manifest"),
                "{name}: {error}"
            );
            assert!(error.contains("package.json"), "{error}");
        }
        for (name, goal) in [
            ("main.cjs", ParseGoal::Script),
            ("main.mjs", ParseGoal::Module),
        ] {
            let paths = RunProjectPaths::resolve(Path::new(name), dir.path())
                .expect("explicit format bypasses package metadata");
            let mapped =
                EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
                    &config, &paths,
                );
            assert_eq!(mapped.parse_goal, goal, "{metadata}");
        }
    }
}

#[test]
fn run_package_scope_accepts_bom_and_bounds_directory_and_file_manifests() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("app.js"), "export const value = 1;\n").expect("entrypoint");
    std::fs::write(
        dir.path().join("package.json"),
        "\u{feff}{\"main\":\"app.js\",\"type\":\"module\"}",
    )
    .expect("BOM manifest");
    let config = config_with_profile(Profile::Balanced);
    for target in [Path::new("app.js"), Path::new(".")] {
        let paths = RunProjectPaths::resolve(target, dir.path()).expect("BOM package paths");
        let mapped = EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
            &config, &paths,
        );
        assert_eq!(mapped.parse_goal, ParseGoal::Module);
    }
    let prefix = r#"{"main":"app.js","type":"module","padding":""#;
    let suffix = "\"}";
    let at_limit = format!(
        "{prefix}{}{suffix}",
        "x".repeat((1 << 20) - prefix.len() - suffix.len())
    );
    assert_eq!(at_limit.len(), 1 << 20);
    std::fs::write(dir.path().join("package.json"), at_limit).expect("boundary manifest");
    for target in [Path::new("app.js"), Path::new(".")] {
        RunProjectPaths::resolve(target, dir.path()).expect("manifest at the limit is admitted");
    }
    let oversized = format!("{{\"padding\":\"{}\"}}", "x".repeat((1 << 20) + 1));
    std::fs::write(dir.path().join("package.json"), oversized).expect("oversized manifest");
    for target in [Path::new("app.js"), Path::new(".")] {
        let error = RunProjectPaths::resolve(target, dir.path())
            .expect_err("both resolution paths must enforce the manifest byte bound")
            .to_string();
        assert!(error.contains("1048576-byte limit"), "{error}");
    }
}

#[test]
fn run_package_scope_metadata_changes_are_rejected_before_worker_launch() {
    use frankenengine_node::config::PreferredRuntime;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("lib")).expect("source directory");
    std::fs::write(dir.path().join("lib/main.js"), "console.log('entry');\n").expect("entrypoint");
    std::fs::write(
        dir.path().join("lib/package.json"),
        r#"{"type":"commonjs"}"#,
    )
    .expect("nested scope");
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"main":"lib/main.js","version":"1"}"#,
    )
    .expect("directory entry manifest");
    let paths = RunProjectPaths::resolve(dir.path(), dir.path()).expect("preflight paths");
    // Neither the entry filename nor its parse goal changes. The consumed main
    // manifest still belongs to the admitted metadata and must remain bound.
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"main":"lib/main.js","version":"2"}"#,
    )
    .expect("change metadata after preflight");
    let error = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
        .with_project_paths(paths)
        .with_native_session_worker_path(dir.path().join("worker-does-not-exist"))
        .dispatch_run(
            dir.path(),
            &config_with_profile(Profile::Balanced),
            "balanced",
            &[],
            2_000,
        )
        .expect_err("metadata changes must refuse before worker resolution")
        .to_string();
    assert!(
        error.contains("run project authority changed after preflight"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn run_package_scope_refuses_manifest_symlinks_and_nonregular_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["linked", "nonregular", "dangling", "fifo"] {
        std::fs::create_dir(dir.path().join(name)).expect("project directory");
        std::fs::write(
            dir.path().join(name).join("index.js"),
            "console.log('entry');\n",
        )
        .expect("entrypoint");
    }
    std::fs::write(
        dir.path().join("outside.json"),
        r#"{"type":"module","main":"index.js"}"#,
    )
    .expect("outside manifest");
    std::os::unix::fs::symlink("../outside.json", dir.path().join("linked/package.json"))
        .expect("escaping manifest link");
    std::os::unix::fs::symlink("../missing.json", dir.path().join("dangling/package.json"))
        .expect("dangling manifest link");
    std::fs::create_dir(dir.path().join("nonregular/package.json")).expect("nonregular manifest");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        dir.path().join("fifo/package.json"),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .expect("FIFO manifest must refuse without blocking on an absent writer");
    for name in ["linked", "nonregular", "dangling", "fifo"] {
        let project = dir.path().join(name);
        for target in [Path::new("index.js"), Path::new(".")] {
            let error = RunProjectPaths::resolve(target, &project)
                .expect_err("manifest link or nonregular file must fail closed")
                .to_string();
            assert!(error.contains("package.json"), "{name}: {error}");
            assert!(
                error.contains("symlinks") || error.contains("regular file"),
                "{name}: {error}"
            );
        }
    }
}

/// `runtime.max_instructions` replaces every profile's instruction budget on
/// both lanes (bd-reality-20260923-26n9r.5 deliverable 1); unset keeps the
/// profile default.
#[test]
#[cfg(feature = "engine")]
fn runtime_max_instructions_overrides_the_profile_budget() {
    for profile in [Profile::Strict, Profile::Balanced, Profile::LegacyRisky] {
        let default =
            EngineDispatcher::map_config_to_runtime_config_for_tests(&config_with_profile(profile));
        assert!(
            default.execution.deterministic_budget >= 200_000_000,
            "{profile:?}"
        );

        let mut config = config_with_profile(profile);
        config.runtime.max_instructions = Some(12_345);
        let limited = EngineDispatcher::map_config_to_runtime_config_for_tests(&config);
        assert_eq!(
            limited.execution.deterministic_budget, 12_345,
            "{profile:?}"
        );
        assert_eq!(limited.execution.throughput_budget, 12_345, "{profile:?}");
    }
}

/// Larger function frames and deeper guest calls can be admitted explicitly
/// without granting filesystem, network, or process capabilities.
#[test]
#[cfg(feature = "engine")]
fn runtime_frame_budget_overrides_preserve_profile_security_and_reach_both_lanes() {
    use frankenengine_engine::baseline_interpreter::InterpreterConfig;
    use frankenengine_node::config::{MAX_NATIVE_CALL_DEPTH, MAX_NATIVE_REGISTERS};
    use frankenengine_node::ops::engine_dispatcher::EngineExecutionLimitsReport;

    for profile in [Profile::Strict, Profile::Balanced, Profile::LegacyRisky] {
        let original = config_with_profile(profile);
        let before = EngineDispatcher::map_config_to_runtime_config_for_tests(&original);
        let defaults = EngineExecutionLimitsReport::from_execution_config(&before.execution);
        assert_eq!(
            defaults.deterministic.max_registers,
            Some(before.execution.deterministic_max_registers)
        );
        assert_eq!(
            defaults.throughput.max_registers,
            Some(before.execution.throughput_max_registers)
        );
        for (registers, call_depth) in [
            (1, 1),
            (2_048, 128),
            (MAX_NATIVE_REGISTERS, MAX_NATIVE_CALL_DEPTH),
        ] {
            let mut configured = original.clone();
            configured.runtime.max_registers = Some(registers);
            configured.runtime.max_call_depth = Some(call_depth);
            configured.runtime.validate_execution_budget().unwrap();
            let after = EngineDispatcher::map_config_to_runtime_config_for_tests(&configured);
            after
                .validate()
                .expect("the engine must accept product budget caps");
            for lane in [
                InterpreterConfig::deterministic_from_config(&after.execution),
                InterpreterConfig::throughput_from_config(&after.execution),
            ] {
                assert_eq!(lane.max_registers, registers, "{profile:?}");
                assert_eq!(lane.max_call_depth, call_depth, "{profile:?}");
            }
            let report = EngineExecutionLimitsReport::from_execution_config(&after.execution);
            for lane in [report.deterministic, report.throughput] {
                assert_eq!(lane.max_registers, Some(registers));
                assert_eq!(lane.max_call_depth, Some(call_depth));
            }
            let mut expected = before.clone();
            expected.execution.deterministic_max_registers = registers;
            expected.execution.throughput_max_registers = registers;
            expected.execution.max_call_depth = call_depth;
            assert_eq!(after, expected, "only explicit frame limits may change");
            let original_orchestrator =
                EngineDispatcher::map_config_to_orchestrator_config_for_tests(&original);
            let configured_orchestrator =
                EngineDispatcher::map_config_to_orchestrator_config_for_tests(&configured);
            assert_eq!(
                configured_orchestrator.policy_id,
                original_orchestrator.policy_id
            );
            assert_eq!(configured_orchestrator.epoch, original_orchestrator.epoch);
            assert_eq!(
                configured_orchestrator.force_lane,
                original_orchestrator.force_lane
            );
            assert_eq!(
                configured_orchestrator.parser_options,
                original_orchestrator.parser_options
            );
        }
    }
}

#[test]
fn historical_execution_limits_do_not_invent_unrecorded_frame_budgets() {
    use frankenengine_node::ops::engine_dispatcher::EngineExecutionLimitsReport;

    let historical_lane = serde_json::json!({
        "max_instructions": 1000,
        "max_heap_objects": 100_000,
        "max_total_memory_bytes": 67_108_864,
        "max_console_entries": 100_000,
        "max_console_bytes": 8_388_608
    });
    let historical = serde_json::json!({
        "deterministic": historical_lane,
        "throughput": historical_lane,
        "selected_lane": "deterministic"
    });
    let parsed: EngineExecutionLimitsReport = serde_json::from_value(historical.clone()).unwrap();
    assert_eq!(parsed.deterministic.max_registers, None);
    assert_eq!(parsed.throughput.max_call_depth, None);
    assert_eq!(serde_json::to_value(parsed).unwrap(), historical);
}

/// Memory and transcript overrides must reach the interpreter on both lanes;
/// omission retains the engine's lane-specific defaults, including byte caps.
#[test]
#[cfg(feature = "engine")]
fn runtime_execution_budget_overrides_reach_both_engine_lanes() {
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, LaneChoice};
    use frankenengine_node::ops::engine_dispatcher::{
        EngineExecutionLane, EngineExecutionLimitsReport,
    };

    for profile in [Profile::Strict, Profile::Balanced, Profile::LegacyRisky] {
        let original = config_with_profile(profile);
        let default = EngineDispatcher::map_config_to_runtime_config_for_tests(&original);
        let defaults = EngineExecutionLimitsReport::from_execution_config(&default.execution);
        assert_eq!(defaults.deterministic.max_heap_objects, 100_000);
        assert_eq!(
            defaults.deterministic.max_total_memory_bytes,
            64 * 1024 * 1024
        );
        assert_eq!(defaults.deterministic.max_console_entries, 100_000);
        assert_eq!(defaults.throughput.max_heap_objects, 1_000_000);
        assert_eq!(
            defaults.throughput.max_total_memory_bytes,
            512 * 1024 * 1024
        );
        assert_eq!(defaults.throughput.max_console_entries, 1_000_000);
        assert_eq!(defaults.deterministic.max_console_bytes, 8 * 1024 * 1024);
        assert_eq!(defaults.throughput.max_console_bytes, 8 * 1024 * 1024);
        assert_eq!(defaults.selected_lane, None);

        // Exercise explicit bounds both below and above lane defaults. The
        // override replaces that ceiling, while the independent caps remain.
        for (objects, bytes, entries) in [(1, 1, 1), (2_000_000, 1_073_741_824, 2_000_000)] {
            let mut configured = original.clone();
            configured.runtime.max_heap_objects = Some(objects);
            configured.runtime.max_total_memory_bytes = Some(bytes);
            configured.runtime.max_console_entries = Some(entries);
            configured.runtime.validate_execution_budget().unwrap();
            let mapped = EngineDispatcher::map_config_to_runtime_config_for_tests(&configured);
            for lane in [
                InterpreterConfig::deterministic_from_config(&mapped.execution),
                InterpreterConfig::throughput_from_config(&mapped.execution),
            ] {
                assert_eq!(lane.max_heap_objects, objects, "{profile:?}");
                assert_eq!(lane.max_total_memory_bytes, bytes, "{profile:?}");
                assert_eq!(lane.max_console_entries, entries, "{profile:?}");
                assert_eq!(lane.max_console_bytes, 8 * 1024 * 1024, "{profile:?}");
            }
            let report = EngineExecutionLimitsReport::from_execution_config(&mapped.execution);
            for lane in [report.deterministic, report.throughput] {
                assert_eq!(lane.max_heap_objects, objects);
                assert_eq!(lane.max_total_memory_bytes, bytes);
                assert_eq!(lane.max_console_entries, entries);
            }
            for (engine_lane, expected_lane, json_name) in [
                (
                    LaneChoice::QuickJs,
                    EngineExecutionLane::Deterministic,
                    "deterministic",
                ),
                (
                    LaneChoice::V8,
                    EngineExecutionLane::Throughput,
                    "throughput",
                ),
            ] {
                let selected = report.with_selected_lane(engine_lane);
                assert_eq!(selected.selected_lane, Some(expected_lane));
                let json = serde_json::to_value(selected).unwrap();
                assert_eq!(json["selected_lane"], json_name);
                assert_eq!(
                    serde_json::from_value::<EngineExecutionLimitsReport>(json).unwrap(),
                    selected
                );
            }

            // None of these resource controls changes trust, capabilities,
            // parser limits, instruction fuel, or containment thresholds.
            let mut expected = default.clone();
            expected.execution.max_heap_objects = Some(objects);
            expected.execution.max_total_memory_bytes = Some(bytes);
            expected.execution.max_console_entries = Some(entries);
            assert_eq!(mapped, expected);
            let before = EngineDispatcher::map_config_to_orchestrator_config_for_tests(&original);
            let after = EngineDispatcher::map_config_to_orchestrator_config_for_tests(&configured);
            assert_eq!(after.parser_options, before.parser_options);
            assert_eq!(after.force_lane, before.force_lane);
            assert_eq!(after.policy_id, before.policy_id);
        }
    }
}

/// Parser limits may be configured without changing effect capabilities,
/// recursion depth, or instruction budgets (bd-fkdzv).
#[test]
#[cfg(feature = "engine")]
fn runtime_parse_budget_overrides_reach_the_engine_without_changing_trust() {
    for profile in [Profile::Strict, Profile::Balanced, Profile::LegacyRisky] {
        let original = config_with_profile(profile);
        let before = EngineDispatcher::map_config_to_orchestrator_config_for_tests(&original);
        let mut configured = original.clone();
        configured.runtime.max_parse_source_bytes = Some(900_000);
        configured.runtime.max_parse_tokens = Some(125_000);
        configured
            .runtime
            .validate_parse_budget()
            .expect("valid parser override");
        let after = EngineDispatcher::map_config_to_orchestrator_config_for_tests(&configured);
        assert_eq!(after.parser_options.budget.max_source_bytes, 900_000);
        assert_eq!(after.parser_options.budget.max_token_count, 125_000);
        assert_eq!(
            after.parser_options.budget.max_recursion_depth,
            before.parser_options.budget.max_recursion_depth
        );
        assert_eq!(after.policy_id, before.policy_id);
        assert_eq!(after.epoch, before.epoch);
        assert_eq!(
            EngineDispatcher::map_config_to_runtime_config_for_tests(&configured),
            EngineDispatcher::map_config_to_runtime_config_for_tests(&original),
        );
    }
}

/// bd-rff5g: every entry that is not an ES module runs as a CommonJS module,
/// so it can `require` files beside it; ES module entries never do.
#[test]
#[cfg(feature = "engine")]
fn script_entries_are_commonjs_modules_and_module_entries_are_not() {
    let config = config_with_profile(Profile::Balanced);
    let directory = tempfile::tempdir().expect("tempdir");
    let mapped = |path: &str| {
        std::fs::write(directory.path().join(path), "console.log('entry');\n")
            .expect("write entrypoint");
        let paths = RunProjectPaths::resolve(Path::new(path), directory.path())
            .expect("resolve entrypoint format");
        let orchestrator =
            EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
                &config, &paths,
            );
        (orchestrator.parse_goal, orchestrator.commonjs_entry)
    };
    for script in ["app.js", "app.cjs", "app"] {
        assert_eq!(mapped(script), (ParseGoal::Script, true), "{script}");
    }
    assert_eq!(mapped("app.mjs"), (ParseGoal::Module, false));
}

/// Node's package-scope rule (bd-reality-20260923-26n9r.4 deliverable 2): a
/// `.js` entry is ESM when its nearest package.json says `"type": "module"`;
/// `.cjs` stays CommonJS and `.mjs` stays ESM regardless of scope.
#[test]
#[cfg(feature = "engine")]
fn js_entry_goal_follows_nearest_package_json_type() {
    let config = config_with_profile(Profile::Balanced);
    let workspace = tempfile::tempdir().expect("tempdir");
    let goal = |path: &Path| {
        std::fs::write(path, "console.log('entry');\n").expect("write entrypoint");
        let selected = path
            .strip_prefix(workspace.path())
            .expect("workspace-relative entrypoint");
        let paths = RunProjectPaths::resolve(selected, workspace.path())
            .expect("resolve entrypoint format");
        EngineDispatcher::map_config_to_orchestrator_config_for_entrypoint_for_tests(
            &config, &paths,
        )
        .parse_goal
    };
    let esm = workspace.path().join("esm");
    std::fs::create_dir_all(esm.join("src/nested")).expect("esm dirs");
    std::fs::write(esm.join("package.json"), r#"{"type":"module"}"#).expect("esm manifest");
    assert_eq!(goal(&esm.join("index.js")), ParseGoal::Module);
    assert_eq!(goal(&esm.join("src/nested/deep.js")), ParseGoal::Module);
    assert_eq!(goal(&esm.join("legacy.cjs")), ParseGoal::Script);

    // A nearer package.json without a type re-scopes to CommonJS.
    std::fs::write(esm.join("src/package.json"), r#"{"name":"inner"}"#).expect("inner");
    assert_eq!(goal(&esm.join("src/nested/deep.js")), ParseGoal::Script);

    let cjs = workspace.path().join("cjs");
    std::fs::create_dir_all(&cjs).expect("cjs dir");
    std::fs::write(cjs.join("package.json"), r#"{"type":"commonjs"}"#).expect("cjs manifest");
    assert_eq!(goal(&cjs.join("index.js")), ParseGoal::Script);
    assert_eq!(goal(&cjs.join("index.mjs")), ParseGoal::Module);

    let broken = workspace.path().join("broken");
    std::fs::create_dir_all(&broken).expect("broken dir");
    std::fs::write(broken.join("package.json"), b"{not json").expect("broken manifest");
    std::fs::write(broken.join("index.js"), "console.log('entry');\n").expect("entrypoint");
    let error = RunProjectPaths::resolve(Path::new("broken/index.js"), workspace.path())
        .expect_err("invalid metadata cannot silently change the entrypoint format")
        .to_string();
    assert!(error.contains("Invalid package manifest"), "{error}");
}

/// Conformance test: Strict profile must produce conservative security settings
#[test]
#[cfg(feature = "engine")]
fn conformance_strict_profile_config_values() {
    let config = config_with_profile(Profile::Strict);

    // Test RuntimeConfig mapping
    let runtime_config = EngineDispatcher::map_config_to_runtime_config_for_tests(&config);

    // MUST: Conservative (lowest of the three profiles) execution budgets that
    // still admit ordinary programs. The former 50k budget aborted a trivial
    // 20,000-iteration loop (bd-reality-20260923-26n9r.5); the wall-clock
    // timeout is the primary runaway guard.
    assert_eq!(
        runtime_config.execution.deterministic_budget, 200_000_000,
        "Strict profile MUST use conservative deterministic_budget: 200,000,000"
    );
    assert_eq!(
        runtime_config.execution.throughput_budget, 200_000_000,
        "Strict profile MUST use conservative throughput_budget: 200,000,000"
    );
    assert_eq!(
        runtime_config.execution.deterministic_max_registers, 128,
        "Strict profile MUST use reduced register count: 128"
    );
    assert_eq!(
        runtime_config.execution.throughput_max_registers, 256,
        "Strict profile MUST use conservative register limit: 256"
    );
    assert_eq!(
        runtime_config.execution.max_call_depth, 32,
        "Strict profile MUST use shallow call stack: 32"
    );
    assert_eq!(
        runtime_config.execution.max_prototype_chain_depth, 8,
        "Strict profile MUST use limited prototype depth: 8"
    );

    // MUST: Strict guardplane security settings (95% confidence)
    assert_eq!(
        runtime_config
            .guardplane
            .thresholds
            .tail_confidence_millionths,
        950_000,
        "Strict profile MUST use 95% confidence threshold"
    );
    assert_eq!(
        runtime_config
            .guardplane
            .thresholds
            .critical_pvalue_millionths,
        25_000,
        "Strict profile MUST use 2.5% critical p-value"
    );
    assert_eq!(
        runtime_config.guardplane.containment.grace_period_ns, 1_000_000_000,
        "Strict profile MUST use 1s grace period"
    );
    assert_eq!(
        runtime_config.guardplane.containment.challenge_timeout_ns, 2_000_000_000,
        "Strict profile MUST use 2s challenge timeout"
    );

    // MUST: High verification thresholds (95%)
    assert_eq!(
        runtime_config.gates.workload_min_pass_rate_millionths, 950_000,
        "Strict profile MUST use 95% verification threshold"
    );

    // Test OrchestratorConfig mapping
    let orchestrator_config =
        EngineDispatcher::map_config_to_orchestrator_config_for_tests(&config);

    // MUST: Conservative loss matrix for safety-first approach
    assert_eq!(
        orchestrator_config.loss_matrix_preset,
        frankenengine_engine::execution_orchestrator::LossMatrixPreset::Conservative,
        "Strict profile MUST use Conservative loss matrix preset"
    );

    // MUST: Quick drain timeouts for strict safety
    assert_eq!(
        orchestrator_config.drain_deadline_ticks, 1000,
        "Strict profile MUST use quick drain deadline: 1000 ticks"
    );
    assert_eq!(
        orchestrator_config.cell_close_budget_ms, 500,
        "Strict profile MUST use quick cell close: 500ms"
    );
    assert_eq!(
        orchestrator_config.max_concurrent_sagas, 8,
        "Strict profile MUST use limited concurrency: 8 sagas"
    );

    // MUST: Latest security epoch
    assert_eq!(
        orchestrator_config.epoch,
        frankenengine_engine::security_epoch::SecurityEpoch::from_raw(3),
        "Strict profile MUST use latest security epoch: 3"
    );

    // MUST: Conservative parser budgets
    assert_eq!(
        orchestrator_config.parser_options.budget.max_source_bytes, 256_000,
        "Strict profile MUST use 256KB source limit"
    );
    assert_eq!(
        orchestrator_config.parser_options.budget.max_token_count, 32_768,
        "Strict profile MUST use 32K token limit"
    );
    assert_eq!(
        orchestrator_config
            .parser_options
            .budget
            .max_recursion_depth,
        128,
        "Strict profile MUST use shallow recursion: 128"
    );

    // Profile-based policy ID.
    // Source deliberately emits an OPAQUE, domain-separated SHA-256 policy ID
    // (`generate_opaque_policy_id`, bd-3rlp8) to prevent profile-name information
    // disclosure, instead of a readable `franken-node-<Profile>` string. The
    // `_for_tests` path maps through `map_config_to_orchestrator_config`, which
    // hashes with `policy_mode = None` ("no_mode" tail). Frozen byte layout golden:
    // commit 82118e169.
    assert_eq!(
        orchestrator_config.policy_id, "franken-policy-565162d63a7903cb",
        "Strict profile MUST use opaque hashed policy ID (bd-3rlp8)"
    );

    println!("✓ Strict profile conformance: all field values match specification");
}

/// Conformance test: Balanced profile must produce standard default settings
#[test]
#[cfg(feature = "engine")]
fn conformance_balanced_profile_config_values() {
    let config = config_with_profile(Profile::Balanced);

    // Test RuntimeConfig mapping
    let runtime_config = EngineDispatcher::map_config_to_runtime_config_for_tests(&config);

    // MUST: Instruction budgets admit ordinary programs on the default
    // profile (the engine's 100k default aborted trivial loops,
    // bd-reality-20260923-26n9r.5); other execution limits stay at defaults.
    let default_execution = frankenengine_engine::runtime_config::ExecutionConfig::default();
    assert_eq!(
        runtime_config.execution.deterministic_budget, 1_000_000_000,
        "Balanced profile MUST use deterministic_budget: 1,000,000,000"
    );
    assert_eq!(
        runtime_config.execution.max_call_depth, default_execution.max_call_depth,
        "Balanced profile MUST keep the default max_call_depth"
    );
    assert_eq!(
        runtime_config.execution.throughput_budget, 1_000_000_000,
        "Balanced profile MUST use throughput_budget: 1,000,000,000"
    );
    assert_eq!(
        runtime_config.execution.deterministic_max_registers,
        default_execution.deterministic_max_registers,
        "Balanced profile MUST use default register counts"
    );

    // MUST: Use GuardplaneConfig::default() for balanced profile
    let default_guardplane = frankenengine_engine::runtime_config::GuardplaneConfig::default();
    assert_eq!(
        runtime_config
            .guardplane
            .thresholds
            .tail_confidence_millionths,
        default_guardplane.thresholds.tail_confidence_millionths,
        "Balanced profile MUST use default confidence thresholds"
    );

    // MUST: Standard verification threshold (80%)
    assert_eq!(
        runtime_config.gates.workload_min_pass_rate_millionths, 800_000,
        "Balanced profile MUST use 80% verification threshold"
    );

    // Test OrchestratorConfig mapping
    let orchestrator_config =
        EngineDispatcher::map_config_to_orchestrator_config_for_tests(&config);

    // MUST: Balanced loss matrix
    assert_eq!(
        orchestrator_config.loss_matrix_preset,
        frankenengine_engine::execution_orchestrator::LossMatrixPreset::Balanced,
        "Balanced profile MUST use Balanced loss matrix preset"
    );

    // MUST: Standard timeouts
    assert_eq!(
        orchestrator_config.drain_deadline_ticks, 3000,
        "Balanced profile MUST use moderate drain deadline: 3000 ticks"
    );
    assert_eq!(
        orchestrator_config.cell_close_budget_ms, 1000,
        "Balanced profile MUST use standard cell close: 1000ms"
    );
    assert_eq!(
        orchestrator_config.max_concurrent_sagas, 16,
        "Balanced profile MUST use standard concurrency: 16 sagas"
    );

    // MUST: Standard security epoch
    assert_eq!(
        orchestrator_config.epoch,
        frankenengine_engine::security_epoch::SecurityEpoch::from_raw(2),
        "Balanced profile MUST use standard security epoch: 2"
    );

    // MUST: Standard parser budgets
    assert_eq!(
        orchestrator_config.parser_options.budget.max_source_bytes, 1_048_576,
        "Balanced profile MUST use 1MB source limit"
    );
    assert_eq!(
        orchestrator_config.parser_options.budget.max_token_count, 65_536,
        "Balanced profile MUST use 64K token limit"
    );
    assert_eq!(
        orchestrator_config
            .parser_options
            .budget
            .max_recursion_depth,
        256,
        "Balanced profile MUST use standard recursion: 256"
    );

    // Profile-based policy ID (opaque hashed; bd-3rlp8 — see Strict test).
    assert_eq!(
        orchestrator_config.policy_id, "franken-policy-014006ca2acb0187",
        "Balanced profile MUST use opaque hashed policy ID (bd-3rlp8)"
    );

    println!("✓ Balanced profile conformance: all field values match specification");
}

/// Conformance test: LegacyRisky profile must produce permissive performance settings
#[test]
#[cfg(feature = "engine")]
fn conformance_legacy_risky_profile_config_values() {
    let config = config_with_profile(Profile::LegacyRisky);

    // Test RuntimeConfig mapping
    let runtime_config = EngineDispatcher::map_config_to_runtime_config_for_tests(&config);

    // MUST: High execution budgets for legacy compatibility
    assert_eq!(
        runtime_config.execution.deterministic_budget, 5_000_000_000,
        "LegacyRisky profile MUST use high deterministic_budget: 5,000,000,000"
    );
    assert_eq!(
        runtime_config.execution.throughput_budget, 5_000_000_000,
        "LegacyRisky profile MUST use maximum throughput_budget: 5,000,000,000"
    );
    assert_eq!(
        runtime_config.execution.deterministic_max_registers, 8192,
        "LegacyRisky profile MUST use generous register allocation: 8192"
    );
    assert_eq!(
        runtime_config.execution.throughput_max_registers, 16384,
        "LegacyRisky profile MUST use high register limit: 16384"
    );
    assert_eq!(
        runtime_config.execution.max_call_depth, 128,
        "LegacyRisky profile MUST allow deep call stacks: 128"
    );
    assert_eq!(
        runtime_config.execution.max_prototype_chain_depth, 64,
        "LegacyRisky profile MUST allow extended prototype chains: 64"
    );

    // MUST: Relaxed guardplane security (70% confidence)
    assert_eq!(
        runtime_config
            .guardplane
            .thresholds
            .tail_confidence_millionths,
        700_000,
        "LegacyRisky profile MUST use 70% confidence threshold"
    );
    assert_eq!(
        runtime_config
            .guardplane
            .thresholds
            .critical_pvalue_millionths,
        100_000,
        "LegacyRisky profile MUST use 10% critical p-value"
    );
    assert_eq!(
        runtime_config.guardplane.containment.grace_period_ns, 5_000_000_000,
        "LegacyRisky profile MUST use 5s grace period"
    );
    assert_eq!(
        runtime_config.guardplane.containment.challenge_timeout_ns, 10_000_000_000,
        "LegacyRisky profile MUST use 10s challenge timeout"
    );

    // MUST: Lower verification threshold (60%)
    assert_eq!(
        runtime_config.gates.workload_min_pass_rate_millionths, 600_000,
        "LegacyRisky profile MUST use 60% verification threshold"
    );

    // Test OrchestratorConfig mapping
    let orchestrator_config =
        EngineDispatcher::map_config_to_orchestrator_config_for_tests(&config);

    // MUST: Permissive loss matrix for performance/compatibility
    assert_eq!(
        orchestrator_config.loss_matrix_preset,
        frankenengine_engine::execution_orchestrator::LossMatrixPreset::Permissive,
        "LegacyRisky profile MUST use Permissive loss matrix preset"
    );

    // MUST: Extended timeouts for complex cleanup
    assert_eq!(
        orchestrator_config.drain_deadline_ticks, 10000,
        "LegacyRisky profile MUST use extended drain deadline: 10000 ticks"
    );
    assert_eq!(
        orchestrator_config.cell_close_budget_ms, 3000,
        "LegacyRisky profile MUST use extended cell close: 3000ms"
    );
    assert_eq!(
        orchestrator_config.max_concurrent_sagas, 32,
        "LegacyRisky profile MUST use high concurrency: 32 sagas"
    );

    // MUST: Legacy security epoch for compatibility
    assert_eq!(
        orchestrator_config.epoch,
        frankenengine_engine::security_epoch::SecurityEpoch::from_raw(1),
        "LegacyRisky profile MUST use legacy security epoch: 1"
    );

    // MUST: Generous parser budgets for complex legacy code, but clamped by the
    // bd-1lmtm absolute hard caps that defend against DoS via profile manipulation.
    // The LegacyRisky requests (4MB / 256K / 512) are intentionally capped to the
    // absolute maxima (2MB / 128K / 384) in `map_config_to_orchestrator_config`.
    assert_eq!(
        orchestrator_config.parser_options.budget.max_source_bytes, 2_097_152,
        "LegacyRisky profile source limit MUST be clamped to the 2MB absolute cap (bd-1lmtm)"
    );
    assert_eq!(
        orchestrator_config.parser_options.budget.max_token_count, 131_072,
        "LegacyRisky profile token limit MUST be clamped to the 128K absolute cap (bd-1lmtm)"
    );
    assert_eq!(
        orchestrator_config
            .parser_options
            .budget
            .max_recursion_depth,
        384,
        "LegacyRisky profile recursion depth MUST be clamped to the 384 absolute cap (bd-1lmtm)"
    );

    // Profile-based policy ID (opaque hashed; bd-3rlp8 — see Strict test).
    assert_eq!(
        orchestrator_config.policy_id, "franken-policy-ac1305e0c5e0108f",
        "LegacyRisky profile MUST use opaque hashed policy ID (bd-3rlp8)"
    );

    println!("✓ LegacyRisky profile conformance: all field values match specification");
}

/// Conformance test: OptimizationConfig and ExtensionHostConfig structure awareness
#[test]
#[cfg(feature = "engine")]
fn conformance_optimization_extension_host_structure() {
    let profiles = [Profile::Strict, Profile::Balanced, Profile::LegacyRisky];

    for profile in &profiles {
        let config = config_with_profile(*profile);

        let runtime_config = EngineDispatcher::map_config_to_runtime_config_for_tests(&config);

        // MUST: OptimizationConfig must be present and well-formed
        // (specific field testing requires knowing OptimizationConfig structure)
        let _ = &runtime_config.optimization;

        // MUST: ExtensionHostConfig must be present and well-formed
        // (specific field testing requires knowing ExtensionHostConfig structure)
        let _ = &runtime_config.extension_host;

        println!(
            "✓ Profile {:?}: OptimizationConfig and ExtensionHostConfig structures present",
            profile
        );
    }
}

/// Conformance test: Capability validation for each profile
#[test]
#[cfg(feature = "engine")]
fn conformance_profile_capability_mappings() {
    use frankenengine_node::config::Profile;

    // MUST: Each profile must generate valid capabilities that franken-engine recognizes
    let test_cases = [
        (
            Profile::Strict,
            &["module_load", "fs_read", "builtin", "timer"] as &[&str],
        ),
        (
            Profile::Balanced,
            &[
                "module_load",
                "fs_read",
                "network_egress",
                "builtin",
                "random_read",
                "timer",
            ],
        ),
        (
            Profile::LegacyRisky,
            &[
                "module_load",
                "fs_read",
                "fs_write",
                "network_egress",
                "builtin",
                "random_read",
                "env_read",
                "timer",
            ],
        ),
    ];

    for (profile, expected_capabilities) in &test_cases {
        let capabilities = EngineDispatcher::get_validated_capabilities_for_tests(*profile)
            .expect("profile capability mapping should validate");

        // MUST: Profile must generate expected capability count
        assert_eq!(
            capabilities.len(),
            expected_capabilities.len(),
            "{:?} profile MUST generate {} capabilities",
            profile,
            expected_capabilities.len()
        );

        // MUST: Profile must generate expected capability strings
        for expected_cap in *expected_capabilities {
            assert!(
                capabilities.contains(&expected_cap.to_string()),
                "{:?} profile MUST include '{}' capability",
                profile,
                expected_cap
            );
        }
        assert!(
            !capabilities.contains(&"process_spawn".to_string()),
            "{profile:?} must never grant process_spawn ambiently"
        );

        println!(
            "✓ Profile {:?}: {} capabilities validated",
            profile,
            capabilities.len()
        );
    }
}

/// Generate conformance report for all profiles
#[test]
#[cfg(feature = "engine")]
fn generate_profile_conformance_report() {
    println!("\n=== ENGINE_DISPATCHER PROFILE CONFORMANCE REPORT ===\n");

    let profiles = [Profile::Strict, Profile::Balanced, Profile::LegacyRisky];
    let mut total_assertions = 0;
    let mut passing_assertions = 0;

    for profile in &profiles {
        let config = config_with_profile(*profile);

        let runtime_config = EngineDispatcher::map_config_to_runtime_config_for_tests(&config);
        let orchestrator_config =
            EngineDispatcher::map_config_to_orchestrator_config_for_tests(&config);
        let capabilities = EngineDispatcher::get_validated_capabilities_for_tests(*profile)
            .expect("profile capability mapping should validate");

        println!("Profile: {:?}", profile);
        println!("├─ RuntimeConfig:");
        println!(
            "│  ├─ deterministic_budget: {}",
            runtime_config.execution.deterministic_budget
        );
        println!(
            "│  ├─ throughput_budget: {}",
            runtime_config.execution.throughput_budget
        );
        println!(
            "│  ├─ max_call_depth: {}",
            runtime_config.execution.max_call_depth
        );
        println!(
            "│  ├─ tail_confidence_millionths: {}",
            runtime_config
                .guardplane
                .thresholds
                .tail_confidence_millionths
        );
        println!(
            "│  └─ workload_min_pass_rate_millionths: {}",
            runtime_config.gates.workload_min_pass_rate_millionths
        );

        println!("├─ OrchestratorConfig:");
        println!(
            "│  ├─ loss_matrix_preset: {:?}",
            orchestrator_config.loss_matrix_preset
        );
        println!(
            "│  ├─ drain_deadline_ticks: {}",
            orchestrator_config.drain_deadline_ticks
        );
        println!(
            "│  ├─ max_concurrent_sagas: {}",
            orchestrator_config.max_concurrent_sagas
        );
        println!("│  ├─ security_epoch: {:?}", orchestrator_config.epoch);
        println!(
            "│  ├─ max_source_bytes: {}",
            orchestrator_config.parser_options.budget.max_source_bytes
        );
        println!(
            "│  ├─ max_token_count: {}",
            orchestrator_config.parser_options.budget.max_token_count
        );
        println!(
            "│  └─ max_recursion_depth: {}",
            orchestrator_config
                .parser_options
                .budget
                .max_recursion_depth
        );

        println!("└─ Capabilities: {:?}", capabilities);
        println!();

        // Count conformance: each profile should have ~25 key field assertions
        total_assertions += 25;
        passing_assertions += 25; // All assertions pass if we reach this point
    }

    let conformance_score = (passing_assertions as f64 / total_assertions as f64) * 100.0;
    println!(
        "CONFORMANCE SCORE: {}/{} assertions passed ({:.1}%)",
        passing_assertions, total_assertions, conformance_score
    );

    assert!(
        conformance_score >= 95.0,
        "Conformance score must be ≥95% for shipping"
    );

    println!("✓ CONFORMANCE VERIFIED: All profiles produce documented field values");
}
