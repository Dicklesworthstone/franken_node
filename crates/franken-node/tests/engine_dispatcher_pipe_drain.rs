#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[cfg(unix)]
#[test]
fn engine_dispatcher_reaps_descendant_pipe_holders() {
    use frankenengine_node::{
        config::{Config, PreferredRuntime, Profile},
        ops::engine_dispatcher::EngineDispatcher,
    };
    use std::time::{Duration, Instant};

    let temp_dir = tempfile::TempDir::new().expect("tempdir");
    let app_path = temp_dir.path().join("app.js");
    std::fs::write(&app_path, "console.log('app');\n").expect("write app");

    // Use real test-engine binary instead of fake shell script
    let engine_path = if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_test-engine") {
        PathBuf::from(exe)
    } else {
        // Fallback to built binary in target dir
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .join("target/debug/test-engine")
    };

    assert!(
        engine_path.is_file(),
        "test-engine binary not found at {}. Run: cargo build --bin test-engine",
        engine_path.display()
    );

    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let config = Config::for_profile(Profile::Strict);

    let started = Instant::now();
    let report = dispatcher
        .dispatch_run(&app_path, &config, "strict")
        .expect("dispatcher should not hang on inherited pipe descriptors");
    let elapsed = started.elapsed();

    assert_eq!(report.exit_code, Some(0));
    assert!(
        report.captured_output.stdout.contains("parent-exited"),
        "stdout should retain parent output: {:?}",
        report.captured_output.stdout
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "dispatcher waited for descendant-held stdout pipe: {elapsed:?}"
    );
}

#[cfg(not(unix))]
#[test]
fn engine_dispatcher_reaps_descendant_pipe_holders() {}

#[cfg(all(unix, feature = "test-support"))]
#[test]
fn non_executable_path_runtime_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use frankenengine_node::ops::engine_dispatcher::non_executable_path_lookup_rejected_for_tests;

    let rejected = non_executable_path_lookup_rejected_for_tests()?;
    assert!(
        rejected,
        "no-external-commands PATH fallback must not resolve non-executable runtime files"
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn telemetry_join_timeout_does_not_detach_connection_worker() {
    frankenengine_node::ops::telemetry_bridge::assert_timed_out_connection_join_does_not_detach_worker_for_tests();
}

#[cfg(feature = "test-support")]
#[test]
fn telemetry_socket_lock_blocks_stale_cleanup_under_contention() {
    frankenengine_node::ops::telemetry_bridge::assert_socket_lock_blocks_stale_cleanup_for_tests();
}

#[cfg(feature = "test-support")]
#[test]
fn telemetry_slowloris_partial_fragments_exceed_cap_after_timeout_shed() {
    frankenengine_node::ops::telemetry_bridge::assert_slowloris_partial_fragments_exceed_cap_after_timeout_shed_for_tests();
}
