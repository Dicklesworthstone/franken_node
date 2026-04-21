#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

    let engine_path = temp_dir.path().join("franken-engine");
    std::fs::write(
        &engine_path,
        "#!/bin/sh\n(sleep 5) &\nprintf 'parent-exited\\n'\nexit 0\n",
    )
    .expect("write fake engine");
    let mut permissions = std::fs::metadata(&engine_path)
        .expect("fake engine metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&engine_path, permissions).expect("chmod fake engine");

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
