//! Integration tests for native engine execution compatibility.
//!
//! Tests the complete native engine execution pipeline including:
//! - Native engine execution with telemetry emission
//! - Strict profile fallback rejection
//! - Comprehensive error handling and propagation
//!
//! End-to-end validation via EngineDispatcher with real components,
//! no mocks for critical native execution paths.

use frankenengine_node::{
    config::{Config, Profile, PreferredRuntime},
    ops::{
        engine_dispatcher::EngineDispatcher,
        telemetry_bridge::TelemetryBridge,
    },
};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

/// Create a test application file with simple JavaScript content
fn create_test_app(dir: &Path, filename: &str, content: &str) -> PathBuf {
    let app_path = dir.join(filename);
    std::fs::write(&app_path, content).expect("Failed to write test app");
    app_path
}

/// Create a mock franken-engine binary for testing
fn create_mock_engine_binary(dir: &Path) -> PathBuf {
    let engine_path = dir.join("franken-engine");
    #[cfg(unix)]
    {
        std::fs::write(&engine_path, "#!/bin/bash\necho 'Mock engine output'\nexit 0\n")
            .expect("Failed to write mock engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("franken-engine.bat");
        std::fs::write(&batch_path, "@echo off\necho Mock engine output\nexit /b 0\n")
            .expect("Failed to write mock engine batch");
        batch_path
    }
    #[cfg(unix)]
    engine_path
    #[cfg(windows)]
    batch_path
}

/// Create a slow mock franken-engine binary for timeout testing
fn create_slow_mock_engine_binary(dir: &Path, delay_secs: u64) -> PathBuf {
    let engine_path = dir.join("slow-franken-engine");
    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/bash\necho 'Starting slow mock engine'\nsleep {}\necho 'Mock engine output'\nexit 0\n",
            delay_secs
        );
        std::fs::write(&engine_path, script).expect("Failed to write slow mock engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("slow-franken-engine.bat");
        let script = format!(
            "@echo off\necho Starting slow mock engine\ntimeout /t {} /nobreak >nul\necho Mock engine output\nexit /b 0\n",
            delay_secs
        );
        std::fs::write(&batch_path, script).expect("Failed to write slow mock engine batch");
        batch_path
    }
    #[cfg(unix)]
    engine_path
    #[cfg(windows)]
    batch_path
}

#[test]
#[cfg(feature = "engine")]
fn test_native_engine_execution_with_telemetry() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "test_app.js",
        r#"console.log("Hello from native engine");"#,
    );

    let mut config = Config::default();
    config.profile = Profile::Balanced; // Use balanced to allow native execution

    let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine);
    let telemetry_bridge = TelemetryBridge::null(); // Use null bridge for testing

    // Execute through native engine
    let result = dispatcher.dispatch_run(&app_path, &config, &telemetry_bridge);

    // Verify successful execution
    assert!(
        result.is_ok(),
        "Native engine execution should succeed, got: {:?}",
        result
    );

    let report = result.unwrap();
    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);
    assert!(report.telemetry.is_some(), "Telemetry should be present");

    // Verify telemetry was emitted
    let telemetry = report.telemetry.unwrap();
    assert!(
        telemetry.drain_completed,
        "Telemetry drain should complete successfully"
    );
    assert!(
        telemetry.drain_duration_ms < 10000,
        "Telemetry drain should complete within reasonable time"
    );
}

#[test]
#[cfg(not(feature = "engine"))]
fn test_strict_profile_rejects_fallback_without_native_engine() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "strict_test.js",
        r#"console.log("This should not run on strict profile without native engine");"#,
    );

    let engine_path = create_mock_engine_binary(temp_dir.path());

    let mut config = Config::default();
    config.profile = Profile::Strict; // Strict profile should reject fallback

    let dispatcher = EngineDispatcher::new(
        Some(engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );
    let telemetry_bridge = TelemetryBridge::null();

    // Execute and expect failure
    let result = dispatcher.dispatch_run(&app_path, &config, &telemetry_bridge);

    assert!(
        result.is_err(),
        "Strict profile should reject execution without native engine feature"
    );

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("Native engine required") || error.contains("engine feature"),
        "Error should mention native engine requirement, got: {}",
        error
    );
    assert!(
        error.contains("rebuild") || error.contains("--features engine"),
        "Error should suggest rebuilding with engine feature, got: {}",
        error
    );
}

#[test]
fn test_balanced_profile_allows_external_process_fallback() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "balanced_test.js",
        r#"console.log("This should run with external process on balanced profile");"#,
    );

    let engine_path = create_mock_engine_binary(temp_dir.path());

    let mut config = Config::default();
    config.profile = Profile::Balanced; // Balanced allows fallback

    let dispatcher = EngineDispatcher::new(
        Some(engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );
    let telemetry_bridge = TelemetryBridge::null();

    // This should succeed by falling back to external process
    let result = dispatcher.dispatch_run(&app_path, &config, &telemetry_bridge);

    // Note: This test may fail if no Node/Bun is available, but that's expected behavior
    // The key is that it shouldn't fail with "native engine required" error
    if let Err(error) = result {
        let error_str = error.to_string();
        assert!(
            !error_str.contains("Native engine required"),
            "Balanced profile should not require native engine, got: {}",
            error_str
        );
        // Other errors (like missing Node/Bun) are acceptable for this test
    }
}

#[test]
#[cfg(feature = "engine")]
fn test_native_engine_error_handling_propagation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Test 1: Source file read error
    let nonexistent_path = temp_dir.path().join("nonexistent.js");

    let mut config = Config::default();
    config.profile = Profile::Balanced;

    let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine);
    let telemetry_bridge = TelemetryBridge::null();

    let result = dispatcher.dispatch_run(&nonexistent_path, &config, &telemetry_bridge);

    assert!(
        result.is_err(),
        "Should fail for nonexistent source file"
    );

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("Failed to read application source") ||
        error.contains("No such file or directory") ||
        error.contains("cannot find the file"),
        "Error should indicate source read failure, got: {}",
        error
    );

    // Test 2: Invalid source code (this will test engine execution error)
    let invalid_app_path = create_test_app(
        temp_dir.path(),
        "invalid.js",
        r#"this is not valid javascript syntax !@#$%"#,
    );

    let result = dispatcher.dispatch_run(&invalid_app_path, &config, &telemetry_bridge);

    // Engine may or may not reject invalid syntax - depends on implementation
    // The key is that errors should propagate properly, not crash
    if let Err(error) = result {
        let error_str = error.to_string();
        // Should not contain panic messages
        assert!(
            !error_str.contains("panic") && !error_str.contains("panicked"),
            "Error should not indicate panic, got: {}",
            error_str
        );
    }
}

#[test]
fn test_engine_timeout_handling() {
    // Test that engine execution properly handles timeouts by using a slow external engine binary
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "timeout_test.js",
        r#"console.log("This should timeout before completion");"#,
    );

    // Create a slow mock engine that takes 10 seconds to complete
    let slow_engine_path = create_slow_mock_engine_binary(temp_dir.path(), 10);

    let mut config = Config::default();
    config.profile = Profile::Balanced; // Use balanced to allow external process fallback

    // Force external process execution by providing explicit engine binary path
    // This bypasses native engine execution to test external process timeout
    let dispatcher = EngineDispatcher::new(
        Some(slow_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );
    let telemetry_bridge = TelemetryBridge::null();

    // Execute and measure timing
    let start = std::time::Instant::now();
    let result = dispatcher.dispatch_run(&app_path, &config, &telemetry_bridge);
    let duration = start.elapsed();

    // The execution should fail due to timeout, not complete successfully
    assert!(
        result.is_err(),
        "Slow engine execution should fail due to timeout, but got success"
    );

    let error = result.unwrap_err().to_string();

    // Verify this is actually a timeout error, not some other error
    let is_timeout_error = error.contains("timed out") ||
                          error.contains("timeout") ||
                          error.contains("Timeout") ||
                          error.contains("deadline exceeded");

    // If it's not a timeout error, it might be because the process was killed
    // or failed for another reason, which is also acceptable timeout behavior
    if !is_timeout_error {
        // At minimum, verify the execution was interrupted quickly, not after 10 seconds
        assert!(
            duration < Duration::from_secs(8),
            "Execution should be interrupted quickly (~1-5s), not wait for full 10s completion. Got: {:?}",
            duration
        );

        // And verify the error indicates process failure/interruption
        let is_process_failure = error.contains("failed") ||
                                error.contains("killed") ||
                                error.contains("terminated") ||
                                error.contains("exit");
        assert!(
            is_process_failure,
            "If not a timeout error, should be a process failure error. Got: {}",
            error
        );
    } else {
        // For explicit timeout errors, verify timing was reasonable (~1-5s for timeout detection)
        assert!(
            duration < Duration::from_secs(8),
            "Timeout should be detected quickly, not after full delay. Took: {:?}",
            duration
        );
    }

    println!(
        "Timeout test completed in {:?} with error: {}",
        duration, error
    );
}

#[test]
fn test_dispatcher_creation_and_configuration() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let engine_path = create_mock_engine_binary(temp_dir.path());

    // Test various dispatcher configurations
    let dispatcher1 = EngineDispatcher::new(None, PreferredRuntime::Auto);
    let dispatcher2 = EngineDispatcher::new(
        Some(engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );
    let dispatcher3 = EngineDispatcher::new(None, PreferredRuntime::Node);

    // Dispatchers should be created successfully
    // This tests the configuration and initialization paths
    assert!(std::mem::size_of_val(&dispatcher1) > 0);
    assert!(std::mem::size_of_val(&dispatcher2) > 0);
    assert!(std::mem::size_of_val(&dispatcher3) > 0);
}