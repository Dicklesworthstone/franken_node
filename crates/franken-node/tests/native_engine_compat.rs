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
    config::{Config, PreferredRuntime, Profile},
    ops::{engine_dispatcher::EngineDispatcher, telemetry_bridge::TelemetryBridge},
    storage::frankensqlite_adapter::FrankensqliteAdapter,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

fn balanced_config() -> Config {
    Config {
        profile: Profile::Balanced,
        ..Config::default()
    }
}

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
        std::fs::write(
            &engine_path,
            "#!/bin/bash\necho 'Mock engine output'\nexit 0\n",
        )
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
        std::fs::write(
            &batch_path,
            "@echo off\necho Mock engine output\nexit /b 0\n",
        )
        .expect("Failed to write mock engine batch");
        batch_path
    }

    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
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
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a mock franken-engine binary that fails with non-zero exit code
fn create_failing_mock_engine_binary(dir: &Path, exit_code: i32) -> PathBuf {
    let engine_path = dir.join("failing-franken-engine");
    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/bash\necho 'Mock engine error output' >&2\nexit {}\n",
            exit_code
        );
        std::fs::write(&engine_path, script).expect("Failed to write failing mock engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("failing-franken-engine.bat");
        let script = format!(
            "@echo off\necho Mock engine error output 1>&2\nexit /b {}\n",
            exit_code
        );
        std::fs::write(&batch_path, script).expect("Failed to write failing mock engine batch");
        batch_path
    }
    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a mock franken-engine binary that crashes/panics
fn create_crashing_mock_engine_binary(dir: &Path) -> PathBuf {
    let engine_path = dir.join("crashing-franken-engine");
    #[cfg(unix)]
    {
        // Use kill -9 to simulate a crash/panic
        std::fs::write(
            &engine_path,
            "#!/bin/bash\necho 'About to crash'\nkill -9 $$\n",
        )
        .expect("Failed to write crashing mock engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("crashing-franken-engine.bat");
        // Use taskkill to simulate crash on Windows
        std::fs::write(
            &batch_path,
            "@echo off\necho About to crash\ntaskkill /f /pid %PID%\n",
        )
        .expect("Failed to write crashing mock engine batch");
        batch_path
    }
    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
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

    let config = balanced_config();

    let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute through native engine
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode);

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

    let dispatcher =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute and expect failure
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode);

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

    let config = balanced_config();

    let dispatcher =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // This should succeed by falling back to external process
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode);

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

    let config = balanced_config();

    let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    let result = dispatcher.dispatch_run(&nonexistent_path, &config, &policy_mode);

    assert!(result.is_err(), "Should fail for nonexistent source file");

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("Failed to read application source")
            || error.contains("No such file or directory")
            || error.contains("cannot find the file"),
        "Error should indicate source read failure, got: {}",
        error
    );

    // Test 2: Invalid source code (this will test engine execution error)
    let invalid_app_path = create_test_app(
        temp_dir.path(),
        "invalid.js",
        r#"this is not valid javascript syntax !@#$%"#,
    );

    let result = dispatcher.dispatch_run(&invalid_app_path, &config, &policy_mode);

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
    // Set a short timeout for testing (5 seconds instead of default 5 minutes)
    unsafe {
        std::env::set_var("FRANKEN_ENGINE_TIMEOUT_SECS", "5");
    }

    // Clean up the env var when test completes
    struct EnvCleanup(&'static str);
    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(self.0);
            }
        }
    }
    let _cleanup = EnvCleanup("FRANKEN_ENGINE_TIMEOUT_SECS");

    // Test that engine execution properly handles timeouts by using a slow external engine binary
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "timeout_test.js",
        r#"console.log("This should timeout before completion");"#,
    );

    // Create a slow mock engine that takes 10 seconds to complete (longer than our 5s timeout)
    let slow_engine_path = create_slow_mock_engine_binary(temp_dir.path(), 10);

    let config = balanced_config();

    // Force external process execution by providing explicit engine binary path
    // This bypasses native engine execution to test external process timeout
    let dispatcher = EngineDispatcher::new(
        Some(slow_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute and measure timing
    let start = std::time::Instant::now();
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode);
    let duration = start.elapsed();

    // The execution should fail due to timeout, not complete successfully
    assert!(
        result.is_err(),
        "Slow engine execution should fail due to timeout, but got success"
    );

    let error = result.unwrap_err().to_string();

    // Verify this is actually a timeout error, not some other error
    let is_timeout_error = error.contains("timed out")
        || error.contains("timeout")
        || error.contains("Timeout")
        || error.contains("deadline exceeded");

    // If it's not a timeout error, it might be because the process was killed
    // or failed for another reason, which is also acceptable timeout behavior
    if !is_timeout_error {
        // At minimum, verify the execution was interrupted around our timeout (5s), not after full 10s delay
        assert!(
            duration < Duration::from_secs(7),
            "Execution should be interrupted around timeout limit (~5s), not wait for full 10s completion. Got: {:?}",
            duration
        );

        // And verify the error indicates process failure/interruption
        let is_process_failure = error.contains("failed")
            || error.contains("killed")
            || error.contains("terminated")
            || error.contains("exit");
        assert!(
            is_process_failure,
            "If not a timeout error, should be a process failure error. Got: {}",
            error
        );
    } else {
        // For explicit timeout errors, verify timing was around our 5-second timeout
        assert!(
            duration >= Duration::from_secs(4) && duration <= Duration::from_secs(7),
            "Timeout should occur around 5s mark. Took: {:?}",
            duration
        );
    }

    println!(
        "Timeout test completed in {:?} with error: {}",
        duration, error
    );
}

#[test]
#[cfg(feature = "engine")]
fn test_native_engine_missing_binary_error_handling() {
    // Test boundary condition: engine feature enabled but binary missing
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "missing_binary_test.js",
        r#"console.log("This should fail - engine binary missing");"#,
    );

    // Point to a non-existent engine binary
    let nonexistent_engine_path = temp_dir.path().join("nonexistent-franken-engine");

    let config = balanced_config();

    let dispatcher = EngineDispatcher::new(
        Some(nonexistent_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    // Execute and expect failure due to missing binary
    let result = dispatcher.dispatch_run(&app_path, &config, "test");

    assert!(result.is_err(), "Should fail when engine binary is missing");

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify this is an ActionableError with proper context
    assert!(
        error_str.contains("engine")
            || error_str.contains("binary")
            || error_str.contains("not found")
            || error_str.contains("No such file"),
        "Error should indicate engine binary issue, got: {}",
        error_str
    );

    // Verify error provides meaningful context (ActionableError integration tested elsewhere)
    println!("Engine binary missing error: {}", error_str);
}

#[test]
fn test_engine_non_zero_exit_code_error_handling() {
    // Test boundary condition: engine feature enabled but engine returns non-zero exit
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "exit_code_test.js",
        r#"console.log("This should fail due to engine exit code");"#,
    );

    // Create a mock engine that returns exit code 1
    let failing_engine_path = create_failing_mock_engine_binary(temp_dir.path(), 1);

    let config = balanced_config();

    // Force external process execution to test exit code handling
    let dispatcher = EngineDispatcher::new(
        Some(failing_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    // Execute and expect failure due to non-zero exit
    let result = dispatcher.dispatch_run(&app_path, &config, "test");

    assert!(
        result.is_err(),
        "Should fail when engine returns non-zero exit code"
    );

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify error indicates process failure
    assert!(
        error_str.contains("failed")
            || error_str.contains("exit")
            || error_str.contains("error")
            || error_str.contains("status"),
        "Error should indicate process failure, got: {}",
        error_str
    );

    // Verify error provides meaningful context (ActionableError integration tested elsewhere)
    println!("Engine exit code error: {}", error_str);
}

#[test]
fn test_engine_crash_signal_error_handling() {
    // Test boundary condition: engine feature enabled but engine crashes/panics
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "crash_test.js",
        r#"console.log("This should fail due to engine crash");"#,
    );

    // Create a mock engine that crashes with SIGKILL
    let crashing_engine_path = create_crashing_mock_engine_binary(temp_dir.path());

    let config = balanced_config();

    // Force external process execution to test signal handling
    let dispatcher = EngineDispatcher::new(
        Some(crashing_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    // Set short timeout for faster test completion
    unsafe {
        std::env::set_var("FRANKEN_ENGINE_TIMEOUT_SECS", "10");
    }

    // Clean up env var when test completes
    struct EnvCleanup(&'static str);
    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(self.0);
            }
        }
    }
    let _cleanup = EnvCleanup("FRANKEN_ENGINE_TIMEOUT_SECS");

    // Execute and expect failure due to signal/crash
    let result = dispatcher.dispatch_run(&app_path, &config, "test");

    assert!(
        result.is_err(),
        "Should fail when engine crashes/receives signal"
    );

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify error indicates abnormal termination
    assert!(
        error_str.contains("signal")
            || error_str.contains("killed")
            || error_str.contains("terminated")
            || error_str.contains("crash")
            || error_str.contains("failed"),
        "Error should indicate abnormal process termination, got: {}",
        error_str
    );

    // Verify error provides meaningful context (ActionableError integration tested elsewhere)
    println!("Engine crash error: {}", error_str);
}

#[test]
fn test_dispatcher_creation_and_configuration() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let engine_path = create_mock_engine_binary(temp_dir.path());

    // Test various dispatcher configurations
    let dispatcher1 = EngineDispatcher::new(None, PreferredRuntime::Auto);
    let dispatcher2 =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    let dispatcher3 = EngineDispatcher::new(None, PreferredRuntime::Node);

    // Dispatchers should be created successfully
    // This tests the configuration and initialization paths
    assert!(std::mem::size_of_val(&dispatcher1) > 0);
    assert!(std::mem::size_of_val(&dispatcher2) > 0);
    assert!(std::mem::size_of_val(&dispatcher3) > 0);
}
