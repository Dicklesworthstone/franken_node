//! bd-5r99w.15 — mock-free e2e: `franken-node run` surfaces a REAL,
//! verdict-derived exit code (and the program's real captured output), with
//! structured logging — never the pre-reality-check debug dump / synthetic
//! success.
//!
//! This is the companion e2e for bd-5r99w.1 (real stdout) and bd-5r99w.2 (real
//! exit status). It drives the *actual built binary* as a subprocess against
//! real fixture apps (no mocks, no stubs) through the in-process franken-engine,
//! and fails RED if either fix regresses:
//!
//! * `bd-5r99w.1` replaced a Rust `{:?}` debug dump
//!   (`format!("Native execution completed: {:?}", ...)`) with the program's
//!   real, level-split console output. Reintroducing the dump trips the
//!   debug-dump-marker assertions.
//! * `bd-5r99w.2` replaced `synthetic_success_status()` (always exit 0) with an
//!   exit code derived from the runtime's containment verdict. The fixtures
//!   below produce *different* real exit codes from the SAME binary — a clean
//!   in-budget program exits 0 (Allow), a guest with an uncaught exception
//!   exits non-zero — so a reintroduced synthetic constant makes one go RED.
//!
//! Honest scope (bd-w1xhn reconciliation): console output is now a surfaced
//! effect — `franken-node run` relays the guest's real stdout/stderr per the
//! README's run contract, so a bare `console.log` program dispatches Allow→0
//! with its output captured (the June-era premise "default profiles do not
//! grant console" no longer holds). The fail-closed story moved to where the
//! capability metering actually lives: an ungranted host effect (e.g. network
//! egress to a denied endpoint) is refused before execution and recorded in
//! the signed host-effect ledger (`denied_count`, per-entry `Denied`
//! outcomes, tamper-evident chain head), while the process exit code derives
//! from the CONTAINMENT verdict (`exit_code_for_containment_severity`:
//! Allow→0 … Quarantine→95) — a single denied effect deliberately does not
//! escalate containment, so it must be surfaced by the ledger, never masked.

#![cfg(feature = "engine")]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Path to the binary under test (set by Cargo for integration tests).
fn franken_node_bin() -> &'static str {
    env!("CARGO_BIN_EXE_franken-node")
}

struct RunOutcome {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// bd-sfr61: the private worker marker is not an alternate public CLI.  Even a
/// caller that discovers the deliberately undocumented argv string must be
/// refused before request decoding unless the authenticated supervisor also
/// supplies the one-shot launch nonce and Unix control channel.
#[test]
fn private_native_session_worker_refuses_direct_cli_invocation() {
    let missing_nonce = Command::new(franken_node_bin())
        .arg("__franken-native-session-worker-v6")
        .stdin(Stdio::null())
        .output()
        .expect("invoke private worker marker directly");

    assert!(
        !missing_nonce.status.success(),
        "private entry must fail closed"
    );
    let stderr = String::from_utf8_lossy(&missing_nonce.stderr);
    assert!(
        stderr.contains("authenticated parent channel") && stderr.contains("launch nonce"),
        "direct entry should explain the missing authenticated supervisor: {stderr}"
    );

    #[cfg(target_os = "linux")]
    {
        let forged_nonce = Command::new(franken_node_bin())
            .args([
                "__franken-native-session-worker-v6",
                "00000000-0000-4000-8000-000000000001",
            ])
            .stdin(Stdio::null())
            .output()
            .expect("invoke private worker with a forged nonce");
        assert!(
            !forged_nonce.status.success(),
            "a forged argv nonce must not replace the supervisor channel"
        );
        let stderr = String::from_utf8_lossy(&forged_nonce.stderr);
        assert!(
            stderr.contains("authenticated Unix control socket"),
            "forged direct entry should fail the kernel-authenticated channel check: {stderr}"
        );
    }
}

fn run_app(app_src: &str, extra_args: &[&str]) -> (tempfile::TempDir, RunOutcome) {
    run_app_with_policy(app_src, "balanced", extra_args)
}

fn run_app_with_policy(
    app_src: &str,
    policy: &str,
    extra_args: &[&str],
) -> (tempfile::TempDir, RunOutcome) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("app.js"), app_src).expect("write fixture app");

    // Bootstrap a fail-closed-valid workspace exactly as a real operator would
    // (`franken-node init` then `franken-node run`): init synthesizes the
    // required security defaults (`trust.registry_signing_key`,
    // `security.authorized_api_keys`) so `run` passes config validation.
    let init = Command::new(franken_node_bin())
        .args(["init", "--profile", "balanced", "--out-dir", "."])
        .current_dir(dir.path())
        .output()
        .expect("spawn franken-node init");
    assert!(
        init.status.success(),
        "init must bootstrap the workspace; exit={:?} stderr=\n{}",
        init.status.code(),
        String::from_utf8_lossy(&init.stderr)
    );

    let mut cmd = Command::new(franken_node_bin());
    // The CLI rejects absolute user-content paths (a path-traversal guard), so we
    // pass a RELATIVE app path and run from inside the freshly-bootstrapped dir.
    // `--runtime franken-engine --engine-bin <existing>` forces the in-process
    // NATIVE engine path (the bd-5r99w.1/.2 surface) instead of an auto-mode
    // node/bun fallback, which would otherwise demand a degraded-mode opt-in.
    //
    // With the `engine` feature, native execution runs in-process and uses the
    // engine binary only as a presence gate (it is never spawned), so we point
    // it at the franken-node binary itself — guaranteed to exist at runtime
    // since it is the command under test. This is NOT a mock: the real native
    // engine produces the real verdict and exit code; the gate file is an
    // artifact of the engine-split dispatch contract.
    cmd.arg("run")
        .arg("app.js")
        .arg("--policy")
        .arg(policy)
        .arg("--runtime")
        .arg("franken-engine")
        .arg("--engine-bin")
        .arg(franken_node_bin());
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.current_dir(dir.path());
    let output = cmd.output().expect("spawn franken-node run");
    let outcome = RunOutcome {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    (dir, outcome)
}

/// bd-reality-20260820-w0fc6.7: default `run` (no degraded-fallback env)
/// executes fixture JS through the embedded engine and surfaces stdout.
#[test]
fn default_run_executes_fixture_js_through_embedded_engine_without_degraded_fallback() {
    let (dir, outcome) = run_app("console.log(\"hello-from-engine\");\n", &[]);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "embedded-engine run must exit 0 without FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK; stderr=\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("hello-from-engine"),
        "guest stdout must include the logged line; stdout=\n{}\nstderr=\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        !outcome
            .stderr
            .contains("FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK"),
        "must not demand degraded Node/Bun fallback; stderr=\n{}",
        outcome.stderr
    );
    let _workspace = dir;
}

fn profile_selection_workspace(profile: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("profile-selection workspace");
    std::fs::write(
        dir.path().join("app.js"),
        "console.log('profile-selected');\n",
    )
    .expect("write profile-selection app");
    let init = Command::new(franken_node_bin())
        .args([
            "init",
            "--profile",
            profile.unwrap_or("balanced"),
            "--out-dir",
            ".",
        ])
        .env_remove("FRANKEN_NODE_PROFILE")
        .current_dir(dir.path())
        .output()
        .expect("bootstrap profile-selection workspace");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    if profile.is_none() {
        // Keep the real init-provisioned keys while exercising the resolver's
        // default when neither the document nor the environment selects one.
        let config_path = dir.path().join("franken_node.toml");
        let mut config: toml::Value = toml::from_str(
            &std::fs::read_to_string(&config_path).expect("read initialized config"),
        )
        .expect("parse initialized config");
        config
            .as_table_mut()
            .expect("config is a table")
            .remove("profile");
        std::fs::write(
            config_path,
            toml::to_string(&config).expect("serialize config without a profile"),
        )
        .expect("write config without a profile");
    }
    dir
}

fn run_with_profile_sources(
    workspace: &std::path::Path,
    environment_profile: Option<&str>,
    cli_policy: Option<&str>,
) -> RunOutcome {
    let mut command = Command::new(franken_node_bin());
    command
        .args(["run", "app.js", "--json"])
        .env_remove("FRANKEN_NODE_PROFILE")
        .current_dir(workspace);
    if let Some(profile) = environment_profile {
        command.env("FRANKEN_NODE_PROFILE", profile);
    }
    if let Some(policy) = cli_policy {
        command.args(["--policy", policy]);
    }
    let output = command.output().expect("run with selected profile sources");
    RunOutcome {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A defaulted CLI value used to overwrite both file and environment policy,
/// silently turning configured strict runs into balanced runs. Verify the
/// actual engine budget and signed receipt as well as the preflight label.
#[test]
fn run_profile_selection_preserves_file_environment_and_explicit_cli_precedence() {
    for (file_profile, environment_profile, cli_policy, expected) in [
        (Some("strict"), None, None, "strict"),
        (Some("balanced"), Some("strict"), None, "strict"),
        (Some("strict"), Some("strict"), Some("balanced"), "balanced"),
        (Some("balanced"), None, Some("STRICT"), "strict"),
        (None, None, None, "balanced"),
    ] {
        let dir = profile_selection_workspace(file_profile);
        let outcome = run_with_profile_sources(dir.path(), environment_profile, cli_policy);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "file={file_profile:?}, env={environment_profile:?}, CLI={cli_policy:?}: {}",
            outcome.stderr
        );
        let report = last_json_document(&outcome.stdout);
        assert_eq!(report["preflight"]["policy_mode"], expected);
        assert_eq!(report["receipt"]["profile"], expected);
        assert_eq!(report["receipt"]["policy_mode"], expected);
        assert_eq!(
            report["dispatch"]["captured_output"]["stdout"],
            "profile-selected\n"
        );
        let expected_token_budget = if expected == "strict" { 32_768 } else { 65_536 };
        assert_eq!(
            report["dispatch"]["engine_decision"]["parser_budget"]["max_token_count"],
            expected_token_budget,
            "the actual engine configuration must follow the selected profile"
        );
    }
}

/// An omitted --policy must retain strict's real admission rule, not merely
/// print "strict" on a receipt while allowing the high-risk dependency.
#[test]
fn run_profile_selection_enforces_configured_and_environment_strict_admission() {
    for (file_profile, environment_profile) in [("strict", None), ("balanced", Some("strict"))] {
        let dir = profile_selection_workspace(Some(file_profile));
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"profile-admission","version":"1.0.0","dependencies":{"lodahs":"1.0.0"}}"#,
        )
        .expect("write dependency that the real offline scan detects as a typosquat");
        let scan = Command::new(franken_node_bin())
            .args(["trust", "scan", ".", "--json"])
            .env_remove("FRANKEN_NODE_PROFILE")
            .current_dir(dir.path())
            .output()
            .expect("scan high-risk dependency");
        assert!(
            scan.status.success(),
            "trust scan failed: {}",
            String::from_utf8_lossy(&scan.stderr)
        );

        let strict = run_with_profile_sources(dir.path(), environment_profile, None);
        assert_ne!(
            strict.exit_code,
            Some(0),
            "strict must refuse the dependency"
        );
        let blocked = last_json_document(&strict.stdout);
        assert_eq!(blocked["policy_mode"], "strict");
        assert_eq!(blocked["verdict"]["status"], "blocked");
        assert!(
            blocked["verdict"]["violations"]
                .as_array()
                .is_some_and(|violations| violations.iter().any(|violation| {
                    violation["kind"] == "high_risk" && violation["extension_id"] == "npm:lodahs"
                })),
            "strict must enforce the trust card's high-risk finding: {blocked}"
        );
        assert!(blocked.get("dispatch").is_none());
        assert!(!strict.stdout.contains("profile-selected"));

        let balanced = run_with_profile_sources(dir.path(), environment_profile, Some("balanced"));
        assert_eq!(balanced.exit_code, Some(0), "{}", balanced.stderr);
        let admitted = last_json_document(&balanced.stdout);
        assert_eq!(admitted["preflight"]["policy_mode"], "balanced");
        assert_eq!(admitted["preflight"]["verdict"]["status"], "passed");
        assert_eq!(admitted["receipt"]["policy_mode"], "balanced");
        assert_eq!(admitted["receipt"]["profile"], "balanced");
        assert_eq!(
            admitted["dispatch"]["captured_output"]["stdout"],
            "profile-selected\n"
        );
        assert!(
            admitted["preflight"]["verdict"]["warnings"]
                .as_array()
                .is_some_and(|warnings| warnings.iter().any(|warning| warning
                    .as_str()
                    .is_some_and(|text| text.contains("npm:lodahs") && text.contains("risk")))),
            "an explicit balanced override must retain the risk warning: {admitted}"
        );
    }
}

/// HostIo and telemetry behind one killable session boundary. A loopback server
/// confirms that an HTTP effect reached its real socket, then withholds the
/// response; the parent deadline must still kill/reap the worker before returning.
#[cfg(target_os = "linux")]
#[test]
fn native_timeout_reaps_a_worker_stuck_in_admitted_http_io() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;

    const ENGINE_TIMEOUT: Duration = Duration::from_secs(10);
    const ADMISSION_DEADLINE: Duration = Duration::from_secs(15);
    const OUTER_DEADLINE: Duration = Duration::from_secs(25);

    fn fixed_binary(candidates: &[&'static str]) -> &'static str {
        candidates
            .iter()
            .copied()
            .find(|path| std::path::Path::new(path).is_file())
            .expect("required fixed system binary is available")
    }

    fn process_start_time(pid: u32) -> Option<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields_after_command = stat.rsplit_once(") ")?.1;
        fields_after_command
            .split_whitespace()
            .nth(19)
            .map(str::to_string)
    }

    fn direct_worker_identity(parent_pid: u32) -> Option<(u32, String)> {
        let children_path = format!("/proc/{parent_pid}/task/{parent_pid}/children");
        let children = std::fs::read_to_string(children_path).ok()?;
        children.split_whitespace().find_map(|pid| {
            let pid = pid.parse::<u32>().ok()?;
            process_start_time(pid).map(|start_time| (pid, start_time))
        })
    }

    fn kill_test_process_tree(child: &mut std::process::Child) {
        // The product worker deliberately creates a nested process group, so
        // kill direct descendants first if the OUTER test deadline ever wins.
        // This is test-harness cleanup only; the passing path never calls it.
        let children_path = format!("/proc/{}/task/{}/children", child.id(), child.id());
        if let Ok(children) = std::fs::read_to_string(children_path) {
            let kill = fixed_binary(&["/bin/kill", "/usr/bin/kill"]);
            for pid in children.split_whitespace() {
                let _ = Command::new(kill)
                    .args(["-KILL", "--", pid])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        let kill = fixed_binary(&["/bin/kill", "/usr/bin/kill"]);
        let _ = Command::new(kill)
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = child.kill();
        let _ = child.wait();
    }

    let dir = tempfile::TempDir::new().expect("timeout fixture tempdir");
    let app_path = dir.path().join("app.js");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind timeout sink");
    listener
        .set_nonblocking(true)
        .expect("make timeout sink accept bounded");
    let sink_addr = listener.local_addr().expect("timeout sink address");
    let (admitted_tx, admitted_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    std::fs::write(
        &app_path,
        format!(
            "require('fs').writeFileSync('entered.marker', 'entered');\n\
             require('http').get('http://{sink_addr}/', (res) => {{\n\
               require('fs').writeFileSync('after.marker', res.body);\n\
             }});\n"
        ),
    )
    .expect("write admitted-effect fixture");

    let init = Command::new(franken_node_bin())
        .args(["init", "--profile", "legacy-risky", "--out-dir", "."])
        .current_dir(dir.path())
        .output()
        .expect("bootstrap timeout workspace");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let config_path = dir.path().join("franken_node.toml");
    let mut config: frankenengine_node::config::Config =
        toml::from_str(&std::fs::read_to_string(&config_path).expect("read initialized config"))
            .expect("parse initialized config");
    config.security.network_policy.allowlist.push(
        frankenengine_node::config::NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: Some(sink_addr.port()),
            reason: "bd-wwjxn real admitted-effect timeout regression".to_string(),
        },
    );
    std::fs::write(
        &config_path,
        config.to_toml().expect("serialize timeout config"),
    )
    .expect("write timeout config");

    // Start the server deadline only after fixture initialization; otherwise a
    // slow debug/CI init could consume the accept budget before the product is
    // even spawned.
    let server = std::thread::spawn(move || {
        let accept_started = Instant::now();
        let (mut stream, _peer) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && accept_started.elapsed() < ADMISSION_DEADLINE =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept admitted HTTP effect: {error}"),
            }
        };
        stream
            .set_nonblocking(false)
            .expect("make accepted timeout connection blocking");
        stream
            .set_read_timeout(Some(ADMISSION_DEADLINE))
            .expect("set timeout sink read deadline");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .expect("read half-closed guest HTTP request");
        admitted_tx
            .send(request)
            .expect("publish admitted HTTP effect");
        release_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("test releases the deliberately withheld response");
        let write_result = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoo-late",
        );
        let _ = stream.flush();
        write_result
    });

    let mut command = Command::new(franken_node_bin());
    command
        .args([
            "run",
            "app.js",
            "--policy",
            "legacy-risky",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--json",
        ])
        .current_dir(dir.path())
        .env(
            "FRANKEN_ENGINE_TIMEOUT_SECS",
            ENGINE_TIMEOUT.as_secs().to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().expect("spawn product timeout run");

    let admitted_request = match admitted_rx.recv_timeout(ADMISSION_DEADLINE) {
        Ok(request) => request,
        Err(error) => {
            kill_test_process_tree(&mut child);
            let mut stderr = String::new();
            if let Some(mut diagnostics) = child.stderr.take() {
                let _ = diagnostics.read_to_string(&mut stderr);
            }
            let _ = release_tx.send(());
            let _ = server.join();
            panic!("product run never admitted the HTTP effect: {error}; stderr: {stderr}");
        }
    };
    if !admitted_request.starts_with(b"GET / HTTP/1.1\r\n") {
        kill_test_process_tree(&mut child);
        let _ = release_tx.send(());
        let _ = server.join();
        panic!("the sink must observe the genuine lowered HTTP request");
    }
    let (worker_pid, worker_start_time) = match direct_worker_identity(child.id()) {
        Some(identity) => identity,
        None => {
            kill_test_process_tree(&mut child);
            let _ = release_tx.send(());
            let _ = server.join();
            panic!("the admitted effect must belong to the direct native-session worker");
        }
    };

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= OUTER_DEADLINE => {
                kill_test_process_tree(&mut child);
                let _ = release_tx.send(());
                let _ = server.join();
                panic!("product timeout exceeded the {OUTER_DEADLINE:?} outer test deadline");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                kill_test_process_tree(&mut child);
                let _ = release_tx.send(());
                let _ = server.join();
                panic!("failed polling product timeout run: {error}");
            }
        }
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("timeout stderr pipe")
        .read_to_string(&mut stderr)
        .expect("read timeout diagnostic");
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("timeout stdout pipe")
        .read_to_string(&mut stdout)
        .expect("read timeout effect evidence");
    let elapsed = started.elapsed();
    let entered_before_timeout = dir.path().join("entered.marker").is_file();
    let callback_absent_before_release = !dir.path().join("after.marker").exists();
    let worker_identity_gone_before_release =
        process_start_time(worker_pid).as_deref() != Some(worker_start_time.as_str());

    // Only after the CLI has returned do we release a valid response. The
    // write may succeed into the kernel buffer or fail because the peer was
    // killed; either way, no guest callback can still consume it.
    release_tx.send(()).expect("release withheld response");
    let _late_response_result = server.join().expect("join timeout sink");
    std::thread::sleep(Duration::from_millis(100));
    let callback_absent_after_release = !dir.path().join("after.marker").exists();

    assert!(!status.success(), "the stuck session must time out");
    assert!(
        stderr.to_ascii_lowercase().contains("timed out"),
        "timeout must be typed and actionable: {stderr}"
    );
    let evidence: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "timeout must surface structured interrupted-effect evidence: {error}; stdout={stdout}; stderr={stderr}"
        )
    });
    assert_eq!(
        evidence.get("schema_version").and_then(Value::as_str),
        Some("franken-node/native-effect-interruption-evidence/v1")
    );
    assert_eq!(
        evidence.get("terminal_state").and_then(Value::as_str),
        Some("timeout_indeterminate")
    );
    assert_eq!(
        evidence.get("replay_certified").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        evidence.get("journal_complete").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        evidence
            .get("interrupted_effect_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        evidence
            .get("completed_effect_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1,
        "the pre-timeout filesystem marker must have a returned-provider WAL pair: {evidence:#}"
    );
    let interrupted = evidence
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.get("effect_kind").and_then(Value::as_str) == Some("network_request")
                    && entry.get("state").and_then(Value::as_str)
                        == Some("interrupted_indeterminate")
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "the admitted HTTP effect must remain explicitly indeterminate, never allowed/denied: {evidence:#}"
            )
        });
    assert!(
        interrupted
            .get("request_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
    );
    assert!(
        interrupted.get("policy_outcome").is_none()
            && interrupted.get("allowed").is_none()
            && interrupted.get("denied").is_none(),
        "interrupted WAL evidence must not masquerade as finalized ledger semantics"
    );
    assert!(
        elapsed >= ENGINE_TIMEOUT && elapsed < OUTER_DEADLINE,
        "whole-session deadline must be bounded: {elapsed:?}"
    );
    assert!(
        entered_before_timeout,
        "the pre-request marker proves guest execution reached the effect site"
    );
    assert!(
        callback_absent_before_release,
        "no response callback effect may survive timeout"
    );
    assert!(
        worker_identity_gone_before_release,
        "the timed-out native-session worker identity must be gone before the CLI returns"
    );
    assert!(
        callback_absent_after_release,
        "the released response must not revive a timed-out guest callback"
    );

    // Persistence is checked only after the real server and worker cleanup
    // above, so a failed assertion cannot leave the admitted request hanging.
    // The parent owns this WAL prefix; it never becomes a finalized effect
    // ledger or a claim that the interrupted guest produced no console.
    assert_eq!(evidence["success"], false);
    assert_eq!(evidence["guest_output_available"], false);
    assert!(
        evidence["error"]
            .as_str()
            .is_some_and(|error| error.to_ascii_lowercase().contains("timed out")),
        "the original timeout remains the run's error: {evidence}"
    );
    assert_eq!(evidence["dispatch"]["runtime"], "franken_engine");
    assert!(evidence["dispatch"]["host_effect_ledger"].is_null());
    assert!(evidence["dispatch"]["engine_decision"].is_null());
    assert!(evidence["dispatch"]["sentinel"].is_null());
    assert!(evidence.get("allowed_count").is_none());
    assert!(evidence.get("denied_count").is_none());

    let typed_wal: frankenengine_node::ops::engine_dispatcher::NativeEffectInterruptionEvidence =
        serde_json::from_value(evidence.clone()).expect("the original typed parent WAL");
    let wal = serde_json::to_value(&typed_wal).expect("serialize every typed WAL field");
    let receipt = &evidence["receipt"];
    assert_eq!(receipt["runtime_used"], "franken_engine");
    assert_eq!(receipt["exit_code"], 1);
    assert_eq!(receipt["execution_failure"], evidence["error"]);
    assert_eq!(receipt["interruption_evidence"], wal);
    assert!(
        receipt["incident_capture"].is_null(),
        "indeterminate provider state cannot auto-produce certified replay evidence"
    );
    let receipt_id = receipt["receipt_id"].as_str().expect("timeout receipt ID");
    let receipt_path = dir.path().join(
        evidence["receipt_path"]
            .as_str()
            .expect("timeout names its durable receipt"),
    );
    let stored_receipt: Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("read timeout receipt"))
            .expect("timeout receipt JSON");
    assert_eq!(stored_receipt, *receipt);
    let ended_at = chrono::DateTime::parse_from_rfc3339(
        receipt["end_time_utc"].as_str().expect("timeout end time"),
    )
    .expect("RFC3339 timeout end time");
    let invented_ledger_path = dir
        .path()
        .join(".franken-node/state/run-ledgers")
        .join(ended_at.format("%Y-%m-%d").to_string())
        .join(format!("{receipt_id}.json"));
    assert!(
        !invented_ledger_path.exists(),
        "the parent WAL must not acquire a fabricated finalized run-ledger record"
    );

    use frankenengine_node::observability::evidence_ledger::{
        DecisionKind, EvidenceEntry, verify_evidence_entry,
    };
    use frankenengine_node::observability::evidence_ledger_durable::DurableEvidenceLedger;
    let rows = DurableEvidenceLedger::open_default(dir.path())
        .expect("open durable timeout decision inventory")
        .entries_json()
        .expect("read timeout decision inventory");
    assert_eq!(
        rows.len(),
        1,
        "the interrupted attempt is retained exactly once"
    );
    let decision: EvidenceEntry = serde_json::from_str(&rows[0]).expect("timeout decision");
    let verifying_key = receipt_verifying_key(dir.path());
    verify_evidence_entry(&decision, &verifying_key)
        .expect("the product signs the interrupted-attempt decision");
    assert_eq!(decision.decision_id, receipt_id);
    assert_eq!(decision.decision_kind, DecisionKind::Deny);
    assert_eq!(decision.payload["receipt_hash"], receipt["receipt_hash"]);
    assert_eq!(decision.payload["run_receipt_snapshot"], *receipt);
    assert_eq!(decision.payload["interruption_evidence"], wal);
    assert_eq!(decision.payload["guest_output_available"], false);
    assert!(decision.payload["host_effect_chain_head"].is_null());
    assert!(decision.payload["host_effects_allowed"].is_null());
    assert!(decision.payload["host_effects_denied"].is_null());
    // This identity captures session context. The product decision signature
    // above, not the engine identity, authenticates the parent-observed WAL.
    assert!(decision.payload["runtime_evidence_identity_capture"].is_object());
    assert_eq!(
        decision.payload["runtime_evidence_identity_capture"],
        evidence["dispatch"]["runtime_evidence_identity_capture"]
    );
    assert_eq!(
        decision.payload["runtime_evidence_identity_capture_path"],
        evidence["dispatch"]["runtime_evidence_identity_capture_path"]
    );
    assert!(decision.payload["runtime_evidence_identity_capture_path"].is_string());
    let interrupted_index = typed_wal
        .entries
        .iter()
        .position(|entry| {
            entry.state
                == frankenengine_node::ops::engine_dispatcher::NativeEffectWalState::InterruptedIndeterminate
        })
        .expect("the admitted HTTP effect remains unmatched");
    for pointer in [
        format!("/interruption_evidence/entries/{interrupted_index}/state"),
        format!("/run_receipt_snapshot/interruption_evidence/entries/{interrupted_index}/state"),
    ] {
        let mut forged = decision.clone();
        *forged
            .payload
            .pointer_mut(&pointer)
            .expect("signed WAL state") = Value::from("provider_returned");
        assert!(
            verify_evidence_entry(&forged, &verifying_key).is_err(),
            "changing interrupted state must invalidate the signature at {pointer}"
        );
    }

    let capture = Command::new(franken_node_bin())
        .args(["incident", "capture", "--from-run", receipt_id, "--json"])
        .current_dir(dir.path())
        .output()
        .expect("try to capture an indeterminate timeout as finalized evidence");
    assert!(
        !capture.status.success(),
        "an interruption is not replay-certifiable"
    );
    let capture_diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&capture.stdout),
        String::from_utf8_lossy(&capture.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        capture_diagnostic.contains("interrupted") || capture_diagnostic.contains("indeterminate"),
        "capture must explain the incomplete effect boundary: {capture_diagnostic}"
    );
    let (listing, list) = run_workspace_json(dir.path(), &["incident", "list", "--json"]);
    assert_eq!(listing.exit_code, Some(0), "{}", listing.stderr);
    assert_eq!(list["incidents"], serde_json::json!([]));
    let (coverage, report) = run_workspace_json(
        dir.path(),
        &["ops", "incident-coverage", "--min-coverage", "1", "--json"],
    );
    assert_ne!(coverage.exit_code, Some(0));
    assert_eq!(report["receipts_scanned"], 1);
    assert_eq!(report["inventory_runs"], 1);
    assert_eq!(report["excluded_non_native_receipts"], 0);
    assert_eq!(report["population_authenticated"], false);
    let source_errors = report["source_errors"]
        .as_array()
        .expect("coverage source errors");
    assert!(
        source_errors.iter().any(|error| {
            let detail = error.to_string().to_ascii_lowercase();
            detail.contains(receipt_id)
                && (detail.contains("interrupted") || detail.contains("indeterminate"))
        }),
        "coverage must retain the timed-out attempt's unavailable final evidence: {report}"
    );
    assert_eq!(report["captured"], 0);
    assert_eq!(report["bundled"], 0);

    // A later product run must start a fresh healthy worker; timeout cleanup
    // cannot poison global admission or telemetry state.
    std::fs::write(
        &app_path,
        "require('fs').writeFileSync('healthy.marker', 'healthy');\n",
    )
    .expect("write post-timeout health fixture");
    let healthy = Command::new(franken_node_bin())
        .args([
            "run",
            "app.js",
            "--policy",
            "legacy-risky",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--console-only",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn post-timeout health run");
    assert!(
        healthy.status.success(),
        "subsequent native run failed: {}",
        String::from_utf8_lossy(&healthy.stderr)
    );
    assert_eq!(
        std::fs::read(dir.path().join("healthy.marker")).expect("healthy marker"),
        b"healthy"
    );
    let (coverage_after_healthy, after_healthy) = run_workspace_json(
        dir.path(),
        &["ops", "incident-coverage", "--min-coverage", "1", "--json"],
    );
    assert_ne!(coverage_after_healthy.exit_code, Some(0));
    assert_eq!(after_healthy["receipts_scanned"], 2);
    assert_eq!(after_healthy["inventory_runs"], 2);
    assert!(
        after_healthy["source_errors"]
            .as_array()
            .expect("post-recovery source errors")
            .iter()
            .any(|error| error.to_string().contains(receipt_id)),
        "a healthy later run must not erase the unresolved timeout: {after_healthy}"
    );
}

const DEBUG_DUMP_MARKERS: &[&str] = &["Native execution completed", "OrchestratorResult"];

/// A pure in-budget program that performs no host I/O, so the trust-native
/// runtime admits it (containment Allow) and `run` completes with exit 0.
const COMPUTE_APP: &str = "const total = 40 + 2;\nconst doubled = total * 2;\n";

/// A guest program with an uncaught exception: the interpreter surfaces the
/// failure and `run` exits non-zero (real error path, not a verdict constant).
const THROW_APP: &str = "throw new Error(\"boom\");\n";

/// A program attempting network egress to the cloud-metadata endpoint, which
/// the capability/SSRF gates refuse under every default profile. The denial
/// is deterministic and happens BEFORE any socket opens, so this fixture
/// needs no network and cannot flake on connectivity.
// The `error` listener is load-bearing, not decoration: this fixture exists to
// prove a denied effect is RECORDED while the run still completes, and the
// assertions below read `dispatch.host_effect_ledger`, which only exists on a
// completed run. Without the listener the refused egress raises an uncaught
// ERR_NETWORK, the run aborts before any dispatch report, and the test fails
// for a reason it was never written to detect. A guest that handles the refusal
// is exactly the "clean guest" this test's contract describes.
const DENIED_EGRESS_APP: &str = "const http = require(\"http\");\n\
    const req = http.get(\"http://169.254.169.254/latest/meta-data/\", (res) => {\n\
    console.log(\"unexpected\", res.statusCode);\n\
    });\n\
    req.on(\"error\", () => {\n\
    console.log(\"egress refused as expected\");\n\
    });\n";

fn assert_no_debug_dump(stream: &str, label: &str) {
    for marker in DEBUG_DUMP_MARKERS {
        assert!(
            !stream.contains(marker),
            "{label} must not contain the debug-dump marker {marker:?}: {stream:?}"
        );
    }
}

fn receipt_verifying_key(workspace: &std::path::Path) -> ed25519_dalek::VerifyingKey {
    let public_hex =
        std::fs::read_to_string(workspace.join(".franken-node/keys/receipt-signing.pub"))
            .expect("read the operator's init-provisioned receipt authority");
    let public_bytes: [u8; 32] = hex::decode(public_hex.trim())
        .expect("receipt public key is hex")
        .try_into()
        .expect("receipt public key is 32 bytes");
    ed25519_dalek::VerifyingKey::from_bytes(&public_bytes).expect("valid receipt public key")
}

fn run_workspace_json(workspace: &std::path::Path, args: &[&str]) -> (RunOutcome, Value) {
    let output = Command::new(franken_node_bin())
        .args(args)
        .current_dir(workspace)
        .output()
        .expect("run the real product command");
    let outcome = RunOutcome {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{args:?} must emit JSON: {error}; exit={:?}; stdout={}; stderr={}",
            outcome.exit_code, outcome.stdout, outcome.stderr
        )
    });
    (outcome, report)
}

fn persisted_failed_run_receipt(
    workspace: &std::path::Path,
    outcome: &RunOutcome,
    evidence: &Value,
) -> (std::path::PathBuf, Value) {
    assert_eq!(outcome.exit_code, Some(1), "{}", outcome.stderr);
    assert_eq!(
        evidence["schema_version"],
        "franken-node/run-failure-effect-evidence/v2"
    );
    assert_eq!(evidence["dispatch"]["runtime"], "franken_engine");
    assert_eq!(evidence["dispatch"]["exit_code"], 1);
    assert_eq!(evidence["dispatch"]["terminated_by_signal"], false);
    assert_eq!(
        evidence["dispatch"]["captured_output"],
        evidence["captured_output"]
    );
    assert_eq!(
        evidence["dispatch"]["host_effect_ledger"],
        evidence["host_effect_ledger"]
    );
    let receipt = &evidence["receipt"];
    assert_eq!(receipt["runtime_used"], "franken_engine");
    assert_eq!(receipt["exit_code"], 1);
    assert_eq!(receipt["execution_failure"], evidence["error"]);
    assert!(
        receipt["execution_failure"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "the durable receipt must bind the original execution failure: {evidence}"
    );
    let receipt_path = workspace.join(
        evidence["receipt_path"]
            .as_str()
            .expect("failed run names its persisted receipt"),
    );
    assert!(
        receipt_path
            .canonicalize()
            .expect("failed receipt exists")
            .starts_with(workspace.canonicalize().expect("workspace exists")),
        "the receipt must live in the run's own project"
    );
    let persisted: Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("read failed receipt"))
            .expect("failed receipt is JSON");
    assert_eq!(persisted, *receipt, "CLI and durable receipt must agree");
    (receipt_path, persisted)
}

fn authenticated_failed_run_record(
    workspace: &std::path::Path,
    evidence: &Value,
    receipt: &Value,
) -> Option<Value> {
    use frankenengine_node::ops::engine_dispatcher::{
        HostEffectLedger, verify_recorded_host_effect_ledger,
    };
    use frankenengine_node::tools::replay_bundle::parse_verified_run_ledger_record;

    let ended_at = chrono::DateTime::parse_from_rfc3339(
        receipt["end_time_utc"].as_str().expect("receipt end time"),
    )
    .expect("receipt has an RFC3339 end time");
    let record_path = workspace
        .join(".franken-node/state/run-ledgers")
        .join(ended_at.format("%Y-%m-%d").to_string())
        .join(format!(
            "{}.json",
            receipt["receipt_id"].as_str().expect("receipt identity")
        ));
    if evidence["host_effect_ledger"].is_null() {
        assert!(
            !record_path.exists(),
            "an unavailable finalized ledger must not acquire a fabricated run record"
        );
        return None;
    }
    let record_bytes = std::fs::read(&record_path).expect("failed run persists its signed ledger");
    let verifying_key = receipt_verifying_key(workspace);
    let record = parse_verified_run_ledger_record(&record_bytes, receipt, &verifying_key)
        .expect("the complete failed receipt and run record authenticate");
    assert_eq!(record["receipt_snapshot"], *receipt);
    assert_eq!(record["host_effect_ledger"], evidence["host_effect_ledger"]);
    assert_eq!(
        record["runtime_evidence_identity_capture_path"],
        evidence["dispatch"]["runtime_evidence_identity_capture_path"]
    );
    let ledger: HostEffectLedger = serde_json::from_value(record["host_effect_ledger"].clone())
        .expect("stored finalized engine ledger");
    verify_recorded_host_effect_ledger(
        workspace,
        &ledger,
        std::path::Path::new(
            record["runtime_evidence_identity_capture_path"]
                .as_str()
                .expect("failed record retains the product-root-signed session identity"),
        ),
    )
    .expect("the failed ledger verifies against the independently stored engine authority");

    let mut forged_receipt = receipt.clone();
    forged_receipt["execution_failure"] = Value::Null;
    assert!(
        parse_verified_run_ledger_record(&record_bytes, &forged_receipt, &verifying_key).is_err(),
        "a genuine record cannot authenticate a receipt with its execution failure removed"
    );
    Some(record)
}

#[test]
fn clean_compute_run_surfaces_real_exit_zero_and_signed_receipt() {
    let (_dir, outcome) = run_app(COMPUTE_APP, &["--json"]);

    // A no-host-IO program is admitted; in --json mode the report is emitted on
    // stdout. Parse first so a non-zero verdict surfaces the dispatch detail.
    let report: Value = serde_json::from_str(&outcome.stdout).unwrap_or_else(|e| {
        panic!(
            "run --json must emit a report for an in-budget program: {e}\nexit={:?}\nstdout=\n{}\nstderr=\n{}",
            outcome.exit_code, outcome.stdout, outcome.stderr
        )
    });

    // bd-5r99w.2: real Allow->0 exit, surfaced by the process, the dispatch
    // report, and the signed receipt alike (not a synthetic constant).
    assert_eq!(
        report["dispatch"]["exit_code"].as_i64(),
        Some(0),
        "in-budget compute must dispatch as Allow->0; dispatch=\n{}",
        serde_json::to_string_pretty(&report["dispatch"]).unwrap_or_default()
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "process exit must match the verdict-derived 0; stderr=\n{}",
        outcome.stderr
    );
    assert_eq!(
        report["receipt"]["exit_code"].as_i64(),
        report["dispatch"]["exit_code"].as_i64(),
        "the signed receipt must record the SAME real exit code as the dispatch"
    );
    assert_eq!(report["success"].as_bool(), Some(true));
    assert!(
        report.get("containment_verdict").is_none(),
        "an ordinary exit carries no containment verdict: {report}"
    );

    // bd-5r99w.1: captured output is the real (here empty) console stream, never
    // the old Rust `{:?}` debug dump of the orchestrator result.
    let captured_stdout = report["dispatch"]["captured_output"]["stdout"]
        .as_str()
        .expect("captured_output.stdout present");
    assert_no_debug_dump(captured_stdout, "captured stdout");
    assert_no_debug_dump(&outcome.stdout, "process stdout");
}

/// bd-w1xhn: a denied host effect must be surfaced fail-VISIBLY in the signed
/// host-effect ledger, never silently dropped. The exit code derives from the
/// containment verdict (a single denied effect does not escalate containment,
/// so a clean guest still exits 0) — the tamper-evident record of the refusal
/// is the ledger's `denied_count` and per-entry `Denied` outcome.
#[test]
fn denied_host_effect_is_surfaced_in_signed_ledger_not_masked() {
    let (_dir, outcome) = run_app(DENIED_EGRESS_APP, &["--json"]);
    let report: Value = serde_json::from_str(&outcome.stdout).unwrap_or_else(|e| {
        panic!(
            "run --json must emit a report: {e}\nexit={:?}\nstdout=\n{}\nstderr=\n{}",
            outcome.exit_code, outcome.stdout, outcome.stderr
        )
    });

    let ledger = &report["dispatch"]["host_effect_ledger"];
    assert!(
        !ledger.is_null(),
        "a run attempting a host effect must surface a host-effect ledger; dispatch=\n{}",
        serde_json::to_string_pretty(&report["dispatch"]).unwrap_or_default()
    );
    let denied = ledger["denied_count"].as_u64().unwrap_or(0);
    assert!(
        denied >= 1,
        "the refused egress must be recorded as a denied effect, got ledger=\n{}",
        serde_json::to_string_pretty(ledger).unwrap_or_default()
    );
    assert!(
        ledger["chain_head_hash"]
            .as_str()
            .is_some_and(|h| h.starts_with("sha256:")),
        "the denial must be committed under the tamper-evident chain head, got ledger=\n{}",
        serde_json::to_string_pretty(ledger).unwrap_or_default()
    );
    // Containment stayed Allow (a single denied effect is refused, not
    // escalated), so the guest ran to completion and the process exits 0.
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "containment Allow must yield exit 0; the denial lives in the ledger; stderr=\n{}",
        outcome.stderr
    );
    assert_no_debug_dump(&outcome.stdout, "process stdout");
}

/// Same refused egress as above, but the guest does NOT handle it, so the
/// uncaught `ERR_NETWORK` aborts the run before any completion report exists.
///
/// bd-muy9u: the abort must not take the evidence with it. Previously the
/// engine dropped the recorder's finalized transcript on the failure path and
/// the dispatcher mapped the error straight to `EngineProcessError`, so the
/// refusal that had already been decided and recorded simply vanished — a
/// denial was indistinguishable from an egress that never happened. The run is
/// still a failure; only its receipts are recovered.
#[test]
fn a_failed_run_still_surfaces_the_denied_effect_receipt_bd_muy9u() {
    const UNHANDLED_DENIED_EGRESS_APP: &str = "const http = require(\"http\");\n\
        http.get(\"http://169.254.169.254/latest/meta-data/\", (res) => {\n\
        console.log(\"unexpected\", res.statusCode);\n\
        });\n";

    let (dir, outcome) = run_app(UNHANDLED_DENIED_EGRESS_APP, &["--json"]);

    assert_ne!(
        outcome.exit_code,
        Some(0),
        "an uncaught denial must still fail the run, never be laundered into a success; stdout=\n{}\nstderr=\n{}",
        outcome.stdout,
        outcome.stderr
    );

    let evidence: Value = serde_json::from_str(&outcome.stdout).unwrap_or_else(|e| {
        panic!(
            "a failed run that already performed host effects must still emit their evidence: {e}\nexit={:?}\nstdout=\n{}\nstderr=\n{}",
            outcome.exit_code, outcome.stdout, outcome.stderr
        )
    });
    assert_eq!(
        evidence["schema_version"].as_str(),
        Some("franken-node/run-failure-effect-evidence/v2"),
        "failure evidence must be self-describing; got=\n{}",
        serde_json::to_string_pretty(&evidence).unwrap_or_default()
    );
    // bd-uqz71: the v2 envelope carries the failure reason and the guest's
    // captured console, not just the ledger, so a --json consumer never has to
    // scrape the human `Error:` line off stderr.
    assert!(
        evidence["error"]
            .as_str()
            .is_some_and(|reason| !reason.trim().is_empty()),
        "failure evidence must carry a non-empty error reason; got=\n{}",
        serde_json::to_string_pretty(&evidence).unwrap_or_default()
    );
    assert!(
        evidence["captured_output"]["stdout"].is_string()
            && evidence["captured_output"]["stderr"].is_string(),
        "failure evidence must carry the guest's captured_output; got=\n{}",
        serde_json::to_string_pretty(&evidence).unwrap_or_default()
    );

    let ledger = &evidence["host_effect_ledger"];
    assert_eq!(
        ledger["denied_count"].as_u64(),
        Some(1),
        "the refusal decided before the abort must survive it; got ledger=\n{}",
        serde_json::to_string_pretty(ledger).unwrap_or_default()
    );
    assert_eq!(
        ledger["allowed_count"].as_u64(),
        Some(0),
        "nothing was permitted to execute; got ledger=\n{}",
        serde_json::to_string_pretty(ledger).unwrap_or_default()
    );

    let receipt = &ledger["entries"][0]["receipt"];
    assert_eq!(
        receipt["policy_outcome"]["outcome"].as_str(),
        Some("denied"),
        "the receipt must record the exact refusal, not a bare count; got=\n{}",
        serde_json::to_string_pretty(receipt).unwrap_or_default()
    );
    assert!(
        receipt["result_hash"].is_null() && receipt["post_state_hash"].is_null(),
        "a denied effect is fail-closed: no result and no post-state; got=\n{}",
        serde_json::to_string_pretty(receipt).unwrap_or_default()
    );
    // The engine's own attempt trace, not a label the product invented for
    // evidence it did not produce.
    assert!(
        ledger["trace_id"]
            .as_str()
            .is_some_and(|trace| !trace.trim().is_empty()),
        "failure evidence must carry the engine's real attempt trace; got ledger=\n{}",
        serde_json::to_string_pretty(ledger).unwrap_or_default()
    );
    assert!(
        ledger["chain_head_hash"]
            .as_str()
            .is_some_and(|head| head.starts_with("sha256:")),
        "recovered evidence is still chain-committed; got ledger=\n{}",
        serde_json::to_string_pretty(ledger).unwrap_or_default()
    );

    // bd-reality-20260923-26n9r.8: a failed attempt must travel through the
    // same durable evidence and incident pipeline as a completed run. The
    // guest above is real and uncaught; none of these artifacts are fixtures.
    let (receipt_path, run_receipt) = persisted_failed_run_receipt(dir.path(), &outcome, &evidence);
    let record = authenticated_failed_run_record(dir.path(), &evidence, &run_receipt)
        .expect("the denied attempt has a finalized ledger");
    assert_eq!(evidence["dispatch"]["sentinel"]["escalated"], false);
    assert!(run_receipt["sentinel_enforcement"].is_null());

    use frankenengine_node::observability::evidence_ledger::{
        DecisionKind, EvidenceEntry, verify_evidence_entry,
    };
    use frankenengine_node::observability::evidence_ledger_durable::DurableEvidenceLedger;
    let entries = DurableEvidenceLedger::open_default(dir.path())
        .expect("open durable failed-run inventory")
        .entries_json()
        .expect("read durable failed-run inventory")
        .into_iter()
        .map(|raw| serde_json::from_str::<EvidenceEntry>(&raw).expect("durable evidence entry"))
        .collect::<Vec<_>>();
    let decision = entries
        .iter()
        .find(|entry| entry.decision_id == run_receipt["receipt_id"].as_str().unwrap())
        .expect("failed attempt is retained in the durable inventory");
    let verifying_key = receipt_verifying_key(dir.path());
    verify_evidence_entry(decision, &verifying_key).expect("failed decision is signed");
    assert_eq!(decision.decision_kind, DecisionKind::Deny);
    assert_eq!(decision.payload["exit_code"], 1);
    assert_eq!(
        decision.payload["receipt_hash"],
        run_receipt["receipt_hash"]
    );
    assert_eq!(decision.payload["host_effects_denied"], 1);

    let incident_id = run_receipt["incident_capture"]["incident_id"]
        .as_str()
        .expect("the failed denial has an automatic incident identity");
    let source_path = dir.path().join(
        run_receipt["incident_capture"]["evidence_path"]
            .as_str()
            .expect("the failed receipt names its captured evidence"),
    );
    let source = frankenengine_node::tools::replay_bundle::read_verified_incident_evidence_package(
        &source_path,
        Some(incident_id),
        &verifying_key,
    )
    .expect("automatic failed-run capture is source-signed by the product authority");
    assert_eq!(
        source.initial_state_snapshot["run_receipt_id"],
        run_receipt["receipt_id"]
    );
    assert_eq!(
        source.initial_state_snapshot["run_receipt_hash"],
        run_receipt["receipt_hash"]
    );
    assert_eq!(source.events.len(), 1);
    assert_eq!(
        source.events[0].payload["effect_receipt_chain_entry"],
        ledger["entries"][0]
    );

    let (listing, list) = run_workspace_json(dir.path(), &["incident", "list", "--json"]);
    assert_eq!(listing.exit_code, Some(0), "{}", listing.stderr);
    assert!(
        list["incidents"]
            .as_array()
            .expect("incident listing")
            .iter()
            .any(|row| {
                row["incident_id"] == incident_id
                    && row["source"] == "captured"
                    && row["status"] == "valid"
            })
    );
    let (capture, captured) = run_workspace_json(
        dir.path(),
        &[
            "incident",
            "capture",
            "--from-run",
            run_receipt["receipt_id"].as_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(capture.exit_code, Some(0), "{}", capture.stderr);
    assert_eq!(captured["status"], "already_captured");
    assert_eq!(captured["verification"]["receipt_binding"], "authenticated");
    assert_eq!(captured["verification"]["source_signature"], "valid");
    assert_eq!(captured["denied_count"], 1);

    let (before, before_report) = run_workspace_json(
        dir.path(),
        &["ops", "incident-coverage", "--min-coverage", "1", "--json"],
    );
    assert_ne!(
        before.exit_code,
        Some(0),
        "capture alone is not a verified replay bundle"
    );
    assert_eq!(before_report["population_authenticated"], true);
    assert_eq!(before_report["inventory_runs"], 1);
    assert_eq!(before_report["high_severity_events"], 1);
    assert_eq!(before_report["captured"], 1);
    assert_eq!(before_report["bundled"], 0);

    let (bundle, bundled) = run_workspace_json(
        dir.path(),
        &[
            "incident",
            "bundle",
            "--id",
            incident_id,
            "--verify",
            "--json",
        ],
    );
    assert_eq!(bundle.exit_code, Some(0), "{}", bundle.stderr);
    assert_eq!(bundled["source_authenticated"], true);
    let (coverage, covered) = run_workspace_json(
        dir.path(),
        &["ops", "incident-coverage", "--min-coverage", "1", "--json"],
    );
    assert_eq!(
        coverage.exit_code,
        Some(0),
        "{}: {covered}",
        coverage.stderr
    );
    assert_eq!(covered["authenticated_receipts"], 1);
    assert_eq!(covered["inventory_runs"], 1);
    assert_eq!(covered["high_severity_events"], 1);
    assert_eq!(covered["bundled"], 1);
    assert_eq!(covered["replay_coverage"], 1.0);
    assert_eq!(covered["source_errors"], serde_json::json!([]));

    // The durable CLI path rejects hand editing even when an already-captured
    // source exists. A failed receipt must never be relabelled as success.
    let original_source = std::fs::read(&source_path).expect("original captured source");
    let mut forged_receipt = run_receipt.clone();
    forged_receipt["exit_code"] = Value::from(0);
    std::fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&forged_receipt).unwrap(),
    )
    .expect("simulate a hand-edited failed receipt");
    let capture_after_tamper = Command::new(franken_node_bin())
        .args([
            "incident",
            "capture",
            "--from-run",
            run_receipt["receipt_id"].as_str().unwrap(),
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("attempt capture of a tampered failed receipt");
    assert!(!capture_after_tamper.status.success());
    assert_eq!(
        std::fs::read(&source_path).expect("capture retained"),
        original_source
    );
    assert_eq!(record["receipt_snapshot"], run_receipt);
}

#[test]
fn a_pure_throw_with_no_console_still_persists_a_failed_run_receipt() {
    let (dir, outcome) = run_app(THROW_APP, &["--json"]);
    let evidence: Value = serde_json::from_str(&outcome.stdout).unwrap_or_else(|error| {
        panic!(
            "pure throw must emit durable failure metadata: {error}; stderr={}",
            outcome.stderr
        )
    });
    let (_receipt_path, receipt) = persisted_failed_run_receipt(dir.path(), &outcome, &evidence);
    assert_eq!(evidence["captured_output"]["stdout"], "");
    assert_eq!(evidence["captured_output"]["stderr"], "");
    assert!(evidence["error"].as_str().unwrap().contains("boom"));
    assert!(
        receipt["incident_capture"].is_null(),
        "a pure guest throw is not a security incident"
    );
    if let Some(record) = authenticated_failed_run_record(dir.path(), &evidence, &receipt) {
        assert_eq!(record["host_effect_ledger"]["effect_count"], 0);
        assert_eq!(
            record["host_effect_ledger"]["entries"],
            serde_json::json!([])
        );
    }

    use frankenengine_node::observability::evidence_ledger::{
        DecisionKind, EvidenceEntry, verify_evidence_entry,
    };
    use frankenengine_node::observability::evidence_ledger_durable::DurableEvidenceLedger;
    let rows = DurableEvidenceLedger::open_default(dir.path())
        .expect("open pure-throw decision inventory")
        .entries_json()
        .expect("read pure-throw decision inventory");
    assert_eq!(
        rows.len(),
        1,
        "the no-output failure remains a recorded attempt"
    );
    let entry: EvidenceEntry = serde_json::from_str(&rows[0]).expect("failed run decision");
    verify_evidence_entry(&entry, &receipt_verifying_key(dir.path()))
        .expect("signed pure-throw decision");
    assert_eq!(entry.decision_id, receipt["receipt_id"].as_str().unwrap());
    assert_eq!(entry.decision_kind, DecisionKind::Deny);
    assert_eq!(entry.payload["exit_code"], 1);
    assert_eq!(entry.payload["receipt_hash"], receipt["receipt_hash"]);
    assert_eq!(
        entry.payload["host_effects_denied"],
        evidence["host_effect_ledger"]["denied_count"]
    );
}

#[test]
fn a_failed_run_still_enforces_its_real_sentinel_quarantine() {
    const REPEATED_DENIAL_THEN_THROW: &str = "const http = require(\"http\");\n\
        for (let i = 0; i < 5; i++) {\n\
            const req = http.get(\"http://169.254.169.254/latest/meta-data/\", () => {});\n\
            req.on(\"error\", () => {});\n\
        }\n\
        throw new Error(\"after repeated denied egress\");\n";
    let (dir, outcome) = run_app(REPEATED_DENIAL_THEN_THROW, &["--json"]);
    let evidence: Value = serde_json::from_str(&outcome.stdout).unwrap_or_else(|error| {
        panic!(
            "failed sentinel run must emit JSON: {error}; stderr={}",
            outcome.stderr
        )
    });
    let (_receipt_path, receipt) = persisted_failed_run_receipt(dir.path(), &outcome, &evidence);
    assert!(
        evidence["error"]
            .as_str()
            .unwrap()
            .contains("after repeated denied egress")
    );
    assert_eq!(evidence["host_effect_ledger"]["denied_count"], 5);
    authenticated_failed_run_record(dir.path(), &evidence, &receipt)
        .expect("repeated denials have an authenticated finalized ledger");
    let sentinel = &evidence["dispatch"]["sentinel"];
    assert_eq!(
        sentinel["escalated"], true,
        "five real denials must reach the Sentinel: {sentinel}"
    );
    assert_eq!(sentinel["e_value_ppm"], 243_000_000_u64);
    let enforcement = &receipt["sentinel_enforcement"];
    assert_eq!(enforcement["mode"], "enforced");
    assert_eq!(
        enforcement["decision_id"],
        sentinel["decision"]["decision_id"]
    );
    let quarantine_path = dir.path().join(
        enforcement["quarantine_record_path"]
            .as_str()
            .expect("persisted subject quarantine"),
    );
    let quarantine: Value = serde_json::from_slice(
        &std::fs::read(&quarantine_path).expect("failed run writes the actual quarantine"),
    )
    .expect("quarantine JSON");
    assert_eq!(quarantine["released"], false);
    assert_eq!(quarantine["decision_id"], enforcement["decision_id"]);
    assert_eq!(
        quarantine["escalation_receipt"],
        sentinel["escalation_receipt"]
    );
    let key_bytes: [u8; 32] = hex::decode(
        quarantine["escalation_verifying_key_hex"]
            .as_str()
            .expect("escalation verification identity"),
    )
    .expect("escalation key hex")
    .try_into()
    .expect("32-byte escalation key");
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).expect("escalation public key");
    let escalation: frankenengine_node::observability::evidence_ledger::EvidenceEntry =
        serde_json::from_value(quarantine["escalation_receipt"].clone())
            .expect("signed escalation");
    frankenengine_node::observability::evidence_ledger::verify_evidence_entry(&escalation, &key)
        .expect("the actual persisted escalation signature verifies");

    let rerun = Command::new(franken_node_bin())
        .args([
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("attempt to rerun the quarantined failed subject");
    assert!(
        !rerun.status.success(),
        "the persisted quarantine must block the next run"
    );
    let rerun_stdout = String::from_utf8_lossy(&rerun.stdout);
    let rerun_stderr = String::from_utf8_lossy(&rerun.stderr);
    assert!(
        rerun_stdout.contains("quarantin") || rerun_stderr.contains("quarantin"),
        "the next refusal must be the subject quarantine: stdout={rerun_stdout}; stderr={rerun_stderr}"
    );
    assert!(
        !rerun_stdout.contains("run-failure-effect-evidence"),
        "the quarantined subject must be refused before guest execution"
    );
}

/// bd-uqz71: a --json run that fails AFTER the guest printed must surface both
/// the printed console and the failure reason in the evidence envelope, not
/// drop them (v1 emitted only the ledger, forcing consumers to scrape the human
/// `Error:` line off stderr).
#[test]
fn failed_run_json_envelope_carries_guest_console_and_error_bd_uqz71() {
    // Print a marker, THEN attempt a filesystem write that balanced refuses.
    const MARK_THEN_DENIED_WRITE_APP: &str = "console.log(\"UQZ71_MARKER\");\n\
        require(\"fs\").writeFileSync(\"uqz71-out.txt\", \"x\");\n";

    let (_dir, outcome) = run_app(MARK_THEN_DENIED_WRITE_APP, &["--json"]);

    assert_ne!(
        outcome.exit_code,
        Some(0),
        "a refused write must fail the run; stdout=\n{}\nstderr=\n{}",
        outcome.stdout,
        outcome.stderr
    );

    let evidence: Value = serde_json::from_str(&outcome.stdout).unwrap_or_else(|e| {
        panic!(
            "--json failure must emit a self-describing envelope on stdout: {e}\nexit={:?}\nstdout=\n{}\nstderr=\n{}",
            outcome.exit_code, outcome.stdout, outcome.stderr
        )
    });
    assert_eq!(
        evidence["schema_version"].as_str(),
        Some("franken-node/run-failure-effect-evidence/v2"),
    );
    assert!(
        evidence["captured_output"]["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("UQZ71_MARKER")),
        "the guest's pre-failure console must survive in the envelope, not be dropped; got=\n{}",
        serde_json::to_string_pretty(&evidence).unwrap_or_default()
    );
    assert!(
        evidence["error"]
            .as_str()
            .is_some_and(|reason| reason.to_ascii_lowercase().contains("fs:write")
                || reason.to_ascii_lowercase().contains("capability")),
        "the envelope must name the failure reason (the refused fs:write), not leave it only on stderr; got=\n{}",
        serde_json::to_string_pretty(&evidence).unwrap_or_default()
    );
    // The human `Error:` line must NOT also be appended after the JSON document.
    assert!(
        !outcome.stdout.trim_end().ends_with("fix_command="),
        "the --json path must not append a human error line after the envelope; stdout=\n{}",
        outcome.stdout
    );
}

#[test]
fn receipt_persistence_failure_preserves_the_guest_error_and_console() {
    let dir = tempfile::TempDir::new().expect("fresh persistence-failure workspace");
    std::fs::write(
        dir.path().join("app.js"),
        "console.log(\"PERSISTENCE_STDOUT\");\n\
         console.error(\"PERSISTENCE_STDERR\");\n\
         throw new Error(\"ORIGINAL_GUEST_FAILURE\");\n",
    )
    .expect("write the real marker-and-throw guest");
    let init = Command::new(franken_node_bin())
        .args(["init", "--profile", "balanced", "--out-dir", "."])
        .current_dir(dir.path())
        .output()
        .expect("initialize the persistence-failure project");
    assert!(
        init.status.success(),
        "init must succeed before the obstruction: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Preserve the directory init actually created, then obstruct its original
    // path with a regular file. This fails for privileged and unprivileged
    // runners alike, without chmod assumptions or deleting a directory.
    let receipts_root = dir.path().join(".franken-node/state/execution-receipts");
    assert!(receipts_root.is_dir(), "init creates the receipt directory");
    let preserved_root = dir
        .path()
        .join(".franken-node/state/execution-receipts-initial");
    std::fs::rename(&receipts_root, &preserved_root)
        .expect("preserve init's receipt directory before obstruction");
    const OBSTRUCTION: &[u8] = b"receipt output is intentionally obstructed\n";
    std::fs::write(&receipts_root, OBSTRUCTION).expect("obstruct receipt output with a file");

    let (outcome, evidence) = run_workspace_json(
        dir.path(),
        &[
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--json",
        ],
    );
    assert_eq!(outcome.exit_code, Some(1), "{}", outcome.stderr);
    assert_eq!(
        evidence["schema_version"],
        "franken-node/run-failure-effect-evidence/v2"
    );
    assert_eq!(
        evidence["captured_output"]["stdout"],
        "PERSISTENCE_STDOUT\n"
    );
    assert_eq!(
        evidence["captured_output"]["stderr"],
        "PERSISTENCE_STDERR\n"
    );
    assert!(
        evidence["error"]
            .as_str()
            .is_some_and(|error| error.contains("ORIGINAL_GUEST_FAILURE")),
        "the storage failure must not replace the original guest failure: {evidence}"
    );
    assert!(
        evidence["persistence_error"]
            .as_str()
            .is_some_and(
                |error| error.contains("failed creating") && error.contains("execution-receipts")
            ),
        "the envelope must separately identify the actual receipt-output obstruction: {evidence}"
    );
    assert!(evidence.get("receipt").is_none());
    assert!(evidence.get("receipt_path").is_none());
    assert_ne!(evidence["success"], true);
    assert_eq!(
        std::fs::read(&receipts_root).expect("obstruction remains a regular file"),
        OBSTRUCTION,
        "failed persistence must not overwrite the obstructing file"
    );
    assert!(
        preserved_root.is_dir(),
        "the original directory is preserved"
    );
}

#[test]
fn run_exit_code_is_derived_not_constant() {
    // The SAME binary yields DIFFERENT real exit codes for the two fixtures: a
    // clean program (0) and a guest whose uncaught exception surfaces as a
    // real non-zero exit. A reintroduced synthetic constant could not satisfy
    // both, so this is the structural anti-regression for bd-5r99w.2
    // (fixture reconciled by bd-w1xhn: console denial no longer fails a run —
    // see denied_host_effect_is_surfaced_in_signed_ledger_not_masked).
    let (_d1, clean) = run_app(COMPUTE_APP, &[]);
    let (_d2, failed) = run_app(THROW_APP, &[]);
    assert_eq!(
        clean.exit_code,
        Some(0),
        "clean run exits 0; stderr=\n{}",
        clean.stderr
    );
    assert_ne!(
        failed.exit_code,
        Some(0),
        "an uncaught guest exception must exit non-zero; stderr=\n{}",
        failed.stderr
    );
    assert_ne!(
        clean.exit_code, failed.exit_code,
        "the exit code must be derived from the per-run outcome, not a constant"
    );
    assert!(
        failed.stderr.contains("uncaught exception")
            || failed.stderr.contains("execution failed")
            || failed.stderr.contains("Engine execution failed"),
        "the failure diagnostic must be the real interpreter error, got:\n{}",
        failed.stderr
    );
}

/// bd-zi9hj: `run --console-only` emits ONLY the guest program's console
/// output and its exit code — no receipt-summary line, no host-effect-ledger
/// lines, no preflight banner. This output purity is the contract the
/// lockstep harness's franken leg depends on: any appended runtime metadata
/// would register as cross-runtime divergence against bun/node.
#[test]
fn console_only_run_emits_guest_streams_verbatim() {
    let (_dir, outcome) = run_app(
        "console.log(\"pure-console-contract\");\n",
        &["--console-only"],
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "clean console run must exit 0; stderr=\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stdout, "pure-console-contract\n",
        "stdout must be exactly the guest console output, nothing appended"
    );
    assert!(
        outcome.stderr.is_empty(),
        "console-only stderr must carry only guest stderr (none here), got:\n{}",
        outcome.stderr
    );
}

/// A run that trips a security control is captured as an incident, but under
/// `--console-only` the capture notice must not reach the guest's streams:
/// the lockstep franken leg compares them byte for byte against node/bun.
#[test]
fn console_only_run_keeps_incident_capture_notice_out_of_guest_streams() {
    let (dir, outcome) = run_app(DENIED_EGRESS_APP, &["--console-only"]);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "a handled egress refusal is a clean run; stderr=\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stdout, "egress refused as expected\n",
        "stdout must be exactly the guest console output"
    );
    assert!(
        outcome.stderr.is_empty(),
        "console-only stderr must carry only guest stderr (none here), got:\n{}",
        outcome.stderr
    );
    let incidents = dir.path().join(".franken-node/state/incidents");
    let captured = std::fs::read_dir(&incidents)
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0);
    assert!(
        captured >= 1,
        "the refused egress must still be captured as an incident under {}",
        incidents.display()
    );
}

/// bd-reality-20260923-26n9r.8 (deliverable 3): `incident list` shows an
/// incident a run captured before anyone bundles it, and a bundle it cannot
/// verify is reported on its own line instead of failing the whole listing.
#[test]
fn incident_list_shows_run_captured_incidents_and_tolerates_bad_bundles() {
    let (dir, outcome) = run_app(DENIED_EGRESS_APP, &["--console-only"]);
    assert_eq!(outcome.exit_code, Some(0), "stderr=\n{}", outcome.stderr);

    let list = |dir: &std::path::Path| {
        let output = Command::new(franken_node_bin())
            .args(["incident", "list", "--json"])
            .current_dir(dir)
            .output()
            .expect("spawn franken-node incident list");
        assert!(
            output.status.success(),
            "incident list must succeed; stderr=\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let payload: Value =
            serde_json::from_slice(&output.stdout).expect("incident list --json is JSON");
        payload["incidents"]
            .as_array()
            .expect("incidents array")
            .clone()
    };

    let incidents = list(dir.path());
    assert_eq!(incidents.len(), 1, "{incidents:?}");
    assert_eq!(incidents[0]["source"], "captured");
    assert_eq!(incidents[0]["status"], "valid");
    assert_eq!(incidents[0]["severity"], "high");
    assert!(
        incidents[0]["incident_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("INC-RUN-")),
        "{incidents:?}"
    );

    std::fs::write(dir.path().join("bogus.fnbundle"), b"not a replay bundle")
        .expect("write corrupt bundle");
    let incidents = list(dir.path());
    assert_eq!(incidents.len(), 2, "{incidents:?}");
    let bogus = incidents
        .iter()
        .find(|entry| entry["source"] == "bundle")
        .expect("the corrupt bundle is listed");
    assert!(
        bogus["status"]
            .as_str()
            .is_some_and(|status| status.starts_with("unverified:")),
        "{bogus:?}"
    );
}

/// bd-bwn5a: reading a file that does not exist is an ordinary host failure,
/// not a policy denial. The signed ledger records it as `failed` (the gates
/// authorized the read; the host reported ENOENT), it is not counted as a
/// denial, and it does not trip incident capture.
#[test]
fn host_io_error_is_recorded_as_failed_not_denied_and_captures_no_incident() {
    const ENOENT_APP: &str = "const fs = require('fs');\n\
        try { fs.readFileSync('./missing.txt', 'utf8'); } catch (e) { console.log('caught:' + e.code); }\n";

    let (dir, outcome) = run_app(ENOENT_APP, &["--json"]);
    let report = last_json_document(&outcome.stdout);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "a handled ENOENT is a clean run; stderr=\n{}",
        outcome.stderr
    );
    assert_eq!(
        report["dispatch"]["captured_output"]["stdout"].as_str(),
        Some("caught:ENOENT\n")
    );
    let ledger = &report["dispatch"]["host_effect_ledger"];
    assert_eq!(
        ledger["effect_count"].as_u64(),
        Some(1),
        "ledger=\n{ledger}"
    );
    assert_eq!(
        ledger["failed_count"].as_u64(),
        Some(1),
        "ledger=\n{ledger}"
    );
    assert_eq!(
        ledger["denied_count"].as_u64(),
        Some(0),
        "ledger=\n{ledger}"
    );
    let receipt = &ledger["entries"][0]["receipt"];
    assert_eq!(
        receipt["policy_outcome"]["outcome"].as_str(),
        Some("failed")
    );
    assert_eq!(
        receipt["policy_outcome"]["capability_ref"].as_str(),
        Some("host-io:fs_read")
    );
    assert!(receipt["result_hash"].is_null());
    // `init` creates the incidents directory; what matters is that the run
    // captured nothing into it.
    let captured = std::fs::read_dir(dir.path().join(".franken-node/state/incidents"))
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0);
    assert_eq!(
        captured, 0,
        "an ordinary I/O error must not be captured as a security incident"
    );
}

/// A program that prints and then throws keeps what it printed, as under
/// Node: the output reaches the operator's streams ahead of the failure and
/// the run still exits non-zero. A throw used to discard everything printed
/// before it, so a failing program looked like it had printed nothing.
#[test]
fn a_failed_run_still_emits_the_output_printed_before_the_throw() {
    const PRINT_THEN_THROW_APP: &str =
        "console.log(\"before\");\nconsole.error(\"warned\");\nthrow new Error(\"boom\");\n";

    let (_dir, console_only) = run_app(PRINT_THEN_THROW_APP, &["--console-only"]);
    assert_ne!(
        console_only.exit_code,
        Some(0),
        "an uncaught throw still fails the run; stderr=\n{}",
        console_only.stderr
    );
    assert_eq!(
        console_only.stdout, "before\n",
        "stdout is exactly what the guest printed; stderr=\n{}",
        console_only.stderr
    );
    assert!(
        console_only.stderr.starts_with("warned\n"),
        "guest stderr precedes the failure diagnostic, got:\n{}",
        console_only.stderr
    );
    assert!(
        console_only.stderr.contains("uncaught exception"),
        "the failure diagnostic is still reported, got:\n{}",
        console_only.stderr
    );

    let (_dir, human) = run_app(PRINT_THEN_THROW_APP, &[]);
    assert_ne!(human.exit_code, Some(0), "stderr=\n{}", human.stderr);
    assert!(
        human.stdout.starts_with("before\n"),
        "the default mode prints guest output before any run metadata, got:\n{}",
        human.stdout
    );
}

/// bd-my9hk: `process.exit(n)` and `process.exitCode = n` set the run's exit
/// status and the output printed before the exit is kept. A program status in
/// the containment-class range (91..=95) is reported as 1 so those codes keep
/// meaning "the runtime contained this run".
#[test]
fn process_exit_and_exit_code_set_the_run_exit_status_bd_my9hk() {
    let (_dir, exited) = run_app(
        "console.log(\"before\");\nprocess.exit(3);\nconsole.log(\"after\");\n",
        &["--console-only"],
    );
    assert_eq!(exited.exit_code, Some(3), "stderr=\n{}", exited.stderr);
    assert_eq!(exited.stdout, "before\n", "stderr=\n{}", exited.stderr);

    let (_dir, exit_code) = run_app(
        "process.exitCode = 7;\nconsole.log(\"done\");\n",
        &["--console-only"],
    );
    assert_eq!(
        exit_code.exit_code,
        Some(7),
        "stderr=\n{}",
        exit_code.stderr
    );
    assert_eq!(exit_code.stdout, "done\n");

    let (_dir, reserved) = run_app("process.exit(92);\n", &["--console-only"]);
    assert_eq!(
        reserved.exit_code,
        Some(1),
        "a program status in the containment range must not pose as a verdict; stderr=\n{}",
        reserved.stderr
    );
}

/// bd-my9hk: the program's own arguments (`run app.js -- a b`) reach
/// `process.argv` where the profile grants process-shape reads (legacy-risky,
/// bd-y30zw); under balanced the read stays refused.
#[test]
fn app_args_reach_process_argv_where_the_profile_allows_it_bd_my9hk() {
    const ARGV_APP: &str = "console.log(process.argv.slice(2).join(\",\"));\n\
        console.log(process.argv[1].endsWith(\"app.js\"));\n";

    let (_dir, legacy) = run_app_with_policy(
        ARGV_APP,
        "legacy-risky",
        &["--console-only", "--", "alpha", "beta"],
    );
    assert_eq!(legacy.exit_code, Some(0), "stderr=\n{}", legacy.stderr);
    assert_eq!(legacy.stdout, "alpha,beta\ntrue\n");

    let (_dir, balanced) = run_app(ARGV_APP, &["--console-only", "--", "alpha", "beta"]);
    assert_ne!(balanced.exit_code, Some(0), "stdout=\n{}", balanced.stdout);
    assert!(
        balanced.stderr.contains("ambient authority violation"),
        "stderr=\n{}",
        balanced.stderr
    );
}

/// A program's whole console output reaches the operator. 1,500 lines used to
/// arrive as lines 500..1499 with exit 0: the engine kept a silent 1,000-entry
/// ring and dropped the oldest lines (fixed in franken_engine fb07b73f2).
#[test]
fn a_run_prints_every_console_line_not_only_the_last_thousand() {
    const MANY_LINES_APP: &str = "for (let i = 0; i < 1500; i++) { console.log(\"line \" + i); }\n";

    let (_dir, outcome) = run_app(MANY_LINES_APP, &["--console-only"]);
    assert_eq!(outcome.exit_code, Some(0), "stderr=\n{}", outcome.stderr);
    let expected: String = (0..1500).map(|i| format!("line {i}\n")).collect();
    assert!(
        outcome.stdout == expected,
        "stdout must be all 1,500 lines in order; got {} lines starting {:?}",
        outcome.stdout.lines().count(),
        outcome.stdout.lines().next()
    );
}

/// Console output past the engine's budget fails the run and names the limit.
/// It used to be truncated silently, or to take the session worker down as
/// "Engine crashed with panic" once the result frame overflowed.
#[test]
fn console_output_over_the_budget_fails_the_run_and_names_the_limit() {
    const HUGE_OUTPUT_APP: &str = "const line = \"x\".repeat(1048576);\n\
        for (let i = 0; i < 9; i++) { console.log(line); }\n";

    let (_dir, outcome) = run_app(HUGE_OUTPUT_APP, &["--console-only"]);
    assert_ne!(outcome.exit_code, Some(0), "stderr=\n{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("console output budget exceeded"),
        "stderr=\n{}",
        outcome.stderr.chars().take(2000).collect::<String>()
    );
    assert!(
        !outcome.stderr.contains("panic"),
        "stderr=\n{}",
        outcome.stderr
    );
    // The eight lines printed before the budget ran out are delivered.
    assert_eq!(outcome.stdout.len(), 8 * (1_048_576 + 1));
}

/// bd-xzemw: an exception thrown in a timer callback ends the program like
/// Node's uncaught exception. It used to be dropped and the run exited 0.
#[test]
fn an_exception_thrown_in_a_timer_callback_fails_the_run_bd_xzemw() {
    const TIMER_THROW_APP: &str = "console.log(\"before\");\n\
        setTimeout(() => { throw new Error(\"timer boom\"); }, 1);\n\
        setTimeout(() => { console.log(\"after\"); }, 50);\n";

    let (_dir, outcome) = run_app(TIMER_THROW_APP, &["--console-only"]);
    assert_ne!(outcome.exit_code, Some(0), "stderr=\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "before\n", "stderr=\n{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("timer boom"),
        "stderr=\n{}",
        outcome.stderr
    );
}

/// bd-xzemw: an unhandled Promise rejection ends the program like Node's
/// default `--unhandled-rejections=throw`; a handled one does not.
#[test]
fn an_unhandled_promise_rejection_fails_the_run_bd_xzemw() {
    const REJECTION_APP: &str = "console.log(\"before\");\n\
        Promise.reject(new Error(\"nobody caught me\"));\n\
        setTimeout(() => { console.log(\"after\"); }, 10);\n";

    let (_dir, outcome) = run_app(REJECTION_APP, &["--console-only"]);
    assert_ne!(outcome.exit_code, Some(0), "stderr=\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "before\n", "stderr=\n{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("nobody caught me"),
        "stderr=\n{}",
        outcome.stderr
    );

    const HANDLED_APP: &str = "Promise.reject(new Error(\"x\")).catch((e) => { console.log(\"caught \" + e.message); });\n";
    let (_dir, handled) = run_app(HANDLED_APP, &["--console-only"]);
    assert_eq!(handled.exit_code, Some(0), "stderr=\n{}", handled.stderr);
    assert_eq!(handled.stdout, "caught x\n");
}

#[test]
fn verify_lockstep_json_fails_closed_when_project_path_missing() {
    let output = Command::new(franken_node_bin())
        .args(["verify", "lockstep", "--json"])
        .output()
        .expect("spawn verify lockstep --json missing project path");
    assert!(
        !output.status.success(),
        "verify lockstep --json should fail when the project path is omitted"
    );
    let payload: Value = serde_json::from_slice(&output.stdout)
        .expect("verify lockstep --json missing path must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/verify-lockstep-error-cli/v1"
    );
    assert_eq!(payload["command"], "verify.lockstep");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("project path"),
        "missing project path --json must name the handler requirement: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: `verify lockstep` requires a project path"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

/// bd-zi9hj: the operator-facing `verify lockstep --runtimes bun,franken-node`
/// franken leg historically spawned a `franken-engine` binary that does not
/// exist anywhere (the engine repo ships no such [[bin]]), so the leg had
/// never executed — strace's own noise became the leg output and every check
/// diverged. The leg now runs THIS binary in console-only mode through the
/// in-process native engine. Positive control: identical guest behavior must
/// agree. Negative control: a genuinely divergent program must still block
/// release, proving the comparison is discriminating rather than vacuous.
#[test]
fn verify_lockstep_json_fails_closed_on_single_runtime() {
    let dir = tempfile::tempdir().expect("lockstep json workspace");
    std::fs::write(dir.path().join("app.js"), "console.log('lockstep');\n")
        .expect("write lockstep fixture");
    let output = Command::new(franken_node_bin())
        .args([
            "verify",
            "lockstep",
            "app.js",
            "--json",
            "--runtimes",
            "bun",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn verify lockstep --json single runtime");
    assert!(
        !output.status.success(),
        "verify lockstep --json with one runtime must fail closed"
    );
    let payload: Value = serde_json::from_slice(&output.stdout)
        .expect("verify lockstep --json early failure must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/verify-lockstep-error-cli/v1"
    );
    assert_eq!(payload["command"], "verify.lockstep");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("at least two distinct runtimes"),
        "single-runtime --json must name the runtime floor: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Lockstep harness failed"),
        "--json must not append a human Error line after the JSON report: {stderr}"
    );
}

#[test]
fn verify_lockstep_franken_leg_executes_against_bun() {
    for (tool, probe_arg) in [("bun", "--version"), ("strace", "-V")] {
        if Command::new(tool).arg(probe_arg).output().is_err() {
            eprintln!(
                "skipping verify_lockstep_franken_leg_executes_against_bun: {tool} unavailable"
            );
            return;
        }
    }

    let (dir, run_outcome) = run_app("console.log(\"lockstep-parity\");\n", &["--console-only"]);
    assert_eq!(
        run_outcome.exit_code,
        Some(0),
        "fixture must run cleanly before lockstep; stderr=\n{}",
        run_outcome.stderr
    );

    let agree = Command::new(franken_node_bin())
        .args([
            "verify",
            "lockstep",
            "app.js",
            "--runtimes",
            "bun,franken-node",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn verify lockstep");
    let agree_stdout = String::from_utf8_lossy(&agree.stdout);
    assert!(
        agree.status.success(),
        "identical guest behavior must pass lockstep; stdout=\n{}\nstderr=\n{}",
        agree_stdout,
        String::from_utf8_lossy(&agree.stderr)
    );
    assert!(
        agree_stdout.contains("\"verdict\": \"Pass\""),
        "lockstep report must record Pass, got:\n{agree_stdout}"
    );

    let agree_json = Command::new(franken_node_bin())
        .args([
            "verify",
            "lockstep",
            "app.js",
            "--runtimes",
            "bun,franken-node",
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn verify lockstep --json");
    assert!(
        agree_json.status.success(),
        "identical guest behavior must pass lockstep --json; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&agree_json.stdout),
        String::from_utf8_lossy(&agree_json.stderr)
    );
    let json_stderr = String::from_utf8_lossy(&agree_json.stderr);
    assert!(
        !json_stderr.contains("Running lockstep verification"),
        "verify lockstep --json must suppress the human stderr banner: {json_stderr}"
    );

    std::fs::write(
        dir.path().join("divergent.js"),
        "console.log(typeof Bun !== \"undefined\" ? \"engine-bun\" : \"engine-other\");\n",
    )
    .expect("write divergent fixture");
    let diverge = Command::new(franken_node_bin())
        .args([
            "verify",
            "lockstep",
            "divergent.js",
            "--runtimes",
            "bun,franken-node",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn verify lockstep divergent");
    assert!(
        !diverge.status.success(),
        "a genuinely divergent program must fail lockstep"
    );
    let diverge_all = format!(
        "{}{}",
        String::from_utf8_lossy(&diverge.stdout),
        String::from_utf8_lossy(&diverge.stderr)
    );
    assert!(
        diverge_all.contains("block_release"),
        "divergence must block release, got:\n{diverge_all}"
    );

    let diverge_json = Command::new(franken_node_bin())
        .args([
            "verify",
            "lockstep",
            "divergent.js",
            "--runtimes",
            "bun,franken-node",
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn verify lockstep divergent --json");
    assert!(
        !diverge_json.status.success(),
        "a genuinely divergent program must fail lockstep --json"
    );
    let diverge_json_stdout = String::from_utf8_lossy(&diverge_json.stdout);
    let diverge_json_stderr = String::from_utf8_lossy(&diverge_json.stderr);
    assert!(
        diverge_json_stdout.contains("block_release"),
        "divergent lockstep --json must still emit the oracle report on stdout, got:\n{diverge_json_stdout}"
    );
    assert!(
        !diverge_json_stderr.contains("Running lockstep verification"),
        "verify lockstep --json must suppress the human stderr banner on failure: {diverge_json_stderr}"
    );
    assert!(
        !diverge_json_stderr.contains("Lockstep harness failed"),
        "verify lockstep --json must keep the human failure line off stderr: {diverge_json_stderr}"
    );
}

#[test]
fn run_emits_correlated_structured_logs() {
    let trace_id = "run-console-exit-e2e-trace-7f3a";
    let (_dir, outcome) = run_app(
        COMPUTE_APP,
        &["--structured-logs-jsonl", "--trace-id", trace_id],
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "in-budget compute must exit 0; stderr=\n{}",
        outcome.stderr
    );

    // Structured logs are emitted on stderr as one JSON object per line.
    let run_lines: Vec<Value> = outcome
        .stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| {
            v.get("event_code")
                .and_then(Value::as_str)
                .is_some_and(|c| c.starts_with("RUN-"))
        })
        .collect();
    assert!(
        !run_lines.is_empty(),
        "expected RUN-* structured log events on stderr:\n{}",
        outcome.stderr
    );

    let codes: Vec<&str> = run_lines
        .iter()
        .filter_map(|v| v["event_code"].as_str())
        .collect();
    assert!(
        codes.contains(&"RUN-001"),
        "expected RUN-001 (preflight) in {codes:?}"
    );
    assert!(
        codes.contains(&"RUN-003"),
        "expected RUN-003 (dispatch) in {codes:?}"
    );

    // Every RUN-* event must carry the SAME supplied trace id (correlation).
    for line in &run_lines {
        assert_eq!(
            line["trace_id"].as_str(),
            Some(trace_id),
            "every RUN-* event must carry the supplied trace id: {line}"
        );
    }
}

/// `run <dir>` in an initialised workspace holding `files`, console-only.
fn run_directory_target(files: &[(&str, &str)], target: &str) -> RunOutcome {
    run_project_target_with_setup(files, target, |_, _| {})
}

fn run_project_target_with_setup(
    files: &[(&str, &str)],
    target: &str,
    setup: impl FnOnce(&std::path::Path, &mut Command),
) -> RunOutcome {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let init = Command::new(franken_node_bin())
        .args(["init", "--profile", "balanced", "--out-dir", "."])
        .current_dir(dir.path())
        .output()
        .expect("spawn franken-node init");
    assert!(init.status.success(), "init must bootstrap the workspace");
    for (relative, contents) in files {
        let path = dir.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture dir");
        std::fs::write(&path, contents).expect("write fixture");
    }
    let mut command = Command::new(franken_node_bin());
    command
        .args([
            "run",
            target,
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--console-only",
        ])
        .current_dir(dir.path());
    setup(dir.path(), &mut command);
    let output = command.output().expect("spawn franken-node run");
    RunOutcome {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// bd-reality-20260923-26n9r.4: `run <dir>` executes package.json `main`,
/// exactly as `node <dir>` does (it previously failed reading the directory
/// as source, which also made `verify lockstep <project>` diverge).
#[test]
fn run_directory_target_executes_package_main() {
    let outcome = run_directory_target(
        &[
            (
                "pkg/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"lib/start"}"#,
            ),
            ("pkg/lib/start.js", "console.log(\"from-main\");\n"),
            ("pkg/index.js", "console.log(\"from-index\");\n"),
        ],
        "pkg",
    );
    assert_eq!(outcome.exit_code, Some(0), "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "from-main\n");
}

/// A nested package main retains the explicitly selected package as both its
/// module boundary and its filesystem root. Resolving `main` must not move
/// `readFileSync('data.txt')` into the source directory.
#[test]
fn run_project_authority_directory_main_reads_sibling_data() {
    let outcome = run_directory_target(
        &[
            (
                "pkg/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"lib/start.js"}"#,
            ),
            (
                "pkg/lib/start.js",
                "const fs = require('fs');\nconsole.log(fs.readFileSync('data.txt', 'utf8'));\n",
            ),
            ("pkg/data.txt", "project-data"),
            ("pkg/lib/data.txt", "wrong-source-directory"),
        ],
        "pkg",
    );
    assert_eq!(outcome.exit_code, Some(0), "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "project-data\n");
}

#[test]
fn run_project_authority_nested_file_reads_root_data_and_modules() {
    let outcome = run_directory_target(
        &[
            (
                "src/main.js",
                "const fs = require('fs');\n\
                 const value = require('../support/value.js');\n\
                 console.log(value + ':' + fs.readFileSync('data.txt', 'utf8'));\n",
            ),
            ("support/value.js", "module.exports = 'support-module';\n"),
            ("data.txt", "project-data"),
            ("src/data.txt", "wrong-source-directory"),
        ],
        "src/main.js",
    );
    assert_eq!(outcome.exit_code, Some(0), "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "support-module:project-data\n");
}

#[test]
fn run_project_authority_refuses_module_escape() {
    let outcome = run_directory_target(
        &[
            ("pkg/package.json", r#"{"name":"pkg","main":"app.js"}"#),
            ("pkg/app.js", "require('../outside.js');\n"),
            ("outside.js", "console.log('outside-module-executed');\n"),
        ],
        "pkg",
    );
    assert_ne!(outcome.exit_code, Some(0));
    assert!(
        !outcome.stdout.contains("outside-module-executed"),
        "a module outside the selected project must not execute: {}",
        outcome.stdout
    );
    assert!(
        outcome.stderr.contains("outside") || outcome.stderr.contains("escape"),
        "the error must identify the refused module: {}",
        outcome.stderr
    );
}

#[cfg(unix)]
#[test]
fn run_project_authority_refuses_directory_main_symlink_escape() {
    let outcome = run_project_target_with_setup(
        &[
            ("pkg/package.json", r#"{"name":"pkg","main":"main.js"}"#),
            ("outside.js", "console.log('outside-main-executed');\n"),
        ],
        "pkg",
        |root, _| {
            std::os::unix::fs::symlink("../outside.js", root.join("pkg/main.js"))
                .expect("link package main outside its root");
        },
    );
    assert_ne!(outcome.exit_code, Some(0));
    assert!(!outcome.stdout.contains("outside-main-executed"));
    assert!(
        outcome.stderr.contains("escapes selected project root"),
        "entrypoint containment must refuse before execution: {}",
        outcome.stderr
    );
}

#[cfg(unix)]
#[test]
fn run_project_authority_refuses_module_symlink_escape() {
    let outcome = run_project_target_with_setup(
        &[
            ("pkg/package.json", r#"{"name":"pkg","main":"main.js"}"#),
            ("pkg/main.js", "require('./linked.js');\n"),
            ("outside.js", "console.log('outside-module-executed');\n"),
        ],
        "pkg",
        |root, _| {
            std::os::unix::fs::symlink("../outside.js", root.join("pkg/linked.js"))
                .expect("link imported module outside its root");
        },
    );
    assert_ne!(outcome.exit_code, Some(0));
    assert!(!outcome.stdout.contains("outside-module-executed"));
    assert!(
        outcome.stderr.contains("outside") || outcome.stderr.contains("escape"),
        "the refused import must identify its boundary: {}",
        outcome.stderr
    );
}

#[cfg(unix)]
#[test]
fn run_project_authority_explicit_directory_symlink_keeps_canonical_root() {
    let outcome = run_project_target_with_setup(
        &[
            ("pkg/package.json", r#"{"name":"pkg","main":"lib/main.js"}"#),
            (
                "pkg/lib/main.js",
                "console.log(require('fs').readFileSync('data.txt', 'utf8'));\n",
            ),
            ("pkg/data.txt", "canonical-project-data"),
        ],
        "selected-project",
        |root, _| {
            std::os::unix::fs::symlink("pkg", root.join("selected-project"))
                .expect("link explicitly selected project");
        },
    );
    assert_eq!(outcome.exit_code, Some(0), "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "canonical-project-data\n");
}

#[test]
fn run_project_authority_refuses_evidence_home_anywhere_inside_project() {
    let outcome = run_project_target_with_setup(
        &[("src/main.js", "console.log('guest-must-not-start');\n")],
        "src/main.js",
        |root, command| {
            // This is outside the entrypoint's parent but inside the selected
            // project. Checking only `src/` would expose the signing authority.
            command.env("XDG_STATE_HOME", root.join("private-state"));
        },
    );
    assert_ne!(outcome.exit_code, Some(0));
    assert!(!outcome.stdout.contains("guest-must-not-start"));
    assert!(
        outcome
            .stderr
            .contains("must remain outside guest filesystem root"),
        "the evidence authority must reject the shared guest root before launch: {}",
        outcome.stderr
    );
}

#[test]
fn run_project_authority_refuses_overlap_with_protected_evidence_subtree() {
    for target in [
        "state/franken-node",
        "state/franken-node/runtime-evidence/keys",
    ] {
        let package_manifest = format!("{target}/package.json");
        let app_path = format!("{target}/app.js");
        let outcome = run_project_target_with_setup(
            &[
                (package_manifest.as_str(), r#"{"main":"app.js"}"#),
                (app_path.as_str(), "console.log('guest-must-not-start');\n"),
            ],
            target,
            |root, command| {
                // The state home is an ancestor, so a state-home-only check
                // misses both the guest containing keys and the guest rooted
                // inside the protected keys directory.
                command.env("XDG_STATE_HOME", root.join("state"));
            },
        );
        assert_ne!(outcome.exit_code, Some(0), "{target}");
        assert!(!outcome.stdout.contains("guest-must-not-start"));
        assert!(
            outcome
                .stderr
                .contains("protected subtree and guest project must not overlap"),
            "{target}: protected authority overlap must refuse before keys or guest execution: {}",
            outcome.stderr
        );
    }
}

#[test]
fn run_project_authority_allows_disjoint_project_beneath_state_home() {
    let outcome = run_project_target_with_setup(
        &[
            ("state/projects/app/package.json", r#"{"main":"app.js"}"#),
            (
                "state/projects/app/app.js",
                "console.log('disjoint-project');\n",
            ),
        ],
        "state/projects/app",
        |root, command| {
            command.env("XDG_STATE_HOME", root.join("state"));
        },
    );
    assert_eq!(outcome.exit_code, Some(0), "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "disjoint-project\n");
}

/// bd-reality-20260923-26n9r.4 / engine bd-rff5g: a CommonJS entry requires a
/// sibling module by relative path, uses `__dirname`, and still reaches the
/// `path` builtin, as `node app.js` does.
#[test]
fn run_commonjs_entry_requires_a_sibling_module() {
    let outcome = run_directory_target(
        &[
            (
                "pkg/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"app.js"}"#,
            ),
            (
                "pkg/app.js",
                "const math = require('./lib/math');\n\
                 const path = require('path');\n\
                 console.log(String(math.add(2, 3)));\n\
                 console.log(path.join('a', 'b'));\n\
                 console.log(typeof __dirname);\n",
            ),
            (
                "pkg/lib/math.js",
                "module.exports = { add: (a, b) => a + b };\n",
            ),
        ],
        "pkg",
    );
    assert_eq!(outcome.exit_code, Some(0), "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "5\na/b\nstring\n");
}

/// bd-reality-20260923-26n9r.4 deliverable 2: a `.js` entry in a
/// `"type": "module"` package is ESM, as in Node; without the type field the
/// same source is a script, where `export` is a syntax error.
#[test]
fn run_type_module_package_executes_js_entry_as_esm() {
    const ESM_SOURCE: &str =
        "const greeting = \"from-esm\";\nexport default greeting;\nconsole.log(greeting);\n";
    let esm = run_directory_target(
        &[
            (
                "pkg/package.json",
                r#"{"name":"pkg","version":"1.0.0","type":"module","main":"main.js"}"#,
            ),
            ("pkg/main.js", ESM_SOURCE),
        ],
        "pkg",
    );
    assert_eq!(esm.exit_code, Some(0), "stderr:\n{}", esm.stderr);
    assert_eq!(esm.stdout, "from-esm\n");

    let script = run_directory_target(
        &[
            (
                "pkg/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"main.js"}"#,
            ),
            ("pkg/main.js", ESM_SOURCE),
        ],
        "pkg",
    );
    assert_ne!(
        script.exit_code,
        Some(0),
        "without \"type\": \"module\" the entry must parse as a script; stdout:\n{}",
        script.stdout
    );
}

#[test]
fn run_directory_target_falls_back_to_index_js() {
    let outcome = run_directory_target(
        &[
            ("package.json", r#"{"name":"app","version":"1.0.0"}"#),
            ("index.js", "console.log(\"from-index\");\n"),
        ],
        ".",
    );
    assert_eq!(outcome.exit_code, Some(0), "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout, "from-index\n");
}

#[test]
fn run_directory_target_refuses_main_outside_the_package() {
    let outcome = run_directory_target(
        &[
            (
                "pkg/package.json",
                r#"{"name":"pkg","version":"1.0.0","main":"../outside.js"}"#,
            ),
            ("outside.js", "console.log(\"escaped\");\n"),
        ],
        "pkg",
    );
    assert_ne!(outcome.exit_code, Some(0));
    assert!(
        !outcome.stdout.contains("escaped"),
        "a main outside the package must never execute: {}",
        outcome.stdout
    );
    assert!(
        outcome.stderr.contains("must be a relative path inside"),
        "the refusal must name the rule, got:\n{}",
        outcome.stderr
    );
}

/// bd-reality-20260923-26n9r.5 deliverable 1: the instruction budget is an
/// operator control. A loop that completes under the profile default stops
/// with the engine's budget error once `runtime.max_instructions` (here via
/// FRANKEN_NODE_RUNTIME_MAX_INSTRUCTIONS) is set below what it needs.
#[test]
fn runtime_max_instructions_bounds_a_run() {
    const LOOP_APP: &str =
        "let s = 0;\nfor (let i = 0; i < 100000; i++) { s += i; }\nconsole.log(String(s));\n";
    let (dir, default_run) = run_app(LOOP_APP, &[]);
    assert_eq!(
        default_run.exit_code,
        Some(0),
        "stderr=\n{}",
        default_run.stderr
    );
    assert!(
        default_run.stdout.starts_with("4999950000\n"),
        "{}",
        default_run.stdout
    );

    let limited = Command::new(franken_node_bin())
        .args([
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
        ])
        .env("FRANKEN_NODE_RUNTIME_MAX_INSTRUCTIONS", "10000")
        .current_dir(dir.path())
        .output()
        .expect("spawn limited run");
    let stderr = String::from_utf8_lossy(&limited.stderr);
    assert_ne!(limited.status.code(), Some(0), "stderr=\n{stderr}");
    assert!(
        stderr.contains("instruction budget exhausted"),
        "the refusal must name the budget:\n{stderr}"
    );
}

/// A sparse data literal retains enough simultaneously live values to need
/// more than the balanced lane's 256 registers. An explicit resource override
/// must admit that program while retaining balanced trust and capability rules.
#[test]
fn runtime_max_registers_admits_a_large_frame_without_changing_policy() {
    let dir = profile_selection_workspace(Some("balanced"));
    let elements = (0..320)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(
        dir.path().join("app.js"),
        format!(
            "const items = [,{elements}];\nconsole.log(items.length);\nconsole.log(items[320]);\n"
        ),
    )
    .expect("write wide-register program");

    let run = |max_registers: Option<&str>| {
        let mut command = Command::new(franken_node_bin());
        command
            .args(["run", "app.js", "--policy", "balanced", "--json"])
            .env_remove("FRANKEN_NODE_RUNTIME_MAX_REGISTERS")
            .current_dir(dir.path());
        if let Some(limit) = max_registers {
            command.env("FRANKEN_NODE_RUNTIME_MAX_REGISTERS", limit);
        }
        command.output().expect("run wide-register program")
    };

    let limited = run(None);
    assert!(
        !limited.status.success(),
        "the default frame must be bounded"
    );
    let refusal = format!(
        "{}\n{}",
        String::from_utf8_lossy(&limited.stdout),
        String::from_utf8_lossy(&limited.stderr)
    );
    assert!(
        refusal.contains("register") && refusal.contains("max 256"),
        "expected the register ceiling, not another execution failure: {refusal}"
    );

    let admitted = run(Some("1024"));
    assert!(
        admitted.status.success(),
        "explicit register budget must admit the same program: {}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let report = last_json_document(&String::from_utf8_lossy(&admitted.stdout));
    assert_eq!(report["preflight"]["policy_mode"], "balanced");
    assert_eq!(report["receipt"]["profile"], "balanced");
    assert_eq!(report["receipt"]["policy_mode"], "balanced");
    assert_eq!(
        report["dispatch"]["captured_output"]["stdout"],
        "321\n319\n"
    );
    assert_eq!(
        report["receipt"]["execution_limits"],
        report["dispatch"]["engine_decision"]["execution_limits"]
    );
    for lane in ["deterministic", "throughput"] {
        assert_eq!(
            report["receipt"]["execution_limits"][lane]["max_registers"],
            1_024
        );
    }
}

/// Strict's finite call-depth ceiling is independently configurable. Growing
/// it must let ordinary recursion finish without selecting a weaker profile.
#[test]
fn runtime_max_call_depth_admits_recursion_without_changing_strict_policy() {
    let dir = profile_selection_workspace(Some("strict"));
    std::fs::write(
        dir.path().join("app.js"),
        "function count(n) {\n\
         if (n <= 0) { return 0; }\n\
         return 1 + count(n - 1);\n\
         }\n\
         console.log(count(48));\n",
    )
    .expect("write recursive program");

    let run = |max_call_depth: Option<&str>| {
        let mut command = Command::new(franken_node_bin());
        command
            .args(["run", "app.js", "--policy", "strict", "--json"])
            .env_remove("FRANKEN_NODE_RUNTIME_MAX_CALL_DEPTH")
            .current_dir(dir.path());
        if let Some(limit) = max_call_depth {
            command.env("FRANKEN_NODE_RUNTIME_MAX_CALL_DEPTH", limit);
        }
        command.output().expect("run recursive program")
    };

    let limited = run(None);
    assert!(
        !limited.status.success(),
        "strict's default depth is bounded"
    );
    let refusal = format!(
        "{}\n{}",
        String::from_utf8_lossy(&limited.stdout),
        String::from_utf8_lossy(&limited.stderr)
    );
    assert!(
        refusal.contains("call stack overflow") && refusal.contains("max 32"),
        "expected the call-depth ceiling, not another execution failure: {refusal}"
    );

    let admitted = run(Some("64"));
    assert!(
        admitted.status.success(),
        "explicit call-depth budget must admit the same program: {}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let report = last_json_document(&String::from_utf8_lossy(&admitted.stdout));
    assert_eq!(report["preflight"]["policy_mode"], "strict");
    assert_eq!(report["receipt"]["profile"], "strict");
    assert_eq!(report["receipt"]["policy_mode"], "strict");
    assert_eq!(report["dispatch"]["captured_output"]["stdout"], "48\n");
    assert_eq!(
        report["receipt"]["execution_limits"],
        report["dispatch"]["engine_decision"]["execution_limits"]
    );
    for lane in ["deterministic", "throughput"] {
        let limits = &report["receipt"]["execution_limits"][lane];
        assert_eq!(limits["max_call_depth"], 64);
        assert_eq!(
            limits["max_registers"],
            if lane == "deterministic" { 128 } else { 256 }
        );
    }
}

/// Operator memory ceilings apply to the real native worker, including
/// allocations made by ordinary array/object programs.
#[test]
fn runtime_heap_and_memory_budgets_fail_closed() {
    let (dir, default_run) = run_app(
        "const rows = []; for (let i = 0; i < 100; i++) rows.push({ id: i }); console.log('finished');",
        &["--console-only"],
    );
    assert_eq!(default_run.exit_code, Some(0), "{}", default_run.stderr);
    assert_eq!(default_run.stdout, "finished\n");

    for (key, value, expected_limit) in [
        (
            "FRANKEN_NODE_RUNTIME_MAX_HEAP_OBJECTS",
            "2",
            "limits 2 heap objects",
        ),
        (
            "FRANKEN_NODE_RUNTIME_MAX_TOTAL_MEMORY_BYTES",
            "1",
            "/ 1 bytes",
        ),
    ] {
        let output = Command::new(franken_node_bin())
            .args(["run", "app.js", "--policy", "balanced", "--console-only"])
            .env(key, value)
            .current_dir(dir.path())
            .output()
            .expect("run with explicit resource ceiling");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{key}: {stderr}");
        assert!(stderr.contains("memory budget exceeded"), "{key}: {stderr}");
        assert!(stderr.contains(expected_limit), "{key}: {stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("finished"));
    }
}

/// Transcript capacity is an explicit fail-closed bound, never a ring buffer
/// that silently replaces earlier output or a JS-catchable resource failure.
#[test]
fn runtime_console_entry_budget_preserves_the_head_and_refuses_overflow() {
    let (dir, default_run) = run_app(
        "console.log('first'); console.error('second'); try { console.log('overflow'); } catch (e) { console.log('caught'); } console.log('after');",
        &["--console-only"],
    );
    assert_eq!(default_run.exit_code, Some(0), "{}", default_run.stderr);
    assert_eq!(default_run.stdout, "first\noverflow\nafter\n");
    assert_eq!(default_run.stderr, "second\n");

    let overflow = Command::new(franken_node_bin())
        .args(["run", "app.js", "--policy", "balanced", "--console-only"])
        .env("FRANKEN_NODE_RUNTIME_MAX_CONSOLE_ENTRIES", "2")
        .current_dir(dir.path())
        .output()
        .expect("run with a two-entry console budget");
    let stderr = String::from_utf8_lossy(&overflow.stderr);
    assert!(!overflow.status.success(), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&overflow.stdout), "first\n");
    assert!(stderr.starts_with("second\n"), "{stderr}");
    assert!(
        stderr.contains("console output budget exceeded"),
        "{stderr}"
    );
    assert!(
        stderr.contains("3 entries") && stderr.contains("limits 2 entries"),
        "{stderr}"
    );

    // At the exact entry count execution succeeds and retains every entry.
    let exact = Command::new(franken_node_bin())
        .args(["run", "app.js", "--policy", "balanced", "--console-only"])
        .env("FRANKEN_NODE_RUNTIME_MAX_CONSOLE_ENTRIES", "4")
        .current_dir(dir.path())
        .output()
        .expect("run at the exact console-entry budget");
    assert!(
        exact.status.success(),
        "{}",
        String::from_utf8_lossy(&exact.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&exact.stdout), default_run.stdout);
    assert_eq!(String::from_utf8_lossy(&exact.stderr), default_run.stderr);
}

#[test]
fn runtime_execution_limits_report_records_actual_lane_defaults_and_overrides() {
    let (dir, default_run) = run_app("console.log('limits');", &["--json"]);
    assert_eq!(default_run.exit_code, Some(0), "{}", default_run.stderr);
    let report = last_json_document(&default_run.stdout);
    let limits = &report["dispatch"]["engine_decision"]["execution_limits"];
    assert_eq!(
        report["receipt"]["execution_limits"],
        report["dispatch"]["engine_decision"]["execution_limits"],
        "the signed receipt must bind the native execution limits"
    );
    assert_eq!(
        limits["deterministic"]["max_total_memory_bytes"],
        67_108_864
    );
    assert_eq!(limits["throughput"]["max_total_memory_bytes"], 536_870_912);
    assert_eq!(limits["deterministic"]["max_heap_objects"], 100_000);
    assert_eq!(limits["throughput"]["max_heap_objects"], 1_000_000);
    assert_eq!(limits["selected_lane"], "deterministic");

    let output = Command::new(franken_node_bin())
        .args(["run", "app.js", "--policy", "balanced", "--json"])
        .env("FRANKEN_NODE_RUNTIME_MAX_INSTRUCTIONS", "123456")
        .env("FRANKEN_NODE_RUNTIME_MAX_HEAP_OBJECTS", "200001")
        .env("FRANKEN_NODE_RUNTIME_MAX_TOTAL_MEMORY_BYTES", "100663296")
        .env("FRANKEN_NODE_RUNTIME_MAX_CONSOLE_ENTRIES", "17")
        .current_dir(dir.path())
        .output()
        .expect("run with explicit execution limits");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = last_json_document(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(
        report["dispatch"]["engine_decision"]["execution_limits"]["selected_lane"],
        "deterministic"
    );
    assert_eq!(
        report["receipt"]["execution_limits"],
        report["dispatch"]["engine_decision"]["execution_limits"],
        "the signed receipt must bind every explicit native execution limit"
    );
    for lane in ["deterministic", "throughput"] {
        let limits = &report["dispatch"]["engine_decision"]["execution_limits"][lane];
        assert_eq!(limits["max_instructions"], 123_456, "{lane}");
        assert_eq!(limits["max_heap_objects"], 200_001, "{lane}");
        assert_eq!(limits["max_total_memory_bytes"], 100_663_296, "{lane}");
        assert_eq!(limits["max_console_entries"], 17, "{lane}");
        assert_eq!(limits["max_console_bytes"], 8_388_608, "{lane}");
    }
}

/// The last JSON document on a `run --json` stdout (the run report; a
/// preflight report may precede it).
fn last_json_document(stdout: &str) -> Value {
    serde_json::Deserializer::from_str(stdout)
        .into_iter::<Value>()
        .filter_map(Result::ok)
        .last()
        .unwrap_or_else(|| panic!("no JSON document on stdout:\n{stdout}"))
}

/// bd-pgzo7 (engine 92c65f951): this benign JSON-heavy program used to exit
/// 92 (Sandbox) under balanced, and every strict run did, because a
/// saturated resource signal and the Conservative matrix's prior tax read as
/// containment. It now completes in both profiles, and the engine's own
/// account of the decision (bd-reality-20260923-26n9r.5) travels in the
/// report: the selector's choice, the final Allow, and the posterior behind
/// it. No guest program reaches a 91-95 verdict after that fix; the
/// containment note's wording is exercised only when one does.
#[test]
fn benign_json_heavy_run_completes_and_the_engine_explains_the_allow() {
    const JSON_HEAVY_APP: &str = "const rows = [];\n\
        for (let i = 0; i < 2000; i++) rows.push({ id: i, name: 'row-' + i, tags: ['a', 'b'], ok: i % 2 === 0 });\n\
        let t = '';\n\
        for (let r = 0; r < 20; r++) t = JSON.stringify(JSON.parse(JSON.stringify(rows)));\n\
        console.log(t.length);\n";

    let (dir, balanced) = run_app(JSON_HEAVY_APP, &["--json"]);
    let strict = Command::new(franken_node_bin())
        .args([
            "run",
            "app.js",
            "--policy",
            "strict",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn strict run");
    let strict = RunOutcome {
        exit_code: strict.status.code(),
        stdout: String::from_utf8_lossy(&strict.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&strict.stderr).into_owned(),
    };

    for (policy, outcome) in [("balanced", &balanced), ("strict", &strict)] {
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "{policy}: benign run must complete; stdout=\n{}\nstderr=\n{}",
            outcome.stdout,
            outcome.stderr
        );
        let report = last_json_document(&outcome.stdout);
        assert!(
            report.get("containment_verdict").is_none(),
            "{policy}: {report}"
        );
        assert_eq!(report["dispatch"]["captured_output"]["stdout"], "112781\n");

        let decision = &report["dispatch"]["engine_decision"];
        assert_eq!(
            decision["containment_action"], "allow",
            "{policy}: {decision}"
        );
        assert_eq!(decision["risk_state"], "benign", "{policy}: {decision}");
        assert!(
            decision["selector_action"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "{policy}: selector action missing: {decision}"
        );
        assert!(
            decision["decision_rationale"]
                .as_str()
                .is_some_and(|value| value.contains("benign_completion_downgrade=")),
            "{policy}: signed rationale missing: {decision}"
        );
        let posterior_total: i64 = [
            "posterior_benign_millionths",
            "posterior_anomalous_millionths",
            "posterior_malicious_millionths",
            "posterior_unknown_millionths",
        ]
        .iter()
        .map(|field| decision[*field].as_i64().expect("posterior component"))
        .sum();
        assert!(
            (999_000..=1_001_000).contains(&posterior_total),
            "{policy}: posterior must be a distribution: {decision}"
        );
        assert!(decision["instructions_executed"].as_u64().unwrap_or(0) > 1_000_000);
    }
}

/// bd-reality-20260923-26n9r.15 deliverable 6: every `run` in an initialized
/// workspace appends a signed, hash-chained entry to the durable evidence
/// ledger, signed with the receipt key `init` provisioned.
#[test]
fn runs_append_signed_chained_entries_to_the_durable_evidence_ledger() {
    use frankenengine_node::observability::evidence_ledger::{
        EvidenceEntry, evidence_entry_hash_hex, verify_evidence_entry,
    };
    use frankenengine_node::observability::evidence_ledger_durable::DurableEvidenceLedger;

    let (dir, first) = run_app(COMPUTE_APP, &["--json"]);
    assert_eq!(first.exit_code, Some(0), "stderr=\n{}", first.stderr);
    let first_report: Value = serde_json::from_str(&first.stdout).expect("first run --json");
    let second = Command::new(franken_node_bin())
        .args([
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn second run");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_report: Value = serde_json::from_slice(&second.stdout).expect("second run --json");

    let store = DurableEvidenceLedger::open_default(dir.path()).expect("open evidence ledger");
    let entries = store
        .entries_json()
        .expect("read evidence ledger")
        .iter()
        .map(|json| serde_json::from_str::<EvidenceEntry>(json).expect("stored evidence entry"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2, "one entry per run");

    let seed_hex =
        std::fs::read_to_string(dir.path().join(".franken-node/keys/receipt-signing.key"))
            .expect("init-provisioned receipt key");
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .expect("hex seed")
        .try_into()
        .expect("32-byte seed");
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    for (entry, report) in entries.iter().zip([&first_report, &second_report]) {
        assert!(
            entry.signature.starts_with("chain-v1:"),
            "durable run signatures must bind their actual predecessor"
        );
        verify_evidence_entry(entry, &verifying_key).expect("entry signature verifies");
        assert_eq!(
            entry.decision_id,
            report["receipt"]["receipt_id"]
                .as_str()
                .expect("receipt id")
        );
        assert_eq!(entry.payload["exit_code"], 0);
        assert_eq!(
            entry.payload["receipt_hash"],
            report["receipt"]["receipt_hash"]
        );
    }
    assert_eq!(
        entries[0].prev_entry_hash, "",
        "first entry starts the chain"
    );
    assert_eq!(
        entries[1].prev_entry_hash,
        evidence_entry_hash_hex(&entries[0]),
        "second entry links to the first"
    );

    // A tampered payload no longer verifies.
    let mut tampered = entries[1].clone();
    tampered.payload["exit_code"] = serde_json::json!(1);
    assert!(verify_evidence_entry(&tampered, &verifying_key).is_err());
    let mut relinked = entries[1].clone();
    relinked.prev_entry_hash.clear();
    assert!(
        verify_evidence_entry(&relinked, &verifying_key).is_err(),
        "a later real run cannot be relinked into a new genesis"
    );

    // init also wrote the matching public key.
    let public_key =
        std::fs::read_to_string(dir.path().join(".franken-node/keys/receipt-signing.pub"))
            .expect("init-provisioned receipt public key");
    assert_eq!(public_key.trim(), hex::encode(verifying_key.to_bytes()));

    // The CLI verifies the same durable ledger: the chain alone is
    // "unproven" (exit 1); with the public key it is "valid" (exit 0).
    let verify = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            "transparency-log",
            ".franken-node/state/evidence-ledger.db",
            "--json",
        ];
        args.extend_from_slice(extra);
        let output = Command::new(franken_node_bin())
            .args(&args)
            .current_dir(dir.path())
            .output()
            .expect("spawn verify transparency-log");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
            panic!(
                "verify transparency-log --json: {err}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), report)
    };
    let (code, report) = verify(&[]);
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "unproven");
    assert_eq!(report["total_entries"], 2);
    assert_eq!(report["hash_chain_errors"], serde_json::json!([]));
    let (code, report) = verify(&["--public-key", ".franken-node/keys/receipt-signing.pub"]);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["status"], "valid");
    assert_eq!(report["signatures_verified"], true);
    assert_eq!(report["chain_links_authenticated"], true);
    assert_eq!(report["unbound_signature_entries"], serde_json::json!([]));
    assert_eq!(report["head_hash"], evidence_entry_hash_hex(&entries[1]));
}

#[test]
fn transparency_log_authenticates_predecessors_and_checks_a_retained_head() {
    use frankenengine_node::observability::evidence_ledger::{
        EvidenceEntry, evidence_entry_hash_hex, sign_chained_evidence_entry, sign_evidence_entry,
        test_entry, verify_evidence_entry,
    };

    let dir = tempfile::TempDir::new().expect("transparency fixture workspace");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[38_u8; 32]);
    let verifying_key = signing_key.verifying_key();
    std::fs::write(
        dir.path().join("receipt.pub"),
        hex::encode(verifying_key.to_bytes()),
    )
    .expect("write independently supplied public key");
    let make_chain = |chained: bool| {
        let mut entries = Vec::new();
        let mut previous_hash = String::new();
        for (decision_id, epoch) in [("A", 1), ("B", 2), ("C", 3)] {
            let mut entry = test_entry(decision_id, epoch);
            entry.prev_entry_hash = previous_hash;
            if chained {
                sign_chained_evidence_entry(&mut entry, &signing_key);
            } else {
                sign_evidence_entry(&mut entry, &signing_key);
            }
            verify_evidence_entry(&entry, &verifying_key).expect("actual fixture signature");
            previous_hash = evidence_entry_hash_hex(&entry);
            entries.push(entry);
        }
        entries
    };
    let write_log = |name: &str, entries: &[EvidenceEntry]| {
        let jsonl = entries
            .iter()
            .map(|entry| serde_json::to_string(entry).expect("serialize signed entry"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(dir.path().join(name), &jsonl).expect("write independent candidate log");
        jsonl
    };
    let verify = |name: &str, expected_head: Option<&str>| {
        let mut args = vec![
            "verify",
            "transparency-log",
            name,
            "--public-key",
            "receipt.pub",
            "--json",
        ];
        if let Some(expected_head) = expected_head {
            args.extend(["--expected-head-hash", expected_head]);
        }
        let (outcome, report) = run_workspace_json(dir.path(), &args);
        assert_eq!(
            report["schema_version"],
            "franken-node/verify-transparency-log-cli/v1"
        );
        (outcome.exit_code, report)
    };

    let entries = make_chain(true);
    let original = write_log("original-abc.jsonl", &entries);
    let original_head = evidence_entry_hash_hex(&entries[2]);
    let (code, report) = verify("original-abc.jsonl", None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["status"], "valid");
    assert_eq!(report["total_entries"], 3);
    assert_eq!(report["signatures_verified"], true);
    assert_eq!(report["chain_links_authenticated"], true);
    assert_eq!(report["unbound_signature_entries"], serde_json::json!([]));
    assert_eq!(report["head_hash"], original_head);
    assert_eq!(report["total_errors"], 0);
    let (code, report) = verify("original-abc.jsonl", Some(&original_head));
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["checkpoint_verified"], true);
    assert_eq!(report["checkpoint_errors"], serde_json::json!([]));

    // An attacker can recompute the visible link after omitting B. The
    // retained C signature must still expose the changed predecessor.
    let mut relinked = vec![entries[0].clone(), entries[2].clone()];
    relinked[1].prev_entry_hash = evidence_entry_hash_hex(&relinked[0]);
    write_log("forged-ac.jsonl", &relinked);
    let (code, report) = verify("forged-ac.jsonl", None);
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "invalid");
    assert_eq!(report["total_entries"], 2);
    assert_eq!(report["hash_chain_errors"], serde_json::json!([]));
    assert_eq!(report["signature_errors"].as_array().unwrap().len(), 1);
    assert_eq!(report["total_errors"], 1);
    assert_eq!(report["chain_links_authenticated"], false);
    assert_eq!(report["unbound_signature_entries"], serde_json::json!([]));

    // Legacy signatures remain valid for entry contents, but cannot prove
    // which predecessor was present when those contents were signed.
    let legacy = make_chain(false);
    write_log("legacy-abc.jsonl", &legacy);
    let (code, report) = verify("legacy-abc.jsonl", None);
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "unproven");
    assert_eq!(report["total_entries"], 3);
    assert_eq!(report["signatures_verified"], true);
    assert_eq!(report["hash_chain_errors"], serde_json::json!([]));
    assert_eq!(report["signature_errors"], serde_json::json!([]));
    assert_eq!(report["total_errors"], 0);
    assert_eq!(report["chain_links_authenticated"], false);
    assert_eq!(
        report["unbound_signature_entries"],
        serde_json::json!([0, 1, 2])
    );

    // A retained suffix has genuine signatures and an internally consistent
    // B-to-C link, but B's signed predecessor is not the required genesis.
    write_log("missing-genesis-bc.jsonl", &entries[1..]);
    let (code, report) = verify("missing-genesis-bc.jsonl", None);
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "invalid");
    assert_eq!(report["signature_errors"], serde_json::json!([]));
    assert_eq!(report["hash_chain_errors"].as_array().unwrap().len(), 1);
    assert_eq!(report["chain_links_authenticated"], false);

    // A genuine older prefix is a valid retained chain. Only a separately
    // retained head can distinguish it from the later complete ABC history.
    write_log("older-prefix-ab.jsonl", &entries[..2]);
    let older_head = evidence_entry_hash_hex(&entries[1]);
    let (code, report) = verify("older-prefix-ab.jsonl", None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["status"], "valid");
    assert_eq!(report["chain_links_authenticated"], true);
    assert_eq!(report["head_hash"], older_head);
    let (code, report) = verify("older-prefix-ab.jsonl", Some(&original_head));
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "invalid");
    assert_eq!(report["hash_chain_errors"], serde_json::json!([]));
    assert_eq!(report["signature_errors"], serde_json::json!([]));
    assert_eq!(report["head_hash"], older_head);
    assert_eq!(report["checkpoint_verified"], false);
    assert_eq!(report["checkpoint_errors"].as_array().unwrap().len(), 1);
    assert_eq!(report["total_errors"], 1);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("original-abc.jsonl"))
            .expect("read preserved original log"),
        original,
        "all tampered candidates are separate files; the original remains intact"
    );
}

/// bd-reality-20260923-26n9r.15 deliverable 6: operator trust decisions and
/// preflight refusals land in the same signed, hash-chained ledger as runs.
#[test]
fn revoke_and_preflight_denial_append_to_the_evidence_ledger() {
    use frankenengine_node::observability::evidence_ledger::{
        DecisionKind, EvidenceEntry, evidence_entry_hash_hex,
    };
    use frankenengine_node::observability::evidence_ledger_durable::DurableEvidenceLedger;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let cli = |args: &[&str]| {
        Command::new(franken_node_bin())
            .args(args)
            .current_dir(dir.path())
            .output()
            .expect("spawn franken-node")
    };
    assert!(
        cli(&["init", "--profile", "balanced", "--out-dir", "."])
            .status
            .success()
    );
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"ledger-app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .expect("write package.json");
    std::fs::write(dir.path().join("app.js"), COMPUTE_APP).expect("write app");
    let scan = cli(&["trust", "scan", "."]);
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let revoke = cli(&["trust", "revoke", "npm:left-pad"]);
    assert!(
        revoke.status.success(),
        "{}",
        String::from_utf8_lossy(&revoke.stderr)
    );

    let run = cli(&[
        "run",
        "app.js",
        "--policy",
        "balanced",
        "--runtime",
        "franken-engine",
        "--engine-bin",
        franken_node_bin(),
    ]);
    assert!(
        !run.status.success(),
        "a revoked dependency must block the run: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let entries = DurableEvidenceLedger::open_default(dir.path())
        .expect("open evidence ledger")
        .entries_json()
        .expect("read evidence ledger")
        .iter()
        .map(|json| serde_json::from_str::<EvidenceEntry>(json).expect("evidence entry"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2, "revoke + preflight denial: {entries:?}");
    assert_eq!(
        entries[0].schema_version,
        "franken-node/trust-decision-evidence/v1"
    );
    assert_eq!(entries[0].decision_kind, DecisionKind::Deny);
    assert_eq!(entries[0].payload["action"], "revoke");
    assert_eq!(entries[0].payload["extension_id"], "npm:left-pad");
    assert_eq!(
        entries[1].schema_version,
        "franken-node/run-preflight-denial-evidence/v1"
    );
    assert_eq!(entries[1].decision_kind, DecisionKind::Deny);
    assert_eq!(
        entries[1].prev_entry_hash,
        evidence_entry_hash_hex(&entries[0])
    );

    let verify = cli(&[
        "verify",
        "transparency-log",
        ".franken-node/state/evidence-ledger.db",
        "--public-key",
        ".franken-node/keys/receipt-signing.pub",
        "--json",
    ]);
    let report: Value = serde_json::from_slice(&verify.stdout).expect("verify --json");
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(verify.status.code(), Some(0));
}
