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

fn run_app(app_src: &str, extra_args: &[&str]) -> (tempfile::TempDir, RunOutcome) {
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
        .arg("balanced")
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

/// bd-wwjxn: the actual product path must place source loading, parse/lower,
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
            "--console-only",
        ])
        .current_dir(dir.path())
        .env(
            "FRANKEN_ENGINE_TIMEOUT_SECS",
            ENGINE_TIMEOUT.as_secs().to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
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
const DENIED_EGRESS_APP: &str = "const http = require(\"http\");\n\
    http.get(\"http://169.254.169.254/latest/meta-data/\", (res) => {\n\
    console.log(\"unexpected\", res.statusCode);\n\
    });\n";

fn assert_no_debug_dump(stream: &str, label: &str) {
    for marker in DEBUG_DUMP_MARKERS {
        assert!(
            !stream.contains(marker),
            "{label} must not contain the debug-dump marker {marker:?}: {stream:?}"
        );
    }
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

/// bd-zi9hj: the operator-facing `verify lockstep --runtimes bun,franken-node`
/// franken leg historically spawned a `franken-engine` binary that does not
/// exist anywhere (the engine repo ships no such [[bin]]), so the leg had
/// never executed — strace's own noise became the leg output and every check
/// diverged. The leg now runs THIS binary in console-only mode through the
/// in-process native engine. Positive control: identical guest behavior must
/// agree. Negative control: a genuinely divergent program must still block
/// release, proving the comparison is discriminating rather than vacuous.
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
