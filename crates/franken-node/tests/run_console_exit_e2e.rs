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
//!   exit code derived from the runtime's containment verdict. The two fixtures
//!   below produce *different* real exit codes from the SAME binary — a clean
//!   in-budget program exits 0 (Allow), a fail-closed program exits non-zero —
//!   so a reintroduced synthetic constant makes one of them go RED.
//!
//! Honest scope: the trust-native runtime is capability-metered and host I/O
//! (e.g. `console.log`) is granted engine-side. The default profiles do not
//! grant console, so a *successful* console run that captures stdout/stderr
//! byte-for-byte is gated on the host-effect runtime-of-record work
//! (bd-f5b04.2.6, two-repo, blocked). This suite therefore proves what the
//! franken_node product layer provably does today: it surfaces the engine's
//! real Allow→0 verdict (with the signed receipt recording it) and fails closed
//! with a real non-zero exit — and a denied host effect, rather than being
//! masked as success, is surfaced as the failure it is.

#![cfg(feature = "engine")]

use std::process::Command;

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

const DEBUG_DUMP_MARKERS: &[&str] = &["Native execution completed", "OrchestratorResult"];

/// A pure in-budget program that performs no host I/O, so the trust-native
/// runtime admits it (containment Allow) and `run` completes with exit 0.
const COMPUTE_APP: &str = "const total = 40 + 2;\nconst doubled = total * 2;\n";

/// A program that requests a host effect (`console.log`) the default profiles do
/// not grant, so the engine denies it and `run` fails closed.
const CONSOLE_APP: &str = "console.log(\"hello\");\n";

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

#[test]
fn denied_host_effect_fails_closed_with_real_nonzero_exit() {
    // The OLD synthetic_success_status() would have reported exit 0 here; the
    // bd-5r99w.2 fix surfaces the real failure. A denied host effect must NOT be
    // masked as success.
    let (_dir, outcome) = run_app(CONSOLE_APP, &[]);
    assert_ne!(
        outcome.exit_code,
        Some(0),
        "a denied/failed host effect must surface a real non-zero exit, never synthetic 0;\nstdout=\n{}\nstderr=\n{}",
        outcome.stdout,
        outcome.stderr
    );
    // Whatever is emitted, it must be the real diagnostic, not the debug dump.
    assert_no_debug_dump(&outcome.stdout, "process stdout");
}

#[test]
fn run_exit_code_is_derived_not_constant() {
    // The SAME binary yields DIFFERENT real exit codes for the two fixtures: a
    // clean program (0) and a fail-closed program (non-zero). A reintroduced
    // synthetic constant could not satisfy both, so this is the structural
    // anti-regression for bd-5r99w.2.
    let (_d1, clean) = run_app(COMPUTE_APP, &[]);
    let (_d2, failed) = run_app(CONSOLE_APP, &[]);
    assert_eq!(
        clean.exit_code,
        Some(0),
        "clean run exits 0; stderr=\n{}",
        clean.stderr
    );
    assert_ne!(
        failed.exit_code,
        Some(0),
        "fail-closed run exits non-zero; stderr=\n{}",
        failed.stderr
    );
    assert_ne!(
        clean.exit_code, failed.exit_code,
        "the exit code must be derived from the per-run verdict, not a constant"
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
