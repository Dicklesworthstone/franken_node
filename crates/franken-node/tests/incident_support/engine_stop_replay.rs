//! Exercise the product worker, signed receipt, incident bundle and native
//! re-execution together. No Node substitute or caller-built execution capture.

use super::{capture_native_run_bundle_with, execute_native_replay_with, resolve_binary_path};
use super::write_authenticated_native_candidate;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const INSTRUCTION_BUDGET: u64 = 10_000;
const EFFECT_PREFIX: &str = "const fs = require('fs'); console.log(fs.readFileSync('input.txt', 'utf8')); console.warn('captured-warning'); ";
const DENIAL: &str = "process.env.FRANKEN_ENGINE_FAILURE_TEST;";
const EXHAUSTION: &str = "while (true) {}";

struct Project {
    workspace: tempfile::TempDir,
    // Keep the product's independently authenticated evidence authority outside
    // guest filesystem authority, without changing process-wide environment.
    state: tempfile::TempDir,
}

impl Project {
    fn new(source: &str) -> Self {
        let project = Self {
            workspace: tempfile::tempdir().expect("guest project"),
            state: tempfile::tempdir().expect("private product evidence state"),
        };
        let initialized = project.invoke(&[
            "init", "--profile", "balanced", "--out-dir", ".", "--json",
        ]);
        assert!(
            initialized.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        fs::write(project.root().join("app.js"), source).unwrap();
        fs::write(project.root().join("input.txt"), "captured-input").unwrap();
        project
    }

    fn root(&self) -> &Path {
        self.workspace.path()
    }

    fn invoke(&self, arguments: &[&str]) -> Output {
        self.invoke_with_budget(arguments, INSTRUCTION_BUDGET)
    }

    fn invoke_with_budget(&self, arguments: &[&str], budget: u64) -> Output {
        let binary = resolve_binary_path().canonicalize().expect("built product executable");
        let mut command = Command::new(binary);
        // Exclude ambient runtime/profile overrides, loader hooks and authority
        // rendezvous hints. Preserve Cargo's dynamic-library search path only.
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.state.path())
            .env("XDG_STATE_HOME", self.state.path())
            .env("TMPDIR", std::env::temp_dir())
            .env("FRANKEN_NODE_RUNTIME_MAX_INSTRUCTIONS", budget.to_string())
            .env("FRANKEN_NODE_RUNTIME_ALLOW_PROCESS_SHAPE", "false")
            .env("FRANKEN_ENGINE_TIMEOUT_SECS", "30")
            .current_dir(self.root())
            .args(arguments);
        if let Some(path) = std::env::var_os("LD_LIBRARY_PATH") {
            command.env("LD_LIBRARY_PATH", path);
        }
        command.output().expect("invoke the real native product")
    }

    fn failed_run(&self, capture: bool) -> Value {
        let mut arguments = vec!["run", "app.js", "--runtime", "franken-engine", "--json"];
        if capture {
            arguments.push("--capture-replay");
        }
        let output = self.invoke(&arguments);
        assert_eq!(
            output.status.code(), Some(1),
            "the original run must remain failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let run: Value = serde_json::from_slice(&output.stdout).expect("failed-run JSON");
        assert_eq!(run["success"], false, "{run}");
        assert_eq!(run["dispatch"]["exit_code"], 1);
        assert_eq!(run["receipt"]["exit_code"], 1);
        assert_eq!(run["dispatch"]["used_fallback_runtime"], false);
        assert!(run["dispatch"]["engine_decision"].is_null());
        assert!(run["receipt"]["execution_failure"].is_string());
        run
    }

    fn bundle(&self, run: &Value) -> (String, Value) {
        let receipt_id = run["receipt"]["receipt_id"].as_str().expect("failed receipt id");
        let (name, bundle) = capture_native_run_bundle_with(self.root(), receipt_id, |args| {
            self.invoke(args)
        });
        assert_eq!(
            bundle["initial_state_snapshot"]["native_replay"],
            run["dispatch"]["native_replay"],
            "the bundle must retain the exact worker capture"
        );
        assert_eq!(
            bundle["initial_state_snapshot"]["execution_failure"],
            run["receipt"]["execution_failure"]
        );
        (name, bundle)
    }

    fn move_originals(&self) {
        for name in ["app.js", "input.txt"] {
            fs::rename(self.root().join(name), self.root().join(format!("saved-{name}")))
                .expect("preserve original inputs away from their execution paths");
        }
    }

    fn replay(&self, bundle: &str) -> Output {
        execute_native_replay_with(bundle, |args| self.invoke(args))
    }
}

fn captured_payload(run: &Value) -> Value {
    let capture = &run["dispatch"]["native_replay"];
    assert!(capture.is_object(), "finalized stop lost its capture: {run}");
    assert_eq!(run["receipt"]["native_replay_payload_sha256"], capture["payload_sha256"]);
    serde_json::from_str(capture["payload_json"].as_str().unwrap()).unwrap()
}

fn assert_engine_prefix(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "native failure replay failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let replay: Value = serde_json::from_slice(&output.stdout).expect("native replay JSON");
    assert_eq!(replay["replay_kind"], "native_reexecution");
    assert_eq!(replay["replay_result"]["matched"], true, "{replay}");
    let execution = &replay["execution_result"];
    assert_eq!(execution["verification_scope"], "engine_failure_prefix");
    assert_eq!(execution["captured_terminal_state"], "engine_failure");
    assert_eq!(execution["replay_terminal_state"], "engine_failure");
    for field in ["matched", "terminal_state_match", "console_match", "host_effects_match", "module_load_disabled"] {
        assert_eq!(execution[field], true, "{field}: {replay}");
    }
    assert_eq!(execution["captured_trace_id"], execution["replay_trace_id"]);
    for unavailable in [
        "ir3_hash_match", "ir4_witness_match", "execution_value_match",
        "instruction_count_match", "nondeterminism_trace_match", "lane_match",
        "exit_code_match", "exception_value_match", "decisions_match",
    ] {
        assert!(execution.get(unavailable).is_some_and(Value::is_null), "{unavailable}: {replay}");
    }
    replay
}

fn exercise_stop(stop: &str, expected_reason: Value) {
    let project = Project::new(&format!("{EFFECT_PREFIX}{stop}"));
    let run = project.failed_run(true);
    assert_eq!(run["dispatch"]["captured_output"]["stdout"], "captured-input\n");
    assert_eq!(run["dispatch"]["captured_output"]["stderr"], "captured-warning\n");
    let ledger = &run["dispatch"]["host_effect_ledger"];
    assert_eq!(ledger["effect_count"], 1);
    assert_eq!(ledger["allowed_count"], 1);
    assert_eq!(ledger["denied_count"], 0, "an interpreter stop is not an invented host effect");
    let payload = captured_payload(&run);
    assert_eq!(payload["expected"]["terminal_state"], "engine_failure");
    assert_eq!(payload["expected"]["reason"], expected_reason);
    assert_eq!(payload["expected"]["trace_id"], ledger["trace_id"]);
    assert_eq!(payload["host_effect_transcript"].as_array().unwrap().len(), 1);
    assert!(payload["expected"].get("ir4_witness").is_none());
    let (name, _) = project.bundle(&run);
    project.move_originals();
    assert_engine_prefix(&project.replay(&name));
    assert!(!project.root().join("app.js").exists());
    assert!(!project.root().join("input.txt").exists());

    // A subsequent replay must still use the same capture, not replacement
    // source or new host bytes that happen to occupy the original paths.
    fs::write(project.root().join("app.js"), "throw 'LIVE_SOURCE_MUST_NOT_RUN';").unwrap();
    fs::write(project.root().join("input.txt"), "LIVE_INPUT_MUST_NOT_BE_READ").unwrap();
    assert_engine_prefix(&project.replay(&name));
    assert_eq!(fs::read_to_string(project.root().join("input.txt")).unwrap(), "LIVE_INPUT_MUST_NOT_BE_READ");
    assert_eq!(fs::read_to_string(project.root().join("saved-input.txt")).unwrap(), "captured-input");
}

#[test]
fn native_engine_stop_cli_captures_and_replays_capability_denial_after_real_read() {
    exercise_stop(DENIAL, serde_json::json!({"kind":"capability_denied","capability":"env_read"}));
}

#[test]
fn native_engine_stop_cli_captures_and_replays_instruction_exhaustion_after_real_read() {
    exercise_stop(EXHAUSTION, serde_json::json!({"kind":"instruction_budget_exhausted","budget":INSTRUCTION_BUDGET}));
}

#[test]
fn native_engine_stop_cli_empty_effect_journal_is_not_a_completed_execution() {
    let project = Project::new(EXHAUSTION);
    let run = project.failed_run(true);
    assert_eq!(run["dispatch"]["host_effect_ledger"]["effect_count"], 0);
    assert_eq!(captured_payload(&run)["expected"]["terminal_state"], "engine_failure");
    let (name, bundle) = project.bundle(&run);
    let events = bundle["timeline"].as_array().expect("real incident timeline");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "state_change");
    let terminal = &events[0]["payload"];
    assert!(terminal.get("effect_receipt_chain_entry").is_none());
    assert!(terminal.get("native_execution_completed").is_none());
    assert_eq!(terminal["native_execution_failed"]["run_receipt_id"], run["receipt"]["receipt_id"]);
    project.move_originals();
    assert_engine_prefix(&project.replay(&name));
}

#[test]
fn native_engine_stop_cli_rejects_signed_wrong_expectations_and_unused_effects() {
    use frankenengine_extension_host::host_io::{HostIoOutcome, HostIoRequest};

    let project = Project::new(&format!("{EFFECT_PREFIX}{EXHAUSTION}"));
    let run = project.failed_run(true);
    let (_, bundle) = project.bundle(&run);
    let original = run["dispatch"]["native_replay"]["payload_json"].as_str().unwrap();
    let message = "\"message\":\"captured-warning\"";
    assert_eq!(original.matches(message).count(), 1);
    write_authenticated_native_candidate(
        project.root(), &bundle, "wrong-stop-output.fnbundle",
        original.replacen(message, "\"message\":\"forged-warning\"", 1),
    );
    let payload = captured_payload(&run);
    let exchange: (HostIoRequest, HostIoOutcome) =
        serde_json::from_value(payload["host_effect_transcript"][0].clone()).unwrap();
    let exchange = serde_json::to_string(&exchange).unwrap();
    let field = "\"host_effect_transcript\":[";
    assert_eq!(original.matches(field).count(), 1);
    write_authenticated_native_candidate(
        project.root(), &bundle, "unused-stop-input.fnbundle",
        original.replacen(field, &format!("{field}{exchange},"), 1),
    );
    project.move_originals();
    let wrong = project.replay("wrong-stop-output.fnbundle");
    assert!(!wrong.status.success());
    let wrong: Value = serde_json::from_slice(&wrong.stdout).unwrap();
    assert_eq!(wrong["execution_result"]["terminal_state_match"], true);
    assert_eq!(wrong["execution_result"]["console_match"], false);
    assert_eq!(wrong["replay_result"]["matched"], false);
    let unused = project.replay("unused-stop-input.fnbundle");
    assert!(!unused.status.success());
    let unused: Value = serde_json::from_slice(&unused.stdout).unwrap();
    assert!(unused["error"].as_str().unwrap().contains("unused"), "{unused}");
}

#[test]
fn native_engine_stop_cli_does_not_classify_guest_exception_text_as_engine_failure() {
    let project = Project::new(&format!(
        "{EFFECT_PREFIX}throw 'capability denied: env_read; instruction budget exhausted';"
    ));
    let run = project.failed_run(true);
    assert_eq!(captured_payload(&run)["expected"]["terminal_state"], "uncaught_exception");
    let (name, _) = project.bundle(&run);
    project.move_originals();
    let replay = project.replay(&name);
    assert!(replay.status.success(), "{}", String::from_utf8_lossy(&replay.stderr));
    let replay: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["execution_result"]["verification_scope"], "guest_failure_prefix");
    assert_eq!(replay["execution_result"]["exception_value_match"], true);
}

#[test]
fn native_engine_stop_cli_keeps_opt_in_and_unsupported_failures_distinct() {
    let project = Project::new(&format!("{EFFECT_PREFIX}{EXHAUSTION}"));
    let run = project.failed_run(false);
    assert!(run["dispatch"].get("native_replay").is_none());
    assert!(run["receipt"]["native_replay_payload_sha256"].is_null());
    assert_eq!(run["dispatch"]["host_effect_ledger"]["effect_count"], 1);
    assert_eq!(run["dispatch"]["captured_output"]["stdout"], "captured-input\n");

    let invalid = Project::new("const = ;");
    let run = invalid.failed_run(true);
    assert!(run["dispatch"].get("native_replay").is_none());
    assert!(run["receipt"]["native_replay_payload_sha256"].is_null());
    assert!(run["dispatch"]["host_effect_ledger"].is_null());
}

#[test]
fn native_engine_stop_cli_restores_captured_budget_not_current_operator_setting() {
    let project = Project::new(&format!("{EFFECT_PREFIX}{EXHAUSTION}"));
    let run = project.failed_run(true);
    let (name, _) = project.bundle(&run);
    project.move_originals();
    for current_budget in [1, INSTRUCTION_BUDGET * 2] {
        let replay = execute_native_replay_with(&name, |args| {
            project.invoke_with_budget(args, current_budget)
        });
        // Matching includes the typed budget and exact engine diagnostic. It
        // cannot pass merely by exhausting whichever limit is configured now.
        assert_engine_prefix(&replay);
    }
}
