#!/usr/bin/env bash
# Comprehensive e2e verification (bd-rjc2m.E2E1): the epic acceptance gate.
#
# Proves the verification scaffolding actually WORKS after remediation (not just compiles):
#   1. full conformance test suite compiles + RUNS
#   2. every fuzz target builds + a bounded smoke runs without immediate crash
#   3. verifier SDK tests run
#   4. supply-chain (cargo deny advisories/bans/sources) + fmt + clippy
# Emits per-target remediation-log JSONL + a human summary report to artifacts/verification/,
# with detailed timestamped logging. Exit code reflects overall pass/fail (any RED => non-zero).
#
# Usage:
#   verify_all_verification_targets.sh            # full run (needs rch/cargo/nightly)
#   verify_all_verification_targets.sh --selftest # validate the script's own parsers offline
#   verify_all_verification_targets.sh --plan-json # print the non-executing command plan
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 1970-01-01T00:00:00Z)"
OUT="artifacts/verification"
RUN_STEM="verify_run_$(echo "$TS" | tr -d ':-')"
JSONL="$OUT/$RUN_STEM.jsonl"
COMMANDS_JSONL="$OUT/${RUN_STEM}_commands.jsonl"
REPORT="$OUT/$RUN_STEM.md"
PLAN_JSON="$OUT/${RUN_STEM}_plan.json"
PLAN_DIGEST="$OUT/${RUN_STEM}_plan.sha256"
RCH="${VERIF_GATE_CARGO_PREFIX:-rch exec --}"
LOCK_GUARD="$SCRIPT_DIR/lockfile_drift_guard.py"
GATES_RC=0

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

millis_now() {
  python3 - <<'PY'
import time
print(time.monotonic_ns() // 1_000_000)
PY
}

run_timed_to_log() {
  log_path="$1"
  shift
  start_ms="$(millis_now)"
  "$@" > "$log_path" 2>&1
  rc=$?
  end_ms="$(millis_now)"
  LAST_DURATION_MS=$((end_ms - start_ms))
  return "$rc"
}

jsonl_count() {
  if [ -f "$1" ]; then
    wc -l < "$1"
  else
    echo 0
  fi
}

status_for_exit_only() {
  if [ "$1" -eq 0 ]; then
    echo "passed"
  else
    echo "command_failed"
  fi
}

parsed_status_since() {
  start_line="$1"
  exit_code="$2"
  python3 - "$SCRIPT_DIR" "$JSONL" "$start_line" "$exit_code" <<'PY'
import json
import sys

script_dir, path, start_line, exit_code = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sys.path.insert(0, script_dir)
from remediation_log import RemediationRecord, parsed_status_for_records

records = []
try:
    with open(path, encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            if index < start_line:
                continue
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            payload.pop("schema_version", None)
            records.append(RemediationRecord(**payload))
except FileNotFoundError:
    pass

print(parsed_status_for_records(records, exit_code))
PY
}

emit_command_receipt() {
  step_id="$1"
  label="$2"
  command_text="$3"
  exit_code="$4"
  duration_ms="$5"
  log_path="$6"
  parsed_status="$7"
  python3 - "$SCRIPT_DIR" "$COMMANDS_JSONL" "$TS" "$step_id" "$label" "$command_text" "$exit_code" "$duration_ms" "$log_path" "$parsed_status" <<'PY'
import hashlib
import sys

script_dir, path, ts, step_id, label, command_text, exit_code, duration_ms, log_path, parsed_status = sys.argv[1:]
sys.path.insert(0, script_dir)
from remediation_log import CommandReceipt

receipt = CommandReceipt(
    step_id=step_id,
    label=label,
    command=command_text,
    command_digest="sha256:" + hashlib.sha256(command_text.encode("utf-8")).hexdigest(),
    exit_code=int(exit_code),
    duration_ms=int(duration_ms),
    log_path=log_path,
    parsed_status=parsed_status,
    ts_rfc3339=ts,
)
errs = receipt.validate()
if errs:
    raise SystemExit(f"invalid command receipt for {step_id}: {errs}")
with open(path, "a", encoding="utf-8") as fh:
    fh.write(receipt.to_json() + "\n")
PY
}

append_command_summary() {
  python3 - "$SCRIPT_DIR" "$COMMANDS_JSONL" >> "$REPORT" <<'PY'
import sys

script_dir, path = sys.argv[1], sys.argv[2]
sys.path.insert(0, script_dir)
from remediation_log import read_command_receipts, render_command_summary

print()
sys.stdout.write(render_command_summary(read_command_receipts(path)))
PY
}

run_guarded_gate() {
  step_id="$1"
  label="$2"
  report_json="$3"
  log_path="$4"
  command_text="$5"
  shift 5

  start_ms="$(millis_now)"
  python3 "$LOCK_GUARD" \
    --label "$label" \
    --report-json "$report_json" \
    -- "$@" > "$log_path" 2>&1
  rc=$?
  end_ms="$(millis_now)"
  duration_ms=$((end_ms - start_ms))
  [ "$rc" -ne 0 ] && GATES_RC=1
  emit_command_receipt "$step_id" "$label" "$command_text" "$rc" "$duration_ms" "$log_path" "$(status_for_exit_only "$rc")"

  {
    echo "## $label"
    tail -20 "$log_path"
    echo "json: $report_json"
  } >> "$OUT/gates.txt"
}

emit_plan_json() {
  python3 - "$TS" "$RCH" "$OUT" "$JSONL" "$COMMANDS_JSONL" "$REPORT" "$PLAN_JSON" "$PLAN_DIGEST" <<'PY'
import json
import sys

ts, rch, out, jsonl, commands_jsonl, report, plan_json, plan_digest = sys.argv[1:]


def with_rch(command: str) -> str:
    return f"{rch} {command}".strip()


steps = [
    {
        "id": "compile_census",
        "label": "compile census (no broken targets allowed)",
        "heavy": True,
        "rch_required": True,
        "command": 'GATE_TS="$TS" python3 "$SCRIPT_DIR/check_verification_targets_compile.py" --run --out "$OUT" --ts "$TS"',
        "log_path": f"{out}/compile_census.log",
        "report_json": None,
    },
    {
        "id": "full_conformance",
        "label": "full conformance suite",
        "heavy": True,
        "rch_required": True,
        "command": with_rch("cargo test -p frankenengine-node --locked --features extended-surfaces,test-support"),
        "log_path": f"{out}/full_test.log",
        "report_json": None,
    },
    {
        "id": "fuzz_smokes",
        "label": "fuzz smokes (bounded 30s each)",
        "heavy": True,
        "rch_required": True,
        "command": with_rch("cargo +nightly fuzz run <target> -- -max_total_time=30 -rss_limit_mb=4096"),
        "log_path": f"{out}/fuzz_<target>.log",
        "report_json": None,
    },
    {
        "id": "verifier_sdk",
        "label": "verifier SDK tests",
        "heavy": True,
        "rch_required": True,
        "command": with_rch("cargo test -p frankenengine-verifier-sdk --locked"),
        "log_path": f"{out}/sdk_test.log",
        "report_json": None,
    },
    {
        "id": "cargo_deny",
        "label": "cargo deny check advisories bans sources",
        "heavy": False,
        "rch_required": False,
        "command": "cargo deny check advisories bans sources",
        "log_path": f"{out}/cargo_deny.log",
        "report_json": f"{out}/cargo_deny_lockfile_drift.json",
    },
    {
        "id": "cargo_fmt",
        "label": "cargo fmt --check -p frankenengine-node",
        "heavy": False,
        "rch_required": False,
        "command": "cargo fmt --check -p frankenengine-node",
        "log_path": f"{out}/cargo_fmt.log",
        "report_json": f"{out}/cargo_fmt_lockfile_drift.json",
    },
    {
        "id": "cargo_clippy",
        "label": "cargo clippy --all-targets -- -D warnings",
        "heavy": True,
        "rch_required": True,
        "command": with_rch("cargo clippy --all-targets -- -D warnings"),
        "log_path": f"{out}/cargo_clippy.log",
        "report_json": f"{out}/cargo_clippy_lockfile_drift.json",
    },
    {
        "id": "summary",
        "label": "render summary report",
        "heavy": False,
        "rch_required": False,
        "command": 'python3 "$SCRIPT_DIR/remediation_log.py" "$JSONL" > "$REPORT"; cat "$OUT/gates.txt" >> "$REPORT"',
        "log_path": report,
        "report_json": None,
    },
]
for step in steps:
    step["receipt_required"] = True

payload = {
    "schema_version": "verification-plan-v1",
    "generated_at": ts,
    "artifact_dir": out,
    "jsonl_path": jsonl,
    "command_receipts_path": commands_jsonl,
    "plan_path": plan_json,
    "plan_sha256_path": plan_digest,
    "report_path": report,
    "rch_prefix": rch,
    "steps": steps,
}
json.dump(payload, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
}

write_plan_artifact() {
  emit_plan_json > "$PLAN_JSON"
  python3 - "$PLAN_JSON" "$PLAN_DIGEST" <<'PY'
import hashlib
import pathlib
import sys

plan_path = pathlib.Path(sys.argv[1])
digest_path = pathlib.Path(sys.argv[2])
digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
digest_path.write_text(f"{digest}  {plan_path}\n", encoding="utf-8")
print(digest)
PY
}

append_plan_summary() {
  {
    echo
    echo "## Verification plan"
    echo "plan: $PLAN_JSON"
    echo "sha256_file: $PLAN_DIGEST"
    echo "sha256: $PLAN_SHA"
  } >> "$REPORT"
}

validate_plan_json() {
  PLAN_JSON="$("$0" --plan-json)" python3 - <<'PY'
import json
import os

plan = json.loads(os.environ["PLAN_JSON"])
required = {
    "compile_census",
    "full_conformance",
    "fuzz_smokes",
    "verifier_sdk",
    "cargo_deny",
    "cargo_fmt",
    "cargo_clippy",
    "summary",
}
steps = {step["id"]: step for step in plan.get("steps", [])}
missing = sorted(required - set(steps))
if missing:
    raise SystemExit(f"verification plan missing steps: {', '.join(missing)}")

rch_prefix = f"{plan['rch_prefix']} "
for step_id, step in steps.items():
    command = step["command"]
    if not step.get("receipt_required"):
        raise SystemExit(f"verification plan step {step_id} must require a command receipt")
    if not step.get("log_path"):
        raise SystemExit(f"verification plan step {step_id} must declare a command log path")
    if step["rch_required"] and "cargo " in command and not command.startswith(rch_prefix):
        raise SystemExit(f"verification plan step {step_id} requires rch but command is unprefixed")
    if not step["rch_required"] and command.startswith(rch_prefix):
        raise SystemExit(f"verification plan step {step_id} is local-only but command is rch-prefixed")
PY
}

if [ "${1:-}" = "--selftest" ]; then
  log "selftest: running parser unit tests"
  python3 "$SCRIPT_DIR/test_remediation_log.py" || exit 1
  python3 "$SCRIPT_DIR/test_check_verification_targets_compile.py" || exit 1
  python3 "$SCRIPT_DIR/test_parse_cargo_test_results.py" || exit 1
  python3 "$SCRIPT_DIR/test_lockfile_drift_guard.py" || exit 1
  log "selftest: validating verification plan"
  validate_plan_json || exit 1
  log "selftest OK"
  exit 0
fi

if [ "${1:-}" = "--plan-json" ]; then
  emit_plan_json
  exit 0
fi

mkdir -p "$OUT"
PLAN_SHA="$(write_plan_artifact)"
: > "$JSONL"
: > "$COMMANDS_JSONL"
log "verify run $TS -> $JSONL"
log "plan -> $PLAN_JSON (sha256 $PLAN_SHA)"
log "command receipts -> $COMMANDS_JSONL"

# 0) compile census MUST be clean first (delegates to the .G1 gate, blocking).
log "step 0: compile census (no broken targets allowed)"
COMPILE_CENSUS_COMMAND='GATE_TS="$TS" python3 "$SCRIPT_DIR/check_verification_targets_compile.py" --run --out "$OUT" --ts "$TS"'
run_timed_to_log "$OUT/compile_census.log" env "GATE_TS=$TS" python3 "$SCRIPT_DIR/check_verification_targets_compile.py" --run --out "$OUT" --ts "$TS"
CENSUS_RC=$?
emit_command_receipt "compile_census" "compile census (no broken targets allowed)" "$COMPILE_CENSUS_COMMAND" "$CENSUS_RC" "$LAST_DURATION_MS" "$OUT/compile_census.log" "$(status_for_exit_only "$CENSUS_RC")"
[ "$CENSUS_RC" -ne 0 ] && log "RED: broken verification targets exist; fix bd-rjc2m remediation before e2e can pass"

# 1) full conformance suite (compile + RUN)
log "step 1: full conformance suite"
FULL_BEFORE="$(jsonl_count "$JSONL")"
FULL_COMMAND="$RCH cargo test -p frankenengine-node --locked --features extended-surfaces,test-support"
run_timed_to_log "$OUT/full_test.log" $RCH cargo test -p frankenengine-node --locked --features extended-surfaces,test-support
FULL_RC=$?
python3 "$SCRIPT_DIR/parse_cargo_test_results.py" "$OUT/full_test.log" "$TS" conformance >> "$JSONL"
emit_command_receipt "full_conformance" "full conformance suite" "$FULL_COMMAND" "$FULL_RC" "$LAST_DURATION_MS" "$OUT/full_test.log" "$(parsed_status_since "$FULL_BEFORE" "$FULL_RC")"

# 2) fuzz smokes (bounded; one per target)
log "step 2: fuzz smokes (bounded 30s each)"
FUZZ_BEFORE="$(jsonl_count "$JSONL")"
FUZZ_LOOP_RC=0
FUZZ_LOOP_START_MS="$(millis_now)"
for t in $(ls fuzz/fuzz_targets/*.rs 2>/dev/null | xargs -n1 basename | sed 's/\.rs$//'); do
  TARGET_BEFORE="$(jsonl_count "$JSONL")"
  TARGET_LOG="$OUT/fuzz_$t.log"
  TARGET_COMMAND="$RCH cargo +nightly fuzz run $t -- -max_total_time=30 -rss_limit_mb=4096"
  run_timed_to_log "$TARGET_LOG" $RCH cargo +nightly fuzz run "$t" -- -max_total_time=30 -rss_limit_mb=4096
  TARGET_RC=$?
  [ "$TARGET_RC" -ne 0 ] && FUZZ_LOOP_RC=1
  python3 - "$t" "$OUT/fuzz_$t.log" "$TS" >> "$JSONL" <<'PY'
import sys; sys.path.insert(0, __import__("os").path.dirname(sys.argv[0]) or ".")
sys.path.insert(0, "scripts")
from parse_cargo_test_results import parse_fuzz_smoke
t, log, ts = sys.argv[1], sys.argv[2], sys.argv[3]
print(parse_fuzz_smoke(t, open(log, encoding="utf-8", errors="ignore").read(), ts).to_json())
PY
  emit_command_receipt "fuzz_smokes:$t" "fuzz smoke $t" "$TARGET_COMMAND" "$TARGET_RC" "$LAST_DURATION_MS" "$TARGET_LOG" "$(parsed_status_since "$TARGET_BEFORE" "$TARGET_RC")"
done
FUZZ_LOOP_END_MS="$(millis_now)"
FUZZ_COMMAND="$RCH cargo +nightly fuzz run <target> -- -max_total_time=30 -rss_limit_mb=4096"
emit_command_receipt "fuzz_smokes" "fuzz smokes (bounded 30s each)" "$FUZZ_COMMAND" "$FUZZ_LOOP_RC" "$((FUZZ_LOOP_END_MS - FUZZ_LOOP_START_MS))" "$OUT/fuzz_<target>.log" "$(parsed_status_since "$FUZZ_BEFORE" "$FUZZ_LOOP_RC")"

# 3) verifier SDK
log "step 3: verifier SDK tests"
SDK_BEFORE="$(jsonl_count "$JSONL")"
SDK_COMMAND="$RCH cargo test -p frankenengine-verifier-sdk --locked"
run_timed_to_log "$OUT/sdk_test.log" $RCH cargo test -p frankenengine-verifier-sdk --locked
SDK_RC=$?
python3 "$SCRIPT_DIR/parse_cargo_test_results.py" "$OUT/sdk_test.log" "$TS" sdk >> "$JSONL"
emit_command_receipt "verifier_sdk" "verifier SDK tests" "$SDK_COMMAND" "$SDK_RC" "$LAST_DURATION_MS" "$OUT/sdk_test.log" "$(parsed_status_since "$SDK_BEFORE" "$SDK_RC")"

# 4) supply-chain + fmt + clippy (recorded in the report tail)
log "step 4: cargo deny / fmt / clippy"
: > "$OUT/gates.txt"
run_guarded_gate \
  "cargo_deny" \
  "cargo deny check advisories bans sources" \
  "$OUT/cargo_deny_lockfile_drift.json" \
  "$OUT/cargo_deny.log" \
  "cargo deny check advisories bans sources" \
  cargo deny check advisories bans sources
run_guarded_gate \
  "cargo_fmt" \
  "cargo fmt --check -p frankenengine-node" \
  "$OUT/cargo_fmt_lockfile_drift.json" \
  "$OUT/cargo_fmt.log" \
  "cargo fmt --check -p frankenengine-node" \
  cargo fmt --check -p frankenengine-node
run_guarded_gate \
  "cargo_clippy" \
  "cargo clippy --all-targets -- -D warnings" \
  "$OUT/cargo_clippy_lockfile_drift.json" \
  "$OUT/cargo_clippy.log" \
  "$RCH cargo clippy --all-targets -- -D warnings" \
  $RCH cargo clippy --all-targets -- -D warnings

# 5) render summary + exit code
log "step 5: summary"
SUMMARY_BEFORE=0
SUMMARY_COMMAND='python3 "$SCRIPT_DIR/remediation_log.py" "$JSONL" > "$REPORT"; cat "$OUT/gates.txt" >> "$REPORT"'
SUMMARY_START_MS="$(millis_now)"
python3 "$SCRIPT_DIR/remediation_log.py" "$JSONL" > "$REPORT"
RC=$?
SUMMARY_END_MS="$(millis_now)"
emit_command_receipt "summary" "render summary report" "$SUMMARY_COMMAND" "$RC" "$((SUMMARY_END_MS - SUMMARY_START_MS))" "$REPORT" "$(parsed_status_since "$SUMMARY_BEFORE" "$RC")"
append_plan_summary
append_command_summary
cat "$OUT/gates.txt" >> "$REPORT"
log "report -> $REPORT (exit $RC)"
# Overall RED if census broke, gates failed, or any target was not green.
[ "$CENSUS_RC" -ne 0 ] && RC=1
[ "$GATES_RC" -ne 0 ] && RC=1
exit "$RC"
