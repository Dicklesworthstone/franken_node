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
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 1970-01-01T00:00:00Z)"
OUT="artifacts/verification"
JSONL="$OUT/verify_run_$(echo "$TS" | tr -d ':-').jsonl"
REPORT="$OUT/verify_run_$(echo "$TS" | tr -d ':-').md"
RCH="${VERIF_GATE_CARGO_PREFIX:-rch exec --}"
LOCK_GUARD="$SCRIPT_DIR/lockfile_drift_guard.py"
GATES_RC=0

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

run_guarded_gate() {
  label="$1"
  report_json="$2"
  log_path="$3"
  shift 3

  python3 "$LOCK_GUARD" \
    --label "$label" \
    --report-json "$report_json" \
    -- "$@" > "$log_path" 2>&1
  rc=$?
  [ "$rc" -ne 0 ] && GATES_RC=1

  {
    echo "## $label"
    tail -20 "$log_path"
    echo "json: $report_json"
  } >> "$OUT/gates.txt"
}

if [ "${1:-}" = "--selftest" ]; then
  log "selftest: running parser unit tests"
  python3 "$SCRIPT_DIR/test_remediation_log.py" || exit 1
  python3 "$SCRIPT_DIR/test_check_verification_targets_compile.py" || exit 1
  python3 "$SCRIPT_DIR/test_parse_cargo_test_results.py" || exit 1
  python3 "$SCRIPT_DIR/test_lockfile_drift_guard.py" || exit 1
  log "selftest OK"
  exit 0
fi

mkdir -p "$OUT"
: > "$JSONL"
log "verify run $TS -> $JSONL"

# 0) compile census MUST be clean first (delegates to the .G1 gate, blocking).
log "step 0: compile census (no broken targets allowed)"
GATE_TS="$TS" python3 "$SCRIPT_DIR/check_verification_targets_compile.py" --run --out "$OUT" --ts "$TS"
CENSUS_RC=$?
[ "$CENSUS_RC" -ne 0 ] && log "RED: broken verification targets exist; fix bd-rjc2m remediation before e2e can pass"

# 1) full conformance suite (compile + RUN)
log "step 1: full conformance suite"
$RCH cargo test -p frankenengine-node --locked --features extended-surfaces,test-support > "$OUT/full_test.log" 2>&1
python3 "$SCRIPT_DIR/parse_cargo_test_results.py" "$OUT/full_test.log" "$TS" conformance >> "$JSONL"

# 2) fuzz smokes (bounded; one per target)
log "step 2: fuzz smokes (bounded 30s each)"
for t in $(ls fuzz/fuzz_targets/*.rs 2>/dev/null | xargs -n1 basename | sed 's/\.rs$//'); do
  $RCH cargo +nightly fuzz run "$t" -- -max_total_time=30 -rss_limit_mb=4096 > "$OUT/fuzz_$t.log" 2>&1
  python3 - "$t" "$OUT/fuzz_$t.log" "$TS" >> "$JSONL" <<'PY'
import sys; sys.path.insert(0, __import__("os").path.dirname(sys.argv[0]) or ".")
sys.path.insert(0, "scripts")
from parse_cargo_test_results import parse_fuzz_smoke
t, log, ts = sys.argv[1], sys.argv[2], sys.argv[3]
print(parse_fuzz_smoke(t, open(log, encoding="utf-8", errors="ignore").read(), ts).to_json())
PY
done

# 3) verifier SDK
log "step 3: verifier SDK tests"
$RCH cargo test -p frankenengine-verifier-sdk --locked > "$OUT/sdk_test.log" 2>&1
python3 "$SCRIPT_DIR/parse_cargo_test_results.py" "$OUT/sdk_test.log" "$TS" sdk >> "$JSONL"

# 4) supply-chain + fmt + clippy (recorded in the report tail)
log "step 4: cargo deny / fmt / clippy"
: > "$OUT/gates.txt"
run_guarded_gate \
  "cargo deny check advisories bans sources" \
  "$OUT/cargo_deny_lockfile_drift.json" \
  "$OUT/cargo_deny.log" \
  cargo deny check advisories bans sources
run_guarded_gate \
  "cargo fmt --check -p frankenengine-node" \
  "$OUT/cargo_fmt_lockfile_drift.json" \
  "$OUT/cargo_fmt.log" \
  cargo fmt --check -p frankenengine-node
run_guarded_gate \
  "cargo clippy --all-targets -- -D warnings" \
  "$OUT/cargo_clippy_lockfile_drift.json" \
  "$OUT/cargo_clippy.log" \
  $RCH cargo clippy --all-targets -- -D warnings

# 5) render summary + exit code
log "step 5: summary"
python3 "$SCRIPT_DIR/remediation_log.py" "$JSONL" > "$REPORT"
RC=$?
cat "$OUT/gates.txt" >> "$REPORT"
log "report -> $REPORT (exit $RC)"
# Overall RED if census broke, gates failed, or any target was not green.
[ "$CENSUS_RC" -ne 0 ] && RC=1
[ "$GATES_RC" -ne 0 ] && RC=1
exit "$RC"
