#!/usr/bin/env bash
# scripts/run_perf_bead_test.sh — shared POSIX shell harness for the
# Tx.tests scripts of the bd-98xo5 performance optimization epic.
#
# Sourced (NOT executed) by every `tests/perf_beads/<bead-id>.sh`:
#
#     source "$(git rev-parse --show-toplevel)/scripts/run_perf_bead_test.sh"
#     perf_test_init "bd-98xo5.1.tests"
#     perf_test_start "build"
#     perf_test_run_cargo build --profile release-perf -p frankenengine-node
#     ...
#     perf_test_summary
#
# Emits the bd-98xo5 canonical JSONL log schema (see
# docs/dev/perf_bead_testing.md) to both stdout (pretty + ANSI-coloured,
# unless NO_COLOR is set) AND the file at $PERF_TEST_LOG.
#
# Designed to run on bash 5+ (the project's swarm hosts) with no
# external deps beyond coreutils. `jq` is for consumer scripts, NOT
# the producer side.
#
# All output is two-stream: structured JSONL to $PERF_TEST_LOG, pretty
# ANSI to stdout. The JSONL file has zero ANSI escape codes.
#
# Author: SilentCompass (bd-98xo5.15.1, parent: bd-98xo5.15).

# Don't bail if the caller's script is sourcing us inside `set -e` —
# our function returns are how callers detect failures.

# ---------------------------------------------------------------------
# Private state — sourced once per perf_test_init call.
# ---------------------------------------------------------------------

# Run-time globals (re-initialised on every perf_test_init call):
#   PERF_TEST_BEAD_ID       — caller bead id (e.g. "bd-98xo5.1.tests")
#   PERF_TEST_TRACE_ID      — uuid-style trace id for this run
#   PERF_TEST_RUN_DIR       — tests/artifacts/perf/test_runs/<bead>_<ts>/
#   PERF_TEST_LOG           — $PERF_TEST_RUN_DIR/test_log.jsonl
#   PERF_TEST_STDERR_TAIL   — last 20 lines of last-captured stderr
#   _PERF_PHASE             — current phase ("build" / "unit" / ...)
#   _PERF_CASE_NAME         — name of the in-flight test case
#   _PERF_CASE_START_NS     — monotonic ns at perf_test_case time
#   _PERF_PHASE_START_NS    — monotonic ns at perf_test_start time
#   _PERF_PHASE_PASSED      — counter (per phase)
#   _PERF_PHASE_FAILED      — counter (per phase)
#   _PERF_PHASE_SKIPPED     — counter (per phase)
#   _PERF_USE_COLOR         — "1" if stdout is a tty and NO_COLOR unset

# ---------------------------------------------------------------------
# Internals.
# ---------------------------------------------------------------------

_perf_now_iso8601() {
    # RFC 3339 with millisecond precision in UTC. `date %N` gives ns
    # on GNU date; we slice to ms.
    local ns
    ns=$(date -u '+%Y-%m-%dT%H:%M:%S.%NZ' 2>/dev/null) || ns=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    # %N may print "N" literally on platforms without ns precision
    # (musl, BSD). Fall back to 000 in that case.
    case "$ns" in
        *.N*) ns=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z') ;;
    esac
    # Trim ns to ms (RFC 3339 with millis is what consumers expect).
    printf '%s\n' "$ns" | sed -E 's/\.([0-9]{3})[0-9]*Z/.\1Z/'
}

_perf_now_ns() {
    # Monotonic-ish elapsed time. `date +%s%N` is gettimeofday — close
    # enough for test-harness duration tracking.
    date '+%s%N' 2>/dev/null || echo "0"
}

_perf_make_trace_id() {
    # uuidgen if available, otherwise hash(pid+nanosecond) — sufficient
    # for a per-run trace id.
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr 'A-Z' 'a-z'
    else
        printf '%s' "$$-$(_perf_now_ns)" | sha256sum 2>/dev/null | cut -c1-32 \
            || printf 'fallback-%s-%s' "$$" "$(_perf_now_ns)"
    fi
}

_perf_escape_json_str() {
    # Minimal JSON-string escape: backslash, quote, control chars.
    # Reads from $1, writes to stdout. Heredoc-safe (no command expansion).
    local s=$1
    # Backslashes first, then quotes, then newlines, CR, tab, backspace, formfeed.
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    s=${s//$'\b'/\\b}
    s=${s//$'\f'/\\f}
    printf '%s' "$s"
}

_perf_color() {
    # _perf_color <code> <text>. Emits ANSI iff _PERF_USE_COLOR=1.
    if [ "${_PERF_USE_COLOR:-0}" = "1" ]; then
        printf '\033[%sm%s\033[0m' "$1" "$2"
    else
        printf '%s' "$2"
    fi
}

_perf_emit() {
    # _perf_emit <event_code> <level> <duration_ms> <test_name|""> <extra_json>
    #
    # Builds a single JSONL line and writes it to both stdout (pretty)
    # and $PERF_TEST_LOG (raw JSONL).
    local code=$1 level=$2 duration_ms=$3 test_name=$4 extra=$5
    local ts
    ts=$(_perf_now_iso8601)
    local name_field
    if [ -z "$test_name" ]; then
        name_field="null"
    else
        name_field=$(printf '"%s"' "$(_perf_escape_json_str "$test_name")")
    fi
    local extra_field=${extra:-"{}"}
    local phase_field
    phase_field=$(printf '"%s"' "$(_perf_escape_json_str "${_PERF_PHASE:-unknown}")")
    local bead_field
    bead_field=$(printf '"%s"' "$(_perf_escape_json_str "${PERF_TEST_BEAD_ID:-unset}")")
    local trace_field
    trace_field=$(printf '"%s"' "$(_perf_escape_json_str "${PERF_TEST_TRACE_ID:-unset}")")
    local jsonl
    jsonl=$(printf '{"timestamp":"%s","level":"%s","event_code":"%s","bead_id":%s,"trace_id":%s,"phase":%s,"test_name":%s,"duration_ms":%s,"extra":%s}' \
        "$ts" "$level" "$code" "$bead_field" "$trace_field" "$phase_field" "$name_field" "$duration_ms" "$extra_field")
    if [ -n "${PERF_TEST_LOG:-}" ]; then
        printf '%s\n' "$jsonl" >>"$PERF_TEST_LOG"
    fi
    _perf_pretty "$code" "$level" "$duration_ms" "$test_name" "$extra"
}

_perf_pretty() {
    # Pretty-printer for stdout — strips ANSI in $PERF_TEST_LOG, ANSI here.
    local code=$1 level=$2 duration_ms=$3 test_name=$4 _extra=$5
    case "$code" in
        TEST-PASS)
            printf '  %s %s' "$(_perf_color 32 "✓ PASS")" "$test_name"
            [ "$duration_ms" != "0" ] && printf ' %s' "$(_perf_color 90 "(${duration_ms} ms)")"
            printf '\n'
            ;;
        TEST-FAIL)
            printf '  %s %s' "$(_perf_color 31 "✗ FAIL")" "$test_name"
            [ "$duration_ms" != "0" ] && printf ' %s' "$(_perf_color 90 "(${duration_ms} ms)")"
            printf '\n'
            ;;
        TEST-START)
            printf '%s %s\n' "$(_perf_color 36 "==>")" "$(_perf_color 1 "phase: ${_PERF_PHASE}")"
            ;;
        TEST-CASE)
            printf '  %s %s\n' "$(_perf_color 36 "→")" "$test_name"
            ;;
        TEST-SUMMARY)
            printf '%s phase=%s passed=%d failed=%d skipped=%d duration=%d ms\n' \
                "$(_perf_color 1 "[summary]")" "${_PERF_PHASE}" \
                "${_PERF_PHASE_PASSED:-0}" "${_PERF_PHASE_FAILED:-0}" "${_PERF_PHASE_SKIPPED:-0}" \
                "$duration_ms"
            ;;
        PERF-MEASUREMENT)
            printf '  %s %s\n' "$(_perf_color 35 "📏 measurement")" "$test_name"
            ;;
        BUILD-START | BUILD-DONE | HOOK-FIRED)
            printf '  %s %s %s\n' "$(_perf_color 33 "[$code]")" "$test_name" "${duration_ms} ms"
            ;;
        *)
            printf '  [%s] %s %s\n' "$code" "$test_name" "$duration_ms"
            ;;
    esac
}

# ---------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------

perf_test_init() {
    # perf_test_init <bead-id>
    # Sets globals + creates the run-id directory + opens the JSONL log.
    local bead_id=${1:-"unknown-bead"}
    PERF_TEST_BEAD_ID=$bead_id
    PERF_TEST_TRACE_ID=$(_perf_make_trace_id)
    local ts
    ts=$(date -u '+%Y%m%dT%H%M%SZ')
    local repo_root
    repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
    PERF_TEST_RUN_DIR="$repo_root/tests/artifacts/perf/test_runs/${bead_id}_${ts}"
    mkdir -p "$PERF_TEST_RUN_DIR"
    PERF_TEST_LOG="$PERF_TEST_RUN_DIR/test_log.jsonl"
    : >"$PERF_TEST_LOG"  # truncate; we always start fresh per run
    PERF_TEST_STDERR_TAIL=$(mktemp)
    _PERF_PHASE=""
    _PERF_CASE_NAME=""
    _PERF_CASE_START_NS=0
    _PERF_PHASE_START_NS=0
    _PERF_PHASE_PASSED=0
    _PERF_PHASE_FAILED=0
    _PERF_PHASE_SKIPPED=0
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        _PERF_USE_COLOR=1
    else
        _PERF_USE_COLOR=0
    fi
    export PERF_TEST_BEAD_ID PERF_TEST_TRACE_ID PERF_TEST_RUN_DIR PERF_TEST_LOG
}

perf_test_start() {
    # perf_test_start <phase>
    local phase=${1:-"unknown"}
    _PERF_PHASE=$phase
    _PERF_PHASE_PASSED=0
    _PERF_PHASE_FAILED=0
    _PERF_PHASE_SKIPPED=0
    _PERF_PHASE_START_NS=$(_perf_now_ns)
    _perf_emit "TEST-START" "info" 0 "" "{}"
}

perf_test_case() {
    # perf_test_case <name>
    _PERF_CASE_NAME=${1:-"unnamed"}
    _PERF_CASE_START_NS=$(_perf_now_ns)
    _perf_emit "TEST-CASE" "info" 0 "$_PERF_CASE_NAME" "{}"
}

perf_test_pass() {
    # Implicit-current-case pass.
    local end_ns dur_ms
    end_ns=$(_perf_now_ns)
    dur_ms=$(( (end_ns - _PERF_CASE_START_NS) / 1000000 ))
    _PERF_PHASE_PASSED=$(( _PERF_PHASE_PASSED + 1 ))
    _perf_emit "TEST-PASS" "info" "$dur_ms" "$_PERF_CASE_NAME" "{}"
}

perf_test_fail() {
    # perf_test_fail <reason>
    local reason=${1:-"unspecified"}
    local end_ns dur_ms
    end_ns=$(_perf_now_ns)
    dur_ms=$(( (end_ns - _PERF_CASE_START_NS) / 1000000 ))
    _PERF_PHASE_FAILED=$(( _PERF_PHASE_FAILED + 1 ))
    local tail_text=""
    if [ -s "${PERF_TEST_STDERR_TAIL:-}" ]; then
        tail_text=$(tail -n 20 "$PERF_TEST_STDERR_TAIL" 2>/dev/null || true)
    fi
    local extra
    extra=$(printf '{"failure_reason":"%s","stderr_tail":"%s"}' \
        "$(_perf_escape_json_str "$reason")" \
        "$(_perf_escape_json_str "$tail_text")")
    _perf_emit "TEST-FAIL" "error" "$dur_ms" "$_PERF_CASE_NAME" "$extra"
}

perf_test_skip() {
    # perf_test_skip <reason>
    local reason=${1:-"skipped"}
    _PERF_PHASE_SKIPPED=$(( _PERF_PHASE_SKIPPED + 1 ))
    local extra
    extra=$(printf '{"skip_reason":"%s"}' "$(_perf_escape_json_str "$reason")")
    _perf_emit "TEST-SKIP" "warn" 0 "$_PERF_CASE_NAME" "$extra"
}

perf_test_measurement() {
    # perf_test_measurement <metric> <value> <unit>
    local metric=${1:-"unspecified"} value=${2:-"0"} unit=${3:-"unspecified"}
    local extra
    extra=$(printf '{"metric":"%s","value":%s,"unit":"%s"}' \
        "$(_perf_escape_json_str "$metric")" \
        "$value" \
        "$(_perf_escape_json_str "$unit")")
    _perf_emit "PERF-MEASUREMENT" "info" 0 "$metric" "$extra"
}

perf_test_summary() {
    # Emits TEST-SUMMARY for the most recent phase. Returns non-zero iff
    # any TEST-FAIL was emitted in that phase.
    local end_ns dur_ms
    end_ns=$(_perf_now_ns)
    dur_ms=$(( (end_ns - _PERF_PHASE_START_NS) / 1000000 ))
    local total=$(( _PERF_PHASE_PASSED + _PERF_PHASE_FAILED + _PERF_PHASE_SKIPPED ))
    local extra
    extra=$(printf '{"passed":%d,"failed":%d,"skipped":%d,"total":%d}' \
        "$_PERF_PHASE_PASSED" "$_PERF_PHASE_FAILED" "$_PERF_PHASE_SKIPPED" "$total")
    _perf_emit "TEST-SUMMARY" "info" "$dur_ms" "" "$extra"
    [ "$_PERF_PHASE_FAILED" -eq 0 ]
}

perf_test_run_cargo() {
    # perf_test_run_cargo <cargo args...>
    # Wraps `rch exec -- cargo $@` with BUILD-START/BUILD-DONE bracket
    # events. Returns the cargo exit code unchanged.
    local start_ns end_ns dur_ms
    start_ns=$(_perf_now_ns)
    local cmd_text
    cmd_text="cargo $*"
    _perf_emit "BUILD-START" "info" 0 "$cmd_text" "{}"
    rch exec -- cargo "$@" 2>"$PERF_TEST_STDERR_TAIL"
    local rc=$?
    end_ns=$(_perf_now_ns)
    dur_ms=$(( (end_ns - start_ns) / 1000000 ))
    local extra
    extra=$(printf '{"exit_code":%d}' "$rc")
    _perf_emit "BUILD-DONE" "info" "$dur_ms" "$cmd_text" "$extra"
    return $rc
}

perf_test_hook_fired() {
    # perf_test_hook_fired <hook_name> <detail>
    local hook=${1:-"unnamed"} detail=${2:-""}
    local extra
    extra=$(printf '{"hook":"%s","detail":"%s"}' \
        "$(_perf_escape_json_str "$hook")" \
        "$(_perf_escape_json_str "$detail")")
    _perf_emit "HOOK-FIRED" "warn" 0 "$hook" "$extra"
}
