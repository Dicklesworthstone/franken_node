#!/usr/bin/env bash
# bd-reality-20260923-26n9r.5 — Live execution-limits, wall-clock, console,
# error-preservation, exit-status, and strict-profile acceptance probe.
set -euo pipefail

BIN="${FRANKEN_NODE_BIN:-target/release/franken-node}"
if [[ ! -x "$BIN" ]]; then
  echo "ERROR: franken-node binary not found or not executable at $BIN" >&2
  exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

PASS_COUNT=0
FAIL_COUNT=0

TMP_WS="$(mktemp -d "${TMPDIR:-/tmp}/fn-probe-exec-limits.XXXXXX")"

(cd "$TMP_WS" && "$BIN" init --profile balanced --out-dir . >/dev/null 2>&1)

report_case() {
  local name="$1"
  local ok="$2"
  local detail="$3"
  if [[ "$ok" == "1" ]]; then
    printf '[PASS] %-28s %s\n' "$name" "$detail"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf '[FAIL] %-28s %s\n' "$name" "$detail"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# 1. CPU loop (5e6 iterations under default balanced profile)
cat >"$TMP_WS/cpu.js" <<'EOF'
let s = 0;
for (let i = 0; i < 5000000; i++) { s += i; }
console.log(s);
EOF
if out="$(cd "$TMP_WS" && "$BIN" run cpu.js --policy balanced --console-only 2>/dev/null)" && [[ "$out" == "12499997500000" ]]; then
  report_case "cpu_5e6_balanced" "1" "exit=0 sum=$out"
else
  report_case "cpu_5e6_balanced" "0" "unexpected output=$out"
fi

# 2. Date.now() realism in wall_clock_mode=real
cat >"$TMP_WS/clock.js" <<'EOF'
console.log(Date.now());
EOF
host_ms="$(python3 -c 'import time; print(int(time.time() * 1000))')"
if guest_ms="$(cd "$TMP_WS" && FRANKEN_NODE_RUNTIME_WALL_CLOCK_MODE=real "$BIN" run clock.js --policy balanced --console-only 2>/dev/null)" \
  && python3 -c "import sys; g=int(sys.argv[1]); h=int(sys.argv[2]); sys.exit(0 if abs(g-h) < 60000 else 1)" "$guest_ms" "$host_ms"; then
  report_case "date_now_real_mode" "1" "exit=0 guest_ms=$guest_ms host_ms=$host_ms"
else
  report_case "date_now_real_mode" "0" "guest_ms=${guest_ms:-err} host_ms=$host_ms"
fi

# 3. 1,500-line console output without silent ring truncation
cat >"$TMP_WS/console1500.js" <<'EOF'
for (let i = 0; i < 1500; i++) console.log(i);
EOF
if out="$(cd "$TMP_WS" && "$BIN" run console1500.js --policy balanced --console-only 2>/dev/null)"; then
  line_count="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  first_line="$(printf '%s\n' "$out" | head -n 1)"
  last_line="$(printf '%s\n' "$out" | tail -n 1)"
  if [[ "$line_count" == "1500" && "$first_line" == "0" && "$last_line" == "1499" ]]; then
    report_case "console_1500_lines" "1" "exit=0 lines=1500 first=0 last=1499"
  else
    report_case "console_1500_lines" "0" "lines=$line_count first=$first_line last=$last_line"
  fi
else
  report_case "console_1500_lines" "0" "run exited non-zero"
fi

# 4. Throw-after-log preserves stdout before uncaught error and exits non-zero
cat >"$TMP_WS/throw_after_log.js" <<'EOF'
console.log("before");
throw new Error("boom");
EOF
set +e
out="$(cd "$TMP_WS" && "$BIN" run throw_after_log.js --policy balanced --console-only 2>/dev/null)"
rc=$?
set -e
if [[ "$rc" -ne 0 && "$out" == "before" ]]; then
  report_case "throw_after_log" "1" "exit=$rc stdout=before"
else
  report_case "throw_after_log" "0" "exit=$rc stdout=$out"
fi

# 5. process.exit(3) -> exit code 3
cat >"$TMP_WS/exit3.js" <<'EOF'
process.exit(3);
EOF
set +e
(cd "$TMP_WS" && "$BIN" run exit3.js --policy balanced --console-only >/dev/null 2>&1)
rc=$?
set -e
if [[ "$rc" -eq 3 ]]; then
  report_case "process_exit_3" "1" "exit=3"
else
  report_case "process_exit_3" "0" "expected exit=3 got exit=$rc"
fi

# 6. Benign strict-profile workload (console.log + JSON.stringify + path.join) -> exit 0
cat >"$TMP_WS/strict_hello.js" <<'EOF'
const path = require("path");
console.log("hello", JSON.stringify({ ok: true }), path.join("a", "b"));
EOF
if out="$(cd "$TMP_WS" && "$BIN" run strict_hello.js --policy strict --console-only 2>/dev/null)" \
  && [[ "$out" == 'hello {"ok":true} a/b' ]]; then
  report_case "strict_hello_json_path" "1" "exit=0 stdout=$out"
else
  report_case "strict_hello_json_path" "0" "stdout=${out:-err}"
fi

echo "Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
[[ "$FAIL_COUNT" -eq 0 ]]
