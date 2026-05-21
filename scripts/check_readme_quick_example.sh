#!/usr/bin/env bash
# scripts/check_readme_quick_example.sh
# ============================================================================
# CI smoke test for the README's "Quick Example" operator workflow.
#
# Runs the documented Day-0 commands end-to-end on a throwaway tempdir to
# catch operator-on-ramp regressions before they ship. Every check below
# corresponds to a real bug fixed during the 2026-05-20 reality-check bridge
# plan:
#
#   1. `init` on an empty directory must succeed (the bootstrap surface; the
#      pre-bridge-plan binary failed here on `trust.registry_signing_key must
#      be configured`).
#   2. The config init writes must round-trip through `Config::resolve` (the
#      pre-bridge-plan binary wrote `[security.network_policy]` but
#      `SecurityOverrides` rejected `network_policy` on read-back).
#   3. `trust scan` on a project must produce trust cards (the pre-bridge-plan
#      binary errored on `registry_signing_key must be configured` even when
#      the operator had a valid cwd config).
#   4. `trust list` must read the freshly-created registry (the pre-bridge-plan
#      binary errored on `trust-card registry high-water signature mismatch`
#      because init signed with `DEFAULT_REGISTRY_KEY` and trust list verified
#      with the operator's key).
#   5. `registry publish --help` must not panic (pre-bridge-plan: clap
#      assertion `version is in use by more than one argument` aborted the
#      binary on every invocation).
#   6. `incident list --json` must accept the flag (pre-bridge-plan: rejected
#      with "unexpected argument '--json'").
#   7. `ops validation-readiness <path>` must accept the positional input
#      form documented in the README.
#   8. `verify recovery-runbook --readiness-input <path>` must accept the
#      long-flag form documented in the README.
#
# Exit codes:
#   0  — all checks passed
#   1  — one or more checks failed (details on stderr)
#
# Usage:
#   scripts/check_readme_quick_example.sh [path/to/franken-node]
#
# When called with no argument, defaults to ./target/debug/franken-node.
# ============================================================================
set -euo pipefail

BIN="${1:-./target/debug/franken-node}"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: franken-node binary not found or not executable: $BIN" >&2
  echo "       build with: cargo build -p frankenengine-node --bin franken-node" >&2
  exit 1
fi

# Resolve to absolute path so subsequent `cd` calls don't break it.
BIN="$(realpath "$BIN")"
readonly BIN

# Each check appends its result here (PASS|FAIL|description). We never abort
# mid-run so the operator sees every failure, not just the first.
declare -a RESULTS=()

record() {
  local status="$1"
  local name="$2"
  RESULTS+=("$status|$name")
  if [[ "$status" == "PASS" ]]; then
    echo "  [PASS] $name"
  else
    echo "  [FAIL] $name" >&2
  fi
}

# Use a fresh tempdir per run so we never collide with prior state. The
# `dcg`-style destructive-command guard in some agent harnesses blocks
# `rm -rf`, so we let the OS clean tempdirs up via natural expiration.
SMOKE_DIR="$(mktemp -d -t franken-node-quick-example.XXXXXX)"
trap 'echo; echo "smoke dir was: $SMOKE_DIR (manual cleanup if desired)"' EXIT
cd "$SMOKE_DIR"

echo "== franken-node README Quick Example smoke test =="
echo "   binary:    $BIN"
echo "   smoke dir: $SMOKE_DIR"
echo

# ---------------------------------------------------------------------------
# Check 1: init on empty directory
# ---------------------------------------------------------------------------
echo "[1] init --profile balanced --out-dir . --json"
init_out="$("$BIN" init --profile balanced --out-dir . --json 2>&1 || true)"
if grep -q '"command": *"init"' <<<"$init_out"; then
  # Confirm synthesis is reported.
  if grep -q '"registry_signing_key_generated": *true' <<<"$init_out"; then
    record PASS "init reports synthesized registry signing key"
  else
    record FAIL "init succeeded but did not report bootstrap_synthesis"
  fi
else
  echo "  init output: $init_out" >&2
  record FAIL "init failed to emit JSON command=init"
fi

# ---------------------------------------------------------------------------
# Check 2: written config round-trips through Config::resolve
# ---------------------------------------------------------------------------
echo "[2] doctor reads the init-written config"
if "$BIN" doctor --json >/dev/null 2>doctor.err; then
  record PASS "doctor accepts init's config (round-trip)"
else
  echo "  doctor stderr: $(head -3 doctor.err)" >&2
  record FAIL "doctor rejected init's config"
fi

# ---------------------------------------------------------------------------
# Check 3: trust scan against a real npm-style app
# ---------------------------------------------------------------------------
echo "[3] trust scan ./app"
mkdir -p app
cat > app/package.json <<'EOF'
{
  "name": "fnode-smoke-app",
  "version": "1.0.0",
  "dependencies": { "lodash": "^4.17.21" }
}
EOF
if scan_out="$("$BIN" trust scan ./app 2>&1)" && grep -q "trust scan completed" <<<"$scan_out"; then
  if grep -q "created npm:lodash" <<<"$scan_out"; then
    record PASS "trust scan created a card for the lodash dependency"
  else
    record FAIL "trust scan ran but did not create the expected card"
  fi
else
  echo "  trust scan output: $scan_out" >&2
  record FAIL "trust scan errored on a fresh project"
fi

# ---------------------------------------------------------------------------
# Check 4: trust list reads the registry trust scan just wrote
# ---------------------------------------------------------------------------
echo "[4] trust list (inside ./app)"
if list_out="$(cd app && "$BIN" trust list 2>&1)" && grep -q "npm:lodash" <<<"$list_out"; then
  record PASS "trust list shows the scan-created card"
else
  echo "  trust list output: $list_out" >&2
  record FAIL "trust list could not read the registry created by scan"
fi

# ---------------------------------------------------------------------------
# Check 5: registry publish --help must not panic
# ---------------------------------------------------------------------------
echo "[5] registry publish --help (must not panic)"
if pub_help="$("$BIN" registry publish --help 2>&1)" && grep -q "Publish signed extension artifact" <<<"$pub_help"; then
  record PASS "registry publish --help renders without panic"
else
  echo "  registry publish --help output: $pub_help" >&2
  record FAIL "registry publish --help panicked or did not render"
fi

# ---------------------------------------------------------------------------
# Check 6: incident list --json
# ---------------------------------------------------------------------------
echo "[6] incident list --json on empty workspace"
if il_out="$("$BIN" incident list --json 2>&1)" && grep -q '"command": *"incident.list"' <<<"$il_out"; then
  record PASS "incident list --json emits canonical JSON on an empty workspace"
else
  echo "  incident list --json output: $il_out" >&2
  record FAIL "incident list --json failed or did not emit canonical JSON"
fi

# ---------------------------------------------------------------------------
# Check 7: ops validation-readiness with positional input
# ---------------------------------------------------------------------------
echo "[7] ops validation-readiness <path> (positional)"
echo '{}' > snap.json
if ovr_out="$("$BIN" ops validation-readiness snap.json --json 2>&1)" && grep -q '"command": *"ops validation-readiness"' <<<"$ovr_out"; then
  record PASS "ops validation-readiness accepts positional input"
else
  echo "  output: $ovr_out" >&2
  record FAIL "ops validation-readiness rejected positional input"
fi

# ---------------------------------------------------------------------------
# Check 8: verify recovery-runbook --readiness-input
# ---------------------------------------------------------------------------
echo "[8] verify recovery-runbook --readiness-input <path>"
if vrr_out="$("$BIN" verify recovery-runbook --readiness-input snap.json 2>&1)" && grep -q "RCH Validation Recovery Runbook" <<<"$vrr_out"; then
  record PASS "verify recovery-runbook accepts --readiness-input long-flag form"
else
  echo "  output: $vrr_out" >&2
  record FAIL "verify recovery-runbook rejected --readiness-input"
fi

# ---------------------------------------------------------------------------
# Aggregate result
# ---------------------------------------------------------------------------
echo
echo "== summary =="
pass=0; fail=0
for r in "${RESULTS[@]}"; do
  status="${r%%|*}"
  if [[ "$status" == "PASS" ]]; then pass=$((pass+1)); else fail=$((fail+1)); fi
done
total=$((pass+fail))
echo "   total=$total pass=$pass fail=$fail"

if (( fail > 0 )); then
  echo "   smoke FAILED" >&2
  exit 1
fi
echo "   smoke OK"
