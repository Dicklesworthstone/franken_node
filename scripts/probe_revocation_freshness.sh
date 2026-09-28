#!/usr/bin/env bash
# Live probe for bd-reality-20260923-26n9r.1 (CLAIM-006, revocation-first
# execution). Drives a real franken-node binary through default `init`
# workspaces that declare one dependency with a trusted card:
#
#   A  signed frontier just recorded by `trust sync --force` -> strict preflight passes
#   B  the same frontier once older than strict's 300s       -> strict BLOCKED (RF_STALE_FRONTIER);
#                                                               balanced passes with a warning
#   C  no frontier ever recorded                              -> strict BLOCKED
#
# B waits out the strict max age for real (FRANKEN_NODE_PROBE_WAIT_SECS,
# default 305): the binary deliberately has no clock override. A frontier
# signed with a foreign key is covered by the integration test
# trust_cli_e2e::run_revocation_frontier_is_signed_data_that_gates_strict_runs.
#
# Usage: scripts/probe_revocation_freshness.sh [path/to/franken-node]
# Prints PASS/FAIL per case and exits 0 only when every case passes. The
# scratch workspaces are left in place for inspection; the path is printed.
set -u

BIN=${1:-franken-node}
WAIT_SECS=${FRANKEN_NODE_PROBE_WAIT_SECS:-305}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/probe-revocation-freshness.XXXXXX") || exit 2
failures=0
echo "probe workspaces: $WORK (binary: $BIN)"

report() { # case ok detail
    if [ "$2" = ok ]; then
        echo "PASS $1: $3"
    else
        echo "FAIL $1: $3"
        failures=$((failures + 1))
    fi
}

# A workspace with a config, an empty registry, optionally a frontier recorded
# while the registry is still empty (no network needed), then one dependency
# scanned into a trusted card.
make_workspace() { # dir sync(yes|no)
    mkdir -p "$1" || return 1
    (
        cd "$1" || exit 1
        "$BIN" init --profile balanced --out-dir . >init.log 2>&1 || exit 1
        if [ "$2" = yes ]; then
            "$BIN" trust sync --force >sync.log 2>&1 || exit 1
        fi
        cat >package.json <<'JSON'
{"name": "probe-revocation-freshness", "version": "1.0.0", "main": "index.js",
 "dependencies": {"react": "^19.2.0"}}
JSON
        cat >package-lock.json <<'JSON'
{"name": "probe-revocation-freshness", "lockfileVersion": 3, "packages": {
  "": {"name": "probe-revocation-freshness", "version": "1.0.0"},
  "node_modules/react": {"version": "19.2.4", "integrity": "sha512-AQIDBA=="}}}
JSON
        echo 'console.log("probe");' >index.js
        "$BIN" trust scan . --json >scan.log 2>&1 || exit 1
    )
}

# Preflight verdict status of `run --policy <policy> --json .`, plus the
# violation kinds and warnings, as one line: "<status>|<kinds>|<warnings>".
preflight() { # dir policy
    (cd "$1" && "$BIN" run --policy "$2" --json . 2>"run-$2.stderr" >"run-$2.json")
    python3 - "$1/run-$2.json" <<'PY'
import json, sys
try:
    payload = json.load(open(sys.argv[1]))
except Exception as error:
    print(f"unparseable|{error}|")
    sys.exit(0)
verdict = payload.get("preflight", {}).get("verdict") or payload.get("verdict") or {}
kinds = ",".join(v.get("kind", "") + ":" + v.get("detail", "") for v in verdict.get("violations", []))
print(f"{verdict.get('status', 'missing')}|{kinds}|{' ; '.join(verdict.get('warnings', []))}")
PY
}

if ! make_workspace "$WORK/synced" yes; then
    echo "FAIL setup: could not bootstrap $WORK/synced (see its *.log)"
    exit 1
fi
if ! make_workspace "$WORK/never-synced" no; then
    echo "FAIL setup: could not bootstrap $WORK/never-synced (see its *.log)"
    exit 1
fi

result=$(preflight "$WORK/synced" strict)
case $result in
    passed\|*) report A ok "strict preflight passed behind a fresh signed frontier" ;;
    *) report A fail "strict preflight should pass behind a fresh frontier, got: $result" ;;
esac

echo "waiting ${WAIT_SECS}s for the frontier to age past strict's 300s max age ..."
sleep "$WAIT_SECS"
result=$(preflight "$WORK/synced" strict)
case $result in
    blocked\|*revocation_stale*RF_STALE_FRONTIER*) report B ok "strict preflight BLOCKED behind a stale frontier: ${result#blocked|}" ;;
    *) report B fail "strict preflight should be blocked (revocation_stale), got: $result" ;;
esac
result=$(preflight "$WORK/synced" balanced)
case $result in
    passed\|*RF_STALE_FRONTIER*) report B-balanced ok "balanced admits with a stale-frontier warning" ;;
    *) report B-balanced fail "balanced should pass with an RF_STALE_FRONTIER warning, got: $result" ;;
esac

result=$(preflight "$WORK/never-synced" strict)
case $result in
    blocked\|*revocation_stale*"no revocation frontier"*) report C ok "strict preflight BLOCKED with no frontier recorded" ;;
    *) report C fail "strict preflight should be blocked with no frontier, got: $result" ;;
esac

echo "probe complete: $failures failure(s)"
[ "$failures" -eq 0 ]
