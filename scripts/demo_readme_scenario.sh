#!/usr/bin/env bash
# bd-reality-20260923-26n9r.15 — Step-by-step hermetic replay of the opening
# README trust scenario + package source inventory and host-effect candidates.
set -euo pipefail

BIN="${FRANKEN_NODE_BIN:-target/release/franken-node}"
if [[ ! -x "$BIN" ]]; then
  echo "ERROR: franken-node binary not found or not executable at $BIN" >&2
  exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

PASS_COUNT=0
FAIL_COUNT=0

report_step() {
  local name="$1"
  local ok="$2"
  local detail="$3"
  if [[ "$ok" == "1" ]]; then
    printf '[PASS] %-36s %s\n' "$name" "$detail"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf '[FAIL] %-36s %s\n' "$name" "$detail"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

TMP_WS="$(mktemp -d "${TMPDIR:-/tmp}/fn-demo-readme-scenario.XXXXXX")"

python3 - "$TMP_WS" <<'PY'
import base64, datetime, hashlib, json, os, pathlib, sys

root = pathlib.Path(sys.argv[1])

def sri(seed: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(seed).digest()).decode()

cfg_sri = sri(b"config-loader@1.0.0")
exp_sri = sri(b"expresss@4.0.0")
tel_sri = sri(b"telemetry-drift@0.0.5")

(root / "package.json").write_text(json.dumps({
    "name": "readme-scenario-app",
    "version": "1.0.0",
    "dependencies": {
        "config-loader": "1.0.0",
        "expresss": "4.0.0",
        "telemetry-drift": "0.0.5",
    },
}, indent=2))

(root / "package-lock.json").write_text(json.dumps({
    "name": "readme-scenario-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "readme-scenario-app",
            "version": "1.0.0",
            "dependencies": {
                "config-loader": "1.0.0",
                "expresss": "4.0.0",
                "telemetry-drift": "0.0.5",
            },
        },
        "node_modules/config-loader": {"version": "1.0.0", "integrity": cfg_sri},
        "node_modules/expresss": {"version": "4.0.0", "integrity": exp_sri},
        "node_modules/telemetry-drift": {"version": "0.0.5", "integrity": tel_sri},
    },
}, indent=2))

(root / "app-config.json").write_text('{"env":"prod"}')

def write_pkg(name: str, version: str, code: str) -> None:
    d = root / "node_modules" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps({"name": name, "version": version, "main": "index.js"}, indent=2))
    (d / "index.js").write_text(code)

write_pkg("config-loader", "1.0.0",
          "const fs = require('fs');\nexports.loadConfig = () => JSON.parse(fs.readFileSync('app-config.json', 'utf8'));\n")
write_pkg("expresss", "4.0.0",
          "exports.banner = (env) => 'route:' + env;\n")
write_pkg("telemetry-drift", "0.0.5",
          "const http = require('http');\nexports.ping = () => {\n  const req = http.get('http://169.254.169.254/latest/meta-data/', () => {});\n  req.on('error', () => console.log('telemetry-egress-refused'));\n};\n")

(root / "app.js").write_text(
    "const cfg = require('config-loader').loadConfig();\n"
    "const banner = require('expresss').banner(cfg.env);\n"
    "require('telemetry-drift').ping();\n"
    "console.log(banner);\n"
)

now = datetime.datetime.now(datetime.timezone.utc)
fourteen_d = (now - datetime.timedelta(days=14)).isoformat()
two_y = (now - datetime.timedelta(days=730)).isoformat()

reg = root / "offline-registry"
reg.mkdir(parents=True, exist_ok=True)

(reg / "config-loader.json").write_text(json.dumps({
    "_fixture": "Hermetic offline npm packument: 14-day-old package + sole maintainer.",
    "_hermetic_dependent_count": 3,
    "name": "config-loader",
    "maintainers": [{"name": "newpub", "email": "newpub@example.test"}],
    "time": {"created": fourteen_d, "1.0.0": fourteen_d},
    "versions": {"1.0.0": {"dist": {"integrity": cfg_sri}}},
}, indent=2))

(reg / "expresss.json").write_text(json.dumps({
    "_fixture": "Hermetic offline npm packument: distance-1 typosquat of express.",
    "_hermetic_dependent_count": 0,
    "name": "expresss",
    "maintainers": [{"name": "squatter", "email": "squatter@example.test"}],
    "time": {"created": fourteen_d, "4.0.0": fourteen_d},
    "versions": {"4.0.0": {"dist": {"integrity": exp_sri}}},
}, indent=2))

(reg / "telemetry-drift.json").write_text(json.dumps({
    "_fixture": "Hermetic offline npm packument: 6-release postinstall + bin drift.",
    "_hermetic_dependent_count": 42,
    "name": "telemetry-drift",
    "maintainers": [{"name": "driftmaint", "email": "drift@example.test"}],
    "time": {
        "created": two_y,
        "0.0.0": "2024-01-01T00:00:00.000Z",
        "0.0.1": "2024-02-01T00:00:00.000Z",
        "0.0.2": "2024-03-01T00:00:00.000Z",
        "0.0.3": "2024-04-01T00:00:00.000Z",
        "0.0.4": "2024-05-01T00:00:00.000Z",
        "0.0.5": "2024-06-01T00:00:00.000Z",
    },
    "versions": {
        "0.0.0": {},
        "0.0.1": {"dependencies": {"helper-a": "1.0.0"}},
        "0.0.2": {"dependencies": {"helper-a": "1.0.1"}},
        "0.0.3": {"scripts": {"postinstall": "node install.js"}},
        "0.0.4": {"scripts": {"postinstall": "node install.js"}, "bin": {"td": "bin/td.js"}},
        "0.0.5": {"scripts": {"postinstall": "node install.js"}, "bin": {"td": "bin/td.js"}, "dist": {"integrity": tel_sri}},
    },
}, indent=2))
PY

# Step 1: init + hermetic deep scan
if (cd "$TMP_WS" && "$BIN" init --profile balanced --out-dir . >/dev/null 2>&1) \
  && scan_json="$(cd "$TMP_WS" && "$BIN" trust scan . --deep --offline-registry-dir offline-registry --json)" \
  && cfg_card="$(cd "$TMP_WS" && "$BIN" trust card npm:config-loader --json)" \
  && exp_card="$(cd "$TMP_WS" && "$BIN" trust card npm:expresss --json)" \
  && tel_card="$(cd "$TMP_WS" && "$BIN" trust card npm:telemetry-drift --json)" \
  && detail="$(python3 - "$scan_json" "$cfg_card" "$exp_card" "$tel_card" <<'PY'
import json, sys
scan, cfg, exp, tel = [json.loads(x) for x in sys.argv[1:5]]
assert scan["metadata_source"] == "hermetic_fixture"
assert cfg["user_facing_risk_assessment"]["level"] == "medium"
assert "new package: first published" in cfg["user_facing_risk_assessment"]["summary"]
assert exp["user_facing_risk_assessment"]["level"] == "high"
assert "typosquat" in exp["user_facing_risk_assessment"]["summary"]
assert tel["user_facing_risk_assessment"]["level"] == "critical"
assert len(tel["camouflage_hints"]) >= 1
print(f"source={scan['metadata_source']} cfg=medium exp=high(typosquat) tel=critical(camouflage_hints={len(tel['camouflage_hints'])})")
PY
)"; then
  report_step "hermetic_deep_scan_signals" "1" "$detail"
else
  report_step "hermetic_deep_scan_signals" "0" "deep scan card assertions failed"
fi

# Step 2: multi-dependency run (plain balanced + frozen replay capture) + package effect candidates
if plain_json="$(cd "$TMP_WS" && "$BIN" run app.js --policy balanced --json 2>/dev/null)" \
  && run_json="$(cd "$TMP_WS" && "$BIN" run app.js --policy balanced --frozen-modules --capture-replay --json 2>/dev/null)" \
  && detail="$(python3 - "$plain_json" "$run_json" <<'PY'
import json, sys
plain, doc = json.loads(sys.argv[1]), json.loads(sys.argv[2])
for item in (plain, doc):
    pa = item["receipt"]["package_attribution"]
    assert pa["schema_version"] == "franken-node/package-attribution-report/v2"
    assert pa["root_package_id"] == "app:readme-scenario-app@1.0.0"
    effects = pa["effects"]
    assert len(effects) == 2
    assert effects[0]["effect_kind"] == "fs_read" and effects[0]["outcome"] == "allowed"
    assert effects[1]["effect_kind"] == "http_request" and effects[1]["outcome"] == "denied"
    packages = {package["package_id"]: package for package in pa["packages"]}
    for effect, importer in zip(effects, ("npm:config-loader@1.0.0", "npm:telemetry-drift@0.0.5")):
        assert effect["attribution_basis"] == "candidate_loaded_packages"
        assert effect.get("attributed_package") is None
        assert effect["capability_importing_packages"] == [importer]
        assert importer in effect["candidate_packages"]
        assert pa["root_package_id"] in effect["candidate_packages"]
        for candidate in effect["candidate_packages"]:
            assert effect["seq"] in packages[candidate]["candidate_effect_seqs"]
    for package in packages.values():
        assert package["manifest_identity"]["status"] == "captured"
        assert package["exact_effect_seqs"] == []
        assert package["allowed_effects"] == package["denied_effects"] == package["failed_effects"] == 0
print(f"receipt={doc['receipt']['receipt_id']} fs_read=allowed(import hint:config-loader) http_request=denied(import hint:telemetry-drift) caller=unknown")
PY
)"; then
  receipt_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["receipt"]["receipt_id"])' "$run_json")"
  report_step "per_package_effect_attribution" "1" "$detail"
else
  receipt_id=""
  report_step "per_package_effect_attribution" "0" "run or package_attribution check failed"
fi

# Step 3: strict preflight refusal on high-risk dependency
set +e
strict_json="$(cd "$TMP_WS" && "$BIN" run app.js --policy strict --json 2>/dev/null)"
strict_rc=$?
set -e
if [[ "$strict_rc" -ne 0 ]] && python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["verdict"]["status"]=="blocked" and d["receipt"]["decision"]=="denied"' "$strict_json"; then
  report_step "strict_preflight_blocks_high_risk" "1" "exit=$strict_rc verdict=blocked decision=denied"
else
  report_step "strict_preflight_blocks_high_risk" "0" "expected non-zero blocked preflight, got exit=$strict_rc"
fi

# Step 4: trust revoke + balanced preflight refusal
set +e
(cd "$TMP_WS" && "$BIN" trust revoke npm:telemetry-drift --json >/dev/null 2>&1)
rev_rc=$?
(cd "$TMP_WS" && "$BIN" run app.js --policy balanced --json >/dev/null 2>&1)
bal_after_rev_rc=$?
set -e
if [[ "$rev_rc" -eq 0 && "$bal_after_rev_rc" -ne 0 ]]; then
  report_step "revoke_blocks_balanced_preflight" "1" "revoke_exit=0 post_revoke_run_exit=$bal_after_rev_rc"
else
  report_step "revoke_blocks_balanced_preflight" "0" "revoke_exit=$rev_rc post_revoke_run_exit=$bal_after_rev_rc"
fi

# Step 5: verify transparency-log over durable signed evidence ledger
if ledger_json="$(cd "$TMP_WS" && "$BIN" verify transparency-log .franken-node/state/evidence-ledger.db --public-key .franken-node/keys/receipt-signing.pub --json 2>/dev/null)" \
  && detail="$(python3 - "$ledger_json" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d["status"] == "valid" and d["signatures_verified"] is True and d["total_entries"] >= 4
print(f"status={d['status']} entries={d['total_entries']} signatures_verified=True")
PY
)"; then
  report_step "evidence_ledger_verified" "1" "$detail"
else
  report_step "evidence_ledger_verified" "0" "transparency-log verification failed"
fi

# Step 6: incident bundle + native replay --execute + counterfactual --policy strict
if [[ -n "$receipt_id" ]] \
  && cap_json="$(cd "$TMP_WS" && "$BIN" incident capture --from-run "$receipt_id" --json 2>/dev/null)" \
  && inc_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["incident_id"])' "$cap_json")" \
  && (cd "$TMP_WS" && "$BIN" incident bundle --id "$inc_id" --verify --json >/dev/null 2>&1) \
  && replay_json="$(cd "$TMP_WS" && "$BIN" incident replay --bundle "${inc_id}.fnbundle" --execute --trusted-public-key .franken-node/keys/receipt-signing.pub --json 2>/dev/null)" \
  && (cd "$TMP_WS" && "$BIN" incident counterfactual --bundle "${inc_id}.fnbundle" --trusted-public-key .franken-node/keys/receipt-signing.pub --policy strict >/dev/null 2>&1) \
  && detail="$(python3 - "$replay_json" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d["replay_result"]["matched"] is True and d["execution_result"]["matched"] is True
print(f"incident={d['incident_id']} replay_matched=True scope={d['execution_result']['verification_scope']}")
PY
)"; then
  report_step "incident_bundle_replay_counterfactual" "1" "$detail"
else
  report_step "incident_bundle_replay_counterfactual" "0" "incident bundle/replay/counterfactual failed"
fi

echo "Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
[[ "$FAIL_COUNT" -eq 0 ]]
