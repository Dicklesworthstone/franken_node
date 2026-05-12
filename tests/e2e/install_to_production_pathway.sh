#!/usr/bin/env bash
# bd-34d5 current-reality boundary sentinel.
#
# This script intentionally does not prove the future full target pathway.
# It verifies that the section-13 checker and timing report preserve the
# current-reality boundary for the unshipped install-to-production target.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 scripts/check_friction_pathway.py --json >/dev/null

python3 - <<'PY'
import json
from pathlib import Path

root = Path.cwd()
report_path = root / "artifacts" / "13" / "onboarding_timing_report.json"
report = json.JSONDecoder().decode(report_path.read_text(encoding="utf-8"))

expected_setups = {
    "macos_npm",
    "linux_npm",
    "windows_npm",
    "docker_container",
    "github_actions_ci",
}
observed = {entry["setup_id"] for entry in report["setup_results"]}

if report["bead_id"] != "bd-34d5":
    raise SystemExit("onboarding timing report is not bound to bd-34d5")
if report["target_pathway_shipped"] is not False:
    raise SystemExit("target_pathway_shipped must remain false until the full pathway ships")
if report["claimed_full_e2e_success"] is not False:
    raise SystemExit("report must not claim full e2e success")
if observed != expected_setups:
    raise SystemExit(f"setup inventory mismatch: {sorted(observed ^ expected_setups)}")
for entry in report["setup_results"]:
    if entry["status"] != "not_measured_target_unshipped":
        raise SystemExit(f"unexpected setup status for {entry['setup_id']}: {entry['status']}")
    if entry["target_total_elapsed_seconds"] is not None:
        raise SystemExit(f"target timing overclaimed for {entry['setup_id']}")

print("bd-34d5 current-reality pathway sentinel: PASS")
PY
