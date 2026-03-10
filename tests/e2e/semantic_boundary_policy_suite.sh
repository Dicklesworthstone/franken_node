#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/asupersync/bd-1now.5.3"
STAGES_DIR="${OUT_DIR}/stage_outputs"
LOG_JSONL="${OUT_DIR}/semantic_boundary_e2e_log.jsonl"
RESULTS_JSONL="${OUT_DIR}/semantic_boundary_stage_results.jsonl"
SUMMARY_JSON="${OUT_DIR}/semantic_boundary_e2e_summary.json"
BUNDLE_JSON="${OUT_DIR}/semantic_boundary_e2e_bundle.json"
SUMMARY_MD="${OUT_DIR}/semantic_boundary_e2e_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-1now-5-3-semantic-boundary-e2e}"
WORK_DIR="${OUT_DIR}/workspaces/${TRACE_ID}"

mkdir -p "${OUT_DIR}" "${STAGES_DIR}" "${WORK_DIR}"
: > "${LOG_JSONL}"
: > "${RESULTS_JSONL}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required" >&2
  exit 2
fi

log_event() {
  local event_code="$1"
  local case_id="$2"
  local status="$3"
  local detail="$4"
  local rule_id="${5:-}"
  local reason_code="${6:-}"

  python3 - "$LOG_JSONL" "$TRACE_ID" "$event_code" "$case_id" "$status" "$detail" "$rule_id" "$reason_code" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "trace_id": sys.argv[2],
    "event_code": sys.argv[3],
    "case_id": sys.argv[4],
    "status": sys.argv[5],
    "detail": sys.argv[6],
    "rule_id": sys.argv[7] or None,
    "reason_code": sys.argv[8] or None,
}
with path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(payload) + "\n")
PY
}

prepare_case_root() {
  local case_id="$1"
  local case_root="${WORK_DIR}/${case_id}"

  mkdir -p \
    "${case_root}/scripts/lib" \
    "${case_root}/docs/architecture" \
    "${case_root}/crates/franken-node/src"

  cp "${ROOT_DIR}/scripts/check_ownership_violations.py" \
    "${case_root}/scripts/check_ownership_violations.py"
  cp "${ROOT_DIR}/scripts/lib/test_logger.py" \
    "${case_root}/scripts/lib/test_logger.py"
  cp "${ROOT_DIR}/docs/capability_ownership_registry.json" \
    "${case_root}/docs/capability_ownership_registry.json"
  cp "${ROOT_DIR}/docs/architecture/tri_kernel_ownership_contract.md" \
    "${case_root}/docs/architecture/tri_kernel_ownership_contract.md"

  echo "${case_root}"
}

write_case_source() {
  local case_root="$1"
  local relative_path="$2"
  local content="$3"

  mkdir -p "${case_root}/$(dirname "${relative_path}")"
  printf '%s\n' "${content}" > "${case_root}/${relative_path}"
}

run_case() {
  local case_id="$1"
  local category="$2"
  local expected_exit="$3"
  local expected_verdict="$4"
  local expected_rule_id="$5"
  local expected_reason_code="$6"
  local source_relative_path="$7"
  local source_content="$8"

  local stdout_path="${STAGES_DIR}/${case_id}.stdout.json"
  local stderr_path="${STAGES_DIR}/${case_id}.stderr.log"
  local case_root
  case_root="$(prepare_case_root "${case_id}")"

  write_case_source "${case_root}" "${source_relative_path}" "${source_content}"
  log_event "SBP-E2E-010" "${case_id}" "start" "case start" "${expected_rule_id}" "${expected_reason_code}"

  set +e
  (
    cd "${case_root}"
    python3 scripts/check_ownership_violations.py --json
  ) >"${stdout_path}" 2>"${stderr_path}"
  local actual_exit=$?
  set -e

  python3 - "${RESULTS_JSONL}" "${case_id}" "${category}" "${expected_exit}" "${actual_exit}" "${expected_verdict}" "${expected_rule_id}" "${expected_reason_code}" "${stdout_path}" "${stderr_path}" "${case_root}" <<'PY'
import json
import sys
from pathlib import Path

results_path = Path(sys.argv[1])
case_id = sys.argv[2]
category = sys.argv[3]
expected_exit = int(sys.argv[4])
actual_exit = int(sys.argv[5])
expected_verdict = sys.argv[6]
expected_rule_id = sys.argv[7]
expected_reason_code = sys.argv[8]
stdout_path = Path(sys.argv[9])
stderr_path = Path(sys.argv[10])
case_root = Path(sys.argv[11])

payload = json.loads(stdout_path.read_text(encoding="utf-8"))
violations = payload.get("violations", [])
rule_ids = [item.get("rule_id") for item in violations]
reason_codes = [item.get("reason_code") for item in violations]

status = "pass"
if actual_exit != expected_exit:
    status = "fail"
elif payload.get("verdict") != expected_verdict:
    status = "fail"
elif expected_rule_id and expected_rule_id not in rule_ids:
    status = "fail"
elif expected_reason_code and expected_reason_code not in reason_codes:
    status = "fail"

record = {
    "case_id": case_id,
    "category": category,
    "expected_exit": expected_exit,
    "actual_exit": actual_exit,
    "expected_verdict": expected_verdict,
    "actual_verdict": payload.get("verdict"),
    "expected_rule_id": expected_rule_id or None,
    "actual_rule_ids": rule_ids,
    "expected_reason_code": expected_reason_code or None,
    "actual_reason_codes": reason_codes,
    "status": status,
    "stdout_path": stdout_path.as_posix(),
    "stderr_path": stderr_path.as_posix(),
    "workspace": case_root.as_posix(),
    "schema_version": payload.get("schema_version"),
    "category_counts": payload.get("category_counts", {}),
    "violations": violations,
}
with results_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record) + "\n")

if status != "pass":
    print(json.dumps(record, indent=2))
    raise SystemExit(1)
PY

  log_event "SBP-E2E-020" "${case_id}" "pass" "case pass" "${expected_rule_id}" "${expected_reason_code}"
}

log_event "SBP-E2E-001" "suite" "start" "starting semantic-boundary e2e suite"

run_case \
  "allowed_local_model_region_tree" \
  "allow" \
  "0" \
  "PASS" \
  "" \
  "" \
  "crates/franken-node/src/runtime/region_tree.rs" \
  $'pub struct RegionTree;\n'

run_case \
  "allowed_canonical_alignment_cancellation" \
  "allow" \
  "0" \
  "PASS" \
  "" \
  "" \
  "crates/franken-node/src/control_plane/cancellation_protocol.rs" \
  $'pub struct CancellationProtocol;\n'

run_case \
  "forbidden_duplicate_family_runtime_cancellation" \
  "deny" \
  "1" \
  "FAIL" \
  "OWN-SEMB-002" \
  "UNDOCUMENTED_SEMANTIC_FAMILY" \
  "crates/franken-node/src/runtime/cancellation_protocol.rs" \
  $'pub struct RuntimeCancellationProtocol;\n'

run_case \
  "forbidden_internal_boundary_crossing" \
  "deny" \
  "1" \
  "FAIL" \
  "OWN-SEMB-003" \
  "FORBIDDEN_INTERNAL_BOUNDARY_CROSSING" \
  "crates/franken-node/src/control_plane/internal_boundary_probe.rs" \
  $'use franken_engine::scheduler_internal::Queue;\n\npub fn probe() {}\n'

python3 - <<'PY' "${ROOT_DIR}" "${RESULTS_JSONL}" "${LOG_JSONL}" "${SUMMARY_JSON}" "${BUNDLE_JSON}" "${SUMMARY_MD}" "${TRACE_ID}"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
results_path = Path(sys.argv[2])
log_path = Path(sys.argv[3])
summary_path = Path(sys.argv[4])
bundle_path = Path(sys.argv[5])
summary_md_path = Path(sys.argv[6])
trace_id = sys.argv[7]

results = [
    json.loads(line)
    for line in results_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
logs = [
    json.loads(line)
    for line in log_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

required_case_ids = [
    "allowed_local_model_region_tree",
    "allowed_canonical_alignment_cancellation",
    "forbidden_duplicate_family_runtime_cancellation",
    "forbidden_internal_boundary_crossing",
]
required_rule_ids = ["OWN-SEMB-002", "OWN-SEMB-003"]
required_reason_codes = [
    "UNDOCUMENTED_SEMANTIC_FAMILY",
    "FORBIDDEN_INTERNAL_BOUNDARY_CROSSING",
]

case_ids = [row["case_id"] for row in results]
missing_case_ids = [case_id for case_id in required_case_ids if case_id not in case_ids]
pass_count = sum(1 for row in results if row["status"] == "pass")
fail_count = len(results) - pass_count

rule_ids = sorted({rule_id for row in results for rule_id in row.get("actual_rule_ids", []) if rule_id})
reason_codes = sorted({reason for row in results for reason in row.get("actual_reason_codes", []) if reason})
missing_rule_ids = [rule_id for rule_id in required_rule_ids if rule_id not in rule_ids]
missing_reason_codes = [reason for reason in required_reason_codes if reason not in reason_codes]

verdict = "PASS"
if fail_count > 0 or missing_case_ids or missing_rule_ids or missing_reason_codes:
    verdict = "FAIL"

summary = {
    "schema_version": "semantic-boundary-e2e-v1",
    "bead_id": "bd-1now.5.3",
    "trace_id": trace_id,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "case_count": len(results),
    "pass_count": pass_count,
    "fail_count": fail_count,
    "required_case_ids": required_case_ids,
    "required_rule_ids": required_rule_ids,
    "required_reason_codes": required_reason_codes,
    "observed_rule_ids": rule_ids,
    "observed_reason_codes": reason_codes,
    "missing_case_ids": missing_case_ids,
    "missing_rule_ids": missing_rule_ids,
    "missing_reason_codes": missing_reason_codes,
    "log_jsonl": str(log_path.relative_to(root)),
    "stage_results_jsonl": str(results_path.relative_to(root)),
    "cases": results,
    "verdict": verdict,
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

bundle = {
    "schema_version": "semantic-boundary-e2e-bundle-v1",
    "bead_id": "bd-1now.5.3",
    "trace_id": trace_id,
    "generated_at": summary["generated_at"],
    "summary_json": str(summary_path.relative_to(root)),
    "log_jsonl": str(log_path.relative_to(root)),
    "stage_results_jsonl": str(results_path.relative_to(root)),
    "artifact_dir": "artifacts/asupersync/bd-1now.5.3",
    "scripts": [
        "tests/e2e/semantic_boundary_policy_suite.sh",
        "scripts/check_ownership_violations.py",
    ],
    "required_rule_ids": required_rule_ids,
    "required_reason_codes": required_reason_codes,
    "verdict": verdict,
}
bundle_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

summary_md_path.write_text(
    "\n".join(
        [
            "# Semantic Boundary E2E Summary",
            "",
            f"- trace_id: `{trace_id}`",
            f"- case_count: `{len(results)}`",
            f"- pass_count: `{pass_count}`",
            f"- fail_count: `{fail_count}`",
            f"- verdict: `{verdict}`",
            f"- summary_json: `{summary_path.relative_to(root)}`",
            f"- bundle_json: `{bundle_path.relative_to(root)}`",
            f"- log_jsonl: `{log_path.relative_to(root)}`",
            f"- stage_results_jsonl: `{results_path.relative_to(root)}`",
            "",
            "## Covered Cases",
            "",
            "- `allowed_local_model_region_tree`",
            "- `allowed_canonical_alignment_cancellation`",
            "- `forbidden_duplicate_family_runtime_cancellation`",
            "- `forbidden_internal_boundary_crossing`",
            "",
            "## Stable Rule Coverage",
            "",
            "- `OWN-SEMB-002` / `UNDOCUMENTED_SEMANTIC_FAMILY`",
            "- `OWN-SEMB-003` / `FORBIDDEN_INTERNAL_BOUNDARY_CROSSING`",
        ]
    )
    + "\n",
    encoding="utf-8",
)
PY

log_event "SBP-E2E-999" "suite" "pass" "semantic-boundary e2e suite complete"
echo "semantic-boundary e2e suite PASS"
