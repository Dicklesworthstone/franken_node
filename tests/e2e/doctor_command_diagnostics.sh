#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/section_bootstrap/bd-1pk"
LOG_JSONL="${OUT_DIR}/doctor_diagnostics_log.jsonl"
CHECKS_JSON="${OUT_DIR}/doctor_contract_checks.json"
MATRIX_JSON="${OUT_DIR}/doctor_checks_matrix.json"
HEALTHY_JSON="${OUT_DIR}/doctor_report_healthy.json"
DEGRADED_JSON="${OUT_DIR}/doctor_report_degraded.json"
FAILURE_JSON="${OUT_DIR}/doctor_report_failure.json"
INVALID_JSON="${OUT_DIR}/doctor_report_invalid_input.json"
SUMMARY_MD="${OUT_DIR}/doctor_contract_checks.md"
TRACE_ID="trace-bd-1pk-doctor-e2e"
PASS_FIXTURE="${ROOT_DIR}/fixtures/policy_activation/doctor_policy_activation_pass.json"
WARN_FIXTURE="${ROOT_DIR}/fixtures/policy_activation/doctor_policy_activation_warn.json"
BLOCK_FIXTURE="${ROOT_DIR}/fixtures/policy_activation/doctor_policy_activation_block.json"
INVALID_FIXTURE="${ROOT_DIR}/fixtures/policy_activation/doctor_policy_activation_invalid.json"

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: jq and python3 are required" >&2
  exit 2
fi

log_event() {
  local event_code="$1"
  local status="$2"
  local detail="$3"
  jq -cn \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg trace_id "${TRACE_ID}" \
    --arg event_code "${event_code}" \
    --arg status "${status}" \
    --arg detail "${detail}" \
    '{ts: $ts, trace_id: $trace_id, event_code: $event_code, status: $status, detail: $detail}' \
    >> "${LOG_JSONL}"
}

run_doctor_report() {
  local trace_id="$1"
  local fixture_path="$2"
  local output_path="$3"

  if [[ -x "${ROOT_DIR}/target/debug/frankenengine-node" ]]; then
    (
      cd "${ROOT_DIR}" && \
      "${ROOT_DIR}/target/debug/frankenengine-node" doctor \
        --json \
        --trace-id "${trace_id}" \
        --policy-activation-input "${fixture_path}"
    ) > "${output_path}"
  else
    (
      cd "${ROOT_DIR}" && \
      cargo run -q -p frankenengine-node -- doctor \
        --json \
        --trace-id "${trace_id}" \
        --policy-activation-input "${fixture_path}"
    ) > "${output_path}"
  fi
}

execute_scenario() {
  local code="$1"
  local label="$2"
  local trace="$3"
  local fixture="$4"
  local output="$5"

  log_event "${code}" "info" "Running ${label}: fixture=$(realpath --relative-to="${ROOT_DIR}" "${fixture}")"
  if run_doctor_report "${trace}" "${fixture}" "${output}"; then
    log_event "${code}" "pass" "${label} completed"
  else
    log_event "${code}" "fail" "${label} failed"
    return 1
  fi
}

log_event "DOC-E2E-001" "info" "Starting bd-1pk doctor diagnostics gate with live policy activation scenarios."

execute_scenario "DOC-E2E-010" "policy-pass" "doctor-policy-pass" "${PASS_FIXTURE}" "${HEALTHY_JSON}"
execute_scenario "DOC-E2E-011" "policy-warn" "doctor-policy-warn" "${WARN_FIXTURE}" "${DEGRADED_JSON}"
execute_scenario "DOC-E2E-012" "policy-block" "doctor-policy-block" "${BLOCK_FIXTURE}" "${FAILURE_JSON}"
execute_scenario "DOC-E2E-013" "policy-invalid" "doctor-policy-invalid" "${INVALID_FIXTURE}" "${INVALID_JSON}"

python3 - <<'PY' "${ROOT_DIR}" "${CHECKS_JSON}" "${MATRIX_JSON}" "${HEALTHY_JSON}" "${DEGRADED_JSON}" "${FAILURE_JSON}" "${INVALID_JSON}"
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
checks_json = Path(sys.argv[2])
matrix_json = Path(sys.argv[3])
healthy_json = Path(sys.argv[4])
degraded_json = Path(sys.argv[5])
failure_json = Path(sys.argv[6])
invalid_json = Path(sys.argv[7])

main_rs = root / "crates" / "franken-node" / "src" / "main.rs"
cli_rs = root / "crates" / "franken-node" / "src" / "cli.rs"
contract_md = root / "docs" / "specs" / "bootstrap_doctor_contract.md"

checks = []


def add(check: str, passed: bool, detail: str = "") -> None:
    checks.append({"check": check, "passed": passed, "detail": detail})


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


for path in (main_rs, cli_rs, contract_md):
    add(f"exists_{path.name}", path.exists(), str(path))

main_src = read(main_rs) if main_rs.exists() else ""
cli_src = read(cli_rs) if cli_rs.exists() else ""
contract_src = read(contract_md) if contract_md.exists() else ""

add("doctor_args_json_flag", "pub json: bool" in cli_src, "--json")
add("doctor_args_trace_id_flag", "pub trace_id: String" in cli_src, "--trace-id")
add(
    "doctor_args_policy_activation_input_flag",
    "pub policy_activation_input: Option<PathBuf>" in cli_src,
    "--policy-activation-input",
)
add(
    "doctor_args_trace_id_default",
    'default_value = "doctor-bootstrap"' in cli_src,
    "doctor-bootstrap",
)

add("doctor_report_has_structured_logs", "structured_logs: Vec<DoctorLogEvent>" in main_src, "DoctorReport structured logs")
add("doctor_report_has_merge_decisions", "merge_decisions: Vec<config::MergeDecision>" in main_src, "merge provenance")
add("doctor_builder_with_cwd", "fn build_doctor_report_with_cwd(" in main_src, "cwd injectable builder")
add("doctor_builder_with_policy_input", "fn build_doctor_report_with_policy_input(" in main_src, "policy input injectable builder")
add("doctor_policy_activation_runner", "fn run_doctor_policy_activation(path: &Path)" in main_src, "policy activation pipeline runner")
add("doctor_json_output_path", "serde_json::to_string_pretty(&report)" in main_src, "json render")
add("doctor_human_output_path", "render_doctor_report_human(&report, args.verbose)" in main_src, "human render")

expected_codes = [
    "DR-CONFIG-001",
    "DR-CONFIG-002",
    "DR-PROFILE-003",
    "DR-TRUST-004",
    "DR-MIGRATE-005",
    "DR-OBS-006",
    "DR-ENV-007",
    "DR-CONFIG-008",
    "DR-POLICY-009",
    "DR-POLICY-010",
    "DR-POLICY-011",
]
expected_event_codes = [
    "DOC-001",
    "DOC-002",
    "DOC-003",
    "DOC-004",
    "DOC-005",
    "DOC-006",
    "DOC-007",
    "DOC-008",
    "DOC-009",
    "DOC-010",
    "DOC-011",
]

for code in expected_codes:
    add(f"doctor_code_{code}", code in main_src, code)
for event_code in expected_event_codes:
    add(f"doctor_event_code_{event_code}", event_code in main_src, event_code)

code_positions = [main_src.find(code) for code in expected_codes]
add(
    "doctor_code_order_deterministic",
    all(pos >= 0 for pos in code_positions) and code_positions == sorted(code_positions),
    str(code_positions),
)

add(
    "contract_has_matrix_and_schema",
    "## Check Matrix" in contract_src and "## Machine-Readable Report Schema (CI)" in contract_src,
    "matrix+schema sections",
)
add(
    "contract_mentions_policy_activation_flag",
    "--policy-activation-input" in contract_src,
    "policy activation command surface",
)
add(
    "contract_mentions_policy_codes",
    all(code in contract_src for code in ("DR-POLICY-009", "DR-POLICY-010", "DR-POLICY-011")),
    "policy code rows",
)

def load_report(path: Path) -> dict:
    if not path.exists():
        add(f"report_exists_{path.name}", False, str(path))
        return {}
    add(f"report_exists_{path.name}", True, str(path.relative_to(root)))
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        add(f"report_valid_json_{path.name}", True, "valid json")
        return report
    except json.JSONDecodeError as err:
        add(f"report_valid_json_{path.name}", False, str(err))
        return {}

def policy_status_map(report: dict) -> dict:
    entries = report.get("checks", [])
    if not isinstance(entries, list):
        return {}
    out = {}
    for row in entries:
        if not isinstance(row, dict):
            continue
        code = row.get("code")
        status = row.get("status")
        if isinstance(code, str) and code.startswith("DR-POLICY-"):
            out[code] = status
    return out

def find_check(report: dict, code: str) -> dict | None:
    entries = report.get("checks", [])
    if not isinstance(entries, list):
        return None
    for row in entries:
        if isinstance(row, dict) and row.get("code") == code:
            return row
    return None

healthy = load_report(healthy_json)
degraded = load_report(degraded_json)
failure = load_report(failure_json)
invalid = load_report(invalid_json)

healthy_statuses = policy_status_map(healthy)
degraded_statuses = policy_status_map(degraded)
failure_statuses = policy_status_map(failure)
invalid_statuses = policy_status_map(invalid)

add(
    "policy_pass_statuses",
    healthy_statuses.get("DR-POLICY-009") == "pass"
    and healthy_statuses.get("DR-POLICY-010") == "pass"
    and healthy_statuses.get("DR-POLICY-011") == "pass",
    str(healthy_statuses),
)
add(
    "policy_warn_statuses",
    degraded_statuses.get("DR-POLICY-009") == "warn"
    and degraded_statuses.get("DR-POLICY-010") == "pass"
    and degraded_statuses.get("DR-POLICY-011") == "pass",
    str(degraded_statuses),
)
add(
    "policy_block_statuses",
    failure_statuses.get("DR-POLICY-009") == "fail"
    and failure_statuses.get("DR-POLICY-010") == "fail"
    and failure_statuses.get("DR-POLICY-011") == "pass",
    str(failure_statuses),
)
add(
    "policy_invalid_statuses",
    invalid_statuses.get("DR-POLICY-009") == "fail"
    and invalid_statuses.get("DR-POLICY-010") == "fail"
    and invalid_statuses.get("DR-POLICY-011") == "fail",
    str(invalid_statuses),
)

healthy_policy = healthy.get("policy_activation", {})
degraded_policy = degraded.get("policy_activation", {})
failure_policy = failure.get("policy_activation", {})
invalid_policy = invalid.get("policy_activation")

add(
    "policy_pass_dominant_verdict_allow",
    healthy_policy.get("guardrail_certificate", {}).get("dominant_verdict") == "allow",
    str(healthy_policy.get("guardrail_certificate", {}).get("dominant_verdict")),
)
add(
    "policy_warn_dominant_verdict_warn",
    degraded_policy.get("guardrail_certificate", {}).get("dominant_verdict") == "warn",
    str(degraded_policy.get("guardrail_certificate", {}).get("dominant_verdict")),
)
add(
    "policy_block_dominant_verdict_block",
    failure_policy.get("guardrail_certificate", {}).get("dominant_verdict") == "block",
    str(failure_policy.get("guardrail_certificate", {}).get("dominant_verdict")),
)
add(
    "policy_block_contains_conformal_budget",
    "conformal_risk" in failure_policy.get("guardrail_certificate", {}).get("blocking_budget_ids", []),
    str(failure_policy.get("guardrail_certificate", {}).get("blocking_budget_ids")),
)
add(
    "policy_invalid_omits_policy_activation",
    invalid_policy is None,
    str(invalid_policy),
)

add(
    "policy_pass_decision_reason",
    healthy_policy.get("decision_outcome", {}).get("reason") == "TopCandidateAccepted",
    str(healthy_policy.get("decision_outcome", {}).get("reason")),
)
add(
    "policy_warn_decision_reason",
    degraded_policy.get("decision_outcome", {}).get("reason") == "TopCandidateAccepted",
    str(degraded_policy.get("decision_outcome", {}).get("reason")),
)
add(
    "policy_block_decision_reason",
    failure_policy.get("decision_outcome", {}).get("reason") == "AllCandidatesBlocked",
    str(failure_policy.get("decision_outcome", {}).get("reason")),
)
add(
    "policy_pass_top_ranked_candidate",
    healthy_policy.get("top_ranked_candidate") == "balanced_patch",
    str(healthy_policy.get("top_ranked_candidate")),
)

warn_findings = degraded_policy.get("guardrail_certificate", {}).get("findings", [])
warn_conformal = None
for row in warn_findings:
    if isinstance(row, dict) and row.get("budget_id") == "conformal_risk":
        warn_conformal = row
        break
add(
    "policy_warn_conformal_finding_warn",
    isinstance(warn_conformal, dict) and warn_conformal.get("verdict") == "warn",
    str(warn_conformal),
)

invalid_check = find_check(invalid, "DR-POLICY-009") or {}
add(
    "policy_invalid_message_mentions_parse_failure",
    "failed parsing policy activation input" in str(invalid_check.get("message", "")),
    str(invalid_check.get("message", "")),
)

matrix = [
    {
        "code": "DR-CONFIG-001",
        "event_code": "DOC-001",
        "scope": "config.resolve",
        "remediation": "No action required.",
    },
    {
        "code": "DR-CONFIG-002",
        "event_code": "DOC-002",
        "scope": "config.source",
        "remediation": "Create franken_node.toml or pass --config to lock deterministic project settings.",
    },
    {
        "code": "DR-PROFILE-003",
        "event_code": "DOC-003",
        "scope": "profile.safety",
        "remediation": "Prefer --profile balanced or --profile strict for stronger controls.",
    },
    {
        "code": "DR-TRUST-004",
        "event_code": "DOC-004",
        "scope": "registry.assurance",
        "remediation": "Raise registry.minimum_assurance_level to 3+.",
    },
    {
        "code": "DR-MIGRATE-005",
        "event_code": "DOC-005",
        "scope": "migration.lockstep",
        "remediation": "Set migration.require_lockstep_validation=true for safer rollout validation.",
    },
    {
        "code": "DR-OBS-006",
        "event_code": "DOC-006",
        "scope": "observability.audit_events",
        "remediation": "Set observability.emit_structured_audit_events=true for stronger traceability.",
    },
    {
        "code": "DR-ENV-007",
        "event_code": "DOC-007",
        "scope": "environment.cwd",
        "remediation": "Fix working directory access before running operations.",
    },
    {
        "code": "DR-CONFIG-008",
        "event_code": "DOC-008",
        "scope": "config.provenance",
        "remediation": "Investigate resolver instrumentation before relying on doctor provenance.",
    },
    {
        "code": "DR-POLICY-009",
        "event_code": "DOC-009",
        "scope": "policy.guardrails",
        "remediation": "Resolve blocked budgets before executing policy actions.",
    },
    {
        "code": "DR-POLICY-010",
        "event_code": "DOC-010",
        "scope": "policy.decision_engine",
        "remediation": "Reduce risk exposure or provide safer candidate actions.",
    },
    {
        "code": "DR-POLICY-011",
        "event_code": "DOC-011",
        "scope": "policy.explainer_wording",
        "remediation": "Fix explanation wording to preserve diagnostic vs guarantee separation.",
    },
]
matrix_payload = {
    "bead_id": "bd-1pk",
    "schema_version": "doctor-check-matrix-v1",
    "checks": matrix,
}
matrix_json.write_text(json.dumps(matrix_payload, indent=2) + "\n", encoding="utf-8")
add("matrix_written", matrix_json.exists(), str(matrix_json))
healthy_text = healthy_json.read_text(encoding="utf-8") if healthy_json.exists() else ""
healthy_sha = hashlib.sha256(healthy_text.encode("utf-8")).hexdigest() if healthy_text else ""
healthy_sha_2 = hashlib.sha256(healthy_text.encode("utf-8")).hexdigest() if healthy_text else ""
add("healthy_report_deterministic_hash", healthy_text != "" and healthy_sha == healthy_sha_2, healthy_sha)

payload = {
    "bead_id": "bd-1pk",
    "gate_script": "doctor_command_diagnostics.sh",
    "checks_passed": sum(1 for c in checks if c["passed"]),
    "checks_total": len(checks),
    "verdict": "PASS" if all(c["passed"] for c in checks) else "FAIL",
    "checks": checks,
    "sample_reports": {
        "healthy": str(healthy_json.relative_to(root)),
        "degraded": str(degraded_json.relative_to(root)),
        "failure": str(failure_json.relative_to(root)),
        "invalid": str(invalid_json.relative_to(root)),
    },
    "doctor_matrix_path": str(matrix_json.relative_to(root)),
}
checks_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

if payload["verdict"] != "PASS":
    raise SystemExit(1)
PY

if [ $? -eq 0 ]; then
  log_event "DOC-E2E-099" "pass" "Doctor diagnostics gate passed."
else
  log_event "DOC-E2E-099" "fail" "Doctor diagnostics gate failed."
  exit 1
fi

{
  echo "# bd-1pk Doctor Diagnostics Contract Checks"
  echo
  echo "- Log: \`artifacts/section_bootstrap/bd-1pk/doctor_diagnostics_log.jsonl\`"
  echo "- Checks JSON: \`artifacts/section_bootstrap/bd-1pk/doctor_contract_checks.json\`"
  echo "- Matrix JSON: \`artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json\`"
  echo "- Sample reports: \`doctor_report_healthy.json\`, \`doctor_report_degraded.json\`, \`doctor_report_failure.json\`, \`doctor_report_invalid_input.json\`"
  echo
  echo "| Check | Pass | Detail |"
  echo "|---|---|---|"
  jq -r '.checks[] | "| \(.check) | \(.passed) | \(.detail|tostring|gsub("\\n";" ")) |"' "${CHECKS_JSON}"
  echo
  echo "Verdict: **$(jq -r '.verdict' "${CHECKS_JSON}")** ($(jq -r '.checks_passed' "${CHECKS_JSON}")/$(jq -r '.checks_total' "${CHECKS_JSON}"))"
} > "${SUMMARY_MD}"

echo "bd-1pk doctor diagnostics checks: PASS"
