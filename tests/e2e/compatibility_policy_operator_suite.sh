#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/replacement_gap/bd-2ek7"
LOG_JSONL="${OUT_DIR}/operator_e2e_log.jsonl"
SUMMARY_JSON="${OUT_DIR}/operator_e2e_summary.json"
SUMMARY_MD="${OUT_DIR}/operator_e2e_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-2ek7-operator-e2e}"

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"
printf '{"schema_version":"bd-2ek7-operator-e2e-v1","verdict":"PENDING"}\n' > "${SUMMARY_JSON}"
printf '# bd-2ek7 Operator E2E Summary\n\n- Verdict: **PENDING**\n' > "${SUMMARY_MD}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for bd-2ek7 operator E2E checks" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for bd-2ek7 operator E2E checks" >&2
  exit 2
fi

log_event() {
  local event_code="$1"
  local decision="$2"
  local reason_code="$3"
  local detail="$4"
  jq -cn \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg trace_id "${TRACE_ID}" \
    --arg event_code "${event_code}" \
    --arg decision "${decision}" \
    --arg reason_code "${reason_code}" \
    --arg predicate_id "compatibility_placeholder_signature_shortcuts" \
    --arg parent_receipt_id "bd-2ek7" \
    --arg derived_scope "bd-2ek7.1" \
    --arg freshness_state "fresh" \
    --arg detail "${detail}" \
    '{
      ts: $ts,
      trace_id: $trace_id,
      event_code: $event_code,
      predicate_id: $predicate_id,
      parent_receipt_id: $parent_receipt_id,
      derived_scope: $derived_scope,
      decision: $decision,
      reason_code: $reason_code,
      freshness_state: $freshness_state,
      explanation_digest: ($detail | @json | @base64),
      detail: $detail
    }' >> "${LOG_JSONL}"
}

log_event "POLICY_COMPAT_E2E_STARTED" "audit" "POLICY_COMPAT_OPERATOR_E2E_STARTED" "starting compatibility policy operator E2E"

CHECK_JSON="$(cd "${ROOT_DIR}" && python3 scripts/check_compat_gates.py --json)"
CHECK_VERDICT="$(jq -r '.verdict' <<<"${CHECK_JSON}")"
CHECK_TOTAL="$(jq -r '.summary.total' <<<"${CHECK_JSON}")"
CHECK_PASSING="$(jq -r '.summary.passing' <<<"${CHECK_JSON}")"
CHECK_FAILING="$(jq -r '.summary.failing' <<<"${CHECK_JSON}")"

if [[ "${CHECK_VERDICT}" != "PASS" ]]; then
  log_event "POLICY_COMPAT_E2E_FAILED" "deny" "POLICY_COMPAT_OPERATOR_E2E_FAILED" "check_compat_gates verdict=${CHECK_VERDICT}"
  echo "${CHECK_JSON}" >&2
  exit 1
fi

log_event "POLICY_COMPAT_E2E_PASSED" "allow" "POLICY_COMPAT_OPERATOR_E2E_PASSED" "compatibility policy operator E2E passed"

python3 - "${LOG_JSONL}" "${SUMMARY_JSON}" "${SUMMARY_MD}" "${TRACE_ID}" "${CHECK_TOTAL}" "${CHECK_PASSING}" "${CHECK_FAILING}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

log_path = Path(sys.argv[1])
summary_json = Path(sys.argv[2])
summary_md = Path(sys.argv[3])
trace_id = sys.argv[4]
total = int(sys.argv[5])
passing = int(sys.argv[6])
failing = int(sys.argv[7])

events = [
    json.loads(line)
    for line in log_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
required_fields = {
    "trace_id",
    "predicate_id",
    "parent_receipt_id",
    "derived_scope",
    "decision",
    "reason_code",
    "freshness_state",
    "explanation_digest",
}
missing = sorted(
    f"{event.get('event_code', '?')}:{field}"
    for event in events
    for field in required_fields
    if field not in event
)

summary = {
    "schema_version": "bd-2ek7-operator-e2e-v1",
    "trace_id": trace_id,
    "verdict": "PASS" if not missing and failing == 0 else "FAIL",
    "check_total": total,
    "check_passing": passing,
    "check_failing": failing,
    "event_count": len(events),
    "required_fields": sorted(required_fields),
    "missing_fields": missing,
    "log_path": "artifacts/replacement_gap/bd-2ek7/operator_e2e_log.jsonl",
}
summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
summary_md.write_text(
    "\n".join(
        [
            "# bd-2ek7 Operator E2E Summary",
            "",
            f"- Trace ID: `{trace_id}`",
            f"- Verdict: **{summary['verdict']}**",
            f"- Checker: `{passing}/{total}` checks passed",
            f"- Event count: `{len(events)}`",
            f"- Log: `{summary['log_path']}`",
            "",
        ]
    ),
    encoding="utf-8",
)
if summary["verdict"] != "PASS":
    raise SystemExit(json.dumps(summary, sort_keys=True))
PY

echo "bd-2ek7 operator E2E PASS (${CHECK_PASSING}/${CHECK_TOTAL} checker assertions)"
