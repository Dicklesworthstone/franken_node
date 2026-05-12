#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/replacement_gap/bd-3hdn"
LOG_JSONL="${OUT_DIR}/operator_e2e_log.jsonl"
SUMMARY_JSON="${OUT_DIR}/operator_e2e_summary.json"
SUMMARY_MD="${OUT_DIR}/operator_e2e_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-3hdn-operator-e2e}"
ARTIFACT_ID="bd-3hdn-extension-registry-admission"
PUBLISHER_KEY_ID="publisher-key-bd-3hdn"
TRANSPARENCY_CHECKPOINT="transparency-checkpoint-bd-3hdn"
ATTESTATION_DIGEST="sha256:bd3hdnattestationdigest0000000000000000000000000000000000000000"

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"
printf '{"schema_version":"bd-3hdn-operator-e2e-v1","verdict":"PENDING"}\n' > "${SUMMARY_JSON}"
printf '# bd-3hdn Operator E2E Summary\n\n- Verdict: **PENDING**\n' > "${SUMMARY_MD}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for bd-3hdn operator E2E checks" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for bd-3hdn operator E2E checks" >&2
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
    --arg artifact_id "${ARTIFACT_ID}" \
    --arg publisher_key_id "${PUBLISHER_KEY_ID}" \
    --arg decision "${decision}" \
    --arg reason_code "${reason_code}" \
    --arg transparency_checkpoint "${TRANSPARENCY_CHECKPOINT}" \
    --arg attestation_digest "${ATTESTATION_DIGEST}" \
    --arg detail "${detail}" \
    '{
      ts: $ts,
      trace_id: $trace_id,
      event_code: $event_code,
      artifact_id: $artifact_id,
      publisher_key_id: $publisher_key_id,
      decision: $decision,
      reason_code: $reason_code,
      transparency_checkpoint: $transparency_checkpoint,
      attestation_digest: $attestation_digest,
      explanation_digest: ($detail | @json | @base64),
      detail: $detail
    }' >> "${LOG_JSONL}"
}

log_event "EXT_REG_ADMISSION_E2E_STARTED" "audit" "EXT_REG_ADMISSION_OPERATOR_E2E_STARTED" "starting signed extension registry admission operator E2E"
log_event "EXT_REG_PROVENANCE_E2E_STARTED" "audit" "EXT_REG_PROVENANCE_OPERATOR_E2E_STARTED" "starting signed extension registry provenance operator E2E"

CHECK_JSON="$(cd "${ROOT_DIR}" && python3 scripts/check_signed_extension_registry.py --json)"
CHECK_VERDICT="$(jq -r '.verdict' <<<"${CHECK_JSON}")"
CHECK_TOTAL="$(jq -r '.summary.total' <<<"${CHECK_JSON}")"
CHECK_PASSING="$(jq -r '.summary.passing' <<<"${CHECK_JSON}")"
CHECK_FAILING="$(jq -r '.summary.failing' <<<"${CHECK_JSON}")"

if [[ "${CHECK_VERDICT}" != "PASS" ]]; then
  log_event "EXT_REG_ADMISSION_E2E_FAILED" "deny" "EXT_REG_ADMISSION_OPERATOR_E2E_FAILED" "check_signed_extension_registry verdict=${CHECK_VERDICT}"
  echo "${CHECK_JSON}" >&2
  exit 1
fi

log_event "EXT_REG_ADMISSION_E2E_PASSED" "allow" "EXT_REG_ADMISSION_OPERATOR_E2E_PASSED" "signed extension registry admission operator E2E passed"
log_event "EXT_REG_PROVENANCE_E2E_PASSED" "allow" "EXT_REG_PROVENANCE_OPERATOR_E2E_PASSED" "signed extension registry provenance operator E2E passed"

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
    "artifact_id",
    "publisher_key_id",
    "decision",
    "reason_code",
    "transparency_checkpoint",
    "attestation_digest",
}
missing = sorted(
    f"{event.get('event_code', '?')}:{field}"
    for event in events
    for field in required_fields
    if field not in event
)
families = {
    "EXT_REG_ADMISSION": any(
        event.get("event_code", "").startswith("EXT_REG_ADMISSION_")
        for event in events
    ),
    "EXT_REG_PROVENANCE": any(
        event.get("event_code", "").startswith("EXT_REG_PROVENANCE_")
        for event in events
    ),
}

summary = {
    "schema_version": "bd-3hdn-operator-e2e-v1",
    "trace_id": trace_id,
    "verdict": "PASS" if not missing and all(families.values()) and failing == 0 else "FAIL",
    "check_total": total,
    "check_passing": passing,
    "check_failing": failing,
    "event_count": len(events),
    "event_families": families,
    "required_fields": sorted(required_fields),
    "missing_fields": missing,
    "log_path": "artifacts/replacement_gap/bd-3hdn/operator_e2e_log.jsonl",
}
summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
summary_md.write_text(
    "\n".join(
        [
            "# bd-3hdn Operator E2E Summary",
            "",
            f"- Trace ID: `{trace_id}`",
            f"- Verdict: **{summary['verdict']}**",
            f"- Checker: `{passing}/{total}` checks passed",
            f"- Event count: `{len(events)}`",
            f"- Event families: `EXT_REG_ADMISSION`, `EXT_REG_PROVENANCE`",
            f"- Log: `{summary['log_path']}`",
            "",
        ]
    ),
    encoding="utf-8",
)
if summary["verdict"] != "PASS":
    raise SystemExit(json.dumps(summary, sort_keys=True))
PY

echo "bd-3hdn operator E2E PASS (${CHECK_PASSING}/${CHECK_TOTAL} checker assertions)"
