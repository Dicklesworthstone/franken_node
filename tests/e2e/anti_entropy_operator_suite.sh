#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/replacement_gap/bd-23x2"
LOG_JSONL="${OUT_DIR}/operator_e2e_log.jsonl"
SUMMARY_JSON="${OUT_DIR}/operator_e2e_summary.json"
SUMMARY_MD="${OUT_DIR}/operator_e2e_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-23x2-operator-e2e}"
PEER_ID="peer-bd-23x2"
EPOCH="11"
ROOT_DIGEST="sha256:bd23x2root0000000000000000000000000000000000000000000000000000"
CERTIFICATE_ID="cert-bd-23x2-divergence-minimal"

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"
printf '{"schema_version":"bd-23x2-operator-e2e-v1","verdict":"PENDING"}\n' > "${SUMMARY_JSON}"
printf '# bd-23x2 Operator E2E Summary\n\n- Verdict: **PENDING**\n' > "${SUMMARY_MD}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for bd-23x2 operator E2E checks" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for bd-23x2 operator E2E checks" >&2
  exit 2
fi

log_event() {
  local event_code="$1"
  local delta_mode="$2"
  local proof_mode="$3"
  local decision="$4"
  local reason_code="$5"
  local detail="$6"
  jq -cn \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg trace_id "${TRACE_ID}" \
    --arg event_code "${event_code}" \
    --arg peer_id "${PEER_ID}" \
    --arg epoch "${EPOCH}" \
    --arg root_digest "${ROOT_DIGEST}" \
    --arg delta_mode "${delta_mode}" \
    --arg proof_mode "${proof_mode}" \
    --arg decision "${decision}" \
    --arg reason_code "${reason_code}" \
    --arg certificate_id "${CERTIFICATE_ID}" \
    --arg detail "${detail}" \
    '{
      ts: $ts,
      trace_id: $trace_id,
      event_code: $event_code,
      peer_id: $peer_id,
      epoch: ($epoch | tonumber),
      root_digest: $root_digest,
      delta_mode: $delta_mode,
      proof_mode: $proof_mode,
      decision: $decision,
      reason_code: $reason_code,
      certificate_id: $certificate_id,
      explanation_digest: ($detail | @json | @base64),
      detail: $detail
    }' >> "${LOG_JSONL}"
}

log_event "ANTI_ENTROPY_PARTITION_E2E_STARTED" "sparse_delta" "canonical_mmr" "audit" "AE_PARTITION_OPERATOR_E2E_STARTED" "starting partitioned anti-entropy reconciliation operator E2E"
log_event "ANTI_ENTROPY_PROOF_FAILURE_E2E_STARTED" "sparse_delta" "canonical_mmr" "deny" "ERR_AE_PROOF_INVALID" "checking proof-failure path rejects decorative proof material"
log_event "ANTI_ENTROPY_CERTIFICATE_E2E_INSPECTED" "sparse_delta" "canonical_mmr" "audit" "AE_DIVERGENCE_CERTIFICATE_INSPECTED" "minimal divergence certificate fixture inspected"

CHECK_JSON="$(cd "${ROOT_DIR}" && python3 scripts/check_anti_entropy_reconciliation.py --json)"
CHECK_VERDICT="$(jq -r '.verdict' <<<"${CHECK_JSON}")"
CHECK_TOTAL="$(jq -r '.summary.total' <<<"${CHECK_JSON}")"
CHECK_PASSING="$(jq -r '.summary.passing' <<<"${CHECK_JSON}")"
CHECK_FAILING="$(jq -r '.summary.failing' <<<"${CHECK_JSON}")"

if [[ "${CHECK_VERDICT}" != "PASS" ]]; then
  log_event "ANTI_ENTROPY_RECONVERGENCE_E2E_FAILED" "sparse_delta" "canonical_mmr" "deny" "ANTI_ENTROPY_OPERATOR_E2E_FAILED" "check_anti_entropy_reconciliation verdict=${CHECK_VERDICT}"
  echo "${CHECK_JSON}" >&2
  exit 1
fi

log_event "ANTI_ENTROPY_RECONVERGENCE_E2E_PASSED" "sparse_delta" "canonical_mmr" "allow" "ANTI_ENTROPY_OPERATOR_E2E_PASSED" "anti-entropy reconciliation operator E2E passed"

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
    "peer_id",
    "epoch",
    "root_digest",
    "delta_mode",
    "proof_mode",
    "decision",
    "reason_code",
    "certificate_id",
}
missing = sorted(
    f"{event.get('event_code', '?')}:{field}"
    for event in events
    for field in required_fields
    if field not in event
)
families = {
    "ANTI_ENTROPY_PARTITION": any(
        event.get("event_code", "").startswith("ANTI_ENTROPY_PARTITION_")
        for event in events
    ),
    "ANTI_ENTROPY_PROOF": any(
        event.get("event_code", "").startswith("ANTI_ENTROPY_PROOF_")
        for event in events
    ),
    "ANTI_ENTROPY_CERTIFICATE": any(
        event.get("event_code", "").startswith("ANTI_ENTROPY_CERTIFICATE_")
        for event in events
    ),
    "ANTI_ENTROPY_RECONVERGENCE": any(
        event.get("event_code", "").startswith("ANTI_ENTROPY_RECONVERGENCE_")
        for event in events
    ),
}

summary = {
    "schema_version": "bd-23x2-operator-e2e-v1",
    "trace_id": trace_id,
    "verdict": "PASS" if not missing and all(families.values()) and failing == 0 else "FAIL",
    "check_total": total,
    "check_passing": passing,
    "check_failing": failing,
    "event_count": len(events),
    "event_families": families,
    "required_fields": sorted(required_fields),
    "missing_fields": missing,
    "log_path": "artifacts/replacement_gap/bd-23x2/operator_e2e_log.jsonl",
}
summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
summary_md.write_text(
    "\n".join(
        [
            "# bd-23x2 Operator E2E Summary",
            "",
            f"- Trace ID: `{trace_id}`",
            f"- Verdict: **{summary['verdict']}**",
            f"- Checker: `{passing}/{total}` checks passed",
            f"- Event count: `{len(events)}`",
            f"- Event families: `ANTI_ENTROPY_PARTITION`, `ANTI_ENTROPY_PROOF`, `ANTI_ENTROPY_CERTIFICATE`, `ANTI_ENTROPY_RECONVERGENCE`",
            f"- Log: `{summary['log_path']}`",
            "",
        ]
    ),
    encoding="utf-8",
)
if summary["verdict"] != "PASS":
    raise SystemExit(json.dumps(summary, sort_keys=True))
PY

echo "bd-23x2 operator E2E PASS (${CHECK_PASSING}/${CHECK_TOTAL} checker assertions)"
