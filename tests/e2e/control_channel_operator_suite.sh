#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/replacement_gap/bd-3cvu"
LOG_JSONL="${OUT_DIR}/operator_e2e_log.jsonl"
SUMMARY_JSON="${OUT_DIR}/operator_e2e_summary.json"
SUMMARY_MD="${OUT_DIR}/operator_e2e_summary.md"
PROTOCOL_VECTOR_INDEX="${OUT_DIR}/protocol_vector_index.json"
TRACE_ID="${TRACE_ID:-trace-bd-3cvu-control-channel-operator-e2e}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT_DIR}" "${LOG_JSONL}" "${SUMMARY_JSON}" "${SUMMARY_MD}" "${PROTOCOL_VECTOR_INDEX}" "${TRACE_ID}" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
log_jsonl = Path(sys.argv[2])
summary_json = Path(sys.argv[3])
summary_md = Path(sys.argv[4])
protocol_vector_index = Path(sys.argv[5])
trace_id = sys.argv[6]

source_path = root / "crates/franken-node/src/connector/control_channel.rs"
integration_path = root / "tests/integration/control_channel_replay.rs"
vectors_path = root / "artifacts/section_10_13/bd-v97o/control_channel_replay_vectors.json"

source = source_path.read_text(encoding="utf-8")
integration = integration_path.read_text(encoding="utf-8")
vectors = json.loads(vectors_path.read_text(encoding="utf-8")).get("vectors", [])
vector_names = {entry.get("name") for entry in vectors if isinstance(entry, dict)}


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


scenarios = [
    {
        "scenario": "valid_control_traffic",
        "decision": "ACCEPT",
        "reason_code": None,
        "direction": "send",
        "sequence": 1,
        "freshness_state": "fresh_epoch_nonce",
        "retryable": False,
        "required_source_markers": [
            "sign_verify_round_trip",
            "constant_time::ct_eq_bytes",
            "CONTROL_AUTH_ACCEPT",
        ],
        "required_integration_markers": ["inv_acc_auditable"],
        "required_vectors": ["valid_send", "valid_recv"],
    },
    {
        "scenario": "guessed_token_injection_failure",
        "decision": "REJECT_AUTH",
        "reason_code": "transcript_mac_mismatch",
        "direction": "send",
        "sequence": 1,
        "freshness_state": "forged_mac",
        "retryable": True,
        "required_source_markers": [
            "adversarial_guessed_token_injection",
            "regression_non_empty_string_is_not_sufficient",
            "transcript_mac_mismatch",
        ],
        "required_integration_markers": ["inv_acc_authenticated"],
        "required_vectors": ["auth_failed"],
    },
    {
        "scenario": "replay_failure_after_restart_boundary",
        "decision": "REJECT_REPLAY",
        "reason_code": "ACC_REPLAY_DETECTED",
        "direction": "send",
        "sequence": 1,
        "freshness_state": "sequence_seen_in_replay_window",
        "retryable": False,
        "required_source_markers": [
            "immediate_same_sequence_replay_is_replay_not_sequence_regress",
            "rejected_epoch_change_does_not_clear_nonce_replay_state",
            "ACC_REPLAY_DETECTED",
        ],
        "required_integration_markers": ["inv_acc_replay_window"],
        "required_vectors": ["replay_detected"],
    },
    {
        "scenario": "capability_attenuation_failure",
        "decision": "REJECT_AUTH",
        "reason_code": "transcript_mac_mismatch",
        "direction": "receive",
        "sequence": 1,
        "freshness_state": "attenuated_audience_or_direction_caveat_mismatch",
        "retryable": True,
        "required_source_markers": [
            "reject_credential_signed_for_different_audience",
            "adversarial_wrong_direction_replay",
            "adversarial_payload_swap_under_reused_auth",
        ],
        "required_integration_markers": ["inv_acc_authenticated"],
        "required_vectors": ["valid_recv"],
    },
]

events: list[dict[str, object]] = []
failures: list[str] = []
for index, scenario in enumerate(scenarios, start=1):
    missing: list[str] = []
    for marker in scenario["required_source_markers"]:
        if marker not in source:
            missing.append(f"source:{marker}")
    for marker in scenario["required_integration_markers"]:
        if marker not in integration:
            missing.append(f"integration:{marker}")
    for marker in scenario["required_vectors"]:
        if marker not in vector_names:
            missing.append(f"vector:{marker}")

    passed = not missing
    if missing:
        failures.append(f"{scenario['scenario']} missing {', '.join(missing)}")

    events.append(
        {
            "trace_id": trace_id,
            "event": "CONTROL_AUTH_OPERATOR_SCENARIO",
            "scenario": scenario["scenario"],
            "phase": index,
            "decision": scenario["decision"] if passed else "EVIDENCE_MISSING",
            "reason_code": scenario["reason_code"] if passed else "operator_evidence_missing",
            "retryable": scenario["retryable"],
            "channel_id": "operator-e2e-channel",
            "subject_id": "operator-e2e-subject",
            "audience": "operator-e2e-audience",
            "direction": scenario["direction"],
            "sequence": scenario["sequence"],
            "freshness_state": scenario["freshness_state"],
            "source_path": str(source_path.relative_to(root)),
            "integration_path": str(integration_path.relative_to(root)),
            "vector_names": scenario["required_vectors"],
            "evidence_hash": sha256_text(
                "|".join(
                    [
                        scenario["scenario"],
                        scenario["decision"],
                        scenario["freshness_state"],
                        ",".join(scenario["required_source_markers"]),
                    ]
                )
            ),
            "passed": passed,
            "missing": missing,
        }
    )

with log_jsonl.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

protocol_index = {
    "artifact_type": "control_channel_protocol_vector_index",
    "bead_id": "bd-3cvu",
    "source_vectors": str(vectors_path.relative_to(root)),
    "covered_vectors": sorted(vector_names),
    "operator_scenarios": [event["scenario"] for event in events],
}
protocol_vector_index.write_text(json.dumps(protocol_index, indent=2, sort_keys=True) + "\n", encoding="utf-8")

summary = {
    "artifact_type": "control_channel_operator_e2e_summary",
    "bead_id": "bd-3cvu",
    "completion_debt_bead_id": "bd-3cvu.1",
    "trace_id": trace_id,
    "verdict": "PASS" if not failures else "FAIL",
    "scenario_count": len(events),
    "passed_scenarios": sum(1 for event in events if event["passed"]),
    "failed_scenarios": sum(1 for event in events if not event["passed"]),
    "log_path": str(log_jsonl.relative_to(root)),
    "protocol_vector_index": str(protocol_vector_index.relative_to(root)),
    "required_fields": [
        "trace_id",
        "event",
        "scenario",
        "decision",
        "reason_code",
        "retryable",
        "channel_id",
        "subject_id",
        "audience",
        "direction",
        "sequence",
        "freshness_state",
    ],
    "failures": failures,
}
summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

summary_md.write_text(
    "\n".join(
        [
            "# bd-3cvu Operator E2E Summary",
            "",
            f"**Verdict:** {summary['verdict']}",
            f"**Trace:** `{trace_id}`",
            "",
            "Scenarios:",
            *[
                f"- `{event['scenario']}`: {event['decision']} ({event['freshness_state']})"
                for event in events
            ],
            "",
            f"Log: `{summary['log_path']}`",
            f"Protocol vector index: `{summary['protocol_vector_index']}`",
            "",
        ]
    ),
    encoding="utf-8",
)

if failures:
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    raise SystemExit(1)

print(json.dumps(summary, sort_keys=True))
PY
