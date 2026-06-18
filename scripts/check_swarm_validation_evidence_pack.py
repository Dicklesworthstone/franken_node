#!/usr/bin/env python3
"""Validate swarm validation admission JSONL evidence packs for bd-0x4fy.10."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


CHECK_BEAD_ID = "bd-0x4fy.10"
TITLE = "Swarm validation evidence-pack closeout checker"
TRANSCRIPT_SCHEMA_VERSION = "franken-node/swarm-validation-admission/transcript/v1"
CHECK_SCHEMA_VERSION = "franken-node/swarm-validation-admission/evidence-pack-check/v1"
DEFAULT_TRANSCRIPT_REL = Path(
    "artifacts/validation_broker/swarm_validation_admission/swarm_validation_transcript.v1.jsonl"
)

REQUIRED_FIELDS = [
    "schema_version",
    "step",
    "command",
    "bead_id",
    "thread_id",
    "trace_id",
    "agent_name",
    "decision",
    "reason_code",
    "event_code",
    "required_action",
    "proof_key",
    "proof_source",
    "coalescing_owner_agent",
    "reservation_evidence",
    "build_slot_evidence",
    "rch_status_class",
    "target_dir_strategy",
    "worker_requirement",
    "max_parallel_rch_jobs",
    "retry_after_ms",
    "closeout_recommendation",
]

DECISIONS = {"run", "coalesce", "defer", "handoff", "blocked"}
RCH_RUN_REASONS = {"SVA_RUN_RCH_READY"}
RCH_RUN_ACTIONS = {"start_rch_validation"}
RCH_READY_CLASSES = {"rch_ready"}
BLOCKED_CLOSEOUTS = {"record_blocker_and_do_not_close"}
DEFER_CLOSEOUTS = {"refresh_admission_after_retry_no_local_cargo"}
HANDOFF_CLOSEOUTS = {"request_handoff_before_claiming"}
PROOF_REUSE_CLOSEOUTS = {"wait_for_or_reuse_receipt_before_closeout", "wait_for_matching_proof_state"}
JSON_DECODER = json.JSONDecoder()


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _resolve_under_root(path: Path, root: Path) -> tuple[Path, bool]:
    candidate = path if path.is_absolute() else root / path
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
        return resolved, True
    except ValueError:
        return resolved, False


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": check,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and "\0" not in value


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) and "\0" not in item for item in value):
        return None
    return value


def _read_jsonl(path: Path, root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.is_file():
        return [], [f"ERR_SVEP_MISSING_TRANSCRIPT: {_safe_rel(path, root)}"]

    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = JSON_DECODER.decode(line)
        except json.JSONDecodeError as exc:
            errors.append(f"ERR_SVEP_MALFORMED_JSONL: line {line_number}: {exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"ERR_SVEP_MALFORMED_ROW: line {line_number} is not a JSON object")
            continue
        rows.append(payload)
    if not rows and not errors:
        errors.append("ERR_SVEP_EMPTY_TRANSCRIPT: no JSONL rows")
    return rows, errors


def _requires_rch(command: str) -> bool:
    text = f" {command.strip()} "
    return " cargo " in text or " CARGO_TARGET_DIR=" in text or " CARGO_BUILD_JOBS=" in text


def _evidence_items(row: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for field in ("reservation_evidence", "build_slot_evidence"):
        values = _string_list(row.get(field))
        if values:
            evidence.extend(item for item in values if item.strip())
    return evidence


def _row_errors(
    row: dict[str, Any],
    index: int,
    *,
    expected_bead_id: str | None,
    expected_thread_id: str | None,
) -> list[str]:
    errors: list[str] = []
    row_label = f"row {index}"

    missing_fields = [field for field in REQUIRED_FIELDS if field not in row]
    if missing_fields:
        errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: missing {','.join(missing_fields)}")
        return errors

    if row.get("schema_version") != TRANSCRIPT_SCHEMA_VERSION:
        errors.append(f"{row_label} ERR_SVEP_INVALID_SCHEMA_VERSION")
    if not _has_text(row.get("step")):
        errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: missing step")
    if not _has_text(row.get("bead_id")):
        errors.append(f"{row_label} ERR_SVEP_MISSING_BEAD_ID")
    if not _has_text(row.get("thread_id")):
        errors.append(f"{row_label} ERR_SVEP_MISSING_THREAD_ID")
    if _has_text(row.get("bead_id")) and _has_text(row.get("thread_id")):
        if row["bead_id"] != row["thread_id"]:
            errors.append(f"{row_label} ERR_SVEP_THREAD_BEAD_MISMATCH")
    if expected_bead_id is not None and row.get("bead_id") != expected_bead_id:
        errors.append(f"{row_label} ERR_SVEP_UNEXPECTED_BEAD_ID")
    if expected_thread_id is not None and row.get("thread_id") != expected_thread_id:
        errors.append(f"{row_label} ERR_SVEP_UNEXPECTED_THREAD_ID")

    for field in ("trace_id", "agent_name", "reason_code", "event_code", "required_action", "closeout_recommendation"):
        if not _has_text(row.get(field)):
            errors.append(f"{row_label} ERR_SVEP_MISSING_{field.upper()}")

    decision = row.get("decision")
    if decision not in DECISIONS:
        errors.append(f"{row_label} ERR_SVEP_UNSUPPORTED_DECISION")

    for field in ("reservation_evidence", "build_slot_evidence"):
        if _string_list(row.get(field)) is None:
            errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: {field} must be a string array")

    jobs = row.get("max_parallel_rch_jobs")
    if not isinstance(jobs, int) or jobs < 0:
        errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: max_parallel_rch_jobs")
    retry_after = row.get("retry_after_ms")
    if retry_after is not None and (not isinstance(retry_after, int) or retry_after < 0):
        errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: retry_after_ms")

    command = row.get("command")
    if command is not None and not _has_text(command):
        errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: command")
    if isinstance(command, str) and _requires_rch(command) and not command.startswith("rch exec --"):
        errors.append(f"{row_label} ERR_SVEP_UNSAFE_LOCAL_CARGO")

    proof_key = row.get("proof_key")
    has_proof_key = _has_text(proof_key)
    proof_source = row.get("proof_source")
    closeout = row.get("closeout_recommendation")
    reason = row.get("reason_code")
    action = row.get("required_action")
    status = row.get("rch_status_class")

    rch_run = reason in RCH_RUN_REASONS or action in RCH_RUN_ACTIONS or status in RCH_READY_CLASSES
    if decision == "run":
        if rch_run:
            if not isinstance(command, str) or not command.startswith("rch exec --"):
                errors.append(f"{row_label} ERR_SVEP_MISSING_RCH_COMMAND")
            if not has_proof_key:
                errors.append(f"{row_label} ERR_SVEP_MISSING_PROOF_KEY")
            if not isinstance(jobs, int) or jobs <= 0:
                errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: rch run requires positive max_parallel_rch_jobs")
        elif not (isinstance(command, str) and command.strip()) and proof_source != "source_only":
            errors.append(f"{row_label} ERR_SVEP_MISSING_RCH_COMMAND")

    if decision == "coalesce":
        if command is not None:
            errors.append(f"{row_label} ERR_SVEP_COALESCED_COMMAND_MUST_BE_NULL")
        if not has_proof_key:
            errors.append(f"{row_label} ERR_SVEP_MISSING_PROOF_KEY")
        if not _has_text(row.get("coalescing_owner_agent")):
            errors.append(f"{row_label} ERR_SVEP_MISSING_COALESCING_OWNER")
        if jobs != 0:
            errors.append(f"{row_label} ERR_SVEP_MALFORMED_ROW: coalesce requires zero max_parallel_rch_jobs")
        if closeout not in PROOF_REUSE_CLOSEOUTS:
            errors.append(f"{row_label} ERR_SVEP_UNDOCUMENTED_CLOSEOUT")

    if decision == "defer":
        if command is not None:
            errors.append(f"{row_label} ERR_SVEP_DEFERRED_COMMAND_MUST_BE_NULL")
        if not isinstance(retry_after, int):
            errors.append(f"{row_label} ERR_SVEP_UNDOCUMENTED_BLOCKER")
        if closeout not in DEFER_CLOSEOUTS:
            errors.append(f"{row_label} ERR_SVEP_UNDOCUMENTED_CLOSEOUT")

    if decision == "handoff":
        if command is not None:
            errors.append(f"{row_label} ERR_SVEP_HANDOFF_COMMAND_MUST_BE_NULL")
        if not _evidence_items(row):
            errors.append(f"{row_label} ERR_SVEP_UNDOCUMENTED_BLOCKER")
        if closeout not in HANDOFF_CLOSEOUTS:
            errors.append(f"{row_label} ERR_SVEP_UNDOCUMENTED_CLOSEOUT")

    if decision == "blocked":
        if command is not None:
            errors.append(f"{row_label} ERR_SVEP_BLOCKED_COMMAND_MUST_BE_NULL")
        if not _evidence_items(row):
            errors.append(f"{row_label} ERR_SVEP_UNDOCUMENTED_BLOCKER")
        if closeout not in BLOCKED_CLOSEOUTS:
            errors.append(f"{row_label} ERR_SVEP_UNDOCUMENTED_CLOSEOUT")

    return errors


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    decision_counts: dict[str, int] = {}
    commands: list[str] = []
    proof_keys: set[str] = set()
    agents: set[str] = set()
    for row in rows:
        decision = row.get("decision")
        if isinstance(decision, str):
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
        command = row.get("command")
        if isinstance(command, str) and command.strip():
            commands.append(command)
        proof_key = row.get("proof_key")
        if isinstance(proof_key, str) and proof_key.strip():
            proof_keys.add(proof_key)
        agent = row.get("agent_name")
        if isinstance(agent, str) and agent.strip():
            agents.add(agent)
    return {
        "row_count": len(rows),
        "decisions": dict(sorted(decision_counts.items())),
        "agents": sorted(agents),
        "proof_keys": sorted(proof_keys),
        "commands": sorted(commands),
    }


def _validate_rows(
    rows: list[dict[str, Any]],
    *,
    expected_bead_id: str | None,
    expected_thread_id: str | None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    checks.append(_check("transcript_has_rows", bool(rows), f"rows={len(rows)}"))
    row_errors: list[str] = []
    for index, row in enumerate(rows, start=1):
        row_errors.extend(
            _row_errors(
                row,
                index,
                expected_bead_id=expected_bead_id,
                expected_thread_id=expected_thread_id,
            )
        )
    checks.append(
        _check(
            "transcript_rows_satisfy_closeout_contract",
            not row_errors,
            "; ".join(row_errors[:40]) if row_errors else "ok",
        )
    )

    bead_ids = sorted({row.get("bead_id") for row in rows if isinstance(row.get("bead_id"), str)})
    thread_ids = sorted({row.get("thread_id") for row in rows if isinstance(row.get("thread_id"), str)})
    checks.append(_check("single_bead_id", len(bead_ids) == 1, ",".join(bead_ids)))
    checks.append(_check("single_agent_mail_thread_id", len(thread_ids) == 1, ",".join(thread_ids)))
    if bead_ids and thread_ids:
        checks.append(_check("bead_id_matches_thread_id", bead_ids == thread_ids, f"beads={bead_ids} threads={thread_ids}"))
    return checks


def run_checks(
    root: Path = ROOT,
    transcript_path: Path | None = None,
    *,
    expected_bead_id: str | None = None,
    expected_thread_id: str | None = None,
) -> dict[str, Any]:
    root = Path(root).resolve()
    raw_path = transcript_path or DEFAULT_TRANSCRIPT_REL
    resolved_path, inside_root = _resolve_under_root(Path(raw_path), root)
    checks = [
        _check(
            "transcript_path_stays_inside_project_root",
            inside_root,
            _safe_rel(resolved_path, root),
        )
    ]

    rows: list[dict[str, Any]] = []
    if inside_root:
        rows, load_errors = _read_jsonl(resolved_path, root)
    else:
        load_errors = ["ERR_SVEP_PATH_OUTSIDE_ROOT"]
    checks.append(
        _check(
            "transcript_jsonl_loads",
            not load_errors,
            "; ".join(load_errors) if load_errors else _safe_rel(resolved_path, root),
        )
    )
    if not load_errors:
        checks.extend(
            _validate_rows(
                rows,
                expected_bead_id=expected_bead_id,
                expected_thread_id=expected_thread_id,
            )
        )

    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    observed_bead_ids = sorted({row.get("bead_id") for row in rows if isinstance(row.get("bead_id"), str)})
    observed_thread_ids = sorted({row.get("thread_id") for row in rows if isinstance(row.get("thread_id"), str)})
    return {
        "schema_version": CHECK_SCHEMA_VERSION,
        "bead_id": CHECK_BEAD_ID,
        "title": TITLE,
        "transcript_path": _safe_rel(resolved_path, root),
        "observed_bead_ids": observed_bead_ids,
        "observed_thread_ids": observed_thread_ids,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "summary": _summarize_rows(rows),
        "closeout_contract": {
            "requires_agent_mail_thread_id": True,
            "requires_beads_issue_id": True,
            "requires_bead_thread_match": True,
            "requires_rch_exec_for_cargo": True,
            "requires_proof_key_for_run_and_coalesce": True,
            "requires_blocker_evidence_for_defer_handoff_blocked": True,
        },
    }


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _valid_transcript_rows(bead_id: str = CHECK_BEAD_ID) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": TRANSCRIPT_SCHEMA_VERSION,
            "step": "agent_a_start_rch_lane",
            "command": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sva cargo test -p frankenengine-node swarm_validation_admission",
            "bead_id": bead_id,
            "thread_id": bead_id,
            "trace_id": f"trace-sva-{bead_id}-run",
            "agent_name": "NavyTurtle",
            "decision": "run",
            "reason_code": "SVA_RUN_RCH_READY",
            "event_code": "SVA-002",
            "required_action": "start_rch_validation",
            "proof_key": "sha256:proof-work-key-evidence-pack",
            "proof_source": "fresh_execution",
            "coalescing_owner_agent": None,
            "reservation_evidence": [],
            "build_slot_evidence": ["rch-build-slot:NavyTurtle:rch-sva-evidence-pack"],
            "rch_status_class": "rch_ready",
            "target_dir_strategy": "reuse_isolated",
            "worker_requirement": "prefer_high_memory_remote",
            "max_parallel_rch_jobs": 1,
            "retry_after_ms": None,
            "closeout_recommendation": "run_rch_command_then_attach_receipt",
        },
        {
            "schema_version": TRANSCRIPT_SCHEMA_VERSION,
            "step": "agent_b_join_same_proof",
            "command": None,
            "bead_id": bead_id,
            "thread_id": bead_id,
            "trace_id": f"trace-sva-{bead_id}-coalesce",
            "agent_name": "SilentGrove",
            "decision": "coalesce",
            "reason_code": "SWARM-COALESCE-IN-FLIGHT",
            "event_code": "SVA-004",
            "required_action": "join_existing_proof",
            "proof_key": "sha256:proof-work-key-evidence-pack",
            "proof_source": "coalescer_waiter",
            "coalescing_owner_agent": "NavyTurtle",
            "reservation_evidence": [],
            "build_slot_evidence": ["rch-build-slot:NavyTurtle:rch-sva-evidence-pack"],
            "rch_status_class": "proof_reuse",
            "target_dir_strategy": "join_existing_proof_lease",
            "worker_requirement": "prefer_high_memory_remote",
            "max_parallel_rch_jobs": 0,
            "retry_after_ms": None,
            "closeout_recommendation": "wait_for_or_reuse_receipt_before_closeout",
        },
        {
            "schema_version": TRANSCRIPT_SCHEMA_VERSION,
            "step": "agent_c_rch_saturated_defer",
            "command": None,
            "bead_id": bead_id,
            "thread_id": bead_id,
            "trace_id": f"trace-sva-{bead_id}-defer",
            "agent_name": "SunnyIvy",
            "decision": "defer",
            "reason_code": "SVA_DEFER_RCH_QUEUE",
            "event_code": "SVA-007",
            "required_action": "wait_for_rch_capacity",
            "proof_key": "sha256:proof-work-key-evidence-pack",
            "proof_source": "none",
            "coalescing_owner_agent": None,
            "reservation_evidence": [],
            "build_slot_evidence": ["rch-build-slot:queue:rch-saturated-depth-24"],
            "rch_status_class": "rch_saturated",
            "target_dir_strategy": "defer_for_capacity",
            "worker_requirement": "wait_for_rch_capacity",
            "max_parallel_rch_jobs": 0,
            "retry_after_ms": 30000,
            "closeout_recommendation": "refresh_admission_after_retry_no_local_cargo",
        },
        {
            "schema_version": TRANSCRIPT_SCHEMA_VERSION,
            "step": "agent_d_reservation_conflict",
            "command": None,
            "bead_id": bead_id,
            "thread_id": bead_id,
            "trace_id": f"trace-sva-{bead_id}-blocked",
            "agent_name": "CrimsonOrchid",
            "decision": "blocked",
            "reason_code": "SVA_BLOCKED_ACTIVE_RESERVATION",
            "event_code": "SVA-014",
            "required_action": "coordinate_with_reservation_holder",
            "proof_key": None,
            "proof_source": "none",
            "coalescing_owner_agent": None,
            "reservation_evidence": ["agent-mail-reservation:ScarletSeal:crates/franken-node/src/ops/swarm_validation_admission.rs"],
            "build_slot_evidence": [],
            "rch_status_class": "blocked",
            "target_dir_strategy": "blocked_by_reservation",
            "worker_requirement": "prefer_high_memory_remote",
            "max_parallel_rch_jobs": 0,
            "retry_after_ms": None,
            "closeout_recommendation": "record_blocker_and_do_not_close",
        },
        {
            "schema_version": TRANSCRIPT_SCHEMA_VERSION,
            "step": "agent_e_stale_handoff",
            "command": None,
            "bead_id": bead_id,
            "thread_id": bead_id,
            "trace_id": f"trace-sva-{bead_id}-handoff",
            "agent_name": "YellowSparrow",
            "decision": "handoff",
            "reason_code": "SWARM-STALE-LEASE",
            "event_code": "SVA-009",
            "required_action": "request_agent_handoff",
            "proof_key": None,
            "proof_source": "none",
            "coalescing_owner_agent": None,
            "reservation_evidence": [],
            "build_slot_evidence": ["rch-build-slot:RainyFrog:rch-proof-bd-0x4fy-2"],
            "rch_status_class": "handoff_required",
            "target_dir_strategy": "handoff_before_claim",
            "worker_requirement": "prefer_high_memory_remote",
            "max_parallel_rch_jobs": 0,
            "retry_after_ms": None,
            "closeout_recommendation": "request_handoff_before_claiming",
        },
    ]


def _materialize_self_test_fixture(root: Path, bead_id: str = CHECK_BEAD_ID) -> Path:
    transcript_path = root / DEFAULT_TRANSCRIPT_REL
    _write_jsonl(transcript_path, _valid_transcript_rows(bead_id))
    return transcript_path


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        transcript_path = _materialize_self_test_fixture(root)
        baseline = run_checks(root, transcript_path, expected_bead_id=CHECK_BEAD_ID)
        if baseline["verdict"] != "PASS":
            return {"verdict": "FAIL", "detail": "baseline fixture did not pass", "baseline": baseline}

        rows = _valid_transcript_rows()
        rows[0]["command"] = "cargo test -p frankenengine-node swarm_validation_admission"
        unsafe_path = root / "unsafe_local_cargo.jsonl"
        _write_jsonl(unsafe_path, rows)
        unsafe_result = run_checks(root, unsafe_path, expected_bead_id=CHECK_BEAD_ID)

        malformed_path = root / "malformed.jsonl"
        malformed_path.write_text("{not-json\n", encoding="utf-8")
        malformed_result = run_checks(root, malformed_path)

        passed = unsafe_result["verdict"] == "FAIL" and malformed_result["verdict"] == "FAIL"
        return {
            "verdict": "PASS" if passed else "FAIL",
            "detail": "mutation checks failed closed" if passed else "mutation checks did not fail closed",
            "contract_result": baseline,
            "unsafe_local_cargo_result": unsafe_result,
            "malformed_result": malformed_result,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="run internal mutation checks")
    parser.add_argument("--root", type=Path, default=ROOT, help="project root for path-scoped transcript resolution")
    parser.add_argument("--transcript", type=Path, help="JSONL transcript path, absolute or relative to --root")
    parser.add_argument("--expected-bead-id", help="require all rows to match this Beads issue id")
    parser.add_argument("--expected-thread-id", help="require all rows to match this Agent Mail thread id")
    args = parser.parse_args(argv)

    logger = configure_test_logging("check_swarm_validation_evidence_pack", json_mode=args.json)

    if args.self_test:
        payload = self_test()
        logger.info("self-test complete", extra={"verdict": payload["verdict"]})
    else:
        payload = run_checks(
            args.root,
            args.transcript,
            expected_bead_id=args.expected_bead_id,
            expected_thread_id=args.expected_thread_id,
        )
        logger.info(
            "swarm validation evidence-pack scan complete",
            extra={"verdict": payload["verdict"], "passed": payload["passed"], "failed": payload["failed"]},
        )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{CHECK_BEAD_ID} swarm validation evidence-pack: {payload['verdict']}")
        if "checks" in payload:
            for check in payload["checks"]:
                status = "PASS" if check["passed"] else "FAIL"
                print(f"- [{status}] {check['check']}: {check['detail']}")
        else:
            print(payload.get("detail", ""))
    return 0 if payload["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
