#!/usr/bin/env python3
"""Plan validation-autopilot next actions without mutating Beads or Agent Mail."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts import check_blocked_bead_freshness as blocked_freshness  # noqa: E402
from scripts import check_tracker_actionability as tracker_actionability  # noqa: E402
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


CHECK_BEAD_ID = "bd-k4pg9"
TITLE = "Validation autopilot source-only planner"
SCHEMA_VERSION = "franken-node/validation-autopilot/planner/v1"
INPUT_SCHEMA_VERSION = "franken-node/validation-autopilot/input/v1"
DECISION_SCHEMA_VERSION = "franken-node/validation-autopilot/decision/v1"
POLICY_SCHEMA_VERSION = "franken-node/validation-autopilot/policy/v1"
DEFAULT_INPUT_FRESHNESS_SECONDS = 3600
DEFAULT_BLOCKED_FRESHNESS_HOURS = 168
DEFAULT_MAX_RCH_RETRIES = 1
DEFAULT_WORKER_QUARANTINE_FAILURE_THRESHOLD = 2
JSON_DECODER = json.JSONDecoder()

REASON_EVENTS: dict[str, tuple[str, str]] = {
    "VALAUTO_READY_CLAIMABLE": ("claim_ready", "VALAUTO-001"),
    "VALAUTO_BLOCKER_STALE": ("refresh_blocker", "VALAUTO-002"),
    "VALAUTO_BLOCKER_INCOMPLETE": ("refresh_blocker", "VALAUTO-003"),
    "VALAUTO_NO_READY_CREATE_CHILD": ("create_followup_bead", "VALAUTO-004"),
    "VALAUTO_RCH_TIMEOUT_RETRY": ("retry_rch_bounded", "VALAUTO-005"),
    "VALAUTO_RCH_STALE_PROGRESS_RETRY": ("retry_rch_bounded", "VALAUTO-006"),
    "VALAUTO_ACTIVE_OWNER": ("coordinate_owner", "VALAUTO-007"),
    "VALAUTO_EXTERNAL_BLOCKER": ("coordinate_owner", "VALAUTO-008"),
    "VALAUTO_NO_SAFE_MUTATION": ("handoff_only", "VALAUTO-009"),
    "VALAUTO_MALFORMED_INPUT": ("blocked", "VALAUTO-010"),
    "VALAUTO_STALE_INPUT": ("blocked", "VALAUTO-011"),
    "VALAUTO_UNSAFE_LOCAL_CARGO": ("blocked", "VALAUTO-012"),
}

RCH_RETRY_REASONS = {
    "ssh_timeout": "VALAUTO_RCH_TIMEOUT_RETRY",
    "stale_progress": "VALAUTO_RCH_STALE_PROGRESS_RETRY",
}
CARGO_HEAVY_TOKENS = {"cargo", "rustc"}
EXTERNAL_REPO_HINTS = ("franken_engine", "frankensqlite", "fastapi_rust", "/data/projects/", "/dp/")
RCH_HINTS = ("rch", "worker", "remote", "timeout", "ssh", "RCH-E104")


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": check,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _load_json_path(path: Path) -> Any:
    if str(path) == "-":
        return JSON_DECODER.decode(sys.stdin.read())
    return JSON_DECODER.decode(path.read_text(encoding="utf-8"))


def _parse_instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_now(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


def _as_issue_list(payload: Any) -> list[dict[str, Any]]:
    return tracker_actionability._as_issue_list(payload)


def _issue_id(issue: dict[str, Any]) -> str:
    return tracker_actionability._issue_id(issue)


def _issues_by_id(payload: Any) -> dict[str, dict[str, Any]]:
    return {_issue_id(issue): issue for issue in _as_issue_list(payload) if _issue_id(issue)}


def _text_blob(issue: dict[str, Any]) -> str:
    return tracker_actionability._text_blob(issue)


def _first_blocker_from_issue(issue: dict[str, Any]) -> str | None:
    text = _text_blob(issue)
    if not text:
        return None
    for raw_line in text.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        lowered = line.lower()
        if "first blocker" in lowered or "blocked on" in lowered or "timeout" in lowered or "failed" in lowered:
            return line[:500]
    return None


def _policy(input_payload: dict[str, Any]) -> dict[str, Any]:
    policy = input_payload.get("policy") if isinstance(input_payload.get("policy"), dict) else {}
    return {
        "schema_version": policy.get("schema_version", POLICY_SCHEMA_VERSION),
        "input_freshness_seconds": int(policy.get("input_freshness_seconds", DEFAULT_INPUT_FRESHNESS_SECONDS)),
        "blocked_freshness_hours": int(policy.get("blocked_freshness_hours", DEFAULT_BLOCKED_FRESHNESS_HOURS)),
        "require_rch_for_cargo": bool(policy.get("require_rch_for_cargo", True)),
        "max_rch_retries_per_blocker": int(policy.get("max_rch_retries_per_blocker", DEFAULT_MAX_RCH_RETRIES)),
        "worker_quarantine_failure_threshold": int(
            policy.get("worker_quarantine_failure_threshold", DEFAULT_WORKER_QUARANTINE_FAILURE_THRESHOLD)
        ),
        "allow_bead_creation": bool(policy.get("allow_bead_creation", True)),
        "allow_tracker_mutation": bool(policy.get("allow_tracker_mutation", False)),
        "fail_closed_on_mail_gap": bool(policy.get("fail_closed_on_mail_gap", True)),
        "fail_closed_on_reservation_conflict": bool(policy.get("fail_closed_on_reservation_conflict", True)),
    }


def _records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]
    if isinstance(payload, dict):
        records = payload.get("records")
        if isinstance(records, list):
            return [record for record in records if isinstance(record, dict)]
    return []


def _argv_from_command(command: Any) -> list[str] | None:
    if command is None:
        return None
    if isinstance(command, list) and all(isinstance(item, str) for item in command):
        return list(command)
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return [command]
    return None


def _requires_rch(argv: list[str] | None) -> bool:
    if not argv:
        return False
    return any(token in CARGO_HEAVY_TOKENS for token in argv)


def _has_rch_prefix(argv: list[str] | None) -> bool:
    return bool(argv and len(argv) >= 3 and argv[0] == "rch" and argv[1] == "exec" and argv[2] == "--")


def _command_text(argv: list[str] | None) -> str:
    return " ".join(argv or [])


def _int_field(record: dict[str, Any], *names: str) -> int:
    for name in names:
        value = record.get(name)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def _retry_budget_remaining(record: dict[str, Any], policy: dict[str, Any]) -> int:
    max_retries = int(policy["max_rch_retries_per_blocker"])
    attempts = _int_field(record, "retry_attempts", "attempt_count", "attempts")
    return max(0, max_retries - attempts)


def _worker_failure_count(record: dict[str, Any]) -> int:
    explicit = _int_field(record, "worker_failure_count", "same_worker_failure_count")
    if explicit:
        return explicit
    history = record.get("worker_failure_history")
    worker_id = record.get("worker_id")
    if isinstance(history, dict) and isinstance(worker_id, str):
        value = history.get(worker_id)
        if isinstance(value, int):
            return value
    return 0


def _worker_action_for_retry(record: dict[str, Any]) -> str:
    classification = record.get("classification")
    if classification == "stale_progress" and record.get("cancellation_observed"):
        return "retry_after_clean_cancellation"
    return "retry_different_worker"


def _classification_issue(
    classification: dict[str, Any],
    issues_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    issue_id = classification.get("id")
    if isinstance(issue_id, str):
        return issues_by_id.get(issue_id, {})
    return {}


def _is_rch_issue(issue: dict[str, Any]) -> bool:
    blob = _text_blob(issue)
    return any(hint.lower() in blob for hint in RCH_HINTS)


def _is_external_repo_issue(issue: dict[str, Any]) -> bool:
    blob = _text_blob(issue)
    return any(hint.lower() in blob for hint in EXTERNAL_REPO_HINTS)


def _blocked_freshness_result(input_payload: dict[str, Any], policy: dict[str, Any], now: datetime) -> dict[str, Any]:
    provided = input_payload.get("blocked_freshness")
    if isinstance(provided, dict):
        return provided
    return blocked_freshness.run_checks(
        input_payload.get("br_active", []),
        now=now,
        max_age_hours=int(policy["blocked_freshness_hours"]),
    )


def _tracker_actionability_result(input_payload: dict[str, Any]) -> dict[str, Any]:
    provided = input_payload.get("tracker_actionability")
    if isinstance(provided, dict):
        return provided
    return tracker_actionability.run_checks(
        input_payload.get("br_ready", []),
        input_payload.get("bv_plan", {}),
        input_payload.get("br_active", []),
        expected_agent=input_payload.get("agent_name") if isinstance(input_payload.get("agent_name"), str) else None,
    )


def _stable_decision_id(decision: dict[str, Any]) -> str:
    digest_payload = dict(decision)
    digest_payload.pop("decision_id", None)
    digest_payload.pop("decided_at", None)
    encoded = json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "valauto-decision-" + hashlib.sha256(encoded).hexdigest()[:16]


def _decision(
    *,
    trace_id: str,
    now: datetime,
    reason_code: str,
    selected_bead_id: str | None = None,
    proposed_bead: dict[str, Any] | None = None,
    recommended_command: list[str] | None = None,
    recommended_rch_command: list[str] | None = None,
    retry_allowed: bool = False,
    retry_budget_remaining: int = 0,
    worker_action: str | None = None,
    stop_reason: str | None = None,
    first_blocker: str | None = None,
    evidence_refs: list[str] | None = None,
    diagnostics: dict[str, Any] | None = None,
    operator_summary: str,
    mutation_allowed: bool = False,
) -> dict[str, Any]:
    decision_value, event_code = REASON_EVENTS[reason_code]
    requires_rch = _requires_rch(recommended_command)
    payload = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "decision_id": "",
        "trace_id": trace_id,
        "decided_at": _iso_now(now),
        "decision": decision_value,
        "reason_code": reason_code,
        "event_code": event_code,
        "selected_bead_id": selected_bead_id,
        "proposed_bead": proposed_bead,
        "recommended_command": recommended_command,
        "recommended_rch_command": recommended_rch_command,
        "requires_rch": requires_rch,
        "mutation_allowed": mutation_allowed,
        "retry_allowed": retry_allowed,
        "retry_budget_remaining": retry_budget_remaining,
        "worker_action": worker_action,
        "stop_reason": stop_reason,
        "operator_summary": operator_summary,
        "first_blocker": first_blocker,
        "evidence_refs": evidence_refs or [],
        "diagnostics": diagnostics or {},
    }
    payload["decision_id"] = _stable_decision_id(payload)
    return payload


def _blocked_decision(
    *,
    trace_id: str,
    now: datetime,
    reason_code: str,
    operator_summary: str,
    first_blocker: str | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _decision(
        trace_id=trace_id,
        now=now,
        reason_code=reason_code,
        operator_summary=operator_summary,
        first_blocker=first_blocker,
        diagnostics=diagnostics,
    )


def _choose_ready(
    input_payload: dict[str, Any],
    *,
    trace_id: str,
    now: datetime,
    policy: dict[str, Any],
) -> dict[str, Any] | None:
    ready_items = _as_issue_list(input_payload.get("br_ready", []))
    expected_agent = input_payload.get("agent_name")
    handoff = input_payload.get("handoff_context") if isinstance(input_payload.get("handoff_context"), dict) else {}
    conflicted = set(handoff.get("conflicting_reservation_bead_ids") or [])
    for item in ready_items:
        issue_id = _issue_id(item)
        assignee = item.get("assignee") if isinstance(item.get("assignee"), str) else None
        if assignee and expected_agent and not hmac.compare_digest(assignee, expected_agent):
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_ACTIVE_OWNER",
                selected_bead_id=issue_id,
                operator_summary=f"{issue_id} is ready but assigned to {assignee}; coordinate before claiming.",
                diagnostics={"assignee": assignee},
            )
        if issue_id in conflicted and policy["fail_closed_on_reservation_conflict"]:
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_ACTIVE_OWNER",
                selected_bead_id=issue_id,
                operator_summary=f"{issue_id} has an active reservation conflict; coordinate before claiming.",
                diagnostics={"conflicting_reservation": True},
            )
        return _decision(
            trace_id=trace_id,
            now=now,
            reason_code="VALAUTO_READY_CLAIMABLE",
            selected_bead_id=issue_id,
            operator_summary=f"{issue_id} is ready, unblocked, and claimable.",
            evidence_refs=["br ready --json", "bv --recipe actionable --robot-plan"],
        )
    return None


def _choose_owner_coordination(
    classifications: list[dict[str, Any]],
    issues_by_id: dict[str, dict[str, Any]],
    *,
    trace_id: str,
    now: datetime,
) -> dict[str, Any] | None:
    for item in classifications:
        issue = _classification_issue(item, issues_by_id)
        issue_id = item.get("id") if isinstance(item.get("id"), str) else None
        classification = item.get("classification")
        if classification == "assigned_elsewhere":
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_ACTIVE_OWNER",
                selected_bead_id=issue_id,
                operator_summary=f"{issue_id} is assigned elsewhere; coordinate with the owner.",
                first_blocker=_first_blocker_from_issue(issue),
                diagnostics={"classification": classification, "assignee": issue.get("assignee")},
            )
        if classification == "external_blocker" and _is_external_repo_issue(issue) and not _is_rch_issue(issue):
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_EXTERNAL_BLOCKER",
                selected_bead_id=issue_id,
                operator_summary=f"{issue_id} is blocked on external repo evidence; coordinate before mutation.",
                first_blocker=_first_blocker_from_issue(issue),
                diagnostics={"classification": classification},
            )
    return None


def _choose_blocker_refresh(
    blocked_result: dict[str, Any],
    issues_by_id: dict[str, dict[str, Any]],
    *,
    trace_id: str,
    now: datetime,
) -> dict[str, Any] | None:
    audits = blocked_result.get("audits") if isinstance(blocked_result.get("audits"), list) else []
    for audit in audits:
        if not isinstance(audit, dict) or audit.get("classification") == "fresh":
            continue
        issue_id = audit.get("id") if isinstance(audit.get("id"), str) else None
        issue = issues_by_id.get(issue_id or "", {})
        classification = audit.get("classification")
        reason = "VALAUTO_BLOCKER_STALE" if classification == "stale" else "VALAUTO_BLOCKER_INCOMPLETE"
        return _decision(
            trace_id=trace_id,
            now=now,
            reason_code=reason,
            selected_bead_id=issue_id,
            recommended_command=["br", "comment", issue_id or "<bead>", "--stdin"],
            operator_summary=f"{issue_id} needs blocker evidence refresh before ownership changes.",
            first_blocker=_first_blocker_from_issue(issue),
            evidence_refs=["scripts/check_blocked_bead_freshness.py"],
            diagnostics={"blocked_freshness": audit},
        )
    return None


def _choose_rch_retry(
    records: list[dict[str, Any]],
    *,
    trace_id: str,
    now: datetime,
    policy: dict[str, Any],
) -> dict[str, Any] | None:
    for record in records:
        classification = record.get("classification")
        if classification == "success":
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_NO_SAFE_MUTATION",
                operator_summary="RCH evidence is already clean; use the success receipt instead of retrying.",
                retry_budget_remaining=0,
                worker_action="none",
                stop_reason="clean_success",
                evidence_refs=["scripts/normalize_rch_evidence.py"],
                diagnostics={"rch_record": record},
            )
        if classification == "dependency_resolver_error":
            proposed = _proposed_bead(
                [
                    {
                        "id": record.get("sample_id") or "rch-dependency-resolver",
                        "classification": "dependency_resolver_error",
                        "recommended_action": "create-dependency-convergence-bead",
                    }
                ]
            )
            proposed["title"] = "Create dependency-convergence follow-up for RCH resolver failure"
            proposed["labels"] = ["validation-autopilot", "rch", "dependency-convergence"]
            proposed["overlap_search_terms"] = [
                "dependency_resolver_error",
                str(record.get("first_blocker") or "failed to select a version"),
            ]
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_NO_READY_CREATE_CHILD",
                proposed_bead=proposed,
                operator_summary="RCH reached a dependency resolver error; create or refresh dependency-convergence work.",
                retry_budget_remaining=0,
                worker_action="none",
                stop_reason="dependency_convergence_required",
                first_blocker=record.get("first_blocker") if isinstance(record.get("first_blocker"), str) else None,
                evidence_refs=["scripts/normalize_rch_evidence.py"],
                diagnostics={"rch_record": record},
            )
        if record.get("product_diagnostics_reached"):
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_NO_SAFE_MUTATION",
                operator_summary="RCH reached a product diagnostic; stop retrying and preserve the blocker.",
                retry_budget_remaining=0,
                worker_action="none",
                stop_reason="product_diagnostic_reached",
                first_blocker=record.get("first_blocker") if isinstance(record.get("first_blocker"), str) else None,
                evidence_refs=["scripts/normalize_rch_evidence.py"],
                diagnostics={"rch_record": record},
            )

    for record in records:
        classification = record.get("classification")
        reason = RCH_RETRY_REASONS.get(classification if isinstance(classification, str) else "")
        if not reason or not record.get("retry_recommended"):
            continue
        budget = _retry_budget_remaining(record, policy)
        command = _argv_from_command(record.get("command"))
        failure_count = _worker_failure_count(record)
        if failure_count >= int(policy["worker_quarantine_failure_threshold"]):
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_NO_SAFE_MUTATION",
                recommended_command=command,
                recommended_rch_command=command if _has_rch_prefix(command) else None,
                retry_allowed=False,
                retry_budget_remaining=0,
                worker_action="quarantine_or_drain_worker",
                stop_reason="worker_quarantine_recommended",
                operator_summary="Repeated failures on the same worker require quarantine/drain coordination before retry.",
                first_blocker=record.get("first_blocker") if isinstance(record.get("first_blocker"), str) else None,
                evidence_refs=["scripts/normalize_rch_evidence.py"],
                diagnostics={"rch_record": record, "worker_failure_count": failure_count},
            )
        if policy["require_rch_for_cargo"] and _requires_rch(command) and not _has_rch_prefix(command):
            return _blocked_decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_UNSAFE_LOCAL_CARGO",
                operator_summary="Recommended cargo-heavy retry is missing the required rch exec -- prefix.",
                first_blocker=record.get("first_blocker") if isinstance(record.get("first_blocker"), str) else None,
                diagnostics={"command": _command_text(command), "rch_record": record},
            )
        if budget <= 0:
            return _decision(
                trace_id=trace_id,
                now=now,
                reason_code="VALAUTO_NO_SAFE_MUTATION",
                operator_summary="RCH retry budget is exhausted; preserve the blocker and hand off.",
                retry_budget_remaining=0,
                worker_action="none",
                stop_reason="retry_budget_exhausted",
                first_blocker=record.get("first_blocker") if isinstance(record.get("first_blocker"), str) else None,
                evidence_refs=["scripts/normalize_rch_evidence.py"],
                diagnostics={"rch_record": record},
            )
        return _decision(
            trace_id=trace_id,
            now=now,
            reason_code=reason,
            recommended_command=command,
            recommended_rch_command=command if _has_rch_prefix(command) else None,
            retry_allowed=True,
            retry_budget_remaining=budget,
            worker_action=_worker_action_for_retry(record),
            stop_reason=None,
            operator_summary="RCH evidence is retryable infrastructure failure; one bounded remote retry is allowed.",
            first_blocker=record.get("first_blocker") if isinstance(record.get("first_blocker"), str) else None,
            evidence_refs=["scripts/normalize_rch_evidence.py"],
            diagnostics={"rch_record": record},
        )
    return None


def _proposed_bead(classifications: list[dict[str, Any]]) -> dict[str, Any]:
    search_terms = sorted(
        {
            str(value)
            for item in classifications[:5]
            for value in (item.get("id"), item.get("classification"), item.get("recommended_action"))
            if value
        }
    )
    return {
        "title": "Create narrow follow-up for no-ready validation-autopilot state",
        "issue_type": "task",
        "priority": 2,
        "labels": ["validation-autopilot", "no-ready", "blocked-refresh"],
        "description": (
            "## What\nCreate the smallest follow-up Bead that preserves the exact no-ready blocker evidence.\n\n"
            "## Why\nNo claimable Bead exists, and the planner found a non-duplicative support task.\n\n"
            "## How\nUse the attached tracker classifications, exact first blocker text, and validation commands.\n\n"
            "## Risks\nDo not reopen or claim blocked work; create only a narrow support bead after dedupe.\n\n"
            "## Success Criteria\nThe new Bead has concrete files, exact blocker evidence, dependencies, and validation steps."
        ),
        "dependency_suggestions": [],
        "overlap_search_terms": search_terms or ["validation-autopilot", "no-ready"],
        "reserved_paths_hint": ["scripts/check_validation_autopilot.py", "tests/test_check_validation_autopilot.py"],
        "validation_plan": [
            "python3 -m py_compile scripts/check_validation_autopilot.py",
            "python3 -m unittest tests.test_check_validation_autopilot",
            "git diff --check",
        ],
        "dedupe_rationale": "Search overlap terms before creating; do not duplicate open blocked-refresh beads.",
    }


def _choose_followup_or_handoff(
    input_payload: dict[str, Any],
    tracker_result: dict[str, Any],
    classifications: list[dict[str, Any]],
    *,
    trace_id: str,
    now: datetime,
    policy: dict[str, Any],
) -> dict[str, Any]:
    first_class = classifications[0] if classifications else {}
    if first_class.get("classification") == "parent_epic":
        issue_id = first_class.get("id") if isinstance(first_class.get("id"), str) else None
        return _decision(
            trace_id=trace_id,
            now=now,
            reason_code="VALAUTO_NO_SAFE_MUTATION",
            selected_bead_id=issue_id,
            operator_summary=f"{issue_id} is a parent epic; do not claim it as implementation work.",
            first_blocker="Candidate is a parent epic and cannot be claimed as implementation work",
            diagnostics={"classification": "parent_epic"},
        )

    summary = tracker_result.get("summary") if isinstance(tracker_result.get("summary"), dict) else {}
    if policy["allow_bead_creation"] and bool(summary.get("no_ready_recovery", not _as_issue_list(input_payload.get("br_ready", [])))):
        proposed = _proposed_bead(classifications)
        return _decision(
            trace_id=trace_id,
            now=now,
            reason_code="VALAUTO_NO_READY_CREATE_CHILD",
            proposed_bead=proposed,
            operator_summary="No claimable Bead exists; propose a narrow follow-up without mutating the tracker.",
            evidence_refs=["scripts/check_tracker_actionability.py", "bv --recipe actionable --robot-plan"],
            diagnostics={"tracker_summary": summary, "classifications": classifications[:5]},
        )

    return _decision(
        trace_id=trace_id,
        now=now,
        reason_code="VALAUTO_NO_SAFE_MUTATION",
        operator_summary="No safe claim, retry, refresh, or follow-up creation decision is available.",
        diagnostics={"tracker_summary": summary, "classifications": classifications[:5]},
    )


def plan_decision(input_payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    policy = _policy(input_payload)
    trace_id = input_payload.get("trace_id") if isinstance(input_payload.get("trace_id"), str) else "valauto-trace"
    generated_at = _parse_instant(input_payload.get("generated_at"))
    checks = [
        _check("input-object", isinstance(input_payload, dict), "input must be a JSON object"),
        _check(
            "schema-version",
            input_payload.get("schema_version", INPUT_SCHEMA_VERSION) == INPUT_SCHEMA_VERSION,
            f"expected {INPUT_SCHEMA_VERSION}",
        ),
        _check("policy-schema", policy["schema_version"] == POLICY_SCHEMA_VERSION, f"expected {POLICY_SCHEMA_VERSION}"),
    ]

    if generated_at is not None:
        age_seconds = max(0.0, (now - generated_at).total_seconds())
        checks.append(
            _check(
                "input-freshness",
                age_seconds <= int(policy["input_freshness_seconds"]),
                f"age_seconds={age_seconds:.0f}",
            )
        )
    else:
        checks.append(_check("input-freshness", True, "generated_at omitted; using file freshness mode"))

    malformed = [check for check in checks if not check["passed"] and check["check"] != "input-freshness"]
    if malformed:
        decision = _blocked_decision(
            trace_id=trace_id,
            now=now,
            reason_code="VALAUTO_MALFORMED_INPUT",
            operator_summary="Validation-autopilot input is malformed; repair input before planning.",
            diagnostics={"failed_checks": malformed},
        )
        return _result(input_payload, policy, decision, checks, None, None)

    stale = [check for check in checks if check["check"] == "input-freshness" and not check["passed"]]
    if stale:
        decision = _blocked_decision(
            trace_id=trace_id,
            now=now,
            reason_code="VALAUTO_STALE_INPUT",
            operator_summary="Validation-autopilot input is stale; refresh tracker, mail, and RCH evidence.",
            diagnostics={"failed_checks": stale},
        )
        return _result(input_payload, policy, decision, checks, None, None)

    tracker_result = _tracker_actionability_result(input_payload)
    blocked_result = _blocked_freshness_result(input_payload, policy, now)
    rch_records = _records_from_payload(input_payload.get("rch_evidence", []))
    issues_by_id = _issues_by_id(input_payload.get("br_active", []))
    classifications = [
        item for item in tracker_result.get("classifications", []) if isinstance(item, dict)
    ]
    checks.extend(
        [
            _check("tracker-actionability", isinstance(tracker_result, dict), "tracker actionability produced JSON"),
            _check("blocked-freshness", isinstance(blocked_result, dict), "blocked freshness produced JSON"),
            _check("reason-table-complete", set(REASON_EVENTS) >= set(REASON_EVENTS), "reason table loaded"),
        ]
    )

    for chooser in (
        lambda: _choose_ready(input_payload, trace_id=trace_id, now=now, policy=policy),
        lambda: _choose_owner_coordination(classifications, issues_by_id, trace_id=trace_id, now=now),
        lambda: _choose_blocker_refresh(blocked_result, issues_by_id, trace_id=trace_id, now=now),
        lambda: _choose_rch_retry(rch_records, trace_id=trace_id, now=now, policy=policy),
        lambda: _choose_followup_or_handoff(
            input_payload,
            tracker_result,
            classifications,
            trace_id=trace_id,
            now=now,
            policy=policy,
        ),
    ):
        decision = chooser()
        if decision is not None:
            checks.append(
                _check(
                    "rch-prefix-policy",
                    not decision["requires_rch"] or _has_rch_prefix(decision["recommended_command"]),
                    _command_text(decision["recommended_command"]),
                )
            )
            checks.append(
                _check(
                    "no-false-claim",
                    not (
                        decision["decision"] == "claim_ready"
                        and decision["diagnostics"].get("classification") in {"parent_epic", "blocked"}
                    ),
                    "claim_ready cannot target blocked work or parent epics",
                )
            )
            return _result(input_payload, policy, decision, checks, tracker_result, blocked_result)

    raise AssertionError("planner did not emit a decision")


def _result(
    input_payload: dict[str, Any],
    policy: dict[str, Any],
    decision: dict[str, Any],
    checks: list[dict[str, Any]],
    tracker_result: dict[str, Any] | None,
    blocked_result: dict[str, Any] | None,
) -> dict[str, Any]:
    verdict = "PASS" if all(check["passed"] for check in checks) else "FAIL"
    ready_count = len(_as_issue_list(input_payload.get("br_ready", [])))
    rch_records = _records_from_payload(input_payload.get("rch_evidence", []))
    return {
        "schema_version": SCHEMA_VERSION,
        "bead_id": CHECK_BEAD_ID,
        "title": TITLE,
        "verdict": verdict,
        "summary": {
            "ready_count": ready_count,
            "decision": decision["decision"],
            "reason_code": decision["reason_code"],
            "selected_bead_id": decision["selected_bead_id"],
            "retry_allowed": decision["retry_allowed"],
            "rch_record_count": len(rch_records),
            "operator_summary": decision["operator_summary"],
        },
        "decision": decision,
        "policy": policy,
        "tracker_actionability": tracker_result,
        "blocked_freshness": blocked_result,
        "checks": checks,
    }


def _input_payload_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.input is not None:
        payload = _load_json_path(args.input)
        if not isinstance(payload, dict):
            raise ValueError("--input must contain a JSON object")
        return payload

    missing = [
        name
        for name, path in (("--ready", args.ready), ("--items", args.items), ("--bv-plan", args.bv_plan))
        if path is None
    ]
    if missing:
        raise ValueError(f"missing required inputs without --input: {', '.join(missing)}")

    payload: dict[str, Any] = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "trace_id": args.trace_id,
        "agent_name": args.agent_name,
        "generated_at": args.generated_at,
        "br_ready": _load_json_path(args.ready) if args.ready else [],
        "br_active": _load_json_path(args.items) if args.items else [],
        "bv_plan": _load_json_path(args.bv_plan) if args.bv_plan else {"plan": {"tracks": []}},
        "bv_priority": _load_json_path(args.bv_priority) if args.bv_priority else None,
        "bv_insights": _load_json_path(args.bv_insights) if args.bv_insights else None,
        "tracker_actionability": _load_json_path(args.tracker_actionability)
        if args.tracker_actionability
        else None,
        "blocked_freshness": _load_json_path(args.blocked_freshness) if args.blocked_freshness else None,
        "rch_evidence": _load_json_path(args.rch_evidence) if args.rch_evidence else [],
        "handoff_context": _load_json_path(args.handoff) if args.handoff else {},
        "policy": _load_json_path(args.policy) if args.policy else {},
    }
    return payload


def _self_test_payloads() -> dict[str, dict[str, Any]]:
    now = "2026-06-18T15:45:00+00:00"
    base_policy = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "input_freshness_seconds": 3600,
        "blocked_freshness_hours": 168,
        "require_rch_for_cargo": True,
        "max_rch_retries_per_blocker": 1,
        "worker_quarantine_failure_threshold": 2,
        "allow_bead_creation": True,
        "allow_tracker_mutation": False,
        "fail_closed_on_mail_gap": True,
        "fail_closed_on_reservation_conflict": True,
    }

    def base(name: str) -> dict[str, Any]:
        return {
            "schema_version": INPUT_SCHEMA_VERSION,
            "trace_id": f"self-test-{name}",
            "agent_name": "NavyTurtle",
            "generated_at": now,
            "br_ready": [],
            "br_active": [],
            "bv_plan": {"plan": {"tracks": [{"track_id": "track-A", "items": []}]}},
            "tracker_actionability": None,
            "blocked_freshness": {"schema_version": "fixture", "verdict": "PASS", "audits": []},
            "rch_evidence": [],
            "handoff_context": {},
            "policy": base_policy,
        }

    ready = base("ready")
    ready["br_ready"] = [{"id": "bd-ready", "title": "Ready", "status": "open"}]
    ready["br_active"] = [{"id": "bd-ready", "title": "Ready", "status": "open", "issue_type": "task"}]
    ready["bv_plan"] = {"plan": {"tracks": [{"track_id": "track-A", "items": [{"id": "bd-ready"}]}]}}

    followup = base("followup")
    followup["tracker_actionability"] = {
        "schema_version": tracker_actionability.CHECK_SCHEMA_VERSION,
        "verdict": "PASS",
        "summary": {"ready_count": 0, "no_ready_recovery": True},
        "classifications": [
            {
                "id": "bd-blocked",
                "title": "Blocked validation support",
                "classification": "blocked",
                "recommended_action": "refresh-blocker",
            }
        ],
    }

    stale = base("stale")
    stale["br_active"] = [
        {
            "id": "bd-stale",
            "title": "Stale blocker",
            "status": "blocked",
            "notes": "Exact command: rch exec -- cargo test -p frankenengine-node. Current first blocker: timeout.",
            "updated_at": "2026-06-01T00:00:00Z",
        }
    ]
    stale["blocked_freshness"] = {
        "schema_version": blocked_freshness.CHECK_SCHEMA_VERSION,
        "verdict": "FAIL",
        "audits": [{"id": "bd-stale", "classification": "stale", "missing": [], "evidence_age_hours": 999}],
    }

    rch = base("rch")
    rch["rch_evidence"] = [
        {
            "schema_version": "franken-node/rch-evidence-normalizer/v1",
            "sample_id": "ssh-timeout",
            "classification": "ssh_timeout",
            "command": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_valauto cargo test -p frankenengine-node validation_autopilot",
            "worker_id": "vmi1156319",
            "worker_failure_count": 1,
            "first_blocker": "[RCH-E104] SSH command timed out",
            "product_diagnostics_reached": False,
            "retry_recommended": True,
        }
    ]

    repeated = base("repeated-timeout")
    repeated["rch_evidence"] = [
        {
            "schema_version": "franken-node/rch-evidence-normalizer/v1",
            "sample_id": "repeated-timeout",
            "classification": "ssh_timeout",
            "command": "rch exec -- cargo clippy --all-targets -- -D warnings",
            "worker_id": "vmi1156319",
            "worker_failure_count": 2,
            "first_blocker": "[RCH-E104] SSH command timed out twice on vmi1156319",
            "product_diagnostics_reached": False,
            "retry_recommended": True,
        }
    ]

    stale_progress = base("stale-progress")
    stale_progress["rch_evidence"] = [
        {
            "schema_version": "franken-node/rch-evidence-normalizer/v1",
            "sample_id": "stale-progress",
            "classification": "stale_progress",
            "command": "rch exec -- cargo test -p frankenengine-node validation_proof_cache",
            "worker_id": "vmi1167313",
            "worker_failure_count": 1,
            "first_blocker": "fresh heartbeat but progress stale before wall timeout",
            "product_diagnostics_reached": False,
            "retry_recommended": True,
            "cancellation_observed": True,
        }
    ]

    dependency = base("dependency")
    dependency["rch_evidence"] = [
        {
            "schema_version": "franken-node/rch-evidence-normalizer/v1",
            "sample_id": "dependency-resolver",
            "classification": "dependency_resolver_error",
            "command": "rch exec -- cargo test -p frankenengine-node",
            "first_blocker": "error: failed to select a version for `getrandom`.",
            "product_diagnostics_reached": True,
            "retry_recommended": False,
        }
    ]

    product = base("product")
    product["rch_evidence"] = [
        {
            "schema_version": "franken-node/rch-evidence-normalizer/v1",
            "sample_id": "product-compile",
            "classification": "product_failure",
            "command": "rch exec -- cargo check --all-targets",
            "first_blocker": "error[E0599]: no method named `emit_receipt` found",
            "product_diagnostics_reached": True,
            "retry_recommended": False,
        }
    ]

    success = base("success")
    success["rch_evidence"] = [
        {
            "schema_version": "franken-node/rch-evidence-normalizer/v1",
            "sample_id": "clean-success",
            "classification": "success",
            "command": "rch exec -- cargo test -p frankenengine-node doctor_policy_activation_e2e",
            "first_blocker": None,
            "product_diagnostics_reached": False,
            "retry_recommended": False,
        }
    ]

    external = base("external")
    external["br_active"] = [
        {
            "id": "bd-engine",
            "title": "Engine blocker",
            "status": "blocked",
            "notes": "Blocked on sibling /data/projects/franken_engine QuickJsLane wiring.",
        }
    ]
    external["tracker_actionability"] = {
        "schema_version": tracker_actionability.CHECK_SCHEMA_VERSION,
        "verdict": "PASS",
        "summary": {"ready_count": 0, "no_ready_recovery": False},
        "classifications": [
            {
                "id": "bd-engine",
                "classification": "external_blocker",
                "recommended_action": "refresh-blocker",
            }
        ],
    }

    parent = base("parent")
    parent["tracker_actionability"] = {
        "schema_version": tracker_actionability.CHECK_SCHEMA_VERSION,
        "verdict": "PASS",
        "summary": {"ready_count": 0, "no_ready_recovery": True},
        "classifications": [
            {
                "id": "bd-epic",
                "classification": "parent_epic",
                "recommended_action": "create-new-bead",
            }
        ],
    }

    unsafe = base("unsafe-local-cargo")
    unsafe["rch_evidence"] = [
        {
            "schema_version": "franken-node/rch-evidence-normalizer/v1",
            "sample_id": "bad-command",
            "classification": "ssh_timeout",
            "command": "cargo test -p frankenengine-node validation_autopilot",
            "first_blocker": "[RCH-E104] SSH command timed out",
            "product_diagnostics_reached": False,
            "retry_recommended": True,
        }
    ]

    return {
        "ready": ready,
        "followup": followup,
        "stale": stale,
        "rch": rch,
        "repeated": repeated,
        "stale_progress": stale_progress,
        "dependency": dependency,
        "product": product,
        "success": success,
        "external": external,
        "parent": parent,
        "unsafe": unsafe,
    }


def _run_self_test(now: datetime) -> dict[str, Any]:
    cases = _self_test_payloads()
    decisions = {name: plan_decision(payload, now=now)["decision"] for name, payload in cases.items()}
    expected = {
        "ready": "claim_ready",
        "followup": "create_followup_bead",
        "stale": "refresh_blocker",
        "rch": "retry_rch_bounded",
        "repeated": "handoff_only",
        "stale_progress": "retry_rch_bounded",
        "dependency": "create_followup_bead",
        "product": "handoff_only",
        "success": "handoff_only",
        "external": "coordinate_owner",
        "parent": "handoff_only",
        "unsafe": "blocked",
    }
    checks = [
        _check(
            f"self-test-{name}",
            decisions[name]["decision"] == decision,
            f"got {decisions[name]['decision']} expected {decision}",
        )
        for name, decision in expected.items()
    ]
    checks.append(
        _check(
            "unsafe-local-cargo-blocked",
            decisions["unsafe"]["reason_code"] == "VALAUTO_UNSAFE_LOCAL_CARGO",
            decisions["unsafe"]["reason_code"],
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "bead_id": CHECK_BEAD_ID,
        "title": f"{TITLE} self-test",
        "verdict": "PASS" if all(check["passed"] for check in checks) else "FAIL",
        "summary": {
            "case_count": len(cases),
            "decisions": {name: decision["decision"] for name, decision in decisions.items()},
        },
        "decisions": decisions,
        "checks": checks,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--input", type=Path, help="Complete ValidationAutopilotInput JSON file, or '-' for stdin")
    parser.add_argument("--ready", type=Path, help="JSON file from br ready --json")
    parser.add_argument("--items", type=Path, help="JSON file containing br show/list issue details")
    parser.add_argument("--bv-plan", type=Path, help="JSON file from bv --recipe actionable --robot-plan")
    parser.add_argument("--bv-priority", type=Path, help="JSON file from bv --robot-priority")
    parser.add_argument("--bv-insights", type=Path, help="JSON file from bv --robot-insights")
    parser.add_argument("--tracker-actionability", type=Path, help="Precomputed tracker-actionability JSON")
    parser.add_argument("--blocked-freshness", type=Path, help="Precomputed blocked-freshness JSON")
    parser.add_argument("--rch-evidence", type=Path, help="Normalized RCH evidence JSON list/object")
    parser.add_argument("--handoff", type=Path, help="Agent Mail handoff metadata JSON")
    parser.add_argument("--policy", type=Path, help="ValidationAutopilotPolicy JSON override")
    parser.add_argument("--agent-name", default="NavyTurtle")
    parser.add_argument("--trace-id", default="valauto-cli")
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--now", help="Override current UTC time for deterministic tests")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_test_logging("check_validation_autopilot")
    now = _parse_instant(args.now) if args.now else datetime.now(timezone.utc)
    if args.now and now is None:
        print(f"invalid --now timestamp: {args.now}", file=sys.stderr)
        return 2

    if args.self_test:
        result = _run_self_test(now.astimezone(timezone.utc))
    else:
        try:
            input_payload = _input_payload_from_args(args)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"invalid validation-autopilot input: {exc}", file=sys.stderr)
            return 2
        result = plan_decision(input_payload, now=now.astimezone(timezone.utc))

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{TITLE}: {result['verdict']}")
        print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
