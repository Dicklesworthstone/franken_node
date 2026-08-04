#!/usr/bin/env python3
"""TNR CI verification and evidence-honesty gate.

This gate fails closed when a reproduction report claims PASS without
executed evidence, when its transcript or metrics artifacts are missing, or
when those artifacts no longer match the report they are meant to prove.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

DEFAULT_REPORT_PATH = ROOT / "reproduction_report.json"
DEFAULT_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "tnr-ci-verification-gate.yml"

TRANSCRIPT_SCHEMA = "tnr-reproduction-transcript-event.v1"
METRICS_SCHEMA = "tnr-reproduction-metrics.v1"
REPORT_SCHEMA = "erp-report.v2"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, f"missing JSON artifact: {_safe_rel(path)}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON artifact {_safe_rel(path)}: {exc}"
    if not isinstance(payload, dict):
        return None, f"JSON artifact must be an object: {_safe_rel(path)}"
    return payload, None


def _load_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows, [f"missing JSONL artifact: {_safe_rel(path)}"]
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{_safe_rel(path)}:{line_number} invalid JSONL row: {exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{_safe_rel(path)}:{line_number} JSONL row must be an object")
            continue
        rows.append(payload)
    if not rows and not errors:
        errors.append(f"JSONL artifact has no rows: {_safe_rel(path)}")
    return rows, errors


def _resolve_artifact_path(ref: str, project_root: Path) -> Path:
    path = Path(ref)
    if not path.is_absolute():
        path = project_root / path
    return path.resolve()


def _report_digest(report: dict[str, Any]) -> str:
    digest_payload = {
        key: value
        for key, value in report.items()
        if key != "artifact_paths"
    }
    canonical = json.dumps(
        digest_payload,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _claim_result_counts(claims: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for claim in claims:
        result_kind = str(claim.get("result_kind", "unknown"))
        counts[result_kind] = counts.get(result_kind, 0) + 1
    return counts


def _finished_events(report: dict[str, Any]) -> list[dict[str, Any]]:
    events = report.get("execution_log", [])
    if not isinstance(events, list):
        return []
    return [
        event
        for event in events
        if isinstance(event, dict) and event.get("event") == "claim_execution_finished"
    ]


def validate_report_honesty(
    report: dict[str, Any],
    *,
    allow_planned: bool = False,
) -> list[str]:
    errors: list[str] = []
    if report.get("schema_version") != REPORT_SCHEMA:
        errors.append(f"report.schema_version must be {REPORT_SCHEMA}")

    run_mode = report.get("run_mode")
    verdict = report.get("verdict")
    claims_raw = report.get("claims")
    if not isinstance(claims_raw, list):
        errors.append("report.claims must be a list")
        claims: list[dict[str, Any]] = []
    else:
        claims = [claim for claim in claims_raw if isinstance(claim, dict)]
        if len(claims) != len(claims_raw):
            errors.append("report.claims entries must all be objects")

    if not isinstance(report.get("execution_log"), list):
        errors.append("report.execution_log must be a list")

    if run_mode == "plan":
        if verdict == "PASS":
            errors.append("planned reports must never report PASS")
        if verdict != "PLANNED":
            errors.append("planned reports must use verdict PLANNED")
        if not allow_planned:
            errors.append(
                "planned report is non-evidence; pass --allow-planned "
                "only for dry-run CI checks"
            )
        for claim in claims:
            claim_id = claim.get("claim_id", "unknown")
            if claim.get("execution_state") != "planned":
                errors.append(f"{claim_id} planned report claim must use execution_state=planned")
            if claim.get("result_kind") != "not_run":
                errors.append(f"{claim_id} planned report claim must use result_kind=not_run")
        return errors

    if run_mode != "executed":
        errors.append("report.run_mode must be either plan or executed")
        return errors

    if verdict not in {"PASS", "FAIL", "ERROR"}:
        errors.append("executed report verdict must be PASS, FAIL, or ERROR")

    counts = _claim_result_counts(claims)
    passed_count = counts.get("pass", 0)
    failed_count = counts.get("fail", 0)
    error_count = counts.get("error", 0)

    expected_counts = {
        "claim_count": len(claims),
        "passed_count": passed_count,
        "failed_count": failed_count,
        "error_count": error_count,
    }
    for field, expected in expected_counts.items():
        if report.get(field) != expected:
            errors.append(f"report.{field} must be {expected}, got {report.get(field)!r}")

    if verdict == "PASS" and (failed_count or error_count or passed_count != len(claims)):
        errors.append("PASS report must have every claim passing and zero failed/error claims")
    if verdict == "FAIL" and failed_count == 0:
        errors.append("FAIL report must contain at least one failed claim")
    if verdict == "ERROR" and error_count == 0:
        errors.append("ERROR report must contain at least one error claim")

    finished_events = _finished_events(report)
    for claim in claims:
        claim_id = str(claim.get("claim_id", "unknown"))
        execution_state = claim.get("execution_state")
        result_kind = claim.get("result_kind")
        if result_kind == "pass":
            if execution_state != "executed":
                errors.append(f"{claim_id} reports pass without execution_state=executed")
            if claim.get("exit_code") != 0:
                errors.append(f"{claim_id} reports pass without exit_code=0")
            for field in ("command", "resolved_procedure_ref", "measured_value", "duration_seconds"):
                if field not in claim:
                    errors.append(f"{claim_id} reports pass without {field}")
            matching_events = [
                event
                for event in finished_events
                if event.get("claim_id") == claim_id
                and event.get("execution_state") == "executed"
                and event.get("result_kind") == "pass"
                and event.get("exit_code") == 0
            ]
            if not matching_events:
                errors.append(f"{claim_id} reports pass without a matching executed transcript event")
        elif result_kind in {"fail", "error"}:
            if execution_state not in {"executed", "error"}:
                errors.append(
                    f"{claim_id} {result_kind} claim has invalid "
                    f"execution_state={execution_state!r}"
                )
        elif result_kind == "not_run":
            errors.append(f"{claim_id} executed report contains non-evidence not_run claim")
        else:
            errors.append(f"{claim_id} has invalid result_kind={result_kind!r}")

    return errors


def validate_evidence_artifacts(
    report: dict[str, Any],
    *,
    project_root: Path = ROOT,
) -> list[str]:
    errors: list[str] = []
    if report.get("run_mode") != "executed":
        return errors

    artifact_paths = report.get("artifact_paths")
    if not isinstance(artifact_paths, dict):
        return ["executed report must include artifact_paths"]

    transcript_ref = artifact_paths.get("transcript_jsonl")
    metrics_ref = artifact_paths.get("metrics_json")
    if not isinstance(transcript_ref, str) or not transcript_ref.strip():
        errors.append("artifact_paths.transcript_jsonl must be a non-empty string")
    if not isinstance(metrics_ref, str) or not metrics_ref.strip():
        errors.append("artifact_paths.metrics_json must be a non-empty string")
    if errors:
        return errors

    transcript_path = _resolve_artifact_path(transcript_ref, project_root)
    metrics_path = _resolve_artifact_path(metrics_ref, project_root)

    rows, row_errors = _load_jsonl(transcript_path)
    errors.extend(row_errors)
    execution_log = report.get("execution_log", [])
    if isinstance(execution_log, list) and rows:
        if len(rows) != len(execution_log):
            errors.append(
                "transcript row count must match report.execution_log "
                f"({len(rows)} != {len(execution_log)})"
            )
        for index, row in enumerate(rows):
            if row.get("schema_version") != TRANSCRIPT_SCHEMA:
                errors.append(f"transcript row {index} has invalid schema_version")
            if row.get("event_index") != index:
                errors.append(f"transcript row {index} has invalid event_index")
            if index < len(execution_log) and row.get("event") != execution_log[index]:
                errors.append(f"transcript row {index} does not match report.execution_log")

    metrics, metrics_error = _load_json(metrics_path)
    if metrics_error:
        errors.append(metrics_error)
        return errors
    if metrics is None:
        errors.append("metrics artifact did not load")
        return errors

    if metrics.get("schema_version") != METRICS_SCHEMA:
        errors.append(f"metrics.schema_version must be {METRICS_SCHEMA}")
    expected_digest = _report_digest(report)
    observed_digest = str(metrics.get("report_digest_sha256", ""))
    if not hmac.compare_digest(observed_digest, expected_digest):
        errors.append("metrics.report_digest_sha256 does not match the report")

    for field in (
        "run_mode",
        "verdict",
        "claim_count",
        "passed_count",
        "failed_count",
        "error_count",
        "duration_seconds",
    ):
        if metrics.get(field) != report.get(field):
            errors.append(f"metrics.{field} must match report.{field}")

    if isinstance(execution_log, list) and metrics.get("execution_event_count") != len(execution_log):
        errors.append("metrics.execution_event_count must match report.execution_log length")

    if metrics.get("claim_result_counts") != _claim_result_counts(
        [claim for claim in report.get("claims", []) if isinstance(claim, dict)]
    ):
        errors.append("metrics.claim_result_counts must match report claims")

    return errors


def validate_workflow(workflow_path: Path = DEFAULT_WORKFLOW_PATH) -> list[str]:
    if not workflow_path.is_file():
        return [f"missing CI workflow: {_safe_rel(workflow_path)}"]
    text = workflow_path.read_text(encoding="utf-8")
    required_markers = {
        "reproduction harness unit tests": "tests/test_reproduce.py",
        "gate unit tests": "tests/test_check_tnr_ci_verification_gate.py",
        "observability registry unit tests": "tests/test_check_tnr_observability_contract.py",
        "observability registry gate": "scripts/check_tnr_observability_contract.py",
        "verification target selftest": "scripts/verify_all_verification_targets.sh --selftest",
        "dry-run honesty check": "--allow-planned",
        "executed reproduction run": "--skip-install --json",
        "gate invocation": "scripts/check_tnr_ci_verification_gate.py",
        "transcript artifact": "reproduction_transcript.jsonl",
        "metrics artifact": "reproduction_metrics_snapshot.json",
        "artifact upload": "actions/upload-artifact",
    }
    errors = [
        f"workflow missing {label}: {marker}"
        for label, marker in required_markers.items()
        if marker not in text
    ]
    return errors


def run_checks(
    *,
    report_path: Path = DEFAULT_REPORT_PATH,
    workflow_path: Path = DEFAULT_WORKFLOW_PATH,
    project_root: Path = ROOT,
    allow_planned: bool = False,
    require_artifacts: bool = True,
    require_workflow: bool = True,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    report, load_error = _load_json(report_path)
    if load_error:
        checks.append({"name": "report_loads", "status": "FAIL", "detail": load_error})
        report = {}
    else:
        checks.append({
            "name": "report_loads",
            "status": "PASS",
            "detail": _safe_rel(report_path, project_root),
        })

    honesty_errors = validate_report_honesty(report, allow_planned=allow_planned) if report else []
    checks.append({
        "name": "report_honesty",
        "status": "PASS" if not honesty_errors else "FAIL",
        "detail": honesty_errors,
    })

    artifact_errors = []
    if report and require_artifacts:
        artifact_errors = validate_evidence_artifacts(report, project_root=project_root)
    checks.append({
        "name": "evidence_artifacts",
        "status": "PASS" if not artifact_errors else "FAIL",
        "detail": artifact_errors,
    })

    workflow_errors = []
    if require_workflow:
        workflow_errors = validate_workflow(workflow_path)
    checks.append({
        "name": "ci_workflow_wiring",
        "status": "PASS" if not workflow_errors else "FAIL",
        "detail": workflow_errors,
    })

    failing = [check for check in checks if check["status"] == "FAIL"]
    return {
        "gate": "tnr_ci_verification_gate",
        "schema_version": "tnr-ci-verification-gate.v1",
        "timestamp": _utc_now_iso(),
        "verdict": "PASS" if not failing else "FAIL",
        "report_path": _safe_rel(report_path, project_root),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main(argv: list[str] | None = None) -> int:
    logger = configure_test_logging("check_tnr_ci_verification_gate")
    parser = argparse.ArgumentParser(description="TNR CI verification evidence gate")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--workflow", type=Path, default=DEFAULT_WORKFLOW_PATH)
    parser.add_argument(
        "--allow-planned",
        action="store_true",
        help="permit dry-run PLANNED reports",
    )
    parser.add_argument("--no-artifacts", action="store_true", help="skip artifact validation")
    parser.add_argument("--no-workflow", action="store_true", help="skip workflow wiring validation")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    logger.info("starting tnr ci verification gate", extra={"report": str(args.report)})
    result = run_checks(
        report_path=args.report,
        workflow_path=args.workflow,
        project_root=ROOT,
        allow_planned=args.allow_planned,
        require_artifacts=not args.no_artifacts,
        require_workflow=not args.no_workflow,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("=== TNR CI Verification Gate ===")
        for check in result["checks"]:
            print(f"  [{'OK' if check['status'] == 'PASS' else 'FAIL'}] {check['name']}")
            detail = check.get("detail")
            if detail:
                if isinstance(detail, list):
                    for entry in detail:
                        print(f"    - {entry}")
                else:
                    print(f"    {detail}")
        print(f"Verdict: {result['verdict']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
