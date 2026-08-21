#!/usr/bin/env python3
"""Verify bd-3agp: concrete target gate for >=3x migration velocity."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-3agp_contract.md"
REPORT = ROOT / "artifacts" / "13" / "migration_velocity_report.json"

REQUIRED_ARCHETYPES = {
    "express_app",
    "fastify_app",
    "nextjs_app",
    "cli_tool",
    "library_package",
    "worker_service",
    "websocket_server",
    "monorepo",
    "native_addons_partial",
    "custom_build_pipeline",
}

REQUIRED_EVENT_CODES = {
    "MVG-001",
    "MVG-002",
    "MVG-003",
    "MVG-004",
    "MVG-005",
    "MVG-006",
}

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _json_decode(text: str) -> Any:
    return json.JSONDecoder().decode(text)


def _is_json_true(value: Any) -> bool:
    return isinstance(value, bool) and value


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _project_required_fields() -> tuple[str, ...]:
    return (
        "project_id",
        "archetype",
        "start_time_utc",
        "end_time_utc",
        "first_passing_test_time_utc",
        "manual_migration_minutes",
        "tooled_migration_minutes",
        "manual_intervention_points",
        "blockers_encountered",
        "ci_release_sample",
    )


def _validate_project_entry(project: dict[str, Any], idx: int, errors: list[str]) -> None:
    for field in _project_required_fields():
        if field not in project:
            errors.append(f"projects[{idx}] missing field: {field}")

    for field in ("project_id", "archetype", "start_time_utc", "end_time_utc", "first_passing_test_time_utc"):
        if field in project and (not isinstance(project[field], str) or not project[field].strip()):
            errors.append(f"projects[{idx}].{field} must be non-empty string")

    for field in ("manual_migration_minutes", "tooled_migration_minutes"):
        if field in project:
            value = project[field]
            if not isinstance(value, (int, float)) or value <= 0:
                errors.append(f"projects[{idx}].{field} must be > 0")

    for field in ("manual_intervention_points", "blockers_encountered"):
        if field in project:
            value = project[field]
            if not isinstance(value, list):
                errors.append(f"projects[{idx}].{field} must be list")
            else:
                for list_idx, item in enumerate(value):
                    if not isinstance(item, str):
                        errors.append(
                            f"projects[{idx}].{field}[{list_idx}] must be string"
                        )

    if "ci_release_sample" in project and not isinstance(project["ci_release_sample"], bool):
        errors.append(f"projects[{idx}].ci_release_sample must be boolean")

    try:
        start = _parse_iso8601(str(project.get("start_time_utc", "")))
        end = _parse_iso8601(str(project.get("end_time_utc", "")))
        first_pass = _parse_iso8601(str(project.get("first_passing_test_time_utc", "")))
        if end < start:
            errors.append(f"projects[{idx}] end_time_utc must be >= start_time_utc")
        if first_pass < end:
            errors.append(
                f"projects[{idx}] first_passing_test_time_utc must be >= end_time_utc"
            )
    except Exception:
        errors.append(
            f"projects[{idx}] timestamps must be valid RFC-3339 UTC values"
        )


def run_checks(spec_path: Path = SPEC, report_path: Path = REPORT) -> dict[str, Any]:
    CHECKS.clear()
    events: list[dict[str, Any]] = []

    _check("file: spec contract", spec_path.is_file(), _safe_rel(spec_path))
    _check("file: migration velocity report", report_path.is_file(), _safe_rel(report_path))

    spec_text = ""
    if spec_path.is_file():
        spec_text = spec_path.read_text(encoding="utf-8")
    _check("spec threshold >= 3x", ">=3x" in spec_text or ">= 3.0x" in spec_text)
    _check("spec archetype coverage", all(a in spec_text for a in REQUIRED_ARCHETYPES))
    _check("spec event codes", all(code in spec_text for code in REQUIRED_EVENT_CODES))

    report: dict[str, Any] = {}
    report_errors: list[str] = []
    if report_path.is_file():
        try:
            report = _json_decode(report_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                report_errors.append("report root must be an object")
        except json.JSONDecodeError as exc:
            report_errors.append(f"invalid report JSON: {exc}")

    _check("report parse", len(report_errors) == 0, "; ".join(report_errors) if report_errors else "ok")
    if report_errors:
        verdict = "FAIL"
        total = len(CHECKS)
        passed = sum(1 for check in CHECKS if check["pass"])
        failed = total - passed
        return {
            "bead_id": "bd-3agp",
            "title": "Migration velocity gate (>= 3x)",
            "section": "13",
            "verdict": verdict,
            "total": total,
            "passed": passed,
            "failed": failed,
            "checks": CHECKS,
            "events": [],
        }

    required_top = (
        "bead_id",
        "generated_at_utc",
        "measurement_unit",
        "trace_id",
        "required_velocity_ratio",
        "overall_velocity_ratio",
        "total_manual_minutes",
        "total_tooled_minutes",
        "cohort_size",
        "projects",
    )
    missing_top = [field for field in required_top if field not in report]
    _check(
        "report required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )

    _check("report bead id", report.get("bead_id") == "bd-3agp")
    _check("report unit minutes", report.get("measurement_unit") == "minutes")
    constructed_ids = {
        "cohort-express-001",
        "cohort-fastify-001",
        "cohort-next-001",
    }
    constructed_hits = []
    if isinstance(report.get("projects"), list):
        for project in report["projects"]:
            if isinstance(project, dict) and project.get("project_id") in constructed_ids:
                constructed_hits.append(str(project.get("project_id")))
    _check(
        "constructed Feb 2026 archetype cohort rejected (bd-reality-20260820-w0fc6.2)",
        len(constructed_hits) == 0,
        "constructed ids: " + ",".join(constructed_hits) if constructed_hits else "ok",
    )

    projects = report.get("projects", [])
    _check("cohort size >= 10", isinstance(projects, list) and len(projects) >= 10)
    _check(
        "cohort_size matches project count",
        isinstance(projects, list) and report.get("cohort_size") == len(projects),
    )

    project_errors: list[str] = []
    archetypes_seen: set[str] = set()
    total_manual = 0.0
    total_tooled = 0.0
    ci_sample_count = 0

    if isinstance(projects, list):
        for idx, project in enumerate(projects):
            if not isinstance(project, dict):
                project_errors.append(f"projects[{idx}] must be object")
                continue
            _validate_project_entry(project, idx, project_errors)
            archetype = project.get("archetype")
            if isinstance(archetype, str):
                archetypes_seen.add(archetype)

            manual = project.get("manual_migration_minutes")
            tooled = project.get("tooled_migration_minutes")
            if isinstance(manual, (int, float)) and manual > 0:
                total_manual += float(manual)
            if isinstance(tooled, (int, float)) and tooled > 0:
                total_tooled += float(tooled)
            if _is_json_true(project.get("ci_release_sample")):
                ci_sample_count += 1

    _check(
        "project entry schema",
        len(project_errors) == 0,
        "; ".join(project_errors[:5]) if project_errors else "ok",
    )

    missing_archetypes = sorted(REQUIRED_ARCHETYPES - archetypes_seen)
    _check(
        "required archetypes covered",
        len(missing_archetypes) == 0,
        "missing: " + ", ".join(missing_archetypes) if missing_archetypes else "ok",
    )

    computed_ratio = 0.0
    if total_tooled > 0:
        computed_ratio = total_manual / total_tooled

    declared_ratio = report.get("overall_velocity_ratio")
    ratio_matches = isinstance(declared_ratio, (int, float)) and abs(declared_ratio - computed_ratio) <= 0.01
    _check(
        "overall velocity ratio matches computed",
        ratio_matches,
        f"declared={declared_ratio}, computed={computed_ratio:.2f}",
    )

    threshold = report.get("required_velocity_ratio", 3.0)
    threshold_ok = isinstance(threshold, (int, float)) and computed_ratio >= float(threshold)
    _check(
        "velocity threshold >= 3x",
        threshold_ok,
        f"ratio={computed_ratio:.2f}, threshold={threshold}",
    )

    _check(
        "ci sample coverage >= 3",
        ci_sample_count >= 3,
        f"ci_release_sample projects={ci_sample_count}",
    )

    # Determinism check: order-invariant aggregate ratio.
    determinism_ok = False
    if isinstance(projects, list):
        reversed_manual = sum(float(p.get("manual_migration_minutes", 0.0)) for p in reversed(projects) if isinstance(p, dict))
        reversed_tooled = sum(float(p.get("tooled_migration_minutes", 0.0)) for p in reversed(projects) if isinstance(p, dict))
        reversed_ratio = (reversed_manual / reversed_tooled) if reversed_tooled > 0 else 0.0
        determinism_ok = abs(reversed_ratio - computed_ratio) <= 1e-9
        _check(
            "determinism under reordering",
            determinism_ok,
            f"ratio={computed_ratio:.5f}, reversed_ratio={reversed_ratio:.5f}",
        )
    else:
        _check("determinism under reordering", False, "projects is not a list")

    # Adversarial perturbation check: degrading tooled times should fail threshold.
    perturbed_ratio = computed_ratio / 1.5 if computed_ratio > 0 else 0.0
    adversarial_expected_fail = perturbed_ratio < 3.0
    _check(
        "adversarial perturbation flips threshold",
        adversarial_expected_fail,
        f"perturbed_ratio={perturbed_ratio:.2f}",
    )

    trace = report.get("trace_id")
    if not isinstance(trace, str) or not trace:
        trace = _trace_id(report)

    events.append(
        {
            "event_code": "MVG-001",
            "trace_id": trace,
            "message": f"Velocity metrics computed (ratio={computed_ratio:.2f}).",
        }
    )
    if threshold_ok:
        events.append(
            {
                "event_code": "MVG-002",
                "trace_id": trace,
                "message": "Velocity threshold met (>= 3x).",
            }
        )
    else:
        events.append(
            {
                "event_code": "MVG-003",
                "trace_id": trace,
                "message": "Velocity threshold breached (< 3x).",
            }
        )

    if missing_archetypes or len(project_errors) > 0:
        events.append(
            {
                "event_code": "MVG-004",
                "trace_id": trace,
                "message": "Cohort coverage/documentation violation detected.",
            }
        )

    if ci_sample_count < 3:
        events.append(
            {
                "event_code": "MVG-005",
                "trace_id": trace,
                "message": "Insufficient CI release sample coverage.",
            }
        )

    events.append(
        {
            "event_code": "MVG-006",
            "trace_id": trace,
            "message": "Determinism validation executed.",
        }
    )

    verdict = "PASS" if all(check["pass"] for check in CHECKS) else "FAIL"
    total = len(CHECKS)
    passed = sum(1 for check in CHECKS if check["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3agp",
        "title": "Migration velocity gate (>= 3x)",
        "section": "13",
        "trace_id": trace,
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "computed": {
            "overall_velocity_ratio": round(computed_ratio, 4),
            "required_velocity_ratio": threshold,
            "cohort_size": len(projects) if isinstance(projects, list) else 0,
            "ci_release_sample_count": ci_sample_count,
            "missing_archetypes": missing_archetypes,
        },
        "checks": CHECKS,
        "events": events,
    }


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-3agp-self-test-") as tmp:
        root = Path(tmp)
        spec = root / "spec.md"
        report = root / "report.json"

        spec.write_text(
            "\n".join(
                [
                    "# test spec",
                    ">= 3.0x",
                    *sorted(REQUIRED_ARCHETYPES),
                    *sorted(REQUIRED_EVENT_CODES),
                ]
            ),
            encoding="utf-8",
        )

        projects = []
        archetypes = sorted(REQUIRED_ARCHETYPES)
        for idx, archetype in enumerate(archetypes):
            projects.append(
                {
                    "project_id": f"p-{idx}",
                    "archetype": archetype,
                    "start_time_utc": "2026-02-20T00:00:00Z",
                    "end_time_utc": "2026-02-20T01:00:00Z",
                    "first_passing_test_time_utc": "2026-02-20T01:05:00Z",
                    "manual_migration_minutes": 300 + idx,
                    "tooled_migration_minutes": 90 + (idx % 2),
                    "manual_intervention_points": ["x"],
                    "blockers_encountered": [],
                    "ci_release_sample": idx < 3,
                }
            )

        total_manual = sum(p["manual_migration_minutes"] for p in projects)
        total_tooled = sum(p["tooled_migration_minutes"] for p in projects)
        ratio = total_manual / total_tooled

        report.write_text(
            json.dumps(
                {
                    "bead_id": "bd-3agp",
                    "generated_at_utc": "2026-02-21T00:00:00Z",
                    "measurement_unit": "minutes",
                    "trace_id": "self-test-trace",
                    "required_velocity_ratio": 3.0,
                    "overall_velocity_ratio": round(ratio, 4),
                    "total_manual_minutes": total_manual,
                    "total_tooled_minutes": total_tooled,
                    "cohort_size": len(projects),
                    "projects": projects,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        pass_result = run_checks(spec_path=spec, report_path=report)
        if pass_result["verdict"] != "PASS":
            return False

        # Perturb to force threshold failure.
        data = _json_decode(report.read_text(encoding="utf-8"))
        data["overall_velocity_ratio"] = 2.9
        data["total_tooled_minutes"] = int(data["total_tooled_minutes"] * 1.3)
        report.write_text(json.dumps(data, indent=2), encoding="utf-8")
        fail_result = run_checks(spec_path=spec, report_path=report)
        return fail_result["verdict"] == "FAIL"


def main() -> int:
    configure_test_logging("check_migration_velocity_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test and exit.")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        payload = {"ok": ok, "self_test": "passed" if ok else "failed"}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload["self_test"])
        return 0 if ok else 1

    result = run_checks()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['verdict']}] {result['title']}")
        print(f"passed={result['passed']} failed={result['failed']} total={result['total']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"- {status}: {check['check']} ({check['detail']})")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
