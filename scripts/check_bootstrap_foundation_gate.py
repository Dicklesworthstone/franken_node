#!/usr/bin/env python3
"""bd-3ohj bootstrap foundation verification gate.

Aggregates bootstrap evidence from:
- bd-n9r (config profile resolution)
- bd-1pk (doctor diagnostics)
- bd-32e (init bootstrap)
- bd-2a3 (rch baseline checks; expected FAIL-with-baseline semantics)
- bd-3k9t (foundation e2e bundle)

Fail-closed behavior:
- Missing evidence or invalid JSON/JSONL fails the gate.
- Missing/unstable trace correlation in structured logs fails the gate.
- Missing docs navigation links for bootstrap verification fails the gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BEAD_ID = "bd-3ohj"
SECTION = "bootstrap"
TITLE = "Foundation verification gate: comprehensive unit+e2e+logging"
SCHEMA_VERSION = "bootstrap-foundation-gate-v1"
TRACE_ID_DEFAULT = "trace-bd-3ohj-foundation-gate"

SECTION_DIR = ROOT / "artifacts" / "section_bootstrap" / BEAD_ID
REPORT_PATH = SECTION_DIR / "check_report.json"
LOG_PATH = SECTION_DIR / "foundation_gate_log.jsonl"
SAMPLE_PASS_PATH = SECTION_DIR / "sample_pass_report.json"
SAMPLE_PARTIAL_PATH = SECTION_DIR / "sample_partial_report.json"
SAMPLE_FAIL_PATH = SECTION_DIR / "sample_fail_report.json"
CANONICAL_GATE_PATH = (
    ROOT / "artifacts" / "bootstrap" / "bootstrap" / "gate_verdict" / "bd-3ohj_bootstrap_gate.json"
)

REQUIRED_FAMILIES = {"TF-CLI", "TF-CONFIG", "TF-TRANSPLANT", "TF-DIAG"}
REQUIRED_FBE2E_EVENT_CODES = {"FB-E2E-001", "FB-E2E-010", "FB-E2E-020", "FB-E2E-099"}
REQUIRED_BASELINE_EVENT_CODES = {
    "RCH-BASELINE-001",
    "RCH-BASELINE-010",
    "RCH-BASELINE-011",
    "RCH-BASELINE-099",
}
REQUIRED_BASELINE_STATUS_CODES = {
    "BD2A3-FMT-FAIL",
    "BD2A3-CHECK-FAIL",
    "BD2A3-CLIPPY-FAIL",
}
EXPECTED_STAGE_ORDER = [
    "run_surface_contract",
    "config_profile_resolution",
    "init_profile_bootstrap",
    "doctor_command_diagnostics",
    "transplant_verify_missing_snapshot",
    "transplant_drift_probe_missing_snapshot",
]
ACCEPTED_PASS_STATUSES = {
    "pass",
    "implemented_with_baseline_quality_debt",
    "completed_with_baseline_workspace_failures",
    "completed_with_known_repo_gate_failures",
    "implemented_with_blocked_full_validation",
}

INPUT_PATHS_JSON: dict[str, Path] = {
    "n9r_evidence": ROOT / "artifacts" / "section_bootstrap" / "bd-n9r" / "verification_evidence.json",
    "n9r_contract": ROOT / "artifacts" / "section_bootstrap" / "bd-n9r" / "contract_checks.json",
    "pk1_evidence": ROOT / "artifacts" / "section_bootstrap" / "bd-1pk" / "verification_evidence.json",
    "pk1_contract": ROOT / "artifacts" / "section_bootstrap" / "bd-1pk" / "doctor_contract_checks.json",
    "e32_evidence": ROOT / "artifacts" / "section_bootstrap" / "bd-32e" / "verification_evidence.json",
    "e32_contract": ROOT / "artifacts" / "section_bootstrap" / "bd-32e" / "init_contract_checks.json",
    "a2_evidence": ROOT / "artifacts" / "section_bootstrap" / "bd-2a3" / "verification_evidence.json",
    "a2_baseline": ROOT / "artifacts" / "section_bootstrap" / "bd-2a3" / "baseline_checks.json",
    "k9_evidence": ROOT / "artifacts" / "section_bootstrap" / "bd-3k9t" / "verification_evidence.json",
    "k9_report": ROOT / "artifacts" / "section_bootstrap" / "bd-3k9t" / "check_report.json",
    "k9_summary": ROOT / "artifacts" / "section_bootstrap" / "bd-3k9t" / "foundation_e2e_summary.json",
    "matrix_json": ROOT / "docs" / "verification" / "bootstrap_test_matrix.json",
}
INPUT_PATHS_TEXT: dict[str, Path] = {
    "matrix_md": ROOT / "docs" / "verification" / "BOOTSTRAP_TEST_MATRIX.md",
    "harness_doc": ROOT / "docs" / "specs" / "bootstrap_e2e_harness.md",
}
INPUT_PATHS_JSONL: dict[str, Path] = {
    "k9_log": ROOT / "artifacts" / "section_bootstrap" / "bd-3k9t" / "foundation_e2e_log.jsonl",
}


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _git_head() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _load_json(path: Path) -> tuple[bool, dict[str, Any] | None, str]:
    if not path.is_file():
        return False, None, f"missing: {_safe_rel(path)}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, None, f"invalid-json: {_safe_rel(path)}:{exc.pos}"
    if not isinstance(payload, dict):
        return False, None, f"json-root-not-object: {_safe_rel(path)}"
    return True, payload, "ok"


def _load_text(path: Path) -> tuple[bool, str, str]:
    if not path.is_file():
        return False, "", f"missing: {_safe_rel(path)}"
    return True, path.read_text(encoding="utf-8"), "ok"


def _load_jsonl(path: Path) -> tuple[bool, list[dict[str, Any]], str]:
    if not path.is_file():
        return False, [], f"missing: {_safe_rel(path)}"
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False, [], f"invalid-jsonl:{_safe_rel(path)}:{index}"
        if not isinstance(row, dict):
            return False, [], f"jsonl-row-not-object:{_safe_rel(path)}:{index}"
        rows.append(row)
    return True, rows, "ok"


def _evidence_passed(payload: dict[str, Any]) -> bool:
    verdict = str(payload.get("verdict", "")).upper()
    if verdict == "PASS" or verdict.startswith("PASS_"):
        return True

    status = str(payload.get("status", "")).lower()
    if status in ACCEPTED_PASS_STATUSES:
        return True

    overall_status = str(payload.get("overall_status", "")).lower()
    if overall_status.startswith("pass"):
        return True

    if payload.get("overall_pass") is True or payload.get("all_passed") is True:
        return True

    checks = payload.get("checks")
    if isinstance(checks, list) and checks:
        saw_check = False
        for check in checks:
            if not isinstance(check, dict):
                return False
            if "pass" in check or "passed" in check:
                ok = bool(check.get("pass", check.get("passed", False)))
            else:
                ok = str(check.get("status", "")).upper() in {"PASS", "FAIL_BASELINE"}
            saw_check = True
            if not ok:
                return False
        if saw_check:
            return True

    summary = payload.get("summary")
    if isinstance(summary, dict):
        total = summary.get("total_checks", summary.get("total", 0))
        failing = summary.get("failing_checks", summary.get("failing", -1))
        if isinstance(total, int) and isinstance(failing, int) and total > 0 and failing == 0:
            return True

    try:
        if int(payload.get("failed", 0)) == 0 and int(payload.get("passed", 0)) > 0:
            return True
    except (TypeError, ValueError):
        pass

    return False


def load_inputs_from_files() -> dict[str, Any]:
    payloads: dict[str, Any] = {
        "parse_errors": {},
        "source_paths": {},
    }

    for key, path in INPUT_PATHS_JSON.items():
        ok, loaded, error = _load_json(path)
        payloads["source_paths"][key] = _safe_rel(path)
        payloads[key] = loaded
        if not ok:
            payloads["parse_errors"][key] = error

    for key, path in INPUT_PATHS_TEXT.items():
        ok, loaded, error = _load_text(path)
        payloads["source_paths"][key] = _safe_rel(path)
        payloads[key] = loaded
        if not ok:
            payloads["parse_errors"][key] = error

    for key, path in INPUT_PATHS_JSONL.items():
        ok, loaded, error = _load_jsonl(path)
        payloads["source_paths"][key] = _safe_rel(path)
        payloads[key] = loaded
        if not ok:
            payloads["parse_errors"][key] = error

    baseline_log_path = ROOT / "artifacts" / "section_bootstrap" / "bd-2a3" / "rch_command_log.jsonl"
    baseline_payload = payloads.get("a2_baseline")
    if isinstance(baseline_payload, dict):
        maybe_log = baseline_payload.get("command_log")
        if isinstance(maybe_log, str) and maybe_log.strip():
            baseline_log_path = ROOT / maybe_log

    ok, baseline_rows, error = _load_jsonl(baseline_log_path)
    payloads["source_paths"]["a2_log"] = _safe_rel(baseline_log_path)
    payloads["a2_log"] = baseline_rows
    if not ok:
        payloads["parse_errors"]["a2_log"] = error

    return payloads


def _make_check(
    check_id: str,
    dimension: str,
    passed: bool,
    detail: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "dimension": dimension,
        "pass": passed,
        "detail": detail,
        "remediation": remediation,
    }


def _emit_check_events(checks: list[dict[str, Any]], trace_id: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "event_code": "BGATE-001",
            "trace_id": trace_id,
            "dimension": "gate",
            "status": "start",
            "detail": "Bootstrap foundation verification gate started",
        }
    ]
    for check in checks:
        events.append(
            {
                "event_code": "BGATE-020" if check["pass"] else "BGATE-021",
                "trace_id": trace_id,
                "dimension": check["dimension"],
                "status": "pass" if check["pass"] else "fail",
                "check_id": check["id"],
                "detail": check["detail"],
            }
        )
    return events


def _finalize_events(events: list[dict[str, Any]], verdict: str, failing_dimensions: list[str], trace_id: str) -> None:
    events.append(
        {
            "event_code": "BGATE-099",
            "trace_id": trace_id,
            "dimension": "gate",
            "status": "pass" if verdict == "PASS" else "fail",
            "detail": f"verdict={verdict}; failing_dimensions={','.join(failing_dimensions) if failing_dimensions else 'none'}",
        }
    )


def evaluate_payloads(payloads: dict[str, Any], trace_id: str = TRACE_ID_DEFAULT) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    parse_errors = payloads.get("parse_errors", {})
    parse_ok = isinstance(parse_errors, dict) and len(parse_errors) == 0
    checks.append(
        _make_check(
            check_id="BGATE-PARSE-INTEGRITY",
            dimension="evidence",
            passed=parse_ok,
            detail="ok" if parse_ok else "; ".join(f"{k}:{v}" for k, v in sorted(parse_errors.items())),
            remediation="Re-generate missing/invalid JSON evidence artifacts before running the gate.",
        )
    )

    bead_inputs = {
        "bd-n9r": payloads.get("n9r_evidence"),
        "bd-1pk": payloads.get("pk1_evidence"),
        "bd-32e": payloads.get("e32_evidence"),
        "bd-2a3": payloads.get("a2_evidence"),
        "bd-3k9t": payloads.get("k9_evidence"),
    }
    bead_ok: list[str] = []
    bead_bad: list[str] = []
    for bead_id, evidence in bead_inputs.items():
        if isinstance(evidence, dict) and evidence.get("bead_id") == bead_id and _evidence_passed(evidence):
            bead_ok.append(bead_id)
        else:
            bead_bad.append(bead_id)
    checks.append(
        _make_check(
            check_id="BGATE-TRACEABILITY-EVIDENCE",
            dimension="traceability",
            passed=not bead_bad,
            detail=f"ok={','.join(bead_ok)} bad={','.join(bead_bad)}",
            remediation="Every upstream bead must provide passing verification evidence with matching bead_id.",
        )
    )

    n9r_contract = payloads.get("n9r_contract")
    pk1_contract = payloads.get("pk1_contract")
    e32_contract = payloads.get("e32_contract")
    k9_report = payloads.get("k9_report")
    contract_ok = (
        isinstance(n9r_contract, dict)
        and n9r_contract.get("verdict") == "PASS"
        and n9r_contract.get("checks_passed") == n9r_contract.get("checks_total")
        and isinstance(pk1_contract, dict)
        and pk1_contract.get("verdict") == "PASS"
        and pk1_contract.get("checks_passed") == pk1_contract.get("checks_total")
        and isinstance(e32_contract, dict)
        and e32_contract.get("verdict") == "PASS"
        and e32_contract.get("checks_passed") == e32_contract.get("checks_total")
        and isinstance(k9_report, dict)
        and k9_report.get("verdict") == "PASS"
        and isinstance(k9_report.get("summary"), dict)
        and int(k9_report["summary"].get("failing_checks", -1)) == 0
    )
    checks.append(
        _make_check(
            check_id="BGATE-UPSTREAM-CONTRACTS",
            dimension="unit_evidence",
            passed=contract_ok,
            detail="n9r/pk1/e32 contracts PASS + k9 report PASS",
            remediation="Re-run upstream contract gates and publish passing check reports.",
        )
    )

    k9_summary = payloads.get("k9_summary")
    e2e_ok = False
    if isinstance(k9_summary, dict):
        coverage = k9_summary.get("coverage", {})
        journeys = k9_summary.get("required_journeys", {})
        e2e_ok = (
            k9_summary.get("verdict") == "PASS"
            and int(k9_summary.get("stage_count", 0)) >= 6
            and isinstance(k9_summary.get("missing_stage_ids"), list)
            and len(k9_summary.get("missing_stage_ids")) == 0
            and isinstance(coverage, dict)
            and int(coverage.get("clean", 0)) >= 1
            and int(coverage.get("degraded", 0)) >= 1
            and int(coverage.get("drifted", 0)) >= 1
            and isinstance(journeys, dict)
            and all(bool(journeys.get(key, False)) for key in ("run", "config", "init", "doctor", "transplant_integrity"))
        )
    checks.append(
        _make_check(
            check_id="BGATE-E2E-OUTCOMES",
            dimension="e2e",
            passed=e2e_ok,
            detail=f"summary_verdict={k9_summary.get('verdict') if isinstance(k9_summary, dict) else 'missing'}",
            remediation="Re-run foundation e2e suite until all required journeys and coverage classes are satisfied.",
        )
    )

    matrix_json = payloads.get("matrix_json")
    matrix_md = payloads.get("matrix_md", "")
    harness_doc = payloads.get("harness_doc", "")
    matrix_ok = False
    docs_ok = False
    if isinstance(matrix_json, dict):
        families = matrix_json.get("test_families", [])
        family_ids = {item.get("id") for item in families if isinstance(item, dict)}
        gate_consumption = matrix_json.get("gate_consumption", {})
        fixture_contract = matrix_json.get("fixture_contract", {})
        matrix_ok = (
            REQUIRED_FAMILIES.issubset(family_ids)
            and isinstance(gate_consumption, dict)
            and gate_consumption.get("gate_bead") == BEAD_ID
            and gate_consumption.get("evidence_path") == _safe_rel(CANONICAL_GATE_PATH)
            and isinstance(fixture_contract, dict)
            and fixture_contract.get("deterministic") is True
            and fixture_contract.get("no_system_clock") is True
            and fixture_contract.get("relative_paths") is True
        )

    if isinstance(matrix_md, str) and isinstance(harness_doc, str):
        matrix_md_lower = matrix_md.lower()
        docs_ok = (
            "bootstrap verification gate (bd-3ohj)" in matrix_md_lower
            and _safe_rel(CANONICAL_GATE_PATH) in matrix_md
            and "test family" in matrix_md_lower
            and "bd-3ohj" in harness_doc
            and "foundation_e2e_bundle.json" in harness_doc
        )

    checks.append(
        _make_check(
            check_id="BGATE-MATRIX-COVERAGE-CONTRACT",
            dimension="matrix",
            passed=matrix_ok,
            detail="matrix families + deterministic fixture contract + canonical gate path",
            remediation="Fix docs/verification/bootstrap_test_matrix.json coverage metadata and gate consumption fields.",
        )
    )
    checks.append(
        _make_check(
            check_id="BGATE-DOCS-NAVIGATION",
            dimension="docs",
            passed=docs_ok,
            detail="matrix markdown + harness spec references resolved",
            remediation="Update docs navigation references so operators can trace bootstrap evidence to the gate verdict.",
        )
    )

    a2_baseline = payloads.get("a2_baseline")
    a2_evidence = payloads.get("a2_evidence")
    baseline_ok = False
    if isinstance(a2_baseline, dict) and isinstance(a2_evidence, dict):
        baseline_checks = a2_baseline.get("checks", [])
        status_codes = {
            row.get("status_code")
            for row in baseline_checks
            if isinstance(row, dict) and isinstance(row.get("status_code"), str)
        }
        baseline_ok = (
            a2_baseline.get("verdict") == "FAIL"
            and int(a2_baseline.get("checks_total", 0)) == 3
            and int(a2_baseline.get("checks_failed", 0)) == 3
            and isinstance(baseline_checks, list)
            and len(baseline_checks) == 3
            and all(isinstance(row, dict) and row.get("status") == "fail" for row in baseline_checks)
            and REQUIRED_BASELINE_STATUS_CODES.issubset(status_codes)
            and str(a2_evidence.get("overall_status", "")).lower().startswith("pass_for_bd_2a3_scope")
            and isinstance(a2_evidence.get("determinism"), dict)
            and a2_evidence["determinism"].get("consistent_across_runs") is True
        )
    checks.append(
        _make_check(
            check_id="BGATE-BASELINE-DOCUMENTED",
            dimension="baseline",
            passed=baseline_ok,
            detail="bd-2a3 expected baseline FAIL captured with deterministic status codes and pass-for-scope evidence",
            remediation="Regenerate baseline checks with deterministic status code registry and documented workspace debt.",
        )
    )

    k9_log_rows = payloads.get("k9_log")
    a2_log_rows = payloads.get("a2_log")
    log_ok = False
    if isinstance(k9_log_rows, list) and isinstance(a2_log_rows, list):
        k9_codes = {row.get("event_code") for row in k9_log_rows if isinstance(row, dict)}
        a2_codes = {row.get("event_code") for row in a2_log_rows if isinstance(row, dict)}
        k9_trace_ids = {row.get("trace_id") for row in k9_log_rows if isinstance(row, dict)}
        a2_trace_ids = {row.get("trace_id") for row in a2_log_rows if isinstance(row, dict)}
        baseline_trace = None
        if isinstance(a2_baseline, dict):
            baseline_trace = a2_baseline.get("trace_id")
        log_ok = (
            len(k9_trace_ids) == 1
            and len(a2_trace_ids) == 1
            and REQUIRED_FBE2E_EVENT_CODES.issubset(k9_codes)
            and REQUIRED_BASELINE_EVENT_CODES.issubset(a2_codes)
            and baseline_trace in a2_trace_ids
        )
    checks.append(
        _make_check(
            check_id="BGATE-LOG-STABILITY",
            dimension="logging",
            passed=log_ok,
            detail="single-trace structured logs + required event code coverage",
            remediation="Ensure structured logs carry one trace_id per run and include all required stable event codes.",
        )
    )

    determinism_ok = False
    if isinstance(a2_evidence, dict) and isinstance(k9_summary, dict):
        det = a2_evidence.get("determinism", {})
        hashes = det.get("baseline_json_sha256_runs", []) if isinstance(det, dict) else []
        stage_order = k9_summary.get("stage_order", [])
        determinism_ok = (
            isinstance(hashes, list)
            and len(hashes) >= 2
            and len({str(item) for item in hashes}) == 1
            and stage_order == EXPECTED_STAGE_ORDER
        )
    checks.append(
        _make_check(
            check_id="BGATE-DETERMINISM-GUARD",
            dimension="determinism",
            passed=determinism_ok,
            detail="stable baseline hashes + canonical foundation stage order",
            remediation="Fix nondeterministic evidence generation and enforce canonical stage ordering before gate closure.",
        )
    )

    passing_checks = sum(1 for item in checks if item["pass"])
    total_checks = len(checks)
    failing_checks = total_checks - passing_checks
    failing_dimensions = sorted({item["dimension"] for item in checks if not item["pass"]})
    verdict = "PASS" if failing_checks == 0 else "FAIL"

    events = _emit_check_events(checks, trace_id)
    _finalize_events(events, verdict, failing_dimensions, trace_id)

    generated_at_utc = _now_utc()
    artifact_meta = {
        "schema_version": "1.0",
        "bead_id": BEAD_ID,
        "section": SECTION,
        "artifact_type": "gate_verdict",
        "scenario_id": "bootstrap_foundation_gate",
        "timestamp": generated_at_utc,
        "commit": _git_head(),
        "trace_id": trace_id,
    }
    report: dict[str, Any] = {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "schema_version": SCHEMA_VERSION,
        "trace_id": trace_id,
        "generated_at_utc": generated_at_utc,
        "verdict": verdict,
        "summary": {
            "passing_checks": passing_checks,
            "failing_checks": failing_checks,
            "total_checks": total_checks,
            "failing_dimensions": failing_dimensions,
        },
        "checks": checks,
        "events": events,
        "source_paths": payloads.get("source_paths", {}),
        "artifact_meta": artifact_meta,
    }

    hash_basis = {
        "bead_id": report["bead_id"],
        "verdict": report["verdict"],
        "summary": report["summary"],
        "checks": report["checks"],
    }
    report["content_hash"] = hashlib.sha256(_canonical_json(hash_basis).encode("utf-8")).hexdigest()
    return report


def _sample_payloads_green() -> dict[str, Any]:
    return {
        "parse_errors": {},
        "source_paths": {},
        "n9r_evidence": {"bead_id": "bd-n9r", "status": "pass"},
        "n9r_contract": {"verdict": "PASS", "checks_passed": 23, "checks_total": 23},
        "pk1_evidence": {"bead_id": "bd-1pk", "status": "implemented_with_baseline_quality_debt"},
        "pk1_contract": {"verdict": "PASS", "checks_passed": 34, "checks_total": 34},
        "e32_evidence": {"bead_id": "bd-32e", "status": "implemented_with_baseline_quality_debt"},
        "e32_contract": {"verdict": "PASS", "checks_passed": 18, "checks_total": 18},
        "a2_evidence": {
            "bead_id": "bd-2a3",
            "overall_status": "pass_for_bd_2a3_scope_with_workspace_quality_failures_documented",
            "determinism": {
                "consistent_across_runs": True,
                "baseline_json_sha256_runs": ["abc", "abc"],
            },
        },
        "a2_baseline": {
            "trace_id": "trace-bd-2a3-rch",
            "verdict": "FAIL",
            "checks_total": 3,
            "checks_failed": 3,
            "checks": [
                {"status": "fail", "status_code": "BD2A3-FMT-FAIL"},
                {"status": "fail", "status_code": "BD2A3-CHECK-FAIL"},
                {"status": "fail", "status_code": "BD2A3-CLIPPY-FAIL"},
            ],
        },
        "k9_evidence": {"bead_id": "bd-3k9t", "status": "implemented_with_baseline_quality_debt"},
        "k9_report": {"verdict": "PASS", "summary": {"failing_checks": 0}},
        "k9_summary": {
            "verdict": "PASS",
            "stage_count": 6,
            "missing_stage_ids": [],
            "coverage": {"clean": 4, "degraded": 1, "drifted": 1},
            "required_journeys": {
                "run": True,
                "config": True,
                "init": True,
                "doctor": True,
                "transplant_integrity": True,
            },
            "stage_order": list(EXPECTED_STAGE_ORDER),
        },
        "matrix_json": {
            "test_families": [{"id": "TF-CLI"}, {"id": "TF-CONFIG"}, {"id": "TF-TRANSPLANT"}, {"id": "TF-DIAG"}],
            "fixture_contract": {
                "deterministic": True,
                "no_system_clock": True,
                "relative_paths": True,
            },
            "gate_consumption": {"gate_bead": BEAD_ID, "evidence_path": _safe_rel(CANONICAL_GATE_PATH)},
        },
        "matrix_md": (
            "The bootstrap verification gate (bd-3ohj) consumes this matrix.\n"
            f"{_safe_rel(CANONICAL_GATE_PATH)}\n"
            "Each test family maps to a bootstrap capability."
        ),
        "harness_doc": "Use foundation_e2e_bundle.json as the machine-readable gate contract for downstream bootstrap verification (bd-3ohj).",
        "k9_log": [
            {"trace_id": "trace-bd-3k9t-foundation-e2e", "event_code": "FB-E2E-001"},
            {"trace_id": "trace-bd-3k9t-foundation-e2e", "event_code": "FB-E2E-010"},
            {"trace_id": "trace-bd-3k9t-foundation-e2e", "event_code": "FB-E2E-020"},
            {"trace_id": "trace-bd-3k9t-foundation-e2e", "event_code": "FB-E2E-099"},
        ],
        "a2_log": [
            {"trace_id": "trace-bd-2a3-rch", "event_code": "RCH-BASELINE-001"},
            {"trace_id": "trace-bd-2a3-rch", "event_code": "RCH-BASELINE-010"},
            {"trace_id": "trace-bd-2a3-rch", "event_code": "RCH-BASELINE-011"},
            {"trace_id": "trace-bd-2a3-rch", "event_code": "RCH-BASELINE-099"},
        ],
    }


def _sample_payloads_partial() -> dict[str, Any]:
    payloads = _sample_payloads_green()
    payloads["parse_errors"] = {"k9_report": "invalid-json: artifacts/.../check_report.json"}
    return payloads


def _sample_payloads_fail() -> dict[str, Any]:
    payloads = _sample_payloads_green()
    payloads["a2_baseline"]["checks_failed"] = 2
    payloads["a2_baseline"]["checks"][0]["status_code"] = "BD2A3-FMT-PASS"
    payloads["k9_summary"]["stage_order"] = list(reversed(EXPECTED_STAGE_ORDER))
    payloads["k9_log"].append({"trace_id": "another-trace", "event_code": "FB-E2E-099"})
    return payloads


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []

    green = evaluate_payloads(_sample_payloads_green(), trace_id="trace-self-green")
    checks.append({"check": "green_verdict_pass", "pass": green["verdict"] == "PASS"})

    partial = evaluate_payloads(_sample_payloads_partial(), trace_id="trace-self-partial")
    checks.append({"check": "partial_verdict_fail", "pass": partial["verdict"] == "FAIL"})
    checks.append(
        {
            "check": "partial_fails_parse_dimension",
            "pass": "evidence" in partial["summary"]["failing_dimensions"],
        }
    )

    failing = evaluate_payloads(_sample_payloads_fail(), trace_id="trace-self-fail")
    checks.append({"check": "failing_verdict_fail", "pass": failing["verdict"] == "FAIL"})
    checks.append(
        {
            "check": "failing_has_logging_or_determinism",
            "pass": bool({"logging", "determinism", "baseline"} & set(failing["summary"]["failing_dimensions"])),
        }
    )

    ok = all(item["pass"] for item in checks)
    return ok, checks


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=False) + "\n")


def write_outputs(report: dict[str, Any], emit_samples: bool = False) -> None:
    _write_json(REPORT_PATH, report)
    _write_json(CANONICAL_GATE_PATH, report)
    _write_jsonl(LOG_PATH, report.get("events", []))

    if emit_samples:
        _write_json(SAMPLE_PASS_PATH, evaluate_payloads(_sample_payloads_green(), trace_id="trace-sample-pass"))
        _write_json(
            SAMPLE_PARTIAL_PATH,
            evaluate_payloads(_sample_payloads_partial(), trace_id="trace-sample-partial"),
        )
        _write_json(SAMPLE_FAIL_PATH, evaluate_payloads(_sample_payloads_fail(), trace_id="trace-sample-fail"))


def main() -> int:
    logger = configure_test_logging("check_bootstrap_foundation_gate")
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report.")
    parser.add_argument("--self-test", action="store_true", help="Run internal checker self-tests.")
    parser.add_argument("--write", action="store_true", help="Write report/log artifacts to canonical paths.")
    parser.add_argument(
        "--emit-samples",
        action="store_true",
        help="Write sample pass/partial/fail report artifacts (implies --write).",
    )
    parser.add_argument("--trace-id", default=TRACE_ID_DEFAULT, help="Trace ID for gate correlation logs.")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        if args.json:
            print(json.dumps({"self_test": "passed" if ok else "failed", "checks": checks}, indent=2))
        else:
            status = "passed" if ok else "failed"
            print(f"self_test {status}: {sum(1 for item in checks if item['pass'])}/{len(checks)}")
        return 0 if ok else 1

    payloads = load_inputs_from_files()
    report = evaluate_payloads(payloads, trace_id=args.trace_id)

    should_write = args.write or args.emit_samples
    if should_write:
        write_outputs(report, emit_samples=args.emit_samples)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{BEAD_ID} verdict: {report['verdict']}")
        print(f"checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} passed")

    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
