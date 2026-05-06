#!/usr/bin/env python3
"""Verification script for bd-nr4: operator runbooks for high-severity trust incidents."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BEAD_ID = "bd-nr4"
SECTION = "10.8"
TITLE = "Implement operator runbooks for high-severity trust incidents"

INDEX_PATH = ROOT / "docs" / "runbooks" / "README.md"
SCHEMA_PATH = ROOT / "fixtures" / "runbooks" / "runbook_schema.json"
DRILL_HARNESS = ROOT / "scripts" / "run_drill.py"
DRILL_RESULTS = ROOT / "artifacts" / "section_10_8" / BEAD_ID / "drill_results.json"

REQUIRED_MD_SECTIONS = [
    "## Detection",
    "## Containment",
    "## Investigation",
    "## Repair",
    "## Verification",
    "## Rollback",
    "## Drill Scenario",
    "## Command References",
    "## Cross-References",
]

REQUIRED_MD_FIELDS = [
    "Category",
    "Severity",
    "Estimated Recovery Time",
    "Required Permissions",
    "Operator Privilege Level",
    "Last Reviewed",
    "Review Cadence",
]

REQUIRED_COVERAGE_TAGS = {
    "trust-anchor-compromise",
    "fleet-wide-quarantine-escalation",
    "control-plane-split-brain",
    "key-rotation-emergency",
    "malicious-extension-detection",
}

REQUIRED_CROSS_REFERENCES = {
    "safe_mode.rs",
    "quarantine_store.rs",
    "fencing.rs",
}

RUNBOOK_COMMAND_TRUTH_REQUIREMENTS = {
    "RB-006": {
        "required": [
            "franken-node ops validation-readiness",
            "franken-node ops resource-governor",
            "franken-node proofs queue status",
            "franken-node proofs workers restart",
            "GET /api/v1/proofs/queue/status",
            "POST /api/v1/proofs/workers/restart",
        ],
        "forbidden": [
            "Future dedicated proof queue/status and worker restart CLI/API surface",
            "Manual: restart or scale proof workers through the deployment supervisor",
        ],
    },
}


@dataclass(frozen=True)
class RunbookEntry:
    runbook_id: str
    markdown: str
    json_fixture: str
    category: str


RUNBOOKS: list[RunbookEntry] = [
    RunbookEntry("RB-001", "docs/runbooks/trust_state_corruption.md", "fixtures/runbooks/rb_001_trust_state_corruption.json", "trust_state_corruption"),
    RunbookEntry("RB-002", "docs/runbooks/mass_revocation_event.md", "fixtures/runbooks/rb_002_mass_revocation_event.json", "mass_revocation_event"),
    RunbookEntry("RB-003", "docs/runbooks/fleet_quarantine_activation.md", "fixtures/runbooks/rb_003_fleet_quarantine_activation.json", "fleet_quarantine_activation"),
    RunbookEntry("RB-004", "docs/runbooks/epoch_transition_failure.md", "fixtures/runbooks/rb_004_epoch_transition_failure.json", "epoch_transition_failure"),
    RunbookEntry("RB-005", "docs/runbooks/evidence_ledger_divergence.md", "fixtures/runbooks/rb_005_evidence_ledger_divergence.json", "evidence_ledger_divergence"),
    RunbookEntry("RB-006", "docs/runbooks/proof_pipeline_outage.md", "fixtures/runbooks/rb_006_proof_pipeline_outage.json", "proof_pipeline_outage"),
]


def parse_date(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def check_file(path: Path, label: str) -> dict[str, Any]:
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def load_json(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if not path.exists():
        return None, {"check": f"json: {path.relative_to(ROOT)}", "pass": False, "detail": "MISSING"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, {"check": f"json: {path.relative_to(ROOT)}", "pass": False, "detail": "invalid-json"}
    return payload, {"check": f"json: {path.relative_to(ROOT)}", "pass": True, "detail": "valid"}


def normalize_operator_reference(reference: Any) -> str:
    text = str(reference).strip()
    if text.startswith("-"):
        text = text[1:].strip()
    return text.strip("`").strip()


def is_operator_reference(reference: Any) -> bool:
    normalized = normalize_operator_reference(reference)
    return (
        "franken-node " in normalized
        or "/api/v1/" in normalized
        or "crates/franken-node/src/" in normalized
        or normalized.startswith("Runtime ")
        or normalized.startswith("Manual:")
    )


def markdown_command_references(text: str) -> list[str]:
    lines: list[str] = []
    in_section = False
    for line in text.splitlines():
        if line == "## Command References":
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section and line.strip().startswith("-"):
            lines.append(line.strip())
    return lines


def check_command_reference_truth(runbook_id: str, references: list[Any]) -> list[dict[str, Any]]:
    requirements = RUNBOOK_COMMAND_TRUTH_REQUIREMENTS.get(runbook_id)
    if not requirements:
        return []

    refs_text = "\n".join(normalize_operator_reference(reference) for reference in references)
    checks: list[dict[str, Any]] = []
    missing_required = [token for token in requirements["required"] if token not in refs_text]
    checks.append({
        "check": f"{runbook_id}: command truth required references",
        "pass": len(missing_required) == 0,
        "detail": "present" if len(missing_required) == 0 else f"missing={missing_required}",
    })

    forbidden_hits = [token for token in requirements["forbidden"] if token in refs_text]
    checks.append({
        "check": f"{runbook_id}: command truth excludes unshipped references",
        "pass": len(forbidden_hits) == 0,
        "detail": "clear" if len(forbidden_hits) == 0 else f"forbidden={forbidden_hits}",
    })
    return checks


def validate_markdown(entry: RunbookEntry) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = ROOT / entry.markdown
    checks: list[dict[str, Any]] = [check_file(path, f"markdown {entry.runbook_id}")]
    meta = {"last_reviewed": None}

    if not path.exists():
        return checks, meta

    text = path.read_text(encoding="utf-8")

    title_ok = f"Runbook {entry.runbook_id}" in text
    checks.append({"check": f"{entry.runbook_id}: markdown title", "pass": title_ok, "detail": "present" if title_ok else "missing title"})

    for field in REQUIRED_MD_FIELDS:
        token = f"**{field}**:"
        present = token in text
        checks.append({"check": f"{entry.runbook_id}: markdown field {field}", "pass": present, "detail": "present" if present else "MISSING"})

    for section in REQUIRED_MD_SECTIONS:
        present = section in text
        checks.append({"check": f"{entry.runbook_id}: markdown section {section}", "pass": present, "detail": "present" if present else "MISSING"})

    command_refs = markdown_command_references(text)
    commands_present = any(is_operator_reference(command_ref) for command_ref in command_refs)
    checks.append({"check": f"{entry.runbook_id}: markdown command references", "pass": commands_present, "detail": "present" if commands_present else "MISSING"})
    checks.extend(check_command_reference_truth(entry.runbook_id, command_refs))

    reviewed_match = re.search(r"\*\*Last Reviewed\*\*:\s*(\d{4}-\d{2}-\d{2})", text)
    reviewed_str = reviewed_match.group(1) if reviewed_match else ""
    reviewed_date = parse_date(reviewed_str) if reviewed_str else None
    meta["last_reviewed"] = reviewed_str
    checks.append({
        "check": f"{entry.runbook_id}: markdown last-reviewed format",
        "pass": reviewed_date is not None,
        "detail": reviewed_str if reviewed_str else "missing",
    })

    return checks, meta


def validate_json_runbook(entry: RunbookEntry, schema: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = ROOT / entry.json_fixture
    checks: list[dict[str, Any]] = [check_file(path, f"json fixture {entry.runbook_id}")]
    meta = {"coverage_tags": [], "cross_references": [], "last_reviewed": None}

    payload, load_check = load_json(path)
    checks.append(load_check)
    if payload is None:
        return checks, meta

    required_keys = schema.get("required", [])
    for key in required_keys:
        present = key in payload
        checks.append({"check": f"{entry.runbook_id}: json required key {key}", "pass": present, "detail": "present" if present else "MISSING"})

    checks.append({
        "check": f"{entry.runbook_id}: runbook id matches",
        "pass": payload.get("runbook_id") == entry.runbook_id,
        "detail": f"value={payload.get('runbook_id')}",
    })
    checks.append({
        "check": f"{entry.runbook_id}: category matches",
        "pass": payload.get("category") == entry.category,
        "detail": f"value={payload.get('category')}",
    })

    severity_ok = payload.get("severity") in {"critical", "high"}
    checks.append({"check": f"{entry.runbook_id}: severity valid", "pass": severity_ok, "detail": f"value={payload.get('severity')}"})

    privilege_ok = payload.get("operator_privilege_level") in {"p1", "p2", "p3"}
    checks.append({
        "check": f"{entry.runbook_id}: operator privilege level valid",
        "pass": privilege_ok,
        "detail": f"value={payload.get('operator_privilege_level')}",
    })

    det = payload.get("detection_signature", {})
    det_ok = isinstance(det.get("metrics"), list) and len(det["metrics"]) > 0 and isinstance(det.get("log_patterns"), list) and len(det["log_patterns"]) > 0
    checks.append({"check": f"{entry.runbook_id}: detection signature populated", "pass": det_ok, "detail": "valid" if det_ok else "invalid"})

    steps = payload.get("steps", {})
    phases_ok = all(isinstance(steps.get(phase), list) and len(steps.get(phase, [])) > 0 for phase in ["containment", "investigation", "repair", "verification", "rollback"])
    checks.append({"check": f"{entry.runbook_id}: all response phases populated", "pass": phases_ok, "detail": "valid" if phases_ok else "missing phases"})

    command_refs = payload.get("command_references", [])
    command_refs_ok = isinstance(command_refs, list) and len(command_refs) > 0 and all(is_operator_reference(cmd) for cmd in command_refs)
    checks.append({
        "check": f"{entry.runbook_id}: explicit command/API references",
        "pass": command_refs_ok,
        "detail": f"count={len(command_refs) if isinstance(command_refs, list) else 0}",
    })
    cross_references = payload.get("cross_references", [])
    truth_refs: list[Any] = list(command_refs) if isinstance(command_refs, list) else []
    if isinstance(cross_references, list):
        truth_refs.extend(cross_references)
    checks.extend(check_command_reference_truth(entry.runbook_id, truth_refs))

    coverage_tags = payload.get("coverage_tags", [])
    coverage_ok = isinstance(coverage_tags, list) and len(coverage_tags) > 0
    checks.append({
        "check": f"{entry.runbook_id}: coverage tags populated",
        "pass": coverage_ok,
        "detail": f"tags={coverage_tags}",
    })

    cadence_ok = payload.get("review_cadence") == "per_release_cycle"
    checks.append({
        "check": f"{entry.runbook_id}: review cadence",
        "pass": cadence_ok,
        "detail": f"value={payload.get('review_cadence')}",
    })

    reviewed_str = str(payload.get("last_reviewed", ""))
    reviewed_date = parse_date(reviewed_str)
    checks.append({
        "check": f"{entry.runbook_id}: last-reviewed format",
        "pass": reviewed_date is not None,
        "detail": reviewed_str if reviewed_str else "missing",
    })

    meta["coverage_tags"] = coverage_tags if isinstance(coverage_tags, list) else []
    meta["cross_references"] = cross_references if isinstance(cross_references, list) else []
    meta["last_reviewed"] = reviewed_str

    return checks, meta


def check_index(entries: list[RunbookEntry]) -> list[dict[str, Any]]:
    checks = [check_file(INDEX_PATH, "runbook index")]
    if not INDEX_PATH.exists():
        return checks

    text = INDEX_PATH.read_text(encoding="utf-8")
    for entry in entries:
        checks.append({
            "check": f"index: {entry.runbook_id} markdown listed",
            "pass": entry.markdown in text,
            "detail": "present" if entry.markdown in text else "MISSING",
        })
        checks.append({
            "check": f"index: {entry.runbook_id} fixture listed",
            "pass": entry.json_fixture in text,
            "detail": "present" if entry.json_fixture in text else "MISSING",
        })
    return checks


def check_drill_results() -> list[dict[str, Any]]:
    checks = [check_file(DRILL_HARNESS, "run_drill harness"), check_file(DRILL_RESULTS, "drill results")]
    if not DRILL_RESULTS.exists():
        return checks

    payload, load_check = load_json(DRILL_RESULTS)
    checks.append(load_check)
    if payload is None:
        return checks

    rows: list[dict[str, Any]]
    if isinstance(payload, dict) and "drills" in payload and isinstance(payload.get("drills"), list):
        rows = payload["drills"]
    elif isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        rows = []

    checks.append({
        "check": "drill: at least one drill entry",
        "pass": len(rows) >= 1,
        "detail": f"entries={len(rows)}",
    })

    any_pass = any(str(row.get("status", "")).upper() == "PASS" for row in rows)
    checks.append({
        "check": "drill: at least one PASS execution",
        "pass": any_pass,
        "detail": "pass found" if any_pass else "no PASS entries",
    })

    freshness_ok = False
    now = datetime.now(timezone.utc)
    for row in rows:
        completed = row.get("completed_at") or row.get("timestamp")
        if not completed:
            continue
        try:
            ts = datetime.fromisoformat(str(completed).replace("Z", "+00:00"))
        except ValueError:
            continue
        age_days = (now - ts).days
        if age_days <= 30:
            freshness_ok = True
            break

    checks.append({
        "check": "drill: freshness <=30 days",
        "pass": freshness_ok,
        "detail": "fresh" if freshness_ok else "stale or missing timestamps",
    })

    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(SCHEMA_PATH, "runbook schema"))

    schema, schema_check = load_json(SCHEMA_PATH)
    checks.append(schema_check)
    if schema is None:
        return {
            "bead_id": BEAD_ID,
            "title": TITLE,
            "section": SECTION,
            "overall_pass": False,
            "verdict": "FAIL",
            "summary": {"passing": 0, "failing": 1, "total": 1},
            "checks": checks,
        }

    all_coverage_tags: set[str] = set()
    all_cross_refs: set[str] = set()

    for entry in RUNBOOKS:
        md_checks, _ = validate_markdown(entry)
        checks.extend(md_checks)
        json_checks, meta = validate_json_runbook(entry, schema)
        checks.extend(json_checks)

        all_coverage_tags.update(str(tag) for tag in meta["coverage_tags"])
        all_cross_refs.update(str(ref) for ref in meta["cross_references"])

    checks.extend(check_index(RUNBOOKS))
    checks.extend(check_drill_results())

    missing_tags = sorted(REQUIRED_COVERAGE_TAGS - all_coverage_tags)
    checks.append({
        "check": "coverage: required high-severity categories covered",
        "pass": len(missing_tags) == 0,
        "detail": "all covered" if len(missing_tags) == 0 else f"missing={missing_tags}",
    })

    missing_refs = sorted(ref for ref in REQUIRED_CROSS_REFERENCES if ref not in all_cross_refs)
    checks.append({
        "check": "cross-references: safe-mode/quarantine/epoch paths covered",
        "pass": len(missing_refs) == 0,
        "detail": "all covered" if len(missing_refs) == 0 else f"missing={missing_refs}",
    })

    passing = sum(1 for check in checks if check["pass"])
    failing = sum(1 for check in checks if not check["pass"])

    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": len(checks),
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    checks = [
        {"check": "self: runbooks_count", "pass": len(RUNBOOKS) == 6},
        {"check": "self: required_coverage_tags", "pass": len(REQUIRED_COVERAGE_TAGS) == 5},
        {"check": "self: parse_date", "pass": parse_date("2026-02-21") is not None},
    ]
    return all(c["pass"] for c in checks), checks


def main() -> int:
    logger = configure_test_logging("check_operator_runbooks")
    as_json = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    if run_self_test:
        ok, checks = self_test()
        payload = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if as_json:
            print(json.dumps(payload, indent=2))
        else:
            print("PASS" if ok else "FAIL")
            for check in checks:
                status = "PASS" if check["pass"] else "FAIL"
                print(f"[{status}] {check['check']}")
        return 0 if ok else 1

    result = run_checks()
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        summary = result["summary"]
        print(f"{result['verdict']}: {TITLE} ({summary['passing']}/{summary['total']} checks passed)")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")

    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
