#!/usr/bin/env python3
"""Verification script for bd-28wj: non-negotiable constraints.

Validates that all 13 constraints are documented with enforcement mechanisms,
event codes, and invariant definitions.

Usage:
    python scripts/check_non_negotiable_constraints.py          # human-readable
    python scripts/check_non_negotiable_constraints.py --json    # machine-readable
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

CONSTRAINT_DOC = ROOT / "docs" / "governance" / "non_negotiable_constraints.md"
WAIVER_REGISTRY = ROOT / "docs" / "governance" / "waiver_registry.json"
SPEC = ROOT / "docs" / "specs" / "section_4" / "bd-28wj_contract.md"

CONSTRAINT_IDS = [f"C-{i:02d}" for i in range(1, 14)]

CONSTRAINT_KEYWORDS = {
    "C-01": ["Engine", "franken_engine", "fork"],
    "C-02": ["Asupersync", "Cx-first", "region-owned"],
    "C-03": ["FrankenTUI", "frankentui"],
    "C-04": ["FrankenSQLite", "frankensqlite"],
    "C-05": ["SQLModel", "sqlmodel_rust"],
    "C-06": ["FastAPI", "fastapi_rust"],
    "C-07": ["Waiver", "rationale", "expiry"],
    "C-08": ["Compatibility", "shim", "policy-visible"],
    "C-09": ["line-by-line", "translation", "spec extraction"],
    "C-10": ["Policy-gated", "dangerous", "auditable"],
    "C-11": ["Evidence", "benchmark", "reproducible"],
    "C-12": ["Deterministic", "migration", "replayable"],
    "C-13": ["Safe defaults", "safe operation"],
}

EVENT_CODES = ["NNC-001", "NNC-002", "NNC-003", "NNC-004"]

INVARIANTS = [
    "INV-NNC-COMPLETE",
    "INV-NNC-ACTIONABLE",
    "INV-NNC-AUDITABLE",
    "INV-NNC-NO-SILENT-EROSION",
]

REQUIRED_DOC_SECTIONS = [
    "Constraint Registry",
    "Waiver Process",
    "Quarterly Audit",
]

SEVERITIES = ["HARD", "SOFT"]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_constraint_doc():
    results = []
    if not CONSTRAINT_DOC.exists():
        results.append({"check": "constraint doc: exists", "pass": False, "detail": "MISSING"})
        return results
    text = CONSTRAINT_DOC.read_text()

    # Required sections
    for section in REQUIRED_DOC_SECTIONS:
        found = section in text
        results.append({
            "check": f"doc section: {section}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # All 13 constraints documented
    for cid in CONSTRAINT_IDS:
        found = cid in text
        results.append({
            "check": f"constraint {cid} documented",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # Keywords for each constraint
    for cid, keywords in CONSTRAINT_KEYWORDS.items():
        for kw in keywords:
            found = kw.lower() in text.lower()
            results.append({
                "check": f"{cid}: keyword '{kw}'",
                "pass": found,
                "detail": "found" if found else "NOT FOUND",
            })

    # Violation codes
    for cid in CONSTRAINT_IDS:
        violation_code = f"NNC-002:{cid}"
        found = violation_code in text
        results.append({
            "check": f"{cid}: violation code {violation_code}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # Severity labels
    for sev in SEVERITIES:
        found = sev in text
        results.append({
            "check": f"severity: {sev}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # Enforcement reference
    has_ci = "CI" in text
    has_review = "review" in text.lower()
    results.append({
        "check": "enforcement: CI gates referenced",
        "pass": has_ci,
        "detail": "found" if has_ci else "NOT FOUND",
    })
    results.append({
        "check": "enforcement: review gates referenced",
        "pass": has_review,
        "detail": "found" if has_review else "NOT FOUND",
    })

    # Fix instructions for each constraint
    fix_count = text.lower().count("**fix:**")
    results.append({
        "check": "fix instructions for all constraints",
        "pass": fix_count >= 13,
        "detail": f"{fix_count} fix instructions (need 13)",
    })

    return results


def check_waiver_registry():
    results = []
    if not WAIVER_REGISTRY.exists():
        results.append({"check": "waiver registry: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "waiver registry: exists", "pass": True, "detail": "found"})
    try:
        data = json.loads(WAIVER_REGISTRY.read_text())
    except json.JSONDecodeError:
        results.append({"check": "waiver registry: valid JSON", "pass": False, "detail": "invalid JSON"})
        return results
    results.append({"check": "waiver registry: valid JSON", "pass": True, "detail": "valid"})

    has_schema = "schema_version" in data
    results.append({
        "check": "waiver registry: schema_version",
        "pass": has_schema,
        "detail": data.get("schema_version", "missing"),
    })

    has_waivers = "waivers" in data and isinstance(data["waivers"], list)
    results.append({
        "check": "waiver registry: waivers array",
        "pass": has_waivers,
        "detail": "array present" if has_waivers else "MISSING",
    })

    return results


def check_spec_content():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec: exists", "pass": False, "detail": "MISSING"})
        return results
    text = SPEC.read_text()

    for code in EVENT_CODES:
        found = code in text
        results.append({
            "check": f"spec: event_code {code}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    for inv in INVARIANTS:
        found = inv in text
        results.append({
            "check": f"spec: invariant {inv}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # All 13 constraints in spec
    has_13 = "13" in text and "constraint" in text.lower()
    results.append({
        "check": "spec: references 13 constraints",
        "pass": has_13,
        "detail": "found" if has_13 else "NOT FOUND",
    })

    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(CONSTRAINT_DOC, "constraint doc"))
    checks.append(check_file(WAIVER_REGISTRY, "waiver registry"))
    checks.append(check_file(SPEC, "spec contract"))

    # Constraint doc content
    checks.extend(check_constraint_doc())

    # Waiver registry
    checks.extend(check_waiver_registry())

    # Spec content
    checks.extend(check_spec_content())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-28wj",
        "title": "Non-Negotiable Constraints — 13 hard guardrails",
        "section": "4",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-28wj verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
