#!/usr/bin/env python3
"""Verification script for bd-1f8m: invariant-breach runbooks.

Validates that all three runbooks exist, reference correct metrics, event codes,
and lab/integration test references from the actual codebase.

Usage:
    python scripts/check_runbook_links.py          # human-readable
    python scripts/check_runbook_links.py --json    # machine-readable
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REGION_RUNBOOK = ROOT / "docs" / "runbooks" / "region_quiescence_breach.md"
OBLIGATION_RUNBOOK = ROOT / "docs" / "runbooks" / "obligation_leak_incident.md"
CANCEL_RUNBOOK = ROOT / "docs" / "runbooks" / "cancel_timeout_incident.md"
DASHBOARD_DOC = ROOT / "docs" / "observability" / "asupersync_control_dashboards.md"
ALERT_MAP = ROOT / "artifacts" / "10.15" / "alert_policy_map.json"

RUNBOOKS = [
    ("region_quiescence_breach", REGION_RUNBOOK),
    ("obligation_leak_incident", OBLIGATION_RUNBOOK),
    ("cancel_timeout_incident", CANCEL_RUNBOOK),
]

# Metrics that must be referenced (from bd-3gnh dashboards)
REGION_METRICS = [
    "fn_region_quiescence_failures",
    "fn_region_close_total",
    "fn_region_active_gauge",
]

OBLIGATION_METRICS = [
    "fn_obligation_leaked_total",
    "fn_obligation_active_gauge",
    "fn_obligation_reserved_total",
    "fn_obligation_committed_total",
]

CANCEL_METRICS = [
    "fn_cancel_total_duration_ms",
    "fn_cancel_drain_duration_ms",
    "fn_cancel_finalize_duration_ms",
    "fn_cancel_request_duration_ms",
]

# Event codes that must be referenced
REGION_EVENT_CODES = ["RGN-004", "RGN-005"]
OBLIGATION_EVENT_CODES = ["OBL-004"]
CANCEL_EVENT_CODES = ["CAN-004"]

# Required sections in each runbook
REQUIRED_SECTIONS = [
    "Detection Signature",
    "Immediate Containment",
    "Replay Procedure",
    "Rollback Procedure",
]

# Cross-references that must appear
CROSS_REFS = {
    "region_quiescence_breach": ["bd-3gnh", "bd-145n", "bd-1f8m"],
    "obligation_leak_incident": ["bd-3gnh", "bd-145n", "bd-1f8m", "bd-1n5p"],
    "cancel_timeout_incident": ["bd-3gnh", "bd-145n", "bd-1f8m", "bd-1cs7"],
}

# Alert names that must be referenced
ALERT_NAMES = {
    "region_quiescence_breach": "RegionQuiescenceFailure",
    "obligation_leak_incident": "ObligationLeak",
    "cancel_timeout_incident": "CancelLatencyBudgetExceeded",
}

# Severity labels
SEVERITY = {
    "region_quiescence_breach": "CRITICAL",
    "obligation_leak_incident": "CRITICAL",
    "cancel_timeout_incident": "WARNING",
}


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_sections(name, path):
    results = []
    if not path.exists():
        for section in REQUIRED_SECTIONS:
            results.append({"check": f"{name}: section '{section}'", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for section in REQUIRED_SECTIONS:
        found = section in text
        results.append({
            "check": f"{name}: section '{section}'",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_metrics(name, path, metrics):
    results = []
    if not path.exists():
        for m in metrics:
            results.append({"check": f"{name}: metric {m}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for m in metrics:
        found = m in text
        results.append({
            "check": f"{name}: metric {m}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_event_codes(name, path, codes):
    results = []
    if not path.exists():
        for code in codes:
            results.append({"check": f"{name}: event code {code}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for code in codes:
        found = code in text
        results.append({
            "check": f"{name}: event code {code}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_cross_refs(name, path, refs):
    results = []
    if not path.exists():
        for ref in refs:
            results.append({"check": f"{name}: cross-ref {ref}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for ref in refs:
        found = ref in text
        results.append({
            "check": f"{name}: cross-ref {ref}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_alert_reference(name, path):
    alert_name = ALERT_NAMES.get(name, "")
    if not path.exists():
        return {"check": f"{name}: alert {alert_name}", "pass": False, "detail": "file missing"}
    text = path.read_text()
    found = alert_name in text
    return {
        "check": f"{name}: alert {alert_name}",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_severity(name, path):
    severity = SEVERITY.get(name, "")
    if not path.exists():
        return {"check": f"{name}: severity {severity}", "pass": False, "detail": "file missing"}
    text = path.read_text()
    found = severity in text
    return {
        "check": f"{name}: severity {severity}",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_replay_lab_reference(name, path):
    if not path.exists():
        return {"check": f"{name}: lab replay (bd-145n)", "pass": False, "detail": "file missing"}
    text = path.read_text()
    has_lab = "franken-lab replay" in text or "deterministic lab" in text.lower()
    has_seed = "--seed" in text
    ok = has_lab and has_seed
    return {
        "check": f"{name}: lab replay with seed",
        "pass": ok,
        "detail": "lab replay + seed found" if ok else "missing lab replay or seed reference",
    }


def check_dashboard_doc_exists():
    return check_file(DASHBOARD_DOC, "dashboard doc (bd-3gnh)")


def check_alert_map_exists():
    return check_file(ALERT_MAP, "alert policy map (bd-3gnh)")


def check_alert_map_references_runbooks():
    results = []
    if not ALERT_MAP.exists():
        results.append({"check": "alert map: references bd-1f8m", "pass": False, "detail": "file missing"})
        return results
    try:
        data = json.loads(ALERT_MAP.read_text())
    except json.JSONDecodeError:
        results.append({"check": "alert map: valid JSON", "pass": False, "detail": "invalid JSON"})
        return results
    alerts = data.get("alerts", [])
    for alert in alerts:
        runbook = alert.get("runbook", "")
        has_ref = "bd-1f8m" in runbook
        results.append({
            "check": f"alert map: {alert.get('name', '?')} references bd-1f8m",
            "pass": has_ref,
            "detail": runbook if has_ref else "missing bd-1f8m reference",
        })
    return results


def check_metrics_in_dashboard(name, metrics):
    """Verify that metrics referenced in runbooks actually exist in the dashboard doc."""
    results = []
    if not DASHBOARD_DOC.exists():
        for m in metrics:
            results.append({"check": f"dashboard: {m} exists", "pass": False, "detail": "dashboard doc missing"})
        return results
    text = DASHBOARD_DOC.read_text()
    for m in metrics:
        found = m in text
        results.append({
            "check": f"dashboard: {m} exists for {name}",
            "pass": found,
            "detail": "found in dashboard" if found else "NOT FOUND in dashboard",
        })
    return results


def run_checks():
    checks = []

    # File existence
    for name, path in RUNBOOKS:
        checks.append(check_file(path, name))
    checks.append(check_dashboard_doc_exists())
    checks.append(check_alert_map_exists())

    # Required sections
    for name, path in RUNBOOKS:
        checks.extend(check_sections(name, path))

    # Metrics
    checks.extend(check_metrics("region", REGION_RUNBOOK, REGION_METRICS))
    checks.extend(check_metrics("obligation", OBLIGATION_RUNBOOK, OBLIGATION_METRICS))
    checks.extend(check_metrics("cancel", CANCEL_RUNBOOK, CANCEL_METRICS))

    # Event codes
    checks.extend(check_event_codes("region", REGION_RUNBOOK, REGION_EVENT_CODES))
    checks.extend(check_event_codes("obligation", OBLIGATION_RUNBOOK, OBLIGATION_EVENT_CODES))
    checks.extend(check_event_codes("cancel", CANCEL_RUNBOOK, CANCEL_EVENT_CODES))

    # Cross-references
    for name, path in RUNBOOKS:
        checks.extend(check_cross_refs(name, path, CROSS_REFS[name]))

    # Alert references
    for name, path in RUNBOOKS:
        checks.append(check_alert_reference(name, path))

    # Severity
    for name, path in RUNBOOKS:
        checks.append(check_severity(name, path))

    # Lab replay references
    for name, path in RUNBOOKS:
        checks.append(check_replay_lab_reference(name, path))

    # Metrics exist in dashboard doc
    checks.extend(check_metrics_in_dashboard("region", REGION_METRICS))
    checks.extend(check_metrics_in_dashboard("obligation", OBLIGATION_METRICS))
    checks.extend(check_metrics_in_dashboard("cancel", CANCEL_METRICS))

    # Alert map references runbooks
    checks.extend(check_alert_map_references_runbooks())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-1f8m",
        "title": "Invariant-breach runbooks for asupersync incidents",
        "section": "10.15",
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
    logger = configure_test_logging("check_runbook_links")
    logger.info("starting runbook links verification")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-1f8m verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
