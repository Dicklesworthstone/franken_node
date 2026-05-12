#!/usr/bin/env python3
"""Verification script for bd-3gnh: observability dashboards for asupersync health.

Usage:
    python scripts/check_observability_dashboards.py          # human-readable
    python scripts/check_observability_dashboards.py --json    # machine-readable
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

DOC = ROOT / "docs" / "observability" / "asupersync_control_dashboards.md"
SNAPSHOT = ROOT / "artifacts" / "10.15" / "dashboard_snapshot.json"
ALERT_MAP = ROOT / "artifacts" / "10.15" / "alert_policy_map.json"

DASHBOARD_CATEGORIES = [
    "region_health",
    "obligation_health",
    "lane_pressure",
    "cancel_latency",
]

METRIC_PREFIXES = [
    "fn_region_",
    "fn_obligation_",
    "fn_lane_",
    "fn_cancel_",
]

EVENT_CODES = [
    "OBS-001",
    "OBS-002",
    "OBS-003",
    "OBS-004",
]

INVARIANTS = [
    "INV-OBS-COMPLETE",
    "INV-OBS-ALERT-LINKED",
    "INV-OBS-STABLE-SCHEMA",
    "INV-OBS-FAIL-VISIBLE",
]

ALERT_NAMES = [
    "RegionQuiescenceFailure",
    "ObligationLeak",
    "LaneStarvation",
    "CancelLatencyBudgetExceeded",
]

DOC_KEYWORDS = [
    "Region Health",
    "Obligation Health",
    "Lane Pressure",
    "Cancel Latency",
    "CRITICAL",
    "WARNING",
    "bd-1f8m",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_doc_content():
    results = []
    if not DOC.exists():
        for kw in DOC_KEYWORDS:
            results.append({"check": f"doc: {kw}", "pass": False, "detail": "doc missing"})
        return results
    text = DOC.read_text()
    for kw in DOC_KEYWORDS:
        found = kw in text
        results.append({
            "check": f"doc: {kw}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    # Event codes
    for ec in EVENT_CODES:
        found = ec in text
        results.append({
            "check": f"doc event_code: {ec}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    # Invariants
    for inv in INVARIANTS:
        found = inv in text
        results.append({
            "check": f"doc invariant: {inv}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_dashboard_snapshot():
    results = []
    if not SNAPSHOT.exists():
        results.append({"check": "snapshot: exists", "pass": False, "detail": "MISSING"})
        return results

    try:
        data = json.loads(SNAPSHOT.read_text())
    except json.JSONDecodeError:
        results.append({"check": "snapshot: valid JSON", "pass": False, "detail": "invalid JSON"})
        return results
    results.append({"check": "snapshot: valid JSON", "pass": True, "detail": "valid"})

    # Schema version
    has_version = "schema_version" in data
    results.append({
        "check": "snapshot: schema_version",
        "pass": has_version,
        "detail": data.get("schema_version", "missing"),
    })

    # Panels
    panels = data.get("panels", [])
    panel_categories = {p.get("category", "") for p in panels}
    for cat in DASHBOARD_CATEGORIES:
        found = cat in panel_categories
        results.append({
            "check": f"snapshot panel: {cat}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # Metrics count per panel
    for panel in panels:
        cat = panel.get("category", "unknown")
        metrics = panel.get("metrics", [])
        has_metrics = len(metrics) >= 3
        results.append({
            "check": f"snapshot metrics: {cat}",
            "pass": has_metrics,
            "detail": f"{len(metrics)} metrics" if has_metrics else "insufficient metrics",
        })

    # Metric type validation
    valid_types = {"counter", "gauge", "histogram"}
    all_valid = True
    for panel in panels:
        for m in panel.get("metrics", []):
            if m.get("type", "") not in valid_types:
                all_valid = False
    results.append({
        "check": "snapshot: all metric types valid",
        "pass": all_valid,
        "detail": "valid" if all_valid else "invalid metric types found",
    })

    # Metric prefix validation
    all_prefixed = True
    for panel in panels:
        for m in panel.get("metrics", []):
            if not m.get("name", "").startswith("fn_"):
                all_prefixed = False
    results.append({
        "check": "snapshot: fn_ metric prefix",
        "pass": all_prefixed,
        "detail": "all metrics use fn_ prefix" if all_prefixed else "some metrics missing fn_ prefix",
    })

    return results


def check_alert_policy_map():
    results = []
    if not ALERT_MAP.exists():
        results.append({"check": "alert map: exists", "pass": False, "detail": "MISSING"})
        return results

    try:
        data = json.loads(ALERT_MAP.read_text())
    except json.JSONDecodeError:
        results.append({"check": "alert map: valid JSON", "pass": False, "detail": "invalid JSON"})
        return results
    results.append({"check": "alert map: valid JSON", "pass": True, "detail": "valid"})

    alerts = data.get("alerts", [])
    alert_names = {a.get("name", "") for a in alerts}

    # Required alerts
    for name in ALERT_NAMES:
        found = name in alert_names
        results.append({
            "check": f"alert: {name}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # All alerts have runbook
    all_have_runbook = all(a.get("runbook", "") for a in alerts)
    results.append({
        "check": "alert map: all alerts have runbook",
        "pass": all_have_runbook,
        "detail": "all linked" if all_have_runbook else "some missing runbook",
    })

    # All alerts have severity
    valid_severities = {"CRITICAL", "WARNING", "INFO"}
    all_have_severity = all(a.get("severity", "") in valid_severities for a in alerts)
    results.append({
        "check": "alert map: all alerts have severity",
        "pass": all_have_severity,
        "detail": "valid" if all_have_severity else "some invalid severity",
    })

    # All alerts have category
    all_have_category = all(a.get("category", "") in DASHBOARD_CATEGORIES for a in alerts)
    results.append({
        "check": "alert map: all alerts have dashboard category",
        "pass": all_have_category,
        "detail": "valid" if all_have_category else "some invalid category",
    })

    # Alert count
    enough = len(alerts) >= 4
    results.append({
        "check": "alert map: alert count",
        "pass": enough,
        "detail": f"{len(alerts)} alerts (minimum 4)",
    })

    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(DOC, "dashboard documentation"))
    checks.append(check_file(SNAPSHOT, "dashboard snapshot"))
    checks.append(check_file(ALERT_MAP, "alert policy map"))

    # Doc content
    checks.extend(check_doc_content())

    # Dashboard snapshot
    checks.extend(check_dashboard_snapshot())

    # Alert policy map
    checks.extend(check_alert_policy_map())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-3gnh",
        "title": "Observability dashboards for asupersync control health",
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
    logger = configure_test_logging("check_observability_dashboards")
    logger.info("starting %s verification", "check_observability_dashboards")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-3gnh verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
