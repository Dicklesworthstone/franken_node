#!/usr/bin/env python3
"""bd-cuut: Control-plane lane mapping policy verification gate.

Usage:
    python scripts/check_control_lane_policy.py          # human-readable
    python scripts/check_control_lane_policy.py --json    # machine-readable
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))

SRC = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "control_lane_policy.rs")
MOD = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_15", "bd-cuut_contract.md")

results: list[dict] = []


def check(name: str, passed: bool, detail: str = "") -> bool:
    results.append({"name": name, "passed": passed, "detail": detail})
    return passed


def read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _configure_logging() -> None:
    from scripts.lib.test_logger import configure_test_logging

    configure_test_logging("check_control_lane_policy")


def run_checks() -> bool:
    results.clear()
    src = read(SRC)
    mod_src = read(MOD)
    spec = read(SPEC)

    # --- Source existence ---
    check("source_exists", bool(src), SRC)

    # --- Module wiring ---
    check("mod_wired", "pub mod control_lane_policy;" in mod_src,
          "control_plane/mod.rs must contain pub mod control_lane_policy")

    # --- Three lane classes ---
    lanes = ["Cancel", "Timed", "Ready"]
    for lane in lanes:
        check(f"lane_{lane.lower()}", lane in src, f"ControlLane::{lane}")

    # --- Lane enum has exactly 3 variants ---
    lane_enum = src.count("ControlLane::Cancel") > 0 and src.count("ControlLane::Timed") > 0 and src.count("ControlLane::Ready") > 0
    check("three_lanes", lane_enum, "ControlLane enum has Cancel, Timed, Ready")

    # --- Core types ---
    types = [
        "ControlLane", "ControlTaskClass", "LaneAssignment",
        "LaneBudget", "LaneTickMetrics", "StarvationEvent",
        "PreemptionEvent", "ControlLanePolicy", "LanePolicyAuditRecord",
        "ControlLanePolicySnapshot",
    ]
    for t in types:
        check(f"type_{t}",
              f"pub struct {t}" in src or f"pub enum {t}" in src,
              f"type {t}")

    # --- 19 task classes ---
    task_classes = [
        "CancellationHandler", "DrainOperation", "RegionClose",
        "GracefulShutdown", "AbortCompensation",
        "HealthCheck", "LeaseRenewal", "EpochTransition",
        "EpochSeal", "TransitionBarrier", "DeadlineEnforcement",
        "ForkDetection",
        "BackgroundMaintenance", "TelemetryFlush", "EvidenceArchival",
        "MarkerCompaction", "AuditLogRotation", "MetricsExport",
        "StaleEntryCleanup",
    ]
    found_classes = sum(1 for tc in task_classes if tc in src)
    check("task_classes_19", found_classes == 19, f"{found_classes}/19 task classes")

    # --- Cancel lane: 5 classes ---
    cancel_classes = ["CancellationHandler", "DrainOperation", "RegionClose",
                      "GracefulShutdown", "AbortCompensation"]
    for cc in cancel_classes:
        check(f"cancel_{cc.lower()}", f"{cc} => ControlLane::Cancel" in src,
              f"{cc} -> Cancel")

    # --- Timed lane: 7 classes ---
    timed_classes = ["HealthCheck", "LeaseRenewal", "EpochTransition",
                     "EpochSeal", "TransitionBarrier", "DeadlineEnforcement",
                     "ForkDetection"]
    for tc in timed_classes:
        check(f"timed_{tc.lower()}", f"{tc} => ControlLane::Timed" in src,
              f"{tc} -> Timed")

    # --- Ready lane: 7 classes ---
    ready_classes = ["BackgroundMaintenance", "TelemetryFlush", "EvidenceArchival",
                     "MarkerCompaction", "AuditLogRotation", "MetricsExport",
                     "StaleEntryCleanup"]
    for rc in ready_classes:
        check(f"ready_{rc.lower()}", f"{rc} => ControlLane::Ready" in src,
              f"{rc} -> Ready")

    # --- Budget constants ---
    check("cancel_budget_20", "CANCEL_LANE_BUDGET_PCT" in src and ": u8 = 20" in src,
          "Cancel budget >= 20%")
    check("timed_budget_30", "TIMED_LANE_BUDGET_PCT" in src and ": u8 = 30" in src,
          "Timed budget >= 30%")
    check("ready_budget_50", "READY_LANE_BUDGET_PCT" in src and ": u8 = 50" in src,
          "Ready budget = remainder 50%")

    # --- Operations ---
    ops = [
        "canonical_lane", "canonical_timeout", "lookup", "verify_all_assigned",
        "verify_budget_sum", "assign_task", "tick", "preempt_task",
        "verify_cancel_no_starve", "export_csv", "export_audit_log_jsonl",
        "class_counts_per_lane", "has_priority",
    ]
    for op in ops:
        check(f"op_{op}", f"pub fn {op}" in src, f"operation {op}")

    # --- Event codes (5) ---
    event_codes = ["LAN-001", "LAN-002", "LAN-003", "LAN-004", "LAN-005"]
    found_events = sum(1 for ec in event_codes if ec in src)
    check("event_codes_5", found_events == 5, f"{found_events}/5 event codes")

    # --- Error codes (8) ---
    error_codes = [
        "ERR_CLP_UNKNOWN_TASK", "ERR_CLP_BUDGET_OVERFLOW",
        "ERR_CLP_STARVATION", "ERR_CLP_PREEMPT_FAIL",
        "ERR_CLP_CANCEL_STARVED", "ERR_CLP_INVALID_BUDGET",
        "ERR_CLP_DUPLICATE_CLASS", "ERR_CLP_POLICY_MISMATCH",
    ]
    found_errors = sum(1 for ec in error_codes if ec in src)
    check("error_codes_8", found_errors == 8, f"{found_errors}/8 error codes")

    # --- Invariant markers (6) ---
    invariants = [
        "INV-CLP-LANE-ASSIGNED", "INV-CLP-BUDGET-SUM",
        "INV-CLP-CANCEL-PRIORITY", "INV-CLP-STARVATION-DETECT",
        "INV-CLP-CANCEL-NO-STARVE", "INV-CLP-PREEMPT",
    ]
    found_invs = sum(1 for inv in invariants if inv in src)
    check("invariants_6", found_invs == 6, f"{found_invs}/6 invariant markers")

    # --- Schema version ---
    check("schema_version", 'clp-v1.0' in src, "SCHEMA_VERSION = clp-v1.0")

    # --- CSV export ---
    check("csv_header", "tick,cancel_lane_tasks_run" in src, "CSV header present")

    # --- Starvation thresholds ---
    check("cancel_max_starve_1", "CANCEL_MAX_STARVE_TICKS: u32 = 1" in src,
          "Cancel max starvation = 1 tick")
    check("default_starve_threshold", "DEFAULT_STARVATION_THRESHOLD_TICKS" in src,
          "Default starvation threshold defined")

    # --- Test coverage ---
    test_pattern = r"#\[test\]"
    test_count = len(re.findall(test_pattern, src))
    check("test_coverage", test_count >= 25,
          f"{test_count} inline tests (need >= 25)")

    # --- Spec contract ---
    check("spec_exists", bool(spec), SPEC)

    # --- Serde derives ---
    check("serde_derives",
          "Serialize" in src and "Deserialize" in src,
          "Serde derives for serialization")

    return all(r["passed"] for r in results)


def self_test():
    """Verify the gate script itself."""
    ok = run_checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"self_test: {passed}/{total} checks passed")
    return ok


def main():
    _configure_logging()
    ok = run_checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)

    if "--json" in sys.argv:
        print(json.dumps({
            "bead_id": "bd-cuut",
            "section": "10.15",
            "gate": "control_lane_policy",
            "passed": passed,
            "total": total,
            "ok": ok,
            "checks": results,
        }, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            detail = f" — {r['detail']}" if r["detail"] else ""
            print(f"  [{status}] {r['name']}{detail}")
        print(f"\n{'PASS' if ok else 'FAIL'}: {passed}/{total} checks passed")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
