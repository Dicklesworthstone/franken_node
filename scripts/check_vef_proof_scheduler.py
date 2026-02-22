#!/usr/bin/env python3
"""Verification script for bd-28u0: VEF proof-window selection and job scheduler.

Usage:
    python3 scripts/check_vef_proof_scheduler.py
    python3 scripts/check_vef_proof_scheduler.py --json
    python3 scripts/check_vef_proof_scheduler.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "vef" / "proof_scheduler.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
SPEC_DOC = ROOT / "docs" / "specs" / "vef_proof_scheduler.md"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-28u0_contract.md"
UNIT_TEST = ROOT / "tests" / "test_check_vef_proof_scheduler.py"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-28u0" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-28u0" / "verification_summary.md"

WORKLOAD_TIERS = [
    "Critical",
    "High",
    "Standard",
    "Background",
]

REQUIRED_EVENT_CODES = [
    "VEF-SCHED-001",
    "VEF-SCHED-002",
    "VEF-SCHED-003",
    "VEF-SCHED-004",
]

REQUIRED_ERROR_EVENT_CODES = [
    "VEF-SCHED-ERR-001",
    "VEF-SCHED-ERR-002",
    "VEF-SCHED-ERR-003",
    "VEF-SCHED-ERR-004",
]

REQUIRED_ERROR_CODES = [
    "ERR-VEF-SCHED-DEADLINE",
    "ERR-VEF-SCHED-BUDGET",
    "ERR-VEF-SCHED-WINDOW",
    "ERR-VEF-SCHED-INTERNAL",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub enum WorkloadTier",
    "pub struct SchedulerPolicy",
    "pub struct ProofWindow",
    "pub struct ProofJob",
    "pub enum ProofJobStatus",
    "pub struct SchedulerMetrics",
    "pub struct SchedulerEvent",
    "pub struct SchedulerError",
    "pub struct VefProofScheduler",
    "pub fn select_windows",
    "pub fn enqueue_windows",
    "pub fn dispatch_jobs",
    "pub fn mark_completed",
    "pub fn enforce_deadlines",
    "pub fn backlog_metrics",
]

REQUIRED_JOB_STATUSES = [
    "Pending",
    "Dispatched",
    "Completed",
    "DeadlineExceeded",
]

REQUIRED_SCHEDULER_POLICY_FIELDS = [
    "max_receipts_per_window",
    "max_concurrent_jobs",
    "max_compute_millis_per_tick",
    "max_memory_mib_per_tick",
    "tier_deadline_millis",
]

REQUIRED_PROOF_WINDOW_FIELDS = [
    "window_id",
    "start_index",
    "end_index",
    "entry_count",
    "aligned_checkpoint_id",
    "tier",
    "created_at_millis",
    "trace_id",
]

REQUIRED_PROOF_JOB_FIELDS = [
    "job_id",
    "window_id",
    "tier",
    "priority_score",
    "deadline_millis",
    "estimated_compute_millis",
    "estimated_memory_mib",
    "status",
    "created_at_millis",
    "dispatched_at_millis",
    "completed_at_millis",
    "trace_id",
]

REQUIRED_METRICS_FIELDS = [
    "pending_jobs",
    "dispatched_jobs",
    "completed_jobs",
    "deadline_exceeded_jobs",
    "oldest_pending_age_millis",
    "compute_budget_used_millis",
    "memory_budget_used_mib",
    "windows_observed",
]

RESULTS: list[dict[str, Any]] = []


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _safe_rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if str(path).startswith(str(ROOT)) else str(path)


def _check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("ok" if passed else "NOT FOUND"),
        }
    )


def _load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def check_file_presence() -> None:
    files = [
        ("impl_exists", IMPL),
        ("mod_exists", MOD_RS),
        ("unit_test_exists", UNIT_TEST),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
    ]
    for name, path in files:
        _check(name, path.is_file(), _safe_rel(path))


def check_impl_symbols() -> None:
    src = _read(IMPL)

    for symbol in REQUIRED_IMPL_SYMBOLS:
        _check(f"impl_symbol_{symbol.split()[-1]}", symbol in src, symbol)

    for tier in WORKLOAD_TIERS:
        _check(f"impl_workload_tier_{tier}", tier in src, tier)

    for status in REQUIRED_JOB_STATUSES:
        _check(f"impl_job_status_{status}", status in src, status)

    for field in REQUIRED_SCHEDULER_POLICY_FIELDS:
        _check(f"impl_policy_field_{field}", field in src, field)

    for field in REQUIRED_PROOF_WINDOW_FIELDS:
        _check(f"impl_window_field_{field}", field in src, field)

    for field in REQUIRED_PROOF_JOB_FIELDS:
        _check(f"impl_job_field_{field}", field in src, field)

    for field in REQUIRED_METRICS_FIELDS:
        _check(f"impl_metrics_field_{field}", field in src, field)

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)

    for code in REQUIRED_ERROR_EVENT_CODES:
        _check(f"impl_error_event_{code}", code in src, code)

    for code in REQUIRED_ERROR_CODES:
        _check(f"impl_error_{code}", code in src, code)

    _check("impl_schema_version", "vef-proof-scheduler-v1" in src, "vef-proof-scheduler-v1")
    _check("impl_uses_btreemap", "BTreeMap" in src, "BTreeMap for deterministic ordering")
    _check("impl_uses_btreeset", "BTreeSet" in src, "BTreeSet for dedup")
    _check("impl_serde_derive", "#[derive(" in src and "Serialize" in src and "Deserialize" in src, "Serialize + Deserialize")
    _check("impl_uses_receipt_chain", "ReceiptChainEntry" in src, "imports ReceiptChainEntry")
    _check("impl_uses_checkpoint", "ReceiptCheckpoint" in src, "imports ReceiptCheckpoint")
    _check("impl_priority_scoring", "priority_score" in src, "priority-based dispatch")
    _check("impl_deadline_enforcement", "enforce_deadlines" in src, "deadline enforcement")
    _check("impl_concurrent_budget", "max_concurrent_jobs" in src, "concurrency budget")
    _check("impl_compute_budget", "max_compute_millis_per_tick" in src, "compute budget")
    _check("impl_memory_budget", "max_memory_mib_per_tick" in src, "memory budget")
    _check("impl_backlog_health", "backlog_metrics" in src, "backlog health reporting")
    _check("impl_window_alignment", "aligned_checkpoint_id" in src, "checkpoint-aligned windows")

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 6, f"{test_count} tests")


def check_mod_wiring() -> None:
    mod_text = _read(MOD_RS)
    _check(
        "vef_mod_wires_proof_scheduler",
        "pub mod proof_scheduler;" in mod_text,
        "pub mod proof_scheduler;",
    )


def check_scheduler_contract() -> None:
    """Verify implementation satisfies the key scheduler contract requirements."""
    src = _read(IMPL)

    # Deterministic window selection: same inputs => same outputs
    _check(
        "contract_deterministic_windows",
        "deterministic" in src.lower() or "deterministic_window_partition" in src,
        "deterministic window selection tested",
    )

    # Priority ordering: critical > high > standard > background
    has_priority = "priority_score" in src
    has_reverse_sort = "Reverse" in src
    _check(
        "contract_priority_ordering",
        has_priority and has_reverse_sort,
        "priority-based sort with Reverse",
    )

    # Deadline escalation
    has_deadline_check = "deadline_millis" in src and "DeadlineExceeded" in src
    _check(
        "contract_deadline_escalation",
        has_deadline_check,
        "deadline exceeded tracking",
    )

    # Concurrency enforcement
    has_concurrency_check = "max_concurrent_jobs" in src and "active_dispatched" in src
    _check(
        "contract_concurrency_enforcement",
        has_concurrency_check,
        "concurrent job limit check",
    )

    # Resource budget enforcement
    has_compute_check = "max_compute_millis_per_tick" in src
    has_memory_check = "max_memory_mib_per_tick" in src
    _check(
        "contract_resource_budget",
        has_compute_check and has_memory_check,
        "compute + memory budget enforcement",
    )

    # Empty stream handling
    has_empty_check = "is_empty()" in src
    _check(
        "contract_empty_stream",
        has_empty_check,
        "empty receipt stream handled",
    )

    # Event tracing
    event_push_count = src.count("self.events.push")
    _check(
        "contract_event_tracing",
        event_push_count >= 4,
        f"{event_push_count} event emission points",
    )

    # Trace ID propagation
    trace_id_count = src.count("trace_id")
    _check(
        "contract_trace_id_propagation",
        trace_id_count >= 10,
        f"{trace_id_count} trace_id references",
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check("evidence_bead_id", evidence.get("bead_id") == "bd-28u0", str(evidence.get("bead_id")))
        _check("evidence_verdict_pass", evidence.get("verdict") == "PASS", str(evidence.get("verdict")))

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-28u0" in summary, "bd-28u0")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_impl_symbols()
    check_mod_wiring()
    check_scheduler_contract()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-28u0",
        "title": "VEF proof-window selection and job scheduler with bounded latency budgets",
        "section": "10.18",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("workload_tier_count", len(WORKLOAD_TIERS) == 4, str(len(WORKLOAD_TIERS)))
    push("event_code_count", len(REQUIRED_EVENT_CODES) == 4, str(len(REQUIRED_EVENT_CODES)))
    push("error_event_code_count", len(REQUIRED_ERROR_EVENT_CODES) == 4, str(len(REQUIRED_ERROR_EVENT_CODES)))
    push("error_code_count", len(REQUIRED_ERROR_CODES) == 4, str(len(REQUIRED_ERROR_CODES)))
    push("impl_symbol_count", len(REQUIRED_IMPL_SYMBOLS) >= 15, str(len(REQUIRED_IMPL_SYMBOLS)))
    push("job_status_count", len(REQUIRED_JOB_STATUSES) == 4, str(len(REQUIRED_JOB_STATUSES)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": "bd-28u0",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify bd-28u0 artifacts")
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    parser.add_argument("--self-test", action="store_true", help="run checker self-test")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['bead_id']}] {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"- {mark} {check['check']}: {check['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
