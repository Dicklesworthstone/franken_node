#!/usr/bin/env python3
"""Verification script for bd-26ux: migration to frankensqlite.

Usage:
    python scripts/check_frankensqlite_migration.py          # human-readable
    python scripts/check_frankensqlite_migration.py --json   # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

MIGRATION_DOC = ROOT / "docs" / "migration" / "to_frankensqlite.md"
MIGRATION_TEST = ROOT / "tests" / "migration" / "frankensqlite_migration_idempotence.rs"
REPORT = ROOT / "artifacts" / "10.16" / "frankensqlite_migration_report.json"

REQUIRED_DOMAINS = [
    {
        "name": "state_model",
        "source_module": "crates/franken-node/src/connector/state_model.rs",
        "source_type": "in_memory_state_root_structs",
    },
    {
        "name": "fencing_token_state",
        "source_module": "crates/franken-node/src/connector/fencing.rs",
        "source_type": "in_memory_fence_state_and_lease_tokens",
    },
    {
        "name": "lease_coordination_state",
        "source_module": "crates/franken-node/src/connector/lease_coordinator.rs",
        "source_type": "in_memory_candidate_and_quorum_material",
    },
    {
        "name": "lease_service_state",
        "source_module": "crates/franken-node/src/connector/lease_service.rs",
        "source_type": "in_memory_lease_map_and_decision_log",
    },
    {
        "name": "lease_conflict_state",
        "source_module": "crates/franken-node/src/connector/lease_conflict.rs",
        "source_type": "in_memory_overlap_resolution_logs",
    },
    {
        "name": "snapshot_policy_state",
        "source_module": "crates/franken-node/src/connector/snapshot_policy.rs",
        "source_type": "in_memory_snapshot_tracker_and_policy_audit",
    },
    {
        "name": "quarantine_store_state",
        "source_module": "crates/franken-node/src/connector/quarantine_store.rs",
        "source_type": "in_memory_quarantine_map_and_eviction_counters",
    },
    {
        "name": "retention_policy_state",
        "source_module": "crates/franken-node/src/connector/retention_policy.rs",
        "source_type": "in_memory_policy_registry_and_message_store",
    },
    {
        "name": "artifact_persistence_state",
        "source_module": "crates/franken-node/src/connector/artifact_persistence.rs",
        "source_type": "in_memory_artifact_map_and_sequence_index",
    },
]

REQUIRED_DOC_SECTIONS = [
    "## Migration inventory",
    "## Migration strategy per domain",
    "## Rollback path",
    "## Idempotency guarantee",
]

REQUIRED_DOMAIN_FIELDS = [
    "name",
    "source_module",
    "source_type",
    "migration_status",
    "rows_migrated",
    "invariants_verified",
    "rollback_tested",
]

REQUIRED_EVENT_CODES = [
    "MIGRATION_DOMAIN_START",
    "MIGRATION_DOMAIN_COMPLETE",
    "MIGRATION_DOMAIN_FAIL",
    "MIGRATION_ROLLBACK_START",
    "MIGRATION_ROLLBACK_COMPLETE",
    "MIGRATION_IDEMPOTENCY_VERIFIED",
]

REQUIRED_TEST_NAMES = [
    "state_model_migration_is_idempotent",
    "fencing_token_migration_is_idempotent",
    "lease_coordination_migration_is_idempotent",
    "lease_service_migration_is_idempotent",
    "lease_conflict_migration_is_idempotent",
    "snapshot_policy_migration_is_idempotent",
    "quarantine_store_migration_is_idempotent",
    "retention_policy_migration_is_idempotent",
    "artifact_persistence_migration_is_idempotent",
    "rollback_restores_interim_state",
    "partial_failure_is_atomic_and_recoverable",
    "migrated_data_preserves_source_invariants",
]


def check_file(path: Path, label: str) -> dict:
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_doc() -> list[dict]:
    results = []

    if not MIGRATION_DOC.exists():
        results.append({"check": "doc: exists", "pass": False, "detail": "MISSING"})
        return results

    text = MIGRATION_DOC.read_text(encoding="utf-8")
    results.append({"check": "doc: exists", "pass": True, "detail": "found"})

    for section in REQUIRED_DOC_SECTIONS:
        found = section in text
        results.append({
            "check": f"doc: section {section}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    for spec in REQUIRED_DOMAINS:
        name_found = spec["name"] in text
        module_found = spec["source_module"] in text
        results.append({
            "check": f"doc: domain {spec['name']}",
            "pass": name_found,
            "detail": "found" if name_found else "NOT FOUND",
        })
        results.append({
            "check": f"doc: module {spec['source_module']}",
            "pass": module_found,
            "detail": "found" if module_found else "NOT FOUND",
        })

    return results


def load_report() -> tuple[dict | None, list[dict]]:
    results = []

    if not REPORT.exists():
        results.append({"check": "report: exists", "pass": False, "detail": "MISSING"})
        return None, results

    results.append({"check": "report: exists", "pass": True, "detail": "found"})

    try:
        data = json.JSONDecoder().decode(REPORT.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        results.append({"check": "report: valid json", "pass": False, "detail": "invalid"})
        return None, results

    results.append({"check": "report: valid json", "pass": True, "detail": "valid"})
    return data, results


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    results = []

    for key in ["domains", "idempotency_results", "rollback_results"]:
        present = key in data
        results.append({
            "check": f"report: key {key}",
            "pass": present,
            "detail": "present" if present else "MISSING",
        })

    domains = data.get("domains", [])
    indexed = {d.get("name"): d for d in domains if isinstance(d, dict)}

    results.append({
        "check": "report: domain count",
        "pass": len(domains) == len(REQUIRED_DOMAINS),
        "detail": f"{len(domains)} domains (expected {len(REQUIRED_DOMAINS)})",
    })

    for spec in REQUIRED_DOMAINS:
        name = spec["name"]
        domain = indexed.get(name)
        exists = domain is not None
        results.append({
            "check": f"report: domain {name}",
            "pass": exists,
            "detail": "present" if exists else "MISSING",
        })
        if not exists:
            continue

        for field in REQUIRED_DOMAIN_FIELDS:
            present = field in domain
            results.append({
                "check": f"report: {name} field {field}",
                "pass": present,
                "detail": "present" if present else "MISSING",
            })

        module_ok = domain.get("source_module") == spec["source_module"]
        source_type_ok = domain.get("source_type") == spec["source_type"]
        status_ok = domain.get("migration_status") == "migrated"
        rows = domain.get("rows_migrated", 0)
        rows_ok = isinstance(rows, int) and rows > 0
        invariants_value = domain.get("invariants_verified")
        rollback_value = domain.get("rollback_tested")
        invariants_ok = isinstance(invariants_value, bool) and invariants_value
        rollback_ok = isinstance(rollback_value, bool) and rollback_value
        primary_ok = domain.get("primary_persistence") == "frankensqlite"

        results.append({
            "check": f"report: {name} source module",
            "pass": module_ok,
            "detail": domain.get("source_module", "<missing>"),
        })
        results.append({
            "check": f"report: {name} source type",
            "pass": source_type_ok,
            "detail": domain.get("source_type", "<missing>"),
        })
        results.append({
            "check": f"report: {name} migration status",
            "pass": status_ok,
            "detail": domain.get("migration_status", "<missing>"),
        })
        results.append({
            "check": f"report: {name} rows migrated",
            "pass": rows_ok,
            "detail": str(rows),
        })
        results.append({
            "check": f"report: {name} invariants verified",
            "pass": invariants_ok,
            "detail": str(domain.get("invariants_verified")),
        })
        results.append({
            "check": f"report: {name} rollback tested",
            "pass": rollback_ok,
            "detail": str(domain.get("rollback_tested")),
        })
        results.append({
            "check": f"report: {name} primary persistence",
            "pass": primary_ok,
            "detail": domain.get("primary_persistence", "<missing>"),
        })

    idempotency = data.get("idempotency_results", {})
    for spec in REQUIRED_DOMAINS:
        name = spec["name"]
        status = idempotency.get(name)
        results.append({
            "check": f"report: idempotency {name}",
            "pass": status == "pass",
            "detail": status if status is not None else "MISSING",
        })

    rollback = data.get("rollback_results", {})
    for spec in REQUIRED_DOMAINS:
        name = spec["name"]
        status = rollback.get(name)
        results.append({
            "check": f"report: rollback {name}",
            "pass": status == "pass",
            "detail": status if status is not None else "MISSING",
        })

    partial = data.get("partial_failure_recovery", {})
    partial_ok = partial.get("status") == "pass"
    results.append({
        "check": "report: partial failure recovery",
        "pass": partial_ok,
        "detail": partial.get("status", "MISSING"),
    })

    return results


def check_migration_test() -> list[dict]:
    results = []

    if not MIGRATION_TEST.exists():
        results.append({"check": "migration test: exists", "pass": False, "detail": "MISSING"})
        return results

    text = MIGRATION_TEST.read_text(encoding="utf-8")
    results.append({"check": "migration test: exists", "pass": True, "detail": "found"})

    test_count = len(re.findall(r"#\[test\]", text))
    results.append({
        "check": "migration test: test count",
        "pass": test_count >= len(REQUIRED_TEST_NAMES),
        "detail": f"{test_count} tests (minimum {len(REQUIRED_TEST_NAMES)})",
    })

    for code in REQUIRED_EVENT_CODES:
        found = code in text
        results.append({
            "check": f"migration test: event code {code}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    for test_name in REQUIRED_TEST_NAMES:
        found = f"fn {test_name}(" in text
        results.append({
            "check": f"migration test: {test_name}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    return results


def run_checks() -> dict:
    checks = []

    checks.append(check_file(MIGRATION_DOC, "migration doc"))
    checks.append(check_file(MIGRATION_TEST, "migration test"))
    checks.append(check_file(REPORT, "migration report"))

    checks.extend(check_doc())

    report, report_checks = load_report()
    checks.extend(report_checks)
    checks.extend(check_report(report))

    checks.extend(check_migration_test())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-26ux",
        "title": "Migration path from interim/local stores to frankensqlite",
        "section": "10.16",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": len(REQUIRED_TEST_NAMES),
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict]]:
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_frankensqlite_migration")
    logger.info("starting %s verification", "check_frankensqlite_migration")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(
            f"bd-26ux verification: {status} "
            f"({result['summary']['passing']}/{result['summary']['total']})"
        )
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"  [{mark}] {check['check']}: {check['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
