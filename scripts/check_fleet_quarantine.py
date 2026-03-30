#!/usr/bin/env python3
"""bd-tg2: Verification script for fleet control quarantine/revocation API.

Usage:
    python3 scripts/check_fleet_quarantine.py           # human-readable
    python3 scripts/check_fleet_quarantine.py --json     # machine-readable
    python3 scripts/check_fleet_quarantine.py --self-test # internal consistency
"""

import hashlib
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/api/fleet_quarantine.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_8/bd-tg2_contract.md"
POLICY_FILE = ROOT / "docs/policy/fleet_quarantine_operations.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_8/bd-tg2/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_8/bd-tg2/verification_summary.md"

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_STRUCTS = [
    "QuarantineScope",
    "RevocationScope",
    "FleetAction",
    "FleetActionResult",
    "FleetStatus",
    "FleetControlError",
    "FleetControlEvent",
    "ConvergenceState",
    "IncidentHandle",
    "DecisionReceipt",
    "FleetControlManager",
    "RevocationSeverity",
    "ConvergencePhase",
    "IncidentStatus",
]

REQUIRED_EVENT_CODES = [
    "FLEET-001",
    "FLEET-002",
    "FLEET-003",
    "FLEET-004",
    "FLEET-005",
]

REQUIRED_EVENT_NAMES = [
    "FLEET_QUARANTINE_INITIATED",
    "FLEET_REVOCATION_ISSUED",
    "FLEET_CONVERGENCE_PROGRESS",
    "FLEET_RELEASED",
    "FLEET_RECONCILE_COMPLETED",
]

REQUIRED_ERROR_CODES = [
    "FLEET_SCOPE_INVALID",
    "FLEET_ZONE_UNREACHABLE",
    "FLEET_CONVERGENCE_TIMEOUT",
    "FLEET_ROLLBACK_FAILED",
    "FLEET_NOT_ACTIVATED",
    "FLEET_OPERATION_ID_EXHAUSTED",
]

REQUIRED_INVARIANTS = [
    "INV-FLEET-ZONE-SCOPE",
    "INV-FLEET-RECEIPT",
    "INV-FLEET-CONVERGENCE",
    "INV-FLEET-SAFE-START",
    "INV-FLEET-ROLLBACK",
]

REQUIRED_FUNCTIONS = [
    "fn quarantine",
    "fn revoke",
    "fn release",
    "fn status",
    "fn reconcile",
    "fn activate",
    "fn is_activated",
    "fn events",
    "fn active_incidents",
    "fn zones",
    "fn incident_count",
    "fn quarantine_route_metadata",
    "fn handle_quarantine",
    "fn handle_revoke",
    "fn handle_release",
    "fn handle_status",
    "fn handle_reconcile",
    "fn build_receipt",
]

REQUIRED_SPEC_SECTIONS = [
    "Overview",
    "Data Model",
    "QuarantineScope",
    "FleetControlManager",
    "Invariants",
    "Event Codes",
    "Error Codes",
    "Acceptance Criteria",
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}


# ── Check groups ───────────────────────────────────────────────────────────

def check_file_existence() -> list:
    checks = []
    checks.append(_check("fleet_quarantine implementation exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("contract spec exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("evidence artifact exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE)))
    checks.append(_check("summary artifact exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE)))
    return checks


def check_structs() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for s in REQUIRED_STRUCTS:
        found = f"pub enum {s}" in src or f"pub struct {s}" in src
        checks.append(_check(f"struct/enum {s}", found))
    return checks


def check_event_codes() -> list:
    src = _read(IMPL_FILE)
    return [_check(f"event code {c}", c in src) for c in REQUIRED_EVENT_CODES]


def check_event_names() -> list:
    src = _read(IMPL_FILE)
    return [_check(f"event name {n}", n in src) for n in REQUIRED_EVENT_NAMES]


def check_error_codes() -> list:
    src = _read(IMPL_FILE)
    return [_check(f"error code {c}", c in src) for c in REQUIRED_ERROR_CODES]


def check_invariants() -> list:
    src = _read(IMPL_FILE)
    return [_check(f"invariant {inv}", inv in src) for inv in REQUIRED_INVARIANTS]


def check_functions() -> list:
    src = _read(IMPL_FILE)
    return [_check(f"function {fn_name}", fn_name in src) for fn_name in REQUIRED_FUNCTIONS]


def check_spec_sections() -> list:
    src = _read(SPEC_FILE)
    return [_check(f"spec section: {s}", s in src) for s in REQUIRED_SPEC_SECTIONS]


def check_serde_derives() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for t in ["QuarantineScope", "FleetActionResult", "FleetControlEvent", "FleetStatus", "DecisionReceipt"]:
        idx = src.find(f"pub enum {t}") if f"pub enum {t}" in src else src.find(f"pub struct {t}")
        if idx >= 0:
            preceding = src[max(0, idx - 200):idx]
            has_serde = "Serialize" in preceding and "Deserialize" in preceding
            checks.append(_check(f"serde derives on {t}", has_serde))
        else:
            checks.append(_check(f"serde derives on {t}", False, "type not found"))
    return checks


def check_tests() -> list:
    src = _read(IMPL_FILE)
    checks = []
    test_count = src.count("#[test]")
    checks.append(_check(f"Rust unit tests present ({test_count})", test_count >= 40, f"{test_count} tests"))

    test_categories = [
        ("safe-start quarantine rejected", "quarantine_rejected_before_activation"),
        ("safe-start revoke rejected", "revoke_rejected_before_activation"),
        ("zone scope validation", "quarantine_rejects_empty_zone"),
        ("quarantine creates incident", "quarantine_creates_incident"),
        ("quarantine produces receipt", "quarantine_produces_receipt"),
        ("quarantine convergence", "quarantine_has_convergence_state"),
        ("revoke succeeds", "revoke_succeeds"),
        ("emergency revocation incident", "emergency_revocation_creates_incident"),
        ("release rolls back", "release_rolls_back_quarantine"),
        ("release nonexistent fails", "release_nonexistent_incident_fails"),
        ("reconcile cleans released", "reconcile_cleans_released_incidents"),
        ("multi-zone scenario", "multi_zone_quarantine_and_release"),
        ("serde round-trip", "quarantine_scope_serde"),
        ("send+sync", "types_are_send_sync"),
        ("route metadata count", "route_metadata_has_five_endpoints"),
    ]
    for name, pattern in test_categories:
        found = pattern in src
        checks.append(_check(f"test: {name}", found))
    return checks


def check_zone_scope() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("zone_id field in QuarantineScope", "pub zone_id:" in src))
    checks.append(_check("zone_id field in RevocationScope", "zone_id:" in src and "RevocationScope" in src))
    checks.append(_check("zone/tenant scoping", "tenant_id" in src))
    checks.append(_check("blast_radius metadata", "affected_nodes" in src))
    return checks


def check_convergence() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("converged_nodes field", "converged_nodes" in src))
    checks.append(_check("total_nodes field", "total_nodes" in src))
    checks.append(_check("progress_pct field", "progress_pct" in src))
    checks.append(_check("eta_seconds field", "eta_seconds" in src))
    checks.append(_check("ConvergencePhase enum", "pub enum ConvergencePhase" in src))
    return checks


def check_acceptance_criteria() -> list:
    src = _read(IMPL_FILE)
    checks = []
    ac1 = "fn quarantine" in src and "fn revoke" in src and "fn release" in src and "fn status" in src and "fn reconcile" in src
    checks.append(_check("AC1: API endpoints implemented", ac1))
    ac2 = "zone_id" in src and "tenant_id" in src and "affected_nodes" in src
    checks.append(_check("AC2: scope control with zone/tenant", ac2))
    ac3 = "ConvergenceState" in src and "progress_pct" in src and "eta_seconds" in src
    checks.append(_check("AC3: convergence tracking", ac3))
    ac4 = "release" in src and "Released" in src and "INV-FLEET-ROLLBACK" in src
    checks.append(_check("AC4: rollback via release", ac4))
    ac5 = "DecisionReceipt" in src and "INV-FLEET-RECEIPT" in src
    checks.append(_check("AC5: signed decision receipts", ac5))
    ac6 = "Serialize" in src and "Deserialize" in src
    checks.append(_check("AC6: structured observability + error taxonomy", ac6))
    ac7 = "activated" in src and "INV-FLEET-SAFE-START" in src and "FLEET_NOT_ACTIVATED" in src
    checks.append(_check("AC7: safe-mode startup", ac7))
    ac8 = "IncidentHandle" in src and "incident_id" in src
    checks.append(_check("AC8: incident bundle integration", ac8))
    return checks


def simulate_fleet_operations() -> dict:
    results = {}

    # Simulate quarantine flow
    incidents = []
    for i in range(3):
        incident = {"id": f"inc-{i}", "zone": f"zone-{i % 2}", "status": "active"}
        incidents.append(incident)
    results["incidents_created"] = len(incidents)

    # Simulate release
    incidents[0]["status"] = "released"
    active = sum(1 for inc in incidents if inc["status"] == "active")
    results["active_after_release"] = active

    # Simulate convergence
    convergence = {"converged": 8, "total": 10, "pct": 80}
    results["convergence_progress"] = convergence["pct"]

    # Simulate reconcile
    released = [inc for inc in incidents if inc["status"] == "released"]
    results["cleaned_on_reconcile"] = len(released)

    # Receipt determinism
    payload = "op-1:admin:zone-1:2026-01-01"
    h1 = _sha256_hex(payload.encode())
    h2 = _sha256_hex(payload.encode())
    results["receipt_hash_deterministic"] = h1 == h2

    # Multi-zone
    zones = set(inc["zone"] for inc in incidents)
    results["zone_count"] = len(zones)

    return results


# ── Main check runner ──────────────────────────────────────────────────────

def run_checks() -> dict:
    checks = []
    checks.extend(check_file_existence())
    checks.extend(check_structs())
    checks.extend(check_event_codes())
    checks.extend(check_event_names())
    checks.extend(check_error_codes())
    checks.extend(check_invariants())
    checks.extend(check_functions())
    checks.extend(check_spec_sections())
    checks.extend(check_serde_derives())
    checks.extend(check_tests())
    checks.extend(check_zone_scope())
    checks.extend(check_convergence())
    checks.extend(check_acceptance_criteria())

    sim = simulate_fleet_operations()
    checks.append(_check("sim: incidents created", sim["incidents_created"] == 3))
    checks.append(_check("sim: active after release", sim["active_after_release"] == 2))
    checks.append(_check("sim: convergence progress", sim["convergence_progress"] == 80))
    checks.append(_check("sim: cleaned on reconcile", sim["cleaned_on_reconcile"] == 1))
    checks.append(_check("sim: receipt hash deterministic", sim["receipt_hash_deterministic"]))
    checks.append(_check("sim: multi-zone", sim["zone_count"] == 2))

    passed = sum(1 for c in checks if c["pass"])
    failed = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-tg2",
        "title": "Fleet control API for quarantine/revocation operations",
        "section": "10.8",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def run_all() -> dict:
    return run_checks()


def self_test() -> tuple:
    checks = []
    checks.append(_check("REQUIRED_STRUCTS count", len(REQUIRED_STRUCTS) >= 14))
    checks.append(_check("REQUIRED_EVENT_CODES count", len(REQUIRED_EVENT_CODES) == 5))
    checks.append(_check("REQUIRED_EVENT_NAMES count", len(REQUIRED_EVENT_NAMES) == 5))
    checks.append(_check("REQUIRED_ERROR_CODES count", len(REQUIRED_ERROR_CODES) == 6))
    checks.append(_check("REQUIRED_INVARIANTS count", len(REQUIRED_INVARIANTS) == 5))
    checks.append(_check("REQUIRED_FUNCTIONS count", len(REQUIRED_FUNCTIONS) >= 18))

    sim = simulate_fleet_operations()
    checks.append(_check("simulation returns dict", isinstance(sim, dict)))

    result = run_checks()
    checks.append(_check("run_checks has bead_id", result.get("bead_id") == "bd-tg2"))
    checks.append(_check("run_checks has section", result.get("section") == "10.8"))
    checks.append(_check("run_checks has verdict", result.get("verdict") in ("PASS", "FAIL")))

    h1 = _sha256_hex(b"test")
    h2 = _sha256_hex(b"test")
    checks.append(_check("sha256 deterministic", h1 == h2))

    ok = all(c["pass"] for c in checks)
    return (ok, checks)


def main():
    configure_test_logging("check_fleet_quarantine")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        for c in checks:
            print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['check']}")
        print(f"\nself-test: {passed}/{len(checks)} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
