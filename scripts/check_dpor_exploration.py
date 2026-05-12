#!/usr/bin/env python3
"""bd-22yy: DPOR-style schedule exploration gates — verification gate."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "dpor_exploration.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_14", "bd-22yy_contract.md")
LAB_TEST = os.path.join(ROOT, "tests", "lab", "control_dpor_exploration.rs")
BEAD, SECTION = "bd-22yy", "10.14"

EVENT_CODES = [
    "DPOR_EXPLORATION_START", "DPOR_SCHEDULE_EXPLORED", "DPOR_VIOLATION_FOUND",
    "DPOR_EXPLORATION_COMPLETE", "DPOR_BUDGET_EXCEEDED", "DPOR_MODEL_REGISTERED",
    "DPOR_PROPERTY_CHECKED", "DPOR_COUNTEREXAMPLE_EMITTED",
    "DPOR_PRUNED_EQUIVALENT", "DPOR_REPORT_EXPORTED",
]
ERROR_CODES = [
    "ERR_DPOR_BUDGET_EXCEEDED", "ERR_DPOR_MEMORY_EXCEEDED",
    "ERR_DPOR_UNKNOWN_MODEL", "ERR_DPOR_INVALID_OPERATION",
    "ERR_DPOR_SAFETY_VIOLATION", "ERR_DPOR_CYCLE_DETECTED",
    "ERR_DPOR_EMPTY_MODEL", "ERR_DPOR_NO_PROPERTIES",
]
INVS = [
    "INV-DPOR-COMPLETE", "INV-DPOR-COUNTEREXAMPLE", "INV-DPOR-BOUNDED",
    "INV-DPOR-DETERMINISTIC", "INV-DPOR-COVERAGE", "INV-DPOR-SAFETY",
]
MODELS = [
    "EpochBarrierCoordination", "RemoteCapabilityOps", "MarkerStreamMutations",
]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)

    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod dpor_exploration;" in _read(MOD_RS))

    # Core types
    for st in ["ProtocolModelId", "Operation", "SafetyProperty", "ProtocolModel",
               "ExplorationBudget", "CounterexampleStep", "Counterexample",
               "ScheduleResult", "ExplorationResult", "DporAuditRecord",
               "DporError", "DporExplorer"]:
        ok(f"struct_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub struct " + st in src), st)

    # Protocol models
    mc = sum(1 for m in MODELS if m in src)
    ok("model_coverage", mc >= 3, f"{mc}/3 models")

    # Core operations
    ok("fn_register_model", "fn register_model" in src, "Register model")
    ok("fn_explore", "fn explore" in src, "Explore schedules")
    ok("fn_register_default_models", "fn register_default_models" in src, "Register defaults")
    ok("fn_validate", "fn validate" in src, "Model validation")
    ok("fn_estimated_schedules", "fn estimated_schedules" in src, "Schedule estimation")
    ok("fn_generate_linearizations", "fn generate_linearizations" in src or "generate_linearizations" in src, "Linearization generation")

    # Safety properties
    ok("safety_properties", "SafetyProperty" in src and "safety_properties" in src, "Safety properties")
    ok("counterexample_trace", "Counterexample" in src and "CounterexampleStep" in src, "Counterexample traces")

    # Budget
    ok("budget_config", "ExplorationBudget" in src and "DEFAULT_BUDGET_SECONDS" in src, "Budget config")
    ok("memory_budget", "DEFAULT_MEMORY_BUDGET" in src, "Memory budget")

    # Coverage
    ok("coverage_pct", "coverage_pct" in src, "Coverage percentage")

    # Audit
    ok("audit_log", "fn export_audit_log_jsonl" in src, "JSONL audit export")

    ec = sum(1 for c in EVENT_CODES if c in src)
    ok("event_codes", ec >= 8, f"{ec}/10")

    erc = sum(1 for c in ERROR_CODES if c in src)
    ok("error_codes", erc >= 8, f"{erc}/8")

    inv = sum(1 for i in INVS if i in src)
    ok("invariants", inv >= 6, f"{inv}/6")

    ok("schema_version", "dpor-v1.0" in src, "dpor-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)
    lab_src = _read(LAB_TEST) if os.path.isfile(LAB_TEST) else ""
    ok(
        "canonical_lab_test",
        os.path.isfile(LAB_TEST) and "DPOR" in lab_src and "DporExplorer" in lab_src,
        LAB_TEST,
    )

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 18, f"{test_count} tests")

    return r

def self_test():
    r = _checks()
    assert len(r) >= 28
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    logger = configure_test_logging("check_dpor_exploration")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv: self_test(); return
    results = _checks(); p = sum(1 for x in results if x["passed"]); t = len(results); v = "PASS" if p == t else "FAIL"
    if as_json:
        print(json.dumps({"bead_id": BEAD, "section": SECTION, "gate_script": os.path.basename(__file__), "checks_passed": p, "checks_total": t, "verdict": v, "checks": results}, indent=2))
    else:
        for x in results: print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks — {v}")
    sys.exit(0 if v == "PASS" else 1)

if __name__ == "__main__": main()
