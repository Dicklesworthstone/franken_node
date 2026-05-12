#!/usr/bin/env python3
"""bd-3he: Verify supervision tree with restart budgets and escalation policies."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "supervision.rs")
MOD = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_11", "bd-3he_contract.md")
TEST_SUITE = os.path.join(ROOT, "tests", "test_check_supervision_tree.py")
EVIDENCE = os.path.join(ROOT, "artifacts", "section_10_11", "bd-3he", "verification_evidence.json")
SUMMARY = os.path.join(ROOT, "artifacts", "section_10_11", "bd-3he", "verification_summary.md")
REPLACEMENT_EVIDENCE_DIR = os.path.join(ROOT, "artifacts", "replacement_gap", "bd-18sp")
REPLACEMENT_EVIDENCE = os.path.join(REPLACEMENT_EVIDENCE_DIR, "verification_evidence.json")
REPLACEMENT_SUMMARY = os.path.join(REPLACEMENT_EVIDENCE_DIR, "verification_summary.md")
REPO_PUBLIC_API_TEST = os.path.join(
    ROOT, "crates", "franken-node", "tests", "supervision_temporal_kernel.rs"
)
HARNESS_LIB = os.path.join(REPLACEMENT_EVIDENCE_DIR, "supervision_kernel_harness", "src", "lib.rs")
HARNESS_PUBLIC_API_TEST = os.path.join(
    REPLACEMENT_EVIDENCE_DIR, "supervision_kernel_harness", "tests", "public_api.rs"
)
HYPERFINE_SCRIPT = os.path.join(REPLACEMENT_EVIDENCE_DIR, "run_hyperfine.sh")
HYPERFINE_RESULTS = os.path.join(REPLACEMENT_EVIDENCE_DIR, "hyperfine_supervision_kernel.json")
BD18SP_REPLACEMENT_BEAD = "bd-18sp"
BD18SP_COMPLETION_DEBT_BEAD = "bd-18sp.1"
COMPLETION_DEBT_ITEMS = {
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
    "tests.property.primary",
}
PROPERTY_TEST_MARKERS = [
    "test_restart_budget_matches_reference_window_model",
    "test_adversarial_burst_schedule_matches_reference_kernel",
    "find_minimal_counterexample",
    "verify_schedule_equivalence",
]
INTEGRATION_TEST_MARKERS = [
    "public_api_uses_elapsed_time_for_restart_window_expiry",
    "public_api_can_record_structured_health_reports",
]


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _rel(path):
    return os.path.relpath(path, ROOT)


def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _checks():
    results = []

    def check(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    # 1. Source file exists
    if not os.path.isfile(SRC):
        check("SOURCE_EXISTS", False, f"missing {SRC}")
        return results
    src = _read(SRC)
    check("SOURCE_EXISTS", True, SRC)

    # 2. Module wired in mod.rs
    if os.path.isfile(MOD):
        mod_src = _read(MOD)
        check("MODULE_WIRED", "pub mod supervision;" in mod_src, "connector/mod.rs")
    else:
        check("MODULE_WIRED", False, "mod.rs not found")

    # 3. Core types
    types = ["Supervisor", "ChildSpec", "SupervisionStrategy"]
    missing_t = [t for t in types if t not in src]
    check("CORE_TYPES", len(missing_t) == 0,
          f"{len(types) - len(missing_t)}/{len(types)} types present")

    # 4. Strategy variants
    variants = ["OneForOne", "OneForAll", "RestForOne"]
    missing_v = [v for v in variants if v not in src]
    check("STRATEGY_VARIANTS", len(missing_v) == 0,
          f"{len(variants) - len(missing_v)}/{len(variants)} strategy variants")

    # 5. RestartType variants
    restart_variants = ["Permanent", "Transient", "Temporary"]
    missing_r = [r for r in restart_variants if r not in src]
    check("RESTART_TYPE_VARIANTS", len(missing_r) == 0,
          f"{len(restart_variants) - len(missing_r)}/{len(restart_variants)} restart type variants")

    # 6. Key methods
    methods = ["handle_failure", "shutdown", "health_status", "add_child"]
    missing_m = [m for m in methods if m not in src]
    check("KEY_METHODS", len(missing_m) == 0,
          f"{len(methods) - len(missing_m)}/{len(methods)} methods present")

    # 7. Event codes SUP-001..008
    event_codes = [f"SUP-00{i}" for i in range(1, 9)]
    missing_e = [e for e in event_codes if e not in src]
    check("EVENT_CODES", len(missing_e) == 0,
          f"{len(event_codes) - len(missing_e)}/{len(event_codes)} event codes")

    # 8. Error codes
    error_codes = [
        "ERR_SUP_CHILD_NOT_FOUND",
        "ERR_SUP_BUDGET_EXHAUSTED",
        "ERR_SUP_MAX_ESCALATION",
        "ERR_SUP_SHUTDOWN_TIMEOUT",
        "ERR_SUP_DUPLICATE_CHILD",
    ]
    missing_err = [e for e in error_codes if e not in src]
    check("ERROR_CODES", len(missing_err) == 0,
          f"{len(error_codes) - len(missing_err)}/{len(error_codes)} error codes")

    # 9. Invariant constants
    invariants = [
        "INV-SUP-BUDGET-BOUND",
        "INV-SUP-ESCALATION-BOUNDED",
        "INV-SUP-SHUTDOWN-ORDER",
        "INV-SUP-TIMEOUT-ENFORCED",
        "INV-SUP-STRATEGY-DETERMINISTIC",
    ]
    missing_inv = [i for i in invariants if i not in src]
    check("INVARIANTS", len(missing_inv) == 0,
          f"{len(invariants) - len(missing_inv)}/{len(invariants)} invariants")

    # 10. Schema version
    check("SCHEMA_VERSION", 'sup-v1.0' in src, "sup-v1.0")

    # 11. Serde derives
    serde_count = len(re.findall(r'Serialize|Deserialize', src))
    check("SERDE_DERIVES", serde_count >= 2, f"{serde_count} serde references")

    # 12. Unit tests >= 15
    test_count = len(re.findall(r'#\[test\]', src))
    check("UNIT_TESTS", test_count >= 15, f"{test_count} tests found")

    # 13. cfg(test) module
    check("CFG_TEST_MODULE", "#[cfg(test)]" in src, "cfg(test) module present")

    # 14. Spec contract exists
    check("SPEC_EXISTS", os.path.isfile(SPEC), SPEC)

    # 15. Test suite exists
    check("TEST_SUITE_EXISTS", os.path.isfile(TEST_SUITE), TEST_SUITE)

    # 16. Evidence exists
    check("EVIDENCE_EXISTS", os.path.isfile(EVIDENCE), EVIDENCE)

    # 17. Summary exists
    check("SUMMARY_EXISTS", os.path.isfile(SUMMARY), SUMMARY)

    # 18. bd-18sp completion-debt evidence exists and covers all audit items.
    check("BD18SP_REPLACEMENT_EVIDENCE_EXISTS", os.path.isfile(REPLACEMENT_EVIDENCE), REPLACEMENT_EVIDENCE)
    check("BD18SP_REPLACEMENT_SUMMARY_EXISTS", os.path.isfile(REPLACEMENT_SUMMARY), REPLACEMENT_SUMMARY)
    replacement_summary = _read(REPLACEMENT_SUMMARY) if os.path.isfile(REPLACEMENT_SUMMARY) else ""
    check(
        "BD18SP_REPLACEMENT_SUMMARY_COMPLETION_BEAD",
        BD18SP_COMPLETION_DEBT_BEAD in replacement_summary,
        _rel(REPLACEMENT_SUMMARY),
    )
    check(
        "BD18SP_REPLACEMENT_SUMMARY_EVIDENCE_LINK",
        _rel(REPLACEMENT_EVIDENCE) in replacement_summary,
        _rel(REPLACEMENT_EVIDENCE),
    )

    replacement_data = None
    if os.path.isfile(REPLACEMENT_EVIDENCE):
        try:
            replacement_data = _load_json(REPLACEMENT_EVIDENCE)
            check("BD18SP_REPLACEMENT_EVIDENCE_JSON", True, REPLACEMENT_EVIDENCE)
        except json.JSONDecodeError as exc:
            check("BD18SP_REPLACEMENT_EVIDENCE_JSON", False, str(exc))
    else:
        check("BD18SP_REPLACEMENT_EVIDENCE_JSON", False, "replacement evidence missing")

    if replacement_data:
        check(
            "BD18SP_REPLACEMENT_BEAD_ID",
            replacement_data.get("bead_id") == BD18SP_REPLACEMENT_BEAD,
            str(replacement_data.get("bead_id")),
        )
        check(
            "BD18SP_COMPLETION_DEBT_BEAD_ID",
            replacement_data.get("completion_debt_bead_id") == BD18SP_COMPLETION_DEBT_BEAD,
            str(replacement_data.get("completion_debt_bead_id")),
        )
        covered_items = set(replacement_data.get("completion_debt", {}).get("covered_spec_items", []))
        check(
            "BD18SP_COMPLETION_DEBT_ITEMS_COVERED",
            COMPLETION_DEBT_ITEMS.issubset(covered_items),
            ",".join(sorted(covered_items)) if covered_items else "none",
        )
        obligations = {
            item.get("spec_item"): item
            for item in replacement_data.get("completion_debt", {}).get("obligations", [])
        }
        for spec_item in sorted(COMPLETION_DEBT_ITEMS):
            obligation = obligations.get(spec_item, {})
            evidence_paths = obligation.get("evidence_paths", [])
            missing_paths = [
                path for path in evidence_paths
                if not os.path.exists(os.path.join(ROOT, path))
            ]
            check(
                f"BD18SP_{spec_item}_EVIDENCE_PATHS",
                bool(evidence_paths) and not missing_paths,
                "ok" if evidence_paths and not missing_paths else f"missing {missing_paths}",
            )
            check(
                f"BD18SP_{spec_item}_TEST_NAMES",
                bool(obligation.get("test_names")),
                ",".join(obligation.get("test_names", [])) or "none",
            )
    else:
        check("BD18SP_REPLACEMENT_BEAD_ID", False, "replacement evidence unavailable")
        check("BD18SP_COMPLETION_DEBT_BEAD_ID", False, "replacement evidence unavailable")
        check("BD18SP_COMPLETION_DEBT_ITEMS_COVERED", False, "replacement evidence unavailable")

    for marker in INTEGRATION_TEST_MARKERS:
        repo_test = _read(REPO_PUBLIC_API_TEST) if os.path.isfile(REPO_PUBLIC_API_TEST) else ""
        harness_test = _read(HARNESS_PUBLIC_API_TEST) if os.path.isfile(HARNESS_PUBLIC_API_TEST) else ""
        check(
            f"BD18SP_INTEGRATION_MARKER_{marker}",
            marker in repo_test and marker in harness_test,
            f"{_rel(REPO_PUBLIC_API_TEST)} + {_rel(HARNESS_PUBLIC_API_TEST)}",
        )

    for marker in PROPERTY_TEST_MARKERS:
        check(
            f"BD18SP_PROPERTY_MARKER_{marker}",
            marker in src,
            "connector/supervision.rs",
        )

    if os.path.isfile(HYPERFINE_RESULTS):
        try:
            hyperfine = _load_json(HYPERFINE_RESULTS)
            commands = {entry.get("command") for entry in hyperfine.get("results", [])}
            exit_codes_ok = all(
                all(code == 0 for code in entry.get("exit_codes", []))
                for entry in hyperfine.get("results", [])
            )
            check(
                "BD18SP_E2E_HYPERFINE_RESULTS",
                {"reference", "monotone-queue"}.issubset(commands) and exit_codes_ok,
                ",".join(sorted(commands)) if commands else "none",
            )
        except json.JSONDecodeError as exc:
            check("BD18SP_E2E_HYPERFINE_RESULTS", False, str(exc))
    else:
        check("BD18SP_E2E_HYPERFINE_RESULTS", False, HYPERFINE_RESULTS)
    check("BD18SP_E2E_HYPERFINE_SCRIPT", os.path.isfile(HYPERFINE_SCRIPT), HYPERFINE_SCRIPT)

    return results


def self_test():
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"self_test: {passed}/{total} checks passed")
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['check']}: {r['detail']}")
    return passed == total


def main():
    configure_test_logging("check_supervision_tree")
    if "--self-test" in sys.argv:
        ok = self_test()
        sys.exit(0 if ok else 1)
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"
    report = {
        "bead": "bd-3he",
        "title": "Supervision Tree with Restart Budgets and Escalation Policies",
        "verdict": verdict,
        "passed": passed,
        "total": total,
        "checks": results,
    }
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-3he supervision_tree: {verdict} ({passed}/{total})")
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
