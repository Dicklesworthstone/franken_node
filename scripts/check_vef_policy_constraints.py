#!/usr/bin/env python3
"""Verification script for bd-16fq: VEF policy-constraint compiler contract.

Usage:
    python3 scripts/check_vef_policy_constraints.py
    python3 scripts/check_vef_policy_constraints.py --json
    python3 scripts/check_vef_policy_constraints.py --self-test
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_policy_constraints.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
SPEC_LANG = ROOT / "docs" / "specs" / "vef_policy_constraint_language.md"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-16fq_contract.md"
SCHEMA = ROOT / "spec" / "vef_policy_constraints_v1.json"
VECTOR = ROOT / "vectors" / "vef_policy_constraint_compiler.json"
CONFORMANCE = ROOT / "tests" / "conformance" / "vef_policy_constraint_compiler.rs"
UNIT_TEST = ROOT / "tests" / "test_check_vef_policy_constraints.py"
REPORT = ROOT / "artifacts" / "10.18" / "vef_constraint_compiler_report.json"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-16fq" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-16fq" / "verification_summary.md"

ACTION_CLASSES = [
    "network_access",
    "filesystem_operation",
    "process_spawn",
    "secret_access",
    "policy_transition",
    "artifact_promotion",
]

REQUIRED_EVENT_CODES = [
    "VEF-COMPILE-001",
    "VEF-COMPILE-002",
    "VEF-COMPILE-ERR-001",
    "VEF-COMPILE-ERR-002",
    "VEF-COMPILE-ERR-003",
    "VEF-COMPILE-ERR-004",
    "VEF-COMPILE-ERR-005",
]

REQUIRED_INVARIANTS = [
    "INV-VEF-COMP-DETERMINISTIC",
    "INV-VEF-COMP-COVERAGE",
    "INV-VEF-COMP-TRACEABLE",
    "INV-VEF-COMP-VERSIONED",
    "INV-VEF-COMP-ROUNDTRIP",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub struct RuntimePolicy",
    "pub struct PolicyRule",
    "pub enum ActionClass",
    "pub enum RuleEffect",
    "pub struct CompiledConstraintEnvelope",
    "pub struct CompiledPredicate",
    "pub struct RuleSemanticProjection",
    "pub struct CompilerEvent",
    "pub struct ConstraintCompileError",
    "pub fn compile_policy",
    "pub fn decompile_projection",
    "pub fn round_trip_semantics",
    "pub fn proof_generator_accepts",
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
        return json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _configure_logging() -> None:
    from scripts.lib.test_logger import configure_test_logging

    configure_test_logging("check_vef_policy_constraints")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_file_presence() -> None:
    paths = [
        ("impl_exists", IMPL),
        ("mod_exists", MOD_RS),
        ("spec_language_exists", SPEC_LANG),
        ("spec_contract_exists", SPEC_CONTRACT),
        ("schema_exists", SCHEMA),
        ("vector_exists", VECTOR),
        ("conformance_exists", CONFORMANCE),
        ("unit_test_exists", UNIT_TEST),
        ("report_exists", REPORT),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
    ]
    for name, path in paths:
        _check(name, path.is_file(), _safe_rel(path))


def check_mod_wiring() -> None:
    text = _read(MOD_RS)
    _check(
        "connector_mod_wires_vef_policy_constraints",
        "pub mod vef_policy_constraints;" in text,
        "pub mod vef_policy_constraints;",
    )


def check_impl_symbols_and_constants() -> None:
    src = _read(IMPL)
    for symbol in REQUIRED_IMPL_SYMBOLS:
        _check(f"impl_symbol_{symbol}", symbol in src, symbol)

    for action in ACTION_CLASSES:
        _check(f"impl_action_class_{action}", action in src, action)

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_code_{code}", code in src, code)

    for invariant in REQUIRED_INVARIANTS:
        _check(f"impl_invariant_{invariant}", invariant in src, invariant)

    _check("impl_trace_link_contract", "trace_link" in src and "policy:" in src, "trace_link + policy:")
    _check("impl_sha256_hashing", "Sha256" in src and "policy_snapshot_hash" in src, "Sha256 + policy_snapshot_hash")

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 15, f"{test_count} tests")


def check_schema_structure() -> None:
    schema = _load_json(SCHEMA)
    if schema is None:
        _check("schema_parseable_json", False, "invalid or missing JSON")
        return

    _check("schema_parseable_json", True, "valid JSON")
    _check("schema_draft_2020_12", schema.get("$schema", "").endswith("2020-12/schema"), schema.get("$schema", ""))

    required_top = {
        "schema_version",
        "language_version",
        "compiler_version",
        "trace_id",
        "policy_id",
        "policy_snapshot_hash",
        "predicates",
        "coverage",
        "rule_projections",
        "events",
    }
    schema_required = set(schema.get("required", []))
    _check("schema_required_top_fields", required_top.issubset(schema_required), f"have={len(schema_required)}")

    defs = schema.get("$defs", {})
    for name in [
        "RuntimePolicy",
        "PolicyRule",
        "CompiledPredicate",
        "RuleSemanticProjection",
        "CompilerEvent",
        "ActionClass",
    ]:
        _check(f"schema_def_{name}", name in defs, name)

    ac_enum = defs.get("ActionClass", {}).get("enum", [])
    _check("schema_action_class_count", len(ac_enum) == 6, f"{len(ac_enum)}")
    _check("schema_action_class_values", set(ac_enum) == set(ACTION_CLASSES), str(ac_enum))


def check_specs_content() -> None:
    lang = _read(SPEC_LANG)
    contract = _read(SPEC_CONTRACT)

    _check("spec_lang_mentions_bead", "bd-16fq" in lang, "bd-16fq")
    _check("spec_lang_mentions_section", "10.18" in lang, "10.18")
    _check("spec_lang_mentions_round_trip", "round-trip" in lang.lower(), "round-trip")

    for code in REQUIRED_EVENT_CODES:
        _check(f"spec_lang_event_{code}", code in lang, code)

    for invariant in REQUIRED_INVARIANTS:
        _check(f"spec_lang_invariant_{invariant}", invariant in lang, invariant)

    _check("contract_mentions_acceptance", "Acceptance Criteria" in contract, "Acceptance Criteria")
    _check("contract_mentions_action_classes", "Required Action Classes" in contract, "Required Action Classes")


def check_vector_fixture() -> None:
    data = _load_json(VECTOR)
    if data is None:
        _check("vector_parseable_json", False, "invalid or missing JSON")
        return

    _check("vector_parseable_json", True, "valid JSON")
    _check("vector_bead_id", data.get("bead_id") == "bd-16fq", str(data.get("bead_id")))

    input_policy = data.get("input_policy", {})
    expected = data.get("expected_output", {})

    _check("vector_has_input_policy", isinstance(input_policy, dict), "input_policy object")
    _check("vector_has_expected_output", isinstance(expected, dict), "expected_output object")

    _check(
        "vector_input_schema_version",
        input_policy.get("schema_version") == "vef-policy-lang-v1",
        str(input_policy.get("schema_version")),
    )
    _check(
        "vector_expected_schema_version",
        expected.get("schema_version") == "vef-policy-constraints-v1",
        str(expected.get("schema_version")),
    )

    rules = input_policy.get("rules", []) if isinstance(input_policy, dict) else []
    _check("vector_input_rule_count", len(rules) >= 6, f"{len(rules)}")

    classes = {r.get("action_class") for r in rules if isinstance(r, dict)}
    _check("vector_covers_all_action_classes", classes == set(ACTION_CLASSES), str(sorted(classes)))


def check_report_and_evidence() -> None:
    report = _load_json(REPORT)
    if report is None:
        _check("report_parseable_json", False, "invalid or missing JSON")
    else:
        _check("report_parseable_json", True, "valid JSON")
        _check("report_section_10_18", report.get("section") == "10.18", str(report.get("section")))
        _check("report_verdict_pass", report.get("verdict") == "PASS", str(report.get("verdict")))

        coverage = report.get("coverage_matrix", {}) if isinstance(report, dict) else {}
        _check("report_has_coverage_matrix", isinstance(coverage, dict), "coverage_matrix")
        if isinstance(coverage, dict):
            _check(
                "report_coverage_matrix_all_classes",
                set(coverage.keys()) == set(ACTION_CLASSES),
                str(sorted(coverage.keys())),
            )

    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check("evidence_bead", evidence.get("bead_id") == "bd-16fq", str(evidence.get("bead_id")))
        _check("evidence_verdict_pass", evidence.get("verdict") == "PASS", str(evidence.get("verdict")))
        refs = evidence.get("artifacts", {}) if isinstance(evidence, dict) else {}
        _check("evidence_artifacts_block", isinstance(refs, dict), "artifacts block")

    summary = _read(SUMMARY)
    _check("summary_mentions_bd", "bd-16fq" in summary, "bd-16fq")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_mod_wiring()
    check_impl_symbols_and_constants()
    check_schema_structure()
    check_specs_content()
    check_vector_fixture()
    check_report_and_evidence()

    total = len(RESULTS)
    passed = sum(1 for x in RESULTS if x["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-16fq",
        "title": "VEF policy-constraint language and compiler contract",
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

    push("action_class_count", len(ACTION_CLASSES) == 6, str(len(ACTION_CLASSES)))
    push("event_code_count", len(REQUIRED_EVENT_CODES) == 7, str(len(REQUIRED_EVENT_CODES)))
    push("invariant_count", len(REQUIRED_INVARIANTS) == 5, str(len(REQUIRED_INVARIANTS)))
    push("symbol_count", len(REQUIRED_IMPL_SYMBOLS) >= 10, str(len(REQUIRED_IMPL_SYMBOLS)))

    report = run_all()
    push("run_all_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_consistent", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for x in checks if x["pass"])
    failed = len(checks) - passed

    return {
        "bead_id": "bd-16fq",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    _configure_logging()
    parser = argparse.ArgumentParser(description="Verify bd-16fq artifacts")
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    parser.add_argument("--self-test", action="store_true", help="run script self-test")
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
    else:
        result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['bead_id']}] {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"- {mark} {c['check']}: {c['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
