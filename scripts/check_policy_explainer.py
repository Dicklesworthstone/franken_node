#!/usr/bin/env python3
"""Verification script for bd-mwvn: Policy action explainer.

Usage:
    python3 scripts/check_policy_explainer.py          # human-readable
    python3 scripts/check_policy_explainer.py --json    # machine-readable
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "policy_explainer.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-mwvn_contract.md"
EXAMPLES_ARTIFACT = ROOT / "artifacts" / "10.14" / "policy_explainer_examples.json"

REQUIRED_TYPES = [
    "pub struct PolicyExplanation",
    "pub struct DiagnosticSection",
    "pub struct GuaranteeSection",
    "pub struct BlockedExplanation",
    "pub struct WordingValidation",
    "pub struct PolicyExplainer",
]

REQUIRED_METHODS = [
    "fn explain(",
    "fn validate_wording(",
    "fn to_json(",
]

EVENT_CODES = [
    "EVD-EXPLAIN-001",
    "EVD-EXPLAIN-002",
    "EVD-EXPLAIN-003",
    "EVD-EXPLAIN-004",
]

INVARIANTS = [
    "INV-EXPLAIN-SEPARATION",
    "INV-EXPLAIN-WORDING",
    "INV-EXPLAIN-COMPLETE",
]

REQUIRED_TESTS = [
    "test_explain_top_accepted",
    "test_explain_fallback",
    "test_explain_all_blocked",
    "test_explain_no_candidates",
    "test_diagnostic_section_present_with_observations",
    "test_diagnostic_section_present_without_observations",
    "test_diagnostic_section_present_all_blocked",
    "test_guarantee_section_present_accepted",
    "test_guarantee_section_present_fallback",
    "test_guarantee_section_present_all_blocked",
    "test_wording_valid_top_accepted",
    "test_wording_valid_fallback",
    "test_wording_valid_all_blocked",
    "test_wording_valid_no_candidates",
    "test_wording_valid_empty_diagnostics",
    "test_wording_rejects_guarantee_term_in_diagnostic",
    "test_wording_rejects_diagnostic_term_in_guarantee",
    "test_blocked_alternatives_empty_when_top_accepted",
    "test_blocked_alternatives_present_on_fallback",
    "test_blocked_alternatives_present_on_all_blocked",
    "test_blocked_explanation_has_guardrail_ids",
    "test_serialization_roundtrip",
    "test_json_has_both_top_level_sections",
    "test_epoch_propagated",
    "test_event_codes_defined",
    "test_guarantee_vocabulary_non_empty",
    "test_diagnostic_vocabulary_non_empty",
    "test_vocabularies_are_disjoint",
    "test_confidence_level_low_with_no_observations",
    "test_confidence_level_with_many_observations",
    "test_invariants_verified_present",
    "test_all_blocked_has_no_panic_invariant",
    "test_wording_validation_serialization",
    "test_diagnostic_summary_uses_heuristic_language",
    "test_guarantee_summary_uses_guarantee_language",
]


def check_file(path, label):
    return {
        "check": f"file: {label}",
        "pass": path.exists(),
        "detail": f"exists: {path.relative_to(ROOT)}" if path.exists() else f"missing: {path}",
    }


def check_content(path, patterns, category):
    results = []
    try:
        text = path.read_text()
    except FileNotFoundError:
        for p in patterns:
            results.append({
                "check": f"{category}: {p}",
                "pass": False,
                "detail": f"file not found: {path}",
            })
        return results
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else f"not found in {path.name}",
        })
    return results


def check_module_registered():
    try:
        text = MOD_RS.read_text()
        found = "pub mod policy_explainer;" in text
    except FileNotFoundError:
        found = False
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "not found",
    }


def check_test_count():
    try:
        text = IMPL.read_text()
        count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        count = 0
    return {
        "check": "unit test count",
        "pass": count >= 25,
        "detail": f"{count} tests (minimum 25)",
    }


def check_serde_derives():
    try:
        text = IMPL.read_text()
        has_serialize = "Serialize" in text and "Deserialize" in text
    except FileNotFoundError:
        has_serialize = False
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_serialize,
        "detail": "found" if has_serialize else "not found",
    }


def check_vocabulary_separation():
    try:
        text = IMPL.read_text()
        has_guarantee = "GUARANTEE_VOCABULARY" in text
        has_diagnostic = "DIAGNOSTIC_VOCABULARY" in text
    except FileNotFoundError:
        has_guarantee = has_diagnostic = False
    return {
        "check": "vocabulary separation constants",
        "pass": has_guarantee and has_diagnostic,
        "detail": "found" if (has_guarantee and has_diagnostic) else "missing",
    }


def check_decision_engine_import():
    try:
        text = IMPL.read_text()
        has_import = "DecisionOutcome" in text and "DecisionReason" in text
    except FileNotFoundError:
        has_import = False
    return {
        "check": "decision engine integration",
        "pass": has_import,
        "detail": "found" if has_import else "not found",
    }


def check_bayesian_import():
    try:
        text = IMPL.read_text()
        has_import = "BayesianDiagnostics" in text and "DiagnosticConfidence" in text
    except FileNotFoundError:
        has_import = False
    return {
        "check": "bayesian diagnostics integration",
        "pass": has_import,
        "detail": "found" if has_import else "not found",
    }


def check_examples_artifact():
    """Verify examples artifact exists and has at least 5 example scenarios."""
    if not EXAMPLES_ARTIFACT.is_file():
        try:
            rel = str(EXAMPLES_ARTIFACT.relative_to(ROOT))
        except ValueError:
            rel = str(EXAMPLES_ARTIFACT)
        return {
            "check": "examples artifact: scenario count",
            "pass": False,
            "detail": f"MISSING: {rel}",
        }
    try:
        data = json.loads(EXAMPLES_ARTIFACT.read_text())
        # Support both "scenarios" and "examples" key names
        scenarios = data.get("scenarios", data.get("examples", []))
        count = len(scenarios)
        ok = count >= 5
        return {
            "check": "examples artifact: scenario count",
            "pass": ok,
            "detail": f"{count} scenarios (minimum 5)",
        }
    except (json.JSONDecodeError, KeyError) as exc:
        return {
            "check": "examples artifact: scenario count",
            "pass": False,
            "detail": f"JSON error: {exc}",
        }


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(EXAMPLES_ARTIFACT, "examples artifact"))
    checks.append(check_examples_artifact())
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.append(check_vocabulary_separation())
    checks.append(check_decision_engine_import())
    checks.append(check_bayesian_import())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = len(checks) - passing

    try:
        text = IMPL.read_text()
        test_count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        test_count = 0

    return {
        "bead_id": "bd-mwvn",
        "title": "Policy action explainer (diagnostic vs guarantee confidence)",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": test_count,
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    return result["overall_pass"], result["checks"]


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        v = result["verdict"]
        s = result["summary"]
        print(f"bd-mwvn policy_explainer: {v} ({s['passing']}/{s['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
