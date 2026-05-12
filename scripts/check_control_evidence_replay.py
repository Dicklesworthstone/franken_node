#!/usr/bin/env python3
"""Verification script for bd-tyr2: control evidence replay integration.

Usage:
    python scripts/check_control_evidence_replay.py          # human-readable
    python scripts/check_control_evidence_replay.py --json    # machine-readable
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

IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "control_evidence_replay.rs"
CONFORMANCE_TEST = ROOT / "tests" / "conformance" / "control_evidence_replay.rs"
ADOPTION_DOC = ROOT / "docs" / "integration" / "control_evidence_replay_adoption.md"
SPEC = ROOT / "docs" / "specs" / "section_10_15" / "bd-tyr2_contract.md"
REPLAY_REPORT = ROOT / "artifacts" / "10.15" / "control_evidence_replay_report.json"
VALIDATOR_IMPL = ROOT / "crates" / "franken-node" / "src" / "tools" / "evidence_replay_validator.rs"
CONTROL_EVIDENCE = ROOT / "crates" / "franken-node" / "src" / "connector" / "control_evidence.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"

REQUIRED_TYPES = [
    "pub enum ReplayVerdict",
    "pub struct ControlReplayGate",
    "pub struct ReplayGateEvent",
    "pub struct ReplayGateSummary",
]

REQUIRED_METHODS = [
    "fn verify(",
    "fn verify_from_entry(",
    "fn verify_batch(",
    "fn gate_pass(",
    "fn summary(",
    "fn to_report(",
    "fn events(",
    "fn take_events(",
    "fn verdicts(",
    "fn map_to_ledger_kind(",
    "fn to_ledger_entry(",
    "fn build_replay_context(",
]

EVENT_CODES = [
    "RPL-001",
    "RPL-002",
    "RPL-003",
    "RPL-004",
    "RPL-005",
]

INVARIANTS = [
    "INV-CRG-CANONICAL",
    "INV-CRG-BLOCK-DIVERGED",
    "INV-CRG-DETERMINISTIC",
    "INV-CRG-COMPLETE",
]

DECISION_TYPES = [
    "HealthGateEval",
    "RolloutTransition",
    "QuarantineAction",
    "FencingDecision",
    "MigrationDecision",
]

GATE_VERDICTS = ["REPRODUCED", "DIVERGED", "ERROR"]

REQUIRED_IMPL_TESTS = [
    "test_map_to_ledger_kind_admit",
    "test_map_to_ledger_kind_deny",
    "test_map_to_ledger_kind_quarantine",
    "test_map_to_ledger_kind_release",
    "test_map_to_ledger_kind_rollback",
    "test_map_to_ledger_kind_throttle",
    "test_map_to_ledger_kind_escalate",
    "test_to_ledger_entry_fields",
    "test_to_ledger_entry_payload",
    "test_build_replay_context_has_primary_candidate",
    "test_build_replay_context_epoch",
    "test_build_replay_context_policy_snapshot",
    "test_build_replay_context_is_valid",
    "test_build_replay_context_constraint_satisfied",
    "test_verdict_reproduced_label",
    "test_verdict_diverged_label",
    "test_verdict_error_label",
    "test_verdict_is_reproduced",
    "test_verdict_is_diverged",
    "test_verdict_is_error",
    "test_verdict_display_reproduced",
    "test_verdict_display_diverged",
    "test_verdict_display_error",
    "test_verdict_serde_roundtrip",
    "test_verdict_diverged_serde_roundtrip",
    "test_summary_gate_pass_all_reproduced",
    "test_summary_gate_fail_on_diverged",
    "test_summary_gate_fail_on_error",
    "test_summary_gate_fail_empty",
    "test_summary_display",
    "test_summary_serde_roundtrip",
    "test_verify_health_gate_reproduced",
    "test_verify_rollout_reproduced",
    "test_verify_quarantine_reproduced",
    "test_verify_fencing_reproduced",
    "test_verify_migration_reproduced",
    "test_verify_mismatch_diverged",
    "test_verify_kind_mismatch_diverged",
    "test_verify_invalid_context_error",
    "test_verify_epoch_mismatch_error",
    "test_verify_emits_rpl001",
    "test_verify_reproduced_emits_rpl002",
    "test_verify_diverged_emits_rpl003",
    "test_verify_error_emits_rpl004",
    "test_verify_emits_rpl005",
    "test_verify_block_emits_rpl005_block",
    "test_gate_pass_all_reproduced",
    "test_gate_fail_on_diverged",
    "test_gate_fail_on_error",
    "test_verify_batch_all_reproduced",
    "test_verify_batch_mixed",
    "test_determinism_identical_runs",
    "test_determinism_100_runs",
    "test_summary_all_reproduced",
    "test_summary_with_diverged",
    "test_report_json_structure",
    "test_report_per_type_results",
    "test_take_events_drains",
    "test_event_trace_id",
    "test_default_gate",
    "test_verdicts_accumulate",
    "test_adversarial_wrong_epoch",
    "test_adversarial_tampered_kind",
    "test_adversarial_empty_candidates",
    "test_all_decision_types_replay",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_replay_gate_event_serde",
]

REQUIRED_CONFORMANCE_TESTS = [
    "test_replay_health_gate_eval_admit",
    "test_replay_health_gate_eval_deny",
    "test_replay_rollout_transition_admit",
    "test_replay_quarantine_action",
    "test_replay_fencing_decision_admit",
    "test_replay_migration_decision_admit",
    "test_diverged_blocks_gate",
    "test_error_blocks_gate",
    "test_epoch_mismatch_detected",
    "test_replay_deterministic_across_runs",
    "test_batch_validation_all_decision_types",
    "test_event_codes_defined",
    "test_replay_event_codes_from_validator",
    "test_invariant_canonical_validator",
    "test_invariant_deterministic",
    "test_invariant_fail_closed",
    "test_invariant_complete",
    "test_summary_report_after_batch",
    "test_gate_verdict_match_passes",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.exists():
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    text = MOD_RS.read_text()
    found = "pub mod control_evidence_replay;" in text
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_impl_test_count():
    if not IMPL.exists():
        return {"check": "impl unit test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 50
    return {
        "check": "impl unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 50)",
    }


def check_conformance_test_count():
    if not CONFORMANCE_TEST.exists():
        return {"check": "conformance test count", "pass": False, "detail": "test file missing"}
    text = CONFORMANCE_TEST.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 15
    return {
        "check": "conformance test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 15)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_canonical_validator_usage():
    if not IMPL.exists():
        return {"check": "uses canonical validator", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    uses_canonical = "EvidenceReplayValidator" in text
    no_custom = "fn replay_decision" not in text
    ok = uses_canonical and no_custom
    return {
        "check": "uses canonical 10.14 validator (no custom replay logic)",
        "pass": ok,
        "detail": "canonical validator used" if ok else "VIOLATION: custom replay logic detected",
    }


def check_adoption_doc():
    results = []
    if not ADOPTION_DOC.exists():
        results.append({"check": "adoption doc: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "adoption doc: exists", "pass": True, "detail": "found"})
    text = ADOPTION_DOC.read_text()
    for dt in DECISION_TYPES:
        found = dt in text
        results.append({
            "check": f"adoption doc: {dt} documented",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    for verdict in GATE_VERDICTS:
        found = verdict in text
        results.append({
            "check": f"adoption doc: verdict {verdict}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_spec_content():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec: exists", "pass": False, "detail": "spec missing"})
        return results
    text = SPEC.read_text()
    for dt in DECISION_TYPES:
        found = dt in text
        results.append({
            "check": f"spec: {dt} documented",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    for verdict in GATE_VERDICTS:
        found = verdict in text
        results.append({
            "check": f"spec: verdict {verdict} documented",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_replay_report():
    results = []
    if not REPLAY_REPORT.exists():
        results.append({"check": "replay report: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "replay report: exists", "pass": True, "detail": "found"})
    try:
        data = json.loads(REPLAY_REPORT.read_text())
    except json.JSONDecodeError:
        results.append({"check": "replay report: valid JSON", "pass": False, "detail": "invalid JSON"})
        return results
    results.append({"check": "replay report: valid JSON", "pass": True, "detail": "valid"})

    # Check all decision types covered
    types_in_report = {dt["type"] for dt in data.get("decision_types", [])}
    all_covered = all(dt in types_in_report for dt in DECISION_TYPES)
    results.append({
        "check": "replay report: all decision types covered",
        "pass": all_covered,
        "detail": f"found {len(types_in_report)} types" if all_covered else "missing types",
    })

    # Check adversarial tests present
    adversarial = data.get("adversarial_tests", [])
    has_adversarial = len(adversarial) >= 3
    results.append({
        "check": "replay report: adversarial tests",
        "pass": has_adversarial,
        "detail": f"{len(adversarial)} scenarios" if has_adversarial else "insufficient",
    })

    # Check determinism
    det_verdict = data.get("determinism_verdict", "")
    has_det = det_verdict == "ALL_IDENTICAL"
    results.append({
        "check": "replay report: determinism verified",
        "pass": has_det,
        "detail": det_verdict if has_det else "NOT VERIFIED",
    })

    # Check gate behavior
    gate = data.get("gate_behavior", {})
    correct_gate = (
        gate.get("REPRODUCED") == "pass"
        and gate.get("DIVERGED") == "fail"
        and gate.get("ERROR") == "fail"
    )
    results.append({
        "check": "replay report: gate behavior correct",
        "pass": correct_gate,
        "detail": "REPRODUCED=pass, DIVERGED/ERROR=fail" if correct_gate else "incorrect gate behavior",
    })

    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(CONFORMANCE_TEST, "conformance test"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(ADOPTION_DOC, "adoption document"))
    checks.append(check_file(REPLAY_REPORT, "replay report"))
    checks.append(check_file(VALIDATOR_IMPL, "canonical validator (10.14)"))
    checks.append(check_file(CONTROL_EVIDENCE, "control evidence (10.15)"))

    # Module registration
    checks.append(check_module_registered())

    # Test counts
    checks.append(check_impl_test_count())
    checks.append(check_conformance_test_count())

    # Serde derives
    checks.append(check_serde_derives())

    # Canonical validator usage
    checks.append(check_canonical_validator_usage())

    # Implementation content: types, methods, events, invariants, tests
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_IMPL_TESTS, "impl_test"))

    # Conformance test content
    checks.extend(check_content(CONFORMANCE_TEST, REQUIRED_CONFORMANCE_TESTS, "conformance_test"))

    # Adoption doc
    checks.extend(check_adoption_doc())

    # Spec content
    checks.extend(check_spec_content())

    # Replay report
    checks.extend(check_replay_report())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-tyr2",
        "title": "Evidence replay validator integration into control-plane gates",
        "section": "10.15",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_impl_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_control_evidence_replay")
    logger.info("starting %s verification", "check_control_evidence_replay")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-tyr2 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
