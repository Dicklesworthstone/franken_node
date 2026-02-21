#!/usr/bin/env python3
"""Verification script for bd-k6o: deterministic safe-mode startup and operation flags.

Usage:
    python3 scripts/check_safe_mode.py              # human-readable
    python3 scripts/check_safe_mode.py --json        # machine-readable
    python3 scripts/check_safe_mode.py --self-test   # smoke-test
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "runtime" / "safe_mode.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_8" / "bd-k6o_contract.md"
POLICY = ROOT / "docs" / "policy" / "safe_mode_operations.md"
EVIDENCE = ROOT / "artifacts" / "section_10_8" / "bd-k6o" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_8" / "bd-k6o" / "verification_summary.md"

EVENT_CODES = ["SMO-001", "SMO-002", "SMO-003", "SMO-004"]

INVARIANTS = [
    "INV-SMO-DETERMINISTIC",
    "INV-SMO-RESTRICTED",
    "INV-SMO-FLAGPARSE",
    "INV-SMO-RECOVERY",
]

REQUIRED_TYPES = [
    "pub enum SafeModeEntryReason",
    "pub struct OperationFlags",
    "pub enum Capability",
    "pub enum EventSeverity",
    "pub struct SafeModeEvent",
    "pub enum SafeModeError",
    "pub struct SafeModeConfig",
    "pub struct SafeModeEntryReceipt",
    "pub struct ExitVerification",
    "pub struct SafeModeStatus",
    "pub struct SafeModeAuditEntry",
    "pub enum SafeModeAction",
    "pub struct SafeModeController",
]

REQUIRED_METHODS = [
    "fn none(",
    "fn safe_mode_only(",
    "fn parse_args(",
    "fn detect_conflicts(",
    "fn any_active(",
    "fn active_flag_names(",
    "fn enter_safe_mode(",
    "fn enter_degraded_state(",
    "fn exit_safe_mode(",
    "fn check_capability(",
    "fn is_active(",
    "fn entry_reason(",
    "fn set_flags(",
    "fn flags(",
    "fn entry_receipt(",
    "fn suspended_capabilities(",
    "fn status(",
    "fn events(",
    "fn take_events(",
    "fn audit_log(",
    "fn evaluate_triggers(",
    "fn check_crash_loop_trigger(",
    "fn check_epoch_mismatch_trigger(",
    "fn compute_restricted_capabilities(",
    "fn verify_trust_state(",
    "fn all_passed(",
    "fn failed_checks(",
    "fn label(",
    "fn all(",
    "fn to_json(",
]

ENTRY_REASON_VARIANTS = [
    "ExplicitFlag",
    "EnvironmentVariable",
    "ConfigField",
    "TrustCorruption",
    "CrashLoop",
    "EpochMismatch",
]

CAPABILITY_VARIANTS = [
    "ExtensionLoading",
    "TrustDelegations",
    "TrustLedgerWrites",
    "OutboundNetwork",
    "ScheduledTasks",
    "NonEssentialListeners",
]

OPERATION_FLAGS = [
    "--safe-mode",
    "--degraded",
    "--read-only",
    "--no-network",
]

REQUIRED_TESTS = [
    "test_flags_none",
    "test_flags_safe_mode_only",
    "test_flags_parse_empty",
    "test_flags_parse_safe_mode",
    "test_flags_parse_degraded",
    "test_flags_parse_read_only",
    "test_flags_parse_no_network",
    "test_flags_parse_all",
    "test_flags_parse_unknown_flag",
    "test_flags_deterministic_parsing",
    "test_flags_any_active",
    "test_flags_active_flag_names",
    "test_flags_detect_conflicts_safe_degraded",
    "test_flags_detect_no_conflicts",
    "test_flags_serde_roundtrip",
    "test_flags_default",
    "test_capability_all",
    "test_capability_labels",
    "test_capability_display",
    "test_capability_serde_roundtrip",
    "test_entry_reason_display",
    "test_entry_reason_crash_loop_display",
    "test_entry_reason_epoch_mismatch_display",
    "test_entry_reason_serde_roundtrip",
    "test_config_default",
    "test_config_serde_roundtrip",
    "test_receipt_pass_when_no_inconsistencies",
    "test_receipt_fail_when_inconsistencies",
    "test_receipt_to_json",
    "test_receipt_serde_roundtrip",
    "test_exit_verification_all_passed",
    "test_exit_verification_some_failed",
    "test_exit_verification_failed_checks",
    "test_status_inactive",
    "test_status_to_json",
    "test_status_serde_roundtrip",
    "test_action_display",
    "test_error_display_unknown_flag",
    "test_error_display_capability_restricted",
    "test_error_display_exit_precondition",
    "test_error_display_trust_verification",
    "test_error_serde_roundtrip",
    "test_severity_display",
    "test_controller_new_inactive",
    "test_controller_enter_safe_mode",
    "test_controller_enter_emits_smo001",
    "test_controller_enter_emits_smo002_for_each_capability",
    "test_controller_entry_receipt_created",
    "test_controller_entry_receipt_with_inconsistencies",
    "test_controller_capability_restricted",
    "test_controller_capability_unrestricted_when_inactive",
    "test_controller_exit_success",
    "test_controller_exit_denied",
    "test_controller_exit_denied_audit_logged",
    "test_controller_exit_requires_confirmation",
    "test_controller_suspended_capabilities",
    "test_controller_status_when_active",
    "test_controller_status_when_inactive",
    "test_controller_audit_log_on_enter",
    "test_controller_audit_log_on_exit",
    "test_controller_set_flags_detects_conflicts",
    "test_controller_take_events_drains",
    "test_controller_enter_degraded_state",
    "test_evaluate_triggers_explicit_flag",
    "test_evaluate_triggers_env_var",
    "test_evaluate_triggers_env_var_true",
    "test_evaluate_triggers_env_var_false",
    "test_evaluate_triggers_config_field",
    "test_evaluate_triggers_precedence_flag_over_env",
    "test_evaluate_triggers_precedence_env_over_config",
    "test_evaluate_triggers_none",
    "test_crash_loop_trigger_above_threshold",
    "test_crash_loop_trigger_below_threshold",
    "test_epoch_mismatch_trigger",
    "test_epoch_match_no_trigger",
    "test_compute_restricted_safe_mode",
    "test_compute_restricted_read_only",
    "test_compute_restricted_no_network",
    "test_compute_restricted_degraded",
    "test_compute_restricted_none",
    "test_compute_restricted_deterministic",
    "test_verify_trust_state_pass",
    "test_verify_trust_state_empty_evidence",
    "test_verify_trust_state_empty_hash",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_full_lifecycle",
    "test_drill_trust_corruption",
    "test_drill_crash_loop",
    "test_drill_epoch_mismatch",
    "test_set_unresolved_incidents",
    "test_config_accessor",
    "test_flags_accessor",
]

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


def _safe_rel(path: Path) -> str:
    """Return a display-friendly relative path, falling back to str(path)."""
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# -- Checks ------------------------------------------------------------------


def check_impl_exists() -> None:
    ok = IMPL.is_file()
    _check("impl_exists", ok,
           f"Implementation {'found' if ok else 'MISSING'}: {_safe_rel(IMPL)}")


def check_spec_exists() -> None:
    ok = SPEC.is_file()
    _check("spec_exists", ok,
           f"Spec file {'found' if ok else 'MISSING'}: {_safe_rel(SPEC)}")


def check_policy_exists() -> None:
    ok = POLICY.is_file()
    _check("policy_exists", ok,
           f"Policy file {'found' if ok else 'MISSING'}: {_safe_rel(POLICY)}")


def check_module_registered() -> None:
    if not MOD_RS.is_file():
        _check("module_registered", False, "mod.rs MISSING")
        return
    text = MOD_RS.read_text()
    ok = "pub mod safe_mode;" in text
    _check("module_registered", ok,
           "safe_mode registered in mod.rs" if ok else "NOT registered")


def check_event_codes_in_impl() -> None:
    if not IMPL.is_file():
        for code in EVENT_CODES:
            _check(f"event_code_impl:{code}", False, "implementation file missing")
        return
    text = IMPL.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"event_code_impl:{code}", ok,
               "found" if ok else "NOT FOUND in implementation")


def check_event_codes_in_spec() -> None:
    if not SPEC.is_file():
        for code in EVENT_CODES:
            _check(f"event_code_spec:{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"event_code_spec:{code}", ok,
               "found" if ok else "NOT FOUND in spec")


def check_invariants_in_impl() -> None:
    if not IMPL.is_file():
        for inv in INVARIANTS:
            _check(f"invariant_impl:{inv}", False, "implementation file missing")
        return
    text = IMPL.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"invariant_impl:{inv}", ok,
               "found" if ok else "NOT FOUND in implementation")


def check_invariants_in_spec() -> None:
    if not SPEC.is_file():
        for inv in INVARIANTS:
            _check(f"invariant_spec:{inv}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"invariant_spec:{inv}", ok,
               "found" if ok else "NOT FOUND in spec")


def check_types() -> None:
    if not IMPL.is_file():
        for ty in REQUIRED_TYPES:
            _check(f"type:{ty}", False, "implementation file missing")
        return
    text = IMPL.read_text()
    for ty in REQUIRED_TYPES:
        ok = ty in text
        _check(f"type:{ty}", ok, "found" if ok else "NOT FOUND")


def check_methods() -> None:
    if not IMPL.is_file():
        for method in REQUIRED_METHODS:
            _check(f"method:{method}", False, "implementation file missing")
        return
    text = IMPL.read_text()
    for method in REQUIRED_METHODS:
        ok = method in text
        _check(f"method:{method}", ok, "found" if ok else "NOT FOUND")


def check_entry_reason_variants() -> None:
    if not IMPL.is_file():
        for v in ENTRY_REASON_VARIANTS:
            _check(f"entry_reason:{v}", False, "implementation file missing")
        return
    text = IMPL.read_text()
    for v in ENTRY_REASON_VARIANTS:
        ok = v in text
        _check(f"entry_reason:{v}", ok, "found" if ok else "NOT FOUND")


def check_capability_variants() -> None:
    if not IMPL.is_file():
        for v in CAPABILITY_VARIANTS:
            _check(f"capability:{v}", False, "implementation file missing")
        return
    text = IMPL.read_text()
    for v in CAPABILITY_VARIANTS:
        ok = v in text
        _check(f"capability:{v}", ok, "found" if ok else "NOT FOUND")


def check_operation_flags_documented() -> None:
    if not SPEC.is_file():
        for flag in OPERATION_FLAGS:
            _check(f"flag_spec:{flag}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for flag in OPERATION_FLAGS:
        ok = flag in text
        _check(f"flag_spec:{flag}", ok, "found" if ok else "NOT FOUND in spec")


def check_serde_derives() -> None:
    if not IMPL.is_file():
        _check("serde_derives", False, "implementation file missing")
        return
    text = IMPL.read_text()
    ok = "Serialize" in text and "Deserialize" in text
    _check("serde_derives", ok, "found" if ok else "NOT FOUND")


def check_impl_tests() -> None:
    if not IMPL.is_file():
        for test in REQUIRED_TESTS:
            _check(f"test:{test}", False, "implementation file missing")
        return
    text = IMPL.read_text()
    for test in REQUIRED_TESTS:
        ok = f"fn {test}(" in text
        _check(f"test:{test}", ok, "found" if ok else "NOT FOUND")


def check_test_count() -> None:
    if not IMPL.is_file():
        _check("test_count", False, "implementation file missing")
        return
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 80
    _check("test_count", ok, f"{count} tests (minimum 80)")


def check_determinism_contract() -> None:
    """Verify that the spec documents determinism requirements."""
    if not SPEC.is_file():
        _check("determinism_contract", False, "spec file missing")
        return
    text = SPEC.read_text().lower()
    ok = "deterministic" in text and "same flags" in text
    _check("determinism_contract", ok,
           "Determinism requirements documented" if ok else "Incomplete determinism requirements")


def check_exit_protocol() -> None:
    """Verify that the spec documents the exit protocol."""
    if not SPEC.is_file():
        _check("exit_protocol", False, "spec file missing")
        return
    text = SPEC.read_text().lower()
    ok = "exit protocol" in text and "explicit operator action" in text
    _check("exit_protocol", ok,
           "Exit protocol documented" if ok else "Incomplete exit protocol")


def check_trust_reverification() -> None:
    """Verify that trust re-verification is documented."""
    if not SPEC.is_file():
        _check("trust_reverification", False, "spec file missing")
        return
    text = SPEC.read_text().lower()
    ok = "trust re-verification" in text or "re-verification" in text
    _check("trust_reverification", ok,
           "Trust re-verification documented" if ok else "Missing trust re-verification")


def check_policy_governance() -> None:
    """Verify that the policy covers key governance areas."""
    if not POLICY.is_file():
        _check("policy_governance", False, "policy file missing")
        return
    text = POLICY.read_text().lower()
    keywords = ["mandatory entry", "capability restrictions", "recovery procedures",
                "flag precedence", "audit"]
    missing = [k for k in keywords if k not in text]
    ok = len(missing) == 0
    _check("policy_governance", ok,
           "All governance sections present" if ok else f"Missing: {missing}")


def check_drill_tests() -> None:
    """Verify that drill tests are present in implementation."""
    if not IMPL.is_file():
        _check("drill_tests", False, "implementation file missing")
        return
    text = IMPL.read_text()
    drills = ["test_drill_trust_corruption", "test_drill_crash_loop", "test_drill_epoch_mismatch"]
    missing = [d for d in drills if f"fn {d}(" not in text]
    ok = len(missing) == 0
    _check("drill_tests", ok,
           "All drill tests present" if ok else f"Missing: {missing}")


def check_verification_evidence() -> None:
    if not EVIDENCE.is_file():
        _check("verification_evidence", False,
               f"Evidence file MISSING: {_safe_rel(EVIDENCE)}")
        return
    try:
        data = json.loads(EVIDENCE.read_text())
        ok = data.get("bead_id") == "bd-k6o" and data.get("status") == "pass"
        _check("verification_evidence", ok,
               "Evidence file valid" if ok else "Evidence has incorrect bead_id or status")
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"Evidence parse error: {exc}")


def check_verification_summary() -> None:
    ok = SUMMARY.is_file()
    _check("verification_summary", ok,
           f"Summary file {'found' if ok else 'MISSING'}: {_safe_rel(SUMMARY)}")


# -- Runner ------------------------------------------------------------------

ALL_CHECKS = [
    check_impl_exists,
    check_spec_exists,
    check_policy_exists,
    check_module_registered,
    check_event_codes_in_impl,
    check_event_codes_in_spec,
    check_invariants_in_impl,
    check_invariants_in_spec,
    check_types,
    check_methods,
    check_entry_reason_variants,
    check_capability_variants,
    check_operation_flags_documented,
    check_serde_derives,
    check_impl_tests,
    check_test_count,
    check_determinism_contract,
    check_exit_protocol,
    check_trust_reverification,
    check_policy_governance,
    check_drill_tests,
    check_verification_evidence,
    check_verification_summary,
]


def run_all() -> dict:
    RESULTS.clear()
    for fn in ALL_CHECKS:
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)
    failed = total - passed
    return {
        "bead_id": "bd-k6o",
        "section": "10.8",
        "title": "Deterministic safe-mode startup and operation flags",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "status": "pass" if failed == 0 else "fail",
        "passed": passed,
        "failed": failed,
        "total": total,
        "all_passed": failed == 0,
        "checks": list(RESULTS),
    }


def self_test() -> None:
    """Smoke-test: run all checks and assert the structure is valid."""
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == "bd-k6o"
    assert result["section"] == "10.8"
    assert isinstance(result["checks"], list)
    assert result["total"] == len(result["checks"])
    assert result["passed"] <= result["total"]
    assert result["failed"] == result["total"] - result["passed"]
    assert result["verdict"] in ("PASS", "FAIL")
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
    print("self_test passed")


def main() -> None:
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("bd-k6o: Deterministic safe-mode startup and operation flags")
        print("=" * 60)
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")
        print(f"\n  {result['passed']}/{result['total']} checks passed"
              f" (verdict={result['verdict']})")
        if result["verdict"] != "PASS":
            sys.exit(1)


if __name__ == "__main__":
    main()
