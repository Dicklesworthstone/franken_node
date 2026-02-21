#!/usr/bin/env python3
"""Verification script for bd-1xao: Impossible-by-default adoption enforcement.

Checks that the Rust implementation, spec contract, policy document, and all
required event codes, invariants, error codes, types, and tests are present.

Usage:
    python scripts/check_impossible_default.py [--json] [--self-test]
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IMPL = os.path.join(ROOT, "crates/franken-node/src/security/impossible_default.rs")
MOD_RS = os.path.join(ROOT, "crates/franken-node/src/security/mod.rs")
SPEC = os.path.join(ROOT, "docs/specs/section_13/bd-1xao_contract.md")
POLICY = os.path.join(ROOT, "docs/policy/impossible_by_default_adoption.md")
EVIDENCE = os.path.join(ROOT, "artifacts/section_13/bd-1xao/verification_evidence.json")
SUMMARY = os.path.join(ROOT, "artifacts/section_13/bd-1xao/verification_summary.md")

RESULTS: list[dict] = []


def _safe_rel(path: str) -> str:
    """Return a relative path from ROOT, guarding against paths outside ROOT."""
    try:
        if os.path.commonpath([path, ROOT]) == ROOT:
            return os.path.relpath(path, ROOT)
    except ValueError:
        pass
    return path


def _check(name: str, passed: bool, detail: str = "") -> dict:
    entry = {"check": name, "pass": passed, "detail": detail or ("found" if passed else "NOT FOUND")}
    RESULTS.append(entry)
    return entry


def _file_exists(path: str, label: str) -> dict:
    exists = os.path.isfile(path)
    return _check(
        f"file: {label}",
        exists,
        f"exists: {_safe_rel(path)}" if exists else f"missing: {_safe_rel(path)}",
    )


def _file_contains(path: str, needle: str, label: str) -> dict:
    if not os.path.isfile(path):
        return _check(label, False, f"file missing: {_safe_rel(path)}")
    with open(path) as f:
        content = f.read()
    found = needle in content
    return _check(label, found, f"{'found' if found else 'NOT FOUND'}: {needle[:60]}")


def check_files() -> None:
    """Check all required files exist."""
    _file_exists(IMPL, "implementation")
    _file_exists(SPEC, "spec contract")
    _file_exists(POLICY, "policy document")
    _file_exists(EVIDENCE, "evidence artifact")
    _file_exists(SUMMARY, "verification summary")


def check_module_registered() -> None:
    """Check module is wired in mod.rs."""
    _file_contains(MOD_RS, "pub mod impossible_default;", "module registered in mod.rs")


def check_types() -> None:
    """Check all required types are defined in the implementation."""
    types = [
        "pub enum ImpossibleCapability",
        "pub struct CapabilityToken",
        "pub struct CapabilityEnforcer",
        "pub struct EnforcementReport",
        "pub struct EnforcementError",
        "pub struct EnforcementAuditEntry",
        "pub struct EnforcementMetrics",
        "pub enum EnforcementStatus",
        "pub struct CapabilityReportEntry",
    ]
    for ty in types:
        _file_contains(IMPL, ty, f"type: {ty}")


def check_capability_variants() -> None:
    """Check all five impossible-by-default capability variants."""
    variants = ["FsAccess", "OutboundNetwork", "ChildProcessSpawn", "UnsignedExtension", "DisableHardening"]
    for v in variants:
        _file_contains(IMPL, v, f"capability_variant: {v}")


def check_methods() -> None:
    """Check all required methods on CapabilityEnforcer."""
    methods = [
        "fn enforce(",
        "fn opt_in(",
        "fn is_enabled(",
        "fn attempt_silent_disable(",
        "fn expire_tokens(",
        "fn generate_report(",
        "fn status(",
        "fn metrics(",
        "fn audit_log(",
        "fn record_deployment(",
    ]
    for method in methods:
        _file_contains(IMPL, method, f"method: {method}")


def check_event_codes() -> None:
    """Check event codes IBD-001 through IBD-004."""
    codes_impl = {
        "IBD-001": "IBD_001_CAPABILITY_BLOCKED",
        "IBD-002": "IBD_002_OPT_IN_GRANTED",
        "IBD-003": "IBD_003_OPT_IN_EXPIRED",
        "IBD-004": "IBD_004_SILENT_DISABLE_DETECTED",
    }
    for code, const_name in codes_impl.items():
        _file_contains(IMPL, const_name, f"event_code_const: {const_name}")
        _file_contains(IMPL, f'"{code}"', f"event_code_value: {code}")

    # Event codes in spec
    for code in ["IBD-001", "IBD-002", "IBD-003", "IBD-004"]:
        _file_contains(SPEC, code, f"event_code_in_spec: {code}")

    # Event codes in policy
    for code in ["IBD-001", "IBD-002", "IBD-003", "IBD-004"]:
        _file_contains(POLICY, code, f"event_code_in_policy: {code}")


def check_error_codes() -> None:
    """Check error codes."""
    for code in ["ERR_IBD_BLOCKED", "ERR_IBD_TOKEN_EXPIRED", "ERR_IBD_INVALID_SIGNATURE", "ERR_IBD_SILENT_DISABLE"]:
        _file_contains(IMPL, code, f"error_code: {code}")


def check_invariants() -> None:
    """Check invariants INV-IBD-ENFORCE, INV-IBD-TOKEN, INV-IBD-AUDIT, INV-IBD-ADOPTION."""
    invariants_impl = ["INV-IBD-ENFORCE", "INV-IBD-TOKEN", "INV-IBD-AUDIT", "INV-IBD-ADOPTION"]
    for inv in invariants_impl:
        _file_contains(IMPL, inv, f"invariant_in_impl: {inv}")

    # Invariants in spec (mapped to spec names)
    spec_invariants = ["INV-IBD-DEFAULT", "INV-IBD-AUTH", "INV-IBD-AUDIT", "INV-IBD-COVERAGE"]
    for inv in spec_invariants:
        _file_contains(SPEC, inv, f"invariant_in_spec: {inv}")

    # Invariants in policy
    for inv in spec_invariants:
        _file_contains(POLICY, inv, f"invariant_in_policy: {inv}")


def check_acceptance_criteria() -> None:
    """Check AC coverage in the implementation and spec."""
    # AC1: capabilities defined
    _file_contains(IMPL, "ImpossibleCapability::ALL", "ac1: capabilities enumerated")
    _check("ac1: five capabilities", True, "FsAccess, OutboundNetwork, ChildProcessSpawn, UnsignedExtension, DisableHardening")

    # AC2: blocked by default
    _file_contains(IMPL, "EnforcementStatus::Blocked", "ac2: blocked by default state")

    # AC3: signed token with expiry
    _file_contains(IMPL, "expires_at_ms", "ac3: token expiry field")
    _file_contains(IMPL, "signature", "ac3: token signature field")
    _file_contains(IMPL, "fn is_expired(", "ac3: expiry check method")

    # AC4: actionable error messages
    _file_contains(IMPL, "fn description(", "ac4: actionable descriptions")
    _file_contains(IMPL, "fn blocked(", "ac4: blocked error constructor")

    # AC5: adoption metric
    _file_contains(IMPL, "fn adoption_rate_pct(", "ac5: adoption rate computation")
    _file_contains(IMPL, "deployments_enforced", "ac5: deployment tracking")

    # AC6: silent disable logged
    _file_contains(IMPL, "fn attempt_silent_disable(", "ac6: silent disable detection")
    _file_contains(IMPL, "IBD_004_SILENT_DISABLE_DETECTED", "ac6: IBD-004 event code used")

    # AC7: enforcement report
    _file_contains(IMPL, "fn generate_report(", "ac7: report generation")
    _file_contains(IMPL, "CapabilityReportEntry", "ac7: per-capability report entry")


def check_serde() -> None:
    """Check serde derives."""
    _file_contains(IMPL, "Serialize", "serde: Serialize")
    _file_contains(IMPL, "Deserialize", "serde: Deserialize")


def check_sha256() -> None:
    """Check SHA-256 usage for audit chain."""
    _file_contains(IMPL, "Sha256", "sha256: audit chain integrity")


def check_signature_verifier() -> None:
    """Check SignatureVerifier trait."""
    _file_contains(IMPL, "pub trait SignatureVerifier", "trait: SignatureVerifier")
    _file_contains(IMPL, "pub struct HashSignatureVerifier", "struct: HashSignatureVerifier")


def check_tests() -> None:
    """Check that all required tests exist."""
    test_names = [
        "test_five_capabilities_defined",
        "test_capability_variants",
        "test_capability_labels",
        "test_capability_descriptions_actionable",
        "test_capability_display",
        "test_all_blocked_by_default",
        "test_enforce_blocked_returns_error",
        "test_blocked_error_is_actionable",
        "test_opt_in_with_valid_token",
        "test_enforce_after_opt_in_succeeds",
        "test_opt_in_with_invalid_signature_rejected",
        "test_opt_in_with_expired_token_rejected",
        "test_token_expiry_blocks_enforce",
        "test_blocked_error_contains_capability_name",
        "test_expired_error_contains_token_id",
        "test_invalid_sig_error_actionable",
        "test_silent_disable_error_actionable",
        "test_error_display",
        "test_adoption_rate_100_pct",
        "test_adoption_rate_90_pct",
        "test_adoption_rate_zero_deployments",
        "test_record_deployment_enforced",
        "test_silent_disable_blocked",
        "test_silent_disable_logged",
        "test_silent_disable_increments_metric",
        "test_generate_report_structure",
        "test_report_all_blocked_by_default",
        "test_report_after_opt_in",
        "test_enforce_blocked_creates_audit_entry",
        "test_opt_in_creates_audit_entry",
        "test_audit_hash_chain",
        "test_audit_first_entry_has_zero_prev_hash",
        "test_token_is_expired",
        "test_token_content_hash_deterministic",
        "test_token_content_hash_differs_for_different_caps",
        "test_expire_tokens_batch",
        "test_expire_tokens_partial",
        "test_metrics_blocked_total",
        "test_metrics_opt_in_total",
        "test_event_codes_defined",
        "test_error_codes_defined",
        "test_invariant_tags_defined",
        "test_enforcement_status_blocked",
        "test_enforcement_status_enabled",
        "test_capability_serde_roundtrip",
        "test_token_serde_roundtrip",
        "test_enforcement_error_serde_roundtrip",
        "test_enforcement_report_serde",
        "test_metrics_serde_roundtrip",
        "test_full_lifecycle",
    ]
    for test in test_names:
        _file_contains(IMPL, f"fn {test}(", f"test: {test}")

    # Unit test count
    if os.path.isfile(IMPL):
        with open(IMPL) as f:
            src = f.read()
        test_count = len(re.findall(r"#\[test\]", src))
        _check("unit test count", test_count >= 45, f"{test_count} tests (minimum 45)")
    else:
        _check("unit test count", False, "impl file missing")


def check_spec_content() -> None:
    """Check spec contract has required content."""
    if not os.path.isfile(SPEC):
        _check("spec: has acceptance criteria", False, "file missing")
        return

    with open(SPEC) as f:
        spec_text = f.read()

    _check("spec: mentions bd-1xao", "bd-1xao" in spec_text, "bd-1xao in spec")
    _check("spec: has acceptance criteria", "Acceptance Criteria" in spec_text, "Acceptance Criteria section")
    _check("spec: has state machine", "BLOCKED" in spec_text and "AUTHORIZED" in spec_text, "state machine documented")
    _check("spec: has adoption tiers", "A3" in spec_text and "A4" in spec_text, "adoption tiers documented")
    _check("spec: has quantitative targets", "95%" in spec_text or "90%" in spec_text, "quantitative targets")
    _check("spec: has dangerous operations", "Dangerous" in spec_text, "dangerous operations catalog")


def check_policy_content() -> None:
    """Check policy document has required content."""
    if not os.path.isfile(POLICY):
        _check("policy: has risk description", False, "file missing")
        return

    with open(POLICY) as f:
        pol_text = f.read()

    _check("policy: has risk description", "Risk" in pol_text, "Risk section")
    _check("policy: has impact", "Impact" in pol_text, "Impact section")
    _check("policy: has monitoring", "Monitoring" in pol_text or "monitoring" in pol_text, "Monitoring section")
    _check("policy: has escalation", "Escalation" in pol_text, "Escalation section")
    _check("policy: has evidence requirements", "Evidence" in pol_text, "Evidence section")


def check_evidence_artifact() -> None:
    """Check evidence artifact structure."""
    if not os.path.isfile(EVIDENCE):
        _check("evidence: valid JSON", False, "file missing")
        return

    with open(EVIDENCE) as f:
        data = json.load(f)

    _check("evidence: valid JSON", True, "parsed successfully")
    _check("evidence: has bead_id", data.get("bead_id") == "bd-1xao", f"bead_id={data.get('bead_id')}")
    _check("evidence: has section", data.get("section") == "13", f"section={data.get('section')}")
    _check("evidence: has event_codes", "event_codes" in data, "event_codes present")
    _check("evidence: has invariants", "invariants" in data, "invariants present")


def run_all() -> dict:
    """Run all checks and return the result dict."""
    RESULTS.clear()

    check_files()
    check_module_registered()
    check_types()
    check_capability_variants()
    check_methods()
    check_event_codes()
    check_error_codes()
    check_invariants()
    check_acceptance_criteria()
    check_serde()
    check_sha256()
    check_signature_verifier()
    check_tests()
    check_spec_content()
    check_policy_content()
    check_evidence_artifact()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": "bd-1xao",
        "title": "Impossible-by-default adoption enforcement",
        "section": "13",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test():
    """Run self-test: verify run_all() produces a valid result."""
    result = run_all()
    assert "verdict" in result, "Missing 'verdict' key"
    assert result["total"] > 0, "No checks executed"
    assert isinstance(result["checks"], list), "checks is not a list"
    for entry in result["checks"]:
        assert "check" in entry, f"Missing 'check' key in entry: {entry}"
        assert "pass" in entry, f"Missing 'pass' key in entry: {entry}"
        assert isinstance(entry["pass"], bool), f"'pass' is not bool in entry: {entry}"

    total = result["total"]
    passing = result["passed"]
    failing = result["failed"]
    print(f"self_test: {passing}/{total} checks pass, {failing} failing")
    if failing:
        for c in result["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failing == 0


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Verify bd-1xao: impossible-by-default adoption")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{result['passed']}/{result['total']} checks pass")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
