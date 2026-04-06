#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-17mb: Fail-closed manifest negotiation."""

import json
import os
import re
import subprocess
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
CHECKS = []


def check(check_id, description, passed, details=None):
    entry = {"id": check_id, "description": description, "status": "PASS" if passed else "FAIL"}
    if details:
        entry["details"] = details
    CHECKS.append(entry)
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {check_id}: {description}")
    if details:
        print(f"         {details}")
    return passed


def main():
    logger = configure_test_logging("check_manifest_negotiation")
    print("bd-17mb: Fail-Closed Manifest Negotiation — Verification\n")
    all_pass = True

    # MN-IMPL: Implementation file
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/manifest_negotiation.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_semver = "struct SemVer" in content
        has_manifest = "struct ConnectorManifest" in content
        has_host = "struct HostCapabilities" in content
        has_negotiate = "fn negotiate" in content
        all_types = has_semver and has_manifest and has_host and has_negotiate
    else:
        all_types = False
    all_pass &= check("MN-IMPL", "Implementation with SemVer, manifest, host caps, negotiate",
                       impl_exists and all_types)

    # MN-SEMVER: Semantic ordering (not lexical)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_ord = "impl Ord for SemVer" in content
        has_cmp = "self.major" in content and ".cmp(" in content
        all_pass &= check("MN-SEMVER", "Semantic version ordering implemented", has_ord and has_cmp)
    else:
        all_pass &= check("MN-SEMVER", "SemVer ordering", False)

    # MN-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["MANIFEST_VERSION_UNSUPPORTED", "MANIFEST_FEATURE_MISSING",
                  "MANIFEST_TRANSPORT_MISMATCH", "MANIFEST_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("MN-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("MN-ERRORS", "Error codes", False)

    # MN-TRANSPORT: Transport capability types
    if impl_exists:
        content = Path(impl_path).read_text()
        caps = ["Http1", "Http2", "Http3", "WebSocket", "Grpc"]
        found = [c for c in caps if c in content]
        all_pass &= check("MN-TRANSPORT", "All 5 transport capability types",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("MN-TRANSPORT", "Transport caps", False)

    # MN-FIXTURES: Negotiation scenarios fixture
    fixture_path = os.path.join(ROOT, "fixtures/manifest_negotiation/negotiation_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 5
        except json.JSONDecodeError:
            pass
    all_pass &= check("MN-FIXTURES", "Negotiation scenarios fixture", fixture_valid)

    # MN-TRACE: Negotiation trace artifact
    trace_path = os.path.join(ROOT, "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json")
    trace_valid = False
    if os.path.isfile(trace_path):
        try:
            data = json.loads(Path(trace_path).read_text())
            trace_valid = "negotiations" in data and len(data["negotiations"]) >= 2
        except json.JSONDecodeError:
            pass
    all_pass &= check("MN-TRACE", "Manifest negotiation trace artifact", trace_valid)

    # MN-CONFORMANCE: Conformance test file
    conf_path = os.path.join(ROOT, "tests/conformance/manifest_negotiation_fail_closed.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_fail_closed = "fails_closed" in content
        has_semantic = "semantic" in content.lower()
        has_trace = "trace" in content
    else:
        has_fail_closed = has_semantic = has_trace = False
    all_pass &= check("MN-CONFORMANCE", "Conformance tests cover fail-closed, semantic, trace",
                       conf_exists and has_fail_closed and has_semantic and has_trace)

    # MN-TESTS: Rust unit tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "connector::manifest_negotiation"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("MN-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("MN-TESTS", "Rust unit tests pass", False, str(e))

    # MN-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-17mb_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-MANIFEST" in content
        has_outcome = "Outcome" in content
    else:
        has_invariants = has_outcome = False
    all_pass &= check("MN-SPEC", "Specification with invariants and outcome types",
                       spec_exists and has_invariants and has_outcome)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "manifest_negotiation_verification",
        "bead": "bd-17mb",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-17mb")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
