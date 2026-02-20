#!/usr/bin/env python3
"""Verification script for bd-1ugy: Stable telemetry namespace."""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
    print("bd-1ugy: Stable Telemetry Namespace — Verification\n")
    all_pass = True

    # 1. Implementation check
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/telemetry_namespace.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_registry = "struct SchemaRegistry" in content
        has_schema = "struct MetricSchema" in content
        has_plane = "enum Plane" in content
        has_register = "fn register" in content
        all_types = has_registry and has_schema and has_plane and has_register
    else:
        all_types = False
    all_pass &= check("TNS-IMPL", "Implementation with all required types", impl_exists and all_types)

    # 2. Error codes
    if impl_exists:
        content = open(impl_path).read()
        errors = ["TNS_INVALID_NAMESPACE", "TNS_VERSION_MISSING", "TNS_FROZEN_CONFLICT",
                  "TNS_ALREADY_DEPRECATED", "TNS_NOT_FOUND"]
        found = [e for e in errors if e in content]
        all_pass &= check("TNS-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("TNS-ERRORS", "Error codes", False)

    # 3. Catalog fixture
    catalog_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1ugy/telemetry_schema_catalog.json")
    catalog_valid = False
    if os.path.isfile(catalog_path):
        try:
            data = json.load(open(catalog_path))
            catalog_valid = "metrics" in data and len(data["metrics"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("TNS-CATALOG", "Telemetry schema catalog fixture", catalog_valid)

    # 4. Integration tests
    integ_path = os.path.join(ROOT, "tests/integration/metric_schema_stability.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_versioned = "inv_tns_versioned" in content
        has_frozen = "inv_tns_frozen" in content
        has_deprecated = "inv_tns_deprecated" in content
        has_namespace = "inv_tns_namespace" in content
    else:
        has_versioned = has_frozen = has_deprecated = has_namespace = False
    all_pass &= check("TNS-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_versioned and has_frozen and has_deprecated and has_namespace)

    # 5. Rust tests
    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::telemetry_namespace"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("TNS-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("TNS-TESTS", "Rust unit tests pass", False, str(e))

    # 6. Spec
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1ugy_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-TNS" in content
        has_types = "SchemaRegistry" in content and "MetricSchema" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("TNS-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "telemetry_namespace_verification",
        "bead": "bd-1ugy",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1ugy")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
