#!/usr/bin/env python3
"""Verification script for bd-3n2u: Formal schema spec and golden vectors."""

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
    print("bd-3n2u: Formal Schema Spec & Golden Vectors — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/golden_vectors.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_registry = "struct SchemaRegistry" in content
        has_vector = "struct GoldenVector" in content
        has_spec = "struct SchemaSpec" in content
        has_verify = "fn verify_vectors" in content
        all_types = has_registry and has_vector and has_spec and has_verify
    else:
        all_types = False
    all_pass &= check("GSV-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["GSV_MISSING_SCHEMA", "GSV_MISSING_VECTOR", "GSV_VECTOR_MISMATCH",
                  "GSV_NO_CHANGELOG", "GSV_INVALID_VERSION"]
        found = [e for e in errors if e in content]
        all_pass &= check("GSV-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("GSV-ERRORS", "Error codes", False)

    vectors_path = os.path.join(ROOT, "vectors/fnode_trust_vectors_v1.json")
    vectors_valid = False
    if os.path.isfile(vectors_path):
        try:
            data = json.load(open(vectors_path))
            vectors_valid = "vectors" in data and len(data["vectors"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("GSV-VECTORS", "Golden vector file", vectors_valid)

    schema_path = os.path.join(ROOT, "spec/FNODE_TRUST_SCHEMA_V1.cddl")
    all_pass &= check("GSV-SCHEMA", "CDDL schema file exists", os.path.isfile(schema_path))

    integ_path = os.path.join(ROOT, "tests/integration/golden_vector_verification.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_schema = "inv_gsv_schema" in content
        has_vectors = "inv_gsv_vectors" in content
        has_verified = "inv_gsv_verified" in content
        has_changelog = "inv_gsv_changelog" in content
    else:
        has_schema = has_vectors = has_verified = has_changelog = False
    all_pass &= check("GSV-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_schema and has_vectors and has_verified and has_changelog)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::golden_vectors"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("GSV-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("GSV-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3n2u_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-GSV" in content
        has_types = "SchemaRegistry" in content or "GoldenVector" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("GSV-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "golden_vectors_verification",
        "bead": "bd-3n2u",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3n2u")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
