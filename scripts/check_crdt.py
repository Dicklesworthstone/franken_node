#!/usr/bin/env python3
"""Verification script for bd-19u: CRDT State Mode Scaffolding."""

import json
import os
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

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
    logger = configure_test_logging("check_crdt")
    print("bd-19u: CRDT State Mode Scaffolding — Verification\n")
    all_pass = True

    # CRDT-IMPL: Implementation file exists with all 4 types
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/crdt.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_lww = "struct LwwMap" in content
        has_or = "struct OrSet" in content
        has_gc = "struct GCounter" in content
        has_pn = "struct PnCounter" in content
        all_types = has_lww and has_or and has_gc and has_pn
    else:
        all_types = False
    all_pass &= check("CRDT-IMPL", "Implementation file with all 4 CRDT types", impl_exists and all_types)

    # CRDT-MERGE: Each type has a merge method
    if impl_exists:
        content = Path(impl_path).read_text()
        merge_count = content.count("fn merge(")
        all_pass &= check("CRDT-MERGE", "All 4 CRDT types implement merge", merge_count >= 4,
                          f"found {merge_count} merge methods")
    else:
        all_pass &= check("CRDT-MERGE", "All 4 CRDT types implement merge", False)

    # CRDT-ERROR: CrdtError with TypeMismatch variant
    if impl_exists:
        content = Path(impl_path).read_text()
        has_error = "enum CrdtError" in content and "TypeMismatch" in content
        all_pass &= check("CRDT-ERROR", "CrdtError with TypeMismatch variant", has_error)
    else:
        all_pass &= check("CRDT-ERROR", "CrdtError with TypeMismatch variant", False)

    # CRDT-TAGGED: Each CRDT carries crdt_type field
    if impl_exists:
        content = Path(impl_path).read_text()
        tagged_count = content.count("pub crdt_type: CrdtType")
        # LwwMap, OrSet, GCounter, PnCounter = 4, but PnCounter embeds GCounters so 4 struct-level
        all_pass &= check("CRDT-TAGGED", "Schema tag on each CRDT struct", tagged_count >= 4,
                          f"found {tagged_count} crdt_type fields")
    else:
        all_pass &= check("CRDT-TAGGED", "Schema tag on each CRDT struct", False)

    # CRDT-FIXTURES: Fixture files exist
    fixture_dir = os.path.join(ROOT, "fixtures/crdt")
    expected_fixtures = ["lww_map_merge.json", "or_set_merge.json", "gcounter_merge.json", "pncounter_merge.json"]
    found_fixtures = []
    for f in expected_fixtures:
        if os.path.isfile(os.path.join(fixture_dir, f)):
            found_fixtures.append(f)
    all_pass &= check("CRDT-FIXTURES", "Merge fixture files for all 4 types",
                      len(found_fixtures) == len(expected_fixtures),
                      f"found {len(found_fixtures)}/{len(expected_fixtures)}")

    # CRDT-FIXTURE-VALID: Fixtures are valid JSON with cases
    fixture_valid = True
    for f in expected_fixtures:
        fpath = os.path.join(fixture_dir, f)
        if os.path.isfile(fpath):
            try:
                data = json.loads(Path(fpath).read_text())
                if "cases" not in data or len(data["cases"]) == 0:
                    fixture_valid = False
            except (json.JSONDecodeError, KeyError):
                fixture_valid = False
        else:
            fixture_valid = False
    all_pass &= check("CRDT-FIXTURE-VALID", "Fixture files are valid JSON with cases", fixture_valid)

    # CRDT-CONFORMANCE: Conformance test file exists
    conf_path = os.path.join(ROOT, "tests/conformance/crdt_merge_fixtures.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_comm = "commutativity" in content
        has_assoc = "associativity" in content
        has_idemp = "idempotency" in content
        all_laws = has_comm and has_assoc and has_idemp
    else:
        all_laws = False
    all_pass &= check("CRDT-CONFORMANCE", "Conformance tests cover all 3 merge laws",
                      conf_exists and all_laws)

    # CRDT-TESTS: Rust tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::crdt"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        # Count passed tests
        import re
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("CRDT-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("CRDT-TESTS", "Rust unit tests pass", False, str(e))

    # CRDT-SPEC: Spec contract exists
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-19u_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_types = "lww_map" in content and "or_set" in content and "gcounter" in content and "pncounter" in content
    else:
        has_types = False
    all_pass &= check("CRDT-SPEC", "Specification contract exists with all types", spec_exists and has_types)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    # Write evidence
    evidence = {
        "gate": "crdt_verification",
        "bead": "bd-19u",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-19u")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
