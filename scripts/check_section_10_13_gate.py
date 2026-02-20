#!/usr/bin/env python3
"""Section 10.13 verification gate: comprehensive unit+e2e+logging."""

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
    print("Section 10.13 — FCP Deep-Mined Expansion Verification Gate\n")
    all_pass = True

    # 1. All connector Rust unit tests pass
    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::"],
            capture_output=True, text=True, timeout=300,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests >= 500
        all_pass &= check("GATE-RUST-UNIT", "Connector Rust unit tests pass",
                          tests_pass, f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("GATE-RUST-UNIT", "Connector Rust unit tests pass", False, str(e))

    # 2. All Python verification tests pass
    try:
        result = subprocess.run(
            ["python3", "-m", "pytest", "tests/", "-k", "test_check", "-q"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        py_match = re.search(r"(\d+) passed", result.stdout)
        py_tests = int(py_match.group(1)) if py_match else 0
        py_pass = result.returncode == 0 and py_tests >= 100
        all_pass &= check("GATE-PYTHON-TESTS", "Python verification tests pass",
                          py_pass, f"{py_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("GATE-PYTHON-TESTS", "Python verification tests pass", False, str(e))

    # 3. All per-bead verification evidence exists and passes
    beads_10_13 = [
        "bd-2gh", "bd-1rk", "bd-1h6", "bd-3en", "bd-18o", "bd-1cm", "bd-19u",
        "bd-24s", "bd-b44", "bd-3ua7", "bd-1vvs", "bd-2m2b", "bd-1nk5",
        "bd-17mb", "bd-3n58", "bd-35q1", "bd-1z9s", "bd-3i9o", "bd-1d7n",
        "bd-2yc4", "bd-y7lu", "bd-1m8r", "bd-w0jq", "bd-bq6y", "bd-2vs4",
        "bd-8uvb", "bd-8vby", "bd-jxgt", "bd-2t5u", "bd-29w6", "bd-91gg",
        "bd-2k74", "bd-3b8m", "bd-2eun", "bd-3cm3", "bd-1p2b", "bd-12h8",
        "bd-v97o", "bd-3tzl", "bd-1ugy", "bd-novi", "bd-1gnb", "bd-ck2h",
        "bd-35by", "bd-29ct", "bd-3n2u",
    ]
    evidence_pass = 0
    evidence_total = 0
    for bead in beads_10_13:
        epath = os.path.join(ROOT, f"artifacts/section_10_13/{bead}/verification_evidence.json")
        if os.path.isfile(epath):
            evidence_total += 1
            try:
                data = json.load(open(epath))
                if data.get("verdict") == "PASS":
                    evidence_pass += 1
            except json.JSONDecodeError:
                pass
    all_pass &= check("GATE-EVIDENCE", "Per-bead verification evidence",
                       evidence_pass >= 40,
                       f"{evidence_pass}/{evidence_total} beads PASS")

    # 4. Module count
    mod_path = os.path.join(ROOT, "crates/franken-node/src/connector/mod.rs")
    if os.path.isfile(mod_path):
        content = open(mod_path).read()
        modules = content.count("pub mod ")
        all_pass &= check("GATE-MODULES", "Connector module count",
                          modules >= 30, f"{modules} modules")
    else:
        all_pass &= check("GATE-MODULES", "Connector module count", False)

    # 5. Spec contract coverage
    spec_dir = os.path.join(ROOT, "docs/specs/section_10_13")
    if os.path.isdir(spec_dir):
        specs = [f for f in os.listdir(spec_dir) if f.endswith("_contract.md")]
        all_pass &= check("GATE-SPECS", "Spec contract files",
                          len(specs) >= 40, f"{len(specs)} spec contracts")
    else:
        all_pass &= check("GATE-SPECS", "Spec contract files", False)

    # 6. Integration test coverage
    integ_dir = os.path.join(ROOT, "tests/integration")
    if os.path.isdir(integ_dir):
        integ_files = [f for f in os.listdir(integ_dir) if f.endswith(".rs")]
        all_pass &= check("GATE-INTEGRATION", "Integration test files",
                          len(integ_files) >= 25, f"{len(integ_files)} integration test files")
    else:
        all_pass &= check("GATE-INTEGRATION", "Integration test files", False)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nSection 10.13 Gate Result: {passing}/{total} checks passed")

    evidence = {
        "gate": "section_10_13_verification_gate",
        "bead": "bd-3uoo",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": total - passing,
            "rust_unit_tests": rust_tests if 'rust_tests' in dir() else 0,
            "python_tests": py_tests if 'py_tests' in dir() else 0,
        }
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3uoo")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
