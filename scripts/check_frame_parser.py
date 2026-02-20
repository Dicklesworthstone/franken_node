#!/usr/bin/env python3
"""Verification script for bd-3tzl: Bounded parser guardrails."""

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
    print("bd-3tzl: Bounded Parser Guardrails — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/frame_parser.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_config = "struct ParserConfig" in content
        has_frame = "struct FrameInput" in content
        has_verdict = "struct DecodeVerdict" in content
        has_check = "fn check_frame" in content
        all_types = has_config and has_frame and has_verdict and has_check
    else:
        all_types = False
    all_pass &= check("BPG-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["BPG_SIZE_EXCEEDED", "BPG_DEPTH_EXCEEDED", "BPG_CPU_EXCEEDED",
                  "BPG_INVALID_CONFIG", "BPG_MALFORMED_FRAME"]
        found = [e for e in errors if e in content]
        all_pass &= check("BPG-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("BPG-ERRORS", "Error codes", False)

    results_path = os.path.join(ROOT, "artifacts/section_10_13/bd-3tzl/frame_decode_guardrail_results.json")
    results_valid = False
    if os.path.isfile(results_path):
        try:
            data = json.load(open(results_path))
            results_valid = "test_frames" in data and len(data["test_frames"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("BPG-RESULTS", "Frame decode guardrail test results", results_valid)

    integ_path = os.path.join(ROOT, "tests/integration/frame_decode_guardrails.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_size = "inv_bpg_size_bounded" in content
        has_depth = "inv_bpg_depth_bounded" in content
        has_cpu = "inv_bpg_cpu_bounded" in content
        has_audit = "inv_bpg_auditable" in content
    else:
        has_size = has_depth = has_cpu = has_audit = False
    all_pass &= check("BPG-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_size and has_depth and has_cpu and has_audit)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::frame_parser"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("BPG-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("BPG-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3tzl_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-BPG" in content
        has_types = "ParserConfig" in content and "FrameInput" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("BPG-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "frame_parser_verification",
        "bead": "bd-3tzl",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3tzl")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
