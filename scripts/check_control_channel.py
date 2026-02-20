#!/usr/bin/env python3
"""Verification script for bd-v97o: Authenticated control channel."""

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
    print("bd-v97o: Authenticated Control Channel — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/control_channel.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_config = "struct ChannelConfig" in content
        has_msg = "struct ChannelMessage" in content
        has_result = "struct AuthCheckResult" in content
        has_channel = "struct ControlChannel" in content
        has_process = "fn process_message" in content
        all_types = has_config and has_msg and has_result and has_channel and has_process
    else:
        all_types = False
    all_pass &= check("ACC-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["ACC_AUTH_FAILED", "ACC_SEQUENCE_REGRESS", "ACC_REPLAY_DETECTED",
                  "ACC_INVALID_CONFIG", "ACC_CHANNEL_CLOSED"]
        found = [e for e in errors if e in content]
        all_pass &= check("ACC-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("ACC-ERRORS", "Error codes", False)

    vectors_path = os.path.join(ROOT, "artifacts/section_10_13/bd-v97o/control_channel_replay_vectors.json")
    vectors_valid = False
    if os.path.isfile(vectors_path):
        try:
            data = json.load(open(vectors_path))
            vectors_valid = "vectors" in data and len(data["vectors"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("ACC-VECTORS", "Control channel replay vectors", vectors_valid)

    integ_path = os.path.join(ROOT, "tests/integration/control_channel_replay.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_auth = "inv_acc_authenticated" in content
        has_mono = "inv_acc_monotonic" in content
        has_replay = "inv_acc_replay_window" in content
        has_audit = "inv_acc_auditable" in content
    else:
        has_auth = has_mono = has_replay = has_audit = False
    all_pass &= check("ACC-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_auth and has_mono and has_replay and has_audit)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::control_channel"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("ACC-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("ACC-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-v97o_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-ACC" in content
        has_types = "ChannelConfig" in content and "ControlChannel" in content or "ChannelMessage" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("ACC-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "control_channel_verification",
        "bead": "bd-v97o",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-v97o")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
