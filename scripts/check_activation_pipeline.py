from pathlib import Path
#!/usr/bin/env python3
"""Verification script for bd-1d7n: Deterministic activation pipeline."""

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
    logger = configure_test_logging("check_activation_pipeline")
    print("bd-1d7n: Deterministic Activation Pipeline — Verification\n")
    all_pass = True

    # Check implementation file
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/activation_pipeline.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_stage = "enum ActivationStage" in content
        has_result = "struct StageResult" in content
        has_transcript = "struct ActivationTranscript" in content
        has_error = "enum StageError" in content
        has_activate = "fn activate" in content
        all_types = has_stage and has_result and has_transcript and has_error and has_activate
    else:
        all_types = False
    all_pass &= check("AP-IMPL", "Implementation with all required types and activate fn",
                       impl_exists and all_types)

    # Check stage ordering
    if impl_exists:
        content = Path(impl_path).read_text()
        stages = ["SandboxCreate", "SecretMount", "CapabilityIssue", "HealthReady"]
        found = [s for s in stages if s in content]
        all_pass &= check("AP-STAGES", "All 4 activation stages present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("AP-STAGES", "Activation stages", False)

    # Check error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["ACT_SANDBOX_FAILED", "ACT_SECRET_MOUNT_FAILED",
                  "ACT_CAPABILITY_FAILED", "ACT_HEALTH_FAILED"]
        found = [e for e in errors if e in content]
        all_pass &= check("AP-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("AP-ERRORS", "Error codes", False)

    # Check fixtures
    fixture_path = os.path.join(ROOT, "fixtures/activation/pipeline_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("AP-FIXTURES", "Pipeline scenarios fixture", fixture_valid)

    # Check stage transcript
    transcript_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl")
    transcript_valid = False
    if os.path.isfile(transcript_path):
        lines = Path(transcript_path).read_text().strip().split("\n")
        try:
            entries = [json.loads(line) for line in lines]
            has_events = any(e.get("event") == "activation_complete" for e in entries)
            has_stages = any(e.get("event") == "stage_complete" for e in entries)
            transcript_valid = has_events and has_stages and len(entries) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("AP-TRANSCRIPT", "Stage transcript artifact", transcript_valid)

    # Check integration tests
    integ_path = os.path.join(ROOT, "tests/integration/activation_pipeline_determinism.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_order = "inv_act_stage_order" in content
        has_health = "inv_act_health_last" in content
        has_determ = "inv_act_deterministic" in content
        has_secret = "inv_act_no_secret_leak" in content
    else:
        has_order = has_health = has_determ = has_secret = False
    all_pass &= check("AP-INTEG-TESTS", "Integration tests cover all 4 invariants",
                       integ_exists and has_order and has_health and has_determ and has_secret)

    # Run Rust unit tests
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "connector::activation_pipeline"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("AP-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("AP-TESTS", "Rust unit tests pass", False, str(e))

    # Check spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1d7n_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-ACT" in content
        has_stages_spec = "SandboxCreate" in content and "HealthReady" in content
    else:
        has_invariants = has_stages_spec = False
    all_pass &= check("AP-SPEC", "Specification with invariants and stages",
                       spec_exists and has_invariants and has_stages_spec)

    # Check secret cleanup invariant in code
    if impl_exists:
        content = Path(impl_path).read_text()
        has_cleanup = "tracker.cleanup()" in content
        has_no_leak = "NO-SECRET-LEAK" in content or "no_secret_leak" in content.lower() or "cleanup" in content.lower()
    else:
        has_cleanup = has_no_leak = False
    all_pass &= check("AP-SECRET-CLEANUP", "Secret cleanup on failure path",
                       has_cleanup and has_no_leak)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "activation_pipeline_verification",
        "bead": "bd-1d7n",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1d7n")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
