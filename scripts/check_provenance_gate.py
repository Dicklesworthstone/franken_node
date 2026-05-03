#!/usr/bin/env python3
"""Verification script for bd-3i9o: Provenance/attestation policy gates."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

CHECKS = []
PROVENANCE_GATE_UNIT_FILTER = "supply_chain::provenance_gate"
PROVENANCE_GATE_SECURITY_TARGET = "attestation_gate"
IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/provenance_gate.rs"
FIXTURE_PATH = ROOT / "fixtures/provenance/gate_scenarios.json"
DECISIONS_PATH = ROOT / "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json"
SECURITY_PATH = ROOT / "tests/security/attestation_gate.rs"
HARNESS_PATH = ROOT / "crates/franken-node/tests/attestation_gate.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-3i9o_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3i9o/verification_evidence.json"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
TEST_RESULT_RE = re.compile(
    r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
    re.IGNORECASE,
)
JSON_DECODER = json.JSONDecoder()
EMIT_HUMAN = True


def read_utf8(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def load_json_object(path: Path) -> tuple[dict[str, object] | None, str | None]:
    try:
        raw = path.read_text(encoding="utf-8")
        parsed = JSON_DECODER.decode(raw)
    except OSError as exc:
        return None, f"unable to read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"

    if not isinstance(parsed, dict):
        return None, f"expected JSON object in {path}"
    return parsed, None


def record_check(check_id, description, status, details=None):
    entry = {"id": check_id, "description": description, "status": status}
    if details:
        entry["details"] = details
    CHECKS.append(entry)
    if EMIT_HUMAN:
        print(f"  [{status}] {check_id}: {description}")
        if details:
            print(f"         {details}")
    return status == "PASS"


def check(check_id, description, passed, details=None):
    return record_check(check_id, description, "PASS" if passed else "FAIL", details)


def parse_rust_test_summary(output):
    running = sum(int(match) for match in re.findall(r"running (\d+) test(?:s)?", output))
    result_matches = TEST_RESULT_RE.findall(output)
    passed = sum(int(match[0]) for match in result_matches)
    failed = sum(int(match[1]) for match in result_matches)
    filtered = sum(int(match[4]) for match in result_matches)
    return {
        "running": running,
        "passed": passed,
        "failed": failed,
        "filtered": filtered,
    }


def summarize_failure_output(output, max_lines=6):
    cleaned_lines = [
        ANSI_ESCAPE_RE.sub("", line).strip() for line in output.splitlines()
    ]
    cleaned_lines = [line for line in cleaned_lines if line]
    error_start = next(
        (idx for idx, line in enumerate(cleaned_lines) if "error" in line.lower()),
        None,
    )
    snippet = (
        cleaned_lines[error_start:error_start + max_lines]
        if error_start is not None
        else cleaned_lines[:max_lines]
    )
    return " | ".join(snippet)


def select_failure_excerpt(*outputs):
    for output in outputs:
        excerpt = summarize_failure_output(output)
        if excerpt:
            return excerpt
    return ""


def run_gate_unit_tests():
    result = subprocess.run(
        [
            "rch",
            "exec",
            "--",
            "cargo",
            "test",
            "-p",
            "frankenengine-node",
            "--lib",
            "--",
            PROVENANCE_GATE_UNIT_FILTER,
        ],
        capture_output=True,
        text=True,
        timeout=3600,
        cwd=ROOT,
        check=False,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def run_gate_security_tests():
    result = subprocess.run(
        [
            "rch",
            "exec",
            "--",
            "cargo",
            "test",
            "-p",
            "frankenengine-node",
            "--test",
            PROVENANCE_GATE_SECURITY_TARGET,
        ],
        capture_output=True,
        text=True,
        timeout=3600,
        cwd=ROOT,
        check=False,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit evidence JSON to stdout")
    parser.add_argument(
        "--run-rust-tests",
        action="store_true",
        help="run the expensive rch cargo test proof even in JSON mode",
    )
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="skip the expensive Rust test proof and only validate checked-in structure",
    )
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help="write artifacts/section_10_13/bd-3i9o/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def main(argv=None):
    global EMIT_HUMAN
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = args.run_rust_tests or (not args.json and not args.structural_only)
    write_artifact = args.write_evidence or not args.json
    EMIT_HUMAN = not args.json
    CHECKS.clear()
    logger = configure_test_logging("check_provenance_gate")
    logger.info(
        "starting verification",
        extra={"json_mode": args.json, "run_rust_tests": run_tests, "write_evidence": write_artifact},
    )
    if EMIT_HUMAN:
        print("bd-3i9o: Provenance/Attestation Policy Gates - Verification\n")
    all_pass = True

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_policy = "struct ProvenancePolicy" in content
        has_prov = "struct ArtifactProvenance" in content
        has_gate = "struct GateDecision" in content
        has_eval = "fn evaluate_gate" in content
        all_types = has_policy and has_prov and has_gate and has_eval
    else:
        all_types = False
    all_pass &= check("PG-IMPL", "Implementation with policy, provenance, gate, evaluate",
                       impl_exists and all_types)

    if impl_exists:
        attest = ["Slsa", "Sigstore", "InToto"]
        found = [a for a in attest if a in content]
        all_pass &= check("PG-ATTEST", "Attestation types present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("PG-ATTEST", "Attestation types", False)

    if impl_exists:
        errors = ["PROV_ATTEST_MISSING", "PROV_ASSURANCE_LOW",
                  "PROV_BUILDER_UNTRUSTED", "PROV_POLICY_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("PG-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("PG-ERRORS", "Error codes", False)

    fixture_valid = False
    fixture_details = None
    fixture_data, fixture_error = load_json_object(FIXTURE_PATH)
    if fixture_data is not None:
        cases = fixture_data.get("cases")
        fixture_valid = isinstance(cases, list) and len(cases) >= 4
        fixture_details = f"found {len(cases) if isinstance(cases, list) else 0} cases"
    elif fixture_error:
        fixture_details = fixture_error
    all_pass &= check("PG-FIXTURES", "Gate scenarios fixture", fixture_valid, fixture_details)

    decisions_valid = False
    decisions_details = None
    decisions_data, decisions_error = load_json_object(DECISIONS_PATH)
    if decisions_data is not None:
        decisions = decisions_data.get("decisions")
        decisions_valid = isinstance(decisions, list) and len(decisions) >= 2
        decisions_details = f"found {len(decisions) if isinstance(decisions, list) else 0} decisions"
    elif decisions_error:
        decisions_details = decisions_error
    all_pass &= check(
        "PG-DECISIONS",
        "Provenance gate decisions artifact",
        decisions_valid,
        decisions_details,
    )

    security_content = read_utf8(SECURITY_PATH)
    sec_exists = security_content is not None
    if security_content is not None:
        has_attest = "attestation" in security_content.lower()
        has_assurance = "assurance" in security_content.lower()
        has_builder = "builder" in security_content.lower()
    else:
        has_attest = has_assurance = has_builder = False
    all_pass &= check("PG-SECURITY-TESTS", "Security tests cover attestation, assurance, builder",
                       sec_exists and has_attest and has_assurance and has_builder)

    harness_content = read_utf8(HARNESS_PATH)
    harness_exists = harness_content is not None
    if harness_content is not None:
        harness_wired = "../../../tests/security/attestation_gate.rs" in harness_content
    else:
        harness_wired = False
    all_pass &= check(
        "PG-HARNESS",
        "Cargo harness wires provenance gate security tests",
        harness_exists and harness_wired,
    )

    if run_tests:
        try:
            unit_summary, unit_output = run_gate_unit_tests()
            security_summary, security_output = run_gate_security_tests()
            unit_ok = (
                unit_summary["returncode"] == 0
                and unit_summary["running"] > 0
                and unit_summary["passed"] > 0
                and unit_summary["failed"] == 0
            )
            security_ok = (
                security_summary["returncode"] == 0
                and security_summary["running"] > 0
                and security_summary["passed"] > 0
                and security_summary["failed"] == 0
            )
            tests_pass = unit_ok and security_ok
            details = (
                f"unit {unit_summary['passed']} passed / {unit_summary['running']} ran / {unit_summary['filtered']} filtered; "
                f"security {security_summary['passed']} passed / {security_summary['running']} ran / {security_summary['filtered']} filtered"
            )
            if not tests_pass:
                failure_excerpt = select_failure_excerpt(
                    unit_output if not unit_ok else "",
                    security_output if not security_ok else "",
                )
                if failure_excerpt:
                    details = (
                        f"{details}; rc=({unit_summary['returncode']}, {security_summary['returncode']}); "
                        f"{failure_excerpt}"
                    )
            all_pass &= check(
                "PG-TESTS",
                "Rust provenance gate unit and security tests pass",
                tests_pass,
                details,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            all_pass &= check(
                "PG-TESTS",
                "Rust provenance gate unit and security tests pass",
                False,
                str(e),
            )
    else:
        record_check(
            "PG-TESTS",
            "Rust provenance gate unit and security tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-PROV" in spec_content
        has_gate = "GateDecision" in spec_content or "GateFailure" in spec_content
    else:
        has_invariants = has_gate = False
    all_pass &= check("PG-SPEC", "Specification with invariants and gate types",
                       spec_exists and has_invariants and has_gate)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    failing = sum(1 for c in CHECKS if c["status"] == "FAIL")
    skipped = sum(1 for c in CHECKS if c["status"] == "SKIP")
    total = len(CHECKS)
    if EMIT_HUMAN:
        print(f"\nResult: {passing}/{total} checks passed ({skipped} skipped)")

    evidence = {
        "gate": "provenance_gate_verification",
        "bead": "bd-3i9o",
        "section": "10.13",
        "mode": "full" if run_tests else "structural",
        "verdict": "PASS" if failing == 0 else "FAIL",
        "checks": CHECKS,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": failing,
            "skipped_checks": skipped,
        },
    }

    if write_artifact:
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(evidence, indent=2))

    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
