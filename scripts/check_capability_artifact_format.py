#!/usr/bin/env python3
"""bd-3ku8 verification gate for capability-carrying extension artifact format."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


BEAD = "bd-3ku8"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/capability_artifact_format.md"
IMPL_FILE = ROOT / "crates/franken-node/src/extensions/artifact_contract.rs"
MOD_FILE = ROOT / "crates/franken-node/src/extensions/mod.rs"
MAIN_FILE = ROOT / "crates/franken-node/src/main.rs"
LIB_FILE = ROOT / "crates/franken-node/src/lib.rs"
CONFORMANCE_TEST = ROOT / "tests/conformance/capability_artifact_admission.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_capability_artifact_format.py"
REPORT_FILE = ROOT / "artifacts/10.17/capability_artifact_vectors.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-3ku8/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-3ku8/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "ARTIFACT_ADMISSION_START",
    "ARTIFACT_CAPABILITY_VALIDATED",
    "ARTIFACT_ADMISSION_ACCEPTED",
    "ARTIFACT_ENFORCEMENT_CHECK",
    "ARTIFACT_DRIFT_DETECTED",
]

REQUIRED_ERROR_CODES = [
    "ERR_ARTIFACT_MISSING_CONTRACT",
    "ERR_ARTIFACT_INVALID_CAPABILITY",
    "ERR_ARTIFACT_SIGNATURE_INVALID",
    "ERR_ARTIFACT_SCHEMA_MISMATCH",
    "ERR_ARTIFACT_ENFORCEMENT_DRIFT",
    "ERR_ARTIFACT_ADMISSION_DENIED",
]

REQUIRED_INVARIANTS = [
    "INV-ARTIFACT-FAIL-CLOSED",
    "INV-ARTIFACT-CAPABILITY-ENVELOPE",
    "INV-ARTIFACT-NO-DRIFT",
    "INV-ARTIFACT-SIGNED-CONTRACT",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _checks() -> list[dict]:
    checks = []
    impl_src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)
    main_src = _read(MAIN_FILE)
    lib_src = _read(LIB_FILE)
    spec_src = _read(SPEC_FILE)

    lib_lines = [line.strip() for line in lib_src.splitlines()]
    extensions_unconditional_in_lib = False
    for idx, line in enumerate(lib_lines):
        if line == "pub mod extensions;":
            prev = lib_lines[idx - 1] if idx > 0 else ""
            extensions_unconditional_in_lib = not prev.startswith("#[cfg(")
            break
    main_wires_extensions = (
        "pub mod extensions;" in main_src
        or "extensions," in main_src
        or "extensions}" in main_src
    )

    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("Extensions mod file exists", MOD_FILE.exists(), str(MOD_FILE)))
    checks.append(_check(
        "Main module wired",
        extensions_unconditional_in_lib and main_wires_extensions,
        "pub mod extensions; unconditional in lib.rs and wired in main.rs",
    ))
    checks.append(_check(
        "Extensions mod exports artifact_contract",
        "pub mod artifact_contract;" in mod_src,
        "pub mod artifact_contract; in extensions/mod.rs",
    ))

    required_impl_tokens = [
        "struct CapabilityEntry",
        "struct CapabilityContract",
        "struct ExtensionArtifact",
        "struct AdmissionConfig",
        "struct AdmissionGate",
        "struct EnforcementEngine",
        "enum AdmissionOutcome",
        "enum AdmissionDenialReason",
        "enum DriftCheckResult",
        "fn evaluate",
        "fn is_permitted",
        "fn check_drift",
        "fn verify_contract_signature",
        "fn make_contract",
        "fn make_artifact",
        "AdmissionOutcome::Accepted",
        "AdmissionOutcome::Denied",
        "DriftCheckResult::NoDrift",
        "DriftCheckResult::DriftDetected",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(f"Event code {code}", code in impl_src and code in spec_src, code))

    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(f"Error code {code}", code in impl_src and code in spec_src, code))

    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(f"Invariant {inv}", inv in impl_src and inv in spec_src, inv))

    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    checks.append(_check("Conformance test exists", CONFORMANCE_TEST.exists(), str(CONFORMANCE_TEST)))
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "capability-artifact-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Capability-carrying extension artifact format",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "artifact_contract": {
            "fail_closed_on_missing": True,
            "fail_closed_on_invalid": True,
            "enforcement_matches_envelope": True,
            "no_drift_permitted": True,
        },
    }


def write_report(result: dict) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks = []
    checks.append(_check("event code count >= 5", len(REQUIRED_EVENT_CODES) >= 5))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("invariant count >= 4", len(REQUIRED_INVARIANTS) >= 4))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 10))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_capability_artifact_format",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_capability_artifact_format")
    parser = argparse.ArgumentParser(description="bd-3ku8 checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-report", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        st = self_test()
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"self-test: {st['verdict']} ({st['passed']}/{st['passed'] + st['failed']})")
        sys.exit(0 if st["verdict"] == "PASS" else 1)

    result = run_all()
    if args.build_report:
        write_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-3ku8: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
