#!/usr/bin/env python3
"""bd-383z verification gate for counterfactual incident lab and mitigation synthesis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-383z"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/section_10_17/bd-383z_contract.md"
IMPL_FILE = ROOT / "crates/franken-node/src/runtime/incident_lab.rs"
RUNTIME_MOD_FILE = ROOT / "crates/franken-node/src/runtime/mod.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_incident_lab.py"
REPORT_FILE = ROOT / "artifacts/10.17/counterfactual_eval_report.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-383z/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-383z/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "ILAB_001",
    "ILAB_002",
    "ILAB_003",
    "ILAB_004",
    "ILAB_005",
    "ILAB_006",
]

REQUIRED_ERROR_CODES = [
    "ERR_ILAB_TRACE_EMPTY",
    "ERR_ILAB_TRACE_CORRUPT",
    "ERR_ILAB_REPLAY_DIVERGENCE",
    "ERR_ILAB_MITIGATION_INVALID",
    "ERR_ILAB_DELTA_NEGATIVE",
    "ERR_ILAB_CONTRACT_UNSIGNED",
]

REQUIRED_INVARIANTS = [
    "INV-ILAB-DETERMINISTIC",
    "INV-ILAB-DELTA-REQUIRED",
    "INV-ILAB-SIGNED-ROLLOUT",
    "INV-ILAB-ROLLBACK-ATTACHED",
    "INV-ILAB-TRACE-INTEGRITY",
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
    spec_src = _read(SPEC_FILE)
    runtime_mod_src = _read(RUNTIME_MOD_FILE)

    # --- File existence ---
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(
        _check(
            "Runtime module wired",
            "pub mod incident_lab;" in runtime_mod_src,
            "pub mod incident_lab; in runtime/mod.rs",
        )
    )

    # --- Required impl tokens ---
    required_impl_tokens = [
        "struct IncidentTrace",
        "struct CounterfactualScenario",
        "struct MitigationPlan",
        "struct IncidentReplay",
        "struct SynthesisResult",
        "struct RolloutContract",
        "struct RollbackClause",
        "struct IncidentLab",
        "struct LabConfig",
        "struct LabError",
        "fn replay_trace",
        "fn compute_delta",
        "fn generate_rollout_contract",
        "fn evaluate_scenario",
        "fn validate_trace",
        "fn validate_mitigation",
        "fn verify_deterministic_replay",
        "fn compute_trace_hash",
        "BTreeMap",
        "SCHEMA_VERSION",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # --- Event codes ---
    for code in REQUIRED_EVENT_CODES:
        checks.append(
            _check(
                f"Event code {code}",
                code in impl_src and code in spec_src,
                code,
            )
        )

    # --- Error codes ---
    for code in REQUIRED_ERROR_CODES:
        checks.append(
            _check(
                f"Error code {code}",
                code in impl_src and code in spec_src,
                code,
            )
        )

    # --- Invariants ---
    for inv in REQUIRED_INVARIANTS:
        checks.append(
            _check(
                f"Invariant {inv}",
                inv in impl_src and inv in spec_src,
                inv,
            )
        )

    # --- Test count ---
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 20", test_count >= 20, f"found {test_count}"))

    # --- Python test file ---
    checks.append(
        _check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE))
    )

    # --- Evidence / summary ---
    checks.append(
        _check("Verification evidence exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE))
    )
    checks.append(
        _check("Verification summary exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE))
    )

    # --- Evidence verdict ---
    if EVIDENCE_FILE.exists():
        try:
            evidence = json.loads(_read(EVIDENCE_FILE))
            checks.append(
                _check(
                    "Evidence verdict is PASS",
                    evidence.get("verdict") == "PASS",
                    evidence.get("verdict", "MISSING"),
                )
            )
        except json.JSONDecodeError:
            checks.append(_check("Evidence JSON valid", False, "JSON parse error"))
    else:
        checks.append(_check("Evidence verdict is PASS", False, "file missing"))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "incident-lab-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Counterfactual incident lab and mitigation synthesis",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
    }


def write_report(result: dict) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks = []
    checks.append(_check("event code count >= 6", len(REQUIRED_EVENT_CODES) >= 6))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("invariant count >= 5", len(REQUIRED_INVARIANTS) >= 5))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 20))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_incident_lab",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="bd-383z checker")
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
        print(f"bd-383z: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
