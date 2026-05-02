#!/usr/bin/env python3
"""
Verifier for bd-aoq6 (BPET migration stability gate).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


REQUIRED_FILES = [
    "crates/franken-node/src/migration/mod.rs",
    "crates/franken-node/src/migration/bpet_migration_gate.rs",
    "tests/integration/bpet_migration_stability_gate.rs",
    "crates/franken-node/tests/bpet_migration_stability_gate.rs",
    "artifacts/10.21/bpet_migration_gate_results.json",
]

REQUIRED_EVENT_CODES = [
    "BPET-MIGRATE-001",
    "BPET-MIGRATE-002",
    "BPET-MIGRATE-003",
    "BPET-MIGRATE-004",
    "BPET-MIGRATE-005",
    "BPET-MIGRATE-006",
    "BPET-MIGRATE-007",
]

REQUIRED_SYMBOLS = [
    "pub fn evaluate_admission",
    "pub fn evaluate_rollout_health",
    "pub fn build_migration_report",
]

ALLOWED_VERDICTS = {"allow", "require_additional_evidence", "staged_rollout_required"}


def _check(condition: bool, check_id: str, detail: str = "") -> dict:
    return {
        "id": check_id,
        "status": "PASS" if condition else "FAIL",
        "detail": detail,
    }


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def check_required_files(root: Path) -> list[dict]:
    checks = []
    for rel in REQUIRED_FILES:
        path = root / rel
        checks.append(_check(path.exists(), f"BDAOQ6-FILE-{rel}", str(path)))
    return checks


def check_rust_contract(root: Path) -> list[dict]:
    gate_path = root / "crates/franken-node/src/migration/bpet_migration_gate.rs"
    if not gate_path.exists():
        return [
            _check(
                False,
                "BDAOQ6-RUST-FILE",
                "missing crates/franken-node/src/migration/bpet_migration_gate.rs",
            )
        ]

    text = gate_path.read_text(encoding="utf-8")
    checks = []
    for symbol in REQUIRED_SYMBOLS:
        checks.append(
            _check(
                symbol in text,
                f"BDAOQ6-RUST-SYMBOL-{symbol}",
                "required API symbol present",
            )
        )
    for code in REQUIRED_EVENT_CODES:
        checks.append(
            _check(
                code in text,
                f"BDAOQ6-RUST-EVENT-{code}",
                "required event code present",
            )
        )
    return checks


def check_report(root: Path) -> list[dict]:
    report_path = root / "artifacts/10.21/bpet_migration_gate_results.json"
    if not report_path.exists():
        return [_check(False, "BDAOQ6-REPORT-EXISTS", str(report_path))]

    try:
        report = json.JSONDecoder().decode(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [_check(False, "BDAOQ6-REPORT-JSON", f"invalid json: {exc}")]

    checks = []
    checks.append(_check(isinstance(report, dict), "BDAOQ6-REPORT-OBJECT", "root object"))
    checks.append(
        _check(
            isinstance(report.get("migration_id"), str) and bool(report.get("migration_id")),
            "BDAOQ6-REPORT-MIGRATION-ID",
            "migration id set",
        )
    )

    admission = report.get("admission", {})
    checks.append(_check(isinstance(admission, dict), "BDAOQ6-ADMISSION-OBJECT", "admission object"))
    checks.append(
        _check(
            admission.get("verdict") in ALLOWED_VERDICTS,
            "BDAOQ6-ADMISSION-VERDICT",
            "valid verdict",
        )
    )

    for section, keys in (
        ("baseline", ("instability_score", "drift_score", "regime_shift_probability")),
        ("projected", ("instability_score", "drift_score", "regime_shift_probability")),
        ("delta", ("instability_delta", "drift_delta", "regime_shift_delta")),
    ):
        data = admission.get(section, {})
        for key in keys:
            checks.append(
                _check(
                    _is_number(data.get(key)),
                    f"BDAOQ6-{section.upper()}-{key}",
                    f"{section}.{key} numeric",
                )
            )

    thresholds = admission.get("thresholds", {})
    for key in (
        "max_instability_delta_for_direct_admit",
        "max_drift_score_for_direct_admit",
        "max_regime_shift_probability_for_direct_admit",
        "max_instability_score_for_staged_rollout",
        "max_regime_shift_probability_for_staged_rollout",
    ):
        checks.append(
            _check(
                _is_number(thresholds.get(key)),
                f"BDAOQ6-THRESHOLD-{key}",
                "threshold value present",
            )
        )

    events = admission.get("events", [])
    checks.append(
        _check(
            isinstance(events, list) and len(events) >= 2,
            "BDAOQ6-EVENTS",
            "events present",
        )
    )
    event_codes = {e.get("code") for e in events if isinstance(e, dict)}
    checks.append(
        _check("BPET-MIGRATE-001" in event_codes, "BDAOQ6-EVENT-BASELINE", "baseline event present")
    )

    verdict = admission.get("verdict")
    staged = admission.get("staged_rollout")
    if verdict == "staged_rollout_required":
        checks.append(
            _check(isinstance(staged, dict), "BDAOQ6-STAGED-ROLLOUT", "staged rollout included")
        )
        fallback = (staged or {}).get("fallback", {})
        checks.append(
            _check(
                isinstance(fallback.get("rollback_to_version"), str) and bool(fallback.get("rollback_to_version")),
                "BDAOQ6-FALLBACK-TARGET",
                "rollback target present",
            )
        )
    else:
        checks.append(_check(True, "BDAOQ6-STAGED-ROLLOUT", "not required for this verdict"))
        checks.append(_check(True, "BDAOQ6-FALLBACK-TARGET", "not required for this verdict"))

    return checks


def run_checks(root: Path = ROOT) -> dict:
    checks = []
    checks.extend(check_required_files(root))
    checks.extend(check_rust_contract(root))
    checks.extend(check_report(root))

    failing = [check for check in checks if check["status"] == "FAIL"]
    return {
        "bead_id": "bd-aoq6",
        "gate": "bpet_migration_stability_gate_verification",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": "PASS" if not failing else "FAIL",
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
        "checks": checks,
    }


def self_test() -> dict:
    import tempfile

    checks = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel in REQUIRED_FILES:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if rel.endswith(".json"):
                path.write_text(
                    json.dumps(
                        {
                            "migration_id": "mig-self-test",
                            "admission": {
                                "verdict": "staged_rollout_required",
                                "baseline": {
                                    "instability_score": 0.2,
                                    "drift_score": 0.1,
                                    "regime_shift_probability": 0.1,
                                },
                                "projected": {
                                    "instability_score": 0.7,
                                    "drift_score": 0.4,
                                    "regime_shift_probability": 0.6,
                                },
                                "delta": {
                                    "instability_delta": 0.5,
                                    "drift_delta": 0.3,
                                    "regime_shift_delta": 0.5,
                                },
                                "thresholds": {
                                    "max_instability_delta_for_direct_admit": 0.08,
                                    "max_drift_score_for_direct_admit": 0.30,
                                    "max_regime_shift_probability_for_direct_admit": 0.22,
                                    "max_instability_score_for_staged_rollout": 0.62,
                                    "max_regime_shift_probability_for_staged_rollout": 0.45,
                                },
                                "additional_evidence_required": ["bpet.calibration_report"],
                                "staged_rollout": {
                                    "steps": [],
                                    "fallback": {
                                        "rollback_to_version": "v1-previous",
                                        "quarantine_window_minutes": 90,
                                        "required_artifacts": []
                                    }
                                },
                                "events": [
                                    {"code": "BPET-MIGRATE-001"},
                                    {"code": "BPET-MIGRATE-004"}
                                ]
                            }
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            elif rel.endswith("bpet_migration_gate.rs"):
                path.write_text(
                    "\n".join(REQUIRED_SYMBOLS + REQUIRED_EVENT_CODES),
                    encoding="utf-8",
                )
            else:
                path.write_text("ok", encoding="utf-8")

        result = run_checks(root)
        checks.append(_check(result["verdict"] == "PASS", "BDAOQ6-SELFTEST-PASS", "pass case"))

        bad = root / "artifacts/10.21/bpet_migration_gate_results.json"
        bad.write_text("{}", encoding="utf-8")
        result2 = run_checks(root)
        checks.append(_check(result2["verdict"] == "FAIL", "BDAOQ6-SELFTEST-FAIL-DETECT", "detect malformed report"))

    failing = [check for check in checks if check["status"] == "FAIL"]
    return {
        "gate": "bpet_migration_stability_gate_self_test",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": "PASS" if not failing else "FAIL",
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
        "checks": checks,
    }


def main() -> int:
    from scripts.lib.test_logger import configure_test_logging

    configure_test_logging("check_bpet_migration_gate")
    json_output = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv
    result = self_test() if run_self_test else run_checks()

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Verifier: {result['gate']}")
        for check in result["checks"]:
            marker = "OK" if check["status"] == "PASS" else "FAIL"
            print(f"  [{marker}] {check['id']}")
        print(f"\nVerdict: {result['verdict']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
