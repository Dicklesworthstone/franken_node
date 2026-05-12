#!/usr/bin/env python3
"""Named verification gate for bd-2yc.1 operator copilot coverage."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_copilot_api as core_checker  # noqa: E402
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

COMPLETION_BEAD_ID = "bd-2yc.1"
PARENT_BEAD_ID = "bd-2yc"
SECTION = "10.5"
TITLE = "Operator Copilot Action Recommendation API named gate"

OPERATOR_CHECKER_PATH = ROOT / "scripts" / "check_operator_copilot.py"
OPERATOR_TEST_PATH = ROOT / "tests" / "test_check_operator_copilot.py"
CORE_CHECKER_PATH = ROOT / "scripts" / "check_copilot_api.py"
CORE_TEST_PATH = ROOT / "tests" / "test_check_copilot_api.py"

REQUIRED_CORE_CHECKS = [
    "spec_invariants",
    "rust_symbols",
    "event_codes",
    "loss_dimensions",
    "engine_methods",
    "tests",
    "mod_registration",
    "voi_formula",
    "degraded_integration",
]

REQUIRED_SELF_BINDINGS = [
    COMPLETION_BEAD_ID,
    PARENT_BEAD_ID,
    "check_copilot_api",
    "run_all_checks",
]


def _check(name: str, passed: bool, detail: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "passed": passed,
        "detail": detail,
    }
    result.update(extra)
    return result


def check_required_files() -> list[dict[str, Any]]:
    required = {
        "operator_checker": OPERATOR_CHECKER_PATH,
        "operator_checker_tests": OPERATOR_TEST_PATH,
        "core_checker": CORE_CHECKER_PATH,
        "core_checker_tests": CORE_TEST_PATH,
        "spec": core_checker.SPEC_PATH,
        "rust_impl": core_checker.RUST_IMPL_PATH,
        "security_mod": core_checker.MOD_PATH,
    }

    checks: list[dict[str, Any]] = []
    for name, path in required.items():
        exists = path.exists()
        detail = f"{path.relative_to(ROOT)} exists" if exists else f"{path.relative_to(ROOT)} missing"
        checks.append(
            _check(
                f"file:{name}",
                exists,
                detail,
                path=str(path.relative_to(ROOT)),
                size_bytes=path.stat().st_size if exists else 0,
            )
        )
    return checks


def check_self_binding() -> list[dict[str, Any]]:
    if not OPERATOR_CHECKER_PATH.exists():
        return [_check("operator_checker_bindings", False, "operator checker missing")]

    content = OPERATOR_CHECKER_PATH.read_text(encoding="utf-8")
    found = [item for item in REQUIRED_SELF_BINDINGS if item in content]
    missing = [item for item in REQUIRED_SELF_BINDINGS if item not in content]
    return [
        _check(
            "operator_checker_bindings",
            not missing,
            "named checker binds bd-2yc.1 to the bd-2yc core gate"
            if not missing
            else f"missing bindings: {', '.join(missing)}",
            found=found,
            missing=missing,
        )
    ]


def check_core_gate() -> list[dict[str, Any]]:
    evidence = core_checker.run_all_checks()
    summary = evidence.get("summary", {})
    checks: list[dict[str, Any]] = [
        _check(
            "core_gate:bead_id",
            evidence.get("bead_id") == PARENT_BEAD_ID,
            f"core gate bead_id={evidence.get('bead_id')!r}",
        ),
        _check(
            "core_gate:overall_pass",
            bool(evidence.get("overall_pass")),
            "core operator copilot gate passes"
            if evidence.get("overall_pass")
            else "core operator copilot gate fails",
        ),
        _check(
            "core_gate:summary_counts",
            summary.get("passed") == summary.get("total_checks") and summary.get("total_checks", 0) >= 10,
            f"{summary.get('passed', 0)}/{summary.get('total_checks', 0)} core checks passed",
        ),
    ]

    core_checks = evidence.get("checks", {})
    for name in REQUIRED_CORE_CHECKS:
        result = core_checks.get(name)
        passed = bool(result and result.get("pass"))
        checks.append(
            _check(
                f"core_check:{name}",
                passed,
                f"{name} passes" if passed else f"{name} missing or failing",
                missing=result.get("missing", []) if isinstance(result, dict) else [],
            )
        )

    files = core_checks.get("files", {})
    file_pass = isinstance(files, dict) and all(info.get("exists") for info in files.values())
    checks.append(
        _check(
            "core_check:files",
            file_pass,
            "core spec, Rust implementation, and module file exist"
            if file_pass
            else "one or more core files are missing",
        )
    )
    return checks


def run_all_checks() -> dict[str, Any]:
    checks = [
        *check_required_files(),
        *check_self_binding(),
        *check_core_gate(),
    ]
    passed = sum(1 for check in checks if check["passed"])
    total = len(checks)
    failed = total - passed
    return {
        "bead_id": COMPLETION_BEAD_ID,
        "parent_bead_id": PARENT_BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_pass": failed == 0,
        "checks": checks,
        "summary": {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
        },
    }


def self_test() -> bool:
    evidence = run_all_checks()
    required = {
        "file:operator_checker",
        "file:operator_checker_tests",
        "core_gate:overall_pass",
    }
    observed = {check["name"] for check in evidence["checks"]}
    if evidence["bead_id"] != COMPLETION_BEAD_ID:
        raise AssertionError(f"unexpected bead_id: {evidence['bead_id']!r}")
    if evidence["parent_bead_id"] != PARENT_BEAD_ID:
        raise AssertionError(f"unexpected parent_bead_id: {evidence['parent_bead_id']!r}")
    if evidence["summary"]["total_checks"] < 20:
        raise AssertionError("expected at least 20 completion checks")
    missing = sorted(required - observed)
    if missing:
        raise AssertionError(f"missing expected checks: {missing}")
    for check in evidence["checks"]:
        if not isinstance(check["name"], str):
            raise AssertionError(f"check name is not a string: {check!r}")
        if not isinstance(check["passed"], bool):
            raise AssertionError(f"check passed flag is not boolean: {check!r}")
        if not isinstance(check["detail"], str):
            raise AssertionError(f"check detail is not a string: {check!r}")
    return True


def main() -> None:
    logger = configure_test_logging("check_operator_copilot")
    parser = argparse.ArgumentParser(description="Verify bd-2yc.1 operator copilot named gate")
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        logger.info("self_test passed")
        print("self_test passed")
        return

    evidence = run_all_checks()

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        summary = evidence["summary"]
        status = "PASS" if evidence["overall_pass"] else "FAIL"
        print(
            f"{COMPLETION_BEAD_ID} operator copilot gate: "
            f"{status} ({summary['passed']}/{summary['total_checks']} checks passed)"
        )
        for check in evidence["checks"]:
            marker = "+" if check["passed"] else "-"
            print(f"  [{marker}] {check['name']}: {check['detail']}")

    if not evidence["overall_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
