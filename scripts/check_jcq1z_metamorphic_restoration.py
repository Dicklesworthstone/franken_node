#!/usr/bin/env python3
"""Guard bd-jcq1z legacy test restoration debt.

bd-jcq1z closed by quarantining unported real-service/metamorphic test drafts
after they caused a large compile failure. This checker keeps that quarantine
truthful: the files must stay source-only and excluded from live-code scanning
until bd-jcq1z.2 ports or replaces them with registered, passing Cargo targets.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
CARGO_TOML = ROOT / "crates/franken-node/Cargo.toml"
BEADS_JSONL = ROOT / ".beads/issues.jsonl"
UBSIGNORE = ROOT / ".ubsignore"

PARENT_BEAD = "bd-jcq1z"
COMPLETION_BEAD = "bd-jcq1z.1"
RESTORATION_BEAD = "bd-jcq1z.2"
RESTORATION_TITLE_FRAGMENT = "Restore and port bd-jcq1z quarantined real-service/metamorphic tests"
ACTIONABLE_STATUSES = {"open", "in_progress", "deferred", "blocked"}

LEGACY_TEST_FILES = (
    "crates/franken-node/tests/api_session_auth_real_service_integration.rs",
    "crates/franken-node/tests/connector_lifecycle_real_service_integration.rs",
    "crates/franken-node/tests/integration_api_session_auth_real_service.rs",
    "crates/franken-node/tests/integration_connector_lifecycle_stress.rs",
    "crates/franken-node/tests/integration_remote_capability_real_enforcement.rs",
    "crates/franken-node/tests/integration_vef_receipt_chain_real_service.rs",
    "crates/franken-node/tests/vef_receipt_real_service_integration.rs",
)

REPLACEMENT_BEADS = (
    {
        "id": "bd-jcq1z.2.1",
        "title_fragment": "Port session-auth real-service integration coverage",
        "legacy_files": (
            "crates/franken-node/tests/api_session_auth_real_service_integration.rs",
            "crates/franken-node/tests/integration_api_session_auth_real_service.rs",
        ),
    },
    {
        "id": "bd-jcq1z.2.2",
        "title_fragment": "Port connector lifecycle and stress integration coverage",
        "legacy_files": (
            "crates/franken-node/tests/connector_lifecycle_real_service_integration.rs",
            "crates/franken-node/tests/integration_connector_lifecycle_stress.rs",
        ),
    },
    {
        "id": "bd-jcq1z.2.3",
        "title_fragment": "Port remote capability real-enforcement coverage",
        "legacy_files": (
            "crates/franken-node/tests/integration_remote_capability_real_enforcement.rs",
        ),
    },
    {
        "id": "bd-jcq1z.2.4",
        "title_fragment": "Port VEF receipt-chain real-service coverage",
        "legacy_files": (
            "crates/franken-node/tests/integration_vef_receipt_chain_real_service.rs",
            "crates/franken-node/tests/vef_receipt_real_service_integration.rs",
        ),
    },
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _check(check_id: str, passed: bool, detail: str) -> dict[str, object]:
    return {
        "check_id": check_id,
        "pass": passed,
        "detail": detail,
    }


def _crate_test_path(rel_path: str) -> str:
    prefix = "crates/franken-node/"
    if not rel_path.startswith(prefix):
        raise ValueError(f"legacy test path must be crate-local: {rel_path}")
    return rel_path[len(prefix):]


def _cargo_registers_path(cargo_toml: str, rel_path: str) -> bool:
    crate_path = _crate_test_path(rel_path)
    return f'path = "{crate_path}"' in cargo_toml


def _dependency_ids(bead: dict[str, object]) -> set[str]:
    deps = bead.get("dependencies", [])
    return {
        str(dep.get("depends_on_id"))
        for dep in deps
        if isinstance(dep, dict)
    }


def load_beads(root: Path = ROOT) -> list[dict[str, object]]:
    beads: list[dict[str, object]] = []
    for line in _read(root / ".beads/issues.jsonl").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)  # ubs:ignore - JSONDecodeError is caught below.
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            beads.append(payload)
    return beads


def check_replacement_beads(
    beads: dict[str, dict[str, object]],
    *,
    required: bool,
) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    covered_files: set[str] = set()

    for spec in REPLACEMENT_BEADS:
        bead_id = str(spec["id"])
        legacy_files = tuple(str(path) for path in spec["legacy_files"])
        covered_files.update(legacy_files)
        bead = beads.get(bead_id)
        checks.append(_check(
            f"replacement bead exists: {bead_id}",
            bead is not None or not required,
            bead_id if bead is not None else "missing",
        ))
        if bead is None:
            continue

        title = str(bead.get("title", ""))
        status = str(bead.get("status", ""))
        description = str(bead.get("description", ""))
        parent_ids = _dependency_ids(bead)
        checks.append(_check(
            f"replacement bead tracks scope: {bead_id}",
            str(spec["title_fragment"]) in title,
            title,
        ))
        checks.append(_check(
            f"replacement bead remains actionable: {bead_id}",
            status in ACTIONABLE_STATUSES,
            status,
        ))
        checks.append(_check(
            f"replacement bead depends on restoration split: {bead_id}",
            RESTORATION_BEAD in parent_ids,
            f"parents={sorted(parent_ids)}",
        ))
        for rel_path in legacy_files:
            checks.append(_check(
                f"replacement bead covers legacy file: {bead_id}: {rel_path}",
                rel_path in description,
                rel_path,
            ))

    expected_files = set(LEGACY_TEST_FILES)
    checks.append(_check(
        "replacement split covers all legacy files",
        covered_files == expected_files,
        f"covered={len(covered_files)} expected={len(expected_files)}",
    ))
    return checks


def check_follow_up_bead(root: Path = ROOT) -> list[dict[str, object]]:
    beads = {str(bead.get("id")): bead for bead in load_beads(root)}
    bead = beads.get(RESTORATION_BEAD)
    checks: list[dict[str, object]] = []

    checks.append(_check(
        "follow-up bead exists",
        bead is not None,
        RESTORATION_BEAD if bead is not None else f"missing {RESTORATION_BEAD}",
    ))
    if bead is None:
        return checks

    title = str(bead.get("title", ""))
    status = str(bead.get("status", ""))
    parent_ids = _dependency_ids(bead)
    replacement_checks = check_replacement_beads(beads, required=status == "closed")
    replacement_split_valid = all(bool(check["pass"]) for check in replacement_checks)
    checks.append(_check(
        "follow-up bead tracks restoration",
        RESTORATION_TITLE_FRAGMENT in title,
        title,
    ))
    checks.append(_check(
        "follow-up bead remains actionable or was split into replacement beads",
        status in ACTIONABLE_STATUSES or (status == "closed" and replacement_split_valid),
        f"status={status}",
    ))
    checks.append(_check(
        "follow-up bead depends on original",
        PARENT_BEAD in parent_ids,
        f"parents={sorted(parent_ids)}",
    ))
    if status == "closed":
        checks.extend(replacement_checks)
    return checks


def check_legacy_test_quarantine(root: Path = ROOT) -> list[dict[str, object]]:
    cargo_toml = _read(root / "crates/franken-node/Cargo.toml")
    ubsignore_entries = {
        line.strip()
        for line in _read(root / ".ubsignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    checks: list[dict[str, object]] = [
        _check(
            "crate disables automatic test discovery",
            "autotests = false" in cargo_toml,
            "autotests=false prevents source-only drafts from compiling implicitly",
        )
    ]

    for rel_path in LEGACY_TEST_FILES:
        path = root / rel_path
        checks.append(_check(
            f"legacy test exists: {rel_path}",
            path.exists(),
            rel_path,
        ))
        checks.append(_check(
            f"legacy test not registered in Cargo: {rel_path}",
            not _cargo_registers_path(cargo_toml, rel_path),
            _crate_test_path(rel_path),
        ))
        checks.append(_check(
            f"legacy test excluded from UBS live-code scan: {rel_path}",
            rel_path in ubsignore_entries,
            ".ubsignore exact quarantine entry",
        ))

    return checks


def run_checks(root: Path = ROOT) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    checks.extend(check_follow_up_bead(root))
    checks.extend(check_legacy_test_quarantine(root))
    passed = sum(1 for check in checks if check["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": PARENT_BEAD,
        "completion_bead_id": COMPLETION_BEAD,
        "restoration_bead_id": RESTORATION_BEAD,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "legacy_test_files": list(LEGACY_TEST_FILES),
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    logger = configure_test_logging("check_jcq1z_metamorphic_restoration")
    logger.info("starting %s verification", "check_jcq1z_metamorphic_restoration")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    result = run_checks()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"bd-jcq1z restoration guard: {result['verdict']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check_id']}: {check['detail']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
