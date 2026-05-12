#!/usr/bin/env python3
"""
Repository Split Contract CI Enforcement.

Verifies that franken_node correctly consumes engine crates from
/dp/franken_engine and does not reintroduce local engine crate copies.

Usage:
    python3 scripts/check_split_contract.py [--json]

Exit codes:
    0 = PASS (all checks pass)
    1 = FAIL (one or more violations)
    2 = ERROR (script failure)
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPT_ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT_ENV_VAR = "FRANKEN_NODE_SPLIT_CONTRACT_ROOT"
ROOT = Path(os.environ.get(ROOT_ENV_VAR, SCRIPT_ROOT)).resolve()
REPORT_SCHEMA_VERSION = "franken-node/split-contract-report/v1"
TELEMETRY_SCHEMA_VERSION = "franken-node/split-contract-telemetry/v1"
MIGRATION_POLICY_SCHEMA_VERSION = "franken-node/split-contract-migration-policy/v1"
TELEMETRY_NAMESPACE = "franken_node.section_10_1.split_contract"
GATE_PASSED_EVENT = "SPLIT_CONTRACT_GATE_PASSED"
GATE_FAILED_EVENT = "SPLIT_CONTRACT_GATE_FAILED"
CHECK_PASSED_EVENT = "SPLIT_CONTRACT_CHECK_PASSED"
CHECK_FAILED_EVENT = "SPLIT_CONTRACT_CHECK_FAILED"


# Directories that must NOT exist (local engine crate reintroduction)
FORBIDDEN_DIRS = [
    ROOT / "crates" / "franken-engine",
    ROOT / "crates" / "franken-extension-host",
]

# Required governance documents
REQUIRED_DOCS = [
    ROOT / "docs" / "ENGINE_SPLIT_CONTRACT.md",
    ROOT / "docs" / "PRODUCT_CHARTER.md",
]

# Expected engine path prefix in Cargo.toml dependencies
ENGINE_PATH_PREFIX = "../../../franken_engine/crates/"

# Engine crate names to check
ENGINE_CRATE_NAMES = [
    "frankenengine-engine",
    "frankenengine-extension-host",
]

# Keywords that must appear in ENGINE_SPLIT_CONTRACT.md
SPLIT_CONTRACT_KEYWORDS = [
    "franken_engine",
    "MUST NOT",
    "path dependencies",
]


def build_telemetry(checks: list[dict], verdict: str, timestamp: str) -> dict:
    """Build stable telemetry events for CI/audit consumers."""
    events = []
    for check in checks:
        status = check["status"]
        events.append({
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "namespace": TELEMETRY_NAMESPACE,
            "event_code": CHECK_PASSED_EVENT if status == "PASS" else CHECK_FAILED_EVENT,
            "gate": "split_contract_enforcement",
            "section": "10.1",
            "check_id": check["id"],
            "status": status,
            "timestamp": timestamp,
            "fail_closed": status != "PASS",
        })

    events.append({
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "namespace": TELEMETRY_NAMESPACE,
        "event_code": GATE_PASSED_EVENT if verdict == "PASS" else GATE_FAILED_EVENT,
        "gate": "split_contract_enforcement",
        "section": "10.1",
        "check_id": "SPLIT-CONTRACT-GATE",
        "status": verdict,
        "timestamp": timestamp,
        "fail_closed": verdict != "PASS",
    })

    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "namespace": TELEMETRY_NAMESPACE,
        "events": events,
    }


def build_migration_policy() -> dict:
    """Describe the only allowed engine-split migration path."""
    return {
        "schema_version": MIGRATION_POLICY_SCHEMA_VERSION,
        "policy_id": "SPLIT-CONTRACT-MIGRATION-POLICY",
        "source_repository": "franken_node",
        "engine_repository": "franken_engine",
        "allowed_engine_path_prefixes": [
            ENGINE_PATH_PREFIX,
            "franken_engine/crates/",
        ],
        "forbidden_local_engine_crate_paths": [
            str(path.relative_to(ROOT)) for path in FORBIDDEN_DIRS
        ],
        "required_governance_documents": [
            str(path.relative_to(ROOT)) for path in REQUIRED_DOCS
        ],
        "boundary_change_rule": (
            "Any migration that changes engine crate ownership or dependency paths "
            "must update docs/ENGINE_SPLIT_CONTRACT.md and pass this gate."
        ),
        "violation_action": "block_merge",
        "fail_closed": True,
    }


def check_no_local_engine_crates() -> dict:
    """Verify no local engine crate directories exist."""
    result = {"id": "SPLIT-NO-LOCAL", "status": "PASS", "details": {}}
    violations = []
    for d in FORBIDDEN_DIRS:
        if d.exists():
            violations.append(str(d.relative_to(ROOT)))
    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Remove local engine crate directories. Engine crates must "
            "come from /dp/franken_engine via path dependencies."
        )
    else:
        result["details"]["checked"] = [str(d.relative_to(ROOT)) for d in FORBIDDEN_DIRS]
    return result


def check_engine_path_deps() -> dict:
    """Verify engine dependencies use correct path references."""
    result = {"id": "SPLIT-PATH-DEPS", "status": "PASS", "details": {"cargo_files": []}}

    cargo_files = list(ROOT.rglob("Cargo.toml"))
    # Exclude target/ and .beads/
    cargo_files = [
        f for f in cargo_files
        if "target" not in f.parts and ".beads" not in f.parts
    ]

    for cargo_file in cargo_files:
        try:
            content = cargo_file.read_text()
        except Exception as e:
            result["status"] = "FAIL"
            result["details"]["error"] = f"Cannot read {cargo_file}: {e}"
            return result

        file_info = {"path": str(cargo_file.relative_to(ROOT)), "engine_deps": []}

        for crate_name in ENGINE_CRATE_NAMES:
            # Match patterns like: frankenengine-engine = { path = "..." }
            pattern = rf'{re.escape(crate_name)}\s*=\s*\{{[^}}]*path\s*=\s*"([^"]*)"'
            matches = re.findall(pattern, content)
            for match_path in matches:
                dep_info = {"crate": crate_name, "path": match_path}
                if ENGINE_PATH_PREFIX not in match_path and "franken_engine/crates/" not in match_path:
                    dep_info["valid"] = False
                    dep_info["remediation"] = (
                        f"Path should reference {ENGINE_PATH_PREFIX}{crate_name.replace('frankenengine-', 'franken-')}"
                    )
                    result["status"] = "FAIL"
                else:
                    dep_info["valid"] = True
                file_info["engine_deps"].append(dep_info)

        if file_info["engine_deps"]:
            result["details"]["cargo_files"].append(file_info)

    return result


def check_no_engine_internal_imports() -> dict:
    """Verify no Rust source files import engine-internal modules."""
    result = {"id": "SPLIT-NO-INTERNALS", "status": "PASS", "details": {"files_scanned": 0}}

    # Patterns that suggest direct engine-internal access
    internal_patterns = [
        r'^\s*use\s+frankenengine_engine::internal\b',
        r'^\s*use\s+frankenengine_extension_host::internal\b',
        r'^\s*mod\s+franken_engine\s*;',
        r'^\s*mod\s+franken_extension_host\s*;',
    ]

    violations = []
    rs_files = list((ROOT / "crates").rglob("*.rs")) if (ROOT / "crates").exists() else []
    # Also check src/ if it exists
    if (ROOT / "src").exists():
        rs_files.extend((ROOT / "src").rglob("*.rs"))

    result["details"]["files_scanned"] = len(rs_files)

    for rs_file in rs_files:
        try:
            content = rs_file.read_text()
        except Exception:
            continue
        for pattern in internal_patterns:
            if re.search(pattern, content, re.MULTILINE):
                violations.append({
                    "file": str(rs_file.relative_to(ROOT)),
                    "pattern": pattern,
                })

    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Remove direct engine-internal imports. Use only the public API surface."
        )

    return result


def check_governance_docs() -> dict:
    """Verify required governance documents exist with expected content."""
    result = {"id": "SPLIT-GOVERNANCE", "status": "PASS", "details": {"docs": []}}

    for doc_path in REQUIRED_DOCS:
        doc_info = {"path": str(doc_path.relative_to(ROOT)), "exists": doc_path.exists()}
        if not doc_path.exists():
            result["status"] = "FAIL"
            doc_info["error"] = "File not found"
        result["details"]["docs"].append(doc_info)

    # Verify split contract has required keywords
    split_path = ROOT / "docs" / "ENGINE_SPLIT_CONTRACT.md"
    if split_path.exists():
        content = split_path.read_text()
        missing_keywords = []
        for kw in SPLIT_CONTRACT_KEYWORDS:
            if kw.lower() not in content.lower():
                missing_keywords.append(kw)
        if missing_keywords:
            result["status"] = "FAIL"
            result["details"]["missing_keywords"] = missing_keywords

    return result


def main():
    logger = configure_test_logging("check_split_contract")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_no_local_engine_crates(),
        check_engine_path_deps(),
        check_no_engine_internal_imports(),
        check_governance_docs(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "gate": "split_contract_enforcement",
        "section": "10.1",
        "verdict": verdict,
        "timestamp": timestamp,
        "scan_root": str(ROOT),
        "checks": checks,
        "telemetry": build_telemetry(checks, verdict, timestamp),
        "migration_policy": build_migration_policy(),
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Repository Split Contract CI Enforcement ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "violations" in details:
                    for v in details["violations"][:5]:
                        print(f"       Violation: {v}")
                if "error" in details:
                    print(f"       Error: {details['error']}")
                if "remediation" in details:
                    print(f"       Fix: {details['remediation']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
