#!/usr/bin/env python3
"""
Dependency-Direction Guard.

Prevents local engine crate reintroduction by checking workspace members,
package names, and dependency paths. This is a deeper, more targeted guard
than the general split contract check.

Usage:
    python3 scripts/guard_dependency_direction.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL (violation detected)
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Engine crate names that must NOT appear as local packages
ENGINE_PACKAGE_NAMES = {
    "frankenengine-engine",
    "frankenengine-extension-host",
    "franken-engine",
    "franken-extension-host",
}

# Directory name patterns that indicate engine crate reintroduction
ENGINE_DIR_PATTERNS = [
    "franken-engine",
    "franken_engine",
    "franken-extension-host",
    "franken_extension_host",
]

# Valid external path prefix for engine dependencies
VALID_ENGINE_PATH_PREFIXES = [
    "../../../franken_engine/",
    "/dp/franken_engine/",
]

EVIDENCE_PATHS = {
    "spec_contract": "docs/specs/section_10_1/bd-2zz_contract.md",
    "guard_script": "scripts/guard_dependency_direction.py",
    "unit_tests": "tests/test_guard_dependency_direction.py",
    "machine_evidence": "artifacts/section_10_1/bd-2zz/verification_evidence.json",
    "human_summary": "artifacts/section_10_1/bd-2zz/verification_summary.md",
}


def check_workspace_members() -> dict:
    """Verify workspace members don't include engine crate directories."""
    result = {"id": "GUARD-WS-MEMBERS", "status": "PASS", "details": {}}

    workspace_toml = ROOT / "Cargo.toml"
    if not workspace_toml.exists():
        result["details"]["note"] = "No workspace Cargo.toml found"
        return result

    content = workspace_toml.read_text(encoding="utf-8")

    # Extract members list
    members_match = re.search(r'members\s*=\s*\[(.*?)\]', content, re.DOTALL)
    if not members_match:
        result["details"]["note"] = "No workspace members found"
        return result

    members_text = members_match.group(1)
    members = re.findall(r'"([^"]*)"', members_text)
    result["details"]["members"] = members

    violations = []
    for member in members:
        member_lower = member.lower()
        for pattern in ENGINE_DIR_PATTERNS:
            if pattern in member_lower:
                violations.append({
                    "member": member,
                    "matched_pattern": pattern,
                })

    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Remove engine crate directories from workspace members. "
            "Engine crates must be consumed via path dependencies to /dp/franken_engine/."
        )

    return result


def check_local_package_names() -> dict:
    """Verify no local Cargo.toml declares an engine package name."""
    result = {"id": "GUARD-PKG-NAMES", "status": "PASS", "details": {"scanned": 0}}

    cargo_files = list(ROOT.rglob("Cargo.toml"))
    cargo_files = [
        f for f in cargo_files
        if "target" not in f.parts and ".beads" not in f.parts
    ]
    result["details"]["scanned"] = len(cargo_files)

    violations = []
    for cargo_file in cargo_files:
        try:
            content = cargo_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # Find [package] name declarations
        name_match = re.search(r'\[package\].*?name\s*=\s*"([^"]*)"', content, re.DOTALL)
        if name_match:
            pkg_name = name_match.group(1)
            if pkg_name in ENGINE_PACKAGE_NAMES:
                violations.append({
                    "file": str(cargo_file.relative_to(ROOT)),
                    "package_name": pkg_name,
                })

    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Remove local crate that declares an engine package name. "
            "This repository must not contain local engine crate implementations."
        )

    return result


def check_dependency_direction() -> dict:
    """Verify all engine-related path deps point outside this repo."""
    result = {"id": "GUARD-DEP-DIR", "status": "PASS", "details": {"deps_checked": 0}}

    cargo_files = list(ROOT.rglob("Cargo.toml"))
    cargo_files = [
        f for f in cargo_files
        if "target" not in f.parts and ".beads" not in f.parts
    ]

    violations = []
    valid_deps = []

    for cargo_file in cargo_files:
        try:
            content = cargo_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # Find all path dependencies
        # Pattern: crate-name = { path = "..." }
        for match in re.finditer(r'(\S+)\s*=\s*\{[^}]*path\s*=\s*"([^"]*)"', content):
            dep_name = match.group(1)
            dep_path = match.group(2)

            # Only check engine-related deps
            is_engine_dep = any(
                pattern in dep_name.lower() or pattern in dep_path.lower()
                for pattern in ENGINE_DIR_PATTERNS
            )

            if not is_engine_dep:
                continue

            result["details"]["deps_checked"] = result["details"].get("deps_checked", 0) + 1

            # Check path points outside this repo
            is_valid = any(dep_path.startswith(prefix) for prefix in VALID_ENGINE_PATH_PREFIXES)

            if is_valid:
                valid_deps.append({
                    "file": str(cargo_file.relative_to(ROOT)),
                    "dep": dep_name,
                    "path": dep_path,
                })
            else:
                # Check if it's a local path (within this repo)
                resolved = (cargo_file.parent / dep_path).resolve()
                if str(resolved).startswith(str(ROOT)):
                    violations.append({
                        "file": str(cargo_file.relative_to(ROOT)),
                        "dep": dep_name,
                        "path": dep_path,
                        "resolved": str(resolved),
                    })
                else:
                    valid_deps.append({
                        "file": str(cargo_file.relative_to(ROOT)),
                        "dep": dep_name,
                        "path": dep_path,
                    })

    result["details"]["valid_deps"] = valid_deps

    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Engine crate path dependencies must point to /dp/franken_engine/. "
            "Local engine crate paths are not allowed."
        )

    return result


def check_crates_dir_clean() -> dict:
    """Verify crates/ directory has no engine-named subdirectories."""
    result = {"id": "GUARD-CRATES-CLEAN", "status": "PASS", "details": {}}

    crates_dir = ROOT / "crates"
    if not crates_dir.exists():
        result["details"]["note"] = "No crates/ directory"
        return result

    violations = []
    for subdir in crates_dir.iterdir():
        if not subdir.is_dir():
            continue
        dir_name = subdir.name.lower()
        for pattern in ENGINE_DIR_PATTERNS:
            if pattern in dir_name:
                violations.append({
                    "directory": str(subdir.relative_to(ROOT)),
                    "matched_pattern": pattern,
                })

    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Remove engine crate directories from crates/. "
            "Engine crates live in /dp/franken_engine/crates/."
        )
    else:
        subdirs = [d.name for d in crates_dir.iterdir() if d.is_dir()]
        result["details"]["crates_present"] = subdirs

    return result


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_workspace_members(),
        check_local_package_names(),
        check_dependency_direction(),
        check_crates_dir_clean(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "dependency_direction_guard",
        "section": "10.1",
        "verdict": verdict,
        "timestamp": timestamp,
        "evidence_paths": EVIDENCE_PATHS,
        "verification_commands": [
            {
                "command": "python3 scripts/guard_dependency_direction.py --json",
                "covers": [
                    "workspace members",
                    "local package names",
                    "dependency path direction",
                    "crates directory cleanliness",
                ],
            },
            {
                "command": "python3 -m unittest tests.test_guard_dependency_direction",
                "covers": [
                    "guard script JSON output",
                    "guard script human output",
                    "guard evidence path citations",
                ],
            },
        ],
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Dependency-Direction Guard ===")
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
                if "remediation" in details:
                    print(f"       Fix: {details['remediation']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
