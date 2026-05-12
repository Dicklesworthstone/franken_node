#!/usr/bin/env python3
"""
Migration Validation Runner.

Executes lockstep checks between Node.js and franken_node to validate
behavioral equivalence after migration.

Usage:
    python3 scripts/migration_validation_runner.py <project_dir> [--json]
    python3 scripts/migration_validation_runner.py --self-test [--json]
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = ROOT / "docs" / "specs" / "section_10_3" / "bd-2st_contract.md"

PRIMARY_IMPLEMENTATION_PATHS = {
    "migration_validation_runner": "scripts/migration_validation_runner.py",
    "lockstep_harness": "crates/franken-node/src/runtime/lockstep_harness.rs",
}

EVIDENCE_PATHS = {
    "migration_validation_runner": PRIMARY_IMPLEMENTATION_PATHS["migration_validation_runner"],
    "lockstep_harness": PRIMARY_IMPLEMENTATION_PATHS["lockstep_harness"],
    "contract": "docs/specs/section_10_3/bd-2st_contract.md",
    "verifier": "scripts/check_migration_validation.py",
    "regression_tests": "tests/test_check_migration_validation.py",
    "machine_evidence": "artifacts/section_10_3/bd-2st/verification_evidence.json",
    "human_summary": "artifacts/section_10_3/bd-2st/verification_summary.md",
}

VERIFICATION_COMMANDS = [
    {
        "command": "python3 scripts/check_migration_validation.py --json",
        "covers": [
            "migration validation runner self-test",
            "primary runner implementation citation",
            "lockstep harness implementation citation",
            "test discovery",
            "output canonicalization",
            "delta comparison",
            "band-aware severity classification",
        ],
    },
    {
        "command": "python3 -m pytest tests/test_check_migration_validation.py",
        "covers": [
            "migration validation runner unit tests",
            "report evidence path citations",
            "checked-in machine evidence citations",
        ],
    },
]

# Test file patterns
TEST_PATTERNS = [
    "**/*.test.js", "**/*.test.ts", "**/*.spec.js", "**/*.spec.ts",
    "**/__tests__/**/*.js", "**/__tests__/**/*.ts",
    "**/test/**/*.js", "**/test/**/*.ts",
]

TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
PID_PATTERN = re.compile(r"\bpid[=: ]+\d+\b", re.IGNORECASE)
ABS_PATH_PATTERN = re.compile(r"(/[a-zA-Z0-9_./-]+){3,}")


def discover_tests(project_dir: Path) -> list[Path]:
    """Find test files in a project directory."""
    tests = []
    for pattern in TEST_PATTERNS:
        for f in project_dir.glob(pattern):
            if "node_modules" not in str(f) and f not in tests:
                tests.append(f)
    return sorted(tests)


def canonicalize_output(output: str) -> str:
    """Normalize runtime-specific values in test output."""
    result = TIMESTAMP_PATTERN.sub("<TIMESTAMP>", output)
    result = PID_PATTERN.sub("pid=<PID>", result)
    result = ABS_PATH_PATTERN.sub("<ABS_PATH>", result)
    return result


def compare_outputs(baseline: str, migration: str) -> dict:
    """Compare canonicalized outputs and detect divergences."""
    b_lines = canonicalize_output(baseline).splitlines()
    m_lines = canonicalize_output(migration).splitlines()

    divergences = []
    max_lines = max(len(b_lines), len(m_lines))

    for i in range(max_lines):
        b_line = b_lines[i] if i < len(b_lines) else "<missing>"
        m_line = m_lines[i] if i < len(m_lines) else "<missing>"
        if b_line != m_line:
            divergences.append({
                "line": i + 1,
                "baseline": b_line,
                "migration": m_line,
            })

    return {
        "identical": len(divergences) == 0,
        "divergence_count": len(divergences),
        "divergences": divergences[:20],  # Cap at 20 for readability
    }


def classify_divergence_severity(divergences: list[dict], band: str = "core") -> str:
    """Classify severity based on band and divergence count."""
    if not divergences:
        return "none"
    if band == "core":
        return "critical"
    if band == "high-value":
        return "high"
    if band == "edge":
        return "informational"
    return "medium"


def check_primary_implementation_cited() -> dict:
    """Verify that the contract cites the primary implementation paths."""
    check = {
        "id": "VALIDATE-IMPL",
        "status": "PASS",
        "details": {
            "paths": PRIMARY_IMPLEMENTATION_PATHS,
            "existing_paths": {},
            "contract_citations": {},
        },
    }
    contract_text = CONTRACT_PATH.read_text(encoding="utf-8") if CONTRACT_PATH.exists() else ""
    missing_paths = []
    missing_contract_citations = []

    for name, path in PRIMARY_IMPLEMENTATION_PATHS.items():
        exists = (ROOT / path).exists()
        contract_cited = path in contract_text
        check["details"]["existing_paths"][name] = exists
        check["details"]["contract_citations"][name] = contract_cited
        if not exists:
            missing_paths.append(path)
        if not contract_cited:
            missing_contract_citations.append(path)

    if missing_paths or missing_contract_citations:
        check["status"] = "FAIL"
        check["details"]["missing_paths"] = missing_paths
        check["details"]["missing_contract_citations"] = missing_contract_citations

    return check


def validate_project(project_dir: Path) -> dict:
    """Run migration validation on a project (design-phase: structure only)."""
    tests = discover_tests(project_dir)

    return {
        "project": str(project_dir),
        "validation_timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "design",
        "test_discovery": {
            "test_files_found": len(tests),
            "test_files": [str(t.relative_to(project_dir)) for t in tests],
        },
        "validation_results": [],
        "summary": {
            "total_tests": len(tests),
            "passed": 0,
            "failed": 0,
            "skipped": len(tests),
            "verdict": "PENDING" if tests else "NO_TESTS",
        },
    }


def self_test() -> dict:
    """Run self-test."""
    import tempfile
    checks = [check_primary_implementation_cited()]

    # Test 1: Test discovery
    with tempfile.TemporaryDirectory() as tmpdir:
        project = Path(tmpdir)
        (project / "app.test.js").write_text("test('x', () => {});")
        (project / "lib.spec.ts").write_text("describe('y', () => {});")
        (project / "src").mkdir()
        (project / "src" / "util.js").write_text("module.exports = {};")
        tests = discover_tests(project)
    checks.append({"id": "VALIDATE-DISCOVERY", "status": "PASS" if len(tests) == 2 else "FAIL",
                    "details": {"found": len(tests)}})

    # Test 2: Canonicalization
    raw = "Error at 2024-01-15T10:30:00 pid=12345 /home/user/project/file.js"
    canon = canonicalize_output(raw)
    has_timestamp = "<TIMESTAMP>" in canon
    has_pid = "pid=<PID>" in canon
    has_path = "<ABS_PATH>" in canon
    checks.append({"id": "VALIDATE-CANONICAL", "status": "PASS" if all([has_timestamp, has_pid, has_path]) else "FAIL",
                    "details": {"timestamp": has_timestamp, "pid": has_pid, "path": has_path}})

    # Test 3: Comparison — identical
    cmp = compare_outputs("hello\nworld", "hello\nworld")
    checks.append({"id": "VALIDATE-COMPARE-SAME", "status": "PASS" if cmp["identical"] else "FAIL"})

    # Test 4: Comparison — divergent
    cmp2 = compare_outputs("hello\nworld", "hello\nearth")
    checks.append({"id": "VALIDATE-COMPARE-DIFF", "status": "PASS" if not cmp2["identical"] and cmp2["divergence_count"] == 1 else "FAIL",
                    "details": {"divergences": cmp2["divergence_count"]}})

    # Test 5: Severity classification
    sev = classify_divergence_severity([{"line": 1}], "core")
    checks.append({"id": "VALIDATE-SEVERITY", "status": "PASS" if sev == "critical" else "FAIL"})

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "migration_validation_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_paths": EVIDENCE_PATHS,
        "verification_commands": VERIFICATION_COMMANDS,
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    json_output = "--json" in sys.argv
    is_self_test = "--self-test" in sys.argv

    if is_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Usage: python3 scripts/migration_validation_runner.py <project_dir> [--json]", file=sys.stderr)
        sys.exit(2)

    report = validate_project(Path(args[0]))
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print(f"Project: {report['project']}")
        print(f"Tests found: {report['test_discovery']['test_files_found']}")
        print(f"Verdict: {report['summary']['verdict']}")


if __name__ == "__main__":
    main()
