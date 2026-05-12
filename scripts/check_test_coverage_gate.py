#!/usr/bin/env python3
"""Test Coverage Gate (bd-17ds.6): full test suite verification across the franken_node tree.

This gate aggregates evidence from the bd-17ds epic ("Comprehensive Test Coverage
& E2E Integration Suite") and produces a living scorecard at
`artifacts/test_coverage/final_gate_evidence.json`.

Targets (from bd-17ds body):
- 7060+ Rust #[test] modules (current baseline 6910 from 2026-02-24)
- 6+ live e2e scenarios
- 50+ cross-module integration tests
- 424/424 Python verification scripts with logging
- 0 files with mock patterns in production paths

Usage:
    python scripts/check_test_coverage_gate.py            # human-readable + emits JSON
    python scripts/check_test_coverage_gate.py --json     # machine-readable
    python scripts/check_test_coverage_gate.py --self-test
    python scripts/check_test_coverage_gate.py --no-write # don't update artifacts/

Exit codes:
    0 — all targets met (PASS)
    1 — one or more targets unmet (FAIL); still writes the evidence artifact
    2 — execution error (e.g. tree not readable)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BEAD = "bd-17ds.6"
SECTION = "test_coverage"

# Targets per bd-17ds body
TARGET_RUST_TESTS = 7060
TARGET_E2E_SCENARIOS = 6
TARGET_CROSS_MODULE = 50
TARGET_SCRIPTS_LOGGED = 1.0     # ratio: all scripts must log
TARGET_MOCK_FILES = 0


@dataclass
class CheckResult:
    name: str
    target: Any
    actual: Any
    passed: bool
    detail: str = ""


def count_rust_tests(repo_root: Path) -> int:
    """Count #[test] and #[cfg(test)] across the workspace."""
    total = 0
    for path in repo_root.rglob("*.rs"):
        # skip target/ and .git/
        s = str(path)
        if "/target/" in s or "/.git/" in s or "/beads_compliance_audit/" in s:
            continue
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        # count both #[test] (function-level) and #[cfg(test)] (module-level)
        # using #[test] only would understate; #[cfg(test)] alone overstates.
        # Heuristic: count #[test] occurrences as the test-function count.
        total += len(re.findall(r"#\[test\]", content))
    return total


def count_e2e_scenarios(repo_root: Path) -> int:
    """Count e2e test files (a scenario = one *_e2e*.rs file with > 0 #[tokio::test]
    or #[test] functions, plus any tests/e2e/*.rs files)."""
    seen: set[Path] = set()
    for pattern in ("**/*_e2e*.rs", "**/e2e_*.rs", "tests/e2e/*.rs", "tests/e2e/**/*.rs"):
        for path in repo_root.glob(pattern):
            if "/target/" in str(path) or "/beads_compliance_audit/" in str(path):
                continue
            try:
                content = path.read_text(errors="replace")
            except Exception:
                continue
            if re.search(r"#\[(?:tokio::)?test\]", content):
                seen.add(path)
    return len(seen)


def count_cross_module_integration(repo_root: Path) -> int:
    """Count integration tests that touch ≥ 2 product modules.

    Heuristic: integration tests in `crates/franken-node/tests/*.rs` or
    `tests/integration/*.rs` whose source imports ≥ 2 distinct `franken_node::*`
    or local `use crates::franken_node::*` modules.
    """
    count = 0
    candidates = list(repo_root.glob("crates/franken-node/tests/*.rs")) + \
                 list(repo_root.glob("tests/integration/**/*.rs"))
    for path in candidates:
        if "/target/" in str(path):
            continue
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        modules = set(re.findall(r"frankenengine_node::(\w+)", content))
        if len(modules) >= 2:
            count += 1
    return count


def script_logging_ratio(repo_root: Path) -> tuple[int, int, float]:
    """Ratio of Python verification scripts that import the project's test_logger."""
    scripts = list((repo_root / "scripts").glob("**/*.py"))
    total = 0
    logged = 0
    for s in scripts:
        if "/.git/" in str(s) or "/__pycache__/" in str(s):
            continue
        total += 1
        try:
            content = s.read_text(errors="replace")
        except Exception:
            continue
        if "configure_test_logging" in content or "test_logger" in content or \
           re.search(r"\blogging\.(getLogger|basicConfig)\b", content):
            logged += 1
    ratio = logged / total if total else 0.0
    return logged, total, ratio


def count_mock_patterns_in_prod(repo_root: Path) -> int:
    """Files with mockall::mock! / mockito::Server / unittest.mock outside test paths."""
    found: set[Path] = set()
    patterns = [
        re.compile(r"\bmockall::mock!"),
        re.compile(r"\bmockito::"),
        re.compile(r"\bMockServer::new"),
        re.compile(r"\bunittest\.mock\b"),
        re.compile(r"\bunittest\.mock\.MagicMock\b"),
    ]
    for path in repo_root.rglob("*.rs"):
        s = str(path)
        if "/target/" in s or "/.git/" in s or "/beads_compliance_audit/" in s:
            continue
        # SKIP test paths
        if "/tests/" in s or s.endswith("_test.rs") or s.endswith("_tests.rs"):
            continue
        # also skip inline #[cfg(test)] modules — heuristic: only count if
        # the match is OUTSIDE any #[cfg(test)] block
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        # cheap: any mock pattern in a non-test file = flagged
        for pat in patterns:
            if pat.search(content):
                found.add(path)
                break
    return len(found)


def section_beads_status(repo_root: Path) -> dict[str, Any]:
    """Try to call `br list` for bd-17ds.* and summarize."""
    db = repo_root / ".beads" / "beads.db"
    if not db.is_file():
        return {"available": False}
    try:
        out = subprocess.run(
            ["br", "--db", str(db), "list", "--limit", "0", "--json"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(out.stdout) if out.returncode == 0 else {}
    except Exception:
        return {"available": False}
    issues = data.get("issues", data) if isinstance(data, dict) else []
    relevant = [i for i in issues if (i.get("id") or "").startswith("bd-17ds")]
    closed = sum(1 for i in relevant if (i.get("status") if isinstance(i.get("status"), str)
                                         else (i.get("status") or {}).get("Custom", "")) == "closed")
    return {
        "available": True,
        "total": len(relevant),
        "closed": closed,
        "open": len(relevant) - closed,
    }


def build_report(repo_root: Path) -> dict[str, Any]:
    checks: list[CheckResult] = []

    rust_tests = count_rust_tests(repo_root)
    checks.append(CheckResult(
        name="rust_test_count",
        target=TARGET_RUST_TESTS,
        actual=rust_tests,
        passed=rust_tests >= TARGET_RUST_TESTS,
        detail=f"counted #[test] markers across non-target *.rs files"
    ))

    e2e = count_e2e_scenarios(repo_root)
    checks.append(CheckResult(
        name="e2e_scenario_count",
        target=TARGET_E2E_SCENARIOS,
        actual=e2e,
        passed=e2e >= TARGET_E2E_SCENARIOS,
        detail="files matching *_e2e*.rs / e2e_*.rs / tests/e2e/*.rs with at least one test function"
    ))

    cross = count_cross_module_integration(repo_root)
    checks.append(CheckResult(
        name="cross_module_integration_count",
        target=TARGET_CROSS_MODULE,
        actual=cross,
        passed=cross >= TARGET_CROSS_MODULE,
        detail="integration test files importing >= 2 distinct frankenengine_node submodules"
    ))

    logged, total_scripts, ratio = script_logging_ratio(repo_root)
    checks.append(CheckResult(
        name="script_logging_ratio",
        target=f">= {TARGET_SCRIPTS_LOGGED:.2f} ({total_scripts} scripts)",
        actual=f"{logged}/{total_scripts} = {ratio:.3f}",
        passed=ratio >= TARGET_SCRIPTS_LOGGED,
        detail="Python scripts under scripts/ that import test_logger or use logging.getLogger / logging.basicConfig"
    ))

    mock_files = count_mock_patterns_in_prod(repo_root)
    checks.append(CheckResult(
        name="mock_patterns_in_prod_files",
        target=TARGET_MOCK_FILES,
        actual=mock_files,
        passed=mock_files <= TARGET_MOCK_FILES,
        detail="files containing mockall::mock! / mockito / unittest.mock outside /tests/ or *_test.rs paths"
    ))

    beads = section_beads_status(repo_root)
    overall_pass = all(c.passed for c in checks)
    report = {
        "bead": BEAD,
        "section": SECTION,
        "evaluated_at": _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": "PASS" if overall_pass else "FAIL",
        "overall_pass": overall_pass,
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.passed),
        "checks": [asdict(c) for c in checks],
        "section_beads": beads,
        "targets": {
            "rust_tests": TARGET_RUST_TESTS,
            "e2e_scenarios": TARGET_E2E_SCENARIOS,
            "cross_module_integration": TARGET_CROSS_MODULE,
            "script_logging_ratio": TARGET_SCRIPTS_LOGGED,
            "mock_pattern_files": TARGET_MOCK_FILES,
        },
        "notes": [
            "This gate is a living scorecard. It can run at any pass through the tree.",
            "Heuristics intentionally lean conservative: actual coverage may exceed counted #[test] markers",
            "(e.g. parameterised tests, helper functions invoked by tests).",
            "When verdict=FAIL, expand on the failing check via the `detail` field rather than guessing.",
        ],
    }
    return report


def write_artifacts(report: dict[str, Any], repo_root: Path) -> None:
    out_dir = repo_root / "artifacts" / "test_coverage"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "final_gate_evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    # Human summary
    summary_lines = [
        f"# Test Coverage Gate — {report['verdict']}\n",
        f"_Bead:_ `{BEAD}`  _Evaluated:_ `{report['evaluated_at']}`\n",
        "## Verdict",
        f"**{report['verdict']}** ({report['checks_passed']}/{report['checks_total']} checks pass)\n",
        "## Checks",
        "",
        "| Check | Target | Actual | Pass |",
        "|-------|--------|--------|:---:|",
    ]
    for c in report["checks"]:
        marker = "✓" if c["passed"] else "✗"
        summary_lines.append(f"| `{c['name']}` | {c['target']} | {c['actual']} | {marker} |")
    if report.get("section_beads", {}).get("available"):
        b = report["section_beads"]
        summary_lines.append("")
        summary_lines.append(f"## Section beads ({b['total']} total)")
        summary_lines.append(f"- closed: {b['closed']}")
        summary_lines.append(f"- open: {b['open']}")
    summary_lines.append("")
    summary_lines.append("## How to interpret")
    summary_lines.append("")
    summary_lines.append("- This gate runs at any time and reports a snapshot. It does NOT alter the bead store.")
    summary_lines.append("- Targets are from the bd-17ds epic body (2026-02-24 baseline).")
    summary_lines.append("- Re-run after landing test work to track progress: `python scripts/check_test_coverage_gate.py`")
    (out_dir / "verification_summary.md").write_text("\n".join(summary_lines) + "\n")


def self_test() -> int:
    """Smoke test: verify the report shape on the current tree, but do not write."""
    report = build_report(ROOT)
    assert isinstance(report, dict)
    assert "verdict" in report
    assert report["verdict"] in ("PASS", "FAIL")
    assert "checks" in report
    assert len(report["checks"]) >= 5
    print(f"self-test: ok ({report['checks_passed']}/{report['checks_total']} checks pass; verdict={report['verdict']})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--self-test", action="store_true", help="smoke test only; no file writes")
    parser.add_argument("--no-write", action="store_true", help="skip writing artifacts/test_coverage/")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    report = build_report(ROOT)
    if not args.no_write:
        write_artifacts(report, ROOT)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Test Coverage Gate — {report['verdict']} ({report['checks_passed']}/{report['checks_total']})")
        for c in report["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: target={c['target']!r:25s} actual={c['actual']!r}")
        if report.get("section_beads", {}).get("available"):
            b = report["section_beads"]
            print(f"  section beads: {b['closed']}/{b['total']} closed")
        if not args.no_write:
            print(f"  wrote artifacts/test_coverage/final_gate_evidence.json + verification_summary.md")

    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
