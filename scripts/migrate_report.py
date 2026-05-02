#!/usr/bin/env python3
"""
One-Command Migration Report Export.

Orchestrates the full migration assessment pipeline and exports
a comprehensive report for enterprise review.

Usage:
    python3 scripts/migrate_report.py <project_dir> [--json]
    python3 scripts/migrate_report.py --self-test [--json]
"""

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

# This script is directly executable, so repo-local helpers need the path shim above.
import migration_confidence_report as confidence_mod  # noqa: E402
import migration_risk_scorer as scorer_mod  # noqa: E402
import project_scanner as scanner_mod  # noqa: E402
import rewrite_suggestion_engine as rewrite_mod  # noqa: E402
import rollout_planner as planner_mod  # noqa: E402


def _check(check_id: str, passed: bool, details: dict | None = None) -> dict:
    check = {"id": check_id, "status": "PASS" if passed else "FAIL"}
    if details is not None:
        check["details"] = details
    return check


def _read_source(root: Path, relative_path: str) -> tuple[str, str | None]:
    path = root / relative_path
    try:
        return path.read_text(), None
    except OSError as exc:
        return "", f"{path}: {exc}"


def check_rust_cli_contract(root: Path = ROOT) -> list[dict]:
    """Verify the shipped Rust CLI surface exists, not just this Python prototype."""
    cli_rs, cli_err = _read_source(root, "crates/franken-node/src/cli.rs")
    main_rs, main_err = _read_source(root, "crates/franken-node/src/main.rs")
    migration_rs, migration_err = _read_source(root, "crates/franken-node/src/migration/mod.rs")
    e2e_rs, e2e_err = _read_source(root, "crates/franken-node/tests/migrate_cli_e2e.rs")

    checks = [
        _check(
            "RUST-CLI-MIGRATE-REPORT-COMMAND",
            cli_err is None
            and '#[command(name = "migrate-report")]' in cli_rs
            and "MigrateReport(MigrateReportArgs)" in cli_rs
            and "pub struct MigrateReportArgs" in cli_rs
            and 'alias = "out"' in cli_rs,
            {"file": "crates/franken-node/src/cli.rs", "error": cli_err},
        ),
        _check(
            "RUST-CLI-MIGRATE-REPORT-DISPATCH",
            main_err is None
            and "fn handle_migrate_report" in main_rs
            and "Command::MigrateReport(args)" in main_rs
            and "handle_migrate_report(&args)" in main_rs,
            {"file": "crates/franken-node/src/main.rs", "error": main_err},
        ),
        _check(
            "RUST-CLI-MIGRATE-REPORT-RENDERER",
            migration_err is None
            and "pub fn run_one_command_report" in migration_rs
            and "pub fn render_one_command_report" in migration_rs
            and "franken-node/migrate-report/v1" in migration_rs
            and "OneCommandMigrationReportFormat::Html" in migration_rs,
            {"file": "crates/franken-node/src/migration/mod.rs", "error": migration_err},
        ),
        _check(
            "RUST-CLI-MIGRATE-REPORT-E2E",
            e2e_err is None
            and "migrate_report_json_stdout_composes_audit_rewrite_validate_sections" in e2e_rs
            and "migrate_report_html_output_writes_escaped_report_file" in e2e_rs
            and '"migrate-report"' in e2e_rs,
            {"file": "crates/franken-node/tests/migrate_cli_e2e.rs", "error": e2e_err},
        ),
    ]
    return checks


def generate_full_report(project_dir: Path) -> dict:
    """Run complete migration pipeline and produce unified report."""
    timestamp = datetime.now(timezone.utc).isoformat()

    # Phase 1: Scan
    scan_report = scanner_mod.scan_project(project_dir)

    # Phase 2: Risk Score
    risk_report = scorer_mod.score_report(scan_report)

    # Phase 3: Rewrite Suggestions
    rewrite_report = rewrite_mod.produce_report(scan_report)

    # Phase 4: Rollout Plan
    rollout_plan = planner_mod.generate_plan(risk_report)

    # Phase 5: Confidence
    conf_report = confidence_mod.generate_report(
        scan_summary=scan_report.get("summary"),
        risk_report=risk_report,
    )

    # Executive summary
    go = conf_report["go_decision"]["proceed"]
    executive = {
        "project": str(project_dir),
        "timestamp": timestamp,
        "go_decision": "GO" if go else "NO-GO",
        "confidence_score": conf_report["confidence"]["confidence_score"],
        "risk_score": risk_report["risk_score"],
        "difficulty": risk_report["difficulty"]["level"],
        "apis_detected": scan_report["summary"]["total_apis_detected"],
        "suggestions_count": len(rewrite_report["suggestions"]),
    }

    return {
        "report_version": "1.0",
        "generated_at": timestamp,
        "executive_summary": executive,
        "scan": scan_report,
        "risk_assessment": risk_report,
        "rewrite_suggestions": rewrite_report,
        "rollout_plan": rollout_plan,
        "confidence": conf_report,
    }


def self_test() -> dict:
    """Run self-test with synthetic project."""
    checks = []

    with tempfile.TemporaryDirectory() as tmpdir:
        project = Path(tmpdir)
        (project / "app.js").write_text(
            "const fs = require('fs');\n"
            "const data = fs.readFileSync('config.json', 'utf8');\n"
            "console.log(process.env.NODE_ENV);\n"
        )
        (project / "package.json").write_text(json.dumps({
            "name": "test-enterprise-app",
            "dependencies": {"express": "^4.18.0"},
        }))

        report = generate_full_report(project)

    # Check 1: Has all sections
    sections = ["executive_summary", "scan", "risk_assessment", "rewrite_suggestions", "rollout_plan", "confidence"]
    has_all = all(s in report for s in sections)
    checks.append(_check(
        "REPORT-SECTIONS",
        has_all,
        {"sections": [s for s in sections if s in report]},
    ))

    # Check 2: Executive summary populated
    exec_summary = report.get("executive_summary", {})
    has_exec = all(k in exec_summary for k in ["go_decision", "confidence_score", "risk_score"])
    checks.append(_check("REPORT-EXECUTIVE", has_exec))

    # Check 3: Scan detected APIs
    apis = report.get("scan", {}).get("summary", {}).get("total_apis_detected", 0)
    checks.append(_check("REPORT-SCAN", apis > 0, {"apis_detected": apis}))

    # Check 4: Risk score present
    risk = report.get("risk_assessment", {}).get("risk_score")
    checks.append(_check("REPORT-RISK", risk is not None, {"risk_score": risk}))

    # Check 5: Rollout plan has phases
    phases = report.get("rollout_plan", {}).get("phases", [])
    checks.append(_check("REPORT-ROLLOUT", len(phases) == 4))

    checks.extend(check_rust_cli_contract())

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "migrate_report_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
        print("Usage: python3 scripts/migrate_report.py <project_dir> [--json]", file=sys.stderr)
        sys.exit(2)

    report = generate_full_report(Path(args[0]))
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        e = report["executive_summary"]
        print(f"=== Migration Report: {e['project']} ===")
        print(f"Decision: {e['go_decision']}")
        print(f"Confidence: {e['confidence_score']}/100")
        print(f"Risk: {e['risk_score']}/100 ({e['difficulty']})")
        print(f"APIs: {e['apis_detected']} detected")
        print(f"Suggestions: {e['suggestions_count']}")


if __name__ == "__main__":
    main()
