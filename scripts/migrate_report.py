#!/usr/bin/env python3
"""Assess captured projects, execute migration tests, and retain failure evidence.

--execute runs trusted code with your authority; workspace copies are NOT an OS
sandbox. Without it this is static assessment only and cannot produce GO.
GO permits evaluation of the captured test scope, never production deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import failure_replay as replay
import migration_confidence_report as confidence_mod
import migration_risk_scorer as scorer_mod
import migration_validation_runner as runner
import project_scanner as scanner_mod
import rewrite_suggestion_engine as rewrite_mod
import rollout_planner as planner_mod

MAX_SCAN_SOURCE_BYTES = 10 * 1024 * 1024


def _check(check_id: str, passed: bool, details: dict | None = None) -> dict:
    return {"id": check_id, "status": "PASS" if passed else "FAIL", "details": details or {}}


def _read_source(root: Path, relative_path: str) -> tuple[str, str | None]:
    try:
        return (root / relative_path).read_text(encoding="utf-8"), None
    except OSError as error:
        return "", str(error)


def check_rust_cli_contract(root: Path = ROOT) -> list[dict]:
    """Check the separate native command; do not imply this Python path is it."""
    contracts = [
        ("COMMAND", "crates/franken-node/src/cli.rs",
         ['#[command(name = "migrate-report")]', "MigrateReport(MigrateReportArgs)",
          "pub struct MigrateReportArgs", 'alias = "out"']),
        ("DISPATCH", "crates/franken-node/src/main.rs",
         ["fn handle_migrate_report", "Command::MigrateReport(args)", "handle_migrate_report(&args)"]),
        ("RENDERER", "crates/franken-node/src/migration/mod.rs",
         ["pub fn run_one_command_report", "pub fn render_one_command_report",
          "franken-node/migrate-report/v1", "OneCommandMigrationReportFormat::Html"]),
        ("E2E", "crates/franken-node/tests/migrate_cli_e2e.rs",
         ["migrate_report_json_stdout_composes_audit_rewrite_validate_sections",
          "migrate_report_html_output_writes_escaped_report_file", '"migrate-report"']),
        ("DETERMINISM-BOUNDARY", "docs/specs/section_10_3/bd-hg1_contract.md",
         ["Stable report content is deterministic", "`generated_at_utc` is intentionally dynamic provenance",
          "Do not remove `generated_at_utc`"]),
    ]
    checks = []
    for name, path, markers in contracts:
        source, error = _read_source(root, path)
        checks.append(_check(f"RUST-CLI-MIGRATE-REPORT-{name}",
                             error is None and all(marker in source for marker in markers),
                             {"file": path, "error": error}))
    return checks


def preflight_destinations(roots: list[Path], *destinations: Path | None) -> None:
    """No overwrite or output nested inside an input tree; check before execution."""
    resolved = []
    for destination in destinations:
        if destination is None:
            continue
        destination = Path(destination)
        if os.path.lexists(destination):
            raise ValueError(f"output already exists: {destination}")
        parent = destination.parent.resolve(strict=True)
        if not parent.is_dir():
            raise ValueError("output parent must be an existing directory")
        target = parent / destination.name
        if any(target.is_relative_to(root) or root.is_relative_to(target) for root in roots):
            raise ValueError("outputs must be outside captured project trees")
        if any(target.is_relative_to(other) or other.is_relative_to(target) for other in resolved):
            raise ValueError("output destinations must be distinct and non-overlapping")
        resolved.append(target)


def assess_snapshot(root: Path, display_path: str, registry: dict, deadline: float) -> dict:
    """Reuse scanner/risk/rewrite rules over the private captured workspace.

    Inspect every project package manifest, including monorepos. Malformed or
    unreadable inputs are errors, not a clean scan. This remains a regex/API
    inventory, not a complete static security analysis.
    """
    usage, dependencies = [], []
    for directory, names, files in os.walk(root, followlinks=False, onerror=runner.raise_walk_error):
        names[:] = sorted(name for name in names if name not in {".git", "node_modules"})
        for name in sorted(files):
            if time.monotonic() >= deadline:
                raise TimeoutError("migration assessment exhausted total budget")
            path = Path(directory) / name
            if path.suffix not in scanner_mod.JS_EXTENSIONS and name != "package.json":
                continue
            if path.stat().st_size > MAX_SCAN_SOURCE_BYTES:
                raise ValueError("assessment source exceeds the 10 MiB bound")
            # Surface encoding/read failures that the legacy scanner suppresses.
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(root).as_posix()
            if name == "package.json":
                package = json.loads(text, object_pairs_hook=replay.unique_object,
                                     parse_constant=replay.reject_constant)
                if not isinstance(package, dict):
                    raise ValueError(f"package manifest must be an object: {relative}")
                for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    declared = package.get(section, {})
                    if not isinstance(declared, dict) or any(not isinstance(version, str) for version in declared.values()):
                        raise ValueError(f"invalid {section} in {relative}")
                    for dependency, version in sorted(declared.items()):
                        native = dependency in scanner_mod.NATIVE_ADDON_PACKAGES
                        dependencies.append({"name": dependency, "version": version, "manifest": relative,
                                             "section": section, "has_native_addon": native,
                                             "risk_level": "critical" if native else "low",
                                             "notes": "Native addon — requires port or replacement" if native else None})
            else:
                found = scanner_mod.scan_file(path, registry)
                for item in found:
                    item["source_file"] = relative
                usage.extend(found)
    usage.sort(key=lambda item: (item["source_file"], item["api_family"], item["api_name"]))
    distribution = {level: 0 for level in ("low", "medium", "high", "critical")}
    for item in usage:
        distribution[item["risk_level"]] += 1
    distribution["critical"] += sum(item["has_native_addon"] for item in dependencies)
    scan = {"project": display_path, "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "analysis_scope": "regex API inventory and declared dependency risks",
            "summary": {"total_apis_detected": len(usage), "risk_distribution": distribution,
                        "migration_readiness": scanner_mod.compute_readiness(distribution)},
            "api_usage": usage, "dependencies": dependencies,
            "recommendations": [{"category": "blocking", "severity": "error", "message": "Resolve critical findings"}]
                               if distribution["critical"] else []}
    rewrites = rewrite_mod.produce_report(scan)
    # Suggestions are not an applied patch or an executed rollback. In
    # particular, legacy shell strings are never used as executable commands.
    rewrites["applied"] = False
    rewrites["advisory_only"] = True
    return {"scan": scan, "risk_assessment": scorer_mod.score_report(scan), "rewrite_suggestions": rewrites}


def generate_full_report(project_dir: Path, *, migrated_project: Path | None = None,
                         execute: bool = False, failure_dir: Path | None = None,
                         baseline_command=runner.DEFAULT_BASELINE_COMMAND,
                         migration_command=runner.DEFAULT_MIGRATION_COMMAND, **options) -> dict:
    """One snapshot feeds assessment, execution, confidence, and failure export."""
    timestamp = datetime.now(timezone.utc).isoformat()
    result = {"report_version": "1.0", "workflow_schema": "measured-migration-report-v1",
              "generated_at": timestamp, "workflow_status": "ERROR", "execution_requested": execute,
              "release_certification": False, "errors": [], "events": [],
              "validation": None, "input_binding_verified": False,
              "failure_artifact": {"status": "not_requested" if failure_dir is None else "pending"},
              "executive_summary": {"project": str(project_dir), "go_decision": "NO-GO",
                                    "decision_scope": "captured-tests-only; not production authorization",
                                    "confidence_score": 0, "risk_score": None, "difficulty": "unknown",
                                    "apis_detected": 0, "suggestions_count": 0}}
    try:
        if type(execute) is not bool or (failure_dir is not None and not execute):
            raise ValueError("failure capture requires explicit execute=True / --execute")
        options = replay.checked_options(options)
        deadline = time.monotonic() + options["total_timeout_seconds"]
        roots = [Path(project_dir).resolve(strict=True), Path(migrated_project or project_dir).resolve(strict=True)]
        if not all(root.is_dir() for root in roots):
            raise ValueError("both migration inputs must be directories")
        preflight_destinations(roots, failure_dir)
        snapshots, input_digests, captured = {}, {}, {}
        for leg, root in zip(replay.LEGS, roots):
            if root not in captured:
                captured[root] = runner.capture_project(root, deadline)
            snapshots[leg], input_digests[f"{leg}_sha256"] = captured[root]
        result["inputs"] = input_digests
        result["events"].append({"stage": "capture", "status": "completed", "inputs": input_digests})
        # If replay export is requested, refuse unrepresentable input before
        # execution rather than discovering lost evidence after a failure.
        manifests = blobs = None
        if failure_dir is not None:
            manifests, blobs = replay.encode_snapshots(snapshots)
            snapshots = replay.decode_snapshots(manifests, blobs)
        registry = scanner_mod.load_registry()
        result["registry_available"] = bool(registry)
        with tempfile.TemporaryDirectory(prefix="measured-migration-report-") as temporary:
            root = Path(temporary)
            assessments = {}
            for leg, display in zip(replay.LEGS, roots):
                workspace = root / leg
                runner.stage_project(snapshots[leg], workspace, deadline)
                # The staged inputs must still be the captured assessment inputs.
                if runner.capture_project(workspace, deadline)[1] != input_digests[f"{leg}_sha256"]:
                    raise ValueError("staged assessment input digest mismatch")
                assessments[leg] = assess_snapshot(workspace, str(display), registry, deadline)
            result.update(assessments["baseline"])
            candidate = assessments["migration"]
            result["candidate_assessment"] = candidate
            result["events"].append({"stage": "assessment", "status": "completed"})
            if execute:
                commands, bindings = replay.runtime_bindings(baseline_command, migration_command, deadline)
                # Reserve some of the total allowance for post-execution identity
                # checking. If it cannot finish, retain results but fail closed.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("no migration execution budget remains")
                validation = runner.validate_project(root / "baseline", migrated_project=root / "migration",
                                                     baseline_command=commands["baseline"],
                                                     migration_command=commands["migration"],
                                                     **{**options, "total_timeout_seconds": remaining * .9})
                result["validation"] = validation
                result["runtime_bindings"] = bindings
                if validation.get("inputs") != input_digests:
                    raise ValueError("assessment and execution input digests disagree")
                _, after = replay.runtime_bindings(commands["baseline"], commands["migration"], deadline)
                if after != bindings:
                    raise ValueError("runtime or validator changed during measured report")
                result["input_binding_verified"] = True
                result["events"].append({"stage": "validation", "status": validation["summary"]["verdict"]})
                # Replace disposable reporting paths, not captured observations.
                validation["project"], validation["migrated_project"] = map(str, roots)
                if failure_dir is not None:
                    if validation["summary"]["verdict"] == "FAIL":
                        capsule = replay.seal({"schema_version": replay.CAPSULE_SCHEMA,
                                              "captured_at": timestamp, "failure_source": "migration_validation_runner",
                                              "snapshots": manifests, "blobs": blobs, "options": options,
                                              "recorded_commands": commands, "runtime_bindings": bindings,
                                              "expected": replay.execution_observation(validation),
                                              "scope": "exact-input re-execution; not deterministic runtime replay",
                                              "environment_captured": False, "release_certification": False})
                        Path(failure_dir).mkdir(mode=0o700)
                        path = Path(failure_dir) / f"{capsule['replay_id']}.json"
                        replay.write_capsule(capsule, path)
                        result["failure_artifact"] = {"status": "captured", "path": str(path),
                                                      "content_sha256": capsule["content_sha256"],
                                                      "replay_id": capsule["replay_id"]}
                    else:
                        result["failure_artifact"] = {"status": "not_needed" if validation["summary"]["verdict"] == "PASS"
                                                      else "unavailable", "reason": validation["summary"]["verdict"]}
            else:
                result["events"].append({"stage": "validation", "status": "NOT_RUN"})
            confidence = confidence_mod.generate_report(candidate["scan"]["summary"], candidate["risk_assessment"],
                                                        result["validation"])
            result["confidence"] = confidence
            blockers = list(confidence["go_decision"]["blocking_reasons"])
            categories = candidate["rewrite_suggestions"]["summary"]["by_category"]
            if any(categories.get(category, 0) for category in ("adapter-needed", "removal-needed", "manual-review")):
                blockers.append("candidate rewrite suggestions still require review")
            if not registry:
                blockers.append("compatibility registry is unavailable")
            go = not blockers and result["input_binding_verified"]
            # Every consumer sees the same decision. The heuristic component
            # cannot authorize progression past an unresolved review item.
            confidence["go_decision"].update(
                proceed=go, blocking_reasons=blockers,
                rationale="; ".join(blockers) if blockers else confidence["go_decision"]["rationale"])
            result["executive_summary"].update(
                timestamp=timestamp, go_decision="GO" if go else "NO-GO", blocking_reasons=blockers,
                confidence_score=confidence["confidence"]["confidence_score"],
                risk_score=candidate["risk_assessment"]["risk_score"],
                difficulty=candidate["risk_assessment"]["difficulty"]["level"],
                apis_detected=candidate["scan"]["summary"]["total_apis_detected"],
                suggestions_count=len(candidate["rewrite_suggestions"]["suggestions"]))
            plan = planner_mod.generate_plan(candidate["risk_assessment"])
            plan["execution_authorized"] = False
            plan["validation_gate"] = {"passed": go, "blocking_reasons": blockers}
            for phase in plan["phases"]:
                phase["status"] = ("eligible_for_evaluation" if go else "blocked") if phase["name"] == "shadow" else "not_evaluated"
                phase["execution_authorized"] = False
            result["rollout_plan"] = plan
            measured_verdict = (result["validation"] or {}).get("summary", {}).get("verdict")
            result["workflow_status"] = ("ASSESSED" if not execute else "ERROR" if measured_verdict == "ERROR"
                                         else "VALIDATED" if go else "BLOCKED")
            if measured_verdict == "ERROR":
                result["errors"].extend(result["validation"]["errors"])
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        result["errors"].append({"type": type(error).__name__, "message": str(error)})
        result["workflow_status"] = "ERROR"
        result["executive_summary"]["go_decision"] = "NO-GO"
        if "confidence" in result:
            result["confidence"]["go_decision"].update(proceed=False, rationale=str(error))
        if "rollout_plan" in result:
            result["rollout_plan"]["validation_gate"] = {"passed": False, "blocking_reasons": [str(error)]}
        if result["failure_artifact"]["status"] == "pending":
            result["failure_artifact"] = {"status": "unavailable", "reason": str(error)}
    return result


def render_html(report: dict) -> str:
    """Standalone report; never embed unescaped project-controlled markup."""
    summary = report["executive_summary"]
    return ("<!doctype html><html><head><meta charset=\"utf-8\"><title>Migration assessment</title></head><body>"
            f"<h1>{html.escape(summary['go_decision'])}: {html.escape(summary['project'])}</h1>"
            f"<p>{html.escape(summary['decision_scope'])}</p>"
            "<p>Heuristic assessment and measured test outcomes; not a production authorization.</p>"
            f"<pre>{html.escape(json.dumps(report, indent=2, allow_nan=False))}</pre></body></html>\n")


def write_new_report(report: dict, path: Path, format: str = "json") -> None:
    """Publish atomically without replacing an existing file, including a race."""
    if format not in {"json", "html"}:
        raise ValueError("report format must be json or html")
    text = render_html(report) if format == "html" else json.dumps(report, indent=2, allow_nan=False) + "\n"
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".migration-report-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def report_exit_code(report: dict) -> int:
    if report["workflow_status"] == "VALIDATED" and report["executive_summary"]["go_decision"] == "GO":
        return 0
    return 1 if report["workflow_status"] == "BLOCKED" else 2


def self_test() -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        project = Path(temporary)
        (project / "app.js").write_text("const fs=require('fs'); fs.readFileSync('config');", encoding="utf-8")
        report = generate_full_report(project)
    checks = [_check("REPORT-SECTIONS", all(key in report for key in
                     ("scan", "risk_assessment", "rewrite_suggestions", "rollout_plan", "confidence"))),
              _check("REPORT-EXECUTIVE", report["executive_summary"]["go_decision"] == "NO-GO"),
              _check("REPORT-SCAN", report["scan"]["summary"]["total_apis_detected"] > 0),
              _check("REPORT-RISK", report["risk_assessment"]["risk_score"] is not None),
              _check("REPORT-ROLLOUT", len(report["rollout_plan"]["phases"]) == 4)]
    checks.extend(check_rust_cli_contract())
    failures = sum(check["status"] == "FAIL" for check in checks)
    return {"gate": "migrate_report_verification", "section": "10.3", "verdict": "FAIL" if failures else "PASS",
            "checks": checks, "summary": {"total_checks": len(checks), "passing_checks": len(checks) - failures,
                                           "failing_checks": failures}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir", nargs="?", type=Path)
    parser.add_argument("--migrated-project", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--failure-dir", type=Path, help="new private directory for measured failure capsules")
    parser.add_argument("--baseline-command", type=json.loads, default=list(runner.DEFAULT_BASELINE_COMMAND))
    parser.add_argument("--migration-command", type=json.loads, default=list(runner.DEFAULT_MIGRATION_COMMAND))
    parser.add_argument("--compare-filesystem", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--total-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--max-output-bytes", type=int, default=1_048_576)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--format", choices=("json", "html"), default="json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(json.dumps(result, indent=2))
        return 0 if result["verdict"] == "PASS" else 1
    if args.project_dir is None:
        parser.error("project_dir is required")
    report = None
    try:
        roots = [args.project_dir.resolve(strict=True), (args.migrated_project or args.project_dir).resolve(strict=True)]
        preflight_destinations(roots, args.out, args.failure_dir)
        report = generate_full_report(args.project_dir, migrated_project=args.migrated_project,
                                      execute=args.execute, failure_dir=args.failure_dir,
                                      baseline_command=args.baseline_command, migration_command=args.migration_command,
                                      compare_filesystem=args.compare_filesystem, timeout_seconds=args.timeout_seconds,
                                      total_timeout_seconds=args.total_timeout_seconds, max_output_bytes=args.max_output_bytes)
        if args.out is not None:
            write_new_report(report, args.out, args.format)
        print(json.dumps(report, indent=2, allow_nan=False) if args.json else
              f"{report['workflow_status']}: {report['executive_summary']['go_decision']}\n"
              f"{report['executive_summary']['decision_scope']}\n"
              f"{json.dumps(report['executive_summary'].get('blocking_reasons', []))}")
        return report_exit_code(report)
    except (OSError, ValueError, TypeError) as error:
        # A publication failure must not discard the already-measured outcome
        # or the path to a successfully retained failure capsule.
        result = {"workflow_status": "ERROR", "error": str(error)}
        if report is not None:
            result["measured_report"] = report
        print(json.dumps(result, allow_nan=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
