#!/usr/bin/env python3
"""Unit tests for scripts/check_tnr_ci_verification_gate.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_tnr_ci_verification_gate as gate

_JSON_DECODER = json.JSONDecoder()


def _executed_pass_report() -> dict:
    finished_event = {
        "timestamp": "2026-06-09T00:00:00Z",
        "phase": "claim",
        "event": "claim_execution_finished",
        "detail": "procedure executed successfully and met threshold",
        "claim_id": "HC-001",
        "command": "python3 scripts/check_claim.py --json",
        "resolved_procedure_ref": "scripts/check_claim.py",
        "execution_state": "executed",
        "result_kind": "pass",
        "duration_seconds": 0.01,
        "exit_code": 0,
        "measured_value": "PASS",
    }
    return {
        "schema_version": gate.REPORT_SCHEMA,
        "run_mode": "executed",
        "environment": {"os": "test", "python_version": "3.11.0"},
        "claims": [
            {
                "claim_id": "HC-001",
                "claim_text": "sample claim",
                "verification_method": "test_suite",
                "acceptance_threshold": "verdict = PASS",
                "test_reference": "scripts/check_claim.py",
                "category": "compatibility",
                "procedure_ref": "scripts/check_claim.py",
                "harness_kind": "python",
                "measurement_key": "verdict",
                "command": "python3 scripts/check_claim.py --json",
                "resolved_procedure_ref": "scripts/check_claim.py",
                "execution_state": "executed",
                "result_kind": "pass",
                "duration_seconds": 0.01,
                "exit_code": 0,
                "measured_value": "PASS",
                "detail": "procedure executed successfully and met threshold",
            }
        ],
        "verdict": "PASS",
        "timestamp": "2026-06-09T00:00:01Z",
        "duration_seconds": 0.01,
        "claim_count": 1,
        "passed_count": 1,
        "failed_count": 0,
        "error_count": 0,
        "skip_install": True,
        "execution_log": [finished_event],
    }


def _planned_report() -> dict:
    return {
        "schema_version": gate.REPORT_SCHEMA,
        "run_mode": "plan",
        "verdict": "PLANNED",
        "claim_count": 1,
        "claims": [
            {
                "claim_id": "HC-001",
                "execution_state": "planned",
                "result_kind": "not_run",
            }
        ],
        "timestamp": "2026-06-09T00:00:01Z",
        "execution_log": [
            {
                "timestamp": "2026-06-09T00:00:00Z",
                "phase": "planning",
                "event": "claim_planned",
                "claim_id": "HC-001",
                "result_kind": "not_run",
            }
        ],
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _loads_json_object(text: str, source: str) -> dict:
    try:
        payload = _JSON_DECODER.decode(text)
    except json.JSONDecodeError as exc:  # pragma: no cover - assertion helper
        raise AssertionError(f"invalid JSON fixture {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise AssertionError(f"JSON fixture must be an object: {source}")
    return payload


def _load_json(path: Path) -> dict:
    return _loads_json_object(path.read_text(encoding="utf-8"), str(path))


def _load_first_jsonl_row(path: Path) -> dict:
    line = path.read_text(encoding="utf-8").splitlines()[0]
    return _loads_json_object(line, f"{path}:1")


_REQUIRED_PLAN_STEP_IDS = {
    "compile_census",
    "full_conformance",
    "fuzz_smokes",
    "verifier_sdk",
    "cargo_deny",
    "cargo_fmt",
    "cargo_clippy",
    "summary",
}

_RCH_REQUIRED_PLAN_STEP_IDS = (
    "compile_census",
    "full_conformance",
    "fuzz_smokes",
    "verifier_sdk",
    "cargo_clippy",
)


def _validate_verification_plan(plan: dict) -> dict:
    if plan.get("schema_version") != "verification-plan-v1":
        raise AssertionError("unexpected verification plan schema")
    if plan.get("rch_prefix") != "rch exec --":
        raise AssertionError("unexpected verification plan rch prefix")
    if not plan.get("plan_path", "").endswith("_plan.json"):
        raise AssertionError("verification plan path must end with _plan.json")
    if not plan.get("plan_sha256_path", "").endswith("_plan.sha256"):
        raise AssertionError("verification plan digest path must end with _plan.sha256")
    if not plan["plan_path"].startswith(f"{plan['artifact_dir']}/"):
        raise AssertionError("verification plan path must live under artifact_dir")
    if not plan["plan_sha256_path"].startswith(f"{plan['artifact_dir']}/"):
        raise AssertionError("verification plan digest path must live under artifact_dir")
    if not plan.get("command_receipts_path", "").endswith("_commands.jsonl"):
        raise AssertionError("verification command receipts path must end with _commands.jsonl")
    if not plan["command_receipts_path"].startswith(f"{plan['artifact_dir']}/"):
        raise AssertionError("verification command receipts path must live under artifact_dir")

    steps = {step["id"]: step for step in plan["steps"]}
    missing = _REQUIRED_PLAN_STEP_IDS - set(steps)
    if missing:
        raise AssertionError(f"missing verification plan steps: {sorted(missing)}")

    for step_id in _RCH_REQUIRED_PLAN_STEP_IDS:
        if not steps[step_id]["heavy"]:
            raise AssertionError(f"{step_id} must be marked heavy")
        if not steps[step_id]["rch_required"]:
            raise AssertionError(f"{step_id} must require rch")

    rch_prefix = f"{plan['rch_prefix']} "
    for step in plan["steps"]:
        command = step["command"]
        if not step.get("receipt_required"):
            raise AssertionError(f"{step['id']} must require a command receipt")
        if not step.get("log_path"):
            raise AssertionError(f"{step['id']} must declare a command log path")
        if step["rch_required"] and "cargo " in command and not command.startswith(rch_prefix):
            raise AssertionError(f"{step['id']} cargo command must use rch prefix")
        if not step["rch_required"] and command.startswith(rch_prefix):
            raise AssertionError(f"{step['id']} local command must not use rch prefix")

    return steps


def _write_valid_artifacts(root: Path, report: dict) -> None:
    transcript_rel = "artifacts/tnr/reproduction_transcript.jsonl"
    metrics_rel = "artifacts/tnr/reproduction_metrics_snapshot.json"
    report["artifact_paths"] = {
        "transcript_jsonl": transcript_rel,
        "metrics_json": metrics_rel,
    }
    transcript_path = root / transcript_rel
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "schema_version": gate.TRANSCRIPT_SCHEMA,
            "event_index": index,
            "run_mode": report["run_mode"],
            "report_timestamp": report["timestamp"],
            "event": event,
        }
        for index, event in enumerate(report["execution_log"])
    ]
    transcript_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    metrics = {
        "schema_version": gate.METRICS_SCHEMA,
        "report_schema_version": gate.REPORT_SCHEMA,
        "run_mode": report["run_mode"],
        "verdict": report["verdict"],
        "timestamp": "2026-06-09T00:00:02Z",
        "report_timestamp": report["timestamp"],
        "report_digest_sha256": gate._report_digest(report),
        "claim_count": report["claim_count"],
        "passed_count": report["passed_count"],
        "failed_count": report["failed_count"],
        "error_count": report["error_count"],
        "duration_seconds": report["duration_seconds"],
        "claim_result_counts": {"pass": 1},
        "claim_category_counts": {"compatibility": 1},
        "claim_ids": ["HC-001"],
        "execution_event_count": len(report["execution_log"]),
    }
    _write_json(root / metrics_rel, metrics)


class TestReportHonesty(unittest.TestCase):
    def test_planned_report_is_allowed_only_when_explicit(self) -> None:
        report = _planned_report()
        self.assertEqual(gate.validate_report_honesty(report, allow_planned=True), [])
        errors = gate.validate_report_honesty(report, allow_planned=False)
        self.assertTrue(any("non-evidence" in error for error in errors))

    def test_planned_report_cannot_claim_pass(self) -> None:
        report = _planned_report()
        report["verdict"] = "PASS"
        errors = gate.validate_report_honesty(report, allow_planned=True)
        self.assertTrue(any("never report PASS" in error for error in errors))

    def test_pass_claim_requires_executed_transcript_event(self) -> None:
        report = _executed_pass_report()
        report["execution_log"] = []
        errors = gate.validate_report_honesty(report)
        self.assertTrue(any("matching executed transcript event" in error for error in errors))

    def test_pass_claim_requires_zero_exit(self) -> None:
        report = _executed_pass_report()
        report["claims"][0]["exit_code"] = 2
        errors = gate.validate_report_honesty(report)
        self.assertTrue(any("exit_code=0" in error for error in errors))


class TestEvidenceArtifacts(unittest.TestCase):
    def test_missing_artifacts_fail_executed_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report = _executed_pass_report()
            root = Path(tmpdir) / "no-such-root"
            errors = gate.validate_evidence_artifacts(report, project_root=root)
        self.assertIn("executed report must include artifact_paths", errors)

    def test_valid_artifacts_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report = _executed_pass_report()
            _write_valid_artifacts(root, report)
            errors = gate.validate_evidence_artifacts(report, project_root=root)
        self.assertEqual(errors, [])

    def test_metrics_digest_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report = _executed_pass_report()
            _write_valid_artifacts(root, report)
            metrics_path = root / report["artifact_paths"]["metrics_json"]
            metrics = _load_json(metrics_path)
            metrics["report_digest_sha256"] = "0" * 64
            _write_json(metrics_path, metrics)
            errors = gate.validate_evidence_artifacts(report, project_root=root)
        self.assertTrue(any("digest" in error for error in errors))

    def test_transcript_forgery_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report = _executed_pass_report()
            _write_valid_artifacts(root, report)
            transcript_path = root / report["artifact_paths"]["transcript_jsonl"]
            row = _load_first_jsonl_row(transcript_path)
            row["event"]["result_kind"] = "not_run"
            transcript_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
            errors = gate.validate_evidence_artifacts(report, project_root=root)
        self.assertTrue(any("does not match" in error for error in errors))


class TestRunChecks(unittest.TestCase):
    def test_run_checks_passes_with_valid_report_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report = _executed_pass_report()
            _write_valid_artifacts(root, report)
            report_path = root / "reproduction_report.json"
            _write_json(report_path, report)
            result = gate.run_checks(
                report_path=report_path,
                project_root=root,
                require_workflow=False,
            )
        self.assertEqual(result["verdict"], "PASS")

    def test_run_checks_fails_missing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = gate.run_checks(
                report_path=root / "missing.json",
                project_root=root,
                require_workflow=False,
            )
        self.assertEqual(result["verdict"], "FAIL")


class TestWorkflowValidation(unittest.TestCase):
    def test_workflow_markers_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workflow = Path(tmpdir) / "gate.yml"
            workflow.write_text(
                "\n".join(
                    [
                        "python3 tests/test_reproduce.py",
                        "python3 tests/test_check_tnr_ci_verification_gate.py",
                        "python3 tests/test_check_tnr_observability_contract.py",
                        "python3 scripts/check_tnr_observability_contract.py",
                        "scripts/verify_all_verification_targets.sh --selftest",
                        "python3 scripts/check_tnr_ci_verification_gate.py --allow-planned",
                        "python3 scripts/reproduce.py --skip-install --json",
                        "reproduction_transcript.jsonl",
                        "reproduction_metrics_snapshot.json",
                        "actions/upload-artifact",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(gate.validate_workflow(workflow), [])

    def test_workflow_missing_markers_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workflow = Path(tmpdir) / "gate.yml"
            workflow.write_text("name: incomplete\n", encoding="utf-8")
            errors = gate.validate_workflow(workflow)
        self.assertGreater(len(errors), 0)


class TestVerificationHarnessContract(unittest.TestCase):
    def _load_plan(self) -> dict:
        script = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "verify_all_verification_targets.sh"
        )
        result = subprocess.run(
            ["/usr/bin/bash", str(script), "--plan-json"],
            cwd=script.parent.parent,
            capture_output=True,
            check=True,
            text=True,
            timeout=10,
        )
        return _loads_json_object(result.stdout, "verify_all_verification_targets.sh --plan-json")

    def test_plan_json_lists_required_verification_steps(self) -> None:
        plan = self._load_plan()
        steps = _validate_verification_plan(plan)

        self.assertIn(
            "cargo test -p frankenengine-node --locked --features extended-surfaces,test-support",
            steps["full_conformance"]["command"],
        )
        self.assertIn("cargo +nightly fuzz run <target>", steps["fuzz_smokes"]["command"])
        self.assertIn("cargo test -p frankenengine-verifier-sdk --locked", steps["verifier_sdk"]["command"])
        self.assertEqual(steps["cargo_clippy"]["command"], "rch exec -- cargo clippy --all-targets -- -D warnings")
        self.assertEqual(steps["cargo_clippy"]["log_path"], "artifacts/verification/cargo_clippy.log")
        self.assertEqual(steps["cargo_clippy"]["report_json"], "artifacts/verification/cargo_clippy_lockfile_drift.json")
        self.assertTrue(plan["command_receipts_path"].endswith("_commands.jsonl"))
        self.assertEqual(steps["compile_census"]["log_path"], "artifacts/verification/compile_census.log")
        self.assertEqual(steps["summary"]["log_path"], plan["report_path"])

    def test_full_run_links_plan_artifact_and_digest_in_report(self) -> None:
        script = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "verify_all_verification_targets.sh"
        ).read_text(encoding="utf-8")
        for marker in (
            'PLAN_JSON="$OUT/${RUN_STEM}_plan.json"',
            'PLAN_DIGEST="$OUT/${RUN_STEM}_plan.sha256"',
            'COMMANDS_JSONL="$OUT/${RUN_STEM}_commands.jsonl"',
            'PLAN_SHA="$(write_plan_artifact)"',
            "append_plan_summary",
            "append_command_summary",
            'echo "plan: $PLAN_JSON"',
            'echo "sha256_file: $PLAN_DIGEST"',
            'echo "sha256: $PLAN_SHA"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, script)

    def test_plan_validation_rejects_missing_required_steps(self) -> None:
        plan = self._load_plan()
        for missing_step in ("cargo_clippy", "full_conformance"):
            with self.subTest(missing_step=missing_step):
                mutated = {
                    **plan,
                    "steps": [step for step in plan["steps"] if step["id"] != missing_step],
                }
                with self.assertRaisesRegex(AssertionError, missing_step):
                    _validate_verification_plan(mutated)

    def test_full_run_keeps_guarded_deny_fmt_and_clippy_gates(self) -> None:
        script = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "verify_all_verification_targets.sh"
        ).read_text(encoding="utf-8")
        for marker in (
            '"cargo deny check advisories bans sources"',
            '"cargo fmt --check -p frankenengine-node"',
            '"cargo clippy --all-targets -- -D warnings"',
            '"$OUT/cargo_deny_lockfile_drift.json"',
            '"$OUT/cargo_fmt_lockfile_drift.json"',
            '"$OUT/cargo_clippy_lockfile_drift.json"',
            '"$OUT/cargo_clippy.log"',
            "$RCH cargo clippy --all-targets -- -D warnings",
            '"cargo_clippy" \\',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, script)


if __name__ == "__main__":
    unittest.main()
