#!/usr/bin/env python3
"""Unit tests for scripts/reproduce.py."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import reproduce


def _write_claims(path: Path, procedure_ref: str, extra_fields: str = "") -> None:
    path.write_text(
        textwrap.dedent(
            f"""
            [[claim]]
            claim_id = "HC-001"
            claim_text = "sample claim"
            verification_method = "test_suite"
            acceptance_threshold = "verdict = PASS"
            test_reference = "{procedure_ref}"
            category = "compatibility"
            procedure_ref = "{procedure_ref}"
            harness_kind = "python"
            measurement_key = "verdict"
            {extra_fields}
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def _write_python_procedure(path: Path, payload: dict[str, object], exit_code: int = 0) -> None:
    path.write_text(
        textwrap.dedent(
            f"""
            #!/usr/bin/env python3
            import json
            import sys

            print(json.dumps({json.dumps(payload)}))
            sys.exit({exit_code})
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def _write_raw_claims(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def _copy_reproduce_script(root: Path) -> Path:
    scripts_dir = root / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    target = scripts_dir / "reproduce.py"
    shutil.copy2(Path(reproduce.__file__), target)
    return target


def _run_reproduce_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, str(root / "scripts" / "reproduce.py"), *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _load_cli_json(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - assertion helper
        raise AssertionError(f"CLI did not emit valid JSON: {exc}\nstdout={result.stdout}") from exc
    return payload


class TestReproductionHelpers(unittest.TestCase):
    def test_missing_claims_file_returns_empty_claim_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing-claims.toml"
            self.assertEqual(reproduce._parse_claims_toml(missing), [])

    def test_boolean_threshold_literals_are_coerced(self) -> None:
        self.assertIs(reproduce._coerce_threshold_value("true"), True)
        self.assertIs(reproduce._coerce_threshold_value("false"), False)


class TestReproductionRunner(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.claims_path = self.root / "claims.toml"
        self.report_path = self.root / "report.json"
        self.procedure_path = self.root / "check_claim.py"

    def _patch_paths(self):
        return patch.multiple(
            reproduce,
            ROOT=self.root,
            CLAIMS_PATH=self.claims_path,
            REPORT_PATH=self.report_path,
        )

    def test_dry_run_uses_plan_schema(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths():
            report = reproduce.run_reproduction(dry_run=True)

        self.assertEqual(report["schema_version"], reproduce.SCHEMA_VERSION)
        self.assertEqual(report["run_mode"], "plan")
        self.assertEqual(report["verdict"], "PLANNED")
        self.assertEqual(report["claim_count"], 1)
        self.assertEqual(report["claims"][0]["execution_state"], "planned")
        self.assertEqual(report["claims"][0]["result_kind"], "not_run")
        self.assertIn("command", report["claims"][0])
        self.assertEqual(report["claims"][0]["resolved_procedure_ref"], "check_claim.py")
        self.assertTrue(report["execution_log"])
        self.assertTrue(
            any(event["event"] == "claim_planned" for event in report["execution_log"])
        )

    def test_executed_claim_passes_when_procedure_passes(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ):
            report = reproduce.run_reproduction()

        self.assertEqual(report["run_mode"], "executed")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["passed_count"], 1)
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["error_count"], 0)
        claim = report["claims"][0]
        self.assertEqual(claim["execution_state"], "executed")
        self.assertEqual(claim["result_kind"], "pass")
        self.assertEqual(claim["measured_value"], "PASS")
        self.assertEqual(claim["resolved_procedure_ref"], "check_claim.py")
        self.assertTrue(self.report_path.is_file())
        self.assertTrue(
            any(
                event["event"] == "claim_execution_finished"
                and event.get("result_kind") == "pass"
                for event in report["execution_log"]
            )
        )

    def test_executed_claim_fails_when_procedure_reports_fail(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "FAIL"}, exit_code=1)
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ):
            report = reproduce.run_reproduction()

        self.assertEqual(report["verdict"], "FAIL")
        claim = report["claims"][0]
        self.assertEqual(claim["execution_state"], "executed")
        self.assertEqual(claim["result_kind"], "fail")
        self.assertEqual(claim["measured_value"], "FAIL")
        self.assertEqual(claim["exit_code"], 1)

    def test_non_zero_exit_with_passing_payload_is_error(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"}, exit_code=2)
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ):
            report = reproduce.run_reproduction()

        self.assertEqual(report["verdict"], "ERROR")
        claim = report["claims"][0]
        self.assertEqual(claim["execution_state"], "executed")
        self.assertEqual(claim["result_kind"], "error")
        self.assertIn("exited non-zero", claim["detail"])

    def test_missing_mapping_fields_becomes_error(self) -> None:
        _write_raw_claims(
            self.claims_path,
            """
            [[claim]]
            claim_id = "HC-001"
            claim_text = "sample claim"
            verification_method = "test_suite"
            acceptance_threshold = "verdict = PASS"
            test_reference = "scripts/check_claim.py"
            category = "compatibility"
            """,
        )
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ):
            report = reproduce.run_reproduction()

        self.assertEqual(report["verdict"], "ERROR")
        claim = report["claims"][0]
        self.assertEqual(claim["execution_state"], "error")
        self.assertEqual(claim["result_kind"], "error")
        self.assertIn("missing mapping fields", claim["detail"])
        self.assertTrue(
            any(
                event["event"] == "claim_execution_finished"
                and event.get("result_kind") == "error"
                for event in report["execution_log"]
            )
        )

    def test_unknown_claim_filter_returns_error_report(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths():
            report = reproduce.run_reproduction(claim_filter="HC-999")

        self.assertEqual(report["verdict"], "ERROR")
        self.assertEqual(report["claim_count"], 0)
        self.assertEqual(report["error"], "unknown claim id: HC-999")

    def test_timeout_becomes_error(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        timeout = subprocess.TimeoutExpired(
            cmd=[sys.executable, str(self.procedure_path), "--json"],
            timeout=5,
        )
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ), patch.object(reproduce.subprocess, "run", side_effect=timeout):
            report = reproduce.run_reproduction(timeout_seconds=5)

        self.assertEqual(report["verdict"], "ERROR")
        claim = report["claims"][0]
        self.assertEqual(claim["result_kind"], "error")
        self.assertIn("timed out", claim["detail"])


class TestReproductionCliE2E(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        (self.root / "docs").mkdir(parents=True, exist_ok=True)
        (self.root / "scripts").mkdir(parents=True, exist_ok=True)
        _copy_reproduce_script(self.root)
        self.claims_path = self.root / "docs" / "headline_claims.toml"
        self.procedure_path = self.root / "scripts" / "check_claim.py"

    def test_cli_dry_run_json_keeps_planned_semantics(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, "scripts/check_claim.py")

        result = _run_reproduce_cli(self.root, "--dry-run", "--json")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = _load_cli_json(result)
        self.assertEqual(payload["run_mode"], "plan")
        self.assertEqual(payload["verdict"], "PLANNED")
        self.assertEqual(payload["claims"][0]["execution_state"], "planned")
        self.assertEqual(payload["claims"][0]["result_kind"], "not_run")
        self.assertEqual(payload["claims"][0]["resolved_procedure_ref"], "scripts/check_claim.py")
        self.assertTrue(
            any(event["event"] == "claim_planned" for event in payload["execution_log"])
        )

    def test_cli_harness_failure_returns_error_without_passing_verdict(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"}, exit_code=2)
        _write_claims(self.claims_path, "scripts/check_claim.py")

        result = _run_reproduce_cli(self.root, "--json")

        self.assertEqual(result.returncode, 1)
        payload = _load_cli_json(result)
        self.assertEqual(payload["verdict"], "ERROR")
        claim = payload["claims"][0]
        self.assertEqual(claim["execution_state"], "executed")
        self.assertEqual(claim["result_kind"], "error")
        self.assertIn("exited non-zero", claim["detail"])

    def test_cli_missing_mapping_surfaces_explicit_error(self) -> None:
        _write_raw_claims(
            self.claims_path,
            """
            [[claim]]
            claim_id = "HC-001"
            claim_text = "sample claim"
            verification_method = "test_suite"
            acceptance_threshold = "verdict = PASS"
            test_reference = "scripts/check_claim.py"
            category = "compatibility"
            """,
        )

        result = _run_reproduce_cli(self.root, "--json")

        self.assertEqual(result.returncode, 1)
        payload = _load_cli_json(result)
        self.assertEqual(payload["verdict"], "ERROR")
        claim = payload["claims"][0]
        self.assertEqual(claim["result_kind"], "error")
        self.assertIn("missing mapping fields", claim["detail"])

    def test_cli_verbose_human_output_prints_command_and_detail(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "FAIL"}, exit_code=1)
        _write_claims(self.claims_path, "scripts/check_claim.py")

        result = _run_reproduce_cli(self.root, "--verbose")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Reproduction verdict: FAIL", result.stdout)
        self.assertIn("command:", result.stdout)
        self.assertIn("resolved_procedure_ref:", result.stdout)
        self.assertIn("execution_state: executed", result.stdout)
        self.assertIn("detail:", result.stdout)
