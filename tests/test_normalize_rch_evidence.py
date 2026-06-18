"""Unit tests for scripts/normalize_rch_evidence.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess  # nosec B404 - fixed-argv CLI smoke tests with no shell.
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "normalize_rch_evidence.py"

spec = importlib.util.spec_from_file_location("normalize_rch_evidence", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
if spec.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

JSON_DECODER = json.JSONDecoder()


class NormalizeRchEvidenceTests(unittest.TestCase):
    def test_self_test_fixtures_cover_required_classes(self) -> None:
        result = mod.run_checks(mod._self_test_records())

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        counts = result["summary"]["class_counts"]
        self.assertEqual(counts["ssh_timeout"], 1)
        self.assertEqual(counts["stale_progress"], 1)
        self.assertEqual(counts["dependency_resolver_error"], 1)
        self.assertEqual(counts["product_failure"], 1)
        self.assertEqual(counts["success"], 1)

    def test_ssh_timeout_preserves_worker_command_and_first_blocker(self) -> None:
        text = (
            "Exact command: rch exec -- cargo clippy --all-targets -- -D warnings\n"
            "build 29750734287276250 selected worker vmi1156319\n"
            "[RCH-E104] SSH command timed out (no local fallback)\n"
            "[RCH] remote vmi1156319 (1800.0s)\n"
        )

        record = mod.normalize_text(text, sample_id="ssh-timeout")

        self.assertEqual(record["classification"], "ssh_timeout")
        self.assertEqual(record["worker_id"], "vmi1156319")
        self.assertEqual(record["job_id"], "29750734287276250")
        self.assertEqual(record["command"], "rch exec -- cargo clippy --all-targets -- -D warnings")
        self.assertEqual(record["first_blocker"], "[RCH-E104] SSH command timed out (no local fallback)")
        self.assertFalse(record["product_diagnostics_reached"])
        self.assertTrue(record["retry_recommended"])
        self.assertIn("first_blocker: [RCH-E104] SSH command timed out", record["beads_comment"])

    def test_fresh_heartbeat_stale_progress_is_retryable_infra(self) -> None:
        text = (
            "Exact command: rch exec -- cargo test -p frankenengine-node validation_proof_cache\n"
            "job_id=29750734287276251 worker=vmi1167313 last_phase=remote_exec_start\n"
            "fresh heartbeat but no output for 900s; progress stale before wall timeout\n"
            "cancelled locally after stale detector marked progress stale\n"
        )

        record = mod.normalize_text(text, sample_id="stale-progress")

        self.assertEqual(record["classification"], "stale_progress")
        self.assertEqual(record["reason_code"], "RCH_STALE_PROGRESS")
        self.assertEqual(record["worker_id"], "vmi1167313")
        self.assertTrue(record["retry_recommended"])
        self.assertTrue(record["cancellation_observed"])
        self.assertFalse(record["product_diagnostics_reached"])
        self.assertIn("fresh heartbeat but no output", record["first_blocker"])

    def test_dependency_resolver_error_is_product_diagnostic_not_retry(self) -> None:
        text = (
            "Exact command: rch exec -- cargo test -p frankenengine-node\n"
            "error: failed to select a version for `getrandom`.\n"
            "required by package `fsqlite-ext-misc v0.1.0 (/dp/frankensqlite/crates/fsqlite-ext-misc)`\n"
        )

        record = mod.normalize_text(text, sample_id="resolver")

        self.assertEqual(record["classification"], "dependency_resolver_error")
        self.assertTrue(record["product_diagnostics_reached"])
        self.assertFalse(record["retry_recommended"])
        self.assertEqual(record["recommended_action"], "fix_product_failure")
        self.assertEqual(record["first_blocker"], "error: failed to select a version for `getrandom`.")

    def test_compile_error_is_product_failure(self) -> None:
        text = (
            "Exact command: rch exec -- cargo check --all-targets\n"
            "error[E0599]: no method named `emit_receipt` found for struct `ValidationBroker`\n"
        )

        record = mod.normalize_text(text, sample_id="compile")

        self.assertEqual(record["classification"], "product_failure")
        self.assertTrue(record["product_diagnostics_reached"])
        self.assertFalse(record["retry_recommended"])
        self.assertEqual(
            record["first_blocker"],
            "error[E0599]: no method named `emit_receipt` found for struct `ValidationBroker`",
        )

    def test_clean_success_has_no_blocker_but_preserves_schema_fields(self) -> None:
        text = (
            "Exact command: rch exec -- cargo test -p frankenengine-node doctor_policy_activation_e2e\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        )

        record = mod.normalize_text(text, sample_id="success")
        result = mod.run_checks([record])

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(record["classification"], "success")
        self.assertIsNone(record["first_blocker"])
        self.assertFalse(record["retry_recommended"])
        self.assertEqual(record["recommended_action"], "use_receipt")

    def test_missing_command_fails_closed(self) -> None:
        record = mod.normalize_text("[RCH-E104] SSH command timed out (no local fallback)", sample_id="missing-command")

        result = mod.run_checks([record])

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("commands-preserved", self._failures(result))

    def test_cli_self_test_json_passes(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))
        self.assertEqual(payload["summary"]["record_count"], 5)

    def test_cli_input_file_accepts_default_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rch.log"
            path.write_text("[RCH-E104] SSH command timed out (no local fallback)\n", encoding="utf-8")
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--input",
                    str(path),
                    "--command",
                    "rch exec -- cargo check --all-targets",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = JSON_DECODER.decode(proc.stdout)
        record = payload["records"][0]
        self.assertEqual(record["classification"], "ssh_timeout")
        self.assertEqual(record["command"], "rch exec -- cargo check --all-targets")

    @staticmethod
    def _failures(result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
