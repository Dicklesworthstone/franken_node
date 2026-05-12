"""Unit tests for check_control_channel.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_control_channel.py"
VECTORS_PATH = ROOT / "artifacts/section_10_13/bd-v97o/control_channel_replay_vectors.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-v97o/verification_evidence.json"
REPLACEMENT_EVIDENCE_PATH = ROOT / "artifacts/replacement_gap/bd-3cvu/verification_evidence.json"
OPERATOR_SUMMARY_PATH = ROOT / "artifacts/replacement_gap/bd-3cvu/operator_e2e_summary.json"
OPERATOR_LOG_PATH = ROOT / "artifacts/replacement_gap/bd-3cvu/operator_e2e_log.jsonl"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestControlChannelVectors(unittest.TestCase):

    def test_vectors_exist(self):
        self.assertTrue(VECTORS_PATH.is_file())

    def test_vectors_valid_json(self):
        data = decode_json_object(VECTORS_PATH.read_text(encoding="utf-8"))
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 3)


class TestControlChannelImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/control_channel.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_channel_config(self):
        self.assertIn("struct ChannelConfig", self.content)

    def test_has_channel_message(self):
        self.assertIn("struct ChannelMessage", self.content)

    def test_has_control_channel(self):
        self.assertIn("struct ControlChannel", self.content)

    def test_has_process_message(self):
        self.assertIn("fn process_message", self.content)

    def test_has_all_error_codes(self):
        for code in ["ACC_AUTH_FAILED", "ACC_SEQUENCE_REGRESS", "ACC_REPLAY_DETECTED",
                     "ACC_INVALID_CONFIG", "ACC_CHANNEL_CLOSED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_transcript_bound_markers(self):
        for marker in [
            "struct ChannelCredential",
            "TRANSCRIPT_HMAC_PREFIX",
            "sign_channel_message",
            "verify_transcript_mac",
            "constant_time::ct_eq_bytes",
            "regression_non_empty_string_is_not_sufficient",
        ]:
            self.assertIn(marker, self.content, f"Missing marker {marker}")


class TestControlChannelSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-v97o_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-ACC-AUTHENTICATED", "INV-ACC-MONOTONIC",
                    "INV-ACC-REPLAY-WINDOW", "INV-ACC-AUDITABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestControlChannelIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/control_channel_replay.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_authenticated(self):
        self.assertIn("inv_acc_authenticated", self.content)

    def test_covers_monotonic(self):
        self.assertIn("inv_acc_monotonic", self.content)

    def test_covers_replay_window(self):
        self.assertIn("inv_acc_replay_window", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_acc_auditable", self.content)


class TestControlChannelOperatorE2E(unittest.TestCase):

    def test_operator_summary_passes(self):
        data = decode_json_object(OPERATOR_SUMMARY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["passed_scenarios"], 4)

    def test_operator_log_covers_required_scenarios(self):
        rows = [
            decode_json_object(line)
            for line in OPERATOR_LOG_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        scenarios = {row["scenario"] for row in rows}
        for scenario in [
            "valid_control_traffic",
            "guessed_token_injection_failure",
            "replay_failure_after_restart_boundary",
            "capability_attenuation_failure",
        ]:
            self.assertIn(scenario, scenarios)
        for row in rows:
            for field in [
                "trace_id",
                "event",
                "decision",
                "reason_code",
                "retryable",
                "channel_id",
                "subject_id",
                "audience",
                "direction",
                "sequence",
                "freshness_state",
            ]:
                self.assertIn(field, row)


class TestControlChannelCli(unittest.TestCase):

    def test_json_mode_is_structural_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "control_channel_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["ACC-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-v97o:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(before, after)


class TestCompletionDebtEvidence(unittest.TestCase):

    def test_completion_debt_evidence_records_all_missing_items(self):
        data = decode_json_object(REPLACEMENT_EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["bead_id"], "bd-3cvu")
        self.assertEqual(data["completion_debt_bead_id"], "bd-3cvu.1")
        covered = set(data["completion_debt"]["covered_spec_items"])
        self.assertTrue({"tests.unit.primary", "tests.integration.primary", "tests.e2e.primary"} <= covered)

    def test_checker_reports_completion_debt_checks(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        check_ids = {check["id"] for check in evidence["checks"]}
        self.assertIn("ACC-COMPLETION-EVIDENCE", check_ids)
        self.assertIn("ACC-E2E-LOG", check_ids)


if __name__ == "__main__":
    unittest.main()
