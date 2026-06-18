"""Unit tests for scripts/check_swarm_validation_evidence_pack.py."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess  # nosec B404 - fixed-argv CLI smoke tests with no shell.
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_swarm_validation_evidence_pack.py"

spec = importlib.util.spec_from_file_location("check_swarm_validation_evidence_pack", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
if spec.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
spec.loader.exec_module(mod)

JSON_DECODER = json.JSONDecoder()


def fixture_root() -> tuple[Path, Path, tempfile.TemporaryDirectory[str]]:
    tmpdir = tempfile.TemporaryDirectory()
    root = Path(tmpdir.name)
    transcript_path = mod._materialize_self_test_fixture(root)
    return root, transcript_path, tmpdir


def read_rows(path: Path) -> list[dict[str, object]]:
    return [JSON_DECODER.decode(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_rows(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )


class SwarmValidationEvidencePackTests(unittest.TestCase):
    def test_valid_green_coalesced_deferred_blocked_and_handoff_passes(self) -> None:
        root, transcript_path, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)

        result = mod.run_checks(root, transcript_path, expected_bead_id=mod.CHECK_BEAD_ID)

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(result["summary"]["decisions"]["run"], 1)
        self.assertEqual(result["summary"]["decisions"]["coalesce"], 1)
        self.assertEqual(result["summary"]["decisions"]["defer"], 1)
        self.assertEqual(result["summary"]["decisions"]["blocked"], 1)
        self.assertEqual(result["summary"]["decisions"]["handoff"], 1)

    def test_missing_bead_id_fails_closed(self) -> None:
        result = self._mutated_result(lambda rows: rows[0].pop("bead_id"))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MALFORMED_ROW", self._failures(result))

    def test_missing_thread_id_fails_closed(self) -> None:
        result = self._mutated_result(lambda rows: rows[0].pop("thread_id"))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MALFORMED_ROW", self._failures(result))

    def test_thread_id_must_match_bead_id(self) -> None:
        result = self._mutated_result(lambda rows: rows[0].__setitem__("thread_id", "bd-other"))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_THREAD_BEAD_MISMATCH", self._failures(result))

    def test_missing_rch_command_for_run_fails_closed(self) -> None:
        result = self._mutated_result(lambda rows: rows[0].__setitem__("command", None))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MISSING_RCH_COMMAND", self._failures(result))

    def test_bare_cargo_command_fails_closed(self) -> None:
        result = self._mutated_result(
            lambda rows: rows[0].__setitem__(
                "command",
                "cargo test -p frankenengine-node swarm_validation_admission",
            )
        )
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_UNSAFE_LOCAL_CARGO", self._failures(result))

    def test_missing_reason_code_fails_closed(self) -> None:
        result = self._mutated_result(lambda rows: rows[0].__setitem__("reason_code", ""))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MISSING_REASON_CODE", self._failures(result))

    def test_missing_proof_key_for_run_fails_closed(self) -> None:
        result = self._mutated_result(lambda rows: rows[0].__setitem__("proof_key", None))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MISSING_PROOF_KEY", self._failures(result))

    def test_missing_proof_key_for_coalesce_fails_closed(self) -> None:
        result = self._mutated_result(lambda rows: rows[1].__setitem__("proof_key", None))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MISSING_PROOF_KEY", self._failures(result))

    def test_blocked_without_evidence_fails_closed(self) -> None:
        def mutate(rows: list[dict[str, object]]) -> None:
            rows[3]["reservation_evidence"] = []
            rows[3]["build_slot_evidence"] = []

        result = self._mutated_result(mutate)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_UNDOCUMENTED_BLOCKER", self._failures(result))

    def test_defer_without_retry_after_fails_closed(self) -> None:
        result = self._mutated_result(lambda rows: rows[2].__setitem__("retry_after_ms", None))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_UNDOCUMENTED_BLOCKER", self._failures(result))

    def test_malformed_jsonl_fails_closed(self) -> None:
        root, transcript_path, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        transcript_path.write_text("{not-json\n", encoding="utf-8")

        result = mod.run_checks(root, transcript_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MALFORMED_JSONL", self._failures(result))

    def test_missing_transcript_fails_closed(self) -> None:
        root, _transcript_path, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)

        result = mod.run_checks(root, Path("missing.jsonl"))

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_MISSING_TRANSCRIPT", self._failures(result))

    def test_path_outside_root_fails_closed(self) -> None:
        root, _transcript_path, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)

        result = mod.run_checks(root, Path("../outside.jsonl"))

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("ERR_SVEP_PATH_OUTSIDE_ROOT", self._failures(result))

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
        self.assertEqual(payload["verdict"], "PASS", payload)
        self.assertEqual(payload["contract_result"]["verdict"], "PASS", self._failures(payload["contract_result"]))

    def test_cli_transcript_json_passes(self) -> None:
        root, transcript_path, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)

        proc = subprocess.run(  # nosec B603
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--json",
                "--root",
                str(root),
                "--transcript",
                str(transcript_path),
                "--expected-bead-id",
                mod.CHECK_BEAD_ID,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))

    def _mutated_result(self, mutate) -> dict[str, object]:
        root, transcript_path, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        rows = copy.deepcopy(read_rows(transcript_path))
        mutate(rows)
        write_rows(transcript_path, rows)
        return mod.run_checks(root, transcript_path, expected_bead_id=mod.CHECK_BEAD_ID)

    @staticmethod
    def _failures(result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
