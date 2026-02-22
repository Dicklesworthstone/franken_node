#!/usr/bin/env python3
"""Regression tests for transplant lockfile generation and verification scripts."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GENERATE_SCRIPT = ROOT / "transplant" / "generate_lockfile.sh"
VERIFY_SCRIPT = ROOT / "transplant" / "verify_lockfile.sh"


class TransplantLockfileScriptsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.work = Path(self.tmpdir.name)
        self.snapshot = self.work / "snapshot"
        self.snapshot.mkdir(parents=True, exist_ok=True)

        (self.snapshot / "alpha.txt").write_text("alpha\n", encoding="utf-8")
        (self.snapshot / "nested").mkdir(parents=True, exist_ok=True)
        (self.snapshot / "nested" / "beta.txt").write_text("beta\n", encoding="utf-8")

        self.manifest = self.work / "manifest.txt"
        # Intentionally unsorted to verify canonical ordering in output.
        self.manifest.write_text(
            "# comment line\n"
            "nested/beta.txt\n"
            "alpha.txt\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _run_generate(self, output_path: Path) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [
                str(GENERATE_SCRIPT),
                "--snapshot-dir",
                str(self.snapshot),
                "--manifest",
                str(self.manifest),
                "--source-root",
                "/tmp/upstream",
                "--output",
                str(output_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"generate_lockfile failed\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )
        return result

    def _run_verify(self, lockfile_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(VERIFY_SCRIPT),
                "--json",
                "--lockfile",
                str(lockfile_path),
                "--snapshot-dir",
                str(self.snapshot),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_generate_is_deterministic_for_equivalent_inputs(self) -> None:
        lockfile_one = self.work / "lockfile_one.sha256"
        lockfile_two = self.work / "lockfile_two.sha256"

        self._run_generate(lockfile_one)
        self._run_generate(lockfile_two)

        self.assertEqual(lockfile_one.read_bytes(), lockfile_two.read_bytes())

        text = lockfile_one.read_text(encoding="utf-8")
        self.assertIn("# generated_utc: 1970-01-01T00:00:00Z", text)
        self.assertIn("# entries: 2", text)

        entries = [
            line
            for line in text.splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(entries, sorted(entries))

    def test_verify_passes_on_clean_snapshot(self) -> None:
        lockfile = self.work / "lockfile.sha256"
        self._run_generate(lockfile)

        result = self._run_verify(lockfile)
        self.assertEqual(
            result.returncode,
            0,
            msg=f"verify_lockfile should pass\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["mismatched"], 0)
        self.assertEqual(payload["missing"], 0)
        self.assertEqual(payload["extra"], 0)

    def test_verify_reports_mismatch_missing_and_extra(self) -> None:
        lockfile = self.work / "lockfile.sha256"
        self._run_generate(lockfile)

        (self.snapshot / "alpha.txt").write_text("tampered\n", encoding="utf-8")
        (self.snapshot / "nested" / "beta.txt").unlink()
        (self.snapshot / "extra.txt").write_text("extra\n", encoding="utf-8")

        result = self._run_verify(lockfile)
        self.assertEqual(
            result.returncode,
            1,
            msg=f"verify_lockfile should fail\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )

        payload = json.loads(result.stdout)
        self.assertIn(payload["verdict"], {"FAIL:MISMATCH", "FAIL:MISSING", "FAIL:EXTRA"})
        self.assertGreaterEqual(payload["mismatched"], 1)
        self.assertGreaterEqual(payload["missing"], 1)
        self.assertGreaterEqual(payload["extra"], 1)
        self.assertIn("mismatch", payload["failing_categories"])
        self.assertIn("missing", payload["failing_categories"])
        self.assertIn("extra", payload["failing_categories"])

    def test_generate_rejects_invalid_generated_utc(self) -> None:
        output = self.work / "bad_utc_lockfile.sha256"
        result = subprocess.run(
            [
                str(GENERATE_SCRIPT),
                "--snapshot-dir",
                str(self.snapshot),
                "--manifest",
                str(self.manifest),
                "--source-root",
                "/tmp/upstream",
                "--output",
                str(output),
                "--generated-utc",
                "not-a-timestamp",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--generated-utc must be ISO-8601 UTC", result.stderr)
        self.assertFalse(output.exists())

    def test_generate_fails_when_manifest_lists_missing_file(self) -> None:
        output = self.work / "partial_lockfile.sha256"
        missing_manifest = self.work / "manifest_with_missing.txt"
        missing_manifest.write_text(
            "alpha.txt\nmissing.txt\n",
            encoding="utf-8",
        )

        result = subprocess.run(
            [
                str(GENERATE_SCRIPT),
                "--snapshot-dir",
                str(self.snapshot),
                "--manifest",
                str(missing_manifest),
                "--source-root",
                "/tmp/upstream",
                "--output",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing partial lockfile generation", result.stderr)
        self.assertFalse(output.exists())

    def test_verify_reports_parse_error_for_malformed_entry(self) -> None:
        lockfile = self.work / "lockfile_parse_fail.sha256"
        self._run_generate(lockfile)

        with lockfile.open("a", encoding="utf-8") as handle:
            handle.write("this-is-not-a-valid-sha256-entry\n")

        result = self._run_verify(lockfile)
        self.assertEqual(
            result.returncode,
            1,
            msg=f"verify_lockfile should fail on parse errors\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "FAIL:PARSE")
        self.assertGreaterEqual(payload["parse_errors"], 1)
        self.assertIn("parse", payload["failing_categories"])
        self.assertIn(
            "this-is-not-a-valid-sha256-entry",
            payload["details"]["parse_error_lines"],
        )

    def test_verify_reports_count_mismatch_for_bad_header(self) -> None:
        lockfile = self.work / "lockfile_count_fail.sha256"
        self._run_generate(lockfile)

        lines = lockfile.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if line.startswith("# entries:"):
                lines[index] = "# entries: 999"
                break
        lockfile.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = self._run_verify(lockfile)
        self.assertEqual(
            result.returncode,
            1,
            msg=f"verify_lockfile should fail on header count mismatch\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "FAIL:COUNT")
        self.assertEqual(payload["count_mismatch"], 1)
        self.assertIn("count", payload["failing_categories"])


if __name__ == "__main__":
    unittest.main()
