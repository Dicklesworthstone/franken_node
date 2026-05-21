"""Unit tests for scripts/render_perf_test_summary.py (bd-98xo5.15.2).

These tests exercise the consumer-side renderer against synthetic
JSONL fixtures that mimic the canonical schema from
`scripts/run_perf_bead_test.sh` (see docs/dev/perf_bead_testing.md).
The fixtures live inline rather than in test data files so the
schema contract is visible directly next to the assertions.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/render_perf_test_summary.py"

PASSING_LOG = "\n".join(
    [
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:31.118Z",
                "level": "info",
                "event_code": "TEST-START",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "build",
                "test_name": None,
                "duration_ms": 0,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:31.300Z",
                "level": "info",
                "event_code": "BUILD-START",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "build",
                "test_name": "cargo build --profile release-perf",
                "duration_ms": 0,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.300Z",
                "level": "info",
                "event_code": "BUILD-DONE",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "build",
                "test_name": "cargo build --profile release-perf",
                "duration_ms": 3000,
                "extra": {"exit_code": 0},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.350Z",
                "level": "info",
                "event_code": "TEST-PASS",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "build",
                "test_name": "cargo build --profile release-perf",
                "duration_ms": 3000,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.400Z",
                "level": "info",
                "event_code": "TEST-SUMMARY",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "build",
                "test_name": None,
                "duration_ms": 3050,
                "extra": {"passed": 1, "failed": 0, "skipped": 0, "total": 1},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.500Z",
                "level": "info",
                "event_code": "TEST-START",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "unit",
                "test_name": None,
                "duration_ms": 0,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.600Z",
                "level": "info",
                "event_code": "TEST-CASE",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "unit",
                "test_name": "preparsed_signer_byte_identical",
                "duration_ms": 0,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.742Z",
                "level": "info",
                "event_code": "TEST-PASS",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "unit",
                "test_name": "preparsed_signer_byte_identical",
                "duration_ms": 142,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.800Z",
                "level": "info",
                "event_code": "TEST-SUMMARY",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "unit",
                "test_name": None,
                "duration_ms": 200,
                "extra": {"passed": 1, "failed": 0, "skipped": 0, "total": 1},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:34.900Z",
                "level": "info",
                "event_code": "PERF-MEASUREMENT",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-abc-1234",
                "phase": "baseline",
                "test_name": "preparsed_sign_p95_us",
                "duration_ms": 0,
                "extra": {
                    "metric": "preparsed_sign_p95_us",
                    "value": 25.12,
                    "unit": "microseconds",
                    "target": 30.0,
                    "baseline": 45.69,
                },
            }
        ),
    ]
)

FAILING_LOG = "\n".join(
    [
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:31.118Z",
                "level": "info",
                "event_code": "TEST-START",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-xyz-5678",
                "phase": "unit",
                "test_name": None,
                "duration_ms": 0,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:31.300Z",
                "level": "info",
                "event_code": "TEST-CASE",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-xyz-5678",
                "phase": "unit",
                "test_name": "broken_test",
                "duration_ms": 0,
                "extra": {},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:31.500Z",
                "level": "error",
                "event_code": "TEST-FAIL",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-xyz-5678",
                "phase": "unit",
                "test_name": "broken_test",
                "duration_ms": 200,
                "extra": {"failure_reason": "assertion failed", "stderr_tail": "foo\nbar"},
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-05-21T05:42:31.600Z",
                "level": "info",
                "event_code": "TEST-SUMMARY",
                "bead_id": "bd-98xo5.X.tests",
                "trace_id": "trace-xyz-5678",
                "phase": "unit",
                "test_name": None,
                "duration_ms": 300,
                "extra": {"passed": 0, "failed": 1, "skipped": 0, "total": 1},
            }
        ),
    ]
)


def _run_renderer(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class TestRenderPerfTestSummary(unittest.TestCase):
    def test_passing_log_human_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            log.write_text(PASSING_LOG)
            result = _run_renderer(str(log))
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("bd-98xo5.X.tests", result.stdout)
            self.assertIn("PASS", result.stdout)
            self.assertIn("build", result.stdout)
            self.assertIn("unit", result.stdout)
            self.assertIn("preparsed_sign_p95_us", result.stdout)
            self.assertIn("baseline 45.69", result.stdout)

    def test_passing_log_ci_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            log.write_text(PASSING_LOG)
            result = _run_renderer("--ci", str(log))
            self.assertEqual(result.returncode, 0)
            self.assertIn("PASS", result.stdout)

    def test_failing_log_ci_mode_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            log.write_text(FAILING_LOG)
            result = _run_renderer("--ci", str(log))
            self.assertEqual(result.returncode, 1)
            self.assertIn("FAIL", result.stdout)

    def test_json_mode_emits_machine_readable_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            log.write_text(PASSING_LOG)
            result = _run_renderer("--json", str(log))
            self.assertEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["bead_id"], "bd-98xo5.X.tests")
            self.assertEqual(payload["verdict"], "PASS")
            phases = {p["phase"]: p for p in payload["phases"]}
            self.assertEqual(phases["build"]["passed"], 1)
            self.assertEqual(phases["unit"]["failed"], 0)
            metrics = [m["metric"] for m in payload["measurements"]]
            self.assertIn("preparsed_sign_p95_us", metrics)

    def test_malformed_jsonl_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            log.write_text("{not json")
            result = _run_renderer(str(log))
            self.assertEqual(result.returncode, 2)
            self.assertIn("schema error", result.stderr)

    def test_missing_required_field_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            # Drop the "extra" field.
            bad_line = json.dumps(
                {
                    "timestamp": "2026-05-21T05:42:31.118Z",
                    "level": "info",
                    "event_code": "TEST-START",
                    "bead_id": "bd-98xo5.X.tests",
                    "trace_id": "trace-abc",
                    "phase": "build",
                    "test_name": None,
                    "duration_ms": 0,
                }
            )
            log.write_text(bad_line)
            result = _run_renderer(str(log))
            self.assertEqual(result.returncode, 2)
            self.assertIn("missing required fields", result.stderr)

    def test_unknown_event_code_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            bad_line = json.dumps(
                {
                    "timestamp": "2026-05-21T05:42:31.118Z",
                    "level": "info",
                    "event_code": "NOT-A-REAL-EVENT",
                    "bead_id": "bd-98xo5.X.tests",
                    "trace_id": "trace-abc",
                    "phase": "build",
                    "test_name": None,
                    "duration_ms": 0,
                    "extra": {},
                }
            )
            log.write_text(bad_line)
            result = _run_renderer(str(log))
            self.assertEqual(result.returncode, 2)
            self.assertIn("unknown event_code", result.stderr)

    def test_mismatched_trace_id_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            log.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "timestamp": "2026-05-21T05:42:31.118Z",
                                "level": "info",
                                "event_code": "TEST-START",
                                "bead_id": "bd-98xo5.X.tests",
                                "trace_id": "trace-A",
                                "phase": "build",
                                "test_name": None,
                                "duration_ms": 0,
                                "extra": {},
                            }
                        ),
                        json.dumps(
                            {
                                "timestamp": "2026-05-21T05:42:31.300Z",
                                "level": "info",
                                "event_code": "TEST-SUMMARY",
                                "bead_id": "bd-98xo5.X.tests",
                                "trace_id": "trace-B-DIFFERENT",
                                "phase": "build",
                                "test_name": None,
                                "duration_ms": 200,
                                "extra": {"passed": 0, "failed": 0, "skipped": 0, "total": 0},
                            }
                        ),
                    ]
                )
            )
            result = _run_renderer(str(log))
            self.assertEqual(result.returncode, 2)
            self.assertIn("trace_id", result.stderr)

    def test_diff_mode_compares_two_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.jsonl"
            new = Path(tmp) / "new.jsonl"
            old.write_text(PASSING_LOG)
            # Same shape but with a faster preparsed_sign_p95_us.
            improved = PASSING_LOG.replace('"value": 25.12,', '"value": 20.0,')
            new.write_text(improved)
            result = _run_renderer("--diff", str(old), str(new))
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("preparsed_sign_p95_us", result.stdout)
            self.assertIn("→", result.stdout)
            self.assertIn("%", result.stdout)

    def test_diff_mode_requires_two_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_log.jsonl"
            log.write_text(PASSING_LOG)
            result = _run_renderer("--diff", str(log))
            self.assertEqual(result.returncode, 2)
            self.assertIn("--diff requires exactly two", result.stderr)

    def test_nonexistent_log_returns_2(self) -> None:
        result = _run_renderer("/nonexistent/path/test_log.jsonl")
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not exist", result.stderr)


if __name__ == "__main__":
    unittest.main()
