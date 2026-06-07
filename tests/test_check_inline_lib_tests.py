#!/usr/bin/env python3
"""Unit tests for scripts/check_inline_lib_tests.py."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_inline_lib_tests import (  # noqa: E402
    SCHEMA_SHARD_RECEIPT,
    build_shard_plan,
    classify_outcome,
    evaluate,
    inline_test_names,
    main,
    run_shards,
    preflight,
)


LIST_OUTPUT = """
security::threshold_sig::tests::rejects_duplicate_signer: test
runtime::lane_scheduler::tests::control_lane_preempts_background: test

2 tests, 0 benchmarks
"""

NOISE_OUTPUT = """
  2026-06-03T10:00:00Z WARN rch::hook: remote command
frankenengine_node::config::tests::loads_balanced_profile: test
warning: `frankenengine-node` generated 12 warnings
    Finished `test` profile [unoptimized + debuginfo] target(s) in 4.17s
"""

ANSI_OUTPUT = (
    "\x1b[32mcontrol_plane::mmr_proofs::tests::inclusion_roundtrip: test\x1b[0m\n"
)

SHARD_LIST_OUTPUT = """
security::threshold_sig::tests::rejects_duplicate_signer: test
security::threshold_sig::tests::accepts_quorum: test
runtime::lane_scheduler::tests::control_lane_preempts_background: test
runtime::lane_scheduler::tests::background_yields_to_realtime: test

4 tests, 0 benchmarks
"""

ZERO_OUTPUT = """
Finished `test` profile [unoptimized + debuginfo] target(s) in 9m 37s
0 tests, 0 benchmarks
"""


class InlineLibTestParserTest(unittest.TestCase):
    def test_extracts_test_names(self) -> None:
        self.assertEqual(
            inline_test_names(LIST_OUTPUT),
            [
                "security::threshold_sig::tests::rejects_duplicate_signer",
                "runtime::lane_scheduler::tests::control_lane_preempts_background",
            ],
        )

    def test_ignores_rch_cargo_noise(self) -> None:
        self.assertEqual(
            inline_test_names(NOISE_OUTPUT),
            ["frankenengine_node::config::tests::loads_balanced_profile"],
        )

    def test_strips_ansi_sequences(self) -> None:
        self.assertEqual(
            inline_test_names(ANSI_OUTPUT),
            ["control_plane::mmr_proofs::tests::inclusion_roundtrip"],
        )

    def test_zero_test_harness_fails_evaluation(self) -> None:
        result = evaluate(ZERO_OUTPUT, min_tests=1)
        self.assertEqual(result["test_count"], 0)
        self.assertFalse(result["passed"])

    def test_threshold_is_enforced(self) -> None:
        self.assertTrue(evaluate(LIST_OUTPUT, min_tests=2)["passed"])
        self.assertFalse(evaluate(LIST_OUTPUT, min_tests=3)["passed"])


class InlineLibGateCliTest(unittest.TestCase):
    def test_main_passes_for_list_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "list.txt"
            path.write_text(LIST_OUTPUT, encoding="utf-8")
            self.assertEqual(main([str(path), "--min-tests", "2"]), 0)

    def test_main_fails_for_zero_test_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "zero.txt"
            path.write_text(ZERO_OUTPUT, encoding="utf-8")
            self.assertEqual(main([str(path)]), 1)

    def test_main_reads_stdin_and_emits_json(self) -> None:
        original_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(LIST_OUTPUT)
            output = io.StringIO()
            with redirect_stdout(output):
                rc = main(["--json", "--min-tests", "2"])
        finally:
            sys.stdin = original_stdin

        self.assertEqual(rc, 0)
        self.assertIn('"passed": true', output.getvalue())
        self.assertIn('"test_count": 2', output.getvalue())


class InlineLibPreflightTest(unittest.TestCase):
    def test_preflight_accepts_override_wiring(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cargo_toml = root / "Cargo.toml"
            lib_rs = root / "lib.rs"
            cargo_toml.write_text(
                """
[lib]
test = true

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(loom)', 'cfg(franken_node_inline_tests)'] }
""",
                encoding="utf-8",
            )
            lib_rs.write_text(
                "#![forbid(unsafe_code)]\n"
                "#![cfg(any(not(test), franken_node_inline_tests))]\n",
                encoding="utf-8",
            )

            result = preflight(cargo_toml, lib_rs)
            self.assertTrue(result["passed"])
            self.assertEqual(result["issues"], [])

    def test_preflight_rejects_hard_disabled_test_crate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cargo_toml = root / "Cargo.toml"
            lib_rs = root / "lib.rs"
            cargo_toml.write_text(
                """
[lib]
test = true

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(franken_node_inline_tests)'] }
""",
                encoding="utf-8",
            )
            lib_rs.write_text(
                "#![forbid(unsafe_code)]\n#![cfg(not(test))]\n",
                encoding="utf-8",
            )

            result = preflight(cargo_toml, lib_rs)
            self.assertFalse(result["passed"])
            self.assertIn("lib_rs_override_gate", result["issues"])

    def test_main_runs_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cargo_toml = root / "Cargo.toml"
            lib_rs = root / "lib.rs"
            cargo_toml.write_text(
                """
[lib]
test = true

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(franken_node_inline_tests)'] }
""",
                encoding="utf-8",
            )
            lib_rs.write_text(
                "#![cfg(any(not(test), franken_node_inline_tests))]\n",
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "--preflight",
                        "--cargo-toml",
                        str(cargo_toml),
                        "--lib-rs",
                        str(lib_rs),
                    ]
                ),
                0,
            )


class InlineLibShardPlanTest(unittest.TestCase):
    def test_shard_plan_groups_by_prefix_and_preserves_rch_command_shape(self) -> None:
        plan = build_shard_plan(
            SHARD_LIST_OUTPUT,
            max_tests_per_shard=2,
            timeout_seconds=900,
        )

        self.assertEqual(plan["schema_version"], "franken-node/inline-lib-test-shard-plan/v1")
        self.assertEqual(plan["total_tests"], 4)
        self.assertEqual(plan["total_shards"], 2)
        self.assertEqual(plan["timeout_seconds"], 900)
        shard = plan["shards"][0]
        self.assertEqual(shard["test_count"], 2)
        self.assertFalse(shard["exact"])
        self.assertEqual(shard["timeout_seconds"], 900)
        self.assertEqual(
            shard["command"][:12],
            [
                "rch",
                "exec",
                "--",
                "env",
                "CARGO_INCREMENTAL=0",
                "RUSTFLAGS=--cfg franken_node_inline_tests",
                "cargo",
                "test",
                "-p",
                "frankenengine-node",
                "--lib",
                "--features",
            ],
        )
        self.assertIn("extended-surfaces,test-support", shard["command"])

    def test_singleton_shard_uses_exact_filter(self) -> None:
        plan = build_shard_plan(LIST_OUTPUT, max_tests_per_shard=1, rch_bin="/bin/rch")
        shard = plan["shards"][0]

        self.assertTrue(shard["exact"])
        self.assertEqual(shard["command"][0], "/bin/rch")
        self.assertEqual(shard["command"][-2:], ["--", "--exact"])


class InlineLibShardReceiptTest(unittest.TestCase):
    def test_run_shards_writes_receipts_and_output_files(self) -> None:
        plan = build_shard_plan(LIST_OUTPUT, max_tests_per_shard=1)
        calls: list[list[str]] = []

        def runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            self.assertEqual(timeout_seconds, 1800)
            test_name = command[-3]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"running 1 test\ntest {test_name} ... ok\n",
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rc = run_shards(
                plan,
                receipt_jsonl=root / "receipts.jsonl",
                output_dir=root / "shards",
                resume=False,
                fail_fast=False,
                runner=runner,
            )
            receipts = [
                json.loads(line)
                for line in (root / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
            ]

            self.assertEqual(rc, 0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(receipts), 2)
            self.assertEqual(receipts[0]["schema_version"], SCHEMA_SHARD_RECEIPT)
            self.assertTrue(receipts[0]["passed"])
            self.assertEqual(receipts[0]["outcome_class"], "passed")
            self.assertTrue(Path(receipts[0]["stdout_path"]).exists())

    def test_run_shards_classifies_rch_storage_pressure_and_stops(self) -> None:
        plan = build_shard_plan(LIST_OUTPUT, max_tests_per_shard=2)

        def runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command,
                101,
                stdout="",
                stderr="failed to unpack crate: No space left on device (os error 28)",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rc = run_shards(
                plan,
                receipt_jsonl=root / "receipts.jsonl",
                output_dir=root / "shards",
                resume=False,
                fail_fast=False,
                runner=runner,
            )
            receipt = json.loads((root / "receipts.jsonl").read_text(encoding="utf-8"))

            self.assertEqual(rc, 1)
            self.assertEqual(receipt["outcome_class"], "rch_infra_failure")
            self.assertIn("No space left on device", receipt["stderr_summary"])

    def test_run_shards_records_timeout_receipt(self) -> None:
        plan = build_shard_plan(LIST_OUTPUT, max_tests_per_shard=2, timeout_seconds=3)

        def runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
            self.assertEqual(timeout_seconds, 3)
            raise subprocess.TimeoutExpired(command, timeout_seconds, output="", stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rc = run_shards(
                plan,
                receipt_jsonl=root / "receipts.jsonl",
                output_dir=root / "shards",
                resume=False,
                fail_fast=False,
                runner=runner,
            )
            receipt = json.loads((root / "receipts.jsonl").read_text(encoding="utf-8"))

            self.assertEqual(rc, 1)
            self.assertEqual(receipt["exit_code"], 124)
            self.assertEqual(receipt["outcome_class"], "timeout")
            self.assertEqual(receipt["timeout_seconds"], 3)
            self.assertIn("timed out", receipt["stderr_summary"])

    def test_resume_skips_previously_passed_shard(self) -> None:
        plan = build_shard_plan(LIST_OUTPUT, max_tests_per_shard=2)
        calls = 0

        def runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            shard = plan["shards"][0]
            (root / "receipts.jsonl").write_text(
                json.dumps(
                    {
                        "shard_id": shard["shard_id"],
                        "target_hash": shard["target_hash"],
                        "passed": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            rc = run_shards(
                plan,
                receipt_jsonl=root / "receipts.jsonl",
                output_dir=root / "shards",
                resume=True,
                fail_fast=False,
                runner=runner,
            )

            self.assertEqual(rc, 0)
            self.assertEqual(calls, 0)

    def test_classify_outcome_distinguishes_compile_and_infra_failures(self) -> None:
        self.assertEqual(classify_outcome(0, "", ""), "passed")
        self.assertEqual(classify_outcome(124, "", "command timed out"), "timeout")
        self.assertEqual(
            classify_outcome(101, "", "error: could not compile `frankenengine-node`"),
            "compile_failure",
        )
        self.assertEqual(
            classify_outcome(101, "", "No space left on device (os error 28)"),
            "rch_infra_failure",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
