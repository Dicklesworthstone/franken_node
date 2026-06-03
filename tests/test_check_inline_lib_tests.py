#!/usr/bin/env python3
"""Unit tests for scripts/check_inline_lib_tests.py."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_inline_lib_tests import evaluate, inline_test_names, main, preflight  # noqa: E402


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
