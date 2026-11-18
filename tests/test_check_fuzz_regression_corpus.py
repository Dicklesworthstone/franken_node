#!/usr/bin/env python3
"""Unit tests for scripts/check_fuzz_regression_corpus.py."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_fuzz_regression_corpus as gate  # noqa: E402


class CheckFuzzRegressionCorpusTests(unittest.TestCase):
    def test_live_repository_passes_fuzz_regression_gate(self) -> None:
        report = gate.evaluate_fuzz_corpus(ROOT)
        self.assertEqual(report["verdict"], "PASS", report["issues"])
        self.assertEqual(report["registered_targets"], 146)
        self.assertEqual(report["seeded_targets"], 146)
        self.assertGreaterEqual(int(report["raw_crash_artifacts"]), 9)
        self.assertGreaterEqual(int(report["crash_inputs_replayed"]), 16)

    def test_fails_when_artifact_crash_is_unpromoted_or_target_unseeded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "fuzz").mkdir(parents=True)
            (repo / "fuzz/Cargo.toml").write_text(
                '[[bin]]\nname = "fuzz_alpha"\npath = "fuzz_targets/fuzz_alpha.rs"\n'
                '[[bin]]\nname = "fuzz_beta"\npath = "fuzz_targets/fuzz_beta.rs"\n',
                encoding="utf-8",
            )
            (repo / "crates/franken-node/fuzz").mkdir(parents=True)
            (repo / "crates/franken-node/fuzz/Cargo.toml").write_text(
                '[package]\nname = "inner"\nversion = "0.0.0"\n'
                '[package.metadata.franken_node]\ncanonical_fuzz_manifest = "../../fuzz/Cargo.toml"\n',
                encoding="utf-8",
            )
            (repo / "fuzz/corpus/fuzz_alpha").mkdir(parents=True)
            (repo / "fuzz/corpus/fuzz_alpha/seed1").write_bytes(b"ok")
            (repo / "fuzz/artifacts/fuzz_alpha").mkdir(parents=True)
            crash_bytes = b"\xff\x00"
            (repo / "fuzz/artifacts/fuzz_alpha/crash-1234").write_bytes(crash_bytes)
            (repo / "fuzz/regression").mkdir(parents=True)
            (repo / "fuzz/regression/manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "franken-node/fuzz-regression-manifest/v1",
                        "promoted_target_regressions": [],
                    }
                ),
                encoding="utf-8",
            )

            report = gate.evaluate_fuzz_corpus(repo)
            self.assertEqual(report["verdict"], "FAIL")
            joined = "\n".join(report["issues"])
            self.assertIn("unpromoted fuzz/artifacts crash input", joined)
            self.assertIn("fuzz_beta", joined)

            # Promote crash and seed fuzz_beta -> PASS
            (repo / "fuzz/corpus/fuzz_beta").mkdir(parents=True)
            (repo / "fuzz/corpus/fuzz_beta/seed1").write_bytes(b"seed")
            (repo / "fuzz/regression/fuzz_alpha").mkdir(parents=True)
            (repo / "fuzz/regression/fuzz_alpha/crash-1234").write_bytes(crash_bytes)
            (repo / "fuzz/regression/fuzz_alpha/minimized-1").write_bytes(b"\xff")
            (repo / "fuzz/regression/manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "franken-node/fuzz-regression-manifest/v1",
                        "promoted_target_regressions": [
                            {
                                "target": "fuzz_alpha",
                                "source_artifact": "fuzz/artifacts/fuzz_alpha/crash-1234",
                                "regression_input": "fuzz/regression/fuzz_alpha/crash-1234",
                                "original_bytes": 2,
                                "original_sha256": hashlib.sha256(crash_bytes).hexdigest(),
                                "minimized_input": "fuzz/regression/fuzz_alpha/minimized-1",
                                "minimized_bytes": 1,
                                "minimized_sha256": hashlib.sha256(b"\xff").hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report_ok = gate.evaluate_fuzz_corpus(repo)
            self.assertEqual(report_ok["verdict"], "PASS", report_ok["issues"])

    def test_risk_weighted_smoke_subset_and_seeded_crash_negative_control(self) -> None:
        import subprocess

        subset = gate.select_fuzz_smoke_subset(ROOT, count=8, rotation_key="sha-alpha")
        self.assertEqual(len(subset), 8)
        self.assertEqual(len(set(subset)), 8)

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "fuzz/artifacts/fuzz_ssrf_policy").mkdir(parents=True)
            (repo / "fuzz/Cargo.toml").write_text(
                '[[bin]]\nname = "fuzz_ssrf_policy"\npath = "fuzz_targets/fuzz_ssrf_policy.rs"\n'
                '[[bin]]\nname = "fuzz_plain_helper"\npath = "fuzz_targets/fuzz_plain_helper.rs"\n',
                encoding="utf-8",
            )
            (repo / "fuzz/regression").mkdir(parents=True)
            (repo / "fuzz/regression/manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "franken-node/fuzz-regression-manifest/v1",
                        "promoted_target_regressions": [],
                    }
                ),
                encoding="utf-8",
            )

            # Clean smoke run passes and emits verified sha256 receipts.
            receipt_ok = repo / "ok_receipts.jsonl"
            rc_ok = gate.run_fuzz_smoke_subset(
                repo,
                targets=["fuzz_ssrf_policy", "fuzz_plain_helper"],
                max_total_time_secs=5,
                receipt_jsonl=receipt_ok,
                runner=lambda cmd, _cwd, _t: subprocess.CompletedProcess(cmd, 0, "", ""),
            )
            self.assertEqual(rc_ok, 0)
            rows_ok = [json.loads(line) for line in receipt_ok.read_text().splitlines()]
            self.assertEqual(len(rows_ok), 2)
            self.assertTrue(all(gate.verify_smoke_receipt_sha256(r) for r in rows_ok))

            # Seeded crash artifact or nonzero exit fails closed (no `|| true` masking!).
            (repo / "fuzz/artifacts/fuzz_ssrf_policy/crash-deadbeef").write_bytes(b"\xde\xad")
            receipt_fail = repo / "fail_receipts.jsonl"
            rc_fail = gate.run_fuzz_smoke_subset(
                repo,
                targets=["fuzz_ssrf_policy"],
                max_total_time_secs=5,
                receipt_jsonl=receipt_fail,
                runner=lambda cmd, _cwd, _t: subprocess.CompletedProcess(cmd, 0, "", ""),
            )
            self.assertEqual(rc_fail, 1)
            row_fail = json.loads(receipt_fail.read_text().splitlines()[0])
            self.assertTrue(row_fail["crash"])
            self.assertFalse(row_fail["passed"])
            self.assertTrue(gate.verify_smoke_receipt_sha256(row_fail))


if __name__ == "__main__":
    unittest.main()
