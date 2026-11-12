"""Unit and adversarial tests for scripts/check_sibling_lock_coherence.py."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_sibling_lock_coherence.py"

spec = importlib.util.spec_from_file_location("check_sibling_lock_coherence", SCRIPT)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckSiblingLockCoherence(unittest.TestCase):
    def test_live_workspace_passes(self) -> None:
        report = mod.run_checks()
        self.assertTrue(report["overall_pass"], json.dumps(report, indent=2))
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["failing"], 0)

    def test_node_fastapi_split_or_fourth_asupersync_generation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "Cargo.lock"
            lock_path.write_text(
                """
version = 4

[[package]]
name = "asupersync"
version = "0.2.9"

[[package]]
name = "asupersync"
version = "0.3.10"

[[package]]
name = "asupersync"
version = "0.5.0"

[[package]]
name = "asupersync"
version = "0.6.2"

[[package]]
name = "fastapi-core"
version = "0.5.0"

[[package]]
name = "fastapi-http"
version = "0.5.0"
dependencies = ["asupersync 0.6.2"]

[[package]]
name = "franken-kernel"
version = "0.2.9"

[[package]]
name = "franken-decision"
version = "0.2.9"

[[package]]
name = "franken-evidence"
version = "0.2.9"

[[package]]
name = "fsqlite-error"
version = "0.4.1"

[[package]]
name = "frankenengine-node"
version = "0.2.0"
dependencies = ["asupersync 0.5.0"]
""".lstrip(),
                encoding="utf-8",
            )
            report = mod.run_checks(cargo_lock=lock_path, check_local_git=False)
        self.assertFalse(report["overall_pass"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("cargo_lock:frankenengine_node_asupersync_0_6", failed)
        self.assertIn("cargo_lock:node_and_fastapi_share_asupersync", failed)
        self.assertIn("cargo_lock:generation_bound:asupersync", failed)

    def test_coverage_exit_zero_masking_and_non_blocking_census_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / "workflows"
            wf_dir.mkdir()
            for wf in mod.REQUIRED_MAIN_PUSH_WORKFLOWS:
                shutil.copy2(ROOT / ".github" / "workflows" / wf, wf_dir / wf)

            cov = (wf_dir / "coverage-report.yml").read_text(encoding="utf-8")
            (wf_dir / "coverage-report.yml").write_text(
                cov.replace(
                    '            exit "${status:-1}"\n          fi',
                    '            exit "${status:-1}"\n          fi\n          exit 0',
                ),
                encoding="utf-8",
            )
            vt = (wf_dir / "verification-target-compile-gate.yml").read_text(encoding="utf-8")
            (wf_dir / "verification-target-compile-gate.yml").write_text(
                vt.replace('BLOCKING: "1"', 'BLOCKING: "0"'),
                encoding="utf-8",
            )
            report = mod.run_checks(workflows_dir=wf_dir, check_local_git=False)
        self.assertFalse(report["overall_pass"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("coverage_report:no_exit_zero_masking", failed)
        self.assertIn("verification_target_compile_gate:blocking_enabled", failed)

    def test_malformed_siblings_tsv_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tsv = Path(tmp) / "source-siblings.tsv"
            tsv.write_text("frankentui\tmain\nfastapi_rust\t" + "a" * 40 + "\n", encoding="utf-8")
            report = mod.run_checks(siblings_tsv=tsv, check_local_git=False)
        self.assertFalse(report["overall_pass"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("siblings_tsv_well_formed", failed)
        self.assertIn("sibling_pinned:sqlmodel_rust", failed)

    def test_duplicate_fastapi_or_fsqlite_generation_and_engine_pin_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "Cargo.lock"
            lock_path.write_text(
                """
version = 4

[[package]]
name = "asupersync"
version = "0.6.2"

[[package]]
name = "fastapi-core"
version = "0.4.4"

[[package]]
name = "fastapi-core"
version = "0.5.0"

[[package]]
name = "fastapi-http"
version = "0.5.0"
dependencies = ["asupersync 0.6.2"]

[[package]]
name = "franken-kernel"
version = "0.6.0"

[[package]]
name = "franken-decision"
version = "0.6.0"

[[package]]
name = "franken-evidence"
version = "0.6.0"

[[package]]
name = "fsqlite-error"
version = "0.1.19"

[[package]]
name = "fsqlite-error"
version = "0.4.1"

[[package]]
name = "frankenengine-node"
version = "0.2.0"
dependencies = ["asupersync 0.6.2"]
""".lstrip(),
                encoding="utf-8",
            )
            wf_dir = Path(tmp) / "workflows"
            wf_dir.mkdir()
            for wf in mod.REQUIRED_MAIN_PUSH_WORKFLOWS:
                shutil.copy2(ROOT / ".github" / "workflows" / wf, wf_dir / wf)
            mutants_path = wf_dir / "mutants-gate.yml"
            mutants_path.write_text(
                mutants_path.read_text(encoding="utf-8").replace(
                    "bbc96b724d68cb9cb0cb3de25b1c494a490eb71d",
                    "1" * 40,
                ),
                encoding="utf-8",
            )
            report = mod.run_checks(
                cargo_lock=lock_path,
                workflows_dir=wf_dir,
                check_local_git=False,
            )
        self.assertFalse(report["overall_pass"])
        self.assertEqual(report["locked_metadata_status"], "drift_detected")
        self.assertIsNotNone(report["failure_code"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("cargo_lock:generation_bound:fastapi-core", failed)
        self.assertIn("cargo_lock:generation_bound:fsqlite-error", failed)
        self.assertIn("engine_pin:workflow_matches_action:mutants-gate.yml", failed)

    def test_cli_json_and_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["verdict"], "PASS")

        st = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(st.returncode, 0, st.stderr)
        self.assertTrue(json.loads(st.stdout)["self_test_passed"])


if __name__ == "__main__":
    unittest.main()
