"""Unit and adversarial tests for scripts/check_runbook_cli_verbs.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_runbook_cli_verbs.py"

spec = importlib.util.spec_from_file_location("check_runbook_cli_verbs", SCRIPT)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckRunbookCliVerbs(unittest.TestCase):
    def test_live_runbooks_and_fixtures_pass(self) -> None:
        report = mod.run_checks()
        self.assertTrue(report["overall_pass"], json.dumps(report, indent=2))
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["failing"], 0)

    def test_unshipped_top_level_ctl_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            md_dir = Path(tmp) / "md"
            json_dir = Path(tmp) / "json"
            md_dir.mkdir()
            json_dir.mkdir()
            (md_dir / "bad.md").write_text(
                "```bash\nfranken-node ctl drain --region r1\n```\n",
                encoding="utf-8",
            )
            (json_dir / "ok.json").write_text(
                json.dumps({"command_references": ["franken-node fleet status --json"]}),
                encoding="utf-8",
            )
            report = mod.run_checks(md_dir=md_dir, json_dir=json_dir)
        self.assertFalse(report["overall_pass"])
        details = " ".join(c["detail"] for c in report["checks"] if not c["pass"])
        self.assertIn("franken-node ctl", details)

    def test_unshipped_subcommand_ops_rotate_key_and_franken_lab_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            md_dir = Path(tmp) / "md"
            json_dir = Path(tmp) / "json"
            md_dir.mkdir()
            json_dir.mkdir()
            (md_dir / "lab.md").write_text(
                "```bash\nfranken-lab replay --seed 42\n```\n",
                encoding="utf-8",
            )
            (json_dir / "bad.json").write_text(
                json.dumps(
                    {
                        "command_references": [
                            "franken-node ops rotate-key --new-key k.pem",
                            "franken-node quarantine list",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            report = mod.run_checks(md_dir=md_dir, json_dir=json_dir)
        self.assertFalse(report["overall_pass"])
        details = " ".join(c["detail"] for c in report["checks"] if not c["pass"])
        self.assertIn("franken-lab", details)
        self.assertIn("franken-node ops rotate-key", details)
        self.assertIn("franken-node quarantine", details)

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
