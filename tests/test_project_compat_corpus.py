"""Verify hand-authored project expectations against a real Node reference.

These tests deliberately do not claim that franken-engine passes these cases.
Run project_compat_runner.py with a built native binary for that measurement.
"""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts import project_compat_runner as runner


class CorpusTests(unittest.TestCase):
    def setUp(self):
        overrides = {key: "" for key in os.environ if key.startswith("FRANKEN_NODE_")}
        overrides.update({key: "" for key in ("NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS",
                                             "LD_PRELOAD", "DYLD_INSERT_LIBRARIES")})
        environment = patch.dict(os.environ, overrides)
        environment.start()
        self.addCleanup(environment.stop)

    def test_corpus_has_multifile_coverage(self):
        corpus = runner.load_corpus(runner.DEFAULT_CORPUS)
        self.assertGreaterEqual(len(corpus["cases"]), 19)
        self.assertTrue(all(len(case["files"]) > 1 for case in corpus["cases"]))
        categories = {case["category"] for case in corpus["cases"]}
        self.assertTrue({"commonjs", "esm", "package-resolution", "filesystem-integration"} <= categories)

    def test_runtime_overrides_rejected_without_disclosing_values(self):
        for name in ("NODE_OPTIONS", "NODE_PATH", "FRANKEN_NODE_CONFIG", "LD_PRELOAD"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "secret-value"}):
                with self.assertRaises(ValueError) as error:
                    runner.reject_runtime_overrides()
                self.assertIn(name, str(error.exception))
                self.assertNotIn("secret-value", str(error.exception))

    @unittest.skipUnless(os.name == "posix" and shutil.which("node"), "requires POSIX and Node reference")
    def test_every_reference_matches_exact_expectations(self):
        runner.reject_runtime_overrides()
        node = runner.executable("node")
        corpus = runner.load_corpus(runner.DEFAULT_CORPUS)
        with tempfile.TemporaryDirectory() as tmp:
            for case in corpus["cases"]:
                with self.subTest(case=case["id"]):
                    base = Path(tmp) / case["id"]
                    workspace = base / "project"
                    runner.stage(case, workspace)
                    receipt = runner.supervise([str(node), "./" + case["entry"], *case.get("args", [])],
                                               base / "execution", cwd=workspace, wall_time_ms=10000,
                                               max_output_bytes=1024 * 1024)
                    self.assertEqual(runner.differences(receipt, case["expected"]), [],
                                     Path(receipt["stderr_path"]).read_text(errors="replace"))
                    for name, expected in case["expected"].get("files", {}).items():
                        observed = runner.inspect_output_file(workspace, name, expected)
                        self.assertTrue(observed["matches"], (name, observed))


@unittest.skipUnless(os.name == "posix", "requires descriptor-relative POSIX access")
class FileObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_exact_file_and_missing_file(self):
        (self.root / "result.txt").write_bytes(b"42\n")
        self.assertTrue(runner.inspect_output_file(self.root, "result.txt", "42\n")["matches"])
        self.assertFalse(runner.inspect_output_file(self.root, "result.txt", "42")["matches"])
        self.assertFalse(runner.inspect_output_file(self.root, "result.txt", None)["matches"])
        self.assertTrue(runner.inspect_output_file(self.root, "missing/result.txt", None)["matches"])
        self.assertFalse(runner.inspect_output_file(self.root, "missing.txt", "")["matches"])

    def test_symlink_and_symlink_parent_are_unsafe(self):
        (self.root / "actual").mkdir()
        (self.root / "actual/result.txt").write_text("42\n")
        (self.root / "link").symlink_to("actual", target_is_directory=True)
        (self.root / "result.txt").symlink_to("actual/result.txt")
        (self.root / "dangling.txt").symlink_to("missing")
        for name in ("link/result.txt", "result.txt", "dangling.txt"):
            with self.subTest(name=name):
                observed = runner.inspect_output_file(self.root, name, None)
                self.assertEqual(observed["status"], "unsafe")
                self.assertFalse(observed["matches"])

    def test_fifo_cannot_block_output_inspection(self):
        os.mkfifo(self.root / "pipe")
        self.assertEqual(runner.inspect_output_file(self.root, "pipe", "")["status"], "unsafe")

    def test_oversized_output_is_not_read_unbounded(self):
        with (self.root / "large").open("wb") as output:
            output.truncate(runner.MAX_PROJECT_BYTES + 1)
        observed = runner.inspect_output_file(self.root, "large", "")
        self.assertEqual(observed["status"], "oversized")
        self.assertFalse(observed["matches"])

    def test_atomic_report_is_complete(self):
        path = self.root / "report.json"
        runner.publish_report(path, {"verdict": "RUNNING"})
        runner.publish_report(path, {"verdict": "FAIL"})
        self.assertEqual(path.read_bytes(), runner.encoded({"verdict": "FAIL"}))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["report.json"])


if __name__ == "__main__":
    unittest.main()
