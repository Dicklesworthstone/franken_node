"""Verify trusted Duplex package fixtures against real Node, not a native shim.

For native evidence use project_compat_runner.py with --corpus
fixtures/compatibility/projects/stream-duplex.corpus.json and real
--bin/--node/--bun executables. These processes are not sandboxes.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "fixtures/compatibility/projects/stream-duplex.corpus.json"


class DuplexProjectReferenceTests(unittest.TestCase):
    def test_five_distinct_complete_package_workflows(self):
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(corpus["schema_version"], "franken-node/project-compat-corpus/v1")
        self.assertEqual(len(corpus["cases"]), 5)
        self.assertEqual(len({case["id"] for case in corpus["cases"]}), 5)
        self.assertTrue(all(len(case["files"]) > 1 for case in corpus["cases"]))
        self.assertTrue(all(case["expected"].get("files") for case in corpus["cases"]))
        self.assertEqual({case["entry"] for case in corpus["cases"]}, {"main.cjs", "main.mjs"})

    @unittest.skipUnless(shutil.which("node"), "requires a real Node reference")
    def test_exact_streams_exits_and_files(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("FRANKEN_NODE_") and key not in
                       {"NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"}}
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, source in case["files"].items():
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.encode("utf-8"))
                result = subprocess.run([shutil.which("node"), "./" + case["entry"]],
                                        cwd=root, env=environment, capture_output=True,
                                        timeout=15, check=False)
                expected = case["expected"]
                self.assertEqual(result.returncode, expected["exit_code"], result.stderr)
                self.assertEqual(result.stdout, expected["stdout"].encode("utf-8"))
                self.assertEqual(result.stderr, expected["stderr"].encode("utf-8"))
                for name, contents in expected["files"].items():
                    target = root / name
                    self.assertFalse(target.is_symlink(), name)
                    if contents is None:
                        self.assertFalse(target.exists(), name)
                    else:
                        self.assertEqual(target.read_bytes(), contents.encode("utf-8"), name)


if __name__ == "__main__":
    unittest.main()
