"""Check the tee package corpus's literal expectations with a real Node process.

This is reference-fixture validation, not a native-engine test. Run the existing
project_compat_runner.py with --corpus fixtures/compatibility/projects/stream-tee.corpus.json
and real --bin/--node/--bun executables for native compatibility evidence.
Fixtures here are trusted programs; this test runner is not a sandbox.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "fixtures/compatibility/projects/stream-tee.corpus.json"


class TeeProjectReferenceTests(unittest.TestCase):
    def test_manifest_has_five_distinct_multifile_projects(self):
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(corpus["schema_version"], "franken-node/project-compat-corpus/v1")
        self.assertEqual(len(corpus["cases"]), 5)
        self.assertEqual(len({case["id"] for case in corpus["cases"]}), 5)
        self.assertTrue(all(len(case["files"]) > 1 for case in corpus["cases"]))

    @unittest.skipUnless(shutil.which("node"), "requires a real Node reference")
    def test_every_project_matches_exact_outputs_and_files(self):
        # Do not allow preloads or option overrides to substitute a runtime or
        # silence reference stderr. No --no-warnings or output normalization.
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
                for name, contents in expected.get("files", {}).items():
                    target = root / name
                    self.assertFalse(target.is_symlink(), name)
                    if contents is None:
                        self.assertFalse(target.exists(), name)
                    else:
                        self.assertEqual(target.read_bytes(), contents.encode("utf-8"), name)


if __name__ == "__main__":
    unittest.main()
