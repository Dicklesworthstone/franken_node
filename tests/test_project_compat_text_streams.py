"""Executable text-stream projects, not a source-pattern conformance gate.

Reference checks run complete captured projects in independent directories.
Set FRANKEN_NODE_BIN to also run the SAME corpus through the existing product
supervisor, or invoke that supervisor directly:

    python3 scripts/project_compat_runner.py \
        --corpus fixtures/compatibility/projects/text_streams.corpus.json \
        --bin target/release/franken-node --node node --bun bun \
        --artifacts-dir /tmp/franken-text-streams-001

Node-only checks never establish native execution or Bun parity.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "fixtures/compatibility/projects/text_streams.corpus.json"


def clean_environment():
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("FRANKEN_NODE_") or key in {
            "NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"
        }:
            env.pop(key)
    return env


class TextStreamProjectTests(unittest.TestCase):
    def test_complete_projects_have_observable_outputs_and_no_relaxed_expectations(self):
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(corpus["schema_version"], "franken-node/project-compat-corpus/v1")
        self.assertEqual(len(corpus["cases"]), 4)
        self.assertEqual(len({case["id"] for case in corpus["cases"]}), 4)
        self.assertEqual({case["entry"] for case in corpus["cases"]}, {"main.cjs", "main.mjs"})
        for case in corpus["cases"]:
            self.assertGreater(len(case["files"]), 1)
            self.assertTrue(case["expected"]["files"])
            self.assertIn("COMPLETE", case["expected"]["stdout"])
            self.assertEqual(case["expected"]["stderr"], "")
            self.assertEqual(case["expected"]["exit_code"], 0)

    @unittest.skipUnless(shutil.which("node"), "requires Node reference with Web Streams")
    def test_reference_executes_all_packages_with_exact_output_files(self):
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        node = shutil.which("node")
        with tempfile.TemporaryDirectory(prefix="text-stream-reference-") as tmp:
            for case in corpus["cases"]:
                with self.subTest(case=case["id"]):
                    workspace = Path(tmp) / case["id"]
                    for name, text in case["files"].items():
                        target = workspace / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(text.encode("utf-8"))
                    result = subprocess.run(
                        [node, "./" + case["entry"]], cwd=workspace,
                        env=clean_environment(), capture_output=True, timeout=15, check=False,
                    )
                    expected = case["expected"]
                    self.assertEqual(result.returncode, expected["exit_code"], result.stderr)
                    self.assertEqual(result.stdout, expected["stdout"].encode("utf-8"))
                    self.assertEqual(result.stderr, expected["stderr"].encode("utf-8"))
                    for name, content in expected["files"].items():
                        target = workspace / name
                        self.assertFalse(target.is_symlink(), name)
                        if content is None:
                            self.assertFalse(target.exists(), name)
                        else:
                            self.assertTrue(target.is_file(), name)
                            self.assertEqual(target.read_bytes(), content.encode("utf-8"), name)

    @unittest.skipUnless(os.environ.get("FRANKEN_NODE_BIN") and shutil.which("node"),
                         "set FRANKEN_NODE_BIN for actual native product execution")
    def test_native_product_uses_the_existing_supervised_runner(self):
        import sys
        binary = shutil.which(os.environ["FRANKEN_NODE_BIN"])
        self.assertIsNotNone(binary, "configured native binary must exist and be executable")
        with tempfile.TemporaryDirectory(prefix="text-stream-native-") as tmp:
            command = [sys.executable, str(ROOT / "scripts/project_compat_runner.py"),
                       "--corpus", str(CORPUS), "--bin", str(Path(binary).resolve()),
                       "--node", shutil.which("node"), "--policy", "balanced",
                       "--artifacts-dir", str(Path(tmp) / "evidence")]
            if shutil.which("bun"):
                command.extend(["--bun", shutil.which("bun")])
            result = subprocess.run(command, cwd=ROOT, env=clean_environment(),
                                    capture_output=True, timeout=180, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["passing_cases"], 4)
            self.assertEqual(report["selected_case_count"], 4)


if __name__ == "__main__":
    unittest.main()
