"""Reference expectations for packaged users of the shared engine dotenv API.

The native/product/Bun check uses the existing supervisor, not a new adapter:

    python3 scripts/project_compat_runner.py \
        --corpus fixtures/compatibility/projects/dotenv.corpus.json \
        --bin target/release/franken-node --node node --bun bun \
        --artifacts-dir /tmp/franken-dotenv-001

These unittest checks validate the captured corpus and Node expectations only.
They do not certify native execution, Bun parity, npm installs or performance.
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

CORPUS = ROOT / "fixtures" / "compatibility" / "projects" / "dotenv.corpus.json"


class DotenvProjectTests(unittest.TestCase):
    def test_captured_configurations_use_the_existing_project_schema(self):
        corpus = runner.load_corpus(CORPUS)
        self.assertEqual(len(corpus["cases"]), 4)
        self.assertEqual({case["entry"] for case in corpus["cases"]}, {"main.cjs", "main.mjs"})
        self.assertTrue(all(len(case["files"]) > 1 for case in corpus["cases"]))
        self.assertTrue(any(case["expected"].get("files") for case in corpus["cases"]))
        self.assertTrue(all(case["category"] == "configuration-integration" for case in corpus["cases"]))

    @unittest.skipUnless(os.name == "posix" and shutil.which("node"), "requires POSIX and Node reference")
    def test_package_configuration_reference_outputs_and_files(self):
        overrides = {key: "" for key in os.environ if key.startswith("FRANKEN_NODE_")}
        overrides.update({key: "" for key in ("NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS",
                                             "LD_PRELOAD", "DYLD_INSERT_LIBRARIES")})
        with patch.dict(os.environ, overrides):
            runner.reject_runtime_overrides()
            node = runner.executable("node")
            corpus = runner.load_corpus(CORPUS)
            with tempfile.TemporaryDirectory() as tmp:
                for case in corpus["cases"]:
                    with self.subTest(case=case["id"]):
                        base = Path(tmp) / case["id"]
                        workspace = base / "project"
                        runner.stage(case, workspace)
                        receipt = runner.supervise([str(node), "./" + case["entry"]],
                                                   base / "execution", cwd=workspace,
                                                   wall_time_ms=10000, max_output_bytes=1024 * 1024)
                        self.assertEqual(runner.differences(receipt, case["expected"]), [],
                                         Path(receipt["stderr_path"]).read_text(errors="replace"))
                        for name, expected in case["expected"].get("files", {}).items():
                            observed = runner.inspect_output_file(workspace, name, expected)
                            self.assertTrue(observed["matches"], (name, observed))


if __name__ == "__main__":
    unittest.main()
