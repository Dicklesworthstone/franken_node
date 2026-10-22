"""Verify project expectations and pinned npm specimens against a real Node reference.

These tests deliberately do not claim that franken-engine passes these cases.
Run project_compat_runner.py with a built native binary for that measurement.
"""
import hashlib
import json
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

NPM_CORPUS = ROOT / "fixtures/compatibility/projects/npm-packages.corpus.json"
# Frozen hashes are from SHA512-verified official npm tarballs, not generated
# from the fixture under test. This prevents changing vendored code or license
# text while retaining the original package/version/integrity claim.
NPM_PINS = {
    "npm-is-number-7-finite-coercion": (
        "is-number", "7.0.0",
        "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==",
        {"index.js": "04255e482e181687823a95b207802ddd32e746c65dce4c95a5176fc192735960",
         "package.json": "51c133f4e41df982aef69027249ff9d7262645029f437d079adc7c83328fb620",
         "LICENSE": "35bdd8a44339719441900fb50fbefc5e2dca1ca662cbaed7a687de842c8b70f2"}),
    "npm-isarray-2-native-and-prototype-shapes": (
        "isarray", "2.0.5",
        "sha512-xHjhDr3cNBK0BzdUJSPXZntQUx/mwMS5Rw4A7lPJ90XGAO6ISP/ePDNuo0vhqOZU+UD5JoodwCAAoZQd3FeAKw==",
        {"index.js": "9b8c691372802da788c9c5f4e1ca2f1ed0b88ab8722176c2aea15e38ec86d249",
         "package.json": "b0802c09bce6bf067d3e5f52390ea26972e11c88bb6ae38991316ac83ca14127",
         "LICENSE": "68f12f6e2c33688699249c01d8f9623c534da20aa71989c57b061b7bc1676d14"}),
    "npm-escape-string-regexp-4-unicode-and-errors": (
        "escape-string-regexp", "4.0.0",
        "sha512-TtpcNJ3XAzx3Gq8sWRzJaVajRs0uVxA2YAkdb1jm2YkPz4G6egUFAyA3n5vtEIZefPk5Wa4UXbKuS5fKkJWdgA==",
        {"index.js": "d7170b45e3faf26da2fcb2b4a2fac19af142b44d2ec5ae7760700896749a5886",
         "package.json": "63763f28aefa6c49e6e6599e44b7c9aa5afd6518ae04bcfa534ff3759ad428e8",
         "license": "5c932d88256b4ab958f64a856fa48e8bd1f55bc1d96b8149c65689e0c61789d3"}),
}


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

    def test_pinned_npm_publication_bytes_and_lock_identity(self):
        cases = runner.load_corpus(NPM_CORPUS)["cases"]
        self.assertEqual({case["id"] for case in cases}, set(NPM_PINS))
        for case in cases:
            with self.subTest(case=case["id"]):
                name, version, integrity, files = NPM_PINS[case["id"]]
                prefix = "node_modules/" + name + "/"
                manifest = json.loads(case["files"][prefix + "package.json"])
                self.assertEqual((manifest["name"], manifest["version"], manifest["license"]),
                                 (name, version, "MIT"))
                self.assertFalse(manifest.get("dependencies"))
                project = json.loads(case["files"]["package.json"])
                self.assertEqual(project["dependencies"], {name: version})
                lock = json.loads(case["files"]["package-lock.json"])
                self.assertEqual(lock["lockfileVersion"], 3)
                self.assertEqual(lock["packages"][""]["dependencies"], {name: version})
                self.assertEqual(lock["packages"][prefix[:-1]], {
                    "version": version, "license": "MIT", "integrity": integrity,
                    "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"})
                self.assertEqual({path[len(prefix):] for path in case["files"] if path.startswith(prefix)},
                                 set(files))
                for path, expected_hash in files.items():
                    self.assertEqual(hashlib.sha256(case["files"][prefix + path].encode()).hexdigest(),
                                     expected_hash, path)

    @unittest.skipUnless(os.name == "posix" and shutil.which("node"), "requires POSIX and Node reference")
    def test_pinned_npm_specimens_match_exact_reference_observations(self):
        runner.reject_runtime_overrides()
        node = runner.executable("node")
        with tempfile.TemporaryDirectory() as tmp:
            for case in runner.load_corpus(NPM_CORPUS)["cases"]:
                with self.subTest(case=case["id"]):
                    base = Path(tmp) / case["id"]
                    runner.stage(case, base / "project")
                    receipt = runner.supervise([str(node), "./" + case["entry"]],
                                               base / "execution", cwd=base / "project",
                                               wall_time_ms=10000, max_output_bytes=1024 * 1024)
                    self.assertEqual(runner.differences(receipt, case["expected"]), [],
                                     Path(receipt["stderr_path"]).read_text(errors="replace"))

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
        corpus = runner.load_corpus_directory(ROOT / "fixtures/compatibility/projects")
        with tempfile.TemporaryDirectory() as tmp:
            for case in corpus["cases"]:
                with self.subTest(case=case["id"]):
                    base = Path(tmp) / case["id"]
                    workspace = base / "project"
                    runner.stage(case, workspace)
                    receipt = runner.supervise([str(node), "./" + case["entry"], *case.get("args", [])],
                                               base / "execution", cwd=workspace, wall_time_ms=10000,
                                               max_output_bytes=1024 * 1024,
                                               stdin_data=case["stdin"].encode("utf-8") if "stdin" in case else None)
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
