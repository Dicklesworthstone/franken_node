"""Executable runner tests. The candidate and Bun wrappers are NOT native evidence."""
from __future__ import annotations

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


def case(name: str = "answer", entry: str = "main.js") -> dict:
    return {"id": name, "category": "commonjs", "entry": entry,
            "files": {entry: "console.log(require('./answer.js'));\n",
                      "answer.js": "module.exports = 42;\n"},
            "expected": {"stdout": "42\n", "stderr": "", "exit_code": 0}}


def corpus(*cases: dict) -> dict:
    return {"schema_version": runner.SCHEMA, "cases": list(cases) or [case()]}


class ValidationTests(unittest.TestCase):
    def test_valid_project_and_stable_fingerprint(self):
        value = corpus()
        self.assertEqual(runner.validate_corpus(value), value)
        reordered = {"cases": value["cases"], "schema_version": runner.SCHEMA}
        self.assertEqual(runner.digest(runner.encoded(value)), runner.digest(runner.encoded(reordered)))

    def test_unsafe_paths(self):
        for path in ("../secret", "/absolute.js", "a/../../b", "a//b", "./main.js",
                     "a\\b", "C:/drive.js", "", "a/./b", ".git/config", ".franken-node/state"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.relative_path(path)

    def test_invalid_corpora(self):
        invalid = [corpus(case(), case()), {"schema_version": runner.SCHEMA, "cases": []}]
        for mutate in (
            lambda c: c["cases"][0].update(entry="absent.js"),
            lambda c: c["cases"][0].update(args="--bad"),
            lambda c: c["cases"][0].update(unknown=True),
            lambda c: c["cases"][0]["expected"].update(exit_code=True),
            lambda c: c["cases"][0]["expected"].update(exit_code=-1),
            lambda c: c["cases"][0]["files"].update({"answer.js/child": "collision"}),
            lambda c: c["cases"][0]["files"].update({"large.js": "x" * (runner.MAX_PROJECT_BYTES + 1)}),
        ):
            value = corpus()
            mutate(value)
            invalid.append(value)
        for value in invalid:
            with self.subTest(value=str(value)[:100]), self.assertRaises(ValueError):
                runner.validate_corpus(value)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.json"
            path.write_text('{"schema_version":"x","schema_version":"y","cases":[]}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                runner.load_corpus(path)

    def test_missing_binary_does_not_fallback(self):
        with self.assertRaisesRegex(ValueError, "executable not found"):
            runner.executable("/definitely-not-installed/franken-node")

    def test_committed_project_collection_is_executable(self):
        directory = ROOT / "fixtures/compatibility/projects"
        combined = runner.load_corpus_directory(directory)
        manifests = [runner.load_corpus(path) for path in sorted(directory.glob("*.json"))]
        self.assertEqual(combined["cases"], [case for value in manifests for case in value["cases"]])
        self.assertGreater(len(combined["cases"]), len(runner.load_corpus(runner.DEFAULT_CORPUS)["cases"]))

    def test_directory_keeps_manifest_order_and_rejects_duplicate_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.json").write_bytes(runner.encoded(corpus(case("second"))))
            (root / "a.json").write_bytes(runner.encoded(corpus(case("first"))))
            combined = runner.load_corpus_directory(root)
            self.assertEqual([value["id"] for value in combined["cases"]], ["first", "second"])
            self.assertEqual(combined["cases"][0]["expected"], case("first")["expected"])
            (root / "b.json").write_bytes(runner.encoded(corpus(case("first"))))
            with self.assertRaisesRegex(ValueError, "duplicate case id"):
                runner.load_corpus_directory(root)

    def test_directory_refuses_empty_invalid_or_oversized_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "JSON manifests"):
                runner.load_corpus_directory(root)
            path = root / "invalid.json"
            path.write_text("{}")
            with self.assertRaisesRegex(ValueError, "missing"):
                runner.load_corpus_directory(root)
            path.write_bytes(runner.encoded(corpus(case("first"), case("second"))))
            with patch.object(runner, "MAX_CASES", 1):
                with self.assertRaisesRegex(ValueError, "cases"):
                    runner.load_corpus_directory(root)


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "requires POSIX and Node reference")
class ExecutionTests(unittest.TestCase):
    def setUp(self):
        overrides = {key: "" for key in os.environ if key.startswith("FRANKEN_NODE_")}
        overrides.update({key: "" for key in ("NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS",
                                             "LD_PRELOAD", "DYLD_INSERT_LIBRARIES")})
        environment = patch.dict(os.environ, overrides)
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.native = self.root / "candidate-test-double"
        # An explicitly synthetic command adapter. This does not execute JS and
        # its PASS results test the harness, not franken-engine compatibility.
        self.native.write_text(f"#!{sys.executable}\n" + '''
import pathlib, sys, time
if sys.argv[1] == 'init':
    assert sys.argv[2:] == ['--profile', 'balanced', '--out-dir', '.']
    raise SystemExit(0)
assert sys.argv[1] == 'run'
assert sys.argv[3:8] == ['--policy', 'balanced', '--runtime', 'franken-engine', '--console-only']
entry = pathlib.Path(sys.argv[2]).name
if entry == 'hang.js':
    time.sleep(20)
if entry == 'flood.js':
    print('x' * 8192)
elif entry == 'wrong.js':
    print('wrong')
elif entry == 'exit.js':
    sys.stderr.write('expected failure\\n')
    raise SystemExit(7)
elif entry == 'isolated.js':
    print(0 if pathlib.Path('reference-created.txt').exists() else 42)
elif entry == 'triad-isolated.js':
    print(0 if pathlib.Path('other-runtime.txt').exists() else 42)
    pathlib.Path('other-runtime.txt').write_text('created')
else:
    print(42)
''')
        self.native.chmod(0o700)
        self.node = runner.executable("node")
        self.bun = self.root / "bun-reference-test-double"
        # A distinct executable wrapper around real Node. It only tests triad
        # orchestration and disagreement classification; it is NOT Bun evidence.
        self.bun.write_text(
            f"#!{sys.executable}\nimport os, sys\n"
            f"os.execv({str(self.node)!r}, [{str(self.node)!r}, *sys.argv[1:]])\n")
        self.bun.chmod(0o700)

    def run_cases(self, *cases, **kwargs):
        return runner.run_corpus(corpus(*cases), self.native, self.node,
                                 self.root / "artifacts", **kwargs)

    def run_triad(self, *cases, bun=None, **kwargs):
        return runner.run_corpus(corpus(*cases), self.native, self.node,
                                 self.root / "artifacts", bun=bun or self.bun, **kwargs)

    def test_real_node_multifile_reference_and_candidate_command(self):
        report = self.run_cases(case())
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["passing_cases"], 1)
        self.assertEqual(report["candidate"], runner.fingerprint(self.native))
        snapshot = runner.load_corpus(self.root / "artifacts/corpus.json")
        self.assertEqual(snapshot, corpus())
        self.assertEqual(report["corpus_sha256"], runner.digest(runner.encoded(snapshot)))
        receipt = json.loads((self.root / "artifacts/answer/candidate/execution/watchdog.json").read_text())
        self.assertIn("franken-engine", receipt["command"])
        self.assertTrue(receipt["output_complete"])

    def test_three_runtime_reference_agreement_is_recorded(self):
        report = self.run_triad(case())
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["oracle"], "node-bun-native")
        self.assertEqual(report["reference"], runner.fingerprint(self.node))
        self.assertEqual(report["bun_reference"], runner.fingerprint(self.bun))
        result = report["results"][0]
        self.assertEqual(result["reference_disagreements"], [])
        self.assertEqual(result["bun"]["differences"], [])
        self.assertTrue((self.root / "artifacts/answer/reference/project/main.js").is_file())
        self.assertTrue((self.root / "artifacts/answer/bun/project/main.js").is_file())
        self.assertTrue((self.root / "artifacts/answer/candidate/project/main.js").is_file())

    def test_bun_reference_disagreement_is_inconclusive_not_native_failure(self):
        disagreeing = self.root / "bun-disagreement-test-double"
        disagreeing.write_text(f"#!{sys.executable}\nprint('41')\n")
        disagreeing.chmod(0o700)
        report = self.run_triad(case(), bun=disagreeing)
        result = report["results"][0]
        self.assertEqual(report["verdict"], "INCONCLUSIVE")
        self.assertEqual(report["inconclusive_cases"], 1)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(result["reference"]["differences"], [])
        self.assertEqual(result["candidate"]["differences"], [])
        self.assertEqual(result["bun"]["differences"], ["stdout"])
        self.assertEqual(result["reference_disagreements"], ["stdout"])

    def test_definite_failure_outranks_unrelated_reference_inconclusive(self):
        bun = self.root / "mixed-outcome-bun-test-double"
        bun.write_text(
            f"#!{sys.executable}\nimport os, pathlib, sys\n"
            f"node={str(self.node)!r}\n"
            "if pathlib.Path(sys.argv[1]).name == 'disagree.js':\n"
            "    print('41')\n"
            "else:\n"
            "    os.execv(node, [node, *sys.argv[1:]])\n")
        bun.chmod(0o700)
        report = self.run_triad(case("uncertain", "disagree.js"),
                                case("native-bad", "wrong.js"), bun=bun)
        self.assertEqual([row["verdict"] for row in report["results"]],
                         ["INCONCLUSIVE", "FAIL"])
        self.assertEqual(report["inconclusive_cases"], 1)
        self.assertEqual(report["failing_cases"], 1)
        self.assertEqual(report["verdict"], "FAIL")

    def test_agreeing_references_with_wrong_golden_are_reference_failed(self):
        value = case()
        value["expected"]["stdout"] = "wrong golden\n"
        report = self.run_triad(value)
        result = report["results"][0]
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(result["verdict"], "REFERENCE_FAILED")
        self.assertEqual(result["reference_disagreements"], [])
        self.assertEqual(result["reference"]["differences"], ["stdout"])
        self.assertEqual(result["bun"]["differences"], ["stdout"])

    def test_mismatch_does_not_skip_following_case(self):
        report = self.run_cases(case("bad", "wrong.js"), case("good"))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual([row["verdict"] for row in report["results"]], ["FAIL", "PASS"])
        self.assertEqual(report["results"][0]["candidate"]["differences"], ["stdout"])

    def test_directory_cli_executes_every_manifest_and_keeps_failure(self):
        manifests = self.root / "manifests"
        manifests.mkdir()
        (manifests / "a.json").write_bytes(runner.encoded(corpus(case("bad", "wrong.js"))))
        (manifests / "b.json").write_bytes(runner.encoded(corpus(case("good"))))
        artifacts = self.root / "collection-results"
        with patch("sys.stdout"):
            status = runner.main(["--corpus-dir", str(manifests), "--bin", str(self.native),
                                  "--node", str(self.node), "--artifacts-dir", str(artifacts)])
        report = json.loads((artifacts / "report.json").read_text())
        self.assertEqual(status, 1)
        self.assertEqual(report["corpus_case_count"], 2)
        self.assertEqual([row["verdict"] for row in report["results"]], ["FAIL", "PASS"])
        self.assertEqual(len(runner.load_corpus(artifacts / "corpus.json")["cases"]), 2)

    def test_reference_must_match_golden_not_only_candidate(self):
        value = case()
        value["expected"]["stdout"] = "incorrect golden\n"
        report = self.run_cases(value)
        self.assertEqual(report["results"][0]["verdict"], "REFERENCE_FAILED")
        self.assertEqual(report["passing_cases"], 0)

    def test_expected_nonzero_is_observable(self):
        value = case(entry="exit.js")
        value["files"]["exit.js"] = "process.stderr.write('expected failure\\n'); process.exit(7);\n"
        value["expected"] = {"stdout": "", "stderr": "expected failure\n", "exit_code": 7}
        self.assertEqual(self.run_cases(value)["verdict"], "PASS")

    def test_timeout_is_not_an_expected_exit(self):
        report = self.run_cases(case(entry="hang.js"), wall_time_ms=1500)
        result = report["results"][0]
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["candidate"]["outcome"], "wrapper_timeout")
        self.assertIn("execution_incomplete", result["candidate"]["differences"])

    def test_output_quota_fails_closed(self):
        report = self.run_cases(case(entry="flood.js"), max_output_bytes=64)
        result = report["results"][0]
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["candidate"]["outcome"], "output_limit_exceeded")
        self.assertLessEqual(result["candidate"]["stdout_bytes"], 64)

    def test_reference_mutations_do_not_seed_candidate(self):
        value = case(entry="isolated.js")
        value["files"]["isolated.js"] = (
            "require('fs').writeFileSync('reference-created.txt', 'secret'); console.log(42);\n")
        self.assertEqual(self.run_cases(value)["verdict"], "PASS")
        base = self.root / "artifacts/answer"
        self.assertTrue((base / "reference/project/reference-created.txt").exists())
        self.assertFalse((base / "candidate/project/reference-created.txt").exists())

    def test_three_runtime_workspaces_are_mutation_isolated(self):
        value = case(entry="triad-isolated.js")
        value["files"]["triad-isolated.js"] = (
            "const fs=require('fs');"
            "console.log(fs.existsSync('other-runtime.txt')?0:42);"
            "fs.writeFileSync('other-runtime.txt','created');\n")
        report = self.run_triad(value)
        self.assertEqual(report["verdict"], "PASS", report)
        base = self.root / "artifacts/answer"
        for runtime in ("reference", "bun", "candidate"):
            self.assertTrue((base / runtime / "project/other-runtime.txt").is_file())

    def test_identical_binary_rejected(self):
        with self.assertRaisesRegex(ValueError, "different runtime binaries"):
            runner.run_corpus(corpus(), self.node, self.node, self.root / "artifacts")

    def test_node_and_bun_must_be_distinct_binaries(self):
        with self.assertRaisesRegex(ValueError, "Node and Bun references"):
            runner.run_corpus(corpus(), self.native, self.node, self.root / "artifacts",
                              bun=self.node)
        self.assertFalse((self.root / "artifacts").exists())

    def test_candidate_and_bun_must_be_distinct_binaries(self):
        with self.assertRaisesRegex(ValueError, "candidate and Bun"):
            runner.run_corpus(corpus(), self.native, self.node, self.root / "artifacts",
                              bun=self.native)
        self.assertFalse((self.root / "artifacts").exists())

    def test_unknown_selection_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown case ids"):
            self.run_cases(case(), selected=["typo"])
        self.assertFalse((self.root / "artifacts").exists())

    def test_existing_artifact_directory_not_reused(self):
        (self.root / "artifacts").mkdir()
        with self.assertRaises(FileExistsError):
            self.run_cases(case())

    def test_selection_keeps_full_corpus_denominator(self):
        report = self.run_cases(case("first"), case("second"), selected=["second"])
        self.assertEqual(report["corpus_case_count"], 2)
        self.assertEqual(report["selected_case_count"], 1)
        self.assertEqual([row["id"] for row in report["results"]], ["second"])

    def test_file_mismatch_fails_even_when_console_matches(self):
        value = case()
        value["files"]["main.js"] = (
            "require('fs').writeFileSync('result.txt', '42'); console.log(42);\n")
        value["expected"]["files"] = {"result.txt": "42"}
        report = self.run_cases(value)
        result = report["results"][0]
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["reference"]["differences"], [])
        self.assertEqual(result["candidate"]["differences"], ["file:result.txt"])

    def test_bun_only_file_difference_is_inconclusive(self):
        value = case()
        value["files"]["main.js"] = (
            "require('fs').writeFileSync('result.txt', '42'); console.log(42);\n")
        value["expected"]["files"] = {"result.txt": "42"}
        bun = self.root / "bun-file-disagreement"
        bun.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\n"
            "Path('result.txt').write_text('different')\nprint(42)\n")
        bun.chmod(0o700)
        report = self.run_triad(value, bun=bun)
        result = report["results"][0]
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(result["reference_disagreements"], ["files"])
        self.assertEqual(result["reference"]["differences"], [])
        self.assertEqual(result["bun"]["differences"], ["file:result.txt"])

    def test_setup_failure_is_not_a_comparison_pass(self):
        self.native.write_text(f"#!{sys.executable}\nraise SystemExit(7)\n")
        report = self.run_cases(case())
        result = report["results"][0]
        self.assertEqual(result["verdict"], "ERROR")
        self.assertEqual(result["setup"]["exit_code"], 7)
        self.assertNotIn("candidate", result)

    def test_setup_cannot_replace_fixture_source(self):
        self.native.write_text(f"#!{sys.executable}\n" +
                               "from pathlib import Path\nPath('main.js').write_text('changed')\n")
        result = self.run_cases(case())["results"][0]
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("changed fixture input", result["detail"])

    def test_digest_pin_rejects_changed_inputs_before_execution(self):
        for pin in ("sha256:" + "0" * 64, "sha256:invalid-\u2603"):
            with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, "corpus digest does not match"):
                self.run_cases(case(), expected_corpus_sha256=pin)
            self.assertFalse((self.root / "artifacts").exists())

    def test_frozen_corpus_can_be_rerun_with_its_digest(self):
        first = self.run_cases(case())
        captured = runner.load_corpus(self.root / "artifacts/corpus.json")
        second = runner.run_corpus(captured, self.native, self.node, self.root / "rerun",
                                   expected_corpus_sha256=first["corpus_sha256"])
        self.assertEqual(second["verdict"], "PASS")
        self.assertEqual(second["results"][0]["case_sha256"], first["results"][0]["case_sha256"])

    def test_script_flags_stay_after_native_argument_separator(self):
        value = case()
        value["args"] = ["--runtime", "node", "--policy", "legacy-risky", "a b"]
        self.assertEqual(self.run_cases(value)["verdict"], "PASS")
        receipt = json.loads((self.root / "artifacts/answer/candidate/execution/watchdog.json").read_text())
        command = receipt["command"]
        separator = command.index("--")
        self.assertEqual(command[separator + 1:], value["args"])
        self.assertEqual(command[command.index("--runtime") + 1], "franken-engine")

    def test_script_arguments_are_identical_for_both_references(self):
        value = case()
        value["args"] = ["--flag", "a b"]
        report = self.run_triad(value)
        self.assertEqual(report["verdict"], "PASS")
        base = self.root / "artifacts/answer"
        node_receipt = json.loads((base / "reference/execution/watchdog.json").read_text())
        bun_receipt = json.loads((base / "bun/execution/watchdog.json").read_text())
        self.assertEqual(node_receipt["command"][2:], value["args"])
        self.assertEqual(bun_receipt["command"][2:], value["args"])

    def test_cancellation_never_passes_an_empty_run(self):
        cancellation = runner.Cancellation()
        cancellation.request(15)
        report = self.run_cases(case(), cancellation=cancellation)
        self.assertEqual(report["verdict"], "CANCELLED")
        self.assertEqual(report["results"], [])


if __name__ == "__main__":
    unittest.main()
