"""Tests for scripts/check_compatibility_corpus.py (bd-2ja)."""

import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_compatibility_corpus.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._script_globals[name] = value


script_globals = runpy.run_path(str(SCRIPT))
mod = ScriptNamespace(script_globals["_checks"].__globals__)


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


def load_json(text: str) -> dict[str, object]:
    return json.JSONDecoder().decode(text)


def checks_with_corpus(path: Path) -> list[dict[str, object]]:
    original = mod.CORPUS
    mod.CORPUS = path
    try:
        return mod._checks()
    finally:
        mod.CORPUS = original


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(mod.self_test())


class TestValidCorpusPasses(unittest.TestCase):
    def test_valid_corpus_passes(self):
        results = mod._checks()
        failed = [result for result in results if not result["passed"]]
        self.assertEqual(failed, [], f"Failed: {[result['check'] for result in failed]}")

    def test_json_output_verdict_pass(self):
        result = run_script("--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = load_json(result.stdout)
        self.assertEqual(data["bead_id"], "bd-2ja")
        self.assertEqual(data["section"], "10.7")
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["checks_passed"], data["checks_total"])

    def test_human_output(self):
        result = run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bd-2ja", result.stdout)
        self.assertIn("PASS", result.stdout)


class TestMissingFixtureFieldFails(unittest.TestCase):
    def test_missing_fixture_field_fails(self):
        """Removing a required field from a fixture causes check failure."""
        corpus_data = load_json(mod._read(mod.CORPUS))
        del corpus_data["fixtures"][0]["api_surface"]

        with tempfile.TemporaryDirectory(prefix="compat-corpus-") as temp_dir:
            bad_corpus = Path(temp_dir) / "corpus_manifest.json"
            bad_corpus.write_text(json.dumps(corpus_data), encoding="utf-8")

            results = checks_with_corpus(bad_corpus)
            required_check = next(
                result for result in results if result["check"] == "fixtures_required_fields"
            )
            self.assertFalse(required_check["passed"], "Should fail when a required field is missing")


class TestInvalidBandFails(unittest.TestCase):
    def test_invalid_band_fails(self):
        """Using an invalid band value causes check failure."""
        corpus_data = load_json(mod._read(mod.CORPUS))
        corpus_data["fixtures"][0]["band"] = "nonexistent_band"

        with tempfile.TemporaryDirectory(prefix="compat-corpus-") as temp_dir:
            bad_corpus = Path(temp_dir) / "corpus_manifest.json"
            bad_corpus.write_text(json.dumps(corpus_data), encoding="utf-8")

            results = checks_with_corpus(bad_corpus)
            band_check = next(
                result for result in results if result["check"] == "valid_bands"
            )
            self.assertFalse(band_check["passed"], "Should fail when band is not in valid set")


if __name__ == "__main__":
    unittest.main()
