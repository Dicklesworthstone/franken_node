"""Tests for scripts/check_compatibility_corpus.py (bd-2ja)."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_compatibility_corpus.py"

spec = importlib.util.spec_from_file_location("check_corpus", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test(self):
        assert mod.self_test() is True


class TestValidCorpusPasses:
    def test_valid_corpus_passes(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_json_output_verdict_pass(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2ja"
        assert data["section"] == "10.7"
        assert data["verdict"] == "PASS"
        assert data["checks_passed"] == data["checks_total"]

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True,
        )
        assert "bd-2ja" in result.stdout
        assert "PASS" in result.stdout


class TestMissingFixtureFieldFails:
    def test_missing_fixture_field_fails(self, tmp_path):
        """Removing a required field from a fixture causes check failure."""
        corpus_data = json.loads(mod._read(mod.CORPUS))
        # Remove 'api_surface' from first fixture
        del corpus_data["fixtures"][0]["api_surface"]

        bad_corpus = tmp_path / "corpus_manifest.json"
        bad_corpus.write_text(json.dumps(corpus_data), encoding="utf-8")

        with mock.patch.object(mod, "CORPUS", bad_corpus):
            results = mod._checks()
            required_check = next(
                r for r in results if r["check"] == "fixtures_required_fields"
            )
            assert not required_check["passed"], \
                "Should fail when a required field is missing"


class TestInvalidBandFails:
    def test_invalid_band_fails(self, tmp_path):
        """Using an invalid band value causes check failure."""
        corpus_data = json.loads(mod._read(mod.CORPUS))
        # Set an invalid band
        corpus_data["fixtures"][0]["band"] = "nonexistent_band"

        bad_corpus = tmp_path / "corpus_manifest.json"
        bad_corpus.write_text(json.dumps(corpus_data), encoding="utf-8")

        with mock.patch.object(mod, "CORPUS", bad_corpus):
            results = mod._checks()
            band_check = next(
                r for r in results if r["check"] == "valid_bands"
            )
            assert not band_check["passed"], \
                "Should fail when band is not in valid set"
