"""Unit tests for scripts/check_migration_velocity_gate.py (live velocity gate)."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_migration_velocity_gate.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]


mod = ScriptNamespace(runpy.run_path(str(SCRIPT)))


class MedianTests(unittest.TestCase):
    def test_odd_length_returns_middle(self) -> None:
        assert mod._median_int([5, 1, 3]) == 3

    def test_even_length_floors_mean_of_middles(self) -> None:
        assert mod._median_int([4, 1, 3, 2]) == 2
        assert mod._median_int([5, 1, 3, 2]) == 2  # (2+3)//2 floor

    def test_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            mod._median_int([])


class RatioTests(unittest.TestCase):
    def test_exact_three_x(self) -> None:
        assert mod._ratio_bp(30_000, 10_000) == 30_000

    def test_basis_point_rounding_is_half_up(self) -> None:
        assert mod._ratio_bp(1, 3) == 3_333
        assert mod._ratio_bp(2, 3) == 6_667

    def test_zero_denominator_raises(self) -> None:
        with self.assertRaises(ValueError):
            mod._ratio_bp(10, 0)


class Splitmix64Tests(unittest.TestCase):
    def test_reference_vector_seed_zero(self) -> None:
        state, out = mod._splitmix64(0)
        assert state == 0x9E3779B97F4A7C15
        assert out == 0xE220A8397B1DCDAF


class BootstrapTests(unittest.TestCase):
    def test_degenerate_population_gives_point_interval(self) -> None:
        ci = mod._bootstrap_ci_bp([(100, 350)] * 5, 2000, 42)
        assert ci == {
            "resamples": 2000,
            "seed": 42,
            "ci95_low_bp": 35_000,
            "ci95_high_bp": 35_000,
        }

    def test_deterministic_for_fixed_seed(self) -> None:
        pairs = [(100, 350), (110, 330), (90, 400), (105, 360), (95, 340)]
        assert mod._bootstrap_ci_bp(pairs, 4000, 7) == mod._bootstrap_ci_bp(pairs, 4000, 7)

    def test_empty_pairs_raise(self) -> None:
        with self.assertRaises(ValueError):
            mod._bootstrap_ci_bp([], 100, 42)


class CanonicalizationTests(unittest.TestCase):
    def test_reject_floats_paths(self) -> None:
        assert mod._reject_floats({"a": {"b": [1, 2]}}) is None
        assert mod._reject_floats({"a": 3.14}) == "$.a"

    def test_canonical_bytes_sorted_compact(self) -> None:
        assert mod._canonical_bytes({"b": 1, "a": [2, 3]}) == b'{"a":[2,3],"b":1}'

    def test_corpus_digest_order_invariant(self) -> None:
        pairs_a = [("f1", "sha256:aa"), ("f2", "sha256:bb")]
        pairs_b = [("f2", "sha256:bb"), ("f1", "sha256:aa")]
        assert mod._corpus_digest(pairs_a) == mod._corpus_digest(pairs_b)


class SignatureTests(unittest.TestCase):
    def test_roundtrip_verifies(self) -> None:
        private, public_hex = mod._harness_keys()
        unsigned = {"schema": mod.MIGTP_SCHEMA, "value_bp": 35_000}
        message = mod._signature_message(mod._canonical_bytes(unsigned))
        signature = {
            "algorithm": mod.MIGTP_SIGNATURE_ALGORITHM,
            "signer_key_id": mod.MIGTP_HARNESS_KEY_ID,
            "signer_public_key_hex": public_hex,
            "signature_hex": private.sign(message).hex(),
        }
        ok, detail = mod._verify_signature(
            unsigned, signature, private, public_hex
        )
        assert ok, detail

    def test_flipped_payload_fails(self) -> None:
        private, public_hex = mod._harness_keys()
        unsigned = {"schema": mod.MIGTP_SCHEMA, "value_bp": 35_000}
        message = mod._signature_message(mod._canonical_bytes(unsigned))
        signature = {
            "algorithm": mod.MIGTP_SIGNATURE_ALGORITHM,
            "signer_key_id": mod.MIGTP_HARNESS_KEY_ID,
            "signer_public_key_hex": public_hex,
            "signature_hex": private.sign(message).hex(),
        }
        tampered = dict(unsigned)
        tampered["value_bp"] = 34_999
        ok, _detail = mod._verify_signature(tampered, signature, private, public_hex)
        assert not ok


class GateCliTests(unittest.TestCase):
    def test_self_test_exit_zero(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        payload = json.loads(completed.stdout)
        assert payload["ok"] is True


if __name__ == "__main__":
    unittest.main()
