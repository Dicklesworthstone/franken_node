#!/usr/bin/env python3
"""Unit tests for scripts/check_verification_targets_compile.py (bd-rjc2m.G1).

Fixtures use the exact cargo `--keep-going` output format observed in the Round-0 census.
Run: python3 scripts/test_check_verification_targets_compile.py
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_verification_targets_compile import (  # noqa: E402
    _CONF_CMD,
    _FUZZ_CMD,
    parse_broken_targets,
    records_from_output,
    main,
)

CONF_FIXTURE = r"""
   Compiling frankenengine-node v0.1.0 (/data/projects/franken_node/crates/franken-node)
warning: unused import: `Foo`
error[E0599]: no method named `check` found for struct `CapabilityGate` in the current scope
error: could not compile `frankenengine-node` (test "bd_1nfu_remote_capability_gate_conformance") due to 45 previous errors; 3 warnings emitted
warning: `frankenengine-node` (test "migrate_cli_e2e") generated 6 warnings
error: could not compile `frankenengine-node` (test "rollback_bundle_conformance") due to 1 previous error
error[E0716]: temporary value dropped while borrowed
error: could not compile `frankenengine-node` (test "rollback_bundle_conformance") due to 36 previous errors
"""

FUZZ_FIXTURE = "\x1b[0m\x1b[1m\x1b[91merror\x1b[0m: could not compile `franken-node-fuzz` (bin \"fuzz_capability_token_parser\") due to 2 previous errors\n" \
    'error: could not compile `franken-node-fuzz` (bin "fuzz_ssrf_policy") due to 13 previous errors; 1 warning emitted\n'

CLEAN_FIXTURE = """
   Compiling frankenengine-node v0.1.0
    Finished `test` profile [unoptimized + debuginfo] target(s) in 10m 02s
warning: `frankenengine-node` (test "fleet_cli_e2e") generated 2 warnings
"""


class TestParser(unittest.TestCase):
    def test_parses_conformance_targets_and_dedups_max_count(self):
        got = parse_broken_targets(CONF_FIXTURE)
        names = {n: c for (n, k, c) in got}
        self.assertIn("bd_1nfu_remote_capability_gate_conformance", names)
        self.assertEqual(names["bd_1nfu_remote_capability_gate_conformance"], 45)
        # rollback_bundle appears twice (1 then 36) -> keep the max
        self.assertEqual(names["rollback_bundle_conformance"], 36)
        # a target that only 'generated warnings' is NOT broken
        self.assertNotIn("migrate_cli_e2e", names)

    def test_parses_fuzz_bins_through_ansi(self):
        got = parse_broken_targets(FUZZ_FIXTURE)
        d = {n: (k, c) for (n, k, c) in got}
        self.assertEqual(d["fuzz_capability_token_parser"], ("bin", 2))
        self.assertEqual(d["fuzz_ssrf_policy"], ("bin", 13))

    def test_clean_output_has_no_broken(self):
        self.assertEqual(parse_broken_targets(CLEAN_FIXTURE), [])

    def test_layer_mapping(self):
        recs = records_from_output(CONF_FIXTURE + FUZZ_FIXTURE, "2026-05-30T00:00:00Z")
        layers = {r.target: r.layer for r in recs}
        self.assertEqual(layers["bd_1nfu_remote_capability_gate_conformance"], "conformance")
        self.assertEqual(layers["fuzz_capability_token_parser"], "fuzz")
        # all census records are compile-failures => not green
        self.assertTrue(all((not r.compiles and not r.is_green()) for r in recs))

    def test_cargo_census_commands_are_locked(self):
        self.assertIn("--locked", _CONF_CMD)
        self.assertIn("--locked", _FUZZ_CMD)


class TestGateExitCode(unittest.TestCase):
    def _write(self, d, name, content):
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        return p

    def test_gate_fails_when_broken(self):
        with tempfile.TemporaryDirectory() as d:
            conf = self._write(d, "conf.txt", CONF_FIXTURE)
            fuzz = self._write(d, "fuzz.txt", FUZZ_FIXTURE)
            rc = main(["--from-log", f"conf={conf},fuzz={fuzz}", "--out", os.path.join(d, "out"), "--ts", "2026-05-30T00:00:00Z"])
            self.assertEqual(rc, 1)

    def test_gate_passes_when_clean(self):
        with tempfile.TemporaryDirectory() as d:
            clean = self._write(d, "clean.txt", CLEAN_FIXTURE)
            rc = main(["--from-log", f"conf={clean}", "--out", os.path.join(d, "out"), "--ts", "2026-05-30T00:00:00Z"])
            self.assertEqual(rc, 0)

    def test_warn_only_never_fails(self):
        with tempfile.TemporaryDirectory() as d:
            conf = self._write(d, "conf.txt", CONF_FIXTURE)
            rc = main(["--from-log", f"conf={conf}", "--warn-only", "--out", os.path.join(d, "out"), "--ts", "2026-05-30T00:00:00Z"])
            self.assertEqual(rc, 0)  # warn-only annotates but does not block


if __name__ == "__main__":
    unittest.main(verbosity=2)
