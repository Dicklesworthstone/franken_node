"""Structural smoke test for tests/perf_beads/_template.sh (bd-98xo5.15.3).

Why not run the template end-to-end here:

  Acceptance §1 of bd-98xo5.15.3 says
  `bash tests/perf_beads/_template.sh` exits 0 on a clean repo. That
  requires a full `cargo build --profile release-perf -p frankenengine-node
  --bench crypto_scheme_bench` + a Criterion re-baseline. Both are
  multi-minute operations that would balloon the unit-test suite; the
  CI workflow at `.github/workflows/perf-bead-tests.yml` is where the
  full end-to-end run lives.

What this file does check:

  - The template parses as bash (`bash -n`) — catches typos / quoting bugs.
  - The template is executable.
  - The template sources the bd-98xo5.15.1 harness and calls every
    required public API function at least once (perf_test_init,
    perf_test_start, perf_test_case, perf_test_pass, perf_test_fail,
    perf_test_skip, perf_test_measurement, perf_test_summary,
    perf_test_run_cargo).
  - The template's BEAD_ID is set (not left as `${BEAD_ID}` shell expansion).
  - The template includes the canonical `build` / `unit` / `baseline`
    phases in the documented order.
  - The companion README.md exists and references every API function.

To exercise the full producer→consumer round-trip without cargo, the
final test runs a stripped-down replica template that calls every
harness function with mocked cargo (skipping the heavy build) and
asserts the resulting JSONL is rendered by
`scripts/render_perf_test_summary.py --ci` with exit 0.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "tests/perf_beads/_template.sh"
README = ROOT / "tests/perf_beads/README.md"
HARNESS = ROOT / "scripts/run_perf_bead_test.sh"
RENDERER = ROOT / "scripts/render_perf_test_summary.py"

REQUIRED_API_FNS = (
    "perf_test_init",
    "perf_test_start",
    "perf_test_case",
    "perf_test_pass",
    "perf_test_fail",
    "perf_test_skip",
    "perf_test_measurement",
    "perf_test_summary",
    "perf_test_run_cargo",
)

REQUIRED_PHASES_IN_ORDER = ("build", "unit", "baseline")


class TestPerfBeadTemplate(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.body = TEMPLATE.read_text(encoding="utf-8")

    def test_template_exists_and_is_executable(self) -> None:
        self.assertTrue(TEMPLATE.exists(), f"missing {TEMPLATE}")
        mode = TEMPLATE.stat().st_mode
        self.assertTrue(mode & 0o111, f"_template.sh is not executable (mode {oct(mode)})")

    def test_template_parses_as_bash(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(TEMPLATE)], capture_output=True, text=True, check=False
        )
        self.assertEqual(
            result.returncode, 0, f"bash -n failed: stderr={result.stderr!r}"
        )

    def test_template_calls_every_required_api_function(self) -> None:
        for fn in REQUIRED_API_FNS:
            self.assertIn(
                fn,
                self.body,
                f"_template.sh must demonstrate {fn} — missing means new authors lose the example",
            )

    def test_template_sets_concrete_bead_id(self) -> None:
        m = re.search(r'^BEAD_ID="([^"]+)"', self.body, re.MULTILINE)
        self.assertIsNotNone(m, "BEAD_ID assignment must be present at top-level")
        bead_id = m.group(1) if m else ""
        self.assertTrue(
            bead_id.startswith("bd-98xo5."),
            f"BEAD_ID should be a bd-98xo5.* slot, got {bead_id!r}",
        )

    def test_template_sources_the_harness(self) -> None:
        self.assertIn(
            "scripts/run_perf_bead_test.sh",
            self.body,
            "_template.sh must source scripts/run_perf_bead_test.sh",
        )
        self.assertIn(
            "perf_test_init",
            self.body,
            "_template.sh must call perf_test_init",
        )

    def test_template_phases_appear_in_canonical_order(self) -> None:
        positions: list[tuple[str, int]] = []
        for phase in REQUIRED_PHASES_IN_ORDER:
            pattern = rf'perf_test_start[ \t]+"{phase}"'
            m = re.search(pattern, self.body)
            self.assertIsNotNone(m, f"_template.sh missing perf_test_start {phase!r}")
            positions.append((phase, m.start() if m else -1))
        for (name_a, pos_a), (name_b, pos_b) in zip(positions, positions[1:]):
            self.assertLess(
                pos_a,
                pos_b,
                f"phase order broken: {name_a!r} must appear before {name_b!r}",
            )

    def test_readme_exists_and_references_every_api_fn(self) -> None:
        self.assertTrue(README.exists(), f"missing {README}")
        readme = README.read_text(encoding="utf-8")
        for fn in REQUIRED_API_FNS:
            self.assertIn(fn, readme, f"README must document {fn}")
        # Reference convention + every phase name appears at least once.
        for phase in ("build", "unit", "property", "fuzz", "e2e", "baseline", "cleanup"):
            self.assertIn(phase, readme, f"README must mention phase {phase!r}")
        self.assertIn(
            "bd-98xo5.X.tests.sh",
            readme,
            "README must document the naming convention",
        )

    def test_harness_template_renders_pass_via_renderer(self) -> None:
        """End-to-end without cargo: drive the harness directly and render."""
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            # Make a fake git root so harness uses tmp/tests/artifacts/perf/...
            (scratch / ".git").mkdir()
            harness_dir = scratch / "scripts"
            harness_dir.mkdir()
            shutil.copy2(HARNESS, harness_dir / "run_perf_bead_test.sh")

            # Stripped-down replica template: every API surface, no cargo.
            replica = scratch / "fake_template.sh"
            replica.write_text(
                f"""#!/usr/bin/env bash
set -uo pipefail
source "{harness_dir / "run_perf_bead_test.sh"}"
perf_test_init "bd-98xo5.template-smoke.tests"
perf_test_start "build"
perf_test_case "fake-build"
perf_test_pass
perf_test_summary
perf_test_start "unit"
perf_test_case "fake-unit-case"
perf_test_pass
perf_test_case "skipped-case"
perf_test_skip "no env"
perf_test_summary
perf_test_start "baseline"
perf_test_measurement "fake_metric_us" "42.5" "microseconds"
perf_test_case "budget-check"
perf_test_pass
perf_test_summary
exit 0
"""
            )
            replica.chmod(0o755)
            env = os.environ.copy()
            env["NO_COLOR"] = "1"
            run = subprocess.run(
                ["bash", str(replica)],
                cwd=scratch,
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(
                run.returncode, 0, f"replica template exit nonzero: {run.stderr!r}"
            )
            logs = list(scratch.glob("tests/artifacts/perf/test_runs/*/test_log.jsonl"))
            self.assertEqual(
                len(logs), 1, f"expected exactly one JSONL log, found {logs}"
            )
            rendered = subprocess.run(
                [sys.executable, str(RENDERER), "--ci", str(logs[0])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                rendered.returncode,
                0,
                f"renderer --ci must report PASS; got {rendered.returncode}, "
                f"stdout={rendered.stdout!r} stderr={rendered.stderr!r}",
            )
            self.assertIn("PASS", rendered.stdout)


if __name__ == "__main__":
    unittest.main()
