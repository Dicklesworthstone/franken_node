#!/usr/bin/env python3
"""Map PR diff to the `tests/perf_beads/<bead>.sh` scripts to run.

Companion to `.github/workflows/perf-bead-tests.yml`. Reads the list
of changed files between two git revs and prints (one per line) the
relative path of every Tx.tests script whose mapped surface area
overlaps. New beads append a row to AFFECTED_MAP — the workflow
matrix expands automatically.

Usage:
  detect_affected_perf_beads.py --base <sha> --head <sha>

Output (stdout):
  tests/perf_beads/bd-98xo5.1.sh
  tests/perf_beads/bd-98xo5.7.sh
  ...

Exit codes:
  0  always — empty output is a valid "no perf bead touched" answer.

If `git diff --name-only` itself fails (e.g. unknown rev), the script
exits 2 and prints the diagnostic; the workflow then treats the PR as
"no perf beads affected" rather than blocking on unrelated infra.

Author: SilentCompass (bd-98xo5.15.2, parent: bd-98xo5.15).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# (test_script_relpath, [path_prefixes_that_trigger_it])
# New Tx.tests beads append a row; the workflow auto-detects.
# Keep the script paths in the canonical tests/perf_beads/ layout
# documented in docs/dev/perf_bead_testing.md.
AFFECTED_MAP: list[tuple[str, tuple[str, ...]]] = [
    # bd-98xo5.1 — threshold_sig preparsed VerifyingKey plumbing
    (
        "tests/perf_beads/bd-98xo5.1.sh",
        (
            "crates/franken-node/src/security/threshold_sig.rs",
            "crates/franken-node/src/crypto/schemes.rs",
        ),
    ),
    # bd-98xo5.2 — Ed25519Scheme preparsed key handle
    (
        "tests/perf_beads/bd-98xo5.2.sh",
        (
            "crates/franken-node/src/crypto/schemes.rs",
            "crates/franken-node/src/security/decision_receipt.rs",
            "crates/franken-node/benches/crypto_scheme_bench.rs",
        ),
    ),
    # bd-98xo5.4 — trust_card deep-clone removal (forward-declared)
    (
        "tests/perf_beads/bd-98xo5.4.sh",
        ("crates/franken-node/src/supply_chain/trust_card.rs",),
    ),
    # bd-98xo5.5 — DGIS NodeId u32 interning
    (
        "tests/perf_beads/bd-98xo5.5.sh",
        (
            "crates/franken-node/src/dgis/node_interner.rs",
            "crates/franken-node/src/dgis/contagion_graph.rs",
            "crates/franken-node/src/dgis/contagion_simulator.rs",
        ),
    ),
    # bd-98xo5.6 — replay_bundle ByteCounter
    (
        "tests/perf_beads/bd-98xo5.6.sh",
        ("crates/franken-node/src/tools/replay_bundle.rs",),
    ),
    # bd-98xo5.7 — fleet_transport path-alloc cleanup
    (
        "tests/perf_beads/bd-98xo5.7.sh",
        (
            "crates/franken-node/src/control_plane/fleet_transport.rs",
            "crates/franken-node/src/connector/canonical_serializer.rs",
        ),
    ),
    # bd-98xo5.8 — vef proof-chain benches
    (
        "tests/perf_beads/bd-98xo5.8.sh",
        (
            "crates/franken-node/src/vef/proof_generator.rs",
            "crates/franken-node/src/vef/receipt_chain.rs",
            "crates/franken-node/benches/vef_proof_chain_bench.rs",
        ),
    ),
    # bd-98xo5.15 — harness changes themselves
    (
        "tests/perf_beads/_self_check.sh",
        (
            "scripts/run_perf_bead_test.sh",
            "scripts/render_perf_test_summary.py",
            "scripts/detect_affected_perf_beads.py",
        ),
    ),
]


def _run_git_diff(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git diff failed: {result.stderr.strip()}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def detect(changed_files: list[str], scripts_root: Path) -> list[str]:
    """Return relative paths of test scripts whose mapped surface overlaps changed_files.

    Only scripts that physically exist on disk under scripts_root are
    returned; mapping rows for forward-declared (not-yet-authored)
    Tx.tests scripts are silently skipped. This keeps the workflow
    matrix from referencing dangling files mid-rollout.
    """
    touched: list[str] = []
    for script_rel, prefixes in AFFECTED_MAP:
        if not any(any(cf.startswith(p) for cf in changed_files) for p in prefixes):
            continue
        if not (scripts_root / script_rel).is_file():
            continue
        touched.append(script_rel)
    # Preserve declaration order; AFFECTED_MAP is the source of truth
    # for matrix order so re-running with the same diff yields the
    # same script list.
    return touched


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="base git rev (PR target)")
    parser.add_argument("--head", required=True, help="head git rev (PR source)")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of scripts/)",
    )
    args = parser.parse_args(argv)

    try:
        changed = _run_git_diff(args.base, args.head)
    except RuntimeError as exc:
        print(f"detect_affected_perf_beads: {exc}", file=sys.stderr)
        return 2

    scripts = detect(changed, args.repo_root)
    for script in scripts:
        print(script)
    return 0


if __name__ == "__main__":
    sys.exit(main())
