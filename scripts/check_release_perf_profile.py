#!/usr/bin/env python3
"""Assert workspace [profile.release-perf] exists with canonical values.

This is the CI back-stop for bd-98xo5.11 — the [profile.release-perf]
section in workspace Cargo.toml has been silently reverted by
concurrent swarm agents during the perf rounds. Every fingerprint.json
under tests/artifacts/perf/<run-id>/ was built against this exact
profile; removing or mutating it silently invalidates every historical
hotspot table in the repo.

Run with --ci to exit non-zero on any mismatch (used by
.github/workflows/release-perf-profile-gate.yml). Run without args
for a friendlier diagnostic that prints what's missing or wrong.

See docs/dev/profiling.md for the canonical block and per-key
rationale.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARGO_TOML = ROOT / "Cargo.toml"

WANT: dict[str, object] = {
    "inherits": "release",
    "opt-level": 3,
    "lto": "thin",
    "codegen-units": 1,
    "debug": "line-tables-only",
    "strip": False,
}


def check_profile(cargo_toml_path: Path) -> tuple[int, str]:
    """Return (exit_code, message). 0 = canonical, 1 = missing or wrong."""
    if not cargo_toml_path.exists():
        return 1, f"FAIL: {cargo_toml_path} does not exist"
    with cargo_toml_path.open("rb") as f:
        data = tomllib.load(f)
    profile = data.get("profile", {}).get("release-perf")
    if profile is None:
        return 1, (
            "FAIL: [profile.release-perf] missing from Cargo.toml. "
            "See docs/dev/profiling.md for the canonical block."
        )
    missing = {k: v for k, v in WANT.items() if profile.get(k) != v}
    if missing:
        return 1, (
            f"FAIL: [profile.release-perf] has wrong values: {missing}. "
            "See docs/dev/profiling.md for the canonical block."
        )
    return 0, "OK: release-perf profile is canonical."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: exit non-zero on mismatch (default exits 1 too, but "
        "prints a friendlier diagnostic without --ci).",
    )
    parser.add_argument(
        "--cargo-toml",
        type=Path,
        default=CARGO_TOML,
        help="Path to Cargo.toml (default: workspace root)",
    )
    args = parser.parse_args(argv)
    code, msg = check_profile(args.cargo_toml)
    print(msg)
    return code


if __name__ == "__main__":
    sys.exit(main())
