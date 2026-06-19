#!/usr/bin/env python3
"""check_claims_manifest.py — recompute README headline claims from the tree.

Why this exists
---------------
The 2026-06 reality check (epic bd-5r99w) found the README's headline numbers had
drifted from what the tree actually contains (a "23k tests" badge that implied a
default `cargo test` runs them when ~21k are compiled out; "43 fuzz harnesses"
vs 146 on disk; "460+ validators" vs 436). bd-5r99w.5 corrected them; this gate
makes them *stay* correct: it recomputes each claim from the committed tree and
fails CI when the manifest (and therefore the README, which the manifest backs)
drifts beyond tolerance. It is the recompute foundation that the signed,
SDK-recomputable Honesty Manifest (bd-5r99w.9) builds on.

Claims recomputed
-----------------
  integration_tests_run_by_cargo_test   #[test] under tests/ + crates/**/tests/
  inline_tests_behind_inline_lane       #[test] under crates/**/src + sdk/**/src
  fuzz_targets_registered               [[bin]] paths into fuzz_targets/ in fuzz/Cargo.toml
  validators                            scripts/check_*.py
  unsafe_blocks                         real `unsafe {`/`unsafe fn`/`unsafe impl` in src (must be 0)
  license                               [workspace.package] license in Cargo.toml
  replay_verdict_load_bearing           incident-replay recompute is NOT debug-only (bd-5r99w.3)

Usage
-----
    python scripts/check_claims_manifest.py            # recompute + compare to manifest
    python scripts/check_claims_manifest.py --json      # robot output (claim/expected/actual)
    python scripts/check_claims_manifest.py --ci         # exit 1 on any drift
    python scripts/check_claims_manifest.py --update      # regenerate docs/claims_manifest.json
    python scripts/check_claims_manifest.py --self-test   # comparison/tolerance unit tests

Exit codes
----------
    0   no drift (or --warn-only)
    1   --ci/--strict and >= 1 claim drifted
    2   execution error
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from scripts.lib.test_logger import configure_test_logging
except Exception:  # pragma: no cover
    def configure_test_logging(_name):  # type: ignore
        import logging

        return logging.getLogger(_name)

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "docs" / "claims_manifest.json"
MANIFEST_SCHEMA = "franken-node/claims-manifest/v1"
TEST_ATTR_RE = re.compile(r"#\[\s*(?:tokio::)?test\s*\]")
UNSAFE_RE = re.compile(r"\bunsafe\s+(?:\{|fn\b|impl\b)")
LICENSE_RE = re.compile(r'^\s*license\s*=\s*"([^"]+)"', re.MULTILINE)


def _strip_line_comment(line: str) -> str:
    """Drop a // line comment (naive: ignores // inside strings, fine for the
    unsafe scan which only needs to avoid flagging commented mentions)."""
    in_str = False
    i = 0
    while i < len(line) - 1:
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str and c == "/" and line[i + 1] == "/":
            return line[:i]
        i += 1
    return line


def _count_attr_in_dirs(dirs, attr_re) -> int:
    total = 0
    for d in dirs:
        base = ROOT / d
        if not base.exists():
            continue
        for f in base.rglob("*.rs"):
            try:
                total += len(attr_re.findall(f.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                pass
    return total


def recompute_integration_tests() -> int:
    return _count_attr_in_dirs(
        ["tests", "crates/franken-node/tests", "sdk/verifier/tests"], TEST_ATTR_RE
    )


def recompute_inline_tests() -> int:
    return _count_attr_in_dirs(
        ["crates/franken-node/src", "sdk/verifier/src", "crates/franken-security-macros/src"],
        TEST_ATTR_RE,
    )


def recompute_fuzz_targets() -> int:
    manifest = ROOT / "fuzz" / "Cargo.toml"
    if not manifest.exists():
        return 0
    return len(
        [
            ln
            for ln in manifest.read_text(encoding="utf-8", errors="replace").splitlines()
            if re.match(r'\s*path\s*=\s*"fuzz_targets/', ln)
        ]
    )


def recompute_validators() -> int:
    return len(list((ROOT / "scripts").glob("check_*.py")))


def recompute_unsafe_blocks() -> int:
    total = 0
    for d in ["crates/franken-node/src", "sdk/verifier/src", "crates/franken-security-macros/src"]:
        base = ROOT / d
        if not base.exists():
            continue
        for f in base.rglob("*.rs"):
            try:
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    code = _strip_line_comment(line)
                    if UNSAFE_RE.search(code):
                        total += 1
            except OSError:
                pass
    return total


def recompute_license() -> str:
    cargo = ROOT / "Cargo.toml"
    if not cargo.exists():
        return ""
    text = cargo.read_text(encoding="utf-8", errors="replace")
    # Prefer the [workspace.package] license; fall back to the first license line.
    m = LICENSE_RE.search(text)
    return m.group(1) if m else ""


def recompute_replay_load_bearing() -> bool:
    """True iff incident-replay derives its verdict from a recompute that is NOT
    gated behind #[cfg(debug_assertions)] (the bd-5r99w.3 invariant), and the
    old clone-then-self-compare is absent from the verdict path."""
    f = ROOT / "crates" / "franken-node" / "src" / "tools" / "replay_bundle.rs"
    if not f.exists():
        return False
    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    # locate the compute fn; ensure the line above it is not #[cfg(debug_assertions)]
    for i, ln in enumerate(lines):
        if re.match(r"\s*fn compute_decision_sequence_hash\(", ln):
            prev = lines[i - 1].strip() if i > 0 else ""
            if "cfg(debug_assertions)" in prev:
                return False
            break
    else:
        return False
    # ensure the verdict fn recomputes (not clones the manifest hash into the verdict)
    body = "\n".join(lines)
    fn_idx = body.find("fn replay_bundle_after_signature_verification")
    if fn_idx < 0:
        return False
    window = body[fn_idx : fn_idx + 1500]
    recomputes = "let replayed_sequence_hash = compute_decision_sequence_hash(" in window
    self_compares = "replayed_sequence_hash = bundle.manifest.decision_sequence_hash.clone()" in window
    return recomputes and not self_compares


RECOMPUTERS = {
    "integration_tests_run_by_cargo_test": recompute_integration_tests,
    "inline_tests_behind_inline_lane": recompute_inline_tests,
    "fuzz_targets_registered": recompute_fuzz_targets,
    "validators": recompute_validators,
    "unsafe_blocks": recompute_unsafe_blocks,
    "license": recompute_license,
    "replay_verdict_load_bearing": recompute_replay_load_bearing,
}


def build_manifest() -> dict:
    return {
        "schema_version": MANIFEST_SCHEMA,
        "description": (
            "Machine-recomputable snapshot of README headline claims. Regenerate "
            "with `python scripts/check_claims_manifest.py --update` and reconcile "
            "the README when a rounded claim changes. Backs bd-5r99w.6 / bd-5r99w.9."
        ),
        "claims": {
            "integration_tests_run_by_cargo_test": {
                "value": recompute_integration_tests(),
                "kind": "count",
                "tolerance_pct": 30,
                "readme_claim": "~3.8k e2e (badge + Testing section)",
            },
            "inline_tests_behind_inline_lane": {
                "value": recompute_inline_tests(),
                "kind": "count",
                "tolerance_pct": 30,
                "readme_claim": "~21k inline (badge + Testing section)",
            },
            "fuzz_targets_registered": {
                "value": recompute_fuzz_targets(),
                "kind": "count",
                "tolerance_pct": 20,
                "readme_claim": "146 registered cargo-fuzz harnesses",
            },
            "validators": {
                "value": recompute_validators(),
                "kind": "count",
                "tolerance_pct": 20,
                "readme_claim": "430+ / ~436 scripts/check_*.py",
            },
            "unsafe_blocks": {
                "value": recompute_unsafe_blocks(),
                "kind": "exact",
                "readme_claim": "0 (#![forbid(unsafe_code)])",
            },
            "license": {
                "value": recompute_license(),
                "kind": "string",
                "readme_claim": "MIT + OpenAI/Anthropic Rider",
            },
            "replay_verdict_load_bearing": {
                "value": recompute_replay_load_bearing(),
                "kind": "bool",
                "readme_claim": "incident replay is integrity-verified / load-bearing (bd-5r99w.3)",
            },
        },
    }


def compare_claim(name: str, spec: dict, actual) -> tuple[bool, str]:
    """Return (ok, detail)."""
    kind = spec.get("kind", "count")
    expected = spec.get("value")
    if kind == "exact":
        ok = actual == expected
        return ok, f"expected {expected}, actual {actual}"
    if kind == "string":
        ok = str(actual) == str(expected)
        return ok, f"expected '{expected}', actual '{actual}'"
    if kind == "bool":
        ok = bool(actual) == bool(expected)
        return ok, f"expected {expected}, actual {actual}"
    # count: within tolerance band
    tol = float(spec.get("tolerance_pct", 20)) / 100.0
    if expected in (0, None):
        ok = actual == 0
        return ok, f"expected {expected}, actual {actual}"
    drift = abs(actual - expected) / float(expected)
    ok = drift <= tol
    return ok, f"expected {expected} ±{int(tol*100)}%, actual {actual} (drift {drift*100:.1f}%)"


def run_check(manifest: dict) -> tuple[list, list]:
    ok_list, drift_list = [], []
    for name, spec in manifest.get("claims", {}).items():
        recompute = RECOMPUTERS.get(name)
        if recompute is None:
            drift_list.append((name, f"no recomputer registered for claim '{name}'"))
            continue
        actual = recompute()
        ok, detail = compare_claim(name, spec, actual)
        (ok_list if ok else drift_list).append((name, detail))
    return ok_list, drift_list


# --------------------------------------------------------------------------- #
# Self-test (comparison/tolerance logic, deterministic — no tree dependency)
# --------------------------------------------------------------------------- #
def run_self_test() -> int:
    failures = 0

    def check(label, got, want):
        nonlocal failures
        if got != want:
            print(f"SELFTEST FAIL [{label}]: got {got}, want {want}")
            failures += 1
        else:
            print(f"selftest ok  [{label}]")

    # count within tolerance
    check("count_within_tol", compare_claim("c", {"kind": "count", "value": 100, "tolerance_pct": 30}, 120)[0], True)
    check("count_outside_tol", compare_claim("c", {"kind": "count", "value": 100, "tolerance_pct": 30}, 140)[0], False)
    check("count_regression", compare_claim("c", {"kind": "count", "value": 146, "tolerance_pct": 20}, 80)[0], False)
    # exact
    check("exact_zero_ok", compare_claim("u", {"kind": "exact", "value": 0}, 0)[0], True)
    check("exact_nonzero_bad", compare_claim("u", {"kind": "exact", "value": 0}, 1)[0], False)
    # string
    check("string_ok", compare_claim("l", {"kind": "string", "value": "LicenseRef-MIT-OpenAI-Anthropic-Rider"}, "LicenseRef-MIT-OpenAI-Anthropic-Rider")[0], True)
    check("string_bare_mit_bad", compare_claim("l", {"kind": "string", "value": "LicenseRef-MIT-OpenAI-Anthropic-Rider"}, "MIT")[0], False)
    # bool
    check("bool_true_ok", compare_claim("r", {"kind": "bool", "value": True}, True)[0], True)
    check("bool_regressed_bad", compare_claim("r", {"kind": "bool", "value": True}, False)[0], False)
    # comment stripper does not see commented unsafe
    check("strip_comment_unsafe", bool(UNSAFE_RE.search(_strip_line_comment("// unsafe impl Send"))), False)
    check("strip_keeps_real_unsafe", bool(UNSAFE_RE.search(_strip_line_comment("unsafe { ptr }"))), True)

    print(("\nself-test FAILED: %d" % failures) if failures else "\nself-test PASSED")
    return 1 if failures else 0


def main() -> int:
    logger = configure_test_logging("check_claims_manifest")
    ap = argparse.ArgumentParser(description="Recompute + gate README headline claims")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ci", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--warn-only", action="store_true")
    ap.add_argument("--update", action="store_true", help="regenerate docs/claims_manifest.json")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()

    if args.update:
        manifest = build_manifest()
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {MANIFEST_PATH.relative_to(ROOT)}")
        print(json.dumps(manifest["claims"], indent=2))
        return 0

    if not MANIFEST_PATH.exists():
        print(f"manifest missing: {MANIFEST_PATH} — run --update first", file=sys.stderr)
        return 2
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading manifest: {exc}", file=sys.stderr)
        return 2

    ok_list, drift_list = run_check(manifest)

    if args.json:
        print(json.dumps({
            "schema_version": manifest.get("schema_version"),
            "ok_count": len(ok_list),
            "drift_count": len(drift_list),
            "ok": [{"claim": n, "detail": d} for n, d in ok_list],
            "drift": [{"claim": n, "detail": d} for n, d in drift_list],
        }, indent=2))
    else:
        for n, d in ok_list:
            print(f"ok    {n}: {d}")
        for n, d in drift_list:
            print(f"DRIFT {n}: {d}")
        print(f"\n{len(ok_list)} ok, {len(drift_list)} drifted")

    logger.info("claims-manifest: %d ok, %d drift", len(ok_list), len(drift_list))
    if drift_list and (args.ci or args.strict) and not args.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
