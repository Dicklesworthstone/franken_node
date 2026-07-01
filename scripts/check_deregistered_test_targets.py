#!/usr/bin/env python3
"""Recurrence-prevention gate .G2: detect orphaned test-file coverage holes (bd-romfp).

Root cause this prevents (complements the .G1 compile-census, bd-rjc2m.2):
`crates/franken-node/Cargo.toml` sets `autotests = false`, so a `tests/*.rs`
source file runs ONLY if it is (a) an explicitly registered `[[test]]` target,
or (b) transitively pulled into a registered target via `#[path]`, `include!`,
or `mod`. A conformance/golden file that is dropped from `[[test]]` (or added but
never registered) silently loses coverage — and the .G1 compile-census CANNOT
see it, because cargo never even attempts to compile an unregistered file.

This gate is PURE STATIC (no cargo/rch builds):
  1. parse registered [[test]] name/path from Cargo.toml,
  2. resolve the transitive #[path]/include!/mod closure reachable from those
     registered target roots (so genuine helper files pulled in by a registered
     wrapper are NOT flagged),
  3. list top-level `tests/*.rs` files NOT in that closure (= orphaned),
  4. classify each orphan and FLAG default-lane test categories
     (conformance / golden / metamorphic / contract / vectors / e2e) while
     ALLOWLISTING intentionally-separate ones (fuzz / loom / bench /
     real-service / no-mocks / *_helpers),
  5. emit a JSONL report + human summary and EXIT NON-ZERO on any FLAGGED orphan.

Modes:
  --warn-only   always exit 0 (annotate only) — matches the .G1 posture while
                the de-registration backlog (bd-rjc2m .C*/.E2E1) is remediated.
  --out DIR     write orphan_census_<ts>.{jsonl,md} (default: artifacts/verification)

The parsing/classification helpers are pure functions, unit-tested separately in
scripts/test_check_deregistered_test_targets.py.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Set, Tuple

# --- pure parsing -----------------------------------------------------------

_TEST_HEADER_RE = re.compile(r"^\s*\[\[test\]\]\s*$")
_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"\s*$')
_PATH_RE = re.compile(r'^\s*path\s*=\s*"([^"]+)"\s*$')
# `#[path = "X"]`, `include!("X")`, and `mod ident;`
_HASH_PATH_RE = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
_INCLUDE_RE = re.compile(r'include!\s*\(\s*"([^"]+)"\s*\)')
_MOD_RE = re.compile(r'^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;')


def parse_registered_targets(cargo_toml_text: str) -> List[Tuple[str, str]]:
    """Pure. Return [(name, path)] for every [[test]] block.

    `path` defaults to `tests/<name>.rs` when a block omits an explicit path
    (cargo's default target path), matching cargo behavior under autotests=false.
    """
    targets: List[Tuple[str, str]] = []
    in_block = False
    name: Optional[str] = None
    path: Optional[str] = None

    def flush() -> None:
        nonlocal name, path
        if name is not None:
            targets.append((name, path if path is not None else f"tests/{name}.rs"))
        name, path = None, None

    for line in cargo_toml_text.splitlines():
        if _TEST_HEADER_RE.match(line):
            if in_block:
                flush()
            in_block = True
            continue
        if not in_block:
            continue
        # A new top-level table header ends the current [[test]] block.
        stripped = line.strip()
        if stripped.startswith("[") and not _TEST_HEADER_RE.match(line):
            flush()
            in_block = False
            continue
        m = _NAME_RE.match(line)
        if m:
            name = m.group(1)
            continue
        m = _PATH_RE.match(line)
        if m:
            path = m.group(1)
    if in_block:
        flush()
    return targets


def extract_includes(rs_text: str) -> List[Tuple[str, str]]:
    """Pure. Return [(kind, ref)] references a source file pulls in.

    kind is 'path' for `#[path = "X"]`/`include!("X")` (X is a path relative to
    the referencing file's directory) or 'mod' for `mod ident;` (ident resolves
    to <dir>/ident.rs or <dir>/ident/mod.rs). `#[path]`-annotated `mod` uses the
    path form (the plain-mod fallback is skipped for those lines).
    """
    refs: List[Tuple[str, str]] = []
    hash_path_lines: Set[int] = set()
    lines = rs_text.splitlines()
    for i, line in enumerate(lines):
        for m in _HASH_PATH_RE.finditer(line):
            refs.append(("path", m.group(1)))
            hash_path_lines.add(i)
            # a `#[path=..]` frequently precedes `mod x;` on the next line
            hash_path_lines.add(i + 1)
    for m in _INCLUDE_RE.finditer(rs_text):
        refs.append(("path", m.group(1)))
    for i, line in enumerate(lines):
        if i in hash_path_lines:
            continue
        m = _MOD_RE.match(line)
        if m:
            refs.append(("mod", m.group(1)))
    return refs


# --- classification ---------------------------------------------------------

# Intentionally NOT registered as crate [[test]] targets. Ordered: first hit wins.
_ALLOWLIST_RULES: List[Tuple[str, str]] = [
    ("fuzz", "fuzz"),               # cargo-fuzz bins under fuzz/Cargo.toml
    ("loom", "loom"),               # run under --cfg loom, separate lane
    ("bench", "bench"),             # criterion [[bench]], not [[test]]
    ("real_service", "real-service"),
    ("real_enforcement", "real-service"),
    ("real_crypto", "real-service"),
    ("no_mocks", "real-service"),
]
# Default-lane categories that SHOULD be a registered/reachable target.
_FLAG_RULES: List[Tuple[str, str]] = [
    ("conformance", "conformance"),
    ("metamorphic", "metamorphic"),
    ("golden", "golden"),
    ("vectors", "vectors"),
    ("contract", "contract"),
    ("_e2e", "e2e"),
]


def classify(name: str) -> Tuple[str, bool]:
    """Pure. Return (category, flagged).

    flagged=True means this orphan is a probable coverage hole that should be
    (re-)registered or wired into a registered target. Helper modules
    (`*_helpers`/`*_helper`) and support shims are allowlisted (they are meant to
    be #[path]-included, so if they surface as orphans it is only because their
    sole includer is itself orphaned — reported as non-flagged 'helper').
    """
    lname = name.lower()
    if lname.endswith("_helpers") or lname.endswith("_helper") or lname.endswith("_support"):
        return ("helper", False)
    for needle, category in _ALLOWLIST_RULES:
        if needle in lname:
            return (category, False)
    for needle, category in _FLAG_RULES:
        if needle in lname:
            return (category, True)
    return ("review", False)


# --- reachability + orphan detection (I/O) ----------------------------------

def _norm(repo_root: str, rel: str) -> str:
    return os.path.normpath(os.path.join(repo_root, rel))


def resolve_reference(kind: str, ref: str, from_file_abs: str) -> List[str]:
    """Return candidate absolute target paths a reference could resolve to."""
    base = os.path.dirname(from_file_abs)
    if kind == "path":
        return [os.path.normpath(os.path.join(base, ref))]
    # kind == "mod": <dir>/ident.rs or <dir>/ident/mod.rs
    return [
        os.path.normpath(os.path.join(base, f"{ref}.rs")),
        os.path.normpath(os.path.join(base, ref, "mod.rs")),
    ]


def compute_reachable(seed_files: List[str]) -> Set[str]:
    """BFS the #[path]/include!/mod closure from the seed (registered) roots.

    Missing files are skipped (a stale registered path is a separate .G1/.E2E1
    concern). Returns the set of absolute source files that are compiled because
    a registered target reaches them.
    """
    reachable: Set[str] = set()
    stack = [os.path.normpath(f) for f in seed_files]
    while stack:
        cur = stack.pop()
        if cur in reachable:
            continue
        reachable.add(cur)
        if not os.path.isfile(cur):
            continue
        try:
            with open(cur, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for kind, ref in extract_includes(text):
            for cand in resolve_reference(kind, ref, cur):
                if cand not in reachable and os.path.isfile(cand):
                    stack.append(cand)
    return reachable


def find_orphans(repo_root: str, crate_dir: str) -> List[dict]:
    """List top-level tests/*.rs orphans (not registered, not reachable)."""
    cargo_toml = os.path.join(crate_dir, "Cargo.toml")
    with open(cargo_toml, encoding="utf-8") as fh:
        registered = parse_registered_targets(fh.read())
    seed = [_norm(crate_dir, path) for _name, path in registered]
    reachable = compute_reachable(seed)

    tests_dir = os.path.join(crate_dir, "tests")
    orphans: List[dict] = []
    for entry in sorted(os.listdir(tests_dir)):
        if not entry.endswith(".rs"):
            continue
        abs_path = os.path.normpath(os.path.join(tests_dir, entry))
        if abs_path in reachable:
            continue
        name = entry[:-3]
        category, flagged = classify(name)
        rel = os.path.relpath(abs_path, repo_root)
        orphans.append({"target": name, "path": rel, "category": category, "flagged": flagged})
    return orphans


# --- gate main --------------------------------------------------------------

def render_summary(orphans: List[dict]) -> str:
    flagged = [o for o in orphans if o["flagged"]]
    allow = [o for o in orphans if not o["flagged"]]
    by_cat: Dict[str, int] = {}
    for o in orphans:
        by_cat[o["category"]] = by_cat.get(o["category"], 0) + 1
    lines = ["# Orphaned test-file census (.G2)\n"]
    lines.append(f"- top-level orphans: {len(orphans)} "
                 f"(flagged coverage holes: {len(flagged)}, allowlisted/review: {len(allow)})")
    lines.append(f"- by category: " + ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items())))
    if flagged:
        lines.append("\n## FLAGGED (should be registered or #[path]-wired):")
        for o in flagged:
            lines.append(f"  - [{o['category']}] {o['target']}  ({o['path']})")
    if allow:
        lines.append("\n## allowlisted / review (informational):")
        for o in allow:
            lines.append(f"  - [{o['category']}] {o['target']}")
    return "\n".join(lines) + "\n"


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="de-registered/orphaned test-file census gate (.G2)")
    ap.add_argument("--crate-dir", default="crates/franken-node")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--warn-only", action="store_true")
    ap.add_argument("--out", default="artifacts/verification")
    ap.add_argument("--ts", default=None)
    args = ap.parse_args(argv)

    ts = args.ts or os.environ.get("GATE_TS", "1970-01-01T00:00:00Z")
    repo_root = os.path.abspath(args.repo_root)
    crate_dir = os.path.join(repo_root, args.crate_dir)

    orphans = find_orphans(repo_root, crate_dir)
    flagged = [o for o in orphans if o["flagged"]]

    os.makedirs(args.out, exist_ok=True)
    stamp = ts.replace(":", "").replace("-", "")
    jsonl = os.path.join(args.out, f"orphan_census_{stamp}.jsonl")
    with open(jsonl, "w", encoding="utf-8") as fh:
        for o in orphans:
            fh.write(json.dumps({**o, "ts": ts}, sort_keys=True) + "\n")

    sys.stdout.write(render_summary(orphans))
    sys.stdout.write(f"\n[gate] flagged orphans: {len(flagged)}; report: {jsonl}\n")

    if args.warn_only:
        if flagged:
            sys.stderr.write(
                f"::warning::{len(flagged)} orphaned test files are not registered or "
                f"reachable (coverage holes; warn-only mode)\n"
            )
        return 0
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
