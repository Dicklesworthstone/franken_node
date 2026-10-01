#!/usr/bin/env python3
"""Recurrence-prevention gate: cap the "library island" surface (bd-reality-20260923-26n9r.14).

Root cause this prevents: the 2026-09-23 reality check found ~57% of non-test
product code under `crates/franken-node/src/**` was unreachable from the binary
(DGIS/BPET/VEF/time-travel/copilot_engine/reputation_graph_apis were "library
islands": compiled, unit-tested, but reachable from no CLI path). Charter §4
forbids "decorative controls without measurable behavior", so an unreachable
security primitive is decorative however well tested. This gate stops the island
surface from GROWING again: the measured count may only go DOWN.

PURE STATIC (no cargo/rch build). The method is a reference-based reachability
PROXY, which is deliberately conservative (it under-reports islands rather than
false-flag live code, so the gate never blocks legitimate work):

  1. Enumerate every module file under `src/**` (a `foo.rs`, or a `foo/mod.rs`
     whose module name is the directory `foo`).
  2. Parse every `(pub) mod NAME;` / `(pub) mod NAME {` declaration across the
     tree, carrying the `#[cfg(...)]` attributes above it, to learn which
     modules are gated behind an OPT-IN feature (anything other than the three
     default features engine/http-client/external-commands). Opt-in-gated
     modules are EXEMPT by construction: the feature exists to hold code that is
     deliberately not wired into the default binary (the bead's "GATE"
     disposition).
  3. A module is REACHABLE when some NON-TEST file other than its own
     file/directory references its name in a module/use/path position
     (`mod NAME`, `use ..::NAME`, `NAME::`, `::NAME`). `#[cfg(test)]` regions
     are blanked (brace-matched) before scanning, so a module reached only from
     tests still counts as an island.
  4. A DEFAULT-compiled module that is reachable from nothing is an island; its
     non-test lines are summed. The total must stay at or below the registered
     ceiling in `scripts/reachability_ceiling.json`.

Modes:
  --json         emit the machine-readable census to stdout.
  --warn-only    always exit 0 (annotate only).
  --update-ceiling  rewrite the ceiling to the current measured total (only ever
                 call this when the total has gone DOWN; CI never passes it).

Exit non-zero when the island line total EXCEEDS the ceiling (a new/opened
island), or when the ceiling is stale by more than the slack (the total dropped
and the ceiling was not tightened). The parsing helpers are pure functions,
unit-tested in scripts/test_check_reachability.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

SCHEMA = "franken-node/reachability-census/v1"

# The only features in the default build (crates/franken-node/Cargo.toml
# `default = ["engine", "http-client", "external-commands"]`). A module gated by
# ANY other feature is opt-in -> exempt (deliberately not in the default binary).
DEFAULT_FEATURES = {"engine", "http-client", "external-commands"}

# `(pub) mod name;` or `(pub) mod name {`, optionally `pub(crate)`/`pub(...)`.
MOD_DECL_RE = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+(?P<name>[a-z0-9_]+)[ \t]*[;{]"
)
ATTR_RE = re.compile(r"^[ \t]*#!?\[(?P<body>.+)\][ \t]*$")
FEATURE_RE = re.compile(r'feature[ \t]*=[ \t]*"(?P<feat>[^"]+)"')

# Files that are roots / declaration hubs, never "island" leaves themselves.
ROOT_FILES = {"lib.rs", "main.rs"}


# --- pure helpers -----------------------------------------------------------


def skip_to_item_end(text: str, start: int) -> int:
    """End offset of the item beginning at/after `start`, brace-matched and
    skipping string/char literals and comments (so a `format!("{}")` inside a
    test item cannot end the block early). An attribute decorating a `use`/
    `const` with no block ends at its semicolon."""
    i, n, depth = start, len(text), 0
    saw_brace = False
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n:
            if text[i + 1] == "/":
                nl = text.find("\n", i)
                if nl == -1:
                    return n
                i = nl
                continue
            if text[i + 1] == "*":
                end = text.find("*/", i + 2)
                i = n if end == -1 else end + 2
                continue
        if ch == '"':
            raw_hashes = 0
            j = i - 1
            while j >= 0 and text[j] == "#":
                raw_hashes += 1
                j -= 1
            if j >= 0 and text[j] == "r":
                closing = '"' + "#" * raw_hashes
                end = text.find(closing, i + 1)
                i = n if end == -1 else end + len(closing)
                continue
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "'":
            # lifetime vs char literal
            if i + 2 < n and text[i + 1] == "\\":
                end = text.find("'", i + 2)
                i = n if end == -1 else end + 1
                continue
            if i + 2 < n and text[i + 2] == "'":
                i += 3
                continue
            i += 1
            continue
        if ch == "{":
            depth += 1
            saw_brace = True
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        elif ch == ";" and depth == 0 and not saw_brace:
            return i + 1
        i += 1
    return n


def strip_test_regions(text: str) -> str:
    """Blank every `#[cfg(test)]` item to its own newlines, so later references
    found in production text are genuinely non-test and reported line numbers
    still line up with the file on disk."""
    out = text
    search_from = 0
    marker = "#[cfg(test)]"
    while True:
        at = out.find(marker, search_from)
        if at == -1:
            return out
        end = skip_to_item_end(out, at + len(marker))
        removed = out[at:end]
        out = out[:at] + "\n" * removed.count("\n") + out[end:]
        search_from = at + removed.count("\n")


def non_test_line_count(text: str) -> int:
    """Non-blank lines after test regions are stripped (the bead's 'non-test
    lines' metric; blank lines excluded so reformatting does not move the gate)."""
    stripped = strip_test_regions(text)
    return sum(1 for line in stripped.splitlines() if line.strip())


def module_name_for(rel_path: str) -> Optional[str]:
    """Module name of a src file: the dir for `foo/mod.rs`, else the file stem.
    Root files (lib.rs/main.rs) and mod.rs hubs map to their directory name."""
    base = os.path.basename(rel_path)
    if base in ROOT_FILES:
        return None
    if base == "mod.rs":
        return os.path.basename(os.path.dirname(rel_path))
    return base[:-3] if base.endswith(".rs") else None


# A `cfg(test)` predicate (the built-in test flag, not a Cargo feature).
_CFG_TEST_RE = re.compile(r"\btest\b")


def opt_in_feature_gated(attrs: List[str]) -> bool:
    """True if any carried `#[cfg(...)]` keeps the module OUT of the default
    release binary: a `cfg(test)` (test-only), or a feature outside the default
    set (engine/http-client/external-commands). A cfg naming only default
    features, or no cfg, is not exempt."""
    for body in attrs:
        if "cfg" not in body:
            continue
        feats = FEATURE_RE.findall(body)
        # Strip the feature="..." strings before looking for a bare `test` token.
        residual = FEATURE_RE.sub("", body)
        if _CFG_TEST_RE.search(residual):
            return True
        if feats and all(f in DEFAULT_FEATURES for f in feats):
            continue
        if feats:
            return True
    return False


def parse_mod_feature_gates(text: str) -> Dict[str, bool]:
    """Map `mod NAME` -> opt-in-gated? for declarations in one file, carrying the
    run of `#[cfg(...)]`/attributes immediately above each declaration."""
    gates: Dict[str, bool] = {}
    pending: List[str] = []
    for line in text.splitlines():
        attr = ATTR_RE.match(line)
        if attr:
            pending.append(attr.group("body"))
            continue
        m = MOD_DECL_RE.match(line)
        if m:
            name = m.group("name")
            gated = opt_in_feature_gated(pending)
            # If the same name is declared twice, opt-in anywhere wins only if
            # EVERY declaration is gated (a default-compiled copy makes it live).
            gates[name] = gates.get(name, True) and gated if name in gates else gated
            pending = []
            continue
        if line.strip() and not line.strip().startswith("//"):
            pending = []
    return gates


# Identifiers that appear adjacent to `::` are path references (`foo::bar`,
# `crate::..::foo`, `use a::b::foo`). The bare `mod NAME;` DECLARATION is
# deliberately NOT a reference: every module is declared by its parent, so a
# module reached only by its declaration (never `use`d / path-referenced) is an
# island.
_PATH_BEFORE_RE = re.compile(r"\b([a-z0-9_]+)::")
_PATH_AFTER_RE = re.compile(r"::([a-z0-9_]+)\b")


def path_referenced_idents(text: str) -> Set[str]:
    """Set of identifiers used in a path position (`foo::` or `::foo`) in `text`."""
    out = set(_PATH_BEFORE_RE.findall(text))
    out.update(_PATH_AFTER_RE.findall(text))
    return out


# --- census -----------------------------------------------------------------


@dataclass
class ModuleFile:
    rel_path: str
    name: str
    lines: int
    opt_in: bool
    own_dir: str


@dataclass
class Census:
    islands: List[ModuleFile] = field(default_factory=list)
    island_lines: int = 0
    scanned_files: int = 0
    exempt_opt_in: int = 0
    # Files with no `mod` declaration anywhere: never compiled, so not
    # "compiled-by-default-but-unreachable" — a separate (dead-file) problem,
    # reported but excluded from the island ceiling.
    undeclared: List[ModuleFile] = field(default_factory=list)
    undeclared_lines: int = 0


def collect_src_files(src_dir: str) -> List[str]:
    out: List[str] = []
    for root, _dirs, files in os.walk(src_dir):
        for f in files:
            if f.endswith(".rs"):
                out.append(os.path.join(root, f))
    return sorted(out)


def _subtree_of(rel: str) -> str:
    """The directory subtree a module 'owns'. For `a/b/foo.rs` it is `a/b/foo`
    (a sibling `a/b/foo/` dir, if any, belongs to the same module); for
    `a/b/foo/mod.rs` it is `a/b/foo`."""
    base = os.path.basename(rel)
    if base == "mod.rs":
        return os.path.dirname(rel)
    return rel[:-3] if rel.endswith(".rs") else rel


def run_census(repo_root: str, crate_dir: str) -> Tuple[Census, Dict[str, str]]:
    src_dir = os.path.join(repo_root, crate_dir, "src")
    abs_files = collect_src_files(src_dir)

    raw_by_rel: Dict[str, str] = {}
    refs_by_rel: Dict[str, Set[str]] = {}
    gates: Dict[str, bool] = {}
    for ap in abs_files:
        with open(ap, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        rel = os.path.relpath(ap, src_dir)
        raw_by_rel[rel] = raw
        # Path references are collected from TEST-STRIPPED text so a module used
        # only by #[cfg(test)] code still reads as an island.
        refs_by_rel[rel] = path_referenced_idents(strip_test_regions(raw))
        for name, gated in parse_mod_feature_gates(raw).items():
            gates[name] = gates.get(name, True) and gated if name in gates else gated

    declared = set(gates.keys())
    census = Census()
    for rel in sorted(raw_by_rel):
        census.scanned_files += 1
        name = module_name_for(rel)
        if name is None:
            continue
        if name not in declared:
            # No `mod NAME` anywhere -> file is never compiled (dead file).
            mf = ModuleFile(
                rel_path=rel,
                name=name,
                lines=non_test_line_count(raw_by_rel[rel]),
                opt_in=False,
                own_dir=os.path.dirname(rel),
            )
            census.undeclared.append(mf)
            census.undeclared_lines += mf.lines
            continue
        own_subtree = _subtree_of(rel)
        # Reachable if some file OUTSIDE this module's own subtree path-references
        # the module name.
        reachable = False
        for other_rel, ids in refs_by_rel.items():
            if other_rel == rel:
                continue
            if other_rel == own_subtree + ".rs" or other_rel.startswith(own_subtree + os.sep):
                continue  # self-reference within the module's own subtree
            if name in ids:
                reachable = True
                break
        if reachable:
            continue
        opt_in = gates.get(name, False)
        mf = ModuleFile(
            rel_path=rel,
            name=name,
            lines=non_test_line_count(raw_by_rel[rel]),
            opt_in=opt_in,
            own_dir=os.path.dirname(rel),
        )
        if opt_in:
            census.exempt_opt_in += 1
            continue
        census.islands.append(mf)
        census.island_lines += mf.lines

    census.islands.sort(key=lambda m: (-m.lines, m.rel_path))
    census.undeclared.sort(key=lambda m: (-m.lines, m.rel_path))
    return census, {}


# --- ceiling ----------------------------------------------------------------


def ceiling_path(repo_root: str) -> str:
    return os.path.join(repo_root, "scripts", "reachability_ceiling.json")


def load_ceiling(repo_root: str) -> Optional[int]:
    p = ceiling_path(repo_root)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return int(json.load(fh)["island_line_ceiling"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def write_ceiling(repo_root: str, value: int) -> None:
    p = ceiling_path(repo_root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    payload = {
        "schema": SCHEMA,
        "island_line_ceiling": value,
        "note": (
            "Max non-test lines in default-compiled, reference-unreachable modules "
            "(library islands). May only DECREASE. Lower it with "
            "`scripts/check_reachability.py --update-ceiling` after wiring or gating "
            "an island; CI never raises it."
        ),
    }
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="library-island reachability ceiling gate")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--crate-dir", default="crates/franken-node")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--warn-only", action="store_true")
    ap.add_argument("--update-ceiling", action="store_true")
    # Slack lets routine churn (a few lines) pass without a ceiling edit, while a
    # whole new island (hundreds of lines) still trips the gate.
    ap.add_argument("--slack", type=int, default=200)
    args = ap.parse_args(argv)

    census, _ = run_census(args.repo_root, args.crate_dir)
    ceiling = load_ceiling(args.repo_root)

    report = {
        "schema": SCHEMA,
        "island_line_total": census.island_lines,
        "island_count": len(census.islands),
        "scanned_files": census.scanned_files,
        "exempt_opt_in_modules": census.exempt_opt_in,
        "undeclared_dead_files": len(census.undeclared),
        "undeclared_dead_lines": census.undeclared_lines,
        "ceiling": ceiling,
        "top_islands": [
            {"module": m.name, "path": m.rel_path, "lines": m.lines}
            for m in census.islands[:25]
        ],
    }

    if args.update_ceiling:
        write_ceiling(args.repo_root, census.island_lines)
        report["ceiling"] = census.island_lines
        report["updated_ceiling"] = True
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"ceiling updated to {census.island_lines} island lines")
        return 0

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"reachability census: {census.island_lines} island lines across "
            f"{len(census.islands)} default-compiled unreachable modules "
            f"({census.exempt_opt_in} opt-in modules exempt; ceiling={ceiling})"
        )
        for m in census.islands[:15]:
            print(f"  ISLAND {m.rel_path} ({m.name}): {m.lines} lines")

    if ceiling is None:
        print(
            "no ceiling registered; run --update-ceiling to establish one",
            file=sys.stderr,
        )
        return 0 if args.warn_only else 1

    exceeded = census.island_lines > ceiling + args.slack
    if exceeded and not args.warn_only:
        print(
            f"FAIL: island line total {census.island_lines} exceeds ceiling "
            f"{ceiling} (+slack {args.slack}). Wire or opt-in-gate the new island, "
            f"or lower the ceiling with --update-ceiling if it legitimately shrank.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
