#!/usr/bin/env python3
"""check_no_self_compare.py — static lint against self-comparison / unexecuted-PASS.

Why this exists
---------------
The 2026-06-18/19 reality-check audit (epic bd-5r99w) found a recurring bug
CLASS, not a single defect:

  * `incident replay` compared a value to a *clone of itself* to manufacture a
    PASS — the genuine recompute lived only behind `#[cfg(debug_assertions)]`,
    so release builds short-circuited to `x = source.clone(); ct_eq(x, source)`
    (fixed in bd-5r99w.3).
  * replay/verify "adapters" returned their own input as the "recomputed" value
    (fixture-tautology), so a verdict could never diverge.

This guard makes that whole class impossible to reintroduce in PRODUCTION code,
complementing the verification-target compile census (bd-rjc2m.2) and the
no-unexecuted-PASS gate (bd-f5b04.8.3).

Scope
-----
The lint targets production verdict/hash logic. Test code is intentionally out
of scope: `tests/`, `fuzz/`, and `benches/` trees are skipped, and inline
`#[cfg(test)]` / `#[test]` regions are blanked before matching, because
reflexivity checks (`ct_eq(&x, &x)` proving the primitive is reflexive) and
snapshot-then-assert-unchanged patterns are legitimate there. Test honesty
(no-unexecuted-PASS in tests) is owned by bd-rjc2m.21 / bd-f5b04.8.3.

Detection rules
---------------
    SC1 (REJECT)  A constant-time/equality comparison whose two operands are
                  textually identical after stripping `&`/`*` and a trailing
                  `.clone()`/`.to_owned()`/`.to_vec()`:
                      ct_eq(x, x)            constant_time::ct_eq(&a, &a)
                      ct_eq(&a, &a.clone())  assert_eq!(h, h)
                      x == x.clone()         debug_assert_eq!(v, v)
    SC2 (REJECT)  Clone-then-compare-to-source within one function window:
                      let replayed = manifest.hash.clone();
                      ... ct_eq(&replayed, &manifest.hash)
                  (the exact bd-5r99w.3 release-build self-compare).
    SC3 (WARN)    A `#[cfg(debug_assertions)]` block computes `let X = recompute(..)`
                  and the release path immediately rebinds `let X = <expr>.clone();`
                  — i.e. the real recompute is debug-only and release clones.

Comments and string-literal contents are stripped before matching, so a doc
comment that *describes* the bug is never itself flagged. Add
`// lint:allow-self-compare` on the flagged line (or the line above) to suppress
a deliberate reflexivity check.

Usage
-----
    python scripts/check_no_self_compare.py                 # scan crates/ + sdk/
    python scripts/check_no_self_compare.py path/a.rs b.rs  # scan specific files
    python scripts/check_no_self_compare.py --json
    python scripts/check_no_self_compare.py --ci            # exit 1 on any REJECT
    python scripts/check_no_self_compare.py --warn-only     # never exit 1
    python scripts/check_no_self_compare.py --self-test     # run fixtures

Exit codes
----------
    0   no REJECT findings (or --warn-only)
    1   --ci / --strict and >= 1 REJECT finding
    2   execution error
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from scripts.lib.test_logger import configure_test_logging
except Exception:  # pragma: no cover - logging is best-effort
    def configure_test_logging(_name):  # type: ignore
        import logging

        return logging.getLogger(_name)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCAN_DIRS = ["crates", "sdk"]
SKIP_DIR_NAMES = {"tests", "fuzz", "benches", "target", "fuzz_targets"}
SUPPRESS_MARKER = "lint:allow-self-compare"

CT_EQ_OPEN = re.compile(r"\b(?:[A-Za-z_][\w]*::)*ct_eq(?:_bytes|_inline)?\s*\(")
ASSERT_EQ_OPEN = re.compile(r"\b(?:debug_)?assert_eq!\s*\(")
TEST_ATTR = re.compile(r"#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|.*\btest\b)")

# `X == X.clone()` / `X.clone() == X`  (backref ties both sides to the same base)
EQ_CLONE_FWD = re.compile(
    r"([\w.\[\]()]+?)\s*(?:==|!=)\s*\1\s*\.(?:clone|to_owned|to_vec)\s*\(\s*\)"
)
EQ_CLONE_REV = re.compile(
    r"([\w.\[\]()]+?)\s*\.(?:clone|to_owned|to_vec)\s*\(\s*\)\s*(?:==|!=)\s*\1\b"
)
# `X == X` for paren-free, non-literal operands
EQ_IDENT = re.compile(r"(?<![\w.])([A-Za-z_][\w.\[\]]*)\s*(?:==|!=)\s*([A-Za-z_][\w.\[\]]*)")

SC2_CLONE_BIND = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*([\w.\[\]()]+?)\.(?:clone|to_owned|to_vec)\(\)\s*;"
)
DEBUG_CFG = re.compile(r"#\[cfg\(debug_assertions\)\]")
LET_CALL = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*[\w:]+\s*\(")
LET_CLONE = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*[\w.\[\]()]+?\.(?:clone|to_owned|to_vec)\(\)\s*;"
)

LITERAL_PREFIX = re.compile(r'^[&*\s]*(?:-?\d|true\b|false\b|None\b|Some\b|Ok\b|Err\b|"|\')')
TRAILING_CONV = re.compile(r"\.(?:clone|to_owned|to_vec)\(\)\s*$")


@dataclass
class Finding:
    rule: str
    severity: str  # "reject" | "warn"
    file: str
    line: int
    snippet: str
    detail: str


def strip_comments_and_strings(text: str) -> str:
    """Blank comments and string-literal contents, preserving newlines/length so
    line numbers stay exact."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = in_char = False
    raw_hashes = -1
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
            continue
        if in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if raw_hashes >= 0:
            if c == '"' and text[i + 1 : i + 1 + raw_hashes] == "#" * raw_hashes:
                out.append('"' + "#" * raw_hashes)
                i += 1 + raw_hashes
                raw_hashes = -1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if in_str:
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == '"':
                out.append('"')
                in_str = False
                i += 1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if in_char:
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == "'":
                out.append("'")
                in_char = False
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        if c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
            continue
        m = re.match(r'(b?r)(#*)"', text[i : i + 8])
        if m:
            raw_hashes = len(m.group(2))
            out.append(m.group(0))
            i += len(m.group(0))
            continue
        if c == '"':
            in_str = True
            out.append('"')
            i += 1
            continue
        if c == "'":
            if re.match(r"'(?:\\.|[^'\\])'", text[i : i + 4]):
                in_char = True
                out.append("'")
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def blank_test_regions(text: str) -> str:
    """Blank `#[cfg(test)]` / `#[test]` items (attribute through closing brace),
    preserving newlines so production-only matching keeps exact line numbers."""
    lines = text.split("\n")
    out = list(lines)
    i = 0
    n = len(lines)
    while i < n:
        if TEST_ATTR.search(lines[i]):
            # find the item's opening brace, then blank to the matching close
            depth = 0
            started = False
            j = i
            while j < n:
                depth += out[j].count("{") - out[j].count("}")
                if "{" in lines[j]:
                    started = True
                # blank this line entirely (attribute + body)
                out[j] = ""
                if started and depth <= 0:
                    break
                # guard: a bare attribute with no following brace within 3 lines
                if not started and j - i > 3:
                    break
                j += 1
            i = j + 1
            continue
        i += 1
    return "\n".join(out)


def _extract_two_args(text: str, open_idx: int) -> Optional[tuple[str, str]]:
    """Given index of '(' , return the first two top-level comma-split args."""
    depth = 0
    args: list[str] = []
    cur = []
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                break
        if depth == 1 and c == ",":
            args.append("".join(cur))
            cur = []
            i += 1
            if len(args) >= 2:
                # we have at least two args; stop scanning further
                # (still want to find close for safety, but two is enough)
                pass
            continue
        cur.append(c)
        i += 1
    if len(args) >= 2:
        return args[0].strip(), args[1].strip()
    return None


def _norm(expr: str) -> str:
    e = expr.strip().lstrip("&* \t").strip()
    prev = None
    while prev != e:
        prev = e
        e = TRAILING_CONV.sub("", e).strip()
    return e


def _is_literalish(expr: str) -> bool:
    e = expr.strip()
    return bool(LITERAL_PREFIX.match(e)) or len(_norm(e)) < 2


def _suppressed(raw_lines: list[str], idx: int) -> bool:
    if 0 <= idx < len(raw_lines) and SUPPRESS_MARKER in raw_lines[idx]:
        return True
    if 0 < idx <= len(raw_lines) and idx - 1 < len(raw_lines) and SUPPRESS_MARKER in raw_lines[idx - 1]:
        return True
    return False


def _line_of(text: str, char_idx: int) -> int:
    return text.count("\n", 0, char_idx)


def lint_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    raw_lines = text.split("\n")
    stripped = blank_test_regions(strip_comments_and_strings(text))
    s_lines = stripped.split("\n")

    def add(rule, severity, line_idx, detail):
        if _suppressed(raw_lines, line_idx):
            return
        snippet = raw_lines[line_idx].strip()[:200] if line_idx < len(raw_lines) else ""
        findings.append(Finding(rule, severity, path, line_idx + 1, snippet, detail))

    # SC1: ct_eq(...) / assert_eq!(...) with two normalize-identical args.
    for opener, label in ((CT_EQ_OPEN, "constant-time comparison"), (ASSERT_EQ_OPEN, "assert_eq!")):
        for m in opener.finditer(stripped):
            two = _extract_two_args(stripped, m.end() - 1)
            if not two:
                continue
            a, b = _norm(two[0]), _norm(two[1])
            if a and a == b and not (label == "assert_eq!" and _is_literalish(a)):
                add("SC1", "reject", _line_of(stripped, m.start()), f"{label} of `{a}` against itself")

    # SC1: == / != self-compare (clone forms + paren-free identical operands).
    for i, sline in enumerate(s_lines):
        for rx in (EQ_CLONE_FWD, EQ_CLONE_REV):
            for cm in rx.finditer(sline):
                base = _norm(cm.group(1))
                if base and not _is_literalish(base):
                    add("SC1", "reject", i, f"equality self-compare of `{base}` against its own clone")
        for cm in EQ_IDENT.finditer(sline):
            a, b = cm.group(1), cm.group(2)
            if a == b and not _is_literalish(a) and "." in a or (a == b and not _is_literalish(a)):
                add("SC1", "reject", i, f"equality self-compare of `{a}`")

    # SC2: clone-bind then compare-to-source within a window.
    WINDOW = 15
    for i, sline in enumerate(s_lines):
        m = SC2_CLONE_BIND.search(sline)
        if not m:
            continue
        name, src = m.group(1), _norm(m.group(2))
        if not src:
            continue
        for j in range(i + 1, min(i + 1 + WINDOW, len(s_lines))):
            probe = s_lines[j]
            if name not in probe:
                continue
            compared = False
            for opener in (CT_EQ_OPEN, ASSERT_EQ_OPEN):
                for cm in opener.finditer(probe):
                    two = _extract_two_args(probe, cm.end() - 1)
                    if two and {_norm(two[0]), _norm(two[1])} == {name, src}:
                        compared = True
            if not compared and (
                re.search(rf"\b{re.escape(name)}\b\s*(==|!=)\s*{re.escape(src)}", probe)
                or re.search(rf"{re.escape(src)}\s*(==|!=)\s*\b{re.escape(name)}\b", probe)
            ):
                compared = True
            if compared:
                add(
                    "SC2",
                    "reject",
                    j,
                    f"`{name}` is a clone of `{src}`; comparing them is tautological "
                    f"(clone-then-compare; see bd-5r99w.3)",
                )
            break

    # SC3: debug-only recompute followed by a release clone of the same binding.
    for i, sline in enumerate(s_lines):
        if not DEBUG_CFG.search(sline):
            continue
        debug_bindings: set[str] = set()
        depth = 0
        started = False
        end = i
        for j in range(i + 1, min(i + 40, len(s_lines))):
            line = s_lines[j]
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            lm = LET_CALL.search(line)
            if lm:
                debug_bindings.add(lm.group(1))
            if started and depth <= 0:
                end = j
                break
        if not debug_bindings:
            continue
        for j in range(end, min(end + 8, len(s_lines))):
            cm = LET_CLONE.search(s_lines[j])
            if cm and cm.group(1) in debug_bindings:
                add(
                    "SC3",
                    "warn",
                    j,
                    f"`{cm.group(1)}` is recomputed only under #[cfg(debug_assertions)] "
                    f"but release rebinds it to a clone (debug-only recompute)",
                )
    return findings


def _skipped(path: Path) -> bool:
    return any(part in SKIP_DIR_NAMES for part in path.parts)


def iter_rust_files(paths: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if not path.is_absolute():
            path = ROOT / path
        if path.is_dir():
            for f in sorted(path.rglob("*.rs")):
                if not _skipped(f.relative_to(ROOT) if str(f).startswith(str(ROOT)) else f):
                    files.append(f)
        elif path.suffix == ".rs" and path.exists():
            rel = path.relative_to(ROOT) if str(path).startswith(str(ROOT)) else path
            if not _skipped(rel):
                files.append(path)
    return files


# --------------------------------------------------------------------------- #
# Self-test fixtures
# --------------------------------------------------------------------------- #
KNOWN_BAD = [
    ('sc1_ct_eq', 'fn f(){ let ok = constant_time::ct_eq(&hash, &hash); }', "SC1"),
    ('sc1_ct_eq_clone', 'fn f(){ let ok = ct_eq(&verdict, &verdict.clone()); }', "SC1"),
    ('sc1_eqeq_clone', 'fn f(){ if digest == digest.clone() { } }', "SC1"),
    ('sc1_assert', 'fn f(){ assert_eq!(replayed_hash, replayed_hash); }', "SC1"),
    (
        'sc2_clone_then_compare',
        'fn f(b: &B) -> O {\n'
        '    let replayed = b.manifest.decision_sequence_hash.clone();\n'
        '    O { matched: ct_eq(&replayed, &b.manifest.decision_sequence_hash) }\n'
        '}',
        "SC2",
    ),
    (
        'sc3_debug_only_recompute',
        'fn f(b: &B) -> String {\n'
        '    #[cfg(debug_assertions)]\n'
        '    {\n'
        '        let recomputed = recompute(b);\n'
        '        let _ = recomputed;\n'
        '    }\n'
        '    let recomputed = b.hash.clone();\n'
        '    recomputed\n'
        '}',
        "SC3",
    ),
]

KNOWN_GOOD = [
    (
        'good_real_recompute',
        'fn f(b: &B) -> O {\n'
        '    let replayed = compute_decision_sequence_hash(&b.timeline, &b.state, &b.policy);\n'
        '    O { matched: ct_eq(&replayed, &b.manifest.decision_sequence_hash) }\n'
        '}',
    ),
    (
        'good_comment_mentions_pattern',
        'fn f() {\n'
        '    // previously: replayed = manifest.hash.clone(); ct_eq(replayed, manifest.hash)\n'
        '    let replayed = recompute();\n'
        '    let _ = ct_eq(&replayed, &manifest.hash);\n'
        '}',
    ),
    (
        'good_suppressed',
        'fn t(){ assert!(ct_eq(&x, &x)); } // lint:allow-self-compare',
    ),
    (
        'good_distinct',
        'fn f(){ let _ = ct_eq(&a, &b); assert_eq!(left, right); if got == want {} }',
    ),
    (
        'good_string_literal',
        'fn f(){ let msg = "verify that h == h.clone() is rejected"; let _ = msg; }',
    ),
    (
        'good_test_module_reflexivity',
        '#[cfg(test)]\n'
        'mod tests {\n'
        '    #[test]\n'
        '    fn ct_eq_is_reflexive() {\n'
        '        assert!(ct_eq(&x, &x));\n'
        '        assert_eq!(snapshot, snapshot);\n'
        '    }\n'
        '}',
    ),
]


def run_self_test() -> int:
    failures = 0
    for name, src, want_rule in KNOWN_BAD:
        rules = {f.rule for f in lint_text(name, src)}
        if want_rule not in rules:
            print(f"SELFTEST FAIL [bad/{name}]: expected {want_rule}, got {sorted(rules) or 'none'}")
            failures += 1
        else:
            print(f"selftest ok  [bad/{name}] -> {want_rule}")
    for name, src in KNOWN_GOOD:
        bad = [f for f in lint_text(name, src) if f.severity == "reject"]
        if bad:
            print(f"SELFTEST FAIL [good/{name}]: unexpected {[(f.rule, f.detail) for f in bad]}")
            failures += 1
        else:
            print(f"selftest ok  [good/{name}] -> clean")
    print(("\nself-test FAILED: %d case(s)" % failures) if failures else "\nself-test PASSED")
    return 1 if failures else 0


def main() -> int:
    logger = configure_test_logging("check_no_self_compare")
    parser = argparse.ArgumentParser(description="Static no-self-compare / no-unexecuted-PASS lint")
    parser.add_argument("paths", nargs="*", help="Rust files or dirs (default: crates/ sdk/)")
    parser.add_argument("--json", action="store_true", help="emit JSON findings")
    parser.add_argument("--ci", action="store_true", help="exit 1 on any REJECT finding")
    parser.add_argument("--strict", action="store_true", help="alias for --ci")
    parser.add_argument("--warn-only", action="store_true", help="never exit 1")
    parser.add_argument("--self-test", action="store_true", help="run lint fixtures and exit")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    files = iter_rust_files(args.paths or DEFAULT_SCAN_DIRS)
    if not files:
        print("no in-scope Rust files found (tests/, fuzz/, benches/ are skipped)", file=sys.stderr)
        return 0

    findings: list[Finding] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover
            print(f"error reading {f}: {exc}", file=sys.stderr)
            return 2
        rel = str(f.relative_to(ROOT)) if str(f).startswith(str(ROOT)) else str(f)
        findings.extend(lint_text(rel, text))

    rejects = [f for f in findings if f.severity == "reject"]
    warns = [f for f in findings if f.severity == "warn"]

    if args.json:
        print(json.dumps({
            "scanned_files": len(files),
            "reject_count": len(rejects),
            "warn_count": len(warns),
            "findings": [asdict(f) for f in findings],
        }, indent=2))
    else:
        for f in findings:
            tag = "REJECT" if f.severity == "reject" else "warn  "
            print(f"{tag} [{f.rule}] {f.file}:{f.line}: {f.detail}")
            print(f"            {f.snippet}")
        print(f"\nscanned {len(files)} file(s): {len(rejects)} reject, {len(warns)} warn")

    logger.info("no-self-compare: %d reject, %d warn", len(rejects), len(warns))
    if rejects and (args.ci or args.strict) and not args.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
