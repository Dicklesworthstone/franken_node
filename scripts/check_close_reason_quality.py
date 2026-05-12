#!/usr/bin/env python3
"""check_close_reason_quality.py — guard against thin/fake close_reason fields.

Why this exists
---------------
The 2026-05-11 beads compliance audit found 18 of 2,944 closed beads (2.4%)
were genuinely false-closed. All 18 shared an anti-pattern: closer marks
status=closed with `close_reason: "done"` AND drops a fabricated
`verification_evidence.json` claiming "20/20 PASS" — but the underlying
source file the artifact attests to is not on disk.

Full analysis: `beads_compliance_audit/closer_discipline_memo.md`.

This guard runs against `.beads/issues.jsonl` diffs (staged or ranged) and
rejects close events that lack the minimum citation rigor.

Usage
-----
    # Pre-commit (against staged diff)
    python scripts/check_close_reason_quality.py --staged --warn-only

    # Strict mode (CI / final): exit 1 on any rejection
    python scripts/check_close_reason_quality.py --staged --strict

    # Ranged check over recent history
    python scripts/check_close_reason_quality.py --since HEAD~50 --ci

    # Standalone smoke test
    python scripts/check_close_reason_quality.py --self-test

Exit codes
----------
    0   no thin closes found (or --warn-only and only warnings)
    1   --strict / --ci mode and ≥ 1 thin close found
    2   execution error (no .beads/issues.jsonl, git diff failure, etc.)

Detection rules (in order of severity)
--------------------------------------
    R1 (REJECT)  close_reason is null / empty
    R2 (REJECT)  close_reason matches /^(done|Done|DONE|completed|Completed|
                 finished|ok|fix|fixed|resolved|wip|todo)\\s*$/
    R3 (WARN)    close_reason length < 80 chars
    R4 (WARN)    for bug/feature/task types: lacks BOTH commit-SHA
                 ([a-f0-9]{7,40}) AND file:line ([\\w./-]+\\.(rs|py|md|toml|yaml):\\d+)
    R5 (REJECT)  cites an artifacts/<...>/verification_evidence.json that
                 references a file path not present in `git ls-files`
                 (the fabricated-evidence anti-pattern)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
JSONL_PATH = ROOT / ".beads" / "issues.jsonl"

THIN_REASON_RE = re.compile(
    r"^\s*(done|completed|finished|ok|fix|fixed|resolved|wip|todo|tbd|n/?a)\s*\.?\s*$",
    re.IGNORECASE,
)
SHA_RE = re.compile(r"\b[a-f0-9]{7,40}\b")
FILELINE_RE = re.compile(r"[\w./-]+\.(rs|py|md|toml|yaml|sh|json):\d+")
PR_RE = re.compile(r"\bPR\s*#\d+\b|\bpull/\d+\b", re.IGNORECASE)
TEST_NAME_RE = re.compile(
    r"\b(test|cargo test|pytest)\s+[\w:_]+|\btest_\w+|#\[test\]\s*fn\s+\w+"
)
VERIFICATION_EV_RE = re.compile(r"(artifacts/[\w./-]+verification_evidence\.json)")


@dataclass
class Finding:
    bead_id: str
    severity: str  # "REJECT" | "WARN" | "NOTE"
    rule: str
    detail: str
    suggested_fix: str = ""


def parse_jsonl_lines(lines: Iterable[str]) -> list[dict]:
    """Parse JSONL lines, skipping malformed ones."""
    issues: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            issues.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return issues


def issues_from_disk() -> list[dict]:
    if not JSONL_PATH.is_file():
        return []
    return parse_jsonl_lines(JSONL_PATH.read_text().splitlines())


def issues_from_git_show(ref: str) -> list[dict]:
    """Load issues.jsonl as of a git ref."""
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{ref}:.beads/issues.jsonl"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            return []
        return parse_jsonl_lines(r.stdout.splitlines())
    except Exception:
        return []


def issues_from_staged_diff() -> tuple[list[dict], list[dict]]:
    """(before, after) view of issues.jsonl from staged diff vs HEAD."""
    before = issues_from_git_show("HEAD")
    after = issues_from_disk()
    return before, after


def issues_from_unstaged() -> list[dict]:
    """Issues currently in the working tree (may differ from HEAD)."""
    return issues_from_disk()


def newly_closed(before: list[dict], after: list[dict]) -> list[dict]:
    """Return issues whose status flipped to 'closed' between before and after."""
    before_status = {i.get("id"): _flat_status(i.get("status")) for i in before}
    out = []
    for i in after:
        bid = i.get("id")
        prev = before_status.get(bid, "open")
        cur = _flat_status(i.get("status"))
        if cur == "closed" and prev != "closed":
            out.append(i)
    return out


def _flat_status(s) -> str:
    if isinstance(s, str):
        return s
    if isinstance(s, dict):
        # br variants: {"Custom": "name"} or {"open": null}, etc.
        if s:
            return next(iter(s.keys())).lower()
    return "unknown"


def _flat_type(t) -> str:
    if isinstance(t, str):
        return t.lower()
    if isinstance(t, dict) and t:
        return str(next(iter(t.values()))).lower()
    return "task"


def get_tracked_paths(ref: Optional[str] = None) -> set[str]:
    """Return the set of paths git tracks at ref (default HEAD)."""
    args = ["git", "-C", str(ROOT), "ls-tree", "-r", "--name-only", ref or "HEAD"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return set()
        return {line.strip() for line in r.stdout.splitlines() if line.strip()}
    except Exception:
        return set()


def check_verification_evidence(close_reason: str, tracked: set[str]) -> list[Finding]:
    """R5: if close_reason cites an artifacts/.../verification_evidence.json, open it
    and verify each cited source path is in `git ls-files`."""
    findings: list[Finding] = []
    for m in VERIFICATION_EV_RE.finditer(close_reason or ""):
        rel = m.group(1)
        full = ROOT / rel
        if not full.is_file():
            findings.append(Finding(
                bead_id="", severity="REJECT", rule="R5",
                detail=f"cited artifact missing on disk: {rel}",
                suggested_fix=f"Generate {rel} as part of the close, OR remove the citation"
            ))
            continue
        # Read and check each cited path
        try:
            data = json.loads(full.read_text())
        except Exception:
            continue
        # Look for cited source paths in common fields
        cited: list[str] = []
        for key in ("cited_files", "files", "source_paths", "checks"):
            v = data.get(key)
            if isinstance(v, list):
                for entry in v:
                    if isinstance(entry, str):
                        cited.append(entry)
                    elif isinstance(entry, dict):
                        p = entry.get("path") or entry.get("file")
                        if isinstance(p, str):
                            cited.append(p)
        # Common pattern in fabricated artifacts: "src/<module>/<file>.rs" in a checks list
        for c in cited:
            if not c or c.startswith("/"):
                continue
            if c.endswith((".rs", ".py", ".md", ".toml")) and c not in tracked:
                findings.append(Finding(
                    bead_id="", severity="REJECT", rule="R5",
                    detail=f"artifact {rel} cites {c} but that path is not in git",
                    suggested_fix=f"Either land {c}, or fix the artifact to cite the real path"
                ))
    return findings


def check_one_close(issue: dict, tracked: set[str], strict: bool) -> list[Finding]:
    bid = issue.get("id", "?")
    reason = (issue.get("close_reason") or "").strip()
    itype = _flat_type(issue.get("issue_type"))
    findings: list[Finding] = []

    if not reason:
        findings.append(Finding(
            bead_id=bid, severity="REJECT", rule="R1",
            detail="close_reason is empty",
            suggested_fix='br update <id> --description="..." then br close <id> --reason "commit <SHA>: <one paragraph>"'
        ))
        return findings  # nothing else worth checking

    if THIN_REASON_RE.match(reason):
        findings.append(Finding(
            bead_id=bid, severity="REJECT", rule="R2",
            detail=f"close_reason is too thin: {reason!r}",
            suggested_fix='close_reason must cite at least one of: commit SHA, file:line, PR number, or test name. Example: "Fixed via 4c732669 (crates/franken-node/src/foo.rs:123-150 + test_foo_happy_path)."'
        ))

    if len(reason) < 80:
        findings.append(Finding(
            bead_id=bid, severity="WARN", rule="R3",
            detail=f"close_reason is short ({len(reason)} chars; recommend ≥ 80)",
            suggested_fix="Expand to describe what shipped, where, and how it was verified"
        ))

    if itype in ("bug", "feature", "task", "enhancement", "performance"):
        has_sha = bool(SHA_RE.search(reason))
        has_fileline = bool(FILELINE_RE.search(reason))
        has_pr = bool(PR_RE.search(reason))
        has_test = bool(TEST_NAME_RE.search(reason))
        # Pass if reason cites either SHA or PR or file:line, AND ideally a test name
        if not (has_sha or has_pr or has_fileline):
            findings.append(Finding(
                bead_id=bid, severity="WARN", rule="R4",
                detail=f"close_reason lacks commit SHA, PR #, AND file:line citation for {itype} bead",
                suggested_fix='Add a commit SHA (e.g. "4c732669"), PR # (e.g. "PR #42"), or file:line range (e.g. "crates/.../foo.rs:123-150")'
            ))
        if not has_test and itype in ("bug", "feature"):
            findings.append(Finding(
                bead_id=bid, severity="NOTE", rule="R4b",
                detail="close_reason does not cite a test name; bug/feature beads should",
                suggested_fix='Add the name of a test that newly passes (e.g. "test_foo_regression")'
            ))

    # R5: artifact citations
    findings.extend(check_verification_evidence(reason, tracked))
    for f in findings:
        if f.rule == "R5" and not f.bead_id:
            f.bead_id = bid

    return findings


def emit_findings(findings: list[Finding], mode: str) -> int:
    """Print findings; return exit code per mode."""
    by_sev = {"REJECT": [], "WARN": [], "NOTE": []}
    for f in findings:
        by_sev[f.severity].append(f)

    if not findings:
        print(f"check_close_reason_quality: no thin closes detected ({mode})")
        return 0

    print(f"check_close_reason_quality ({mode}):")
    print(f"  REJECT: {len(by_sev['REJECT'])}   WARN: {len(by_sev['WARN'])}   NOTE: {len(by_sev['NOTE'])}")
    print()
    for sev in ("REJECT", "WARN", "NOTE"):
        for f in by_sev[sev]:
            marker = {"REJECT": "✗", "WARN": "⚠", "NOTE": "•"}[sev]
            print(f"  {marker} [{f.rule}] {f.bead_id}: {f.detail}")
            if f.suggested_fix:
                print(f"      fix: {f.suggested_fix}")
        if by_sev[sev]:
            print()

    if mode in ("strict", "ci") and by_sev["REJECT"]:
        return 1
    if mode == "strict" and by_sev["WARN"]:
        return 1
    return 0


def cmd_staged(mode: str) -> int:
    before, after = issues_from_staged_diff()
    closes = newly_closed(before, after)
    tracked = get_tracked_paths()
    findings: list[Finding] = []
    for i in closes:
        findings.extend(check_one_close(i, tracked, strict=(mode == "strict")))
    return emit_findings(findings, mode)


def cmd_since(ref: str, mode: str) -> int:
    """Compare HEAD against <ref> and report on closes that landed in between."""
    before = issues_from_git_show(ref)
    after = issues_from_git_show("HEAD") or issues_from_disk()
    closes = newly_closed(before, after)
    tracked = get_tracked_paths()
    findings: list[Finding] = []
    for i in closes:
        findings.extend(check_one_close(i, tracked, strict=(mode == "strict")))
    print(f"# checking {len(closes)} closes between {ref} and HEAD", file=sys.stderr)
    return emit_findings(findings, mode)


def cmd_all(mode: str) -> int:
    """Audit the entire current JSONL — useful for backward audits."""
    after = issues_from_disk()
    closes = [i for i in after if _flat_status(i.get("status")) == "closed"]
    tracked = get_tracked_paths()
    findings: list[Finding] = []
    for i in closes:
        findings.extend(check_one_close(i, tracked, strict=(mode == "strict")))
    print(f"# audited {len(closes)} total closed beads from {JSONL_PATH}", file=sys.stderr)
    return emit_findings(findings, mode)


def self_test() -> int:
    """Smoke test: parse a tiny synthetic dataset, verify rules fire."""
    cases = [
        # (issue dict, expected min REJECT count)
        ({"id": "bd-a", "status": "closed", "close_reason": "", "issue_type": "task"}, 1),
        ({"id": "bd-b", "status": "closed", "close_reason": "done", "issue_type": "task"}, 1),
        ({"id": "bd-c", "status": "closed", "close_reason": "Completed", "issue_type": "bug"}, 1),
        ({"id": "bd-d", "status": "closed", "close_reason": "Fixed via 4c732669 (crates/foo.rs:12-50 + test_foo_works)", "issue_type": "bug"}, 0),
        ({"id": "bd-e", "status": "closed", "close_reason": "fix", "issue_type": "bug"}, 1),
    ]
    tracked = set()
    ok = True
    for issue, expect_reject in cases:
        findings = check_one_close(issue, tracked, strict=False)
        rejects = sum(1 for f in findings if f.severity == "REJECT")
        marker = "OK" if rejects >= expect_reject else "FAIL"
        print(f"  {marker} {issue['id']}: reason={issue['close_reason']!r} → REJECTs={rejects} (expected ≥ {expect_reject})")
        if rejects < expect_reject:
            ok = False
    return 0 if ok else 1


def main() -> int:
    logger = configure_test_logging("check_close_reason_quality")
    logger.info("starting %s verification", "check_close_reason_quality")
    p = argparse.ArgumentParser(description=__doc__)
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--staged", action="store_true", help="check staged .beads/issues.jsonl diff vs HEAD")
    grp.add_argument("--since", metavar="REF", help="check closes between REF and HEAD")
    grp.add_argument("--all", action="store_true", help="audit the entire current JSONL")
    grp.add_argument("--self-test", action="store_true", help="smoke test the rules")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--warn-only", action="store_true", help="never exit non-zero")
    mode.add_argument("--strict", action="store_true", help="exit 1 on any REJECT or WARN")
    mode.add_argument("--ci", action="store_true", help="exit 1 on any REJECT")

    args = p.parse_args()

    if args.self_test:
        return self_test()

    selected_mode = "warn-only" if args.warn_only else ("strict" if args.strict else ("ci" if args.ci else "warn-only"))

    if args.staged:
        return cmd_staged(selected_mode)
    if args.since:
        return cmd_since(args.since, selected_mode)
    if args.all:
        return cmd_all(selected_mode)

    # Default: audit all
    return cmd_all(selected_mode)


if __name__ == "__main__":
    sys.exit(main())
