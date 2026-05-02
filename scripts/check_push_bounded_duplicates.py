#!/usr/bin/env python3
"""Report and gate duplicate push_bounded helper semantics."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


DEFAULT_SOURCE_ROOT = Path("crates/franken-node/src")
DEFAULT_ALLOWED_DOMINANT = {"crates/franken-node/src/main.rs"}
TOP_LEVEL_HELPER_RE = re.compile(
    r"(?m)^fn\s+push_bounded\s*<[^>]*>\s*\([^)]*\)\s*\{"
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    category: str
    allowed_dominant: bool


def normalized(body: str) -> str:
    return "".join(body.split())


def find_matching_brace(source: str, start: int) -> int:
    depth = 1
    idx = start
    while idx < len(source) and depth:
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        idx += 1
    if depth != 0:
        raise ValueError("unclosed function body")
    return idx


def classify(body: str) -> str:
    compact = normalized(body)
    has_clear_zero = "ifcap==0{items.clear();return;}" in compact
    has_capacity_check = "items.len()>=cap" in compact
    has_saturating_overflow = "saturating_sub(cap).saturating_add(1)" in compact
    has_front_drain = (
        "items.drain(0..overflow.min(items.len()));" in compact
        or (
            "letdrain_until=overflow.min(items.len());" in compact
            and "items.drain(0..drain_until);" in compact
        )
    )
    has_push = (
        "items.push(item);" in compact
        or "items.extend(std::iter::once(item));" in compact
    )
    if has_clear_zero and has_capacity_check and has_saturating_overflow and has_front_drain and has_push:
        return "dominant_clear_zero_drain_front_push"
    if "ifcap==0{return;}" in compact:
        return "non_dominant_zero_capacity_noop"
    if not has_clear_zero:
        return "non_dominant_zero_capacity_preserves_items"
    if "pop_front()" in compact or "VecDeque" in body:
        return "non_dominant_deque_or_pop_front"
    return "non_dominant_other"


def scan(source_root: Path, allowed_dominant: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(source_root.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in TOP_LEVEL_HELPER_RE.finditer(text):
            marker = match.start()
            brace = match.end() - 1
            end = find_matching_brace(text, brace + 1)
            body = text[brace + 1 : end - 1]
            rel_path = path.as_posix()
            category = classify(body)
            findings.append(
                Finding(
                    path=rel_path,
                    line=text.count("\n", 0, marker) + 1,
                    category=category,
                    allowed_dominant=(
                        category == "dominant_clear_zero_drain_front_push"
                        and rel_path in allowed_dominant
                    ),
                )
            )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", default=str(DEFAULT_SOURCE_ROOT))
    parser.add_argument(
        "--allow-dominant",
        action="append",
        default=sorted(DEFAULT_ALLOWED_DOMINANT),
        help="Repo-relative file path allowed to retain dominant helper semantics.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    findings = scan(Path(args.source_root), set(args.allow_dominant))
    dominant = [
        finding
        for finding in findings
        if finding.category == "dominant_clear_zero_drain_front_push"
    ]
    disallowed_dominant = [finding for finding in dominant if not finding.allowed_dominant]
    payload = {
        "summary": {
            "total": len(findings),
            "dominant": len(dominant),
            "allowed_dominant": sum(1 for finding in dominant if finding.allowed_dominant),
            "disallowed_dominant": len(disallowed_dominant),
            "non_dominant": len(findings) - len(dominant),
        },
        "findings": [asdict(finding) for finding in findings],
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            "push_bounded duplicate scan: "
            f"total={summary['total']} dominant={summary['dominant']} "
            f"allowed_dominant={summary['allowed_dominant']} "
            f"disallowed_dominant={summary['disallowed_dominant']} "
            f"non_dominant={summary['non_dominant']}"
        )
        for finding in findings:
            allowed = " allowed" if finding.allowed_dominant else ""
            print(f"{finding.path}:{finding.line}: {finding.category}{allowed}")

    return 1 if disallowed_dominant else 0


if __name__ == "__main__":
    raise SystemExit(main())
