#!/usr/bin/env python3
"""bd-2hqd.4: Proof-Carrying Execution Ledger (PCEL) v1 gate.

This gate builds a deterministic ledger over closed bead verification artifacts.
It computes canonical hashes, dependency closure checks, and a Merkle root.

Usage:
  python3 scripts/check_proof_carrying_execution_ledger.py
  python3 scripts/check_proof_carrying_execution_ledger.py --json
  python3 scripts/check_proof_carrying_execution_ledger.py --build-report --json
  python3 scripts/check_proof_carrying_execution_ledger.py --self-test --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-2hqd.4"
SECTION = "10.17"
TITLE = "Proof-Carrying Execution Ledger (PCEL) v1"
SCHEMA_VERSION = "pcel-v1.0"

ISSUES_PATH = ROOT / ".beads" / "issues.jsonl"
ARTIFACTS_ROOT = ROOT / "artifacts"
DEFAULT_BEAD_PREFIX = "bd-2hqd"
DEFAULT_LEDGER_PATH = ROOT / "artifacts" / "assurance" / "proof_carrying_execution_ledger_v1.json"
DEFAULT_SUMMARY_PATH = ROOT / "artifacts" / "assurance" / "proof_carrying_execution_ledger_v1.md"

LEAF_DOMAIN = b"pcel:v1:leaf:"
NODE_DOMAIN = b"pcel:v1:node:"


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _normalize_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _load_issue_index(issues_path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    issues: dict[str, dict[str, Any]] = {}
    if not issues_path.is_file():
        return issues, ""

    raw = issues_path.read_bytes()
    source_sha256 = _sha256_hex(raw)

    for idx, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            # Ignore malformed rows but preserve deterministic behavior.
            continue
        if not isinstance(payload, dict):
            continue
        issue_id = payload.get("id")
        if isinstance(issue_id, str) and issue_id:
            issues[issue_id] = payload
    return issues, source_sha256


def _issue_dependencies(issue: dict[str, Any]) -> list[str]:
    deps: set[str] = set()
    raw_deps = issue.get("dependencies")
    if isinstance(raw_deps, list):
        for dep in raw_deps:
            if not isinstance(dep, dict):
                continue
            dep_id = dep.get("depends_on_id") or dep.get("id") or dep.get("depends_on")
            if isinstance(dep_id, str) and dep_id.strip():
                deps.add(dep_id.strip())
    return sorted(deps)


def _scan_bead_dirs(artifacts_root: Path) -> dict[str, list[Path]]:
    mapping: dict[str, list[Path]] = {}
    if not artifacts_root.is_dir():
        return mapping

    for candidate in sorted(artifacts_root.rglob("bd-*")):
        if candidate.is_dir() and candidate.name.startswith("bd-"):
            mapping.setdefault(candidate.name, []).append(candidate)

    for bead_id in mapping:
        mapping[bead_id] = sorted(mapping[bead_id], key=lambda p: (_safe_rel(p), len(_safe_rel(p))))

    return mapping


def _primary_bead_dir(artifact_dirs: dict[str, list[Path]], bead_id: str) -> Path | None:
    candidates = artifact_dirs.get(bead_id, [])
    if not candidates:
        return None
    ranked = sorted(
        candidates,
        key=lambda candidate: (
            not (
                (candidate / "verification_evidence.json").is_file()
                and (candidate / "verification_summary.md").is_file()
            ),
            not (
                (candidate / "verification_evidence.json").is_file()
                or (candidate / "verification_summary.md").is_file()
            ),
            _safe_rel(candidate),
        ),
    )
    return ranked[0]


def _leaf_hash(canonical_leaf_json: str) -> str:
    return _sha256_hex(LEAF_DOMAIN + canonical_leaf_json.encode("utf-8"))


def _merkle_root_hex(leaf_hashes: list[str]) -> tuple[str, int]:
    if not leaf_hashes:
        return "", 0

    level = [bytes.fromhex(leaf_hash) for leaf_hash in leaf_hashes]
    levels = 1
    while len(level) > 1:
        next_level: list[bytes] = []
        for idx in range(0, len(level), 2):
            left = level[idx]
            right = level[idx + 1] if idx + 1 < len(level) else left
            next_level.append(hashlib.sha256(NODE_DOMAIN + left + right).digest())
        level = next_level
        levels += 1
    return level[0].hex(), levels


def _build_bead_entry(
    bead_id: str,
    issue: dict[str, Any],
    bead_dir: Path | None,
) -> dict[str, Any]:
    dependency_ids = _issue_dependencies(issue)

    entry: dict[str, Any] = {
        "bead_id": bead_id,
        "status": str(issue.get("status", "")),
        "closed_at": str(issue.get("closed_at", "")),
        "dependencies": dependency_ids,
        "artifact_dir": _safe_rel(bead_dir) if bead_dir else "",
        "evidence_path": "",
        "summary_path": "",
        "evidence_exists": False,
        "summary_exists": False,
        "evidence_valid_json": False,
        "evidence_sha256": "",
        "summary_sha256": "",
        "dependency_sha256": _sha256_hex(_canonical_json(dependency_ids).encode("utf-8")),
        "leaf_sha256": "",
        "checks": [],
    }

    if bead_dir is None:
        entry["checks"].append({
            "check": "artifact_directory_exists",
            "passed": False,
            "detail": "No artifacts/**/bd-* directory found for bead",
        })
        return entry

    evidence_path = bead_dir / "verification_evidence.json"
    summary_path = bead_dir / "verification_summary.md"

    entry["evidence_path"] = _safe_rel(evidence_path)
    entry["summary_path"] = _safe_rel(summary_path)
    entry["evidence_exists"] = evidence_path.is_file()
    entry["summary_exists"] = summary_path.is_file()

    entry["checks"].append({
        "check": "verification_evidence_present",
        "passed": entry["evidence_exists"],
        "detail": entry["evidence_path"],
    })
    entry["checks"].append({
        "check": "verification_summary_present",
        "passed": entry["summary_exists"],
        "detail": entry["summary_path"],
    })

    if entry["evidence_exists"]:
        try:
            evidence_text = evidence_path.read_text(encoding="utf-8")
            entry["checks"].append({
                "check": "verification_evidence_utf8",
                "passed": True,
                "detail": "readable UTF-8",
            })
        except (OSError, UnicodeDecodeError) as exc:
            entry["checks"].append({
                "check": "verification_evidence_utf8",
                "passed": False,
                "detail": f"failed to read UTF-8 evidence: {exc}",
            })
            evidence_text = None

        if evidence_text is not None:
            try:
                payload = json.loads(evidence_text)
                if isinstance(payload, dict):
                    entry["evidence_valid_json"] = True
                    canonical = _canonical_json(payload)
                    entry["evidence_sha256"] = _sha256_hex(canonical.encode("utf-8"))
                else:
                    entry["checks"].append({
                        "check": "verification_evidence_is_object",
                        "passed": False,
                        "detail": "verification_evidence.json root must be object",
                    })
            except json.JSONDecodeError as exc:
                entry["checks"].append({
                    "check": "verification_evidence_json_parse",
                    "passed": False,
                    "detail": f"JSON decode error: {exc}",
                })

    if entry["evidence_exists"] and entry["evidence_valid_json"]:
        entry["checks"].append({
            "check": "verification_evidence_json_parse",
            "passed": True,
            "detail": "parsed canonical JSON",
        })

    if entry["summary_exists"]:
        try:
            summary_text = summary_path.read_text(encoding="utf-8")
            entry["checks"].append({
                "check": "verification_summary_utf8",
                "passed": True,
                "detail": "readable UTF-8",
            })
        except (OSError, UnicodeDecodeError) as exc:
            entry["checks"].append({
                "check": "verification_summary_utf8",
                "passed": False,
                "detail": f"failed to read UTF-8 summary: {exc}",
            })
            summary_text = None

        if summary_text is not None:
            normalized_summary = _normalize_text(summary_text)
            entry["summary_sha256"] = _sha256_hex(normalized_summary.encode("utf-8"))

    leaf_payload = {
        "bead_id": bead_id,
        "evidence_sha256": entry["evidence_sha256"],
        "summary_sha256": entry["summary_sha256"],
        "dependency_sha256": entry["dependency_sha256"],
        "closed_at": entry["closed_at"],
    }
    entry["leaf_sha256"] = _leaf_hash(_canonical_json(leaf_payload))

    return entry


def _compute_dependency_closure(
    entries: list[dict[str, Any]],
    issue_index: dict[str, dict[str, Any]],
    scope_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_id = {entry["bead_id"]: entry for entry in entries}

    missing: list[dict[str, Any]] = []
    out_of_scope_closed: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []

    for entry in entries:
        bead_id = entry["bead_id"]
        for dep_id in entry.get("dependencies", []):
            dep_issue = issue_index.get(dep_id)
            if dep_issue is None:
                unresolved.append({
                    "bead_id": bead_id,
                    "missing_dependency": dep_id,
                    "reason": "dependency id not present in issues index",
                })
                continue
            dep_closed = str(dep_issue.get("status", "")) == "closed"
            if not dep_closed:
                continue

            if dep_id not in scope_ids:
                out_of_scope_closed.append({
                    "bead_id": bead_id,
                    "missing_dependency": dep_id,
                    "reason": "closed dependency outside selected PCEL scope",
                })
                continue

            dep_entry = by_id.get(dep_id)
            if dep_entry is None:
                missing.append({
                    "bead_id": bead_id,
                    "missing_dependency": dep_id,
                    "reason": "dependency bead not represented in ledger scope",
                })
                continue

            dep_has_proof = bool(dep_entry.get("evidence_sha256")) and bool(dep_entry.get("summary_sha256"))
            if not dep_has_proof:
                missing.append({
                    "bead_id": bead_id,
                    "missing_dependency": dep_id,
                    "reason": "dependency bead lacks complete proof artifacts",
                })

    missing = sorted(missing, key=lambda item: (item["bead_id"], item["missing_dependency"]))
    out_of_scope_closed = sorted(
        out_of_scope_closed,
        key=lambda item: (item["bead_id"], item["missing_dependency"]),
    )
    unresolved = sorted(
        unresolved,
        key=lambda item: (item["bead_id"], item["missing_dependency"]),
    )
    return missing, out_of_scope_closed, unresolved


def run_all(
    *,
    issues_path: Path = ISSUES_PATH,
    artifacts_root: Path = ARTIFACTS_ROOT,
    bead_prefix: str = DEFAULT_BEAD_PREFIX,
    include_all_closed: bool = False,
) -> dict[str, Any]:
    issue_index, issues_sha256 = _load_issue_index(issues_path)
    artifact_dirs = _scan_bead_dirs(artifacts_root)

    closed_issue_ids = sorted(
        issue_id
        for issue_id, payload in issue_index.items()
        if str(payload.get("status", "")) == "closed"
    )
    scoped_closed_issue_ids = [issue_id for issue_id in closed_issue_ids if issue_id != BEAD_ID]

    if include_all_closed:
        selected_ids = scoped_closed_issue_ids
        scope_label = "all_closed"
    else:
        selected_ids = [
            issue_id for issue_id in scoped_closed_issue_ids if issue_id.startswith(bead_prefix)
        ]
        scope_label = f"prefix:{bead_prefix}"

    entries = [
        _build_bead_entry(
            bead_id=issue_id,
            issue=issue_index[issue_id],
            bead_dir=_primary_bead_dir(artifact_dirs, issue_id),
        )
        for issue_id in selected_ids
    ]

    selected_scope_ids = {entry["bead_id"] for entry in entries}
    (
        missing_dependency_proofs,
        out_of_scope_closed_dependencies,
        unresolved_dependency_references,
    ) = _compute_dependency_closure(
        entries=entries,
        issue_index=issue_index,
        scope_ids=selected_scope_ids,
    )

    full_proof_count = sum(
        1
        for entry in entries
        if entry["evidence_exists"]
        and entry["summary_exists"]
        and entry["evidence_valid_json"]
        and bool(entry["evidence_sha256"])
        and bool(entry["summary_sha256"])
    )

    evidence_missing = sum(1 for entry in entries if not entry["evidence_exists"])
    summary_missing = sum(1 for entry in entries if not entry["summary_exists"])
    invalid_evidence_json = sum(
        1 for entry in entries if entry["evidence_exists"] and not entry["evidence_valid_json"]
    )

    merkle_leaf_hashes = [entry["leaf_sha256"] for entry in entries if entry["leaf_sha256"]]
    merkle_root, merkle_depth = _merkle_root_hex(merkle_leaf_hashes)

    dependency_map = {
        entry["bead_id"]: entry["dependencies"] for entry in entries
    }

    checks = [
        {
            "id": "PCEL-SCOPE-NONEMPTY",
            "check": "selected closed-bead scope is non-empty",
            "passed": len(entries) > 0,
            "detail": f"selected_closed_beads={len(entries)} scope={scope_label}",
        },
        {
            "id": "PCEL-PROOF-COMPLETE",
            "check": "all selected closed beads have evidence + summary proof artifacts",
            "passed": len(entries) == full_proof_count,
            "detail": (
                f"full_proof={full_proof_count} total={len(entries)} "
                f"missing_evidence={evidence_missing} missing_summary={summary_missing} "
                f"invalid_evidence_json={invalid_evidence_json}"
            ),
        },
        {
            "id": "PCEL-DEP-CLOSURE",
            "check": "closed dependency proof-chain closure holds within selected scope",
            "passed": len(missing_dependency_proofs) == 0,
            "detail": f"missing_dependency_proofs={len(missing_dependency_proofs)}",
        },
        {
            "id": "PCEL-DEP-SCOPE-COMPLETE",
            "check": "closed dependencies are fully represented inside selected ledger scope",
            "passed": len(out_of_scope_closed_dependencies) == 0,
            "detail": f"out_of_scope_closed_dependencies={len(out_of_scope_closed_dependencies)}",
        },
        {
            "id": "PCEL-DEP-RESOLVED",
            "check": "all dependency ids resolve in .beads/issues.jsonl",
            "passed": len(unresolved_dependency_references) == 0,
            "detail": f"unresolved_dependency_references={len(unresolved_dependency_references)}",
        },
        {
            "id": "PCEL-MERKLE-ROOT",
            "check": "deterministic Merkle root computed for selected scope",
            "passed": len(merkle_leaf_hashes) > 0 and bool(merkle_root),
            "detail": f"leaf_count={len(merkle_leaf_hashes)} depth={merkle_depth} root={merkle_root or '<empty>'}",
        },
        {
            "id": "PCEL-CANONICAL-DETERMINISM",
            "check": "canonical JSON serialization is deterministic",
            "passed": _canonical_json({"b": 1, "a": 2}) == _canonical_json({"a": 2, "b": 1}),
            "detail": "json.dumps(sort_keys=True,separators=(',',':'),ensure_ascii=True)",
        },
    ]

    verdict = "PASS" if all(check["passed"] for check in checks) else "FAIL"

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "generated_at": _now_rfc3339(),
        "verdict": verdict,
        "scope": {
            "label": scope_label,
            "bead_prefix": bead_prefix,
            "include_all_closed": include_all_closed,
            "selected_closed_bead_count": len(entries),
            "total_closed_beads_in_issue_index": len(closed_issue_ids),
        },
        "sources": {
            "issues_jsonl": _safe_rel(issues_path),
            "issues_jsonl_sha256": issues_sha256,
            "artifacts_root": _safe_rel(artifacts_root),
        },
        "summary": {
            "selected_closed_beads": len(entries),
            "full_proof_beads": full_proof_count,
            "missing_evidence": evidence_missing,
            "missing_summary": summary_missing,
            "invalid_evidence_json": invalid_evidence_json,
        },
        "checks": checks,
        "dependency_map": dependency_map,
        "dependency_closure": {
            "missing_dependency_proofs": missing_dependency_proofs,
            "out_of_scope_closed_dependencies": out_of_scope_closed_dependencies,
            "unresolved_dependency_references": unresolved_dependency_references,
        },
        "merkle": {
            "algorithm": "sha256",
            "domain_leaf": LEAF_DOMAIN.decode("ascii"),
            "domain_node": NODE_DOMAIN.decode("ascii"),
            "leaf_count": len(merkle_leaf_hashes),
            "tree_depth": merkle_depth,
            "root_sha256": merkle_root,
        },
        "beads": entries,
    }

    report["content_hash"] = _sha256_hex(
        _canonical_json(
            {
                "schema_version": report["schema_version"],
                "scope": report["scope"],
                "sources": report["sources"],
                "summary": report["summary"],
                "checks": report["checks"],
                "dependency_map": report["dependency_map"],
                "dependency_closure": report["dependency_closure"],
                "merkle": report["merkle"],
                "beads": report["beads"],
                "verdict": report["verdict"],
            }
        ).encode("utf-8")
    )

    return report


def write_report(report: dict[str, Any], ledger_path: Path = DEFAULT_LEDGER_PATH, summary_path: Path = DEFAULT_SUMMARY_PATH) -> None:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Proof-Carrying Execution Ledger (PCEL) v1",
        "",
        f"- Bead: `{report['bead_id']}`",
        f"- Verdict: `{report['verdict']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Scope: `{report['scope']['label']}`",
        f"- Selected closed beads: `{report['scope']['selected_closed_bead_count']}`",
        f"- Full proof beads: `{report['summary']['full_proof_beads']}`",
        f"- Merkle root: `{report['merkle']['root_sha256'] or '<empty>'}`",
        "",
        "## Gate Checks",
        "",
        "| Check | Pass | Detail |",
        "|-------|------|--------|",
    ]

    for check in report["checks"]:
        lines.append(
            f"| {check['id']} | {'PASS' if check['passed'] else 'FAIL'} | {check['detail']} |"
        )

    lines.extend([
        "",
        "## Included Beads",
        "",
        "| Bead | Artifact Dir | Evidence | Summary | Leaf |",
        "|------|--------------|----------|---------|------|",
    ])

    for entry in report["beads"]:
        lines.append(
            "| {bead} | {dir} | {evidence} | {summary} | {leaf} |".format(
                bead=entry["bead_id"],
                dir=entry["artifact_dir"] or "<missing>",
                evidence="yes" if entry["evidence_exists"] else "NO",
                summary="yes" if entry["summary_exists"] else "NO",
                leaf=entry["leaf_sha256"][:16] + "..." if entry["leaf_sha256"] else "<none>",
            )
        )

    if report["dependency_closure"]["missing_dependency_proofs"]:
        lines.extend([
            "",
            "## Missing Dependency Proofs",
            "",
        ])
        for missing in report["dependency_closure"]["missing_dependency_proofs"]:
            lines.append(
                f"- `{missing['bead_id']}` missing `{missing['missing_dependency']}`: {missing['reason']}"
            )

    if report["dependency_closure"]["out_of_scope_closed_dependencies"]:
        lines.extend([
            "",
            "## Out-of-Scope Closed Dependencies",
            "",
        ])
        for item in report["dependency_closure"]["out_of_scope_closed_dependencies"]:
            lines.append(
                f"- `{item['bead_id']}` references `{item['missing_dependency']}` ({item['reason']})"
            )

    if report["dependency_closure"]["unresolved_dependency_references"]:
        lines.extend([
            "",
            "## Unresolved Dependency References",
            "",
        ])
        for item in report["dependency_closure"]["unresolved_dependency_references"]:
            lines.append(
                f"- `{item['bead_id']}` references unknown `{item['missing_dependency']}` ({item['reason']})"
            )

    lines.append("")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines), encoding="utf-8")


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    checks.append(
        {
            "check": "canonical_json_deterministic",
            "passed": _canonical_json({"z": 1, "a": 2}) == _canonical_json({"a": 2, "z": 1}),
        }
    )

    h1 = _sha256_hex(b"pcel-test")
    h2 = _sha256_hex(b"pcel-test")
    checks.append({"check": "sha256_deterministic", "passed": h1 == h2})
    checks.append({"check": "sha256_length_64", "passed": len(h1) == 64})

    leaf_a = _leaf_hash(_canonical_json({"bead_id": "a"}))
    leaf_b = _leaf_hash(_canonical_json({"bead_id": "b"}))
    root1, depth1 = _merkle_root_hex([leaf_a, leaf_b])
    root2, depth2 = _merkle_root_hex([leaf_a, leaf_b])
    checks.append({"check": "merkle_root_deterministic", "passed": root1 == root2 and depth1 == depth2})
    checks.append({"check": "merkle_root_non_empty", "passed": bool(root1)})

    sample_issue = {
        "id": "bd-sample",
        "dependencies": [
            {"depends_on_id": "bd-parent"},
            {"depends_on_id": "bd-parent"},
            {"id": "bd-alt-parent"},
        ],
    }
    deps = _issue_dependencies(sample_issue)
    checks.append(
        {
            "check": "dependency_parser_deduplicates_and_sorts",
            "passed": deps == ["bd-alt-parent", "bd-parent"],
        }
    )

    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_proof_carrying_execution_ledger",
        "bead_id": BEAD_ID,
        "verdict": verdict,
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def _print_human(report: dict[str, Any]) -> None:
    print(
        "{bead}: {verdict} ({full}/{total} full-proof beads, merkle={merkle})".format(
            bead=report["bead_id"],
            verdict=report["verdict"],
            full=report["summary"]["full_proof_beads"],
            total=report["summary"]["selected_closed_beads"],
            merkle=(report["merkle"]["root_sha256"][:16] + "...") if report["merkle"]["root_sha256"] else "<empty>",
        )
    )
    for check in report["checks"]:
        print(f"[{'PASS' if check['passed'] else 'FAIL'}] {check['id']}: {check['detail']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Proof-Carrying Execution Ledger (PCEL) v1 gate")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-tests")
    parser.add_argument("--build-report", action="store_true", help="Write report files under artifacts/assurance")
    parser.add_argument(
        "--bead-prefix",
        default=DEFAULT_BEAD_PREFIX,
        help=f"Closed-bead prefix scope (default: {DEFAULT_BEAD_PREFIX})",
    )
    parser.add_argument(
        "--include-all-closed",
        action="store_true",
        help="Include every closed bead from .beads/issues.jsonl (ignores --bead-prefix)",
    )
    parser.add_argument(
        "--issues-file",
        default=str(ISSUES_PATH),
        help="Path to issues.jsonl source",
    )
    parser.add_argument(
        "--artifacts-root",
        default=str(ARTIFACTS_ROOT),
        help="Artifacts root for bead evidence discovery",
    )
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"self-test: {result['verdict']} ({result['passed']}/{result['passed'] + result['failed']})")
            for check in result["checks"]:
                print(f"[{'PASS' if check['passed'] else 'FAIL'}] {check['check']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    report = run_all(
        issues_path=Path(args.issues_file),
        artifacts_root=Path(args.artifacts_root),
        bead_prefix=args.bead_prefix,
        include_all_closed=args.include_all_closed,
    )

    if args.build_report:
        write_report(report)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
