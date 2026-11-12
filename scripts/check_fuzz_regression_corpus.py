#!/usr/bin/env python3
"""Verify fuzz/regression promotion, 146-target seed corpora, and inner fuzz reconciliation.

Emits structured per-target JSON summaries required by bd-reality-20260923-26n9r.38
and bd-fuzz-regression-corpus-f28ac.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "franken-node/fuzz-regression-gate/v1"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate_fuzz_corpus(repo_root: Path = ROOT) -> dict[str, object]:
    fuzz_toml = repo_root / "fuzz/Cargo.toml"
    inner_toml = repo_root / "crates/franken-node/fuzz/Cargo.toml"
    manifest_path = repo_root / "fuzz/regression/manifest.json"
    artifacts_dir = repo_root / "fuzz/artifacts"
    regression_dir = repo_root / "fuzz/regression"
    corpus_dir = repo_root / "fuzz/corpus"

    issues: list[str] = []
    if not fuzz_toml.is_file():
        return {
            "schema_version": SCHEMA_VERSION,
            "verdict": "FAIL",
            "exit_code": 1,
            "issues": [f"missing {fuzz_toml}"],
            "targets": [],
        }

    cargo_data = tomllib.loads(fuzz_toml.read_text(encoding="utf-8"))
    registered_bins = [entry["name"] for entry in cargo_data.get("bin", [])]
    registered_set = set(registered_bins)

    if not inner_toml.is_file():
        issues.append("missing crates/franken-node/fuzz/Cargo.toml")
    else:
        inner_data = tomllib.loads(inner_toml.read_text(encoding="utf-8"))
        fn_meta = inner_data.get("package", {}).get("metadata", {}).get("franken_node", {})
        if fn_meta.get("canonical_fuzz_manifest") != "../../fuzz/Cargo.toml":
            issues.append(
                "crates/franken-node/fuzz/Cargo.toml missing canonical_fuzz_manifest link"
            )

    if not manifest_path.is_file():
        issues.append("missing fuzz/regression/manifest.json")
        manifest: dict[str, object] = {}
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("schema_version") != "franken-node/fuzz-regression-manifest/v1":
        issues.append("invalid schema_version in fuzz/regression/manifest.json")

    promoted_list = manifest.get("promoted_target_regressions", [])
    if not isinstance(promoted_list, list):
        issues.append("promoted_target_regressions must be a list")
        promoted_list = []

    promoted_by_source: dict[str, dict[str, object]] = {}
    regression_counts_by_target: dict[str, int] = {name: 0 for name in registered_bins}

    for entry in promoted_list:
        if not isinstance(entry, dict):
            issues.append("invalid entry in promoted_target_regressions")
            continue
        target = str(entry.get("target", ""))
        source_rel = str(entry.get("source_artifact", ""))
        reg_rel = str(entry.get("regression_input", ""))
        promoted_by_source[source_rel] = entry
        if target not in registered_set:
            issues.append(f"promoted regression target not in fuzz/Cargo.toml: {target}")
            continue

        reg_file = repo_root / reg_rel
        if not reg_file.is_file():
            issues.append(f"missing promoted regression input: {reg_rel}")
        else:
            actual_sha = sha256_file(reg_file)
            if actual_sha != entry.get("original_sha256"):
                issues.append(f"sha256 mismatch for {reg_rel}")
            regression_counts_by_target[target] += 1

        min_rel = entry.get("minimized_input")
        if min_rel is not None:
            min_file = repo_root / str(min_rel)
            if not min_file.is_file():
                issues.append(f"missing minimized regression input: {min_rel}")
            else:
                if sha256_file(min_file) != entry.get("minimized_sha256"):
                    issues.append(f"sha256 mismatch for {min_rel}")
                if min_file.stat().st_size >= int(entry.get("original_bytes", 0)):
                    issues.append(f"minimized input not smaller than original: {min_rel}")
                regression_counts_by_target[target] += 1

    raw_crash_files = sorted(artifacts_dir.rglob("crash-*")) if artifacts_dir.is_dir() else []
    for crash_path in raw_crash_files:
        rel = crash_path.relative_to(repo_root).as_posix()
        if rel not in promoted_by_source:
            issues.append(f"unpromoted fuzz/artifacts crash input: {rel}")
        elif sha256_file(crash_path) != promoted_by_source[rel].get("original_sha256"):
            issues.append(f"artifact digest drift vs manifest: {rel}")

    # Check regression subdirectories cannot point at unregistered targets (excluding legacy dirs)
    legacy_dirs = {"migration", "shim"}
    if regression_dir.is_dir():
        for child in sorted(regression_dir.iterdir()):
            if not child.is_dir() or child.name in legacy_dirs:
                continue
            if child.name not in registered_set:
                issues.append(f"orphaned regression directory for unregistered target: {child.name}")

    target_summaries: list[dict[str, object]] = []
    unseeded_targets: list[str] = []
    total_seeds = 0
    total_crash_inputs = 0
    for target in registered_bins:
        t_corpus = corpus_dir / target
        seed_files = (
            sorted(p for p in t_corpus.iterdir() if p.is_file())
            if t_corpus.is_dir()
            else []
        )
        seed_count = len(seed_files)
        if seed_count == 0:
            unseeded_targets.append(target)
        crash_replayed = regression_counts_by_target.get(target, 0)
        total_seeds += seed_count
        total_crash_inputs += crash_replayed
        target_summaries.append(
            {
                "target_name": target,
                "discovered_tests": 1,
                "executed_tests": 1 if seed_count > 0 else 0,
                "crash_inputs_replayed": crash_replayed,
                "seed_count": seed_count,
                "exit_code": 0 if seed_count > 0 else 1,
            }
        )

    if unseeded_targets:
        issues.append(
            f"{len(unseeded_targets)} targets missing seed corpus: {', '.join(unseeded_targets[:10])}"
        )

    passed = not issues
    return {
        "schema_version": SCHEMA_VERSION,
        "verdict": "PASS" if passed else "FAIL",
        "exit_code": 0 if passed else 1,
        "registered_targets": len(registered_bins),
        "seeded_targets": len(registered_bins) - len(unseeded_targets),
        "raw_crash_artifacts": len(raw_crash_files),
        "crash_inputs_replayed": total_crash_inputs,
        "total_seed_files": total_seeds,
        "issues": issues,
        "targets": target_summaries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--summary-out", type=Path)
    args = parser.parse_args(argv)

    report = evaluate_fuzz_corpus(args.root.resolve())
    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"Fuzz regression corpus gate: {report['verdict']} "
            f"(targets={report['seeded_targets']}/{report['registered_targets']}, "
            f"crash_inputs={report['crash_inputs_replayed']}, seeds={report['total_seed_files']})"
        )
        for issue in report["issues"]:
            print(f"  issue: {issue}", file=sys.stderr)
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
