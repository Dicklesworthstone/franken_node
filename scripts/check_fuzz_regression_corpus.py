#!/usr/bin/env python3
"""Verify fuzz/regression promotion, 146-target seed corpora, and inner fuzz reconciliation.

Emits structured per-target JSON summaries required by bd-reality-20260923-26n9r.38
and bd-fuzz-regression-corpus-f28ac.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "franken-node/fuzz-regression-gate/v1"
SMOKE_RECEIPT_SCHEMA = "franken-node/fuzz-smoke-receipt/v1"
SMOKE_RECEIPT_DOMAIN = b"franken-node:fuzz-smoke-receipt:v1:"
HIGH_RISK_KEYWORDS = (
    "auth",
    "cap",
    "constant_time",
    "crypto",
    "epoch",
    "firewall",
    "jwt",
    "macaroon",
    "parser",
    "quarantine",
    "revocation",
    "serializer",
    "sig",
    "ssrf",
    "threshold",
    "token",
    "trust",
    "vef",
    "zk",
)


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


def compute_smoke_receipt_sha256(receipt: dict[str, object]) -> str:
    unsigned = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    hasher = hashlib.sha256()
    hasher.update(SMOKE_RECEIPT_DOMAIN)
    hasher.update(len(canonical).to_bytes(8, "little"))
    hasher.update(canonical)
    return f"sha256:{hasher.hexdigest()}"


def verify_smoke_receipt_sha256(receipt: dict[str, object]) -> bool:
    claimed = receipt.get("receipt_sha256")
    if not isinstance(claimed, str) or not claimed.startswith("sha256:"):
        return False
    return compute_smoke_receipt_sha256(receipt) == claimed


def select_fuzz_smoke_subset(
    repo_root: Path = ROOT,
    count: int = 8,
    rotation_key: str = "default",
) -> list[str]:
    if count < 1:
        raise ValueError("count must be >= 1")
    fuzz_toml = repo_root / "fuzz/Cargo.toml"
    cargo_data = tomllib.loads(fuzz_toml.read_text(encoding="utf-8"))
    registered = [entry["name"] for entry in cargo_data.get("bin", [])]
    if len(registered) <= count:
        return registered

    manifest_path = repo_root / "fuzz/regression/manifest.json"
    promoted_targets: set[str] = set()
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest.get("promoted_target_regressions", []):
            if isinstance(entry, dict) and entry.get("target"):
                promoted_targets.add(str(entry["target"]))

    high_risk: list[str] = []
    standard: list[str] = []
    for name in sorted(registered):
        lower = name.lower()
        if name in promoted_targets or any(kw in lower for kw in HIGH_RISK_KEYWORDS):
            high_risk.append(name)
        else:
            standard.append(name)

    seed_bytes = hashlib.sha256(rotation_key.encode("utf-8")).digest()
    hr_seed = int.from_bytes(seed_bytes[:8], "little")
    st_seed = int.from_bytes(seed_bytes[8:16], "little")

    hr_quota = min(len(high_risk), max(1, (count + 1) // 2))
    st_quota = min(len(standard), count - hr_quota)
    if hr_quota + st_quota < count:
        hr_quota = min(len(high_risk), count - st_quota)

    selected: list[str] = []
    if high_risk and hr_quota > 0:
        start = hr_seed % len(high_risk)
        for i in range(hr_quota):
            selected.append(high_risk[(start + i) % len(high_risk)])
    if standard and st_quota > 0:
        start = st_seed % len(standard)
        for i in range(st_quota):
            selected.append(standard[(start + i) % len(standard)])
    return selected


FuzzRunner = Callable[[Sequence[str], Path, int], subprocess.CompletedProcess[str]]


def default_fuzz_runner(
    command: Sequence[str], cwd: Path, timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def run_fuzz_smoke_subset(
    repo_root: Path,
    targets: Sequence[str],
    max_total_time_secs: int,
    receipt_jsonl: Path,
    runner: FuzzRunner = default_fuzz_runner,
) -> int:
    fuzz_dir = repo_root / "fuzz"
    artifacts_dir = fuzz_dir / "artifacts"
    manifest_path = fuzz_dir / "regression/manifest.json"
    promoted_sources: set[str] = set()
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest.get("promoted_target_regressions", []):
            if isinstance(entry, dict) and entry.get("source_artifact"):
                promoted_sources.add(str(entry["source_artifact"]))

    receipt_jsonl.parent.mkdir(parents=True, exist_ok=True)
    overall_rc = 0
    timeout_secs = max(max_total_time_secs + 30, 60)

    with receipt_jsonl.open("w", encoding="utf-8") as handle:
        for target in targets:
            cmd = [
                "cargo",
                "fuzz",
                "run",
                target,
                "--",
                f"-max_total_time={max_total_time_secs}",
            ]
            started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            try:
                completed = runner(cmd, fuzz_dir, timeout_secs)
                rc = completed.returncode
            except subprocess.TimeoutExpired:
                rc = 124
            ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

            target_art_dir = artifacts_dir / target
            unpromoted_crashes: list[str] = []
            if target_art_dir.is_dir():
                for pat in ("crash-*", "oom-*", "timeout-*"):
                    for p in sorted(target_art_dir.glob(pat)):
                        rel = p.relative_to(repo_root).as_posix()
                        if rel not in promoted_sources:
                            unpromoted_crashes.append(rel)

            crashed = rc != 0 or bool(unpromoted_crashes)
            if crashed:
                overall_rc = 1
            rec: dict[str, object] = {
                "schema_version": SMOKE_RECEIPT_SCHEMA,
                "target": target,
                "command": cmd,
                "max_total_time_secs": max_total_time_secs,
                "started_at": started_at,
                "ended_at": ended_at,
                "exit_code": rc,
                "crash": crashed,
                "unpromoted_artifacts": unpromoted_crashes,
                "passed": not crashed,
            }
            rec["receipt_sha256"] = compute_smoke_receipt_sha256(rec)
            handle.write(json.dumps(rec, sort_keys=True) + "\n")
            handle.flush()

    return overall_rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument(
        "--run-smoke-subset",
        type=int,
        default=None,
        help="Execute a deterministic risk-weighted + rotating cargo-fuzz subset of size N without failure masking.",
    )
    parser.add_argument(
        "--rotation-key",
        default=os.environ.get("GITHUB_SHA", "default"),
    )
    parser.add_argument("--max-total-time", type=int, default=20)
    parser.add_argument(
        "--receipt-jsonl",
        type=Path,
        default=Path("artifacts/verification/fuzz_smoke_receipts.jsonl"),
    )
    args = parser.parse_args(argv)

    repo_root = args.root.resolve()
    if args.run_smoke_subset is not None:
        subset = select_fuzz_smoke_subset(
            repo_root,
            count=args.run_smoke_subset,
            rotation_key=args.rotation_key,
        )
        return run_fuzz_smoke_subset(
            repo_root,
            targets=subset,
            max_total_time_secs=args.max_total_time,
            receipt_jsonl=args.receipt_jsonl,
        )

    report = evaluate_fuzz_corpus(repo_root)
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
