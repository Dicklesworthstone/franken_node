#!/usr/bin/env python3
"""Measured franken-node vs Node.js latency benchmark (HC-003).

HC-003 claims "franken_node API latency is within 10% of Node.js for
equivalent workloads". This script measures that claim instead of inspecting
documents: it runs a fixed workload set under `franken-node run` and under
`node` on the same host, interleaved in the same invocation, and decides each
workload with a bootstrap confidence interval on the ratio of medians.

Rules:
  * A workload is only timed if franken-node first produces byte-identical
    stdout to node and exits 0; otherwise it is INVALID (a fast wrong answer
    is not a latency result).
  * A workload PASSes only if the upper bound of the 95% bootstrap CI of
    median(franken) / median(node) is <= 1.10.
  * The overall verdict is PASS only if every workload PASSes. A missing
    binary or reference runtime is ERROR, never PASS.

Usage:
    python3 scripts/bench_runtime_vs_node.py --json
    python3 scripts/bench_runtime_vs_node.py --bin target/release/franken-node --runs 20
    FRANKEN_NODE_BIN=/path/to/franken-node python3 scripts/bench_runtime_vs_node.py --out artifacts/perf/runtime_vs_node.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "franken-node/runtime-vs-node-bench/v1"
RATIO_CEILING = 1.10
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20260924
RUN_TIMEOUT_SECONDS = 60

# Each workload prints a deterministic result so the two runtimes can be
# checked for identical output before anything is timed.
WORKLOADS: dict[str, str] = {
    "hello": 'console.log("hello");\n',
    "json_roundtrip": (
        "const rows = [];\n"
        "for (let i = 0; i < 2000; i++) { rows.push({ id: i, name: 'row-' + i, tags: ['a', 'b'], ok: i % 2 === 0 }); }\n"
        "let text = '';\n"
        "for (let round = 0; round < 20; round++) { text = JSON.stringify(JSON.parse(JSON.stringify(rows))); }\n"
        "console.log(text.length);\n"
    ),
    "compute_loop": (
        "let acc = 0;\n"
        "for (let i = 0; i < 1000000; i++) { acc = (acc + i * i) % 1000003; }\n"
        "console.log(acc);\n"
    ),
    "fs_read": (
        "const fs = require('fs');\n"
        "const data = fs.readFileSync('bench-data.txt', 'utf8');\n"
        "console.log(data.length);\n"
    ),
}
FS_READ_BYTES = 1 << 20


def resolve_binary(explicit: str | None) -> Path | None:
    """An explicit --bin is authoritative: it never falls back to another binary."""
    candidates: list[Path] = []
    if explicit:
        path = Path(explicit)
        return path.resolve() if path.is_file() and os.access(path, os.X_OK) else None
    env_bin = os.environ.get("FRANKEN_NODE_BIN")
    if env_bin:
        candidates.append(Path(env_bin))
    target_dir = os.environ.get("CARGO_TARGET_DIR")
    if target_dir:
        candidates.append(Path(target_dir) / "release" / "franken-node")
    candidates.append(ROOT / "target" / "release" / "franken-node")
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def median_ratio(franken: list[float], node: list[float]) -> float:
    return statistics.median(franken) / statistics.median(node)


def bootstrap_ratio_ci(
    franken: list[float],
    node: list[float],
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> tuple[float, float]:
    """95% percentile-bootstrap CI of median(franken) / median(node)."""
    if not franken or not node:
        raise ValueError("bootstrap needs at least one sample per runtime")
    rng = random.Random(seed)
    ratios = sorted(
        median_ratio(rng.choices(franken, k=len(franken)), rng.choices(node, k=len(node)))
        for _ in range(resamples)
    )
    low = ratios[int(0.025 * (resamples - 1))]
    high = ratios[int(0.975 * (resamples - 1))]
    return low, high


def workload_verdict(ci_high: float, ceiling: float = RATIO_CEILING) -> str:
    return "PASS" if ci_high <= ceiling else "FAIL"


def overall_verdict(workload_verdicts: list[str]) -> str:
    if not workload_verdicts:
        return "ERROR"
    if all(v == "PASS" for v in workload_verdicts):
        return "PASS"
    return "FAIL"


def _run_once(argv: list[str], cwd: Path) -> tuple[float, subprocess.CompletedProcess[bytes]]:
    start = time.perf_counter_ns()
    completed = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=RUN_TIMEOUT_SECONDS)
    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
    return elapsed_ms, completed


def _setup_workspace(workspace: Path, binary: Path, policy: str) -> None:
    init = subprocess.run(
        [str(binary), "init", "--profile", policy, "--out-dir", "."],
        cwd=workspace,
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )
    if init.returncode != 0:
        raise RuntimeError(f"franken-node init failed: {init.stderr.decode(errors='replace')}")
    for name, source in WORKLOADS.items():
        (workspace / f"{name}.js").write_text(source, encoding="utf-8")
    (workspace / "bench-data.txt").write_text("x" * FS_READ_BYTES, encoding="utf-8")


def _host_fingerprint(binary: Path, node: str) -> dict[str, Any]:
    def version_of(argv: list[str]) -> str:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS
        ).stdout.strip()

    node_version = version_of([node, "--version"])
    version = version_of([str(binary), "--version"])
    return {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "node_version": node_version,
        "franken_node_version": version,
        "franken_node_binary": str(binary),
        "franken_node_sha256": sha256_file(binary),
    }


def measure(binary: Path, node: str, policy: str, runs: int, warmup: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="fn-bench-vs-node-") as tmp:
        workspace = Path(tmp)
        _setup_workspace(workspace, binary, policy)
        return _measure_in(workspace, binary, node, policy, runs, warmup)


def _measure_in(
    workspace: Path, binary: Path, node: str, policy: str, runs: int, warmup: int
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    load_before = os.getloadavg()
    for name in WORKLOADS:
        script = f"{name}.js"
        argvs = {
            "node": [node, script],
            "franken-node": [
                str(binary), "run", script, "--policy", policy,
                "--runtime", "franken-engine", "--console-only",
            ],
        }
        _, reference = _run_once(argvs["node"], workspace)
        _, candidate = _run_once(argvs["franken-node"], workspace)
        entry: dict[str, Any] = {
            "node_stdout": reference.stdout.decode(errors="replace").strip(),
            "franken_stdout": candidate.stdout.decode(errors="replace").strip(),
            "franken_exit_code": candidate.returncode,
        }
        if reference.returncode != 0 or candidate.returncode != 0 or reference.stdout != candidate.stdout:
            entry["verdict"] = "INVALID"
            entry["detail"] = (
                "franken-node output/exit differs from node; latency not measured "
                f"(node exit {reference.returncode}, franken exit {candidate.returncode})"
            )
            entry["franken_stderr_tail"] = candidate.stderr.decode(errors="replace")[-600:]
            results[name] = entry
            continue
        samples: dict[str, list[float]] = {"node": [], "franken-node": []}
        order = ["node", "franken-node"]
        for iteration in range(warmup + runs):
            # Alternate which runtime goes first so slow drift in host load
            # does not systematically favour either side.
            for runtime in order if iteration % 2 == 0 else list(reversed(order)):
                elapsed_ms, completed = _run_once(argvs[runtime], workspace)
                if completed.returncode != 0:
                    raise RuntimeError(f"{runtime} {script} failed mid-measurement")
                if iteration >= warmup:
                    samples[runtime].append(elapsed_ms)
        ci_low, ci_high = bootstrap_ratio_ci(samples["franken-node"], samples["node"])
        entry.update(
            {
                "runs": runs,
                "node_median_ms": round(statistics.median(samples["node"]), 3),
                "franken_median_ms": round(statistics.median(samples["franken-node"]), 3),
                "median_ratio": round(median_ratio(samples["franken-node"], samples["node"]), 4),
                "ratio_ci95": [round(ci_low, 4), round(ci_high, 4)],
                "node_samples_ms": [round(s, 3) for s in samples["node"]],
                "franken_samples_ms": [round(s, 3) for s in samples["franken-node"]],
                "verdict": workload_verdict(ci_high),
            }
        )
        results[name] = entry
    return {
        "load_average_before":[round(x, 2) for x in load_before],
        "load_average_after": [round(x, 2) for x in os.getloadavg()],
        "workloads": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure franken-node vs node latency (HC-003)")
    parser.add_argument("--bin", help="franken-node binary (default: $FRANKEN_NODE_BIN, then release builds)")
    parser.add_argument("--node", default="node", help="reference node executable")
    parser.add_argument("--policy", default="balanced", choices=["strict", "balanced", "legacy-risky"])
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--out", help="also write the report to this path")
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("--runs must be at least 3")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "claim_id": "HC-003",
        "ratio_ceiling": RATIO_CEILING,
        "policy": args.policy,
    }
    binary = resolve_binary(args.bin)
    node = shutil.which(args.node)
    if binary is None or node is None:
        report["verdict"] = "ERROR"
        report["detail"] = (
            "franken-node binary not found (pass --bin or set FRANKEN_NODE_BIN)"
            if binary is None
            else f"reference runtime {args.node!r} not found on PATH"
        )
    else:
        report["host"] = _host_fingerprint(binary, node)
        try:
            report.update(measure(binary, node, args.policy, args.runs, args.warmup))
            report["verdict"] = overall_verdict(
                [w["verdict"] for w in report["workloads"].values()]
            )
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            report["verdict"] = "ERROR"
            report["detail"] = str(exc)

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    if args.json:
        print(rendered)
    else:
        print(f"HC-003 franken-node vs node ({args.policy}): {report['verdict']}")
        for name, entry in report.get("workloads", {}).items():
            if entry["verdict"] == "INVALID":
                print(f"  {name:15s} INVALID  {entry['detail']}")
            else:
                print(
                    f"  {name:15s} {entry['verdict']:5s} node {entry['node_median_ms']:9.1f} ms"
                    f"  franken {entry['franken_median_ms']:9.1f} ms  ratio {entry['median_ratio']:.2f}"
                    f"  ci95 [{entry['ratio_ci95'][0]:.2f}, {entry['ratio_ci95'][1]:.2f}]"
                )
        if "detail" in report:
            print(f"  {report['detail']}")
    return {"PASS": 0, "FAIL": 1}.get(report["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
