#!/usr/bin/env python3
"""Measured franken-node vs Node.js / Bun latency & RSS benchmark (HC-003).

HC-003 claims "franken_node API latency is within 10% of Node.js for
equivalent workloads". This script measures that claim instead of inspecting
documents: it runs a fixed 6-workload suite (`hello`, `json_roundtrip`,
`compute_loop`, `fs_read`, `require_pkg`, `loopback_http`) under
`franken-node run`, `node`, and `bun` (when available) on the same host,
in a randomized interleaved schedule within a single invocation.

Rules:
  * A workload is only timed if franken-node (and bun, when active) first
    produces byte-identical stdout to node and exits 0; otherwise it is
    INVALID (a fast wrong answer is not a latency result).
  * A workload PASSes HC-003 only if the upper bound of the 95% bootstrap CI
    of median(franken) / median(node) is <= 1.10.
  * Each runtime records cold-start latency + RSS, warm-dispatch p50/p95/p99
    with exact distribution-free binomial order-statistic confidence intervals,
    and per-invocation peak RSS (`ru_maxrss` via `os.wait4`).
  * The overall HC-003 `verdict` is PASS only if every workload PASSes. A
    missing binary or reference `node` runtime is ERROR, never PASS.
  * `--enforce-cold-start-budget <profile>` additionally enforces
    `perf/budgets.toml` (`min_iterations`, `warmup_iterations`, and
    `profiles.<profile>.cold_start_ms` on `hello`) for canary CI while keeping
    top-level `verdict` strictly bound to HC-003 (`<= 1.10x` vs `node`).
"""

from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BUDGETS_PATH = ROOT / "perf" / "budgets.toml"
SCHEMA_VERSION = "franken-node/runtime-vs-node-bench/v2"
REPORT_SIGNATURE_DOMAIN = b"franken-node:runtime-vs-node-bench:v1:"
RATIO_CEILING = 1.10
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20260924
INTERLEAVE_SEED = 20261118
RUN_TIMEOUT_SECONDS = 60
LOOPBACK_PORT_TOKEN = "__LOOPBACK_PORT__"
LOOPBACK_RESPONSE_BODY = b"loopback-bench-ok:42"

# Each workload prints a deterministic result so all runtimes are verified for
# byte-identical output before any timing sample is accepted.
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
    "require_pkg": (
        "const pkg = require('bench-pkg');\n"
        "console.log(pkg.computeChecksum('franken-bench', 250));\n"
    ),
    "loopback_http": (
        "const http = require('http');\n"
        f"http.get('http://127.0.0.1:{LOOPBACK_PORT_TOKEN}/ping', (res) => {{\n"
        "  let body = '';\n"
        "  res.on('data', (chunk) => { body += chunk; });\n"
        "  res.on('end', () => { console.log(body); });\n"
        "});\n"
    ),
}
FS_READ_BYTES = 1 << 20

VENDORED_BENCH_PKG_JSON = json.dumps(
    {
        "name": "bench-pkg",
        "version": "1.0.0",
        "main": "index.js",
    },
    indent=2,
) + "\n"

VENDORED_BENCH_PKG_INDEX = (
    "'use strict';\n"
    "exports.computeChecksum = function computeChecksum(seed, rounds) {\n"
    "  let h = 2166136261;\n"
    "  for (let r = 0; r < rounds; r++) {\n"
    "    const text = seed + ':' + r;\n"
    "    for (let i = 0; i < text.length; i++) {\n"
    "      h = ((h ^ text.charCodeAt(i)) * 16777619) >>> 0;\n"
    "    }\n"
    "  }\n"
    "  return 'fnv1a:' + h;\n"
    "};\n"
)


class _QuietLoopbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(LOOPBACK_RESPONSE_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(LOOPBACK_RESPONSE_BODY)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


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


def resolve_bun(explicit: str | None) -> str | None:
    """Resolve optional or required Bun incumbent executable."""
    if explicit and explicit != "bun":
        path = Path(explicit)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        return shutil.which(explicit)
    found = shutil.which(explicit or "bun")
    if found:
        return found
    home_bun = Path.home() / ".bun" / "bin" / "bun"
    if home_bun.is_file() and os.access(home_bun, os.X_OK):
        return str(home_bun)
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


def sample_quantile(samples: list[float], q: float) -> float:
    """Continuous linear-interpolation sample quantile for q in [0, 1]."""
    if not samples:
        raise ValueError("sample_quantile requires at least one sample")
    if not 0.0 <= q <= 1.0:
        raise ValueError("quantile q must lie in [0, 1]")
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return ordered[lo]
    weight = pos - lo
    return ordered[lo] * (1.0 - weight) + ordered[hi] * weight


def order_statistic_quantile_ci(
    samples: list[float],
    q: float,
    confidence: float = 0.95,
) -> dict[str, Any]:
    """Exact distribution-free binomial order-statistic CI for quantile q.

    For sorted X_(1) <= ... <= X_(n), P(X_(r) <= Q_q <= X_(s)) equals
    sum_{k=r}^{s-1} C(n, k) q^k (1-q)^(n-k). When n is too small to achieve
    `confidence`, clamps to [X_(1), X_(n)] and reports exact `actual_coverage`.
    """
    if not samples:
        raise ValueError("order_statistic_quantile_ci requires at least one sample")
    if not 0.0 < q < 1.0:
        raise ValueError("quantile q must lie in (0, 1)")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must lie in (0, 1)")

    ordered = sorted(samples)
    n = len(ordered)
    estimate = sample_quantile(ordered, q)
    if n == 1:
        return {
            "estimate": round(estimate, 3),
            "ci_low": round(ordered[0], 3),
            "ci_high": round(ordered[0], 3),
            "rank_low": 1,
            "rank_high": 1,
            "nominal_confidence": confidence,
            "actual_coverage": 0.0,
        }

    probs = [math.comb(n, k) * (q ** k) * ((1.0 - q) ** (n - k)) for k in range(n + 1)]
    alpha_half = (1.0 - confidence) / 2.0

    # Largest 1-indexed r in [1, n] with P(Q_q < X_(r)) = sum_{k=0}^{r-1} probs[k] <= alpha_half.
    r = 1
    lower_tail = probs[0]
    if lower_tail <= alpha_half + 1e-15:
        for candidate_r in range(2, n + 1):
            next_tail = lower_tail + probs[candidate_r - 1]
            if next_tail <= alpha_half + 1e-15:
                lower_tail = next_tail
                r = candidate_r
            else:
                break

    # Smallest 1-indexed s in [r, n] with sum_{k=s}^{n} probs[k] <= alpha_half.
    s = n
    upper_tail = probs[n]
    if upper_tail <= alpha_half + 1e-15:
        for candidate_s in range(n - 1, r - 1, -1):
            next_tail = upper_tail + probs[candidate_s]
            if next_tail <= alpha_half + 1e-15:
                upper_tail = next_tail
                s = candidate_s
            else:
                break

    if r >= s:
        r = max(1, s - 1)

    coverage = max(0.0, min(1.0, sum(probs[r:s])))
    return {
        "estimate": round(estimate, 3),
        "ci_low": round(ordered[r - 1], 3),
        "ci_high": round(ordered[s - 1], 3),
        "rank_low": r,
        "rank_high": s,
        "nominal_confidence": confidence,
        "actual_coverage": round(coverage, 6),
    }


def summarize_runtime_samples(
    cold_start_ms: float,
    cold_maxrss_kb: int,
    warm_samples_ms: list[float],
    warm_rss_kb: list[int],
) -> dict[str, Any]:
    return {
        "cold_start_ms": round(cold_start_ms, 3),
        "cold_maxrss_kb": int(cold_maxrss_kb),
        "warm_dispatch": {
            "runs": len(warm_samples_ms),
            "p50_ms": round(sample_quantile(warm_samples_ms, 0.50), 3),
            "p95_ms": round(sample_quantile(warm_samples_ms, 0.95), 3),
            "p99_ms": round(sample_quantile(warm_samples_ms, 0.99), 3),
            "mean_ms": round(statistics.fmean(warm_samples_ms), 3),
            "stdev_ms": round(statistics.stdev(warm_samples_ms), 3) if len(warm_samples_ms) > 1 else 0.0,
            "min_ms": round(min(warm_samples_ms), 3),
            "max_ms": round(max(warm_samples_ms), 3),
            "p50_ci95": order_statistic_quantile_ci(warm_samples_ms, 0.50),
            "p95_ci95": order_statistic_quantile_ci(warm_samples_ms, 0.95),
            "p99_ci95": order_statistic_quantile_ci(warm_samples_ms, 0.99),
        },
        "rss_kb": {
            "p50_kb": int(round(sample_quantile([float(x) for x in warm_rss_kb], 0.50))),
            "p95_kb": int(round(sample_quantile([float(x) for x in warm_rss_kb], 0.95))),
            "max_kb": int(max(warm_rss_kb)),
            "samples_kb": [int(x) for x in warm_rss_kb],
        },
    }


def workload_verdict(ci_high: float, ceiling: float = RATIO_CEILING) -> str:
    return "PASS" if ci_high <= ceiling else "FAIL"


def overall_verdict(workload_verdicts: list[str]) -> str:
    if not workload_verdicts:
        return "ERROR"
    if all(v == "PASS" for v in workload_verdicts):
        return "PASS"
    return "FAIL"


def _normalize_ru_maxrss_kb(raw_maxrss: int) -> int:
    if raw_maxrss <= 0:
        return 0
    if sys.platform == "darwin":
        return max(1, raw_maxrss // 1024)
    return int(raw_maxrss)


def _run_once_with_rusage(
    argv: list[str], cwd: Path, env: dict[str, str] | None = None
) -> tuple[float, int, subprocess.CompletedProcess[bytes]]:
    """Execute `argv` and capture wall-clock ms + child peak RSS (`ru_maxrss` KiB)."""
    if not hasattr(os, "wait4"):
        start = time.perf_counter_ns()
        completed = subprocess.run(
            argv, cwd=cwd, env=env, capture_output=True, timeout=RUN_TIMEOUT_SECONDS
        )
        elapsed_ms = (time.perf_counter_ns() - start) / 1e6
        return elapsed_ms, 0, completed

    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        timed_out = threading.Event()
        start = time.perf_counter_ns()
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out_f, stderr=err_f)

        def _kill_on_timeout() -> None:
            timed_out.set()
            try:
                proc.kill()
            except ProcessLookupError:
                pass

        timer = threading.Timer(RUN_TIMEOUT_SECONDS, _kill_on_timeout)
        timer.daemon = True
        timer.start()
        try:
            _, wait_status, rusage = os.wait4(proc.pid, 0)
            elapsed_ms = (time.perf_counter_ns() - start) / 1e6
        finally:
            timer.cancel()

        returncode = os.waitstatus_to_exitcode(wait_status)
        proc.returncode = returncode
        out_f.seek(0)
        err_f.seek(0)
        stdout_bytes = out_f.read()
        stderr_bytes = err_f.read()

        if timed_out.is_set():
            raise subprocess.TimeoutExpired(
                argv, RUN_TIMEOUT_SECONDS, output=stdout_bytes, stderr=stderr_bytes
            )

        completed = subprocess.CompletedProcess(
            args=argv,
            returncode=returncode,
            stdout=stdout_bytes,
            stderr=stderr_bytes,
        )
        return elapsed_ms, _normalize_ru_maxrss_kb(int(rusage.ru_maxrss)), completed


def _run_once(argv: list[str], cwd: Path) -> tuple[float, subprocess.CompletedProcess[bytes]]:
    elapsed_ms, _, completed = _run_once_with_rusage(argv, cwd)
    return elapsed_ms, completed


def _setup_workspace(
    workspace: Path,
    binary: Path,
    policy: str,
    loopback_port: int,
    env: dict[str, str] | None = None,
) -> None:
    init = subprocess.run(
        [str(binary), "init", "--profile", policy, "--out-dir", "."],
        cwd=workspace,
        env=env,
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )
    if init.returncode != 0:
        raise RuntimeError(f"franken-node init failed: {init.stderr.decode(errors='replace')}")

    toml_path = workspace / "franken_node.toml"
    if toml_path.is_file():
        toml_text = toml_path.read_text(encoding="utf-8")
        if "allowlist = []" in toml_text:
            toml_text = toml_text.replace(
                "allowlist = []",
                (
                    "allowlist = [\n"
                    f'  {{ host = "127.0.0.1", port = {loopback_port}, reason = "benchmark loopback_http workload" }}\n'
                    "]"
                ),
            )
            toml_path.write_text(toml_text, encoding="utf-8")

    pkg_dir = workspace / "node_modules" / "bench-pkg"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "package.json").write_text(VENDORED_BENCH_PKG_JSON, encoding="utf-8")
    (pkg_dir / "index.js").write_text(VENDORED_BENCH_PKG_INDEX, encoding="utf-8")

    for name, source in WORKLOADS.items():
        rendered = source.replace(LOOPBACK_PORT_TOKEN, str(loopback_port))
        (workspace / f"{name}.js").write_text(rendered, encoding="utf-8")
    (workspace / "bench-data.txt").write_text("x" * FS_READ_BYTES, encoding="utf-8")


def _git_head_sha(repo_dir: Path) -> str | None:
    if not repo_dir.is_dir():
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    sha = completed.stdout.strip()
    return sha if completed.returncode == 0 and len(sha) == 40 else None


def _host_fingerprint(binary: Path, node: str, bun: str | None = None) -> dict[str, Any]:
    def version_of(argv: list[str]) -> str:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS
        ).stdout.strip()

    fp: dict[str, Any] = {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "node_version": version_of([node, "--version"]),
        "bun_available": bun is not None,
        "bun_version": version_of([bun, "--version"]) if bun else None,
        "franken_node_version": version_of([str(binary), "--version"]),
        "franken_node_binary": str(binary),
        "franken_node_sha256": sha256_file(binary),
        "franken_node_commit": _git_head_sha(ROOT),
        "franken_engine_commit": _git_head_sha(ROOT.parent / "franken_engine"),
    }
    return fp


def load_perf_budgets(path: Path = BUDGETS_PATH) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        import tomllib
    except ImportError:
        return None
    with path.open("rb") as handle:
        return tomllib.load(handle)


def evaluate_cold_start_budget(
    workloads: dict[str, Any],
    budgets: dict[str, Any] | None,
    profile: str,
    runs: int,
    warmup: int,
) -> dict[str, Any]:
    if budgets is None:
        return {"verdict": "ERROR", "profile": profile, "detail": "perf/budgets.toml missing"}
    meta = budgets.get("meta", {})
    profile_cfg = budgets.get("profiles", {}).get(profile)
    if not isinstance(profile_cfg, dict):
        return {
            "verdict": "ERROR",
            "profile": profile,
            "detail": f"unknown budget profile {profile!r} in perf/budgets.toml",
        }
    budget_ms = float(profile_cfg.get("cold_start_ms", 0))
    early_warning_pct = float(meta.get("early_warning_pct", 80))
    min_iterations = int(meta.get("min_iterations", 30))
    min_warmup = int(meta.get("warmup_iterations", 5))
    hello = workloads.get("hello")
    if not isinstance(hello, dict) or hello.get("verdict") == "INVALID":
        return {
            "verdict": "FAIL",
            "profile": profile,
            "cold_start_budget_ms": budget_ms,
            "detail": "hello workload missing or INVALID",
        }
    fn_stats = hello.get("runtimes", {}).get("franken-node", {})
    warm = fn_stats.get("warm_dispatch", {})
    p50_ms = float(warm.get("p50_ms", hello.get("franken_median_ms", 0.0)))
    p99_ms = float(warm.get("p99_ms", 0.0))
    cold_first_ms = float(fn_stats.get("cold_start_ms", p50_ms))
    sufficient_samples = runs >= min_iterations and warmup >= min_warmup
    within_budget = p50_ms <= budget_ms
    warning_threshold_ms = budget_ms * (early_warning_pct / 100.0)
    return {
        "profile": profile,
        "cold_start_budget_ms": budget_ms,
        "early_warning_threshold_ms": round(warning_threshold_ms, 3),
        "early_warning": p50_ms >= warning_threshold_ms,
        "min_iterations_required": min_iterations,
        "warmup_iterations_required": min_warmup,
        "runs_measured": runs,
        "warmup_measured": warmup,
        "sufficient_iterations": sufficient_samples,
        "hello_cold_first_ms": round(cold_first_ms, 3),
        "hello_p50_ms": round(p50_ms, 3),
        "hello_p99_ms": round(p99_ms, 3),
        "hello_p99_ci95": warm.get("p99_ci95"),
        "within_budget": within_budget,
        "verdict": "PASS" if (within_budget and sufficient_samples) else "FAIL",
    }


def _parse_ed25519_seed(raw: bytes) -> bytes | None:
    try:
        text = raw.decode("utf-8")
        if "-----BEGIN" in text:
            return None
        trimmed = text.strip()
        if len(trimmed) == 64:
            return bytes.fromhex(trimmed)
    except (UnicodeDecodeError, ValueError):
        pass
    if len(raw) == 32:
        return raw
    return None


def _canonical_signing_payload(report: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in report.items() if k != "signature"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return REPORT_SIGNATURE_DOMAIN + canonical


def sign_report_ed25519(report: dict[str, Any], raw_key: bytes) -> dict[str, str] | None:
    seed = _parse_ed25519_seed(raw_key)
    if seed is None:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        return None
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    message = _canonical_signing_payload(report)
    sig_bytes = priv.sign(message)
    return {
        "scheme": "ed25519",
        "domain": REPORT_SIGNATURE_DOMAIN.decode("ascii"),
        "payload_sha256": "sha256:" + hashlib.sha256(message).hexdigest(),
        "signer_public_key_hex": pub_bytes.hex(),
        "signature_hex": sig_bytes.hex(),
    }


def verify_report_ed25519(report: dict[str, Any]) -> bool:
    sig = report.get("signature")
    if not isinstance(sig, dict) or sig.get("scheme") != "ed25519":
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["signer_public_key_hex"]))
        signature_bytes = bytes.fromhex(sig["signature_hex"])
        message = _canonical_signing_payload(report)
        expected_digest = "sha256:" + hashlib.sha256(message).hexdigest()
        if sig.get("payload_sha256") != expected_digest:
            return False
        pub.verify(signature_bytes, message)
        return True
    except (ImportError, KeyError, ValueError, InvalidSignature):
        return False


def measure(
    binary: Path,
    node: str,
    policy: str,
    runs: int,
    warmup: int,
    bun: str | None = None,
) -> tuple[dict[str, Any], bytes | None]:
    with (
        tempfile.TemporaryDirectory(prefix="fn-bench-vs-node-") as tmp,
        tempfile.TemporaryDirectory(prefix="fn-bench-state-") as state_tmp,
    ):
        workspace = Path(tmp)
        state_home = Path(state_tmp)
        os.chmod(state_home, 0o700)
        franken_env = {**os.environ, "XDG_STATE_HOME": str(state_home)}
        with ThreadingHTTPServer(("127.0.0.1", 0), _QuietLoopbackHandler) as httpd:
            loopback_port = int(httpd.server_address[1])
            server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            server_thread.start()
            try:
                _setup_workspace(workspace, binary, policy, loopback_port, env=franken_env)
                measured = _measure_in(
                    workspace, binary, node, policy, runs, warmup, bun=bun, franken_env=franken_env
                )
                key_path = workspace / ".franken-node" / "keys" / "receipt-signing.key"
                workspace_key = key_path.read_bytes() if key_path.is_file() else None
                return measured, workspace_key
            finally:
                httpd.shutdown()
                server_thread.join(timeout=5)


def _measure_in(
    workspace: Path,
    binary: Path,
    node: str,
    policy: str,
    runs: int,
    warmup: int,
    bun: str | None = None,
    franken_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    load_before = os.getloadavg()
    rng = random.Random(INTERLEAVE_SEED)
    active_runtimes = ["node", "franken-node"] + (["bun"] if bun else [])

    for name in WORKLOADS:
        script = f"{name}.js"
        argvs: dict[str, list[str]] = {
            "node": [node, script],
            "franken-node": [
                str(binary),
                "run",
                script,
                "--policy",
                policy,
                "--runtime",
                "franken-engine",
                "--console-only",
            ],
        }
        if bun:
            argvs["bun"] = [bun, script]

        cold_order = rng.sample(active_runtimes, k=len(active_runtimes))
        cold_runs: dict[str, tuple[float, int, subprocess.CompletedProcess[bytes]]] = {}
        for runtime in cold_order:
            rt_env = franken_env if runtime == "franken-node" else None
            cold_runs[runtime] = _run_once_with_rusage(argvs[runtime], workspace, env=rt_env)

        _, _, reference = cold_runs["node"]
        _, _, candidate = cold_runs["franken-node"]
        entry: dict[str, Any] = {
            "node_stdout": reference.stdout.decode(errors="replace").strip(),
            "franken_stdout": candidate.stdout.decode(errors="replace").strip(),
            "franken_exit_code": candidate.returncode,
        }
        bun_mismatch = False
        if bun:
            _, _, bun_proc = cold_runs["bun"]
            entry["bun_stdout"] = bun_proc.stdout.decode(errors="replace").strip()
            entry["bun_exit_code"] = bun_proc.returncode
            bun_mismatch = bun_proc.returncode != 0 or bun_proc.stdout != reference.stdout

        if (
            reference.returncode != 0
            or candidate.returncode != 0
            or reference.stdout != candidate.stdout
            or bun_mismatch
        ):
            entry["verdict"] = "INVALID"
            entry["detail"] = (
                "runtime output/exit differs from node; latency not measured "
                f"(node exit {reference.returncode}, franken exit {candidate.returncode}"
                + (f", bun exit {cold_runs['bun'][2].returncode})" if bun else ")")
            )
            entry["franken_stderr_tail"] = candidate.stderr.decode(errors="replace")[-600:]
            results[name] = entry
            continue

        samples_ms: dict[str, list[float]] = {rt: [] for rt in active_runtimes}
        samples_rss_kb: dict[str, list[int]] = {rt: [] for rt in active_runtimes}
        interleave_schedule: list[list[str]] = []

        for iteration in range(warmup + runs):
            # Randomized permutation per iteration prevents drift/periodic host
            # load from systematically favoring any runtime in the triad.
            perm = rng.sample(active_runtimes, k=len(active_runtimes))
            if iteration >= warmup:
                interleave_schedule.append(perm)
            for runtime in perm:
                rt_env = franken_env if runtime == "franken-node" else None
                elapsed_ms, maxrss_kb, completed = _run_once_with_rusage(
                    argvs[runtime], workspace, env=rt_env
                )
                if completed.returncode != 0 or completed.stdout != reference.stdout:
                    raise RuntimeError(
                        f"{runtime} {script} failed or drifted mid-measurement (exit {completed.returncode})"
                    )
                if iteration >= warmup:
                    samples_ms[runtime].append(elapsed_ms)
                    samples_rss_kb[runtime].append(maxrss_kb)

        ci_low, ci_high = bootstrap_ratio_ci(samples_ms["franken-node"], samples_ms["node"])
        runtimes_summary = {
            rt: summarize_runtime_samples(
                cold_start_ms=cold_runs[rt][0],
                cold_maxrss_kb=cold_runs[rt][1],
                warm_samples_ms=samples_ms[rt],
                warm_rss_kb=samples_rss_kb[rt],
            )
            for rt in active_runtimes
        }

        entry.update(
            {
                "runs": runs,
                "warmup": warmup,
                "interleave_mode": "randomized_triad" if bun else "randomized_pair",
                "interleave_seed": INTERLEAVE_SEED,
                "node_median_ms": round(statistics.median(samples_ms["node"]), 3),
                "franken_median_ms": round(statistics.median(samples_ms["franken-node"]), 3),
                "median_ratio": round(
                    median_ratio(samples_ms["franken-node"], samples_ms["node"]), 4
                ),
                "ratio_ci95": [round(ci_low, 4), round(ci_high, 4)],
                "node_samples_ms": [round(s, 3) for s in samples_ms["node"]],
                "franken_samples_ms": [round(s, 3) for s in samples_ms["franken-node"]],
                "runtimes": runtimes_summary,
                "verdict": workload_verdict(ci_high),
            }
        )
        if bun:
            bun_ci_low, bun_ci_high = bootstrap_ratio_ci(
                samples_ms["franken-node"], samples_ms["bun"]
            )
            entry.update(
                {
                    "bun_median_ms": round(statistics.median(samples_ms["bun"]), 3),
                    "bun_samples_ms": [round(s, 3) for s in samples_ms["bun"]],
                    "franken_vs_bun_median_ratio": round(
                        median_ratio(samples_ms["franken-node"], samples_ms["bun"]), 4
                    ),
                    "franken_vs_bun_ratio_ci95": [
                        round(bun_ci_low, 4),
                        round(bun_ci_high, 4),
                    ],
                }
            )
        results[name] = entry

    return {
        "active_runtimes": active_runtimes,
        "load_average_before": [round(x, 2) for x in load_before],
        "load_average_after": [round(x, 2) for x in os.getloadavg()],
        "workloads": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure franken-node vs node/bun latency & RSS (HC-003)"
    )
    parser.add_argument(
        "--bin", help="franken-node binary (default: $FRANKEN_NODE_BIN, then release builds)"
    )
    parser.add_argument("--node", default="node", help="reference node executable")
    parser.add_argument("--bun", default="bun", help="incumbent bun executable (optional unless --require-bun)")
    parser.add_argument("--no-bun", action="store_true", help="skip bun even if installed")
    parser.add_argument(
        "--require-bun", action="store_true", help="fail with ERROR if bun is not installed"
    )
    parser.add_argument(
        "--policy", default="balanced", choices=["strict", "balanced", "legacy-risky"]
    )
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument(
        "--budget-profile",
        default="ci_dev",
        choices=["dev_local", "ci_dev", "enterprise"],
        help="perf/budgets.toml profile used to populate cold_start_budget",
    )
    parser.add_argument(
        "--enforce-cold-start-budget",
        choices=["dev_local", "ci_dev", "enterprise"],
        help="enforce perf/budgets.toml min_iterations/warmup and exit 0 iff cold_start_budget PASSes (canary gate)",
    )
    parser.add_argument(
        "--signing-key", help="optional 32-byte/64-hex Ed25519 key file used to sign the report"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--out", help="also write the report to this path")
    args = parser.parse_args()

    budgets = load_perf_budgets()
    effective_budget_profile = args.enforce_cold_start_budget or args.budget_profile
    runs = args.runs
    warmup = args.warmup
    if args.enforce_cold_start_budget and budgets is not None:
        meta = budgets.get("meta", {})
        runs = max(runs, int(meta.get("min_iterations", 30)))
        warmup = max(warmup, int(meta.get("warmup_iterations", 5)))

    if runs < 3:
        parser.error("--runs must be at least 3")
    if warmup < 0:
        parser.error("--warmup must be >= 0")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "claim_id": "HC-003",
        "ratio_ceiling": RATIO_CEILING,
        "policy": args.policy,
    }
    binary = resolve_binary(args.bin)
    node = shutil.which(args.node)
    bun = None if args.no_bun else resolve_bun(args.bun)

    signing_key_bytes: bytes | None = None
    if args.signing_key:
        key_file = Path(args.signing_key)
        if not key_file.is_file():
            report["verdict"] = "ERROR"
            report["detail"] = f"signing key {args.signing_key!r} not found"
            rendered = json.dumps(report, indent=2, sort_keys=True)
            if args.out:
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(rendered + "\n", encoding="utf-8")
            if args.json:
                print(rendered)
            return 2
        signing_key_bytes = key_file.read_bytes()

    if binary is None or node is None or (args.require_bun and bun is None):
        report["verdict"] = "ERROR"
        if binary is None:
            report["detail"] = "franken-node binary not found (pass --bin or set FRANKEN_NODE_BIN)"
        elif node is None:
            report["detail"] = f"reference runtime {args.node!r} not found on PATH"
        else:
            report["detail"] = f"incumbent runtime {args.bun!r} not found on PATH"
    else:
        report["host"] = _host_fingerprint(binary, node, bun=bun)
        try:
            measured, workspace_key = measure(binary, node, args.policy, runs, warmup, bun=bun)
            report.update(measured)
            report["verdict"] = overall_verdict(
                [w["verdict"] for w in report["workloads"].values()]
            )
            report["cold_start_budget"] = evaluate_cold_start_budget(
                report["workloads"], budgets, effective_budget_profile, runs, warmup
            )
            effective_key = signing_key_bytes if signing_key_bytes is not None else workspace_key
            if effective_key is not None:
                sig = sign_report_ed25519(report, effective_key)
                if sig is not None:
                    report["signature"] = sig
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            report["verdict"] = "ERROR"
            report["detail"] = str(exc)

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    if args.json:
        print(rendered)
    else:
        print(f"HC-003 franken-node vs node/bun ({args.policy}): {report['verdict']}")
        for name, entry in report.get("workloads", {}).items():
            if entry["verdict"] == "INVALID":
                print(f"  {name:15s} INVALID  {entry['detail']}")
            else:
                fn_rt = entry["runtimes"]["franken-node"]
                bun_col = (
                    f"  bun {entry['bun_median_ms']:7.1f} ms"
                    if "bun_median_ms" in entry
                    else ""
                )
                print(
                    f"  {name:15s} {entry['verdict']:5s} node {entry['node_median_ms']:7.1f} ms"
                    f"{bun_col}  franken {entry['franken_median_ms']:7.1f} ms"
                    f" (p99 {fn_rt['warm_dispatch']['p99_ms']:7.1f} ms,"
                    f" rss {fn_rt['rss_kb']['p50_kb']:6d} KiB)"
                    f"  ratio {entry['median_ratio']:.2f}"
                    f"  ci95 [{entry['ratio_ci95'][0]:.2f}, {entry['ratio_ci95'][1]:.2f}]"
                )
        if "cold_start_budget" in report:
            cs = report["cold_start_budget"]
            print(
                f"  cold_start_budget ({cs.get('profile')} <= {cs.get('cold_start_budget_ms')} ms): "
                f"{cs.get('verdict')} (hello p50={cs.get('hello_p50_ms')} ms, p99={cs.get('hello_p99_ms')} ms)"
            )
        if "detail" in report:
            print(f"  {report['detail']}")

    if args.enforce_cold_start_budget:
        if report.get("verdict") == "ERROR":
            return 2
        cs_verdict = report.get("cold_start_budget", {}).get("verdict")
        return 0 if cs_verdict == "PASS" else 1
    return {"PASS": 0, "FAIL": 1}.get(report["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
