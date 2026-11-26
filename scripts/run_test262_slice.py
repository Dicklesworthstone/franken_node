#!/usr/bin/env python3
"""Execute a deterministic, stratified >=1,000-case official TC39 Test262
language conformance slice through the real `franken-node` binary and live
`node` reference oracle.

Purpose (bd-reality-20260923-26n9r.6):
- Turns ECMAScript language conformance from a small probe list / provisional
  3-vector check into an honest, reproducible, directory-stratified official
  Test262 measurement with full provenance and per-case structured JSONL logs.
- Selection is 100% blind to pass/fail (deterministic uniform stride across
  every `test/language/<subdir>/` directory at the pinned tc39/test262 commit).
- Every selected case runs against BOTH live `node` (verifying harness
  validity) and `franken-node run --policy <profile> --runtime franken-engine
  --console-only`.
- Negative tests require non-zero exit AND a matching error class (never
  counting capability denials or panics as passing SyntaxError/TypeError tests).
- Never claims full-suite conformance (`full_suite_claim_allowed: false`).
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PINNED_COMMIT = "d0c1b4555b03dd404873fd6422a4b5da00136500"
ASYNC_DONE_SENTINEL = "__TEST262_ASYNC_DONE__"
FRONTMATTER_RE = re.compile(r"/\*---\s*(.*?)\s*---\*/", re.DOTALL)

# Features requiring host-specific $262 / cross-realm / Atomics agent APIs or
# unstandardized post-ES2024 proposals that do not run standalone without a
# custom $262 host shell. Recorded transparently in `skipped_by_reason`.
UNSUPPORTED_FLAGS = frozenset({"module", "CanBlockIsFalse", "CanBlockIsTrue", "non-deterministic"})
UNSUPPORTED_FEATURES = frozenset(
    {
        "IsHTMLDDA",
        "cross-realm",
        "caller",
        "tail-call-optimization",
        "ShadowRealm",
        "Temporal",
        "decorators",
        "explicit-resource-management",
        "import-attributes",
        "import-assertions",
        "json-modules",
        "source-phase-imports",
        "defer-import-eval",
        "regexp-modifiers",
        "regexp-duplicate-named-groups",
        "regexp-v-flag",
        "resizable-arraybuffer",
        "arraybuffer-transfer",
        "Float16Array",
        "Atomics.waitAsync",
        "SharedArrayBuffer",
        "Atomics",
        "FinalizationRegistry",
        "WeakRef",
        "iterator-helpers",
        "set-methods",
        "uint8array-base64",
    }
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_frontmatter(source: str) -> dict[str, Any] | None:
    match = FRONTMATTER_RE.search(source)
    if not match:
        return None
    try:
        meta = yaml.safe_load(match.group(1))
    except Exception:
        return None
    return meta if isinstance(meta, dict) else None


def discover_and_select_cases(
    test262_root: Path,
    target_cases: int,
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, int]]:
    lang_root = test262_root / "test" / "language"
    if not lang_root.is_dir():
        raise SystemExit(f"ERROR: missing test/language directory under {test262_root}")

    skipped_by_reason: Counter[str] = Counter()
    eligible_by_dir: dict[str, list[dict[str, Any]]] = defaultdict(list)

    all_files = sorted(lang_root.rglob("*.js"))
    for path in all_files:
        rel = path.relative_to(test262_root / "test").as_posix()
        if path.name.endswith("_FIXTURE.js"):
            skipped_by_reason["fixture_file"] += 1
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skipped_by_reason["non_utf8"] += 1
            continue
        meta = parse_frontmatter(source)
        if meta is None:
            skipped_by_reason["missing_or_invalid_frontmatter"] += 1
            continue

        flags = [str(f) for f in (meta.get("flags") or [])]
        features = [str(f) for f in (meta.get("features") or [])]
        includes = [str(i) for i in (meta.get("includes") or [])]
        negative = meta.get("negative")
        if negative is not None and not isinstance(negative, dict):
            skipped_by_reason["malformed_negative"] += 1
            continue

        bad_flag = next((f for f in flags if f in UNSUPPORTED_FLAGS), None)
        if bad_flag is not None:
            skipped_by_reason[f"flag:{bad_flag}"] += 1
            continue
        bad_feat = next((f for f in features if f in UNSUPPORTED_FEATURES), None)
        if bad_feat is not None:
            skipped_by_reason[f"feature:{bad_feat}"] += 1
            continue
        if "$262" in source:
            skipped_by_reason["uses_$262_host_api"] += 1
            continue
        if "_FIXTURE" in source or "dynamic-import" in rel:
            skipped_by_reason["requires_sibling_fixture"] += 1
            continue

        top_subdir = rel.split("/")[1] if len(rel.split("/")) > 2 else "root"
        eligible_by_dir[top_subdir].append(
            {
                "test_id": rel,
                "subdir": top_subdir,
                "path": path,
                "flags": flags,
                "features": features,
                "includes": includes,
                "negative": negative,
            }
        )

    total_eligible = sum(len(v) for v in eligible_by_dir.values())
    if total_eligible < target_cases:
        raise SystemExit(
            f"ERROR: only {total_eligible} eligible test/language cases found, need >= {target_cases}"
        )

    # Deterministic, pass/fail-blind stratified allocation across all subdirectories.
    subdirs = sorted(eligible_by_dir.keys())
    alloc: dict[str, int] = {}
    remaining = target_cases
    # Guarantee every subdirectory gets at least min(len, 5) cases.
    for d in subdirs:
        base = min(len(eligible_by_dir[d]), 5)
        alloc[d] = base
        remaining -= base

    # Distribute remaining budget proportionally to remaining pool size.
    while remaining > 0:
        capacities = {d: len(eligible_by_dir[d]) - alloc[d] for d in subdirs}
        total_cap = sum(capacities.values())
        if total_cap <= 0:
            break
        progress = 0
        # Sort by largest fractional share deterministically.
        shares = []
        for d in subdirs:
            cap = capacities[d]
            if cap <= 0:
                continue
            exact = remaining * (cap / total_cap)
            whole = min(cap, int(exact))
            alloc[d] += whole
            progress += whole
            shares.append((exact - whole, d))
        remaining -= progress
        if remaining > 0:
            shares.sort(key=lambda pair: (-pair[0], pair[1]))
            for _, d in shares:
                if remaining <= 0:
                    break
                if alloc[d] < len(eligible_by_dir[d]):
                    alloc[d] += 1
                    remaining -= 1

    selected: list[dict[str, Any]] = []
    for d in subdirs:
        pool = eligible_by_dir[d]
        k = alloc[d]
        if k >= len(pool):
            chosen = list(pool)
        else:
            # Uniform deterministic stride across the lexicographically sorted pool.
            chosen = [pool[(i * len(pool)) // k] for i in range(k)]
        selected.extend(chosen)

    pool_counts = {d: len(eligible_by_dir[d]) for d in subdirs}
    return selected, dict(sorted(skipped_by_reason.items())), pool_counts


def load_harness_cache(test262_root: Path) -> dict[str, str]:
    harness_dir = test262_root / "harness"
    cache: dict[str, str] = {}
    for p in harness_dir.glob("*.js"):
        cache[p.name] = p.read_text(encoding="utf-8")
    return cache


def assemble_script(case: dict[str, Any], harness: dict[str, str]) -> str:
    source = case["path"].read_text(encoding="utf-8")
    flags = set(case["flags"])
    if "raw" in flags:
        return source

    parts: list[str] = []
    if "onlyStrict" in flags:
        parts.append('"use strict";\n')

    # Standard Test262 prelude: sta.js + assert.js + frontmatter includes.
    ordered_includes: list[str] = ["sta.js", "assert.js"]
    for inc in case["includes"]:
        if inc not in ordered_includes:
            ordered_includes.append(inc)
    for inc in ordered_includes:
        if inc not in harness:
            raise FileNotFoundError(f"missing Test262 harness include: {inc}")
        parts.append(f"// --- harness/{inc} ---\n{harness[inc]}\n")

    if "async" in flags:
        parts.append(
            "function $DONE(err) {\n"
            "  if (err) { throw err; }\n"
            f"  console.log({ASYNC_DONE_SENTINEL!r});\n"
            "}\n"
        )

    parts.append("// --- test case ---\n")
    parts.append(source)
    return "\n".join(parts)


def classify_error(returncode: int | None, stderr: str, stdout: str, timed_out: bool) -> str:
    if timed_out:
        return "timeout"
    combined = f"{stderr}\n{stdout}"
    if "panicked at" in combined or "RUST_BACKTRACE" in combined:
        return "panic"
    if (
        returncode == 2
        or "error: invalid value" in combined
        or "Usage: franken-node" in combined
        or "must remain outside guest filesystem root" in combined
    ):
        return "cli_or_harness_error"
    lower = combined.lower()
    if "capability denied" in lower or "preflight" in lower or ("ifc" in lower and "blocked" in lower):
        return "capability_or_policy_denied"
    if "err_module_registry_incomplete" in lower:
        return "frozen_module_registry_incomplete"
    if "err_module_engine_parse" in lower or "native execution failed: parse:" in lower:
        return "SyntaxError"
    for err_type in (
        "SyntaxError",
        "ReferenceError",
        "TypeError",
        "RangeError",
        "URIError",
        "EvalError",
        "Test262Error",
    ):
        if err_type in combined:
            return err_type
    if any(
        tok in lower
        for tok in (
            "parse error",
            "parse_error",
            "parseerror",
            "syntax error",
            "static semantics",
            "unexpected token",
            "unterminated",
            "expected expression",
            "expected identifier",
            "expected `;`",
            "duplicate parameter",
            "duplicate lexical",
            "cannot assign to",
            "illegal return",
            "illegal break",
            "illegal continue",
        )
    ):
        return "SyntaxError"
    if "reference error" in lower or "not defined" in lower:
        return "ReferenceError"
    if "type error" in lower:
        return "TypeError"
    if "range error" in lower:
        return "RangeError"
    if "interpreter: uncaught exception:" in lower:
        return "uncaught_exception"
    return "other_error"


def evaluate_outcome(
    case: dict[str, Any],
    returncode: int | None,
    stdout: str,
    stderr: str,
    timed_out: bool,
) -> tuple[bool, str]:
    if timed_out:
        return False, "timeout"
    flags = set(case["flags"])
    negative = case["negative"]
    if negative is not None:
        expected_type = str(negative.get("type", "")).strip()
        phase = str(negative.get("phase", "")).strip()
        if returncode == 0:
            return False, f"unexpected_exit_0_expected_{expected_type}"
        observed = classify_error(returncode, stderr, stdout, False)
        if observed in ("panic", "capability_or_policy_denied", "cli_or_harness_error"):
            return False, f"invalid_negative_failure:{observed}"
        if expected_type and observed == expected_type:
            return True, f"negative_matched:{phase}:{expected_type}"
        return False, f"negative_mismatch:expected_{expected_type}_got_{observed}"

    # Positive test case
    if returncode != 0:
        return False, f"unexpected_error:{classify_error(returncode, stderr, stdout, False)}"
    if "async" in flags and ASYNC_DONE_SENTINEL not in stdout:
        return False, "async_missing_done_sentinel"
    return True, "ok"


def get_franken_provenance(franken_bin: Path) -> dict[str, Any]:
    out = subprocess.run(
        [str(franken_bin), "ops", "health-check", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    health = json.loads(out.stdout)
    ver = subprocess.run(
        [str(franken_bin), "--version"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return {
        "binary_path": str(franken_bin),
        "binary_sha256": sha256_file(franken_bin),
        "binary_version": ver,
        "build_version": health.get("build_version"),
        "health_check_pass": health.get("pass"),
        "franken_node_git_sha": health.get("git_sha") or health.get("source_git_sha"),
        "health_summary": {
            k: health.get(k)
            for k in ("pass", "git_sha", "build_version", "pass_source")
            if k in health
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic official Test262 language slice")
    parser.add_argument("--test262-root", required=True, type=Path)
    parser.add_argument("--expected-commit", default=DEFAULT_PINNED_COMMIT)
    parser.add_argument(
        "--franken-engine-commit",
        default="",
        help="Exact sibling franken_engine commit SHA compiled into --franken-node-bin",
    )
    parser.add_argument(
        "--franken-node-bin",
        type=Path,
        default=ROOT / "target" / "release" / "franken-node",
    )
    parser.add_argument("--node-bin", default=shutil.which("node") or "node")
    parser.add_argument("--profile", default="balanced", choices=["balanced", "legacy-risky", "strict"])
    parser.add_argument("--target-cases", type=int, default=1200)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout-secs", type=float, default=5.0)
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "artifacts" / "compat" / "test262_language_slice.json",
    )
    parser.add_argument(
        "--output-jsonl",
        type=Path,
        default=ROOT / "artifacts" / "compat" / "test262_language_slice_cases.jsonl",
    )
    args = parser.parse_args()

    franken_bin = args.franken_node_bin.resolve()
    if not franken_bin.is_file():
        print(f"ERROR: franken-node binary not found: {franken_bin}", file=sys.stderr)
        return 2

    test262_commit = subprocess.run(
        ["git", "-C", str(args.test262_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if args.expected_commit and test262_commit != args.expected_commit:
        print(
            f"ERROR: test262 commit mismatch: got {test262_commit}, expected {args.expected_commit}",
            file=sys.stderr,
        )
        return 2

    node_version = subprocess.run(
        [args.node_bin, "--version"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    franken_engine_commit = args.franken_engine_commit.strip()
    if not franken_engine_commit:
        sibling_engine = ROOT.parent / "franken_engine"
        if sibling_engine.is_dir():
            proc = subprocess.run(
                ["git", "-C", str(sibling_engine), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                franken_engine_commit = proc.stdout.strip()
    franken_prov = get_franken_provenance(franken_bin)
    if franken_engine_commit:
        franken_prov["franken_engine_commit"] = franken_engine_commit
    harness = load_harness_cache(args.test262_root)
    selected, skipped_by_reason, pool_counts = discover_and_select_cases(
        args.test262_root, args.target_cases
    )

    print(
        f"[test262] commit={test262_commit[:12]} selected={len(selected)} "
        f"subdirs={len(pool_counts)} profile={args.profile} workers={args.workers} "
        f"node={node_version}",
        flush=True,
    )

    t_start = time.monotonic()
    thread_local = threading.local()
    temp_dirs: list[tempfile.TemporaryDirectory[str]] = []
    temp_dirs_lock = threading.Lock()

    def get_worker_ctx() -> dict[str, Any]:
        ctx = getattr(thread_local, "ctx", None)
        if ctx is None:
            td = tempfile.TemporaryDirectory(prefix="franken_test262_w_")
            with temp_dirs_lock:
                temp_dirs.append(td)
            wdir = Path(td.name)
            proj = wdir / "proj"
            proj.mkdir()
            state_dir = wdir / "state_0"
            state_dir.mkdir()
            subprocess.run(
                [str(franken_bin), "init", "--profile", args.profile, "--out-dir", "."],
                cwd=str(proj),
                capture_output=True,
                text=True,
                check=True,
                env={**os.environ, "XDG_STATE_HOME": str(state_dir)},
            )
            ctx = {"wdir": wdir, "proj": proj, "state_dir": state_dir, "count": 0, "state_idx": 0}
            thread_local.ctx = ctx
        # Rotate XDG_STATE_HOME every 64 runs to stay far below native-session inventory caps.
        if ctx["count"] > 0 and ctx["count"] % 64 == 0:
            ctx["state_idx"] += 1
            new_state = ctx["wdir"] / f"state_{ctx['state_idx']}"
            new_state.mkdir(exist_ok=True)
            ctx["state_dir"] = new_state
        ctx["count"] += 1
        return ctx

    def run_one(case: dict[str, Any]) -> dict[str, Any]:
        ctx = get_worker_ctx()
        script = assemble_script(case, harness)
        script_path = ctx["proj"] / f"case_{ctx['count']}.js"
        script_path.write_text(script, encoding="utf-8")

        # 1. Live Node reference oracle (real Script-goal evaluation via vm.runInThisContext,
        # not CommonJS module wrapper, so global-code and strict/sloppy script tests run faithfully).
        node_timed_out = False
        try:
            node_proc = subprocess.run(
                [
                    args.node_bin,
                    "-e",
                    "const fs=require('fs'),vm=require('vm'); vm.runInThisContext(fs.readFileSync(process.argv[1],'utf8'), {filename: process.argv[1]});",
                    script_path.name,
                ],
                cwd=str(ctx["proj"]),
                capture_output=True,
                text=True,
                timeout=args.timeout_secs,
            )
            node_rc, node_out, node_err = node_proc.returncode, node_proc.stdout, node_proc.stderr
        except subprocess.TimeoutExpired:
            node_timed_out = True
            node_rc, node_out, node_err = None, "", "timeout"
        node_pass, node_detail = evaluate_outcome(case, node_rc, node_out, node_err, node_timed_out)

        # 2. Live franken-node execution (relative path inside cwd project root).
        fn_timed_out = False
        t0 = time.monotonic()
        try:
            fn_proc = subprocess.run(
                [
                    str(franken_bin),
                    "run",
                    "--policy",
                    args.profile,
                    "--runtime",
                    "franken-engine",
                    "--console-only",
                    script_path.name,
                ],
                cwd=str(ctx["proj"]),
                capture_output=True,
                text=True,
                timeout=args.timeout_secs,
                env={**os.environ, "XDG_STATE_HOME": str(ctx["state_dir"])},
            )
            fn_rc, fn_out, fn_err = fn_proc.returncode, fn_proc.stdout, fn_proc.stderr
        except subprocess.TimeoutExpired:
            fn_timed_out = True
            fn_rc, fn_out, fn_err = None, "", "timeout"
        fn_ms = round((time.monotonic() - t0) * 1000.0, 2)
        fn_pass, fn_detail = evaluate_outcome(case, fn_rc, fn_out, fn_err, fn_timed_out)

        return {
            "test_id": case["test_id"],
            "subdir": case["subdir"],
            "flags": case["flags"],
            "negative": case["negative"],
            "node_pass": node_pass,
            "node_detail": node_detail,
            "franken_pass": fn_pass,
            "franken_detail": fn_detail,
            "franken_exit_code": fn_rc,
            "franken_timed_out": fn_timed_out,
            "franken_ms": fn_ms,
            "franken_stderr_excerpt": fn_err.strip()[:240] if not fn_pass else "",
        }

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(run_one, selected))
    finally:
        for td in temp_dirs:
            td.cleanup()

    elapsed_s = round(time.monotonic() - t_start, 2)
    by_dir: dict[str, dict[str, Any]] = {}
    failure_categories: Counter[str] = Counter()
    node_passed = 0
    franken_passed = 0
    franken_passed_on_node_passed = 0
    franken_timed_out = 0
    franken_panics = 0

    for subdir in sorted(pool_counts.keys()):
        by_dir[subdir] = {
            "pool_eligible": pool_counts[subdir],
            "executed": 0,
            "node_passed": 0,
            "franken_passed": 0,
            "franken_failed": 0,
            "franken_timed_out": 0,
        }

    for r in results:
        d = by_dir[r["subdir"]]
        d["executed"] += 1
        if r["node_pass"]:
            node_passed += 1
            d["node_passed"] += 1
        if r["franken_pass"]:
            franken_passed += 1
            d["franken_passed"] += 1
            if r["node_pass"]:
                franken_passed_on_node_passed += 1
        else:
            d["franken_failed"] += 1
            failure_categories[r["franken_detail"]] += 1
            if r["franken_timed_out"]:
                franken_timed_out += 1
                d["franken_timed_out"] += 1
            if "panic" in r["franken_detail"]:
                franken_panics += 1

    for d in by_dir.values():
        denom = d["executed"]
        d["pass_rate_pct"] = round((100.0 * d["franken_passed"] / denom), 2) if denom else 0.0
        d["node_pass_rate_pct"] = round((100.0 * d["node_passed"] / denom), 2) if denom else 0.0

    executed = len(results)
    summary = {
        "schema_version": "franken-node/test262-language-slice/v1",
        "owning_bead": "bd-reality-20260923-26n9r.6",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "proof_state": "measured_stratified_slice",
        "full_suite_claim_allowed": False,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
        },
        "provenance": {
            "test262_repo": "tc39/test262",
            "test262_commit": test262_commit,
            "node_version": node_version,
            "profile": args.profile,
            "runtime": "franken-engine",
            **franken_prov,
        },
        "selection_policy": {
            "scope": "test/language/**/*.js",
            "stratification": "deterministic_uniform_stride_per_top_level_subdir_blind_to_outcome",
            "target_cases": args.target_cases,
            "executed_cases": executed,
            "total_eligible_in_language": sum(pool_counts.values()),
            "skipped_by_reason": skipped_by_reason,
            "harness_preloaded": ["sta.js", "assert.js", "frontmatter includes", "$DONE (async)"],
        },
        "totals": {
            "executed": executed,
            "node_passed": node_passed,
            "node_pass_rate_pct": round(100.0 * node_passed / executed, 2) if executed else 0.0,
            "franken_passed": franken_passed,
            "franken_failed": executed - franken_passed,
            "franken_timed_out": franken_timed_out,
            "franken_panics": franken_panics,
            "franken_pass_rate_pct": round(100.0 * franken_passed / executed, 2) if executed else 0.0,
            "franken_pass_rate_on_node_passed_pct": (
                round(100.0 * franken_passed_on_node_passed / node_passed, 2)
                if node_passed
                else 0.0
            ),
            "elapsed_seconds": elapsed_s,
        },
        "failure_categories": dict(failure_categories.most_common()),
        "by_directory": by_dir,
        "case_log_path": str(args.output_jsonl.resolve().relative_to(ROOT))
        if args.output_jsonl.resolve().is_relative_to(ROOT)
        else str(args.output_jsonl),
        "limitations": [
            "Stratified slice of test/language/* (non-module, non-$262-host-API script tests), not the full official Test262 suite.",
            "full_suite_claim_allowed is strictly false; built-ins/*, annexB/*, intl402/*, and module-graph tests are outside this slice.",
        ],
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    with args.output_jsonl.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")

    print(
        f"[test262] DONE in {elapsed_s}s: executed={executed}, "
        f"node_passed={node_passed}/{executed} ({summary['totals']['node_pass_rate_pct']}%), "
        f"franken_passed={franken_passed}/{executed} ({summary['totals']['franken_pass_rate_pct']}%), "
        f"panics={franken_panics}, timeouts={franken_timed_out}",
        flush=True,
    )
    print(f"[test262] top failures: {dict(failure_categories.most_common(8))}", flush=True)
    print(f"[test262] wrote {args.output_json} and {args.output_jsonl}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
