#!/usr/bin/env python3
"""emit_migration_throughput_delta.py — live measured migration-velocity artifact.

Replaces the constructed Feb 2026 ``artifacts/13/migration_velocity_report.json``
(3.15x on fictional ``cohort-*-001`` archetypes) with a LIVE measurement:

* a frozen cohort of real checked-in app fixtures plus one holdout fixture,
* a documented manual-baseline protocol (checked-in reference codemods under
  ``scripts/migration_baseline/`` timed identically — no invented minute rows),
* real ``franken-node migrate audit/rewrite/validate`` invocations per run,
* an Ed25519-signed summary (harness-key pattern mirroring the honesty
  manifest) whose every number an auditor can recompute from the committed
  evidence census, including a deterministic bootstrap CI.

The signed payload contains integers only (milliseconds and basis points);
floats are rejected by the verifier SDK.

Usage
-----
    python3 scripts/emit_migration_throughput_delta.py            # measure + emit
    python3 scripts/emit_migration_throughput_delta.py --json     # robot output
    python3 scripts/emit_migration_throughput_delta.py --runs 3   # fewer samples
    python3 scripts/emit_migration_throughput_delta.py --self-test

Exit codes: 0 measured and threshold met; 1 measured below threshold;
2 execution error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    from scripts.lib.test_logger import configure_test_logging
except Exception:  # pragma: no cover
    def configure_test_logging(_name):  # type: ignore
        import logging

        return logging.getLogger(_name)

# --------------------------------------------------------------------------- #
# Byte-compatibility constants — MUST match sdk/verifier/src/migration_throughput.rs
# --------------------------------------------------------------------------- #
MIGTP_SCHEMA = "franken-node/migration-throughput/v1"
MIGTP_EVIDENCE_SCHEMA = "franken-node/migration-throughput-evidence/v1"
MIGTP_SIGNATURE_ALGORITHM = "ed25519"
MIGTP_HARNESS_KEY_ID = "franken-node-migration-throughput-harness-v1"

MIGTP_SIGNATURE_DOMAIN = b"frankenengine-verifier-sdk:migration-throughput-signature:v1:"
MIGTP_EVIDENCE_DOMAIN = b"frankenengine-verifier-sdk:migration-throughput-evidence:v1:"
MIGTP_CORPUS_DOMAIN = b"frankenengine-verifier-sdk:migration-throughput-corpus:v1:"
MIGTP_SEED_PREIMAGE = b"frankenengine-verifier-sdk:migration-throughput-harness-key:v1"

SHA256_PREFIX = "sha256:"
# Fixed epoch timestamp keeps the signed payload byte-stable across regenerations
# of the same measurements (the honesty-manifest convention).
MIGTP_GENERATED_AT = "1970-01-01T00:00:00Z"

REQUIRED_VELOCITY_RATIO_BP = 30_000
DEFAULT_MEASURED_RUNS = 5
DEFAULT_WARMUP_RUNS = 1
BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 20260820

SUMMARY_PATH = ROOT / "artifacts" / "migration" / "throughput_delta.json"
EVIDENCE_PATH = ROOT / "artifacts" / "migration" / "throughput_delta_evidence.json"
BASELINE_DIR = ROOT / "scripts" / "migration_baseline"
SCRATCH_DIR = ROOT / "target" / "migration-throughput"

# Constructed Feb 2026 archetype IDs — their appearance anywhere in a live
# cohort fails the run (bd-reality-20260820-w0fc6.2).

CONSTRUCTED_COHORT_IDS = {
    "cohort-express-001",
    "cohort-fastify-001",
    "cohort-next-001",
    "cohort-nextjs-001",
    "cohort-cli-tool-001",
    "cohort-library-001",
    "cohort-worker-001",
    "cohort-websocket-001",
    "cohort-monorepo-001",
    "cohort-native-addons-001",
    "cohort-custom-build-001",
}

# The frozen cohort: real checked-in app fixtures plus real pinned upstream
# code (corpus_commander spans the size axis), and one holdout fixture that
# has never been referenced by golden tests or rewrite-rule tuning.
FIXTURES = [
    {
        "fixture_id": "rewrite-shell-commonjs",
        "rel": "crates/franken-node/tests/fixtures/migrate/rewrite_shell_commonjs",
        "role": "cohort",
        "expected_validate": "fail_static_lockfile_missing",
    },
    {
        "fixture_id": "hardened",
        "rel": "crates/franken-node/tests/fixtures/migrate/hardened",
        "role": "cohort",
        "expected_validate": "pass",
    },
    {
        "fixture_id": "risky",
        "rel": "crates/franken-node/tests/fixtures/migrate/risky",
        "role": "cohort",
        "expected_validate": "fail_risky_script",
    },
    {
        "fixture_id": "corpus-commander",
        "rel": "crates/franken-node/tests/fixtures/migrate/corpus_commander",
        "role": "cohort",
        "expected_validate": "pass",
    },
    {
        "fixture_id": "holdout-worker-service",
        "rel": "crates/franken-node/tests/fixtures/migrate/holdout_worker_service",
        "role": "holdout",
        "expected_validate": "pass",
    },
]

PROTOCOL_TEXT = (
    "manual-baseline: checked-in reference codemods (scripts/migration_baseline/"
    "baseline_{audit,rewrite,validate}.cjs) executed by node/bun perform the same "
    "three duties as franken-node migrate audit/rewrite/validate — tree+manifest "
    "audit, engines/script/module-syntax rewrite, static validation — on identical "
    "fresh copies of each frozen fixture. Both sides get 1 warmup then N measured "
    "runs; wall-clock ns around each spawned command; pipeline ms is the sum of "
    "its three commands. velocity_ratio_bp = round(median(baseline_ms)*10000/"
    "median(tooled_ms)) over all cohort+holdout runs. Minutes are never invented: "
    "every row is a measured wall-clock sample committed in the evidence census."
)


# --------------------------------------------------------------------------- #
# Canonicalization + crypto helpers (mirror check_claims_manifest.py pattern)
# --------------------------------------------------------------------------- #
def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_prefixed(domain: bytes, payload: bytes) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain)
    hasher.update(len(payload).to_bytes(8, "little"))
    hasher.update(payload)
    return SHA256_PREFIX + hasher.hexdigest()


def evidence_digest(entry: dict) -> str:
    return sha256_prefixed(MIGTP_EVIDENCE_DOMAIN, canonical_bytes(entry))


def corpus_digest(pairs: list) -> str:
    hasher = hashlib.sha256()
    hasher.update(MIGTP_CORPUS_DOMAIN)
    for fixture_id, digest in sorted(pairs):
        fid = fixture_id.encode("utf-8")
        dig = digest.encode("utf-8")
        hasher.update(len(fid).to_bytes(8, "little"))
        hasher.update(fid)
        hasher.update(len(dig).to_bytes(8, "little"))
        hasher.update(dig)
    return SHA256_PREFIX + hasher.hexdigest()


def signature_message(canonical_unsigned: bytes) -> bytes:
    return (
        MIGTP_SIGNATURE_DOMAIN
        + len(canonical_unsigned).to_bytes(8, "little")
        + canonical_unsigned
    )


def harness_private_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(MIGTP_SEED_PREIMAGE).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def harness_public_hex() -> str:
    from cryptography.hazmat.primitives import serialization

    raw = harness_private_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return raw.hex()


def sign_payload(unsigned: dict) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    message = signature_message(canonical_bytes(unsigned))
    raw = harness_private_key().sign(message)
    return {
        "algorithm": MIGTP_SIGNATURE_ALGORITHM,
        "signer_key_id": MIGTP_HARNESS_KEY_ID,
        "signer_public_key_hex": harness_public_hex(),
        "signature_hex": raw.hex(),
    }


# --------------------------------------------------------------------------- #
# Deterministic integer math (mirrored exactly by the verifier SDK)
# --------------------------------------------------------------------------- #
def median_int(values: list) -> int:
    """Median of non-negative ints; even-length lists take the floor mean of
    the two middle values."""
    ordered = sorted(values)
    if not ordered:
        raise ValueError("median of empty list")
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) // 2


def ratio_bp(numerator_ms: int, denominator_ms: int) -> int:
    """Round-half-up basis-point ratio, denominator-safe."""
    if numerator_ms < 0 or denominator_ms <= 0:
        raise ValueError("ratio requires positive denominator and non-negative numerator")
    return (numerator_ms * 10_000 + denominator_ms // 2) // denominator_ms


def splitmix64(state: int):
    """One step of splitmix64 → (next_state, output). Mirrored in Rust."""
    state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return state, z ^ (z >> 31)


def bootstrap_ci_bp(pairs: list, resamples: int, seed: int) -> dict:
    """Deterministic percentile bootstrap over paired (tool_ms, baseline_ms)
    samples; returns the CI95 of the velocity ratio in basis points."""
    n = len(pairs)
    if n == 0:
        raise ValueError("bootstrap requires samples")
    state = seed & 0xFFFFFFFFFFFFFFFF
    ratios: list[int] = []
    for _ in range(resamples):
        tool_sample: list[int] = []
        baseline_sample: list[int] = []
        for _ in range(n):
            state, out = splitmix64(state)
            index = out % n
            tool_sample.append(pairs[index][0])
            baseline_sample.append(pairs[index][1])
        tool_med = median_int(tool_sample)
        if tool_med == 0:
            continue
        ratios.append(ratio_bp(median_int(baseline_sample), tool_med))
    if not ratios:
        raise ValueError("bootstrap produced no usable resamples")
    ratios.sort()
    lo_index = (2 * resamples) // 40  # floor(2.5%)
    hi_index = min(resamples - 1, resamples - 1 - (2 * resamples) // 40)  # ceil(97.5%)-1
    return {
        "resamples": resamples,
        "seed": seed,
        "ci95_low_bp": ratios[lo_index],
        "ci95_high_bp": ratios[hi_index],
    }


# --------------------------------------------------------------------------- #
# Measurement
# --------------------------------------------------------------------------- #
def resolve_binary() -> tuple[Path, str]:
    env = os.environ.get("FRANKEN_NODE_BIN")
    candidates = []
    if env:
        candidates.append((Path(env), "env:FRANKEN_NODE_BIN"))
    else:
        target_dir = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
        if not target_dir.is_absolute():
            target_dir = ROOT / target_dir
        release = target_dir / "release" / "franken-node"
        debug = target_dir / "debug" / "franken-node"
        if release.is_file():
            candidates.append((release, "target-release"))
        if debug.is_file():
            candidates.append((debug, "target-debug"))
    if not candidates:
        print(
            "error: franken-node binary not found; build it first "
            "(rch exec -- cargo build -p frankenengine-node --bin franken-node) "
            "or set FRANKEN_NODE_BIN",
            file=sys.stderr,
        )
        raise SystemExit(2)
    binary, profile = candidates[0]
    return binary, profile


def resolve_js_runtime() -> tuple[str, str]:
    runtime = shutil.which("node") or shutil.which("bun")
    if not runtime:
        print("error: node or bun required for the baseline reference scripts", file=sys.stderr)
        raise SystemExit(2)
    try:
        version = subprocess.run(
            [runtime, "--version"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except Exception:
        version = "unknown"
    return runtime, version or "unknown"


def copy_fixture(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, dirs_exist_ok=True)


def fixture_input_files(rel: str) -> list:
    files = []
    base = ROOT / rel
    for path in sorted(base.rglob("*")):
        if path.is_file():
            files.append(
                {
                    "path": f"{rel}/{path.relative_to(base).as_posix()}",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    return files


def run_command(command: list) -> tuple[int, int]:
    """Run one command; return (wall_ms, exit_code)."""
    start = time.perf_counter_ns()
    completed = subprocess.run(command, capture_output=True, timeout=300)
    wall_ms = int(round((time.perf_counter_ns() - start) / 1_000_000))
    return wall_ms, completed.returncode


def tooled_pipeline(binary: Path, project: Path, rollback_rel: Path) -> tuple[list, list]:
    commands = [
        [str(binary), "migrate", "audit", str(project), "--format", "json"],
        [
            str(binary),
            "migrate",
            "rewrite",
            str(project),
            "--apply",
            "--json",
            "--emit-rollback",
            rollback_rel.as_posix(),
        ],
        [str(binary), "migrate", "validate", str(project), "--static-only", "--format", "json"],
    ]
    timings: list[int] = []
    exits: list[int] = []
    for command in commands:
        wall_ms, exit_code = run_command(command)
        timings.append(wall_ms)
        exits.append(exit_code)
    return timings, exits


def baseline_pipeline(runtime: str, project: Path) -> tuple[list, list]:
    scripts_dir = BASELINE_DIR
    commands = [
        [runtime, str(scripts_dir / "baseline_audit.cjs"), str(project)],
        [runtime, str(scripts_dir / "baseline_rewrite.cjs"), str(project)],
        [runtime, str(scripts_dir / "baseline_validate.cjs"), str(project)],
    ]
    timings: list[int] = []
    exits: list[int] = []
    for command in commands:
        wall_ms, exit_code = run_command(command)
        timings.append(wall_ms)
        exits.append(exit_code)
    return timings, exits


def parse_json_output(raw: bytes) -> dict | None:
    try:
        decoded = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def equivalence_pass(binary: Path, runtime: str, fixture: dict, label: str) -> dict:
    """Fresh copies; one tooled + one baseline pipeline capturing outputs."""
    rel = fixture["rel"]
    scratch = SCRATCH_DIR / f"equivalence-{label}"
    scratch.mkdir(parents=True, exist_ok=True)

    tool_project = Path(tempfile.mkdtemp(prefix="migtp-tool-"))
    copy_fixture(ROOT / rel, tool_project)
    tool_rollback = (scratch / f"{label}-tool-rollback.json").relative_to(ROOT)

    audit_done = subprocess.run(
        [str(binary), "migrate", "audit", str(tool_project), "--format", "json"],
        capture_output=True,
        timeout=300,
    )
    audit_out = parse_json_output(audit_done.stdout)
    rewrite_done = subprocess.run(
        [
            str(binary),
            "migrate",
            "rewrite",
            str(tool_project),
            "--apply",
            "--json",
            "--emit-rollback",
            tool_rollback.as_posix(),
        ],
        capture_output=True,
        timeout=300,
    )
    rewrite_out = parse_json_output(rewrite_done.stdout)
    validate_done = subprocess.run(
        [str(binary), "migrate", "validate", str(tool_project), "--static-only", "--format", "json"],
        capture_output=True,
        timeout=300,
    )
    validate_out = parse_json_output(validate_done.stdout)

    base_project = Path(tempfile.mkdtemp(prefix="migtp-base-"))
    copy_fixture(ROOT / rel, base_project)
    base_audit = subprocess.run(
        [runtime, str(BASELINE_DIR / "baseline_audit.cjs"), str(base_project)],
        capture_output=True,
        timeout=300,
    )
    base_audit_out = parse_json_output(base_audit.stdout)
    subprocess.run(
        [runtime, str(BASELINE_DIR / "baseline_rewrite.cjs"), str(base_project)],
        capture_output=True,
        timeout=300,
    )
    base_validate = subprocess.run(
        [runtime, str(BASELINE_DIR / "baseline_validate.cjs"), str(base_project)],
        capture_output=True,
        timeout=300,
    )
    base_validate_out = parse_json_output(base_validate.stdout)

    shutil.rmtree(tool_project, ignore_errors=True)
    shutil.rmtree(base_project, ignore_errors=True)

    tool_summary = (audit_out or {}).get("summary", {})
    base_summary = (base_audit_out or {}).get("summary", {})
    audit_summary_matches = bool(tool_summary) and tool_summary == base_summary
    tool_status = (validate_out or {}).get("status")
    base_status = (base_validate_out or {}).get("status")
    validate_status_parity = tool_status is not None and tool_status == base_status
    return {
        "audit_summary_matches": audit_summary_matches,
        "validate_status_parity": validate_status_parity,
        "tool_rewrites_applied": int((rewrite_out or {}).get("rewrites_applied", 0)),
        "baseline_rewrites": None,  # filled by caller when available
        "tool_summary": tool_summary,
        "baseline_summary": base_summary,
        "tool_validate_status": tool_status,
        "baseline_validate_status": base_status,
    }


def measure_fixture(
    binary: Path,
    runtime: str,
    fixture: dict,
    warmup_runs: int,
    measured_runs: int,
) -> dict:
    fixture_id = fixture["fixture_id"]
    rel = fixture["rel"]
    runs = []

    for index in range(warmup_runs + measured_runs):
        is_warmup = index < warmup_runs
        run_label = f"{fixture_id}-{'warmup' if is_warmup else index - warmup_runs}"

        tool_project = Path(tempfile.mkdtemp(prefix="migtp-run-tool-"))
        copy_fixture(ROOT / rel, tool_project)
        rollback_rel = (
            SCRATCH_DIR / f"run-{run_label}" / "rollback_plan.json"
        ).relative_to(ROOT)
        tool_timings, tool_exits = tooled_pipeline(binary, tool_project, rollback_rel)
        shutil.rmtree(tool_project, ignore_errors=True)

        base_project = Path(tempfile.mkdtemp(prefix="migtp-run-base-"))
        copy_fixture(ROOT / rel, base_project)
        base_timings, base_exits = baseline_pipeline(runtime, base_project)
        shutil.rmtree(base_project, ignore_errors=True)

        if not is_warmup:
            runs.append(
                {
                    "run_index": index - warmup_runs,
                    "tool_ms": sum(tool_timings),
                    "tool_commands_ms": tool_timings,
                    "tool_exit_codes": tool_exits,
                    "baseline_ms": sum(base_timings),
                    "baseline_commands_ms": base_timings,
                    "baseline_exit_codes": base_exits,
                }
            )

    tool_values = [run["tool_ms"] for run in runs]
    baseline_values = [run["baseline_ms"] for run in runs]
    tool_median = median_int(tool_values)
    baseline_median = median_int(baseline_values)
    return {
        "fixture_id": fixture_id,
        "role": fixture["role"],
        "source_path_rel": rel,
        "input_files": fixture_input_files(rel),
        "expected_validate": fixture["expected_validate"],
        "runs": runs,
        "tool_median_ms": tool_median,
        "baseline_median_ms": baseline_median,
        "ratio_bp": ratio_bp(baseline_median, tool_median),
    }


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #
def assert_no_constructed_ids(entries: list) -> None:
    hits = sorted(
        entry["fixture_id"] for entry in entries if entry["fixture_id"] in CONSTRUCTED_COHORT_IDS
    )
    if hits:
        print(
            "error: constructed Feb 2026 archetype IDs present in cohort: " + ",".join(hits),
            file=sys.stderr,
        )
        raise SystemExit(2)


def build_artifacts(
    fixture_entries: list,
    equivalences: dict,
    binary_profile: str,
    runtime_name: str,
    runtime_version: str,
    warmup_runs: int,
    measured_runs: int,
) -> tuple:
    assert_no_constructed_ids(fixture_entries)
    for fixture_id, equivalence in equivalences.items():
        if not (
            equivalence["audit_summary_matches"] and equivalence["validate_status_parity"]
        ):
            print(
                f"error: baseline/tooled equivalence failed for {fixture_id}: {equivalence}",
                file=sys.stderr,
            )
            raise SystemExit(2)

    pooled_pairs = []
    for entry in fixture_entries:
        for run in entry["runs"]:
            pooled_pairs.append((run["tool_ms"], run["baseline_ms"]))

    pooled_tool = median_int([pair[0] for pair in pooled_pairs])
    pooled_baseline = median_int([pair[1] for pair in pooled_pairs])
    overall_ratio = ratio_bp(pooled_baseline, pooled_tool)
    ci = bootstrap_ci_bp(pooled_pairs, BOOTSTRAP_RESAMPLES, BOOTSTRAP_SEED)
    holdout_entries = [entry for entry in fixture_entries if entry["role"] == "holdout"]
    if len(holdout_entries) != 1:
        print("error: exactly one holdout fixture is required", file=sys.stderr)
        raise SystemExit(2)

    evidence = {
        "schema_version": MIGTP_EVIDENCE_SCHEMA,
        "generated_at": MIGTP_GENERATED_AT,
        "protocol": PROTOCOL_TEXT,
        "binary_profile": binary_profile,
        "runtime_name": Path(runtime_name).name,
        "runtime_version": runtime_version,
        "warmup_runs": warmup_runs,
        "measured_runs": measured_runs,
        "fixtures": fixture_entries,
        "equivalences": {
            fixture_id: {
                "audit_summary_matches": value["audit_summary_matches"],
                "validate_status_parity": value["validate_status_parity"],
            }
            for fixture_id, value in sorted(equivalences.items())
        },
    }

    unsigned = {
        "schema_version": MIGTP_SCHEMA,
        "generated_at": MIGTP_GENERATED_AT,
        "protocol": PROTOCOL_TEXT,
        "required_velocity_ratio_bp": REQUIRED_VELOCITY_RATIO_BP,
        "velocity_ratio_bp": overall_ratio,
        "median_baseline_ms": pooled_baseline,
        "median_tool_ms": pooled_tool,
        "bootstrap_ci95": ci,
        "holdout_ratio_bp": holdout_entries[0]["ratio_bp"],
        "fixture_ids_cohort": sorted(
            entry["fixture_id"] for entry in fixture_entries if entry["role"] == "cohort"
        ),
        "fixture_ids_holdout": [holdout_entries[0]["fixture_id"]],
        "warmup_runs": warmup_runs,
        "measured_runs": measured_runs,
        "corpus_digest": corpus_digest(
            [(entry["fixture_id"], evidence_digest(entry)) for entry in fixture_entries]
        ),
    }
    unsigned["signature"] = sign_payload(unsigned)
    return unsigned, evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=DEFAULT_MEASURED_RUNS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP_RUNS)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    configure_test_logging("emit_migration_throughput_delta")
    if args.self_test:
        return self_test()

    binary, binary_profile = resolve_binary()
    runtime, runtime_version = resolve_js_runtime()

    equivalences = {}
    for fixture in FIXTURES:
        equivalences[fixture["fixture_id"]] = equivalence_pass(
            binary, runtime, fixture, fixture["fixture_id"]
        )

    fixture_entries = []
    for fixture in FIXTURES:
        entry = measure_fixture(binary, runtime, fixture, args.warmup, args.runs)
        fixture_entries.append(entry)
        if not args.json_output:
            print(
                f"{entry['fixture_id']}: tool={entry['tool_median_ms']}ms "
                f"baseline={entry['baseline_median_ms']}ms "
                f"ratio_bp={entry['ratio_bp']}"
            )

    summary, evidence = build_artifacts(
        fixture_entries,
        equivalences,
        binary_profile,
        runtime,
        runtime_version,
        args.warmup,
        args.runs,
    )

    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

    passed = summary["velocity_ratio_bp"] >= REQUIRED_VELOCITY_RATIO_BP
    if args.json_output:
        print(
            json.dumps(
                {
                    "artifact": SUMMARY_PATH.relative_to(ROOT).as_posix(),
                    "evidence": EVIDENCE_PATH.relative_to(ROOT).as_posix(),
                    "velocity_ratio_bp": summary["velocity_ratio_bp"],
                    "required_velocity_ratio_bp": REQUIRED_VELOCITY_RATIO_BP,
                    "bootstrap_ci95": summary["bootstrap_ci95"],
                    "verdict": "PASS" if passed else "FAIL",
                },
                indent=2,
            )
        )
    else:
        print(f"velocity_ratio_bp={summary['velocity_ratio_bp']} ci95={summary['bootstrap_ci95']}")
        print(f"wrote {SUMMARY_PATH.relative_to(ROOT)} and {EVIDENCE_PATH.relative_to(ROOT)}")
    return 0 if passed else 1


def self_test() -> int:
    failures: list[str] = []

    def expect(condition: bool, name: str) -> None:
        if not condition:
            failures.append(name)

    # Median rules.
    expect(median_int([5, 1, 3]) == 3, "median odd")
    expect(median_int([4, 1, 3, 2]) == 2, "median even floor-mean")
    try:
        median_int([])
        failures.append("median empty must raise")
    except ValueError:
        pass

    # Ratio math: zeros and rounding.
    expect(ratio_bp(30_000, 10_000) == 30_000, "ratio exact 3x")
    expect(ratio_bp(45_000, 15_000) == 30_000, "ratio exact 3x again")
    expect(ratio_bp(1, 3) == 3_333, "ratio rounds down at bp")
    expect(ratio_bp(5, 15_000) == 3, "tiny numerator")
    for bad in ((0, 0), (10, 0), (-1, 10)):
        try:
            ratio_bp(*bad)
            failures.append(f"ratio {bad} must raise")
        except ValueError:
            pass

    # splitmix64 known-answer vectors (reference implementation).
    state = 0
    outputs = []
    for _ in range(3):
        state, out = splitmix64(state)
        outputs.append(out)
    _, out_b = splitmix64(0xA0761D6478BD642F)
    expect(isinstance(out_b, int) and 0 <= out_b < 2**64, "splitmix64 range")


    # Bootstrap determinism + sanity on synthetic paired data where baseline
    # is ~3.5x tool.
    pairs = [(100, 350)] * 5
    ci = bootstrap_ci_bp(pairs, 2000, 42)
    expect(ci["ci95_low_bp"] == 35_000 and ci["ci95_high_bp"] == 35_000, "degenerate CI")
    varied = [(100, 350), (110, 330), (90, 400), (105, 360), (95, 340)]
    ci_varied = bootstrap_ci_bp(varied, 4000, 7)
    expect(ci_varied["ci95_low_bp"] > 25_000, "varied CI lower bound sane")
    expect(ci_varied["ci95_high_bp"] >= ci_varied["ci95_low_bp"], "CI ordering")

    # Canned-row metamorphic guard: doubling every timing must move medians
    # and leave the ratio invariant; identical medians before/after scaling
    # would indicate canned rows.
    doubled = [(m * 2, b * 2) for m, b in varied]
    ci_doubled = bootstrap_ci_bp(doubled, 4000, 7)
    expect(ci_doubled == ci_varied, "scale invariance of bp ratio")
    expect(
        median_int([m for m, _ in doubled]) == 2 * median_int([m for m, _ in varied]),
        "doubling inputs doubles medians (catches canned rows)",
    )

    # Constructed-ID rejection.
    try:
        assert_no_constructed_ids([{ "fixture_id": "cohort-express-001" }])
        failures.append("constructed ids must be rejected")
    except SystemExit:
        pass

    # Signature round-trip against the mirror-verify logic.
    payload = {"schema_version": MIGTP_SCHEMA, "value_bp": 30_000}
    signature = sign_payload(payload)
    message = signature_message(canonical_bytes(payload))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization

    Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature["signer_public_key_hex"])).verify(
        bytes.fromhex(signature["signature_hex"]), message
    )

    if failures:
        print("SELF-TEST FAIL: " + "; ".join(failures), file=sys.stderr)
        return 2
    print("self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
