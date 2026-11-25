#!/usr/bin/env python3
"""Executable Continuous Lockstep Validation Gate (bd-1w78 / bd-2djfa).

Combines:
  1. Policy/contract completeness checks (`run_all()`, preserving bd-1w78 API).
  2. Real corpus lockstep artifact evaluation (`--evaluate-corpus`):
     - Verifies provenance (`lockstep-oracle-run`), triad runtime topology,
       and byte-for-byte recomputed `ccg_corpus_result_digest_v1` SHA-256.
     - Enforces overall pass rate (>=95%), per-family floor (>=80%), per-band
       floors (core >=99%, high-value >=95%, edge >=90%), corpus size floor,
       100 ms timing-anomaly budget, divergence receipt validation, and
       non-regression against a previous baseline (`--baseline`).
  3. Live multi-runtime lockstep execution (`--execute-live`):
     - Executes real `node`, `bun`, and `franken-node` (or fail-closed error
       when a requested runtime binary is absent) over deterministic fixture
       cases, captures stdout/stderr/exit_code/elapsed_ms and filesystem
       content/mode changes (network activity is explicitly unobserved),
       classifies divergences into
       `agree` / `harmless` / `acceptable` / `blocking`, validates divergence
       receipts, evaluates thresholds, writes a machine-readable report, and
       emits structured JSONL lifecycle events (`lockstep_run_started`,
       `runtime_invoked`, `case_completed`, `divergence_classified`,
       `receipt_verified`, `threshold_evaluated`, `artifact_written`,
       `lockstep_run_completed`).

Usage:
    python3 scripts/check_lockstep_validation.py [--json]
    python3 scripts/check_lockstep_validation.py --evaluate-corpus [PATH] [--baseline PATH] [--receipts PATH] [--json]
    python3 scripts/check_lockstep_validation.py --execute-live --fixtures-dir DIR [--runtimes node,bun,franken-node] [--json]
    python3 scripts/check_lockstep_validation.py --self-test
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-1w78"
REALITY_BEAD_ID = "bd-2djfa"

SPEC_PATH = ROOT / "docs" / "specs" / "section_13" / "bd-1w78_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "continuous_lockstep_validation.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_13" / "bd-1w78" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_13" / "bd-1w78" / "verification_summary.md"
DEFAULT_CORPUS_RESULTS_PATH = ROOT / "artifacts" / "13" / "compatibility_corpus_results.json"

EVENT_CODES = ["CLV-001", "CLV-002", "CLV-003", "CLV-004"]
INVARIANTS = [
    "INV-CLV-CONTINUOUS",
    "INV-CLV-COVERAGE",
    "INV-CLV-REGRESSION",
    "INV-CLV-CORPUS",
]
LIFECYCLE_EVENTS = (
    "lockstep_run_started",
    "runtime_invoked",
    "case_completed",
    "divergence_classified",
    "receipt_verified",
    "threshold_evaluated",
    "artifact_written",
    "lockstep_run_completed",
)

REQUIRED_FILES = [SPEC_PATH, POLICY_PATH, EVIDENCE_PATH, SUMMARY_PATH]

CCG_RESULT_DIGEST_DOMAIN = b"ccg_corpus_result_digest_v1:"
DEFAULT_OVERALL_MIN_PCT = 95.0
DEFAULT_FAMILY_FLOOR_PCT = 80.0
DEFAULT_BAND_FLOORS = {"core": 99.0, "high-value": 95.0, "edge": 90.0}
DEFAULT_TIMING_BUDGET_MS = 100.0
DEFAULT_MIN_CORPUS_CASES = 500
POLICY_TARGET_CORPUS_CASES = 1000
VALID_DIVERGENCE_CLASSES = {"agree", "harmless", "acceptable", "blocking"}
MAX_SNAPSHOT_ENTRIES = 50_000
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOT_DEPTH = 128
SNAPSHOT_TIMEOUT_SECS = 15.0

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TEMP_PATH_RE = re.compile(r"(/tmp|/var/folders|/data/tmp)/[^\s:\"'`]+")
_ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(dt: datetime | None = None) -> str:
    return (dt or _utc_now()).isoformat().replace("+00:00", "Z")


def _parse_iso_utc(raw: str) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _read(path: Path) -> str:
    """Read file contents or return empty string if missing."""
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return ""


# ---------------------------------------------------------------------------
# Policy/contract completeness checks (bd-1w78 API preserved)
# ---------------------------------------------------------------------------


def check_files_exist() -> dict:
    """Verify all required deliverable files exist."""
    missing = [str(f.relative_to(ROOT)) for f in REQUIRED_FILES if not f.is_file()]
    return {
        "name": "files_exist",
        "passed": len(missing) == 0,
        "detail": f"missing: {missing}" if missing else "all files present",
    }


def check_spec_completeness() -> dict:
    """Verify the spec contract covers all required sections."""
    content = _read(SPEC_PATH)
    required_sections = [
        "Purpose",
        "Targets",
        "Lockstep Architecture",
        "Event Codes",
        "Invariants",
        "Acceptance Criteria",
    ]
    missing = [s for s in required_sections if s not in content]
    return {
        "name": "spec_completeness",
        "passed": len(missing) == 0,
        "detail": f"missing sections: {missing}" if missing else "all sections present",
    }


def check_lockstep_architecture() -> dict:
    """Verify lockstep oracle architecture (L1 + L2) is documented."""
    spec = _read(SPEC_PATH)
    policy = _read(POLICY_PATH)
    combined = spec + policy
    has_l1 = "L1" in combined and ("Product Layer" in combined or "Product" in combined)
    has_l2 = "L2" in combined and ("Engine Layer" in combined or "Engine" in combined)
    passed = has_l1 and has_l2
    detail_parts = []
    if not has_l1:
        detail_parts.append("missing L1 Product Layer")
    if not has_l2:
        detail_parts.append("missing L2 Engine Layer")
    return {
        "name": "lockstep_architecture",
        "passed": passed,
        "detail": "; ".join(detail_parts) if detail_parts else "L1 + L2 architecture documented",
    }


def check_ci_integration() -> dict:
    """Verify CI integration requirements are documented."""
    policy = _read(POLICY_PATH)
    keywords = ["every", "push", "gate", "block", "merge"]
    missing = [k for k in keywords if k.lower() not in policy.lower()]
    passed = len(missing) == 0
    return {
        "name": "ci_integration",
        "passed": passed,
        "detail": f"missing keywords: {missing}" if missing else "CI integration documented",
    }


def check_corpus_requirements() -> dict:
    """Verify corpus management requirements (>= 1000, version-controlled, community)."""
    policy = _read(POLICY_PATH)
    spec = _read(SPEC_PATH)
    combined = policy + spec
    has_min_size = "1000" in combined
    has_version_control = "version-controlled" in combined.lower() or "version control" in combined.lower()
    has_community = "community" in combined.lower() or "pull request" in combined.lower()
    issues = []
    if not has_min_size:
        issues.append("missing 1000 minimum corpus size")
    if not has_version_control:
        issues.append("missing version-control requirement")
    if not has_community:
        issues.append("missing community contribution workflow")
    return {
        "name": "corpus_requirements",
        "passed": len(issues) == 0,
        "detail": "; ".join(issues) if issues else "corpus requirements met",
    }


def check_divergence_classification() -> dict:
    """Verify three-tier divergence classification is documented."""
    policy = _read(POLICY_PATH)
    classes = ["harmless", "acceptable", "blocking"]
    missing = [c for c in classes if c.lower() not in policy.lower()]
    return {
        "name": "divergence_classification",
        "passed": len(missing) == 0,
        "detail": f"missing classes: {missing}" if missing else "all divergence classes documented",
    }


def check_event_codes() -> dict:
    """Verify all CLV event codes are defined in the spec."""
    spec = _read(SPEC_PATH)
    missing = [code for code in EVENT_CODES if code not in spec]
    return {
        "name": "event_codes",
        "passed": len(missing) == 0,
        "detail": f"missing: {missing}" if missing else "all event codes defined",
    }


def check_invariants() -> dict:
    """Verify all INV-CLV invariants are defined in the spec."""
    spec = _read(SPEC_PATH)
    missing = [inv for inv in INVARIANTS if inv not in spec]
    return {
        "name": "invariants",
        "passed": len(missing) == 0,
        "detail": f"missing: {missing}" if missing else "all invariants defined",
    }


def check_targets() -> dict:
    """Verify quantitative targets are specified."""
    spec = _read(SPEC_PATH)
    targets = ["95%", "100 ms", "1000", "zero"]
    missing = [t for t in targets if t.lower() not in spec.lower()]
    return {
        "name": "targets",
        "passed": len(missing) == 0,
        "detail": f"missing targets: {missing}" if missing else "all quantitative targets present",
    }


def check_alerting_policy() -> dict:
    """Verify alerting on score drops is documented."""
    policy = _read(POLICY_PATH)
    has_alert = "alert" in policy.lower()
    has_score_drop = "score drop" in policy.lower() or "drop" in policy.lower()
    passed = has_alert and has_score_drop
    return {
        "name": "alerting_policy",
        "passed": passed,
        "detail": "alerting policy documented" if passed else "missing alerting on score drops",
    }


ALL_CHECKS = [
    check_files_exist,
    check_spec_completeness,
    check_lockstep_architecture,
    check_ci_integration,
    check_corpus_requirements,
    check_divergence_classification,
    check_event_codes,
    check_invariants,
    check_targets,
    check_alerting_policy,
]


def run_all() -> dict:
    """Run all policy/contract checks and return a consolidated result."""
    results = [fn() for fn in ALL_CHECKS]
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    return {
        "bead_id": BEAD_ID,
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": results,
    }


# ---------------------------------------------------------------------------
# Executable Lockstep Validation Engine (bd-2djfa)
# ---------------------------------------------------------------------------


class LockstepEventLogger:
    """Structured JSONL lifecycle event recorder for continuous lockstep runs."""

    def __init__(self, trace_id: str, jsonl_path: Path | None = None) -> None:
        self.trace_id = trace_id
        self.jsonl_path = jsonl_path
        self.events: list[dict] = []

    def emit(
        self,
        event: str,
        *,
        case_id: str | None = None,
        runtime: str | None = None,
        family: str | None = None,
        divergence_class: str | None = None,
        artifact_path: str | None = None,
        details: dict | None = None,
    ) -> dict:
        if event not in LIFECYCLE_EVENTS:
            raise ValueError(f"unknown lockstep lifecycle event: {event}")
        record = {
            "event": event,
            "timestamp_utc": _iso_utc(),
            "trace_id": self.trace_id,
            "case_id": case_id,
            "runtime": runtime,
            "family": family,
            "class": divergence_class,
            "artifact_path": artifact_path,
            "details": details or {},
        }
        self.events.append(record)
        return record

    def flush(self) -> None:
        if self.jsonl_path is None:
            return
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with self.jsonl_path.open("w", encoding="utf-8") as fh:
            for record in self.events:
                fh.write(json.dumps(record, sort_keys=True) + "\n")


def compute_corpus_result_digest(per_test_results: list[dict]) -> str:
    """Recompute Rust `compute_compatibility_corpus_result_digest` byte-for-byte."""
    rows: list[list[str]] = []
    for row in per_test_results:
        rows.append(
            [
                str(row.get("test_id") or ""),
                str(row.get("api_family") or ""),
                str(row.get("band") or ""),
                str(row.get("risk_band") or ""),
                str(row.get("status") or ""),
            ]
        )
    rows.sort()
    hasher = hashlib.sha256()
    hasher.update(CCG_RESULT_DIGEST_DOMAIN)
    for row in rows:
        for field in row:
            hasher.update(field.encode("utf-8"))
            hasher.update(b"\x1f")
        hasher.update(b"\x1e")
    return f"sha256:{hasher.hexdigest()}"


def _normalize_text_for_harmless(text: str) -> str:
    cleaned = _ANSI_ESCAPE_RE.sub("", text)
    cleaned = cleaned.replace("\r\n", "\n")
    cleaned = _TEMP_PATH_RE.sub("<TMP>", cleaned)
    cleaned = _ISO_TS_RE.sub("<TS>", cleaned)
    return "\n".join(line.rstrip() for line in cleaned.splitlines()).strip()


def _finite_nonnegative(value: object, field: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{field} must be a finite nonnegative number")
    try:
        number = float(value)
    except OverflowError as err:
        raise ValueError(f"{field} is outside the supported numeric range") from err
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be a finite nonnegative number")
    return number


def _normalize_fs_entry(entry: object) -> dict | None:
    if entry is None:
        return None
    if not isinstance(entry, dict) or entry.get("kind") not in ("file", "directory", "symlink"):
        raise ValueError("filesystem changes require typed entry fingerprints")
    mode = entry.get("mode")
    if type(mode) is not int or not 0 <= mode <= 0o7777:
        raise ValueError("filesystem entry mode is invalid")
    fields = {"kind", "mode"}
    if entry["kind"] == "file":
        fields.update(("sha256", "size_bytes"))
        if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("filesystem file fingerprint is missing its SHA-256")
        if type(entry.get("size_bytes")) is not int or entry["size_bytes"] < 0:
            raise ValueError("filesystem file size is invalid")
    elif entry["kind"] == "symlink":
        fields.add("target")
        if not isinstance(entry.get("target"), str):
            raise ValueError("filesystem symlink fingerprint is missing its target")
    if set(entry) != fields:
        raise ValueError("filesystem entry fingerprint has unexpected or missing fields")
    return {key: entry[key] for key in sorted(fields)}


def _normalize_side_effects(raw: object) -> dict:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("side_effects must be an object")
    result = {}
    for key in ("fs_created", "fs_modified", "fs_deleted", "network_targets"):
        values = raw.get(key, [])
        if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
            raise ValueError(f"{key} must contain nonempty paths or targets")
        if len(set(values)) != len(values):
            raise ValueError(f"{key} contains duplicate observations")
        result[key] = sorted(values)
    changes = raw.get("filesystem_changes", [])
    if not isinstance(changes, list):
        raise ValueError("filesystem_changes must be a list")
    by_path = {}
    classified = {key: [] for key in ("fs_created", "fs_modified", "fs_deleted")}
    for change in changes:
        if not isinstance(change, dict) or set(change) != {"path", "before", "after"}:
            raise ValueError("filesystem changes require path, before and after fingerprints")
        path = change["path"]
        if not isinstance(path, str) or not path or path in by_path:
            raise ValueError("filesystem change paths must be nonempty and unique")
        before = _normalize_fs_entry(change["before"])
        after = _normalize_fs_entry(change["after"])
        if before == after:
            raise ValueError("filesystem change has identical before and after entries")
        key = "fs_created" if before is None else "fs_deleted" if after is None else "fs_modified"
        classified[key].append(path)
        by_path[path] = {"path": path, "before": before, "after": after}
    if any(sorted(paths) != result[key] for key, paths in classified.items()):
        raise ValueError("filesystem side-effect mismatch: path lists lack matching content fingerprints")
    result["filesystem_changes"] = [by_path[path] for path in sorted(by_path)]
    network_scope = raw.get("network_observation", "not_observed")
    if network_scope not in ("not_observed", "observed") or (network_scope == "not_observed" and result["network_targets"]):
        raise ValueError("network observation scope contradicts its targets")
    result["network_observation"] = network_scope
    return result


def normalize_runtime_result(raw: dict) -> dict:
    """Validate a result before canonicalizing it; defaults never hide missing exits."""
    if not isinstance(raw, dict):
        raise ValueError("runtime observation must be an object")
    if not isinstance(raw.get("stdout"), str) or not isinstance(raw.get("stderr"), str):
        raise ValueError("runtime stdout and stderr must be complete strings")
    stdout = raw["stdout"].replace("\r\n", "\n")
    stderr = raw["stderr"].replace("\r\n", "\n")
    exit_code = raw.get("exit_code")
    if type(exit_code) is not int:
        raise ValueError("runtime observation requires an integer exit_code")
    elapsed_ms = _finite_nonnegative(raw.get("elapsed_ms"), "elapsed_ms")
    timed_out = raw.get("timed_out", False)
    if type(timed_out) is not bool:
        raise ValueError("timed_out must be a boolean")
    execution_error = raw.get("execution_error")
    if execution_error is not None and (not isinstance(execution_error, str) or not execution_error.strip()):
        raise ValueError("execution_error must be a nonempty string or null")
    side_effects = _normalize_side_effects(raw.get("side_effects"))
    return {
        "stdout": stdout,
        "stderr": stderr,
        "stdout_harmless": _normalize_text_for_harmless(stdout),
        "stderr_harmless": _normalize_text_for_harmless(stderr),
        "stdout_sha256": f"sha256:{hashlib.sha256(stdout.encode('utf-8')).hexdigest()}",
        "stderr_sha256": f"sha256:{hashlib.sha256(stderr.encode('utf-8')).hexdigest()}",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "execution_error": execution_error,
        "elapsed_ms": round(elapsed_ms, 3),
        "side_effects": side_effects,
    }


def compute_divergence_sha256(
    case_id: str,
    family: str,
    normalized_by_runtime: dict[str, dict],
) -> str:
    """Deterministic digest binding a divergence receipt to the exact observed mismatch."""
    canonical_view = {
        "case_id": case_id,
        "family": family,
        "runtimes": {
            rt: {
                "exit_code": obs["exit_code"],
                "timed_out": obs["timed_out"],
                "execution_error": obs["execution_error"],
                "stdout_sha256": obs["stdout_sha256"],
                "stderr_sha256": obs["stderr_sha256"],
                "side_effects": obs["side_effects"],
            }
            for rt, obs in sorted(normalized_by_runtime.items())
        },
    }
    payload = json.dumps(canonical_view, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(b'clv_divergence_v2:' + payload).hexdigest()}"


def verify_divergence_receipt(
    receipt: dict | None,
    *,
    case_id: str,
    family: str,
    divergence_sha256: str,
    now_utc: datetime | None = None,
    require_timing_waiver: bool = False,
) -> tuple[bool, str]:
    """Validate an acceptable-divergence receipt fail-closed."""
    if not isinstance(receipt, dict):
        return False, "missing divergence receipt"
    for field in ("receipt_id", "case_id", "family", "divergence_sha256", "approver", "reason", "expires_at_utc"):
        val = receipt.get(field)
        if not isinstance(val, str) or not val.strip():
            return False, f"receipt missing required field `{field}`"
    if receipt["case_id"] != case_id:
        return False, f"receipt case_id `{receipt['case_id']}` != `{case_id}`"
    if receipt["family"] != family:
        return False, f"receipt family `{receipt['family']}` != `{family}`"
    if receipt["divergence_sha256"] != divergence_sha256:
        return False, "receipt divergence_sha256 does not match observed divergence"
    expires_at = _parse_iso_utc(receipt["expires_at_utc"])
    if expires_at is None:
        return False, "receipt expires_at_utc is not valid RFC 3339"
    check_now = now_utc or _utc_now()
    if expires_at <= check_now:
        return False, f"receipt expired at {receipt['expires_at_utc']}"
    if require_timing_waiver and receipt.get("allows_timing_anomaly") is not True:
        return False, "receipt does not authorize timing anomaly waiver"
    return True, f"verified receipt {receipt['receipt_id']} by {receipt['approver']}"


def classify_lockstep_case(
    case_id: str,
    family: str,
    observations_by_runtime: dict[str, dict],
    *,
    reference_runtime: str = "node",
    product_runtime: str = "franken-node",
    required_runtimes: tuple[str, ...] | None = None,
    receipts_by_case: dict[str, dict] | None = None,
    timing_budget_ms: float = DEFAULT_TIMING_BUDGET_MS,
    now_utc: datetime | None = None,
) -> dict:
    """Compare every configured role; incomplete executions cannot be waived."""
    normalized = {}
    invalid = []
    required = set(observations_by_runtime if required_runtimes is None else required_runtimes)
    required.update((reference_runtime, product_runtime))
    if reference_runtime == product_runtime:
        invalid.append("reference and product runtime roles must be distinct")
    missing = required.difference(observations_by_runtime)
    unexpected = set(observations_by_runtime).difference(required)
    if missing:
        invalid.append(f"missing required runtime observation(s): {sorted(missing)}")
    if unexpected:
        invalid.append(f"unexpected runtime observation(s): {sorted(unexpected)}")
    try:
        timing_budget_ms = _finite_nonnegative(timing_budget_ms, "timing_budget_ms")
    except ValueError as err:
        invalid.append(str(err))
    for runtime, observation in observations_by_runtime.items():
        try:
            normalized[runtime] = normalize_runtime_result(observation)
        except (TypeError, ValueError, OverflowError) as err:
            invalid.append(f"{runtime}: invalid observation: {err}")
            continue
        result = normalized[runtime]
        if result["timed_out"] or not 0 <= result["exit_code"] <= 0xFFFFFFFF or result["execution_error"]:
            invalid.append(
                f"{runtime}: incomplete execution (exit_code={result['exit_code']}, "
                f"timed_out={result['timed_out']}, execution_error={result['execution_error']!r})"
            )
    if invalid:
        return {
            "case_id": case_id,
            "family": family,
            "class": "blocking",
            "passed": False,
            "reason": "; ".join(invalid),
            "timing_anomaly": False,
            "timing_delta_ms": None,
            "divergence_sha256": compute_divergence_sha256(case_id, family, normalized) if normalized else None,
            "receipt_verified": False,
            "receipt_detail": "invalid or incomplete execution evidence cannot be waived",
            "observations": normalized,
        }

    ref = normalized[reference_runtime]
    compared = {runtime: obs for runtime, obs in normalized.items() if runtime != reference_runtime}
    timing_delta_ms = round(max(obs["elapsed_ms"] - ref["elapsed_ms"] for obs in compared.values()), 3)
    timing_anomaly = timing_delta_ms > timing_budget_ms
    exact_match = all(
        obs["exit_code"] == ref["exit_code"]
        and obs["stdout"] == ref["stdout"]
        and obs["stderr"] == ref["stderr"]
        and obs["side_effects"] == ref["side_effects"]
        for obs in compared.values()
    )
    harmless_match = all(
        obs["exit_code"] == ref["exit_code"]
        and obs["side_effects"] == ref["side_effects"]
        and obs["stdout_harmless"] == ref["stdout_harmless"]
        and obs["stderr_harmless"] == ref["stderr_harmless"]
        for obs in compared.values()
    )
    div_sha = compute_divergence_sha256(case_id, family, normalized)
    receipt = (receipts_by_case or {}).get(case_id)

    if exact_match and not timing_anomaly:
        return {
            "case_id": case_id,
            "family": family,
            "class": "agree",
            "passed": True,
            "reason": "all configured runtimes match within timing budget",
            "timing_anomaly": False,
            "timing_delta_ms": timing_delta_ms,
            "divergence_sha256": div_sha,
            "receipt_verified": False,
            "receipt_detail": "not required",
            "observations": normalized,
        }

    if harmless_match and not timing_anomaly:
        return {
            "case_id": case_id,
            "family": family,
            "class": "harmless",
            "passed": True,
            "reason": "non-semantic formatting/path/timestamp difference only",
            "timing_anomaly": False,
            "timing_delta_ms": timing_delta_ms,
            "divergence_sha256": div_sha,
            "receipt_verified": False,
            "receipt_detail": "not required",
            "observations": normalized,
        }

    receipt_ok, receipt_detail = verify_divergence_receipt(
        receipt,
        case_id=case_id,
        family=family,
        divergence_sha256=div_sha,
        now_utc=now_utc,
        require_timing_waiver=timing_anomaly,
    )
    if receipt_ok:
        return {
            "case_id": case_id,
            "family": family,
            "class": "acceptable",
            "passed": True,
            "reason": f"acceptable divergence covered by receipt: {receipt_detail}",
            "timing_anomaly": timing_anomaly,
            "timing_delta_ms": timing_delta_ms,
            "divergence_sha256": div_sha,
            "receipt_verified": True,
            "receipt_detail": receipt_detail,
            "observations": normalized,
        }

    reasons = []
    for runtime, obs in compared.items():
        if obs["exit_code"] != ref["exit_code"]:
            reasons.append(f"{runtime}: exit_code mismatch ({obs['exit_code']} vs {reference_runtime}={ref['exit_code']})")
        if obs["stdout_harmless"] != ref["stdout_harmless"]:
            reasons.append(f"{runtime}: stdout semantic mismatch")
        if obs["stderr_harmless"] != ref["stderr_harmless"]:
            reasons.append(f"{runtime}: stderr semantic mismatch")
        if obs["side_effects"] != ref["side_effects"]:
            reasons.append(f"{runtime}: filesystem/network side-effect mismatch")
    if timing_anomaly:
        reasons.append(f"timing anomaly +{timing_delta_ms:.1f}ms > {timing_budget_ms:.1f}ms budget")
    reasons.append(receipt_detail)
    return {
        "case_id": case_id,
        "family": family,
        "class": "blocking",
        "passed": False,
        "reason": "; ".join(reasons),
        "timing_anomaly": timing_anomaly,
        "timing_delta_ms": timing_delta_ms,
        "divergence_sha256": div_sha,
        "receipt_verified": False,
        "receipt_detail": receipt_detail,
        "observations": normalized,
    }


def compare_against_baseline(
    current_overall_pct: float,
    current_families: dict[str, float],
    baseline: dict | None,
) -> list[str]:
    """Return regression error messages when current pass rates drop below baseline."""
    if not isinstance(baseline, dict):
        return []
    regressions: list[str] = []
    base_overall = baseline.get("overall_pass_rate_pct")
    if base_overall is None and isinstance(baseline.get("totals"), dict):
        base_overall = baseline["totals"].get("overall_pass_rate_pct")
    if isinstance(base_overall, (int, float)) and current_overall_pct + 1e-9 < float(base_overall):
        regressions.append(
            f"overall pass rate regressed: {current_overall_pct:.2f}% < baseline {float(base_overall):.2f}%"
        )

    base_families: dict[str, float] = {}
    if isinstance(baseline.get("per_family_scores"), dict):
        for fam, info in baseline["per_family_scores"].items():
            if isinstance(info, dict) and isinstance(info.get("pass_rate_pct"), (int, float)):
                base_families[str(fam)] = float(info["pass_rate_pct"])
            elif isinstance(info, (int, float)):
                base_families[str(fam)] = float(info)
    elif isinstance(baseline.get("api_families"), list):
        for row in baseline["api_families"]:
            if isinstance(row, dict) and row.get("family") and isinstance(row.get("pass_rate_pct"), (int, float)):
                base_families[str(row["family"])] = float(row["pass_rate_pct"])

    for fam, base_pct in sorted(base_families.items()):
        cur_pct = current_families.get(fam)
        if cur_pct is None:
            regressions.append(f"family `{fam}` missing from current run (was {base_pct:.2f}%)")
        elif cur_pct + 1e-9 < base_pct:
            regressions.append(f"family `{fam}` regressed: {cur_pct:.2f}% < baseline {base_pct:.2f}%")
    return regressions


def evaluate_corpus_artifact(
    corpus_path: Path = DEFAULT_CORPUS_RESULTS_PATH,
    *,
    baseline_path: Path | None = None,
    receipts_path: Path | None = None,
    min_corpus_cases: int = DEFAULT_MIN_CORPUS_CASES,
    overall_min_pct: float = DEFAULT_OVERALL_MIN_PCT,
    family_min_pct: float = DEFAULT_FAMILY_FLOOR_PCT,
    band_floors: dict[str, float] | None = None,
    timing_budget_ms: float = DEFAULT_TIMING_BUDGET_MS,
    jsonl_log_path: Path | None = None,
    output_artifact_path: Path | None = None,
    trace_id: str | None = None,
    now_utc: datetime | None = None,
) -> dict:
    """Evaluate a real compatibility_corpus_results.json artifact fail-closed."""
    tid = trace_id or f"clv-{uuid.uuid4().hex[:12]}"
    logger = LockstepEventLogger(tid, jsonl_log_path)
    band_thresholds = dict(band_floors or DEFAULT_BAND_FLOORS)
    blocking_reasons: list[str] = []

    logger.emit(
        "lockstep_run_started",
        artifact_path=str(corpus_path),
        details={"mode": "corpus_artifact", "min_corpus_cases": min_corpus_cases},
    )

    if not corpus_path.is_file():
        blocking_reasons.append(f"missing corpus results artifact: {corpus_path}")
        report = _finalize_gate_report(
            tid,
            mode="corpus_artifact",
            passed=False,
            blocking_reasons=blocking_reasons,
            logger=logger,
            output_artifact_path=output_artifact_path,
        )
        return report

    try:
        data = json.loads(corpus_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        blocking_reasons.append(f"malformed corpus results JSON: {err}")
        return _finalize_gate_report(
            tid,
            mode="corpus_artifact",
            passed=False,
            blocking_reasons=blocking_reasons,
            logger=logger,
            output_artifact_path=output_artifact_path,
        )

    corpus_meta = data.get("corpus") or {}
    provenance = corpus_meta.get("provenance")
    if provenance != "lockstep-oracle-run":
        blocking_reasons.append(f"untrusted corpus provenance: {provenance!r} (expected 'lockstep-oracle-run')")

    ref_runtimes = [r.get("runtime_id") for r in (corpus_meta.get("reference_runtimes") or []) if isinstance(r, dict)]
    product_rt = (corpus_meta.get("product_runtime") or {}).get("runtime_id")
    if "node" not in ref_runtimes or "bun" not in ref_runtimes or not product_rt:
        blocking_reasons.append(
            f"corpus topology must include node, bun, and product runtime (got refs={ref_runtimes}, product={product_rt!r})"
        )

    per_test = data.get("per_test_results")
    if not isinstance(per_test, list) or not per_test:
        blocking_reasons.append("corpus artifact has no per_test_results")
        per_test = []

    if len(per_test) < min_corpus_cases:
        blocking_reasons.append(f"undersized corpus: {len(per_test)} cases < required minimum {min_corpus_cases}")

    claimed_digest = corpus_meta.get("result_digest")
    recomputed_digest = compute_corpus_result_digest(per_test) if per_test else None
    if not claimed_digest or claimed_digest != recomputed_digest:
        blocking_reasons.append(
            f"result_digest integrity mismatch (claimed={claimed_digest!r}, recomputed={recomputed_digest!r})"
        )

    receipts_by_case: dict[str, dict] = {}
    if receipts_path is not None:
        if not receipts_path.is_file():
            blocking_reasons.append(f"missing divergence receipts file: {receipts_path}")
        else:
            try:
                loaded = json.loads(receipts_path.read_text(encoding="utf-8"))
                for item in loaded.get("receipts", loaded) if isinstance(loaded, dict) else loaded:
                    if isinstance(item, dict) and item.get("case_id"):
                        receipts_by_case[str(item["case_id"])] = item
            except (OSError, json.JSONDecodeError, TypeError) as err:
                blocking_reasons.append(f"malformed divergence receipts JSON: {err}")

    family_totals: dict[str, dict[str, int]] = {}
    band_totals: dict[str, dict[str, int]] = {}
    timing_anomalies: list[dict] = []
    unreceipted_failures: list[str] = []
    receipted_failures: list[str] = []
    passed_count = 0

    for row in per_test:
        case_id = str(row.get("test_id") or "")
        family = str(row.get("api_family") or "unknown")
        band = str(row.get("band") or "unknown")
        status = str(row.get("status") or "fail")
        fam_entry = family_totals.setdefault(family, {"total": 0, "passed": 0})
        fam_entry["total"] += 1
        band_entry = band_totals.setdefault(band, {"total": 0, "passed": 0})
        band_entry["total"] += 1

        obs = row.get("runtime_observations") or {}
        node_obs = obs.get("node") or {}
        prod_obs = obs.get(product_rt) or obs.get("franken-engine-native") or {}
        node_ms = node_obs.get("elapsed_ms")
        prod_ms = prod_obs.get("elapsed_ms")
        if isinstance(node_ms, (int, float)) and isinstance(prod_ms, (int, float)):
            delta_ms = round(float(prod_ms) - float(node_ms), 3)
            if delta_ms > timing_budget_ms:
                timing_anomalies.append(
                    {
                        "case_id": case_id,
                        "family": family,
                        "node_ms": float(node_ms),
                        "product_ms": float(prod_ms),
                        "delta_ms": delta_ms,
                    }
                )

        if status == "pass":
            passed_count += 1
            fam_entry["passed"] += 1
            band_entry["passed"] += 1
        else:
            receipt = receipts_by_case.get(case_id)
            row_div_sha = f"sha256:{hashlib.sha256(f'{case_id}:{family}:{status}'.encode('utf-8')).hexdigest()}"
            ok_rec, rec_detail = verify_divergence_receipt(
                receipt,
                case_id=case_id,
                family=family,
                divergence_sha256=receipt.get("divergence_sha256", row_div_sha) if isinstance(receipt, dict) else row_div_sha,
                now_utc=now_utc,
            )
            if ok_rec and isinstance(receipt, dict) and receipt.get("divergence_sha256") == row_div_sha:
                receipted_failures.append(case_id)
                logger.emit(
                    "receipt_verified",
                    case_id=case_id,
                    family=family,
                    divergence_class="acceptable",
                    details={"detail": rec_detail},
                )
            else:
                unreceipted_failures.append(case_id)

    total_cases = len(per_test)
    overall_pct = round((passed_count / total_cases) * 100.0, 2) if total_cases else 0.0
    per_family_scores = {
        fam: {
            "total": counts["total"],
            "passed": counts["passed"],
            "pass_rate_pct": round((counts["passed"] / counts["total"]) * 100.0, 2) if counts["total"] else 0.0,
        }
        for fam, counts in sorted(family_totals.items())
    }
    per_band_scores = {
        band: {
            "total": counts["total"],
            "passed": counts["passed"],
            "pass_rate_pct": round((counts["passed"] / counts["total"]) * 100.0, 2) if counts["total"] else 0.0,
        }
        for band, counts in sorted(band_totals.items())
    }

    if overall_pct < overall_min_pct:
        blocking_reasons.append(f"overall pass rate {overall_pct:.2f}% < required {overall_min_pct:.2f}%")
    for fam, info in per_family_scores.items():
        if info["pass_rate_pct"] < family_min_pct:
            blocking_reasons.append(f"family `{fam}` pass rate {info['pass_rate_pct']:.2f}% < floor {family_min_pct:.2f}%")
    for band, floor in sorted(band_thresholds.items()):
        band_info = per_band_scores.get(band)
        if band_info is None:
            blocking_reasons.append(f"required band `{band}` missing from corpus")
        elif band_info["pass_rate_pct"] < floor:
            blocking_reasons.append(f"band `{band}` pass rate {band_info['pass_rate_pct']:.2f}% < floor {floor:.2f}%")

    if baseline_path is not None:
        if not baseline_path.is_file():
            blocking_reasons.append(f"missing baseline artifact: {baseline_path}")
        else:
            try:
                baseline_doc = json.loads(baseline_path.read_text(encoding="utf-8"))
                blocking_reasons.extend(
                    compare_against_baseline(
                        overall_pct,
                        {f: v["pass_rate_pct"] for f, v in per_family_scores.items()},
                        baseline_doc,
                    )
                )
            except (OSError, json.JSONDecodeError) as err:
                blocking_reasons.append(f"malformed baseline JSON: {err}")

    threshold_met = len(blocking_reasons) == 0
    logger.emit(
        "threshold_evaluated",
        artifact_path=str(corpus_path),
        details={
            "overall_pass_rate_pct": overall_pct,
            "total_cases": total_cases,
            "policy_target_cases": POLICY_TARGET_CORPUS_CASES,
            "timing_anomaly_count": len(timing_anomalies),
            "unreceipted_failures": len(unreceipted_failures),
            "threshold_met": threshold_met,
        },
    )

    return _finalize_gate_report(
        tid,
        mode="corpus_artifact",
        passed=threshold_met,
        blocking_reasons=blocking_reasons,
        logger=logger,
        output_artifact_path=output_artifact_path,
        extra={
            "corpus_path": str(corpus_path),
            "result_digest": recomputed_digest,
            "total_cases": total_cases,
            "passed_cases": passed_count,
            "overall_pass_rate_pct": overall_pct,
            "policy_target_cases": POLICY_TARGET_CORPUS_CASES,
            "policy_target_gap_cases": max(0, POLICY_TARGET_CORPUS_CASES - total_cases),
            "per_family_scores": per_family_scores,
            "per_band_scores": per_band_scores,
            "timing_budget_ms": timing_budget_ms,
            "timing_anomalies_count": len(timing_anomalies),
            "timing_anomalies_sample": timing_anomalies[:10],
            "unreceipted_failures": unreceipted_failures,
            "receipted_failures": receipted_failures,
            "baseline_reference": str(baseline_path) if baseline_path else None,
        },
    )


def _snapshot_directory(root: Path) -> dict[str, dict]:
    """Bounded, no-follow observation; a missing observation is never an empty one."""
    if os.scandir not in os.supports_fd or not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")):
        raise OSError("filesystem observation requires fd-relative no-follow support")
    deadline = time.monotonic() + SNAPSHOT_TIMEOUT_SECS
    total_bytes = 0
    total_entries = 1
    snap: dict[str, dict] = {}

    def check_budget() -> None:
        if time.monotonic() >= deadline:
            raise ValueError("filesystem observation deadline exceeded")

    def excluded(relative: str) -> bool:
        return relative == ".franken-node" or relative.startswith(".franken-node/") or relative == "franken_node.toml"

    def version(info: os.stat_result) -> tuple:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def visit(directory_fd: int, relative_directory: str, expected: os.stat_result, depth: int) -> None:
        nonlocal total_bytes, total_entries
        check_budget()
        if depth > MAX_SNAPSHOT_DEPTH:
            raise ValueError("filesystem observation depth limit exceeded")
        directory_before = os.fstat(directory_fd)
        if version(expected) != version(directory_before):
            raise ValueError("filesystem directory changed before observation")
        # Iterate lazily so a hostile directory cannot allocate an unbounded
        # list of names before the entry/deadline checks get a chance to run.
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                check_budget()
                if total_entries >= MAX_SNAPSHOT_ENTRIES:
                    raise ValueError("filesystem observation entry limit exceeded")
                total_entries += 1
                name = entry.name
                relative = name if relative_directory == "." else f"{relative_directory}/{name}"
                if excluded(relative):
                    continue
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                record = {"mode": stat.S_IMODE(info.st_mode)}
                if stat.S_ISREG(info.st_mode):
                    if info.st_size > MAX_SNAPSHOT_BYTES - total_bytes:
                        raise ValueError("filesystem observation byte limit exceeded")
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                    with os.fdopen(descriptor, "rb") as stream:
                        if version(info) != version(os.fstat(stream.fileno())):
                            raise ValueError("filesystem entry changed before observation")
                        digest = hashlib.sha256()
                        size = 0
                        while True:
                            check_budget()
                            chunk = stream.read(min(65536, MAX_SNAPSHOT_BYTES - total_bytes + 1))
                            if not chunk:
                                break
                            total_bytes += len(chunk)
                            size += len(chunk)
                            if total_bytes > MAX_SNAPSHOT_BYTES:
                                raise ValueError("filesystem observation byte limit exceeded")
                            digest.update(chunk)
                        if version(info) != version(os.fstat(stream.fileno())):
                            raise ValueError("filesystem entry changed during observation")
                    record.update(kind="file", sha256=digest.hexdigest(), size_bytes=size)
                elif stat.S_ISDIR(info.st_mode):
                    record["kind"] = "directory"
                    child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    try:
                        visit(child_fd, relative, info, depth + 1)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISLNK(info.st_mode):
                    record.update(kind="symlink", target=os.readlink(name, dir_fd=directory_fd))
                else:
                    raise ValueError(f"unsupported filesystem entry: {relative}")
                if version(info) != version(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)):
                    raise ValueError("filesystem entry changed during observation")
                snap[relative] = record
        if version(directory_before) != version(os.fstat(directory_fd)):
            raise ValueError("filesystem directory changed during observation")

    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_before = os.fstat(root_fd)
        snap["."] = {"kind": "directory", "mode": stat.S_IMODE(root_before.st_mode)}
        visit(root_fd, ".", root_before, 0)
    finally:
        os.close(root_fd)
    return snap


def _diff_directory_snapshots(before: dict[str, dict], after: dict[str, dict]) -> dict:
    created = sorted(k for k in after if k not in before)
    deleted = sorted(k for k in before if k not in after)
    modified = sorted(k for k in after if k in before and after[k] != before[k])
    return {
        "fs_created": created,
        "fs_modified": modified,
        "fs_deleted": deleted,
        "filesystem_changes": [
            {"path": path, "before": before.get(path), "after": after.get(path)}
            for path in sorted(set(created + deleted + modified))
        ],
        "network_targets": [],
        "network_observation": "not_observed",
    }


def _resolve_runtime_command(runtime: str, franken_node_bin: str | None = None) -> list[str] | None:
    if runtime == "node":
        exe = shutil.which("node")
        return [exe] if exe else None
    if runtime == "bun":
        exe = shutil.which("bun")
        return [exe, "run"] if exe else None
    if runtime == "franken-node":
        candidates = []
        if franken_node_bin:
            candidates.append(Path(franken_node_bin))
        candidates.extend(
            [
                ROOT / "target" / "release" / "franken-node",
                ROOT / "target" / "debug" / "franken-node",
            ]
        )
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return [str(cand), "run", "--policy", "legacy-risky", "--console-only"]
        exe = shutil.which("franken-node")
        return [exe, "run", "--policy", "legacy-risky", "--console-only"] if exe else None
    return None


def _execute_one_runtime_fixture(
    runtime: str,
    cmd_prefix: list[str],
    source_code: str,
    *,
    timeout_secs: float = 15.0,
) -> dict:
    # Keep isolated runtime-evidence state outside `workdir` so hermetic live
    # lockstep fixtures never fail against a full ~/.local/state/franken-node
    # or leak retained sessions into the host user's state home.
    with (
        tempfile.TemporaryDirectory(prefix=f"clv-{runtime}-") as tmp,
        tempfile.TemporaryDirectory(prefix=f"clv-state-{runtime}-") as state_tmp,
    ):
        workdir = Path(tmp)
        script_path = workdir / "case.js"
        script_path.write_text(source_code, encoding="utf-8")
        if runtime == "franken-node":
            (workdir / "franken_node.toml").write_text(
                'profile = "legacy-risky"\n\n'
                '[trust]\nregistry_signing_key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="\n\n'
                '[security]\nauthorized_api_keys = ["clv-live-key"]\n',
                encoding="utf-8",
            )
        run_env = os.environ.copy()
        run_env.pop("FORCE_COLOR", None)
        run_env["NO_COLOR"] = "1"
        run_env["XDG_STATE_HOME"] = state_tmp
        run_env["LOCALAPPDATA"] = state_tmp
        started = None
        timed_out = False
        stdout = stderr = ""
        exit_code = -1
        execution_error = None
        before = None
        try:
            if _finite_nonnegative(timeout_secs, "timeout_secs") == 0:
                raise ValueError("timeout_secs must be positive")
            before = _snapshot_directory(workdir)
            started = time.perf_counter()
            proc = subprocess.run(
                [*cmd_prefix, "case.js"],
                cwd=workdir,
                env=run_env,
                capture_output=True,
                text=True,
                timeout=timeout_secs,
                check=False,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as err:
            timed_out = True
            stdout = (err.stdout or "") if isinstance(err.stdout, str) else (err.stdout or b"").decode("utf-8", "replace")
            stderr = (err.stderr or "") if isinstance(err.stderr, str) else (err.stderr or b"").decode("utf-8", "replace")
            exit_code = 124
        except (OSError, ValueError, UnicodeError) as err:
            execution_error = f"runtime observation failed: {type(err).__name__}: {err}"
        elapsed_ms = (time.perf_counter() - started) * 1000.0 if started is not None else 0.0
        side_effects = {}
        if before is not None:
            try:
                side_effects = _diff_directory_snapshots(before, _snapshot_directory(workdir))
            except (OSError, ValueError) as err:
                detail = f"filesystem observation failed: {type(err).__name__}: {err}"
                execution_error = f"{execution_error}; {detail}" if execution_error else detail
        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "execution_error": execution_error,
            "elapsed_ms": round(elapsed_ms, 3),
            "side_effects": side_effects,
        }


def run_live_lockstep_fixtures(
    fixtures: list[dict],
    *,
    runtime_commands: dict[str, list[str] | None],
    reference_runtime: str = "node",
    product_runtime: str = "franken-node",
    receipts_by_case: dict[str, dict] | None = None,
    timing_budget_ms: float = DEFAULT_TIMING_BUDGET_MS,
    overall_min_pct: float = DEFAULT_OVERALL_MIN_PCT,
    family_min_pct: float = DEFAULT_FAMILY_FLOOR_PCT,
    baseline_report: dict | None = None,
    jsonl_log_path: Path | None = None,
    output_artifact_path: Path | None = None,
    trace_id: str | None = None,
    now_utc: datetime | None = None,
) -> dict:
    """Execute real runtime processes across lockstep fixtures and evaluate the gate fail-closed."""
    tid = trace_id or f"clv-live-{uuid.uuid4().hex[:12]}"
    logger = LockstepEventLogger(tid, jsonl_log_path)
    blocking_reasons: list[str] = []

    logger.emit(
        "lockstep_run_started",
        artifact_path=str(output_artifact_path) if output_artifact_path else None,
        details={"mode": "live_fixtures", "runtimes": sorted(runtime_commands.keys()), "fixture_count": len(fixtures)},
    )

    # Pair mode is explicit and supported, but every configured role must be
    # present and compared. The default CLI population remains Node/Bun/native.
    if reference_runtime == product_runtime:
        blocking_reasons.append("reference and product runtime roles must be distinct")
    missing_roles = {reference_runtime, product_runtime}.difference(runtime_commands)
    if missing_roles:
        blocking_reasons.append(f"missing required runtime role(s): {sorted(missing_roles)}")
    for field, value in (
        ("timing_budget_ms", timing_budget_ms),
        ("overall_min_pct", overall_min_pct),
        ("family_min_pct", family_min_pct),
    ):
        try:
            checked = _finite_nonnegative(value, field)
            if field.endswith("_pct") and checked > 100:
                raise ValueError(f"{field} must not exceed 100")
        except ValueError as err:
            blocking_reasons.append(str(err))
    # Fail-closed missing-runtime check
    missing_runtimes = [
        rt
        for rt, cmd in runtime_commands.items()
        if not cmd or not Path(cmd[0]).is_file() or not os.access(cmd[0], os.X_OK)
    ]
    if missing_runtimes:
        blocking_reasons.append(f"missing required runtime executable(s): {sorted(missing_runtimes)}")
    if blocking_reasons:
        return _finalize_gate_report(
            tid,
            mode="live_fixtures",
            passed=False,
            blocking_reasons=blocking_reasons,
            logger=logger,
            output_artifact_path=output_artifact_path,
        )

    if not fixtures:
        blocking_reasons.append("fixture suite is empty")
        return _finalize_gate_report(
            tid,
            mode="live_fixtures",
            passed=False,
            blocking_reasons=blocking_reasons,
            logger=logger,
            output_artifact_path=output_artifact_path,
        )

    case_results: list[dict] = []
    family_counts: dict[str, dict[str, int]] = {}
    timing_anomalies: list[dict] = []
    blocking_cases: list[str] = []

    for fixture in fixtures:
        case_id = str(fixture["case_id"])
        family = str(fixture.get("family", "core"))
        source_code = str(fixture["source"])
        observations: dict[str, dict] = {}
        for rt, cmd_prefix in runtime_commands.items():
            assert cmd_prefix is not None
            logger.emit("runtime_invoked", case_id=case_id, runtime=rt, family=family)
            observations[rt] = _execute_one_runtime_fixture(rt, cmd_prefix, source_code)

        classified = classify_lockstep_case(
            case_id,
            family,
            observations,
            reference_runtime=reference_runtime,
            product_runtime=product_runtime,
            required_runtimes=tuple(runtime_commands),
            receipts_by_case=receipts_by_case,
            timing_budget_ms=timing_budget_ms,
            now_utc=now_utc,
        )
        case_results.append(classified)
        fam = family_counts.setdefault(family, {"total": 0, "passed": 0})
        fam["total"] += 1
        if classified["passed"]:
            fam["passed"] += 1
        if classified["timing_anomaly"]:
            timing_anomalies.append(
                {
                    "case_id": case_id,
                    "family": family,
                    "timing_delta_ms": classified["timing_delta_ms"],
                    "class": classified["class"],
                }
            )
        if classified["class"] == "blocking":
            blocking_cases.append(case_id)

        logger.emit(
            "case_completed",
            case_id=case_id,
            runtime=product_runtime,
            family=family,
            divergence_class=classified["class"],
            details={"passed": classified["passed"], "timing_delta_ms": classified["timing_delta_ms"]},
        )
        logger.emit(
            "divergence_classified",
            case_id=case_id,
            runtime=product_runtime,
            family=family,
            divergence_class=classified["class"],
            details={"reason": classified["reason"], "divergence_sha256": classified["divergence_sha256"]},
        )
        if (receipts_by_case or {}).get(case_id) is not None or classified["receipt_verified"]:
            logger.emit(
                "receipt_verified",
                case_id=case_id,
                runtime=product_runtime,
                family=family,
                divergence_class=classified["class"],
                details={"verified": classified["receipt_verified"], "detail": classified["receipt_detail"]},
            )

    passed_total = sum(1 for c in case_results if c["passed"])
    overall_pct = round((passed_total / len(case_results)) * 100.0, 2)
    per_family_scores = {
        fam: {
            "total": counts["total"],
            "passed": counts["passed"],
            "pass_rate_pct": round((counts["passed"] / counts["total"]) * 100.0, 2) if counts["total"] else 0.0,
        }
        for fam, counts in sorted(family_counts.items())
    }

    if blocking_cases:
        blocking_reasons.append(f"unreceipted blocking divergences: {blocking_cases}")
    if overall_pct < overall_min_pct:
        blocking_reasons.append(f"overall pass rate {overall_pct:.2f}% < required {overall_min_pct:.2f}%")
    for fam, info in per_family_scores.items():
        if info["pass_rate_pct"] < family_min_pct:
            blocking_reasons.append(f"family `{fam}` pass rate {info['pass_rate_pct']:.2f}% < floor {family_min_pct:.2f}%")
    blocking_reasons.extend(
        compare_against_baseline(
            overall_pct,
            {f: v["pass_rate_pct"] for f, v in per_family_scores.items()},
            baseline_report,
        )
    )

    threshold_met = len(blocking_reasons) == 0
    logger.emit(
        "threshold_evaluated",
        artifact_path=str(output_artifact_path) if output_artifact_path else None,
        details={
            "overall_pass_rate_pct": overall_pct,
            "blocking_count": len(blocking_cases),
            "timing_anomalies_count": len(timing_anomalies),
            "threshold_met": threshold_met,
        },
    )

    return _finalize_gate_report(
        tid,
        mode="live_fixtures",
        passed=threshold_met,
        blocking_reasons=blocking_reasons,
        logger=logger,
        output_artifact_path=output_artifact_path,
        extra={
            "runtimes": sorted(runtime_commands.keys()),
            "comparison_scope": "configured_runtime_set",
            "network_observation": "not_observed",
            "total_cases": len(case_results),
            "passed_cases": passed_total,
            "overall_pass_rate_pct": overall_pct,
            "per_family_scores": per_family_scores,
            "timing_budget_ms": timing_budget_ms,
            "timing_anomalies": timing_anomalies,
            "blocking_cases": blocking_cases,
            "cases": case_results,
        },
    )


def _finalize_gate_report(
    trace_id: str,
    *,
    mode: str,
    passed: bool,
    blocking_reasons: list[str],
    logger: LockstepEventLogger,
    output_artifact_path: Path | None,
    extra: dict | None = None,
) -> dict:
    report = {
        "schema_version": "franken-node/continuous-lockstep-validation/v2",
        "bead_id": REALITY_BEAD_ID,
        "policy_bead_id": BEAD_ID,
        "trace_id": trace_id,
        "mode": mode,
        "generated_at_utc": _iso_utc(),
        "passed": passed,
        "blocking_reasons": blocking_reasons,
        "artifact_path": str(output_artifact_path) if output_artifact_path else None,
        **(extra or {}),
    }
    if output_artifact_path is not None:
        output_artifact_path.parent.mkdir(parents=True, exist_ok=True)
        output_artifact_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        logger.emit(
            "artifact_written",
            artifact_path=str(output_artifact_path),
            details={"passed": passed},
        )
    logger.emit(
        "lockstep_run_completed",
        artifact_path=str(output_artifact_path) if output_artifact_path else None,
        details={"passed": passed, "blocking_reason_count": len(blocking_reasons)},
    )
    logger.flush()
    report["events"] = logger.events
    return report


def self_test() -> int:
    """Built-in self-test suite for both policy checks and executable lockstep engine."""

    class SelfTest(unittest.TestCase):
        def test_bead_id(self):
            self.assertEqual(BEAD_ID, "bd-1w78")

        def test_event_codes_count(self):
            self.assertEqual(len(EVENT_CODES), 4)

        def test_invariants_count(self):
            self.assertEqual(len(INVARIANTS), 4)

        def test_required_files_count(self):
            self.assertEqual(len(REQUIRED_FILES), 4)

        def test_all_checks_count(self):
            self.assertGreaterEqual(len(ALL_CHECKS), 8)

        def test_run_all_structure(self):
            result = run_all()
            self.assertIn("bead_id", result)
            self.assertIn("passed", result)
            self.assertIn("total", result)
            self.assertIn("all_passed", result)
            self.assertIn("checks", result)
            self.assertEqual(result["bead_id"], BEAD_ID)
            self.assertIsInstance(result["checks"], list)

        def test_each_check_returns_dict(self):
            for fn in ALL_CHECKS:
                result = fn()
                self.assertIn("name", result)
                self.assertIn("passed", result)
                self.assertIn("detail", result)

        def test_digest_matches_checked_in_corpus(self):
            if DEFAULT_CORPUS_RESULTS_PATH.is_file():
                doc = json.loads(DEFAULT_CORPUS_RESULTS_PATH.read_text(encoding="utf-8"))
                self.assertEqual(
                    compute_corpus_result_digest(doc["per_test_results"]),
                    doc["corpus"]["result_digest"],
                )

        def test_divergence_classification_tiers(self):
            base = {"stdout": "ok\n", "stderr": "", "exit_code": 0, "elapsed_ms": 10.0}
            agree = classify_lockstep_case("c1", "core", {"node": base, "franken-node": base})
            self.assertEqual(agree["class"], "agree")
            harmless = classify_lockstep_case(
                "c2",
                "core",
                {
                    "node": {**base, "stdout": "/tmp/run-a/f.js 2026-01-01T00:00:00Z\n"},
                    "franken-node": {**base, "stdout": "/tmp/run-b/f.js 2026-11-20T12:00:00Z\n"},
                },
            )
            self.assertEqual(harmless["class"], "harmless")
            blocking = classify_lockstep_case(
                "c3",
                "core",
                {"node": base, "franken-node": {**base, "stdout": "diverged\n"}},
            )
            self.assertEqual(blocking["class"], "blocking")
            self.assertFalse(blocking["passed"])

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(SelfTest)
    runner = unittest.TextTestRunner(verbosity=2)
    outcome = runner.run(suite)
    return 0 if outcome.wasSuccessful() else 1


def _load_fixtures_dir(fixtures_dir: Path) -> list[dict]:
    fixtures: list[dict] = []
    for path in sorted(fixtures_dir.glob("*.js")):
        fixtures.append(
            {
                "case_id": path.stem,
                "family": path.parent.name or "core",
                "source": path.read_text(encoding="utf-8"),
            }
        )
    return fixtures


def main(argv: list[str] | None = None) -> int:
    configure_test_logging("check_lockstep_validation")
    parser = argparse.ArgumentParser(description="Continuous Lockstep Validation Gate (bd-1w78 / bd-2djfa)")
    parser.add_argument("--self-test", action="store_true", help="Run built-in unit self-tests")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--evaluate-corpus",
        nargs="?",
        const=str(DEFAULT_CORPUS_RESULTS_PATH),
        default=None,
        help="Evaluate a measured compatibility_corpus_results.json artifact fail-closed",
    )
    parser.add_argument("--baseline", type=Path, default=None, help="Previous baseline JSON for non-regression check")
    parser.add_argument("--receipts", type=Path, default=None, help="JSON file containing signed/hashed divergence receipts")
    parser.add_argument("--min-corpus-cases", type=int, default=DEFAULT_MIN_CORPUS_CASES)
    parser.add_argument("--timing-budget-ms", type=float, default=DEFAULT_TIMING_BUDGET_MS)
    parser.add_argument("--execute-live", action="store_true", help="Run live multi-runtime lockstep fixtures")
    parser.add_argument("--fixtures-dir", type=Path, default=None, help="Directory of *.js fixtures for --execute-live")
    parser.add_argument("--runtimes", default="node,bun,franken-node", help="Comma-separated runtimes for --execute-live")
    parser.add_argument("--franken-node-bin", default=None, help="Explicit franken-node binary path for --execute-live")
    parser.add_argument("--output-artifact", type=Path, default=None, help="Write machine-readable report artifact")
    parser.add_argument("--jsonl-log", type=Path, default=None, help="Write structured JSONL lifecycle event log")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.evaluate_corpus is not None:
        report = evaluate_corpus_artifact(
            Path(args.evaluate_corpus),
            baseline_path=args.baseline,
            receipts_path=args.receipts,
            min_corpus_cases=args.min_corpus_cases,
            timing_budget_ms=args.timing_budget_ms,
            jsonl_log_path=args.jsonl_log,
            output_artifact_path=args.output_artifact,
        )
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            verdict = "PASS" if report["passed"] else "FAIL"
            print(
                f"bd-2djfa Continuous Lockstep Corpus Gate [{verdict}]: "
                f"{report.get('passed_cases', 0)}/{report.get('total_cases', 0)} "
                f"({report.get('overall_pass_rate_pct', 0.0):.2f}%)"
            )
            for reason in report["blocking_reasons"]:
                print(f"  BLOCKING: {reason}")
        return 0 if report["passed"] else 1

    if args.execute_live:
        runtimes = [r.strip() for r in args.runtimes.split(",") if r.strip()]
        runtime_commands = {rt: _resolve_runtime_command(rt, args.franken_node_bin) for rt in runtimes}
        fixtures = _load_fixtures_dir(args.fixtures_dir) if args.fixtures_dir and args.fixtures_dir.is_dir() else []
        receipts_map: dict[str, dict] = {}
        if args.receipts and args.receipts.is_file():
            loaded = json.loads(args.receipts.read_text(encoding="utf-8"))
            for item in loaded.get("receipts", loaded) if isinstance(loaded, dict) else loaded:
                if isinstance(item, dict) and item.get("case_id"):
                    receipts_map[str(item["case_id"])] = item
        baseline_doc = json.loads(args.baseline.read_text(encoding="utf-8")) if args.baseline and args.baseline.is_file() else None
        report = run_live_lockstep_fixtures(
            fixtures,
            runtime_commands=runtime_commands,
            receipts_by_case=receipts_map,
            timing_budget_ms=args.timing_budget_ms,
            baseline_report=baseline_doc,
            jsonl_log_path=args.jsonl_log,
            output_artifact_path=args.output_artifact,
        )
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            verdict = "PASS" if report["passed"] else "FAIL"
            print(f"bd-2djfa Live Lockstep Gate [{verdict}]: {report.get('passed_cases', 0)}/{report.get('total_cases', 0)}")
            for reason in report["blocking_reasons"]:
                print(f"  BLOCKING: {reason}")
        return 0 if report["passed"] else 1

    result = run_all()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-1w78 Continuous Lockstep Validation: {result['passed']}/{result['total']} checks passed")
        print()
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['name']}: {check['detail']}")
        print()
        print("Result: ALL CHECKS PASSED" if result["all_passed"] else "Result: SOME CHECKS FAILED")

    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
