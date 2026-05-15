#!/usr/bin/env python3
"""Verification script for bd-15t category-shift reporting pipeline."""
# ruff: noqa: E402

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402
from typing import Any


IMPL = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "category_shift.rs"
MOD_FILE = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_9" / "bd-15t_contract.md"
POLICY = ROOT / "docs" / "policy" / "category_shift_reporting.md"
EVIDENCE = ROOT / "artifacts" / "section_10_9" / "bd-15t" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_9" / "bd-15t" / "verification_summary.md"
REPORTS_CHECKER = ROOT / "scripts" / "check_category_shift_reports.py"
FIXTURE_DIR = ROOT / "fixtures" / "category-shift"
FIXTURE_MANIFEST = FIXTURE_DIR / "manifest.json"
FIXTURE_REPORT_JSON = FIXTURE_DIR / "category_shift_report.json"
FIXTURE_REPORT_MD = FIXTURE_DIR / "category_shift_report.md"

RESULTS: list[dict[str, Any]] = []

# ── Required patterns in the Rust implementation ─────────────────────────────

REQUIRED_STRUCTS = [
    "pub struct CategoryShiftReport",
    "pub struct ShiftEvidence",
    "pub struct ReportingPipeline",
    "pub struct ReportClaim",
    "pub struct ThresholdResult",
    "pub struct MoonshotBetEntry",
    "pub struct ManifestEntry",
    "pub struct DimensionData",
    "pub struct ReportDiffEntry",
    "pub struct PipelineEvent",
    "pub struct PipelineConfig",
    "pub struct ClaimInput",
    "pub struct EvidenceInput",
]

REQUIRED_ENUMS = [
    "pub enum ThresholdStatus",
    "pub enum ReportDimension",
    "pub enum BetStatus",
    "pub enum FreshnessStatus",
    "pub enum ClaimOutcome",
    "pub enum CategoryShiftError",
]

REQUIRED_EVENT_CODES = [
    "CSR_PIPELINE_STARTED",
    "CSR_DIMENSION_COLLECTED",
    "CSR_CLAIM_VERIFIED",
    "CSR_REPORT_GENERATED",
]

REQUIRED_ERROR_CODES = [
    "ERR_CSR_SOURCE_UNAVAILABLE",
    "ERR_CSR_CLAIM_STALE",
    "ERR_CSR_CLAIM_INVALID",
    "ERR_CSR_HASH_MISMATCH",
]

REQUIRED_INVARIANTS = [
    "INV_CSR_CLAIM_VALID",
    "INV_CSR_MANIFEST",
    "INV_CSR_REPRODUCE",
    "INV_CSR_IDEMPOTENT",
]

REQUIRED_FUNCTIONS = [
    "pub fn start(",
    "pub fn ingest_dimension(",
    "pub fn register_bet(",
    "pub fn generate_report(",
    "pub fn render_markdown(",
    "pub fn render_json(",
    "pub fn diff_reports(",
    "pub fn sha256_hex(",
    "pub fn demo_pipeline(",
]

REQUIRED_THRESHOLDS = [
    "THRESHOLD_COMPAT_PERCENT",
    "THRESHOLD_MIGRATION_VELOCITY",
    "THRESHOLD_COMPROMISE_REDUCTION",
]

REQUIRED_SPEC_SECTIONS = [
    "## Scope",
    "## Report Dimensions",
    "## Category-Defining Thresholds",
    "## Reproducibility Requirements",
    "## Output Formats",
    "## Event Codes",
    "## Error Codes",
    "## Invariants",
    "## Acceptance Criteria",
]

REQUIRED_POLICY_SECTIONS = [
    "## 1. Overview",
    "## 2. Report Generation",
    "## 3. Claim Integrity",
    "## 4. Category-Defining Thresholds",
    "## 5. Moonshot Bet Status",
    "## 6. Output Format Requirements",
    "## 7. Versioning and Retention",
    "## 8. Idempotency",
]


# ── Helpers ──────────────────────────────────────────────────────────────────


def _safe_rel(path: Path) -> str:
    """Return a relative path string safely, avoiding crashes on temp dirs."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    result = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(result)
    return result


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, pattern: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: {pattern}", False, "file missing")
    content = _read_text(path)
    return _check(
        f"{label}: {pattern}",
        pattern in content,
        "found" if pattern in content else "not found in file",
    )


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read_text(path))


def _rust_file_contains(path: Path, pattern: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: {pattern}", False, "file missing")
    content = _read_rust_source(path)
    return _check(
        f"{label}: {pattern}",
        pattern in content,
        "found" if pattern in content else "not found in file",
    )


def _strip_rust_comments(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        raw_start = _rust_raw_string_start(text, i)
        if raw_start is not None:
            body_start, hashes = raw_start
            end = _rust_raw_string_end(text, body_start + 1, hashes)
            if end is None:
                out.append(text[i:])
                break
            out.append(text[i:end])
            i = end
            continue

        if ch == '"':
            end = _rust_quoted_literal_end(text, i, ch)
            out.append(text[i:end])
            i = end
            continue

        if text.startswith("//", i):
            newline = text.find("\n", i + 2)
            if newline == -1:
                break
            out.append("\n")
            i = newline + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def _rust_raw_string_start(text: str, index: int) -> tuple[int, int] | None:
    n = len(text)
    if text.startswith("br", index):
        cursor = index + 2
    elif text.startswith("r", index):
        cursor = index + 1
    else:
        return None

    hashes = 0
    while cursor < n and text[cursor] == "#":
        hashes += 1
        cursor += 1
    if cursor < n and text[cursor] == '"':
        return cursor, hashes
    return None


def _rust_raw_string_end(text: str, index: int, hashes: int) -> int | None:
    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, index)
    if end == -1:
        return None
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, index: int, quote: str) -> int:
    i = index + 1
    n = len(text)
    escaped = False
    while i < n:
        ch = text[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == quote:
            return i + 1
        i += 1
    return n


def _rust_block_comment_end(text: str, index: int) -> int:
    depth = 1
    i = index
    n = len(text)
    while i < n and depth:
        if text.startswith("/*", i):
            depth += 1
            i += 2
        elif text.startswith("*/", i):
            depth -= 1
            i += 2
        else:
            i += 1
    return i


def _add_check(results: list[dict[str, Any]], name: str, passed: bool, detail: str = "") -> None:
    results.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("found" if passed else "NOT FOUND"),
        }
    )


def _read_json_file(path: Path) -> tuple[dict[str, Any] | None, str]:
    try:
        data = json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "top-level JSON must be an object"
    return data, "valid JSON object"


def report_fixture_checks() -> list[dict[str, Any]]:
    """Validate the checked-in category-shift report fixtures."""
    checks: list[dict[str, Any]] = []

    _add_check(
        checks,
        "file: category shift reports checker",
        REPORTS_CHECKER.is_file(),
        f"exists: {_safe_rel(REPORTS_CHECKER)}" if REPORTS_CHECKER.is_file() else f"missing: {_safe_rel(REPORTS_CHECKER)}",
    )
    _add_check(
        checks,
        "fixture: category-shift directory",
        FIXTURE_DIR.is_dir(),
        f"exists: {_safe_rel(FIXTURE_DIR)}" if FIXTURE_DIR.is_dir() else f"missing: {_safe_rel(FIXTURE_DIR)}",
    )
    for path, label in [
        (FIXTURE_MANIFEST, "fixture manifest"),
        (FIXTURE_REPORT_JSON, "fixture report JSON"),
        (FIXTURE_REPORT_MD, "fixture report Markdown"),
    ]:
        _add_check(
            checks,
            f"file: {label}",
            path.is_file(),
            f"exists: {_safe_rel(path)}" if path.is_file() else f"missing: {_safe_rel(path)}",
        )

    manifest, manifest_detail = _read_json_file(FIXTURE_MANIFEST)
    _add_check(checks, "fixture manifest: valid JSON", manifest is not None, manifest_detail)
    if manifest is not None:
        fixture_paths = {entry.get("path") for entry in manifest.get("fixtures", []) if isinstance(entry, dict)}
        _add_check(checks, "fixture manifest: bead_id", manifest.get("bead_id") == "bd-15t")
        _add_check(
            checks,
            "fixture manifest: expected checker",
            manifest.get("expected_checker") == "scripts/check_category_shift_reports.py",
        )
        _add_check(
            checks,
            "fixture manifest: report fixtures listed",
            {
                "fixtures/category-shift/category_shift_report.json",
                "fixtures/category-shift/category_shift_report.md",
            }.issubset(fixture_paths),
            f"{len(fixture_paths)} fixture path(s) listed",
        )

    report, report_detail = _read_json_file(FIXTURE_REPORT_JSON)
    _add_check(checks, "fixture report: valid JSON", report is not None, report_detail)
    if report is not None:
        claims = report.get("claims", [])
        dimensions = report.get("dimensions", {})
        thresholds = report.get("thresholds", [])
        manifest_entries = report.get("manifest", [])
        report_hash = report.get("report_hash", "")
        claim_ids = {claim.get("claim_id") for claim in claims if isinstance(claim, dict)}

        _add_check(checks, "fixture report: version", report.get("version") == 1)
        _add_check(checks, "fixture report: five dimensions", isinstance(dimensions, dict) and len(dimensions) == 5)
        _add_check(checks, "fixture report: five claims", isinstance(claims, list) and len(claims) == 5)
        _add_check(checks, "fixture report: three thresholds", isinstance(thresholds, list) and len(thresholds) == 3)
        _add_check(checks, "fixture report: manifest entries", isinstance(manifest_entries, list) and len(manifest_entries) >= 5)
        _add_check(
            checks,
            "fixture report: deterministic claim ids",
            {f"CSR-CLAIM-{idx:03d}" for idx in range(1, 6)}.issubset(claim_ids),
        )
        _add_check(
            checks,
            "fixture report: report hash",
            isinstance(report_hash, str) and bool(re.fullmatch(r"[0-9a-f]{64}", report_hash)),
            "64 lowercase hex chars" if isinstance(report_hash, str) else "not a string",
        )

    if FIXTURE_REPORT_MD.is_file():
        md = FIXTURE_REPORT_MD.read_text(encoding="utf-8")
        _add_check(checks, "fixture markdown: title", "# Category-Shift Report v1" in md)
        _add_check(checks, "fixture markdown: claim id", "CSR-CLAIM-001" in md)
        _add_check(checks, "fixture markdown: manifest", "## Artifact Manifest" in md)
    else:
        _add_check(checks, "fixture markdown: title", False, "file missing")
        _add_check(checks, "fixture markdown: claim id", False, "file missing")
        _add_check(checks, "fixture markdown: manifest", False, "file missing")

    return checks


# ── Fixture report analysis ──────────────────────────────────────────────────


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def _expected_report_hash(report: dict[str, Any]) -> str:
    report_for_hash = dict(report)
    report_for_hash["report_hash"] = ""
    canonical = json.dumps(
        _canonical(report_for_hash), separators=(",", ":"), ensure_ascii=True
    )
    return _sha256_hex(canonical.encode("utf-8"))


def analyze_fixture_report(
    report_path: Path | None = None,
    markdown_path: Path | None = None,
) -> dict[str, Any]:
    """Analyze the checked-in report fixture instead of synthesizing evidence."""
    report_path = report_path or FIXTURE_REPORT_JSON
    markdown_path = markdown_path or FIXTURE_REPORT_MD
    report, detail = _read_json_file(report_path)

    if report is None:
        return {
            "valid_report": False,
            "detail": detail,
            "claims_count": 0,
            "dimensions_count": 0,
            "all_claims_verified": False,
            "all_claim_ids_present": False,
            "claim_dimensions_declared": False,
            "thresholds_count": 0,
            "all_thresholds_met": False,
            "bet_status_count": 0,
            "manifest_count": 0,
            "manifest_entries_have_hashes": False,
            "all_manifest_entries_fresh": False,
            "report_hash_matches": False,
            "has_json_format": False,
            "has_markdown_format": markdown_path.is_file(),
            "markdown_mentions_manifest": False,
        }

    claims = report.get("claims", [])
    dimensions = report.get("dimensions", {})
    thresholds = report.get("thresholds", [])
    bet_status = report.get("bet_status", [])
    manifest_entries = report.get("manifest", [])
    report_hash = report.get("report_hash", "")
    expected_claim_ids = {f"CSR-CLAIM-{idx:03d}" for idx in range(1, 6)}
    claim_ids = {claim.get("claim_id") for claim in claims if isinstance(claim, dict)}
    dimension_keys = set(dimensions) if isinstance(dimensions, dict) else set()

    if markdown_path.is_file():
        markdown = markdown_path.read_text(encoding="utf-8")
    else:
        markdown = ""

    return {
        "valid_report": True,
        "detail": "valid JSON object",
        "claims_count": len(claims) if isinstance(claims, list) else 0,
        "dimensions_count": len(dimensions) if isinstance(dimensions, dict) else 0,
        "all_claims_verified": isinstance(claims, list)
        and all(
            isinstance(claim, dict) and claim.get("outcome") == "verified"
            for claim in claims
        ),
        "all_claim_ids_present": expected_claim_ids.issubset(claim_ids),
        "claim_dimensions_declared": isinstance(claims, list)
        and all(
            isinstance(claim, dict) and claim.get("dimension") in dimension_keys
            for claim in claims
        ),
        "thresholds_count": len(thresholds) if isinstance(thresholds, list) else 0,
        "all_thresholds_met": isinstance(thresholds, list)
        and all(
            isinstance(threshold, dict)
            and threshold.get("status") in ("met", "exceeded")
            for threshold in thresholds
        ),
        "bet_status_count": len(bet_status) if isinstance(bet_status, list) else 0,
        "manifest_count": len(manifest_entries) if isinstance(manifest_entries, list) else 0,
        "manifest_entries_have_hashes": isinstance(manifest_entries, list)
        and all(
            isinstance(entry, dict)
            and re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256_hash", "")))
            for entry in manifest_entries
        ),
        "all_manifest_entries_fresh": isinstance(manifest_entries, list)
        and all(
            isinstance(entry, dict) and entry.get("freshness") == "fresh"
            for entry in manifest_entries
        ),
        "report_hash_matches": isinstance(report_hash, str)
        and report_hash == _expected_report_hash(report),
        "has_json_format": True,
        "has_markdown_format": markdown_path.is_file()
        and expected_claim_ids.issubset(
            {claim_id for claim_id in expected_claim_ids if claim_id in markdown}
        ),
        "markdown_mentions_manifest": "## Artifact Manifest" in markdown,
    }


# ── Main check runner ────────────────────────────────────────────────────────


def run_all() -> dict[str, Any]:
    """Run all verification checks and return structured report."""
    global RESULTS
    RESULTS = []

    # File existence checks
    _file_exists(IMPL, "category_shift implementation")
    _file_exists(MOD_FILE, "supply_chain module")
    _file_exists(SPEC, "bd-15t contract spec")
    _file_exists(POLICY, "category shift reporting policy")
    _file_exists(EVIDENCE, "verification evidence")
    _file_exists(SUMMARY, "verification summary")
    RESULTS.extend(report_fixture_checks())

    # Module wiring
    if MOD_FILE.is_file():
        content = _read_rust_source(MOD_FILE)
        _check("mod export: category_shift", "pub mod category_shift;" in content)
    else:
        _check("mod export: category_shift", False, "mod file missing")

    # Struct checks
    for pattern in REQUIRED_STRUCTS:
        _rust_file_contains(IMPL, pattern, "impl")

    # Enum checks
    for pattern in REQUIRED_ENUMS:
        _rust_file_contains(IMPL, pattern, "impl")

    # Event code checks
    for code in REQUIRED_EVENT_CODES:
        _rust_file_contains(IMPL, code, "event_code")

    # Error code checks
    for code in REQUIRED_ERROR_CODES:
        _rust_file_contains(IMPL, code, "error_code")

    # Invariant checks
    for inv in REQUIRED_INVARIANTS:
        _rust_file_contains(IMPL, inv, "invariant")

    # Function checks
    for fn_pat in REQUIRED_FUNCTIONS:
        _rust_file_contains(IMPL, fn_pat, "function")

    # Threshold constant checks
    for th in REQUIRED_THRESHOLDS:
        _rust_file_contains(IMPL, th, "threshold")

    # Spec section checks
    for section in REQUIRED_SPEC_SECTIONS:
        _file_contains(SPEC, section, "spec")

    # Policy section checks
    for section in REQUIRED_POLICY_SECTIONS:
        _file_contains(POLICY, section, "policy")

    # Unit test count in Rust
    if IMPL.is_file():
        src = _read_rust_source(IMPL)
        test_count = len(re.findall(r"#\[test\]", src))
        _check("rust unit test count", test_count >= 25, f"{test_count} tests found")
    else:
        _check("rust unit test count", False, "impl file missing")

    # cfg(test) module present
    _rust_file_contains(IMPL, "#[cfg(test)]", "impl")

    # Fixture-backed report checks
    fixture_report = analyze_fixture_report()
    _check("fixture analysis: JSON report loaded", fixture_report["valid_report"], fixture_report["detail"])
    _check("fixture analysis: 5 dimensions collected", fixture_report["dimensions_count"] == 5)
    _check("fixture analysis: 5 claims present", fixture_report["claims_count"] == 5)
    _check("fixture analysis: deterministic claim ids", fixture_report["all_claim_ids_present"])
    _check("fixture analysis: claim dimensions declared", fixture_report["claim_dimensions_declared"])
    _check("fixture analysis: all claims verified", fixture_report["all_claims_verified"])
    _check("fixture analysis: 3 thresholds evaluated", fixture_report["thresholds_count"] == 3)
    _check("fixture analysis: all thresholds met or exceeded", fixture_report["all_thresholds_met"])
    _check("fixture analysis: bet status entries present", fixture_report["bet_status_count"] >= 3)
    _check("fixture analysis: manifest has entries", fixture_report["manifest_count"] >= 5)
    _check("fixture analysis: manifest hashes are valid", fixture_report["manifest_entries_have_hashes"])
    _check("fixture analysis: manifest entries are fresh", fixture_report["all_manifest_entries_fresh"])
    _check("fixture analysis: report hash matches payload", fixture_report["report_hash_matches"])
    _check("fixture analysis: JSON format supported", fixture_report["has_json_format"])
    _check("fixture analysis: Markdown format supported", fixture_report["has_markdown_format"])
    _check("fixture analysis: Markdown manifest present", fixture_report["markdown_mentions_manifest"])

    # Category threshold values in spec
    _file_contains(SPEC, ">= 95%", "spec_threshold")
    _file_contains(SPEC, ">= 3x", "spec_threshold")
    _file_contains(SPEC, ">= 10x", "spec_threshold")

    # Evidence file structure
    if EVIDENCE.is_file():
        try:
            evidence_data = json.JSONDecoder().decode(EVIDENCE.read_text(encoding="utf-8"))
            _check("evidence: has bead_id", evidence_data.get("bead_id") == "bd-15t")
            _check("evidence: has section", evidence_data.get("section") == "10.9")
            _check("evidence: has verdict", "verdict" in evidence_data)
        except (json.JSONDecodeError, Exception) as exc:
            _check("evidence: valid JSON", False, str(exc))
    else:
        _check("evidence: exists", False, "missing")

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-15t",
        "title": "Category-shift reporting pipeline with reproducible evidence bundles",
        "section": "10.9",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    report = run_all()
    ok = report["verdict"] == "PASS"
    return ok, report["checks"]


def main() -> None:
    configure_test_logging("check_category_shift")
    parser = argparse.ArgumentParser(
        description="Verify bd-15t category-shift reporting pipeline"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        if args.json:
            print(json.dumps({"ok": ok, "checks": checks}, indent=2))
        else:
            passing = sum(1 for c in checks if c["pass"])
            print(f"self_test: {passing}/{len(checks)} checks pass")
            if not ok:
                for c in checks:
                    if not c["pass"]:
                        print(f"  FAIL: {c['check']} :: {c['detail']}")
        sys.exit(0 if ok else 1)

    report = run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(
            f"\n{report['passed']}/{report['total']} checks pass "
            f"(verdict={report['verdict']})"
        )

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
