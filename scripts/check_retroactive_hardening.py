#!/usr/bin/env python3
"""Verification script for bd-1daz: Retroactive hardening pipeline.

Usage:
    python3 scripts/check_retroactive_hardening.py          # human-readable
    python3 scripts/check_retroactive_hardening.py --json    # machine-readable
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "retroactive_hardening.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-1daz_contract.md"
REPORT_ARTIFACT = ROOT / "artifacts" / "10.14" / "retroactive_hardening_report.json"

REQUIRED_TYPES = [
    "pub struct ObjectId",
    "pub enum ProtectionType",
    "pub struct ProtectionArtifact",
    "pub struct CanonicalObject",
    "pub struct RepairabilityScore",
    "pub struct HardeningProgressRecord",
    "pub struct HardeningResult",
    "pub struct RetroactiveHardeningPipeline",
]

REQUIRED_METHODS = [
    "fn harden(",
    "fn harden_corpus(",
    "fn verify_identity_stable(",
    "fn measure_repairability(",
    "fn required_protections(",
]

EVENT_CODES = [
    "EVD-RETROHARDEN-001",
    "EVD-RETROHARDEN-002",
    "EVD-RETROHARDEN-003",
    "EVD-RETROHARDEN-004",
]

INVARIANTS = [
    "INV-RETROHARDEN-UNION-ONLY",
    "INV-RETROHARDEN-MONOTONIC",
    "INV-RETROHARDEN-IDEMPOTENT",
    "INV-RETROHARDEN-BOUNDED",
]

PROTECTION_TYPES = [
    "Checksum",
    "Parity",
    "IntegrityProof",
    "RedundantCopy",
]

REQUIRED_TESTS = [
    "test_object_id_display",
    "test_protection_type_labels",
    "test_protection_type_all",
    "test_protection_type_weights_sum_close_to_one",
    "test_protection_type_display",
    "test_canonical_object_creation",
    "test_canonical_object_hash_deterministic",
    "test_canonical_object_different_content_different_hash",
    "test_required_protections_baseline_empty",
    "test_required_protections_standard_checksum",
    "test_required_protections_enhanced",
    "test_required_protections_maximum",
    "test_required_protections_critical_all_four",
    "test_required_protections_monotonically_increasing",
    "test_harden_baseline_to_standard",
    "test_harden_standard_to_enhanced",
    "test_harden_baseline_to_critical",
    "test_harden_same_level_no_artifacts",
    "test_harden_reverse_direction_no_artifacts",
    "test_harden_already_at_max_no_artifacts",
    "test_harden_artifact_ids_contain_object_id",
    "test_harden_artifact_data_nonempty",
    "test_harden_redundant_copy_matches_content",
    "test_verify_identity_stable_same_object",
    "test_verify_identity_stable_clone",
    "test_verify_identity_unstable_different_id",
    "test_verify_identity_unstable_different_content",
    "test_harden_does_not_modify_object",
    "test_repairability_no_artifacts",
    "test_repairability_with_checksum",
    "test_repairability_with_all_protections",
    "test_repairability_increases_with_hardening",
    "test_repairability_capped_at_one",
    "test_repairability_deduplicates_same_type",
    "test_harden_corpus_basic",
    "test_harden_corpus_empty",
    "test_harden_corpus_repairability_improves",
    "test_harden_corpus_same_level_no_artifacts",
    "test_harden_corpus_progress_record_fields",
    "test_harden_corpus_multi_level_gap",
    "test_harden_idempotent",
    "test_harden_large_corpus",
    "test_protection_artifact_serialization",
    "test_hardening_result_serialization",
    "test_repairability_score_serialization",
    "test_event_codes_defined",
    "test_checksum_deterministic",
    "test_parity_data_length",
    "test_harden_empty_content_object",
]


def check_file(path, label):
    exists = path.exists()
    if exists:
        try:
            rel = str(path.relative_to(ROOT))
        except ValueError:
            rel = str(path)
    else:
        rel = str(path)
    return {
        "check": f"file: {label}",
        "pass": exists,
        "detail": f"exists: {rel}" if exists else f"missing: {rel}",
    }


def check_content(path, patterns, category):
    results = []
    try:
        text = path.read_text()
    except FileNotFoundError:
        for p in patterns:
            results.append({
                "check": f"{category}: {p}",
                "pass": False,
                "detail": f"file not found: {path}",
            })
        return results
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else f"not found in {path.name}",
        })
    return results


def check_module_registered():
    try:
        text = MOD_RS.read_text()
        found = "pub mod retroactive_hardening;" in text
    except FileNotFoundError:
        found = False
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "not found",
    }


def check_test_count():
    try:
        text = IMPL.read_text()
        count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        count = 0
    return {
        "check": "unit test count",
        "pass": count >= 40,
        "detail": f"{count} tests (minimum 40)",
    }


def check_serde_derives():
    try:
        text = IMPL.read_text()
        has_serialize = "Serialize" in text and "Deserialize" in text
    except FileNotFoundError:
        has_serialize = False
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_serialize,
        "detail": "found" if has_serialize else "not found",
    }


def check_hardening_level_import():
    try:
        text = IMPL.read_text()
        has_import = "HardeningLevel" in text
    except FileNotFoundError:
        has_import = False
    return {
        "check": "hardening state machine integration",
        "pass": has_import,
        "detail": "found" if has_import else "not found",
    }


def check_sha256_usage():
    try:
        text = IMPL.read_text()
        has_sha = "Sha256" in text
    except FileNotFoundError:
        has_sha = False
    return {
        "check": "SHA-256 content hashing",
        "pass": has_sha,
        "detail": "found" if has_sha else "not found",
    }


def check_report_artifact():
    if not REPORT_ARTIFACT.is_file():
        return {
            "check": "report artifact: per-object repairability",
            "pass": False,
            "detail": "missing",
        }
    try:
        data = json.loads(REPORT_ARTIFACT.read_text())
        objects = data.get("objects", [])
        count = len(objects)
        if count < 3:
            return {
                "check": "report artifact: per-object repairability",
                "pass": False,
                "detail": f"only {count} objects (minimum 3)",
            }
        problems = []
        for obj in objects:
            oid = obj.get("object_id", "?")
            if "repairability_before" not in obj:
                problems.append(f"{oid}: missing repairability_before")
            if "repairability_after" not in obj:
                problems.append(f"{oid}: missing repairability_after")
            before = obj.get("repairability_before", 0.0)
            after = obj.get("repairability_after", 0.0)
            if after < before - 1e-9:
                problems.append(
                    f"{oid}: repairability decreased ({before}->{after}): "
                    "violates INV-RETROHARDEN-MONOTONIC"
                )
        if problems:
            return {
                "check": "report artifact: per-object repairability",
                "pass": False,
                "detail": "; ".join(problems),
            }
        return {
            "check": "report artifact: per-object repairability",
            "pass": True,
            "detail": f"{count} objects with valid per-object repairability scores",
        }
    except (json.JSONDecodeError, KeyError) as exc:
        return {
            "check": "report artifact: per-object repairability",
            "pass": False,
            "detail": f"JSON error: {exc}",
        }


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(REPORT_ARTIFACT, "report artifact"))
    checks.append(check_report_artifact())
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.append(check_hardening_level_import())
    checks.append(check_sha256_usage())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, PROTECTION_TYPES, "protection_type"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = len(checks) - passing

    try:
        text = IMPL.read_text()
        test_count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        test_count = 0

    return {
        "bead_id": "bd-1daz",
        "title": "Retroactive hardening pipeline (union-only protection artifacts)",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": test_count,
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    return result["overall_pass"], result["checks"]


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        v = result["verdict"]
        s = result["summary"]
        print(f"bd-1daz retroactive_hardening: {v} ({s['passing']}/{s['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
