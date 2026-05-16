#!/usr/bin/env python3
"""Verification script for bd-2aj ecosystem network-effect APIs."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

CONTRACT_PATH = ROOT / "docs/specs/section_10_12/bd-2aj_contract.md"
API_SCHEMA_PATH = ROOT / "docs/specs/section_10_12/bd-2aj_api_schema.md"
REGISTRY_PATH = ROOT / "crates/franken-node/src/connector/ecosystem_registry.rs"
REPUTATION_PATH = ROOT / "crates/franken-node/src/connector/ecosystem_reputation.rs"
COMPLIANCE_PATH = ROOT / "crates/franken-node/src/connector/ecosystem_compliance.rs"
MOD_PATH = ROOT / "crates/franken-node/src/connector/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_12/bd-2aj"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_CONTRACT_INVARIANTS = [
    "INV-ENE-REGISTRY",
    "INV-ENE-DETERM",
    "INV-ENE-TAMPER",
    "INV-ENE-SYBIL",
    "INV-ENE-ANOMALY",
]

REQUIRED_SCHEMA_ENDPOINTS = [
    "POST `/api/v1/registry/extensions`",
    "GET `/api/v1/registry/extensions/{extension_id}`",
    "GET `/api/v1/registry/extensions/{extension_id}/lineage`",
    "GET `/api/v1/registry/extensions/{extension_id}/compat`",
    "POST `/api/v1/registry/extensions/{extension_id}/deprecate`",
    "POST `/api/v1/registry/extensions/{extension_id}/revoke`",
    "GET `/api/v1/registry/audit`",
    "GET `/api/v1/reputation/{publisher_id}`",
    "POST `/api/v1/reputation/{publisher_id}/compute`",
    "GET `/api/v1/reputation/{publisher_id}/history`",
    "POST `/api/v1/reputation/dispute`",
    "POST `/api/v1/compliance/evidence`",
    "GET `/api/v1/compliance/evidence/{content_hash}`",
    "GET `/api/v1/compliance/evidence/{content_hash}/verify`",
    "GET `/api/v1/compliance/index`",
]

REQUIRED_SCHEMA_AUTH_TERMS = [
    "mTLS",
    "X-API-Key",
    "Rate Limiting",
    "Pagination",
]

REQUIRED_REGISTRY_SYMBOLS = [
    "pub struct EcosystemRegistry",
    "pub fn register_extension",
    "pub fn get_extension",
    "pub fn get_lineage",
    "pub fn get_compatibility",
    "pub fn deprecate_extension",
    "pub fn revoke_extension",
    "pub fn verify_audit_integrity",
    "pub const ENE_001_REGISTRY_MUTATION",
    "pub const ENE_011_SYBIL_REJECT",
]

REQUIRED_REPUTATION_SYMBOLS = [
    "pub struct EcosystemReputationApi",
    "pub fn deterministic_reputation_score",
    "pub fn is_anomalous_delta",
    "pub fn register_publisher",
    "pub fn compute_reputation",
    "pub fn file_dispute",
    "pub fn resolve_dispute",
    "pub const ENE_003_REPUTATION_COMPUTED",
    "pub const ENE_004_REPUTATION_ANOMALY",
]

REQUIRED_COMPLIANCE_SYMBOLS = [
    "pub struct ComplianceEvidenceStore",
    "pub fn compute_content_hash",
    "pub fn store_evidence",
    "pub fn retrieve_evidence",
    "pub fn verify_tamper_evidence",
    "EvidenceSource::MigrationSingularity",
    "EvidenceSource::TrustFabric",
    "pub const ENE_005_COMPLIANCE_EVIDENCE_STORED",
    "pub const ENE_007_COMPLIANCE_TAMPER_CHECK_PASS",
]

REQUIRED_EVENT_CODES = [
    "ENE-001",
    "ENE-002",
    "ENE-003",
    "ENE-004",
    "ENE-005",
    "ENE-006",
    "ENE-007",
    "ENE-008",
    "ENE-009",
    "ENE-010",
    "ENE-011",
]

REQUIRED_CROSS_PROGRAM_TESTS = [
    "test_cross_program_migration_singularity_evidence",
    "test_cross_program_trust_fabric_evidence",
]


def check_file_exists(path: Path) -> dict[str, Any]:
    exists = path.exists()
    return {
        "path": str(path.relative_to(ROOT)),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
    }


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        raw_end = _rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = _rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def _rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def check_content(
    path: Path,
    required: list[str],
    reason: str,
    *,
    strip_comments: bool = False,
) -> dict[str, Any]:
    if not path.exists():
        return {"pass": False, "reason": reason, "found": [], "missing": required}
    content = _read_rust_source(path) if strip_comments else _read_text(path)
    found = [item for item in required if item in content]
    missing = [item for item in required if item not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_mod_registration() -> dict[str, Any]:
    required = [
        "pub mod ecosystem_registry;",
        "pub mod ecosystem_reputation;",
        "pub mod ecosystem_compliance;",
    ]
    result = check_content(MOD_PATH, required, "connector mod.rs not found", strip_comments=True)
    return {
        "pass": result["pass"],
        "found": result["found"],
        "missing": result["missing"],
    }


def check_event_codes() -> dict[str, Any]:
    if not CONTRACT_PATH.exists() or not API_SCHEMA_PATH.exists():
        return {
            "pass": False,
            "reason": "contract or api schema not found",
            "found": [],
            "missing": REQUIRED_EVENT_CODES,
        }

    joined = "\n".join(
        [
            _read_text(CONTRACT_PATH),
            _read_text(API_SCHEMA_PATH),
            _read_rust_source(REGISTRY_PATH) if REGISTRY_PATH.exists() else "",
            _read_rust_source(REPUTATION_PATH) if REPUTATION_PATH.exists() else "",
            _read_rust_source(COMPLIANCE_PATH) if COMPLIANCE_PATH.exists() else "",
        ]
    )
    found = [code for code in REQUIRED_EVENT_CODES if code in joined]
    missing = [code for code in REQUIRED_EVENT_CODES if code not in joined]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_endpoint_coverage() -> dict[str, Any]:
    if not API_SCHEMA_PATH.exists():
        return {
            "pass": False,
            "reason": "api schema file not found",
            "found": [],
            "missing": REQUIRED_SCHEMA_ENDPOINTS,
            "coverage_pct": 0.0,
        }

    content = _read_text(API_SCHEMA_PATH)
    found = [ep for ep in REQUIRED_SCHEMA_ENDPOINTS if ep in content]
    missing = [ep for ep in REQUIRED_SCHEMA_ENDPOINTS if ep not in content]
    coverage = len(found) / len(REQUIRED_SCHEMA_ENDPOINTS) if REQUIRED_SCHEMA_ENDPOINTS else 1.0
    return {
        "pass": coverage >= 0.95,
        "found": found,
        "missing": missing,
        "coverage_pct": round(coverage * 100.0, 2),
        "required_coverage_pct": 95.0,
    }


def check_anti_gaming() -> dict[str, Any]:
    required_markers = [
        "SybilDuplicate",
        "RateLimitExceeded",
        "is_anomalous_delta",
        "file_dispute",
        "resolve_dispute",
        "ENE_004_REPUTATION_ANOMALY",
        "ENE_011_SYBIL_REJECT",
    ]
    if not REGISTRY_PATH.exists() or not REPUTATION_PATH.exists():
        return {
            "pass": False,
            "reason": "registry or reputation module not found",
            "found": [],
            "missing": required_markers,
        }
    content = _read_rust_source(REGISTRY_PATH) + "\n" + _read_rust_source(REPUTATION_PATH)
    found = [marker for marker in required_markers if marker in content]
    missing = [marker for marker in required_markers if marker not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_cross_program_evidence() -> dict[str, Any]:
    if not COMPLIANCE_PATH.exists():
        return {
            "pass": False,
            "reason": "compliance module not found",
            "found": [],
            "missing": REQUIRED_CROSS_PROGRAM_TESTS,
        }

    content = _read_rust_source(COMPLIANCE_PATH)
    found = [name for name in REQUIRED_CROSS_PROGRAM_TESTS if name in content]
    missing = [name for name in REQUIRED_CROSS_PROGRAM_TESTS if name not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def run_all_checks() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = {
        "files": {
            "contract": check_file_exists(CONTRACT_PATH),
            "api_schema": check_file_exists(API_SCHEMA_PATH),
            "registry_module": check_file_exists(REGISTRY_PATH),
            "reputation_module": check_file_exists(REPUTATION_PATH),
            "compliance_module": check_file_exists(COMPLIANCE_PATH),
            "connector_mod": check_file_exists(MOD_PATH),
        },
        "contract_invariants": check_content(
            CONTRACT_PATH,
            REQUIRED_CONTRACT_INVARIANTS,
            "contract file not found",
        ),
        "api_schema_contract": check_content(
            API_SCHEMA_PATH,
            REQUIRED_SCHEMA_ENDPOINTS,
            "api schema file not found",
        ),
        "registry_symbols": check_content(
            REGISTRY_PATH,
            REQUIRED_REGISTRY_SYMBOLS,
            "registry module not found",
            strip_comments=True,
        ),
        "reputation_symbols": check_content(
            REPUTATION_PATH,
            REQUIRED_REPUTATION_SYMBOLS,
            "reputation module not found",
            strip_comments=True,
        ),
        "compliance_symbols": check_content(
            COMPLIANCE_PATH,
            REQUIRED_COMPLIANCE_SYMBOLS,
            "compliance module not found",
            strip_comments=True,
        ),
        "event_codes": check_event_codes(),
        "anti_gaming": check_anti_gaming(),
        "cross_program_evidence": check_cross_program_evidence(),
        "mod_registration": check_mod_registration(),
        "endpoint_coverage": check_endpoint_coverage(),
        "auth_and_pagination": check_content(
            API_SCHEMA_PATH,
            REQUIRED_SCHEMA_AUTH_TERMS,
            "api schema file not found",
        ),
    }

    check_results = [
        checks["contract_invariants"],
        checks["api_schema_contract"],
        checks["registry_symbols"],
        checks["reputation_symbols"],
        checks["compliance_symbols"],
        checks["event_codes"],
        checks["anti_gaming"],
        checks["cross_program_evidence"],
        checks["mod_registration"],
        checks["endpoint_coverage"],
        checks["auth_and_pagination"],
    ]

    all_checks_pass = all(item.get("pass", False) for item in check_results)
    files_pass = all(item["exists"] for item in checks["files"].values())
    passed_checks = sum(1 for item in check_results if item.get("pass", False)) + (
        1 if files_pass else 0
    )

    return {
        "bead_id": "bd-2aj",
        "section": "10.12",
        "title": "Ecosystem Network-Effect APIs (Registry/Reputation/Compliance)",
        "timestamp": timestamp,
        "overall_pass": all_checks_pass and files_pass,
        "checks": checks,
        "summary": {
            "total_checks": 12,
            "passed": passed_checks,
            "failed": 12 - passed_checks,
        },
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def write_summary(evidence: dict[str, Any]) -> None:
    summary = evidence["summary"]
    lines = [
        f"# Verification Summary: {evidence['title']}",
        "",
        f"**Bead:** {evidence['bead_id']} | **Section:** {evidence['section']}",
        f"**Timestamp:** {evidence['timestamp']}",
        f"**Overall:** {'PASS' if evidence['overall_pass'] else 'FAIL'}",
        f"**Checks:** {summary['passed']}/{summary['total_checks']} passed",
        "",
        "## Check Results",
        "",
    ]

    for name, result in sorted(evidence["checks"].items()):
        if name == "files":
            for file_name, file_info in sorted(result.items()):
                status = "PASS" if file_info["exists"] else "FAIL"
                lines.append(
                    f"- **File {file_name}:** {status} ({file_info['path']}, {file_info['size_bytes']} bytes)"
                )
            continue

        status = "PASS" if result.get("pass", False) else "FAIL"
        lines.append(f"- **{name}:** {status}")
        if "coverage_pct" in result:
            lines.append(
                f"  - Coverage: {result['coverage_pct']}% (required {result.get('required_coverage_pct', 0)}%)"
            )
        if result.get("missing"):
            for missing in result["missing"]:
                lines.append(f"  - Missing: `{missing}`")

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Contract: `{CONTRACT_PATH.relative_to(ROOT)}`",
            f"- API schema: `{API_SCHEMA_PATH.relative_to(ROOT)}`",
            f"- Verification evidence: `{EVIDENCE_PATH.relative_to(ROOT)}`",
            "",
        ]
    )

    SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test() -> bool:
    evidence = run_all_checks()
    if not isinstance(evidence, dict):
        print("self_test failed: evidence is not a dict", file=sys.stderr)
        return False
    if evidence.get("bead_id") != "bd-2aj":
        print("self_test failed: bead_id mismatch", file=sys.stderr)
        return False
    if "checks" not in evidence or "summary" not in evidence:
        print("self_test failed: missing checks or summary", file=sys.stderr)
        return False
    if _strip_rust_comments('"kept // literal"; // removed') != '"kept // literal"; ':
        print("self_test failed: Rust comment stripper corrupted string literals", file=sys.stderr)
        return False

    required_categories = [
        "files",
        "contract_invariants",
        "api_schema_contract",
        "registry_symbols",
        "reputation_symbols",
        "compliance_symbols",
        "event_codes",
        "anti_gaming",
        "cross_program_evidence",
        "mod_registration",
        "endpoint_coverage",
        "auth_and_pagination",
    ]
    for category in required_categories:
        if category not in evidence["checks"]:
            print(f"self_test failed: missing category: {category}", file=sys.stderr)
            return False

    return True


def main() -> None:
    configure_test_logging("check_ecosystem_apis")
    parser = argparse.ArgumentParser(description="Verify bd-2aj ecosystem APIs")
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    evidence = run_all_checks()

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        status = "PASS" if evidence["overall_pass"] else "FAIL"
        summary = evidence["summary"]
        print(
            f"bd-2aj verification: {status} ({summary['passed']}/{summary['total_checks']} checks passed)"
        )
        for name, result in sorted(evidence["checks"].items()):
            if name == "files":
                for file_name, file_info in sorted(result.items()):
                    symbol = "+" if file_info["exists"] else "-"
                    print(f"  [{symbol}] file:{file_name} {file_info['path']}")
            else:
                symbol = "+" if result.get("pass", False) else "-"
                print(f"  [{symbol}] {name}")
                if result.get("missing"):
                    for missing in result["missing"]:
                        print(f"       missing: {missing}")

    write_evidence(evidence)
    write_summary(evidence)


if __name__ == "__main__":
    main()
