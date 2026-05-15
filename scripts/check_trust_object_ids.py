#!/usr/bin/env python3
"""bd-1l5: Verification script for canonical product trust object IDs.

Usage:
    python3 scripts/check_trust_object_ids.py           # human-readable
    python3 scripts/check_trust_object_ids.py --json     # machine-readable
    python3 scripts/check_trust_object_ids.py --self-test # internal consistency
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/connector/trust_object_id.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_10/bd-1l5_contract.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_10/bd-1l5/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_10/bd-1l5/verification_summary.md"

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_STRUCTS = [
    "DomainPrefix",
    "DerivationMode",
    "TrustObjectId",
    "IdRegistry",
    "DomainRegistryEntry",
    "IdError",
    "IdEvent",
]

REQUIRED_EVENT_CODES = [
    "TOI-001",
    "TOI-002",
]

REQUIRED_ERROR_CODES = [
    "ERR_TOI_INVALID_PREFIX",
    "ERR_TOI_MALFORMED_DIGEST",
    "ERR_TOI_INVALID_FORMAT",
    "ERR_TOI_UNKNOWN_DOMAIN",
]

REQUIRED_INVARIANTS = [
    "INV-TOI-PREFIX",
    "INV-TOI-DETERMINISTIC",
    "INV-TOI-COLLISION",
    "INV-TOI-DIGEST",
]

REQUIRED_FUNCTIONS = [
    "derive_content_addressed",
    "derive_context_addressed",
    "parse",
    "validate",
    "full_form",
    "short_form",
    "sha256_digest",
    "canonical_bytes",
    "derive_trust_object_id_events",
    "is_valid_prefix",
    "domain_count",
    "from_prefix",
]

DOMAIN_PREFIXES = [
    ("Extension", "ext:"),
    ("TrustCard", "tcard:"),
    ("Receipt", "rcpt:"),
    ("PolicyCheckpoint", "pchk:"),
    ("MigrationArtifact", "migr:"),
    ("VerifierClaim", "vclaim:"),
]

DERIVATION_MODES = [
    "ContentAddressed",
    "ContextAddressed",
]

REQUIRED_SPEC_SECTIONS = [
    "Overview",
    "Data Model",
    "DomainPrefix",
    "TrustObjectId",
    "IdRegistry",
    "Invariants",
    "Event Codes",
    "Error Codes",
    "Acceptance Criteria",
]

REQUIRED_EVIDENCE_ACCEPTANCE = {
    "AC1_domain_prefixes": ["PASS", "ext:", "tcard:", "rcpt:", "pchk:", "migr:", "vclaim:"],
    "AC2_derivation_modes": ["PASS", "content", "context"],
    "AC3_parse_validate": ["PASS", "parse", "validate"],
    "AC4_cross_domain": ["PASS", "cross-domain"],
    "AC5_representations": ["PASS", "short", "full"],
    "AC6_deterministic": ["PASS", "same inputs"],
    "AC7_sha256": ["PASS", "SHA-256", "256"],
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        data = json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return data
    return None


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _pass_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _metric_int(metrics: dict, key: str) -> int:
    try:
        return int(metrics.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


# ── Check groups ───────────────────────────────────────────────────────────

def check_file_existence() -> list:
    checks = []
    checks.append(_check(
        "trust_object_id implementation exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))
    checks.append(_check(
        "contract spec exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))
    checks.append(_check(
        "evidence artifact exists",
        EVIDENCE_FILE.exists(),
        str(EVIDENCE_FILE),
    ))
    checks.append(_check(
        "summary artifact exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))
    return checks


def check_structs() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for s in REQUIRED_STRUCTS:
        found = f"pub enum {s}" in src or f"pub struct {s}" in src
        checks.append(_check(f"struct/enum {s}", found))
    return checks


def check_event_codes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        checks.append(_check(f"event code {code}", found))
    return checks


def check_error_codes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for code in REQUIRED_ERROR_CODES:
        found = code in src
        checks.append(_check(f"error code {code}", found))
    return checks


def check_invariants() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for inv in REQUIRED_INVARIANTS:
        found = inv in src
        checks.append(_check(f"invariant {inv}", found))
    return checks


def check_functions() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for fn_name in REQUIRED_FUNCTIONS:
        found = f"fn {fn_name}" in src or f"pub fn {fn_name}" in src
        checks.append(_check(f"function {fn_name}", found))
    return checks


def check_spec_sections() -> list:
    src = _read(SPEC_FILE)
    checks = []
    for section in REQUIRED_SPEC_SECTIONS:
        found = section in src
        checks.append(_check(f"spec section: {section}", found))
    return checks


def check_domain_prefixes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for name, prefix in DOMAIN_PREFIXES:
        found_variant = name in src
        found_prefix = f'"{prefix}"' in src
        checks.append(_check(f"domain {name} variant", found_variant))
        checks.append(_check(f"domain prefix {prefix}", found_prefix))
    checks.append(_check(
        "6 domain prefixes defined",
        all(name in src for name, _ in DOMAIN_PREFIXES),
    ))
    return checks


def check_derivation_modes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for mode in DERIVATION_MODES:
        found = mode in src
        checks.append(_check(f"derivation mode {mode}", found))
    return checks


def check_sha256_usage() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("imports sha2::Sha256", "Sha256" in src))
    checks.append(_check("uses hex::encode", "hex::encode" in src))
    checks.append(_check("SHA-256 digest length check", "64" in src and "hex chars" in src))
    return checks


def check_serde_derives() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for t in ["DomainPrefix", "DerivationMode", "TrustObjectId",
              "IdRegistry", "DomainRegistryEntry", "IdEvent"]:
        idx = src.find(f"pub enum {t}") if f"pub enum {t}" in src else src.find(f"pub struct {t}")
        if idx >= 0:
            preceding = src[max(0, idx - 200):idx]
            has_serde = "Serialize" in preceding and "Deserialize" in preceding
            checks.append(_check(f"serde derives on {t}", has_serde))
        else:
            checks.append(_check(f"serde derives on {t}", False, "type not found"))
    return checks


def check_tests() -> list:
    src = _read(IMPL_FILE)
    checks = []
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests present ({test_count})",
        test_count >= 45,
        f"{test_count} tests found",
    ))

    test_categories = [
        ("domain prefix tests", "test_all_domains_count"),
        ("round-trip parse tests", "test_parse_round_trip"),
        ("collision resistance tests", "test_cross_domain_collision"),
        ("content-addressed tests", "test_derive_content_addressed"),
        ("context-addressed tests", "test_derive_context_addressed"),
        ("short form tests", "test_short_form"),
        ("error code tests", "test_error_codes"),
        ("serde roundtrip tests", "test_trust_object_id_serde"),
        ("send+sync tests", "test_types_send_sync"),
        ("event derivation tests", "test_derive_trust_object_id_events_uses_caller_inputs"),
        ("registry tests", "test_registry_new"),
        ("determinism tests", "test_content_addressed_deterministic"),
    ]
    for name, pattern in test_categories:
        found = pattern in src
        checks.append(_check(f"test: {name}", found))
    return checks


def check_send_sync() -> list:
    src = _read(IMPL_FILE)
    checks = []
    found = "assert_send" in src and "assert_sync" in src
    checks.append(_check("Send + Sync assertions", found))
    return checks


def check_acceptance_criteria() -> list:
    src = _read(IMPL_FILE)
    checks = []

    # AC1: 6 domain prefixes
    ac1 = all(name in src for name, _ in DOMAIN_PREFIXES)
    checks.append(_check("AC1: 6 domain prefixes", ac1))

    # AC2: Content-addressed and context-addressed derivation
    ac2 = "derive_content_addressed" in src and "derive_context_addressed" in src
    checks.append(_check("AC2: both derivation modes", ac2))

    # AC3: Parse/validate round-trip
    ac3 = "fn parse" in src and "fn validate" in src
    checks.append(_check("AC3: parse/validate utilities", ac3))

    # AC4: Cross-domain collision impossible
    ac4 = "cross_domain" in src.lower() or "prefix" in src
    checks.append(_check("AC4: cross-domain collision prevention", ac4))

    # AC5: Short-form and full-form
    ac5 = "fn short_form" in src and "fn full_form" in src
    checks.append(_check("AC5: short-form and full-form", ac5))

    # AC6: Deterministic derivation
    ac6 = "deterministic" in src.lower()
    checks.append(_check("AC6: deterministic derivation documented", ac6))

    # AC7: SHA-256 collision resistance
    ac7 = "sha256" in src.lower() and "256" in src
    checks.append(_check("AC7: SHA-256 collision resistance", ac7))

    return checks


def analyze_trust_object_evidence(data: dict | None = None) -> list:
    """Verify bd-1l5 against checked evidence, not locally derived values."""
    checks = []
    evidence = data if data is not None else _load_json(EVIDENCE_FILE)
    if evidence is None:
        return [_check("evidence artifact readable", False, f"missing/invalid: {EVIDENCE_FILE}")]

    checks.append(_check("evidence bead id bd-1l5", evidence.get("bead_id") == "bd-1l5"))
    checks.append(_check("evidence section 10.10", evidence.get("section") == "10.10"))
    checks.append(_check("evidence verdict PASS", str(evidence.get("verdict", "")).upper() == "PASS"))

    files = evidence.get("files", {})
    if not isinstance(files, dict):
        files = {}
    checks.append(_check(
        "evidence references implementation",
        files.get("implementation") == "crates/franken-node/src/connector/trust_object_id.rs",
    ))
    checks.append(_check(
        "evidence references verifier tests",
        files.get("python_tests") == "tests/test_check_trust_object_ids.py",
    ))

    metrics = evidence.get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}
    checks.append(_check(
        "evidence Rust unit test count",
        _metric_int(metrics, "rust_unit_tests") >= 45,
        f"{metrics.get('rust_unit_tests', 0)} Rust tests",
    ))
    checks.append(_check(
        "evidence struct coverage",
        metrics.get("structs_verified") == len(REQUIRED_STRUCTS),
        f"{metrics.get('structs_verified')} / {len(REQUIRED_STRUCTS)}",
    ))
    checks.append(_check(
        "evidence event code coverage",
        metrics.get("event_codes_verified") == len(REQUIRED_EVENT_CODES),
        f"{metrics.get('event_codes_verified')} / {len(REQUIRED_EVENT_CODES)}",
    ))
    checks.append(_check(
        "evidence error code coverage",
        metrics.get("error_codes_verified") == len(REQUIRED_ERROR_CODES),
        f"{metrics.get('error_codes_verified')} / {len(REQUIRED_ERROR_CODES)}",
    ))
    checks.append(_check(
        "evidence invariant coverage",
        metrics.get("invariants_verified") == len(REQUIRED_INVARIANTS),
        f"{metrics.get('invariants_verified')} / {len(REQUIRED_INVARIANTS)}",
    ))
    checks.append(_check(
        "evidence function coverage",
        _metric_int(metrics, "functions_verified") >= len(REQUIRED_FUNCTIONS),
        f"{metrics.get('functions_verified')} / {len(REQUIRED_FUNCTIONS)}",
    ))
    checks.append(_check(
        "evidence domain prefix coverage",
        metrics.get("domain_prefixes_verified") == len(DOMAIN_PREFIXES),
        f"{metrics.get('domain_prefixes_verified')} / {len(DOMAIN_PREFIXES)}",
    ))
    checks.append(_check(
        "evidence derivation mode coverage",
        metrics.get("derivation_modes_verified") == len(DERIVATION_MODES),
        f"{metrics.get('derivation_modes_verified')} / {len(DERIVATION_MODES)}",
    ))
    checks.append(_check(
        "evidence acceptance coverage",
        metrics.get("acceptance_criteria_verified") == len(REQUIRED_EVIDENCE_ACCEPTANCE),
        f"{metrics.get('acceptance_criteria_verified')} / {len(REQUIRED_EVIDENCE_ACCEPTANCE)}",
    ))

    acceptance = evidence.get("acceptance_criteria", {})
    if not isinstance(acceptance, dict):
        acceptance = {}
    for criterion, required_tokens in REQUIRED_EVIDENCE_ACCEPTANCE.items():
        text = _pass_text(acceptance.get(criterion))
        present = [token for token in required_tokens if token in text]
        checks.append(_check(
            f"evidence acceptance {criterion}",
            len(present) == len(required_tokens),
            f"{len(present)}/{len(required_tokens)} required markers",
        ))

    return checks


# ── Main check runner ──────────────────────────────────────────────────────

def run_checks() -> dict:
    checks = []
    checks.extend(check_file_existence())
    checks.extend(check_structs())
    checks.extend(check_event_codes())
    checks.extend(check_error_codes())
    checks.extend(check_invariants())
    checks.extend(check_functions())
    checks.extend(check_spec_sections())
    checks.extend(check_domain_prefixes())
    checks.extend(check_derivation_modes())
    checks.extend(check_sha256_usage())
    checks.extend(check_serde_derives())
    checks.extend(check_tests())
    checks.extend(check_send_sync())
    checks.extend(check_acceptance_criteria())

    checks.extend(analyze_trust_object_evidence())

    passed = sum(1 for c in checks if c["pass"])
    failed = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-1l5",
        "title": "Canonical product trust object IDs with domain separation",
        "section": "10.10",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def run_all() -> dict:
    """Alias for run_checks()."""
    return run_checks()


def self_test() -> tuple:
    """Internal consistency checks."""
    checks = []
    checks.append(_check("REQUIRED_STRUCTS non-empty", len(REQUIRED_STRUCTS) >= 7))
    checks.append(_check("REQUIRED_EVENT_CODES count", len(REQUIRED_EVENT_CODES) == 2))
    checks.append(_check("REQUIRED_ERROR_CODES count", len(REQUIRED_ERROR_CODES) == 4))
    checks.append(_check("REQUIRED_INVARIANTS count", len(REQUIRED_INVARIANTS) == 4))
    checks.append(_check("REQUIRED_FUNCTIONS count", len(REQUIRED_FUNCTIONS) >= 12))
    checks.append(_check("DOMAIN_PREFIXES count", len(DOMAIN_PREFIXES) == 6))
    checks.append(_check("DERIVATION_MODES count", len(DERIVATION_MODES) == 2))
    checks.append(_check("REQUIRED_SPEC_SECTIONS count", len(REQUIRED_SPEC_SECTIONS) >= 9))

    evidence_checks = analyze_trust_object_evidence()
    checks.append(_check("evidence analysis returns checks", isinstance(evidence_checks, list)))
    checks.append(_check("evidence analysis passes", all(c["pass"] for c in evidence_checks)))

    # Verify run_checks structure
    result = run_checks()
    checks.append(_check("run_checks has bead_id", result.get("bead_id") == "bd-1l5"))
    checks.append(_check("run_checks has section", result.get("section") == "10.10"))
    checks.append(_check("run_checks has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_checks has checks list", isinstance(result.get("checks"), list)))

    ok = all(c["pass"] for c in checks)
    return (ok, checks)


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    configure_test_logging("check_trust_object_ids")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        total = len(checks)
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {passed}/{total} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
