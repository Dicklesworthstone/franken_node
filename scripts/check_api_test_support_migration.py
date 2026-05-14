#!/usr/bin/env python3
"""bd-2mt88.1: API test-support migration path verification gate."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BEAD_ID = "bd-2mt88.1"
PARENT_BEAD_ID = "bd-2mt88"
DOC = ROOT / "docs/policy/api_test_support_migration.md"
CARGO = ROOT / "crates/franken-node/Cargo.toml"
LIB_RS = ROOT / "crates/franken-node/src/lib.rs"
API_MOD = ROOT / "crates/franken-node/src/api/mod.rs"
MIDDLEWARE = ROOT / "crates/franken-node/src/api/middleware.rs"
FLEET_QUARANTINE = ROOT / "crates/franken-node/src/api/fleet_quarantine.rs"
BEADS_JSONL = ROOT / ".beads/issues.jsonl"

API_FILES = [API_MOD, MIDDLEWARE, FLEET_QUARANTINE]

DOC_REQUIRED_TOKENS = [
    "bd-2mt88",
    "bd-2mt88.1",
    "f3aa5372",
    "test-support",
    "control-plane",
    "extended-surfaces",
    "operator_routes",
    "session_auth",
    "middleware",
    "fleet_quarantine",
    "QuarantineRequest",
    "RevokeRequest",
    "quarantine_route_metadata",
    "StatusRequest",
    "Do not rely on `test-support` as the API feature.",
    "scripts/check_api_test_support_migration.py",
]


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _check(name: str, passed: bool, detail: object = "") -> dict:
    return {"check": name, "passed": bool(passed), "detail": detail}


def _api_test_support_refs() -> list[dict]:
    refs = []
    for path in API_FILES:
        for line_no, line in enumerate(_read(path).splitlines(), start=1):
            if 'feature = "test-support"' in line:
                refs.append(
                    {
                        "file": _rel(path),
                        "line": line_no,
                        "text": line.strip(),
                    }
                )
    return refs


def _line_window(path: Path, line_no: int, radius: int = 4) -> str:
    lines = _read(path).splitlines()
    start = max(0, line_no - 1)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _bead_record() -> dict:
    for raw_line in _read(BEADS_JSONL).splitlines():
        if f'"id":"{BEAD_ID}"' not in raw_line:
            continue
        try:
            return json.loads(raw_line)
        except json.JSONDecodeError:
            return {"parse_error": True}
    return {}


def _checks() -> list[dict]:
    doc = _read(DOC)
    cargo = _read(CARGO)
    lib_rs = _read(LIB_RS)
    api_mod = _read(API_MOD)
    middleware = _read(MIDDLEWARE)
    fleet_quarantine = _read(FLEET_QUARANTINE)
    refs = _api_test_support_refs()
    bead = _bead_record()
    close_reason = str(bead.get("close_reason", ""))

    checks = [
        _check("doc_exists", DOC.is_file(), _rel(DOC)),
        _check(
            "doc_required_terms",
            all(token in doc for token in DOC_REQUIRED_TOKENS),
            [token for token in DOC_REQUIRED_TOKENS if token not in doc],
        ),
        _check(
            "cargo_test_support_composes_control_plane",
            'test-support = ["control-plane", "admin-tools"]' in cargo,
            _rel(CARGO),
        ),
        _check(
            "api_namespace_owned_by_control_plane",
            '#[cfg(feature = "control-plane")]\npub mod api;' in lib_rs,
            _rel(LIB_RS),
        ),
        _check(
            "api_mod_wiring_is_not_test_support_gated",
            "pub mod operator_routes;" in api_mod
            and "pub mod session_auth;" in api_mod
            and 'feature = "test-support"' not in api_mod,
            _rel(API_MOD),
        ),
        _check(
            "middleware_has_no_direct_test_support_gate",
            'feature = "test-support"' not in middleware,
            _rel(MIDDLEWARE),
        ),
        _check(
            "fleet_mutating_requests_are_control_plane_owned",
            '#[cfg(any(test, feature = "control-plane"))]\n#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\npub struct QuarantineRequest'
            in fleet_quarantine
            and '#[cfg(any(test, feature = "control-plane"))]\n#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\npub struct RevokeRequest'
            in fleet_quarantine,
            _rel(FLEET_QUARANTINE),
        ),
        _check(
            "fleet_route_metadata_is_control_plane_owned",
            '#[cfg(any(test, feature = "control-plane"))]\n/// # Examples\n/// ```ignore\n/// let routes = quarantine_route_metadata();'
            in fleet_quarantine,
            _rel(FLEET_QUARANTINE),
        ),
        _check(
            "direct_api_test_support_refs_limited",
            len(refs) == 1
            and refs[0]["file"] == _rel(FLEET_QUARANTINE)
            and refs[0]["line"] > 0,
            refs,
        ),
    ]

    if refs:
        remaining_ref_window = _line_window(ROOT / refs[0]["file"], int(refs[0]["line"]))
    else:
        remaining_ref_window = ""
    checks.append(
        _check(
            "remaining_direct_ref_is_status_request",
            "pub struct StatusRequest" in remaining_ref_window,
            remaining_ref_window,
        )
    )
    checks.append(
        _check(
            "doc_explains_remaining_status_request",
            "read-only `GET /v1/fleet/status`" in doc
            and "It is not a precedent for adding new direct `test-support` API gates." in doc,
            _rel(DOC),
        )
    )
    checks.append(
        _check(
            "doc_has_downstream_migration_rules",
            "features = [\"control-plane\"]" in doc
            and "features = [\"extended-surfaces\"]" in doc
            and "`features = [\"test-support\"]` only for repository harness utilities" in doc,
            _rel(DOC),
        )
    )
    checks.append(
        _check(
            "bead_record_present",
            bool(bead) and not bead.get("parse_error"),
            BEAD_ID,
        )
    )
    checks.append(
        _check(
            "bead_closed",
            bead.get("status") == "closed",
            bead.get("status"),
        )
    )
    checks.append(
        _check(
            "close_reason_documents_migration_path",
            BEAD_ID in close_reason
            and _rel(DOC) in close_reason
            and "scripts/check_api_test_support_migration.py" in close_reason,
            close_reason,
        )
    )
    return checks


def self_test() -> bool:
    results = _checks()
    assert len(results) >= 15
    for result in results:
        assert "check" in result
        assert "passed" in result
        assert "detail" in result
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_api_test_support_migration")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test()
        return

    results = _checks()
    passed = sum(1 for result in results if result["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"
    payload = {
        "bead_id": BEAD_ID,
        "parent_bead_id": PARENT_BEAD_ID,
        "gate_script": "scripts/check_api_test_support_migration.py",
        "checks_passed": passed,
        "checks_total": total,
        "verdict": verdict,
        "checks": results,
    }

    logger.info(
        "api test-support migration gate complete",
        extra={"checks_passed": passed, "checks_total": total, "verdict": verdict},
    )
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        for result in results:
            status = "PASS" if result["passed"] else "FAIL"
            print(f"  [{status}] {result['check']}: {result['detail']}")
        print(f"\n{BEAD_ID}: {passed}/{total} checks - {verdict}")
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
