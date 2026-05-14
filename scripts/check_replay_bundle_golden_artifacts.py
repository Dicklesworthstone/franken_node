#!/usr/bin/env python3
"""bd-1vier.1: verify replay bundle golden artifact registration."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BEAD_ID = "bd-1vier.1"
PARENT_BEAD_ID = "bd-1vier"
CARGO = ROOT / "crates/franken-node/Cargo.toml"
TEST_FILE = ROOT / "crates/franken-node/tests/replay_bundle_golden_artifacts.rs"
GOLDEN_FILE = ROOT / "crates/franken-node/tests/golden/replay_bundle/canonical_small_fixture.golden"
BEADS_JSONL = ROOT / ".beads/issues.jsonl"

REQUIRED_TESTS = [
    "replay_bundle_canonical_json_golden",
    "replay_bundle_determinism_verification",
    "replay_bundle_structure_golden",
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


def _git_tracked(path: Path) -> bool:
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", _rel(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0


def _bead_record() -> dict:
    for raw_line in _read(BEADS_JSONL).splitlines():
        if f'"id":"{BEAD_ID}"' not in raw_line:
            continue
        try:
            return json.loads(raw_line)
        except json.JSONDecodeError:
            return {"parse_error": True}
    return {}


def _canonical_test_body(src: str) -> str:
    marker = "fn replay_bundle_canonical_json_golden()"
    start = src.find(marker)
    if start < 0:
        return ""
    next_test = src.find("#[test]", start + len(marker))
    return src[start:] if next_test < 0 else src[start:next_test]


def _checks() -> list[dict]:
    cargo = _read(CARGO)
    test_src = _read(TEST_FILE)
    golden = _read(GOLDEN_FILE)
    bead = _bead_record()
    close_reason = str(bead.get("close_reason", ""))
    canonical_body = _canonical_test_body(test_src)

    checks = [
        _check(
            "cargo_target_registered",
            'name = "replay_bundle_golden_artifacts"' in cargo
            and 'path = "tests/replay_bundle_golden_artifacts.rs"' in cargo,
            _rel(CARGO),
        ),
        _check("test_file_exists", TEST_FILE.is_file(), _rel(TEST_FILE)),
        _check("test_file_tracked", _git_tracked(TEST_FILE), _rel(TEST_FILE)),
        _check("golden_file_exists", GOLDEN_FILE.is_file(), _rel(GOLDEN_FILE)),
        _check("golden_file_tracked", _git_tracked(GOLDEN_FILE), _rel(GOLDEN_FILE)),
        _check("golden_file_non_empty", len(golden.strip()) > 100, len(golden.strip())),
        _check(
            "test_includes_checked_in_golden",
            'include_str!("golden/replay_bundle/canonical_small_fixture.golden")' in test_src
            and "CANONICAL_SMALL_FIXTURE_GOLDEN" in test_src,
            _rel(TEST_FILE),
        ),
        _check(
            "canonical_test_compares_actual_to_golden",
            "scrubbed_json" in canonical_body
            and "assert_eq!" in canonical_body
            and "CANONICAL_SMALL_FIXTURE_GOLDEN" in canonical_body,
            _rel(TEST_FILE),
        ),
        _check(
            "canonical_test_not_inline_empty_snapshot",
            "assert_snapshot!" not in canonical_body
            and "assert_json_snapshot!" not in canonical_body
            and '@""' not in canonical_body,
            _rel(TEST_FILE),
        ),
        _check(
            "required_tests_present",
            all(f"fn {name}()" in test_src for name in REQUIRED_TESTS),
            [name for name in REQUIRED_TESTS if f"fn {name}()" not in test_src],
        ),
        _check(
            "golden_has_replay_bundle_shape",
            all(token in golden for token in ["bundle_id", "timeline", "integrity_hash", "INC-GOLDEN-TEST-001"]),
            _rel(GOLDEN_FILE),
        ),
        _check("bead_record_present", bool(bead) and not bead.get("parse_error"), BEAD_ID),
        _check("bead_closed", bead.get("status") == "closed", bead.get("status")),
        _check(
            "close_reason_documents_artifacts",
            BEAD_ID in close_reason
            and _rel(TEST_FILE) in close_reason
            and _rel(GOLDEN_FILE) in close_reason
            and "scripts/check_replay_bundle_golden_artifacts.py" in close_reason,
            close_reason,
        ),
    ]
    return checks


def self_test() -> bool:
    results = _checks()
    assert len(results) >= 14
    for result in results:
        assert "check" in result
        assert "passed" in result
        assert "detail" in result
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_replay_bundle_golden_artifacts")
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
        "gate_script": "scripts/check_replay_bundle_golden_artifacts.py",
        "checks_passed": passed,
        "checks_total": total,
        "verdict": verdict,
        "checks": results,
    }
    logger.info(
        "replay bundle golden artifact gate complete",
        extra={"checks_passed": passed, "checks_total": total, "verdict": verdict},
    )
    if "--json" in sys.argv:
        print(json.dumps(payload, indent=2))
    else:
        for result in results:
            status = "PASS" if result["passed"] else "FAIL"
            print(f"  [{status}] {result['check']}: {result['detail']}")
        print(f"\n{BEAD_ID}: {passed}/{total} checks - {verdict}")
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
