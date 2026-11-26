"""Unit tests for scripts/run_test262_slice.py (bd-reality-20260923-26n9r.6)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "run_test262_slice.py"
SPEC = importlib.util.spec_from_file_location("run_test262_slice", str(SCRIPT))
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def test_parse_frontmatter_extracts_flags_includes_and_negative() -> None:
    src = """// header
/*---
description: parse negative syntax test
flags: [onlyStrict, async]
includes: [compareArray.js]
negative:
  phase: parse
  type: SyntaxError
---*/
$DONOTEVALUATE();
{ 1 2 } 3
"""
    meta = MOD.parse_frontmatter(src)
    assert meta is not None
    assert meta["flags"] == ["onlyStrict", "async"]
    assert meta["includes"] == ["compareArray.js"]
    assert meta["negative"] == {"phase": "parse", "type": "SyntaxError"}


def test_negative_test_rejects_cli_panic_capability_and_frozen_module_refusals() -> None:
    case = {
        "flags": [],
        "negative": {"phase": "parse", "type": "SyntaxError"},
    }
    # CLI exit-2 usage error MUST NOT count as a passing negative SyntaxError.
    passed, detail = MOD.evaluate_outcome(
        case, 2, "", "error: invalid value '/abs/path.js' for '[APP_PATH]'", False
    )
    assert not passed
    assert detail == "invalid_negative_failure:cli_or_harness_error"

    # Panic MUST NOT count as a passing negative test.
    passed, detail = MOD.evaluate_outcome(
        case, 101, "", "thread 'main' panicked at 'boom'", False
    )
    assert not passed
    assert detail == "invalid_negative_failure:panic"

    # Capability/policy denial MUST NOT count as a passing negative test.
    passed, detail = MOD.evaluate_outcome(
        case, 1, "", "Capability denied: fs.read refused by preflight", False
    )
    assert not passed
    assert detail == "invalid_negative_failure:capability_or_policy_denied"

    # Frozen module static graph refusal stays distinct from SyntaxError.
    passed, detail = MOD.evaluate_outcome(
        case,
        1,
        "",
        "Frozen module source admission failed: ERR_MODULE_REGISTRY_INCOMPLETE",
        False,
    )
    assert not passed
    assert detail == "negative_mismatch:expected_SyntaxError_got_frozen_module_registry_incomplete"

    # Genuine engine parse error matches SyntaxError cleanly.
    passed, detail = MOD.evaluate_outcome(
        case,
        1,
        "",
        "Native execution failed: parse: unexpected token `2`",
        False,
    )
    assert passed
    assert detail == "negative_matched:parse:SyntaxError"


def test_positive_async_requires_done_sentinel() -> None:
    case = {"flags": ["async"], "negative": None}
    passed, detail = MOD.evaluate_outcome(case, 0, "hello\n", "", False)
    assert not passed
    assert detail == "async_missing_done_sentinel"

    passed, detail = MOD.evaluate_outcome(
        case, 0, f"ok\n{MOD.ASYNC_DONE_SENTINEL}\n", "", False
    )
    assert passed
    assert detail == "ok"


def test_committed_test262_slice_artifact_schema_and_provenance() -> None:
    import json

    summary_path = ROOT / "artifacts" / "compat" / "test262_language_slice.json"
    jsonl_path = ROOT / "artifacts" / "compat" / "test262_language_slice_cases.jsonl"
    assert summary_path.is_file()
    assert jsonl_path.is_file()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["schema_version"] == "franken-node/test262-language-slice/v1"
    assert summary["full_suite_claim_allowed"] is False
    assert summary["totals"]["executed"] >= 1000
    assert summary["provenance"]["test262_commit"] == MOD.DEFAULT_PINNED_COMMIT
    assert len(summary["provenance"]["franken_node_git_sha"]) == 40
    assert len(summary["provenance"]["franken_engine_commit"]) == 40

    rows = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(rows) == summary["totals"]["executed"]
    assert len({r["test_id"] for r in rows}) == len(rows)
    assert sum(1 for r in rows if r["franken_pass"]) == summary["totals"]["franken_passed"]
    assert sum(1 for r in rows if r["node_pass"]) == summary["totals"]["node_passed"]
