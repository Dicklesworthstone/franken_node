#!/usr/bin/env python3
"""bd-vll verification: deterministic incident replay bundle generation."""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "tools" / "replay_bundle.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
MAIN_RS = ROOT / "crates" / "franken-node" / "src" / "main.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_5" / "bd-vll_contract.md"
FIXTURE = ROOT / "fixtures" / "interop" / "interop_test_vectors.json"

MAX_BUNDLE_BYTES = 10 * 1024 * 1024

REQUIRED_IMPL_PATTERNS = [
    "pub struct ReplayBundle",
    "pub struct TimelineEvent",
    "pub struct BundleManifest",
    "pub struct BundleChunk",
    "pub fn generate_replay_bundle(",
    "pub fn validate_bundle_integrity(",
    "pub fn replay_bundle(",
    "INV-RB-DETERMINISTIC",
]


def canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: canonical(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [canonical(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(canonical(value), separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_rfc3339(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def normalize_rfc3339(ts: str) -> str:
    dt = parse_rfc3339(ts).astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def load_fixture_vectors() -> list[dict[str, Any]]:
    data = json.loads(FIXTURE.read_text())
    return data.get("test_vectors", [])


def fixture_to_events(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    base = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    event_types = ["external_signal", "policy_eval", "state_change", "operator_action"]
    events = []
    for idx, item in enumerate(vectors):
        ts = base + timedelta(microseconds=idx + 1)
        events.append(
            {
                "timestamp": ts.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                "event_type": event_types[idx % len(event_types)],
                "payload": {
                    "case_id": item.get("case_id"),
                    "class": item.get("class"),
                    "input": item.get("input"),
                    "expected_output": item.get("expected_output"),
                },
                "causal_parent": idx if idx > 0 else None,
            }
        )
    return events


def chunk_events(bundle_id: str, timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not timeline:
        return [
            {
                "bundle_id": bundle_id,
                "chunk_index": 0,
                "total_chunks": 1,
                "event_count": 0,
                "first_sequence_number": 0,
                "last_sequence_number": 0,
                "compressed_size_bytes": 0,
                "chunk_hash": sha256_hex(b"[]"),
                "events": [],
            }
        ]

    buckets: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_size = 2
    for event in timeline:
        payload = canonical_json(event).encode("utf-8")
        extra = len(payload) + (1 if current else 0)
        if current and current_size + extra > MAX_BUNDLE_BYTES:
            buckets.append(current)
            current = []
            current_size = 2
        current.append(event)
        current_size += extra
    if current:
        buckets.append(current)

    total = len(buckets)
    chunks = []
    for idx, events in enumerate(buckets):
        event_bytes = canonical_json(events).encode("utf-8")
        chunks.append(
            {
                "bundle_id": bundle_id,
                "chunk_index": idx,
                "total_chunks": total,
                "event_count": len(events),
                "first_sequence_number": events[0]["sequence_number"],
                "last_sequence_number": events[-1]["sequence_number"],
                "compressed_size_bytes": len(gzip.compress(event_bytes)),
                "chunk_hash": sha256_hex(event_bytes),
                "events": events,
            }
        )
    return chunks


def generate_sample_bundle(incident_id: str, vectors: list[dict[str, Any]]) -> dict[str, Any]:
    events = fixture_to_events(vectors)
    timeline = []
    for idx, event in enumerate(events, start=1):
        timeline.append(
            {
                "sequence_number": idx,
                "timestamp": normalize_rfc3339(event["timestamp"]),
                "event_type": event["event_type"],
                "payload": canonical(event["payload"]),
                "causal_parent": event["causal_parent"] if event["causal_parent"] and event["causal_parent"] < idx else None,
            }
        )

    created_at = timeline[-1]["timestamp"] if timeline else "1970-01-01T00:00:00.000000Z"
    initial_snapshot = {
        "epoch": 1,
        "hardening_level": "standard",
        "active_policies": ["strict-revocation"],
    }
    policy_version = "1.0.0"

    timeline_bytes = canonical_json(timeline).encode("utf-8")
    sequence_hash = sha256_hex(
        canonical_json(
            {
                "timeline": timeline,
                "initial_state_snapshot": initial_snapshot,
                "policy_version": policy_version,
            }
        ).encode("utf-8")
    )
    seed = sha256_hex(
        canonical_json(
            {"incident_id": incident_id, "created_at": created_at, "timeline": timeline}
        ).encode("utf-8")
    )
    bundle_id = f"v7-{seed[:32]}"
    chunks = chunk_events(bundle_id, timeline)
    first_ts = timeline[0]["timestamp"] if timeline else None
    last_ts = timeline[-1]["timestamp"] if timeline else None
    span_us = 0
    if first_ts and last_ts:
        span_us = int((parse_rfc3339(last_ts) - parse_rfc3339(first_ts)).total_seconds() * 1_000_000)

    bundle = {
        "bundle_id": bundle_id,
        "incident_id": incident_id,
        "created_at": created_at,
        "timeline": timeline,
        "initial_state_snapshot": initial_snapshot,
        "policy_version": policy_version,
        "manifest": {
            "event_count": len(timeline),
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "time_span_micros": span_us,
            "compressed_size_bytes": len(gzip.compress(timeline_bytes)),
            "chunk_count": len(chunks),
            "decision_sequence_hash": sequence_hash,
        },
        "chunks": chunks,
        "integrity_hash": "",
    }
    integrity_source = dict(bundle)
    integrity_source.pop("integrity_hash", None)
    bundle["integrity_hash"] = sha256_hex(canonical_json(integrity_source).encode("utf-8"))
    return bundle


def validate_sample_bundle_integrity(bundle: dict[str, Any]) -> bool:
    copy = dict(bundle)
    expected = copy.pop("integrity_hash", "")
    actual = sha256_hex(canonical_json(copy).encode("utf-8"))
    return expected == actual


def check_file(path: Path, label: str) -> dict[str, Any]:
    ok = path.is_file()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"missing: {path}",
    }


def check_contains(path: Path, patterns: list[str], label: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return [{"check": f"{label}: {p}", "pass": False, "detail": "file missing"} for p in patterns]
    content = path.read_text()
    checks = []
    for pattern in patterns:
        checks.append(
            {
                "check": f"{label}: {pattern}",
                "pass": pattern in content,
                "detail": "found" if pattern in content else "not found",
            }
        )
    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(IMPL, "replay bundle implementation"))
    checks.append(check_file(SPEC, "contract"))
    checks.append(check_file(FIXTURE, "interop fixture"))
    checks.extend(check_contains(IMPL, REQUIRED_IMPL_PATTERNS, "impl"))
    checks.extend(check_contains(MOD_RS, ["pub mod replay_bundle;"], "module wiring"))
    checks.extend(
        check_contains(
            MAIN_RS,
            [
                "generate_replay_bundle",
                "read_bundle_from_path",
                "incident bundle written",
                "incident replay result",
            ],
            "cli wiring",
        )
    )

    vectors = load_fixture_vectors() if FIXTURE.is_file() else []
    fixture_ok = len(vectors) > 0
    checks.append(
        {
            "check": "fixture vectors",
            "pass": fixture_ok,
            "detail": f"vectors={len(vectors)}",
        }
    )

    if fixture_ok:
        bundle_a = generate_sample_bundle("INC-SAMPLE-001", vectors)
        bundle_b = generate_sample_bundle("INC-SAMPLE-001", vectors)
        deterministic = canonical_json(bundle_a) == canonical_json(bundle_b)
        integrity_ok = validate_sample_bundle_integrity(bundle_a)
        checks.append(
            {
                "check": "sample determinism",
                "pass": deterministic,
                "detail": "bundle A == bundle B",
            }
        )
        checks.append(
            {
                "check": "sample integrity",
                "pass": integrity_ok,
                "detail": "integrity hash recomputes",
            }
        )

    passed = sum(1 for check in checks if check["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-vll",
        "title": "Deterministic incident replay bundle generation",
        "section": "10.5",
        "verdict": "PASS" if passed == total else "FAIL",
        "overall_pass": passed == total,
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    result = run_checks()
    return result["verdict"] == "PASS", result["checks"]


def main() -> None:
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'} ({len(checks)} checks)")
        raise SystemExit(0 if ok else 1)

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-vll: replay bundle verification ===")
        print(f"Verdict: {result['verdict']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    raise SystemExit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
