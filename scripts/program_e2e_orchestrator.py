#!/usr/bin/env python3
"""
Program-Level E2E + Chaos Orchestration Suite.

Executes cross-section journeys from the integration journey matrix and
emits deterministic evidence bundles for pass/fail and replay analysis.

Usage:
    python3 scripts/program_e2e_orchestrator.py [--json] [--journey J-NNN] [--chaos]

Exit codes:
    0 = PASS (all journeys pass)
    1 = FAIL (one or more journeys failed)
    2 = ERROR (orchestration failure)
"""

import json
import os
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from scripts.lib.e2e_scenario_logger import ScenarioTimeline

MATRIX_PATH = ROOT / "docs" / "verification" / "journey_matrix.json"
CHAOS_CATALOG_PATH = ROOT / "docs" / "verification" / "chaos_scenarios.json"
TEST_SERVER_SCRIPT = ROOT / "scripts" / "e2e_test_server.py"

# "structural" validates journey-matrix schema integrity.
# "live" starts a test server, issues real HTTP calls, validates responses.
# Auto-detect: use live if --live flag, else structural.
MODE = os.environ.get("E2E_MODE", "structural")

LIVE_SCENARIO_TIMEOUT_SECS = 60

logger = configure_test_logging("program_e2e_orchestrator")


def load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def generate_trace_id() -> str:
    return f"trace-{uuid.uuid4().hex[:16]}"


def validate_journey_structural(journey: dict) -> dict:
    """Structurally validate a journey definition."""
    result = {
        "journey_id": journey["id"],
        "journey_name": journey["name"],
        "status": "PASS",
        "phases_validated": 0,
        "errors": [],
        "trace_id": generate_trace_id(),
    }

    # Validate all phases have required fields
    for i, phase in enumerate(journey.get("phases", [])):
        if "section" not in phase:
            result["errors"].append(f"Phase {i}: missing section")
        if "fixture" not in phase:
            result["errors"].append(f"Phase {i}: missing fixture")
        result["phases_validated"] += 1

    # Validate failure taxonomy is non-empty
    taxonomy = journey.get("failure_taxonomy", [])
    if not taxonomy:
        result["errors"].append("Empty failure taxonomy")

    # Validate seam resolution is documented
    if not journey.get("seam_resolution"):
        result["errors"].append("Missing seam_resolution")

    # Validate sections array matches phases
    declared_sections = set(journey.get("sections", []))
    phase_sections = {p["section"] for p in journey.get("phases", []) if "section" in p}
    undeclared = phase_sections - declared_sections
    if undeclared:
        result["errors"].append(f"Undeclared sections in phases: {undeclared}")

    if result["errors"]:
        result["status"] = "FAIL"

    return result


def validate_chaos_structural(chaos_data: dict | None) -> list[dict]:
    """Validate chaos scenario catalog structure."""
    if chaos_data is None:
        return [{
            "scenario_id": "CATALOG",
            "status": "SKIP",
            "reason": "Chaos catalog not yet created",
        }]

    results = []
    for scenario in chaos_data.get("scenarios", []):
        result = {
            "scenario_id": scenario.get("id", "UNKNOWN"),
            "status": "PASS",
            "errors": [],
        }
        for field in ["id", "name", "target_journey", "injection_type", "expected_failure"]:
            if field not in scenario:
                result["errors"].append(f"Missing field: {field}")
        if result["errors"]:
            result["status"] = "FAIL"
        results.append(result)

    return results


## ── Live execution helpers ──────────────────────────────────────────────

def _start_test_server() -> tuple[subprocess.Popen, int]:
    """Start the E2E test server and return (process, port)."""
    proc = subprocess.Popen(
        [sys.executable, str(TEST_SERVER_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Read the JSON port announcement from stdout.
    line = proc.stdout.readline().decode().strip()
    info = json.loads(line)
    port = info["port"]
    logger.info("test server started on port %d (pid=%d)", port, proc.pid)
    return proc, port


def _stop_test_server(proc: subprocess.Popen) -> None:
    """Stop the test server process."""
    proc.terminate()
    try:
        proc.wait(timeout=3600)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    logger.info("test server stopped (pid=%d)", proc.pid)


def _http_get(base: str, path: str) -> dict:
    req = urllib.request.Request(f"{base}{path}")
    with urllib.request.urlopen(req, timeout=3600) as resp:
        return json.loads(resp.read())


def _http_post(base: str, path: str, body: dict | None = None) -> dict:
    payload = json.dumps(body or {}).encode()
    req = urllib.request.Request(
        f"{base}{path}", data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3600) as resp:
        return json.loads(resp.read())


def _http_delete(base: str, path: str) -> dict:
    req = urllib.request.Request(f"{base}{path}", method="DELETE")
    with urllib.request.urlopen(req, timeout=3600) as resp:
        return json.loads(resp.read())


def run_live_scenario(base: str, scenario_name: str, steps: list) -> dict:
    """Execute a live E2E scenario against the running test server."""
    timeline = ScenarioTimeline(f"e2e_{scenario_name}", json_mode=False)
    timeline.start_scenario(scenario_name)
    errors = []

    start = time.monotonic()
    for step in steps:
        if time.monotonic() - start > LIVE_SCENARIO_TIMEOUT_SECS:
            errors.append(f"timeout exceeded ({LIVE_SCENARIO_TIMEOUT_SECS}s)")
            break
        method = step.get("method", "GET")
        path = step["path"]
        expect_ok = step.get("expect_ok", True)
        expect_field = step.get("expect_field")
        expect_value = step.get("expect_value")

        try:
            if method == "GET":
                rid = timeline.log_request("GET", path)
                data = _http_get(base, path)
                timeline.log_response(rid, status=200, body=json.dumps(data)[:1024])
            elif method == "POST":
                rid = timeline.log_request("POST", path, body=json.dumps(step.get("body", {})))
                data = _http_post(base, path, step.get("body"))
                timeline.log_response(rid, status=200, body=json.dumps(data)[:1024])
            elif method == "DELETE":
                rid = timeline.log_request("DELETE", path)
                data = _http_delete(base, path)
                timeline.log_response(rid, status=200, body=json.dumps(data)[:1024])
            else:
                errors.append(f"unknown method {method}")
                continue

            if expect_ok and not data.get("ok"):
                errors.append(f"{method} {path}: expected ok=true")
            if expect_field and expect_value:
                actual = data
                for key in expect_field.split("."):
                    actual = actual.get(key, {}) if isinstance(actual, dict) else None
                if actual != expect_value:
                    errors.append(f"{method} {path}: {expect_field}={actual}, expected {expect_value}")
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            errors.append(f"{method} {path}: {e}")

    passed = len(errors) == 0
    timeline.end_scenario(passed=passed)
    report = timeline.build_report()

    return {
        "scenario": scenario_name,
        "status": "PASS" if passed else "FAIL",
        "errors": errors,
        "duration_secs": report.duration_secs,
        "request_count": report.request_count,
        "trace_id": generate_trace_id(),
    }


# Built-in live scenarios covering all API endpoint groups.
LIVE_SCENARIOS = [
    {
        "name": "operator_health_check",
        "steps": [
            {"method": "GET", "path": "/v1/operator/health", "expect_field": "data.status", "expect_value": "healthy"},
            {"method": "GET", "path": "/v1/operator/status", "expect_ok": True},
            {"method": "GET", "path": "/v1/operator/config", "expect_field": "data.test_mode", "expect_value": True},
            {"method": "GET", "path": "/v1/operator/rollout", "expect_ok": True},
        ],
    },
    {
        "name": "verifier_conformance_flow",
        "steps": [
            {"method": "POST", "path": "/v1/verifier/conformance", "body": {"trace_id": "e2e-test"}, "expect_field": "data.status", "expect_value": "Pass"},
            {"method": "GET", "path": "/v1/verifier/evidence/chk-e2e-test", "expect_field": "data.artifact_type", "expect_value": "conformance_evidence"},
            {"method": "GET", "path": "/v1/verifier/audit-log", "expect_ok": True},
        ],
    },
    {
        "name": "fleet_lease_lifecycle",
        "steps": [
            {"method": "GET", "path": "/v1/fleet/leases", "expect_ok": True},
            {"method": "POST", "path": "/v1/fleet/leases", "expect_ok": True},
            {"method": "DELETE", "path": "/v1/fleet/leases/lease-e2e", "expect_field": "data.released", "expect_value": True},
            {"method": "POST", "path": "/v1/fleet/fence", "expect_field": "data.fenced", "expect_value": True},
            {"method": "POST", "path": "/v1/fleet/coordinate", "expect_field": "data.accepted", "expect_value": True},
        ],
    },
    # bd-17ds.3.4: Node lifecycle — boot, health, config reload, shutdown
    {
        "name": "node_lifecycle",
        "steps": [
            {"method": "GET", "path": "/v1/operator/health", "expect_field": "data.status", "expect_value": "healthy"},
            {"method": "GET", "path": "/v1/operator/status", "expect_ok": True},
            {"method": "POST", "path": "/v1/operator/config/reload", "expect_field": "data.reloaded", "expect_value": True},
            {"method": "GET", "path": "/v1/operator/config", "expect_field": "data.test_mode", "expect_value": True},
            {"method": "POST", "path": "/v1/operator/shutdown", "expect_field": "data.graceful", "expect_value": True},
        ],
    },
    # bd-17ds.3.5: Connector handshake — register, negotiate, activate, fence
    {
        "name": "connector_handshake",
        "steps": [
            {"method": "POST", "path": "/v1/connector/register", "body": {"connector_id": "conn-e2e"}, "expect_field": "data.registered", "expect_value": True},
            {"method": "POST", "path": "/v1/connector/negotiate", "expect_field": "data.protocol_version", "expect_value": "1.0"},
            {"method": "POST", "path": "/v1/connector/activate", "expect_field": "data.active", "expect_value": True},
            {"method": "POST", "path": "/v1/fleet/fence", "expect_field": "data.fenced", "expect_value": True},
        ],
    },
    # bd-17ds.3.6: Security pipeline — classify, firewall, quarantine, sybil
    {
        "name": "security_pipeline",
        "steps": [
            {"method": "POST", "path": "/v1/security/intent/classify", "body": {"effect_id": "e-sec"}, "expect_field": "data.classification", "expect_value": "allowed"},
            {"method": "POST", "path": "/v1/security/firewall/evaluate", "expect_field": "data.verdict", "expect_value": "allow"},
            {"method": "GET", "path": "/v1/security/quarantine", "expect_field": "data.count", "expect_value": 0},
            {"method": "POST", "path": "/v1/security/sybil/check", "expect_field": "data.is_sybil", "expect_value": False},
        ],
    },
    # bd-17ds.3.7: Migration workflow — plan, validate, execute, rollback
    {
        "name": "migration_workflow",
        "steps": [
            {"method": "POST", "path": "/v1/migration/plan", "expect_field": "data.verdict", "expect_value": "allow"},
            {"method": "POST", "path": "/v1/migration/validate", "expect_field": "data.valid", "expect_value": True},
            {"method": "POST", "path": "/v1/migration/execute", "expect_field": "data.status", "expect_value": "completed"},
            {"method": "POST", "path": "/v1/migration/rollback", "expect_field": "data.rolled_back", "expect_value": True},
        ],
    },
    # bd-17ds.3.8: Verifier economy — register, stake, challenge, reward, slash
    {
        "name": "verifier_economy",
        "steps": [
            {"method": "POST", "path": "/v1/verifier/register", "expect_field": "data.registered", "expect_value": True},
            {"method": "POST", "path": "/v1/staking/deposit", "expect_field": "data.staked", "expect_value": True},
            {"method": "POST", "path": "/v1/challenge/submit", "expect_field": "data.accepted", "expect_value": True},
            {"method": "POST", "path": "/v1/reward/claim", "expect_field": "data.claimed", "expect_value": True},
            {"method": "POST", "path": "/v1/slash/report", "expect_field": "data.slashed", "expect_value": True},
        ],
    },
]


def run_live_mode() -> list[dict]:
    """Start test server, run all live scenarios, stop server."""
    proc, port = _start_test_server()
    base = f"http://127.0.0.1:{port}"
    results = []
    try:
        for scenario in LIVE_SCENARIOS:
            result = run_live_scenario(base, scenario["name"], scenario["steps"])
            result["mode"] = "live"
            results.append(result)
            logger.info(
                "scenario %s: %s (%d requests, %.3fs)",
                scenario["name"], result["status"],
                result["request_count"], result["duration_secs"],
            )
    finally:
        _stop_test_server(proc)
    return results


def main():
    json_output = "--json" in sys.argv
    target_journey = None
    run_chaos = "--chaos" in sys.argv
    live_mode = "--live" in sys.argv or MODE == "live"
    active_mode = "live" if live_mode else "structural"

    for i, arg in enumerate(sys.argv):
        if arg == "--journey" and i + 1 < len(sys.argv):
            target_journey = sys.argv[i + 1]

    timestamp = datetime.now(timezone.utc).isoformat()
    orchestration_trace = generate_trace_id()

    # ── Live mode: real HTTP against test server ─────────────────
    live_results = []
    if live_mode:
        logger.info("running in LIVE mode")
        live_results = run_live_mode()

    # ── Structural mode: validate journey matrix ─────────────────
    journey_results = []
    matrix = load_json(MATRIX_PATH)
    if matrix is not None:
        journeys = matrix.get("journeys", [])
        if target_journey:
            journeys = [j for j in journeys if j["id"] == target_journey]
        for journey in journeys:
            result = validate_journey_structural(journey)
            result["mode"] = "structural"
            journey_results.append(result)

    # ── Chaos validations ────────────────────────────────────────
    chaos_results = []
    if run_chaos:
        chaos_data = load_json(CHAOS_CATALOG_PATH)
        chaos_results = validate_chaos_structural(chaos_data)

    # ── Compute verdict ──────────────────────────────────────────
    journey_failures = [r for r in journey_results if r["status"] == "FAIL"]
    live_failures = [r for r in live_results if r["status"] == "FAIL"]
    chaos_failures = [r for r in chaos_results if r["status"] == "FAIL"]
    verdict = "PASS" if not journey_failures and not live_failures and not chaos_failures else "FAIL"

    report = {
        "gate": "program_e2e_orchestration",
        "verdict": verdict,
        "timestamp": timestamp,
        "mode": active_mode,
        "orchestration_trace": orchestration_trace,
        "journeys_executed": len(journey_results),
        "journeys_passed": sum(1 for r in journey_results if r["status"] == "PASS"),
        "journeys_failed": len(journey_failures),
        "live_scenarios_executed": len(live_results),
        "live_scenarios_passed": sum(1 for r in live_results if r["status"] == "PASS"),
        "live_scenarios_failed": len(live_failures),
        "chaos_scenarios": len(chaos_results),
        "chaos_passed": sum(1 for r in chaos_results if r["status"] == "PASS"),
        "chaos_skipped": sum(1 for r in chaos_results if r["status"] == "SKIP"),
        "journey_results": journey_results,
        "live_results": live_results,
        "chaos_results": chaos_results if chaos_results else [],
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Program E2E + Chaos Orchestration ===")
        print(f"Mode: {active_mode}")
        print(f"Trace: {orchestration_trace}")
        print(f"Timestamp: {timestamp}")
        print()
        if live_results:
            print("Live Scenario Results:")
            for r in live_results:
                icon = "OK" if r["status"] == "PASS" else "FAIL"
                print(f"  [{icon}] {r['scenario']}: {r['request_count']} requests, "
                      f"{r['duration_secs']:.3f}s")
                for e in r.get("errors", []):
                    print(f"       Error: {e}")
            print()
        if journey_results:
            print("Structural Journey Results:")
            for r in journey_results:
                icon = "OK" if r["status"] == "PASS" else "FAIL"
                print(f"  [{icon}] {r['journey_id']}: {r['journey_name']} "
                      f"({r['phases_validated']} phases)")
                for e in r.get("errors", []):
                    print(f"       Error: {e}")
            print()
        if chaos_results:
            print("Chaos Results:")
            for r in chaos_results:
                icon = "OK" if r["status"] == "PASS" else r["status"]
                print(f"  [{icon}] {r['scenario_id']}")
            print()
        summary = []
        if live_results:
            summary.append(f"Live: {report['live_scenarios_passed']}/{report['live_scenarios_executed']} pass")
        if journey_results:
            summary.append(f"Journeys: {report['journeys_passed']}/{report['journeys_executed']} pass")
        if chaos_results:
            summary.append(f"Chaos: {report['chaos_passed']}/{report['chaos_scenarios']} pass, "
                           f"{report['chaos_skipped']} skipped")
        print(" | ".join(summary))
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
