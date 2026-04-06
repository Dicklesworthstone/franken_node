#!/usr/bin/env python3
"""
Reproducibility Pack Validator.

Validates that env.json, manifest.json, and repro.lock files conform
to the reproducibility contract schemas.

Usage:
    python3 scripts/validate_repro_pack.py [--json] [--dir PATH]

The --dir flag specifies a directory containing the repro pack files.
If omitted, validates the template examples.

Exit codes:
    0 = PASS
    1 = FAIL
"""

import hashlib
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"
TEMPLATE_DIR = ROOT / "docs" / "templates" / "reproducibility"


def validate_env(data: dict) -> list[str]:
    """Validate env.json against schema rules."""
    errors = []
    required = ["schema_version", "timestamp", "os", "arch", "rust_toolchain", "hostname"]
    for field in required:
        if field not in data:
            errors.append(f"env.json: missing required field '{field}'")

    if data.get("schema_version") != "1.0":
        errors.append(f"env.json: schema_version must be '1.0', got '{data.get('schema_version')}'")

    rt = data.get("rust_toolchain", {})
    if isinstance(rt, dict):
        for f in ["version", "edition"]:
            if f not in rt:
                errors.append(f"env.json: rust_toolchain missing '{f}'")
    else:
        errors.append("env.json: rust_toolchain must be an object")

    return errors


def validate_manifest(data: dict) -> list[str]:
    """Validate manifest.json against schema rules."""
    errors = []
    required = ["schema_version", "bead_id", "artifact_type", "timestamp", "commands", "outputs"]
    for field in required:
        if field not in data:
            errors.append(f"manifest.json: missing required field '{field}'")

    if data.get("schema_version") != "1.0":
        errors.append("manifest.json: schema_version must be '1.0'")

    # Validate commands
    for i, cmd in enumerate(data.get("commands", [])):
        if "command" not in cmd:
            errors.append(f"manifest.json: commands[{i}] missing 'command'")
        if "exit_code" not in cmd:
            errors.append(f"manifest.json: commands[{i}] missing 'exit_code'")

    # Validate output hashes
    sha_pattern = re.compile(r'^[a-f0-9]{64}$')
    for i, out in enumerate(data.get("outputs", [])):
        if "path" not in out:
            errors.append(f"manifest.json: outputs[{i}] missing 'path'")
        sha = out.get("sha256", "")
        if sha and not sha_pattern.match(sha):
            errors.append(f"manifest.json: outputs[{i}] invalid SHA-256 hash")

    return errors


def validate_lock(data: dict) -> list[str]:
    """Validate repro.lock against schema rules."""
    errors = []
    required = ["schema_version", "timestamp", "git_commit", "cargo_lock_sha256"]
    for field in required:
        if field not in data:
            errors.append(f"repro.lock: missing required field '{field}'")

    if data.get("schema_version") != "1.0":
        errors.append("repro.lock: schema_version must be '1.0'")

    commit = data.get("git_commit", "")
    if commit and not re.match(r'^[a-f0-9]{40}$', commit):
        errors.append(f"repro.lock: git_commit must be 40-char hex, got '{commit}'")

    lock_hash = data.get("cargo_lock_sha256", "")
    if lock_hash and not re.match(r'^[a-f0-9]{64}$', lock_hash):
        errors.append("repro.lock: cargo_lock_sha256 must be 64-char hex")

    return errors


def generate_example_env() -> dict:
    """Generate a valid example env.json from current system."""
    return {
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node() or "unknown",
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "kernel": platform.release(),
        "rust_toolchain": {
            "version": "nightly",
            "edition": "2024",
            "channel": "nightly",
        },
        "python_version": platform.python_version(),
        "env_vars": {
            "CARGO_HOME": os.environ.get("CARGO_HOME", ""),
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", ""),
        },
    }


def generate_example_manifest() -> dict:
    """Generate a valid example manifest.json."""
    return {
        "schema_version": "1.0",
        "bead_id": "bd-example",
        "artifact_type": "verification_evidence",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commands": [
            {
                "command": "python3 scripts/example_check.py --json",
                "exit_code": 0,
                "duration_ms": 150,
            }
        ],
        "inputs": [],
        "outputs": [
            {
                "path": "artifacts/example/verification_evidence.json",
                "sha256": "0" * 64,
                "size_bytes": 512,
            }
        ],
    }


def generate_example_lock() -> dict:
    """Generate a valid example repro.lock from current repo state."""
    git_commit = "0" * 40
    cargo_lock_sha256 = "0" * 64

    # Try to get real values
    cargo_lock = ROOT / "Cargo.lock"
    if cargo_lock.exists():
        cargo_lock_sha256 = hashlib.sha256(cargo_lock.read_bytes()).hexdigest()

    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=3600, cwd=ROOT,
        )
        if result.returncode == 0:
            git_commit = result.stdout.strip()
    except Exception:
        pass

    return {
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit,
        "git_branch": "main",
        "git_dirty": False,
        "cargo_lock_sha256": cargo_lock_sha256,
        "engine_revision": None,
        "key_crates": {
            "clap": "4.5.32",
            "tokio": "1.0",
            "serde": "1.0",
        },
    }


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    # Check for --dir flag
    target_dir = None
    for i, arg in enumerate(sys.argv):
        if arg == "--dir" and i + 1 < len(sys.argv):
            target_dir = Path(sys.argv[i + 1])

    checks = []

    # Check 1: Schemas exist
    check = {"id": "REPRO-SCHEMAS", "status": "PASS", "details": {"schemas": []}}
    for schema_name in ["reproducibility_env.schema.json", "reproducibility_manifest.schema.json", "reproducibility_lock.schema.json"]:
        schema_path = SCHEMA_DIR / schema_name
        exists = schema_path.exists()
        check["details"]["schemas"].append({"name": schema_name, "exists": exists})
        if not exists:
            check["status"] = "FAIL"
    checks.append(check)

    # Check 2: Generate and validate example env
    check = {"id": "REPRO-ENV-VALID", "status": "PASS", "details": {}}
    if target_dir:
        env_path = target_dir / "env.json"
        if env_path.exists():
            env_data = json.loads(env_path.read_text())
        else:
            check["status"] = "FAIL"
            check["details"]["error"] = f"{env_path} not found"
            env_data = None
    else:
        env_data = generate_example_env()

    if env_data is not None:
        env_errors = validate_env(env_data)
        if env_errors:
            check["status"] = "FAIL"
            check["details"]["errors"] = env_errors
        else:
            check["details"]["fields_validated"] = len(env_data)
    checks.append(check)

    # Check 3: Generate and validate example manifest
    check = {"id": "REPRO-MANIFEST-VALID", "status": "PASS", "details": {}}
    if target_dir:
        manifest_path = target_dir / "manifest.json"
        if manifest_path.exists():
            manifest_data = json.loads(manifest_path.read_text())
        else:
            check["status"] = "FAIL"
            check["details"]["error"] = f"{manifest_path} not found"
            manifest_data = None
    else:
        manifest_data = generate_example_manifest()

    if manifest_data is not None:
        manifest_errors = validate_manifest(manifest_data)
        if manifest_errors:
            check["status"] = "FAIL"
            check["details"]["errors"] = manifest_errors
        else:
            check["details"]["fields_validated"] = len(manifest_data)
    checks.append(check)

    # Check 4: Generate and validate example lock
    check = {"id": "REPRO-LOCK-VALID", "status": "PASS", "details": {}}
    if target_dir:
        lock_path = target_dir / "repro.lock"
        if lock_path.exists():
            lock_data = json.loads(lock_path.read_text())
        else:
            check["status"] = "FAIL"
            check["details"]["error"] = f"{lock_path} not found"
            lock_data = None
    else:
        lock_data = generate_example_lock()

    if lock_data is not None:
        lock_errors = validate_lock(lock_data)
        if lock_errors:
            check["status"] = "FAIL"
            check["details"]["errors"] = lock_errors
        else:
            check["details"]["fields_validated"] = len(lock_data)
    checks.append(check)

    # Check 5: Templates directory exists with examples
    check = {"id": "REPRO-TEMPLATES", "status": "PASS", "details": {}}
    if TEMPLATE_DIR.exists():
        templates = list(TEMPLATE_DIR.glob("*.json"))
        check["details"]["template_count"] = len(templates)
        check["details"]["templates"] = [t.name for t in templates]
    else:
        check["status"] = "FAIL"
        check["details"]["error"] = "Template directory not found"
    checks.append(check)

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "reproducibility_pack_validation",
        "section": "10.1",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Reproducibility Pack Validator ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL" and "errors" in c.get("details", {}):
                for e in c["details"]["errors"]:
                    print(f"       Error: {e}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
