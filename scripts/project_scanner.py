#!/usr/bin/env python3
"""
Project Scanner — API/Runtime/Dependency Risk Inventory.

Scans a JS/TS project directory for Node.js/Bun API usage, dependency
risks, and migration readiness. Produces a structured JSON report.

Usage:
    python3 scripts/project_scanner.py <project_dir> [--json]
    python3 scripts/project_scanner.py --self-test [--json]
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "docs" / "COMPATIBILITY_REGISTRY.json"

# API detection patterns: (family, api_name, pattern)
API_PATTERNS = [
    ("fs", "readFile", re.compile(r"""(?:require\s*\(\s*['"]fs['"]\s*\)|from\s+['"]fs['"]).*?\.readFile""", re.DOTALL)),
    ("fs", "readFileSync", re.compile(r"""(?:fs\.readFileSync|readFileSync)\s*\(""")),
    ("fs", "writeFile", re.compile(r"""(?:require\s*\(\s*['"]fs['"]\s*\)|from\s+['"]fs['"]).*?\.writeFile""", re.DOTALL)),
    ("fs", "writeFileSync", re.compile(r"""(?:fs\.writeFileSync|writeFileSync)\s*\(""")),
    ("path", "join", re.compile(r"""path\.join\s*\(""")),
    ("path", "resolve", re.compile(r"""path\.resolve\s*\(""")),
    ("process", "env", re.compile(r"""process\.env\b""")),
    ("process", "argv", re.compile(r"""process\.argv\b""")),
    ("process", "exit", re.compile(r"""process\.exit\s*\(""")),
    ("http", "createServer", re.compile(r"""http\.createServer\s*\(""")),
    ("http", "request", re.compile(r"""http\.request\s*\(""")),
    ("crypto", "createHash", re.compile(r"""crypto\.createHash\s*\(""")),
    ("crypto", "randomBytes", re.compile(r"""crypto\.randomBytes\s*\(""")),
    ("child_process", "exec", re.compile(r"""(?:child_process\.exec|exec)\s*\(""")),
    ("child_process", "spawn", re.compile(r"""(?:child_process\.spawn|spawn)\s*\(""")),
]

# Unsafe patterns
UNSAFE_PATTERNS = [
    ("eval", re.compile(r"""\beval\s*\(""")),
    ("Function", re.compile(r"""\bnew\s+Function\s*\(""")),
    ("vm.runInNewContext", re.compile(r"""vm\.runInNewContext\s*\(""")),
    ("process.binding", re.compile(r"""process\.binding\s*\(""")),
]

# Known native addon packages
NATIVE_ADDON_PACKAGES = {
    "bcrypt", "sharp", "canvas", "better-sqlite3", "node-gyp",
    "node-pre-gyp", "nan", "node-addon-api", "ffi-napi",
    "ref-napi", "leveldown", "sodium-native", "argon2",
}

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}


def load_registry() -> dict:
    """Load compatibility registry for band/status lookups."""
    if not REGISTRY_PATH.exists():
        return {}
    data = json.loads(REGISTRY_PATH.read_text())
    lookup = {}
    for entry in data.get("behaviors", []):
        key = (entry.get("api_family", ""), entry.get("api_name", ""))
        lookup[key] = {
            "band": entry.get("band", "unknown"),
            "shim_type": entry.get("shim_type", "unknown"),
        }
    return lookup


def classify_risk(band: str | None, impl_status: str | None, is_unsafe: bool = False) -> str:
    """Classify risk level based on band and implementation status."""
    if is_unsafe:
        return "critical"
    if band == "core" and impl_status in ("native", "polyfill", "bridge"):
        return "low"
    if band == "core":
        return "medium"
    if band == "high-value" and impl_status in ("native", "polyfill", "bridge"):
        return "low"
    if band == "high-value":
        return "high"
    if band == "edge":
        return "medium"
    return "medium"


def scan_file(filepath: Path, registry: dict) -> list[dict]:
    """Scan a single JS/TS file for API usage."""
    results = []
    try:
        text = filepath.read_text(errors="replace")
    except OSError:
        return results

    for family, api_name, pattern in API_PATTERNS:
        if pattern.search(text):
            reg_entry = registry.get((family, api_name), {})
            band = reg_entry.get("band")
            impl_status = reg_entry.get("shim_type")
            results.append({
                "api_family": family,
                "api_name": api_name,
                "source_file": str(filepath),
                "line_number": None,
                "band": band,
                "impl_status": impl_status,
                "risk_level": classify_risk(band, impl_status),
            })

    for name, pattern in UNSAFE_PATTERNS:
        if pattern.search(text):
            results.append({
                "api_family": "unsafe",
                "api_name": name,
                "source_file": str(filepath),
                "line_number": None,
                "band": "unsafe",
                "impl_status": None,
                "risk_level": "critical",
            })

    return results


def scan_dependencies(project_dir: Path) -> list[dict]:
    """Analyze package.json for dependency risks."""
    results = []
    pkg_json = project_dir / "package.json"
    if not pkg_json.exists():
        return results

    try:
        pkg = json.loads(pkg_json.read_text())
    except (json.JSONDecodeError, OSError):
        return results

    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))

    for name, version in all_deps.items():
        is_native = name in NATIVE_ADDON_PACKAGES
        risk = "critical" if is_native else "low"
        results.append({
            "name": name,
            "version": version,
            "has_native_addon": is_native,
            "risk_level": risk,
            "notes": "Native addon — requires port or replacement" if is_native else None,
        })

    return results


def compute_readiness(risk_dist: dict) -> str:
    """Compute migration readiness from risk distribution."""
    if risk_dist.get("critical", 0) > 0:
        return "not-ready"
    if risk_dist.get("high", 0) > 0:
        return "partial"
    return "ready"


def scan_project(project_dir: Path) -> dict:
    """Full project scan producing a report."""
    registry = load_registry()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Scan source files
    api_usage = []
    if project_dir.is_dir():
        for ext in JS_EXTENSIONS:
            for f in project_dir.rglob(f"*{ext}"):
                if "node_modules" in str(f):
                    continue
                api_usage.extend(scan_file(f, registry))

    # Scan dependencies
    dependencies = scan_dependencies(project_dir)

    # Compute risk distribution
    risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for item in api_usage:
        risk_dist[item["risk_level"]] += 1
    for dep in dependencies:
        if dep["risk_level"] == "critical":
            risk_dist["critical"] += 1

    # Generate recommendations
    recommendations = []
    if risk_dist["critical"] > 0:
        recommendations.append({
            "category": "blocking",
            "message": f"{risk_dist['critical']} critical risk items found — address before migration",
            "severity": "error",
        })
    if risk_dist["high"] > 0:
        recommendations.append({
            "category": "high-risk",
            "message": f"{risk_dist['high']} high-risk API usages — verify compatibility before migration",
            "severity": "warning",
        })

    return {
        "project": str(project_dir),
        "scan_timestamp": timestamp,
        "summary": {
            "total_apis_detected": len(api_usage),
            "risk_distribution": risk_dist,
            "migration_readiness": compute_readiness(risk_dist),
        },
        "api_usage": api_usage,
        "dependencies": dependencies,
        "recommendations": recommendations,
    }


def self_test() -> dict:
    """Run self-test by scanning a synthetic project."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        project = Path(tmpdir)

        # Create synthetic JS files
        (project / "app.js").write_text(
            "const fs = require('fs');\n"
            "const path = require('path');\n"
            "const data = fs.readFileSync('config.json', 'utf8');\n"
            "const full = path.join(__dirname, 'data');\n"
            "console.log(process.env.NODE_ENV);\n"
        )
        (project / "server.js").write_text(
            "const http = require('http');\n"
            "http.createServer((req, res) => res.end('ok')).listen(3000);\n"
        )
        (project / "package.json").write_text(json.dumps({
            "name": "test-project",
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }))

        report = scan_project(project)

    # Validate
    checks = []
    checks.append({"id": "SCAN-RUNS", "status": "PASS"})

    has_apis = report["summary"]["total_apis_detected"] > 0
    checks.append({"id": "SCAN-DETECTS-APIS", "status": "PASS" if has_apis else "FAIL",
                    "details": {"apis_detected": report["summary"]["total_apis_detected"]}})

    has_deps = len(report["dependencies"]) > 0
    checks.append({"id": "SCAN-DETECTS-DEPS", "status": "PASS" if has_deps else "FAIL",
                    "details": {"deps_detected": len(report["dependencies"])}})

    has_readiness = report["summary"]["migration_readiness"] in ("ready", "partial", "not-ready")
    checks.append({"id": "SCAN-READINESS", "status": "PASS" if has_readiness else "FAIL"})

    has_schema_fields = all(k in report for k in ("project", "scan_timestamp", "summary", "api_usage", "dependencies"))
    checks.append({"id": "SCAN-SCHEMA", "status": "PASS" if has_schema_fields else "FAIL"})

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "project_scanner_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
        "sample_report": report,
    }


def main():
    logger = configure_test_logging("project_scanner")
    logger.info("starting project_scanner", extra={"argv": sys.argv[1:]})
    json_output = "--json" in sys.argv
    is_self_test = "--self-test" in sys.argv

    if is_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            print("=== Project Scanner Self-Test ===")
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    # Normal scan mode
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Usage: python3 scripts/project_scanner.py <project_dir> [--json]", file=sys.stderr)
        sys.exit(2)

    project_dir = Path(args[0])
    report = scan_project(project_dir)

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        s = report["summary"]
        print(f"Project: {report['project']}")
        print(f"APIs detected: {s['total_apis_detected']}")
        print(f"Risk: low={s['risk_distribution']['low']} medium={s['risk_distribution']['medium']} "
              f"high={s['risk_distribution']['high']} critical={s['risk_distribution']['critical']}")
        print(f"Readiness: {s['migration_readiness']}")


if __name__ == "__main__":
    main()
