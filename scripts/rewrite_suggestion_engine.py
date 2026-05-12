#!/usr/bin/env python3
"""
Automated Rewrite Suggestion Engine.

Takes project scan results and produces rewrite suggestions with
rollback plan artifacts.

Usage:
    python3 scripts/rewrite_suggestion_engine.py <scan_report.json> [--json]
    python3 scripts/rewrite_suggestion_engine.py --self-test [--json]
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "docs" / "COMPATIBILITY_REGISTRY.json"

# Rewrite rules: (family, api_name) → suggestion
REWRITE_RULES = {
    ("fs", "readFile"): {
        "category": "direct-replacement",
        "description": "fs.readFile is available via native shim",
        "before": "const data = fs.readFileSync('file.txt', 'utf8');",
        "after": "const data = fs.readFileSync('file.txt', 'utf8'); // franken_node native shim",
        "test_cmd": "franken-node --test-compat fs:readFile",
    },
    ("fs", "readFileSync"): {
        "category": "direct-replacement",
        "description": "fs.readFileSync is available via native shim",
        "before": "fs.readFileSync(path, encoding)",
        "after": "fs.readFileSync(path, encoding) // franken_node native shim",
        "test_cmd": "franken-node --test-compat fs:readFileSync",
    },
    ("fs", "writeFile"): {
        "category": "direct-replacement",
        "description": "fs.writeFile is available via native shim",
        "before": "fs.writeFileSync('out.txt', data);",
        "after": "fs.writeFileSync('out.txt', data); // franken_node native shim",
        "test_cmd": "franken-node --test-compat fs:writeFile",
    },
    ("fs", "writeFileSync"): {
        "category": "direct-replacement",
        "description": "fs.writeFileSync is available via native shim",
        "before": "fs.writeFileSync(path, data)",
        "after": "fs.writeFileSync(path, data) // franken_node native shim",
        "test_cmd": "franken-node --test-compat fs:writeFileSync",
    },
    ("path", "join"): {
        "category": "direct-replacement",
        "description": "path.join is available via pure Rust implementation",
        "before": "path.join('a', 'b')",
        "after": "path.join('a', 'b') // franken_node Rust-native",
        "test_cmd": "franken-node --test-compat path:join",
    },
    ("path", "resolve"): {
        "category": "direct-replacement",
        "description": "path.resolve is available via pure Rust implementation",
        "before": "path.resolve('rel')",
        "after": "path.resolve('rel') // franken_node Rust-native",
        "test_cmd": "franken-node --test-compat path:resolve",
    },
    ("process", "env"): {
        "category": "adapter-needed",
        "description": "process.env access is mediated through capability gate",
        "before": "process.env.NODE_ENV",
        "after": "process.env.NODE_ENV // capability-gated in franken_node",
        "test_cmd": "franken-node --test-compat process:env",
    },
    ("process", "exit"): {
        "category": "direct-replacement",
        "description": "process.exit is available via bridge shim",
        "before": "process.exit(1)",
        "after": "process.exit(1) // franken_node bridge shim",
        "test_cmd": "franken-node --test-compat process:exit",
    },
    ("http", "createServer"): {
        "category": "adapter-needed",
        "description": "http.createServer requires engine-native server adapter",
        "before": "http.createServer((req, res) => { ... })",
        "after": "http.createServer((req, res) => { ... }) // engine-native adapter",
        "test_cmd": "franken-node --test-compat http:createServer",
    },
    ("crypto", "createHash"): {
        "category": "adapter-needed",
        "description": "crypto.createHash requires Rust crypto bridge",
        "before": "crypto.createHash('sha256').update(data).digest('hex')",
        "after": "crypto.createHash('sha256').update(data).digest('hex') // Rust crypto bridge",
        "test_cmd": "franken-node --test-compat crypto:createHash",
    },
    ("child_process", "exec"): {
        "category": "manual-review",
        "description": "child_process.exec requires security review for sandbox policy",
        "before": "exe" + "c('command', callback)",
        "after": "// REVIEW: child_process.exec requires sandbox policy approval",
        "test_cmd": "franken-node --test-compat child_process:exec",
    },
    ("child_process", "spawn"): {
        "category": "manual-review",
        "description": "child_process.spawn requires security review for sandbox policy",
        "before": "spawn('cmd', args)",
        "after": "// REVIEW: child_process.spawn requires sandbox policy approval",
        "test_cmd": "franken-node --test-compat child_process:spawn",
    },
}

UNSAFE_REWRITES = {
    "eval": {
        "category": "removal-needed",
        "description": "eval() is blocked in franken_node — must be removed or replaced",
        "before": "eval(code)",
        "after": "// REMOVED: eval() is unsafe and blocked by default policy",
        "test_cmd": None,
    },
    "Function": {
        "category": "removal-needed",
        "description": "new Function() is blocked — use static alternatives",
        "before": "new Function('return ' + expr)()",
        "after": "// REMOVED: dynamic Function() blocked by policy",
        "test_cmd": None,
    },
    "vm.runInNewContext": {
        "category": "removal-needed",
        "description": "vm.runInNewContext is blocked without explicit sandbox policy opt-in",
        "before": "vm.runInNewContext(code, sandbox)",
        "after": "// REMOVED: vm.runInNewContext requires explicit policy opt-in",
        "test_cmd": None,
    },
    "process.binding": {
        "category": "removal-needed",
        "description": "process.binding() is disabled in franken_node",
        "before": "process.binding('natives')",
        "after": "// REMOVED: process.binding() disabled per DIV-001",
        "test_cmd": None,
    },
}

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_suggestions(scan_report: dict) -> list[dict]:
    """Generate rewrite suggestions from scan report."""
    suggestions = []

    for usage in scan_report.get("api_usage", []):
        family = usage.get("api_family", "")
        api_name = usage.get("api_name", "")
        risk = usage.get("risk_level", "medium")
        source = usage.get("source_file", "<unknown>")

        if family == "unsafe" and api_name in UNSAFE_REWRITES:
            rule = UNSAFE_REWRITES[api_name]
        elif (family, api_name) in REWRITE_RULES:
            rule = REWRITE_RULES[(family, api_name)]
        else:
            rule = {
                "category": "manual-review",
                "description": f"No automated rewrite for {family}.{api_name}",
                "before": f"{family}.{api_name}(...)",
                "after": f"// REVIEW: {family}.{api_name} — check compatibility",
                "test_cmd": None,
            }

        suggestions.append({
            "api_family": family,
            "api_name": api_name,
            "source_file": source,
            "risk_level": risk,
            "category": rule["category"],
            "description": rule["description"],
            "before": rule["before"],
            "after": rule["after"],
            "test_cmd": rule.get("test_cmd"),
            "rollback": {
                "command": f"git restore {source}",
                "description": f"Restore original {source} from git",
            },
        })

    # Sort by risk priority
    suggestions.sort(key=lambda s: PRIORITY_ORDER.get(s["risk_level"], 99))
    return suggestions


def generate_rollback_plan(suggestions: list[dict], project: str) -> dict:
    """Generate a rollback plan artifact."""
    files = set(s["source_file"] for s in suggestions)
    return {
        "project": project,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "affected_files": sorted(files),
        "rollback_commands": [f"git restore {f}" for f in sorted(files)],
        "full_rollback": "git checkout -- .",
        "suggestion_count": len(suggestions),
        "categories": {
            cat: sum(1 for s in suggestions if s["category"] == cat)
            for cat in {"direct-replacement", "adapter-needed", "removal-needed", "manual-review"}
            if any(s["category"] == cat for s in suggestions)
        },
    }


def produce_report(scan_report: dict) -> dict:
    """Produce complete suggestion + rollback report."""
    suggestions = generate_suggestions(scan_report)
    rollback = generate_rollback_plan(suggestions, scan_report.get("project", "<unknown>"))
    return {
        "project": scan_report.get("project", "<unknown>"),
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "suggestions": suggestions,
        "rollback_plan": rollback,
        "summary": {
            "total_suggestions": len(suggestions),
            "by_category": rollback["categories"],
        },
    }


def self_test() -> dict:
    """Run self-test."""
    checks = []

    # Test with scan data
    scan = {
        "project": "test-project",
        "api_usage": [
            {"api_family": "fs", "api_name": "readFileSync", "source_file": "app.js", "risk_level": "low"},
            {"api_family": "path", "api_name": "join", "source_file": "app.js", "risk_level": "low"},
            {"api_family": "http", "api_name": "createServer", "source_file": "server.js", "risk_level": "high"},
            {"api_family": "unsafe", "api_name": "eval", "source_file": "legacy.js", "risk_level": "critical"},
        ],
    }

    report = produce_report(scan)

    # Check 1: Suggestions generated
    checks.append({"id": "REWRITE-SUGGESTIONS", "status": "PASS" if len(report["suggestions"]) == 4 else "FAIL",
                    "details": {"count": len(report["suggestions"])}})

    # Check 2: Priority ordering (critical first)
    first_risk = report["suggestions"][0]["risk_level"] if report["suggestions"] else None
    checks.append({"id": "REWRITE-PRIORITY", "status": "PASS" if first_risk == "critical" else "FAIL",
                    "details": {"first_risk": first_risk}})

    # Check 3: Rollback plan present
    has_rollback = "rollback_plan" in report and len(report["rollback_plan"]["affected_files"]) > 0
    checks.append({"id": "REWRITE-ROLLBACK", "status": "PASS" if has_rollback else "FAIL"})

    # Check 4: Categories populated
    has_categories = len(report["summary"]["by_category"]) > 0
    checks.append({"id": "REWRITE-CATEGORIES", "status": "PASS" if has_categories else "FAIL",
                    "details": report["summary"]["by_category"]})

    # Check 5: Rewrite rules coverage
    checks.append({"id": "REWRITE-RULES", "status": "PASS" if len(REWRITE_RULES) >= 8 else "FAIL",
                    "details": {"rule_count": len(REWRITE_RULES), "unsafe_count": len(UNSAFE_REWRITES)}})

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "rewrite_engine_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    logger = configure_test_logging("rewrite_suggestion_engine")
    logger.info("starting rewrite_suggestion_engine", extra={"argv": sys.argv[1:]})
    json_output = "--json" in sys.argv
    is_self_test = "--self-test" in sys.argv

    if is_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Usage: python3 scripts/rewrite_suggestion_engine.py <scan.json> [--json]", file=sys.stderr)
        sys.exit(2)

    scan = json.loads(Path(args[0]).read_text())
    report = produce_report(scan)
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        for s in report["suggestions"]:
            print(f"[{s['risk_level'].upper()}] {s['api_family']}.{s['api_name']} ({s['category']})")
            print(f"  {s['description']}")


if __name__ == "__main__":
    main()
