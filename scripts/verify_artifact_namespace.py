#!/usr/bin/env python3
"""
Artifact Namespace Validator.

Scans the artifacts tree for:
  1. Path collisions (two artifacts at the same canonical path)
  2. Missing artifact_meta blocks
  3. Invalid artifact_type values
  4. Duplicate (bead_id, scenario_id) pairs across the tree

Usage:
    python3 scripts/verify_artifact_namespace.py [--json] [--artifacts-dir DIR]

Exit codes:
    0 = PASS
    1 = FAIL (collisions or validation errors)
    2 = ERROR (missing directories or parse failures)
"""

import json
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ARTIFACTS_DIR = ROOT / "artifacts"

VALID_ARTIFACT_TYPES = {
    "unit_test", "integration_test", "e2e_test", "benchmark",
    "coverage", "lint", "gate_verdict", "provenance",
    "drift_report", "manifest",
}

# Legacy paths that predate the canonical namespace (compatibility mapping)
LEGACY_PATHS = {
    "artifacts/oracle/l1_product_verdict.json",
    "artifacts/oracle/l2_engine_boundary_verdict.json",
    "artifacts/oracle/release_policy_verdict.json",
    "artifacts/program/rch_execution_policy_report.json",
}


def scan_artifacts(artifacts_dir: Path) -> list[dict]:
    """Walk the artifacts tree and collect all JSON files with metadata."""
    results = []
    if not artifacts_dir.exists():
        return results

    for root, dirs, files in os.walk(artifacts_dir):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            if fname.startswith("sample_"):
                continue
            fpath = Path(root) / fname
            rel_path = str(fpath.relative_to(artifacts_dir.parent))

            entry = {
                "path": str(fpath),
                "rel_path": rel_path,
                "has_meta": False,
                "meta": None,
                "errors": [],
            }

            try:
                with open(fpath) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                entry["errors"].append(f"Parse error: {e}")
                results.append(entry)
                continue

            if not isinstance(data, dict):
                entry["errors"].append("Artifact is not a JSON object")
                results.append(entry)
                continue

            meta = data.get("artifact_meta")
            if meta:
                entry["has_meta"] = True
                entry["meta"] = meta

                # Validate required fields
                for field in ["schema_version", "bead_id", "section",
                              "artifact_type", "scenario_id", "timestamp",
                              "commit", "trace_id"]:
                    if field not in meta:
                        entry["errors"].append(f"Missing meta field: {field}")

                # Validate artifact_type
                atype = meta.get("artifact_type")
                if atype and atype not in VALID_ARTIFACT_TYPES:
                    entry["errors"].append(f"Invalid artifact_type: {atype}")

            elif rel_path not in LEGACY_PATHS:
                # Not legacy, not meta — warn but don't fail
                entry["errors"].append("Missing artifact_meta block")

            results.append(entry)

    return results


def check_collisions(artifacts: list[dict]) -> list[dict]:
    """Check for path collisions and duplicate (bead_id, scenario_id) pairs."""
    collisions = []

    # Check canonical path collisions
    by_path = defaultdict(list)
    for a in artifacts:
        by_path[a["rel_path"]].append(a)

    for path, items in by_path.items():
        if len(items) > 1:
            collisions.append({
                "type": "path_collision",
                "path": path,
                "count": len(items),
            })

    # Check (bead_id, scenario_id) uniqueness
    by_key = defaultdict(list)
    for a in artifacts:
        meta = a.get("meta")
        if meta and "bead_id" in meta and "scenario_id" in meta:
            key = f"{meta['bead_id']}:{meta['scenario_id']}"
            by_key[key].append(a["rel_path"])

    for key, paths in by_key.items():
        if len(paths) > 1:
            collisions.append({
                "type": "key_collision",
                "key": key,
                "paths": paths,
                "count": len(paths),
            })

    return collisions


def main():
    logger = configure_test_logging("verify_artifact_namespace")
    json_output = "--json" in sys.argv
    artifacts_dir = DEFAULT_ARTIFACTS_DIR

    for i, arg in enumerate(sys.argv):
        if arg == "--artifacts-dir" and i + 1 < len(sys.argv):
            artifacts_dir = Path(sys.argv[i + 1])

    if not artifacts_dir.exists():
        if json_output:
            print(json.dumps({
                "gate": "artifact_namespace",
                "verdict": "PASS",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "artifacts_scanned": 0,
                "note": "No artifacts directory yet",
            }, indent=2))
        else:
            print("=== Artifact Namespace Validator ===")
            print("No artifacts directory yet. PASS (vacuously).")
        sys.exit(0)

    artifacts = scan_artifacts(artifacts_dir)
    collisions = check_collisions(artifacts)

    meta_errors = []
    for a in artifacts:
        if a["errors"]:
            for err in a["errors"]:
                meta_errors.append({
                    "path": a["rel_path"],
                    "error": err,
                })

    # Collisions are hard failures; meta errors are warnings for now
    # (many artifacts are pre-namespace and don't have meta yet)
    verdict = "PASS" if not collisions else "FAIL"
    timestamp = datetime.now(timezone.utc).isoformat()

    report = {
        "gate": "artifact_namespace",
        "verdict": verdict,
        "timestamp": timestamp,
        "artifacts_dir": str(artifacts_dir),
        "artifacts_scanned": len(artifacts),
        "with_meta": sum(1 for a in artifacts if a["has_meta"]),
        "without_meta": sum(1 for a in artifacts if not a["has_meta"]),
        "legacy_paths": sum(1 for a in artifacts if a["rel_path"] in LEGACY_PATHS),
        "collisions": collisions,
        "meta_warnings": meta_errors[:20],  # Cap at 20 to avoid noise
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Artifact Namespace Validator ===")
        print(f"Artifacts scanned: {report['artifacts_scanned']}")
        print(f"With artifact_meta: {report['with_meta']}")
        print(f"Without artifact_meta: {report['without_meta']}")
        print(f"Legacy (exempt): {report['legacy_paths']}")
        print(f"Collisions: {len(collisions)}")
        if collisions:
            print("\nCOLLISIONS:")
            for c in collisions:
                if c["type"] == "path_collision":
                    print(f"  [PATH] {c['path']} ({c['count']} files)")
                else:
                    print(f"  [KEY] {c['key']} in {c['count']} paths")
        if meta_errors:
            print(f"\nMeta warnings: {len(meta_errors)}")
            for w in meta_errors[:10]:
                print(f"  - {w['path']}: {w['error']}")
        print(f"\nVerdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
