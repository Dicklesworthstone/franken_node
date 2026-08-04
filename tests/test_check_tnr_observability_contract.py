#!/usr/bin/env python3
"""Unit tests for scripts/check_tnr_observability_contract.py."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_tnr_observability_contract as gate


def _load_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - assertion helper
        raise AssertionError(f"invalid JSON fixture {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise AssertionError(f"JSON fixture must be an object: {path}")
    return payload


def _real_registry() -> dict:
    return _load_json(gate.REGISTRY_PATH)


class TestRegistryContract(unittest.TestCase):
    def test_real_registry_passes(self) -> None:
        registry = _real_registry()
        self.assertEqual(gate.check_registry(registry), [])

    def test_missing_required_subsystem_fails(self) -> None:
        registry = copy.deepcopy(_real_registry())
        registry["subsystems"] = [
            subsystem
            for subsystem in registry["subsystems"]
            if subsystem["id"] != "FN-COMPAT"
        ]
        errors = gate.check_registry(registry)
        self.assertTrue(any("FN-COMPAT" in error for error in errors))

    def test_invalid_metric_name_fails(self) -> None:
        registry = copy.deepcopy(_real_registry())
        registry["subsystems"][0]["metrics"][0]["name"] = "not prometheus metric"
        errors = gate.check_registry(registry)
        self.assertTrue(any("invalid name" in error for error in errors))

    def test_duplicate_event_code_fails(self) -> None:
        registry = copy.deepcopy(_real_registry())
        duplicate = registry["subsystems"][0]["event_codes"][0]["code"]
        registry["subsystems"][0]["event_codes"][1]["code"] = duplicate
        errors = gate.check_registry(registry)
        self.assertTrue(any("duplicate" in error for error in errors))


class TestDocumentationContract(unittest.TestCase):
    def test_real_docs_list_registered_codes_and_metrics(self) -> None:
        registry = _real_registry()
        self.assertEqual(gate.check_docs(registry), [])

    def test_missing_metric_in_docs_fails(self) -> None:
        registry = _real_registry()
        with tempfile.TemporaryDirectory() as tmpdir:
            docs_path = Path(tmpdir) / "registry.md"
            docs_path.write_text("FN-COMPAT\nFN-COMPAT-001\n", encoding="utf-8")
            errors = gate.check_docs(registry, docs_path)
        self.assertTrue(any("docs missing metric" in error for error in errors))


class TestSourceScan(unittest.TestCase):
    def test_unknown_concrete_code_fails(self) -> None:
        registry = _real_registry()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "source.rs"
            source.write_text('pub const BAD: &str = "FN-NOTREG-001";\n', encoding="utf-8")
            errors = gate.check_scan(registry, (root,))
        self.assertTrue(any("FN-NOTREG-001" in error for error in errors))

    def test_legacy_range_code_passes(self) -> None:
        registry = _real_registry()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "source.rs"
            source.write_text('pub const OLD: &str = "FN-CX-010";\n', encoding="utf-8")
            errors = gate.check_scan(registry, (root,))
        self.assertEqual(errors, [])


class TestRunChecks(unittest.TestCase):
    def test_real_gate_passes(self) -> None:
        result = gate.run_checks()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
