#!/usr/bin/env python3
"""Tests for bd-1961: Reputation graph APIs gate."""
import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_reputation_graph_apis.py")

def _load():
    spec = importlib.util.spec_from_file_location("chk", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

mod = _load()

class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True

class TestJsonOutput:
    def test_json_has_required_keys(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        for k in ("bead_id", "section", "gate_script", "checks_passed", "checks_total", "verdict", "checks"):
            assert k in d

    def test_bead_id(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        assert d["bead_id"] == "bd-1961"
        assert d["section"] == "15"

    def test_verdict_field(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        assert d["verdict"] in ("PASS", "FAIL")

    def test_checks_is_list(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        assert isinstance(d["checks"], list)
        assert len(d["checks"]) >= 16

    def test_each_check_has_fields(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        for c in d["checks"]:
            assert "check" in c and "passed" in c and "detail" in c

class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {x["check"]: x for x in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_node_types(self, results): assert results["node_types"]["passed"]
    def test_struct_reputation_node(self, results): assert results["struct_ReputationNode"]["passed"]
    def test_struct_reputation_edge(self, results): assert results["struct_ReputationEdge"]["passed"]
    def test_struct_reputation_score(self, results): assert results["struct_ReputationScore"]["passed"]
    def test_struct_graph_snapshot(self, results): assert results["struct_GraphSnapshot"]["passed"]
    def test_struct_reputation_graph_apis(self, results): assert results["struct_ReputationGraphApis"]["passed"]
    def test_edge_weight(self, results): assert results["edge_weight"]["passed"]
    def test_composite_score(self, results): assert results["composite_score"]["passed"]
    def test_graph_queries(self, results): assert results["graph_queries"]["passed"]
    def test_decay_support(self, results): assert results["decay_support"]["passed"]
    def test_content_hash(self, results): assert results["content_hash"]["passed"]
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
    def test_audit_log(self, results): assert results["audit_log"]["passed"]
    def test_schema_version(self, results): assert results["schema_version"]["passed"]
    def test_spec_alignment(self, results): assert results["spec_alignment"]["passed"]
    def test_test_coverage(self, results): assert results["test_coverage"]["passed"]

class TestOverall:
    def test_all_pass(self):
        results = mod._checks()
        failed = [x["check"] for x in results if not x["passed"]]
        assert not failed, f"Failed: {failed}"

    def test_minimum_check_count(self):
        assert len(mod._checks()) >= 16
