"""Unit tests for check_activation_pipeline.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPipelineFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/activation/pipeline_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/activation/pipeline_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_success_case(self):
        path = os.path.join(ROOT, "fixtures/activation/pipeline_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        success = [c for c in data["cases"] if c.get("expected_completed") is True]
        self.assertGreater(len(success), 0)

    def test_fixture_has_failure_cases(self):
        path = os.path.join(ROOT, "fixtures/activation/pipeline_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        failures = [c for c in data["cases"] if c.get("expected_completed") is False]
        self.assertGreater(len(failures), 0)

    def test_fixture_has_all_error_codes(self):
        path = os.path.join(ROOT, "fixtures/activation/pipeline_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        codes = {c.get("expected_error_code") for c in data["cases"] if c.get("expected_error_code")}
        for code in ["ACT_SANDBOX_FAILED", "ACT_SECRET_MOUNT_FAILED",
                     "ACT_CAPABILITY_FAILED", "ACT_HEALTH_FAILED"]:
            self.assertIn(code, codes, f"Missing error code scenario: {code}")


class TestPipelineTranscript(unittest.TestCase):

    def test_transcript_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl")
        self.assertTrue(os.path.isfile(path))

    def test_transcript_valid_jsonl(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl")
        with open(path) as f:
            lines = f.read().strip().split("\n")
        for line in lines:
            json.loads(line)  # Should not raise

    def test_transcript_has_stage_events(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl")
        with open(path) as f:
            entries = [json.loads(line) for line in f.read().strip().split("\n")]
        stage_events = [e for e in entries if e.get("event") == "stage_complete"]
        self.assertGreaterEqual(len(stage_events), 4)

    def test_transcript_has_activation_complete(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl")
        with open(path) as f:
            entries = [json.loads(line) for line in f.read().strip().split("\n")]
        complete = [e for e in entries if e.get("event") == "activation_complete"]
        self.assertGreater(len(complete), 0)

    def test_transcript_has_cleanup_event(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl")
        with open(path) as f:
            entries = [json.loads(line) for line in f.read().strip().split("\n")]
        cleanup = [e for e in entries if e.get("event") == "secret_cleanup"]
        self.assertGreater(len(cleanup), 0)


class TestPipelineImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/activation_pipeline.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_activation_stage(self):
        self.assertIn("enum ActivationStage", self.content)

    def test_has_stage_result(self):
        self.assertIn("struct StageResult", self.content)

    def test_has_activation_transcript(self):
        self.assertIn("struct ActivationTranscript", self.content)

    def test_has_stage_error(self):
        self.assertIn("enum StageError", self.content)

    def test_has_activate_fn(self):
        self.assertIn("fn activate", self.content)

    def test_default_executor_fails_closed(self):
        self.assertIn("struct DefaultExecutor", self.content)
        self.assertIn("ACTIVATION_EXECUTOR_REQUIRED", self.content)
        self.assertIn("Err(ACTIVATION_EXECUTOR_REQUIRED.to_string())", self.content)

    def test_has_fixture_activation_executor(self):
        self.assertIn("struct FixtureActivationExecutor", self.content)
        self.assertIn("must not be cited as production activation evidence", self.content)

    def test_has_all_stages(self):
        for stage in ["SandboxCreate", "SecretMount", "CapabilityIssue", "HealthReady"]:
            self.assertIn(stage, self.content, f"Missing stage {stage}")

    def test_has_all_error_codes(self):
        for code in ["ACT_SANDBOX_FAILED", "ACT_SECRET_MOUNT_FAILED",
                     "ACT_CAPABILITY_FAILED", "ACT_HEALTH_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_secret_cleanup(self):
        self.assertIn("tracker.cleanup()", self.content)

    def test_has_verify_stage_order(self):
        self.assertIn("fn verify_stage_order", self.content)

    def test_has_transcripts_match(self):
        self.assertIn("fn transcripts_match", self.content)


class TestPipelineSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1d7n_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-ACT-STAGE-ORDER", "INV-ACT-NO-SECRET-LEAK",
                    "INV-ACT-DETERMINISTIC", "INV-ACT-HEALTH-LAST"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["ACT_SANDBOX_FAILED", "ACT_SECRET_MOUNT_FAILED",
                     "ACT_CAPABILITY_FAILED", "ACT_HEALTH_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestPipelineIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/activation_pipeline_determinism.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_stage_order(self):
        self.assertIn("inv_act_stage_order", self.content)

    def test_covers_fail_closed_default(self):
        self.assertIn("default_executor_fails_closed_without_real_hooks", self.content)
        self.assertIn("ACTIVATION_EXECUTOR_REQUIRED", self.content)

    def test_covers_health_last(self):
        self.assertIn("inv_act_health_last", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_act_deterministic", self.content)

    def test_covers_no_secret_leak(self):
        self.assertIn("inv_act_no_secret_leak", self.content)


if __name__ == "__main__":
    unittest.main()
