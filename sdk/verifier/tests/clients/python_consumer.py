"""Real isolated consumer: production bindings + trusted executable only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

from franken_verifier import (
    MAX_INPUT_BYTES, MAX_NATIVE_SESSION_INPUT_BYTES, MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES, MAX_SOURCE_GRAPH_REPORT_BYTES,
    VerifierError, verify_artifact,
)


def check_bounded_transport() -> int:
    """Exercise actual child pipes; these controls make no signature claims."""
    controls = [
        ("stdout_overflow", "PROTOCOL_INVALID"),
        ("stderr_overflow", "PROTOCOL_INVALID"),
        ("stdout_boundary", "TRANSPORT_CONTROL"),
        ("stderr_boundary", "TRANSPORT_CONTROL"),
        ("duplex", "TRANSPORT_CONTROL"),
        ("early_refusal", "TRANSPORT_CONTROL"),
        ("blocked_stdin", "PROCESS_TIMEOUT"),
        ("closed_streams_running", "PROCESS_TIMEOUT"),
    ]
    if os.name == "posix":
        controls.append(("inherited_pipes", "PROCESS_TIMEOUT"))
    data = bytes(range(256)) * 8192
    evidence = Path(tempfile.mkdtemp(prefix="franken-verifier-transport-"))
    failures = []
    for mode, expected in controls:
        pid_file = evidence / (mode + ".pid")
        old_mode = os.environ.get("FRANKEN_VERIFIER_TEST_TRANSPORT_CONTROL")
        old_pid_file = os.environ.get("FRANKEN_VERIFIER_TEST_PID_FILE")
        os.environ["FRANKEN_VERIFIER_TEST_TRANSPORT_CONTROL"] = mode
        os.environ["FRANKEN_VERIFIER_TEST_PID_FILE"] = str(pid_file)
        started = time.monotonic()
        try:
            try:
                verify_artifact(data, "11" * 32, verifier=str(Path.cwd() / "fake_verifier"), timeout=1)
            except VerifierError as error:
                assert error.code == expected, (mode, error.code, expected)
                if mode in ("stderr_boundary", "duplex"):
                    assert error.stderr == b"e" * (64 * 1024 + 1), mode
                if mode == "duplex":
                    assert str(error) == hashlib.sha256(data).hexdigest(), mode
                if mode == "early_refusal":
                    assert error.exit_code == 2 and error.stderr == b"\xff\x00private diagnostic\n", mode
            else:
                raise AssertionError((mode, "unexpected successful verification"))
            elapsed = time.monotonic() - started
            assert elapsed < 3, (mode, "deadline exceeded during pipe cleanup", elapsed)
            if os.name == "posix":
                pid = int(pid_file.read_text())
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
                else:
                    raise AssertionError((mode, "verifier child was not reaped"))
            print(json.dumps({"case": "transport_" + mode, "result": expected}), flush=True)
        except AssertionError as error:
            failures.append(str(error))
        finally:
            for key, previous in (("FRANKEN_VERIFIER_TEST_TRANSPORT_CONTROL", old_mode),
                                  ("FRANKEN_VERIFIER_TEST_PID_FILE", old_pid_file)):
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous
    assert not failures, "bounded transport regressions: " + "; ".join(failures)
    return len(controls)


if sys.argv[1:] == ["--transport-only"]:
    print(json.dumps({"transport_cases": check_bounded_transport(), "passed": True}), flush=True)
    raise SystemExit(0)

root = Path.cwd()
executable = os.environ.get("VERIFIER_EXECUTABLE", str(root / "verifier"))
for path in json.loads(os.environ.get("ABSENT_CHECKOUTS", "[]")):
    assert not Path(path).exists(), f"product checkout visible: {path}"
assert not (root / "Cargo.toml").exists()
assert not (root / "src").exists()
cases = json.loads((root / "vectors.json").read_text())
for case in cases:
    data = bytes.fromhex(case["input_hex"])
    try:
        result = verify_artifact(data, case["anchor"], verifier=executable,
                                 format=case["format"], signature_hex=case.get("signature_hex"),
                                 trusted_run_public_key_hex=case.get("run_anchor"),
                                 trusted_runtime_public_key_hex=case.get("runtime_anchor"),
                                 trusted_incident_public_key_hex=case.get("incident_anchor"),
                                 expected_baseline_integrity_hash=case.get("expected_baseline_integrity_hash"),
                                 trusted_revocation_public_key_hex=case.get("revocation_anchor"),
                                 trusted_provenance_public_key_hex=case.get("provenance_anchor"),
                                 evaluation_time=case.get("evaluation_time"),
                                 max_revocation_age_secs=case.get("max_revocation_age_secs"),
                                 trusted_fleet_policy=case.get("fleet_policy_path"),
                                 trusted_coordinator_id=case.get("coordinator_id"),
                                 trusted_coordinator_public_key_hex=case.get("coordinator_key_hex"),
                                 expected_manifest_sha256=case.get("expected_manifest_sha256"),
                                 expected_source_artifact_sha256=case.get("expected_source_artifact_sha256"),
                                 expected_graph_input_hash=case.get("expected_graph_input_hash"),
                                 graph_report=Path(case["graph_report_path"]) if "graph_report_path" in case else None,
                                 expected_session_nonce=case.get("expected_session_nonce"),
                                 expected_admission_sha256=case.get("expected_admission_sha256"),
                                 expected_archive_root_sha256=case.get("expected_archive_root_sha256"))
    except VerifierError as error:
        assert error.code == case["expected"], (case["name"], error.code, case["expected"])
        if case["format"] in ("publisher-source", "publisher-source-trust", "native-session-forensics", "native-session-cold-archive", "signed-session"):
            assert "PRIVATE-" not in str(error)
        print(json.dumps({"case": case["name"], "result": error.code}), flush=True)
    else:
        assert case["expected"] == "verified", case["name"]
        assert result["artifact_sha256"] == hashlib.sha256(data).hexdigest()
        if case["format"] == "incident-bundle":
            if "incident_graph_report" in case:
                assert result["facts"]["graph_report"] == case["incident_graph_report"], case["name"]
                assert result["facts"]["native_capture"] is not None
            else:
                assert "graph_report" not in result["facts"]
            if case.get("run_anchor") is not None:
                assert result["scope"] == ("authenticated_runtime_incident" if case.get("runtime_anchor") else "authenticated_run_incident")
                assert result["facts"]["run_origin"]["signer_public_key_hex"] == case["run_anchor"].lower()
                assert result["facts"]["run_origin"]["receipt_hash"].startswith("sha256:")
                if "event_count" in case:
                    assert result["facts"]["event_count"] == case["event_count"]
                if case.get("runtime_anchor") is not None:
                    assert result["facts"]["runtime_origin"]["product_root_key_id"] == "ed25519:" + case["runtime_anchor"]
                    assert result["facts"]["runtime_origin"]["signed_epoch"] == "18446744073709551615"
            else:
                assert result["scope"] == "authenticated_recorded_incident"
                assert result["facts"]["event_count"] == 3
                assert result["facts"]["signing_identity"] == "339eefa3a988f613"
                assert "run_origin" not in result["facts"]
        elif case["format"] == "native-session-forensics":
            assert result["scope"] == "authenticated_supervisor_observations"
            assert result["facts"] == case["native_facts"], case["name"]
            assert result["facts"]["replay_certified"] is False
            assert result["facts"]["quiescence_certified"] is False
            assert result["facts"]["historical_completeness"] is False
            assert isinstance(result["facts"]["security_epoch"], str)
        elif case["format"] == "native-session-cold-archive":
            assert result["scope"] == "authenticated_archived_supervisor_observations"
            assert result["facts"] == case["archive_facts"], case["name"]
            assert result["facts"]["archive_sha256"] == result["artifact_sha256"]
            assert all(result["facts"][field] is False for field in (
                "original_receipt_signatures_verified", "replay_certified",
                "quiescence_certified", "historical_completeness",
            ))
            assert "PRIVATE-" not in json.dumps(result["facts"])
        elif case["format"] == "resolution-receipt":
            assert result["scope"] == "authenticated_resolution_decision"
            assert result["facts"]["decision"] == case["decision"]
            assert result["facts"]["module_graph_hash"] == case["graph_hash"]
            assert result["facts"]["selected_version"] == ("1.2.3" if case["decision"] == "admit" else None)
            assert result["facts"]["capability_budget_mode"] == "enforced"
        if case["format"] == "signed-session":
            assert result["scope"] == "authenticated_verification_session"
            assert result["facts"] == case["session_facts"], case["name"]
            assert "steps" not in result["facts"]
            assert "replay_certified" not in result["facts"]
        if case["format"] == "publisher-source":
            assert result["scope"] == "authenticated_publisher_source_content"
            assert result["facts"] == case["publisher_facts"]
            assert result["facts"]["capsule"]["graph_hash_recomputed"] is False
        if case["format"] == "publisher-source-trust":
            assert result["scope"] == "authenticated_publisher_source_trust"
            assert result["facts"] == case["publisher_trust_facts"]
            assert result["facts"]["source"]["capsule"]["graph_hash_recomputed"] is False
        if case["format"] == "counterfactual-receipt":
            assert result["scope"] == "authenticated_counterfactual_receipt"
            assert result["facts"]["mode"] == case["cf_mode"]
            assert result["facts"]["result_count"] == case["cf_count"]
            assert result["facts"]["baseline_integrity_hash"] == case["cf_baseline"]
        if case["format"] == "counterfactual-incident":
            assert result["scope"] == "authenticated_counterfactual_incident"
            facts = result["facts"]
            assert facts["mode"] == case["cf_mode"]
            assert facts["result_count"] == case["cf_count"]
            assert facts["baseline_integrity_hash"] == case["cf_baseline"]
            assert facts["counterfactual_output_sha256"] == case["cf_output_hash"]
            assert facts["signer_public_key_hex"] == case["anchor"]
            assert facts["guest_execution_verified"] is False
            assert facts["baseline"]["integrity_hash"] == case["cf_baseline"]
            assert facts["baseline"]["signer_public_key_hex"] == case["incident_anchor"]
            expected_scope = "authenticated_recorded_incident"
            if case.get("run_anchor") is not None:
                expected_scope = "authenticated_run_incident"
                assert facts["baseline"]["run_origin"]["signer_public_key_hex"] == case["run_anchor"]
            if case.get("runtime_anchor") is not None:
                expected_scope = "authenticated_runtime_incident"
                assert facts["baseline"]["runtime_origin"]["product_root_key_id"] == "ed25519:" + case["runtime_anchor"]
                assert facts["baseline"]["runtime_origin"]["signed_epoch"] == "18446744073709551615"
            assert facts["baseline_scope"] == expected_scope
        if case["format"] == "counterfactual-promotion":
            assert result["scope"] == "authenticated_counterfactual_promotion"
            facts = result["facts"]
            for key, expected in case.get("promotion_expected", {}).items():
                assert facts[key] == expected, (case["name"], key, facts[key], expected)
            assert facts["baseline_integrity_hash"] == case["expected_baseline_integrity_hash"]
            assert facts["baseline"]["integrity_hash"] == case["expected_baseline_integrity_hash"]
            assert facts["signer_public_key_hex"] == case["anchor"].lower()
            assert facts["baseline"]["signer_public_key_hex"] == case["incident_anchor"].lower()
            report_bytes = base64.b64decode(json.loads(data)["report_base64"], validate=True)
            assert facts["report_sha256"] == hashlib.sha256(report_bytes).hexdigest()
            assert facts["guest_execution_verified"] is False
            assert facts["rollout_authorized"] is False
            assert facts["executor"] in ("synthetic", "production")
            assert facts["mode"] in ("single", "sweep")
            assert 1 <= facts["result_count"] <= 20
            assert all(isinstance(facts[key], str) for key in (
                "expected_loss_delta", "valid_from_epoch_ms", "valid_until_epoch_ms"))
            assert int(facts["expected_loss_delta"]) > 0
            assert int(facts["valid_until_epoch_ms"]) > int(facts["valid_from_epoch_ms"])
            expected_scope = ("authenticated_runtime_incident" if case.get("runtime_anchor") else
                              "authenticated_run_incident" if case.get("run_anchor") else
                              "authenticated_recorded_incident")
            assert facts["baseline_scope"] == expected_scope
            if case.get("run_anchor"):
                assert facts["baseline"]["run_origin"]["signer_public_key_hex"] == case["run_anchor"].lower()
            if case.get("runtime_anchor"):
                assert facts["baseline"]["runtime_origin"]["product_root_key_id"] == "ed25519:" + case["runtime_anchor"].lower()
        if case["format"] == "ltv-evidence":
            assert result["scope"] == "authenticated_ltv_anteriority"
            assert result["facts"] == case["ltv_facts"], case["name"]
        if case["format"] == "fleet-quiescence-observations":
            assert result["scope"] == "authenticated_fleet_supervisor_observations"
            assert result["facts"] == case["fleet_facts"], case["name"]
            assert result["facts"]["epoch_commit_authenticated"] is False
            assert result["facts"]["current_quiescence_proven"] is False
            assert isinstance(result["facts"]["admitted_sessions"], str)
            assert isinstance(result["facts"]["terminal_sessions"], str)
            assert result["facts"]["trusted_policy_input_sha256"] == hashlib.sha256(
                Path(case["fleet_policy_path"]).read_bytes()).hexdigest()
            assert "trace-maintenance" not in json.dumps(result)
        if case["format"] == "fleet-epoch-commit":
            assert result["scope"] == "authenticated_fleet_epoch_commit"
            assert result["facts"] == case["epoch_facts"], case["name"]
            assert result["facts"]["epoch_commit_authenticated"] is True
            assert result["facts"]["current_quiescence_proven"] is False
            assert isinstance(result["facts"]["committed_epoch"], str)
            assert isinstance(result["facts"]["admitted_sessions"], str)
            assert result["facts"]["trusted_policy_input_sha256"] == hashlib.sha256(
                Path(case["fleet_policy_path"]).read_bytes()).hexdigest()
            assert "trace-maintenance" not in json.dumps(result)
        assert "PRIVATE-" not in json.dumps(result)
        print(json.dumps({"case": case["name"], "result": "verified", "scope": result["scope"]}), flush=True)

cf_incident_case = next(case for case in cases if case["name"] == "counterfactual_incident_runtime_origin")
cf_incident_options = {
    "verifier": str(root / "fake_verifier"), "format": "counterfactual-incident",
    "signature_hex": cf_incident_case["signature_hex"],
    "trusted_incident_public_key_hex": cf_incident_case["incident_anchor"],
    "expected_baseline_integrity_hash": cf_incident_case["expected_baseline_integrity_hash"],
    "trusted_run_public_key_hex": cf_incident_case["run_anchor"],
    "trusted_runtime_public_key_hex": cf_incident_case["runtime_anchor"],
}
for mode in (
    "cf_incident_wrong_pin", "cf_incident_wrong_nested_pin", "cf_incident_wrong_receipt_signer",
    "cf_incident_wrong_exporter", "cf_incident_guest_execution_claim", "cf_incident_wrong_scope",
    "cf_incident_downgraded_baseline", "cf_incident_missing_run_origin", "cf_incident_missing_runtime_origin",
    "cf_incident_extra_field", "cf_incident_bad_output_hash", "cf_incident_noncanonical_output_hash",
    "cf_incident_boolean_count", "cf_incident_excessive_count", "cf_incident_single_count_mismatch",
):
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cf_incident_case["anchor"],
                        **cf_incident_options)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
cf_incident_protocol = verify_artifact(json.dumps({"protocol_control": "cf_incident_valid"}).encode(),
                                      cf_incident_case["anchor"], **cf_incident_options)
assert cf_incident_protocol["facts"]["baseline_scope"] == "authenticated_runtime_incident"
assert cf_incident_protocol["facts"]["guest_execution_verified"] is False
print(json.dumps({"case": "protocol_cf_incident_valid", "result": "verified"}), flush=True)

promotion_cases = [case for case in cases if case["format"] == "counterfactual-promotion"]
assert sum(case["expected"] == "verified" for case in promotion_cases) >= 5
assert sum(case["expected"] != "verified" for case in promotion_cases) >= 20
promotion_case = next(case for case in promotion_cases if case["expected"] == "verified" and case.get("runtime_anchor"))
promotion_options = {
    "verifier": str(root / "fake_verifier"), "format": "counterfactual-promotion",
    "trusted_incident_public_key_hex": promotion_case["incident_anchor"],
    "expected_baseline_integrity_hash": promotion_case["expected_baseline_integrity_hash"],
    "trusted_run_public_key_hex": promotion_case["run_anchor"],
    "trusted_runtime_public_key_hex": promotion_case["runtime_anchor"],
}
promotion_controls = [
    "cf_promotion_wrong_scope", "cf_promotion_wrong_format", "cf_promotion_wrong_signer",
    "cf_promotion_wrong_pin", "cf_promotion_wrong_nested_pin", "cf_promotion_wrong_exporter",
    "cf_promotion_wrong_run_signer", "cf_promotion_wrong_runtime_key", "cf_promotion_missing_run_origin",
    "cf_promotion_missing_runtime_origin", "cf_promotion_downgraded_baseline", "cf_promotion_missing_field",
    "cf_promotion_extra_field", "cf_promotion_bad_report_hash", "cf_promotion_bad_output_hash",
    "cf_promotion_bad_counterfactual_digest", "cf_promotion_bad_contract_digest", "cf_promotion_empty_operator",
    "cf_promotion_operator_whitespace", "cf_promotion_operator_control", "cf_promotion_operator_oversize",
    "cf_promotion_operator_surrogate", "cf_promotion_empty_mitigation", "cf_promotion_mitigation_whitespace",
    "cf_promotion_mitigation_control", "cf_promotion_invalid_executor", "cf_promotion_invalid_mode",
    "cf_promotion_zero_count", "cf_promotion_boolean_count", "cf_promotion_single_count_mismatch",
    "cf_promotion_excessive_count", "cf_promotion_numeric_delta", "cf_promotion_overflow_delta",
    "cf_promotion_zero_delta", "cf_promotion_negative_delta", "cf_promotion_noncanonical_delta",
    "cf_promotion_numeric_from", "cf_promotion_underflow_from", "cf_promotion_plus_from",
    "cf_promotion_negative_zero_from", "cf_promotion_numeric_until", "cf_promotion_overflow_until",
    "cf_promotion_newline_until", "cf_promotion_empty_window", "cf_promotion_reversed_window",
    "cf_promotion_guest_execution_claim", "cf_promotion_rollout_claim", "cf_promotion_boolean_number",
]
for mode in promotion_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), promotion_case["anchor"],
                        **promotion_options)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
for mode in ("cf_promotion_valid", "cf_promotion_valid_sweep"):
    promoted = verify_artifact(json.dumps({"protocol_control": mode}).encode(), promotion_case["anchor"],
                               **promotion_options)
    assert promoted["facts"]["rollout_authorized"] is False
    assert promoted["facts"]["guest_execution_verified"] is False
    assert promoted["facts"]["expected_loss_delta"] == (
        "9223372036854775807" if mode.endswith("_sweep") else "9007199254740993")
    assert promoted["facts"]["valid_from_epoch_ms"] == ("0" if mode.endswith("_sweep") else "-9223372036854775808")
    print(json.dumps({"case": f"protocol_{mode}", "result": "verified"}), flush=True)
promotion_inputs = [
    ("promotion_missing_exporter", {"trusted_incident_public_key_hex": None}, "INCIDENT_ANCHOR_INVALID"),
    ("promotion_bad_exporter", {"trusted_incident_public_key_hex": "bad-key"}, "INCIDENT_ANCHOR_INVALID"),
    ("promotion_missing_pin", {"expected_baseline_integrity_hash": None}, "EXPECTED_BASELINE_INVALID"),
    ("promotion_noncanonical_pin", {"expected_baseline_integrity_hash": "A" * 64}, "EXPECTED_BASELINE_INVALID"),
    ("promotion_prefixed_pin", {"expected_baseline_integrity_hash": "sha256:" + "a" * 64}, "EXPECTED_BASELINE_INVALID"),
    ("promotion_detached_signature", {"signature_hex": "00" * 64}, "INPUT_INVALID"),
    ("promotion_runtime_requires_run", {"trusted_run_public_key_hex": None}, "INPUT_INVALID"),
]
for name, overrides, code in promotion_inputs:
    try:
        verify_artifact(b"{}", promotion_case["anchor"], **{**promotion_options, **overrides})
    except VerifierError as error:
        assert error.code == code, (name, error.code, code)
        print(json.dumps({"case": name, "result": code}), flush=True)
    else:
        raise AssertionError(name)

fleet_case = next(case for case in cases if case["name"] == "fleet_independent_http_observations")
epoch_case = next(case for case in cases if case["name"] == "epoch_independent_http_commit")
epoch_controls = [
    "epoch_wrong_scope", "epoch_wrong_format", "epoch_wrong_schema", "epoch_missing_field",
    "epoch_unknown_field", "epoch_wrong_coordinator", "epoch_wrong_key", "epoch_missing_commit_claim",
    "epoch_current_quiescence_claim", "epoch_numeric_epoch", "epoch_noncanonical_epoch",
    "epoch_overflow_epoch", "epoch_wrong_committed_epoch", "epoch_bad_statement_hash",
    "epoch_uppercase_statement_hash", "epoch_empty_transition", "epoch_transition_control",
    "epoch_wrong_policy_input", "epoch_wrong_evidence_input", "epoch_unverified_supervisors",
]
for mode in epoch_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), None,
                        verifier=str(root / "fake_verifier"), format="fleet-epoch-commit",
                        trusted_fleet_policy=epoch_case["fleet_policy_path"],
                        trusted_coordinator_id=epoch_case["coordinator_id"],
                        trusted_coordinator_public_key_hex=epoch_case["coordinator_key_hex"])
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
for name in ("epoch_independent_http_commit", "epoch_exact_u64_maximum_commit"):
    candidate = next(case for case in cases if case["name"] == name)
    result = verify_artifact(json.dumps({"protocol_control": "epoch_valid"}).encode(), None,
                             verifier=str(root / "fake_verifier"), format="fleet-epoch-commit",
                             trusted_fleet_policy=candidate["fleet_policy_path"],
                             trusted_coordinator_id=epoch_case["coordinator_id"],
                             trusted_coordinator_public_key_hex=epoch_case["coordinator_key_hex"])
    assert result["facts"]["committed_epoch"] == candidate["epoch_facts"]["committed_epoch"]
    assert result["facts"]["epoch_commit_authenticated"] is True
    assert result["facts"]["current_quiescence_proven"] is False
    print(json.dumps({"case": f"protocol_{name}", "result": "verified"}), flush=True)
    try:
        verify_artifact(json.dumps({"protocol_control": "epoch_wrong_committed_epoch"}).encode(), None,
                        verifier=str(root / "fake_verifier"), format="fleet-epoch-commit",
                        trusted_fleet_policy=candidate["fleet_policy_path"],
                        trusted_coordinator_id=epoch_case["coordinator_id"],
                        trusted_coordinator_public_key_hex=epoch_case["coordinator_key_hex"])
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (name, error.code)
        print(json.dumps({"case": f"protocol_wrong_epoch_{name}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_wrong_epoch_{name}")
fleet_controls = [
    "fleet_wrong_scope", "fleet_wrong_format", "fleet_unknown_field", "fleet_missing_field",
    "fleet_wrong_policy_input", "fleet_canonical_hash_as_input_hash", "fleet_malformed_policy_hash",
    "fleet_wrong_evidence_input", "fleet_wrong_evaluation_time", "fleet_stale_observation",
    "fleet_future_observation", "fleet_wrong_population", "fleet_boolean_population",
    "fleet_numeric_count", "fleet_noncanonical_count", "fleet_overflow_count", "fleet_terminal_mismatch",
    "fleet_unverified_signatures", "fleet_incomplete_population", "fleet_unmatched_action_context",
    "fleet_epoch_commit_claim", "fleet_current_quiescence_claim",
]
for mode in fleet_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), None,
                        verifier=str(root / "fake_verifier"), format="fleet-quiescence-observations",
                        trusted_fleet_policy=fleet_case["fleet_policy_path"])
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
for mode, count in (("fleet_valid", str(2**64 - 1)), ("fleet_valid_empty_session_set", "0")):
    result = verify_artifact(json.dumps({"protocol_control": mode}).encode(), None,
                             verifier=str(root / "fake_verifier"), format="fleet-quiescence-observations",
                             trusted_fleet_policy=fleet_case["fleet_policy_path"])
    assert result["facts"]["admitted_sessions"] == count
    assert result["facts"]["terminal_sessions"] == count
    assert result["facts"]["epoch_commit_authenticated"] is False
    assert result["facts"]["current_quiescence_proven"] is False
    print(json.dumps({"case": f"protocol_{mode}", "result": "verified"}), flush=True)

session_controls = [
    "session_wrong_scope", "session_wrong_signer", "session_unknown_field", "session_missing_field",
    "session_boolean_count", "session_negative_count", "session_excessive_count",
    "session_empty_pass", "session_nonempty_inconclusive", "session_bad_identity",
    "session_empty_id", "session_long_id", "session_id_newline", "session_bad_time",
    "session_bad_verdict", "session_bad_hash", "session_uppercase_hash",
]
for mode in session_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="signed-session")
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
for mode, verdict in (("session_valid", "pass"), ("session_fail", "fail"), ("session_empty", "inconclusive")):
    result = verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                             verifier=str(root / "fake_verifier"), format="signed-session")
    assert result["facts"]["final_verdict"] == verdict
    assert (result["facts"]["step_count"] == 0) == (verdict == "inconclusive")
    print(json.dumps({"case": f"protocol_{mode}", "result": "verified"}), flush=True)

client_controls = [
    ("oversize_client_input", b" " * (MAX_INPUT_BYTES + 1), {}, "INPUT_TOO_LARGE"),
    ("bad_key_shape", b"{}", {"trusted_public_key_hex": "00"}, "ANCHOR_INVALID"),
    ("bad_run_key_shape", b"{}", {"trusted_run_public_key_hex": "00"}, "RUN_ANCHOR_INVALID"),
    ("run_key_wrong_format", b"{}", {"format": "capsule", "trusted_run_public_key_hex": cases[0]["anchor"]}, "INPUT_INVALID"),
    ("runtime_key_requires_run_key", b"{}", {"trusted_runtime_public_key_hex": cases[0]["anchor"]}, "INPUT_INVALID"),
    ("bad_runtime_key_shape", b"{}", {"trusted_run_public_key_hex": cases[0]["anchor"], "trusted_runtime_public_key_hex": "00"}, "RUNTIME_ANCHOR_INVALID"),
    ("native_detached_signature_refused", b"{}", {"format": "native-session-forensics", "signature_hex": "00" * 64}, "INPUT_INVALID"),
    ("native_run_anchor_refused", b"{}", {"format": "native-session-forensics", "trusted_run_public_key_hex": cases[0]["anchor"]}, "INPUT_INVALID"),
    ("session_detached_signature_refused", b"{}", {"format": "signed-session", "signature_hex": "00" * 64}, "INPUT_INVALID"),
    ("session_run_anchor_refused", b"{}", {"format": "signed-session", "trusted_run_public_key_hex": cases[0]["anchor"]}, "INPUT_INVALID"),
    ("invalid_timeout", b"{}", {"timeout": 0}, "TIMEOUT_INVALID"),
    ("enormous_timeout_integer", b"{}", {"timeout": 10**1000}, "TIMEOUT_INVALID"),
    ("missing_executable", b"{}", {"verifier": str(root / "does-not-exist")}, "PROCESS_UNAVAILABLE"),
]
for label, data, options, expected in client_controls:
    kwargs = {"verifier": str(root / "verifier"), "trusted_public_key_hex": cases[0]["anchor"], **options}
    try:
        verify_artifact(data, **kwargs)
    except VerifierError as error:
        assert error.code == expected, (label, error.code)
        print(json.dumps({"case": label, "result": error.code}), flush=True)
    else:
        raise AssertionError(label)
controls = ["malformed", "duplicate", "wrong_schema", "wrong_scope", "wrong_hash", "wrong_anchor",
            "unsafe_count", "invalid_capture_state", "extra_member", "success_with_failure_exit",
            "rejection_with_success_exit", "invalid_utf8", "oversize", "deep_response", "timeout"]
for mode in controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), timeout=0.1 if mode == "timeout" else 10)
    except VerifierError as error:
        expected = "PROCESS_TIMEOUT" if mode == "timeout" else "PROTOCOL_INVALID"
        assert error.code == expected, (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")

run_anchor = next(case["anchor"] for case in cases if case["name"] == "foreign_anchor")
run_controls = ["run_scope_downgrade", "run_origin_missing", "run_wrong_anchor",
                "run_invalid_receipt_id", "run_invalid_receipt_hash", "run_invalid_record_digest",
                "run_extra_origin_field", "run_origin_non_object", "run_duplicate_origin"]
for mode in run_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), trusted_run_public_key_hex=run_anchor.upper())
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
try:
    verify_artifact(b'{"protocol_control":"run_unrequested_scope"}', cases[0]["anchor"],
                    verifier=str(root / "fake_verifier"))
except VerifierError as error:
    assert error.code == "PROTOCOL_INVALID", error.code
    print(json.dumps({"case": "protocol_run_unrequested_scope", "result": error.code}), flush=True)
else:
    raise AssertionError("unsolicited original-run authority was accepted")
runtime_anchor = next(case["runtime_anchor"] for case in cases if case["name"] == "independently_signed_runtime_origin")
runtime_controls = ["runtime_scope_downgrade", "runtime_origin_missing", "runtime_wrong_root",
                    "runtime_rounded_epoch", "runtime_overflow_epoch", "runtime_extra_claim"]
for mode in runtime_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), trusted_run_public_key_hex=run_anchor,
                        trusted_runtime_public_key_hex=runtime_anchor.upper())
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
native_controls = [
  "native_wrong_scope",
  "native_wrong_nested_scope",
  "native_wrong_root",
  "native_bad_nonce",
  "native_bad_admission_digest",
  "native_bad_paths",
  "native_numeric_epoch",
  "native_overflow_epoch",
  "native_noncanonical_epoch",
  "native_negative_epoch",
  "native_epoch_trailing_newline",
  "native_bad_admission_time",
  "native_bad_observation_time",
  "native_unknown_field",
  "native_missing_field",
  "native_pending_with_outcome",
  "native_impossible_process",
  "native_impossible_effect",
  "native_unknown_outcome",
  "native_unsafe_count",
  "native_boolean_count",
  "native_missing_count",
  "native_impossible_wal_count",
  "native_missing_completeness",
  "native_impossible_ledger_count",
  "native_replay_claim",
  "native_quiescence_claim",
  "native_history_claim",
  "native_v1_with_journal",
  "native_v2_without_journal",
  "native_unknown_schema",
  "native_journal_wrong_nonce",
  "native_journal_wrong_root",
  "native_journal_wrong_admission",
  "native_journal_wrong_scope",
  "native_journal_wrong_schema",
  "native_journal_empty_prefix",
  "native_journal_event_mismatch",
  "native_journal_call_mismatch",
  "native_journal_missing_pending",
  "native_journal_bad_head",
  "native_journal_bad_torn_flag",
  "native_journal_unknown_field",
  "native_journal_replay_claim",
  "native_journal_quiescence_claim",
  "native_journal_history_claim",
  "native_journal_contradicts_complete_outcome",
  "native_v3_missing_source",
  "native_v3_null_source",
  "native_v3_source_wrong_schema",
  "native_v3_source_wrong_graph",
  "native_v3_source_graph_claim",
  "native_v3_source_unknown_field",
  "native_v3_source_oversize",
  "native_v3_source_payload_oversize",
  "native_v3_source_payload_exceeds_capsule",
  "native_v3_source_counts_disagree",
  "native_v3_source_boolean_count",
  "native_v3_source_excess_inputs",
  "native_v3_source_forbidden_symlink",
  "native_v3_source_excess_conditions",
  "native_v3_source_on_v1",
  "native_v3_source_on_v2",
]
for mode in native_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="native-session-forensics")
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": "protocol_" + mode, "result": error.code}), flush=True)
    else:
        raise AssertionError("protocol_" + mode)
native_positives = ["native_valid", "native_zero_epoch", "native_pending_prefix", "native_incomplete_with_later_journal",
                    "native_v3_valid", "native_v3_without_journal", "native_v3_maximum_source"]
for mode in native_positives:
    verified = verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                               verifier=str(root / "fake_verifier"), format="native-session-forensics")
    assert verified["scope"] == "authenticated_supervisor_observations", mode
    assert verified["facts"]["historical_completeness"] is False, mode
    if mode == "native_pending_prefix":
        assert verified["facts"]["completed_provider_calls"] is None
        assert verified["facts"]["durable_journal"]["admitted_provider_calls"] == 2
    if mode == "native_incomplete_with_later_journal":
        assert verified["facts"]["journal_complete"] is False
        assert verified["facts"]["durable_journal"]["returned_provider_calls"] == 1
    if mode.startswith("native_v3_"):
        assert verified["facts"]["source_capsule"]["graph_hash_recomputed"] is False
        assert verified["facts"]["source_capsule"]["input_count"] == 3
    if mode == "native_v3_without_journal":
        assert verified["facts"]["durable_journal"] is None
    print(json.dumps({"case": "protocol_" + mode, "result": "verified"}), flush=True)

# A distributed executable must not silently ignore a requested admission.
native_identity_pins = {
    "expected_session_nonce": "0199abcd-1234-7000-8000-123456789abc",
    "expected_admission_sha256": "a" * 64,
}
native_identity_input = json.dumps({"protocol_control": "native_valid"}).encode()
verify_artifact(native_identity_input, cases[0]["anchor"], verifier=str(root / "fake_verifier"),
                format="native-session-forensics", **native_identity_pins)
for field, value in (("expected_session_nonce", "0199abcd-1234-7000-8000-123456789abd"),
                     ("expected_admission_sha256", "b" * 64)):
    try:
        verify_artifact(native_identity_input, cases[0]["anchor"], verifier=str(root / "fake_verifier"),
                        format="native-session-forensics", **{**native_identity_pins, field: value})
    except VerifierError as error:
        assert error.code == "EXPECTED_NATIVE_IDENTITY_MISMATCH", (field, error.code)
        assert value not in str(error)
    else:
        raise AssertionError("executable ignored " + field)
    print(json.dumps({"case": "native_ignored_" + field, "result": "EXPECTED_NATIVE_IDENTITY_MISMATCH"}), flush=True)

# BEGIN cold archive protocol controls (fake child; no signature claims).
archive_client_cases = 0
archive_protocol_cases = 0
archive_root_pin = "a" * 64
for pin in ("", False, 7, [], {}, b"a" * 64, "a" * 63, "A" * 64, "sha256:" + "a" * 64, "a" * 64 + "\n"):
    try:
        verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist",
                        format="native-session-cold-archive", expected_archive_root_sha256=pin)
    except VerifierError as error:
        assert error.code == "EXPECTED_ARCHIVE_ROOT_INVALID" and error.exit_code is None
    else:
        raise AssertionError("invalid archive root pin reached the child")
    archive_client_cases += 1
for format in ("incident-bundle", "native-session-forensics", "capsule", "signed-session"):
    try:
        verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist",
                        format=format, expected_archive_root_sha256=archive_root_pin)
    except VerifierError as error:
        assert error.code == "EXPECTED_ARCHIVE_ROOT_INVALID" and error.exit_code is None
    else:
        raise AssertionError("archive pin accepted for " + format)
    archive_client_cases += 1
for untrusted in (None, "", "aa", False):
    try:
        verify_artifact(b"{}", untrusted, verifier=root / "does-not-exist", format="native-session-cold-archive")
    except VerifierError as error:
        assert error.code == "ANCHOR_INVALID" and error.exit_code is None
    else:
        raise AssertionError("archive evidence selected its own product root")
    archive_client_cases += 1
for options, expected in (
    ({"graph_report": "PRIVATE-missing-report"}, "INPUT_INVALID"),
    ({"signature_hex": "00" * 64}, "INPUT_INVALID"),
    ({"expected_session_nonce": "0199abcd-1234-7000-8000-123456789abc",
      "expected_admission_sha256": "a" * 64}, "EXPECTED_NATIVE_IDENTITY_INVALID"),
    ({"expected_manifest_sha256": "sha256:" + "a" * 64}, "EXPECTED_IDENTITY_INVALID"),
):
    try:
        verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist",
                        format="native-session-cold-archive", **options)
    except VerifierError as error:
        assert error.code == expected and error.exit_code is None and "PRIVATE-" not in str(error)
    else:
        raise AssertionError("unrelated evidence option accepted for an archive")
    archive_client_cases += 1
archive_controls = [
    "wrong_schema", "wrong_scope", "wrong_nested_scope", "wrong_signer", "wrong_root_key", "substituted_bytes",
    "bad_archive_digest", "uppercase_merkle", "prefixed_merkle", "newline_merkle", "short_merkle",
    "invalid_time", "empty_population", "excess_population", "boolean_population", "fractional_population",
    "string_population", "excess_sources", "negative_sources", "boolean_sources", "original_signatures_claim",
    "replay_claim", "quiescence_claim", "history_claim", "numeric_proof_flag", "missing_root",
    "missing_proof_flag", "unknown_field", "missing_identities", "partial_identities", "excess_identities",
    "negative_identities", "boolean_identities", "fractional_identities", "string_identities",
]
for prefix in ("", "v2_"):
    controls = archive_controls + (["empty_identities"] if prefix else [])
    for control in controls:
        try:
            verify_artifact(json.dumps({"protocol_control": "archive_" + prefix + control}).encode(), cases[0]["anchor"],
                            verifier=root / "fake_verifier", format="native-session-cold-archive",
                            expected_archive_root_sha256=archive_root_pin)
        except VerifierError as error:
            assert error.code == "PROTOCOL_INVALID" and "PRIVATE-" not in str(error), (prefix, control, error.code)
        else:
            raise AssertionError("invalid archive facts accepted: " + prefix + control)
        archive_protocol_cases += 1
    for control in ("valid", "maximum_population", "forwarded"):
        data = json.dumps({"protocol_control": "archive_" + prefix + control}).encode()
        options = {"expected_archive_root_sha256": archive_root_pin} if control == "forwarded" else {}
        verified = verify_artifact(data, cases[0]["anchor"].upper(), verifier=root / "fake_verifier",
                                   format="native-session-cold-archive", **options)
        assert verified["scope"] == "authenticated_archived_supervisor_observations"
        assert verified["facts"]["archive_sha256"] == hashlib.sha256(data).hexdigest()
        assert all(verified["facts"][field] is False for field in (
            "original_receipt_signatures_verified", "replay_certified", "quiescence_certified",
            "historical_completeness",
        ))
        assert verified["facts"]["session_count"] == (16_384 if control == "maximum_population" else 3)
        assert verified["facts"]["schema_version"] == "franken-node/native-session-cold-archive/" + ("v2" if prefix else "v1")
        assert verified["facts"]["identity_captures_verified"] == (verified["facts"]["session_count"] if prefix else 0)
        archive_protocol_cases += 1
try:
    verify_artifact(json.dumps({"protocol_control": "archive_ignored_pin"}).encode(), cases[0]["anchor"],
                    verifier=root / "fake_verifier", format="native-session-cold-archive",
                    expected_archive_root_sha256="b" * 64)
except VerifierError as error:
    assert error.code == "EXPECTED_ARCHIVE_ROOT_MISMATCH" and "b" * 64 not in str(error)
else:
    raise AssertionError("child ignored the archive population pin")
archive_protocol_cases += 1
assert MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES == 64 * 1024 * 1024
try:
    verify_artifact(bytes(MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES + 1), cases[0]["anchor"],
                    verifier=root / "does-not-exist", format="native-session-cold-archive")
except VerifierError as error:
    assert error.code == "INPUT_TOO_LARGE" and error.exit_code is None
else:
    raise AssertionError("oversized archive reached the child")
archive_client_cases += 1
# END cold archive protocol controls.

# Exercise the exact transport boundary without launching a subprocess or
# constructing a large JSON/base64 artifact. Other formats retain their cap.
assert MAX_NATIVE_SESSION_INPUT_BYTES == 96 * 1024 * 1024
for size, expected in ((MAX_NATIVE_SESSION_INPUT_BYTES, "EXECUTABLE_INVALID"),
                       (MAX_NATIVE_SESSION_INPUT_BYTES + 1, "INPUT_TOO_LARGE")):
    try:
        verify_artifact(bytes(size), cases[0]["anchor"], verifier="", format="native-session-forensics")
    except VerifierError as error:
        assert error.code == expected, (size, error.code)
    else:
        raise AssertionError("native transport boundary must reject before execution")
    print(json.dumps({"case": f"native_transport_boundary_{size}", "result": expected}), flush=True)

resolution_controls = ["resolution_invalid_decision", "resolution_reject_with_candidate",
                       "resolution_admit_without_candidate", "resolution_bad_graph", "resolution_wrong_signer",
                       "resolution_unsafe_count", "resolution_wrong_scope", "resolution_unknown_field",
                       "resolution_bad_profile", "resolution_bad_budget_mode", "resolution_invalid_unicode"]
for mode in resolution_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="resolution-receipt")
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
publisher_controls = ["publisher_wrong_scope", "publisher_wrong_signer", "publisher_graph_recomputed",
                      "publisher_unknown_field", "publisher_authority_missing", "publisher_v1_authority",
                      "publisher_rounded_ceiling", "publisher_overflow_ceiling", "publisher_zero_ceiling",
                      "publisher_invalid_capability", "publisher_authority_extra", "publisher_count_inconsistent",
                      "publisher_unsafe_count", "publisher_bad_digest", "publisher_capsule_not_object",
                      "publisher_host_null", "publisher_host_unknown_field", "publisher_host_missing_quotas",
                      "publisher_host_numeric_quota", "publisher_host_overflow_quota", "publisher_host_beyond_instruction_quota",
                      "publisher_host_undeclared_quota", "publisher_host_noncanonical_quota", "publisher_host_quota_newline",
                      "publisher_host_wildcard", "publisher_host_url", "publisher_host_invalid_port", "publisher_host_uppercase",
                      "publisher_host_invalid_ipv6", "publisher_host_duplicate_scope", "publisher_host_unsorted_scope",
                      "publisher_host_null_scope", "publisher_host_undeclared_scope", "publisher_host_invalid_env",
                      "publisher_host_env_newline", "publisher_host_excessive_scope",
                      "publisher_host_process_undeclared", "publisher_host_process_overflow",
                      "publisher_host_process_beyond_instruction"]
for mode in publisher_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="publisher-source", signature_hex="00" * 64)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
publisher_host_positives = ["publisher_host_valid", "publisher_host_empty", "publisher_host_unspecified",
                           "publisher_host_process_maximum", "publisher_host_process_zero"]
for mode in publisher_host_positives:
    verified = verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                               verifier=str(root / "fake_verifier"), format="publisher-source", signature_hex="00" * 64)
    host = verified["facts"]["runtime_authority"]["host_io"]
    if mode == "publisher_host_valid":
        assert host["max_calls_per_epoch"]["network_egress"] == "18446744073709551615"
        assert host["max_calls_per_epoch"]["fs_read"] == "0"
        assert host["host_ports"] == ["[2001:db8::1]:443", "api.example.test:443"]
    elif mode == "publisher_host_empty":
        assert host == {"host_ports": [], "env_keys": [], "max_calls_per_epoch": {}}
    elif mode == "publisher_host_unspecified":
        assert host == {"max_calls_per_epoch": {"fs_read": "0"}}
    else:
        assert host["max_calls_per_epoch"]["process_spawn"] == ("0" if mode.endswith("_zero") else "18446744073709551615")
        assert len(host["max_calls_per_epoch"]) == 6
    print(json.dumps({"case": f"protocol_{mode}", "result": "verified"}), flush=True)
publisher_trust_options = {
    "format": "publisher-source-trust", "signature_hex": "00" * 64,
    "trusted_revocation_public_key_hex": "11" * 32,
    "trusted_provenance_public_key_hex": "22" * 32,
    "evaluation_time": "2026-10-24T00:00:30.123456789Z",
    "max_revocation_age_secs": "60",
}
publisher_trust_inputs = [
    ("trust_missing_revocation_key", {"trusted_revocation_public_key_hex": None}, "REVOCATION_ANCHOR_INVALID"),
    ("trust_bad_revocation_key", {"trusted_revocation_public_key_hex": "00"}, "REVOCATION_ANCHOR_INVALID"),
    ("trust_bad_provenance_key", {"trusted_provenance_public_key_hex": "00"}, "PROVENANCE_ANCHOR_INVALID"),
    ("trust_missing_time", {"evaluation_time": None}, "EVALUATION_TIME_INVALID"),
    ("trust_invalid_calendar_date", {"evaluation_time": "2026-02-30T00:00:00Z"}, "EVALUATION_TIME_INVALID"),
    ("trust_leap_second", {"evaluation_time": "2026-10-24T00:00:60Z"}, "EVALUATION_TIME_INVALID"),
    ("trust_excess_time_precision", {"evaluation_time": "2026-10-24T00:00:30.1234567890Z"}, "EVALUATION_TIME_INVALID"),
    ("trust_time_trailing_newline", {"evaluation_time": "2026-10-24T00:00:30Z\n"}, "EVALUATION_TIME_INVALID"),
    ("trust_missing_window", {"max_revocation_age_secs": None}, "REVOCATION_FRESHNESS_POLICY_INVALID"),
    ("trust_numeric_window", {"max_revocation_age_secs": 60}, "REVOCATION_FRESHNESS_POLICY_INVALID"),
    ("trust_zero_window", {"max_revocation_age_secs": "0"}, "REVOCATION_FRESHNESS_POLICY_INVALID"),
    ("trust_noncanonical_window", {"max_revocation_age_secs": "060"}, "REVOCATION_FRESHNESS_POLICY_INVALID"),
    ("trust_overflow_window", {"max_revocation_age_secs": "18446744073709551616"}, "REVOCATION_FRESHNESS_POLICY_INVALID"),
    ("trust_window_trailing_newline", {"max_revocation_age_secs": "60\n"}, "REVOCATION_FRESHNESS_POLICY_INVALID"),
    ("trust_options_wrong_format", {"format": "publisher-source"}, "INPUT_INVALID"),
    ("trust_missing_source_signature", {"signature_hex": None}, "SIGNATURE_MALFORMED"),
]
# BEGIN publisher identity protocol controls (no cryptographic proof claims).
graph_witness_path = str(Path(tempfile.mkdtemp(prefix="franken-graph-witness-")) / "private graph; $(ignored).json")
graph_witness_bytes = b"{}\n"
Path(graph_witness_path).write_bytes(graph_witness_bytes)
graph_witness_controls = [
    "ignored", "null", "wrong_schema", "not_recomputed", "semantic_claim", "wrong_graph", "wrong_capsule",
    "wrong_report_hash", "prefixed_report_hash", "uppercase_report_hash", "newline_report_hash",
    "observation_mismatch", "zero_observations", "too_many_observations", "boolean_count", "unsafe_count",
    "zero_modules", "too_many_targets", "negative_count", "nonboolean_resolution",
    "inconsistent_resolution", "unknown_field", "missing_field", "replaced_file",
]
graph_client_cases = 0
graph_protocol_cases = 0
for trusted in (False, True):
    prefix = "publisher_trust_graph_witness_" if trusted else "publisher_graph_witness_"
    options = publisher_trust_options if trusted else {"format": "publisher-source", "signature_hex": "00" * 64}
    for path in ("", False, 7, [], {}, b"private-report.json", "private\0report", "\ud800"):
        try:
            verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist",
                            **options, graph_report=path)
        except VerifierError as error:
            assert error.code == "GRAPH_REPORT_INVALID" and error.exit_code is None, (path, error.code)
        else:
            raise AssertionError("invalid graph path reached the verifier")
        graph_client_cases += 1
    forwarded = verify_artifact(json.dumps({"protocol_control": prefix + "forwarded",
                                           "expected_graph_report_path": graph_witness_path}).encode(),
                                cases[0]["anchor"], verifier=root / "fake_verifier",
                                **options, graph_report=Path(graph_witness_path))
    source = forwarded["facts"]["source"] if trusted else forwarded["facts"]
    assert source["graph_report"]["graph_hash_recomputed"] is True
    assert source["graph_report"]["graph_semantics_reconstructed"] is False
    assert source["graph_report"]["report_sha256"] == hashlib.sha256(graph_witness_bytes).hexdigest()
    assert source["graph_report"]["module_count"] > source["capsule"]["file_count"]
    graph_protocol_cases += 1
    for control in graph_witness_controls:
        Path(graph_witness_path).write_bytes(graph_witness_bytes)
        try:
            verify_artifact(json.dumps({"protocol_control": prefix + control}).encode(),
                            cases[0]["anchor"], verifier=root / "fake_verifier",
                            **options, graph_report=graph_witness_path)
        except VerifierError as error:
            assert error.code == "PROTOCOL_INVALID" and graph_witness_path not in str(error), (control, error.code)
        else:
            raise AssertionError("unverified graph summary accepted: " + prefix + control)
        graph_protocol_cases += 1
        print(json.dumps({"case": prefix + control, "result": "PROTOCOL_INVALID"}), flush=True)
    Path(graph_witness_path).write_bytes(graph_witness_bytes)
    try:
        verify_artifact(json.dumps({"protocol_control": prefix + "unsolicited"}).encode(),
                        cases[0]["anchor"], verifier=root / "fake_verifier", **options)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID"
    else:
        raise AssertionError("unsolicited publisher graph commitment accepted")
    graph_protocol_cases += 1
try:
    verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist",
                    format="capsule", graph_report=graph_witness_path)
except VerifierError as error:
    assert error.code == "INPUT_INVALID" and error.exit_code is None
else:
    raise AssertionError("graph report accepted for unsupported format")
graph_client_cases += 1

# These fake-child controls exercise the client contract, never signatures.
incident_graph_payload = {
    "module_sources": {"capsule_base64": "Y2Fwc3VsZQ==", "capsule_digest": "sha256:" + "c" * 64,
                       "graph_input_hash": "sha256:" + "d" * 64},
    "expected": {"terminal_state": "completed"}, "host_effect_transcript": [],
}
incident_graph_raw = json.dumps(incident_graph_payload, separators=(",", ":"))


def incident_graph_input(action: str, raw: str = incident_graph_raw) -> bytes:
    return json.dumps({
        "protocol_control": "incident_graph_witness_" + action,
        "expected_graph_report_path": graph_witness_path,
        "initial_state_snapshot": {"native_replay": {
            "schema_version": "franken-node/native-replay-capture/v3", "payload_json": raw,
            "payload_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }},
    }).encode()


incident_graph_controls = [control for control in graph_witness_controls if control != "observation_mismatch"]
incident_graph_controls += ["missing_capture", "wrong_capture_hash", "wrong_capture_bytes",
                            "wrong_capture_state", "wrong_capture_count", "wrong_scope"]
for origins, expected_scope in (
    ({}, "authenticated_recorded_incident"),
    ({"trusted_run_public_key_hex": run_anchor}, "authenticated_run_incident"),
    ({"trusted_run_public_key_hex": run_anchor, "trusted_runtime_public_key_hex": runtime_anchor},
     "authenticated_runtime_incident"),
):
    Path(graph_witness_path).write_bytes(graph_witness_bytes)
    verified = verify_artifact(incident_graph_input("forwarded"), cases[0]["anchor"],
                               verifier=root / "fake_verifier", graph_report=Path(graph_witness_path), **origins)
    assert verified["scope"] == expected_scope
    assert verified["facts"]["graph_report"]["report_sha256"] == hashlib.sha256(graph_witness_bytes).hexdigest()
    assert verified["facts"]["native_capture"]["captured_terminal_state"] == "completed"
    assert ("run_origin" in verified["facts"]) == ("trusted_run_public_key_hex" in origins)
    assert ("runtime_origin" in verified["facts"]) == ("trusted_runtime_public_key_hex" in origins)
    graph_protocol_cases += 1
    controls_for_scope = list(incident_graph_controls)
    if "trusted_run_public_key_hex" in origins:
        controls_for_scope += ["scope_downgrade", "missing_run_origin", "wrong_run_anchor"]
    if "trusted_runtime_public_key_hex" in origins:
        controls_for_scope += ["missing_runtime_origin", "wrong_runtime_anchor"]
    for control in controls_for_scope:
        Path(graph_witness_path).write_bytes(graph_witness_bytes)
        try:
            verify_artifact(incident_graph_input(control), cases[0]["anchor"],
                            verifier=root / "fake_verifier", graph_report=graph_witness_path, **origins)
        except VerifierError as error:
            assert error.code == "PROTOCOL_INVALID" and graph_witness_path not in str(error), (control, error.code)
        else:
            raise AssertionError("forged incident graph facts accepted: " + control)
        graph_protocol_cases += 1
    try:
        verify_artifact(incident_graph_input("unsolicited"), cases[0]["anchor"],
                        verifier=root / "fake_verifier", **origins)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID"
    else:
        raise AssertionError("unsolicited incident graph commitment accepted")
    graph_protocol_cases += 1

Path(graph_witness_path).write_bytes(graph_witness_bytes)
for raw in (
    "{}",
    incident_graph_raw.replace('"module_sources":', '"module_sources":{},"module_sources":', 1),
    incident_graph_raw.replace('"module_sources":', '"module_sources":{},"module_\\u0073ources":', 1),
    incident_graph_raw.replace('"capsule_base64":', '"unsigned_claim":true,"capsule_base64":', 1),
):
    try:
        verify_artifact(incident_graph_input("valid", raw), cases[0]["anchor"],
                        verifier=root / "fake_verifier", graph_report=graph_witness_path)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (raw, error.code)
    else:
        raise AssertionError("missing or ambiguous captured sources accepted")
    graph_protocol_cases += 1
missing_capture_input = json.dumps({"protocol_control": "incident_graph_witness_valid"}).encode()
duplicate_capture_input = incident_graph_input("valid").replace(
    b'"initial_state_snapshot":', b'"initial_state_snapshot":{},"initial_state_snapshot":', 1)
for data in (missing_capture_input, duplicate_capture_input):
    try:
        verify_artifact(data, cases[0]["anchor"], verifier=root / "fake_verifier", graph_report=graph_witness_path)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID"
    else:
        raise AssertionError("missing or ambiguous incident capture accepted")
    graph_protocol_cases += 1

for path in ("", False, 7, [], {}, b"private-report.json", "private\0report", "\ud800"):
    try:
        verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist", graph_report=path)
    except VerifierError as error:
        assert error.code == "GRAPH_REPORT_INVALID" and error.exit_code is None
    else:
        raise AssertionError("invalid incident graph path reached the verifier")
    graph_client_cases += 1
native_graph_admission = {
    "session_nonce": "0199abcd-1234-7000-8000-123456789abc", "product_root_key_id": "ed25519:" + cases[0]["anchor"],
    "source_capsule": {"capsule_digest": "sha256:" + "c" * 64,
                       "graph_input_hash": "sha256:" + "d" * 64, "capsule_bytes": 128},
}
native_graph_raw = json.dumps(native_graph_admission, separators=(",", ":"))


def native_graph_input(action: str, raw: str = native_graph_raw) -> bytes:
    admission_bytes = raw.encode("utf-8")
    return json.dumps({
        "protocol_control": "native_v3_graph_witness_" + action,
        "expected_graph_report_path": graph_witness_path,
        "schema_version": "franken-node/native-session-forensics/v3", "admission_json": raw,
        "admission_receipt": {
            "schema_version": "franken-node/native-session-admission-receipt/v1",
            "session_nonce": native_graph_admission["session_nonce"],
            "product_root_key_id": native_graph_admission["product_root_key_id"],
            "admission_sha256": hashlib.sha256(b"franken-node/native-session-admission/v1\0"
                + len(admission_bytes).to_bytes(8, "big") + admission_bytes).hexdigest(),
        },
        "source_capsule_base64": "Y2Fwc3VsZQ==", "outcome": None,
    }).encode()


native_graph_options = {"verifier": root / "fake_verifier", "format": "native-session-forensics",
                        "graph_report": Path(graph_witness_path)}
native_graph_receipt = json.loads(native_graph_input("valid"))["admission_receipt"]
for pinned in (False, True):
    Path(graph_witness_path).write_bytes(graph_witness_bytes)
    pins = ({"expected_session_nonce": native_graph_receipt["session_nonce"],
             "expected_admission_sha256": native_graph_receipt["admission_sha256"]} if pinned else {})
    verified = verify_artifact(native_graph_input("forwarded" if pinned else "valid"), cases[0]["anchor"],
                               **native_graph_options, **pins)
    facts = verified["facts"]
    assert verified["scope"] == "authenticated_supervisor_observations"
    assert facts["graph_report"]["report_sha256"] == hashlib.sha256(graph_witness_bytes).hexdigest()
    assert facts["graph_report"]["graph_hash_recomputed"] is True
    assert facts["graph_report"]["graph_semantics_reconstructed"] is False
    assert facts["source_capsule"]["graph_hash_recomputed"] is False
    assert facts["outcome_kind"] == "interrupted"
    assert all(facts[field] is False for field in ("replay_certified", "quiescence_certified", "historical_completeness"))
    graph_protocol_cases += 1
for control in graph_witness_controls + ["wrong_source_graph", "wrong_source_length", "wrong_admission",
        "wrong_session", "downgrade", "wrong_scope", "replay_claim", "quiescence_claim", "history_claim"]:
    Path(graph_witness_path).write_bytes(graph_witness_bytes)
    try:
        verify_artifact(native_graph_input(control), cases[0]["anchor"], **native_graph_options)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID" and graph_witness_path not in str(error), (control, error.code)
    else:
        raise AssertionError("unbound native graph commitment accepted: " + control)
    graph_protocol_cases += 1
Path(graph_witness_path).write_bytes(graph_witness_bytes)
for raw in ("{}", "{",
    native_graph_raw.replace('"source_capsule":', '"source_capsule":{},"source_capsule":'),
    native_graph_raw.replace('"source_capsule":', '"source_capsule":{},"source_\\u0063apsule":'),
    native_graph_raw.replace('"capsule_bytes":128', '"capsule_bytes":129'),
    native_graph_raw.replace('"capsule_bytes":128', '"capsule_bytes":128,"unsigned_claim":true'),
):
    try:
        verify_artifact(native_graph_input("valid", raw), cases[0]["anchor"], **native_graph_options)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID"
    else:
        raise AssertionError("ambiguous or mismatched native admission accepted")
    graph_protocol_cases += 1
for data in (
    native_graph_input("valid").replace(b'"admission_json":', b'"admission_json":"{}","admission_json":'),
    native_graph_input("valid").replace(b"native-session-admission-receipt/v1", b"untrusted/v1"),
):
    try:
        verify_artifact(data, cases[0]["anchor"], **native_graph_options)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID"
    else:
        raise AssertionError("ambiguous native envelope or foreign receipt schema accepted")
    graph_protocol_cases += 1
try:
    verify_artifact(native_graph_input("unsolicited"), cases[0]["anchor"],
                    verifier=root / "fake_verifier", format="native-session-forensics")
except VerifierError as error:
    assert error.code == "PROTOCOL_INVALID"
else:
    raise AssertionError("unsolicited native graph commitment accepted")
graph_protocol_cases += 1
for path in ("", False, 7, [], {}, b"private-report.json", "private\0report", "\ud800"):
    try:
        verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist",
                        format="native-session-forensics", graph_report=path)
    except VerifierError as error:
        assert error.code == "GRAPH_REPORT_INVALID" and error.exit_code is None, (path, error.code)
    else:
        raise AssertionError("invalid native graph path reached the verifier")
    graph_client_cases += 1
graph_files = Path(tempfile.mkdtemp(prefix="franken-graph-input-"))
oversized_graph = graph_files / "PRIVATE-oversized-report.json"
with oversized_graph.open("wb") as graph_file:
    graph_file.truncate(MAX_SOURCE_GRAPH_REPORT_BYTES + 1)
graph_file_controls = [
    (graph_files / "PRIVATE-absent-report.json", "GRAPH_REPORT_IO"),
    (graph_files, "GRAPH_REPORT_IO"),
    (oversized_graph, "INPUT_TOO_LARGE"),
]
if os.name == "posix":
    graph_fifo = graph_files / "PRIVATE-report-pipe"
    os.mkfifo(graph_fifo)
    graph_file_controls.append((graph_fifo, "GRAPH_REPORT_IO"))
for path, expected in graph_file_controls:
    started = time.monotonic()
    try:
        verify_artifact(b"{}", cases[0]["anchor"], verifier=root / "does-not-exist", graph_report=path)
    except VerifierError as error:
        assert error.code == expected and error.exit_code is None and "PRIVATE-" not in str(error), (path, error.code)
    else:
        raise AssertionError("unbounded or non-regular graph report accepted")
    assert time.monotonic() - started < 2, "graph file admission must not block on a pipe"
    graph_client_cases += 1

identity_pins = {
    "expected_manifest_sha256": "sha256:" + "a" * 64,
    "expected_source_artifact_sha256": "sha256:" + "b" * 64,
    "expected_graph_input_hash": "sha256:" + "d" * 64,
}
identity_invalid_inputs = [
    ("missing_manifest_for_artifact", {"expected_manifest_sha256": None}),
    ("missing_manifest_for_graph", {"expected_manifest_sha256": None, "expected_source_artifact_sha256": None}),
    ("empty_manifest", {"expected_manifest_sha256": ""}),
    ("manifest_without_prefix", {"expected_manifest_sha256": "a" * 64}),
    ("uppercase_manifest", {"expected_manifest_sha256": "sha256:" + "A" * 64}),
    ("manifest_newline", {"expected_manifest_sha256": identity_pins["expected_manifest_sha256"] + "\n"}),
    ("source_artifact_type", {"expected_source_artifact_sha256": []}),
    ("graph_wrong_length", {"expected_graph_input_hash": "sha256:dd"}),
]
identity_client_cases = 0
identity_protocol_cases = 0
for trusted in (False, True):
    prefix = "publisher_trust_identity" if trusted else "publisher_identity"
    options = publisher_trust_options if trusted else {"format": "publisher-source", "signature_hex": "00" * 64}
    for name, overrides in identity_invalid_inputs:
        try:
            verify_artifact(b"{}", cases[0]["anchor"], verifier=str(root / "does-not-exist"),
                            **{**options, **identity_pins, **overrides})
        except VerifierError as error:
            assert error.code == "EXPECTED_IDENTITY_INVALID" and error.exit_code is None, (name, error.code)
        else:
            raise AssertionError(name)
        identity_client_cases += 1
        print(json.dumps({"case": f"{prefix}_{name}", "result": "EXPECTED_IDENTITY_INVALID"}), flush=True)
    for mode, pins in (
        (f"{prefix}_valid", {"expected_manifest_sha256": identity_pins["expected_manifest_sha256"]}),
        (f"{prefix}_forwarded", identity_pins),
    ):
        verified = verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                                   verifier=str(root / "fake_verifier"), **{**options, **pins})
        source = verified["facts"]["source"] if trusted else verified["facts"]
        assert source["manifest_sha256"] == identity_pins["expected_manifest_sha256"]
        assert source["capsule"]["graph_hash_recomputed"] is False
        identity_protocol_cases += 1
        print(json.dumps({"case": mode, "result": "verified"}), flush=True)
    # The child ignores the forwarded pins and reports an otherwise valid success.
    for field in identity_pins:
        try:
            verify_artifact(json.dumps({"protocol_control": f"{prefix}_ignore_args"}).encode(), cases[0]["anchor"],
                            verifier=str(root / "fake_verifier"),
                            **{**options, **identity_pins, field: "sha256:" + "e" * 64})
        except VerifierError as error:
            assert error.code == "EXPECTED_IDENTITY_MISMATCH" and "sha256:" not in str(error), (field, error.code)
        else:
            raise AssertionError(field)
        identity_protocol_cases += 1
        print(json.dumps({"case": f"{prefix}_ignored_{field}", "result": "EXPECTED_IDENTITY_MISMATCH"}), flush=True)
try:
    verify_artifact(b"{}", cases[0]["anchor"], verifier=str(root / "does-not-exist"),
                    format="incident-bundle", **identity_pins)
except VerifierError as error:
    assert error.code == "EXPECTED_IDENTITY_INVALID" and error.exit_code is None
else:
    raise AssertionError("publisher identity options accepted for incident")
identity_client_cases += 1
# END publisher identity protocol controls.
for label, overrides, expected in publisher_trust_inputs:
    try:
        # Invalid trusted inputs must fail before attempting any child process.
        verify_artifact(b"{}", cases[0]["anchor"], verifier=str(root / "does-not-exist"),
                        **{**publisher_trust_options, **overrides})
    except VerifierError as error:
        assert error.code == expected and error.exit_code is None, (label, error.code)
        print(json.dumps({"case": label, "result": error.code}), flush=True)
    else:
        raise AssertionError(label)
publisher_trust_controls = [
    "publisher_trust_scope_downgrade", "publisher_trust_format_downgrade",
    "publisher_trust_wrong_revocation_anchor", "publisher_trust_wrong_provenance_anchor",
    "publisher_trust_missing_provenance", "publisher_trust_unrequested_provenance",
    "publisher_trust_partial_provenance", "publisher_trust_zero_provenance",
    "publisher_trust_overflow_provenance", "publisher_trust_unsafe_provenance",
    "publisher_trust_unknown_field", "publisher_trust_bad_revocation_digest",
    "publisher_trust_bad_provenance_digest", "publisher_trust_wrong_evaluation_time",
    "publisher_trust_rounded_evaluation_time", "publisher_trust_wrong_window",
    "publisher_trust_rounded_window", "publisher_trust_future_revocations",
    "publisher_trust_stale_revocations", "publisher_trust_malformed_time",
    "publisher_trust_nested_wrong_signer", "publisher_trust_nested_authority_missing",
    "publisher_trust_nested_unknown_field", "publisher_trust_nested_non_object",
]
for mode in publisher_trust_controls:
    options = dict(publisher_trust_options)
    if mode == "publisher_trust_unrequested_provenance":
        options["trusted_provenance_public_key_hex"] = None
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), **options)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
publisher_trust_positives = [
    ("publisher_trust_valid", {}),
    ("publisher_trust_valid_no_provenance", {"trusted_provenance_public_key_hex": None}),
    ("publisher_trust_equivalent_offset", {"evaluation_time": "2026-10-24T01:00:30.123456789+01:00"}),
    ("publisher_trust_large_window", {"max_revocation_age_secs": "18446744073709551615"}),
    ("publisher_trust_before_boundary", {}),
]
for mode, overrides in publisher_trust_positives:
    result = verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                             verifier=str(root / "fake_verifier"),
                             **{**publisher_trust_options, **overrides})
    assert result["scope"] == "authenticated_publisher_source_trust", mode
    print(json.dumps({"case": f"protocol_{mode}", "result": "verified"}), flush=True)

counterfactual_controls = ["counterfactual_wrong_scope", "counterfactual_invalid_mode",
                           "counterfactual_single_count_mismatch", "counterfactual_zero_count",
                           "counterfactual_unknown_field"]
for mode in counterfactual_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="counterfactual-receipt", signature_hex="00" * 64)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
ltv_controls = ["ltv_wrong_scope", "ltv_rounded_timestamp", "ltv_overflow_timestamp",
                "ltv_bad_artifact_hash", "ltv_unknown_field", "ltv_missing_policy_hash",
                "ltv_wrong_policy_hash", "ltv_uppercase_policy_hash"]
ltv_protocol = verify_artifact(json.dumps({
    "protocol_control": "ltv_policy_bound", "witness_anchor_base64": "e30=",
}).encode(), cases[0]["anchor"], verifier=str(root / "fake_verifier"), format="ltv-evidence")
assert ltv_protocol["facts"]["trust_policy_sha256"] == hashlib.sha256(b"{}").hexdigest()
for mode in ltv_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode, "witness_anchor_base64": "e30="}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="ltv-evidence")
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
print(json.dumps({"consumer": "python", "matrix_cases": len(cases),
                  "transport_cases": check_bounded_transport(),
                  "client_cases": len(client_controls) + len(publisher_trust_inputs) + identity_client_cases + graph_client_cases + archive_client_cases + len(promotion_inputs),
                  "protocol_cases": len(controls) + len(run_controls) + len(runtime_controls)
                  + len(resolution_controls) + len(publisher_controls) + len(publisher_host_positives)
                  + len(publisher_trust_controls) + len(publisher_trust_positives) + identity_protocol_cases + graph_protocol_cases
                  + len(counterfactual_controls) + len(ltv_controls) + len(promotion_controls) + 2
                  + len(native_controls) + len(native_positives) + archive_protocol_cases + 1, "passed": True}), flush=True)
