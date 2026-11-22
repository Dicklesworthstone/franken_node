"""Real isolated consumer: production bindings + trusted executable only."""
import hashlib
import json
import os
from pathlib import Path

from franken_verifier import MAX_INPUT_BYTES, MAX_NATIVE_SESSION_INPUT_BYTES, VerifierError, verify_artifact

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
                                 trusted_revocation_public_key_hex=case.get("revocation_anchor"),
                                 trusted_provenance_public_key_hex=case.get("provenance_anchor"),
                                 evaluation_time=case.get("evaluation_time"),
                                 max_revocation_age_secs=case.get("max_revocation_age_secs"),
                                 expected_manifest_sha256=case.get("expected_manifest_sha256"),
                                 expected_source_artifact_sha256=case.get("expected_source_artifact_sha256"),
                                 expected_graph_input_hash=case.get("expected_graph_input_hash"))
    except VerifierError as error:
        assert error.code == case["expected"], (case["name"], error.code, case["expected"])
        if case["format"] in ("publisher-source", "publisher-source-trust", "native-session-forensics", "signed-session"):
            assert "PRIVATE-" not in str(error)
        print(json.dumps({"case": case["name"], "result": error.code}), flush=True)
    else:
        assert case["expected"] == "verified", case["name"]
        assert result["artifact_sha256"] == hashlib.sha256(data).hexdigest()
        if case["format"] == "incident-bundle":
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
        if case["format"] == "ltv-evidence":
            assert result["scope"] == "authenticated_ltv_anteriority"
            assert result["facts"] == case["ltv_facts"], case["name"]
        assert "PRIVATE-" not in json.dumps(result)
        print(json.dumps({"case": case["name"], "result": "verified", "scope": result["scope"]}), flush=True)

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
                  "client_cases": len(client_controls) + len(publisher_trust_inputs) + identity_client_cases,
                  "protocol_cases": len(controls) + len(run_controls) + len(runtime_controls)
                  + len(resolution_controls) + len(publisher_controls) + len(publisher_host_positives)
                  + len(publisher_trust_controls) + len(publisher_trust_positives) + identity_protocol_cases
                  + len(counterfactual_controls) + len(ltv_controls)
                  + len(native_controls) + len(native_positives) + 1, "passed": True}), flush=True)
