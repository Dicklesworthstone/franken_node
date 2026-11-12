"""Real isolated consumer: production bindings + trusted executable only."""
import hashlib
import json
import os
from pathlib import Path

from franken_verifier import MAX_INPUT_BYTES, VerifierError, verify_artifact

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
                                 max_revocation_age_secs=case.get("max_revocation_age_secs"))
    except VerifierError as error:
        assert error.code == case["expected"], (case["name"], error.code, case["expected"])
        if case["format"] in ("publisher-source", "publisher-source-trust"):
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
        elif case["format"] == "resolution-receipt":
            assert result["scope"] == "authenticated_resolution_decision"
            assert result["facts"]["decision"] == case["decision"]
            assert result["facts"]["module_graph_hash"] == case["graph_hash"]
            assert result["facts"]["selected_version"] == ("1.2.3" if case["decision"] == "admit" else None)
            assert result["facts"]["capability_budget_mode"] == "enforced"
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
        assert "PRIVATE-" not in json.dumps(result)
        print(json.dumps({"case": case["name"], "result": "verified", "scope": result["scope"]}), flush=True)

client_controls = [
    ("oversize_client_input", b" " * (MAX_INPUT_BYTES + 1), {}, "INPUT_TOO_LARGE"),
    ("bad_key_shape", b"{}", {"trusted_public_key_hex": "00"}, "ANCHOR_INVALID"),
    ("bad_run_key_shape", b"{}", {"trusted_run_public_key_hex": "00"}, "RUN_ANCHOR_INVALID"),
    ("run_key_wrong_format", b"{}", {"format": "capsule", "trusted_run_public_key_hex": cases[0]["anchor"]}, "INPUT_INVALID"),
    ("runtime_key_requires_run_key", b"{}", {"trusted_runtime_public_key_hex": cases[0]["anchor"]}, "INPUT_INVALID"),
    ("bad_runtime_key_shape", b"{}", {"trusted_run_public_key_hex": cases[0]["anchor"], "trusted_runtime_public_key_hex": "00"}, "RUNTIME_ANCHOR_INVALID"),
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
                      "publisher_unsafe_count", "publisher_bad_digest", "publisher_capsule_not_object"]
for mode in publisher_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="publisher-source", signature_hex="00" * 64)
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
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
                "ltv_bad_artifact_hash", "ltv_unknown_field"]
for mode in ltv_controls:
    try:
        verify_artifact(json.dumps({"protocol_control": mode}).encode(), cases[0]["anchor"],
                        verifier=str(root / "fake_verifier"), format="ltv-evidence")
    except VerifierError as error:
        assert error.code == "PROTOCOL_INVALID", (mode, error.code)
        print(json.dumps({"case": f"protocol_{mode}", "result": error.code}), flush=True)
    else:
        raise AssertionError(f"protocol_{mode}")
print(json.dumps({"consumer": "python", "matrix_cases": len(cases),
                  "client_cases": len(client_controls) + len(publisher_trust_inputs),
                  "protocol_cases": len(controls) + len(run_controls) + len(runtime_controls)
                  + len(resolution_controls) + len(publisher_controls)
                  + len(publisher_trust_controls) + len(publisher_trust_positives)
                  + len(counterfactual_controls) + len(ltv_controls) + 1, "passed": True}), flush=True)
