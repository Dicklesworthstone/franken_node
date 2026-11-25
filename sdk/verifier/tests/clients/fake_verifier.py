#!/usr/bin/python3
"""Intentionally broken child process; never part of the distribution.

Used to prove typed protocol refusal, timeout handling and failure propagation.
It does not authenticate anything. The normal consumer matrix must fail on it.
"""
import hashlib
import json
import os
import sys
import time

transport_control = os.environ.get("FRANKEN_VERIFIER_TEST_TRANSPORT_CONTROL")
if transport_control:
    # Real pipe/deadline controls, isolated from the signature/protocol matrix.
    # The parent records this PID to verify that it reaped its direct child.
    with open(os.environ["FRANKEN_VERIFIER_TEST_PID_FILE"], "w") as pid_file:
        pid_file.write(str(os.getpid()))
    response_limit = 64 * 1024 + 1
    rejection = {"schema_version": "franken-verifier-cli/v1", "verdict": "rejected",
                 "error": {"code": "TRANSPORT_CONTROL", "message": "bounded refusal"}}
    if transport_control in ("stdout_overflow", "stderr_overflow"):
        stream = sys.stdout.buffer if transport_control == "stdout_overflow" else sys.stderr.buffer
        stream.write(b"x" * (response_limit + 1))
        stream.flush()
        time.sleep(5)
    elif transport_control == "blocked_stdin":
        time.sleep(5)
    elif transport_control == "closed_streams_running":
        os.close(1)
        os.close(2)
        time.sleep(5)
    elif transport_control == "inherited_pipes":
        if os.fork() == 0:
            time.sleep(5)
            os._exit(0)
        os._exit(0)
    elif transport_control == "early_refusal":
        sys.stdin.close()
        sys.stderr.buffer.write(b"\xff\x00private diagnostic\n")
    else:
        if transport_control in ("stderr_boundary", "duplex"):
            sys.stderr.buffer.write(b"e" * response_limit)
            sys.stderr.buffer.flush()
        data = sys.stdin.buffer.read()
        if transport_control == "duplex":
            rejection["error"]["message"] = hashlib.sha256(data).hexdigest()
    encoded = json.dumps(rejection, separators=(",", ":")).encode()
    if transport_control == "stdout_boundary":
        encoded += b" " * (response_limit - len(encoded))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    sys.exit(2)

data = sys.stdin.buffer.read()
try:
    mode = json.loads(data).get("protocol_control", "accept_everything")
except (ValueError, AttributeError):
    mode = "accept_everything"
anchor = (sys.argv[sys.argv.index("--trusted-key-hex") + 1]
          if "--trusted-key-hex" in sys.argv else "00" * 32)
run_anchor = (sys.argv[sys.argv.index("--trusted-run-key-hex") + 1]
              if "--trusted-run-key-hex" in sys.argv else "11" * 32)
runtime_anchor = (sys.argv[sys.argv.index("--trusted-runtime-key-hex") + 1]
                  if "--trusted-runtime-key-hex" in sys.argv else "22" * 32)
revocation_anchor = (sys.argv[sys.argv.index("--trusted-revocation-key-hex") + 1]
                     if "--trusted-revocation-key-hex" in sys.argv else "11" * 32)
provenance_anchor = (sys.argv[sys.argv.index("--trusted-provenance-key-hex") + 1]
                     if "--trusted-provenance-key-hex" in sys.argv else None)
max_age = (sys.argv[sys.argv.index("--max-revocation-age-secs") + 1]
           if "--max-revocation-age-secs" in sys.argv else "60")
response = {
    "schema_version": "franken-verifier-cli/v1", "verdict": "verified",
    "format": "incident-bundle", "scope": "authenticated_recorded_incident",
    "artifact_sha256": hashlib.sha256(data).hexdigest(),
    "facts": {
        "bundle_id": "fake", "incident_id": "fake", "created_at": "2026-10-24T00:00:00Z",
        "policy_version": "fake", "event_count": 3, "integrity_hash": "0" * 64,
        "decision_sequence_hash": "0" * 64, "signer_public_key_hex": anchor,
        "signing_identity": "339eefa3a988f613", "native_capture": None,
    },
}
if mode.startswith(("run_", "runtime_")):
    response["scope"] = "authenticated_run_incident"
    response["facts"]["run_origin"] = {
        "receipt_id": "run-protocol-control", "receipt_hash": "sha256:" + "a" * 64,
        "signer_public_key_hex": run_anchor, "record_sha256": "b" * 64,
    }
if mode.startswith("runtime_"):
    response["scope"] = "authenticated_runtime_incident"
    response["facts"]["runtime_origin"] = {
        "session_nonce": "0199abcd-1234-7000-8000-123456789abc",
        "product_root_key_id": "ed25519:" + runtime_anchor,
        "producer_id": "runtime-protocol-control", "evidence_key_id": "ed25519:" + "c" * 64,
        "signed_epoch": "18446744073709551615",
    }
if mode.startswith("session_"):
    response["format"] = "signed-session"
    response["scope"] = "authenticated_verification_session"
    response["facts"] = {
        "session_id": "protocol-session", "verifier_identity": "verifier://protocol-test",
        "created_at": "2026-11-16T00:00:00.123456789Z", "final_verdict": "pass",
        "step_count": 1, "transcript_hash": "a" * 64, "signer_public_key_hex": anchor,
    }
if mode.startswith("native_"):
    response["format"] = "native-session-forensics"
    response["scope"] = "authenticated_supervisor_observations"
    response["facts"] = {
        "schema_version": "franken-node/native-session-forensics/v2",
        "scope": "authenticated_supervisor_observations",
        "session_nonce": "0199abcd-1234-7000-8000-123456789abc",
        "product_root_key_id": "ed25519:" + anchor, "admission_sha256": "a" * 64,
        "project_root": "/captured/project", "entrypoint": "/captured/project/main.mjs",
        "security_epoch": "18446744073709551615", "admitted_at": "2026-11-14T12:00:00Z",
        "observed_at": "2026-11-14T12:00:01Z", "outcome_kind": "interrupted",
        "process_observation": "worker_reaped", "effect_observation": "interrupted",
        "containment_empty_observed": False, "completed_provider_calls": 1,
        "indeterminate_provider_calls": 1, "final_ledger_effect_count": None,
        "failed_effect_count": None, "journal_complete": True,
        "durable_journal": {
            "schema_version": "franken-node/native-effect-journal-record/v1",
            "scope": "host_io_provider_calls",
            "session_nonce": "0199abcd-1234-7000-8000-123456789abc",
            "product_root_key_id": "ed25519:" + anchor, "admission_sha256": "a" * 64,
            "record_count": 4, "event_count": 3, "admitted_provider_calls": 2,
            "returned_provider_calls": 1, "indeterminate_provider_calls": 1,
            "head_record_sha256": "b" * 64, "trailing_partial_record": False,
            "replay_certified": False, "quiescence_certified": False,
            "historical_completeness": False,
        },
        "replay_certified": False, "quiescence_certified": False, "historical_completeness": False,
    }
if mode.startswith("native_v3_"):
    response["facts"]["schema_version"] = "franken-node/native-session-forensics/v3"
    response["facts"]["source_capsule"] = {
        "schema_version": "franken-node/module-source-capsule/v1",
        "graph_input_hash": "sha256:" + "d" * 64, "graph_hash_recomputed": False,
        "capsule_bytes": 128, "payload_bytes": 16, "input_count": 3, "file_count": 1,
        "metadata_file_count": 0, "directory_count": 1, "missing_count": 1, "symlink_count": 0,
        "symlink_policy": "reject", "condition_count": None, "additional_condition_count": 0,
    }
if mode.startswith("resolution_"):
    response["format"] = "resolution-receipt"
    response["scope"] = "authenticated_resolution_decision"
    response["facts"] = {
        "receipt_id": "resolution-control", "crypto_suite": "ed25519-v1",
        "module_graph_hash": "sha256:" + "a" * 64, "package_name": "demo-package",
        "requested_range": "^1", "policy_profile": "strict", "capability_budget_mode": "enforced",
        "decision": "admit", "selected_version": "1.2.3", "rejected_alternative_count": 0,
        "canonical_hash": "sha256:" + "b" * 64,
        "signer_key_id": "sha256:" + hashlib.sha256(
            b"franken-node/resolution-receipt/signer-key-id/v1:" + bytes.fromhex(anchor)
        ).hexdigest(), "signer_public_key_hex": anchor,
    }
if mode.startswith("publisher_"):
    response["format"] = "publisher-source"
    response["scope"] = "authenticated_publisher_source_content"
    response["facts"] = {
        "registration_schema": "franken-node/extension-registration-manifest/v2",
        "package_name": "source-vector", "publisher_id": "publisher-control", "version": "1.2.3",
        "manifest_sha256": "sha256:" + "a" * 64, "artifact_sha256": "sha256:" + "b" * 64,
        "capsule_digest": "sha256:" + "c" * 64, "signer_public_key_hex": anchor,
        "signer_key_id": hashlib.sha256(
            b"artifact_signing_keyid_v1:" + (32).to_bytes(8, "little") + bytes.fromhex(anchor)
        ).hexdigest()[:16],
        "runtime_authority": {
            "schema_version": "franken-node/artifact-runtime-authority/v1", "policy_revision": "control-v1",
            "allowed_capabilities": ["console", "heap_allocate", "vm_dispatch"], "allow_process_shape": False,
            "max_instructions": "18446744073709551615", "max_registers": "65536",
            "max_call_depth": "10000", "max_heap_objects": "4294967295",
            "max_total_memory_bytes": "18446744073709551615", "max_console_entries": "4294967295",
            "max_parse_source_bytes": "2097152", "max_parse_tokens": "131072", "max_parse_recursion_depth": "384",
        },
        "capsule": {
            "schema_version": "franken-node/module-source-capsule/v1",
            "graph_input_hash": "sha256:" + "d" * 64, "graph_hash_recomputed": False,
            "capsule_bytes": 128, "payload_bytes": 16, "input_count": 3, "file_count": 1,
            "metadata_file_count": 0, "directory_count": 1, "missing_count": 1, "symlink_count": 0,
            "symlink_policy": "reject", "condition_count": None, "additional_condition_count": 0,
        },
    }
if mode.startswith("publisher_trust_"):
    source = response["facts"]
    response["format"] = "publisher-source-trust"
    response["scope"] = "authenticated_publisher_source_trust"
    response["facts"] = {
        "source": source,
        "revocation_list_sha256": "sha256:" + "a" * 64,
        "revocation_authority_public_key_hex": revocation_anchor,
        "revocation_issued_at": "2026-10-24T00:00:00.123456789Z",
        "revocation_evaluated_at": "2026-10-24T00:00:30.123456789Z",
        "max_revocation_age_secs": max_age,
        "provenance_chain_sha256": "sha256:" + "b" * 64 if provenance_anchor else None,
        "provenance_authority_public_key_hex": provenance_anchor,
        "provenance_link_count": 2 if provenance_anchor else None,
    }
if mode.startswith("counterfactual_"):
    response["format"] = "counterfactual-receipt"
    response["scope"] = "authenticated_counterfactual_receipt"
    response["facts"] = {
        "baseline_integrity_hash": "a" * 64,
        "mode": "sweep",
        "result_count": 2,
        "signer_public_key_hex": anchor,
    }
if mode.startswith(("cf_incident_", "cf_promotion_")):
    baseline = response["facts"]
    baseline["signer_public_key_hex"] = sys.argv[sys.argv.index("--trusted-incident-key-hex") + 1]
    baseline["integrity_hash"] = sys.argv[sys.argv.index("--expected-baseline-integrity-hash") + 1]
    baseline_scope = "authenticated_recorded_incident"
    if "--trusted-run-key-hex" in sys.argv:
        baseline_scope = "authenticated_run_incident"
        baseline["run_origin"] = {
            "receipt_id": "run-protocol-control", "receipt_hash": "sha256:" + "a" * 64,
            "signer_public_key_hex": run_anchor, "record_sha256": "b" * 64,
        }
    if "--trusted-runtime-key-hex" in sys.argv:
        baseline_scope = "authenticated_runtime_incident"
        baseline["runtime_origin"] = {
            "session_nonce": "0199abcd-1234-7000-8000-123456789abc",
            "product_root_key_id": "ed25519:" + runtime_anchor,
            "producer_id": "runtime-protocol-control", "evidence_key_id": "ed25519:" + "c" * 64,
            "signed_epoch": "18446744073709551615",
        }
    response["format"] = "counterfactual-incident"
    response["scope"] = "authenticated_counterfactual_incident"
    facts = response["facts"] = {
        "baseline_integrity_hash": baseline["integrity_hash"],
        "counterfactual_output_sha256": "d" * 64, "signer_public_key_hex": anchor,
        "mode": "single", "result_count": 1, "baseline_scope": baseline_scope,
        "baseline": baseline, "guest_execution_verified": False,
    }
    if mode == "cf_incident_wrong_pin":
        facts["baseline_integrity_hash"] = "e" * 64
    elif mode == "cf_incident_wrong_nested_pin":
        baseline["integrity_hash"] = "e" * 64
    elif mode == "cf_incident_wrong_receipt_signer":
        facts["signer_public_key_hex"] = "e" * 64
    elif mode == "cf_incident_wrong_exporter":
        baseline["signer_public_key_hex"] = anchor
    elif mode == "cf_incident_guest_execution_claim":
        facts["guest_execution_verified"] = True
    elif mode == "cf_incident_wrong_scope":
        response["scope"] = "authenticated_runtime_incident"
    elif mode == "cf_incident_downgraded_baseline":
        facts["baseline_scope"] = "authenticated_recorded_incident"
    elif mode == "cf_incident_missing_run_origin":
        baseline.pop("run_origin", None)
    elif mode == "cf_incident_missing_runtime_origin":
        baseline.pop("runtime_origin", None)
    elif mode == "cf_incident_extra_field":
        facts["replay_certified"] = True
    elif mode == "cf_incident_bad_output_hash":
        facts["counterfactual_output_sha256"] = "sha256:" + "d" * 64
    elif mode == "cf_incident_noncanonical_output_hash":
        facts["counterfactual_output_sha256"] = "D" * 64
    elif mode == "cf_incident_boolean_count":
        facts["result_count"] = True
    elif mode == "cf_incident_excessive_count":
        facts["mode"] = "sweep"
        facts["result_count"] = 21
    elif mode == "cf_incident_single_count_mismatch":
        facts["result_count"] = 2
if mode.startswith("cf_promotion_"):
    response["format"] = "counterfactual-promotion"
    response["scope"] = "authenticated_counterfactual_promotion"
    facts.update({
        "operator_id": "protocol-operator", "report_sha256": "a" * 64,
        "counterfactual_digest": "sha256:" + "b" * 64,
        "promotion_contract_digest": "sha256:" + "c" * 64,
        "mitigation_id": "incident-policy-mitigation", "executor": "production",
        "expected_loss_delta": "9007199254740993",
        "valid_from_epoch_ms": "-9223372036854775808",
        "valid_until_epoch_ms": "9223372036854775807",
        "rollout_authorized": False,
    })
    changes = {
        "cf_promotion_wrong_signer": ("signer_public_key_hex", "e" * 64),
        "cf_promotion_wrong_pin": ("baseline_integrity_hash", "e" * 64),
        "cf_promotion_bad_report_hash": ("report_sha256", "sha256:" + "a" * 64),
        "cf_promotion_bad_output_hash": ("counterfactual_output_sha256", "D" * 64),
        "cf_promotion_bad_counterfactual_digest": ("counterfactual_digest", "b" * 64),
        "cf_promotion_bad_contract_digest": ("promotion_contract_digest", "sha256:" + "C" * 64),
        "cf_promotion_empty_operator": ("operator_id", ""),
        "cf_promotion_operator_whitespace": ("operator_id", " operator"),
        "cf_promotion_operator_control": ("operator_id", "operator\n"),
        "cf_promotion_operator_oversize": ("operator_id", "a" * 4097),
        "cf_promotion_operator_surrogate": ("operator_id", "\ud800"),
        "cf_promotion_empty_mitigation": ("mitigation_id", ""),
        "cf_promotion_mitigation_whitespace": ("mitigation_id", "mitigation "),
        "cf_promotion_mitigation_control": ("mitigation_id", "mitigation\x7f"),
        "cf_promotion_invalid_executor": ("executor", "native"),
        "cf_promotion_invalid_mode": ("mode", "parallel"),
        "cf_promotion_zero_count": ("result_count", 0),
        "cf_promotion_boolean_count": ("result_count", True),
        "cf_promotion_single_count_mismatch": ("result_count", 2),
        "cf_promotion_numeric_delta": ("expected_loss_delta", 9007199254740993),
        "cf_promotion_overflow_delta": ("expected_loss_delta", "9223372036854775808"),
        "cf_promotion_zero_delta": ("expected_loss_delta", "0"),
        "cf_promotion_negative_delta": ("expected_loss_delta", "-1"),
        "cf_promotion_noncanonical_delta": ("expected_loss_delta", "01"),
        "cf_promotion_numeric_from": ("valid_from_epoch_ms", -9007199254740993),
        "cf_promotion_underflow_from": ("valid_from_epoch_ms", "-9223372036854775809"),
        "cf_promotion_plus_from": ("valid_from_epoch_ms", "+1"),
        "cf_promotion_negative_zero_from": ("valid_from_epoch_ms", "-0"),
        "cf_promotion_numeric_until": ("valid_until_epoch_ms", 9007199254740993),
        "cf_promotion_overflow_until": ("valid_until_epoch_ms", "9223372036854775808"),
        "cf_promotion_newline_until": ("valid_until_epoch_ms", "9223372036854775807\n"),
        "cf_promotion_empty_window": ("valid_until_epoch_ms", "-9223372036854775808"),
        "cf_promotion_guest_execution_claim": ("guest_execution_verified", True),
        "cf_promotion_rollout_claim": ("rollout_authorized", True),
        "cf_promotion_boolean_number": ("rollout_authorized", 0),
        "cf_promotion_downgraded_baseline": ("baseline_scope", "authenticated_recorded_incident"),
    }
    if mode in changes:
        key, value = changes[mode]
        facts[key] = value
    elif mode == "cf_promotion_wrong_scope":
        response["scope"] = "authenticated_counterfactual_incident"
    elif mode == "cf_promotion_wrong_format":
        response["format"] = "counterfactual-incident"
    elif mode == "cf_promotion_wrong_nested_pin":
        baseline["integrity_hash"] = "e" * 64
    elif mode == "cf_promotion_wrong_exporter":
        baseline["signer_public_key_hex"] = anchor
    elif mode == "cf_promotion_wrong_run_signer":
        baseline["run_origin"]["signer_public_key_hex"] = anchor
    elif mode == "cf_promotion_wrong_runtime_key":
        baseline["runtime_origin"]["product_root_key_id"] = "ed25519:" + anchor
    elif mode == "cf_promotion_missing_run_origin":
        baseline.pop("run_origin", None)
    elif mode == "cf_promotion_missing_runtime_origin":
        baseline.pop("runtime_origin", None)
    elif mode == "cf_promotion_missing_field":
        facts.pop("report_sha256")
    elif mode == "cf_promotion_extra_field":
        facts["replay_certified"] = True
    elif mode == "cf_promotion_excessive_count":
        facts["mode"] = "sweep"
        facts["result_count"] = 21
    elif mode == "cf_promotion_reversed_window":
        facts["valid_from_epoch_ms"], facts["valid_until_epoch_ms"] = "1", "0"
    elif mode == "cf_promotion_valid_sweep":
        facts["executor"], facts["mode"], facts["result_count"] = "synthetic", "sweep", 20
        facts["expected_loss_delta"] = "9223372036854775807"
        facts["valid_from_epoch_ms"], facts["valid_until_epoch_ms"] = "0", "1"
if mode.startswith("ltv_"):
    response["format"] = "ltv-evidence"
    response["scope"] = "authenticated_ltv_anteriority"
    response["facts"] = {
        "artifact_id": "ltv-control",
        "artifact_hash": "a" * 64,
        "crypto_suite": "ed25519-v1",
        "as_of_unix_seconds": "1700000500",
        "claimed_at_unix_seconds": "1700000100",
        "witness_group_id": "witness-quorum",
        "witness_policy_id": "policy-2of2",
        "trust_policy_sha256": hashlib.sha256(b"{}").hexdigest(),
        "reattestation_count": 1,
        "hybrid_survived_algo_death": False,
        "signer_public_key_hex": anchor,
    }
if mode.startswith(("fleet_", "epoch_")):
    # An explicitly fake child can make protocol claims without authenticating
    # anything. Test consumers must bind the claims to both retained inputs and
    # refuse broader proof scopes, even when the process exits successfully.
    policy_path = sys.argv[sys.argv.index("--trusted-fleet-policy") + 1]
    with open(policy_path, "rb") as policy_file:
        policy_bytes = policy_file.read()
    policy = json.loads(policy_bytes)
    response["format"] = "fleet-quiescence-observations"
    response["scope"] = "authenticated_fleet_supervisor_observations"
    response["facts"] = {
        "schema_version": "franken-verifier/fleet-quiescence-observations/v1",
        "evidence_sha256": hashlib.sha256(data).hexdigest(),
        "trust_policy_sha256": hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "trusted_policy_input_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "evaluation_time": policy["evaluation_time"],
        "observed_at": "2026-11-23T01:00:05Z",
        "participant_count": len(policy["participants"]),
        "admitted_sessions": str(2**64 - 1),
        "terminal_sessions": str(2**64 - 1),
        "supervisor_signatures_verified": True,
        "expected_population_complete": True,
        "expected_action_context_matched": True,
        "epoch_commit_authenticated": False,
        "current_quiescence_proven": False,
    }
    if "--trusted-key-hex" in sys.argv:
        raise AssertionError("fleet policy must be forwarded without a single-key anchor")
    if mode.startswith("epoch_"):
        coordinator_id = sys.argv[sys.argv.index("--trusted-coordinator-id") + 1]
        coordinator_key = sys.argv[sys.argv.index("--trusted-coordinator-key-hex") + 1]
        response["format"] = "fleet-epoch-commit"
        response["scope"] = "authenticated_fleet_epoch_commit"
        response["facts"].update({
            "schema_version": "franken-verifier/fleet-epoch-commit/v1",
            "epoch_commit_authenticated": True,
            "coordinator_id": coordinator_id,
            "coordinator_key_id": "ed25519:" + coordinator_key,
            "committed_epoch": str(policy["expected_pre_epoch"] + 1),
            "transition_id": "epoch-protocol-control",
            "statement_sha256": "a" * 64,
        })
exit_code = 0
graph_prefix = next((prefix for prefix in ("publisher_graph_witness_", "publisher_trust_graph_witness_")
                     if mode.startswith(prefix)), None)
if graph_prefix is not None:
    source = response["facts"]["source"] if mode.startswith("publisher_trust_") else response["facts"]
    action = mode[len(graph_prefix):]
    if action != "ignored":
        source["graph_report"] = {
            "schema_version": "franken-verifier/source-graph-commitment/v1",
            "graph_input_hash": source["capsule"]["graph_input_hash"],
            "graph_hash_recomputed": True, "graph_semantics_reconstructed": False,
            "capsule_digest": source["capsule_digest"], "report_sha256": "e" * 64,
            "observation_count": source["capsule"]["input_count"],
            # Multiple query/fragment identities can share one captured file.
            "module_count": 2, "resolution_target_count": 0, "edge_count": 1,
            "diagnostic_count": 0, "declared_fully_resolved": True,
        }
        changes = {
            "wrong_schema": ("schema_version", "untrusted/v2"),
            "not_recomputed": ("graph_hash_recomputed", False),
            "semantic_claim": ("graph_semantics_reconstructed", True),
            "wrong_graph": ("graph_input_hash", "sha256:" + "f" * 64),
            "wrong_capsule": ("capsule_digest", "sha256:" + "f" * 64),
            "prefixed_report_hash": ("report_sha256", "sha256:" + "e" * 64),
            "uppercase_report_hash": ("report_sha256", "E" * 64),
            "newline_report_hash": ("report_sha256", "e" * 64 + "\n"),
            "observation_mismatch": ("observation_count", 2),
            "boolean_count": ("edge_count", True),
            "unsafe_count": ("edge_count", 2**53),
            "zero_modules": ("module_count", 0),
            "too_many_targets": ("resolution_target_count", 257),
            "negative_count": ("diagnostic_count", -1),
            "nonboolean_resolution": ("declared_fully_resolved", "true"),
            "inconsistent_resolution": ("diagnostic_count", 1),
        }
        if action in changes:
            field, value = changes[action]
            source["graph_report"][field] = value
        elif action == "unknown_field":
            source["graph_report"]["execution_verified"] = True
        elif action == "missing_field":
            del source["graph_report"]["report_sha256"]
        elif action == "null":
            source["graph_report"] = None
    if action == "forwarded":
        if (sys.argv.count("--graph-report") != 1
                or sys.argv[sys.argv.index("--graph-report") + 1] != "private graph; $(ignored).json"):
            response = {"schema_version": "franken-verifier-cli/v1", "verdict": "rejected",
                        "error": {"code": "GRAPH_ARGUMENT_MISSING", "message": "graph report path was not forwarded"}}
            exit_code = 2
if mode in ("publisher_identity_forwarded", "publisher_trust_identity_forwarded"):
    for option, expected in (
        ("--expected-manifest-sha256", "sha256:" + "a" * 64),
        ("--expected-source-artifact-sha256", "sha256:" + "b" * 64),
        ("--expected-graph-input-hash", "sha256:" + "d" * 64),
    ):
        if option not in sys.argv or sys.argv[sys.argv.index(option) + 1] != expected:
            response = {"schema_version": "franken-verifier-cli/v1", "verdict": "rejected",
                        "error": {"code": "PIN_ARGUMENT_MISSING", "message": "identity pin was not forwarded"}}
            exit_code = 2
            break
if mode == "timeout":
    time.sleep(5)
elif mode == "oversize":
    sys.stdout.write("x" * 70000)
    sys.exit(0)
elif mode == "invalid_utf8":
    sys.stdout.buffer.write(b"\xff")
    sys.exit(0)
elif mode == "deep_response":
    sys.stdout.write("[" * 2000 + "0" + "]" * 2000)
    sys.exit(0)
elif mode == "malformed":
    sys.stdout.write("not-json")
    sys.exit(0)
elif mode == "wrong_schema":
    response["schema_version"] = "untrusted/v99"
elif mode == "wrong_scope":
    response["scope"] = "guest_executed"
elif mode == "wrong_hash":
    response["artifact_sha256"] = "0" * 64
elif mode == "wrong_anchor":
    response["facts"]["signer_public_key_hex"] = "0" * 64
elif mode == "unsafe_count":
    response["facts"]["event_count"] = 2**53
elif mode == "invalid_capture_state":
    response["facts"]["native_capture"] = {
        "payload_sha256": "0" * 64, "payload_bytes": 1,
        "host_io_exchange_count": 0, "captured_terminal_state": [],
    }
elif mode == "extra_member":
    response["unsigned_claim"] = "trusted"
elif mode == "success_with_failure_exit":
    exit_code = 1
elif mode == "rejection_with_success_exit":
    response = {"schema_version": "franken-verifier-cli/v1", "verdict": "rejected",
                "error": {"code": "SIGNATURE_INVALID", "message": "bad signature"}}
elif mode == "run_scope_downgrade":
    response["scope"] = "authenticated_recorded_incident"
    del response["facts"]["run_origin"]
elif mode == "run_origin_missing":
    del response["facts"]["run_origin"]
elif mode == "run_wrong_anchor":
    response["facts"]["run_origin"]["signer_public_key_hex"] = anchor
elif mode == "run_invalid_receipt_id":
    response["facts"]["run_origin"]["receipt_id"] = "../run"
elif mode == "run_invalid_receipt_hash":
    response["facts"]["run_origin"]["receipt_hash"] = "sha256:claimed"
elif mode == "run_invalid_record_digest":
    response["facts"]["run_origin"]["record_sha256"] = "b" * 63
elif mode == "run_extra_origin_field":
    response["facts"]["run_origin"]["engine_execution_verified"] = True
elif mode == "run_origin_non_object":
    response["facts"]["run_origin"] = []
elif mode == "runtime_scope_downgrade":
    response["scope"] = "authenticated_run_incident"
    del response["facts"]["runtime_origin"]
elif mode == "runtime_origin_missing":
    del response["facts"]["runtime_origin"]
elif mode == "runtime_wrong_root":
    response["facts"]["runtime_origin"]["product_root_key_id"] = "ed25519:" + anchor
elif mode == "runtime_rounded_epoch":
    response["facts"]["runtime_origin"]["signed_epoch"] = 2**64 - 1
elif mode == "runtime_overflow_epoch":
    response["facts"]["runtime_origin"]["signed_epoch"] = str(2**64)
elif mode == "runtime_extra_claim":
    response["facts"]["runtime_origin"]["quiescence_certified"] = True
elif mode == "native_wrong_scope":
    response["scope"] = "authenticated_runtime_incident"
elif mode == "native_wrong_nested_scope":
    response["facts"]["scope"] = "guest_executed"
elif mode == "native_wrong_root":
    response["facts"]["product_root_key_id"] = "ed25519:" + "0" * 64
elif mode == "native_bad_nonce":
    response["facts"]["session_nonce"] = "00000000-0000-0000-0000-000000000000"
elif mode == "native_bad_admission_digest":
    response["facts"]["admission_sha256"] = "sha256:" + "a" * 64
elif mode == "native_bad_paths":
    response["facts"]["entrypoint"] = "/another-project/main.mjs"
elif mode == "native_numeric_epoch":
    response["facts"]["security_epoch"] = 2**64 - 1
elif mode == "native_overflow_epoch":
    response["facts"]["security_epoch"] = str(2**64)
elif mode == "native_noncanonical_epoch":
    response["facts"]["security_epoch"] = "07"
elif mode == "native_negative_epoch":
    response["facts"]["security_epoch"] = "-1"
elif mode == "native_epoch_trailing_newline":
    response["facts"]["security_epoch"] = "7\n"
elif mode == "native_bad_admission_time":
    response["facts"]["admitted_at"] = "2026-02-30T00:00:00Z"
elif mode == "native_bad_observation_time":
    response["facts"]["observed_at"] = None
elif mode == "native_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "native_missing_field":
    del response["facts"]["journal_complete"]
elif mode == "native_pending_with_outcome":
    response["facts"]["outcome_kind"] = "pending"
elif mode == "native_impossible_process":
    response["facts"]["process_observation"] = "not_spawned"
elif mode == "native_impossible_effect":
    response["facts"]["effect_observation"] = "unknown"
elif mode == "native_unknown_outcome":
    response["facts"]["outcome_kind"] = "replayed"
elif mode == "native_unsafe_count":
    response["facts"]["completed_provider_calls"] = 2**53
elif mode == "native_boolean_count":
    response["facts"]["completed_provider_calls"] = True
elif mode == "native_missing_count":
    response["facts"]["indeterminate_provider_calls"] = None
elif mode == "native_impossible_wal_count":
    response["facts"]["indeterminate_provider_calls"] = 2
elif mode == "native_missing_completeness":
    response["facts"]["journal_complete"] = None
elif mode == "native_impossible_ledger_count":
    response["facts"]["final_ledger_effect_count"] = 2
elif mode == "native_replay_claim":
    response["facts"]["replay_certified"] = True
elif mode == "native_quiescence_claim":
    response["facts"]["quiescence_certified"] = True
elif mode == "native_history_claim":
    response["facts"]["historical_completeness"] = True
elif mode == "native_v1_with_journal":
    response["facts"]["schema_version"] = "franken-node/native-session-forensics/v1"
elif mode == "native_v2_without_journal":
    response["facts"]["durable_journal"] = None
elif mode == "native_v3_without_journal":
    response["facts"]["durable_journal"] = None
elif mode == "native_v3_maximum_source":
    response["facts"]["source_capsule"]["capsule_bytes"] = 40 * 1024 * 1024 + 12
    response["facts"]["source_capsule"]["payload_bytes"] = 32 * 1024 * 1024
elif mode == "native_v3_missing_source":
    del response["facts"]["source_capsule"]
elif mode == "native_v3_null_source":
    response["facts"]["source_capsule"] = None
elif mode == "native_v3_source_wrong_schema":
    response["facts"]["source_capsule"]["schema_version"] = "franken-node/module-source-capsule/v99"
elif mode == "native_v3_source_wrong_graph":
    response["facts"]["source_capsule"]["graph_input_hash"] = "a" * 64
elif mode == "native_v3_source_graph_claim":
    response["facts"]["source_capsule"]["graph_hash_recomputed"] = True
elif mode == "native_v3_source_unknown_field":
    response["facts"]["source_capsule"]["guest_executed"] = True
elif mode == "native_v3_source_oversize":
    response["facts"]["source_capsule"]["capsule_bytes"] = 40 * 1024 * 1024 + 13
elif mode == "native_v3_source_payload_oversize":
    response["facts"]["source_capsule"]["capsule_bytes"] = 40 * 1024 * 1024 + 12
    response["facts"]["source_capsule"]["payload_bytes"] = 32 * 1024 * 1024 + 1
elif mode == "native_v3_source_payload_exceeds_capsule":
    response["facts"]["source_capsule"]["payload_bytes"] = 128
elif mode == "native_v3_source_counts_disagree":
    response["facts"]["source_capsule"]["file_count"] = 2
elif mode == "native_v3_source_boolean_count":
    response["facts"]["source_capsule"]["input_count"] = True
elif mode == "native_v3_source_excess_inputs":
    response["facts"]["source_capsule"]["input_count"] = 1025
    response["facts"]["source_capsule"]["file_count"] = 1023
elif mode == "native_v3_source_forbidden_symlink":
    response["facts"]["source_capsule"]["missing_count"] = 0
    response["facts"]["source_capsule"]["symlink_count"] = 1
elif mode == "native_v3_source_excess_conditions":
    response["facts"]["source_capsule"]["condition_count"] = 64
    response["facts"]["source_capsule"]["additional_condition_count"] = 1
elif mode == "native_v3_source_on_v1":
    response["facts"]["schema_version"] = "franken-node/native-session-forensics/v1"
    response["facts"]["durable_journal"] = None
elif mode == "native_v3_source_on_v2":
    response["facts"]["schema_version"] = "franken-node/native-session-forensics/v2"
elif mode == "native_unknown_schema":
    response["facts"]["schema_version"] = "franken-node/native-session-forensics/v99"
elif mode == "native_journal_wrong_nonce":
    response["facts"]["durable_journal"]["session_nonce"] = "0199abcd-1234-7000-8000-123456789abd"
elif mode == "native_journal_wrong_root":
    response["facts"]["durable_journal"]["product_root_key_id"] = "ed25519:" + "0" * 64
elif mode == "native_journal_wrong_admission":
    response["facts"]["durable_journal"]["admission_sha256"] = "c" * 64
elif mode == "native_journal_wrong_scope":
    response["facts"]["durable_journal"]["scope"] = "all_effects_completed"
elif mode == "native_journal_wrong_schema":
    response["facts"]["durable_journal"]["schema_version"] = "franken-node/native-effect-journal-record/v99"
elif mode == "native_journal_empty_prefix":
    response["facts"]["durable_journal"]["record_count"] = 0
elif mode == "native_journal_event_mismatch":
    response["facts"]["durable_journal"]["event_count"] = 4
elif mode == "native_journal_call_mismatch":
    response["facts"]["durable_journal"]["returned_provider_calls"] = 2
elif mode == "native_journal_missing_pending":
    response["facts"]["durable_journal"]["indeterminate_provider_calls"] = 0
elif mode == "native_journal_bad_head":
    response["facts"]["durable_journal"]["head_record_sha256"] = "invalid"
elif mode == "native_journal_bad_torn_flag":
    response["facts"]["durable_journal"]["trailing_partial_record"] = None
elif mode == "native_journal_unknown_field":
    response["facts"]["durable_journal"]["completed_external_effects"] = 1
elif mode == "native_journal_replay_claim":
    response["facts"]["durable_journal"]["replay_certified"] = True
elif mode == "native_journal_quiescence_claim":
    response["facts"]["durable_journal"]["quiescence_certified"] = True
elif mode == "native_journal_history_claim":
    response["facts"]["durable_journal"]["historical_completeness"] = True
elif mode == "native_journal_contradicts_complete_outcome":
    response["facts"]["completed_provider_calls"] = 0
elif mode == "native_incomplete_with_later_journal":
    response["facts"]["completed_provider_calls"] = 0
    response["facts"]["journal_complete"] = False
elif mode == "native_pending_prefix":
    response["facts"]["outcome_kind"] = "pending"
    for name in ("observed_at", "process_observation", "effect_observation", "containment_empty_observed",
                 "completed_provider_calls", "indeterminate_provider_calls", "final_ledger_effect_count",
                 "failed_effect_count", "journal_complete"):
        response["facts"][name] = None
elif mode == "native_zero_epoch":
    response["facts"]["security_epoch"] = "0"
elif mode == "resolution_invalid_decision":
    response["facts"]["decision"] = "verified"
elif mode == "resolution_reject_with_candidate":
    response["facts"]["decision"] = "reject"
elif mode == "resolution_admit_without_candidate":
    response["facts"]["selected_version"] = None
elif mode == "resolution_bad_graph":
    response["facts"]["module_graph_hash"] = "sha256:claimed"
elif mode == "resolution_wrong_signer":
    response["facts"]["signer_key_id"] = "sha256:" + "0" * 64
elif mode == "resolution_unsafe_count":
    response["facts"]["rejected_alternative_count"] = 1025
elif mode == "resolution_wrong_scope":
    response["scope"] = "guest_execution"
elif mode == "resolution_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "resolution_bad_profile":
    response["facts"]["policy_profile"] = "unsafe"
elif mode == "resolution_bad_budget_mode":
    response["facts"]["capability_budget_mode"] = "unlimited"
elif mode == "resolution_invalid_unicode":
    response["facts"]["package_name"] = "\ud800"
elif mode == "publisher_wrong_scope":
    response["scope"] = "publisher_execution_authorized"
elif mode == "publisher_wrong_signer":
    response["facts"]["signer_key_id"] = "0" * 16
elif mode == "publisher_graph_recomputed":
    response["facts"]["capsule"]["graph_hash_recomputed"] = True
elif mode == "publisher_unknown_field":
    response["facts"]["provenance_verified"] = True
elif mode == "publisher_authority_missing":
    response["facts"]["runtime_authority"] = None
elif mode == "publisher_v1_authority":
    response["facts"]["registration_schema"] = "franken-node/extension-registration-manifest/v1"
elif mode == "publisher_rounded_ceiling":
    response["facts"]["runtime_authority"]["max_instructions"] = 2**64 - 1
elif mode == "publisher_overflow_ceiling":
    response["facts"]["runtime_authority"]["max_total_memory_bytes"] = str(2**64)
elif mode == "publisher_zero_ceiling":
    response["facts"]["runtime_authority"]["max_heap_objects"] = "0"
elif mode == "publisher_invalid_capability":
    response["facts"]["runtime_authority"]["allowed_capabilities"].append("unrestricted")
elif mode == "publisher_authority_extra":
    response["facts"]["runtime_authority"]["execution_authorized"] = True
elif mode.startswith("publisher_host_"):
    authority = response["facts"]["runtime_authority"]
    authority["allowed_capabilities"] += ["env_read", "fs_read", "network_egress"]
    host = {
        "host_ports": ["[2001:db8::1]:443", "api.example.test:443"],
        "env_keys": ["PUBLIC_NAME"],
        "max_calls_per_epoch": {"env_read": "1", "fs_read": "0", "network_egress": str(2**64 - 1)},
    }
    authority["host_io"] = host
    if mode == "publisher_host_empty":
        authority["host_io"] = {"host_ports": [], "env_keys": [], "max_calls_per_epoch": {}}
    elif mode == "publisher_host_unspecified":
        authority["host_io"] = {"max_calls_per_epoch": {"fs_read": "0"}}
    elif mode in {"publisher_host_process_maximum", "publisher_host_process_zero"}:
        authority["allowed_capabilities"] += ["fs_write", "random_read", "process_spawn"]
        host["max_calls_per_epoch"].update({
            "fs_write": "1", "random_read": "1",
            "process_spawn": "0" if mode.endswith("_zero") else str(2**64 - 1),
        })
    elif mode == "publisher_host_process_undeclared":
        host["max_calls_per_epoch"]["process_spawn"] = "1"
    elif mode == "publisher_host_process_overflow":
        authority["allowed_capabilities"].append("process_spawn")
        host["max_calls_per_epoch"]["process_spawn"] = str(2**64)
    elif mode == "publisher_host_process_beyond_instruction":
        authority["allowed_capabilities"].append("process_spawn")
        authority["max_instructions"] = "1"
        host["max_calls_per_epoch"]["network_egress"] = "1"
        host["max_calls_per_epoch"]["process_spawn"] = "2"
    elif mode == "publisher_host_null":
        authority["host_io"] = None
    elif mode == "publisher_host_unknown_field":
        host["execution_authorized"] = True
    elif mode == "publisher_host_missing_quotas":
        del host["max_calls_per_epoch"]
    elif mode == "publisher_host_numeric_quota":
        host["max_calls_per_epoch"]["fs_read"] = 0
    elif mode == "publisher_host_overflow_quota":
        host["max_calls_per_epoch"]["network_egress"] = str(2**64)
    elif mode == "publisher_host_beyond_instruction_quota":
        authority["max_instructions"] = "1"
        host["max_calls_per_epoch"]["network_egress"] = "2"
    elif mode == "publisher_host_undeclared_quota":
        host["max_calls_per_epoch"]["fs_write"] = "1"
    elif mode == "publisher_host_noncanonical_quota":
        host["max_calls_per_epoch"]["fs_read"] = "00"
    elif mode == "publisher_host_quota_newline":
        host["max_calls_per_epoch"]["fs_read"] = "0\n"
    elif mode == "publisher_host_wildcard":
        host["host_ports"] = ["*.example.test:443"]
    elif mode == "publisher_host_url":
        host["host_ports"] = ["https://api.example.test:443/"]
    elif mode == "publisher_host_invalid_port":
        host["host_ports"] = ["api.example.test:65536"]
    elif mode == "publisher_host_uppercase":
        host["host_ports"] = ["API.example.test:443"]
    elif mode == "publisher_host_invalid_ipv6":
        host["host_ports"] = ["[fe80::1%eth0]:443"]
    elif mode == "publisher_host_duplicate_scope":
        host["host_ports"] = ["api.example.test:443", "api.example.test:443"]
    elif mode == "publisher_host_unsorted_scope":
        host["host_ports"].reverse()
    elif mode == "publisher_host_null_scope":
        host["host_ports"] = None
    elif mode == "publisher_host_undeclared_scope":
        authority["allowed_capabilities"].remove("network_egress")
        host["max_calls_per_epoch"].pop("network_egress")
    elif mode == "publisher_host_invalid_env":
        host["env_keys"] = ["NAME=VALUE"]
    elif mode == "publisher_host_env_newline":
        host["env_keys"] = ["NAME\n"]
    elif mode == "publisher_host_excessive_scope":
        host["env_keys"] = sorted(f"KEY_{index}" for index in range(129))
elif mode == "publisher_count_inconsistent":
    response["facts"]["capsule"]["metadata_file_count"] = 1
elif mode == "publisher_unsafe_count":
    response["facts"]["capsule"]["input_count"] = 2**53
elif mode == "publisher_bad_digest":
    response["facts"]["capsule_digest"] = "sha256:claimed"
elif mode == "publisher_capsule_not_object":
    response["facts"]["capsule"] = []
elif mode == "publisher_trust_scope_downgrade":
    response["scope"] = "authenticated_publisher_source_content"
elif mode == "publisher_trust_format_downgrade":
    response["format"] = "publisher-source"
    response["scope"] = "authenticated_publisher_source_content"
    response["facts"] = response["facts"]["source"]
elif mode == "publisher_trust_wrong_revocation_anchor":
    response["facts"]["revocation_authority_public_key_hex"] = "33" * 32
elif mode == "publisher_trust_wrong_provenance_anchor":
    response["facts"]["provenance_authority_public_key_hex"] = revocation_anchor
elif mode == "publisher_trust_missing_provenance":
    for key in ("provenance_chain_sha256", "provenance_authority_public_key_hex", "provenance_link_count"):
        response["facts"][key] = None
elif mode == "publisher_trust_unrequested_provenance":
    response["facts"]["provenance_chain_sha256"] = "sha256:" + "b" * 64
    response["facts"]["provenance_authority_public_key_hex"] = "22" * 32
    response["facts"]["provenance_link_count"] = 2
elif mode == "publisher_trust_partial_provenance":
    response["facts"]["provenance_chain_sha256"] = None
elif mode == "publisher_trust_zero_provenance":
    response["facts"]["provenance_link_count"] = 0
elif mode == "publisher_trust_overflow_provenance":
    response["facts"]["provenance_link_count"] = 257
elif mode == "publisher_trust_unsafe_provenance":
    response["facts"]["provenance_link_count"] = 2**53
elif mode == "publisher_trust_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "publisher_trust_bad_revocation_digest":
    response["facts"]["revocation_list_sha256"] = "sha256:invalid"
elif mode == "publisher_trust_bad_provenance_digest":
    response["facts"]["provenance_chain_sha256"] = "sha256:invalid"
elif mode == "publisher_trust_wrong_evaluation_time":
    response["facts"]["revocation_evaluated_at"] = "2026-10-24T00:00:30.123456788Z"
elif mode == "publisher_trust_rounded_evaluation_time":
    response["facts"]["revocation_evaluated_at"] = "2026-10-24T00:00:30.123Z"
elif mode == "publisher_trust_wrong_window":
    response["facts"]["max_revocation_age_secs"] = "61"
elif mode == "publisher_trust_rounded_window":
    response["facts"]["max_revocation_age_secs"] = 60
elif mode == "publisher_trust_future_revocations":
    response["facts"]["revocation_issued_at"] = "2026-10-24T00:00:30.123456790Z"
elif mode == "publisher_trust_stale_revocations":
    response["facts"]["revocation_issued_at"] = "2026-10-23T23:59:30.123456789Z"
elif mode == "publisher_trust_malformed_time":
    response["facts"]["revocation_issued_at"] = "2026-02-30T00:00:00Z"
elif mode == "publisher_trust_nested_wrong_signer":
    response["facts"]["source"]["signer_public_key_hex"] = "00" * 32
elif mode == "publisher_trust_nested_authority_missing":
    response["facts"]["source"]["runtime_authority"] = None
elif mode == "publisher_trust_nested_unknown_field":
    response["facts"]["source"]["provenance_verified"] = True
elif mode == "publisher_trust_nested_non_object":
    response["facts"]["source"] = []
elif mode == "publisher_trust_before_boundary":
    response["facts"]["revocation_issued_at"] = "2026-10-23T23:59:30.123456790Z"
elif mode == "counterfactual_wrong_scope":
    response["scope"] = "guest_executed"
elif mode == "counterfactual_invalid_mode":
    response["facts"]["mode"] = "parallel"
elif mode == "counterfactual_single_count_mismatch":
    response["facts"]["mode"] = "single"
    response["facts"]["result_count"] = 2
elif mode == "counterfactual_zero_count":
    response["facts"]["result_count"] = 0
elif mode == "counterfactual_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "ltv_wrong_scope":
    response["scope"] = "guest_executed"
elif mode == "ltv_rounded_timestamp":
    response["facts"]["as_of_unix_seconds"] = 1700000500
elif mode == "ltv_overflow_timestamp":
    response["facts"]["as_of_unix_seconds"] = str(2**64)
elif mode == "ltv_bad_artifact_hash":
    response["facts"]["artifact_hash"] = "sha256:invalid"
elif mode == "ltv_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "ltv_missing_policy_hash":
    del response["facts"]["trust_policy_sha256"]
elif mode == "ltv_wrong_policy_hash":
    response["facts"]["trust_policy_sha256"] = "a" * 64
elif mode == "ltv_uppercase_policy_hash":
    response["facts"]["trust_policy_sha256"] = response["facts"]["trust_policy_sha256"].upper()
elif mode == "fleet_wrong_scope":
    response["scope"] = "authenticated_epoch_commit"
elif mode == "fleet_wrong_format":
    response["format"] = "native-session-forensics"
elif mode == "fleet_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "fleet_missing_field":
    del response["facts"]["current_quiescence_proven"]
elif mode == "fleet_wrong_policy_input":
    response["facts"]["trusted_policy_input_sha256"] = "a" * 64
elif mode == "fleet_canonical_hash_as_input_hash":
    response["facts"]["trusted_policy_input_sha256"] = response["facts"]["trust_policy_sha256"]
elif mode == "fleet_malformed_policy_hash":
    response["facts"]["trust_policy_sha256"] = "sha256:invalid"
elif mode == "fleet_wrong_evidence_input":
    response["facts"]["evidence_sha256"] = "a" * 64
elif mode == "fleet_wrong_evaluation_time":
    response["facts"]["evaluation_time"] = "2026-11-23T01:00:11Z"
elif mode == "fleet_stale_observation":
    response["facts"]["observed_at"] = "2026-11-23T00:59:40Z"
elif mode == "fleet_future_observation":
    response["facts"]["observed_at"] = "2026-11-23T01:00:11Z"
elif mode == "fleet_wrong_population":
    response["facts"]["participant_count"] = 1
elif mode == "fleet_boolean_population":
    response["facts"]["participant_count"] = True
elif mode == "fleet_numeric_count":
    response["facts"]["admitted_sessions"] = 2**64 - 1
    response["facts"]["terminal_sessions"] = 2**64 - 1
elif mode == "fleet_noncanonical_count":
    response["facts"]["admitted_sessions"] = "01"
    response["facts"]["terminal_sessions"] = "01"
elif mode == "fleet_overflow_count":
    response["facts"]["admitted_sessions"] = str(2**64)
    response["facts"]["terminal_sessions"] = str(2**64)
elif mode == "fleet_terminal_mismatch":
    response["facts"]["terminal_sessions"] = "0"
elif mode == "fleet_unverified_signatures":
    response["facts"]["supervisor_signatures_verified"] = False
elif mode == "fleet_incomplete_population":
    response["facts"]["expected_population_complete"] = False
elif mode == "fleet_unmatched_action_context":
    response["facts"]["expected_action_context_matched"] = False
elif mode == "fleet_epoch_commit_claim":
    response["facts"]["epoch_commit_authenticated"] = True
elif mode == "fleet_current_quiescence_claim":
    response["facts"]["current_quiescence_proven"] = True
elif mode == "fleet_valid_empty_session_set":
    response["facts"]["admitted_sessions"] = "0"
    response["facts"]["terminal_sessions"] = "0"
elif mode == "epoch_wrong_scope":
    response["scope"] = "authenticated_fleet_supervisor_observations"
elif mode == "epoch_wrong_format":
    response["format"] = "fleet-quiescence-observations"
elif mode == "epoch_wrong_schema":
    response["facts"]["schema_version"] = "franken-verifier/fleet-quiescence-observations/v1"
elif mode == "epoch_missing_field":
    del response["facts"]["statement_sha256"]
elif mode == "epoch_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "epoch_wrong_coordinator":
    response["facts"]["coordinator_id"] = "coordinator-other"
elif mode == "epoch_wrong_key":
    response["facts"]["coordinator_key_id"] = "ed25519:" + "33" * 32
elif mode == "epoch_missing_commit_claim":
    response["facts"]["epoch_commit_authenticated"] = False
elif mode == "epoch_current_quiescence_claim":
    response["facts"]["current_quiescence_proven"] = True
elif mode == "epoch_numeric_epoch":
    response["facts"]["committed_epoch"] = 8
elif mode == "epoch_noncanonical_epoch":
    response["facts"]["committed_epoch"] = "08"
elif mode == "epoch_overflow_epoch":
    response["facts"]["committed_epoch"] = str(2**64)
elif mode == "epoch_wrong_committed_epoch":
    response["facts"]["committed_epoch"] = "9"
elif mode == "epoch_bad_statement_hash":
    response["facts"]["statement_sha256"] = "sha256:" + "a" * 64
elif mode == "epoch_uppercase_statement_hash":
    response["facts"]["statement_sha256"] = "A" * 64
elif mode == "epoch_empty_transition":
    response["facts"]["transition_id"] = ""
elif mode == "epoch_transition_control":
    response["facts"]["transition_id"] = "epoch-protocol\ncontrol"
elif mode == "epoch_wrong_policy_input":
    response["facts"]["trusted_policy_input_sha256"] = "a" * 64
elif mode == "epoch_wrong_evidence_input":
    response["facts"]["evidence_sha256"] = "a" * 64
elif mode == "epoch_unverified_supervisors":
    response["facts"]["supervisor_signatures_verified"] = False
elif mode == "session_fail":
    response["facts"]["final_verdict"] = "fail"
elif mode == "session_empty":
    response["facts"]["final_verdict"] = "inconclusive"
    response["facts"]["step_count"] = 0
elif mode == "session_wrong_scope":
    response["scope"] = "guest_executed"
elif mode == "session_wrong_signer":
    response["facts"]["signer_public_key_hex"] = "33" * 32
elif mode == "session_unknown_field":
    response["facts"]["execution_authorized"] = True
elif mode == "session_missing_field":
    del response["facts"]["final_verdict"]
elif mode == "session_boolean_count":
    response["facts"]["step_count"] = True
elif mode == "session_negative_count":
    response["facts"]["step_count"] = -1
elif mode == "session_excessive_count":
    response["facts"]["step_count"] = 1025
elif mode == "session_empty_pass":
    response["facts"]["step_count"] = 0
elif mode == "session_nonempty_inconclusive":
    response["facts"]["final_verdict"] = "inconclusive"
elif mode == "session_bad_identity":
    response["facts"]["verifier_identity"] = "internal://protocol-test"
elif mode == "session_empty_id":
    response["facts"]["session_id"] = ""
elif mode == "session_long_id":
    response["facts"]["session_id"] = "a" * 256
elif mode == "session_id_newline":
    response["facts"]["session_id"] += "\n"
elif mode == "session_bad_time":
    response["facts"]["created_at"] = "2026-02-30T00:00:00Z"
elif mode == "session_bad_verdict":
    response["facts"]["final_verdict"] = "verified"
elif mode == "session_bad_hash":
    response["facts"]["transcript_hash"] = "sha256:" + "a" * 64
elif mode == "session_uppercase_hash":
    response["facts"]["transcript_hash"] = "A" * 64
encoded = json.dumps(response, separators=(",", ":"), sort_keys=True)
if mode == "duplicate":
    encoded = encoded[:-1] + ',"verdict":"verified"}'
elif mode == "run_duplicate_origin":
    encoded = encoded.replace('"receipt_id":"run-protocol-control"',
                              '"receipt_id":"run-protocol-control","receipt_id":"run-protocol-control"')
sys.stdout.write(encoded)
sys.exit(exit_code)
