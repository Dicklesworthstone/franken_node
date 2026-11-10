#!/usr/bin/python3
"""Intentionally broken child process; never part of the distribution.

Used to prove typed protocol refusal, timeout handling and failure propagation.
It does not authenticate anything. The normal consumer matrix must fail on it.
"""
import hashlib
import json
import sys
import time

data = sys.stdin.buffer.read()
try:
    mode = json.loads(data).get("protocol_control", "accept_everything")
except (ValueError, AttributeError):
    mode = "accept_everything"
anchor = sys.argv[sys.argv.index("--trusted-key-hex") + 1]
run_anchor = (sys.argv[sys.argv.index("--trusted-run-key-hex") + 1]
              if "--trusted-run-key-hex" in sys.argv else "11" * 32)
runtime_anchor = (sys.argv[sys.argv.index("--trusted-runtime-key-hex") + 1]
                  if "--trusted-runtime-key-hex" in sys.argv else "22" * 32)
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
exit_code = 0
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
elif mode == "publisher_count_inconsistent":
    response["facts"]["capsule"]["metadata_file_count"] = 1
elif mode == "publisher_unsafe_count":
    response["facts"]["capsule"]["input_count"] = 2**53
elif mode == "publisher_bad_digest":
    response["facts"]["capsule_digest"] = "sha256:claimed"
elif mode == "publisher_capsule_not_object":
    response["facts"]["capsule"] = []
encoded = json.dumps(response, separators=(",", ":"), sort_keys=True)
if mode == "duplicate":
    encoded = encoded[:-1] + ',"verdict":"verified"}'
elif mode == "run_duplicate_origin":
    encoded = encoded.replace('"receipt_id":"run-protocol-control"',
                              '"receipt_id":"run-protocol-control","receipt_id":"run-protocol-control"')
sys.stdout.write(encoded)
sys.exit(exit_code)
