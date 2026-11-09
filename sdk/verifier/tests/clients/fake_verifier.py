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
encoded = json.dumps(response, separators=(",", ":"), sort_keys=True)
if mode == "duplicate":
    encoded = encoded[:-1] + ',"verdict":"verified"}'
elif mode == "run_duplicate_origin":
    encoded = encoded.replace('"receipt_id":"run-protocol-control"',
                              '"receipt_id":"run-protocol-control","receipt_id":"run-protocol-control"')
sys.stdout.write(encoded)
sys.exit(exit_code)
