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
encoded = json.dumps(response, separators=(",", ":"), sort_keys=True)
if mode == "duplicate":
    encoded = encoded[:-1] + ',"verdict":"verified"}'
sys.stdout.write(encoded)
sys.exit(exit_code)
