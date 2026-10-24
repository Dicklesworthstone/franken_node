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
                                 format=case["format"], signature_hex=case.get("signature_hex"))
    except VerifierError as error:
        assert error.code == case["expected"], (case["name"], error.code, case["expected"])
        print(json.dumps({"case": case["name"], "result": error.code}), flush=True)
    else:
        assert case["expected"] == "verified", case["name"]
        assert result["artifact_sha256"] == hashlib.sha256(data).hexdigest()
        if case["format"] == "incident-bundle":
            assert result["facts"]["event_count"] == 3
            assert result["facts"]["signing_identity"] == "339eefa3a988f613"
        assert "PRIVATE-" not in json.dumps(result)
        print(json.dumps({"case": case["name"], "result": "verified", "scope": result["scope"]}), flush=True)

for label, data, options, expected in [
    ("oversize_client_input", b" " * (MAX_INPUT_BYTES + 1), {}, "INPUT_TOO_LARGE"),
    ("bad_key_shape", b"{}", {"trusted_public_key_hex": "00"}, "ANCHOR_INVALID"),
    ("invalid_timeout", b"{}", {"timeout": 0}, "TIMEOUT_INVALID"),
    ("enormous_timeout_integer", b"{}", {"timeout": 10**1000}, "TIMEOUT_INVALID"),
    ("missing_executable", b"{}", {"verifier": str(root / "does-not-exist")}, "PROCESS_UNAVAILABLE"),
]:
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
print(json.dumps({"consumer": "python", "matrix_cases": len(cases), "client_cases": 5,
                  "protocol_cases": len(controls), "passed": True}), flush=True)
