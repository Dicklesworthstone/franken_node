"""Tests for scripts/check_oracle_close_condition.py (dual-oracle gate)."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_oracle_close_condition.py"
ORACLE_GATE_FIXTURES = ROOT / "tests" / "fixtures" / "oracle_gate"

spec = importlib.util.spec_from_file_location("check_oracle_close_condition", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_required_dimensions_count():
    assert len(mod.REQUIRED_DIMENSIONS) == 3


def test_dimension_ids():
    ids = {d["id"] for d in mod.REQUIRED_DIMENSIONS}
    assert ids == {"l1_product", "l2_engine_boundary", "release_policy_linkage"}


def l1_proof_evidence():
    return {
        "evidence": {
            "proof_carrying_effects": {
                "schema_version": "franken-node/l1-proof-carrying-effects/v1",
                "required_subjects": ["fs.read", "fs.write", "http.request"],
                "verified_subjects": ["fs.read", "fs.write", "http.request"],
                "effect_receipts_verified": 3,
                "invalid_receipts": 0,
                "receipt_chain_verified": True,
            }
        }
    }


def green_payload(dim_id):
    payload = {"verdict": "GREEN"}
    if dim_id == "l1_product":
        payload.update(l1_proof_evidence())
    return payload


# ---------------------------------------------------------------------------
# check_dimension
# ---------------------------------------------------------------------------

class TestCheckDimension:
    def _dim(self, dim_id="l1_product"):
        return next(d for d in mod.REQUIRED_DIMENSIONS if d["id"] == dim_id)

    def test_green_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps(green_payload(dim["id"])))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "GREEN"
        assert result["error"] is None

    def test_yellow_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        payload = green_payload(dim["id"])
        payload["verdict"] = "YELLOW"
        artifact.write_text(json.dumps(payload))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "YELLOW"
        assert result["error"] is not None
        assert "YELLOW" in result["error"]

    def test_red_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        payload = green_payload(dim["id"])
        payload["verdict"] = "RED"
        artifact.write_text(json.dumps(payload))
        result = mod.check_dimension(tmp_path, dim)
        assert result["verdict"] == "RED"
        assert "RED" in result["error"]

    def test_missing_artifact(self, tmp_path):
        dim = self._dim()
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is False
        assert result["verdict"] is None
        assert "not found" in result["error"]

    def test_malformed_json(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text("not json")
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert "Malformed" in result["error"]

    def test_invalid_verdict_value(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "BLUE"}))
        result = mod.check_dimension(tmp_path, dim)
        assert "Invalid verdict" in result["error"]

    def test_missing_verdict_key(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"status": "ok"}))
        result = mod.check_dimension(tmp_path, dim)
        assert "Invalid verdict" in result["error"]

    def test_all_dimensions_green(self, tmp_path):
        for dim in mod.REQUIRED_DIMENSIONS:
            artifact = tmp_path / dim["artifact"]
            artifact.write_text(json.dumps(green_payload(dim["id"])))
        results = [mod.check_dimension(tmp_path, d) for d in mod.REQUIRED_DIMENSIONS]
        assert all(r["verdict"] == "GREEN" for r in results)
        assert all(r["error"] is None for r in results)

    def test_result_structure(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps(green_payload(dim["id"])))
        result = mod.check_dimension(tmp_path, dim)
        expected_keys = {"dimension", "label", "owner_track", "present", "verdict"}
        missing_keys = expected_keys.difference(result)
        if missing_keys:
            raise AssertionError(f"missing result keys: {sorted(missing_keys)}")
        assert result["dimension"] == "l1_product"

    def test_l2_engine_boundary_dimension(self, tmp_path):
        dim = self._dim("l2_engine_boundary")
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps(green_payload(dim["id"])))
        result = mod.check_dimension(tmp_path, dim)
        assert result["dimension"] == "l2_engine_boundary"
        assert result["verdict"] == "GREEN"

    def test_l1_green_without_proof_carrying_effects_fails_closed(self, tmp_path):
        dim = self._dim("l1_product")
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "GREEN", "evidence": {}}))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "GREEN"
        assert "proof_carrying_effects evidence missing" in result["error"]

    def test_l1_incomplete_proof_carrying_effects_fails_closed(self, tmp_path):
        dim = self._dim("l1_product")
        artifact = tmp_path / dim["artifact"]
        payload = green_payload("l1_product")
        proof = payload["evidence"]["proof_carrying_effects"]
        proof["verified_subjects"] = ["fs.read", "fs.write"]
        proof["effect_receipts_verified"] = 2
        proof["receipt_chain_verified"] = False
        artifact.write_text(json.dumps(payload))
        result = mod.check_dimension(tmp_path, dim)
        assert "missing subject http.request" in result["error"]
        assert "effect_receipts_verified below required 3" in result["error"]
        assert "receipt_chain_verified is not true" in result["error"]


# ---------------------------------------------------------------------------
# proof_carrying_effects v2: the gate re-derives the embedded chain
# (bd-qr5i2.3, mirroring the Rust doctor gate's v2 path)
# ---------------------------------------------------------------------------

EMPTY_LINEAGE = "sha256:" + hashlib.sha256(b"").hexdigest()
CHAIN_GENESIS = "sha256:" + "0" * 64


def _content_hash(data: bytes) -> str:
    """Mirror storage::cas::content_hash: CAS domain separator + u64-LE
    length prefix + bytes (NOT a plain sha256 of the payload)."""
    h = hashlib.sha256()
    h.update(b"storage_cas_content_hash_v1:")
    h.update(len(data).to_bytes(8, "little"))
    h.update(data)
    return "sha256:" + h.hexdigest()


def allowed_receipt(seq, kind):
    """Mirror EffectReceipt::allowed + the deterministic inputs used by the
    Rust parity helper l1_acceptance_chain_entries (doctor_close_condition_e2e)."""
    return {
        "schema_version": "effect-receipt-v1.1",
        "seq": seq,
        "trace_id": "acceptance-evidence-v2-e2e",
        "effect_kind": kind,
        "policy_outcome": {"outcome": "allowed", "capability_ref": "cap-l1-acceptance"},
        "pre_state_hash": _content_hash(b"pre-state"),
        "args_hash": _content_hash(b"args"),
        "result_hash": _content_hash(b"result"),
        "post_state_hash": _content_hash(b"post-state"),
        "input_lineage_hash": EMPTY_LINEAGE,
        "output_lineage_hash": EMPTY_LINEAGE,
        "label_set_commitment": EMPTY_LINEAGE,
        "declassification_ref": None,
        "flow_policy_verdict": "label_clean",
        "recorded_at_millis": 1_774_000_000_000,
    }


def denied_receipt(seq, kind, reason="policy refused the effect"):
    """Mirror EffectReceipt::denied — no result/post-state/output lineage."""
    return {
        "schema_version": "effect-receipt-v1.1",
        "seq": seq,
        "trace_id": "acceptance-evidence-v2-e2e",
        "effect_kind": kind,
        "policy_outcome": {"outcome": "denied", "reason": reason},
        "pre_state_hash": _content_hash(b"pre-state"),
        "args_hash": _content_hash(b"args"),
        "result_hash": None,
        "post_state_hash": None,
        "input_lineage_hash": EMPTY_LINEAGE,
        "output_lineage_hash": None,
        "label_set_commitment": EMPTY_LINEAGE,
        "declassification_ref": None,
        "flow_policy_verdict": "label_clean",
        "recorded_at_millis": 1_774_000_000_000,
    }


def build_chain(receipts):
    """Build a genuine chain through the module's own canonical hashing."""
    entries = []
    prev = CHAIN_GENESIS
    for index, receipt in enumerate(receipts):
        rh = mod.receipt_hash(receipt)
        ch = mod.chain_hash(index, prev, rh)
        entries.append(
            {
                "index": index,
                "prev_chain_hash": prev,
                "receipt_hash": rh,
                "chain_hash": ch,
                "receipt": receipt,
            }
        )
        prev = ch
    return entries


def acceptance_chain_entries():
    return build_chain(
        [
            allowed_receipt(0, "fs_read"),
            allowed_receipt(1, "fs_write"),
            allowed_receipt(2, "http_request"),
        ]
    )


def v2_proof(entries, verified_subjects, effect_receipts_verified,
             invalid_receipts=0, receipt_chain_verified=True):
    return {
        "schema_version": mod.L1_PROOF_EVIDENCE_SCHEMA_V2,
        "required_subjects": ["fs.read", "fs.write", "http.request"],
        "verified_subjects": verified_subjects,
        "effect_receipts_verified": effect_receipts_verified,
        "invalid_receipts": invalid_receipts,
        "receipt_chain_verified": receipt_chain_verified,
        "receipt_chain_entries": entries,
    }


def test_parity_pin_hashes():
    """Cross-language parity pin: these constants are also asserted by the
    Rust test effect_receipt_hash_cross_language_parity_pin_bd_qr5i2_3 in
    crates/franken-node/tests/doctor_close_condition_e2e.rs against the
    production EffectReceipt implementation. Preimage drift on either side
    breaks exactly one suite and names the divergent implementation."""
    entries = acceptance_chain_entries()
    assert entries[0]["receipt_hash"] == (
        "sha256:4c95c6f0ba9a43d07dbf8646b3876e1588873165b1ee91862490fc4bf4939979"
    )
    assert entries[2]["chain_hash"] == (
        "sha256:ff29fcb4bbbff4bcd338d6b7bdaa2a9f137de11990190aebc841feb034c1b3c1"
    )


class TestProofCarryingV2:
    def test_green_rederivable_chain_yields_no_errors(self):
        proof = v2_proof(
            acceptance_chain_entries(), ["fs.read", "fs.write", "http.request"], 3
        )
        assert mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        ) == []

    def test_missing_receipt_chain_entries_fails_closed(self):
        proof = v2_proof([], ["fs.read", "fs.write", "http.request"], 3)
        del proof["receipt_chain_entries"]
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        assert any("missing receipt_chain_entries" in e for e in errors)

    def test_unparseable_entries_fail_closed(self):
        entries = acceptance_chain_entries()
        entries[1]["receipt"]["effect_kind"] = "teleport"
        proof = v2_proof(entries, ["fs.read", "fs.write", "http.request"], 3)
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        assert any("failed to parse" in e for e in errors)

    def test_tampered_receipt_hash_fails_rederivation(self):
        entries = acceptance_chain_entries()
        rh = entries[1]["receipt_hash"]
        entries[1]["receipt_hash"] = rh[:-1] + ("0" if rh[-1] != "0" else "1")
        proof = v2_proof(entries, ["fs.read", "fs.write", "http.request"], 3)
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        assert any("failed re-derivation" in e for e in errors)
        # The declared summary now also disagrees with the derived chain state.
        assert any("receipt_chain_verified" in e for e in errors)

    def test_tampered_receipt_contents_fail_rederivation(self):
        entries = acceptance_chain_entries()
        entries[2]["receipt"]["trace_id"] = "rewritten-history"
        proof = v2_proof(entries, ["fs.read", "fs.write", "http.request"], 3)
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        assert any("failed re-derivation" in e for e in errors)

    def test_inflated_declared_count_fails_closed(self):
        proof = v2_proof(
            acceptance_chain_entries(), ["fs.read", "fs.write", "http.request"], 4
        )
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        assert any(
            "effect_receipts_verified" in e and "does not match re-derived 3" in e
            for e in errors
        )

    def test_overstated_declared_subjects_fail_closed(self):
        entries = build_chain(
            [allowed_receipt(0, "fs_read"), allowed_receipt(1, "fs_write")]
        )
        proof = v2_proof(entries, ["fs.read", "fs.write", "http.request"], 2)
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        assert any("verified_subjects" in e and "do not match" in e for e in errors)

    def test_honest_missing_subject_still_fails_acceptance(self):
        entries = build_chain(
            [allowed_receipt(0, "fs_read"), allowed_receipt(1, "fs_write")]
        )
        proof = v2_proof(entries, ["fs.read", "fs.write"], 2)
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        assert any("missing subject http.request" in e for e in errors)
        assert any("below required 3" in e for e in errors)

    def test_denied_receipt_tolerated_in_chain_but_never_counted(self):
        receipts = [
            allowed_receipt(0, "fs_read"),
            allowed_receipt(1, "fs_write"),
            allowed_receipt(2, "http_request"),
            denied_receipt(3, "spawn"),
        ]
        entries = build_chain(receipts)
        proof = v2_proof(entries, ["fs.read", "fs.write", "http.request"], 3)
        assert mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        ) == []

    def test_invalid_receipt_counted_and_fails_acceptance(self):
        # An allowed receipt whose result_hash was stripped violates the
        # allowed/denied invariant: parseable, but invalid on validate().
        receipts = [
            allowed_receipt(0, "fs_read"),
            allowed_receipt(1, "fs_write"),
            allowed_receipt(2, "http_request"),
        ]
        receipts[2]["result_hash"] = None
        entries = build_chain(receipts)
        proof = v2_proof(
            entries, ["fs.read", "fs.write"], 2, invalid_receipts=1
        )
        errors = mod.validate_l1_proof_carrying_evidence(
            {"evidence": {"proof_carrying_effects": proof}}
        )
        # Declared matches derived (honest), but acceptance still fails on the
        # derived values: missing subject, count floor, nonzero invalid.
        assert any("missing subject http.request" in e for e in errors)
        assert any("below required 3" in e for e in errors)
        assert any("contains 1 invalid receipt(s)" in e for e in errors)
        assert not any("does not match" in e for e in errors)

    def test_v2_pass_fixture_directory_is_green(self):
        for dim in mod.REQUIRED_DIMENSIONS:
            result = mod.check_dimension(ORACLE_GATE_FIXTURES / "pass_v2", dim)
            assert result["verdict"] == "GREEN", result
            assert result["error"] is None, result

    def test_v2_tampered_fixture_directory_fails_l1(self):
        dim = next(d for d in mod.REQUIRED_DIMENSIONS if d["id"] == "l1_product")
        result = mod.check_dimension(ORACLE_GATE_FIXTURES / "fail_v2_tampered", dim)
        assert result["error"] is not None
        assert "failed re-derivation" in result["error"]
