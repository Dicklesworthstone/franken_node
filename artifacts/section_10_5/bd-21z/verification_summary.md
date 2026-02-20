# bd-21z: Signed Decision Receipt Export — Verification Summary

## Bead: bd-21z | Section: 10.5

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Spec contract | `docs/specs/section_10_5/bd-21z_contract.md` | PASS |
| Receipt implementation | `crates/franken-node/src/security/decision_receipt.rs` | PASS |
| Security module wiring | `crates/franken-node/src/security/mod.rs` | PASS |
| CLI receipt export wiring | `crates/franken-node/src/cli.rs`, `crates/franken-node/src/main.rs` | PASS |
| Integration test | `tests/integration/decision_receipt_export.rs` | PASS |
| Verification script | `scripts/check_signed_receipt.py` | PASS |
| Python verification tests | `tests/test_check_signed_receipt.py` | PASS |
| Fixture corpus | `fixtures/security/decision_receipt_samples.json` | PASS |
| Receipt chain artifact | `artifacts/section_10_5/bd-21z/decision_receipt_chain.json` | PASS |
| Verification evidence | `artifacts/section_10_5/bd-21z/verification_evidence.json` | PASS |

## Verification Results

- `python3 scripts/check_signed_receipt.py --json` -> PASS (7/7 checks)
- `python3 -m unittest tests/test_check_signed_receipt.py` -> PASS (12 tests)

## Notes

- Signature validation is deterministic and cryptographic over canonical payloads.
- Hash-chain integrity is validated against `previous_receipt_hash` and `chain_hash`.
- Cargo offload through `rch` remains blocked in this repo for sibling path dependencies (`../franken_engine`) on remote workers; this is a known project-level constraint already reported by other active agents.

## Verdict: PASS
