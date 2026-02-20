# bd-3tzl Verification Summary

## Bead
**bd-3tzl** — Bounded parser/resource-accounting guardrails on control-channel frame decode

## Verdict: PASS

All 6 verification checks passed.

| Check | Description | Status |
|-------|-------------|--------|
| BPG-IMPL | Implementation with all required types | PASS |
| BPG-ERRORS | All 5 error codes present (5/5) | PASS |
| BPG-RESULTS | Frame decode guardrail test results | PASS |
| BPG-INTEG | Integration tests cover all 4 invariants | PASS |
| BPG-TESTS | Rust unit tests pass (17 passed) | PASS |
| BPG-SPEC | Specification with invariants and types | PASS |

## Artifacts
- Spec: `docs/specs/section_10_13/bd-3tzl_contract.md`
- Impl: `crates/franken-node/src/connector/frame_parser.rs`
- Integration tests: `tests/integration/frame_decode_guardrails.rs`
- Test fixtures: `artifacts/section_10_13/bd-3tzl/frame_decode_guardrail_results.json`
- Verification script: `scripts/check_frame_parser.py`
- Python tests: `tests/test_check_frame_parser.py` (12 passed)
- Evidence: `artifacts/section_10_13/bd-3tzl/verification_evidence.json`

## Invariants Covered
- **INV-BPG-SIZE-BOUNDED** — Frames exceeding max_frame_bytes are rejected
- **INV-BPG-DEPTH-BOUNDED** — Frames exceeding max_nesting_depth are rejected
- **INV-BPG-CPU-BOUNDED** — Frames exceeding max_decode_cpu_ms are rejected
- **INV-BPG-AUDITABLE** — Every check produces a DecodeAuditEntry with limits and timestamp
