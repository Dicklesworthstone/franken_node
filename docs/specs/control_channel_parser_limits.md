# Control Channel Parser Limits Specification

This file preserves the plan-level artifact path for bd-3tzl and points to the
canonical Section 10.13 implementation contract.

## Canonical Contract

- Spec: `docs/specs/section_10_13/bd-3tzl_contract.md`
- Implementation: `crates/franken-node/src/connector/frame_parser.rs`
- Integration tests: `tests/integration/frame_decode_guardrails.rs`
- Verification gate: `scripts/check_frame_parser.py`
- Evidence: `artifacts/section_10_13/bd-3tzl/verification_evidence.json`

## Required Invariants

- **INV-BPG-SIZE-BOUNDED**: Oversized frames are rejected before parsing.
- **INV-BPG-DEPTH-BOUNDED**: Decoded structure depth stays within the configured
  maximum.
- **INV-BPG-CPU-BOUNDED**: Decode work is accounted per frame and aborted when
  it exceeds the configured CPU budget.
- **INV-BPG-AUDITABLE**: Every decode attempt emits a structured resource
  accounting record.

The registered Rust coverage lives under `tests/integration/` because it
exercises the real frame parser API and its guardrail verdicts rather than a
standalone security-only harness.
