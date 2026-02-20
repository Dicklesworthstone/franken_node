# bd-27o2: Profile Tuning Harness with Signed Policy Updates

## Scope

Reproducible harness that recomputes candidate policy updates from
benchmark data, signs them for provenance, and rejects any update
that would regress safety-critical performance thresholds.

## Harness Workflow

1. **Load baseline** — read current policy from `object_class_policy_report.csv`
2. **Run benchmarks** — execute benchmark suite (or consume synthetic results)
3. **Compute candidates** — derive new tuning parameters from benchmark data
4. **Delta analysis** — compare candidate vs. baseline per class
5. **Regression check** — reject if any p99 latency degrades > threshold (default 20%)
6. **Sign bundle** — produce HMAC-SHA256 signed artifact with provenance
7. **Verify** — read-back and validate signature integrity

## Signed Bundle Format

```json
{
  "version": 1,
  "timestamp": "ISO-8601",
  "run_id": "unique-id",
  "hardware_fingerprint": "sha256-of-hw-info",
  "previous_bundle_hash": "sha256|null",
  "candidates": [...],
  "deltas": [...],
  "signature": "hmac-sha256-hex",
  "regression_threshold_pct": 20.0
}
```

## Signing Specification

- **Algorithm**: HMAC-SHA256
- **Key management**: Key provided at harness initialization; not stored in bundle
- **Signed payload**: JSON-serialized candidates + provenance fields (excluding signature field)
- **Provenance chain**: Each bundle includes `previous_bundle_hash` referencing
  the SHA-256 of the prior signed bundle (null for first bundle)
- **Rollback**: Re-run harness with prior benchmark data; new bundle supersedes

## Regression Rejection

If any candidate update would increase p99 encode or decode latency
by more than `regression_threshold_pct` (default 20%), the harness:
- Rejects the entire update
- Emits `PT_REGRESSION_REJECTED` event with diagnostic details
- Does NOT produce a signed bundle

## Idempotency

Same benchmark data + same baseline + same key = identical signed bundle.
Achieved by: deterministic candidate computation, fixed timestamp in
reproducible mode, no randomness in signing.

## Event Codes

| Code | Trigger |
|------|---------|
| PT_HARNESS_START | Harness invocation begins |
| PT_BENCHMARK_COMPLETE | Benchmark phase done |
| PT_CANDIDATE_COMPUTED | Delta analysis complete |
| PT_REGRESSION_REJECTED | Unsafe update blocked |
| PT_BUNDLE_SIGNED | Signed artifact produced |
| PT_BUNDLE_VERIFIED | Read-back integrity confirmed |

## Invariants

| ID | Statement |
|----|-----------|
| INV-PT-IDEMPOTENT | Same inputs always produce identical output |
| INV-PT-SIGNED | Every accepted bundle carries a valid HMAC signature |
| INV-PT-REGRESSION-SAFE | No bundle is produced if p99 regresses beyond threshold |
| INV-PT-CHAIN | Each bundle references the previous bundle's hash |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/tools/profile_tuning_harness.rs` |
| Spec contract | `docs/specs/section_10_14/bd-27o2_contract.md` |
| Signed bundle | `artifacts/10.14/signed_policy_update_bundle.json` |
| Verification script | `scripts/check_profile_tuning_harness.py` |
| Python unit tests | `tests/test_check_profile_tuning_harness.py` |
| Verification evidence | `artifacts/section_10_14/bd-27o2/verification_evidence.json` |
| Verification summary | `artifacts/section_10_14/bd-27o2/verification_summary.md` |
