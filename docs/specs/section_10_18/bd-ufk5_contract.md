# bd-ufk5: VEF Performance Budget Gates for p95/p99 Hot Paths

**Section:** 10.18 — Verifiable Execution Fabric (Enhancement Map 9L)
**Track:** E — Frontier Industrialization (Production Readiness)
**Status:** Active

## Purpose

Define and enforce performance budgets for VEF (Verifiable Execution Fabric)
overhead in both control-plane and extension-host hot paths. VEF adds
cryptographic proof operations (receipt emission, chain hashing, checkpoint
computation, verification gate checks, mode transitions) to runtime hot paths.
This contract ensures that overhead stays within agreed p95/p99 latency limits
per VEF mode (normal, restricted, quarantine) and that regressions are caught
in CI with reproducible profiling evidence.

## Scope

### In scope

- Per-operation latency budgets (p95 and p99) for seven VEF operations.
- Per-mode budgets (normal, restricted, quarantine) reflecting degraded-mode tradeoffs.
- CI-executable gate that fails on budget breach.
- Baseline snapshot recording and regression detection.
- Noise tolerance to prevent false failures from measurement jitter.
- Structured audit events for every gate evaluation.

### Out of scope

- Live production profiling dashboards (observability layer responsibility).
- Flamegraph generation tooling (external profiler integration).
- VEF proof generation itself (separate implementation beads).

## VEF Operations

| Operation | Type | Description | Owner Module |
|-----------|------|-------------|--------------|
| `receipt_emission` | Micro | Emit a signed decision receipt | `vef_claim_integration` |
| `chain_append` | Micro | Append an entry to the evidence chain | `vef_claim_integration` |
| `checkpoint_computation` | Micro | Compute a checkpoint hash | `runtime/checkpoint` |
| `verification_gate_check` | Micro | Evaluate a verification gate (proof check) | `vef_claim_integration` |
| `mode_transition` | Micro | Transition between VEF modes | `vef_degraded_mode` |
| `control_plane_hot_path` | Integration | End-to-end control-plane path with VEF active | multiple |
| `extension_host_hot_path` | Integration | End-to-end extension-host path with VEF active | multiple |

## Budget Thresholds (microseconds)

### Normal Mode (tightest)

| Operation | p95 (us) | p99 (us) |
|-----------|----------|----------|
| `receipt_emission` | 50 | 100 |
| `chain_append` | 30 | 60 |
| `checkpoint_computation` | 100 | 200 |
| `verification_gate_check` | 40 | 80 |
| `mode_transition` | 20 | 50 |
| `control_plane_hot_path` | 500 | 1000 |
| `extension_host_hot_path` | 300 | 600 |

### Restricted Mode (1.5-2x normal)

| Operation | p95 (us) | p99 (us) |
|-----------|----------|----------|
| `receipt_emission` | 80 | 150 |
| `chain_append` | 50 | 100 |
| `checkpoint_computation` | 150 | 300 |
| `verification_gate_check` | 60 | 120 |
| `mode_transition` | 30 | 80 |
| `control_plane_hot_path` | 750 | 1500 |
| `extension_host_hot_path` | 450 | 900 |

### Quarantine Mode (2-2.5x normal)

| Operation | p95 (us) | p99 (us) |
|-----------|----------|----------|
| `receipt_emission` | 120 | 250 |
| `chain_append` | 80 | 160 |
| `checkpoint_computation` | 250 | 500 |
| `verification_gate_check` | 100 | 200 |
| `mode_transition` | 50 | 120 |
| `control_plane_hot_path` | 1200 | 2500 |
| `extension_host_hot_path` | 750 | 1500 |

## Configuration

- **noise_tolerance_cv_pct**: 15.0 — maximum coefficient of variation before measurement is flagged unstable.
- **min_samples**: 30 — minimum sample count for a measurement to be valid.
- **regression_threshold_pct**: 10.0 — percentage increase from baseline that triggers regression alert.

## Gate Semantics

1. Gate **fails** if any stable measurement exceeds its budget.
2. Unstable measurements (CV > tolerance) are **skipped**, not failed — they produce `VEF-PERF-005` events.
3. Insufficient-sample measurements are **skipped** with a reason.
4. Gate **passes** if there are zero failures (skips allowed).

## Invariants

| ID | Statement |
|----|-----------|
| INV-VEF-PBG-BUDGET | Every VEF operation has defined p95/p99 budgets per mode |
| INV-VEF-PBG-GATE | CI gate fails when any stable measurement exceeds its budget |
| INV-VEF-PBG-BASELINE | Committed baselines enable regression detection |
| INV-VEF-PBG-NOISE | Noise tolerance prevents false failures from jitter |
| INV-VEF-PBG-EVIDENCE | Budget breaches produce profiling evidence for triage |
| INV-VEF-PBG-MODE | Per-mode budgets enforce mode-appropriate limits |

## Event Codes

| Code | Description |
|------|-------------|
| `VEF-PERF-001` | Benchmark started for a VEF operation |
| `VEF-PERF-002` | Benchmark completed within budget |
| `VEF-PERF-003` | Budget exceeded — gate fails |
| `VEF-PERF-004` | Baseline measurement recorded |
| `VEF-PERF-005` | Noise tolerance applied (unstable measurement) |
| `VEF-PERF-006` | Mode budget scaling applied |
| `VEF-PERF-ERR-001` | Benchmark infrastructure failure |
| `VEF-PERF-ERR-002` | Mode transition error |

## Acceptance Criteria

1. Budget thresholds defined for all 7 operations x 3 modes = 21 budget pairs.
2. Normal-mode budgets are tightest; quarantine-mode budgets are most relaxed.
3. p99 budget >= p95 budget for every operation/mode pair.
4. Gate correctly passes when all measurements are within budget.
5. Gate correctly fails when any stable measurement exceeds budget.
6. Unstable measurements produce VEF-PERF-005 events but do not cause gate failure.
7. Insufficient-sample measurements are skipped with documented reason.
8. Baseline snapshots are serializable and support regression detection.
9. Regression detection correctly identifies regressions above threshold.
10. Gate evaluation is deterministic: identical inputs produce identical verdicts.

## Artifacts

- `crates/franken-node/src/tools/vef_perf_budget_gate.rs` — Rust implementation
- `crates/franken-node/src/tools/mod.rs` — module wiring
- `scripts/check_vef_perf_budget_gate.py` — verification script
- `tests/test_check_vef_perf_budget_gate.py` — Python unit tests
- `artifacts/section_10_18/bd-ufk5/verification_evidence.json` — CI evidence
- `artifacts/section_10_18/bd-ufk5/verification_summary.md` — human summary

## Dependencies

- None (measures overhead of assembled VEF pipeline).
- Depended on by: bd-2hjg (section gate), bd-32p (plan tracker).
