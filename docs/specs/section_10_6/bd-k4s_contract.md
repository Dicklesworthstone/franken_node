# bd-k4s: Product-Level Benchmark Suite with Secure-Extension Scenarios

## Bead: bd-k4s | Section: 10.6

## Purpose

Build a comprehensive product-level benchmark suite that validates franken_node
performance under realistic security-hardened conditions. The suite covers all
major workflow categories with secure-extension scenarios active, producing
machine-readable results with confidence intervals for CI/release gating and
public reporting.

## Benchmark Dimensions

| Dimension | Description |
|-----------|-------------|
| Cold-start latency | Time from process launch to first request serviced |
| p99 tail latency | 99th percentile request latency under sustained load |
| Extension-host overhead | Overhead ratio with sandbox enforcement active vs disabled |
| Migration scanner throughput | Fixtures processed per second by the migration scanner |
| Lockstep harness throughput | Comparative fixture throughput across Node/Bun/franken_node |
| Quarantine propagation latency | Time from policy violation to fleet-wide containment |
| Trust-card materialization latency | Time to materialize a trust card from registry data |

## Scenario Categories

| Category | Scenarios | Section 14 Family |
|----------|-----------|-------------------|
| Correctness | Compatibility pass rate by API family and risk band | compatibility_correctness |
| Performance | p50/p95/p99 latency, throughput, cold start, memory overhead | performance_under_hardening |
| Containment | Detection-to-containment latency, revocation propagation | containment_latency |
| Replay | Bit-identical replay percentage across runtime versions | replay_determinism |
| Adversarial | Pass rate against malicious extension test suite | adversarial_resilience |
| Migration | Time and success rate for representative project migration | migration_speed |

## Event Codes

| Code | Trigger |
|------|---------|
| BS-001 | Benchmark suite initialized with scenario configuration. |
| BS-002 | Individual benchmark scenario started. |
| BS-003 | Benchmark measurement recorded with raw value and confidence interval. |
| BS-004 | Scoring formula applied; normalized score computed. |
| BS-005 | Regression detected; metric degraded beyond threshold. |
| BS-006 | Benchmark suite completed; aggregate report emitted. |
| BS-007 | Deterministic check passed; variance within 5% threshold. |
| BS-008 | Individual benchmark scenario completed with sample count, warmup count, score, and variance. |
| BS-009 | Individual benchmark scenario failed before producing authoritative evidence. |
| BS-010 | Fixture-only deterministic measurement mode used; result is quarantined from release evidence. |

## Invariants

| ID | Statement |
|----|-----------|
| INV-BS-DETERMINISTIC | Identical inputs produce statistically equivalent results (variance < 5% across runs on identical hardware). |
| INV-BS-SECURE | All benchmarks run with sandbox enforcement active, measuring realistic overhead. |
| INV-BS-CONFIDENCE | Every measurement includes confidence intervals and reproducibility metadata. |
| INV-BS-SCORING | Scoring formulas are versioned and published alongside results. |
| INV-BS-MACHINE-READABLE | Results export as structured JSON with full provenance metadata. |
| INV-BS-COVERAGE | All six Section 14 benchmark dimensions are represented. |

## Quantitative Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Cold-start latency | < 500ms for balanced profile | Wall-clock from launch to ready |
| p99 latency | < 10ms for standard request path | Histogram percentile computation |
| Extension overhead ratio | < 1.5x vs unsandboxed | Ratio of sandboxed to unsandboxed throughput |
| Variance across runs | < 5% | Coefficient of variation over N=5 runs |
| Scenario coverage | 6 of 6 dimensions | Dimension count in report |
| Scoring formula version | Pinned per report | Formula hash in result metadata |

## Scoring Formulas

Each dimension uses a normalized 0-100 score:

```
score = clamp(100 * (1 - (measured - ideal) / (threshold - ideal)), 0, 100)
```

Where:
- `ideal`: best achievable value for the metric
- `threshold`: unacceptable value (score = 0)
- `measured`: actual measurement

Formula version is embedded in every result for attribution.

## Result Schema

```json
{
  "suite_version": "1.0.0",
  "scoring_formula_version": "sf-v1",
  "timestamp_utc": "2026-02-21T00:00:00Z",
  "hardware_profile": { "cpu": "...", "memory_mb": 0, "os": "..." },
  "runtime_versions": { "franken_node": "...", "node": "...", "bun": "..." },
  "scenarios": [
    {
      "dimension": "performance_under_hardening",
      "name": "cold_start_latency",
      "raw_value": 0.0,
      "unit": "ms",
      "confidence_interval": [0.0, 0.0],
      "score": 0,
      "iterations": 0,
      "variance_pct": 0.0
    }
  ],
  "aggregate_score": 0,
  "provenance_hash": "sha256:..."
}
```

## Dependencies

- Compatibility matrix from 10.2 for correctness benchmarks
- Execution normalization contract (10.N) for deterministic scenario execution
- Migration pipeline (10.3) for migration speed benchmarks
- Security + policy surfaces (10.5) for secure-extension scenario configuration

## Testing & Logging Requirements

- Unit tests for scoring formula calculations and threshold evaluation.
- Unit tests for result serialization/deserialization roundtrip.
- Unit tests for deterministic fixture selection logic.
- Regression detection: automatic flagging when metrics degrade beyond threshold.
- Structured logs: BS-001 through BS-010 with trace IDs, scenario IDs, profile, and evidence path when file-backed output is produced.

## Expected Artifacts

- `crates/franken-node/src/tools/benchmark_suite.rs` — Rust benchmark harness
- `docs/specs/section_10_6/bd-k4s_contract.md` — this specification
- `docs/policy/benchmark_suite.md` — benchmark policy document
- `scripts/check_benchmark_suite.py` — verification script
- `tests/test_check_benchmark_suite.py` — unit tests
- `artifacts/section_10_6/bd-k4s/verification_evidence.json` — CI evidence
- `artifacts/section_10_6/bd-k4s/verification_summary.md` — human summary
