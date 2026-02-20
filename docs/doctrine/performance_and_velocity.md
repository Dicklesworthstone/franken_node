# Performance and Developer Velocity Doctrine

**Bead:** bd-2vl5 | **Section:** 7

## 7.1 Core Principles

Performance is a product feature, not a benchmark vanity metric. Every
performance decision in franken_node is governed by four core principles:

### PRF-01: Low Startup Overhead

**Target:** Cold-start < 100ms for migration and CI loops.

Migration and CI workflows run frequently and are latency-sensitive. A slow
cold-start creates friction that drives developers away from the trust-native
workflow. Cold-start includes: process init, config load, trust state hydration,
and first-operation readiness.

**Measurement:** Time from process spawn to first-operation readiness, measured
across 100 samples with p50/p95/p99 breakdown.

**CI gate:** Cold-start benchmark in CI with 100ms p99 threshold.

### PRF-02: Predictable p99 Under Extension Churn

**Target:** p99 latency remains within per-subsystem budget under realistic
extension churn patterns.

Extensions are added, removed, and updated frequently during development. The
runtime must maintain predictable tail latency even when the extension set is
changing. Spikes during churn are acceptable only if they remain within the
defined budget.

**Measurement:** p99 latency under synthetic churn workload (100 extension
add/remove cycles), compared to static baseline.

**CI gate:** Churn benchmark with per-subsystem p99 budgets.

### PRF-03: Bounded Security Instrumentation Overhead

**Target:** Security instrumentation adds < 5% overhead to hot-path operations.

Trust-native security features (provenance checks, policy evaluation, audit
logging) must not make the runtime unacceptably slower. The 5% budget is measured
against uninstrumented baseline for each hot path.

**Measurement:** Hot-path latency with security instrumentation enabled vs.
disabled, measured as percentage overhead.

**CI gate:** Instrumentation overhead benchmark with 5% threshold.

### PRF-04: Fast Migration Feedback

**Target:** Compatibility diff generation < 500ms for typical workloads.

Developers need rapid feedback when evaluating migration compatibility. Slow
compatibility analysis creates friction and discourages incremental migration.

**Measurement:** Time to generate compatibility diff for representative workload
sizes (10, 100, 1000 modules).

**CI gate:** Diff generation benchmark with 500ms p99 threshold.

## 7.2 Candidate High-EV Optimization Levers

These optimization candidates must pass the MS-01 (extreme-software-optimization)
loop before adoption. Each lever requires baseline, profile, prove, implement,
verify, re-profile evidence.

### LEV-01: Compatibility Cache with Deterministic Invalidation

Cache compatibility analysis results with content-hash-based invalidation.
Avoids re-analyzing unchanged modules on subsequent runs.

**Expected impact:** 5-10x speedup for incremental compatibility checks.
**Risk:** Cache coherence bugs could produce incorrect compatibility results.
**Owner track:** 10.6

### LEV-02: Lockstep Differential Harness Acceleration

Optimize the lockstep oracle harness that compares Node/Bun behavior against
franken_node output. Use structural diffing instead of full serialization.

**Expected impact:** 2-5x faster conformance comparison.
**Risk:** Structural diff could miss subtle serialization differences.
**Owner track:** 10.6

### LEV-03: Zero-Copy Hostcall Bridge Paths

Where safety permits, use zero-copy semantics for hostcall arguments and
return values between the JS engine and Rust runtime.

**Expected impact:** 3-8x latency reduction for high-frequency hostcalls.
**Risk:** Memory safety requires careful lifetime management.
**Owner track:** 10.6

### LEV-04: Batch Policy Evaluation

Evaluate multiple policy decisions in a single pass rather than one-at-a-time.
Amortizes policy engine overhead across operations.

**Expected impact:** 2-4x throughput improvement for policy-heavy workloads.
**Risk:** Batch semantics may differ from sequential for state-dependent policies.
**Owner track:** 10.5

### LEV-05: Multi-Lane Scheduler Tuning

Tune the asupersync scheduler for franken_node's specific workload mix of
cancel, timed, and ready operations.

**Expected impact:** 1.5-3x throughput improvement under mixed workloads.
**Risk:** Tuning may not generalize across deployment profiles.
**Owner track:** 10.15

## 7.3 Required Performance Artifacts

Every performance-affecting change MUST produce the following artifacts:

### ART-01: Baseline Reports

Reproducible baseline measurements with:
- Hardware/environment specification
- Exact command to reproduce
- p50/p95/p99 latency, throughput, memory footprint
- Timestamp and git commit hash

### ART-02: Profile Artifacts

Profiling evidence showing where time is spent:
- Flamegraph (SVG or folded stacks)
- Top-10 hotspots with percentage breakdown
- Allocation profile if memory-relevant

### ART-03: Before/After Comparison Tables

Side-by-side comparison of key metrics:
- p50/p95/p99 latency
- Throughput (ops/sec)
- Memory usage (peak RSS)
- Cold-start time
- Improvement percentage

### ART-04: Compatibility Correctness Proofs

For tuned paths, evidence that optimization preserves correctness:
- Conformance test results before and after
- Lockstep oracle comparison showing identical output
- Edge case coverage for the optimized path

### ART-05: Tail-Latency Impact Notes

For security instrumentation changes:
- p99 impact measurement
- Overhead percentage relative to uninstrumented baseline
- Justification if overhead exceeds 5% budget

## 7.4 Implementation Mapping

| Subsystem | Owner Track | Performance Concern |
|-----------|-------------|-------------------|
| Cold-start and p99 gates | 10.6 | PRF-01, PRF-02 |
| Lockstep harness optimization | 10.6 | LEV-02 |
| Migration scanner throughput | 10.6 | PRF-04 |
| Security instrumentation overhead | 10.18 (VEF) | PRF-03 |
| Scheduler tuning | 10.15 (Asupersync) | LEV-05 |

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| PRF-001 | info | Performance doctrine compliance verified |
| PRF-002 | error | Missing required performance artifact |
| PRF-003 | info | Optimization lever profiled with before/after evidence |
| PRF-004 | error | p99 budget exceeded for subsystem |
| PRF-005 | info | Cold-start budget met |

## Invariants

| ID | Statement |
|----|-----------|
| INV-PRF-PRINCIPLES | All 4 core principles have measurable metrics and CI gates |
| INV-PRF-ARTIFACTS | Performance-affecting PRs include all 5 required artifact types |
| INV-PRF-PROFILED | Every optimization lever has before/after evidence |
| INV-PRF-COMPAT | Tuned paths have compatibility correctness proofs |
