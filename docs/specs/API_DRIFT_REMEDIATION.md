# API-Drift Remediation Guide (verification-scaffolding integrity)

> Status: contract/spec for `bd-rjc2m` (gauntlet Round-0). This is the authoritative
> in-repo reference for recompiling the rotted verification targets against the current
> API. Origin: a release-readiness gauntlet found that fast API evolution was not
> propagated to the test/fuzz/SDK layer, silently dropping coverage.

## The problem (why this matters)

`cargo test` aborts the **entire** build if **any** `[[test]]` target fails to compile,
and the same is true for the fuzz crate. So a single drifted target silently removes a
whole slice of coverage with no signal. A Round-0 census found:

| Layer | Rotted / total | Census command |
|---|---|---|
| Conformance `[[test]]` | **23 / 264 (~9%)** | `cargo build -p frankenengine-node --tests --keep-going --features extended-surfaces,test-support` |
| Fuzz targets | **45 / 146 (~31%)** | `cargo build --manifest-path fuzz/Cargo.toml --bins --keep-going` |
| Verifier-SDK lib-tests | broken (60 errs) | `cargo test -p frankenengine-verifier-sdk` |

All from the same systemic drift. **None of this is a production-security defect** — the
production code is sound; the *tests that prove it* rotted.

## CONFIRMED old → new symbol map (apply mechanically across all targets)

| Old (in rotted tests) | New (current API) | Source |
|---|---|---|
| crate `franken_node::…` | `frankenengine_node::…` | crate was renamed |
| `RemoteOperation::Upload` | `RemoteOperation::ArtifactUpload` (`"artifact_upload"`) | `security/remote_cap.rs` |
| `CapabilityGate::check(...)` | `CapabilityGate::authorize_local_operation(...)` / `authorize_network(...)` | `security/remote_cap.rs` |
| `CapabilityProvider`/`CapabilityGate` construction (infallible) | now returns `Result` → add `?`/`.expect(...)` | (E0599 method-on-`Result`) |
| `RemoteCap.signature_b64` (field) | field removed — use current accessor | `security/remote_cap.rs` |
| `BudgetCheckResult.within_budget` (field) | `BudgetCheckResult.within_budget()` (method) | `tools/performance_hardening_metrics.rs:165` |
| `BudgetCheckResult.{measured_p95_us, measured_p99_us}` (fields) | methods (cf. `within_budget()`) | same |
| `PerformanceHardeningMetrics::new(...)` | `PerformanceHardeningMetrics::default()` | `tools/performance_hardening_metrics.rs:219` |
| `RailRouter.audit_events()` | `RailRouter.audit_log()` → `&[AuditEntry]` | `security/isolation_rail_router.rs:601` |
| `StateSnapshot { version, timestamp_rfc3339, state_data }` | restructured → `{ config_checksums, schema_version, policy_set, binary_version }` | `connector/rollback_bundle.rs:256` |

## RESOLVE (drift confirmed; map to current API by grepping the cited module)

`MeasuredLatency::new` · `ManifestComponent.{expected_hash,size_bytes}` + `.integrity_hash()`/`.canonical_bytes()` ·
`HealthCheckResult.{check_name,error_message,duration_ms}` · `ElevationPolicy::new` ·
`SignedExtensionRegistry::get_extension` (registry uses `get_*`) · `GuardrailMonitorSet::add_monitor` ·
governor `PredictedMetrics.{latency_p99_ms,cpu_util_pct}` + `OptimizationProposal.predicted_metrics` ·
SDK `SdkEvent.event_id`, `VerifierKeyPair`, `VerifierPublicKey` ·
`HardeningLevel::{Minimal,Maximal}` variants · E0753 inner-doc-comments (`//!` mid-file → `///`/move to top) ·
`TestCategory: Ord` / `fn()->TestResult: Deserialize` harness derives.

## Per-target procedure (MANDATORY discipline)

1. **Reserve the target file** (MCP Agent Mail) — concurrent agents touch this surface.
2. Get the target's FULL error set: `cargo build -p frankenengine-node --tests --test <target>`
   (the crate-rename is a module-resolution error that *masks* the rest — fix it first, recompile).
3. Apply the CONFIRMED map; for RESOLVE rows, grep the cited production module for the current symbol.
4. **PRESERVE every assertion.** Do **not** delete or weaken a MUST/SHOULD check to force a compile.
   If a contract genuinely changed (e.g. anti-entropy reconcile went fail-fast → fail-graceful,
   `bd_3h7k` MUST-AER-005/006), update the assertion **and** reconcile the spec — never drop the test.
   No loss of coverage, features, or invariants vs the pre-drift intent.
5. Target must **compile AND run green** (`cargo test --test <target>`), not merely compile.
6. Log the result through the shared remediation logging schema (below).
7. Close the bead per `br` close-reason discipline (commit SHA + the now-passing test name).

## Shared remediation logging schema (one JSONL record per verification target)

```json
{
  "ts_rfc3339": "2026-05-30T12:00:00Z",
  "target": "vef_perf_budget_gate_conformance",
  "layer": "conformance",            // conformance | fuzz | sdk
  "errors_before": 37,
  "errors_after": 0,
  "compiles": true,
  "ran": true,
  "tests_run": 14,
  "tests_passed": 14,
  "assertions_preserved": true,
  "duration_ms": 8421,
  "notes": "within_budget field->method(); MeasuredLatency::new->record()"
}
```

The `verify_all_verification_targets.sh` e2e script (bead `.E2E1`) emits these to
`artifacts/verification/verify_run_<ts>.jsonl` plus a human summary; the recurrence-prevention
gate (`.G1`) emits the same shape for the compile census.

## CRITICAL: distinguish RENAME drift from REDESIGN drift

Not all rotted targets are mechanical renames. Two classes — handle differently:

- **RENAME drift** (mechanical): a symbol moved/renamed but the *contract is unchanged*
  (e.g. `RemoteOperation::Upload`→`ArtifactUpload`, `within_budget` field→method). Apply the
  map; the assertion's meaning is preserved automatically.
- **REDESIGN drift** (semantic): the *shape/contract changed*, so there is **no 1:1 mapping** and
  some assertions have no mechanical equivalent. These require **per-assertion intent-mapping and a
  spec decision** — and carry real coverage-loss risk if rushed. **Do NOT delete the assertion to
  compile.** Either map it to the new contract's equivalent property, or (if the new API genuinely
  dropped a property the MUST relied on) escalate: is that a production gap or an outdated contract?

### Worked example — `vef_perf_budget_gate_conformance` is a REDESIGN
Current production (`crates/franken-node/src/tools/vef_perf_budget_gate.rs`):
- `MeasuredLatency::new(p95, p99, sample_count)` (3-arg ctor) is **gone**; `MeasuredLatency` is now a
  struct literal: `{ operation: VefOperation, mode: BudgetMode, p50_us, p95_us, p99_us, max_us,
  sample_count, coefficient_of_variation_pct }`. Remediation must build the literal (pick p50<p95,
  max≥p99, and a cv that matches the test's intent — several cases test stability via cv/sample_count).
- `BudgetCheckResult.within_budget` → `.passed` (+ new `p95_within_budget`/`p99_within_budget`/`*_headroom_pct`).
- `BudgetCheckResult.measured_p95_us`/`.measured_p99_us` (the test asserts these are `Some`) **do not
  exist** in the new struct. **No mechanical equivalent.** SPEC DECISION required: should the gate
  result echo measured percentiles (production gap → add fields), or is that assertion obsolete (→
  replace with an equivalent property such as `p95_headroom_pct.is_finite()` AND reconcile the spec)?
  Resolve WITH the spec owner; record the decision; never silently drop the MUST.

REDESIGN targets (more than the crate-rename) must be triaged this way during remediation.

## Recurrence prevention

Once remediated, the `.G1` CI gate runs the two census commands above on every relevant change
and **fails on any non-compiling target** — so this class of silent coverage loss cannot recur.
