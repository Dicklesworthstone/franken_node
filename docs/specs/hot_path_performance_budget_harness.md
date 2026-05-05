# Hot-Path Performance Budget Harness

This contract defines the deterministic smoke harness for `bd-ncwlf`.

The harness lives in `policy::perf_budget_guard` because it reuses the existing
budget policy, timing measurement, and gate-report structures instead of
creating a second performance schema. It is intentionally a CI smoke contract,
not an authoritative wall-clock benchmark. It records deterministic work-unit
budgets for hot paths where the relevant regression shape is lock acquisition,
full-vector clone work, eager formatting, or serialized persistence work.

## Evidence

Canonical machine-readable evidence:

```text
artifacts/performance_budgets/bd-ncwlf_hot_path_budget_evidence.json
```

Schema:

```text
franken-node/hot-path-budget-smoke/v1
```

The evidence includes:

- `cases`: every smoke case, its source bead, owning source file, metric kind,
  before-fix and post-fix work-unit budgets, correctness assertions, and skip
  policy.
- `gate_result`: the existing `PerformanceBudgetGuard` result over those cases.
- `rch_command`: the exact remote test command expected for CI or closeout.
- `skip_blocker`: explicit reason when the environment cannot run the smoke
  proof. A skipped report is not a passing report.

## Default Cases

| Hot path | Source bead | Metric |
| --- | --- | --- |
| `ops.telemetry_bridge.persistence_batch` | `bd-2ruyf` | Adapter lock acquisitions per ready batch |
| `control_plane.fleet_transport.read_snapshot` | `bd-42obl` | Exclusive lock and clone work per read |
| `observability.evidence_ledger.len_snapshot` | `bd-1689l`, `bd-2ahez` | Ledger clone and diagnostic serialization work |
| `storage.frankensqlite_adapter.write_event` | `bd-1ulnv` | Eager string allocation work per write |

Each case must keep at least three correctness assertions next to the metric so
future optimization changes do not pass by removing trust, ordering, audit, or
persistence behavior.

## CI Smoke Command

Run the contract through RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly-2026-02-19 test -p frankenengine-node --no-default-features --features policy-engine,http-client,external-commands --test hot_path_perf_budget_contract hot_path_budget -- --nocapture
```

The smoke proof is deterministic and does not depend on local timing noise.
It catches order-of-magnitude regressions by failing when post-fix work units
exceed the configured overhead budget relative to the before-fix baseline.

## Adding a Case

1. Add a `HotPathBudgetSmokeCase` in
   `default_hot_path_budget_smoke_cases()`.
2. Use a stable `hot_path` label in `domain.module.operation` form.
3. Record the source bead and owning source file.
4. Use `deterministic_work_units` unless the metric has a different bounded
   unit that is independent of wall-clock noise.
5. Pair the budget with correctness assertions that would fail if an
   optimization weakened evidence, trust, ordering, audit, or persistence
   semantics.
6. Refresh the committed JSON evidence and extend
   `hot_path_perf_budget_contract` if the new case introduces a new skip or
   regression mode.

If RCH workers are unavailable, emit a report with `verdict = "SKIP"` and a
non-empty `skip_blocker`. Do not mark a skipped report as passing.
