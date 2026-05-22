# Baseline — round 2 — 2026-05-20 — git aa3b1c9a

## Headline numbers

### `evidence_ledger_performance/entry_with_server_computed_size`

| Metric                     | Value         |
|----------------------------|--------------:|
| p95 wall-time              | **16.62 µs**  |
| mean                       | 16.21 µs      |
| 95 % CI low                | 15.76 µs      |
| samples                    | 100           |
| total runtime (heaptrack)  | 17.82 s       |
| allocs / 146 k iterations  | 1 158 614     |
| allocs / second            | 65 017        |
| peak heap                  | 7.06 MiB      |
| % allocs from criterion bootstrap (scaffolding) | 87 % |

**Interpretation:** Append path is **fast** (16 µs / entry, well under the
100 µs scenario budget). The 1.16 M allocations are dominated by Criterion's
bootstrap resampling (`criterion::stats::univariate::bootstrap` callsite =
1 005 881 alloc calls / 1 158 614 total). The actual evidence_ledger code
emits ~150 k allocations across 146 k iterations — that's ~1 allocation per
append, consistent with one short-lived payload buffer.

**`json_string_size` flat profile share:** 0.81 % — the only visible
evidence_ledger symbol above 0.3 %. The append path is **not** an alloc
hotspot.

### `dgis_contagion_simulator` (integration test, 200x loop under perf)

| Metric                     | Value         |
|----------------------------|--------------:|
| per-test wall              | ≈ 10 ms       |
| samples collected          | 171 498       |
| allocs / test              | ≈ 5 162       |
| temporary allocs ratio     | 42 %          |
| peak heap (single test)    | 937 KiB       |

**Top flat profile (post-criterion-exclusion, see hotspot_table.md):**

| % cycles | symbol |
|---------:|--------|
| 14.85 % | `ContagionGraph::generate_deterministic` |
| 14.10 % | `__memcmp_avx2_movbe` (BTreeMap String NodeId comparisons) |
| 5.07 %  | `ContagionGraph::validate` |
| 4.10 %  | `validate_node_id` |
| 3.98 %  | `ContagionGraph::add_edge` |
| 3.84 %  | `BTreeMap<String, Vec<ContagionEdge>>::insert` |
| 2.95 %  | `memset_orig` |
| 1.42 %  | `ContagionGraph::add_node` |
| 0.70 %  | `push_bounded::<ContagionEdge>` |
| **0.45 %** | **`contagion_simulator::step`** |
| 0.43 %  | `format_inner` |

**Interpretation:** The round-1 deferred hypothesis "contagion_simulator::step
is hot because of per-tick build_in_edges rebuild + BTreeSet clone" is
**rejected**. step() accounts for only 0.45 % of cycles on this 200x
workload. The actual hotspot is **graph construction** (~30 %) plus
**String NodeId memcmp** (~17 %) in BTreeMap operations. If production
DGIS workloads do many short-lived graphs (one per profile evaluation),
graph construction dominates; if production runs few large graphs for
many steps, that profile would show different costs — measure before
optimising.

### `proof_generator_timeout_race` (integration test, 1000x loop under perf)

| Metric                     | Value         |
|----------------------------|--------------:|
| per-test wall              | ≈ 0 ms        |
| user-code symbols ≥ 0.3 %  | **0**         |
| top symbol                 | `memset_orig` (10.50 %) — kernel page-table init |
| allocs / single test       | 926           |

**Interpretation:** Measurement gap. This test exercises proof_generator
internals but completes in ≤ 1 ms; under a 1000-loop perf run, fork/exec
and page-table-init dominate. **No round-2 conclusion about vef hot
paths**; deferred to round 3 (needs a Criterion bench or a long-running
test).

### `fleet_transport::canonical_fleet_convergence_receipt_payload`

Not built / measured directly (no Criterion bench, refused to author one
to honour the no-file-proliferation rule). **Source confirmation only:**

```rust
fn canonicalize_json_value(value: Value, path: &str) -> Result<Value, FleetTransportError> {
    match value {
        Value::Array(items) => items
            .into_iter()                                           // consuming, no clone
            .enumerate()
            .map(|(index, item)| canonicalize_json_value(item, &format!("{path}[{index}]")))  // path alloc per element
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>(); // consuming, no clone
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = serde_json::Map::new();
            for (key, item) in entries {
                canonical.insert(
                    key.clone(),
                    canonicalize_json_value(item, &format!("{path}.{key}"))?, // path alloc per key
                );
            }
            ...
```
(`crates/franken-node/src/control_plane/fleet_transport.rs:154-180`)

**Difference from trust_card hotspot:**
- ❌ No deep clone of subtrees — `items.into_iter()` consumes, doesn't clone.
- ⚠ Two `format!()` per recursion level, building a `path` string used only in the unhappy-path float error message at L176. Wasted work on the happy path, but O(1) per Value visited.
- ⚠ `key.clone()` per object entry (cheap String clone).
- ⚠ No `Map::with_capacity(entries.len())` pre-allocation.

**Verdict:** This is a small-constant-factor allocation hygiene issue
(format! for unused path strings, missing capacity hint), **not** the
Θ(W^N × N) deep-clone cliff that dominated `trust_card_canonical`. The
round-1 hypothesis that fleet_transport "has the same structural
pattern as trust_card" is **partially rejected** — the symptoms look
similar but the root cause is different.

## Variance snapshot

Single Criterion outlier band on evidence_ledger (16.62 µs high CI vs 15.76 µs
low CI = ±2.7 % around the mean). Within envelope.

## Memory baseline

| Bench                              | Allocs   | Peak heap | Heaptrack runtime |
|------------------------------------|---------:|----------:|------------------:|
| evidence_ledger_performance        | 1 158 614| 7.06 MiB  | 17.82 s           |
| dgis_contagion_simulator (1 run)   |    61 939| 937 KiB   | 0.50 s            |
| proof_generator_timeout_race (1 run)|     926 |   negligible | 0.03 s         |

## What's in this directory

```
20260520T231041Z_franken_node_perf_r2/
├── DEFINE.md
├── BASELINE.md
├── fingerprint.json
├── criterion_raw/
│   └── evidence_ledger.txt
└── profiles/
    ├── evidence_ledger.perf.data
    ├── evidence_ledger.perf.flat.txt
    ├── evidence_ledger.heaptrack.zst
    ├── evidence_ledger.heaptrack.report.txt
    ├── dgis_contagion.perf.data
    ├── dgis_contagion.perf.flat.txt
    ├── dgis_contagion.heaptrack.zst
    ├── dgis_contagion.heaptrack.report.txt
    ├── proof_generator.perf.data
    ├── proof_generator.perf.flat.txt
    ├── proof_generator.heaptrack.zst
    └── proof_generator.heaptrack.report.txt
```
