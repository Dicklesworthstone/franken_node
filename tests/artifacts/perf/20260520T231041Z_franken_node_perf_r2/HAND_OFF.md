# Hand-off — round 2 — `extreme-software-optimization`

> Profile complete: round 2 of `franken_node` — run-id `20260520T231041Z_franken_node_perf_r2`

## What round 2 settled

Two **rejections** (remove from queue):
- `observability::evidence_ledger::append` — 16.62 µs at full large-payload; not a hotspot at current scale.
- `dgis::contagion_simulator::step()` — 0.45 % cycles on integration-test workload; the round-1 static-read hypothesis about per-tick `build_in_edges` + `BTreeSet::clone` was incorrect at the workloads available.

Two **new findings** (add to queue):
- **R2-A: DGIS String NodeId BTreeMap operations** — ~17 % of contagion-test cycles in `__memcmp_avx2_movbe + BTreeMap<String, ...>` work. Interning NodeId to integer with a side `Vec<&str>` table would erase the band. Confidence: 4 (production graph-traversal frequency is unmeasured; the absolute % is from a CI-style workload).
- **R2-7 (reframed from round 1 deferred): fleet_transport canonicalize_json_value `format!()` of `path`** — small constant-factor allocation hygiene issue, not the Θ(W^N × N) deep-clone cliff that dominated trust_card. Demote priority.

One **measurement gap remains** for round 3:
- `vef::proof_generator::compute_proof_bytes` + `vef::receipt_chain::verify_integrity` — the available test binary exits in 0 ms; perf samples fork/exec overhead instead of user code. A 10-line Criterion bench mirroring `crypto_scheme_bench` would close this gap.

## Unified ranking across both rounds

See `tests/artifacts/perf/HISTORY.md`. Head of queue:

1. trust_card recursive `Value::clone()` (round 1)
2. Ed25519Scheme key cache (round 1)
3. threshold_sig preparsed keys (round 1)
4. cuckoo insert cliff (round 1)
5. **DGIS String NodeId interning (round 2, new)**
6. replay_bundle_event_size streaming (round 1)
7. fleet_transport `path` format!() (round 2, reframed/demoted)

## Suggested scoring for `extreme-software-optimization`

| Item | Impact | Confidence | Effort | Score | Notes |
|------|-------:|-----------:|-------:|------:|------|
| threshold_sig preparsed | 3 | 5 | 1 | **15.0** | unchanged from round 1 |
| Ed25519Scheme key cache | 5 | 5 | 2 | **12.5** | unchanged from round 1 |
| cuckoo insert policy decision | 2 | 5 | 1 | 10.0 | unchanged from round 1 |
| trust_card deep-clone restructure | 5 | 5 | 4 | 6.3 | unchanged from round 1 |
| replay_bundle_event_size → streaming_counter | 1 | 5 | 1 | 5.0 | unchanged from round 1 |
| **DGIS NodeId → u32 interning** | 3 | 4 | 3 | **4.0** | new; cleanly contained |
| fleet_transport `path` defer-to-error | 1 | 5 | 1 | 5.0 | demoted from round-1 deferred |

## Golden / equivalence preservation requirements

Same as round 1, plus:

- **DGIS NodeId interning** must preserve `ContagionGraph` external API
  (`graph.nodes()` returns user-facing NodeIds). The interning is a
  internal representation change; canonical hashes over contagion
  trace exports must not shift. Verified by:
  - Existing `tests/security/dgis_contagion_simulator.rs` integration
    tests must continue to pass (campaign verdicts unchanged).
  - Existing tests/integration/dgis_atc_interop.rs and dgis_migration_gate.rs
    must continue to pass.
- **fleet_transport canonicalize_json_value `path` change** must preserve
  the float-error message format. The current shape is "fleet
  convergence receipt contains non-deterministic float at {path}";
  changing how `path` is built must produce the same string at error
  time. Verified by:
  - The inline `#[test]` `fleet_convergence_receipt_payload_hash_domain_separation`
    in `fleet_transport.rs:3383` must continue to produce the same canonical bytes.

## Cargo.toml registrations made this round

(For the next maintainer: these may have been reverted again by
concurrent agents. Re-add if needed.)

```toml
# workspace Cargo.toml:
[profile.release-perf]
inherits = "release"
opt-level = 3
lto = "thin"
codegen-units = 1
debug = "line-tables-only"
strip = false

# crates/franken-node/Cargo.toml:
[[bench]]
name = "evidence_ledger_performance"
harness = false
```

## Re-baseline command for any of the round-2 scenarios

```bash
# Ensure release-perf profile is present (re-add if reverted).
RUSTFLAGS="-C force-frame-pointers=yes" \
    rch exec -- cargo build --profile release-perf -p frankenengine-node \
    --bench evidence_ledger_performance

./target/release-perf/deps/evidence_ledger_performance-<hash> --bench
```

For the dgis profile (test binary, not bench):

```bash
RUSTFLAGS="-C force-frame-pointers=yes" \
    rch exec -- cargo test --profile release-perf -p frankenengine-node \
    --test dgis_contagion_simulator --no-run

perf record -F 999 --call-graph dwarf \
    -- bash -c 'for i in $(seq 200); do ./target/release-perf/deps/dgis_contagion_simulator-<hash> >/dev/null; done'
perf report -g none --no-children --stdio --percent-limit 0.3 --sort overhead,symbol
```

## Summary statement (verbatim for the user)

```
Round-2 profile complete: franken_node workspace — run-id 20260520T231041Z_franken_node_perf_r2.

Rejected (remove from optimization queue):
  - observability::evidence_ledger::append (16.62 µs / large entry; not a hotspot at current scale)
  - dgis::contagion_simulator::step (0.45 % of cycles on the integration-test workload)

New hotspot:
  - DGIS contagion_graph String NodeId BTreeMap operations ~17 % cycles
    (interning NodeId to u32 with a side Vec<&str> erases this band)

Reframed:
  - fleet_transport::canonicalize_json_value is NOT the trust_card deep-clone pattern;
    just two `format!()` per Value building a `path` string used only on error.

Measurement gap:
  - vef::proof_generator + receipt_chain — needs a 10-line Criterion bench.
    The proof_generator_timeout_race test finishes in 0 ms; not a viable profile target.

Unified ranking and per-scenario history live in
  tests/artifacts/perf/HISTORY.md
Round-2 artifacts under
  tests/artifacts/perf/20260520T231041Z_franken_node_perf_r2/
```
