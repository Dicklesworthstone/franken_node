# DEFINE — round 2 (deferred coverage)

Run-id: `20260520T231041Z_franken_node_perf_r2`
Iteration-of: `20260520T214003Z_franken_node_perf` (round 1)
Requestor: Jeffrey Emanuel — "ok do round 2"

Round 1's hand-off explicitly named four deferred items. This round
profiles them.

## Scenarios this round

| # | Scenario                                                | Surface                                                                                   | Why it was deferred | This-round target |
|--:|----------------------------------------------------------|-------------------------------------------------------------------------------------------|---------------------|-------------------|
| 1 | `evidence_ledger_performance` (`entry_with_server_computed_size`) | `observability::evidence_ledger::EvidenceLedger::append` + size/hash chain bookkeeping | bench file existed but was **not registered** as `[[bench]] harness = false` → libtest wrapped it → 0 measurements | register; rebuild; Criterion + perf record + heaptrack |
| 2 | `dgis::contagion_simulator::simulate` end-to-end on shipped profiles | `dgis::contagion_simulator::step` (per-tick) + `build_in_edges` rebuild + `BTreeSet::clone` | no Criterion harness — only an integration test (`tests/security/dgis_contagion_simulator.rs`) | profile the integration-test binary as a real workload via perf record |
| 3 | `vef::proof_generator::compute_proof_bytes` + receipt chain | `vef::proof_generator`, `vef::receipt_chain::verify_integrity` | `proof_verifier_gate_bench` had a single case; static read flagged `Sha256::new()` per call + `format!("sha256:{}", hex::encode(...))` | profile the `proof_generator_timeout_race` test binary as a real workload |
| 4 | `control_plane::fleet_transport::canonical_fleet_convergence_receipt_payload` | `canonicalize_json_value` (lines 154-180) — same recursive `format!()` pattern as trust_card | only inline `#[test]` coverage; no Criterion bench | source-cross-check confirmation against trust_card hotspot pattern; no new bench (avoid file proliferation per AGENTS.md) |

## Metric

Same as round 1 (`DEFINE.md` in round-1 directory):
- p50, p95, p99 per Criterion run for scenarios with a bench
- For perf-only scenarios (2 + 3): symbol-level CPU share from the
  flat profile; user-code % to confirm or reject "user code is the
  hotspot" vs "library dependency is the hotspot"
- alloc count and peak heap from heaptrack for scenario 1

## Budget

Round 1 fallback (current p95 × 0.5) does not apply because round 1
didn't measure these scenarios. The first round-2 number IS the
baseline.

For scenario 1 specifically:
- `entry_with_server_computed_size`: target `< 100 µs` p95 per append.
  Justification: the perf-budget-guard contract document for
  `observability.evidence_ledger.len_snapshot` (in
  `artifacts/performance_budgets/bd-ncwlf_hot_path_budget_evidence.json`)
  pegs post-fix work-units at 3.0 — a wall-time of 100 µs is generous
  by comparison.

## Golden output

Same as round 1: this is profile-only; no code change ships. The
`golden_checksums.txt` for round 2 records the sha256 of any new bench
binary built.

## Scope boundary

This run does **not** revisit round 1 numbers (trust_card_canonical,
threshold_sig, crypto_scheme, cuckoo_revocation, replay_bundle_gzip,
proof_verifier_gate). Those baselines are frozen at run-id
`20260520T214003Z_franken_node_perf`. If a re-baseline is wanted, it
happens after `extreme-software-optimization` ships a change, per the
methodology iteration protocol.

## Variance envelope

Same as round 1: ±10 % p95 drift on same host = noise. The host is
quieter at run start than during round 1 (fewer concurrent rch builds
visible in `rch queue`); a stricter envelope may apply this round.

## Stakeholder / requester

Jeffrey Emanuel: "ok do round 2". Decision being supported: confirm
or reject the round-1 deferred hypotheses, and produce a unified
ranked hotspot table across both rounds for `extreme-software-optimization`.
