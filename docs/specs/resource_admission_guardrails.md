# Resource Admission Guardrails

This contract covers `bd-w7tx8`: swarm-scale admission control for work that can saturate a node before evidence, replay, fleet, remote, or command work begins.

`bd-c9hho` extends this admission boundary into the multi-agent validation loop.
The program composes resource admission, workspace pressure, validation
planning, RCH classification, proof rehydration, deterministic swarm scenarios,
and evidence-hotset planning without introducing a second orchestration model.

## Swarm Validation Program Evidence

The `bd-c9hho` child beads are the executable evidence set for swarm-scale
responsiveness and resource utilization:

| Bead | Surface | Proof |
| --- | --- | --- |
| `bd-c9hho.1` | Capacity-market admission over validation proof coalescing at `crates/franken-node/src/ops/validation_proof_coalescer.rs` | `capacity_market_bids_cover_contention_actions_and_render_stable_output` |
| `bd-c9hho.2` | Target-dir lease planning in `crates/franken-node/src/ops/workspace_pressure_policy.rs` | `target_dir_lease_plan_golden_ranks_roots_without_cleanup_commands` |
| `bd-c9hho.3` | Blocked-proof rehydration planning in `crates/franken-node/src/ops/validation_recovery_planner.rs` | `blocked_proof_rehydration_prioritizes_fresh_safe_proofs_and_suppresses_duplicates` |
| `bd-c9hho.4` | RCH queue and worker-failure classification in `crates/franken-node/src/ops/rch_adapter.rs` | `worker_rmeta_loss_is_infrastructure_failure` |
| `bd-c9hho.5` | High-contention deterministic swarm scenarios in `crates/franken-node/src/tools/swarm_scenario.rs` | `high_contention_scenario_pack_emits_reason_codes_trace_ids_and_operator_actions` |
| `bd-c9hho.6` | Read-only evidence-hotset prefetch planning in `crates/franken-node/src/runtime/resource_governor.rs` | `evidence_hotset_prefetch` |

Together these surfaces make validation admission deterministic: agents can
decide when to stay source-only, reuse cached proof evidence, wait on an
existing proof, reserve an isolated target directory, classify stale RCH
progress, or replay high-contention operator incidents with stable reason codes.

## Work Classes

The admission inventory is:

- `control_plane_lane`
- `fleet_reconciliation`
- `evidence_append_export`
- `replay_incident_generation`
- `remote_computation_dispatch`
- `benchmark_perf_work`
- `external_command_helper`

## Budget Model

`ResourceBudget` evaluates five dimensions before mutation:

- `max_cpu_slots`
- `max_memory_bytes`
- `max_io_leases`
- `max_queue_depth`
- `min_deadline_ms`

The default model reuses centralized capacity defaults for I/O leases and queue-oriented limits where the existing buckets apply. Memory, CPU slot, and deadline values remain explicit because they are resource-policy decisions rather than collection capacities.

## Decisions

`AdmissionController::dry_run` and `AdmissionController::admit` return stable outcomes:

- `admit` with `RA_ADMIT_WITHIN_BUDGET`
- `defer` with `RA_DEFER_CPU_SLOTS_EXHAUSTED`
- `shed` with `RA_SHED_QUEUE_DEPTH_EXCEEDED`
- `reject` with fail-closed reason codes such as `RA_REJECT_MEMORY_BUDGET_EXCEEDED`, `RA_REJECT_IO_LEASES_EXHAUSTED`, and `RA_REJECT_DEADLINE_TOO_SHORT`

Callers that need a hard pre-mutation boundary should use `run_if_admitted`; non-admitted work does not execute the supplied allocation/filesystem/signature/command closure.

## Operator Visibility

Admission counters are exported through the existing observability metrics registry:

- `franken_node_resource_admission_decisions_total{decision=...}`
- `franken_node_resource_admission_work_class_decisions_total{work_class=...,decision=...}`

The operator health/readiness output includes a `resource_admission` component with JSON detail fields for `admitted`, `deferred`, `shed`, `rejected`, `reason_code`, and `recovery_hint`.

## Evidence

The committed evidence record is `artifacts/resource_admission/bd-w7tx8_admission_evidence.json`. It proves all four decision states, includes at least three representative work classes that go through the admission path, and records admitted/deferred/shed/rejected counts in machine-readable JSON.
