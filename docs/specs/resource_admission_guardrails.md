# Resource Admission Guardrails

This contract covers `bd-w7tx8`: swarm-scale admission control for work that can saturate a node before evidence, replay, fleet, remote, or command work begins.

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
