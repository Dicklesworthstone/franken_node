# Control Epoch Validity Adoption (bd-181w)

This document defines how Section 10.15 control-plane artifacts and remote contracts adopt canonical epoch-window validation from Section 10.14.

## Canonical Source

All epoch validation in this bead must use:

- `crates/franken-node/src/control_plane/control_epoch.rs`
- `check_artifact_epoch(...)`
- `ValidityWindowPolicy`

Custom epoch acceptance logic is prohibited.

## Epoch-Scoped Artifact Inventory

### Control Artifacts

1. Rollout plans (`connector/rollout_state.rs`)
- Artifact ID format: `rollout-plan:{connector_id}`
- Epoch field: `RolloutState.rollout_epoch`
- Enforcement path: `persist_epoch_scoped(...)`

2. Health-gate policies (`connector/health_gate.rs`)
- Artifact ID format: `{policy_id}`
- Epoch field: `EpochScopedHealthPolicy.policy_epoch`
- Enforcement path: `evaluate_epoch_scoped_policy(...)`

3. Fencing tokens (`connector/fencing.rs`)
- Artifact ID format: `fencing:{object_id}:{lease_seq}`
- Epoch field: `Lease.epoch`
- Enforcement path: `validate_write_epoch_scoped(...)`

### Remote Contracts

For this bead, the remote contract class is represented by fencing leases/tokens used in distributed coordination. The same canonical check applies before a fenced write is accepted.

## Validity Rule

Each artifact epoch is accepted only if it is within:

`[current_epoch - max_staleness, current_epoch]` (inclusive)

Rejection behavior is fail-closed:

1. Future epoch (`artifact_epoch > current_epoch`) -> reject (`EPV-002`)
2. Expired epoch (`artifact_epoch < current_epoch - max_staleness`) -> reject (`EPV-003`)

Accepted checks emit `EPV-001` and accepted high-impact operations emit an epoch-scope log `EPV-004`.

## Logging Contract

- `EPV-001`: epoch check passed
- `EPV-002`: future epoch rejected
- `EPV-003`: stale epoch rejected
- `EPV-004`: epoch scope logged for accepted high-impact operation

Each log record includes:

- `artifact_type`
- `artifact_id`
- `artifact_epoch`
- `current_epoch`
- `trace_id`

## Test Coverage

`tests/security/control_epoch_validity.rs` validates:

- current epoch acceptance
- past-but-valid acceptance
- future-epoch fail-closed rejection
- expired-epoch rejection
- EPV-004 scope logging for accepted health policy, rollout plan, and fencing token operations
