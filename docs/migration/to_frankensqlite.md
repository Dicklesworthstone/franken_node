# Migration to Frankensqlite

This document defines the migration path from interim/local connector stores to the `frankensqlite` substrate for section 10.16. The goal is a single durable source of truth with deterministic replay, explicit rollback, and idempotent reruns.

## Migration inventory

| Domain | Source module | Current source type | Migration status target | Primary persistence after cutover |
|---|---|---|---|---|
| `state_model` | `crates/franken-node/src/connector/state_model.rs` | In-memory `StateRoot` objects with JSON head/hash/version fields | `frankensqlite` table set with canonical root rows | `frankensqlite` |
| `fencing_token_state` | `crates/franken-node/src/connector/fencing.rs` | In-memory `FenceState` + `Lease` sequence and holder metadata | `frankensqlite` fencing token rows keyed by object + sequence | `frankensqlite` |
| `lease_coordination_state` | `crates/franken-node/src/connector/lease_coordinator.rs` | In-memory candidate/signature sets and deterministic selection output | `frankensqlite` coordination snapshots keyed by lease id | `frankensqlite` |
| `lease_service_state` | `crates/franken-node/src/connector/lease_service.rs` | In-memory lease map + decision log vector | `frankensqlite` lease and lease_decision tables | `frankensqlite` |
| `lease_conflict_state` | `crates/franken-node/src/connector/lease_conflict.rs` | In-memory active lease inputs and fork-resolution log entries | `frankensqlite` conflict + fork-log tables | `frankensqlite` |
| `snapshot_policy_state` | `crates/franken-node/src/connector/snapshot_policy.rs` | In-memory `SnapshotTracker` counters + policy audit vector | `frankensqlite` snapshot policy and snapshot record tables | `frankensqlite` |
| `quarantine_store_state` | `crates/franken-node/src/connector/quarantine_store.rs` | In-memory quarantine entry map + eviction counters | `frankensqlite` quarantine entry and eviction audit tables | `frankensqlite` |
| `retention_policy_state` | `crates/franken-node/src/connector/retention_policy.rs` | In-memory policy registry map + retention store map | `frankensqlite` retention policy/message/decision tables | `frankensqlite` |
| `artifact_persistence_state` | `crates/franken-node/src/connector/artifact_persistence.rs` | In-memory artifact map + per-type sequence vectors | `frankensqlite` artifact and replay-hook tables | `frankensqlite` |

## Migration strategy per domain

Each domain follows the same deterministic pipeline:

1. Export current state from interim store.
2. Transform to the `frankensqlite` schema using canonical keys.
3. Import with idempotent upsert semantics.
4. Verify row counts and domain invariants.
5. Cut over primary reads/writes to `frankensqlite`.

### Domain-specific details

- `state_model`
  - Export `connector_id`, `root_hash`, `version`, `state_model`, and canonical JSON head.
  - Verify `root_hash` integrity and monotonic version ordering.
- `fencing_token_state`
  - Export `object_id`, `current_seq`, and holder metadata.
  - Verify uniqueness of `(object_id, current_seq)` and stale-fence rejection parity.
- `lease_coordination_state`
  - Export coordinator selection inputs, selected coordinator, and quorum result material.
  - Verify deterministic coordinator selection for the same lease inputs.
- `lease_service_state`
  - Export lease lifecycle records and decision log entries.
  - Verify no active lease violates TTL/revocation rules.
- `lease_conflict_state`
  - Export overlap windows, conflict classification, and deterministic winner metadata.
  - Verify non-overlap policy and deterministic winner/tiebreak replay.
- `snapshot_policy_state`
  - Export snapshot policy thresholds, tracker counters, and audit records.
  - Verify replay distance bounds and policy validation behavior are preserved.
- `quarantine_store_state`
  - Export quarantine objects, ingest timestamps, and eviction history.
  - Verify TTL/quota eviction decisions remain deterministic.
- `retention_policy_state`
  - Export message class policies and stored message metadata.
  - Verify required-vs-ephemeral behavior and TTL cleanup semantics.
- `artifact_persistence_state`
  - Export persisted artifacts, per-type sequence numbers, and replay hooks.
  - Verify sequence monotonicity and replay hash checks.

## Rollback path

Rollback is mandatory for every migration run and is executed per migration run id.

1. Start dual-write mode for the run id (`run_id`) so interim stores and `frankensqlite` receive the same write set.
2. Snapshot interim stores to immutable rollback artifacts.
3. Execute domain migration in transactional staging.
4. If any domain fails verification, abort cutover and run rollback.
5. Rollback command:

```bash
franken-node migrate to-frankensqlite --rollback --run-id <run_id>
```

6. Rollback verification:
  - Interim store hash matches pre-migration snapshot hash.
  - No domain remains in a half-migrated state.
  - `frankensqlite` writes from the failed run id are discarded or marked invalid.

## Idempotency guarantee

Idempotency is guaranteed by deterministic domain ordering and stable primary keys.

- Domain import uses upsert keys derived from canonical source identifiers.
- Running migration twice on the same source data produces identical row values and row counts.
- No duplicate rows are introduced on rerun.
- Invariant checks (fencing uniqueness, lease non-overlap, replay ordering) must pass on both first and second runs.

## Migration events

Every domain migration emits the following event codes with `run_id` and `domain` fields:

- `MIGRATION_DOMAIN_START` (info)
- `MIGRATION_DOMAIN_COMPLETE` (info)
- `MIGRATION_DOMAIN_FAIL` (error)
- `MIGRATION_ROLLBACK_START` (warning)
- `MIGRATION_ROLLBACK_COMPLETE` (info)
- `MIGRATION_IDEMPOTENCY_VERIFIED` (info)
