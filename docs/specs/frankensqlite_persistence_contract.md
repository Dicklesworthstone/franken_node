# frankensqlite Persistence Integration Contract (`bd-1a1j`)

## Purpose

This contract defines how `franken_node` maps control, audit, and replay state to `frankensqlite` with explicit durability, replay, schema ownership, and concurrency guarantees.

This contract is the root dependency for:
- `bd-2tua` (adapter implementation)
- `bd-10g0` (10.16 section gate)

## Scope

- Applies to stateful modules under `crates/franken-node/src/connector/`.
- Covers persistence classes, safety tiers, durability modes, schema ownership, replay semantics, and concurrent access constraints.
- Excludes non-stateful pure computation modules.

## Persistence Class Enumeration

Persistence classes are grouped by product safety tier.

### Tier 1 (`tier_1`) - Crash-safe, fail-closed, WAL durability

Tier 1 stores control-critical state and audit evidence that must survive crash/restart and support deterministic incident replay.

Examples:
- Fencing tokens and lease authority state
- Rollout state and health-gate policy state
- Control-channel sequence/replay-window state
- Artifact journal + replay index
- Durable-claim gate evidence

### Tier 2 (`tier_2`) - Durable with periodic flush

Tier 2 stores durable operational state where bounded lag is acceptable but replayability remains required.

Examples:
- Snapshot policy state and snapshot records
- CRDT merge state
- Schema migration registry/receipts
- Quarantine store + promotion receipts
- Retention decisions
- Offline coverage metrics
- Repair-cycle audit records

### Tier 3 (`tier_3`) - Ephemeral/best-effort

Tier 3 stores cache-like, recomputable state with no strict replay requirement.

Examples:
- Lifecycle transition cache materialized from canonical transition rules

## Durability Mode Mapping

`frankensqlite` durability modes used by this contract are valid SQLite-backed configurations:

| Durability mode | journal_mode | synchronous | Intended use |
|---|---|---|---|
| `wal_full` | `WAL` | `FULL` | Tier 1 crash-safe control + audit state |
| `wal_normal` | `WAL` | `NORMAL` | Tier 2 durable periodic-flush state |
| `memory` | `MEMORY` | `OFF` | Tier 3 ephemeral cache state |

ACID expectations:
- `wal_full`: atomic + durable commit per transaction, fail-closed for control decisions.
- `wal_normal`: atomic commit with periodic flush tolerance.
- `memory`: atomic in-process only, no crash-durability guarantee.

## Schema Ownership and Evolution

- Each table name has exactly one owning module.
- Table ownership is declared in `artifacts/10.16/frankensqlite_persistence_matrix.json`.
- Schema changes are coordinated through `crates/franken-node/src/connector/schema_migration.rs` migration hints/receipts.
- Cross-module access must use module interfaces; table ownership does not transfer.

## Replay Semantics

- Tier 1 and Tier 2 classes require replay semantics.
- Replay support is explicitly declared per class (`replay_support: true` + `replay_strategy`).
- Replay strategies use WAL-ordered reconstruction and deterministic ordering keys where applicable.
- Tier 3 replay support is optional and may be `false`.

## Concurrency Model

- Connection model: pooled connections shared across connector subsystems.
- Tier 1 writes: fenced writer discipline + explicit transaction boundaries.
- Isolation level: serializable for Tier 1, read-committed for Tier 2, best-effort for Tier 3.
- Conflict resolution: writer fencing, bounded retry with backoff, deterministic winner selection for lease/quorum paths.

## Event Codes

- `PERSISTENCE_CONTRACT_LOADED` (info)
- `PERSISTENCE_CLASS_UNMAPPED` (error)
- `PERSISTENCE_TIER_INVALID` (error)
- `PERSISTENCE_REPLAY_UNSUPPORTED` (warning)

All events include `trace_correlation` = SHA-256 hash of canonical persistence matrix JSON.

## Artifact Linkage

- `artifacts/10.16/frankensqlite_persistence_matrix.json`
- `scripts/check_frankensqlite_contract.py`
- `tests/test_check_frankensqlite_contract.py`
- `artifacts/section_10_16/bd-1a1j/verification_evidence.json`
- `artifacts/section_10_16/bd-1a1j/verification_summary.md`
