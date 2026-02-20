# bd-2tua: Frankensqlite Adapter Layer

**Section:** 10.16 — Adjacent Substrate Integration
**Status:** Implementation Complete

## Purpose

Implement the adapter layer that routes all franken_node persistence APIs through
frankensqlite. Replaces interim/ad-hoc stores with a unified persistence surface
supporting tiered durability (WAL-mode crash-safe, periodic flush, ephemeral cache).

## Scope

- 4 persistence traits (ControlState, AuditLog, Snapshot, Cache)
- 3 durability tiers with explicit guarantees
- Adapter struct wrapping connection pool
- Schema initialization and migration hooks
- Structured error mapping to error registry codes
- Conformance tests for round-trip, crash simulation, concurrent access, replay

## Types

| Type | Kind | Description |
|------|------|-------------|
| `DurabilityTier` | enum | Tier1 (WAL crash-safe), Tier2 (periodic flush), Tier3 (ephemeral) |
| `PersistenceClass` | enum | ControlState, AuditLog, Snapshot, Cache |
| `AdapterConfig` | struct | Database path, pool size, tier config |
| `WriteResult` | struct | Success/failure with latency and tier |
| `ReadResult` | struct | Data retrieval with tier and cache status |
| `AdapterEvent` | struct | Event code, persistence class, detail |
| `AdapterSummary` | struct | Operations by tier, errors, replay count |
| `FrankensqliteAdapter` | struct | Main adapter wrapping pool and event log |
| `SchemaVersion` | struct | Version tracking for migrations |
| `AdapterError` | enum | Structured errors mapped to error registry |

## Methods

| Method | Owner | Description |
|--------|-------|-------------|
| `DurabilityTier::all()` | Tier | Returns all 3 tiers |
| `DurabilityTier::label()` | Tier | Human-readable label |
| `PersistenceClass::all()` | Class | Returns all 4 classes |
| `PersistenceClass::tier()` | Class | Maps class to durability tier |
| `FrankensqliteAdapter::write()` | Adapter | Write with tier-appropriate durability |
| `FrankensqliteAdapter::read()` | Adapter | Read with cache awareness |
| `FrankensqliteAdapter::replay()` | Adapter | Deterministic replay from WAL |
| `FrankensqliteAdapter::schema_version()` | Adapter | Current schema version |
| `FrankensqliteAdapter::migrate()` | Adapter | Apply schema migration |
| `FrankensqliteAdapter::summary()` | Adapter | Aggregate operation counts |
| `FrankensqliteAdapter::events()` | Adapter | Borrow event log |
| `FrankensqliteAdapter::take_events()` | Adapter | Drain event log |
| `FrankensqliteAdapter::to_report()` | Adapter | Structured JSON report |
| `FrankensqliteAdapter::gate_pass()` | Adapter | True if all operations succeed |

## Event Codes

| Code | Level | Trigger |
|------|-------|---------|
| `FRANKENSQLITE_ADAPTER_INIT` | info | Adapter initialized |
| `FRANKENSQLITE_WRITE_SUCCESS` | debug | Write completed |
| `FRANKENSQLITE_WRITE_FAIL` | error | Write failed |
| `FRANKENSQLITE_CRASH_RECOVERY` | warning | Crash recovery executed |
| `FRANKENSQLITE_REPLAY_START` | info | Replay initiated |
| `FRANKENSQLITE_REPLAY_MISMATCH` | error | Replay divergence detected |

## Invariants

| ID | Rule |
|----|------|
| `INV-FSA-TIER1-DURABLE` | Tier 1 writes survive simulated crash |
| `INV-FSA-REPLAY-DETERMINISTIC` | Replay produces identical state |
| `INV-FSA-CONCURRENT-SAFE` | Concurrent access causes no corruption |
| `INV-FSA-SCHEMA-VERSIONED` | Schema migrations are versioned and reversible |

## Artifacts

| File | Description |
|------|-------------|
| `crates/franken-node/src/storage/frankensqlite_adapter.rs` | Adapter implementation |
| `tests/integration/frankensqlite_adapter_conformance.rs` | Conformance tests |
| `artifacts/10.16/frankensqlite_adapter_report.json` | Conformance report |
| `scripts/check_frankensqlite_adapter.py` | Verification script |
| `tests/test_check_frankensqlite_adapter.py` | Python unit tests |

## Acceptance Criteria

1. All 4 persistence classes have trait implementations in the adapter
2. All 3 durability tiers are represented and tested
3. Tier 1 crash simulation tests pass
4. Concurrent access tests pass without corruption
5. Replay determinism verified for Tier 1 and Tier 2
6. Schema migration is versioned
7. All types implement Serialize + Deserialize
8. At least 40 Rust conformance tests
9. Verification script passes all checks with `--json` output
