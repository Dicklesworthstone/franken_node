# bd-1xtf: Frankentui Surface Migration

**Section:** 10.16 — Adjacent Substrate Integration
**Status:** Implementation Complete

## Purpose

Migrate all operator-facing console/TUI surfaces in franken_node to frankentui
primitives. After this migration, no homegrown terminal rendering or raw ANSI
escape sequences remain in frankentui-mandatory modules. All rendering routes
through the unified frankentui presentation layer defined in the bd-34ll contract.

## Scope

- 12 surface entries across 7 franken_node modules
- 7 frankentui component types (CommandSurface, Panel, Table, StatusBar, AlertBanner, DiffPanel, LogStreamPanel)
- 3 boundary types (surface_definition, renderer, diagnostic_renderer)
- Surface inventory CSV with migration status tracking
- Migration gate with event emission and JSON reporting

## Types

| Type | Kind | Description |
|------|------|-------------|
| `FrankentuiComponent` | enum | 7 component types from bd-34ll contract |
| `MigrationStatus` | enum | Complete, InProgress, NotStarted |
| `BoundaryType` | enum | SurfaceDefinition, Renderer, DiagnosticRenderer |
| `SurfaceEntry` | struct | Module path, surface name, component, status |
| `MigrationEvent` | struct | Code, surface name, detail |
| `FrankentuiMigrationGate` | struct | Gate engine tracking surfaces and events |
| `MigrationSummary` | struct | Counts: total, complete, incomplete, raw_violations |

## Methods

| Method | Owner | Description |
|--------|-------|-------------|
| `FrankentuiComponent::all()` | Component | Returns all 7 components |
| `FrankentuiComponent::label()` | Component | Human-readable label |
| `MigrationStatus::is_complete()` | Status | True only for Complete |
| `FrankentuiMigrationGate::register_surface()` | Gate | Register a surface entry |
| `FrankentuiMigrationGate::register_raw_output()` | Gate | Record a raw output violation |
| `FrankentuiMigrationGate::gate_pass()` | Gate | True if all complete, no raw violations |
| `FrankentuiMigrationGate::summary()` | Gate | Aggregate counts |
| `FrankentuiMigrationGate::surfaces()` | Gate | Borrow surface list |
| `FrankentuiMigrationGate::events()` | Gate | Borrow event log |
| `FrankentuiMigrationGate::take_events()` | Gate | Drain event log |
| `FrankentuiMigrationGate::to_report()` | Gate | Structured JSON report |

## Event Codes

| Code | Level | Trigger |
|------|-------|---------|
| `FRANKENTUI_SURFACE_MIGRATED` | info | Surface successfully migrated |
| `FRANKENTUI_RAW_OUTPUT_DETECTED` | error | Raw ANSI/println! found in mandatory module |
| `FRANKENTUI_MIGRATION_INCOMPLETE` | warning | Surface not yet fully migrated |

## Invariants

| ID | Rule |
|----|------|
| `INV-FTM-COMPLETE` | All surfaces must have migration_status = complete |
| `INV-FTM-NO-RAW` | No raw ANSI escape sequences in mandatory modules |
| `INV-FTM-MAPPED` | Every contract module has at least one surface entry |
| `INV-FTM-SNAPSHOT` | Snapshot tests produce deterministic output |

## Artifacts

| File | Description |
|------|-------------|
| `tests/integration/frankentui_surface_migration.rs` | 44 Rust integration tests |
| `artifacts/10.16/frankentui_surface_inventory.csv` | 12 surfaces, all complete |
| `scripts/check_frankentui_migration.py` | Verification script |
| `tests/test_check_frankentui_migration.py` | Python unit tests |

## Acceptance Criteria

1. All 12 surfaces from the bd-34ll contract are registered in the inventory CSV
2. All surfaces have migration_status = "complete"
3. All 7 frankentui component types are used at least once
4. All 7 contract modules have at least one surface entry
5. All 3 boundary types (surface_definition, renderer, diagnostic_renderer) are represented
6. Gate passes: no incomplete surfaces, no raw output violations
7. All types implement Serialize + Deserialize
8. At least 35 Rust integration tests
9. Verification script passes all checks with `--json` machine-readable output
