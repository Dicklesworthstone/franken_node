# bd-1xtf: Frankentui Surface Migration

**Section:** 10.16 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust integration tests | 44 | 44 |
| Python verification checks | 102 | 102 |
| Python unit tests | 38 | 38 |

## Implementation

`tests/integration/frankentui_surface_migration.rs`

- **Types:** FrankentuiComponent (7 variants), MigrationStatus (3 variants), BoundaryType (3 variants), SurfaceEntry, MigrationEvent, FrankentuiMigrationGate, MigrationSummary
- **Event codes:** FRANKENTUI_SURFACE_MIGRATED, FRANKENTUI_RAW_OUTPUT_DETECTED, FRANKENTUI_MIGRATION_INCOMPLETE
- **Invariants:** INV-FTM-COMPLETE, INV-FTM-NO-RAW, INV-FTM-MAPPED, INV-FTM-SNAPSHOT
- **Methods:** register_surface, register_raw_output, gate_pass, summary, surfaces, events, take_events, to_report, all, label, is_complete

## Surface Inventory

12 surfaces across 7 modules, all migration_status = complete:

| Module | Surfaces | Components |
|--------|----------|------------|
| src/cli.rs | 1 | CommandSurface |
| src/main.rs | 3 | Panel, Table, StatusBar |
| src/policy/correctness_envelope.rs | 1 | AlertBanner |
| src/policy/controller_boundary_checks.rs | 2 | AlertBanner, Table |
| src/policy/evidence_emission.rs | 2 | StatusBar, Table |
| src/observability/evidence_ledger.rs | 1 | LogStreamPanel |
| src/tools/evidence_replay_validator.rs | 2 | DiffPanel, AlertBanner |

## Verification Coverage

- File existence (integration test, CSV, spec doc)
- Rust test count (44, minimum 35)
- Serde derives present
- All 7 types, 11 methods, 3 event codes, 4 invariants verified
- All 44 integration test names verified
- Inventory CSV: 12 rows, all complete, all 7 modules covered, all 7 components used, required columns present
- Spec doc: Types, Methods, Event Codes, Invariants, Acceptance Criteria sections
