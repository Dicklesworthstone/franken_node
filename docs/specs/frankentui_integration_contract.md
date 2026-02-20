# frankentui Integration Contract (`bd-34ll`)

## Purpose

This contract defines how `franken_node` presentation surfaces integrate with `frankentui` so all operator-visible console/TUI rendering follows one deterministic, testable policy.

## Scope

- Applies to all operator-facing console/TUI surfaces in `crates/franken-node/src/`.
- Defines rendering boundaries, token/styling policy, event-loop ownership, input routing, and error display conventions.
- Establishes snapshot-test hooks for downstream migration work (`bd-1xtf`) and conformance gates.

## Component Boundaries

| franken_node module | frankentui component | boundary type | Notes |
|---|---|---|---|
| `crates/franken-node/src/cli.rs` | `CommandSurface` | `surface_definition` | Defines command schema and output mode selection. |
| `crates/franken-node/src/main.rs` | `Panel`, `Table`, `StatusBar` | `renderer` | Primary command execution and human/JSON render handoff. |
| `crates/franken-node/src/policy/correctness_envelope.rs` | `AlertBanner` | `diagnostic_renderer` | Policy/correctness diagnostics for operator review. |
| `crates/franken-node/src/policy/controller_boundary_checks.rs` | `AlertBanner`, `Table` | `diagnostic_renderer` | Boundary-check event output and summaries. |
| `crates/franken-node/src/policy/evidence_emission.rs` | `StatusBar`, `Table` | `diagnostic_renderer` | Evidence emission progress and anomaly notifications. |
| `crates/franken-node/src/observability/evidence_ledger.rs` | `LogStreamPanel` | `diagnostic_renderer` | Audit/evidence stream visualization hooks. |
| `crates/franken-node/src/tools/evidence_replay_validator.rs` | `DiffPanel`, `AlertBanner` | `diagnostic_renderer` | Replay mismatch/match visibility with deterministic ordering. |

## Styling and Token Strategy

1. `franken_node` must not hardcode raw ANSI escape sequences for operator UI styling.
2. Visual semantics must be expressed via `frankentui` token families (color, spacing, emphasis, severity).
3. Token lookups must be centralized through adapter helpers (`frankentui::tokens::*`), not inlined in feature modules.
4. Non-TTY mode must degrade to plain text while preserving semantic labels and event codes.

## Rendering + Event Loop Contract

- **Loop ownership**: `franken_node` owns the root async runtime (`tokio`), while `frankentui` owns frame rendering once a TUI surface is activated.
- **Tick target**: 16 ms default render cadence for interactive surfaces (60 FPS nominal); 100 ms fallback for high-load/degraded mode.
- **State propagation**: domain modules publish immutable view-model deltas -> presentation adapter merges deltas -> render invalidation queue schedules frame updates.
- **Backpressure**: rendering is best-effort and must never block policy/control critical-path operations.

## Input Handling Contract

1. `frankentui` captures keyboard/mouse input and routes through a typed input router.
2. Router dispatches to `franken_node` command handlers by registered action IDs.
3. Key bindings are declared in one registry for deterministic replay/snapshot tests.
4. Any action requiring elevated privileges must pass existing policy gates before execution.

## Error Rendering Contract

- Error payloads originate from canonical error registry (`crates/franken-node/src/connector/error_code_registry.rs`).
- `frankentui` renders errors as structured Problem/Diagnostic cards with:
  - stable error code,
  - human remediation text,
  - trace correlation ID,
  - optional safe next action.
- Severity mapping:
  - `critical/high` -> blocking alert panel,
  - `medium` -> warning banner,
  - `low` -> inline status row.

## Testability Contract

Each component type must expose deterministic snapshot hooks:

- `CommandSurface`: command parse + rendered output fixture snapshots.
- `Panel/Table/StatusBar`: deterministic width/theme snapshots.
- `AlertBanner/DiffPanel`: deterministic severity and diff rendering fixtures.
- `LogStreamPanel`: stable ordering snapshots keyed by event timestamp + sequence.

Snapshot hooks must accept explicit seed/theme/terminal-width inputs to eliminate nondeterminism.

## Contract Event Codes

- `FRANKENTUI_CONTRACT_LOADED` (info)
- `FRANKENTUI_COMPONENT_UNMAPPED` (error)
- `FRANKENTUI_STYLING_VIOLATION` (error)

All events include `trace_correlation` = SHA-256 of the checklist artifact canonical JSON.

## Artifact Linkage

Machine-readable contract checklist:

- `artifacts/10.16/frankentui_contract_checklist.json`

Verification surfaces:

- `scripts/check_frankentui_contract.py`
- `tests/test_check_frankentui_contract.py`
- `artifacts/section_10_16/bd-34ll/verification_evidence.json`
- `artifacts/section_10_16/bd-34ll/verification_summary.md`
