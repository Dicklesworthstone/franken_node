# Engine Architecture

## Goal
Create a standalone JavaScript runtime that can evolve into a full replacement for Node/Bun.

## Repository Topology
- Engine core: `/dp/franken_engine`
- Product/compatibility layer: `/dp/franken_node`

`franken_node` consumes engine crates from `franken_engine`; engine internals are not duplicated locally.

## Dual-Lane Execution Strategy
- QuickJS lane: deterministic embedding, low startup overhead, extension-host control plane.
- V8 lane: high compatibility/performance lane for modern JS semantics and heavier workloads.
- Hybrid router: policy-based dispatch chooses a lane per execution unit.

## Near-Term Direction
1. Stabilize a shared runtime trait (`franken-engine`) for execution, module loading, and hostcall bridging.
2. Integrate transplanted extension-host logic from Pi Rust into `franken-extension-host` behind an adapter boundary.
3. Build a compatibility surface for Node/Bun APIs in layers (timers, process, fs, network, child process).
4. Add engine conformance + behavioral parity gates before enabling production defaults.

## Why This Shape
- Avoids hard lock-in to one JS engine implementation.
- Allows incremental migration from transplanted extension-host logic without freezing architecture.
- Supports workload-specific optimization while sharing a single hostcall/capability model.

## Current `run` Control Flow

Today the user-visible `franken-node run` path is:

1. `crates/franken-node/src/main.rs` parses the CLI and resolves `Config`.
2. `ops::engine_dispatcher::EngineDispatcher::dispatch_run()` resolves the external
   `franken_engine` binary path and serializes the effective config payload.
3. `EngineDispatcher` creates a temporary directory, places a Unix-domain socket
   path inside it, and exports that path to the child process via
   `FRANKEN_ENGINE_TELEMETRY_SOCKET`.
4. `ops::telemetry_bridge::TelemetryBridge::start_listener()` removes any stale
   socket at that path, binds a listener, and spawns background threads.
5. `EngineDispatcher` launches the external `franken_engine` child process.
6. Telemetry events are read line-by-line from the socket and written into
   `FrankensqliteAdapter` as audit-log records for replay/audit use.

That gives `franken_node` a narrow but important runtime seam: it does not own
the engine execution core, but it does own telemetry ingestion, child-process
launch sequencing, and the user-visible behavior when telemetry startup or
drain fails.

## Telemetry Ingestion Contract

**Bead:** `bd-1now.4.1`

The detailed ownership, lifecycle, backpressure, accounting, and proof
contract for this seam now lives in the canonical migration-plan appendix:

- [docs/migration/asupersync_control_surface_migration.md](/data/projects/franken_node/docs/migration/asupersync_control_surface_migration.md)
  under `## Selective Runtime Seam Contract (bd-1now.4.1)`

That appendix is the source of truth for:

- the owned-worker topology for `TelemetryBridge`,
- the `EngineDispatcher` stop/join/error contract,
- bounded admission and overflow semantics,
- structured event families and reason-code vocabulary,
- event-accounting invariants,
- fixed vs tunable vs auto-derived budgets,
- and the proof/baseline obligations for follow-on beads.

This document intentionally keeps only the high-level runtime/dispatch context
so the repo does not end up with two competing `.4.1` contract sources.
