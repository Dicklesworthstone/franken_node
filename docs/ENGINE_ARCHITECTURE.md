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
