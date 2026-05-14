# bd-b541 — Canonical Dependency/Topology Graph Schema

## Verdict

PASS

## Concrete Implementation

The canonical DGIS graph schema is implemented in
`crates/franken-node/src/dgis/graph_ingestion.rs`.

Key schema symbols are present at concrete source locations:

| Symbol | Evidence |
| --- | --- |
| `ManifestObservation` | `crates/franken-node/src/dgis/graph_ingestion.rs:137` |
| `NodeKind` | `crates/franken-node/src/dgis/graph_ingestion.rs:253` |
| `EdgeKind` | `crates/franken-node/src/dgis/graph_ingestion.rs:284` |
| `GraphNode` | `crates/franken-node/src/dgis/graph_ingestion.rs:309` |
| `GraphEdge` | `crates/franken-node/src/dgis/graph_ingestion.rs:336` |
| `canonical_observation_bytes` | `crates/franken-node/src/dgis/graph_ingestion.rs:402` |
| `observation_hash` | `crates/franken-node/src/dgis/graph_ingestion.rs:463` |
| `finalize_window` | `crates/franken-node/src/dgis/graph_ingestion.rs:900` |

## Invariants Covered

- Canonical observation encoding is length-prefixed and domain-separated.
- Dependency ordering is deterministic through `BTreeMap`.
- Node and edge wire tags are locked by tests.
- Ingestion rejects oversized maintainer/dependency sets and non-finite edge
  weights.
- Window finalization produces deterministic node and edge sets for replay.
- The module has 30 inline `#[test]` cases covering schema construction,
  canonicalization, bounded growth, deterministic replay, and fail-closed
  numeric handling.

## Verification

- `python3 scripts/check_section_10_20_gate.py --json` reports section verdict
  PASS and keeps `bd-b541` in the graph-schema coverage group.
- Source evidence was inspected directly with `rg` over
  `crates/franken-node/src/dgis/graph_ingestion.rs`; no proxy-only evidence is
  required to identify the implementation surface.
