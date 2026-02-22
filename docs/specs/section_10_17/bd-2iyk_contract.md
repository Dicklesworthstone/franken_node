# bd-2iyk: Information-Flow Lineage and Exfiltration Sentinel

**Section:** 10.17 -- Radical Expansion Execution Track
**Status:** Delivered

## Objective

Implement information-flow lineage tracking and an exfiltration sentinel that
detects covert data leakage across taint boundaries.  Sensitive lineage tags
must persist across all supported execution flows.  Simulated covert
exfiltration scenarios are detected and auto-contained above defined
recall/precision thresholds.

## Acceptance Criteria

1. Every data payload entering a tracked flow receives a `TaintLabel` that
   propagates through the `LineageGraph`.
2. Flow edges record source, sink, operation, and timestamp for full lineage
   reconstruction.
3. The `ExfiltrationSentinel` monitors flow edges and raises
   `ExfiltrationAlert` when a taint label crosses an unauthorized boundary.
4. Detection recall >= 95% and precision >= 90% on the built-in scenario
   corpus.
5. Auto-containment quarantines the offending flow within one graph tick.
6. All decisions produce machine-readable `ContainmentReceipt` records.
7. Deterministic ordering via `BTreeMap` for reproducible replay.

## Types

| Type | Purpose |
|------|---------|
| `TaintLabel` | Immutable sensitivity classification tag |
| `TaintSet` | Ordered set of active taint labels on a datum |
| `FlowEdge` | Directed edge: (source, sink, operation, taint_set, timestamp) |
| `LineageGraph` | Append-only DAG of `FlowEdge` records |
| `ExfiltrationSentinel` | Policy engine evaluating flow edges against taint boundaries |
| `ExfiltrationAlert` | Structured alert raised on boundary violation |
| `ContainmentReceipt` | Proof that a flow was quarantined |
| `TaintBoundary` | Policy rule defining allowed/denied taint crossings |
| `SentinelConfig` | Tuning knobs: thresholds, cooldowns, max-graph-depth |
| `FlowVerdict` | Per-edge pass/quarantine/alert decision |
| `LineageQuery` | Query filter for subgraph extraction |
| `LineageSnapshot` | Serialisable snapshot of the graph at a point in time |

## Event Codes

| Code | Meaning |
|------|---------|
| `FN-IFL-001` | Taint label assigned to datum |
| `FN-IFL-002` | Flow edge appended to lineage graph |
| `FN-IFL-003` | Taint propagation through operation |
| `FN-IFL-004` | Boundary crossing detected |
| `FN-IFL-005` | Exfiltration alert raised |
| `FN-IFL-006` | Flow quarantined (auto-containment) |
| `FN-IFL-007` | Containment receipt generated |
| `FN-IFL-008` | Lineage snapshot exported |
| `FN-IFL-009` | Sentinel configuration reloaded |
| `FN-IFL-010` | Graph depth limit reached |
| `FN-IFL-011` | Taint merge on confluence node |
| `FN-IFL-012` | Sentinel health check completed |

## Error Codes

| Code | Meaning |
|------|---------|
| `ERR_IFL_LABEL_NOT_FOUND` | Referenced taint label does not exist |
| `ERR_IFL_DUPLICATE_EDGE` | Flow edge already present in graph |
| `ERR_IFL_GRAPH_FULL` | Graph has reached max capacity |
| `ERR_IFL_BOUNDARY_INVALID` | Taint boundary rule is malformed |
| `ERR_IFL_CONTAINMENT_FAILED` | Auto-containment could not quarantine the flow |
| `ERR_IFL_SNAPSHOT_FAILED` | Lineage snapshot serialisation failed |
| `ERR_IFL_QUERY_INVALID` | Lineage query parameters are invalid |
| `ERR_IFL_CONFIG_REJECTED` | Sentinel configuration did not pass validation |
| `ERR_IFL_ALREADY_QUARANTINED` | Flow was already quarantined |
| `ERR_IFL_TIMEOUT` | Sentinel evaluation exceeded deadline |

## Invariants

| ID | Statement |
|----|-----------|
| `INV-IFL-LABEL-PERSIST` | Once assigned, a taint label is never silently removed from a datum's taint set. |
| `INV-IFL-EDGE-APPEND-ONLY` | Flow edges are append-only; no edge is ever deleted or mutated. |
| `INV-IFL-QUARANTINE-RECEIPT` | Every quarantine action produces exactly one `ContainmentReceipt`. |
| `INV-IFL-BOUNDARY-ENFORCED` | No flow edge crossing a denied boundary proceeds without an alert. |
| `INV-IFL-DETERMINISTIC` | Given the same graph state and sentinel config, the same verdict is always produced. |
| `INV-IFL-SNAPSHOT-FAITHFUL` | A lineage snapshot faithfully represents the graph at the moment of capture. |

## Schema Version

`ifl-v1.0`

## Deliverables

- `crates/franken-node/src/security/lineage_tracker.rs`
- `docs/specs/section_10_17/bd-2iyk_contract.md` (this file)
- `scripts/check_info_flow_lineage.py`
- `tests/test_check_info_flow_lineage.py`
- `artifacts/section_10_17/bd-2iyk/verification_evidence.json`
- `artifacts/section_10_17/bd-2iyk/verification_summary.md`
