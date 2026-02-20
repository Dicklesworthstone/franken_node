# bd-1gnb — Distributed Trace Correlation IDs

## Overview

Requires all high-impact connector flows to carry distributed trace correlation
IDs end-to-end.  A `TraceContext` propagates `trace_id`, `span_id`, and
`parent_span_id` through every control-plane artifact and execution step.
Missing trace context is surfaced as a conformance failure.  Traces can be
stitched across services using the shared `trace_id`.

## Trace Context Format

```
trace_id:   128-bit hex string (32 chars)
span_id:    64-bit hex string (16 chars)
parent_span_id: optional 64-bit hex string
```

## Invariants

- **INV-TRC-REQUIRED** — Every traced operation must carry a non-empty
  `trace_id` and `span_id`; operations with missing context are rejected.
- **INV-TRC-PROPAGATED** — Child spans inherit the parent `trace_id` and
  record the parent `span_id` for stitching.
- **INV-TRC-STITCHABLE** — Given a `trace_id`, all spans in the trace can
  be collected and ordered by creation timestamp.
- **INV-TRC-CONFORMANCE** — A conformance checker validates that every
  artifact in a flow carries valid trace context; violations produce a
  machine-readable report.

## Types

- `TraceContext` — trace_id, span_id, parent_span_id, timestamp
- `TracedArtifact` — artifact_id, artifact_type, trace_context
- `TraceViolation` — artifact_id, reason
- `ConformanceReport` — trace_id, total_artifacts, violations, verdict
- `TraceError` — error codes for contract violations

## Error Codes

| Code | Meaning |
|------|---------|
| `TRC_MISSING_TRACE_ID` | trace_id is empty |
| `TRC_MISSING_SPAN_ID` | span_id is empty |
| `TRC_INVALID_FORMAT` | ID does not match expected hex format |
| `TRC_PARENT_NOT_FOUND` | Parent span not in the trace |
| `TRC_CONFORMANCE_FAILED` | One or more artifacts lack valid context |
