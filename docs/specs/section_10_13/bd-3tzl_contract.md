# bd-3tzl: Bounded Parser / Resource-Accounting Guardrails

## Purpose

Bounded parser and resource-accounting guardrails for control-channel frame decode. Prevents decode-DoS via frame size limits, nesting depth, and CPU budget.

## Invariants

- **INV-BPG-SIZE-BOUNDED**: Frame size never exceeds configured maximum; oversized frames rejected before parsing.
- **INV-BPG-DEPTH-BOUNDED**: Nesting depth in decoded structures never exceeds configured maximum.
- **INV-BPG-CPU-BOUNDED**: Decode CPU time tracked per frame; frames exceeding budget are aborted.
- **INV-BPG-AUDITABLE**: Every decode attempt emits a structured record with frame_id, size, depth, cpu_used, verdict.

## Types

### ParserConfig

Limits: max_frame_bytes, max_nesting_depth, max_decode_cpu_ms.

### FrameInput

Incoming frame: frame_id, raw_bytes_len, nesting_depth, decode_cpu_ms.

### DecodeVerdict

Result: frame_id, allowed, violations, resource_usage.

### DecodeAuditEntry

Audit record: frame_id, size, depth, cpu_used, limits, verdict, timestamp.

## Error Codes

- `BPG_SIZE_EXCEEDED` — frame exceeds size limit
- `BPG_DEPTH_EXCEEDED` — nesting depth exceeds limit
- `BPG_CPU_EXCEEDED` — decode CPU budget exceeded
- `BPG_INVALID_CONFIG` — parser configuration invalid
- `BPG_MALFORMED_FRAME` — frame structurally invalid
