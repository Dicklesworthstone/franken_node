# bd-1p2b: Control-Plane Retention Policy

## Purpose

Enforce retention class (`required` vs `ephemeral`) per control-plane message type. Required objects are durably stored. Ephemeral objects may be dropped only under policy constraints.

## Invariants

- **INV-CPR-CLASSIFIED**: Every control-plane message has a mandatory retention class; unclassified messages are rejected.
- **INV-CPR-REQUIRED-DURABLE**: Objects classified as `required` are never dropped by automatic cleanup.
- **INV-CPR-EPHEMERAL-POLICY**: Ephemeral objects are dropped only when TTL expires or storage pressure exceeds threshold.
- **INV-CPR-AUDITABLE**: Every retention decision (store/drop) emits an audit record with message_type, class, reason.

## Types

### RetentionClass

Enum: Required, Ephemeral.

### RetentionPolicy

Per-type policy: message_type, retention_class, ephemeral_ttl_seconds (if ephemeral).

### RetentionRegistry

Registry of retention policies per message type.

### StoredMessage

Stored control-plane message: message_id, message_type, retention_class, stored_at, size_bytes.

### RetentionDecision

Audit record: message_id, message_type, retention_class, action (store/drop), reason, timestamp.

## Error Codes

- `CPR_UNCLASSIFIED` — message type has no retention class
- `CPR_DROP_REQUIRED` — attempted to drop a required object
- `CPR_INVALID_POLICY` — policy configuration invalid
- `CPR_STORAGE_FULL` — storage capacity exceeded
- `CPR_NOT_FOUND` — message not in store
