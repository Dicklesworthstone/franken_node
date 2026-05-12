# bd-2eun: Quarantine-by-Default Store

## Purpose

Unknown/unreferenced objects enter quarantine by default. Quota and TTL eviction enforce hard caps. Quarantined objects are excluded from primary gossip state.

## Implementation Surface

- Authoritative module: `crates/franken-node/src/connector/quarantine_store.rs`
- The historical admission-module artifact path is not a live implementation path for this bead; validation and closeout evidence must cite the connector module above.

## Invariants

- **INV-QDS-DEFAULT**: Every object without a known reference enters quarantine class by default.
- **INV-QDS-BOUNDED**: Total quarantine storage never exceeds configured quota (bytes and count).
- **INV-QDS-TTL**: Objects exceeding TTL are evicted before any new admission.
- **INV-QDS-EXCLUDED**: Quarantined objects are never included in primary gossip state snapshots.

## Types

### QuarantineConfig

Quota and TTL settings: max_objects, max_bytes, ttl_seconds.

### QuarantineEntry

Stored object: object_id, size_bytes, ingested_at (epoch seconds), source_peer.

### QuarantineStats

Current state: object_count, total_bytes, oldest_entry_age, evictions_total.

### EvictionRecord

Audit record: object_id, reason (ttl_expired | quota_exceeded), evicted_at, age_seconds.

## Error Codes

- `QDS_QUOTA_EXCEEDED` — quarantine quota exceeded, object rejected
- `QDS_TTL_EXPIRED` — object TTL expired, evicted
- `QDS_DUPLICATE` — object already in quarantine
- `QDS_NOT_FOUND` — object not in quarantine
- `QDS_INVALID_CONFIG` — quarantine configuration invalid
