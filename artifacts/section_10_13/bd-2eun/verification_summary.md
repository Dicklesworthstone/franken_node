# bd-2eun: Quarantine-by-Default Store — Verification Summary

## Verdict: PASS (7/7 checks)

## Implementation

`crates/franken-node/src/connector/quarantine_store.rs`

- `QuarantineStore`: BTreeMap-backed store with quota (objects + bytes) and TTL enforcement
- `ingest()`: TTL eviction first, then quota eviction (oldest-first, deterministic tiebreak), then admit
- `evict_expired()`: removes all entries past TTL
- `promote()`: removes from quarantine after validation
- `quarantined_ids()`: sorted list for gossip exclusion (INV-QDS-EXCLUDED)

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-QDS-DEFAULT | PASS | All unknown objects enter quarantine via ingest() (19 unit tests, integration test) |
| INV-QDS-BOUNDED | PASS | Quota eviction ensures count <= max_objects and bytes <= max_bytes |
| INV-QDS-TTL | PASS | Expired entries evicted before new admission |
| INV-QDS-EXCLUDED | PASS | quarantined_ids() returns sorted list for gossip exclusion |

## Error Codes

All 5 error codes present: QDS_QUOTA_EXCEEDED, QDS_TTL_EXPIRED, QDS_DUPLICATE, QDS_NOT_FOUND, QDS_INVALID_CONFIG.

## Test Results

- 19 Rust unit tests passed
- 4 integration tests (1 per invariant)
- 25 Python verification tests passed
- Usage metrics CSV with 5 time-series snapshots

## Path Truth Ratchet

- Canonical implementation path: `crates/franken-node/src/connector/quarantine_store.rs`
- Historical admission-module artifact paths are not live module paths and are excluded from verification evidence.
