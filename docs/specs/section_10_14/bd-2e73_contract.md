# bd-2e73: Bounded Evidence Ledger Ring Buffer

## Purpose

Fixed-capacity, allocation-stable container for evidence entries with deterministic
FIFO overflow semantics. In lab/test mode, spills the complete evidence stream to
JSONL for post-mortem analysis.

## Dependencies

- **Upstream:** bd-nupr (EvidenceEntry schema)
- **Downstream:** bd-3epz (section gate), bd-15j6 (mandatory ledger emission)

## Types

### `EvidenceEntry`

Product control decision record: `schema_version`, `decision_id`, `decision_kind`,
`decision_time`, `trace_id`, `epoch_id`, `payload`.

### `DecisionKind`

Enum: admit, deny, quarantine, release, rollback, throttle, escalate.

### `LedgerCapacity`

Configuration: `max_entries: usize`, `max_bytes: usize`.

### `EvidenceLedger`

Bounded ring buffer. Evicts oldest entry on overflow (FIFO). Enforces both
`max_entries` and `max_bytes` independently.

### `SharedEvidenceLedger`

Thread-safe `Arc<Mutex<EvidenceLedger>>` wrapper. `Send + Sync`.

### `LabSpillMode`

Wraps `EvidenceLedger` and writes every entry to a JSONL file with fsync.

## Operations

| Method | Description |
|--------|-------------|
| `append(entry)` | Add entry, evict oldest on overflow, return EntryId |
| `iter_recent(n)` | Iterate most recent N entries |
| `iter_all()` | Iterate all entries oldest-first |
| `snapshot()` | Clone-safe snapshot for export |

## Event Codes

| Code | Description |
|------|-------------|
| EVD-LEDGER-001 | Append success |
| EVD-LEDGER-002 | Eviction (includes evicted entry_id) |
| EVD-LEDGER-003 | Lab spill write |
| EVD-LEDGER-004 | Capacity breach warning |

## Artifacts

- Implementation: `crates/franken-node/src/observability/evidence_ledger.rs`
- Spec: `docs/specs/section_10_14/bd-2e73_contract.md`
- Evidence: `artifacts/section_10_14/bd-2e73/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-2e73/verification_summary.md`
