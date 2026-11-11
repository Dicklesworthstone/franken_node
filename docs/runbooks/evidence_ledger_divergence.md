# Runbook RB-005: Evidence Ledger Divergence

**Category**: evidence_ledger_divergence
**Severity**: High
**Estimated Recovery Time**: 45 minutes
**Required Permissions**: operator, ledger_admin
**Operator Privilege Level**: P2
**Last Reviewed**: 2026-02-21
**Review Cadence**: per_release_cycle

## Detection

### Metrics
- `evidence_ledger_divergence_detected == 1`
- `ledger_hash_mismatch_total > 0`

### Log Patterns
- `EVIDENCE_LEDGER_DIVERGENCE_DETECTED`
- `ledger_consistency_check_failed`

## Containment

1. Mark divergent ledger replicas as untrusted.
2. Suspend ledger writes to prevent further divergence.
3. Snapshot all divergent ledger states for forensic comparison.
4. Alert ledger operations team.

## Investigation

1. Identify the divergence point by comparing ledger hashes at each entry.
2. Determine which replica(s) diverged from the canonical chain.
3. Check for concurrent write conflicts or replication lag.
4. Audit recent ledger mutations for unauthorized entries.
5. Determine whether divergence is due to software bug, network partition, or malicious action.

## Repair

1. Identify canonical ledger chain (highest quorum agreement).
2. Re-sync divergent replicas from canonical chain.
3. Replay any valid entries that exist only on divergent replicas.
4. Compact ledger after re-sync to remove divergent entries.

## Verification

1. Run full ledger consistency check across all replicas.
2. Confirm all replicas have identical head hash.
3. Validate evidence chain integrity end-to-end.
4. Verify dependent trust decisions are consistent with repaired ledger.

## Rollback

1. If re-sync fails, restore all replicas from last consistent backup.
2. Replay ledger entries from backup point forward.
3. If entries are irrecoverably lost, document gap and escalate.
4. Consider epoch reset if divergence affects trust state integrity.

## Drill Scenario

Introduce a simulated divergence by injecting a conflicting entry into one
ledger replica in staging.  Verify divergence detection fires, containment
suspends writes, and the re-sync procedure restores consistency.

## Command References

- `franken-node debug evidence <evidence-ledger.jsonl> --json`
- `franken-node verify transparency-log --receipt <inclusion-receipt.json> --json`
- `franken-node ops health-check --json`
- `crates/franken-node/src/observability/evidence_ledger.rs` (library-level hash-chain verification; no standalone `ledger` CLI subcommand is shipped)
- `POST /api/v1/ledger/reconcile`

## Cross-References

- Evidence ledger subsystem
- transparency_log fixtures
- Ledger consistency verification
