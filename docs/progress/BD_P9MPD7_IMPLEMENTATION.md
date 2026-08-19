bd-p9mpd.7: Add audited cleanup executor for approved generated artifacts - IMPLEMENTATION COMPLETE

✅ **Implementation Summary:**

**Core Cleanup Executor (crates/franken-node/src/ops/cleanup_executor.rs):**
- CleanupExecutor: Main execution engine with dry-run/execute modes, safety protections
- CleanupMode::DryRun/Execute: Safe-by-default with explicit execution approval required
- CleanupOutcome: Detailed audit trail (Removed, SkippedProtected, SkippedReserved, SkippedTooYoung, etc.)
- CleanupProtectionRules: Configurable safety (protected extensions, directories, patterns, age thresholds)
- FileDeletionAdapter trait: Isolated file operations for testing (FilesystemDeletionAdapter, MockDeletionAdapter)
- CleanupReceipt: Complete audit record with operation details, bytes freed/skipped, summary statistics

**Audit Receipt Storage (crates/franken-node/src/storage/cleanup_receipts.rs):**
- CleanupReceiptsStorage: Persistent storage with JSON receipts, searchable index
- ReceiptIndex: Fast searching by actor, bead_id, mode, date ranges, bytes freed
- ReceiptSearchFilter: Flexible filtering for compliance queries and forensics
- Receipt lifecycle: Store → Search → Retrieve → Delete with integrity protection
- Audit report generation: Human-readable summaries with statistics

**Integration Testing (tests/cleanup_executor_integration.rs):**
- End-to-end workflow: Policy → Candidates → Execution → Storage → Audit
- Mock-free temp directory testing with real file operations
- Protection rules verification: Source files, reservations, age thresholds
- Receipt storage integration: Store/retrieve/search cycles
- Workspace pressure policy integration: Cleanup candidates from bd-p9mpd.4

**Safety Features:**
- Default dry-run mode: No destructive action without explicit execute approval
- Protection by extension: .rs, .toml, .md, .json, .lock files protected
- Protection by directory: src/, tests/, .git/ directories protected  
- Protection by pattern: Configurable glob patterns (src/**, *.rs, etc.)
- Age threshold: 24-hour minimum age before cleanup eligibility
- Active reservation checking: File reservation integration prevents conflicts
- Isolated deletion adapter: Real/mock adapters for production/testing

**Audit Trail & Compliance:**
- Complete operation receipts: Path, size, outcome, reason, timestamp per operation
- Candidate list digest: Reproducible fingerprint for approval verification
- Actor/bead tracking: Full attribution for compliance and forensics
- Receipt search: Find operations by actor, time range, bead, bytes freed
- Storage statistics: Summary metrics for reporting and monitoring
- Corruption detection: Missing files automatically cleaned from index

**Usage Examples:**
```rust
// Create executor with custom protection rules
let rules = CleanupProtectionRules {
    protected_extensions: ['.rs', '.toml'].into(),
    protected_directories: ['src/', 'tests/'].into(),
    min_age_seconds: 24 * 60 * 60, // 24 hours
    ..Default::default()
};
let executor = CleanupExecutor::with_protection_rules(rules, FilesystemDeletionAdapter);

// Generate candidates from workspace pressure policy
let policy_decision = workspace_policy.decide_admission(WorkCostClass::Cleanup, 2, &inputs);
let candidates = policy_decision.cleanup_candidates;

// Execute dry-run first (safe by default)
let dry_receipt = executor.execute_cleanup(
    &candidates,
    CleanupMode::DryRun,
    "operator_alice",
    "Disk pressure cleanup",
    Some("bd-p9mpd-urgent")
);

// After approval, execute actual cleanup
let exec_receipt = executor.execute_cleanup(
    &candidates,
    CleanupMode::Execute,
    "operator_alice",
    "Approved: Disk pressure cleanup",
    Some("bd-p9mpd-urgent")
);

// Store receipt for audit trail
let mut storage = CleanupReceiptsStorage::new()?;
storage.store_receipt(&exec_receipt)?;

// Query audit trail
let filter = ReceiptSearchFilter {
    actor: Some("operator_alice".to_string()),
    since: Some(yesterday),
    min_bytes_freed: Some(1_000_000), // > 1MB
    ..Default::default()
};
let audit_results = storage.search_receipts(&filter);
```

**Files Created/Modified:**
1. `crates/franken-node/src/ops/cleanup_executor.rs` [NEW] - 800+ lines core executor
2. `crates/franken-node/src/storage/cleanup_receipts.rs` [NEW] - 700+ lines receipt storage
3. `tests/cleanup_executor_integration.rs` [NEW] - 500+ lines E2E integration tests
4. `crates/franken-node/src/storage/mod.rs` [MODIFIED] - Added cleanup_receipts module
5. `crates/franken-node/src/ops/mod.rs` [MODIFIED] - Added cleanup_executor module

**Architecture & Integration:**
- Builds on workspace_pressure_policy.rs (bd-p9mpd.4) CleanupCandidate structures
- Isolated file operations via adapter pattern for test safety
- JSON schema versioning for receipt format compatibility
- Saturating arithmetic for all counter operations (security hardening)
- Bounded collections (push_bounded) for DoS protection
- Receipt storage with automatic index management and cleanup

**Test Coverage:**
- Mock adapter testing: Tracks deletion requests without actual file operations
- Protection rule testing: Extensions, directories, patterns, age, reservations
- E2E workflow testing: Real temp files, dry-run → execute → receipt → storage
- Integration testing: Workspace pressure policy → cleanup executor → receipt storage
- Audit compliance: Receipt searching, statistics, report generation
- Error handling: Missing files, failed deletions, storage corruption

**Compliance & Forensics Ready:**
- Complete audit trail: Who deleted what, when, why, with what outcome
- Reproducible candidate digests: Verify approved cleanup list integrity  
- Receipt search & export: Support compliance queries and investigations
- Storage statistics: Monitor cleanup activity patterns and effectiveness
- Corruption detection: Automatic cleanup of stale index entries

This completes the bd-p9mpd epic workspace pressure governance with safe, auditable cleanup execution.
