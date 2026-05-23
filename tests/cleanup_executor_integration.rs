//! Integration tests for audited cleanup executor (bd-p9mpd.7).
//!
//! Tests the complete cleanup workflow with real temp directories,
//! audit receipts, and protection rules.

use frankenengine_node::ops::workspace_pressure_policy::{
    CleanupCandidate, WorkspacePressureInputs, WorkspacePressurePolicy,
};
#[cfg(feature = "test-support")]
use frankenengine_node::storage::cleanup_receipts::CleanupReceiptsError;
use frankenengine_node::storage::cleanup_receipts::{CleanupReceiptsStorage, ReceiptSearchFilter};
use frankenengine_node::{
    lock_utils,
    ops::cleanup_executor::{
        CleanupExecutor, CleanupMode, CleanupOutcome, CleanupProtectionRules,
        FilesystemDeletionAdapter, MockDeletionAdapter,
    },
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::MutexGuard;
use tempfile::TempDir;

/// Create test cleanup candidate.
fn create_candidate(
    path: &str,
    size: u64,
    reason: &str,
    requires_approval: bool,
) -> CleanupCandidate {
    CleanupCandidate {
        path: PathBuf::from(path),
        size_bytes: size,
        reason: reason.to_string(),
        requires_approval,
        mtime: None,
    }
}

fn test_cleanup_rules() -> CleanupProtectionRules {
    CleanupProtectionRules {
        min_age_seconds: 0,
        ..CleanupProtectionRules::default()
    }
}

fn lock_deletion_requests(adapter: &MockDeletionAdapter) -> MutexGuard<'_, Vec<PathBuf>> {
    lock_utils::try_lock(
        adapter.deletion_requests.as_ref(),
        "cleanup executor deletion request test mutex",
    )
    .expect("cleanup executor deletion request test mutex should not be poisoned")
}

#[derive(Debug, PartialEq, Eq)]
struct CleanupPermutationDigest {
    candidates_digest: String,
    total_candidates: usize,
    removed_count: usize,
    skipped_count: usize,
    failed_count: usize,
    bytes_freed: u64,
    bytes_skipped: u64,
    skipped_pins: u64,
    outcomes_by_path: BTreeMap<String, CleanupOutcome>,
    deletion_requests: BTreeSet<String>,
}

fn path_label(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn execute_cleanup_permutation_digest(
    base: &Path,
    candidates: &[CleanupCandidate],
    reservations: BTreeSet<PathBuf>,
) -> CleanupPermutationDigest {
    let mock_adapter = MockDeletionAdapter::default();
    let mut executor =
        CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter.clone());
    executor.update_reservations(reservations);

    let receipt = executor.execute_cleanup(
        candidates,
        CleanupMode::Execute,
        "permutation_test".to_string(),
        "Permutation invariant cleanup execution".to_string(),
        Some("r100-cod2-0047".to_string()),
    );

    let outcomes_by_path = receipt
        .operations
        .iter()
        .map(|operation| (path_label(base, &operation.path), operation.outcome))
        .collect();
    let deletion_requests = lock_deletion_requests(&mock_adapter)
        .iter()
        .map(|path| path_label(base, path))
        .collect();

    CleanupPermutationDigest {
        candidates_digest: receipt.candidates_digest,
        total_candidates: receipt.summary.total_candidates,
        removed_count: receipt.summary.removed_count,
        skipped_count: receipt.summary.skipped_count,
        failed_count: receipt.summary.failed_count,
        bytes_freed: receipt.bytes_freed,
        bytes_skipped: receipt.bytes_skipped,
        skipped_pins: receipt.skipped_pins,
        outcomes_by_path,
        deletion_requests,
    }
}

/// Create temporary test files for cleanup testing.
fn create_test_files(temp_dir: &TempDir) -> Vec<PathBuf> {
    let mut files = Vec::new();

    // Create various test files
    let test_files = [
        ("target/debug/deps/test1.rlib", "Test library file"),
        ("target/debug/deps/test2.rlib", "Another library"),
        ("target/debug/incremental/cache", "Incremental cache"),
        ("generated/artifacts/output.txt", "Generated artifact"),
        ("temp_build/intermediate.o", "Build intermediate"),
    ];

    for (path, content) in &test_files {
        let full_path = temp_dir.path().join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&full_path, content).expect("write test file");
        files.push(full_path);
    }

    files
}

#[test]
fn test_cleanup_executor_dry_run() {
    let temp_dir = TempDir::new().expect("temp dir");
    let test_files = create_test_files(&temp_dir);

    let mock_adapter = MockDeletionAdapter::default();
    let executor =
        CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter.clone());

    let candidates = vec![CleanupCandidate {
        path: test_files[0].clone(),
        size_bytes: 1024,
        reason: "Test cleanup candidate".to_string(),
        requires_approval: false,
        mtime: None,
    }];

    let receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::DryRun,
        "test_actor".to_string(),
        "Integration test dry run".to_string(),
        Some("test_bead_123".to_string()),
    );

    // Verify receipt structure
    assert_eq!(receipt.mode, CleanupMode::DryRun);
    assert_eq!(receipt.actor, "test_actor");
    assert_eq!(receipt.bead_id, Some("test_bead_123".to_string()));
    assert!(!receipt.receipt_id.is_empty());
    assert_eq!(receipt.operations.len(), 1);

    // Verify no actual deletion happened in dry-run
    assert!(test_files[0].exists());

    // Verify mock adapter wasn't called for dry-run
    let deletion_requests = lock_deletion_requests(&mock_adapter);
    assert!(deletion_requests.is_empty());

    // Verify receipt shows simulated success
    assert!(receipt.diagnostics.iter().any(|d| d.contains("DRY-RUN")));
    assert_eq!(receipt.operations[0].outcome, CleanupOutcome::WouldRemove);
    assert_eq!(receipt.summary.removed_count, 0);
    assert_eq!(receipt.bytes_freed, 0);
}

#[test]
fn test_cleanup_executor_with_protection_rules() {
    let temp_dir = TempDir::new().expect("temp dir");
    let test_files = create_test_files(&temp_dir);

    // Create protected source file
    let protected_file = temp_dir.path().join("src/protected.rs");
    fs::create_dir_all(protected_file.parent().unwrap()).expect("create src dir");
    fs::write(&protected_file, "protected source code").expect("write protected file");

    let mock_adapter = MockDeletionAdapter::default();
    let protection_rules = test_cleanup_rules();
    let executor = CleanupExecutor::with_protection_rules(protection_rules, mock_adapter);

    let candidates = vec![
        // This should be protected
        CleanupCandidate {
            path: protected_file.clone(),
            size_bytes: 512,
            reason: "Protected source file".to_string(),
            requires_approval: false,
            mtime: None,
        },
        // This should be allowed (non-protected)
        CleanupCandidate {
            path: test_files[3].clone(), // generated/artifacts/output.txt
            size_bytes: 1024,
            reason: "Generated artifact".to_string(),
            requires_approval: false,
            mtime: None,
        },
    ];

    let receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::Execute,
        "test_actor".to_string(),
        "Protection test".to_string(),
        None,
    );

    // Verify receipt shows mixed outcomes
    assert_eq!(receipt.operations.len(), 2);

    // Find operations by path
    let protected_op = receipt
        .operations
        .iter()
        .find(|op| op.path == protected_file)
        .expect("protected operation");
    let allowed_op = receipt
        .operations
        .iter()
        .find(|op| op.path == test_files[3])
        .expect("allowed operation");

    // Verify protected file was skipped
    assert_eq!(protected_op.outcome, CleanupOutcome::SkippedProtected);
    assert!(protected_op.reason.contains("Extension"));

    // Verify non-protected file was removed
    assert_eq!(allowed_op.outcome, CleanupOutcome::Removed);

    // Verify summary statistics
    assert_eq!(receipt.summary.total_candidates, 2);
    assert_eq!(receipt.summary.skipped_count, 1);
    assert_eq!(receipt.summary.removed_count, 1);
    assert_eq!(receipt.skipped_pins, 1);
}

#[test]
fn test_cleanup_executor_with_file_reservations() {
    let temp_dir = TempDir::new().expect("temp dir");
    let test_files = create_test_files(&temp_dir);

    let mock_adapter = MockDeletionAdapter::default();
    let mut executor = CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);

    // Mark one file as reserved
    let mut reservations = BTreeSet::new();
    reservations.insert(test_files[1].clone());
    executor.update_reservations(reservations);

    let candidates = vec![
        CleanupCandidate {
            path: test_files[1].clone(), // Reserved file
            size_bytes: 1024,
            reason: "Reserved file".to_string(),
            requires_approval: false,
            mtime: None,
        },
        CleanupCandidate {
            path: test_files[2].clone(), // Non-reserved file
            size_bytes: 2048,
            reason: "Non-reserved file".to_string(),
            requires_approval: false,
            mtime: None,
        },
    ];

    let receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::Execute,
        "reservation_test".to_string(),
        "File reservation test".to_string(),
        Some("reservation_bead".to_string()),
    );

    assert_eq!(receipt.operations.len(), 2);

    // Find operations
    let reserved_op = receipt
        .operations
        .iter()
        .find(|op| op.path == test_files[1])
        .expect("reserved operation");
    let non_reserved_op = receipt
        .operations
        .iter()
        .find(|op| op.path == test_files[2])
        .expect("non-reserved operation");

    // Verify reserved file was skipped
    assert_eq!(reserved_op.outcome, CleanupOutcome::SkippedReserved);
    assert!(reserved_op.reason.contains("reservation"));

    // Verify non-reserved file was removed
    assert_eq!(non_reserved_op.outcome, CleanupOutcome::Removed);

    // Verify summary
    assert_eq!(receipt.summary.skipped_count, 1);
    assert_eq!(receipt.summary.removed_count, 1);
    assert!(receipt.bytes_freed > 0);
    assert!(receipt.bytes_skipped > 0);
}

#[test]
fn test_cleanup_integration_with_workspace_pressure_policy() {
    let temp_dir = TempDir::new().expect("temp dir");
    let _test_files = create_test_files(&temp_dir);

    // Create workspace pressure policy to generate cleanup candidates
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let inputs = WorkspacePressureInputs {
        free_disk_bytes: 400_000_000,     // Below balanced cleanup threshold
        target_dir_bytes: 12_000_000_000, // Above balanced target-dir threshold
        active_build_count: 3,
        rch_available_slots: Some(2),
        memory_pressure: 0.7,
        active_reservations: 15,
        coordination_healthy: true,
    };

    let policy_decision = policy.decide_admission(
        frankenengine_node::ops::workspace_pressure_policy::WorkCostClass::Cleanup,
        2,
        &inputs,
    );

    // Policy should generate cleanup candidates due to pressure
    assert!(
        !policy_decision.cleanup_candidates.is_empty(),
        "Policy should generate cleanup candidates under pressure"
    );

    // Use cleanup executor to process the candidates
    let mock_adapter = MockDeletionAdapter::default();
    let executor =
        CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter.clone());

    let receipt = executor.execute_cleanup(
        &policy_decision.cleanup_candidates,
        CleanupMode::DryRun,
        "policy_integration".to_string(),
        policy_decision.summary.clone(),
        Some("policy_test_bead".to_string()),
    );

    // Verify integration worked
    assert_eq!(receipt.actor, "policy_integration");
    assert_eq!(receipt.approved_reason, policy_decision.summary);
    assert_eq!(
        receipt.operations.len(),
        policy_decision.cleanup_candidates.len()
    );
    assert!(receipt.diagnostics.iter().any(|d| d.contains("DRY-RUN")));
}

#[test]
fn test_cleanup_receipts_storage_integration() {
    let temp_dir = TempDir::new().expect("temp dir");
    let receipts_dir = temp_dir.path().join("receipts");

    let mut storage =
        CleanupReceiptsStorage::with_directory(receipts_dir).expect("create receipts storage");

    // Create and execute cleanup
    let mock_adapter = MockDeletionAdapter::default();
    let executor = CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);

    let candidates = vec![create_candidate(
        "/tmp/test_file.tmp",
        1024,
        "Test cleanup",
        false,
    )];

    let receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::Execute,
        "storage_test".to_string(),
        "Storage integration test".to_string(),
        Some("storage_bead".to_string()),
    );

    // Store receipt
    let file_path = storage.store_receipt(&receipt).expect("store receipt");
    assert!(file_path.exists());

    // Retrieve receipt
    let retrieved = storage
        .get_receipt(&receipt.receipt_id)
        .expect("retrieve receipt");
    assert_eq!(retrieved.receipt_id, receipt.receipt_id);
    assert_eq!(retrieved.actor, "storage_test");
    assert_eq!(retrieved.mode, CleanupMode::Execute);

    // Search receipts
    let filter = ReceiptSearchFilter {
        actor: Some("storage_test".to_string()),
        ..Default::default()
    };
    let search_results = storage.search_receipts(&filter);
    assert_eq!(search_results.len(), 1);
    assert_eq!(search_results[0].receipt_id, receipt.receipt_id);

    // Get statistics
    let stats = storage.get_statistics();
    assert_eq!(stats.total_receipts, 1);
    assert_eq!(stats.execute_receipts, 1);
    assert_eq!(stats.dry_run_receipts, 0);
}

#[cfg(feature = "test-support")]
#[test]
fn delete_receipt_rejects_index_path_escape_before_unlink() {
    let temp_dir = TempDir::new().expect("temp dir");
    let outside_dir = TempDir::new().expect("outside temp dir");
    let outside_file = outside_dir.path().join("outside-receipt.json");
    fs::write(&outside_file, "{}").expect("write outside file");

    let receipts_dir = temp_dir.path().join("receipts");
    let mut storage =
        CleanupReceiptsStorage::with_directory(receipts_dir).expect("create receipts storage");

    let mock_adapter = MockDeletionAdapter::default();
    let executor = CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);
    let candidates = vec![create_candidate(
        "/tmp/delete_escape.tmp",
        1024,
        "Test delete escape",
        false,
    )];
    let receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::Execute,
        "delete_escape_test".to_string(),
        "Delete escape regression".to_string(),
        Some("delete_escape_bead".to_string()),
    );
    storage.store_receipt(&receipt).expect("store receipt");
    storage
        .override_receipt_file_path_for_test(&receipt.receipt_id, outside_file.clone())
        .expect("override receipt path");

    let err = storage
        .delete_receipt(&receipt.receipt_id)
        .expect_err("escaped index path must fail before unlink");

    assert!(
        matches!(err, CleanupReceiptsError::Corruption(ref message) if message.contains("escapes")),
        "unexpected error: {err:?}"
    );
    assert!(
        outside_file.exists(),
        "escaped index path must not be removed by delete_receipt"
    );
}

#[test]
fn test_end_to_end_cleanup_workflow() {
    let temp_dir = TempDir::new().expect("temp dir");
    let test_files = create_test_files(&temp_dir);
    let receipts_dir = temp_dir.path().join("receipts");

    // Set up storage
    let mut storage = CleanupReceiptsStorage::with_directory(receipts_dir).expect("create storage");

    // Set up executor with real filesystem for this test
    let executor =
        CleanupExecutor::with_protection_rules(test_cleanup_rules(), FilesystemDeletionAdapter);

    // Create candidates for files that actually exist
    let candidates = vec![
        CleanupCandidate {
            path: test_files[3].clone(), // generated/artifacts/output.txt
            size_bytes: fs::metadata(&test_files[3]).unwrap().len(),
            reason: "Generated artifact cleanup".to_string(),
            requires_approval: false,
            mtime: None,
        },
        CleanupCandidate {
            path: test_files[4].clone(), // temp_build/intermediate.o
            size_bytes: fs::metadata(&test_files[4]).unwrap().len(),
            reason: "Build intermediate cleanup".to_string(),
            requires_approval: false,
            mtime: None,
        },
    ];

    // First do a dry run
    let dry_run_receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::DryRun,
        "e2e_test".to_string(),
        "End-to-end dry run".to_string(),
        Some("e2e_bead".to_string()),
    );

    assert_eq!(dry_run_receipt.mode, CleanupMode::DryRun);
    assert_eq!(dry_run_receipt.summary.total_candidates, 2);
    assert_eq!(dry_run_receipt.summary.removed_count, 0);
    assert_eq!(dry_run_receipt.bytes_freed, 0);
    assert!(
        dry_run_receipt
            .operations
            .iter()
            .all(|operation| operation.outcome == CleanupOutcome::WouldRemove)
    );

    // Files should still exist after dry run
    assert!(test_files[3].exists());
    assert!(test_files[4].exists());

    // Store dry run receipt
    storage
        .store_receipt(&dry_run_receipt)
        .expect("store dry run receipt");

    // Now do actual execution
    let execute_receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::Execute,
        "e2e_test".to_string(),
        "End-to-end execution".to_string(),
        Some("e2e_bead".to_string()),
    );

    assert_eq!(execute_receipt.mode, CleanupMode::Execute);
    assert_eq!(execute_receipt.summary.removed_count, 2);
    assert!(execute_receipt.bytes_freed > 0);

    // Files should be removed after execution
    assert!(!test_files[3].exists());
    assert!(!test_files[4].exists());

    // Store execution receipt
    storage
        .store_receipt(&execute_receipt)
        .expect("store execute receipt");

    // Verify we have both receipts in storage
    let all_receipts = storage.get_recent_receipts(10);
    assert_eq!(all_receipts.len(), 2);

    // Verify we can search by mode
    let dry_run_filter = ReceiptSearchFilter {
        mode: Some(CleanupMode::DryRun),
        ..Default::default()
    };
    let dry_run_results = storage.search_receipts(&dry_run_filter);
    assert_eq!(dry_run_results.len(), 1);

    let execute_filter = ReceiptSearchFilter {
        mode: Some(CleanupMode::Execute),
        ..Default::default()
    };
    let execute_results = storage.search_receipts(&execute_filter);
    assert_eq!(execute_results.len(), 1);

    // Generate audit report
    let audit_report =
        frankenengine_node::storage::cleanup_receipts::generate_cleanup_audit_report(&storage);
    assert!(audit_report.contains("# Cleanup Audit Report"));
    assert!(audit_report.contains("Total Receipts: 2"));
    assert!(audit_report.contains("Execute Operations: 1"));
    assert!(audit_report.contains("Dry-Run Operations: 1"));
    assert!(audit_report.contains("e2e_test"));
}

#[test]
fn test_candidate_digest_consistency() {
    let mock_adapter = MockDeletionAdapter::default();
    let executor = CleanupExecutor::with_adapter(mock_adapter);

    let candidates1 = vec![
        create_candidate("/path/a", 100, "First", false),
        create_candidate("/path/b", 200, "Second", false),
    ];

    let candidates2 = vec![
        create_candidate("/path/b", 200, "Second", false),
        create_candidate("/path/a", 100, "First", false),
    ];

    let receipt1 = executor.execute_cleanup(
        &candidates1,
        CleanupMode::DryRun,
        "digest_test".to_string(),
        "Digest test 1".to_string(),
        None,
    );

    let receipt2 = executor.execute_cleanup(
        &candidates2,
        CleanupMode::DryRun,
        "digest_test".to_string(),
        "Digest test 2".to_string(),
        None,
    );

    // Digests should be the same regardless of order
    assert_eq!(receipt1.candidates_digest, receipt2.candidates_digest);
}

#[test]
fn metamorphic_cleanup_execute_summary_survives_candidate_permutation() {
    let temp_dir = TempDir::new().expect("temp dir");
    let test_files = create_test_files(&temp_dir);
    let protected_file = temp_dir.path().join("src/protected.rs");
    fs::create_dir_all(protected_file.parent().expect("protected file parent"))
        .expect("create protected file parent");
    fs::write(&protected_file, "protected source code").expect("write protected file");
    let missing_file = temp_dir.path().join("target/debug/deps/missing.rlib");

    let candidates = vec![
        CleanupCandidate {
            path: test_files[3].clone(),
            size_bytes: fs::metadata(&test_files[3])
                .expect("generated artifact metadata")
                .len(),
            reason: "Generated artifact".to_string(),
            requires_approval: false,
            mtime: None,
        },
        CleanupCandidate {
            path: protected_file.clone(),
            size_bytes: fs::metadata(&protected_file)
                .expect("protected file metadata")
                .len(),
            reason: "Protected source file".to_string(),
            requires_approval: false,
            mtime: None,
        },
        CleanupCandidate {
            path: test_files[1].clone(),
            size_bytes: fs::metadata(&test_files[1])
                .expect("reserved artifact metadata")
                .len(),
            reason: "Reserved file".to_string(),
            requires_approval: false,
            mtime: None,
        },
        CleanupCandidate {
            path: test_files[4].clone(),
            size_bytes: fs::metadata(&test_files[4])
                .expect("build intermediate metadata")
                .len(),
            reason: "Build intermediate cleanup".to_string(),
            requires_approval: false,
            mtime: None,
        },
        CleanupCandidate {
            path: missing_file,
            size_bytes: 4096,
            reason: "Missing stale artifact".to_string(),
            requires_approval: false,
            mtime: None,
        },
    ];
    let mut reversed = candidates.clone();
    reversed.reverse();
    let reservations = BTreeSet::from([test_files[1].clone()]);

    let baseline =
        execute_cleanup_permutation_digest(temp_dir.path(), &candidates, reservations.clone());
    let transformed = execute_cleanup_permutation_digest(temp_dir.path(), &reversed, reservations);

    assert_eq!(transformed, baseline);
    assert_eq!(baseline.total_candidates, 5);
    assert_eq!(baseline.removed_count, 2);
    assert_eq!(baseline.skipped_count, 2);
    assert_eq!(baseline.failed_count, 0);
    assert!(baseline.bytes_freed > 0);
    assert!(baseline.bytes_skipped > 0);
    assert_eq!(baseline.skipped_pins, 1);
    assert_eq!(
        baseline.deletion_requests,
        BTreeSet::from([
            "generated/artifacts/output.txt".to_string(),
            "temp_build/intermediate.o".to_string(),
        ])
    );
    assert_eq!(
        baseline
            .outcomes_by_path
            .get("generated/artifacts/output.txt"),
        Some(&CleanupOutcome::Removed)
    );
    assert_eq!(
        baseline.outcomes_by_path.get("temp_build/intermediate.o"),
        Some(&CleanupOutcome::Removed)
    );
    assert_eq!(
        baseline.outcomes_by_path.get("src/protected.rs"),
        Some(&CleanupOutcome::SkippedProtected)
    );
    assert_eq!(
        baseline
            .outcomes_by_path
            .get("target/debug/deps/test2.rlib"),
        Some(&CleanupOutcome::SkippedReserved)
    );
    assert_eq!(
        baseline
            .outcomes_by_path
            .get("target/debug/deps/missing.rlib"),
        Some(&CleanupOutcome::NotFound)
    );
}

#[test]
fn test_cleanup_with_missing_files() {
    let mock_adapter = MockDeletionAdapter::default();
    let executor = CleanupExecutor::with_adapter(mock_adapter);

    let candidates = vec![
        create_candidate("/nonexistent/file1.tmp", 1024, "Missing file", false),
        create_candidate(
            "/nonexistent/file2.tmp",
            2048,
            "Another missing file",
            false,
        ),
    ];

    let receipt = executor.execute_cleanup(
        &candidates,
        CleanupMode::Execute,
        "missing_test".to_string(),
        "Missing files test".to_string(),
        None,
    );

    assert_eq!(receipt.operations.len(), 2);

    // All operations should show NotFound outcome
    for operation in &receipt.operations {
        assert_eq!(operation.outcome, CleanupOutcome::NotFound);
        assert!(operation.reason.contains("not exist"));
    }

    assert_eq!(receipt.summary.removed_count, 0);
    assert_eq!(receipt.bytes_freed, 0);
}
