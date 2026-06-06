//! bd-p9mpd.7: Audited cleanup executor for approved generated artifacts.
//!
//! Provides safe, auditable execution of workspace cleanup operations with
//! detailed receipts, dry-run support, and protection against destructive actions.

use crate::ops::workspace_pressure_policy::{CleanupCandidate, PolicyDecision};
use crate::push_bounded;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Maximum cleanup operations to record in one receipt.
const MAX_CLEANUP_OPERATIONS: usize = 1000;

/// Maximum diagnostic messages per cleanup receipt.
const MAX_CLEANUP_DIAGNOSTICS: usize = 100;

/// Minimum age threshold for cleanup eligibility (24 hours).
const MIN_CLEANUP_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Cleanup execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanupMode {
    /// Report-only mode: analyze candidates but don't remove anything.
    DryRun,
    /// Execute mode: actually remove approved artifacts.
    Execute,
}

/// Outcome of a cleanup operation on a single path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanupOutcome {
    /// Path was successfully removed.
    Removed,
    /// Path would be removed in dry-run mode.
    WouldRemove,
    /// Path was skipped due to protection rules.
    SkippedProtected,
    /// Path was skipped due to active file reservations.
    SkippedReserved,
    /// Path was skipped due to being too young.
    SkippedTooYoung,
    /// Path was skipped due to being an open file.
    SkippedOpenFile,
    /// Path was not found or already removed.
    NotFound,
    /// Path removal failed with error.
    Failed,
}

impl CleanupOutcome {
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Removed)
    }

    #[must_use]
    pub const fn is_skipped(self) -> bool {
        matches!(
            self,
            Self::SkippedProtected
                | Self::SkippedReserved
                | Self::SkippedTooYoung
                | Self::SkippedOpenFile
        )
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "REMOVED",
            Self::WouldRemove => "WOULD_REMOVE",
            Self::SkippedProtected => "SKIPPED_PROTECTED",
            Self::SkippedReserved => "SKIPPED_RESERVED",
            Self::SkippedTooYoung => "SKIPPED_TOO_YOUNG",
            Self::SkippedOpenFile => "SKIPPED_OPEN_FILE",
            Self::NotFound => "NOT_FOUND",
            Self::Failed => "FAILED",
        }
    }
}

/// Cleanup operation record for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupOperation {
    /// Path that was targeted for cleanup.
    pub path: PathBuf,
    /// Size of the file/directory in bytes.
    pub size_bytes: u64,
    /// Age of the artifact in seconds.
    pub age_seconds: u64,
    /// Outcome of the cleanup attempt.
    pub outcome: CleanupOutcome,
    /// Reason for the outcome.
    pub reason: String,
    /// Error message if the operation failed.
    pub error: Option<String>,
    /// Timestamp when the operation was attempted.
    pub timestamp: DateTime<Utc>,
}

/// Complete audit receipt for a cleanup execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupReceipt {
    /// Schema version for compatibility.
    pub schema_version: String,
    /// Unique receipt ID for this cleanup execution.
    pub receipt_id: String,
    /// Mode used for this cleanup (dry-run or execute).
    pub mode: CleanupMode,
    /// Digest of the cleanup candidate list.
    pub candidates_digest: String,
    /// Reason for approving this cleanup.
    pub approved_reason: String,
    /// Agent/actor that initiated the cleanup.
    pub actor: String,
    /// Bead ID that requested the cleanup.
    pub bead_id: Option<String>,
    /// Timestamp when cleanup was initiated.
    pub initiated_at: DateTime<Utc>,
    /// Timestamp when cleanup completed.
    pub completed_at: DateTime<Utc>,
    /// Individual cleanup operations performed.
    pub operations: Vec<CleanupOperation>,
    /// Total bytes that were freed.
    pub bytes_freed: u64,
    /// Total bytes that were skipped due to protections.
    pub bytes_skipped: u64,
    /// Number of protected pins that blocked cleanup.
    pub skipped_pins: usize,
    /// Diagnostic messages from the cleanup process.
    pub diagnostics: Vec<String>,
    /// Summary statistics.
    pub summary: CleanupSummary,
}

/// Summary statistics for a cleanup execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupSummary {
    /// Total number of candidates evaluated.
    pub total_candidates: usize,
    /// Number of paths successfully removed.
    pub removed_count: usize,
    /// Number of paths skipped due to protections.
    pub skipped_count: usize,
    /// Number of operations that failed.
    pub failed_count: usize,
    /// Overall success rate (0.0-1.0).
    pub success_rate: f32,
}

/// Protection rules for cleanup safety.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupProtectionRules {
    /// File extensions that are protected from cleanup.
    pub protected_extensions: BTreeSet<String>,
    /// Path patterns that are protected from cleanup.
    pub protected_patterns: Vec<String>,
    /// Directories that should never be cleaned.
    pub protected_directories: BTreeSet<PathBuf>,
    /// Minimum age before a file is eligible for cleanup.
    pub min_age_seconds: u64,
}

impl Default for CleanupProtectionRules {
    fn default() -> Self {
        let mut protected_extensions = BTreeSet::new();
        protected_extensions.insert(".rs".to_string());
        protected_extensions.insert(".toml".to_string());
        protected_extensions.insert(".md".to_string());
        protected_extensions.insert(".json".to_string());
        protected_extensions.insert(".lock".to_string());

        let protected_patterns = vec![
            "src/**".to_string(),
            "tests/**".to_string(),
            "Cargo.toml".to_string(),
            "Cargo.lock".to_string(),
            ".git/**".to_string(),
            "*.rs".to_string(),
        ];

        let mut protected_directories = BTreeSet::new();
        protected_directories.insert(PathBuf::from("src"));
        protected_directories.insert(PathBuf::from("tests"));
        protected_directories.insert(PathBuf::from(".git"));

        Self {
            protected_extensions,
            protected_patterns,
            protected_directories,
            min_age_seconds: MIN_CLEANUP_AGE_SECONDS,
        }
    }
}

/// File deletion adapter trait for isolation and testing.
pub trait FileDeletionAdapter {
    /// Remove a file, returning success/failure.
    fn remove_file(&self, path: &Path) -> Result<(), std::io::Error>;

    /// Remove a directory and all its contents.
    fn remove_dir_all(&self, path: &Path) -> Result<(), std::io::Error>;

    /// Check if a path exists.
    fn exists(&self, path: &Path) -> bool;

    /// Get metadata for a path.
    fn metadata(&self, path: &Path) -> Result<std::fs::Metadata, std::io::Error>;
}

/// Standard filesystem deletion adapter.
pub struct FilesystemDeletionAdapter;

impl FileDeletionAdapter for FilesystemDeletionAdapter {
    fn remove_file(&self, path: &Path) -> Result<(), std::io::Error> {
        fs::remove_file(path)
    }

    fn remove_dir_all(&self, path: &Path) -> Result<(), std::io::Error> {
        fs::remove_dir_all(path)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn metadata(&self, path: &Path) -> Result<std::fs::Metadata, std::io::Error> {
        fs::metadata(path)
    }
}

/// Mock deletion adapter for testing (tracks operations without deleting).
#[derive(Debug, Clone, Default)]
pub struct MockDeletionAdapter {
    /// Paths that were requested for deletion.
    pub deletion_requests: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>>,
}

impl FileDeletionAdapter for MockDeletionAdapter {
    fn remove_file(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Ok(mut requests) = self.deletion_requests.lock() {
            requests.push(path.to_path_buf());
        }
        Ok(()) // Always succeed in mock mode
    }

    fn remove_dir_all(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Ok(mut requests) = self.deletion_requests.lock() {
            requests.push(path.to_path_buf());
        }
        Ok(()) // Always succeed in mock mode
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists() // Use real filesystem for existence checks
    }

    fn metadata(&self, path: &Path) -> Result<std::fs::Metadata, std::io::Error> {
        fs::metadata(path) // Use real filesystem for metadata
    }
}

/// Audited cleanup executor with safety protections.
pub struct CleanupExecutor<T: FileDeletionAdapter> {
    /// Protection rules for safe cleanup.
    protection_rules: CleanupProtectionRules,
    /// File deletion adapter.
    deletion_adapter: T,
    /// Current active file reservations.
    active_reservations: BTreeSet<PathBuf>,
}

impl CleanupExecutor<FilesystemDeletionAdapter> {
    /// Create new executor with default filesystem adapter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            protection_rules: CleanupProtectionRules::default(),
            deletion_adapter: FilesystemDeletionAdapter,
            active_reservations: BTreeSet::new(),
        }
    }
}

impl<T: FileDeletionAdapter> CleanupExecutor<T> {
    /// Create executor with custom deletion adapter.
    #[must_use]
    pub fn with_adapter(deletion_adapter: T) -> Self {
        Self {
            protection_rules: CleanupProtectionRules::default(),
            deletion_adapter,
            active_reservations: BTreeSet::new(),
        }
    }

    /// Create executor with custom protection rules.
    #[must_use]
    pub fn with_protection_rules(
        protection_rules: CleanupProtectionRules,
        deletion_adapter: T,
    ) -> Self {
        Self {
            protection_rules,
            deletion_adapter,
            active_reservations: BTreeSet::new(),
        }
    }

    /// Update the active file reservations.
    pub fn update_reservations(&mut self, reservations: BTreeSet<PathBuf>) {
        self.active_reservations = reservations;
    }

    /// Execute cleanup on approved candidates with audit receipt.
    pub fn execute_cleanup(
        &self,
        candidates: &[CleanupCandidate],
        mode: CleanupMode,
        actor: String,
        approved_reason: String,
        bead_id: Option<String>,
    ) -> CleanupReceipt {
        let initiated_at = Utc::now();
        let receipt_id = format!("cleanup_{}", initiated_at.format("%Y%m%d_%H%M%S_%f"));
        let candidates_digest = self.compute_candidates_digest(candidates);

        let mut operations = Vec::new();
        let mut diagnostics = Vec::new();
        let mut bytes_freed = 0u64;
        let mut bytes_skipped = 0u64;
        let mut skipped_pins = 0usize;

        push_bounded(
            &mut diagnostics,
            format!(
                "Starting cleanup: mode={:?}, candidates={}",
                mode,
                candidates.len()
            ),
            MAX_CLEANUP_DIAGNOSTICS,
        );

        for candidate in candidates {
            let operation = self.process_candidate(candidate, mode, &mut diagnostics);

            match operation.outcome {
                CleanupOutcome::Removed => {
                    bytes_freed = bytes_freed.saturating_add(operation.size_bytes);
                }
                outcome if outcome.is_skipped() => {
                    bytes_skipped = bytes_skipped.saturating_add(operation.size_bytes);
                    if outcome == CleanupOutcome::SkippedProtected {
                        skipped_pins = skipped_pins.saturating_add(1);
                    }
                }
                _ => {}
            }

            push_bounded(&mut operations, operation, MAX_CLEANUP_OPERATIONS);
        }

        let completed_at = Utc::now();

        // Calculate summary statistics
        let total_candidates = candidates.len();
        let removed_count = operations
            .iter()
            .filter(|op| op.outcome.is_success())
            .count();
        let skipped_count = operations
            .iter()
            .filter(|op| op.outcome.is_skipped())
            .count();
        let failed_count = operations
            .iter()
            .filter(|op| op.outcome == CleanupOutcome::Failed)
            .count();
        let success_rate = if total_candidates > 0 {
            removed_count as f32 / total_candidates as f32
        } else {
            1.0
        };

        let summary = CleanupSummary {
            total_candidates,
            removed_count,
            skipped_count,
            failed_count,
            success_rate,
        };

        push_bounded(
            &mut diagnostics,
            format!(
                "Cleanup complete: {} removed, {} skipped, {} failed",
                removed_count, skipped_count, failed_count
            ),
            MAX_CLEANUP_DIAGNOSTICS,
        );

        CleanupReceipt {
            schema_version: "franken-node/cleanup-executor/v1".to_string(),
            receipt_id,
            mode,
            candidates_digest,
            approved_reason,
            actor,
            bead_id,
            initiated_at,
            completed_at,
            operations,
            bytes_freed,
            bytes_skipped,
            skipped_pins,
            diagnostics,
            summary,
        }
    }

    fn process_candidate(
        &self,
        candidate: &CleanupCandidate,
        mode: CleanupMode,
        diagnostics: &mut Vec<String>,
    ) -> CleanupOperation {
        let timestamp = Utc::now();
        let path = &candidate.path;

        if path_has_parent_traversal(path) {
            return CleanupOperation {
                path: path.clone(),
                size_bytes: 0,
                age_seconds: 0,
                outcome: CleanupOutcome::SkippedProtected,
                reason: "Path contains parent traversal".to_string(),
                error: None,
                timestamp,
            };
        }

        // Check if path exists
        if !self.deletion_adapter.exists(path) {
            return CleanupOperation {
                path: path.clone(),
                size_bytes: 0,
                age_seconds: 0,
                outcome: CleanupOutcome::NotFound,
                reason: "Path does not exist".to_string(),
                error: None,
                timestamp,
            };
        }

        // Get metadata for size and age
        let metadata = match self.deletion_adapter.metadata(path) {
            Ok(metadata) => metadata,
            Err(err) => {
                return CleanupOperation {
                    path: path.clone(),
                    size_bytes: 0,
                    age_seconds: 0,
                    outcome: CleanupOutcome::Failed,
                    reason: "Failed to read metadata".to_string(),
                    error: Some(err.to_string()),
                    timestamp,
                };
            }
        };

        let size_bytes = metadata.len();
        let age_seconds = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        // Apply protection checks
        if let Some((outcome, reason)) = self.check_protections(path, age_seconds) {
            return CleanupOperation {
                path: path.clone(),
                size_bytes,
                age_seconds,
                outcome,
                reason,
                error: None,
                timestamp,
            };
        }

        // In dry-run mode, don't actually delete
        if mode == CleanupMode::DryRun {
            push_bounded(
                diagnostics,
                format!(
                    "DRY-RUN: Would remove {} ({} bytes)",
                    path.display(),
                    size_bytes
                ),
                MAX_CLEANUP_DIAGNOSTICS,
            );
            return CleanupOperation {
                path: path.clone(),
                size_bytes,
                age_seconds,
                outcome: CleanupOutcome::WouldRemove,
                reason: "Dry-run simulation".to_string(),
                error: None,
                timestamp,
            };
        }

        // Execute actual deletion
        let deletion_result = if metadata.is_dir() {
            self.deletion_adapter.remove_dir_all(path)
        } else {
            self.deletion_adapter.remove_file(path)
        };

        match deletion_result {
            Ok(()) => {
                push_bounded(
                    diagnostics,
                    format!("Removed {} ({} bytes)", path.display(), size_bytes),
                    MAX_CLEANUP_DIAGNOSTICS,
                );
                CleanupOperation {
                    path: path.clone(),
                    size_bytes,
                    age_seconds,
                    outcome: CleanupOutcome::Removed,
                    reason: "Successfully removed".to_string(),
                    error: None,
                    timestamp,
                }
            }
            Err(err) => {
                push_bounded(
                    diagnostics,
                    format!("Failed to remove {}: {}", path.display(), err),
                    MAX_CLEANUP_DIAGNOSTICS,
                );
                CleanupOperation {
                    path: path.clone(),
                    size_bytes,
                    age_seconds,
                    outcome: CleanupOutcome::Failed,
                    reason: "Deletion failed".to_string(),
                    error: Some(err.to_string()),
                    timestamp,
                }
            }
        }
    }

    fn check_protections(&self, path: &Path, age_seconds: u64) -> Option<(CleanupOutcome, String)> {
        // Check protected extensions
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str())
            && self
                .protection_rules
                .protected_extensions
                .contains(&format!(".{}", extension))
        {
            return Some((
                CleanupOutcome::SkippedProtected,
                format!("Extension .{} is protected", extension),
            ));
        }

        // Check protected directories
        for protected_dir in &self.protection_rules.protected_directories {
            if path.starts_with(protected_dir) || path_has_component(path, protected_dir) {
                return Some((
                    CleanupOutcome::SkippedProtected,
                    format!(
                        "Path is in protected directory: {}",
                        protected_dir.display()
                    ),
                ));
            }
        }

        // Check protected patterns (simplified pattern matching)
        let path_str = path.to_string_lossy();
        for pattern in &self.protection_rules.protected_patterns {
            if self.matches_pattern(&path_str, pattern) {
                return Some((
                    CleanupOutcome::SkippedProtected,
                    format!("Path matches protected pattern: {}", pattern),
                ));
            }
        }

        // Check active file reservations
        if self
            .active_reservations
            .iter()
            .any(|reservation| paths_overlap_by_component(path, reservation))
        {
            return Some((
                CleanupOutcome::SkippedReserved,
                "Path has active file reservation".to_string(),
            ));
        }

        // Check age threshold after hard protection gates so receipts preserve the
        // strongest reason a path was refused.
        if age_seconds < self.protection_rules.min_age_seconds {
            return Some((
                CleanupOutcome::SkippedTooYoung,
                format!(
                    "File is {} seconds old, minimum age is {} seconds",
                    age_seconds, self.protection_rules.min_age_seconds
                ),
            ));
        }

        None // No protection rules triggered
    }

    fn matches_pattern(&self, path: &str, pattern: &str) -> bool {
        // Simplified glob pattern matching
        if pattern.contains("**") {
            let prefix = pattern.split("**").next().unwrap_or("");
            path.starts_with(prefix)
        } else if let Some(extension) = pattern
            .strip_prefix('*')
            .filter(|suffix| suffix.starts_with('.'))
        {
            path.ends_with(extension)
        } else {
            path.contains(pattern) || path == pattern
        }
    }

    fn compute_candidates_digest(&self, candidates: &[CleanupCandidate]) -> String {
        let mut hasher = Sha256::new();

        let mut candidates: Vec<&CleanupCandidate> = candidates.iter().collect();
        candidates.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.size_bytes.cmp(&right.size_bytes))
                .then_with(|| left.reason.cmp(&right.reason))
        });

        hasher.update(len_to_u64(candidates.len()).to_be_bytes());
        for candidate in candidates {
            update_digest_field(&mut hasher, &candidate.path.to_string_lossy());
            hasher.update(candidate.size_bytes.to_be_bytes());
            update_digest_field(&mut hasher, &candidate.reason);
            hasher.update([u8::from(candidate.requires_approval)]);
            match candidate.mtime.as_deref() {
                Some(mtime) => {
                    hasher.update([1]);
                    update_digest_field(&mut hasher, mtime);
                }
                None => hasher.update([0]),
            }
        }

        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

fn path_has_component(path: &Path, protected_dir: &Path) -> bool {
    let Some(protected_name) = protected_dir.file_name() else {
        return false;
    };

    path.components().any(|component| match component {
        Component::Normal(name) => name == protected_name,
        _ => false,
    })
}

fn paths_overlap_by_component(path: &Path, reservation: &Path) -> bool {
    if path.as_os_str().is_empty() || reservation.as_os_str().is_empty() {
        return false;
    }

    path.starts_with(reservation) || reservation.starts_with(path)
}

fn path_has_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

fn update_digest_field(hasher: &mut Sha256, value: &str) {
    hasher.update(len_to_u64(value.len()).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn len_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

impl Default for CleanupExecutor<FilesystemDeletionAdapter> {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert cleanup candidates from policy decision to execution format.
pub fn extract_cleanup_candidates_from_policy(
    policy_decision: &PolicyDecision,
) -> Vec<CleanupCandidate> {
    policy_decision.cleanup_candidates.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn create_test_candidate(path: &str, size: u64, reason: &str) -> CleanupCandidate {
        CleanupCandidate {
            path: PathBuf::from(path),
            size_bytes: size,
            reason: reason.to_string(),
            requires_approval: false,
            mtime: None,
        }
    }

    fn test_cleanup_rules() -> CleanupProtectionRules {
        let mut rules = CleanupProtectionRules::default();
        rules.min_age_seconds = 0;
        rules
    }

    #[test]
    fn test_dry_run_mode() {
        let mock_adapter = MockDeletionAdapter::default();
        let executor = CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let test_file = temp_dir.path().join("test_file.tmp");
        std::fs::write(&test_file, "dry run").expect("write test file");

        let candidates = vec![create_test_candidate(
            &test_file.to_string_lossy(),
            1024,
            "Test cleanup",
        )];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::DryRun,
            "test_actor".to_string(),
            "Test dry run".to_string(),
            Some("test_bead".to_string()),
        );

        assert_eq!(receipt.mode, CleanupMode::DryRun);
        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(receipt.operations[0].outcome, CleanupOutcome::WouldRemove);
        assert_eq!(receipt.summary.removed_count, 0);
        assert_eq!(receipt.bytes_freed, 0);
        assert_eq!(receipt.summary.total_candidates, 1);
        assert!(receipt.diagnostics.iter().any(|d| d.contains("DRY-RUN")));
    }

    #[test]
    fn test_protection_rules_extension() {
        let mock_adapter = MockDeletionAdapter::default();
        let executor = CleanupExecutor::with_adapter(mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let source_file = temp_dir.path().join("src/main.rs");
        std::fs::create_dir_all(source_file.parent().expect("source parent"))
            .expect("create source dir");
        std::fs::write(&source_file, "fn main() {}").expect("write source file");

        let candidates = vec![create_test_candidate(
            &source_file.to_string_lossy(),
            1024,
            "Protected source file",
        )];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test protection".to_string(),
            None,
        );

        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(
            receipt.operations[0].outcome,
            CleanupOutcome::SkippedProtected
        );
        assert!(receipt.operations[0].reason.contains("Extension"));
        assert_eq!(receipt.summary.skipped_count, 1);
        assert_eq!(receipt.skipped_pins, 1);
    }

    #[test]
    fn test_protection_rules_directory() {
        let mock_adapter = MockDeletionAdapter::default();
        let executor = CleanupExecutor::with_adapter(mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let source_file = temp_dir.path().join("src/subdir/file.txt");
        std::fs::create_dir_all(source_file.parent().expect("source parent"))
            .expect("create source dir");
        std::fs::write(&source_file, "source tree content").expect("write source file");

        let candidates = vec![create_test_candidate(
            &source_file.to_string_lossy(),
            1024,
            "File in protected directory",
        )];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test directory protection".to_string(),
            None,
        );

        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(
            receipt.operations[0].outcome,
            CleanupOutcome::SkippedProtected
        );
        assert!(receipt.operations[0].reason.contains("protected directory"));
    }

    #[test]
    fn test_active_reservations() {
        let mock_adapter = MockDeletionAdapter::default();
        let mut executor = CleanupExecutor::with_adapter(mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let reserved_path = temp_dir.path().join("reserved_file.tmp");
        std::fs::write(&reserved_path, "reserved").expect("write reserved file");

        let mut reservations = BTreeSet::new();
        reservations.insert(reserved_path.clone());
        executor.update_reservations(reservations);

        let candidates = vec![CleanupCandidate {
            path: reserved_path,
            size_bytes: 1024,
            reason: "Reserved file".to_string(),
            requires_approval: false,
            mtime: None,
        }];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test reservations".to_string(),
            None,
        );

        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(
            receipt.operations[0].outcome,
            CleanupOutcome::SkippedReserved
        );
        assert!(receipt.operations[0].reason.contains("reservation"));
    }

    #[test]
    fn test_active_reservations_block_nested_paths() {
        let mock_adapter = MockDeletionAdapter::default();
        let mut executor = CleanupExecutor::with_adapter(mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let reserved_dir = temp_dir.path().join("reserved-dir");
        let nested_path = reserved_dir.join("nested.tmp");
        std::fs::create_dir_all(&reserved_dir).expect("create reserved dir");
        std::fs::write(&nested_path, "reserved").expect("write nested reserved file");

        let mut reservations = BTreeSet::new();
        reservations.insert(reserved_dir);
        executor.update_reservations(reservations);

        let candidates = vec![CleanupCandidate {
            path: nested_path,
            size_bytes: 1024,
            reason: "Nested reserved file".to_string(),
            requires_approval: false,
            mtime: None,
        }];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test nested reservations".to_string(),
            None,
        );

        assert_eq!(
            receipt.operations[0].outcome,
            CleanupOutcome::SkippedReserved
        );
    }

    #[test]
    fn test_active_reservations_use_path_component_boundaries() {
        let mock_adapter = MockDeletionAdapter::default();
        let mut executor =
            CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let reserved_path = temp_dir.path().join("reserved");
        let sibling_path = temp_dir.path().join("reserved-sibling.tmp");
        std::fs::write(&sibling_path, "reclaimable").expect("write sibling file");

        let mut reservations = BTreeSet::new();
        reservations.insert(reserved_path);
        executor.update_reservations(reservations);

        let candidates = vec![CleanupCandidate {
            path: sibling_path,
            size_bytes: 1024,
            reason: "Sibling prefix should not be reserved".to_string(),
            requires_approval: false,
            mtime: None,
        }];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test reservation component boundaries".to_string(),
            None,
        );

        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(receipt.operations[0].outcome, CleanupOutcome::Removed);
    }

    #[test]
    fn test_empty_active_reservation_entries_do_not_block_cleanup() {
        let mock_adapter = MockDeletionAdapter::default();
        let mut executor =
            CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let reclaimable_path = temp_dir.path().join("reclaimable.tmp");
        std::fs::write(&reclaimable_path, "reclaimable").expect("write reclaimable file");

        let mut reservations = BTreeSet::new();
        reservations.insert(PathBuf::new());
        executor.update_reservations(reservations);

        let candidates = vec![CleanupCandidate {
            path: reclaimable_path,
            size_bytes: 1024,
            reason: "Empty reservation should not block".to_string(),
            requires_approval: false,
            mtime: None,
        }];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test empty reservation".to_string(),
            None,
        );

        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(receipt.operations[0].outcome, CleanupOutcome::Removed);
    }

    #[test]
    fn test_parent_traversal_candidates_are_skipped_before_deletion() {
        let mock_adapter = MockDeletionAdapter::default();
        let deletion_requests = mock_adapter.deletion_requests.clone();
        let executor = CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);
        let temp_dir = TempDir::new().expect("temp dir");
        let subdir = temp_dir.path().join("subdir");
        let target_path = temp_dir.path().join("victim.tmp");
        let traversal_path = subdir.join("..").join("victim.tmp");
        std::fs::create_dir_all(&subdir).expect("create subdir");
        std::fs::write(&target_path, "must not be touched").expect("write target");

        let candidates = vec![CleanupCandidate {
            path: traversal_path,
            size_bytes: 1024,
            reason: "Traversal candidate should be refused".to_string(),
            requires_approval: false,
            mtime: None,
        }];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test traversal candidate".to_string(),
            None,
        );

        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(
            receipt.operations[0].outcome,
            CleanupOutcome::SkippedProtected
        );
        assert!(receipt.operations[0].reason.contains("parent traversal"));
        assert!(target_path.exists());
        assert!(deletion_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn test_star_patterns_without_extension_are_not_global_wildcards() {
        let mock_adapter = MockDeletionAdapter::default();
        let executor = CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);

        assert!(executor.matches_pattern("/tmp/build/reclaimable.tmp", "*.tmp"));
        assert!(!executor.matches_pattern("/tmp/build/reclaimable.tmp", "*"));
        assert!(!executor.matches_pattern("/tmp/build/reclaimable.tmp", "*tmp"));
    }

    #[test]
    fn test_cleanup_receipt_structure() {
        let mock_adapter = MockDeletionAdapter::default();
        let executor = CleanupExecutor::with_adapter(mock_adapter);

        let candidates = vec![create_test_candidate(
            "/nonexistent/file",
            1024,
            "Test structure",
        )];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::DryRun,
            "test_actor".to_string(),
            "Test receipt structure".to_string(),
            Some("test_bead_id".to_string()),
        );

        // Verify receipt structure
        assert!(!receipt.receipt_id.is_empty());
        assert_eq!(receipt.schema_version, "franken-node/cleanup-executor/v1");
        assert_eq!(receipt.actor, "test_actor");
        assert_eq!(receipt.approved_reason, "Test receipt structure");
        assert_eq!(receipt.bead_id, Some("test_bead_id".to_string()));
        assert!(!receipt.candidates_digest.is_empty());
        assert!(receipt.candidates_digest.starts_with("sha256:"));
        assert_eq!(receipt.candidates_digest.len(), "sha256:".len() + 64);
        assert_eq!(receipt.summary.total_candidates, 1);
        assert!(receipt.initiated_at <= receipt.completed_at);
    }

    #[test]
    fn test_candidates_digest_consistency() {
        let mock_adapter = MockDeletionAdapter::default();
        let executor = CleanupExecutor::with_adapter(mock_adapter);

        let candidates1 = vec![
            create_test_candidate("/path/a", 100, "First"),
            create_test_candidate("/path/b", 200, "Second"),
        ];

        let candidates2 = vec![
            create_test_candidate("/path/b", 200, "Second"),
            create_test_candidate("/path/a", 100, "First"),
        ];

        let digest1 = executor.compute_candidates_digest(&candidates1);
        let digest2 = executor.compute_candidates_digest(&candidates2);

        // Digests should be the same regardless of order
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_mock_adapter_tracking() {
        let mock_adapter = MockDeletionAdapter::default();
        let deletion_requests = Arc::clone(&mock_adapter.deletion_requests);
        let executor = CleanupExecutor::with_protection_rules(test_cleanup_rules(), mock_adapter);

        // Create temp file for test
        let temp_dir = TempDir::new().expect("temp dir");
        let test_file = temp_dir.path().join("test.tmp");
        std::fs::write(&test_file, "test content").expect("write test file");

        let candidates = vec![CleanupCandidate {
            path: test_file.clone(),
            size_bytes: 12,
            reason: "Mock test".to_string(),
            requires_approval: false,
            mtime: None,
        }];

        let receipt = executor.execute_cleanup(
            &candidates,
            CleanupMode::Execute,
            "test_actor".to_string(),
            "Test mock tracking".to_string(),
            None,
        );

        // Verify the mock adapter tracked the deletion request
        let requests = crate::lock_utils::try_lock(
            deletion_requests.as_ref(),
            "cleanup executor mock deletion requests",
        )
        .expect("cleanup executor mock deletion requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0], test_file);

        // Verify receipt shows success
        assert_eq!(receipt.operations.len(), 1);
        assert_eq!(receipt.operations[0].outcome, CleanupOutcome::Removed);
        assert_eq!(receipt.bytes_freed, 12);
    }
}
