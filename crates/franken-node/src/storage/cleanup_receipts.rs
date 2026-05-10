//! Storage and persistence for cleanup execution receipts (bd-p9mpd.7).
//!
//! Provides durable audit trail for cleanup operations with retrieval and
//! search capabilities for compliance and forensics.

use crate::ops::cleanup_executor::{CleanupMode, CleanupReceipt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Maximum receipts to return in search results.
const MAX_RECEIPT_SEARCH_RESULTS: usize = 1000;

/// Maximum receipts to track in index.
const MAX_RECEIPT_INDEX_SIZE: usize = 10000;

/// Default cleanup receipts storage directory.
pub const DEFAULT_RECEIPTS_DIR: &str = "cleanup_receipts";

/// Storage error for cleanup receipts operations.
#[derive(Debug, thiserror::Error)]
pub enum CleanupReceiptsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Receipt not found: {0}")]
    ReceiptNotFound(String),
    #[error("Invalid receipt format: {0}")]
    InvalidFormat(String),
    #[error("Storage corruption: {0}")]
    Corruption(String),
}

/// Receipt storage metadata for indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptMetadata {
    /// Receipt ID.
    pub receipt_id: String,
    /// Cleanup mode (dry-run or execute).
    pub mode: CleanupMode,
    /// Actor who initiated the cleanup.
    pub actor: String,
    /// Bead ID associated with cleanup.
    pub bead_id: Option<String>,
    /// When cleanup was initiated.
    pub initiated_at: DateTime<Utc>,
    /// When cleanup completed.
    pub completed_at: DateTime<Utc>,
    /// Number of operations in the receipt.
    pub operation_count: usize,
    /// Total bytes freed by the cleanup.
    pub bytes_freed: u64,
    /// Overall success rate of operations.
    pub success_rate: f32,
    /// File path where receipt is stored.
    pub file_path: PathBuf,
}

/// Receipt storage index for efficient searching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptIndex {
    /// Schema version for index format.
    pub schema_version: String,
    /// When the index was last updated.
    pub last_updated: DateTime<Utc>,
    /// Metadata for all stored receipts.
    pub receipts: BTreeMap<String, ReceiptMetadata>,
}

impl Default for ReceiptIndex {
    fn default() -> Self {
        Self {
            schema_version: "franken-node/cleanup-receipts-index/v1".to_string(),
            last_updated: Utc::now(),
            receipts: BTreeMap::new(),
        }
    }
}

/// Search filters for cleanup receipts.
#[derive(Debug, Clone, Default)]
pub struct ReceiptSearchFilter {
    /// Filter by actor name.
    pub actor: Option<String>,
    /// Filter by bead ID.
    pub bead_id: Option<String>,
    /// Filter by cleanup mode.
    pub mode: Option<CleanupMode>,
    /// Filter by minimum timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Filter by maximum timestamp.
    pub until: Option<DateTime<Utc>>,
    /// Filter by minimum bytes freed.
    pub min_bytes_freed: Option<u64>,
    /// Filter by minimum success rate.
    pub min_success_rate: Option<f32>,
}

/// Cleanup receipts storage manager.
pub struct CleanupReceiptsStorage {
    /// Base directory for receipt storage.
    storage_dir: PathBuf,
    /// In-memory index for fast searching.
    index: ReceiptIndex,
}

impl CleanupReceiptsStorage {
    /// Create new storage manager with default directory.
    pub fn new() -> Result<Self, CleanupReceiptsError> {
        Self::with_directory(PathBuf::from(DEFAULT_RECEIPTS_DIR))
    }

    /// Create storage manager with custom directory.
    pub fn with_directory(storage_dir: PathBuf) -> Result<Self, CleanupReceiptsError> {
        // Ensure storage directory exists (TOCTOU-safe)
        if let Err(e) = fs::create_dir_all(&storage_dir)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(e.into());
        }

        let mut storage = Self {
            storage_dir,
            index: ReceiptIndex::default(),
        };

        // Load existing index if available
        if let Err(err) = storage.load_index() {
            eprintln!(
                "Warning: Failed to load receipt index, creating new: {}",
                err
            );
            // Continue with empty index - will rebuild on save
        }

        Ok(storage)
    }

    /// Store a cleanup receipt with audit trail.
    pub fn store_receipt(
        &mut self,
        receipt: &CleanupReceipt,
    ) -> Result<PathBuf, CleanupReceiptsError> {
        // Generate file path based on timestamp and receipt ID
        let filename = format!(
            "{}_{}.json",
            receipt.initiated_at.format("%Y%m%d_%H%M%S"),
            sanitize_filename(&receipt.receipt_id)
        );
        let file_path = self.storage_dir.join(filename);

        // Serialize and write receipt
        let receipt_json = serde_json::to_string_pretty(receipt)?;
        fs::write(&file_path, receipt_json)?;

        // Update index
        let metadata = ReceiptMetadata {
            receipt_id: receipt.receipt_id.clone(),
            mode: receipt.mode,
            actor: receipt.actor.clone(),
            bead_id: receipt.bead_id.clone(),
            initiated_at: receipt.initiated_at,
            completed_at: receipt.completed_at,
            operation_count: receipt.operations.len(),
            bytes_freed: receipt.bytes_freed,
            success_rate: receipt.summary.success_rate,
            file_path: file_path.clone(),
        };

        if self.index.receipts.len() >= MAX_RECEIPT_INDEX_SIZE {
            // Remove oldest entries to maintain size limit
            self.trim_index_to_size(MAX_RECEIPT_INDEX_SIZE - 1);
        }

        self.index
            .receipts
            .insert(receipt.receipt_id.clone(), metadata);
        self.index.last_updated = Utc::now();

        // Save updated index
        self.save_index()?;

        Ok(file_path)
    }

    /// Retrieve a specific receipt by ID.
    pub fn get_receipt(&self, receipt_id: &str) -> Result<CleanupReceipt, CleanupReceiptsError> {
        let metadata = self
            .index
            .receipts
            .get(receipt_id)
            .ok_or_else(|| CleanupReceiptsError::ReceiptNotFound(receipt_id.to_string()))?;

        if !metadata.file_path.exists() {
            return Err(CleanupReceiptsError::Corruption(format!(
                "Receipt file missing: {}",
                metadata.file_path.display()
            )));
        }

        let receipt_data = fs::read_to_string(&metadata.file_path)?;
        let receipt: CleanupReceipt = serde_json::from_str(&receipt_data)
            .map_err(|e| CleanupReceiptsError::InvalidFormat(e.to_string()))?;

        Ok(receipt)
    }

    /// Search receipts based on filters.
    pub fn search_receipts(&self, filter: &ReceiptSearchFilter) -> Vec<ReceiptMetadata> {
        // Collect matching references first to avoid per-result clones
        let mut matching_refs = Vec::new();

        for metadata in self.index.receipts.values() {
            if self.matches_filter(metadata, filter) {
                if matching_refs.len() < MAX_RECEIPT_SEARCH_RESULTS {
                    matching_refs.push(metadata);
                } else {
                    break; // Respect search result limit
                }
            }
        }

        // Sort references by timestamp (newest first)
        matching_refs.sort_by_key(|metadata| std::cmp::Reverse(metadata.initiated_at));

        // Clone only the final sorted results
        matching_refs.into_iter().cloned().collect()
    }

    /// Get all receipts for a specific actor.
    pub fn get_receipts_by_actor(&self, actor: &str) -> Vec<ReceiptMetadata> {
        let filter = ReceiptSearchFilter {
            actor: Some(actor.to_string()),
            ..Default::default()
        };
        self.search_receipts(&filter)
    }

    /// Get all receipts for a specific bead.
    pub fn get_receipts_by_bead(&self, bead_id: &str) -> Vec<ReceiptMetadata> {
        let filter = ReceiptSearchFilter {
            bead_id: Some(bead_id.to_string()),
            ..Default::default()
        };
        self.search_receipts(&filter)
    }

    /// Get recent receipts (last N).
    pub fn get_recent_receipts(&self, limit: usize) -> Vec<ReceiptMetadata> {
        let mut all_receipts: Vec<_> = self.index.receipts.values().cloned().collect();
        all_receipts.sort_by_key(|metadata| std::cmp::Reverse(metadata.initiated_at));
        all_receipts.truncate(limit);
        all_receipts
    }

    /// Delete a receipt and update index.
    pub fn delete_receipt(&mut self, receipt_id: &str) -> Result<(), CleanupReceiptsError> {
        let metadata = self
            .index
            .receipts
            .remove(receipt_id)
            .ok_or_else(|| CleanupReceiptsError::ReceiptNotFound(receipt_id.to_string()))?;

        // Remove file atomically (TOCTOU-safe)
        if let Err(e) = fs::remove_file(&metadata.file_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(e.into());
        }

        self.index.last_updated = Utc::now();
        self.save_index()?;

        Ok(())
    }

    /// Get storage statistics.
    pub fn get_statistics(&self) -> ReceiptStorageStatistics {
        let total_receipts = self.index.receipts.len();
        let total_bytes_freed: u64 = self.index.receipts.values().map(|m| m.bytes_freed).sum();

        let execute_receipts = self
            .index
            .receipts
            .values()
            .filter(|m| m.mode == CleanupMode::Execute)
            .count();

        let dry_run_receipts = total_receipts - execute_receipts;

        let avg_success_rate = if total_receipts > 0 {
            self.index
                .receipts
                .values()
                .map(|m| m.success_rate)
                .sum::<f32>()
                / total_receipts as f32
        } else {
            0.0
        };

        ReceiptStorageStatistics {
            total_receipts,
            execute_receipts,
            dry_run_receipts,
            total_bytes_freed,
            avg_success_rate,
            oldest_receipt: self.index.receipts.values().map(|m| m.initiated_at).min(),
            newest_receipt: self.index.receipts.values().map(|m| m.initiated_at).max(),
        }
    }

    fn matches_filter(&self, metadata: &ReceiptMetadata, filter: &ReceiptSearchFilter) -> bool {
        if let Some(ref actor) = filter.actor
            && metadata.actor != *actor
        {
            return false;
        }

        if let Some(ref bead_id) = filter.bead_id
            && metadata.bead_id.as_ref() != Some(bead_id)
        {
            return false;
        }

        if let Some(mode) = filter.mode
            && metadata.mode != mode
        {
            return false;
        }

        if let Some(since) = filter.since
            && metadata.initiated_at < since
        {
            return false;
        }

        if let Some(until) = filter.until
            && metadata.initiated_at > until
        {
            return false;
        }

        if let Some(min_bytes) = filter.min_bytes_freed
            && metadata.bytes_freed < min_bytes
        {
            return false;
        }

        if let Some(min_success) = filter.min_success_rate
            && metadata.success_rate < min_success
        {
            return false;
        }

        true
    }

    fn load_index(&mut self) -> Result<(), CleanupReceiptsError> {
        let index_path = self.storage_dir.join("index.json");
        // Load index file atomically (TOCTOU-safe)
        match fs::read_to_string(&index_path) {
            Ok(index_data) => {
                self.index = serde_json::from_str(&index_data)?;
                // Validate that referenced files still exist
                self.cleanup_stale_index_entries();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No index file exists yet, use default empty index
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    fn save_index(&self) -> Result<(), CleanupReceiptsError> {
        let index_path = self.storage_dir.join("index.json");
        let index_json = serde_json::to_string_pretty(&self.index)?;
        fs::write(&index_path, index_json)?;
        Ok(())
    }

    fn cleanup_stale_index_entries(&mut self) {
        // Collect stale keys as references to avoid cloning
        let stale_keys: Vec<String> = self
            .index
            .receipts
            .iter()
            .filter_map(|(receipt_id, metadata)| {
                if !metadata.file_path.exists() {
                    Some(receipt_id.clone())
                } else {
                    None
                }
            })
            .collect();

        for key in stale_keys {
            self.index.receipts.remove(&key);
        }

        if !self.index.receipts.is_empty() {
            self.index.last_updated = Utc::now();
        }
    }

    fn trim_index_to_size(&mut self, target_size: usize) {
        if self.index.receipts.len() <= target_size {
            return;
        }

        // Collect and sort by timestamp
        let mut entries: Vec<_> = self.index.receipts.iter().collect();
        entries.sort_by_key(|entry| entry.1.initiated_at);

        // Collect keys to remove first, then remove them
        let to_remove = entries.len() - target_size;
        let keys_to_remove: Vec<String> = entries
            .iter()
            .take(to_remove)
            .map(|(receipt_id, _)| (*receipt_id).clone())
            .collect();

        for key in keys_to_remove {
            self.index.receipts.remove(&key);
        }
    }
}

impl Default for CleanupReceiptsStorage {
    fn default() -> Self {
        Self::new().expect("Failed to create default cleanup receipts storage")
    }
}

/// Storage statistics summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptStorageStatistics {
    pub total_receipts: usize,
    pub execute_receipts: usize,
    pub dry_run_receipts: usize,
    pub total_bytes_freed: u64,
    pub avg_success_rate: f32,
    pub oldest_receipt: Option<DateTime<Utc>>,
    pub newest_receipt: Option<DateTime<Utc>>,
}

/// Sanitize filename for safe storage.
fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

/// Generate summary report for all receipts.
pub fn generate_cleanup_audit_report(storage: &CleanupReceiptsStorage) -> String {
    let stats = storage.get_statistics();
    let recent_receipts = storage.get_recent_receipts(10);

    let mut report = String::new();
    report.push_str("# Cleanup Audit Report\n\n");

    // Overall statistics
    report.push_str("## Summary Statistics\n");
    report.push_str(&format!("- Total Receipts: {}\n", stats.total_receipts));
    report.push_str(&format!(
        "- Execute Operations: {}\n",
        stats.execute_receipts
    ));
    report.push_str(&format!(
        "- Dry-Run Operations: {}\n",
        stats.dry_run_receipts
    ));
    report.push_str(&format!(
        "- Total Bytes Freed: {}\n",
        format_bytes(stats.total_bytes_freed)
    ));
    report.push_str(&format!(
        "- Average Success Rate: {:.1}%\n",
        stats.avg_success_rate * 100.0
    ));

    if let (Some(oldest), Some(newest)) = (stats.oldest_receipt, stats.newest_receipt) {
        report.push_str(&format!(
            "- Date Range: {} to {}\n",
            oldest.format("%Y-%m-%d"),
            newest.format("%Y-%m-%d")
        ));
    }

    report.push_str("\n## Recent Activity\n");
    if recent_receipts.is_empty() {
        report.push_str("No recent cleanup activity.\n");
    } else {
        for receipt in &recent_receipts {
            report.push_str(&format!(
                "- {}: {} by {} ({} ops, {:.1}% success, {} freed)\n",
                receipt.initiated_at.format("%Y-%m-%d %H:%M"),
                receipt.mode,
                receipt.actor,
                receipt.operation_count,
                receipt.success_rate * 100.0,
                format_bytes(receipt.bytes_freed)
            ));
        }
    }

    report
}

/// Format byte count as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx = unit_idx.saturating_add(1);
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}

impl std::fmt::Display for CleanupMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DryRun => write!(f, "dry-run"),
            Self::Execute => write!(f, "execute"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::cleanup_executor::{CleanupOperation, CleanupSummary};
    use tempfile::TempDir;

    fn create_test_receipt(receipt_id: &str, actor: &str, mode: CleanupMode) -> CleanupReceipt {
        let timestamp = Utc::now();
        CleanupReceipt {
            schema_version: "test/v1".to_string(),
            receipt_id: receipt_id.to_string(),
            mode,
            candidates_digest: "test_digest".to_string(),
            approved_reason: "Test cleanup".to_string(),
            actor: actor.to_string(),
            bead_id: Some("test_bead".to_string()),
            initiated_at: timestamp,
            completed_at: timestamp,
            operations: vec![],
            bytes_freed: 1024,
            bytes_skipped: 0,
            skipped_pins: 0,
            diagnostics: vec!["Test diagnostic".to_string()],
            summary: CleanupSummary {
                total_candidates: 1,
                removed_count: 1,
                skipped_count: 0,
                failed_count: 0,
                success_rate: 1.0,
            },
        }
    }

    #[test]
    fn test_store_and_retrieve_receipt() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut storage =
            CleanupReceiptsStorage::with_directory(temp_dir.path().to_path_buf()).expect("storage");

        let receipt = create_test_receipt("test_001", "test_actor", CleanupMode::Execute);

        // Store receipt
        let file_path = storage.store_receipt(&receipt).expect("store receipt");
        assert!(file_path.exists());

        // Retrieve receipt
        let retrieved = storage.get_receipt("test_001").expect("get receipt");
        assert_eq!(retrieved.receipt_id, "test_001");
        assert_eq!(retrieved.actor, "test_actor");
        assert_eq!(retrieved.mode, CleanupMode::Execute);
    }

    #[test]
    fn test_search_receipts() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut storage =
            CleanupReceiptsStorage::with_directory(temp_dir.path().to_path_buf()).expect("storage");

        // Store multiple receipts
        let receipt1 = create_test_receipt("test_001", "actor_a", CleanupMode::Execute);
        let receipt2 = create_test_receipt("test_002", "actor_b", CleanupMode::DryRun);
        let receipt3 = create_test_receipt("test_003", "actor_a", CleanupMode::Execute);

        storage.store_receipt(&receipt1).expect("store 1");
        storage.store_receipt(&receipt2).expect("store 2");
        storage.store_receipt(&receipt3).expect("store 3");

        // Search by actor
        let filter = ReceiptSearchFilter {
            actor: Some("actor_a".to_string()),
            ..Default::default()
        };
        let results = storage.search_receipts(&filter);
        assert_eq!(results.len(), 2);

        // Search by mode
        let filter = ReceiptSearchFilter {
            mode: Some(CleanupMode::DryRun),
            ..Default::default()
        };
        let results = storage.search_receipts(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].receipt_id, "test_002");
    }

    #[test]
    fn test_receipt_deletion() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut storage =
            CleanupReceiptsStorage::with_directory(temp_dir.path().to_path_buf()).expect("storage");

        let receipt = create_test_receipt("test_delete", "test_actor", CleanupMode::Execute);
        storage.store_receipt(&receipt).expect("store receipt");

        // Verify receipt exists
        assert!(storage.get_receipt("test_delete").is_ok());

        // Delete receipt
        storage
            .delete_receipt("test_delete")
            .expect("delete receipt");

        // Verify receipt is gone
        assert!(storage.get_receipt("test_delete").is_err());
    }

    #[test]
    fn test_storage_statistics() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut storage =
            CleanupReceiptsStorage::with_directory(temp_dir.path().to_path_buf()).expect("storage");

        let receipt1 = create_test_receipt("test_001", "actor_a", CleanupMode::Execute);
        let receipt2 = create_test_receipt("test_002", "actor_b", CleanupMode::DryRun);

        storage.store_receipt(&receipt1).expect("store 1");
        storage.store_receipt(&receipt2).expect("store 2");

        let stats = storage.get_statistics();
        assert_eq!(stats.total_receipts, 2);
        assert_eq!(stats.execute_receipts, 1);
        assert_eq!(stats.dry_run_receipts, 1);
        assert_eq!(stats.total_bytes_freed, 2048); // 2 * 1024
    }

    #[test]
    fn test_filename_sanitization() {
        assert_eq!(sanitize_filename("test_123"), "test_123");
        assert_eq!(
            sanitize_filename("test/with\\special:chars"),
            "testwithspecialchars"
        );
        assert_eq!(sanitize_filename("test-receipt_001"), "test-receipt_001");
    }

    #[test]
    fn test_audit_report_generation() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut storage =
            CleanupReceiptsStorage::with_directory(temp_dir.path().to_path_buf()).expect("storage");

        let receipt = create_test_receipt("test_report", "test_actor", CleanupMode::Execute);
        storage.store_receipt(&receipt).expect("store receipt");

        let report = generate_cleanup_audit_report(&storage);
        assert!(report.contains("# Cleanup Audit Report"));
        assert!(report.contains("Total Receipts: 1"));
        assert!(report.contains("Execute Operations: 1"));
        assert!(report.contains("test_actor"));
    }

    #[test]
    fn test_search_optimization_preserves_identical_behavior() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut storage =
            CleanupReceiptsStorage::with_directory(temp_dir.path().to_path_buf()).expect("storage");

        // Create receipts with different timestamps for ordering verification
        let base_time = Utc::now();
        let mut receipts = Vec::new();

        for i in 0..5 {
            let mut receipt = create_test_receipt(
                &format!("test_{:03}", i),
                "test_actor",
                CleanupMode::Execute,
            );
            receipt.initiated_at = base_time - chrono::Duration::minutes(i as i64 * 10);
            receipt.completed_at = receipt.initiated_at + chrono::Duration::minutes(1);
            receipts.push(receipt);
        }

        for receipt in &receipts {
            storage.store_receipt(receipt).expect("store receipt");
        }

        // Test search returns same count and ordering as before optimization
        let filter = ReceiptSearchFilter {
            actor: Some("test_actor".to_string()),
            ..Default::default()
        };
        let results = storage.search_receipts(&filter);

        // Verify count matches expected (all 5 receipts)
        assert_eq!(
            results.len(),
            5,
            "Search should return all matching receipts"
        );

        // Verify ordering is newest-first by timestamp
        for i in 1..results.len() {
            assert!(
                results[i - 1].initiated_at >= results[i].initiated_at,
                "Results should be ordered newest-first by initiated_at timestamp"
            );
        }

        // Verify receipt IDs are in expected order (newest timestamp = test_000)
        assert_eq!(results[0].receipt_id, "test_000");
        assert_eq!(results[4].receipt_id, "test_004");
    }
}
