#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use chrono::{DateTime, Utc, Duration};
use std::path::PathBuf;

use frankenengine_node::storage::cleanup_receipts::{
    CleanupReceiptsStorage, ReceiptSearchFilter, ReceiptMetadata, ReceiptIndex,
};
use frankenengine_node::ops::cleanup_executor::{
    CleanupReceipt, CleanupMode, CleanupItem, CleanupAction, CleanupResult,
};

// Size limits for bounded fuzzing
const MAX_RECEIPTS: usize = 100;
const MAX_ITEMS_PER_RECEIPT: usize = 20;
const MAX_STRING_LEN: usize = 512;
const MAX_PATH_LEN: usize = 1024;
const MAX_FILENAME_LEN: usize = 255;
const MAX_SEARCH_RESULTS: usize = 50;
const MAX_TIMESTAMP_OFFSET_SECONDS: i64 = 86400 * 365; // 1 year

/// Fuzzable cleanup receipt with bounded fields
#[derive(Debug, Clone, Arbitrary)]
struct FuzzCleanupReceipt {
    #[arbitrary(with = bounded_receipt_id)]
    receipt_id: String,
    mode: CleanupMode,
    #[arbitrary(with = bounded_actor)]
    actor: String,
    #[arbitrary(with = bounded_bead_id)]
    bead_id: Option<String>,
    #[arbitrary(with = bounded_timestamp_offset)]
    initiated_offset_seconds: i64,
    #[arbitrary(with = bounded_timestamp_offset)]
    completed_offset_seconds: i64,
    #[arbitrary(with = bounded_cleanup_items)]
    items: Vec<FuzzCleanupItem>,
}

impl From<FuzzCleanupReceipt> for CleanupReceipt {
    fn from(fuzz: FuzzCleanupReceipt) -> Self {
        let base_time = Utc::now();
        let initiated_at = base_time + Duration::seconds(fuzz.initiated_offset_seconds);
        let completed_at = base_time + Duration::seconds(fuzz.completed_offset_seconds);

        Self {
            receipt_id: fuzz.receipt_id,
            mode: fuzz.mode,
            actor: fuzz.actor,
            bead_id: fuzz.bead_id,
            initiated_at,
            completed_at,
            items: fuzz.items.into_iter().map(|i| i.into()).collect(),
        }
    }
}

/// Fuzzable cleanup item
#[derive(Debug, Clone, Arbitrary)]
struct FuzzCleanupItem {
    #[arbitrary(with = bounded_item_path)]
    path: String,
    action: CleanupAction,
    result: CleanupResult,
    #[arbitrary(with = bounded_size)]
    size_bytes: u64,
    #[arbitrary(with = bounded_error_message)]
    error_message: Option<String>,
}

impl From<FuzzCleanupItem> for CleanupItem {
    fn from(fuzz: FuzzCleanupItem) -> Self {
        Self {
            path: fuzz.path,
            action: fuzz.action,
            result: fuzz.result,
            size_bytes: fuzz.size_bytes,
            error_message: fuzz.error_message,
        }
    }
}

/// Fuzzable search filter
#[derive(Debug, Clone, Arbitrary)]
struct FuzzReceiptSearchFilter {
    #[arbitrary(with = bounded_actor_filter)]
    actor: Option<String>,
    #[arbitrary(with = bounded_bead_id_filter)]
    bead_id: Option<String>,
    mode: Option<CleanupMode>,
    #[arbitrary(with = bounded_timestamp_filter)]
    since_offset_seconds: Option<i64>,
    #[arbitrary(with = bounded_timestamp_filter)]
    until_offset_seconds: Option<i64>,
}

impl From<FuzzReceiptSearchFilter> for ReceiptSearchFilter {
    fn from(fuzz: FuzzReceiptSearchFilter) -> Self {
        let base_time = Utc::now();
        let since = fuzz.since_offset_seconds.map(|offset| base_time + Duration::seconds(offset));
        let until = fuzz.until_offset_seconds.map(|offset| base_time + Duration::seconds(offset));

        Self {
            actor: fuzz.actor,
            bead_id: fuzz.bead_id,
            mode: fuzz.mode,
            since,
            until,
        }
    }
}

/// Operations to test on the cleanup receipts storage
#[derive(Debug, Clone, Arbitrary)]
enum CleanupReceiptsOperation {
    CreateStorage {
        #[arbitrary(with = bounded_storage_path)]
        storage_path: String,
    },
    StoreReceipt {
        receipt: FuzzCleanupReceipt,
    },
    RetrieveReceipt {
        #[arbitrary(with = bounded_receipt_id)]
        receipt_id: String,
    },
    SearchReceipts {
        filter: FuzzReceiptSearchFilter,
    },
    LoadIndex,
    SaveIndex,
    TestFilenameSanitization {
        #[arbitrary(with = bounded_filename_test)]
        filename: String,
    },
    TestPathConstruction {
        #[arbitrary(with = bounded_storage_path)]
        base_path: String,
        #[arbitrary(with = bounded_filename_test)]
        filename: String,
    },
}

/// Complete fuzz input
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    #[arbitrary(with = bounded_storage_operations)]
    operations: Vec<CleanupReceiptsOperation>,
}

// Bounded arbitrary helpers

fn bounded_receipt_id(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=8)?;
    Ok(match choice {
        0 => String::new(), // Empty
        1 => "CLEANUP-001".to_string(), // Valid format
        2 => "cleanup\x00002".to_string(), // Null byte
        3 => "cleanup\n003".to_string(), // Newline
        4 => "cleanup/004".to_string(), // Slash
        5 => "cleanup\\005".to_string(), // Backslash
        6 => "cleanup..006".to_string(), // Double dot
        7 => "a".repeat(300), // Very long
        8 => {
            let len = u.int_in_range(0..=MAX_STRING_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_actor(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=6)?;
    Ok(match choice {
        0 => String::new(), // Empty
        1 => "user123".to_string(), // Valid actor
        2 => "system".to_string(), // System actor
        3 => "actor\nwith\nnewlines".to_string(), // Newlines
        4 => "actor\twith\ttabs".to_string(), // Tabs
        5 => "actor\x00null".to_string(), // Null byte
        6 => {
            let len = u.int_in_range(0..=100)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_bead_id(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(bounded_receipt_id(u)?)) // Use same logic
    } else {
        Ok(None)
    }
}

fn bounded_actor_filter(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(bounded_actor(u)?))
    } else {
        Ok(None)
    }
}

fn bounded_bead_id_filter(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(bounded_receipt_id(u)?)) // Use same logic
    } else {
        Ok(None)
    }
}

fn bounded_timestamp_offset(u: &mut Unstructured) -> arbitrary::Result<i64> {
    u.int_in_range(-MAX_TIMESTAMP_OFFSET_SECONDS..=MAX_TIMESTAMP_OFFSET_SECONDS)
}

fn bounded_timestamp_filter(u: &mut Unstructured) -> arbitrary::Result<Option<i64>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(bounded_timestamp_offset(u)?))
    } else {
        Ok(None)
    }
}

fn bounded_item_path(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=10)?;
    Ok(match choice {
        0 => String::new(), // Empty
        1 => "file.txt".to_string(), // Simple file
        2 => "dir/file.txt".to_string(), // Path with directory
        3 => "/absolute/path.txt".to_string(), // Absolute path
        4 => "../../../etc/passwd".to_string(), // Path traversal
        5 => "file\x00name".to_string(), // Null byte
        6 => "file name".to_string(), // Space
        7 => "file\nname".to_string(), // Newline
        8 => "file\\name".to_string(), // Backslash
        9 => "a".repeat(2000), // Very long
        10 => {
            let len = u.int_in_range(0..=MAX_PATH_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_size(u: &mut Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=u64::MAX / 1000) // Prevent overflow in calculations
}

fn bounded_error_message(u: &mut Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        let len = u.int_in_range(0..=MAX_STRING_LEN)?;
        let bytes = u.bytes(len)?;
        Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
    } else {
        Ok(None)
    }
}

fn bounded_storage_path(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=8)?;
    Ok(match choice {
        0 => String::new(), // Empty
        1 => "cleanup_receipts".to_string(), // Default
        2 => "/tmp/receipts".to_string(), // Absolute
        3 => "../receipts".to_string(), // Parent directory
        4 => "receipts\x00dir".to_string(), // Null byte
        5 => "receipts dir".to_string(), // Space
        6 => "receipts\ndir".to_string(), // Newline
        7 => "receipts\\dir".to_string(), // Backslash
        8 => {
            let len = u.int_in_range(0..=MAX_PATH_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_filename_test(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=10)?;
    Ok(match choice {
        0 => String::new(), // Empty
        1 => "file.json".to_string(), // Valid filename
        2 => "file/with/slashes".to_string(), // Path separators
        3 => "file\\with\\backslashes".to_string(), // Windows separators
        4 => "file\x00null".to_string(), // Null byte
        5 => "file\nnewline".to_string(), // Newline
        6 => "file\ttab".to_string(), // Tab
        7 => "file:colon".to_string(), // Colon (Windows issue)
        8 => "file*asterisk".to_string(), // Asterisk (Windows issue)
        9 => "a".repeat(500), // Very long
        10 => {
            let len = u.int_in_range(0..=MAX_FILENAME_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_cleanup_items(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzCleanupItem>> {
    let len = u.int_in_range(0..=MAX_ITEMS_PER_RECEIPT)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_storage_operations(u: &mut Unstructured) -> arbitrary::Result<Vec<CleanupReceiptsOperation>> {
    let len = u.int_in_range(1..=10)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fuzz_target!(|data: &[u8]| {
    // Input size guard to prevent OOM
    if data.len() > 150_000 {
        return;
    }

    let input: FuzzInput = match Unstructured::new(data).arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip silently
    };

    // Track state for invariant checking
    let mut storage_creation_attempts = 0;
    let mut successful_storage_creations = 0;
    let mut store_attempts = 0;
    let mut successful_stores = 0;
    let mut retrieve_attempts = 0;
    let mut successful_retrieves = 0;
    let mut search_attempts = 0;
    let mut successful_searches = 0;

    // Track stored receipts for validation
    let mut stored_receipt_ids = std::collections::HashSet::new();

    // We'll use a temporary directory to avoid filesystem conflicts
    let temp_dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => return, // Skip if we can't create temp directory
    };

    let mut current_storage: Option<CleanupReceiptsStorage> = None;

    // Execute fuzzed operations
    for op in input.operations {
        match op {
            CleanupReceiptsOperation::CreateStorage { storage_path } => {
                storage_creation_attempts += 1;

                // Create storage path within temp directory to avoid conflicts
                let safe_path = if storage_path.is_empty() {
                    temp_dir.path().join("default")
                } else {
                    // Sanitize path to avoid traversal outside temp directory
                    let sanitized = storage_path.replace(['/', '\\', '\0'], "_");
                    temp_dir.path().join(sanitized)
                };

                match CleanupReceiptsStorage::with_directory(safe_path) {
                    Ok(storage) => {
                        successful_storage_creations += 1;
                        current_storage = Some(storage);
                    }
                    Err(_) => {
                        // Storage creation can fail due to invalid paths or permissions
                    }
                }
            }

            CleanupReceiptsOperation::StoreReceipt { receipt } => {
                store_attempts += 1;

                if let Some(ref mut storage) = current_storage {
                    let cleanup_receipt: CleanupReceipt = receipt.into();

                    match storage.store_receipt(&cleanup_receipt) {
                        Ok(_file_path) => {
                            successful_stores += 1;
                            stored_receipt_ids.insert(cleanup_receipt.receipt_id.clone());

                            // Verify storage invariants
                            let index = storage.index();
                            assert!(index.receipts.len() <= 10000, "Index should respect size limits");

                            // Verify receipt is in index
                            if !cleanup_receipt.receipt_id.is_empty() {
                                assert!(index.receipts.contains_key(&cleanup_receipt.receipt_id),
                                       "Stored receipt should be in index");
                            }
                        }
                        Err(_) => {
                            // Storage can fail due to invalid receipt data or IO errors
                        }
                    }
                }
            }

            CleanupReceiptsOperation::RetrieveReceipt { receipt_id } => {
                retrieve_attempts += 1;

                if let Some(ref storage) = current_storage {
                    match storage.retrieve_receipt(&receipt_id) {
                        Ok(retrieved_receipt) => {
                            successful_retrieves += 1;

                            // Verify retrieved receipt properties
                            assert_eq!(retrieved_receipt.receipt_id, receipt_id,
                                     "Retrieved receipt should have matching ID");

                            // Verify receipt structure is valid
                            assert!(retrieved_receipt.initiated_at <= retrieved_receipt.completed_at ||
                                   (retrieved_receipt.completed_at - retrieved_receipt.initiated_at).num_seconds().abs() <= 86400,
                                   "Receipt timestamps should be reasonable");

                            // Verify items have consistent data
                            for item in &retrieved_receipt.items {
                                if item.result == CleanupResult::Success {
                                    assert!(item.error_message.is_none(),
                                           "Successful items should not have error messages");
                                }
                            }
                        }
                        Err(_) => {
                            // Retrieval can fail if receipt doesn't exist or file is corrupted
                        }
                    }
                }
            }

            CleanupReceiptsOperation::SearchReceipts { filter } => {
                search_attempts += 1;

                if let Some(ref storage) = current_storage {
                    let search_filter: ReceiptSearchFilter = filter.into();
                    let results = storage.search_receipts(&search_filter);
                    successful_searches += 1;

                    // Verify search results constraints
                    assert!(results.len() <= 1000, "Search results should respect MAX_RECEIPT_SEARCH_RESULTS");

                    // Verify filter logic
                    for result in &results {
                        // Check actor filter
                        if let Some(ref actor_filter) = search_filter.actor {
                            assert_eq!(result.actor, *actor_filter, "Result should match actor filter");
                        }

                        // Check bead ID filter
                        if let Some(ref bead_filter) = search_filter.bead_id {
                            assert_eq!(result.bead_id.as_ref(), Some(bead_filter),
                                     "Result should match bead ID filter");
                        }

                        // Check mode filter
                        if let Some(mode_filter) = search_filter.mode {
                            assert_eq!(result.mode, mode_filter, "Result should match mode filter");
                        }

                        // Check time filters
                        if let Some(since) = search_filter.since {
                            assert!(result.initiated_at >= since, "Result should be after 'since' filter");
                        }

                        if let Some(until) = search_filter.until {
                            assert!(result.initiated_at <= until, "Result should be before 'until' filter");
                        }

                        // Verify metadata consistency
                        assert!(!result.receipt_id.is_empty() || result.receipt_id.trim().is_empty(),
                               "Receipt ID should be non-empty or whitespace");
                        assert!(!result.actor.is_empty() || result.actor.trim().is_empty(),
                               "Actor should be non-empty or whitespace");
                    }
                }
            }

            CleanupReceiptsOperation::LoadIndex => {
                if let Some(ref mut storage) = current_storage {
                    match storage.load_index() {
                        Ok(()) => {
                            let index = storage.index();
                            assert!(index.receipts.len() <= 10000, "Loaded index should respect size limits");
                            assert!(!index.schema_version.is_empty(), "Index should have schema version");
                        }
                        Err(_) => {
                            // Loading can fail if index file doesn't exist or is corrupted
                        }
                    }
                }
            }

            CleanupReceiptsOperation::SaveIndex => {
                if let Some(ref mut storage) = current_storage {
                    match storage.save_index() {
                        Ok(()) => {
                            // Index should have been saved successfully
                        }
                        Err(_) => {
                            // Saving can fail due to IO errors or permissions
                        }
                    }
                }
            }

            CleanupReceiptsOperation::TestFilenameSanitization { filename } => {
                // This tests filename sanitization logic
                let sanitized = filename.chars()
                    .map(|c| match c {
                        '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                        c if c.is_control() => '_',
                        c => c,
                    })
                    .collect::<String>();

                // Verify sanitization properties
                assert!(!sanitized.contains('/'), "Sanitized filename should not contain slashes");
                assert!(!sanitized.contains('\\'), "Sanitized filename should not contain backslashes");
                assert!(!sanitized.contains('\0'), "Sanitized filename should not contain null bytes");
                assert!(!sanitized.chars().any(|c| c.is_control()),
                       "Sanitized filename should not contain control characters");

                // Length should be preserved or reduced
                assert!(sanitized.len() <= filename.len(),
                       "Sanitized filename should not be longer than original");
            }

            CleanupReceiptsOperation::TestPathConstruction { base_path, filename } => {
                // Test path construction and validation
                let base = PathBuf::from(base_path);
                let file = PathBuf::from(filename);

                // Construct path
                let full_path = base.join(&file);

                // Verify path properties
                if !base.as_os_str().is_empty() && !file.as_os_str().is_empty() {
                    assert!(full_path.starts_with(&base) || base.as_os_str().is_empty(),
                           "Constructed path should start with base path");
                }

                // Test path string conversion
                let path_str = full_path.to_string_lossy();
                assert!(path_str.len() >= base.to_string_lossy().len(),
                       "Full path should be at least as long as base path");
            }
        }
    }

    // Invariant checks - these must hold regardless of input
    assert!(successful_storage_creations <= storage_creation_attempts,
           "Successful creations should not exceed attempts");
    assert!(successful_stores <= store_attempts,
           "Successful stores should not exceed attempts");
    assert!(successful_retrieves <= retrieve_attempts,
           "Successful retrieves should not exceed attempts");
    assert!(successful_searches <= search_attempts,
           "Successful searches should not exceed attempts");

    // If we have storage, verify its consistency
    if let Some(ref storage) = current_storage {
        let index = storage.index();

        // Index should be consistent
        assert!(index.receipts.len() <= 10000, "Index should respect maximum size");
        assert!(!index.schema_version.is_empty(), "Index should have schema version");

        // All stored receipt IDs should be in index (if they were non-empty)
        for receipt_id in &stored_receipt_ids {
            if !receipt_id.is_empty() && !receipt_id.trim().is_empty() {
                assert!(index.receipts.contains_key(receipt_id),
                       "All stored receipts should be in index");
            }
        }
    }

    // Test edge cases with extreme inputs
    let empty_filter = ReceiptSearchFilter {
        actor: None,
        bead_id: None,
        mode: None,
        since: None,
        until: None,
    };

    // Create temporary storage for edge case testing
    if let Ok(mut test_storage) = CleanupReceiptsStorage::with_directory(temp_dir.path().join("edge_test")) {
        // Empty search should work
        let empty_results = test_storage.search_receipts(&empty_filter);
        assert!(empty_results.is_empty(), "Empty storage should return empty search results");

        // Test with extreme time filters
        let far_future = Utc::now() + Duration::days(10000);
        let far_past = Utc::now() - Duration::days(10000);

        let extreme_filter = ReceiptSearchFilter {
            actor: None,
            bead_id: None,
            mode: None,
            since: Some(far_future),
            until: Some(far_past),
        };

        let extreme_results = test_storage.search_receipts(&extreme_filter);
        assert!(extreme_results.is_empty(), "Extreme time filter should return empty results");
    }
});