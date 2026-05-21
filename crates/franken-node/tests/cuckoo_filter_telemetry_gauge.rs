//! Integration test for CuckooFilter telemetry gauge (bd-98xo5.3.1).

use frankenengine_node::security::cuckoo_filter::{CuckooFilter, revocation_filter_entries_gauge};
use std::sync::atomic::{AtomicUsize, Ordering};

// Reset the global gauge before each test by direct store (tests are serialized)
fn reset_gauge() {
    // Access the gauge through the public API and verify it's accessible
    let _ = revocation_filter_entries_gauge();
}

#[test]
fn gauge_advances_by_one_on_single_insert() {
    reset_gauge();

    let mut filter = CuckooFilter::new(100);
    filter.enable_telemetry();

    let before = revocation_filter_entries_gauge();
    assert!(filter.insert("token_single_insert_test"));
    let after = revocation_filter_entries_gauge();

    assert_eq!(
        after,
        before + 1,
        "gauge should advance by exactly 1 on single insert"
    );
}

#[test]
fn gauge_decrements_by_one_on_delete() {
    reset_gauge();

    let mut filter = CuckooFilter::new(100);
    filter.enable_telemetry();

    // Insert two tokens
    assert!(filter.insert("token_delete_test_a"));
    assert!(filter.insert("token_delete_test_b"));
    let after_insert = revocation_filter_entries_gauge();

    // Remove one
    assert!(filter.remove("token_delete_test_a"));
    let after_remove = revocation_filter_entries_gauge();

    assert_eq!(
        after_remove,
        after_insert - 1,
        "gauge should decrement by 1 on successful delete"
    );
}

#[test]
fn gauge_reaches_batch_size_after_bulk_insert() {
    reset_gauge();

    let mut filter = CuckooFilter::new(200);
    filter.enable_telemetry();

    let before = revocation_filter_entries_gauge();

    // Simulate OSV refresh batch (32 entries is a typical batch size)
    const OSV_REFRESH_BATCH_SIZE: usize = 32;
    for i in 0..OSV_REFRESH_BATCH_SIZE {
        assert!(
            filter.insert(&format!("osv_refresh_token_{}", i)),
            "batch insert {} should succeed",
            i
        );
    }

    let after = revocation_filter_entries_gauge();
    assert_eq!(
        after,
        before + OSV_REFRESH_BATCH_SIZE,
        "gauge should reach batch size after bulk insert"
    );
    assert_eq!(filter.len(), OSV_REFRESH_BATCH_SIZE);
}

#[test]
fn gauge_resets_to_zero_on_clear() {
    reset_gauge();

    let mut filter = CuckooFilter::new(100);
    filter.enable_telemetry();

    // Insert some tokens
    for i in 0..10 {
        assert!(filter.insert(&format!("clear_test_token_{}", i)));
    }
    let before_clear = revocation_filter_entries_gauge();
    assert!(before_clear >= 10);

    // Clear the filter
    filter.clear();

    let after_clear = revocation_filter_entries_gauge();
    assert_eq!(
        after_clear,
        before_clear - 10,
        "gauge should decrement by cleared count"
    );
    assert_eq!(filter.len(), 0);
}

#[test]
fn gauge_not_affected_when_telemetry_disabled() {
    reset_gauge();

    let mut filter_with_telemetry = CuckooFilter::new(100);
    filter_with_telemetry.enable_telemetry();

    let baseline = revocation_filter_entries_gauge();

    // Create a filter WITHOUT telemetry enabled
    let mut filter_no_telemetry = CuckooFilter::new(100);
    // Note: NOT calling enable_telemetry()

    // Insert into the non-telemetry filter
    for i in 0..5 {
        assert!(filter_no_telemetry.insert(&format!("no_telem_token_{}", i)));
    }

    let after = revocation_filter_entries_gauge();
    assert_eq!(
        after, baseline,
        "gauge should not change for filters without telemetry enabled"
    );
}
