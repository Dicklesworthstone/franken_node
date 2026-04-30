#[path = "../../../tests/integration/frankensqlite_adapter_conformance.rs"]
mod frankensqlite_adapter_conformance;

use frankenengine_node::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use frankenengine_node::storage::frankensqlite_adapter::{
    CallerContext, FrankensqliteAdapter, PersistenceClass,
};

#[cfg(feature = "advanced-features")]
use frankenengine_node::conformance::fsqlite_inspired_suite::{
    ConformanceDomain, ConformanceFixture, ConformanceId, ConformanceSuiteRunner,
};

#[test]
fn audit_replay_truncation_sentinel_is_first_and_preserves_window() {
    let mut adapter = FrankensqliteAdapter::default();
    let caller = CallerContext::system(
        "tests::frankensqlite_adapter_conformance",
        "trace-audit-replay-truncation",
    );

    for idx in 0..=(MAX_AUDIT_LOG_ENTRIES + 2) {
        adapter
            .write(
                &caller,
                PersistenceClass::AuditLog,
                &format!("audit-{idx:04}"),
                format!("value-{idx:04}").as_bytes(),
            )
            .expect("audit write should succeed");
    }
    let _ = adapter.take_events();

    let replay_results = adapter.replay();

    assert_eq!(
        replay_results
            .first()
            .map(|(key, matches)| (key.as_str(), *matches)),
        Some(("__audit_log_window_truncated__", false)),
        "truncated audit replay must surface the sentinel before bounded audit entries"
    );
    assert_eq!(
        replay_results.len(),
        MAX_AUDIT_LOG_ENTRIES + 1,
        "sentinel metadata must not evict the bounded audit replay window"
    );
    assert_eq!(
        replay_results
            .iter()
            .filter(|(key, _)| key != "__audit_log_window_truncated__")
            .count(),
        MAX_AUDIT_LOG_ENTRIES
    );
    assert_eq!(adapter.summary().replay_mismatches, 1);
}

#[cfg(feature = "advanced-features")]
fn fixture(number: u16) -> ConformanceFixture {
    ConformanceFixture {
        conformance_id: ConformanceId::new(ConformanceDomain::Determinism, number),
        domain: ConformanceDomain::Determinism,
        description: format!("overflow fixture {number}"),
        input: serde_json::json!({"number": number}),
        expected: serde_json::json!({"accepted": true}),
    }
}

#[cfg(feature = "advanced-features")]
#[test]
fn conformance_suite_fixture_overflow_evicts_oldest_id() {
    let mut runner = ConformanceSuiteRunner::new();

    for number in 1..=4097 {
        runner
            .register_fixture(fixture(number))
            .expect("unique fixture should register");
    }

    assert_eq!(runner.fixture_count(), 4096);
    runner
        .register_fixture(fixture(1))
        .expect("evicted oldest fixture id should be reusable");
    assert_eq!(runner.fixture_count(), 4096);
    assert!(
        runner.register_fixture(fixture(3)).is_err(),
        "non-evicted fixture id should remain registered"
    );
}
