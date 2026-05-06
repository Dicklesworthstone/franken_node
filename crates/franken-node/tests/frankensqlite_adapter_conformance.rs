#[path = "../../../tests/integration/frankensqlite_adapter_conformance.rs"]
mod frankensqlite_adapter_conformance;

use frankenengine_node::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use frankenengine_node::storage::frankensqlite_adapter::{
    event_codes, AdapterError, CallerContext, FrankensqliteAdapter, PersistenceClass,
    MAX_STORE_ENTRIES, MAX_STORE_KEY_BYTES, MAX_STORE_VALUE_BYTES,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const FRANKENSQLITE_PERSISTENCE_CONTRACT: &str =
    include_str!("../../../docs/specs/frankensqlite_persistence_contract.md");
const FRANKENSQLITE_PERSISTENCE_MATRIX: &str =
    include_str!("../../../artifacts/10.16/frankensqlite_persistence_matrix.json");

#[cfg(feature = "advanced-features")]
use frankenengine_node::conformance::fsqlite_inspired_suite::{
    ConformanceDomain, ConformanceFixture, ConformanceId, ConformanceSuiteRunner,
};

fn persistence_matrix() -> Value {
    serde_json::from_str(FRANKENSQLITE_PERSISTENCE_MATRIX)
        .expect("checked-in frankensqlite persistence matrix must be valid JSON")
}

fn object_field<'a>(value: &'a Value, field: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(field)
        .and_then(Value::as_object)
        .expect("matrix field must be an object")
}

fn array_field<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .expect("matrix field must be an array")
}

fn str_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .expect("matrix field must be a string")
}

fn bool_field(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_bool)
        .expect("matrix field must be a bool")
}

fn tier_for_adapter_label(label: &str) -> Option<&'static str> {
    match label {
        "tier1_wal_crash_safe" => Some("tier_1"),
        "tier2_periodic_flush" => Some("tier_2"),
        "tier3_ephemeral" => Some("tier_3"),
        _ => None,
    }
}

#[test]
fn checked_in_persistence_matrix_satisfies_contract_tiers_and_replay_rules() {
    assert!(
        FRANKENSQLITE_PERSISTENCE_CONTRACT.contains("Tier 1 (`tier_1`)"),
        "the test must stay anchored to the checked-in frankensqlite persistence contract"
    );
    assert!(
        FRANKENSQLITE_PERSISTENCE_CONTRACT
            .contains("Tier 1 and Tier 2 classes require replay semantics."),
        "contract replay requirement text changed; update this conformance test with it"
    );

    let matrix = persistence_matrix();
    let durability_modes = object_field(&matrix, "durability_modes");
    let mode_catalog = object_field(&matrix, "mode_catalog");
    let classes = array_field(&matrix, "persistence_classes");

    assert!(
        !classes.is_empty(),
        "persistence matrix must declare at least one persistence class"
    );

    let mut table_owners = BTreeMap::new();
    let mut tier_counts = BTreeMap::new();
    let mut replay_enabled = 0usize;

    for class in classes {
        let domain = str_field(class, "domain");
        let owner_module = str_field(class, "owner_module");
        let safety_tier = str_field(class, "safety_tier");
        let durability_mode = str_field(class, "durability_mode");
        let tables = array_field(class, "tables");
        let replay_support = bool_field(class, "replay_support");
        let replay_strategy = str_field(class, "replay_strategy");

        assert!(
            owner_module.starts_with("crates/franken-node/src/connector/"),
            "{domain} owner module must stay inside the connector source tree"
        );
        assert!(
            !tables.is_empty(),
            "{domain} must declare at least one owned table"
        );

        let tier_mode = durability_modes
            .get(safety_tier)
            .expect("persistence class must reference a known safety tier");
        let expected_mode = str_field(tier_mode, "durability_mode");
        assert_eq!(
            durability_mode, expected_mode,
            "{domain} durability mode must match its declared safety tier"
        );

        let catalog_mode = mode_catalog
            .get(durability_mode)
            .expect("persistence class must reference a known durability mode");
        assert_eq!(
            str_field(tier_mode, "journal_mode"),
            str_field(catalog_mode, "journal_mode"),
            "{domain} journal mode must match mode catalog"
        );
        assert_eq!(
            str_field(tier_mode, "synchronous"),
            str_field(catalog_mode, "synchronous"),
            "{domain} synchronous mode must match mode catalog"
        );

        match safety_tier {
            "tier_1" | "tier_2" => {
                assert!(
                    replay_support,
                    "{domain} is {safety_tier} and must support replay"
                );
                assert!(
                    !replay_strategy.trim().is_empty(),
                    "{domain} must declare a replay strategy"
                );
                replay_enabled += 1;
            }
            "tier_3" => {
                assert!(
                    !replay_support,
                    "{domain} is tier_3 and must not claim replay support in the checked-in matrix"
                );
            }
            other => panic!("{domain} uses unknown safety tier {other}"),
        }

        *tier_counts.entry(safety_tier.to_string()).or_insert(0usize) += 1;

        for table in tables {
            let table_name = table
                .as_str()
                .expect("persistence class table names must be strings");
            assert!(
                table_owners
                    .insert(table_name.to_string(), domain.to_string())
                    .is_none(),
                "table {table_name} must have exactly one owner"
            );
        }
    }

    assert_eq!(tier_counts.get("tier_1").copied(), Some(11));
    assert_eq!(tier_counts.get("tier_2").copied(), Some(12));
    assert_eq!(tier_counts.get("tier_3").copied(), Some(1));
    assert_eq!(replay_enabled, 23);
}

#[test]
fn adapter_runtime_report_is_fail_closed_subset_of_checked_in_matrix() {
    let matrix = persistence_matrix();
    let matrix_tiers = array_field(&matrix, "persistence_classes")
        .iter()
        .map(|class| str_field(class, "safety_tier"))
        .collect::<BTreeSet<_>>();

    let adapter = FrankensqliteAdapter::default();
    let report = adapter.to_report();

    assert_eq!(str_field(&report, "gate_verdict"), "FAIL");

    let reported_classes = array_field(&report, "persistence_classes");
    assert_eq!(
        reported_classes.len(),
        PersistenceClass::all().len(),
        "runtime report should describe the current coarse adapter classes exactly"
    );
    assert!(
        array_field(&matrix, "persistence_classes").len() > reported_classes.len(),
        "the checked-in matrix is per-domain; the current adapter report is intentionally coarse"
    );

    for reported in reported_classes {
        let class_name = str_field(reported, "class");
        let tier_label = str_field(reported, "tier");
        let contract_tier = tier_for_adapter_label(tier_label)
            .expect("runtime report must use a known adapter tier");
        assert!(
            matrix_tiers.contains(contract_tier),
            "{class_name} tier {tier_label} must map to a checked-in contract tier"
        );
    }
}

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

#[test]
fn adapter_write_rejects_oversized_keys_values_and_new_entries_at_capacity() {
    let mut adapter = FrankensqliteAdapter::default();
    let caller = CallerContext::system(
        "tests::frankensqlite_adapter_conformance",
        "trace-store-bounds",
    );

    let oversized_key = "k".repeat(MAX_STORE_KEY_BYTES + 1);
    let key_err = adapter
        .write(
            &caller,
            PersistenceClass::ControlState,
            &oversized_key,
            b"value",
        )
        .expect_err("oversized key must fail closed before insertion");
    assert!(matches!(key_err, AdapterError::WriteFailure { .. }));

    let oversized_value = vec![0x42; MAX_STORE_VALUE_BYTES + 1];
    let value_err = adapter
        .write(
            &caller,
            PersistenceClass::Snapshot,
            "snapshot-too-large",
            &oversized_value,
        )
        .expect_err("oversized value must fail closed before insertion");
    assert!(matches!(value_err, AdapterError::WriteFailure { .. }));

    assert_eq!(adapter.summary().total_writes, 0);
    assert_eq!(adapter.summary().write_failures, 2);
    assert!(adapter.events().iter().any(|event| {
        event.code == event_codes::FRANKENSQLITE_WRITE_FAIL && event.detail.contains("key length")
    }));
    assert!(adapter.events().iter().any(|event| {
        event.code == event_codes::FRANKENSQLITE_WRITE_FAIL && event.detail.contains("value length")
    }));

    for idx in 0..MAX_STORE_ENTRIES {
        adapter
            .write(
                &caller,
                PersistenceClass::Cache,
                &format!("cache-{idx}"),
                b"x",
            )
            .expect("bounded store should accept entries until capacity");
    }

    let overflow_err = adapter
        .write(
            &caller,
            PersistenceClass::Cache,
            "cache-overflow",
            b"blocked",
        )
        .expect_err("new entry past store capacity must fail closed");
    assert!(matches!(overflow_err, AdapterError::WriteFailure { .. }));
    assert_eq!(adapter.summary().total_writes, MAX_STORE_ENTRIES);
    assert_eq!(adapter.summary().write_failures, 3);
    assert!(
        !adapter
            .read(&caller, PersistenceClass::Cache, "cache-overflow")
            .expect("read should remain authorized")
            .found
    );

    adapter
        .write(&caller, PersistenceClass::Cache, "cache-0", b"updated")
        .expect("overwrite at capacity must not grow the store");
    let updated = adapter
        .read(&caller, PersistenceClass::Cache, "cache-0")
        .expect("updated entry should remain readable");
    assert_eq!(updated.value.as_deref(), Some(b"updated".as_slice()));
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
