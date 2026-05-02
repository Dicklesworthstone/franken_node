#[path = "../src/encoding/deterministic_seed.rs"]
mod deterministic_seed;

use deterministic_seed::{
    ContentHash, DeterministicSeed, DomainTag, ScheduleConfig, VersionBumpRecord,
};
use proptest::{collection::btree_map, prelude::*};

fn domain_strategy() -> impl Strategy<Value = DomainTag> {
    prop_oneof![
        Just(DomainTag::Encoding),
        Just(DomainTag::Repair),
        Just(DomainTag::Scheduling),
        Just(DomainTag::Placement),
        Just(DomainTag::Verification),
    ]
}

fn bounded_text() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.:/= -]{0,32}"
}

fn schedule_config_strategy() -> impl Strategy<Value = ScheduleConfig> {
    (
        1_u32..=u32::MAX,
        btree_map(bounded_text(), bounded_text(), 0..16),
    )
        .prop_map(|(version, parameters)| ScheduleConfig {
            version,
            parameters,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn content_hash_hex_and_json_roundtrip(bytes in any::<[u8; 32]>()) {
        let content_hash = ContentHash::from_bytes(bytes);
        let hex = content_hash.to_hex();
        let decoded_from_hex = ContentHash::from_hex(&hex)
            .expect("content hash hex output should parse");
        prop_assert_eq!(&decoded_from_hex, &content_hash);

        let encoded = serde_json::to_string(&content_hash)
            .expect("content hash should encode");
        let decoded_from_json: ContentHash = serde_json::from_str(&encoded)
            .expect("encoded content hash should decode");
        prop_assert_eq!(&decoded_from_json, &content_hash);
        prop_assert_eq!(serde_json::to_string(&decoded_from_json).expect("re-encode"), encoded);
    }

    #[test]
    fn schedule_config_json_roundtrip(config in schedule_config_strategy()) {
        let encoded = serde_json::to_string(&config)
            .expect("schedule config should encode");
        let decoded: ScheduleConfig = serde_json::from_str(&encoded)
            .expect("encoded schedule config should decode");

        prop_assert_eq!(&decoded, &config);
        prop_assert_eq!(decoded.config_hash(), config.config_hash());
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }

    #[test]
    fn deterministic_seed_json_roundtrip(
        bytes in any::<[u8; 32]>(),
        domain in domain_strategy(),
        config_version in any::<u32>(),
    ) {
        let seed = DeterministicSeed {
            bytes,
            domain,
            config_version,
        };
        let encoded = serde_json::to_string(&seed)
            .expect("deterministic seed should encode");
        let decoded: DeterministicSeed = serde_json::from_str(&encoded)
            .expect("encoded deterministic seed should decode");

        prop_assert_eq!(&decoded, &seed);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }

    #[test]
    fn version_bump_record_json_roundtrip(
        domain in domain_strategy(),
        content_hash in "[0-9a-f]{64}",
        old_config_hash in "[0-9a-f]{64}",
        new_config_hash in "[0-9a-f]{64}",
        old_seed_hex in "[0-9a-f]{64}",
        new_seed_hex in "[0-9a-f]{64}",
        old_version in any::<u32>(),
        new_version in any::<u32>(),
        bump_reason in bounded_text(),
        timestamp in "20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z",
    ) {
        let record = VersionBumpRecord {
            domain,
            content_hash_hex: content_hash,
            old_config_hash,
            new_config_hash,
            old_seed_hex,
            new_seed_hex,
            old_version,
            new_version,
            bump_reason,
            timestamp,
        };
        let encoded = serde_json::to_string(&record)
            .expect("version bump record should encode");
        let decoded: VersionBumpRecord = serde_json::from_str(&encoded)
            .expect("encoded version bump record should decode");

        prop_assert_eq!(&decoded, &record);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }
}
