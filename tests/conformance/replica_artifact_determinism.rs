//! Conformance tests for bd-1iyx: multi-replica determinism verification.
//!
//! Instantiates N independent processing pipelines with identical content
//! and configuration, runs them to completion, and compares all output
//! artifacts byte-for-byte.
//!
//! ## Event Codes
//!
//! - `DETERMINISM_CHECK_STARTED` — Test run begins for a fixture
//! - `DETERMINISM_CHECK_PASSED` — All replicas produced identical outputs
//! - `DETERMINISM_CHECK_FAILED` — Divergence detected between replicas

// Pull in the source modules directly (binary crate, no lib.rs)
#[path = "../../crates/franken-node/src/encoding/deterministic_seed.rs"]
mod deterministic_seed;

use deterministic_seed::{
    ContentHash, DeterministicSeed, DeterministicSeedDeriver, DomainTag, ScheduleConfig,
    derive_seed,
};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

const DETERMINISM_CHECK_STARTED: &str = "DETERMINISM_CHECK_STARTED";
const DETERMINISM_CHECK_PASSED: &str = "DETERMINISM_CHECK_PASSED";
const DETERMINISM_CHECK_FAILED: &str = "DETERMINISM_CHECK_FAILED";

// ---------------------------------------------------------------------------
// Divergence reporting
// ---------------------------------------------------------------------------

/// Describes a single divergence between replica artifacts.
#[derive(Debug)]
struct Divergence {
    artifact_name: String,
    first_mismatch_offset: usize,
    replica_a: u8,
    replica_b: u8,
    context_hex_a: String,
    context_hex_b: String,
    root_cause: String,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "divergence in '{}' at offset {}: replica_a=0x{:02x} vs replica_b=0x{:02x} ({})\n  context_a: {}\n  context_b: {}",
            self.artifact_name,
            self.first_mismatch_offset,
            self.replica_a,
            self.replica_b,
            self.root_cause,
            self.context_hex_a,
            self.context_hex_b,
        )
    }
}

/// Compare two byte slices and return a Divergence if they differ.
fn compare_artifacts(name: &str, a: &[u8], b: &[u8]) -> Option<Divergence> {
    if a == b {
        return None;
    }

    let min_len = a.len().min(b.len());

    // Find first mismatch
    for i in 0..min_len {
        if a[i] != b[i] {
            let ctx_start = i.saturating_sub(8);
            let ctx_end_a = (i + 8).min(a.len());
            let ctx_end_b = (i + 8).min(b.len());
            return Some(Divergence {
                artifact_name: name.to_string(),
                first_mismatch_offset: i,
                replica_a: a[i],
                replica_b: b[i],
                context_hex_a: hex::encode(&a[ctx_start..ctx_end_a]),
                context_hex_b: hex::encode(&b[ctx_start..ctx_end_b]),
                root_cause: guess_root_cause(name, i, a, b),
            });
        }
    }

    // Length mismatch
    Some(Divergence {
        artifact_name: name.to_string(),
        first_mismatch_offset: min_len,
        replica_a: if a.len() > min_len { a[min_len] } else { 0 },
        replica_b: if b.len() > min_len { b[min_len] } else { 0 },
        context_hex_a: format!("len={}", a.len()),
        context_hex_b: format!("len={}", b.len()),
        root_cause: "length mismatch".to_string(),
    })
}

/// Heuristic root-cause guesser for common divergence patterns.
fn guess_root_cause(_name: &str, offset: usize, a: &[u8], b: &[u8]) -> String {
    // Check if the divergence looks like a timestamp (8 bytes at aligned offset)
    if offset % 8 == 0 && offset + 8 <= a.len() && offset + 8 <= b.len() {
        let va = u64::from_le_bytes(a[offset..offset + 8].try_into().unwrap());
        let vb = u64::from_le_bytes(b[offset..offset + 8].try_into().unwrap());
        let diff = if va > vb { va - vb } else { vb - va };
        // If values are close (within 10 seconds in milliseconds), likely timestamp
        if diff < 10_000 && diff > 0 {
            return "timestamp field differs (values within 10s)".to_string();
        }
    }

    // Check for hash map ordering (often appears as reordered but same bytes)
    if offset > 0 {
        let window = 32.min(a.len() - offset).min(b.len() - offset);
        let a_window: Vec<u8> = a[offset..offset + window].to_vec();
        let mut b_window: Vec<u8> = b[offset..offset + window].to_vec();
        b_window.sort();
        let mut a_sorted = a_window.clone();
        a_sorted.sort();
        if a_sorted == b_window {
            return "hash map ordering differs (same bytes, different order)".to_string();
        }
    }

    format!("unknown cause at byte offset {}", offset)
}

// ---------------------------------------------------------------------------
// Replica simulation
// ---------------------------------------------------------------------------

/// A simulated replica that derives seeds from fixtures.
struct Replica {
    id: usize,
    deriver: DeterministicSeedDeriver,
}

impl Replica {
    fn new(id: usize) -> Self {
        Self {
            id,
            deriver: DeterministicSeedDeriver::new(),
        }
    }

    /// Process a fixture and return (domain_label, seed_bytes) pairs.
    fn process_fixture(
        &mut self,
        content_hash: &ContentHash,
        domains: &[DomainTag],
        config: &ScheduleConfig,
    ) -> Vec<(String, Vec<u8>)> {
        let mut artifacts = Vec::new();
        for domain in domains {
            let (seed, _bump) = self.deriver.derive_seed(domain, content_hash, config);
            artifacts.push((format!("seed_{}", domain.label()), seed.bytes.to_vec()));
        }
        artifacts
    }
}

/// Parse domain label string to DomainTag.
fn parse_domain(s: &str) -> DomainTag {
    match s {
        "encoding" => DomainTag::Encoding,
        "repair" => DomainTag::Repair,
        "scheduling" => DomainTag::Scheduling,
        "placement" => DomainTag::Placement,
        "verification" => DomainTag::Verification,
        other => panic!("unknown domain: {}", other),
    }
}

// ---------------------------------------------------------------------------
// Fixture runner
// ---------------------------------------------------------------------------

struct FixtureResult {
    fixture_name: String,
    replica_count: usize,
    artifact_count: usize,
    all_identical: bool,
    first_divergence: Option<Divergence>,
}

fn run_fixture(
    fixture_name: &str,
    content_hash: &ContentHash,
    domains: &[DomainTag],
    config: &ScheduleConfig,
    replica_count: usize,
) -> FixtureResult {
    let _ = DETERMINISM_CHECK_STARTED;

    let mut all_artifacts: Vec<Vec<(String, Vec<u8>)>> = Vec::new();

    for i in 0..replica_count {
        let mut replica = Replica::new(i);
        let artifacts = replica.process_fixture(content_hash, domains, config);
        all_artifacts.push(artifacts);
    }

    let reference = &all_artifacts[0];
    let artifact_count = reference.len();
    let mut first_divergence: Option<Divergence> = None;

    for replica_artifacts in &all_artifacts[1..] {
        if replica_artifacts.len() != reference.len() {
            first_divergence = Some(Divergence {
                artifact_name: "artifact_count".to_string(),
                first_mismatch_offset: 0,
                replica_a: reference.len() as u8,
                replica_b: replica_artifacts.len() as u8,
                context_hex_a: String::new(),
                context_hex_b: String::new(),
                root_cause: "different number of artifacts".to_string(),
            });
            break;
        }

        for (i, (ref_name, ref_bytes)) in reference.iter().enumerate() {
            let (rep_name, rep_bytes) = &replica_artifacts[i];
            if ref_name != rep_name {
                first_divergence = Some(Divergence {
                    artifact_name: format!("artifact_name[{}]", i),
                    first_mismatch_offset: 0,
                    replica_a: 0,
                    replica_b: 0,
                    context_hex_a: ref_name.clone(),
                    context_hex_b: rep_name.clone(),
                    root_cause: "artifact name mismatch".to_string(),
                });
                break;
            }
            if let Some(div) = compare_artifacts(ref_name, ref_bytes, rep_bytes) {
                first_divergence = Some(div);
                break;
            }
        }

        if first_divergence.is_some() {
            break;
        }
    }

    let all_identical = first_divergence.is_none();
    if all_identical {
        let _ = DETERMINISM_CHECK_PASSED;
    } else {
        let _ = DETERMINISM_CHECK_FAILED;
    }

    FixtureResult {
        fixture_name: fixture_name.to_string(),
        replica_count,
        artifact_count,
        all_identical,
        first_divergence,
    }
}

// ---------------------------------------------------------------------------
// Expected seed verification
// ---------------------------------------------------------------------------

fn verify_expected_seeds(
    content_hash: &ContentHash,
    domains: &[DomainTag],
    config: &ScheduleConfig,
    expected_seeds: &BTreeMap<String, String>,
) -> Vec<(String, bool, String)> {
    let mut results = Vec::new();
    for domain in domains {
        let seed = derive_seed(domain, content_hash, config);
        let hex = seed.to_hex();
        let label = domain.label().to_string();
        if let Some(expected) = expected_seeds.get(&label) {
            let ok = &hex == expected;
            results.push((
                label,
                ok,
                if ok {
                    "match".to_string()
                } else {
                    format!("expected {}, got {}", expected, hex)
                },
            ));
        }
    }
    results
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_REPLICAS: usize = 3;

    // -- Fixture: small_encoding -------------------------------------------

    #[test]
    fn test_small_encoding_replicas_identical() {
        let ch = ContentHash::from_bytes([0u8; 32]);
        let cfg = ScheduleConfig::new(1)
            .with_param("chunk_size", "65536")
            .with_param("erasure_k", "4")
            .with_param("erasure_m", "2");
        let domains = vec![
            DomainTag::Encoding,
            DomainTag::Repair,
            DomainTag::Scheduling,
        ];

        let result = run_fixture("small_encoding", &ch, &domains, &cfg, DEFAULT_REPLICAS);
        assert!(
            result.all_identical,
            "small_encoding: replicas diverged: {:?}",
            result.first_divergence.map(|d| d.to_string())
        );
        assert_eq!(result.artifact_count, 3);
    }

    #[test]
    fn test_small_encoding_expected_seeds() {
        let ch = ContentHash::from_bytes([0u8; 32]);
        let cfg = ScheduleConfig::new(1)
            .with_param("chunk_size", "65536")
            .with_param("erasure_k", "4")
            .with_param("erasure_m", "2");
        let domains = vec![
            DomainTag::Encoding,
            DomainTag::Repair,
            DomainTag::Scheduling,
        ];
        let mut expected = BTreeMap::new();
        expected.insert(
            "encoding".to_string(),
            "5c3b07805bc7aec22bc2b91ad7aa65c7c8785d5707de02e911fea345fc92d2d2".to_string(),
        );
        expected.insert(
            "repair".to_string(),
            "3288d4f014f645a3f4cb540f1b20cf88b60e12d6ed312027a1a5937348e03e90".to_string(),
        );
        expected.insert(
            "scheduling".to_string(),
            "37241cb9f603b259036ffb7a82cfd6d68deaa8a6dd45f54b3810dbdcaa9da9e4".to_string(),
        );

        let results = verify_expected_seeds(&ch, &domains, &cfg, &expected);
        for (label, ok, detail) in &results {
            assert!(ok, "seed mismatch for domain {}: {}", label, detail);
        }
    }

    // -- Fixture: medium_multi_domain ---------------------------------------

    #[test]
    fn test_medium_multi_domain_replicas_identical() {
        let ch = ContentHash::from_bytes([0xab; 32]);
        let cfg = ScheduleConfig::new(2)
            .with_param("chunk_size", "131072")
            .with_param("erasure_k", "8")
            .with_param("erasure_m", "4")
            .with_param("replicas", "3");
        let domains = vec![
            DomainTag::Encoding,
            DomainTag::Repair,
            DomainTag::Scheduling,
            DomainTag::Placement,
            DomainTag::Verification,
        ];

        let result = run_fixture("medium_multi_domain", &ch, &domains, &cfg, DEFAULT_REPLICAS);
        assert!(
            result.all_identical,
            "medium_multi_domain: replicas diverged: {:?}",
            result.first_divergence.map(|d| d.to_string())
        );
        assert_eq!(result.artifact_count, 5);
    }

    #[test]
    fn test_medium_multi_domain_expected_seeds() {
        let ch = ContentHash::from_bytes([0xab; 32]);
        let cfg = ScheduleConfig::new(2)
            .with_param("chunk_size", "131072")
            .with_param("erasure_k", "8")
            .with_param("erasure_m", "4")
            .with_param("replicas", "3");
        let domains = vec![
            DomainTag::Encoding,
            DomainTag::Repair,
            DomainTag::Scheduling,
            DomainTag::Placement,
            DomainTag::Verification,
        ];
        let mut expected = BTreeMap::new();
        expected.insert(
            "encoding".to_string(),
            "8d1f2a24520700c91929a66a161c92295f8ff8d024d04d15b0fc4f93fac90d34".to_string(),
        );
        expected.insert(
            "repair".to_string(),
            "c927cdea6baffc735d855ce39a22a64783e9708b07e417fc39a32ac2c92ca8e5".to_string(),
        );
        expected.insert(
            "scheduling".to_string(),
            "ea98014f58ab4a3e761bf4815ad980d924ef91cdf8f2750b39c11d7ec7feb0aa".to_string(),
        );
        expected.insert(
            "placement".to_string(),
            "262a150f6e3b09146a0da27acfe458d8c8d6e3d5a9387f26950d3c723cf0a6c3".to_string(),
        );
        expected.insert(
            "verification".to_string(),
            "075c510235ca74e2225153c3fb418d2b6259bd7fc9f8f7dea5351b610d190f27".to_string(),
        );

        let results = verify_expected_seeds(&ch, &domains, &cfg, &expected);
        for (label, ok, detail) in &results {
            assert!(ok, "seed mismatch for domain {}: {}", label, detail);
        }
    }

    // -- Fixture: edge_case_minimal -----------------------------------------

    #[test]
    fn test_edge_case_minimal_replicas_identical() {
        let mut h = [0u8; 32];
        h[31] = 1;
        let ch = ContentHash::from_bytes(h);
        let cfg = ScheduleConfig::new(1);
        let domains = vec![DomainTag::Encoding, DomainTag::Repair];

        let result = run_fixture("edge_case_minimal", &ch, &domains, &cfg, DEFAULT_REPLICAS);
        assert!(
            result.all_identical,
            "edge_case_minimal: replicas diverged: {:?}",
            result.first_divergence.map(|d| d.to_string())
        );
        assert_eq!(result.artifact_count, 2);
    }

    #[test]
    fn test_edge_case_minimal_expected_seeds() {
        let mut h = [0u8; 32];
        h[31] = 1;
        let ch = ContentHash::from_bytes(h);
        let cfg = ScheduleConfig::new(1);
        let domains = vec![DomainTag::Encoding, DomainTag::Repair];
        let mut expected = BTreeMap::new();
        expected.insert(
            "encoding".to_string(),
            "96f841d435f56cbaff467b6d93b5129dce983a5d243f4dd6d7ca8f82d7b02b7c".to_string(),
        );
        expected.insert(
            "repair".to_string(),
            "80287ee0edd64bb10d66304b2b61f633ff6e06ef4f5ce385f433446fcadbbb59".to_string(),
        );

        let results = verify_expected_seeds(&ch, &domains, &cfg, &expected);
        for (label, ok, detail) in &results {
            assert!(ok, "seed mismatch for domain {}: {}", label, detail);
        }
    }

    // -- Scalability: 10 replicas -------------------------------------------

    #[test]
    fn test_ten_replicas_identical() {
        let ch = ContentHash::from_bytes([0u8; 32]);
        let cfg = ScheduleConfig::new(1).with_param("chunk_size", "65536");
        let domains = vec![DomainTag::Encoding, DomainTag::Repair];

        let result = run_fixture("ten_replicas", &ch, &domains, &cfg, 10);
        assert!(result.all_identical);
    }

    // -- Divergence detection: intentional injection -------------------------

    #[test]
    fn test_divergence_detected_when_injected() {
        // Simulate divergence by comparing artifacts from different inputs
        let cfg = ScheduleConfig::new(1).with_param("chunk_size", "65536");
        let domains = vec![DomainTag::Encoding];

        let ch_a = ContentHash::from_bytes([0u8; 32]);
        let ch_b = ContentHash::from_bytes([1u8; 32]);

        let mut replica_a = Replica::new(0);
        let mut replica_b = Replica::new(1);

        let arts_a = replica_a.process_fixture(&ch_a, &domains, &cfg);
        let arts_b = replica_b.process_fixture(&ch_b, &domains, &cfg);

        let div = compare_artifacts("seed_encoding", &arts_a[0].1, &arts_b[0].1);
        assert!(
            div.is_some(),
            "should detect divergence with different inputs"
        );
        let div = div.unwrap();
        assert!(!div.context_hex_a.is_empty());
        assert!(!div.context_hex_b.is_empty());
    }

    #[test]
    fn test_divergence_reports_correct_offset() {
        let a = vec![0u8, 1, 2, 3, 4, 5];
        let b = vec![0u8, 1, 2, 99, 4, 5]; // differs at offset 3
        let div = compare_artifacts("test", &a, &b).unwrap();
        assert_eq!(div.first_mismatch_offset, 3);
        assert_eq!(div.replica_a, 3);
        assert_eq!(div.replica_b, 99);
    }

    #[test]
    fn test_divergence_length_mismatch() {
        let a = vec![0u8, 1, 2];
        let b = vec![0u8, 1, 2, 3, 4];
        let div = compare_artifacts("test", &a, &b).unwrap();
        assert_eq!(div.root_cause, "length mismatch");
    }

    #[test]
    fn test_no_divergence_identical() {
        let a = vec![0u8, 1, 2, 3];
        let b = vec![0u8, 1, 2, 3];
        assert!(compare_artifacts("test", &a, &b).is_none());
    }

    // -- Root cause hinting -------------------------------------------------

    #[test]
    fn test_timestamp_root_cause_hint() {
        // Construct two 16-byte arrays where first 8 bytes are u64 LE
        // with values 1000ms apart
        let mut a = vec![0u8; 16];
        let mut b = vec![0u8; 16];
        let ts_a: u64 = 1_708_000_000_000;
        let ts_b: u64 = 1_708_000_005_000; // 5 seconds later
        a[0..8].copy_from_slice(&ts_a.to_le_bytes());
        b[0..8].copy_from_slice(&ts_b.to_le_bytes());
        let div = compare_artifacts("test", &a, &b).unwrap();
        assert!(
            div.root_cause.contains("timestamp"),
            "should hint timestamp: {}",
            div.root_cause
        );
    }

    // -- Context hex dump ---------------------------------------------------

    #[test]
    fn test_context_hex_dump_correct_length() {
        let a: Vec<u8> = (0..32).collect();
        let mut b = a.clone();
        b[16] = 255; // flip byte at offset 16
        let div = compare_artifacts("test", &a, &b).unwrap();
        // Context should be 16 bytes (8 before + 8 after), so 32 hex chars
        assert!(div.context_hex_a.len() <= 32);
        assert!(div.context_hex_b.len() <= 32);
    }

    // -- Event codes exist ---------------------------------------------------

    #[test]
    fn test_event_codes() {
        assert_eq!(DETERMINISM_CHECK_STARTED, "DETERMINISM_CHECK_STARTED");
        assert_eq!(DETERMINISM_CHECK_PASSED, "DETERMINISM_CHECK_PASSED");
        assert_eq!(DETERMINISM_CHECK_FAILED, "DETERMINISM_CHECK_FAILED");
    }

    // -- Configurable replica count ------------------------------------------

    #[test]
    fn test_single_replica_always_passes() {
        let ch = ContentHash::from_bytes([0u8; 32]);
        let cfg = ScheduleConfig::new(1);
        let result = run_fixture("single", &ch, &[DomainTag::Encoding], &cfg, 1);
        assert!(result.all_identical);
    }

    // -- All fixtures combined -----------------------------------------------

    #[test]
    fn test_all_fixtures_pass() {
        let fixtures = vec![
            (
                "small_encoding",
                [0u8; 32],
                vec![
                    DomainTag::Encoding,
                    DomainTag::Repair,
                    DomainTag::Scheduling,
                ],
                ScheduleConfig::new(1)
                    .with_param("chunk_size", "65536")
                    .with_param("erasure_k", "4")
                    .with_param("erasure_m", "2"),
            ),
            (
                "medium_multi_domain",
                [0xab; 32],
                vec![
                    DomainTag::Encoding,
                    DomainTag::Repair,
                    DomainTag::Scheduling,
                    DomainTag::Placement,
                    DomainTag::Verification,
                ],
                ScheduleConfig::new(2)
                    .with_param("chunk_size", "131072")
                    .with_param("erasure_k", "8")
                    .with_param("erasure_m", "4")
                    .with_param("replicas", "3"),
            ),
            (
                "edge_case_minimal",
                {
                    let mut h = [0u8; 32];
                    h[31] = 1;
                    h
                },
                vec![DomainTag::Encoding, DomainTag::Repair],
                ScheduleConfig::new(1),
            ),
        ];

        for (name, hash_bytes, domains, config) in &fixtures {
            let ch = ContentHash::from_bytes(*hash_bytes);
            let result = run_fixture(name, &ch, domains, config, DEFAULT_REPLICAS);
            assert!(
                result.all_identical,
                "fixture '{}' failed: {:?}",
                name,
                result.first_divergence.map(|d| d.to_string())
            );
        }
    }

    // -- Divergence display format ------------------------------------------

    #[test]
    fn test_divergence_display() {
        let div = Divergence {
            artifact_name: "test_artifact".to_string(),
            first_mismatch_offset: 42,
            replica_a: 0xAA,
            replica_b: 0xBB,
            context_hex_a: "aa".to_string(),
            context_hex_b: "bb".to_string(),
            root_cause: "test cause".to_string(),
        };
        let display = format!("{}", div);
        assert!(display.contains("test_artifact"));
        assert!(display.contains("42"));
        assert!(display.contains("0xaa"));
        assert!(display.contains("0xbb"));
        assert!(display.contains("test cause"));
    }

    // -- Parse domain round-trip --------------------------------------------

    #[test]
    fn test_parse_all_domains() {
        for label in &[
            "encoding",
            "repair",
            "scheduling",
            "placement",
            "verification",
        ] {
            let domain = parse_domain(label);
            assert_eq!(domain.label(), *label);
        }
    }

    #[test]
    #[should_panic(expected = "unknown domain")]
    fn test_parse_unknown_domain_panics() {
        parse_domain("nonexistent");
    }
}
