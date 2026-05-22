#![no_main]
#![forbid(unsafe_code)]

//! Structure-aware fuzzing for federation ATC reciprocity controls.
//!
//! The target exercises bounded contribution batches through the public
//! `ReciprocityEngine` API and checks deterministic tier assignment, grace and
//! exception precedence, free-rider blocking, audit integrity, matrix
//! aggregation, and JSON round trips.

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use chrono::{DateTime, FixedOffset};
use frankenengine_node::federation::atc_reciprocity::{
    event_codes, AccessAuditEntry, AccessDecision, AccessTier, ContributionMetrics,
    ReciprocityConfig, ReciprocityEngine, ReciprocityMatrix,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_METRICS: usize = 64;
const MAX_LABEL_BYTES: usize = 16;
const ACTIVE_TIMESTAMP: &str = "2026-02-20T00:00:00Z";
const EPSILON: f64 = 1.0e-9;

#[derive(Debug)]
struct ReciprocityCase {
    config: ConfigSpec,
    timestamp_seed: u8,
    snapshot_seed: Vec<u8>,
    metrics: Vec<MetricsSpec>,
}

impl<'a> Arbitrary<'a> for ReciprocityCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            config: ConfigSpec::arbitrary(u)?,
            timestamp_seed: u8::arbitrary(u)?,
            snapshot_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            metrics: bounded_vec(u, MAX_METRICS)?,
        })
    }
}

#[derive(Debug)]
struct ConfigSpec {
    full_seed: u16,
    standard_seed: u16,
    limited_seed: u16,
    grace_seed: u32,
    grace_tier_seed: u8,
    flags: u8,
}

impl<'a> Arbitrary<'a> for ConfigSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            full_seed: u16::arbitrary(u)?,
            standard_seed: u16::arbitrary(u)?,
            limited_seed: u16::arbitrary(u)?,
            grace_seed: u32::arbitrary(u)?,
            grace_tier_seed: u8::arbitrary(u)?,
            flags: u8::arbitrary(u)?,
        })
    }
}

impl ConfigSpec {
    fn to_config(&self) -> ReciprocityConfig {
        let mut thresholds = [
            threshold_from(self.limited_seed),
            threshold_from(self.standard_seed),
            threshold_from(self.full_seed),
        ];
        thresholds.sort_by(|left, right| left.total_cmp(right));
        let [limited, standard, full] = thresholds;
        ReciprocityConfig {
            full_tier_min_ratio: full,
            standard_tier_min_ratio: standard,
            limited_tier_min_ratio: limited,
            grace_period_seconds: u64::from(self.grace_seed % (86_400 * 30)),
            grace_period_tier: tier_from(self.grace_tier_seed),
            use_quality_adjustment: self.flags & 0b0000_0001 != 0,
        }
    }
}

#[derive(Debug)]
struct MetricsSpec {
    id_seed: Vec<u8>,
    made_seed: u32,
    consumed_seed: u32,
    quality_seed: u16,
    age_seed: u32,
    flags: u8,
    reason_seed: Vec<u8>,
    expiry_seed: u8,
}

impl<'a> Arbitrary<'a> for MetricsSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            id_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            made_seed: u32::arbitrary(u)?,
            consumed_seed: u32::arbitrary(u)?,
            quality_seed: u16::arbitrary(u)?,
            age_seed: u32::arbitrary(u)?,
            flags: u8::arbitrary(u)?,
            reason_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            expiry_seed: u8::arbitrary(u)?,
        })
    }
}

impl MetricsSpec {
    fn to_metrics(&self, index: usize) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: bounded_label("participant", index, &self.id_seed),
            contributions_made: u64::from(self.made_seed % 1_000_000),
            intelligence_consumed: u64::from(self.consumed_seed % 1_000_000),
            contribution_quality: quality_from(self.quality_seed),
            membership_age_seconds: u64::from(self.age_seed % (86_400 * 60)),
            has_exception: self.flags & 0b0000_0001 != 0,
            exception_reason: if self.flags & 0b0000_0010 != 0 {
                Some(bounded_label("reason", index, &self.reason_seed))
            } else {
                None
            },
            exception_expires_at: exception_expiry_from(self.expiry_seed),
        }
    }
}

#[derive(Debug)]
struct ExpectedDecision {
    tier: AccessTier,
    granted: bool,
    exception_applied: bool,
    grace_period_active: bool,
    event_code: &'static str,
}

fn bounded_vec<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    max_len: usize,
) -> ArbResult<Vec<T>> {
    let len = u.int_in_range::<usize>(0..=max_len)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::arbitrary(u)?);
    }
    Ok(out)
}

fn bounded_bytes(u: &mut Unstructured<'_>, max_len: usize) -> ArbResult<Vec<u8>> {
    let len = u.int_in_range::<usize>(0..=max_len)?;
    Ok(u.bytes(len)?.to_vec())
}

fn bounded_label(prefix: &str, index: usize, seed: &[u8]) -> String {
    let mut out = String::with_capacity(prefix.len().saturating_add(MAX_LABEL_BYTES + 24));
    out.push_str(prefix);
    out.push('-');
    out.push_str(&index.to_string());
    for byte in seed.iter().take(MAX_LABEL_BYTES) {
        out.push('-');
        out.push(char::from(b'a'.saturating_add(byte % 26)));
    }
    out
}

fn threshold_from(seed: u16) -> f64 {
    f64::from(seed % 1_000) / 1_000.0
}

fn quality_from(seed: u16) -> f64 {
    match seed % 6 {
        0 => f64::NAN,
        1 => -0.5,
        2 => 1.5,
        _ => f64::from(seed % 1_000) / 1_000.0,
    }
}

fn tier_from(seed: u8) -> AccessTier {
    match seed % 4 {
        0 => AccessTier::Blocked,
        1 => AccessTier::Limited,
        2 => AccessTier::Standard,
        _ => AccessTier::Full,
    }
}

fn timestamp_from(seed: u8) -> String {
    match seed % 4 {
        0 => ACTIVE_TIMESTAMP,
        1 => "2025-01-01T00:00:00Z",
        2 => "2027-02-20T00:00:00Z",
        _ => "not-a-timestamp",
    }
    .to_string()
}

fn exception_expiry_from(seed: u8) -> Option<String> {
    match seed % 5 {
        0 => Some("2027-01-01T00:00:00Z".to_string()),
        1 => Some("2025-01-01T00:00:00Z".to_string()),
        2 => Some("not-a-timestamp".to_string()),
        3 => None,
        _ => Some("2026-02-20T00:00:00Z".to_string()),
    }
}

fn metrics_from(specs: &[MetricsSpec]) -> Vec<ContributionMetrics> {
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| spec.to_metrics(index))
        .collect()
}

fn parse_rfc3339(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

fn exception_is_active(metrics: &ContributionMetrics, timestamp: &str) -> bool {
    if !metrics.has_exception {
        return false;
    }
    let Some(expires_at) = metrics
        .exception_expires_at
        .as_deref()
        .and_then(parse_rfc3339)
    else {
        return false;
    };
    let Some(now) = parse_rfc3339(timestamp) else {
        return false;
    };
    now < expires_at
}

fn classify_tier(config: &ReciprocityConfig, effective_ratio: f64) -> AccessTier {
    if effective_ratio >= config.full_tier_min_ratio {
        AccessTier::Full
    } else if effective_ratio >= config.standard_tier_min_ratio {
        AccessTier::Standard
    } else if effective_ratio >= config.limited_tier_min_ratio {
        AccessTier::Limited
    } else {
        AccessTier::Blocked
    }
}

fn expected_decision(
    config: &ReciprocityConfig,
    metrics: &ContributionMetrics,
    timestamp: &str,
) -> ExpectedDecision {
    if metrics.membership_age_seconds < config.grace_period_seconds {
        let tier = config.grace_period_tier;
        return ExpectedDecision {
            tier,
            granted: tier != AccessTier::Blocked,
            exception_applied: false,
            grace_period_active: true,
            event_code: event_codes::GRACE_PERIOD_GRANTED,
        };
    }

    if exception_is_active(metrics, timestamp) {
        return ExpectedDecision {
            tier: AccessTier::Standard,
            granted: true,
            exception_applied: true,
            grace_period_active: false,
            event_code: event_codes::EXCEPTION_ACTIVATED,
        };
    }

    let effective_ratio = if config.use_quality_adjustment {
        metrics.quality_adjusted_ratio()
    } else {
        metrics.contribution_ratio()
    };
    let tier = classify_tier(config, effective_ratio);
    ExpectedDecision {
        tier,
        granted: tier != AccessTier::Blocked,
        exception_applied: false,
        grace_period_active: false,
        event_code: if tier == AccessTier::Blocked {
            event_codes::ACCESS_DENIED
        } else {
            event_codes::ACCESS_GRANTED
        },
    }
}

fn expected_feeds(tier: AccessTier) -> Vec<String> {
    tier.accessible_feeds()
        .iter()
        .map(|feed| (*feed).to_string())
        .collect()
}

fn approx_eq(left: f64, right: f64) -> bool {
    (left - right).abs() <= EPSILON
}

fn check_decision(
    decision: &AccessDecision,
    metrics: &ContributionMetrics,
    expected: &ExpectedDecision,
) {
    assert_eq!(decision.participant_id, metrics.participant_id);
    assert_eq!(decision.tier, expected.tier);
    assert_eq!(decision.granted, expected.granted);
    assert_eq!(decision.exception_applied, expected.exception_applied);
    assert_eq!(decision.grace_period_active, expected.grace_period_active);
    assert_eq!(decision.accessible_feeds, expected_feeds(expected.tier));
    assert!(
        (0.0..=1.0).contains(&decision.contribution_ratio),
        "raw contribution ratio must be normalized"
    );
    assert!(
        (0.0..=1.0).contains(&decision.quality_adjusted_ratio),
        "quality-adjusted ratio must be normalized"
    );
    assert!(
        approx_eq(decision.contribution_ratio, metrics.contribution_ratio()),
        "decision must report the same raw ratio as the metrics"
    );
    assert!(
        approx_eq(
            decision.quality_adjusted_ratio,
            metrics.quality_adjusted_ratio()
        ),
        "decision must report the same quality-adjusted ratio as the metrics"
    );
    assert!(
        !decision.reason.is_empty(),
        "access decisions must include an audit reason"
    );
}

fn check_matrix(
    matrix: &ReciprocityMatrix,
    metrics: &[ContributionMetrics],
    config: &ReciprocityConfig,
    timestamp: &str,
) {
    assert_eq!(matrix.total_participants, metrics.len());
    assert_eq!(matrix.entries.len(), metrics.len());
    assert_eq!(matrix.timestamp, timestamp);
    assert_eq!(matrix.content_hash.len(), 64);
    assert_eq!(
        matrix.tier_distribution.values().sum::<usize>(),
        matrix.entries.len()
    );
    assert_eq!(
        matrix.freeriders_blocked,
        matrix
            .entries
            .iter()
            .filter(|entry| entry.tier == AccessTier::Blocked)
            .count()
    );
    assert_eq!(
        matrix.exceptions_active,
        matrix
            .entries
            .iter()
            .filter(|entry| entry.exception_active)
            .count()
    );

    for (metric, entry) in metrics.iter().zip(matrix.entries.iter()) {
        let expected = expected_decision(config, metric, timestamp);
        assert_eq!(entry.participant_id, metric.participant_id);
        assert_eq!(entry.tier, expected.tier);
        assert_eq!(entry.exception_active, expected.exception_applied);
        assert_eq!(entry.grace_period_active, expected.grace_period_active);
        assert!(
            approx_eq(entry.contribution_ratio, metric.contribution_ratio()),
            "matrix entry must preserve raw contribution ratio"
        );
        assert!(
            approx_eq(
                entry.quality_adjusted_ratio,
                metric.quality_adjusted_ratio()
            ),
            "matrix entry must preserve quality-adjusted contribution ratio"
        );
    }
}

fn check_audit_log(
    engine: &ReciprocityEngine,
    metrics: &[ContributionMetrics],
    config: &ReciprocityConfig,
    timestamp: &str,
) {
    assert_eq!(engine.audit_log().len(), metrics.len());
    for (metric, audit) in metrics.iter().zip(engine.audit_log().iter()) {
        let expected = expected_decision(config, metric, timestamp);
        assert_eq!(audit.participant_id, metric.participant_id);
        assert_eq!(audit.timestamp, timestamp);
        assert_eq!(audit.event_code, expected.event_code);
        assert_eq!(audit.content_hash.len(), 64);
        assert_eq!(
            audit.content_hash,
            AccessAuditEntry::compute_hash(&audit.decision)
        );
        check_decision(&audit.decision, metric, &expected);
    }

    let exported = engine.export_audit_jsonl();
    assert!(exported.is_ok(), "audit JSONL export must serialize");
    if let Ok(exported) = exported {
        let line_count = if exported.is_empty() {
            0
        } else {
            exported.lines().count()
        };
        assert_eq!(line_count, engine.audit_log().len());
        for line in exported.lines() {
            let parsed = serde_json::from_str::<AccessAuditEntry>(line);
            assert!(parsed.is_ok(), "each audit JSONL line must parse");
            if let Ok(parsed) = parsed {
                assert_eq!(
                    parsed.content_hash,
                    AccessAuditEntry::compute_hash(&parsed.decision)
                );
            }
        }
    }
}

fn check_serialization(matrix: &ReciprocityMatrix) {
    let encoded = serde_json::to_vec(matrix);
    assert!(encoded.is_ok(), "reciprocity matrix must serialize");
    if let Ok(encoded) = encoded {
        let decoded = serde_json::from_slice::<ReciprocityMatrix>(&encoded);
        assert!(decoded.is_ok(), "reciprocity matrix must deserialize");
        if let Ok(decoded) = decoded {
            assert_eq!(decoded, *matrix);
        }
    }
}

fn check_monotone_tiers() {
    let config = ReciprocityConfig {
        full_tier_min_ratio: 0.8,
        standard_tier_min_ratio: 0.4,
        limited_tier_min_ratio: 0.1,
        grace_period_seconds: 0,
        grace_period_tier: AccessTier::Blocked,
        use_quality_adjustment: false,
    };
    let mut engine = ReciprocityEngine::new(config);
    let low = ContributionMetrics {
        participant_id: "low-ratio".to_string(),
        contributions_made: 1,
        intelligence_consumed: 100,
        contribution_quality: 1.0,
        membership_age_seconds: 86_400,
        has_exception: false,
        exception_reason: None,
        exception_expires_at: None,
    };
    let mid = ContributionMetrics {
        participant_id: "mid-ratio".to_string(),
        contributions_made: 50,
        intelligence_consumed: 100,
        contribution_quality: 1.0,
        membership_age_seconds: 86_400,
        has_exception: false,
        exception_reason: None,
        exception_expires_at: None,
    };
    let high = ContributionMetrics {
        participant_id: "high-ratio".to_string(),
        contributions_made: 100,
        intelligence_consumed: 100,
        contribution_quality: 1.0,
        membership_age_seconds: 86_400,
        has_exception: false,
        exception_reason: None,
        exception_expires_at: None,
    };
    let low_decision = engine.evaluate_access(&low, ACTIVE_TIMESTAMP);
    let mid_decision = engine.evaluate_access(&mid, ACTIVE_TIMESTAMP);
    let high_decision = engine.evaluate_access(&high, ACTIVE_TIMESTAMP);
    assert!(low_decision.tier <= mid_decision.tier);
    assert!(mid_decision.tier <= high_decision.tier);
    assert_eq!(low_decision.tier, AccessTier::Blocked);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(case) = ReciprocityCase::arbitrary(&mut u) else {
        return;
    };

    let config = case.config.to_config();
    let metrics = metrics_from(&case.metrics);
    let timestamp = timestamp_from(case.timestamp_seed);
    let snapshot_id = bounded_label("snapshot", 0, &case.snapshot_seed);

    let mut engine = ReciprocityEngine::new(config.clone());
    let matrix = engine.evaluate_batch(&metrics, &snapshot_id, &timestamp);
    assert_eq!(matrix.snapshot_id, snapshot_id);
    check_matrix(&matrix, &metrics, &config, &timestamp);
    check_audit_log(&engine, &metrics, &config, &timestamp);
    check_serialization(&matrix);

    let mut replay_engine = ReciprocityEngine::new(config.clone());
    let replayed = replay_engine.evaluate_batch(&metrics, &snapshot_id, &timestamp);
    assert_eq!(
        matrix, replayed,
        "same reciprocity inputs must produce the same matrix"
    );

    check_monotone_tiers();
});
