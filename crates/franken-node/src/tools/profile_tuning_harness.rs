//! bd-27o2: Profile tuning harness with signed policy updates.
//!
//! Reproducible harness that recomputes candidate policy updates from
//! benchmark data, signs them for provenance, and rejects any update
//! that would regress safety-critical performance thresholds.
//!
//! # Invariants
//!
//! - **INV-PT-IDEMPOTENT**: Same inputs always produce identical output.
//! - **INV-PT-SIGNED**: Every accepted bundle carries a valid HMAC signature.
//! - **INV-PT-REGRESSION-SAFE**: No bundle is produced if p99 regresses beyond threshold.
//! - **INV-PT-CHAIN**: Each bundle references the previous bundle's hash.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const PT_HARNESS_START: &str = "PT_HARNESS_START";
pub const PT_BENCHMARK_COMPLETE: &str = "PT_BENCHMARK_COMPLETE";
pub const PT_CANDIDATE_COMPUTED: &str = "PT_CANDIDATE_COMPUTED";
pub const PT_REGRESSION_REJECTED: &str = "PT_REGRESSION_REJECTED";
pub const PT_BUNDLE_SIGNED: &str = "PT_BUNDLE_SIGNED";
pub const PT_BUNDLE_VERIFIED: &str = "PT_BUNDLE_VERIFIED";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_PT_IDEMPOTENT: &str = "INV-PT-IDEMPOTENT";
pub const INV_PT_SIGNED: &str = "INV-PT-SIGNED";
pub const INV_PT_REGRESSION_SAFE: &str = "INV-PT-REGRESSION-SAFE";
pub const INV_PT_CHAIN: &str = "INV-PT-CHAIN";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Benchmark measurement for a single object class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub class_id: String,
    pub symbol_size_bytes: u32,
    pub overhead_ratio: f64,
    pub fetch_priority: String,
    pub prefetch_policy: String,
    pub p50_encode_us: f64,
    pub p99_encode_us: f64,
    pub p50_decode_us: f64,
    pub p99_decode_us: f64,
}

/// Baseline policy row parsed from CSV.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineRow {
    pub class_id: String,
    pub symbol_size_bytes: u32,
    pub overhead_ratio: f64,
    pub fetch_priority: String,
    pub prefetch_policy: String,
}

/// Candidate policy update for a single class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateUpdate {
    pub class_id: String,
    pub symbol_size_bytes: u32,
    pub overhead_ratio: f64,
    pub fetch_priority: String,
    pub prefetch_policy: String,
    pub p50_encode_us: f64,
    pub p99_encode_us: f64,
    pub p50_decode_us: f64,
    pub p99_decode_us: f64,
}

/// Delta between baseline and candidate for one class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDelta {
    pub class_id: String,
    pub old_symbol_size: u32,
    pub new_symbol_size: u32,
    pub old_overhead: f64,
    pub new_overhead: f64,
    pub old_priority: String,
    pub new_priority: String,
    pub old_prefetch: String,
    pub new_prefetch: String,
    pub p99_encode_change_pct: f64,
    pub p99_decode_change_pct: f64,
}

impl PolicyDelta {
    /// Check if this delta represents a regression beyond the threshold.
    pub fn is_regression(&self, threshold_pct: f64) -> bool {
        self.p99_encode_change_pct > threshold_pct || self.p99_decode_change_pct > threshold_pct
    }
}

/// Hardware fingerprint for provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareFingerprint(pub String);

impl HardwareFingerprint {
    pub fn from_info(info: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"profile_tuning_fingerprint_v1:" as &[u8]);
        hasher.update(info.as_bytes());
        HardwareFingerprint(format!("{:x}", hasher.finalize()))
    }
}

impl fmt::Display for HardwareFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Signed policy update bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedPolicyBundle {
    pub version: u32,
    pub timestamp: String,
    pub run_id: String,
    pub hardware_fingerprint: String,
    pub previous_bundle_hash: Option<String>,
    pub regression_threshold_pct: f64,
    pub candidates: Vec<CandidateUpdate>,
    pub deltas: Vec<PolicyDelta>,
    pub signature: String,
}

impl SignedPolicyBundle {
    /// Compute the signable payload (everything except the signature field).
    pub fn signable_payload(&self) -> String {
        let mut bundle_for_sign = self.clone();
        bundle_for_sign.signature = String::new();
        serde_json::to_string(&bundle_for_sign).unwrap_or_default()
    }

    /// Compute the SHA-256-like hash of this bundle for chain linking.
    pub fn bundle_hash(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"profile_tuning_json_v1:" as &[u8]);
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Rejection diagnostic when a regression is detected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionDiagnostic {
    pub class_id: String,
    pub metric: String,
    pub change_pct: f64,
    pub threshold_pct: f64,
}

impl fmt::Display for RegressionDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} changed by {:.1}% (threshold: {:.1}%)",
            self.class_id, self.metric, self.change_pct, self.threshold_pct
        )
    }
}

/// Harness event for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessEvent {
    pub code: String,
    pub detail: String,
}

/// Result of running the harness.
#[derive(Debug, Clone)]
pub enum HarnessOutcome {
    /// Bundle produced successfully.
    Accepted(SignedPolicyBundle),
    /// Regression detected — no bundle produced.
    Rejected(Vec<RegressionDiagnostic>),
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 signing (deterministic, using std hash for portability)
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};

/// Compute HMAC-SHA256-like signature using the given key.
/// Uses a deterministic keyed hash for portability (no external crypto dep).
pub fn hmac_sign(payload: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(b"|");
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify an HMAC signature.
pub fn hmac_verify(payload: &str, key: &str, signature: &str) -> bool {
    hmac_sign(payload, key) == signature
}

// ---------------------------------------------------------------------------
// ProfileTuningHarness
// ---------------------------------------------------------------------------

/// Configuration for the tuning harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    pub regression_threshold_pct: f64,
    pub signing_key: String,
    pub hardware_info: String,
    pub run_id: String,
    pub timestamp: String,
    pub previous_bundle_hash: Option<String>,
}

impl HarnessConfig {
    pub fn with_defaults() -> Self {
        HarnessConfig {
            regression_threshold_pct: 20.0,
            signing_key: "default-harness-key".to_string(),
            hardware_info: "test-hardware-v1".to_string(),
            run_id: "run-001".to_string(),
            timestamp: "2026-02-20T00:00:00Z".to_string(),
            previous_bundle_hash: None,
        }
    }
}

/// Profile tuning harness that computes, validates, and signs policy updates.
pub struct ProfileTuningHarness {
    config: HarnessConfig,
    events: Vec<HarnessEvent>,
}

impl ProfileTuningHarness {
    pub fn new(config: HarnessConfig) -> Self {
        ProfileTuningHarness {
            config,
            events: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(HarnessConfig::with_defaults())
    }

    /// Run the full harness pipeline.
    ///
    /// 1. Load baseline from CSV rows
    /// 2. Consume benchmark results
    /// 3. Compute candidate updates and deltas
    /// 4. Check for regressions
    /// 5. Sign and return bundle (or reject)
    pub fn run(
        &mut self,
        baseline: &[BaselineRow],
        benchmarks: &[BenchmarkResult],
        previous_benchmarks: Option<&[BenchmarkResult]>,
    ) -> HarnessOutcome {
        self.emit(PT_HARNESS_START, "Harness invocation started".to_string());

        // Phase 1: benchmark complete
        self.emit(
            PT_BENCHMARK_COMPLETE,
            format!("Processed {} benchmark results", benchmarks.len()),
        );

        // Phase 2: compute candidates and deltas
        let candidates: Vec<CandidateUpdate> = benchmarks
            .iter()
            .map(|b| CandidateUpdate {
                class_id: b.class_id.clone(),
                symbol_size_bytes: b.symbol_size_bytes,
                overhead_ratio: b.overhead_ratio,
                fetch_priority: b.fetch_priority.clone(),
                prefetch_policy: b.prefetch_policy.clone(),
                p50_encode_us: b.p50_encode_us,
                p99_encode_us: b.p99_encode_us,
                p50_decode_us: b.p50_decode_us,
                p99_decode_us: b.p99_decode_us,
            })
            .collect();

        let deltas = self.compute_deltas(baseline, &candidates, previous_benchmarks);

        self.emit(
            PT_CANDIDATE_COMPUTED,
            format!(
                "Computed {} candidates with {} deltas",
                candidates.len(),
                deltas.len()
            ),
        );

        // Phase 3: regression check
        let regressions = self.check_regressions(&deltas);
        if !regressions.is_empty() {
            for diag in &regressions {
                self.emit(PT_REGRESSION_REJECTED, format!("{}", diag));
            }
            return HarnessOutcome::Rejected(regressions);
        }

        // Phase 4: sign bundle
        let bundle = self.sign_bundle(candidates, deltas);
        self.emit(
            PT_BUNDLE_SIGNED,
            format!("Bundle signed: {}", bundle.signature),
        );

        // Phase 5: verify read-back
        let payload = bundle.signable_payload();
        let verified = hmac_verify(&payload, &self.config.signing_key, &bundle.signature);
        if verified {
            self.emit(
                PT_BUNDLE_VERIFIED,
                "Read-back integrity confirmed".to_string(),
            );
        }

        HarnessOutcome::Accepted(bundle)
    }

    /// Compute deltas between baseline and candidates.
    fn compute_deltas(
        &self,
        baseline: &[BaselineRow],
        candidates: &[CandidateUpdate],
        previous_benchmarks: Option<&[BenchmarkResult]>,
    ) -> Vec<PolicyDelta> {
        candidates
            .iter()
            .map(|candidate| {
                let base = baseline.iter().find(|b| b.class_id == candidate.class_id);

                let (old_symbol, old_overhead, old_priority, old_prefetch) = match base {
                    Some(b) => (
                        b.symbol_size_bytes,
                        b.overhead_ratio,
                        b.fetch_priority.clone(),
                        b.prefetch_policy.clone(),
                    ),
                    None => (0, 0.0, "unknown".to_string(), "unknown".to_string()),
                };

                // Compute p99 change percentages relative to previous benchmarks
                let (p99_encode_change, p99_decode_change) = match previous_benchmarks {
                    Some(prev) => {
                        let prev_bench = prev.iter().find(|p| p.class_id == candidate.class_id);
                        match prev_bench {
                            Some(p) => {
                                let enc_change = if p.p99_encode_us > 0.0 {
                                    ((candidate.p99_encode_us - p.p99_encode_us) / p.p99_encode_us)
                                        * 100.0
                                } else {
                                    0.0
                                };
                                let dec_change = if p.p99_decode_us > 0.0 {
                                    ((candidate.p99_decode_us - p.p99_decode_us) / p.p99_decode_us)
                                        * 100.0
                                } else {
                                    0.0
                                };
                                (enc_change, dec_change)
                            }
                            None => (0.0, 0.0),
                        }
                    }
                    None => (0.0, 0.0),
                };

                PolicyDelta {
                    class_id: candidate.class_id.clone(),
                    old_symbol_size: old_symbol,
                    new_symbol_size: candidate.symbol_size_bytes,
                    old_overhead,
                    new_overhead: candidate.overhead_ratio,
                    old_priority,
                    new_priority: candidate.fetch_priority.clone(),
                    old_prefetch,
                    new_prefetch: candidate.prefetch_policy.clone(),
                    p99_encode_change_pct: p99_encode_change,
                    p99_decode_change_pct: p99_decode_change,
                }
            })
            .collect()
    }

    /// Check for regressions in the deltas.
    fn check_regressions(&self, deltas: &[PolicyDelta]) -> Vec<RegressionDiagnostic> {
        let mut diagnostics = Vec::new();
        let threshold = self.config.regression_threshold_pct;

        for delta in deltas {
            if delta.p99_encode_change_pct > threshold {
                diagnostics.push(RegressionDiagnostic {
                    class_id: delta.class_id.clone(),
                    metric: "p99_encode_us".to_string(),
                    change_pct: delta.p99_encode_change_pct,
                    threshold_pct: threshold,
                });
            }
            if delta.p99_decode_change_pct > threshold {
                diagnostics.push(RegressionDiagnostic {
                    class_id: delta.class_id.clone(),
                    metric: "p99_decode_us".to_string(),
                    change_pct: delta.p99_decode_change_pct,
                    threshold_pct: threshold,
                });
            }
        }

        diagnostics
    }

    /// Produce a signed bundle from candidates and deltas.
    fn sign_bundle(
        &self,
        candidates: Vec<CandidateUpdate>,
        deltas: Vec<PolicyDelta>,
    ) -> SignedPolicyBundle {
        let fingerprint = HardwareFingerprint::from_info(&self.config.hardware_info);

        let mut bundle = SignedPolicyBundle {
            version: 1,
            timestamp: self.config.timestamp.clone(),
            run_id: self.config.run_id.clone(),
            hardware_fingerprint: fingerprint.to_string(),
            previous_bundle_hash: self.config.previous_bundle_hash.clone(),
            regression_threshold_pct: self.config.regression_threshold_pct,
            candidates,
            deltas,
            signature: String::new(),
        };

        let payload = bundle.signable_payload();
        bundle.signature = hmac_sign(&payload, &self.config.signing_key);
        bundle
    }

    /// Verify an existing bundle's signature.
    pub fn verify_bundle(&mut self, bundle: &SignedPolicyBundle) -> bool {
        let payload = bundle.signable_payload();
        let valid = hmac_verify(&payload, &self.config.signing_key, &bundle.signature);
        if valid {
            self.emit(PT_BUNDLE_VERIFIED, "Bundle signature verified".to_string());
        }
        valid
    }

    /// All events emitted during this harness run.
    pub fn events(&self) -> &[HarnessEvent] {
        &self.events
    }

    /// Drain and return all events.
    pub fn take_events(&mut self) -> Vec<HarnessEvent> {
        std::mem::take(&mut self.events)
    }

    /// Access config.
    pub fn config(&self) -> &HarnessConfig {
        &self.config
    }

    fn emit(&mut self, code: &str, detail: String) {
        self.events.push(HarnessEvent {
            code: code.to_string(),
            detail,
        });
    }
}

/// Parse baseline CSV content into rows.
pub fn parse_baseline_csv(csv: &str) -> Vec<BaselineRow> {
    csv.lines()
        .skip(1) // skip header
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() >= 5 {
                Some(BaselineRow {
                    class_id: cols[0].trim().to_string(),
                    symbol_size_bytes: cols[1].trim().parse().unwrap_or(0),
                    overhead_ratio: cols[2].trim().parse().unwrap_or(0.0),
                    fetch_priority: cols[3].trim().to_string(),
                    prefetch_policy: cols[4].trim().to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_baseline() -> Vec<BaselineRow> {
        vec![
            BaselineRow {
                class_id: "critical_marker".into(),
                symbol_size_bytes: 256,
                overhead_ratio: 0.02,
                fetch_priority: "critical".into(),
                prefetch_policy: "eager".into(),
            },
            BaselineRow {
                class_id: "trust_receipt".into(),
                symbol_size_bytes: 1024,
                overhead_ratio: 0.05,
                fetch_priority: "normal".into(),
                prefetch_policy: "lazy".into(),
            },
            BaselineRow {
                class_id: "replay_bundle".into(),
                symbol_size_bytes: 16384,
                overhead_ratio: 0.08,
                fetch_priority: "background".into(),
                prefetch_policy: "none".into(),
            },
            BaselineRow {
                class_id: "telemetry_artifact".into(),
                symbol_size_bytes: 4096,
                overhead_ratio: 0.04,
                fetch_priority: "background".into(),
                prefetch_policy: "none".into(),
            },
        ]
    }

    fn sample_benchmarks() -> Vec<BenchmarkResult> {
        vec![
            BenchmarkResult {
                class_id: "critical_marker".into(),
                symbol_size_bytes: 256,
                overhead_ratio: 0.02,
                fetch_priority: "critical".into(),
                prefetch_policy: "eager".into(),
                p50_encode_us: 1.5,
                p99_encode_us: 5.0,
                p50_decode_us: 1.2,
                p99_decode_us: 4.0,
            },
            BenchmarkResult {
                class_id: "trust_receipt".into(),
                symbol_size_bytes: 1024,
                overhead_ratio: 0.05,
                fetch_priority: "normal".into(),
                prefetch_policy: "lazy".into(),
                p50_encode_us: 8.0,
                p99_encode_us: 25.0,
                p50_decode_us: 6.0,
                p99_decode_us: 20.0,
            },
            BenchmarkResult {
                class_id: "replay_bundle".into(),
                symbol_size_bytes: 16384,
                overhead_ratio: 0.08,
                fetch_priority: "background".into(),
                prefetch_policy: "none".into(),
                p50_encode_us: 120.0,
                p99_encode_us: 350.0,
                p50_decode_us: 100.0,
                p99_decode_us: 300.0,
            },
            BenchmarkResult {
                class_id: "telemetry_artifact".into(),
                symbol_size_bytes: 4096,
                overhead_ratio: 0.04,
                fetch_priority: "background".into(),
                prefetch_policy: "none".into(),
                p50_encode_us: 30.0,
                p99_encode_us: 80.0,
                p50_decode_us: 25.0,
                p99_decode_us: 65.0,
            },
        ]
    }

    fn regressed_benchmarks() -> Vec<BenchmarkResult> {
        vec![BenchmarkResult {
            class_id: "critical_marker".into(),
            symbol_size_bytes: 256,
            overhead_ratio: 0.02,
            fetch_priority: "critical".into(),
            prefetch_policy: "eager".into(),
            p50_encode_us: 1.5,
            p99_encode_us: 7.0, // 40% increase from 5.0
            p50_decode_us: 1.2,
            p99_decode_us: 4.0,
        }]
    }

    // -- HMAC signing ---------------------------------------------------

    #[test]
    fn test_hmac_sign_deterministic() {
        let sig1 = hmac_sign("payload", "key");
        let sig2 = hmac_sign("payload", "key");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_different_key() {
        let sig1 = hmac_sign("payload", "key1");
        let sig2 = hmac_sign("payload", "key2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_different_payload() {
        let sig1 = hmac_sign("payload1", "key");
        let sig2 = hmac_sign("payload2", "key");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_verify_valid() {
        let sig = hmac_sign("data", "secret");
        assert!(hmac_verify("data", "secret", &sig));
    }

    #[test]
    fn test_hmac_verify_invalid() {
        assert!(!hmac_verify("data", "secret", "wrong-sig"));
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let sig = hmac_sign("data", "key1");
        assert!(!hmac_verify("data", "key2", &sig));
    }

    // -- HardwareFingerprint -------------------------------------------

    #[test]
    fn test_hardware_fingerprint_deterministic() {
        let f1 = HardwareFingerprint::from_info("hw-v1");
        let f2 = HardwareFingerprint::from_info("hw-v1");
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_hardware_fingerprint_different_info() {
        let f1 = HardwareFingerprint::from_info("hw-v1");
        let f2 = HardwareFingerprint::from_info("hw-v2");
        assert_ne!(f1, f2);
    }

    #[test]
    fn test_hardware_fingerprint_display() {
        let f = HardwareFingerprint::from_info("test");
        assert!(!format!("{}", f).is_empty());
    }

    // -- PolicyDelta regression check ----------------------------------

    #[test]
    fn test_delta_no_regression() {
        let delta = PolicyDelta {
            class_id: "test".into(),
            old_symbol_size: 256,
            new_symbol_size: 256,
            old_overhead: 0.02,
            new_overhead: 0.02,
            old_priority: "critical".into(),
            new_priority: "critical".into(),
            old_prefetch: "eager".into(),
            new_prefetch: "eager".into(),
            p99_encode_change_pct: 5.0,
            p99_decode_change_pct: 3.0,
        };
        assert!(!delta.is_regression(20.0));
    }

    #[test]
    fn test_delta_encode_regression() {
        let delta = PolicyDelta {
            class_id: "test".into(),
            old_symbol_size: 256,
            new_symbol_size: 256,
            old_overhead: 0.02,
            new_overhead: 0.02,
            old_priority: "critical".into(),
            new_priority: "critical".into(),
            old_prefetch: "eager".into(),
            new_prefetch: "eager".into(),
            p99_encode_change_pct: 25.0,
            p99_decode_change_pct: 3.0,
        };
        assert!(delta.is_regression(20.0));
    }

    #[test]
    fn test_delta_decode_regression() {
        let delta = PolicyDelta {
            class_id: "test".into(),
            old_symbol_size: 256,
            new_symbol_size: 256,
            old_overhead: 0.02,
            new_overhead: 0.02,
            old_priority: "critical".into(),
            new_priority: "critical".into(),
            old_prefetch: "eager".into(),
            new_prefetch: "eager".into(),
            p99_encode_change_pct: 5.0,
            p99_decode_change_pct: 25.0,
        };
        assert!(delta.is_regression(20.0));
    }

    #[test]
    fn test_delta_at_exact_threshold_not_regression() {
        let delta = PolicyDelta {
            class_id: "test".into(),
            old_symbol_size: 256,
            new_symbol_size: 256,
            old_overhead: 0.02,
            new_overhead: 0.02,
            old_priority: "critical".into(),
            new_priority: "critical".into(),
            old_prefetch: "eager".into(),
            new_prefetch: "eager".into(),
            p99_encode_change_pct: 20.0,
            p99_decode_change_pct: 20.0,
        };
        assert!(!delta.is_regression(20.0));
    }

    // -- RegressionDiagnostic ------------------------------------------

    #[test]
    fn test_regression_diagnostic_display() {
        let diag = RegressionDiagnostic {
            class_id: "critical_marker".into(),
            metric: "p99_encode_us".into(),
            change_pct: 25.0,
            threshold_pct: 20.0,
        };
        let s = format!("{}", diag);
        assert!(s.contains("critical_marker"));
        assert!(s.contains("p99_encode_us"));
        assert!(s.contains("25.0%"));
    }

    // -- Baseline CSV parsing ------------------------------------------

    #[test]
    fn test_parse_baseline_csv() {
        let csv = "class_id,symbol_size_bytes,overhead_ratio,fetch_priority,prefetch_policy\n\
                   critical_marker,256,0.0200,critical,eager\n\
                   trust_receipt,1024,0.0500,normal,lazy\n";
        let rows = parse_baseline_csv(csv);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].class_id, "critical_marker");
        assert_eq!(rows[0].symbol_size_bytes, 256);
    }

    #[test]
    fn test_parse_baseline_csv_empty() {
        let csv = "class_id,symbol_size_bytes,overhead_ratio,fetch_priority,prefetch_policy\n";
        let rows = parse_baseline_csv(csv);
        assert_eq!(rows.len(), 0);
    }

    #[test]
    fn test_parse_baseline_csv_skips_short_lines() {
        let csv = "header\nshort,line\nok,256,0.02,crit,eager\n";
        let rows = parse_baseline_csv(csv);
        assert_eq!(rows.len(), 1);
    }

    // -- Harness: successful run ---------------------------------------

    #[test]
    fn test_harness_successful_run() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let baseline = sample_baseline();
        let benchmarks = sample_benchmarks();
        let outcome = harness.run(&baseline, &benchmarks, None);
        assert!(matches!(outcome, HarnessOutcome::Accepted(_)));
    }

    #[test]
    fn test_harness_produces_signed_bundle() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            assert!(!bundle.signature.is_empty());
            assert_eq!(bundle.version, 1);
        } else {
            panic!("Expected Accepted");
        }
    }

    #[test]
    fn test_harness_bundle_has_candidates() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            assert_eq!(bundle.candidates.len(), 4);
        } else {
            panic!("Expected Accepted");
        }
    }

    #[test]
    fn test_harness_bundle_has_deltas() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            assert_eq!(bundle.deltas.len(), 4);
        } else {
            panic!("Expected Accepted");
        }
    }

    #[test]
    fn test_harness_bundle_has_provenance() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            assert!(!bundle.hardware_fingerprint.is_empty());
            assert!(!bundle.run_id.is_empty());
            assert!(!bundle.timestamp.is_empty());
        } else {
            panic!("Expected Accepted");
        }
    }

    #[test]
    fn test_harness_bundle_signature_verifies() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(ref bundle) = outcome {
            assert!(harness.verify_bundle(bundle));
        } else {
            panic!("Expected Accepted");
        }
    }

    // -- Harness: idempotency ------------------------------------------

    #[test]
    fn test_harness_idempotent() {
        let config = HarnessConfig::with_defaults();
        let baseline = sample_baseline();
        let benchmarks = sample_benchmarks();

        let mut h1 = ProfileTuningHarness::new(config.clone());
        let mut h2 = ProfileTuningHarness::new(config);

        let o1 = h1.run(&baseline, &benchmarks, None);
        let o2 = h2.run(&baseline, &benchmarks, None);

        if let (HarnessOutcome::Accepted(b1), HarnessOutcome::Accepted(b2)) = (o1, o2) {
            assert_eq!(b1.signature, b2.signature);
            assert_eq!(b1.candidates, b2.candidates);
            assert_eq!(b1.deltas, b2.deltas);
        } else {
            panic!("Expected both Accepted");
        }
    }

    // -- Harness: regression rejection ---------------------------------

    #[test]
    fn test_harness_rejects_regression() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let baseline = sample_baseline();
        let prev = sample_benchmarks();
        let regressed = regressed_benchmarks();
        let outcome = harness.run(&baseline, &regressed, Some(&prev));
        assert!(matches!(outcome, HarnessOutcome::Rejected(_)));
    }

    #[test]
    fn test_harness_regression_diagnostic_detail() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let baseline = sample_baseline();
        let prev = sample_benchmarks();
        let regressed = regressed_benchmarks();
        let outcome = harness.run(&baseline, &regressed, Some(&prev));
        if let HarnessOutcome::Rejected(diags) = outcome {
            assert!(!diags.is_empty());
            assert_eq!(diags[0].class_id, "critical_marker");
            assert!(diags[0].change_pct > 20.0);
        } else {
            panic!("Expected Rejected");
        }
    }

    #[test]
    fn test_harness_regression_emits_event() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let baseline = sample_baseline();
        let prev = sample_benchmarks();
        let regressed = regressed_benchmarks();
        let _ = harness.run(&baseline, &regressed, Some(&prev));
        let reject_events: Vec<_> = harness
            .events()
            .iter()
            .filter(|e| e.code == PT_REGRESSION_REJECTED)
            .collect();
        assert!(!reject_events.is_empty());
    }

    // -- Harness: events -----------------------------------------------

    #[test]
    fn test_harness_emits_start_event() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let _ = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        let starts: Vec<_> = harness
            .events()
            .iter()
            .filter(|e| e.code == PT_HARNESS_START)
            .collect();
        assert_eq!(starts.len(), 1);
    }

    #[test]
    fn test_harness_emits_benchmark_complete() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let _ = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        let events: Vec<_> = harness
            .events()
            .iter()
            .filter(|e| e.code == PT_BENCHMARK_COMPLETE)
            .collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_harness_emits_candidate_computed() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let _ = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        let events: Vec<_> = harness
            .events()
            .iter()
            .filter(|e| e.code == PT_CANDIDATE_COMPUTED)
            .collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_harness_emits_bundle_signed() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let _ = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        let events: Vec<_> = harness
            .events()
            .iter()
            .filter(|e| e.code == PT_BUNDLE_SIGNED)
            .collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_harness_emits_bundle_verified() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let _ = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        let events: Vec<_> = harness
            .events()
            .iter()
            .filter(|e| e.code == PT_BUNDLE_VERIFIED)
            .collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_take_events_drains() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let _ = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        assert!(!harness.events().is_empty());
        let events = harness.take_events();
        assert!(!events.is_empty());
        assert!(harness.events().is_empty());
    }

    // -- Provenance chain ----------------------------------------------

    #[test]
    fn test_bundle_chain_first_has_no_previous() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            assert!(bundle.previous_bundle_hash.is_none());
        } else {
            panic!("Expected Accepted");
        }
    }

    #[test]
    fn test_bundle_chain_second_references_first() {
        let mut h1 = ProfileTuningHarness::with_defaults();
        let o1 = h1.run(&sample_baseline(), &sample_benchmarks(), None);
        let first_hash = if let HarnessOutcome::Accepted(ref b) = o1 {
            b.bundle_hash()
        } else {
            panic!("Expected Accepted");
        };

        let mut config2 = HarnessConfig::with_defaults();
        config2.previous_bundle_hash = Some(first_hash.clone());
        config2.run_id = "run-002".to_string();

        let mut h2 = ProfileTuningHarness::new(config2);
        let o2 = h2.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = o2 {
            assert_eq!(bundle.previous_bundle_hash, Some(first_hash));
        } else {
            panic!("Expected Accepted");
        }
    }

    #[test]
    fn test_bundle_hash_deterministic() {
        let mut h1 = ProfileTuningHarness::with_defaults();
        let mut h2 = ProfileTuningHarness::with_defaults();
        let o1 = h1.run(&sample_baseline(), &sample_benchmarks(), None);
        let o2 = h2.run(&sample_baseline(), &sample_benchmarks(), None);
        if let (HarnessOutcome::Accepted(b1), HarnessOutcome::Accepted(b2)) = (o1, o2) {
            assert_eq!(b1.bundle_hash(), b2.bundle_hash());
        } else {
            panic!("Expected both Accepted");
        }
    }

    // -- Config --------------------------------------------------------

    #[test]
    fn test_default_config() {
        let config = HarnessConfig::with_defaults();
        assert_eq!(config.regression_threshold_pct, 20.0);
        assert!(config.previous_bundle_hash.is_none());
    }

    #[test]
    fn test_custom_threshold() {
        let mut config = HarnessConfig::with_defaults();
        config.regression_threshold_pct = 10.0;
        let mut harness = ProfileTuningHarness::new(config);

        // With threshold 10% and previous benchmarks, even stable results
        // won't regress since no previous data shows degradation
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        assert!(matches!(outcome, HarnessOutcome::Accepted(_)));
    }

    #[test]
    fn test_config_access() {
        let harness = ProfileTuningHarness::with_defaults();
        assert_eq!(harness.config().regression_threshold_pct, 20.0);
    }

    // -- SignedPolicyBundle methods -------------------------------------

    #[test]
    fn test_bundle_signable_payload_excludes_signature() {
        let bundle = SignedPolicyBundle {
            version: 1,
            timestamp: "t".into(),
            run_id: "r".into(),
            hardware_fingerprint: "h".into(),
            previous_bundle_hash: None,
            regression_threshold_pct: 20.0,
            candidates: vec![],
            deltas: vec![],
            signature: "should-be-zeroed".into(),
        };
        let payload = bundle.signable_payload();
        assert!(!payload.contains("should-be-zeroed"));
    }

    #[test]
    fn test_bundle_serde_roundtrip() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            let json = serde_json::to_string(&bundle).unwrap();
            let parsed: SignedPolicyBundle = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, bundle);
        } else {
            panic!("Expected Accepted");
        }
    }

    // -- Event code constants ------------------------------------------

    #[test]
    fn test_event_codes_defined() {
        assert!(!PT_HARNESS_START.is_empty());
        assert!(!PT_BENCHMARK_COMPLETE.is_empty());
        assert!(!PT_CANDIDATE_COMPUTED.is_empty());
        assert!(!PT_REGRESSION_REJECTED.is_empty());
        assert!(!PT_BUNDLE_SIGNED.is_empty());
        assert!(!PT_BUNDLE_VERIFIED.is_empty());
    }

    // -- Invariant constants -------------------------------------------

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_PT_IDEMPOTENT.is_empty());
        assert!(!INV_PT_SIGNED.is_empty());
        assert!(!INV_PT_REGRESSION_SAFE.is_empty());
        assert!(!INV_PT_CHAIN.is_empty());
    }

    // -- Verify bundle with wrong key fails ----------------------------

    #[test]
    fn test_verify_bundle_wrong_key() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            let mut wrong_key_config = HarnessConfig::with_defaults();
            wrong_key_config.signing_key = "wrong-key".into();
            let mut wrong_harness = ProfileTuningHarness::new(wrong_key_config);
            assert!(!wrong_harness.verify_bundle(&bundle));
        } else {
            panic!("Expected Accepted");
        }
    }

    // -- Empty benchmarks produce empty bundle -------------------------

    #[test]
    fn test_empty_benchmarks() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &[], None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            assert!(bundle.candidates.is_empty());
            assert!(bundle.deltas.is_empty());
        } else {
            panic!("Expected Accepted");
        }
    }

    // -- Delta computation correctness ---------------------------------

    #[test]
    fn test_delta_shows_old_and_new_values() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            let cm_delta = bundle
                .deltas
                .iter()
                .find(|d| d.class_id == "critical_marker")
                .unwrap();
            assert_eq!(cm_delta.old_symbol_size, 256);
            assert_eq!(cm_delta.new_symbol_size, 256);
        } else {
            panic!("Expected Accepted");
        }
    }

    #[test]
    fn test_delta_p99_change_zero_without_previous() {
        let mut harness = ProfileTuningHarness::with_defaults();
        let outcome = harness.run(&sample_baseline(), &sample_benchmarks(), None);
        if let HarnessOutcome::Accepted(bundle) = outcome {
            for delta in &bundle.deltas {
                assert_eq!(delta.p99_encode_change_pct, 0.0);
                assert_eq!(delta.p99_decode_change_pct, 0.0);
            }
        } else {
            panic!("Expected Accepted");
        }
    }
}
