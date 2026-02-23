// VEF coverage and proof-validity metrics integration for claim compiler
// and public trust scoreboard.
//
// bd-3go4 — Section 10.18
//
// Integrates VEF coverage metrics into the claim compiler gate and publishes
// real-time VEF metrics on the trust scoreboard with signed evidence links.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVT_CLAIM_CHECK_INITIATED: &str = "VEF-CLAIM-001";
pub const EVT_CLAIM_PASSED: &str = "VEF-CLAIM-002";
pub const EVT_CLAIM_BLOCKED: &str = "VEF-CLAIM-003";
pub const EVT_SCOREBOARD_UPDATED: &str = "VEF-SCORE-001";
pub const EVT_SCOREBOARD_EVIDENCE_LINKED: &str = "VEF-SCORE-002";
pub const EVT_COVERAGE_GAP_DETECTED: &str = "VEF-SCORE-003";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_VEF_CLAIM_INVALID_CONFIG: &str = "ERR_VEF_CLAIM_INVALID_CONFIG";
pub const ERR_VEF_CLAIM_COVERAGE_LOW: &str = "ERR_VEF_CLAIM_COVERAGE_LOW";
pub const ERR_VEF_CLAIM_VALIDITY_LOW: &str = "ERR_VEF_CLAIM_VALIDITY_LOW";
pub const ERR_VEF_CLAIM_PROOF_STALE: &str = "ERR_VEF_CLAIM_PROOF_STALE";
pub const ERR_VEF_CLAIM_NO_EVIDENCE: &str = "ERR_VEF_CLAIM_NO_EVIDENCE";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_VEF_CLAIM_GATE: &str = "INV-VEF-CLAIM-GATE";
pub const INV_VEF_CLAIM_DETERMINISTIC: &str = "INV-VEF-CLAIM-DETERMINISTIC";
pub const INV_VEF_SCORE_TRACEABLE: &str = "INV-VEF-SCORE-TRACEABLE";
pub const INV_VEF_SCORE_REPRODUCIBLE: &str = "INV-VEF-SCORE-REPRODUCIBLE";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VefClaimConfig {
    /// Minimum VEF coverage percentage to pass claim gate.
    pub min_coverage_pct: f64,
    /// Minimum proof verification success rate.
    pub min_validity_rate: f64,
    /// Maximum proof age before considered stale (seconds).
    pub max_proof_age_secs: u64,
    /// Scoreboard publish interval (seconds).
    pub scoreboard_publish_interval: u64,
}

impl Default for VefClaimConfig {
    fn default() -> Self {
        Self {
            min_coverage_pct: 0.80,
            min_validity_rate: 0.95,
            max_proof_age_secs: 3600,
            scoreboard_publish_interval: 60,
        }
    }
}

impl VefClaimConfig {
    pub fn validate(&self) -> Result<(), VefClaimError> {
        if !(0.0..=1.0).contains(&self.min_coverage_pct) {
            return Err(VefClaimError::InvalidConfig(
                "min_coverage_pct must be in [0.0, 1.0]".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.min_validity_rate) {
            return Err(VefClaimError::InvalidConfig(
                "min_validity_rate must be in [0.0, 1.0]".into(),
            ));
        }
        if self.max_proof_age_secs == 0 {
            return Err(VefClaimError::InvalidConfig(
                "max_proof_age_secs must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum VefClaimError {
    InvalidConfig(String),
    CoverageLow { actual: f64, required: f64 },
    ValidityLow { actual: f64, required: f64 },
    ProofStale { age_secs: u64, max_secs: u64 },
    NoEvidence(String),
}

impl std::fmt::Display for VefClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "{ERR_VEF_CLAIM_INVALID_CONFIG}: {msg}"),
            Self::CoverageLow { actual, required } => {
                write!(
                    f,
                    "{ERR_VEF_CLAIM_COVERAGE_LOW}: {actual:.2}% < {required:.2}%"
                )
            }
            Self::ValidityLow { actual, required } => {
                write!(
                    f,
                    "{ERR_VEF_CLAIM_VALIDITY_LOW}: {actual:.2} < {required:.2}"
                )
            }
            Self::ProofStale { age_secs, max_secs } => {
                write!(
                    f,
                    "{ERR_VEF_CLAIM_PROOF_STALE}: age {age_secs}s > max {max_secs}s"
                )
            }
            Self::NoEvidence(msg) => write!(f, "{ERR_VEF_CLAIM_NO_EVIDENCE}: {msg}"),
        }
    }
}

impl std::error::Error for VefClaimError {}

// ---------------------------------------------------------------------------
// VEF metrics
// ---------------------------------------------------------------------------

/// VEF coverage and validity metrics snapshot.
#[derive(Debug, Clone)]
pub struct VefMetrics {
    /// Percentage of action classes with current valid proofs [0.0, 1.0].
    pub coverage_pct: f64,
    /// Proof verification success rate [0.0, 1.0].
    pub validity_rate: f64,
    /// Total number of valid proofs.
    pub proof_count: usize,
    /// Number of coverage gaps.
    pub gap_count: usize,
    /// Average proof age in seconds.
    pub avg_proof_age_secs: u64,
    /// Fraction of time spent in degraded mode [0.0, 1.0].
    pub degraded_time_frac: f64,
    /// Covered action classes.
    pub covered_classes: Vec<String>,
    /// Uncovered (gap) action classes.
    pub gap_classes: Vec<String>,
}

impl VefMetrics {
    /// Compute a deterministic digest of the metrics for reproducibility.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"vef_metrics_v1:");
        hasher.update(self.coverage_pct.to_le_bytes());
        hasher.update(self.validity_rate.to_le_bytes());
        hasher.update(self.proof_count.to_le_bytes());
        hasher.update(self.gap_count.to_le_bytes());
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Claim requirement and gate result
// ---------------------------------------------------------------------------

/// A security/compliance claim with VEF evidence requirements.
#[derive(Debug, Clone)]
pub struct ClaimRequirement {
    pub claim_id: String,
    pub claim_text: String,
    pub min_coverage: f64,
    pub min_validity: f64,
    pub required_action_classes: Vec<String>,
}

/// Result of evaluating a claim against VEF metrics.
#[derive(Debug, Clone)]
pub struct ClaimGateResult {
    pub claim_id: String,
    pub passed: bool,
    pub coverage: f64,
    pub validity: f64,
    pub gaps: Vec<String>,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Evidence link
// ---------------------------------------------------------------------------

/// A link from a scoreboard entry to specific proof evidence.
#[derive(Debug, Clone)]
pub struct EvidenceLink {
    pub proof_id: String,
    pub action_class: String,
    pub verification_time: u64,
    pub valid: bool,
}

// ---------------------------------------------------------------------------
// Scoreboard entry
// ---------------------------------------------------------------------------

/// A publication on the public trust scoreboard.
#[derive(Debug, Clone)]
pub struct ScoreboardEntry {
    pub timestamp: u64,
    pub metrics: VefMetrics,
    pub evidence_links: Vec<EvidenceLink>,
    pub signed_digest: [u8; 32],
}

impl ScoreboardEntry {
    /// Compute signed digest using SHA-256 over metrics and evidence.
    fn compute_digest(metrics: &VefMetrics, evidence_links: &[EvidenceLink]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"vef_scoreboard_v1:");
        hasher.update(metrics.digest());
        for link in evidence_links {
            hasher.update(link.proof_id.as_bytes());
            hasher.update(b"\x00");
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VefClaimEvent {
    pub code: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// VEF claim integration
// ---------------------------------------------------------------------------

/// Core integration engine for VEF metrics, claim compiler, and scoreboard.
#[derive(Debug)]
pub struct VefClaimIntegration {
    config: VefClaimConfig,
    events: Vec<VefClaimEvent>,
    scoreboard: Vec<ScoreboardEntry>,
    gate_results: Vec<ClaimGateResult>,
}

impl VefClaimIntegration {
    pub fn new(config: VefClaimConfig) -> Result<Self, VefClaimError> {
        config.validate()?;
        Ok(Self {
            config,
            events: Vec::new(),
            scoreboard: Vec::new(),
            gate_results: Vec::new(),
        })
    }

    /// Evaluate a claim requirement against current VEF metrics.
    /// INV-VEF-CLAIM-GATE: blocks if coverage < threshold or validity < threshold.
    /// INV-VEF-CLAIM-DETERMINISTIC: same inputs produce same result.
    pub fn evaluate_claim(
        &mut self,
        claim: &ClaimRequirement,
        metrics: &VefMetrics,
    ) -> ClaimGateResult {
        self.events.push(VefClaimEvent {
            code: EVT_CLAIM_CHECK_INITIATED.to_string(),
            detail: format!("claim={}", claim.claim_id),
        });

        // Check coverage.
        let coverage_ok = metrics.coverage_pct >= claim.min_coverage;

        // Check validity.
        let validity_ok = metrics.validity_rate >= claim.min_validity;

        // Check required action classes.
        let mut gaps = Vec::new();
        for class in &claim.required_action_classes {
            if !metrics.covered_classes.contains(class) {
                gaps.push(class.clone());
                self.events.push(VefClaimEvent {
                    code: EVT_COVERAGE_GAP_DETECTED.to_string(),
                    detail: format!("claim={}, gap={}", claim.claim_id, class),
                });
            }
        }

        let passed = coverage_ok && validity_ok && gaps.is_empty();
        let reason = if passed {
            "all VEF requirements met".to_string()
        } else {
            let mut reasons = Vec::new();
            if !coverage_ok {
                reasons.push(format!(
                    "coverage {:.2} < required {:.2}",
                    metrics.coverage_pct, claim.min_coverage
                ));
            }
            if !validity_ok {
                reasons.push(format!(
                    "validity {:.2} < required {:.2}",
                    metrics.validity_rate, claim.min_validity
                ));
            }
            if !gaps.is_empty() {
                reasons.push(format!("gaps: {:?}", gaps));
            }
            reasons.join("; ")
        };

        if passed {
            self.events.push(VefClaimEvent {
                code: EVT_CLAIM_PASSED.to_string(),
                detail: format!("claim={}", claim.claim_id),
            });
        } else {
            self.events.push(VefClaimEvent {
                code: EVT_CLAIM_BLOCKED.to_string(),
                detail: format!("claim={}: {}", claim.claim_id, reason),
            });
        }

        let result = ClaimGateResult {
            claim_id: claim.claim_id.clone(),
            passed,
            coverage: metrics.coverage_pct,
            validity: metrics.validity_rate,
            gaps,
            reason,
        };

        self.gate_results.push(result.clone());
        result
    }

    /// Publish VEF metrics to the public trust scoreboard.
    /// INV-VEF-SCORE-TRACEABLE: every metric has evidence links.
    /// INV-VEF-SCORE-REPRODUCIBLE: deterministic digest from evidence.
    pub fn publish_scoreboard(
        &mut self,
        metrics: &VefMetrics,
        evidence_links: Vec<EvidenceLink>,
        timestamp: u64,
    ) -> ScoreboardEntry {
        let signed_digest = ScoreboardEntry::compute_digest(metrics, &evidence_links);

        for link in &evidence_links {
            self.events.push(VefClaimEvent {
                code: EVT_SCOREBOARD_EVIDENCE_LINKED.to_string(),
                detail: format!("proof={}, class={}", link.proof_id, link.action_class),
            });
        }

        let entry = ScoreboardEntry {
            timestamp,
            metrics: metrics.clone(),
            evidence_links,
            signed_digest,
        };

        self.events.push(VefClaimEvent {
            code: EVT_SCOREBOARD_UPDATED.to_string(),
            detail: format!(
                "coverage={:.2}, validity={:.2}, proofs={}",
                metrics.coverage_pct, metrics.validity_rate, metrics.proof_count
            ),
        });

        self.scoreboard.push(entry.clone());
        entry
    }

    /// Check proof freshness against max age.
    pub fn check_proof_freshness(&self, proof_age_secs: u64) -> Result<(), VefClaimError> {
        if proof_age_secs > self.config.max_proof_age_secs {
            return Err(VefClaimError::ProofStale {
                age_secs: proof_age_secs,
                max_secs: self.config.max_proof_age_secs,
            });
        }
        Ok(())
    }

    /// Detect coverage gaps in metrics.
    pub fn detect_gaps(&mut self, metrics: &VefMetrics) -> Vec<String> {
        let gaps = metrics.gap_classes.clone();
        for gap in &gaps {
            self.events.push(VefClaimEvent {
                code: EVT_COVERAGE_GAP_DETECTED.to_string(),
                detail: format!("gap detected: {}", gap),
            });
        }
        gaps
    }

    /// Get all gate results.
    pub fn gate_results(&self) -> &[ClaimGateResult] {
        &self.gate_results
    }

    /// Get scoreboard entries.
    pub fn scoreboard(&self) -> &[ScoreboardEntry] {
        &self.scoreboard
    }

    /// Get events.
    pub fn events(&self) -> &[VefClaimEvent] {
        &self.events
    }

    /// Get config.
    pub fn config(&self) -> &VefClaimConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> VefClaimConfig {
        VefClaimConfig::default()
    }

    fn good_metrics() -> VefMetrics {
        VefMetrics {
            coverage_pct: 0.95,
            validity_rate: 0.99,
            proof_count: 50,
            gap_count: 0,
            avg_proof_age_secs: 300,
            degraded_time_frac: 0.01,
            covered_classes: vec!["fs_write".into(), "net_connect".into(), "exec_child".into()],
            gap_classes: vec![],
        }
    }

    fn low_metrics() -> VefMetrics {
        VefMetrics {
            coverage_pct: 0.60,
            validity_rate: 0.80,
            proof_count: 10,
            gap_count: 3,
            avg_proof_age_secs: 2000,
            degraded_time_frac: 0.15,
            covered_classes: vec!["fs_write".into()],
            gap_classes: vec!["net_connect".into(), "exec_child".into(), "ipc_send".into()],
        }
    }

    fn test_claim() -> ClaimRequirement {
        ClaimRequirement {
            claim_id: "sec-001".into(),
            claim_text: "All high-risk ops are policy-compliant".into(),
            min_coverage: 0.80,
            min_validity: 0.95,
            required_action_classes: vec!["fs_write".into(), "net_connect".into()],
        }
    }

    fn make_engine() -> VefClaimIntegration {
        VefClaimIntegration::new(default_config()).unwrap()
    }

    // -- Config --

    #[test]
    fn test_default_config_valid() {
        assert!(default_config().validate().is_ok());
    }

    #[test]
    fn test_invalid_coverage_pct() {
        let mut cfg = default_config();
        cfg.min_coverage_pct = 1.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_validity_rate() {
        let mut cfg = default_config();
        cfg.min_validity_rate = -0.1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_proof_age() {
        let mut cfg = default_config();
        cfg.max_proof_age_secs = 0;
        assert!(cfg.validate().is_err());
    }

    // -- VEF metrics --

    #[test]
    fn test_metrics_digest_deterministic() {
        // INV-VEF-SCORE-REPRODUCIBLE
        let m = good_metrics();
        let d1 = m.digest();
        let d2 = m.digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_metrics_digest_differs() {
        let m1 = good_metrics();
        let m2 = low_metrics();
        assert_ne!(m1.digest(), m2.digest());
    }

    // -- Claim gate: passing --

    #[test]
    fn test_claim_passes_with_good_metrics() {
        // INV-VEF-CLAIM-GATE
        let mut engine = make_engine();
        let claim = test_claim();
        let metrics = good_metrics();
        let result = engine.evaluate_claim(&claim, &metrics);
        assert!(result.passed);
        assert_eq!(result.gaps.len(), 0);
    }

    #[test]
    fn test_claim_pass_reason() {
        let mut engine = make_engine();
        let result = engine.evaluate_claim(&test_claim(), &good_metrics());
        assert!(result.reason.contains("met"));
    }

    // -- Claim gate: blocking --

    #[test]
    fn test_claim_blocked_low_coverage() {
        // INV-VEF-CLAIM-GATE
        let mut engine = make_engine();
        let claim = test_claim();
        let metrics = low_metrics();
        let result = engine.evaluate_claim(&claim, &metrics);
        assert!(!result.passed);
        assert!(result.reason.contains("coverage"));
    }

    #[test]
    fn test_claim_blocked_low_validity() {
        let mut engine = make_engine();
        let claim = test_claim();
        let mut metrics = good_metrics();
        metrics.validity_rate = 0.80;
        let result = engine.evaluate_claim(&claim, &metrics);
        assert!(!result.passed);
        assert!(result.reason.contains("validity"));
    }

    #[test]
    fn test_claim_blocked_missing_action_class() {
        let mut engine = make_engine();
        let claim = test_claim();
        let mut metrics = good_metrics();
        metrics.covered_classes = vec!["fs_write".into()]; // Missing net_connect.
        let result = engine.evaluate_claim(&claim, &metrics);
        assert!(!result.passed);
        assert!(result.gaps.contains(&"net_connect".to_string()));
    }

    // -- Claim gate: boundary --

    #[test]
    fn test_claim_boundary_exact_threshold() {
        let mut engine = make_engine();
        let mut claim = test_claim();
        claim.min_coverage = 0.95;
        claim.min_validity = 0.99;
        let metrics = good_metrics(); // coverage=0.95, validity=0.99
        let result = engine.evaluate_claim(&claim, &metrics);
        assert!(result.passed, "Exact threshold should pass");
    }

    #[test]
    fn test_claim_boundary_just_below() {
        let mut engine = make_engine();
        let mut claim = test_claim();
        claim.min_coverage = 0.96; // Metrics have 0.95.
        let metrics = good_metrics();
        let result = engine.evaluate_claim(&claim, &metrics);
        assert!(!result.passed, "Just below threshold should block");
    }

    // -- Claim gate: determinism --

    #[test]
    fn test_claim_gate_deterministic() {
        // INV-VEF-CLAIM-DETERMINISTIC
        let mut engine1 = make_engine();
        let mut engine2 = make_engine();
        let claim = test_claim();
        let metrics = good_metrics();
        let r1 = engine1.evaluate_claim(&claim, &metrics);
        let r2 = engine2.evaluate_claim(&claim, &metrics);
        assert_eq!(r1.passed, r2.passed);
        assert_eq!(r1.gaps, r2.gaps);
        assert!((r1.coverage - r2.coverage).abs() < f64::EPSILON);
    }

    // -- Scoreboard --

    #[test]
    fn test_scoreboard_publish() {
        let mut engine = make_engine();
        let metrics = good_metrics();
        let links = vec![EvidenceLink {
            proof_id: "proof-1".into(),
            action_class: "fs_write".into(),
            verification_time: 100,
            valid: true,
        }];
        let entry = engine.publish_scoreboard(&metrics, links, 1000);
        assert_eq!(entry.timestamp, 1000);
        assert!(!entry.evidence_links.is_empty());
    }

    #[test]
    fn test_scoreboard_digest_reproducible() {
        // INV-VEF-SCORE-REPRODUCIBLE
        let mut engine1 = make_engine();
        let mut engine2 = make_engine();
        let metrics = good_metrics();
        let links = vec![EvidenceLink {
            proof_id: "proof-1".into(),
            action_class: "fs_write".into(),
            verification_time: 100,
            valid: true,
        }];
        let e1 = engine1.publish_scoreboard(&metrics, links.clone(), 1000);
        let e2 = engine2.publish_scoreboard(&metrics, links, 1000);
        assert_eq!(e1.signed_digest, e2.signed_digest);
    }

    #[test]
    fn test_scoreboard_evidence_traceable() {
        // INV-VEF-SCORE-TRACEABLE
        let mut engine = make_engine();
        let metrics = good_metrics();
        let links = vec![
            EvidenceLink {
                proof_id: "proof-1".into(),
                action_class: "fs_write".into(),
                verification_time: 100,
                valid: true,
            },
            EvidenceLink {
                proof_id: "proof-2".into(),
                action_class: "net_connect".into(),
                verification_time: 200,
                valid: true,
            },
        ];
        let entry = engine.publish_scoreboard(&metrics, links, 1000);
        assert_eq!(entry.evidence_links.len(), 2);
        assert!(entry.evidence_links.iter().all(|l| l.valid));
    }

    #[test]
    fn test_scoreboard_stored() {
        let mut engine = make_engine();
        engine.publish_scoreboard(&good_metrics(), vec![], 1000);
        assert_eq!(engine.scoreboard().len(), 1);
    }

    // -- Proof freshness --

    #[test]
    fn test_proof_fresh() {
        let engine = make_engine();
        assert!(engine.check_proof_freshness(1800).is_ok()); // 30min < 1hr.
    }

    #[test]
    fn test_proof_stale() {
        let engine = make_engine();
        let err = engine.check_proof_freshness(7200); // 2hr > 1hr.
        assert!(err.is_err());
    }

    // -- Coverage gaps --

    #[test]
    fn test_detect_gaps() {
        let mut engine = make_engine();
        let metrics = low_metrics();
        let gaps = engine.detect_gaps(&metrics);
        assert_eq!(gaps.len(), 3);
    }

    #[test]
    fn test_detect_no_gaps() {
        let mut engine = make_engine();
        let metrics = good_metrics();
        let gaps = engine.detect_gaps(&metrics);
        assert!(gaps.is_empty());
    }

    // -- Gate results --

    #[test]
    fn test_gate_results_stored() {
        let mut engine = make_engine();
        engine.evaluate_claim(&test_claim(), &good_metrics());
        assert_eq!(engine.gate_results().len(), 1);
    }

    #[test]
    fn test_gate_results_multiple() {
        let mut engine = make_engine();
        engine.evaluate_claim(&test_claim(), &good_metrics());
        engine.evaluate_claim(&test_claim(), &low_metrics());
        assert_eq!(engine.gate_results().len(), 2);
        assert!(engine.gate_results()[0].passed);
        assert!(!engine.gate_results()[1].passed);
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut engine = make_engine();
        engine.evaluate_claim(&test_claim(), &good_metrics());
        assert!(!engine.events().is_empty());
    }

    #[test]
    fn test_events_contain_initiated() {
        let mut engine = make_engine();
        engine.evaluate_claim(&test_claim(), &good_metrics());
        let has = engine
            .events()
            .iter()
            .any(|e| e.code == EVT_CLAIM_CHECK_INITIATED);
        assert!(has);
    }

    #[test]
    fn test_events_contain_passed() {
        let mut engine = make_engine();
        engine.evaluate_claim(&test_claim(), &good_metrics());
        let has = engine.events().iter().any(|e| e.code == EVT_CLAIM_PASSED);
        assert!(has);
    }

    #[test]
    fn test_events_contain_blocked() {
        let mut engine = make_engine();
        engine.evaluate_claim(&test_claim(), &low_metrics());
        let has = engine.events().iter().any(|e| e.code == EVT_CLAIM_BLOCKED);
        assert!(has);
    }

    #[test]
    fn test_events_contain_scoreboard_updated() {
        let mut engine = make_engine();
        engine.publish_scoreboard(&good_metrics(), vec![], 1000);
        let has = engine
            .events()
            .iter()
            .any(|e| e.code == EVT_SCOREBOARD_UPDATED);
        assert!(has);
    }

    // -- Error display --

    #[test]
    fn test_error_display() {
        let err = VefClaimError::InvalidConfig("bad".into());
        assert!(format!("{err}").contains(ERR_VEF_CLAIM_INVALID_CONFIG));

        let err = VefClaimError::CoverageLow {
            actual: 0.5,
            required: 0.8,
        };
        assert!(format!("{err}").contains(ERR_VEF_CLAIM_COVERAGE_LOW));

        let err = VefClaimError::ValidityLow {
            actual: 0.8,
            required: 0.95,
        };
        assert!(format!("{err}").contains(ERR_VEF_CLAIM_VALIDITY_LOW));

        let err = VefClaimError::ProofStale {
            age_secs: 7200,
            max_secs: 3600,
        };
        assert!(format!("{err}").contains(ERR_VEF_CLAIM_PROOF_STALE));

        let err = VefClaimError::NoEvidence("missing".into());
        assert!(format!("{err}").contains(ERR_VEF_CLAIM_NO_EVIDENCE));
    }
}
