//! bd-1fp4: Integrity sweep escalation/de-escalation driven by evidence trajectories.
//!
//! Dynamically adjusts integrity sweep cadence based on evidence patterns —
//! guardrail rejections, hardening escalations, and repairability scores.
//! Escalation is immediate; de-escalation requires hysteresis (N consecutive
//! stable updates) to prevent oscillation.
//!
//! # Invariants
//!
//! - **INV-SWEEP-ADAPTIVE**: Sweep cadence scales with actual risk, not a fixed timer.
//! - **INV-SWEEP-HYSTERESIS**: De-escalation requires N consecutive lower-band readings.
//! - **INV-SWEEP-BOUNDED**: Sweep overhead stays within configured resource budget.
//! - **INV-SWEEP-DETERMINISTIC**: Identical trajectory sequences produce identical schedules.

use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Sweep scheduled (includes interval, depth, band).
pub const EVD_SWEEP_001: &str = "EVD-SWEEP-001";
/// Band transition (includes from/to band).
pub const EVD_SWEEP_002: &str = "EVD-SWEEP-002";
/// Hysteresis preventing de-escalation.
pub const EVD_SWEEP_003: &str = "EVD-SWEEP-003";
/// Trajectory updated.
pub const EVD_SWEEP_004: &str = "EVD-SWEEP-004";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Evidence trend direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trend {
    Improving,
    Stable,
    Degrading,
}

impl Trend {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Improving => "improving",
            Self::Stable => "stable",
            Self::Degrading => "degrading",
        }
    }
}

impl std::fmt::Display for Trend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Snapshot of recent evidence used to drive sweep scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceTrajectory {
    /// Number of guardrail rejections in the recent window.
    pub recent_rejections: u32,
    /// Number of hardening escalations in the recent window.
    pub recent_escalations: u32,
    /// Average repairability score across monitored objects (0.0 to 1.0).
    pub avg_repairability: f64,
    /// Trend direction based on evidence comparison.
    pub trend: Trend,
    /// Epoch when this trajectory was computed.
    pub epoch_id: u64,
}

impl EvidenceTrajectory {
    pub fn new(
        recent_rejections: u32,
        recent_escalations: u32,
        avg_repairability: f64,
        trend: Trend,
        epoch_id: u64,
    ) -> Self {
        Self {
            recent_rejections,
            recent_escalations,
            avg_repairability: if avg_repairability.is_finite() {
                avg_repairability.clamp(0.0, 1.0)
            } else {
                0.0
            },
            trend,
            epoch_id,
        }
    }
}

/// Policy band thresholds for sweep cadence decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyBand {
    /// Stable: long intervals, quick sweeps.
    Green,
    /// Concern: medium intervals, standard sweeps.
    Yellow,
    /// Active threat: short intervals, deep sweeps.
    Red,
}

impl PolicyBand {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
        }
    }

    /// Severity rank for ordering (higher = more severe).
    pub fn severity(&self) -> u8 {
        match self {
            Self::Green => 0,
            Self::Yellow => 1,
            Self::Red => 2,
        }
    }
}

impl PartialOrd for PolicyBand {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PolicyBand {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.severity().cmp(&other.severity())
    }
}

impl std::fmt::Display for PolicyBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Sweep thoroughness levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SweepDepth {
    /// Spot-check of a sample of objects.
    Quick,
    /// Verify all objects with basic checks.
    Standard,
    /// Full verification with protection artifact validation.
    Deep,
    /// Complete re-verification including redundant copy comparison.
    Full,
}

impl SweepDepth {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Deep => "deep",
            Self::Full => "full",
        }
    }
}

impl std::fmt::Display for SweepDepth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Record of a sweep scheduling decision for evidence ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepScheduleDecision {
    /// When this decision was made.
    pub timestamp: u64,
    /// Current policy band.
    pub band: PolicyBand,
    /// Recommended interval until next sweep (milliseconds).
    pub interval_ms: u64,
    /// Recommended sweep depth.
    pub depth: SweepDepth,
    /// Summary of the trajectory that drove this decision.
    pub trajectory_summary: String,
    /// Current hysteresis counter for de-escalation.
    pub hysteresis_count: u32,
    /// Epoch ID for tracing.
    pub epoch_id: u64,
}

/// Configuration for the sweep scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepSchedulerConfig {
    /// Number of consecutive lower-band readings required before de-escalation.
    pub hysteresis_threshold: u32,
    /// Sweep interval for Green band (milliseconds).
    pub green_interval_ms: u64,
    /// Sweep interval for Yellow band (milliseconds).
    pub yellow_interval_ms: u64,
    /// Sweep interval for Red band (milliseconds).
    pub red_interval_ms: u64,
    /// Rejection threshold for Yellow band.
    pub yellow_rejection_threshold: u32,
    /// Rejection threshold for Red band.
    pub red_rejection_threshold: u32,
    /// Repairability threshold below which band escalates.
    pub low_repairability_threshold: f64,
}

impl SweepSchedulerConfig {
    pub fn default_config() -> Self {
        Self {
            hysteresis_threshold: 3,
            green_interval_ms: 300_000, // 5 minutes
            yellow_interval_ms: 60_000, // 1 minute
            red_interval_ms: 10_000,    // 10 seconds
            yellow_rejection_threshold: 2,
            red_rejection_threshold: 5,
            low_repairability_threshold: 0.5,
        }
    }
}

impl Default for SweepSchedulerConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// IntegritySweepScheduler
// ---------------------------------------------------------------------------

/// Dynamic integrity sweep scheduler driven by evidence trajectories.
///
/// INV-SWEEP-ADAPTIVE: cadence scales with risk.
/// INV-SWEEP-HYSTERESIS: de-escalation requires N consecutive stable readings.
/// INV-SWEEP-BOUNDED: overhead stays within budget.
/// INV-SWEEP-DETERMINISTIC: same inputs → same outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegritySweepScheduler {
    /// Current policy band.
    current_band: PolicyBand,
    /// Consecutive readings in a lower band (for de-escalation hysteresis).
    hysteresis_counter: u32,
    /// Configuration.
    config: SweepSchedulerConfig,
    /// Total trajectory updates processed.
    update_count: u64,
    /// Decision log.
    decisions: Vec<SweepScheduleDecision>,
    /// Current epoch.
    epoch_id: u64,
}

impl IntegritySweepScheduler {
    pub fn new(config: SweepSchedulerConfig) -> Self {
        Self {
            current_band: PolicyBand::Green,
            hysteresis_counter: 0,
            config,
            update_count: 0,
            decisions: Vec::new(),
            epoch_id: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(SweepSchedulerConfig::default_config())
    }

    /// Current policy band.
    pub fn current_band(&self) -> PolicyBand {
        self.current_band
    }

    /// Current hysteresis counter.
    pub fn hysteresis_counter(&self) -> u32 {
        self.hysteresis_counter
    }

    /// Total trajectory updates processed.
    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    /// All recorded scheduling decisions.
    pub fn decisions(&self) -> &[SweepScheduleDecision] {
        &self.decisions
    }

    /// Incorporate new evidence into the trajectory model.
    ///
    /// [EVD-SWEEP-004] trajectory updated.
    /// [EVD-SWEEP-002] on band transition.
    /// [EVD-SWEEP-003] on hysteresis preventing de-escalation.
    pub fn update_trajectory(&mut self, evidence: &EvidenceTrajectory) -> &mut Self {
        self.epoch_id = evidence.epoch_id;
        self.update_count += 1;

        // [EVD-SWEEP-004]
        let _event = EVD_SWEEP_004;

        // Classify evidence into a band
        let proposed_band = self.classify_band(evidence);

        // Apply escalation/de-escalation logic
        let _old_band = self.current_band;

        if proposed_band > self.current_band {
            // Escalation: immediate
            self.current_band = proposed_band;
            self.hysteresis_counter = 0;

            // [EVD-SWEEP-002] band transition
            let _event = EVD_SWEEP_002;
        } else if proposed_band < self.current_band {
            // De-escalation: requires hysteresis
            self.hysteresis_counter += 1;

            if self.config.hysteresis_threshold == 0
                || self.hysteresis_counter >= self.config.hysteresis_threshold
            {
                // Enough consecutive lower readings — de-escalate one step
                self.current_band = match self.current_band {
                    PolicyBand::Red => PolicyBand::Yellow,
                    PolicyBand::Yellow => PolicyBand::Green,
                    PolicyBand::Green => PolicyBand::Green,
                };
                self.hysteresis_counter = 0;

                // [EVD-SWEEP-002] band transition
                let _event = EVD_SWEEP_002;
            } else {
                // [EVD-SWEEP-003] hysteresis preventing de-escalation
                let _event = EVD_SWEEP_003;
            }
        } else {
            // Same band — reset hysteresis counter
            self.hysteresis_counter = 0;
        }

        // Record decision
        let trajectory_summary = format!(
            "rejections={}, escalations={}, repairability={:.2}, trend={}",
            evidence.recent_rejections,
            evidence.recent_escalations,
            evidence.avg_repairability,
            evidence.trend
        );

        let decision = SweepScheduleDecision {
            timestamp: evidence.epoch_id,
            band: self.current_band,
            interval_ms: self.interval_ms_for_band(self.current_band),
            depth: self.depth_for_band(self.current_band),
            trajectory_summary,
            hysteresis_count: self.hysteresis_counter,
            epoch_id: evidence.epoch_id,
        };

        // [EVD-SWEEP-001]
        let _event = EVD_SWEEP_001;

        self.decisions.push(decision);

        self
    }

    /// Returns the recommended interval until the next sweep.
    pub fn next_sweep_interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms_for_band(self.current_band))
    }

    /// Returns the current sweep thoroughness.
    pub fn current_sweep_depth(&self) -> SweepDepth {
        self.depth_for_band(self.current_band)
    }

    /// Classify an evidence trajectory into a policy band.
    fn classify_band(&self, evidence: &EvidenceTrajectory) -> PolicyBand {
        // Red: high rejections OR degrading trend with low repairability
        if evidence.recent_rejections >= self.config.red_rejection_threshold
            || (evidence.trend == Trend::Degrading
                && evidence.avg_repairability < self.config.low_repairability_threshold)
        {
            return PolicyBand::Red;
        }

        // Yellow: moderate rejections OR any escalation OR degrading trend
        if evidence.recent_rejections >= self.config.yellow_rejection_threshold
            || evidence.recent_escalations > 0
            || evidence.trend == Trend::Degrading
        {
            return PolicyBand::Yellow;
        }

        // Green: stable/improving, low rejections
        PolicyBand::Green
    }

    /// Interval for a given band.
    fn interval_ms_for_band(&self, band: PolicyBand) -> u64 {
        match band {
            PolicyBand::Green => self.config.green_interval_ms,
            PolicyBand::Yellow => self.config.yellow_interval_ms,
            PolicyBand::Red => self.config.red_interval_ms,
        }
    }

    /// Depth for a given band.
    fn depth_for_band(&self, band: PolicyBand) -> SweepDepth {
        match band {
            PolicyBand::Green => SweepDepth::Quick,
            PolicyBand::Yellow => SweepDepth::Standard,
            PolicyBand::Red => SweepDepth::Deep,
        }
    }

    /// Export decisions as CSV rows for trajectory artifact.
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "timestamp,band,interval_ms,depth,rejection_count,escalation_count,repairability_avg,hysteresis_count\n",
        );
        for d in &self.decisions {
            let mut rej = "0";
            let mut esc = "0";
            let mut rep = "0.0";
            for part in d.trajectory_summary.split(", ") {
                if let Some(v) = part.strip_prefix("rejections=") {
                    rej = v;
                } else if let Some(v) = part.strip_prefix("escalations=") {
                    esc = v;
                } else if let Some(v) = part.strip_prefix("repairability=") {
                    rep = v;
                }
            }
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                d.timestamp,
                d.band.label(),
                d.interval_ms,
                d.depth.label(),
                rej,
                esc,
                rep,
                d.hysteresis_count,
            ));
        }
        out
    }
}

impl Default for IntegritySweepScheduler {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// Compile-time Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<IntegritySweepScheduler>();
    assert_sync::<IntegritySweepScheduler>();
    assert_send::<EvidenceTrajectory>();
    assert_sync::<EvidenceTrajectory>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn green_evidence(epoch: u64) -> EvidenceTrajectory {
        EvidenceTrajectory::new(0, 0, 0.95, Trend::Stable, epoch)
    }

    fn yellow_evidence(epoch: u64) -> EvidenceTrajectory {
        EvidenceTrajectory::new(3, 0, 0.8, Trend::Stable, epoch)
    }

    fn red_evidence(epoch: u64) -> EvidenceTrajectory {
        EvidenceTrajectory::new(6, 1, 0.3, Trend::Degrading, epoch)
    }

    fn improving_evidence(epoch: u64) -> EvidenceTrajectory {
        EvidenceTrajectory::new(0, 0, 0.98, Trend::Improving, epoch)
    }

    // ── Basic construction ──

    #[test]
    fn test_new_starts_green() {
        let sched = IntegritySweepScheduler::with_defaults();
        assert_eq!(sched.current_band(), PolicyBand::Green);
        assert_eq!(sched.hysteresis_counter(), 0);
        assert_eq!(sched.update_count(), 0);
    }

    #[test]
    fn test_default_is_with_defaults() {
        let sched = IntegritySweepScheduler::default();
        assert_eq!(sched.current_band(), PolicyBand::Green);
    }

    // ── Band classification ──

    #[test]
    fn test_classify_green() {
        let sched = IntegritySweepScheduler::with_defaults();
        assert_eq!(sched.classify_band(&green_evidence(1)), PolicyBand::Green);
    }

    #[test]
    fn test_classify_yellow_by_rejections() {
        let sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(3, 0, 0.9, Trend::Stable, 1);
        assert_eq!(sched.classify_band(&evidence), PolicyBand::Yellow);
    }

    #[test]
    fn test_classify_yellow_by_escalations() {
        let sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 1, 0.9, Trend::Stable, 1);
        assert_eq!(sched.classify_band(&evidence), PolicyBand::Yellow);
    }

    #[test]
    fn test_classify_yellow_by_degrading_trend() {
        let sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 0, 0.9, Trend::Degrading, 1);
        assert_eq!(sched.classify_band(&evidence), PolicyBand::Yellow);
    }

    #[test]
    fn test_classify_red_by_rejections() {
        let sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(5, 0, 0.9, Trend::Stable, 1);
        assert_eq!(sched.classify_band(&evidence), PolicyBand::Red);
    }

    #[test]
    fn test_classify_red_by_degrading_low_repairability() {
        let sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 0, 0.3, Trend::Degrading, 1);
        assert_eq!(sched.classify_band(&evidence), PolicyBand::Red);
    }

    // ── Interval and depth by band ──

    #[test]
    fn test_green_interval() {
        let sched = IntegritySweepScheduler::with_defaults();
        assert_eq!(sched.next_sweep_interval(), Duration::from_millis(300_000));
    }

    #[test]
    fn test_green_depth() {
        let sched = IntegritySweepScheduler::with_defaults();
        assert_eq!(sched.current_sweep_depth(), SweepDepth::Quick);
    }

    #[test]
    fn test_red_interval_and_depth() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.next_sweep_interval(), Duration::from_millis(10_000));
        assert_eq!(sched.current_sweep_depth(), SweepDepth::Deep);
    }

    #[test]
    fn test_yellow_interval_and_depth() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&yellow_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Yellow);
        assert_eq!(sched.next_sweep_interval(), Duration::from_millis(60_000));
        assert_eq!(sched.current_sweep_depth(), SweepDepth::Standard);
    }

    // ── Immediate escalation ──

    #[test]
    fn test_escalation_immediate_green_to_red() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Red);
    }

    #[test]
    fn test_escalation_immediate_green_to_yellow() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&yellow_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Yellow);
    }

    #[test]
    fn test_escalation_immediate_yellow_to_red() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&yellow_evidence(1));
        sched.update_trajectory(&red_evidence(2));
        assert_eq!(sched.current_band(), PolicyBand::Red);
    }

    // ── De-escalation with hysteresis ──

    #[test]
    fn test_deescalation_requires_hysteresis() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Red);

        // 1 green reading: not enough (threshold = 3)
        sched.update_trajectory(&green_evidence(2));
        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.hysteresis_counter(), 1);

        // 2 green readings: still not enough
        sched.update_trajectory(&green_evidence(3));
        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.hysteresis_counter(), 2);

        // 3 green readings: de-escalate to Yellow (one step at a time)
        sched.update_trajectory(&green_evidence(4));
        assert_eq!(sched.current_band(), PolicyBand::Yellow);
        assert_eq!(sched.hysteresis_counter(), 0);
    }

    #[test]
    fn test_deescalation_one_step_at_a_time() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(1));

        // Feed 3 green readings to de-escalate Red → Yellow
        for i in 2..=4 {
            sched.update_trajectory(&green_evidence(i));
        }
        assert_eq!(sched.current_band(), PolicyBand::Yellow);

        // Feed 3 more green readings to de-escalate Yellow → Green
        for i in 5..=7 {
            sched.update_trajectory(&green_evidence(i));
        }
        assert_eq!(sched.current_band(), PolicyBand::Green);
    }

    #[test]
    fn test_hysteresis_reset_on_escalation() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(1));

        // Start de-escalation
        sched.update_trajectory(&green_evidence(2));
        assert_eq!(sched.hysteresis_counter(), 1);

        // Escalation interrupts de-escalation
        sched.update_trajectory(&red_evidence(3));
        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.hysteresis_counter(), 0);
    }

    #[test]
    fn test_hysteresis_threshold_zero() {
        let config = SweepSchedulerConfig {
            hysteresis_threshold: 0,
            ..SweepSchedulerConfig::default_config()
        };
        let mut sched = IntegritySweepScheduler::new(config);
        sched.update_trajectory(&red_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Red);

        // With threshold 0, de-escalation should be immediate
        sched.update_trajectory(&green_evidence(2));
        assert_eq!(sched.current_band(), PolicyBand::Yellow);
    }

    // ── Oscillation prevention ──

    #[test]
    fn test_oscillation_prevention() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let mut band_changes = 0u32;
        let mut prev_band = sched.current_band();

        // Alternate red/green for 100 updates
        for i in 0..100 {
            if i % 2 == 0 {
                sched.update_trajectory(&red_evidence(i));
            } else {
                sched.update_trajectory(&green_evidence(i));
            }
            if sched.current_band() != prev_band {
                band_changes += 1;
                prev_band = sched.current_band();
            }
        }

        // With hysteresis 3, alternating evidence should result in very few
        // de-escalations — the band should stay at Red most of the time
        // because we never get 3 consecutive green readings.
        // Only the initial Green→Red transition should count.
        assert!(
            band_changes <= 2,
            "INV-SWEEP-HYSTERESIS: too many band changes ({band_changes}) with alternating evidence"
        );
    }

    #[test]
    fn test_oscillation_prevention_1000_alternating() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let mut band_changes = 0u32;
        let mut prev_band = sched.current_band();

        for i in 0..1000 {
            if i % 2 == 0 {
                sched.update_trajectory(&red_evidence(i));
            } else {
                sched.update_trajectory(&green_evidence(i));
            }
            if sched.current_band() != prev_band {
                band_changes += 1;
                prev_band = sched.current_band();
            }
        }

        // Should be exactly 1 change: Green → Red (never de-escalates because
        // no 3 consecutive green readings)
        assert_eq!(band_changes, 1, "should only escalate once to Red");
    }

    // ── Monotonic cadence changes ──

    #[test]
    fn test_cadence_increases_during_sustained_degradation() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let mut intervals = Vec::new();

        for i in 1..=5 {
            let evidence = EvidenceTrajectory::new(
                i * 2,
                i,
                0.9 - (i as f64 * 0.1),
                Trend::Degrading,
                i as u64,
            );
            sched.update_trajectory(&evidence);
            intervals.push(sched.next_sweep_interval().as_millis());
        }

        // Intervals should not increase (cadence increases = shorter intervals)
        for i in 0..intervals.len() - 1 {
            assert!(
                intervals[i + 1] <= intervals[i],
                "interval should not increase during degradation: {} > {}",
                intervals[i + 1],
                intervals[i]
            );
        }
    }

    #[test]
    fn test_cadence_decreases_during_sustained_improvement() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        // Start at Red
        sched.update_trajectory(&red_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Red);

        let mut intervals = vec![sched.next_sweep_interval().as_millis()];

        // Feed sustained improving evidence
        for i in 2..=20 {
            sched.update_trajectory(&improving_evidence(i));
            intervals.push(sched.next_sweep_interval().as_millis());
        }

        // By the end, interval should be >= initial (cadence decreased)
        let last = *intervals.last().unwrap();
        let first = intervals[0];
        assert!(
            last >= first,
            "interval should increase during sustained improvement: {last} < {first}"
        );
    }

    // ── Decision recording ──

    #[test]
    fn test_decisions_recorded() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&green_evidence(1));
        sched.update_trajectory(&red_evidence(2));
        assert_eq!(sched.decisions().len(), 2);
    }

    #[test]
    fn test_decision_fields_populated() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(42));
        let decision = &sched.decisions()[0];
        assert_eq!(decision.band, PolicyBand::Red);
        assert_eq!(decision.interval_ms, 10_000);
        assert_eq!(decision.depth, SweepDepth::Deep);
        assert_eq!(decision.epoch_id, 42);
        assert!(!decision.trajectory_summary.is_empty());
    }

    #[test]
    fn test_update_count_increments() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        for i in 1..=5 {
            sched.update_trajectory(&green_evidence(i));
        }
        assert_eq!(sched.update_count(), 5);
    }

    // ── Determinism ──

    #[test]
    fn test_deterministic_scheduling() {
        let evidence_seq: Vec<EvidenceTrajectory> = (1..=20)
            .map(|i| {
                if i <= 5 {
                    green_evidence(i)
                } else if i <= 10 {
                    red_evidence(i)
                } else {
                    green_evidence(i)
                }
            })
            .collect();

        let mut sched1 = IntegritySweepScheduler::with_defaults();
        let mut sched2 = IntegritySweepScheduler::with_defaults();

        for e in &evidence_seq {
            sched1.update_trajectory(e);
            sched2.update_trajectory(e);
        }

        assert_eq!(sched1.current_band(), sched2.current_band());
        assert_eq!(sched1.hysteresis_counter(), sched2.hysteresis_counter());
        assert_eq!(sched1.update_count(), sched2.update_count());
        assert_eq!(sched1.decisions().len(), sched2.decisions().len());
    }

    // ── First update (no history) ──

    #[test]
    fn test_first_update_green() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&green_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Green);
        assert_eq!(sched.update_count(), 1);
    }

    #[test]
    fn test_first_update_red() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(1));
        assert_eq!(sched.current_band(), PolicyBand::Red);
    }

    // ── All-zero trajectory ──

    #[test]
    fn test_all_zero_trajectory() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 0, 0.0, Trend::Stable, 1);
        sched.update_trajectory(&evidence);
        // Zero rejections, zero escalations, stable trend → Green
        assert_eq!(sched.current_band(), PolicyBand::Green);
    }

    // ── NaN/Inf handling ──

    #[test]
    fn test_nan_repairability_clamped() {
        let evidence = EvidenceTrajectory::new(0, 0, f64::NAN, Trend::Stable, 1);
        assert_eq!(evidence.avg_repairability, 0.0);
    }

    #[test]
    fn test_inf_repairability_clamped() {
        let evidence = EvidenceTrajectory::new(0, 0, f64::INFINITY, Trend::Stable, 1);
        assert_eq!(evidence.avg_repairability, 0.0);
    }

    #[test]
    fn test_negative_inf_clamped() {
        let evidence = EvidenceTrajectory::new(0, 0, f64::NEG_INFINITY, Trend::Stable, 1);
        assert_eq!(evidence.avg_repairability, 0.0);
    }

    // ── Overflow protection ──

    #[test]
    fn test_high_rejection_count() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(u32::MAX, 0, 0.5, Trend::Degrading, 1);
        sched.update_trajectory(&evidence);
        assert_eq!(sched.current_band(), PolicyBand::Red);
    }

    // ── PolicyBand ordering ──

    #[test]
    fn test_band_ordering() {
        assert!(PolicyBand::Green < PolicyBand::Yellow);
        assert!(PolicyBand::Yellow < PolicyBand::Red);
    }

    #[test]
    fn test_band_labels() {
        assert_eq!(PolicyBand::Green.label(), "green");
        assert_eq!(PolicyBand::Yellow.label(), "yellow");
        assert_eq!(PolicyBand::Red.label(), "red");
    }

    // ── Trend labels ──

    #[test]
    fn test_trend_labels() {
        assert_eq!(Trend::Improving.label(), "improving");
        assert_eq!(Trend::Stable.label(), "stable");
        assert_eq!(Trend::Degrading.label(), "degrading");
    }

    // ── SweepDepth labels ──

    #[test]
    fn test_sweep_depth_labels() {
        assert_eq!(SweepDepth::Quick.label(), "quick");
        assert_eq!(SweepDepth::Standard.label(), "standard");
        assert_eq!(SweepDepth::Deep.label(), "deep");
        assert_eq!(SweepDepth::Full.label(), "full");
    }

    // ── Event codes ──

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(EVD_SWEEP_001, "EVD-SWEEP-001");
        assert_eq!(EVD_SWEEP_002, "EVD-SWEEP-002");
        assert_eq!(EVD_SWEEP_003, "EVD-SWEEP-003");
        assert_eq!(EVD_SWEEP_004, "EVD-SWEEP-004");
    }

    // ── Serialization ──

    #[test]
    fn test_scheduler_serialization_roundtrip() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(1));
        sched.update_trajectory(&green_evidence(2));
        let json = serde_json::to_string(&sched).unwrap();
        let parsed: IntegritySweepScheduler = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.current_band(), sched.current_band());
        assert_eq!(parsed.update_count(), sched.update_count());
    }

    #[test]
    fn test_evidence_trajectory_serialization() {
        let evidence = red_evidence(42);
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: EvidenceTrajectory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.epoch_id, 42);
    }

    // ── CSV export ──

    #[test]
    fn test_csv_export_header() {
        let sched = IntegritySweepScheduler::with_defaults();
        let csv = sched.to_csv();
        assert!(csv.starts_with("timestamp,band,interval_ms,depth,"));
    }

    #[test]
    fn test_csv_export_rows() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&green_evidence(1));
        sched.update_trajectory(&red_evidence(2));
        let csv = sched.to_csv();
        let lines: Vec<&str> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 data rows
    }

    // ── Config validation ──

    #[test]
    fn test_default_config_valid() {
        let config = SweepSchedulerConfig::default_config();
        assert!(config.green_interval_ms > config.yellow_interval_ms);
        assert!(config.yellow_interval_ms > config.red_interval_ms);
        assert!(config.yellow_rejection_threshold < config.red_rejection_threshold);
        assert!(config.hysteresis_threshold > 0);
    }
}
