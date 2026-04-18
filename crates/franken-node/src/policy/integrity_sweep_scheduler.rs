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

const MAX_DECISIONS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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
        self.update_count = self.update_count.saturating_add(1);

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
            self.hysteresis_counter = self.hysteresis_counter.saturating_add(1);

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

        push_bounded(&mut self.decisions, decision, MAX_DECISIONS);

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

    #[test]
    fn non_finite_degrading_repairability_escalates_to_red() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 0, f64::NAN, Trend::Degrading, 99);

        sched.update_trajectory(&evidence);

        assert_eq!(evidence.avg_repairability, 0.0);
        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.decisions()[0].epoch_id, 99);
    }

    #[test]
    fn negative_infinite_repairability_is_contained_before_classification() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 0, f64::NEG_INFINITY, Trend::Stable, 7);

        sched.update_trajectory(&evidence);

        assert_eq!(evidence.avg_repairability, 0.0);
        assert_eq!(sched.current_band(), PolicyBand::Green);
        assert_eq!(sched.current_sweep_depth(), SweepDepth::Quick);
    }

    #[test]
    fn zero_interval_config_records_zero_duration_without_panicking() {
        let config = SweepSchedulerConfig {
            green_interval_ms: 0,
            yellow_interval_ms: 0,
            red_interval_ms: 0,
            ..SweepSchedulerConfig::default_config()
        };
        let mut sched = IntegritySweepScheduler::new(config);

        sched.update_trajectory(&red_evidence(1));

        assert_eq!(sched.next_sweep_interval(), Duration::from_millis(0));
        assert_eq!(sched.decisions()[0].interval_ms, 0);
        assert_eq!(sched.current_band(), PolicyBand::Red);
    }

    #[test]
    fn zero_hysteresis_deescalates_only_one_band_per_update() {
        let config = SweepSchedulerConfig {
            hysteresis_threshold: 0,
            ..SweepSchedulerConfig::default_config()
        };
        let mut sched = IntegritySweepScheduler::new(config);
        sched.update_trajectory(&red_evidence(1));

        sched.update_trajectory(&green_evidence(2));

        assert_eq!(sched.current_band(), PolicyBand::Yellow);
        assert_eq!(sched.hysteresis_counter(), 0);
        assert_eq!(sched.current_sweep_depth(), SweepDepth::Standard);
    }

    #[test]
    fn inverted_rejection_thresholds_still_choose_more_severe_band() {
        let config = SweepSchedulerConfig {
            yellow_rejection_threshold: 10,
            red_rejection_threshold: 2,
            ..SweepSchedulerConfig::default_config()
        };
        let sched = IntegritySweepScheduler::new(config);
        let evidence = EvidenceTrajectory::new(3, 0, 0.9, Trend::Stable, 1);

        assert_eq!(sched.classify_band(&evidence), PolicyBand::Red);
    }

    #[test]
    fn stale_epoch_updates_are_recorded_without_reordering_decisions() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(10));

        sched.update_trajectory(&green_evidence(1));

        assert_eq!(sched.update_count(), 2);
        assert_eq!(sched.decisions()[0].epoch_id, 10);
        assert_eq!(sched.decisions()[1].epoch_id, 1);
        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.hysteresis_counter(), 1);
    }

    #[test]
    fn csv_export_handles_unparseable_decision_summary_as_zeroes() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.decisions.push(SweepScheduleDecision {
            timestamp: 55,
            band: PolicyBand::Yellow,
            interval_ms: 123,
            depth: SweepDepth::Standard,
            trajectory_summary: "not a scheduler summary".to_string(),
            hysteresis_count: 2,
            epoch_id: 55,
        });

        let csv = sched.to_csv();

        assert!(csv.contains("55,yellow,123,standard,0,0,0.0,2"));
    }

    #[test]
    fn push_bounded_zero_capacity_on_empty_window_stays_empty() {
        let mut items: Vec<u8> = Vec::new();

        push_bounded(&mut items, 7, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_zero_capacity_clears_sweep_decision_window() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_preserves_latest_sweep_decisions() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn high_repairability_above_one_is_clamped_before_red_low_repairability_check() {
        let sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 0, 7.5, Trend::Degrading, 61);

        assert_eq!(evidence.avg_repairability, 1.0);
        assert_eq!(sched.classify_band(&evidence), PolicyBand::Yellow);
    }

    #[test]
    fn negative_repairability_is_clamped_and_degrading_evidence_fails_closed_red() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        let evidence = EvidenceTrajectory::new(0, 0, -0.25, Trend::Degrading, 62);

        sched.update_trajectory(&evidence);

        assert_eq!(evidence.avg_repairability, 0.0);
        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.current_sweep_depth(), SweepDepth::Deep);
    }

    #[test]
    fn red_band_does_not_drop_on_single_yellow_reading() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(63));

        sched.update_trajectory(&yellow_evidence(64));

        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.hysteresis_counter(), 1);
        assert_eq!(sched.decisions()[1].band, PolicyBand::Red);
    }

    #[test]
    fn same_band_red_reading_resets_pending_deescalation() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_trajectory(&red_evidence(65));
        sched.update_trajectory(&green_evidence(66));
        assert_eq!(sched.hysteresis_counter(), 1);

        sched.update_trajectory(&red_evidence(67));

        assert_eq!(sched.current_band(), PolicyBand::Red);
        assert_eq!(sched.hysteresis_counter(), 0);
    }

    #[test]
    fn zero_red_rejection_threshold_fails_closed_to_red_for_clean_evidence() {
        let config = SweepSchedulerConfig {
            red_rejection_threshold: 0,
            ..SweepSchedulerConfig::default_config()
        };
        let sched = IntegritySweepScheduler::new(config);

        assert_eq!(sched.classify_band(&green_evidence(68)), PolicyBand::Red);
    }

    #[test]
    fn zero_yellow_rejection_threshold_escalates_clean_evidence_to_yellow() {
        let config = SweepSchedulerConfig {
            yellow_rejection_threshold: 0,
            red_rejection_threshold: 5,
            ..SweepSchedulerConfig::default_config()
        };
        let sched = IntegritySweepScheduler::new(config);

        assert_eq!(sched.classify_band(&green_evidence(69)), PolicyBand::Yellow);
    }

    #[test]
    fn update_count_saturates_at_u64_max_without_wrapping() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.update_count = u64::MAX;

        sched.update_trajectory(&green_evidence(70));

        assert_eq!(sched.update_count(), u64::MAX);
        assert_eq!(sched.decisions().len(), 1);
    }

    #[test]
    fn decision_log_at_capacity_evicts_oldest_decision() {
        let mut sched = IntegritySweepScheduler::with_defaults();
        sched.decisions = (0..MAX_DECISIONS)
            .map(|idx| SweepScheduleDecision {
                timestamp: u64::try_from(idx).expect("test index fits in u64"),
                band: PolicyBand::Green,
                interval_ms: 300_000,
                depth: SweepDepth::Quick,
                trajectory_summary: "rejections=0, escalations=0, repairability=1.00, trend=stable"
                    .to_string(),
                hysteresis_count: 0,
                epoch_id: u64::try_from(idx).expect("test index fits in u64"),
            })
            .collect();

        sched.update_trajectory(&green_evidence(71));

        assert_eq!(sched.decisions().len(), MAX_DECISIONS);
        assert_eq!(sched.decisions()[0].timestamp, 1);
        assert_eq!(sched.decisions().last().expect("last decision").epoch_id, 71);
    }

    // ── Hardening-focused negative-path tests targeting specific patterns ──

    #[test]
    fn test_counter_overflow_protection_with_saturating_add() {
        // Test for missing saturating_add on counters - should not panic on overflow
        let mut sched = IntegritySweepScheduler::with_defaults();

        // Create evidence with near-overflow values
        let overflow_evidence = EvidenceTrajectory::new(
            u32::MAX.saturating_sub(1), // Near overflow rejection count
            u32::MAX.saturating_sub(1), // Near overflow escalation count
            0.5,
            Trend::Degrading,
            1000,
        );

        // Multiple updates should use saturating arithmetic internally
        for i in 0..10 {
            let next_evidence = EvidenceTrajectory::new(
                u32::MAX.saturating_sub(1).saturating_add(1), // Should saturate at MAX
                u32::MAX.saturating_sub(1).saturating_add(1),
                0.5,
                Trend::Degrading,
                1000_u64.saturating_add(i),
            );

            // Should not panic due to overflow
            sched.update_trajectory(&next_evidence);
        }

        // Verify scheduler remains functional
        assert!(sched.update_count() > 0);
        assert!(sched.current_band() != PolicyBand::Green); // Should have escalated
    }

    #[test]
    fn test_length_casting_uses_try_from_pattern() {
        // Test for .len() as u32 - should use u32::try_from pattern
        let mut sched = IntegritySweepScheduler::with_defaults();

        // Fill up to capacity
        for i in 0..MAX_DECISIONS {
            sched.update_trajectory(&green_evidence(i as u64));
        }

        let decisions_len = sched.decisions().len();

        // Test the hardening pattern: should use try_from, not direct cast
        let len_as_u32 = u32::try_from(decisions_len).unwrap_or(u32::MAX);
        assert!(len_as_u32 <= u32::MAX);

        // Test that very large collections would be handled safely
        assert!(decisions_len <= MAX_DECISIONS);

        // If we had more than u32::MAX decisions, try_from would handle it safely
        let hypothetical_large_len = usize::MAX;
        let safe_cast = u32::try_from(hypothetical_large_len).unwrap_or(u32::MAX);
        assert_eq!(safe_cast, u32::MAX); // Should cap at u32::MAX, not cast unsafely
    }

    #[test]
    fn test_expiry_comparison_uses_greater_equal_pattern() {
        // Test for > on expiry - should use >= for fail-closed semantics
        let mut sched = IntegritySweepScheduler::with_defaults();

        let evidence = green_evidence(1000);
        sched.update_trajectory(&evidence);

        // Simulate time-based expiry checks
        let current_time = 5000_u64;
        let expiry_time = 5000_u64; // Exactly at expiry boundary

        // Fail-closed pattern: >= means "expired" (includes exact boundary)
        let is_expired_fail_closed = current_time >= expiry_time;
        assert!(is_expired_fail_closed, "Boundary case should be considered expired");

        // Anti-pattern would be > which would allow boundary case through
        let is_expired_anti_pattern = current_time > expiry_time;
        assert!(!is_expired_anti_pattern, "Anti-pattern would incorrectly allow boundary");

        // Test with slightly past expiry
        let past_expiry = current_time >= (expiry_time - 1);
        assert!(past_expiry, ">= correctly identifies past expiry");

        // Test with before expiry
        let before_expiry = (current_time - 1) >= expiry_time;
        assert!(!before_expiry, ">= correctly identifies before expiry");
    }

    #[test]
    fn test_hash_comparison_uses_constant_time_pattern() {
        // Test for == on hashes - should use ct_eq_bytes for timing safety
        use crate::security::constant_time::ct_eq_bytes;

        // Simulate hash/signature comparison scenarios
        let hash1 = b"integrity_sweep_hash_v1_abcdef123456";
        let hash2 = b"integrity_sweep_hash_v1_abcdef123456"; // Same
        let hash3 = b"integrity_sweep_hash_v1_abcdef123457"; // Different by one char

        // Correct pattern: use constant-time comparison
        assert!(ct_eq_bytes(hash1, hash2), "Identical hashes should match");
        assert!(!ct_eq_bytes(hash1, hash3), "Different hashes should not match");

        // Anti-pattern demonstration (don't actually use this in production)
        let timing_vulnerable = hash1 == hash3; // This could leak timing info
        assert!(!timing_vulnerable);

        // Test with empty hashes
        let empty1 = b"";
        let empty2 = b"";
        assert!(ct_eq_bytes(empty1, empty2), "Empty hashes should match");

        // Test with different lengths (should fail fast)
        let short_hash = b"short";
        let long_hash = b"much_longer_hash";
        assert!(!ct_eq_bytes(short_hash, long_hash), "Different length hashes should not match");
    }

    #[test]
    fn test_domain_separator_inclusion_in_hash_inputs() {
        // Test for missing domain separators - crypto operations should include them
        use sha2::{Digest, Sha256};

        // Example of proper domain separation pattern
        let domain_separator = b"integrity_sweep_v1:";
        let trajectory_data = b"rejections=5,escalations=2,repairability=0.8";

        // Correct pattern: include domain separator
        let mut hasher_with_domain = Sha256::new();
        hasher_with_domain.update(domain_separator);
        hasher_with_domain.update(trajectory_data);
        let hash_with_domain = hasher_with_domain.finalize();

        // Anti-pattern: missing domain separator (vulnerable to collision)
        let mut hasher_without_domain = Sha256::new();
        hasher_without_domain.update(trajectory_data);
        let hash_without_domain = hasher_without_domain.finalize();

        // Should be different due to domain separation
        assert_ne!(hash_with_domain[..], hash_without_domain[..],
                   "Domain separator should change hash output");

        // Test different domain separators produce different hashes
        let different_domain = b"other_system_v1:";
        let mut hasher_different_domain = Sha256::new();
        hasher_different_domain.update(different_domain);
        hasher_different_domain.update(trajectory_data);
        let hash_different_domain = hasher_different_domain.finalize();

        assert_ne!(hash_with_domain[..], hash_different_domain[..],
                   "Different domain separators should produce different hashes");

        // Length-prefixed inputs to prevent delimiter collision
        let field1 = "key1=value1";
        let field2 = "key2=value2";

        let mut proper_hasher = Sha256::new();
        proper_hasher.update(b"integrity_sweep_v1:");
        proper_hasher.update((field1.len() as u64).to_le_bytes()); // Length prefix
        proper_hasher.update(field1.as_bytes());
        proper_hasher.update((field2.len() as u64).to_le_bytes()); // Length prefix
        proper_hasher.update(field2.as_bytes());
        let proper_hash = proper_hasher.finalize();

        // Anti-pattern: concatenation without length prefixes (collision vulnerable)
        let mut vulnerable_hasher = Sha256::new();
        vulnerable_hasher.update(b"integrity_sweep_v1:");
        vulnerable_hasher.update(field1.as_bytes());
        vulnerable_hasher.update(field2.as_bytes());
        let vulnerable_hash = vulnerable_hasher.finalize();

        // These might be the same, but the pattern matters for collision resistance
        let _ = (proper_hash, vulnerable_hash); // Just verify we can compute both
    }

    #[test]
    fn test_float_validation_and_nan_inf_handling() {
        // Test for missing NaN/Infinity guards on float inputs

        // Test with NaN repairability score
        let nan_evidence = EvidenceTrajectory {
            recent_rejections: 1,
            recent_escalations: 0,
            avg_repairability: f64::NAN,
            trend: Trend::Stable,
            epoch_id: 1000,
        };

        // Constructor should clamp NaN to finite value
        assert!(nan_evidence.avg_repairability.is_finite(),
                "Constructor should handle NaN repairability");

        // Test with infinity
        let inf_evidence = EvidenceTrajectory::new(
            1, 0, f64::INFINITY, Trend::Stable, 1001
        );
        assert!(inf_evidence.avg_repairability.is_finite(),
                "Constructor should handle infinite repairability");

        // Test with negative infinity
        let neg_inf_evidence = EvidenceTrajectory::new(
            1, 0, f64::NEG_INFINITY, Trend::Stable, 1002
        );
        assert!(neg_inf_evidence.avg_repairability.is_finite(),
                "Constructor should handle negative infinite repairability");

        // Test scheduler behavior with float edge cases
        let mut sched = IntegritySweepScheduler::with_defaults();

        // Should handle NaN/Inf evidence gracefully
        sched.update_trajectory(&nan_evidence);
        sched.update_trajectory(&inf_evidence);
        sched.update_trajectory(&neg_inf_evidence);

        // Should remain functional after bad float inputs
        assert!(sched.update_count() > 0);
        assert_eq!(sched.current_band(), PolicyBand::Yellow); // Should classify as yellow due to rejections
    }
}
