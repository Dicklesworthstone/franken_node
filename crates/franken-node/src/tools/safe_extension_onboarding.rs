//! bd-elog: Automation-first safe-extension onboarding (Section 15).
//!
//! Delivers friction-minimized onboarding from install to first safe extension
//! with deterministic validation. Tracks onboarding steps, validation gates,
//! and time-to-first-extension metrics.
//!
//! # Capabilities
//!
//! - Onboarding step management (5 phases)
//! - Validation gate enforcement per step
//! - Time-to-first-extension measurement
//! - Friction scoring and bottleneck detection
//! - Automation coverage tracking
//! - Onboarding health reporting
//!
//! # Invariants
//!
//! - **INV-SEO-PHASED**: Every onboarding follows defined phases.
//! - **INV-SEO-VALIDATED**: Every phase has a validation gate.
//! - **INV-SEO-DETERMINISTIC**: Same inputs produce same onboarding report.
//! - **INV-SEO-GATED**: Extensions blocked until onboarding completes.
//! - **INV-SEO-VERSIONED**: Schema version embedded in every export.
//! - **INV-SEO-AUDITABLE**: Every step produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod event_codes {
    pub const SEO_SESSION_STARTED: &str = "SEO-001";
    pub const SEO_STEP_COMPLETED: &str = "SEO-002";
    pub const SEO_GATE_PASSED: &str = "SEO-003";
    pub const SEO_GATE_FAILED: &str = "SEO-004";
    pub const SEO_EXTENSION_ACTIVATED: &str = "SEO-005";
    pub const SEO_FRICTION_SCORED: &str = "SEO-006";
    pub const SEO_REPORT_GENERATED: &str = "SEO-007";
    pub const SEO_BOTTLENECK_DETECTED: &str = "SEO-008";
    pub const SEO_VERSION_EMBEDDED: &str = "SEO-009";
    pub const SEO_AUTOMATION_MEASURED: &str = "SEO-010";
    pub const SEO_ERR_STEP_BLOCKED: &str = "SEO-ERR-001";
    pub const SEO_ERR_GATE_TIMEOUT: &str = "SEO-ERR-002";
}

pub mod invariants {
    pub const INV_SEO_PHASED: &str = "INV-SEO-PHASED";
    pub const INV_SEO_VALIDATED: &str = "INV-SEO-VALIDATED";
    pub const INV_SEO_DETERMINISTIC: &str = "INV-SEO-DETERMINISTIC";
    pub const INV_SEO_GATED: &str = "INV-SEO-GATED";
    pub const INV_SEO_VERSIONED: &str = "INV-SEO-VERSIONED";
    pub const INV_SEO_AUDITABLE: &str = "INV-SEO-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "seo-v1.0";
pub const MAX_FRICTION_SCORE: f64 = 3.0;
pub const TARGET_TTFE_SECONDS: u64 = 300;
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_STEPS: usize = 4096;

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

fn hash_f64(hasher: &mut Sha256, value: f64) {
    if value.is_finite() {
        hasher.update(value.to_le_bytes());
    } else {
        hasher.update(f64::NAN.to_le_bytes());
    }
}

/// Onboarding phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OnboardingPhase {
    Install,
    Configure,
    Validate,
    Activate,
    Monitor,
}

impl OnboardingPhase {
    pub fn all() -> &'static [OnboardingPhase] {
        &[
            Self::Install,
            Self::Configure,
            Self::Validate,
            Self::Activate,
            Self::Monitor,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Configure => "configure",
            Self::Validate => "validate",
            Self::Activate => "activate",
            Self::Monitor => "monitor",
        }
    }
    pub fn next(&self) -> Option<OnboardingPhase> {
        match self {
            Self::Install => Some(Self::Configure),
            Self::Configure => Some(Self::Validate),
            Self::Validate => Some(Self::Activate),
            Self::Activate => Some(Self::Monitor),
            Self::Monitor => None,
        }
    }
}

/// Validation gate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateResult {
    Passed,
    Failed,
    Skipped,
}

/// A single onboarding step record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingStep {
    pub step_id: String,
    pub session_id: String,
    pub phase: OnboardingPhase,
    pub duration_seconds: u64,
    pub automated: bool,
    pub gate_result: GateResult,
    pub manual_interventions: u32,
    pub recorded_at: String,
}

/// Per-phase aggregated stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseStats {
    pub phase: OnboardingPhase,
    pub total_sessions: usize,
    pub avg_duration_seconds: f64,
    pub automation_rate: f64,
    pub gate_pass_rate: f64,
    pub friction_score: f64,
}

/// Onboarding health report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingReport {
    pub schema_version: String,
    pub total_sessions: usize,
    pub completed_sessions: usize,
    pub completion_rate: f64,
    pub mean_ttfe_seconds: f64,
    pub meets_ttfe_target: bool,
    pub overall_automation_rate: f64,
    pub overall_friction_score: f64,
    pub phase_stats: Vec<PhaseStats>,
    pub bottleneck_phases: Vec<String>,
    pub content_hash: String,
    pub generated_at: String,
}

/// Audit record for JSONL export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeoAuditRecord {
    pub event_code: String,
    pub entity_id: String,
    pub detail: String,
    pub trace_id: String,
    pub timestamp: String,
}

/// Safe extension onboarding engine.
#[derive(Debug, Clone)]
pub struct SafeExtensionOnboarding {
    pub steps: Vec<OnboardingStep>,
    pub audit_log: Vec<SeoAuditRecord>,
    pub schema_version: String,
}

impl Default for SafeExtensionOnboarding {
    fn default() -> Self {
        Self {
            steps: Vec::new(),
            audit_log: Vec::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }
}

impl SafeExtensionOnboarding {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an onboarding step.
    pub fn record_step(&mut self, step: OnboardingStep) {
        let sid = step.session_id.clone();
        let phase = step.phase.label().to_string();

        if step.phase == OnboardingPhase::Install {
            self.log(
                event_codes::SEO_SESSION_STARTED,
                &sid,
                &format!("phase={}", phase),
            );
        }

        self.log(
            event_codes::SEO_STEP_COMPLETED,
            &step.step_id,
            &format!(
                "session={} phase={} duration={}s automated={}",
                sid, phase, step.duration_seconds, step.automated
            ),
        );

        match step.gate_result {
            GateResult::Passed => self.log(event_codes::SEO_GATE_PASSED, &step.step_id, &phase),
            GateResult::Failed => {
                self.log(event_codes::SEO_GATE_FAILED, &step.step_id, &phase);
                self.log(
                    event_codes::SEO_ERR_STEP_BLOCKED,
                    &step.step_id,
                    &format!("blocked at {}", phase),
                );
            }
            GateResult::Skipped => {}
        }

        if step.phase == OnboardingPhase::Activate && step.gate_result == GateResult::Passed {
            self.log(
                event_codes::SEO_EXTENSION_ACTIVATED,
                &sid,
                "first safe extension activated",
            );
        }

        push_bounded(&mut self.steps, step, MAX_STEPS);
    }

    /// Compute time-to-first-extension for a session (sum of all step durations).
    pub fn session_ttfe(&self, session_id: &str) -> Option<u64> {
        let session_steps: Vec<&OnboardingStep> = self
            .steps
            .iter()
            .filter(|s| s.session_id == session_id)
            .collect();
        if session_steps.is_empty() {
            return None;
        }
        Some(
            session_steps
                .iter()
                .map(|s| s.duration_seconds)
                .fold(0u64, |a, b| a.saturating_add(b)),
        )
    }

    /// Generate onboarding health report.
    pub fn generate_report(&mut self) -> OnboardingReport {
        // Group by session
        let mut sessions: BTreeMap<String, Vec<&OnboardingStep>> = BTreeMap::new();
        for s in &self.steps {
            sessions.entry(s.session_id.clone()).or_default().push(s);
        }

        let total_sessions = sessions.len();
        let completed = sessions
            .values()
            .filter(|steps| {
                steps.iter().any(|s| {
                    s.phase == OnboardingPhase::Activate && s.gate_result == GateResult::Passed
                })
            })
            .count();
        let completion_rate = if total_sessions > 0 {
            completed as f64 / total_sessions as f64
        } else {
            0.0
        };

        // Mean TTFE
        let ttfes: Vec<u64> = sessions
            .keys()
            .filter_map(|sid| self.session_ttfe(sid))
            .collect();
        let mean_ttfe = if !ttfes.is_empty() {
            ttfes.iter().fold(0u64, |a, b| a.saturating_add(*b)) as f64 / ttfes.len() as f64
        } else {
            0.0
        };

        // Per-phase stats — collect owned data to avoid borrowing self.steps during self.log()
        let mut phase_groups: BTreeMap<OnboardingPhase, Vec<(f64, bool, bool, f64)>> =
            BTreeMap::new();
        for s in &self.steps {
            phase_groups.entry(s.phase).or_default().push((
                s.duration_seconds as f64,
                s.automated,
                s.gate_result == GateResult::Passed,
                s.manual_interventions as f64,
            ));
        }

        let mut phase_stats = Vec::new();
        let mut bottleneck_phases = Vec::new();

        for phase in OnboardingPhase::all() {
            if let Some(steps) = phase_groups.get(phase) {
                let n = steps.len();
                if n == 0 {
                    continue;
                }
                let avg_dur = steps.iter().map(|(d, _, _, _)| d).sum::<f64>() / n as f64;
                let auto_rate = steps.iter().filter(|(_, a, _, _)| *a).count() as f64 / n as f64;
                let pass_rate = steps.iter().filter(|(_, _, p, _)| *p).count() as f64 / n as f64;

                // Friction = (1 - automation_rate) * avg_interventions
                let avg_interventions = steps.iter().map(|(_, _, _, m)| m).sum::<f64>() / n as f64;
                let friction = (1.0 - auto_rate) * avg_interventions + (1.0 - pass_rate) * 2.0;

                if friction > MAX_FRICTION_SCORE {
                    bottleneck_phases.push(phase.label().to_string());
                    self.log(
                        event_codes::SEO_BOTTLENECK_DETECTED,
                        "report",
                        &format!("phase={} friction={:.2}", phase.label(), friction),
                    );
                }

                phase_stats.push(PhaseStats {
                    phase: *phase,
                    total_sessions: n,
                    avg_duration_seconds: avg_dur,
                    automation_rate: auto_rate,
                    gate_pass_rate: pass_rate,
                    friction_score: friction,
                });
            }
        }

        let overall_auto = if !self.steps.is_empty() {
            self.steps.iter().filter(|s| s.automated).count() as f64 / self.steps.len() as f64
        } else {
            0.0
        };

        let overall_friction = if !phase_stats.is_empty() {
            phase_stats.iter().map(|p| p.friction_score).sum::<f64>() / phase_stats.len() as f64
        } else {
            0.0
        };

        let meets_ttfe = mean_ttfe > 0.0 && mean_ttfe <= TARGET_TTFE_SECONDS as f64;

        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"safe_extension_hash_v1:");
            h.update((SCHEMA_VERSION.len() as u64).to_le_bytes());
            h.update(SCHEMA_VERSION.as_bytes());
            h.update((total_sessions as u64).to_le_bytes());
            h.update((completed as u64).to_le_bytes());
            hash_f64(&mut h, completion_rate);
            hash_f64(&mut h, mean_ttfe);
            h.update([u8::from(meets_ttfe)]);
            hash_f64(&mut h, overall_auto);
            hash_f64(&mut h, overall_friction);
            h.update((phase_stats.len() as u64).to_le_bytes());
            for ps in &phase_stats {
                let label = ps.phase.label();
                h.update((label.len() as u64).to_le_bytes());
                h.update(label.as_bytes());
                h.update((ps.total_sessions as u64).to_le_bytes());
                hash_f64(&mut h, ps.avg_duration_seconds);
                hash_f64(&mut h, ps.automation_rate);
                hash_f64(&mut h, ps.gate_pass_rate);
                hash_f64(&mut h, ps.friction_score);
            }
            h.update((bottleneck_phases.len() as u64).to_le_bytes());
            for bp in &bottleneck_phases {
                h.update((bp.len() as u64).to_le_bytes());
                h.update(bp.as_bytes());
            }
            format!("{:x}", h.finalize())
        };

        self.log(
            event_codes::SEO_REPORT_GENERATED,
            "report",
            &format!("sessions={} completed={}", total_sessions, completed),
        );
        self.log(
            event_codes::SEO_FRICTION_SCORED,
            "report",
            &format!("friction={:.3}", overall_friction),
        );
        self.log(
            event_codes::SEO_AUTOMATION_MEASURED,
            "report",
            &format!("rate={:.3}", overall_auto),
        );
        self.log(event_codes::SEO_VERSION_EMBEDDED, "report", SCHEMA_VERSION);

        OnboardingReport {
            schema_version: self.schema_version.clone(),
            total_sessions,
            completed_sessions: completed,
            completion_rate,
            mean_ttfe_seconds: mean_ttfe,
            meets_ttfe_target: meets_ttfe,
            overall_automation_rate: overall_auto,
            overall_friction_score: overall_friction,
            phase_stats,
            bottleneck_phases,
            content_hash,
            generated_at: Utc::now().to_rfc3339(),
        }
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn log(&mut self, event_code: &str, entity_id: &str, detail: &str) {
        push_bounded(
            &mut self.audit_log,
            SeoAuditRecord {
                event_code: event_code.to_string(),
                entity_id: entity_id.to_string(),
                detail: detail.to_string(),
                trace_id: Uuid::now_v7().to_string(),
                timestamp: Utc::now().to_rfc3339(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

#[allow(dead_code)]
fn sample_step(step_id: &str, session_id: &str, phase: OnboardingPhase) -> OnboardingStep {
    OnboardingStep {
        step_id: step_id.to_string(),
        session_id: session_id.to_string(),
        phase,
        duration_seconds: 30,
        automated: true,
        gate_result: GateResult::Passed,
        manual_interventions: 0,
        recorded_at: Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_engine_has_version() {
        let e = SafeExtensionOnboarding::default();
        assert_eq!(e.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn phase_all_returns_five() {
        assert_eq!(OnboardingPhase::all().len(), 5);
    }

    #[test]
    fn phase_labels_unique() {
        let labels: Vec<&str> = OnboardingPhase::all().iter().map(|p| p.label()).collect();
        let mut d = labels.clone();
        d.sort();
        d.dedup();
        assert_eq!(labels.len(), d.len());
    }

    #[test]
    fn phase_progression() {
        assert_eq!(
            OnboardingPhase::Install.next(),
            Some(OnboardingPhase::Configure)
        );
        assert_eq!(OnboardingPhase::Monitor.next(), None);
    }

    #[test]
    fn record_step_adds() {
        let mut e = SafeExtensionOnboarding::new();
        e.record_step(sample_step("s1", "sess1", OnboardingPhase::Install));
        assert_eq!(e.steps.len(), 1);
    }

    #[test]
    fn record_step_produces_audit() {
        let mut e = SafeExtensionOnboarding::new();
        e.record_step(sample_step("s1", "sess1", OnboardingPhase::Install));
        assert_eq!(e.audit_log.len(), 3);
    }

    #[test]
    fn gate_failed_produces_blocked_event() {
        let mut e = SafeExtensionOnboarding::new();
        let mut step = sample_step("s1", "sess1", OnboardingPhase::Validate);
        step.gate_result = GateResult::Failed;
        e.record_step(step);
        let codes: Vec<&str> = e.audit_log.iter().map(|r| r.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::SEO_ERR_STEP_BLOCKED));
    }

    #[test]
    fn activate_produces_extension_event() {
        let mut e = SafeExtensionOnboarding::new();
        e.record_step(sample_step("s1", "sess1", OnboardingPhase::Activate));
        let codes: Vec<&str> = e.audit_log.iter().map(|r| r.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::SEO_EXTENSION_ACTIVATED));
    }

    #[test]
    fn session_ttfe_computed() {
        let mut e = SafeExtensionOnboarding::new();
        let mut s1 = sample_step("s1", "sess1", OnboardingPhase::Install);
        s1.duration_seconds = 60;
        let mut s2 = sample_step("s2", "sess1", OnboardingPhase::Configure);
        s2.duration_seconds = 90;
        e.record_step(s1);
        e.record_step(s2);
        assert_eq!(e.session_ttfe("sess1"), Some(150));
    }

    #[test]
    fn session_ttfe_missing() {
        let e = SafeExtensionOnboarding::new();
        assert_eq!(e.session_ttfe("missing"), None);
    }

    #[test]
    fn report_empty() {
        let mut e = SafeExtensionOnboarding::new();
        let r = e.generate_report();
        assert_eq!(r.total_sessions, 0);
        assert_eq!(r.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_populated() {
        let mut e = SafeExtensionOnboarding::new();
        for phase in OnboardingPhase::all() {
            e.record_step(sample_step(
                &format!("s-{}", phase.label()),
                "sess1",
                *phase,
            ));
        }
        let r = e.generate_report();
        assert_eq!(r.total_sessions, 1);
        assert_eq!(r.completed_sessions, 1);
    }

    #[test]
    fn report_meets_ttfe_target() {
        let mut e = SafeExtensionOnboarding::new();
        for phase in OnboardingPhase::all() {
            e.record_step(sample_step(
                &format!("s-{}", phase.label()),
                "sess1",
                *phase,
            ));
        }
        let r = e.generate_report();
        assert!(r.meets_ttfe_target); // 5 * 30s = 150s < 300s target
    }

    #[test]
    fn report_exceeds_ttfe_target() {
        let mut e = SafeExtensionOnboarding::new();
        for phase in OnboardingPhase::all() {
            let mut step = sample_step(&format!("s-{}", phase.label()), "sess1", *phase);
            step.duration_seconds = 120;
            e.record_step(step);
        }
        let r = e.generate_report();
        assert!(!r.meets_ttfe_target); // 5 * 120s = 600s > 300s target
    }

    #[test]
    fn bottleneck_detection() {
        let mut e = SafeExtensionOnboarding::new();
        let mut step = sample_step("s1", "sess1", OnboardingPhase::Configure);
        step.automated = false;
        step.manual_interventions = 5;
        step.gate_result = GateResult::Failed;
        e.record_step(step);
        let r = e.generate_report();
        assert!(r.bottleneck_phases.contains(&"configure".to_string()));
    }

    #[test]
    fn automation_rate_all_automated() {
        let mut e = SafeExtensionOnboarding::new();
        for phase in OnboardingPhase::all() {
            e.record_step(sample_step(
                &format!("s-{}", phase.label()),
                "sess1",
                *phase,
            ));
        }
        let r = e.generate_report();
        assert!((r.overall_automation_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn report_hash_deterministic() {
        let mut e1 = SafeExtensionOnboarding::new();
        let mut e2 = SafeExtensionOnboarding::new();
        assert_eq!(
            e1.generate_report().content_hash,
            e2.generate_report().content_hash
        );
    }

    #[test]
    fn completion_rate_computed() {
        let mut e = SafeExtensionOnboarding::new();
        // Session 1: completed
        e.record_step(sample_step("s1", "sess1", OnboardingPhase::Activate));
        // Session 2: not completed (only install)
        e.record_step(sample_step("s2", "sess2", OnboardingPhase::Install));
        let r = e.generate_report();
        assert!((r.completion_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn export_audit_log_jsonl_format() {
        let mut e = SafeExtensionOnboarding::new();
        e.record_step(sample_step("s1", "sess1", OnboardingPhase::Install));
        let jsonl = e.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        for line in jsonl.lines() {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        }
    }

    #[test]
    fn audit_codes_present() {
        let mut e = SafeExtensionOnboarding::new();
        e.record_step(sample_step("s1", "sess1", OnboardingPhase::Install));
        let codes: Vec<&str> = e.audit_log.iter().map(|r| r.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::SEO_SESSION_STARTED));
        assert!(codes.contains(&event_codes::SEO_STEP_COMPLETED));
    }

    #[test]
    fn gate_result_variants() {
        assert_ne!(GateResult::Passed, GateResult::Failed);
        assert_ne!(GateResult::Failed, GateResult::Skipped);
    }

    #[test]
    fn phase_stats_populated() {
        let mut e = SafeExtensionOnboarding::new();
        e.record_step(sample_step("s1", "sess1", OnboardingPhase::Install));
        let r = e.generate_report();
        assert!(!r.phase_stats.is_empty());
        assert_eq!(r.phase_stats[0].phase, OnboardingPhase::Install);
    }

    // === bd-12ej7: report hash coverage regression ===

    #[test]
    fn report_hash_changes_with_different_automation_rate() {
        // Same session count and phases but different automation rates
        // must produce different content hashes.
        let mut e1 = SafeExtensionOnboarding::new();
        let mut e2 = SafeExtensionOnboarding::new();
        // e1: automated step
        e1.record_step(sample_step("s1", "sess1", OnboardingPhase::Install));
        // e2: manual step
        let mut step = sample_step("s1", "sess1", OnboardingPhase::Install);
        step.automated = false;
        step.manual_interventions = 5;
        e2.record_step(step);
        let r1 = e1.generate_report();
        let r2 = e2.generate_report();
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "Different automation rates must produce different report hash"
        );
    }

    #[test]
    fn report_hash_changes_with_different_phase_average_duration() {
        let mut e1 = SafeExtensionOnboarding::new();
        let mut e2 = SafeExtensionOnboarding::new();

        let mut e1_install = sample_step("s1", "sess1", OnboardingPhase::Install);
        e1_install.duration_seconds = 30;
        let mut e1_configure = sample_step("s2", "sess1", OnboardingPhase::Configure);
        e1_configure.duration_seconds = 60;
        e1.record_step(e1_install);
        e1.record_step(e1_configure);

        let mut e2_install = sample_step("s1", "sess1", OnboardingPhase::Install);
        e2_install.duration_seconds = 60;
        let mut e2_configure = sample_step("s2", "sess1", OnboardingPhase::Configure);
        e2_configure.duration_seconds = 30;
        e2.record_step(e2_install);
        e2.record_step(e2_configure);

        let r1 = e1.generate_report();
        let r2 = e2.generate_report();
        assert!((r1.mean_ttfe_seconds - r2.mean_ttfe_seconds).abs() < f64::EPSILON);
        assert_ne!(
            r1.phase_stats[0].avg_duration_seconds, r2.phase_stats[0].avg_duration_seconds,
            "Install phase average duration should differ"
        );
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "Different per-phase average durations must produce different report hash"
        );
    }

    #[test]
    fn report_hash_changes_with_different_phase_gate_pass_rate() {
        let mut e1 = SafeExtensionOnboarding::new();
        let mut e2 = SafeExtensionOnboarding::new();

        let passed_auto = sample_step("s1", "sess1", OnboardingPhase::Validate);
        let mut passed_manual = sample_step("s2", "sess2", OnboardingPhase::Validate);
        passed_manual.automated = false;
        passed_manual.manual_interventions = 4;
        e1.record_step(passed_auto);
        e1.record_step(passed_manual);

        let passed_auto = sample_step("s1", "sess1", OnboardingPhase::Validate);
        let mut failed_manual = sample_step("s2", "sess2", OnboardingPhase::Validate);
        failed_manual.automated = false;
        failed_manual.gate_result = GateResult::Failed;
        failed_manual.manual_interventions = 0;
        e2.record_step(passed_auto);
        e2.record_step(failed_manual);

        let r1 = e1.generate_report();
        let r2 = e2.generate_report();
        assert!((r1.mean_ttfe_seconds - r2.mean_ttfe_seconds).abs() < f64::EPSILON);
        assert!(
            (r1.phase_stats[0].automation_rate - r2.phase_stats[0].automation_rate).abs()
                < f64::EPSILON
        );
        assert!(
            (r1.phase_stats[0].friction_score - r2.phase_stats[0].friction_score).abs()
                < f64::EPSILON
        );
        assert_ne!(
            r1.phase_stats[0].gate_pass_rate, r2.phase_stats[0].gate_pass_rate,
            "Validate phase gate pass rate should differ"
        );
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "Different per-phase gate pass rates must produce different report hash"
        );
    }

    #[test]
    fn push_bounded_zero_capacity_discards_stale_entries() {
        let mut items = vec!["stale-install", "stale-configure"];

        push_bounded(&mut items, "new-step", 0);

        assert!(
            items.is_empty(),
            "zero-capacity bounded buffers must not retain stale onboarding entries"
        );
    }

    #[test]
    fn push_bounded_over_capacity_keeps_latest_entries() {
        let mut items = vec!["install", "configure", "validate"];

        push_bounded(&mut items, "activate", 2);

        assert_eq!(items, vec!["validate", "activate"]);
    }

    #[test]
    fn skipped_gate_does_not_emit_pass_or_failure_events() {
        let mut e = SafeExtensionOnboarding::new();
        let mut step = sample_step("skip-validate", "sess-skip", OnboardingPhase::Validate);
        step.gate_result = GateResult::Skipped;

        e.record_step(step);

        let codes: Vec<&str> = e.audit_log.iter().map(|r| r.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::SEO_STEP_COMPLETED));
        assert!(!codes.contains(&event_codes::SEO_GATE_PASSED));
        assert!(!codes.contains(&event_codes::SEO_GATE_FAILED));
        assert!(!codes.contains(&event_codes::SEO_ERR_STEP_BLOCKED));
    }

    #[test]
    fn failed_activate_gate_does_not_activate_extension_or_complete_session() {
        let mut e = SafeExtensionOnboarding::new();
        let mut step = sample_step("activate-failed", "sess-failed", OnboardingPhase::Activate);
        step.gate_result = GateResult::Failed;

        e.record_step(step);
        let report = e.generate_report();

        assert_eq!(report.completed_sessions, 0);
        assert_eq!(report.completion_rate, 0.0);
        assert!(
            e.audit_log
                .iter()
                .all(|record| record.event_code != event_codes::SEO_EXTENSION_ACTIVATED),
            "failed activation gates must not emit extension activation events"
        );
    }

    #[test]
    fn monitor_only_session_does_not_count_as_completed() {
        let mut e = SafeExtensionOnboarding::new();
        let mut step = sample_step("monitor-only", "sess-monitor", OnboardingPhase::Monitor);
        step.duration_seconds = TARGET_TTFE_SECONDS.saturating_add(1);
        e.record_step(step);

        let report = e.generate_report();

        assert_eq!(report.total_sessions, 1);
        assert_eq!(report.completed_sessions, 0);
        assert!(!report.meets_ttfe_target);
    }

    #[test]
    fn session_ttfe_saturates_on_extreme_durations() {
        let mut e = SafeExtensionOnboarding::new();
        let mut first = sample_step("huge-1", "sess-huge", OnboardingPhase::Install);
        first.duration_seconds = u64::MAX;
        let mut second = sample_step("huge-2", "sess-huge", OnboardingPhase::Configure);
        second.duration_seconds = 42;

        e.record_step(first);
        e.record_step(second);

        assert_eq!(e.session_ttfe("sess-huge"), Some(u64::MAX));
    }

    #[test]
    fn failed_gate_has_zero_pass_rate_for_phase() {
        let mut e = SafeExtensionOnboarding::new();
        let mut step = sample_step(
            "failed-configure",
            "sess-config",
            OnboardingPhase::Configure,
        );
        step.automated = false;
        step.gate_result = GateResult::Failed;
        step.manual_interventions = 2;

        e.record_step(step);
        let report = e.generate_report();

        let configure = report
            .phase_stats
            .iter()
            .find(|stats| stats.phase == OnboardingPhase::Configure)
            .expect("configure stats should be present");
        assert_eq!(configure.gate_pass_rate, 0.0);
        assert!(
            report.bottleneck_phases.contains(&"configure".to_string()),
            "failed gates should be visible as onboarding bottlenecks"
        );
    }

    #[test]
    fn empty_audit_log_exports_empty_jsonl() {
        let e = SafeExtensionOnboarding::new();

        assert_eq!(e.export_audit_log_jsonl(), "");
    }

    #[test]
    fn report_generation_on_empty_engine_keeps_bottlenecks_empty() {
        let mut e = SafeExtensionOnboarding::new();

        let report = e.generate_report();

        assert_eq!(report.total_sessions, 0);
        assert_eq!(report.completed_sessions, 0);
        assert!(report.phase_stats.is_empty());
        assert!(report.bottleneck_phases.is_empty());
        assert!(!report.meets_ttfe_target);
    }

    #[test]
    fn onboarding_phase_deserialize_rejects_unknown_variant() {
        let result: Result<OnboardingPhase, _> = serde_json::from_str(r#""rollback""#);

        assert!(result.is_err());
    }

    #[test]
    fn gate_result_deserialize_rejects_lowercase_variant() {
        let result: Result<GateResult, _> = serde_json::from_str(r#""passed""#);

        assert!(result.is_err());
    }

    #[test]
    fn onboarding_step_deserialize_rejects_missing_phase() {
        let raw = serde_json::json!({
            "step_id": "missing-phase",
            "session_id": "sess-missing-phase",
            "duration_seconds": 30,
            "automated": true,
            "gate_result": "Passed",
            "manual_interventions": 0,
            "recorded_at": "2026-04-17T00:00:00Z"
        });

        let result: Result<OnboardingStep, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn onboarding_step_deserialize_rejects_manual_intervention_overflow() {
        let raw = serde_json::json!({
            "step_id": "overflow-manual",
            "session_id": "sess-overflow-manual",
            "phase": "Configure",
            "duration_seconds": 30,
            "automated": false,
            "gate_result": "Failed",
            "manual_interventions": 4_294_967_296_u64,
            "recorded_at": "2026-04-17T00:00:00Z"
        });

        let result: Result<OnboardingStep, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn onboarding_step_deserialize_rejects_string_duration() {
        let raw = serde_json::json!({
            "step_id": "string-duration",
            "session_id": "sess-string-duration",
            "phase": "Install",
            "duration_seconds": "30",
            "automated": true,
            "gate_result": "Passed",
            "manual_interventions": 0,
            "recorded_at": "2026-04-17T00:00:00Z"
        });

        let result: Result<OnboardingStep, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn onboarding_report_deserialize_rejects_missing_content_hash() {
        let raw = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "total_sessions": 0,
            "completed_sessions": 0,
            "completion_rate": 0.0,
            "mean_ttfe_seconds": 0.0,
            "meets_ttfe_target": false,
            "overall_automation_rate": 0.0,
            "overall_friction_score": 0.0,
            "phase_stats": [],
            "bottleneck_phases": [],
            "generated_at": "2026-04-17T00:00:00Z"
        });

        let result: Result<OnboardingReport, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn audit_record_deserialize_rejects_missing_trace_id() {
        let raw = serde_json::json!({
            "event_code": event_codes::SEO_STEP_COMPLETED,
            "entity_id": "step-without-trace",
            "detail": "missing trace id",
            "timestamp": "2026-04-17T00:00:00Z"
        });

        let result: Result<SeoAuditRecord, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }
}
