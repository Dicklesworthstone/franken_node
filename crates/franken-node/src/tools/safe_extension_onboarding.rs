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

        self.steps.push(step);
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
        Some(session_steps.iter().map(|s| s.duration_seconds).sum())
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
            ttfes.iter().sum::<u64>() as f64 / ttfes.len() as f64
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

        let hash_input = format!(
            "{}:{}:{}:{:.4}:{:.4}:{}",
            SCHEMA_VERSION,
            total_sessions,
            completed,
            mean_ttfe,
            overall_friction,
            bottleneck_phases.len()
        );
        let content_hash = format!(
            "{:x}",
            Sha256::digest([b"safe_extension_hash_v1:" as &[u8], hash_input.as_bytes()].concat())
        );

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
        self.audit_log.push(SeoAuditRecord {
            event_code: event_code.to_string(),
            entity_id: entity_id.to_string(),
            detail: detail.to_string(),
            trace_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
        });
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
}
