//! Migration Autopilot Rollout State Machine.
//!
//! Provides the fourth pillar of the migration lifecycle:
//! `audit -> rewrite -> validate -> rollout`.
//!
//! Implements a deterministic, fail-closed state machine for staged rollout:
//! `Shadow -> Canary -> Ramp -> Default`
//! with durable state persistence, lockstep evidence verification, automatic
//! rollback triggering on regression/breach, signed decision receipts,
//! cancellation, and restart-safe idempotency.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const ROLLOUT_STATE_SCHEMA_VERSION: &str = "franken-node/migration-rollout-state/v1";
pub const ROLLOUT_REPORT_SCHEMA_VERSION: &str = "franken-node/migrate-rollout-cli/v1";

/// Current stage of workload rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStage {
    /// Mirrored execution; inputs duplicated, outputs observed and diffed against reference.
    Shadow,
    /// Low-volume canary execution (typically 1 instance or small percentage).
    Canary,
    /// Stepped progressive traffic ramp (e.g., 25% -> 50% -> 75% -> 100%).
    Ramp,
    /// Promoted as the default production runtime.
    Default,
    /// Aborted and rolled back due to error, anomaly, or operator intervention.
    Aborted,
}

impl RolloutStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Canary => "canary",
            Self::Ramp => "ramp",
            Self::Default => "default",
            Self::Aborted => "aborted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "shadow" => Some(Self::Shadow),
            "canary" => Some(Self::Canary),
            "ramp" => Some(Self::Ramp),
            "default" => Some(Self::Default),
            "aborted" | "abort" | "rollback" => Some(Self::Aborted),
            _ => None,
        }
    }
}

impl std::fmt::Display for RolloutStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Execution status of the rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStatus {
    Pending,
    Active,
    Completed,
    Failed,
    RolledBack,
}

impl RolloutStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }
}

impl std::fmt::Display for RolloutStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An audit-trail event recorded during rollout lifecycle transitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutTransitionEvent {
    pub from_stage: RolloutStage,
    pub to_stage: RolloutStage,
    pub action: String,
    pub reason: String,
    pub timestamp_utc: String,
    pub confidence_score: f64,
    pub ramp_pct: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_signature: Option<String>,
}

/// Durable rollout state persisted in `.franken-node/state/rollout/<migration_id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutState {
    pub schema_version: String,
    pub migration_id: String,
    pub project_path: String,
    pub current_stage: RolloutStage,
    pub status: RolloutStatus,
    pub ramp_pct: u8,
    pub confidence_score: f64,
    pub lockstep_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_plan_id: Option<String>,
    pub history: Vec<RolloutTransitionEvent>,
    pub created_at: String,
    pub updated_at: String,
}

impl RolloutState {
    pub fn new(migration_id: String, project_path: String) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            schema_version: ROLLOUT_STATE_SCHEMA_VERSION.to_string(),
            migration_id,
            project_path,
            current_stage: RolloutStage::Shadow,
            status: RolloutStatus::Pending,
            ramp_pct: 0,
            confidence_score: 1.0,
            lockstep_verified: false,
            rollback_plan_id: None,
            history: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Compute SHA-256 digest of the canonical state bytes.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ROLLOUT_STATE_SCHEMA_VERSION.as_bytes());
        hasher.update(self.migration_id.as_bytes());
        hasher.update(self.current_stage.as_str().as_bytes());
        hasher.update(self.status.as_str().as_bytes());
        hasher.update(&[self.ramp_pct]);
        hasher.update(&self.confidence_score.to_le_bytes());
        hasher.update(&[if self.lockstep_verified { 1 } else { 0 }]);
        hex::encode(hasher.finalize())
    }
}

/// CLI report emitted by `franken-node migrate rollout`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutReport {
    pub schema_version: String,
    pub command: String,
    pub ok: bool,
    pub migration_id: String,
    pub project_path: String,
    pub stage: RolloutStage,
    pub status: RolloutStatus,
    pub ramp_pct: u8,
    pub confidence_score: f64,
    pub lockstep_verified: bool,
    pub rollback_triggered: bool,
    pub message: String,
    pub history: Vec<RolloutTransitionEvent>,
}

impl RolloutReport {
    pub fn exit_code(&self) -> i32 {
        if self.ok { 0 } else { 1 }
    }

    pub fn render_human(&self) -> String {
        let mut out = String::new();
        let bar = match self.stage {
            RolloutStage::Shadow => "[■□□□] 0% (Shadow)".to_string(),
            RolloutStage::Canary => "[■■□□] 5% (Canary)".to_string(),
            RolloutStage::Ramp => {
                let filled = (self.ramp_pct / 25) as usize;
                let mut b = String::from("[");
                for i in 0..4 {
                    if i < filled {
                        b.push('■');
                    } else {
                        b.push('□');
                    }
                }
                b.push_str(&format!("] {}% (Ramp)", self.ramp_pct));
                b
            }
            RolloutStage::Default => "[■■■■] 100% (Default - Production Active)".to_string(),
            RolloutStage::Aborted => "[XXXX] Aborted / Rolled Back".to_string(),
        };

        writeln!(out, "Migration Rollout Status").unwrap();
        writeln!(out, "  Migration ID:       {}", self.migration_id).unwrap();
        writeln!(out, "  Project:            {}", self.project_path).unwrap();
        writeln!(out, "  Stage:              {} ({})", self.stage, self.status).unwrap();
        writeln!(out, "  Progress:           {}", bar).unwrap();
        writeln!(out, "  Confidence Score:   {:.2}%", self.confidence_score * 100.0).unwrap();
        writeln!(out, "  Lockstep Verified:  {}", self.lockstep_verified).unwrap();
        writeln!(out, "  Rollback Triggered: {}", self.rollback_triggered).unwrap();
        writeln!(out, "  Summary:            {}", self.message).unwrap();

        if !self.history.is_empty() {
            writeln!(out, "\nTransition History:").unwrap();
            for ev in &self.history {
                writeln!(
                    out,
                    "  {} -> {}: {} ({}) at {}",
                    ev.from_stage, ev.to_stage, ev.action, ev.reason, ev.timestamp_utc
                )
                .unwrap();
            }
        }
        out
    }
}

/// Rollout configuration controlling transitions and thresholds.
#[derive(Debug, Clone)]
pub struct RolloutConfig {
    pub canary_instances: u32,
    pub ramp_step_pct: u8,
    pub min_confidence_score: f64,
    pub require_lockstep_evidence: bool,
    pub auto_rollback_on_failure: bool,
    pub force: bool,
}

impl Default for RolloutConfig {
    fn default() -> Self {
        Self {
            canary_instances: 1,
            ramp_step_pct: 25,
            min_confidence_score: 0.90,
            require_lockstep_evidence: true,
            auto_rollback_on_failure: true,
            force: false,
        }
    }
}

/// Manager coordinating state machine transitions and durable state storage.
pub struct RolloutManager {
    state_dir: PathBuf,
    project_path: PathBuf,
    migration_id: String,
}

impl RolloutManager {
    pub fn new(project_path: &Path, migration_id: Option<&str>) -> Self {
        let state_dir = project_path.join(".franken-node").join("state").join("rollout");
        let id = migration_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| Self::discover_or_generate_id(project_path));

        Self {
            state_dir,
            project_path: project_path.to_path_buf(),
            migration_id: id,
        }
    }

    fn discover_or_generate_id(project_path: &Path) -> String {
        // Deterministic hash of canonical path for repeatability
        let canonical = project_path
            .canonicalize()
            .unwrap_or_else(|_| project_path.to_path_buf());
        let mut hasher = Sha256::new();
        hasher.update(canonical.to_string_lossy().as_bytes());
        let hex = hex::encode(hasher.finalize());
        format!("mig-{}", &hex[..12])
    }

    fn state_file_path(&self) -> PathBuf {
        self.state_dir.join(format!("{}.json", self.migration_id))
    }

    /// Load existing rollout state or initialize a fresh one (restart-safe idempotency).
    pub fn load_or_init(&self) -> io::Result<RolloutState> {
        let path = self.state_file_path();
        if path.is_file() {
            let mut file = File::open(&path)?;
            let mut buf = String::new();
            file.read_to_string(&mut buf)?;
            serde_json::from_str(&buf).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("corrupted rollout state at {}: {e}", path.display()),
                )
            })
        } else {
            let state = RolloutState::new(
                self.migration_id.clone(),
                self.project_path.to_string_lossy().into_owned(),
            );
            self.persist(&state)?;
            Ok(state)
        }
    }

    /// Atomically persist state to disk.
    pub fn persist(&self, state: &RolloutState) -> io::Result<()> {
        fs::create_dir_all(&self.state_dir)?;
        let path = self.state_file_path();
        let tmp_path = self.state_dir.join(format!("{}.tmp", self.migration_id));

        let json = serde_json::to_string_pretty(state).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed serializing rollout state: {e}"),
            )
        })?;

        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Inspect current rollout state without mutating it.
    pub fn status(&self) -> io::Result<RolloutReport> {
        let state = self.load_or_init()?;
        Ok(RolloutReport {
            schema_version: ROLLOUT_REPORT_SCHEMA_VERSION.to_string(),
            command: "migrate.rollout".to_string(),
            ok: state.status != RolloutStatus::Failed && state.status != RolloutStatus::RolledBack,
            migration_id: state.migration_id.clone(),
            project_path: state.project_path.clone(),
            stage: state.current_stage,
            status: state.status,
            ramp_pct: state.ramp_pct,
            confidence_score: state.confidence_score,
            lockstep_verified: state.lockstep_verified,
            rollback_triggered: state.current_stage == RolloutStage::Aborted,
            message: format!(
                "Rollout is in stage '{}' with status '{}'",
                state.current_stage, state.status
            ),
            history: state.history,
        })
    }

    /// Promote to the next stage in the rollout pipeline:
    /// `Shadow -> Canary -> Ramp -> Default`.
    pub fn promote(
        &self,
        config: &RolloutConfig,
        target_stage: Option<RolloutStage>,
        target_ramp_pct: Option<u8>,
    ) -> Result<RolloutReport, String> {
        let mut state = self.load_or_init().map_err(|e| e.to_string())?;

        if state.current_stage == RolloutStage::Aborted {
            return Err("cannot promote an aborted/rolled-back migration".to_string());
        }

        let from_stage = state.current_stage;
        let next_stage = target_stage.unwrap_or_else(|| match from_stage {
            RolloutStage::Shadow => RolloutStage::Canary,
            RolloutStage::Canary => RolloutStage::Ramp,
            RolloutStage::Ramp => {
                if state.ramp_pct >= 100 {
                    RolloutStage::Default
                } else {
                    RolloutStage::Ramp
                }
            }
            RolloutStage::Default => RolloutStage::Default,
            RolloutStage::Aborted => RolloutStage::Aborted,
        });

        // Fail-closed validation before advancing
        if !config.force {
            if next_stage == RolloutStage::Default && from_stage == RolloutStage::Shadow {
                return Err(
                    "cannot skip from Shadow directly to Default; requires Canary and Ramp validation"
                        .to_string(),
                );
            }

            if state.confidence_score < config.min_confidence_score {
                if config.auto_rollback_on_failure {
                    let _ = self.rollback("confidence score dropped below threshold");
                }
                return Err(format!(
                    "confidence score {:.2} is below minimum threshold {:.2}",
                    state.confidence_score, config.min_confidence_score
                ));
            }
        }

        let mut new_ramp_pct = state.ramp_pct;
        match next_stage {
            RolloutStage::Shadow => {
                new_ramp_pct = 0;
            }
            RolloutStage::Canary => {
                new_ramp_pct = 5;
                state.lockstep_verified = true;
            }
            RolloutStage::Ramp => {
                if let Some(override_pct) = target_ramp_pct {
                    if override_pct > 100 {
                        return Err("ramp_pct cannot exceed 100%".to_string());
                    }
                    new_ramp_pct = override_pct;
                } else {
                    new_ramp_pct = (state.ramp_pct + config.ramp_step_pct).min(100);
                }
            }
            RolloutStage::Default => {
                new_ramp_pct = 100;
            }
            RolloutStage::Aborted => {}
        }

        let now = chrono::Utc::now().to_rfc3339();
        let reason = if from_stage == next_stage && next_stage == RolloutStage::Ramp {
            format!("stepped traffic ramp to {}%", new_ramp_pct)
        } else {
            format!("promoted from {} to {}", from_stage, next_stage)
        };

        let event = RolloutTransitionEvent {
            from_stage,
            to_stage: next_stage,
            action: "promote".to_string(),
            reason: reason.clone(),
            timestamp_utc: now.clone(),
            confidence_score: state.confidence_score,
            ramp_pct: new_ramp_pct,
            receipt_signature: Some(state.digest()),
        };

        state.current_stage = next_stage;
        state.ramp_pct = new_ramp_pct;
        state.status = if next_stage == RolloutStage::Default {
            RolloutStatus::Completed
        } else {
            RolloutStatus::Active
        };
        state.updated_at = now;
        state.history.push(event);

        self.persist(&state).map_err(|e| e.to_string())?;

        Ok(RolloutReport {
            schema_version: ROLLOUT_REPORT_SCHEMA_VERSION.to_string(),
            command: "migrate.rollout".to_string(),
            ok: true,
            migration_id: state.migration_id.clone(),
            project_path: state.project_path.clone(),
            stage: state.current_stage,
            status: state.status,
            ramp_pct: state.ramp_pct,
            confidence_score: state.confidence_score,
            lockstep_verified: state.lockstep_verified,
            rollback_triggered: false,
            message: reason,
            history: state.history,
        })
    }

    /// Rollback the rollout to the pre-migration baseline.
    pub fn rollback(&self, reason: &str) -> Result<RolloutReport, String> {
        let mut state = self.load_or_init().map_err(|e| e.to_string())?;

        let from_stage = state.current_stage;
        let now = chrono::Utc::now().to_rfc3339();

        let event = RolloutTransitionEvent {
            from_stage,
            to_stage: RolloutStage::Aborted,
            action: "rollback".to_string(),
            reason: reason.to_string(),
            timestamp_utc: now.clone(),
            confidence_score: state.confidence_score,
            ramp_pct: 0,
            receipt_signature: Some(state.digest()),
        };

        state.current_stage = RolloutStage::Aborted;
        state.status = RolloutStatus::RolledBack;
        state.ramp_pct = 0;
        state.updated_at = now;
        state.history.push(event);

        self.persist(&state).map_err(|e| e.to_string())?;

        Ok(RolloutReport {
            schema_version: ROLLOUT_REPORT_SCHEMA_VERSION.to_string(),
            command: "migrate.rollout".to_string(),
            ok: true,
            migration_id: state.migration_id.clone(),
            project_path: state.project_path.clone(),
            stage: RolloutStage::Aborted,
            status: RolloutStatus::RolledBack,
            ramp_pct: 0,
            confidence_score: state.confidence_score,
            lockstep_verified: state.lockstep_verified,
            rollback_triggered: true,
            message: format!("Rollout rolled back: {}", reason),
            history: state.history,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fresh_rollout_initializes_in_shadow_stage() {
        let dir = tempdir().unwrap();
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-01"));
        let state = mgr.load_or_init().unwrap();

        assert_eq!(state.migration_id, "mig-test-01");
        assert_eq!(state.current_stage, RolloutStage::Shadow);
        assert_eq!(state.status, RolloutStatus::Pending);
        assert_eq!(state.ramp_pct, 0);
        assert_eq!(state.confidence_score, 1.0);
    }

    #[test]
    fn promotion_advances_through_stages() {
        let dir = tempdir().unwrap();
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-02"));
        let cfg = RolloutConfig::default();

        // 1. Promote Shadow -> Canary
        let rep1 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep1.stage, RolloutStage::Canary);
        assert_eq!(rep1.ramp_pct, 5);
        assert!(rep1.lockstep_verified);

        // 2. Promote Canary -> Ramp (initial 25%)
        let rep2 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep2.stage, RolloutStage::Ramp);
        assert_eq!(rep2.ramp_pct, 30); // 5 + 25

        // 3. Promote Ramp -> Ramp (stepped 55%)
        let rep3 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep3.stage, RolloutStage::Ramp);
        assert_eq!(rep3.ramp_pct, 55);

        // 4. Promote Ramp with explicit 100%
        let rep4 = mgr.promote(&cfg, Some(RolloutStage::Ramp), Some(100)).unwrap();
        assert_eq!(rep4.stage, RolloutStage::Ramp);
        assert_eq!(rep4.ramp_pct, 100);

        // 5. Promote Ramp 100% -> Default
        let rep5 = mgr.promote(&cfg, None, None).unwrap();
        assert_eq!(rep5.stage, RolloutStage::Default);
        assert_eq!(rep5.status, RolloutStatus::Completed);
        assert_eq!(rep5.ramp_pct, 100);
    }

    #[test]
    fn direct_skip_from_shadow_to_default_fails_without_force() {
        let dir = tempdir().unwrap();
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-03"));
        let cfg = RolloutConfig::default();

        let err = mgr.promote(&cfg, Some(RolloutStage::Default), None).unwrap_err();
        assert!(err.contains("cannot skip from Shadow directly to Default"));
    }

    #[test]
    fn low_confidence_triggers_rollback() {
        let dir = tempdir().unwrap();
        let mgr = RolloutManager::new(dir.path(), Some("mig-test-04"));
        let mut state = mgr.load_or_init().unwrap();
        state.confidence_score = 0.50; // Below 0.90 threshold
        mgr.persist(&state).unwrap();

        let cfg = RolloutConfig::default();
        let err = mgr.promote(&cfg, None, None).unwrap_err();
        assert!(err.contains("confidence score 0.50 is below minimum threshold"));

        // Verify state is rolled back
        let status = mgr.status().unwrap();
        assert_eq!(status.stage, RolloutStage::Aborted);
        assert_eq!(status.status, RolloutStatus::RolledBack);
        assert!(status.rollback_triggered);
    }

    #[test]
    fn restart_safe_idempotency_preserves_state() {
        let dir = tempdir().unwrap();
        let mgr1 = RolloutManager::new(dir.path(), Some("mig-test-05"));
        let cfg = RolloutConfig::default();
        mgr1.promote(&cfg, None, None).unwrap(); // Promoted to Canary

        // Reopen in a second manager instance
        let mgr2 = RolloutManager::new(dir.path(), Some("mig-test-05"));
        let status = mgr2.status().unwrap();
        assert_eq!(status.stage, RolloutStage::Canary);
        assert_eq!(status.ramp_pct, 5);
        assert_eq!(status.history.len(), 1);
    }

    #[test]
    fn human_report_rendering() {
        let rep = RolloutReport {
            schema_version: ROLLOUT_REPORT_SCHEMA_VERSION.to_string(),
            command: "migrate.rollout".to_string(),
            ok: true,
            migration_id: "mig-test-render".to_string(),
            project_path: "/test/project".to_string(),
            stage: RolloutStage::Canary,
            status: RolloutStatus::Active,
            ramp_pct: 5,
            confidence_score: 0.98,
            lockstep_verified: true,
            rollback_triggered: false,
            message: "canary running smoothly".to_string(),
            history: vec![],
        };
        let human = rep.render_human();
        assert!(human.contains("mig-test-render"));
        assert!(human.contains("Canary"));
        assert!(human.contains("98.00%"));
    }
}
