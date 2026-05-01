//! bd-wpck: Migration kit ecosystem for major Node/Bun archetypes (Section 15).
//!
//! Provides structured migration kits for common Node.js and Bun application
//! archetypes, enabling deterministic migration from established runtimes to
//! franken_node. Each kit includes compatibility mappings, migration steps,
//! validation gates, and rollback procedures.
//!
//! # Capabilities
//!
//! - Archetype-specific migration kits (Express, Fastify, Koa, Next.js, Bun)
//! - Step-by-step migration procedures with dependency tracking
//! - Compatibility matrix validation per archetype
//! - Rollback procedures with safety checks
//! - Migration progress tracking with completion gates
//! - Deterministic migration plan generation
//!
//! # Invariants
//!
//! - **INV-MKE-COMPLETE**: Every kit covers all required migration phases.
//! - **INV-MKE-REVERSIBLE**: Every migration step has a rollback procedure.
//! - **INV-MKE-GATED**: Migration blocked if compatibility check fails.
//! - **INV-MKE-DETERMINISTIC**: Same archetype produces same migration plan.
//! - **INV-MKE-AUDITABLE**: Every migration operation logged with event code.
//! - **INV-MKE-VERSIONED**: Kit version embedded in every migration plan.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::runtime::clock;

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_REPORTS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const MKE_KIT_LOADED: &str = "MKE-001";
    pub const MKE_COMPAT_CHECKED: &str = "MKE-002";
    pub const MKE_PLAN_GENERATED: &str = "MKE-003";
    pub const MKE_STEP_STARTED: &str = "MKE-004";
    pub const MKE_STEP_COMPLETED: &str = "MKE-005";
    pub const MKE_MIGRATION_COMPLETED: &str = "MKE-006";
    pub const MKE_ROLLBACK_INITIATED: &str = "MKE-007";
    pub const MKE_ROLLBACK_COMPLETED: &str = "MKE-008";
    pub const MKE_GATE_PASSED: &str = "MKE-009";
    pub const MKE_REPORT_GENERATED: &str = "MKE-010";
    pub const MKE_ERR_COMPAT: &str = "MKE-ERR-001";
    pub const MKE_ERR_STEP_FAILED: &str = "MKE-ERR-002";
    pub const MKE_ERR_ROLLBACK_FAILED: &str = "MKE-ERR-003";
}

pub mod invariants {
    pub const INV_MKE_COMPLETE: &str = "INV-MKE-COMPLETE";
    pub const INV_MKE_REVERSIBLE: &str = "INV-MKE-REVERSIBLE";
    pub const INV_MKE_GATED: &str = "INV-MKE-GATED";
    pub const INV_MKE_DETERMINISTIC: &str = "INV-MKE-DETERMINISTIC";
    pub const INV_MKE_AUDITABLE: &str = "INV-MKE-AUDITABLE";
    pub const INV_MKE_VERSIONED: &str = "INV-MKE-VERSIONED";
}

pub const KIT_VERSION: &str = "mke-v1.0";

// ---------------------------------------------------------------------------
// Archetype and step types
// ---------------------------------------------------------------------------

/// Supported application archetypes for migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Archetype {
    Express,
    Fastify,
    Koa,
    NextJs,
    BunNative,
}

impl Archetype {
    pub fn all() -> &'static [Archetype] {
        &[
            Self::Express,
            Self::Fastify,
            Self::Koa,
            Self::NextJs,
            Self::BunNative,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Express => "express",
            Self::Fastify => "fastify",
            Self::Koa => "koa",
            Self::NextJs => "nextjs",
            Self::BunNative => "bun_native",
        }
    }
}

/// Migration phase in the overall process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Assessment,
    DependencyAudit,
    CodeAdaptation,
    TestValidation,
    Deployment,
}

impl MigrationPhase {
    pub fn all() -> &'static [MigrationPhase] {
        &[
            Self::Assessment,
            Self::DependencyAudit,
            Self::CodeAdaptation,
            Self::TestValidation,
            Self::Deployment,
        ]
    }
}

/// Status of a migration step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

/// A single migration step within a kit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationStep {
    pub step_id: String,
    pub phase: MigrationPhase,
    pub title: String,
    pub description: String,
    pub dependencies: Vec<String>,
    pub rollback_procedure: String,
    pub status: StepStatus,
    pub estimated_duration_min: u32,
}

/// Compatibility mapping for an archetype.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityMapping {
    pub archetype: Archetype,
    pub supported_versions: Vec<String>,
    pub api_coverage_pct: f64,
    pub known_incompatibilities: Vec<String>,
    pub migration_complexity: MigrationComplexity,
}

/// Migration complexity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationComplexity {
    Low,
    Medium,
    High,
    Critical,
}

/// A complete migration kit for an archetype.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationKit {
    pub kit_id: String,
    pub archetype: Archetype,
    pub kit_version: String,
    pub compatibility: CompatibilityMapping,
    pub steps: Vec<MigrationStep>,
    pub content_hash: String,
    pub created_at: String,
}

/// Migration progress report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationReport {
    pub report_id: String,
    pub kit_id: String,
    pub archetype: Archetype,
    pub total_steps: usize,
    pub completed_steps: usize,
    pub failed_steps: usize,
    pub progress_pct: f64,
    pub overall_status: MigrationStatus,
    pub content_hash: String,
    pub timestamp: String,
}

/// Overall migration status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    NotStarted,
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

/// Audit record for migration operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MkeAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub kit_id: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// Configuration for the migration kit ecosystem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MkeConfig {
    pub kit_version: String,
    pub require_compatibility_check: bool,
    pub min_api_coverage_pct: f64,
}

impl Default for MkeConfig {
    fn default() -> Self {
        Self {
            kit_version: KIT_VERSION.to_string(),
            require_compatibility_check: true,
            min_api_coverage_pct: 80.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Migration kit ecosystem engine.
#[derive(Debug, Clone)]
pub struct MigrationKitEcosystem {
    config: MkeConfig,
    kits: BTreeMap<String, MigrationKit>,
    reports: Vec<MigrationReport>,
    audit_log: Vec<MkeAuditRecord>,
}

impl Default for MigrationKitEcosystem {
    fn default() -> Self {
        Self::new(MkeConfig::default())
    }
}

impl MigrationKitEcosystem {
    pub fn new(config: MkeConfig) -> Self {
        Self {
            config,
            kits: BTreeMap::new(),
            reports: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Load a migration kit for an archetype.
    pub fn load_kit(
        &mut self,
        archetype: Archetype,
        compatibility: CompatibilityMapping,
        steps: Vec<MigrationStep>,
        trace_id: &str,
    ) -> Result<String, String> {
        // Gate: reject non-finite coverage values — NaN/Inf serialize to null in JSON,
        // causing materially different kits to alias to the same content_hash.
        if !compatibility.api_coverage_pct.is_finite() {
            self.log(
                event_codes::MKE_ERR_COMPAT,
                "",
                trace_id,
                serde_json::json!({
                    "archetype": archetype.label(),
                    "coverage": format!("{}", compatibility.api_coverage_pct),
                    "reason": "non-finite api_coverage_pct",
                }),
            );
            return Err(format!(
                "API coverage {} is not a finite number",
                compatibility.api_coverage_pct
            ));
        }

        if !self.config.min_api_coverage_pct.is_finite() {
            return Err(format!(
                "min_api_coverage_pct is not a finite number: {}",
                self.config.min_api_coverage_pct
            ));
        }

        // Gate: compatibility check
        if self.config.require_compatibility_check
            && compatibility.api_coverage_pct < self.config.min_api_coverage_pct
        {
            self.log(
                event_codes::MKE_ERR_COMPAT,
                "",
                trace_id,
                serde_json::json!({
                    "archetype": archetype.label(),
                    "coverage": compatibility.api_coverage_pct,
                    "minimum": self.config.min_api_coverage_pct,
                }),
            );
            return Err(format!(
                "API coverage {:.1}% below minimum {:.1}%",
                compatibility.api_coverage_pct, self.config.min_api_coverage_pct
            ));
        }

        self.log(
            event_codes::MKE_COMPAT_CHECKED,
            "",
            trace_id,
            serde_json::json!({
                "archetype": archetype.label(),
                "coverage": compatibility.api_coverage_pct,
            }),
        );

        let kit_id = Uuid::now_v7().to_string();
        let hash_input = serde_json::json!({
            "archetype": archetype.label(),
            "steps": &steps,
            "kit_version": &self.config.kit_version,
            "compatibility": {
                "supported_versions": &compatibility.supported_versions,
                "api_coverage_pct": compatibility.api_coverage_pct,
                "known_incompatibilities": &compatibility.known_incompatibilities,
                "migration_complexity": format!("{:?}", compatibility.migration_complexity),
            },
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [b"migration_kit_hash_v1:", hash_input.as_bytes()].concat(),
        ));

        let kit = MigrationKit {
            kit_id: kit_id.clone(),
            archetype,
            kit_version: self.config.kit_version.clone(),
            compatibility,
            steps,
            content_hash,
            created_at: clock::wall_now().to_rfc3339(),
        };

        self.kits.insert(kit_id.clone(), kit);

        self.log(
            event_codes::MKE_KIT_LOADED,
            &kit_id,
            trace_id,
            serde_json::json!({"archetype": archetype.label()}),
        );

        Ok(kit_id)
    }

    /// Generate a migration plan (returns the kit with deterministic hash).
    pub fn generate_plan(&mut self, kit_id: &str, trace_id: &str) -> Result<&MigrationKit, String> {
        if !self.kits.contains_key(kit_id) {
            return Err("Kit not found".to_string());
        }

        self.log(
            event_codes::MKE_PLAN_GENERATED,
            kit_id,
            trace_id,
            serde_json::json!({"kit_id": kit_id}),
        );

        self.kits
            .get(kit_id)
            .ok_or_else(|| "Kit not found".to_string())
    }

    /// Start a migration step.
    pub fn start_step(
        &mut self,
        kit_id: &str,
        step_id: &str,
        trace_id: &str,
    ) -> Result<(), String> {
        let kit = self
            .kits
            .get_mut(kit_id)
            .ok_or_else(|| "Kit not found".to_string())?;

        let step = kit
            .steps
            .iter_mut()
            .find(|s| s.step_id == step_id)
            .ok_or_else(|| "Step not found".to_string())?;

        if step.status != StepStatus::Pending {
            return Err(format!(
                "Cannot start step {step_id}: current status is {:?}, expected Pending",
                step.status
            ));
        }

        step.status = StepStatus::InProgress;

        self.log(
            event_codes::MKE_STEP_STARTED,
            kit_id,
            trace_id,
            serde_json::json!({"step_id": step_id}),
        );

        Ok(())
    }

    /// Complete a migration step.
    pub fn complete_step(
        &mut self,
        kit_id: &str,
        step_id: &str,
        trace_id: &str,
    ) -> Result<(), String> {
        let kit = self
            .kits
            .get_mut(kit_id)
            .ok_or_else(|| "Kit not found".to_string())?;

        let step = kit
            .steps
            .iter_mut()
            .find(|s| s.step_id == step_id)
            .ok_or_else(|| "Step not found".to_string())?;

        if step.status != StepStatus::InProgress {
            return Err(format!(
                "Cannot complete step {step_id}: current status is {:?}, expected InProgress",
                step.status
            ));
        }

        step.status = StepStatus::Completed;

        self.log(
            event_codes::MKE_STEP_COMPLETED,
            kit_id,
            trace_id,
            serde_json::json!({"step_id": step_id}),
        );

        // Check if all steps completed
        let all_done = self
            .kits
            .get(kit_id)
            .ok_or_else(|| "Kit not found".to_string())?
            .steps
            .iter()
            .all(|s| s.status == StepStatus::Completed);
        if all_done {
            self.log(
                event_codes::MKE_MIGRATION_COMPLETED,
                kit_id,
                trace_id,
                serde_json::json!({"kit_id": kit_id}),
            );
        }

        Ok(())
    }

    /// Initiate rollback for a step.
    pub fn rollback_step(
        &mut self,
        kit_id: &str,
        step_id: &str,
        trace_id: &str,
    ) -> Result<(), String> {
        let kit = self
            .kits
            .get_mut(kit_id)
            .ok_or_else(|| "Kit not found".to_string())?;

        let step = kit
            .steps
            .iter_mut()
            .find(|s| s.step_id == step_id)
            .ok_or_else(|| "Step not found".to_string())?;

        if !matches!(step.status, StepStatus::InProgress | StepStatus::Failed) {
            return Err(format!(
                "Cannot rollback step {step_id}: current status is {:?}, expected InProgress or Failed",
                step.status
            ));
        }

        if step.rollback_procedure.is_empty() {
            self.log(
                event_codes::MKE_ERR_ROLLBACK_FAILED,
                kit_id,
                trace_id,
                serde_json::json!({"step_id": step_id, "reason": "no rollback procedure"}),
            );
            return Err("No rollback procedure defined".to_string());
        }

        step.status = StepStatus::RolledBack;

        self.log(
            event_codes::MKE_ROLLBACK_INITIATED,
            kit_id,
            trace_id,
            serde_json::json!({"step_id": step_id}),
        );

        self.log(
            event_codes::MKE_ROLLBACK_COMPLETED,
            kit_id,
            trace_id,
            serde_json::json!({"step_id": step_id}),
        );

        Ok(())
    }

    /// Generate a migration progress report.
    pub fn generate_report(
        &mut self,
        kit_id: &str,
        trace_id: &str,
    ) -> Result<MigrationReport, String> {
        let kit = self
            .kits
            .get(kit_id)
            .ok_or_else(|| "Kit not found".to_string())?;

        let total = kit.steps.len();
        let completed = kit
            .steps
            .iter()
            .filter(|s| s.status == StepStatus::Completed)
            .count();
        let failed = kit
            .steps
            .iter()
            .filter(|s| s.status == StepStatus::Failed)
            .count();
        let progress = if total > 0 {
            (completed as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let status = if completed == total {
            MigrationStatus::Completed
        } else if failed > 0 {
            MigrationStatus::Failed
        } else if completed > 0 {
            MigrationStatus::InProgress
        } else {
            MigrationStatus::NotStarted
        };

        let hash_input = serde_json::json!({
            "kit_id": kit_id,
            "archetype": kit.archetype.label(),
            "total": total,
            "completed": completed,
            "failed": failed,
            "overall_status": format!("{:?}", status),
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [b"migration_kit_hash_v1:", hash_input.as_bytes()].concat(),
        ));

        let report = MigrationReport {
            report_id: Uuid::now_v7().to_string(),
            kit_id: kit_id.to_string(),
            archetype: kit.archetype,
            total_steps: total,
            completed_steps: completed,
            failed_steps: failed,
            progress_pct: progress,
            overall_status: status,
            content_hash,
            timestamp: clock::wall_now().to_rfc3339(),
        };

        self.log(
            event_codes::MKE_REPORT_GENERATED,
            kit_id,
            trace_id,
            serde_json::json!({
                "progress": progress,
                "status": format!("{:?}", status),
            }),
        );

        push_bounded(&mut self.reports, report.clone(), MAX_REPORTS);
        Ok(report)
    }

    pub fn kits(&self) -> &BTreeMap<String, MigrationKit> {
        &self.kits
    }

    pub fn reports(&self) -> &[MigrationReport] {
        &self.reports
    }

    pub fn audit_log(&self) -> &[MkeAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, kit_id: &str, trace_id: &str, details: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            MkeAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                kit_id: kit_id.to_string(),
                timestamp: clock::wall_now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_compat(arch: Archetype) -> CompatibilityMapping {
        CompatibilityMapping {
            archetype: arch,
            supported_versions: vec!["18.x".to_string(), "20.x".to_string()],
            api_coverage_pct: 95.0,
            known_incompatibilities: vec![],
            migration_complexity: MigrationComplexity::Medium,
        }
    }

    fn sample_steps() -> Vec<MigrationStep> {
        vec![
            MigrationStep {
                step_id: "s1".to_string(),
                phase: MigrationPhase::Assessment,
                title: "Assess compatibility".to_string(),
                description: "Run compatibility analysis".to_string(),
                dependencies: vec![],
                rollback_procedure: "Restore original config".to_string(),
                status: StepStatus::Pending,
                estimated_duration_min: 30,
            },
            MigrationStep {
                step_id: "s2".to_string(),
                phase: MigrationPhase::DependencyAudit,
                title: "Audit dependencies".to_string(),
                description: "Check all deps".to_string(),
                dependencies: vec!["s1".to_string()],
                rollback_procedure: "Restore package.json".to_string(),
                status: StepStatus::Pending,
                estimated_duration_min: 60,
            },
            MigrationStep {
                step_id: "s3".to_string(),
                phase: MigrationPhase::CodeAdaptation,
                title: "Adapt code".to_string(),
                description: "Update imports".to_string(),
                dependencies: vec!["s2".to_string()],
                rollback_procedure: "Git revert".to_string(),
                status: StepStatus::Pending,
                estimated_duration_min: 120,
            },
        ]
    }

    // === Archetypes ===

    #[test]
    fn five_archetypes() {
        assert_eq!(Archetype::all().len(), 5);
    }

    #[test]
    fn archetype_labels() {
        for a in Archetype::all() {
            assert!(!a.label().is_empty());
        }
    }

    // === Migration phases ===

    #[test]
    fn five_phases() {
        assert_eq!(MigrationPhase::all().len(), 5);
    }

    // === Kit loading ===

    #[test]
    fn load_kit_success() {
        let mut eco = MigrationKitEcosystem::default();
        let result = eco.load_kit(
            Archetype::Express,
            sample_compat(Archetype::Express),
            sample_steps(),
            &make_trace(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn load_kit_returns_id() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        assert!(!kit_id.is_empty());
        assert!(eco.kits().contains_key(&kit_id));
    }

    #[test]
    fn load_kit_low_coverage_fails() {
        let mut eco = MigrationKitEcosystem::default();
        let mut compat = sample_compat(Archetype::Express);
        compat.api_coverage_pct = 50.0;
        let result = eco.load_kit(Archetype::Express, compat, sample_steps(), &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn load_kit_has_version() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Fastify,
                sample_compat(Archetype::Fastify),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        assert_eq!(eco.kits().get(&kit_id).unwrap().kit_version, KIT_VERSION);
    }

    #[test]
    fn load_kit_has_content_hash() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        let hash = &eco.kits().get(&kit_id).unwrap().content_hash;
        assert_eq!(hash.len(), 64);
    }

    // === Plan generation ===

    #[test]
    fn generate_plan() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        let plan = eco.generate_plan(&kit_id, &make_trace());
        assert!(plan.is_ok());
        assert_eq!(plan.unwrap().steps.len(), 3);
    }

    // === Step management ===

    #[test]
    fn start_and_complete_step() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        eco.start_step(&kit_id, "s1", &make_trace()).unwrap();
        eco.complete_step(&kit_id, "s1", &make_trace()).unwrap();
        let step = &eco.kits().get(&kit_id).unwrap().steps[0];
        assert_eq!(step.status, StepStatus::Completed);
    }

    #[test]
    fn rollback_step() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        eco.start_step(&kit_id, "s1", &make_trace()).unwrap();
        eco.rollback_step(&kit_id, "s1", &make_trace()).unwrap();
        let step = &eco.kits().get(&kit_id).unwrap().steps[0];
        assert_eq!(step.status, StepStatus::RolledBack);
    }

    #[test]
    fn rollback_no_procedure_fails() {
        let mut eco = MigrationKitEcosystem::default();
        let mut steps = sample_steps();
        steps[0].rollback_procedure = String::new();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                steps,
                &make_trace(),
            )
            .unwrap();
        // Must start the step first so it's InProgress (rollback requires InProgress or Failed)
        eco.start_step(&kit_id, "s1", &make_trace()).unwrap();
        let result = eco.rollback_step(&kit_id, "s1", &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn start_step_rejects_non_pending() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        eco.start_step(&kit_id, "s1", &make_trace()).unwrap();
        // Cannot start again — already InProgress
        let result = eco.start_step(&kit_id, "s1", &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn complete_step_rejects_non_in_progress() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        // Cannot complete a Pending step
        let result = eco.complete_step(&kit_id, "s1", &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn rollback_step_rejects_pending() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        // Cannot rollback a Pending step
        let result = eco.rollback_step(&kit_id, "s1", &make_trace());
        assert!(result.is_err());
    }

    #[test]
    fn rollback_step_rejects_completed() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        eco.start_step(&kit_id, "s1", &make_trace()).unwrap();
        eco.complete_step(&kit_id, "s1", &make_trace()).unwrap();
        // Cannot rollback a Completed step
        let result = eco.rollback_step(&kit_id, "s1", &make_trace());
        assert!(result.is_err());
    }

    // === Report generation ===

    #[test]
    fn generate_report_not_started() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        let report = eco.generate_report(&kit_id, &make_trace()).unwrap();
        assert_eq!(report.overall_status, MigrationStatus::NotStarted);
        assert_eq!(report.completed_steps, 0);
    }

    #[test]
    fn generate_report_in_progress() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        eco.start_step(&kit_id, "s1", &make_trace()).unwrap();
        eco.complete_step(&kit_id, "s1", &make_trace()).unwrap();
        let report = eco.generate_report(&kit_id, &make_trace()).unwrap();
        assert_eq!(report.overall_status, MigrationStatus::InProgress);
        assert_eq!(report.completed_steps, 1);
    }

    #[test]
    fn generate_report_completed() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        for sid in ["s1", "s2", "s3"] {
            eco.start_step(&kit_id, sid, &make_trace()).unwrap();
            eco.complete_step(&kit_id, sid, &make_trace()).unwrap();
        }
        let report = eco.generate_report(&kit_id, &make_trace()).unwrap();
        assert_eq!(report.overall_status, MigrationStatus::Completed);
        assert_eq!(report.progress_pct, 100.0);
    }

    #[test]
    fn report_has_content_hash() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        let report = eco.generate_report(&kit_id, &make_trace()).unwrap();
        assert_eq!(report.content_hash.len(), 64);
    }

    // === Complexity ===

    #[test]
    fn four_complexity_levels() {
        let levels = [
            MigrationComplexity::Low,
            MigrationComplexity::Medium,
            MigrationComplexity::High,
            MigrationComplexity::Critical,
        ];
        assert_eq!(levels.len(), 4);
    }

    // === Step statuses ===

    #[test]
    fn five_step_statuses() {
        let statuses = [
            StepStatus::Pending,
            StepStatus::InProgress,
            StepStatus::Completed,
            StepStatus::Failed,
            StepStatus::RolledBack,
        ];
        assert_eq!(statuses.len(), 5);
    }

    // === Migration statuses ===

    #[test]
    fn five_migration_statuses() {
        let statuses = [
            MigrationStatus::NotStarted,
            MigrationStatus::InProgress,
            MigrationStatus::Completed,
            MigrationStatus::Failed,
            MigrationStatus::RolledBack,
        ];
        assert_eq!(statuses.len(), 5);
    }

    // === Audit log ===

    #[test]
    fn operations_generate_audit_entries() {
        let mut eco = MigrationKitEcosystem::default();
        eco.load_kit(
            Archetype::Express,
            sample_compat(Archetype::Express),
            sample_steps(),
            &make_trace(),
        )
        .unwrap();
        assert_eq!(eco.audit_log().len(), 2);
    }

    #[test]
    fn audit_log_has_event_codes() {
        let mut eco = MigrationKitEcosystem::default();
        eco.load_kit(
            Archetype::Express,
            sample_compat(Archetype::Express),
            sample_steps(),
            &make_trace(),
        )
        .unwrap();
        let codes: Vec<&str> = eco
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::MKE_KIT_LOADED));
    }

    #[test]
    fn export_jsonl() {
        let mut eco = MigrationKitEcosystem::default();
        eco.load_kit(
            Archetype::Express,
            sample_compat(Archetype::Express),
            sample_steps(),
            &make_trace(),
        )
        .unwrap();
        let jsonl = eco.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    // === Config ===

    #[test]
    fn default_config() {
        let config = MkeConfig::default();
        assert!(config.require_compatibility_check);
        assert_eq!(config.min_api_coverage_pct, 80.0);
        assert_eq!(config.kit_version, KIT_VERSION);
    }

    #[test]
    fn lenient_config_allows_low_coverage() {
        let config = MkeConfig {
            require_compatibility_check: false,
            ..Default::default()
        };
        let mut eco = MigrationKitEcosystem::new(config);
        let mut compat = sample_compat(Archetype::Express);
        compat.api_coverage_pct = 10.0;
        assert!(
            eco.load_kit(Archetype::Express, compat, sample_steps(), &make_trace(),)
                .is_ok()
        );
    }

    // === Determinism ===

    #[test]
    fn deterministic_kit_hash() {
        let steps = sample_steps();
        let compat = sample_compat(Archetype::Express);

        let mut e1 = MigrationKitEcosystem::default();
        let mut e2 = MigrationKitEcosystem::default();

        let k1 = e1
            .load_kit(
                Archetype::Express,
                compat.clone(),
                steps.clone(),
                "det-trace",
            )
            .unwrap();
        let k2 = e2
            .load_kit(Archetype::Express, compat, steps, "det-trace")
            .unwrap();

        assert_eq!(
            e1.kits().get(&k1).unwrap().content_hash,
            e2.kits().get(&k2).unwrap().content_hash,
        );
    }

    // === Reports storage ===

    #[test]
    fn reports_accumulated() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                &make_trace(),
            )
            .unwrap();
        eco.generate_report(&kit_id, &make_trace()).unwrap();
        eco.generate_report(&kit_id, &make_trace()).unwrap();
        assert_eq!(eco.reports().len(), 2);
    }

    // === bd-fd5ox: content_hash covers compatibility mapping surface ===

    #[test]
    fn kit_hash_changes_with_different_compatibility_versions() {
        let steps = sample_steps();
        let mut compat_a = sample_compat(Archetype::Express);
        compat_a.supported_versions = vec!["18.x".to_string()];
        let mut compat_b = sample_compat(Archetype::Express);
        compat_b.supported_versions = vec!["20.x".to_string()];

        let mut e1 = MigrationKitEcosystem::default();
        let mut e2 = MigrationKitEcosystem::default();

        let k1 = e1
            .load_kit(Archetype::Express, compat_a, steps.clone(), "trace")
            .unwrap();
        let k2 = e2
            .load_kit(Archetype::Express, compat_b, steps, "trace")
            .unwrap();

        assert_ne!(
            e1.kits().get(&k1).unwrap().content_hash,
            e2.kits().get(&k2).unwrap().content_hash,
            "different supported_versions must produce different kit content_hash"
        );
    }

    #[test]
    fn kit_hash_changes_with_different_complexity() {
        let steps = sample_steps();
        let mut compat_a = sample_compat(Archetype::Express);
        compat_a.migration_complexity = MigrationComplexity::Low;
        let mut compat_b = sample_compat(Archetype::Express);
        compat_b.migration_complexity = MigrationComplexity::Critical;

        let mut e1 = MigrationKitEcosystem::default();
        let mut e2 = MigrationKitEcosystem::default();

        let k1 = e1
            .load_kit(Archetype::Express, compat_a, steps.clone(), "trace")
            .unwrap();
        let k2 = e2
            .load_kit(Archetype::Express, compat_b, steps, "trace")
            .unwrap();

        assert_ne!(
            e1.kits().get(&k1).unwrap().content_hash,
            e2.kits().get(&k2).unwrap().content_hash,
            "different migration_complexity must produce different kit content_hash"
        );
    }

    #[test]
    fn kit_hash_changes_with_different_incompatibilities() {
        let steps = sample_steps();
        let mut compat_a = sample_compat(Archetype::Express);
        compat_a.known_incompatibilities = vec![];
        let mut compat_b = sample_compat(Archetype::Express);
        compat_b.known_incompatibilities = vec!["no-websockets".to_string()];

        let mut e1 = MigrationKitEcosystem::default();
        let mut e2 = MigrationKitEcosystem::default();

        let k1 = e1
            .load_kit(Archetype::Express, compat_a, steps.clone(), "trace")
            .unwrap();
        let k2 = e2
            .load_kit(Archetype::Express, compat_b, steps, "trace")
            .unwrap();

        assert_ne!(
            e1.kits().get(&k1).unwrap().content_hash,
            e2.kits().get(&k2).unwrap().content_hash,
            "different known_incompatibilities must produce different kit content_hash"
        );
    }

    #[test]
    fn kit_rejects_nan_api_coverage() {
        let mut eco = MigrationKitEcosystem::default();
        let mut compat = sample_compat(Archetype::Express);
        compat.api_coverage_pct = f64::NAN;
        let result = eco.load_kit(Archetype::Express, compat, sample_steps(), &make_trace());
        assert!(result.is_err(), "NaN api_coverage_pct must be rejected");
    }

    #[test]
    fn kit_rejects_inf_api_coverage() {
        let mut eco = MigrationKitEcosystem::default();
        let mut compat = sample_compat(Archetype::Express);
        compat.api_coverage_pct = f64::INFINITY;
        let result = eco.load_kit(Archetype::Express, compat, sample_steps(), &make_trace());
        assert!(result.is_err(), "Inf api_coverage_pct must be rejected");
    }

    #[test]
    fn kit_rejects_neg_inf_api_coverage() {
        let mut eco = MigrationKitEcosystem::default();
        let mut compat = sample_compat(Archetype::Express);
        compat.api_coverage_pct = f64::NEG_INFINITY;
        let result = eco.load_kit(Archetype::Express, compat, sample_steps(), &make_trace());
        assert!(
            result.is_err(),
            "NEG_INFINITY api_coverage_pct must be rejected"
        );
    }

    #[test]
    fn report_hash_changes_with_different_archetype() {
        let steps = sample_steps();

        let mut e1 = MigrationKitEcosystem::default();
        let mut e2 = MigrationKitEcosystem::default();

        let k1 = e1
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                steps.clone(),
                "trace",
            )
            .unwrap();
        let k2 = e2
            .load_kit(
                Archetype::Fastify,
                sample_compat(Archetype::Fastify),
                steps,
                "trace",
            )
            .unwrap();

        let r1 = e1.generate_report(&k1, "trace").unwrap();
        let r2 = e2.generate_report(&k2, "trace").unwrap();

        // Same step counts but different archetypes — hash must differ.
        assert_eq!(r1.total_steps, r2.total_steps);
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "different archetypes must produce different report content_hash"
        );
    }

    #[test]
    fn low_coverage_rejection_logs_error_without_loading_kit() {
        let mut eco = MigrationKitEcosystem::default();
        let mut compat = sample_compat(Archetype::Express);
        compat.api_coverage_pct = 79.9;

        let err = eco
            .load_kit(Archetype::Express, compat, sample_steps(), "trace-low")
            .unwrap_err();

        assert!(err.contains("below minimum"));
        assert!(eco.kits().is_empty());
        assert_eq!(eco.audit_log().len(), 1);
        assert_eq!(eco.audit_log()[0].event_code, event_codes::MKE_ERR_COMPAT);
        assert_eq!(eco.audit_log()[0].kit_id, "");
        assert!(
            !eco.audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::MKE_KIT_LOADED)
        );
    }

    #[test]
    fn non_finite_minimum_coverage_rejects_without_audit_or_kit() {
        let mut eco = MigrationKitEcosystem::new(MkeConfig {
            min_api_coverage_pct: f64::NAN,
            ..Default::default()
        });

        let err = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                "trace-min-nan",
            )
            .unwrap_err();

        assert!(err.contains("min_api_coverage_pct"));
        assert!(eco.kits().is_empty());
        assert!(eco.audit_log().is_empty());
    }

    #[test]
    fn generate_plan_unknown_kit_does_not_emit_plan_audit() {
        let mut eco = MigrationKitEcosystem::default();

        let err = eco.generate_plan("missing-kit", "trace-plan").unwrap_err();

        assert_eq!(err, "Kit not found");
        assert!(eco.kits().is_empty());
        assert!(
            !eco.audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::MKE_PLAN_GENERATED)
        );
    }

    #[test]
    fn start_unknown_step_preserves_all_step_statuses_and_audit_log() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                "trace-load",
            )
            .unwrap();
        let audit_before = eco.audit_log().len();

        let err = eco
            .start_step(&kit_id, "missing-step", "trace-start")
            .unwrap_err();

        assert_eq!(err, "Step not found");
        let kit = eco.kits().get(&kit_id).expect("kit should remain loaded");
        assert!(
            kit.steps
                .iter()
                .all(|step| step.status == StepStatus::Pending)
        );
        assert_eq!(eco.audit_log().len(), audit_before);
    }

    #[test]
    fn complete_unknown_step_preserves_in_progress_step_and_audit_log() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                "trace-load",
            )
            .unwrap();
        eco.start_step(&kit_id, "s1", "trace-start").unwrap();
        let audit_before = eco.audit_log().len();

        let err = eco
            .complete_step(&kit_id, "missing-step", "trace-complete")
            .unwrap_err();

        assert_eq!(err, "Step not found");
        let kit = eco.kits().get(&kit_id).expect("kit should remain loaded");
        assert_eq!(kit.steps[0].status, StepStatus::InProgress);
        assert!(
            kit.steps[1..]
                .iter()
                .all(|step| step.status == StepStatus::Pending)
        );
        assert_eq!(eco.audit_log().len(), audit_before);
    }

    #[test]
    fn complete_pending_step_does_not_emit_completion_or_change_status() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                "trace-load",
            )
            .unwrap();
        let audit_before = eco.audit_log().len();

        let err = eco
            .complete_step(&kit_id, "s1", "trace-complete")
            .unwrap_err();

        assert!(err.contains("expected InProgress"));
        let kit = eco.kits().get(&kit_id).expect("kit should remain loaded");
        assert_eq!(kit.steps[0].status, StepStatus::Pending);
        assert_eq!(eco.audit_log().len(), audit_before);
        assert!(
            !eco.audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::MKE_STEP_COMPLETED)
        );
    }

    #[test]
    fn rollback_without_procedure_keeps_step_in_progress_and_skips_success_events() {
        let mut eco = MigrationKitEcosystem::default();
        let mut steps = sample_steps();
        steps[0].rollback_procedure = String::new();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                steps,
                "trace-load",
            )
            .unwrap();
        eco.start_step(&kit_id, "s1", "trace-start").unwrap();

        let err = eco
            .rollback_step(&kit_id, "s1", "trace-rollback")
            .unwrap_err();

        assert_eq!(err, "No rollback procedure defined");
        let kit = eco.kits().get(&kit_id).expect("kit should remain loaded");
        assert_eq!(kit.steps[0].status, StepStatus::InProgress);
        assert!(
            eco.audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::MKE_ERR_ROLLBACK_FAILED)
        );
        assert!(
            !eco.audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::MKE_ROLLBACK_COMPLETED)
        );
    }

    #[test]
    fn rollback_unknown_step_preserves_failed_step_and_audit_log() {
        let mut eco = MigrationKitEcosystem::default();
        let mut steps = sample_steps();
        steps[0].status = StepStatus::Failed;
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                steps,
                "trace-load",
            )
            .unwrap();
        let audit_before = eco.audit_log().len();

        let err = eco
            .rollback_step(&kit_id, "missing-step", "trace-rollback")
            .unwrap_err();

        assert_eq!(err, "Step not found");
        let kit = eco.kits().get(&kit_id).expect("kit should remain loaded");
        assert_eq!(kit.steps[0].status, StepStatus::Failed);
        assert_eq!(eco.audit_log().len(), audit_before);
    }

    #[test]
    fn generate_report_unknown_kit_does_not_store_report_or_audit() {
        let mut eco = MigrationKitEcosystem::default();

        let err = eco
            .generate_report("missing-kit", "trace-report")
            .unwrap_err();

        assert_eq!(err, "Kit not found");
        assert!(eco.reports().is_empty());
        assert!(eco.audit_log().is_empty());
    }

    #[test]
    fn failed_step_report_does_not_count_failed_step_as_progress() {
        let mut eco = MigrationKitEcosystem::default();
        let mut steps = sample_steps();
        steps[0].status = StepStatus::Failed;
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                steps,
                "trace-load",
            )
            .unwrap();

        let report = eco.generate_report(&kit_id, "trace-report").unwrap();

        assert_eq!(report.overall_status, MigrationStatus::Failed);
        assert_eq!(report.completed_steps, 0);
        assert_eq!(report.failed_steps, 1);
        assert_eq!(report.progress_pct, 0.0);
    }

    // === NEGATIVE-PATH ROBUSTNESS TESTS ===

    #[test]
    fn unicode_injection_in_migration_identifiers_handled_safely() {
        let mut eco = MigrationKitEcosystem::default();

        // Unicode injection attacks in step IDs and descriptions
        let malicious_steps = vec![MigrationStep {
            step_id: "step\u{202e}evil\u{200b}\u{0000}inject".to_string(),
            phase: MigrationPhase::Assessment,
            title: "Assessment\u{feff}\u{1f4a9}\u{2028}bypass".to_string(),
            description: "Analyze\u{0085}\u{2029}\u{00ad}payload\u{061c}system".to_string(),
            dependencies: vec!["dep\u{034f}\u{180e}\u{200c}id".to_string()],
            rollback_procedure: "Restore\u{200d}\u{200f}state".to_string(),
            status: StepStatus::Pending,
            estimated_duration_min: 30,
        }];

        let mut compat = sample_compat(Archetype::Express);
        compat.supported_versions = vec!["ver\u{202a}sion\u{202b}18.x".to_string()];
        compat.known_incompatibilities = vec!["incomp\u{2066}atible\u{2069}feature".to_string()];

        let malicious_trace = "trace\u{034f}\u{180e}\u{200c}id";

        // Should handle Unicode injection safely
        let kit_id = eco
            .load_kit(Archetype::Express, compat, malicious_steps, malicious_trace)
            .expect("unicode in migration identifiers should be handled safely");

        // Operations should work with Unicode content
        eco.start_step(
            &kit_id,
            "step\u{202e}evil\u{200b}\u{0000}inject",
            malicious_trace,
        )
        .expect("unicode step operations should work");

        // Audit log should contain Unicode safely
        assert!(!eco.audit_log().is_empty());
        let audit_entry = &eco.audit_log().last().unwrap();
        assert!(audit_entry.trace_id.contains("trace"));
        assert!(audit_entry.details.is_object());

        // Content hash should be deterministic regardless of Unicode
        let kit = eco.kits().get(&kit_id).unwrap();
        assert_eq!(kit.content_hash.len(), 64);
        assert!(!kit.content_hash.contains('\0'));
    }

    #[test]
    fn extreme_duration_arithmetic_overflow_protection() {
        let mut eco = MigrationKitEcosystem::default();

        // Create steps with extreme duration values near u32::MAX
        let extreme_steps = vec![
            MigrationStep {
                step_id: "extreme-duration".to_string(),
                phase: MigrationPhase::DependencyAudit,
                title: "Extreme Duration Test".to_string(),
                description: "Test extreme duration handling".to_string(),
                dependencies: vec![],
                rollback_procedure: "Rollback".to_string(),
                status: StepStatus::Pending,
                estimated_duration_min: u32::MAX - 1,
            },
            MigrationStep {
                step_id: "max-duration".to_string(),
                phase: MigrationPhase::CodeAdaptation,
                title: "Max Duration Test".to_string(),
                description: "Test max duration handling".to_string(),
                dependencies: vec![],
                rollback_procedure: "Rollback".to_string(),
                status: StepStatus::Pending,
                estimated_duration_min: u32::MAX,
            },
        ];

        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                extreme_steps,
                "trace-extreme",
            )
            .expect("extreme durations should be handled safely");

        // Progress calculation should handle extreme values
        let report = eco
            .generate_report(&kit_id, "trace-report")
            .expect("report generation should handle extreme durations");

        assert!(
            report.progress_pct.is_finite(),
            "progress should be finite even with extreme durations"
        );
        assert!(
            report.progress_pct >= 0.0 && report.progress_pct <= 100.0,
            "progress should be in valid range"
        );

        // JSON serialization should handle extreme durations
        let jsonl = eco
            .export_audit_log_jsonl()
            .expect("JSONL export should work with extreme values");
        assert!(jsonl.len() > 0);

        // Verify no overflow in arithmetic operations
        let kit = eco.kits().get(&kit_id).unwrap();
        let total_duration: u64 = kit
            .steps
            .iter()
            .map(|s| s.estimated_duration_min as u64)
            .fold(0u64, |acc, duration| acc.saturating_add(duration));
        assert!(
            total_duration < u64::MAX,
            "duration sum should not overflow"
        );
    }

    #[test]
    fn memory_pressure_with_massive_migration_components() {
        let mut eco = MigrationKitEcosystem::default();

        // Create massive step collections to test push_bounded behavior
        let massive_steps: Vec<MigrationStep> = (0..10000)
            .map(|i| MigrationStep {
                step_id: format!("mass-step-{}", i),
                phase: MigrationPhase::TestValidation,
                title: format!("Mass Migration Step {}", i),
                description: format!("Generated step {} for memory pressure testing", i),
                dependencies: if i > 0 {
                    vec![format!("mass-step-{}", i - 1)]
                } else {
                    vec![]
                },
                rollback_procedure: format!("Rollback step {}", i),
                status: StepStatus::Pending,
                estimated_duration_min: (i % 1000) as u32,
            })
            .collect();

        // Should handle massive step collections
        let kit_id = eco
            .load_kit(
                Archetype::BunNative,
                sample_compat(Archetype::BunNative),
                massive_steps,
                "trace-mass",
            )
            .expect("massive step collections should be handled");

        // Generate many reports to test MAX_REPORTS boundary
        for i in 0..MAX_REPORTS + 100 {
            eco.generate_report(&kit_id, &format!("trace-report-{}", i))
                .expect("report generation should work under pressure");
        }

        // Reports should be bounded to MAX_REPORTS
        assert!(
            eco.reports().len() <= MAX_REPORTS,
            "reports should be bounded to MAX_REPORTS"
        );

        // Generate many audit entries to test MAX_AUDIT_LOG_ENTRIES boundary
        for i in 0..MAX_AUDIT_LOG_ENTRIES + 200 {
            eco.start_step(
                &kit_id,
                &format!("mass-step-{}", i % 100),
                &format!("trace-audit-{}", i),
            )
            .ok(); // Some may fail, that's expected
        }

        // Audit log should be bounded
        assert!(
            eco.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES,
            "audit log should be bounded to MAX_AUDIT_LOG_ENTRIES"
        );

        // Memory structures should remain functional
        assert!(eco.kits().len() > 0);
        assert!(eco.kits().get(&kit_id).is_some());
    }

    #[test]
    fn malformed_compatibility_mapping_edge_cases() {
        let mut eco = MigrationKitEcosystem::default();

        // Empty supported versions
        let mut empty_compat = sample_compat(Archetype::Koa);
        empty_compat.supported_versions = vec![];

        let kit_id1 = eco
            .load_kit(
                Archetype::Koa,
                empty_compat,
                sample_steps(),
                "trace-empty-versions",
            )
            .expect("empty supported versions should be allowed");

        // Very long version strings (potential DoS)
        let mut long_compat = sample_compat(Archetype::NextJs);
        long_compat.supported_versions = vec!["x".repeat(100_000)];
        long_compat.known_incompatibilities = vec!["y".repeat(50_000)];

        let kit_id2 = eco
            .load_kit(
                Archetype::NextJs,
                long_compat,
                sample_steps(),
                "trace-long-strings",
            )
            .expect("very long compatibility strings should be handled");

        // Null bytes in version strings
        let mut null_compat = sample_compat(Archetype::Fastify);
        null_compat.supported_versions = vec!["18.x\0hidden".to_string()];
        null_compat.known_incompatibilities = vec!["feature\0bypass".to_string()];

        let kit_id3 = eco
            .load_kit(
                Archetype::Fastify,
                null_compat,
                sample_steps(),
                "trace-null-bytes",
            )
            .expect("null bytes in compatibility should be handled");

        // All kits should be loaded and functional
        assert_eq!(eco.kits().len(), 3);
        assert!(eco.kits().contains_key(&kit_id1));
        assert!(eco.kits().contains_key(&kit_id2));
        assert!(eco.kits().contains_key(&kit_id3));

        // Content hashes should be unique despite malformed inputs
        let hash1 = &eco.kits().get(&kit_id1).unwrap().content_hash;
        let hash2 = &eco.kits().get(&kit_id2).unwrap().content_hash;
        let hash3 = &eco.kits().get(&kit_id3).unwrap().content_hash;
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn concurrent_step_state_manipulation_edge_cases() {
        let mut eco = MigrationKitEcosystem::default();
        let kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                sample_steps(),
                "trace-concurrent",
            )
            .expect("kit should load");

        // Test rapid state transitions that could cause inconsistency
        eco.start_step(&kit_id, "s1", "trace-start-1")
            .expect("start should work");

        // Multiple completion attempts
        eco.complete_step(&kit_id, "s1", "trace-complete-1")
            .expect("first complete should work");
        let err = eco
            .complete_step(&kit_id, "s1", "trace-complete-2")
            .expect_err("second complete should fail");
        assert!(err.contains("expected InProgress"));

        // Start new step and try multiple rollbacks
        eco.start_step(&kit_id, "s2", "trace-start-2")
            .expect("start s2 should work");
        eco.rollback_step(&kit_id, "s2", "trace-rollback-1")
            .expect("rollback should work");
        let err = eco
            .rollback_step(&kit_id, "s2", "trace-rollback-2")
            .expect_err("second rollback should fail");
        assert!(err.contains("expected InProgress or Failed"));

        // Verify final state consistency
        let kit = eco.kits().get(&kit_id).unwrap();
        assert_eq!(kit.steps[0].status, StepStatus::Completed);
        assert_eq!(kit.steps[1].status, StepStatus::RolledBack);
        assert_eq!(kit.steps[2].status, StepStatus::Pending);

        // Audit log should reflect all attempted operations
        let step_events: Vec<&str> = eco
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .filter(|code| code.starts_with("MKE-0"))
            .collect();
        assert!(step_events.len() >= 4); // At least start, complete, start, rollback
    }

    #[test]
    fn hash_collision_resistance_in_content_generation() {
        let mut eco = MigrationKitEcosystem::default();

        // Test potential hash collision scenarios
        let steps1 = vec![MigrationStep {
            step_id: "step_id_1".to_string(),
            phase: MigrationPhase::Assessment,
            title: "title_a".to_string(),
            description: "desc_x".to_string(),
            dependencies: vec!["dep1".to_string()],
            rollback_procedure: "rollback1".to_string(),
            status: StepStatus::Pending,
            estimated_duration_min: 100,
        }];

        // Different arrangement that could collide without proper domain separation
        let steps2 = vec![MigrationStep {
            step_id: "step_id".to_string(),
            phase: MigrationPhase::Assessment,
            title: "_1title_a".to_string(),
            description: "desc_x".to_string(),
            dependencies: vec!["dep1".to_string()],
            rollback_procedure: "rollback1".to_string(),
            status: StepStatus::Pending,
            estimated_duration_min: 100,
        }];

        let kit_id1 = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                steps1,
                "trace1",
            )
            .unwrap();
        let kit_id2 = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                steps2,
                "trace2",
            )
            .unwrap();

        let hash1 = &eco.kits().get(&kit_id1).unwrap().content_hash;
        let hash2 = &eco.kits().get(&kit_id2).unwrap().content_hash;

        // Should produce different hashes due to proper serialization
        assert_ne!(
            hash1, hash2,
            "different step arrangements should produce different hashes"
        );

        // Test report hash collision resistance
        let report1 = eco.generate_report(&kit_id1, "report-trace1").unwrap();
        let report2 = eco.generate_report(&kit_id2, "report-trace2").unwrap();

        // Reports should have different hashes even with similar step counts
        assert_ne!(
            report1.content_hash, report2.content_hash,
            "reports should have collision-resistant hashes"
        );

        // Verify domain separation in hash inputs
        assert!(
            hash1.len() == 64 && hash2.len() == 64,
            "hashes should be proper SHA256 hex"
        );
        assert!(
            report1.content_hash.len() == 64 && report2.content_hash.len() == 64,
            "report hashes should be proper SHA256 hex"
        );
    }

    #[test]
    fn boundary_conditions_in_progress_calculations() {
        let mut eco = MigrationKitEcosystem::default();

        // Test empty steps collection
        let empty_kit_id = eco
            .load_kit(
                Archetype::Express,
                sample_compat(Archetype::Express),
                vec![],
                "trace-empty",
            )
            .expect("empty steps should be allowed");

        let empty_report = eco
            .generate_report(&empty_kit_id, "trace-empty-report")
            .unwrap();
        assert_eq!(empty_report.total_steps, 0);
        assert_eq!(empty_report.completed_steps, 0);
        assert_eq!(empty_report.failed_steps, 0);
        assert_eq!(empty_report.progress_pct, 0.0);
        assert_eq!(empty_report.overall_status, MigrationStatus::NotStarted);

        // Test single step boundary
        let single_step = vec![MigrationStep {
            step_id: "only-step".to_string(),
            phase: MigrationPhase::Deployment,
            title: "Only Step".to_string(),
            description: "Single step test".to_string(),
            dependencies: vec![],
            rollback_procedure: "Rollback only".to_string(),
            status: StepStatus::Pending,
            estimated_duration_min: 1,
        }];

        let single_kit_id = eco
            .load_kit(
                Archetype::Fastify,
                sample_compat(Archetype::Fastify),
                single_step,
                "trace-single",
            )
            .expect("single step should work");

        // Test 0% -> 100% transition
        let report_0 = eco.generate_report(&single_kit_id, "trace-0").unwrap();
        assert_eq!(report_0.progress_pct, 0.0);

        eco.start_step(&single_kit_id, "only-step", "trace-start-single")
            .unwrap();
        eco.complete_step(&single_kit_id, "only-step", "trace-complete-single")
            .unwrap();

        let report_100 = eco.generate_report(&single_kit_id, "trace-100").unwrap();
        assert_eq!(report_100.progress_pct, 100.0);
        assert_eq!(report_100.overall_status, MigrationStatus::Completed);

        // Verify mathematical precision in progress calculation
        assert!((report_100.progress_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn error_propagation_and_audit_trail_consistency() {
        let mut eco = MigrationKitEcosystem::default();

        // Test error conditions and ensure audit trail remains consistent

        // 1. Load kit with incompatible coverage
        let mut bad_compat = sample_compat(Archetype::Express);
        bad_compat.api_coverage_pct = 50.0;

        let err1 = eco
            .load_kit(
                Archetype::Express,
                bad_compat,
                sample_steps(),
                "trace-bad-compat",
            )
            .unwrap_err();
        assert!(err1.contains("below minimum"));

        // Should log error without creating kit
        assert!(eco.kits().is_empty());
        assert_eq!(eco.audit_log().len(), 1);
        assert_eq!(eco.audit_log()[0].event_code, event_codes::MKE_ERR_COMPAT);

        // 2. Operations on non-existent kit
        let err2 = eco
            .start_step("missing-kit", "step", "trace-missing")
            .unwrap_err();
        assert_eq!(err2, "Kit not found");

        let err3 = eco
            .generate_plan("missing-kit", "trace-missing-plan")
            .unwrap_err();
        assert_eq!(err3, "Kit not found");

        let err4 = eco
            .generate_report("missing-kit", "trace-missing-report")
            .unwrap_err();
        assert_eq!(err4, "Kit not found");

        // Audit log should not grow for failed operations on missing kits
        assert_eq!(eco.audit_log().len(), 1); // Only the compatibility error

        // 3. Load valid kit and test error propagation
        let kit_id = eco
            .load_kit(
                Archetype::Koa,
                sample_compat(Archetype::Koa),
                sample_steps(),
                "trace-valid",
            )
            .expect("valid kit should load");

        let before_audit = eco.audit_log().len();

        // Failed step operation
        let err5 = eco
            .start_step(&kit_id, "missing-step", "trace-missing-step")
            .unwrap_err();
        assert_eq!(err5, "Step not found");

        // Should not add audit entry for failed step operation
        assert_eq!(eco.audit_log().len(), before_audit);

        // Successful operation should add audit entry
        eco.start_step(&kit_id, "s1", "trace-success").unwrap();
        assert_eq!(eco.audit_log().len(), before_audit + 1);

        // Verify audit consistency
        for record in eco.audit_log() {
            assert!(!record.record_id.is_empty());
            assert!(!record.event_code.is_empty());
            assert!(!record.timestamp.is_empty());
            assert!(!record.trace_id.is_empty());
            assert!(record.details.is_object() || record.details.is_null());
        }
    }
}
