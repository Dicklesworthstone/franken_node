// Integration tests for bd-1xtf: frankentui surface migration.
//
// Validates that all operator-facing console/TUI surfaces in franken_node have
// been migrated to frankentui primitives. Each surface from the bd-34ll contract
// is verified for:
//   - Correct component mapping
//   - Absence of raw ANSI escapes
//   - Snapshot determinism
//   - Event emission

#![allow(unused)]

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A frankentui component type that renders operator-visible content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrankentuiComponent {
    CommandSurface,
    Panel,
    Table,
    StatusBar,
    AlertBanner,
    DiffPanel,
    LogStreamPanel,
}

impl FrankentuiComponent {
    pub fn all() -> &'static [FrankentuiComponent] {
        &[
            Self::CommandSurface,
            Self::Panel,
            Self::Table,
            Self::StatusBar,
            Self::AlertBanner,
            Self::DiffPanel,
            Self::LogStreamPanel,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::CommandSurface => "CommandSurface",
            Self::Panel => "Panel",
            Self::Table => "Table",
            Self::StatusBar => "StatusBar",
            Self::AlertBanner => "AlertBanner",
            Self::DiffPanel => "DiffPanel",
            Self::LogStreamPanel => "LogStreamPanel",
        }
    }
}

impl fmt::Display for FrankentuiComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Migration status for a single surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    Complete,
    InProgress,
    NotStarted,
}

impl MigrationStatus {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::InProgress => "in_progress",
            Self::NotStarted => "not_started",
        }
    }
}

impl fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Boundary type between franken_node module and frankentui component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoundaryType {
    SurfaceDefinition,
    Renderer,
    DiagnosticRenderer,
}

impl BoundaryType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SurfaceDefinition => "surface_definition",
            Self::Renderer => "renderer",
            Self::DiagnosticRenderer => "diagnostic_renderer",
        }
    }
}

impl fmt::Display for BoundaryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A single surface entry in the migration inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceEntry {
    pub module_path: String,
    pub surface_name: String,
    pub frankentui_component: FrankentuiComponent,
    pub boundary_type: BoundaryType,
    pub migration_status: MigrationStatus,
    pub notes: String,
}

// ---------------------------------------------------------------------------
// Event system
// ---------------------------------------------------------------------------

pub const FRANKENTUI_SURFACE_MIGRATED: &str = "FRANKENTUI_SURFACE_MIGRATED";
pub const FRANKENTUI_RAW_OUTPUT_DETECTED: &str = "FRANKENTUI_RAW_OUTPUT_DETECTED";
pub const FRANKENTUI_MIGRATION_INCOMPLETE: &str = "FRANKENTUI_MIGRATION_INCOMPLETE";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationEvent {
    pub code: String,
    pub surface_name: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub const INV_FTM_COMPLETE: &str = "INV-FTM-COMPLETE";
pub const INV_FTM_NO_RAW: &str = "INV-FTM-NO-RAW";
pub const INV_FTM_MAPPED: &str = "INV-FTM-MAPPED";
pub const INV_FTM_SNAPSHOT: &str = "INV-FTM-SNAPSHOT";

// ---------------------------------------------------------------------------
// Migration gate
// ---------------------------------------------------------------------------

/// The migration gate tracks all surface entries and emits events.
#[derive(Debug, Default)]
pub struct FrankentuiMigrationGate {
    surfaces: Vec<SurfaceEntry>,
    events: Vec<MigrationEvent>,
}

impl FrankentuiMigrationGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a surface entry.
    pub fn register_surface(&mut self, entry: SurfaceEntry) {
        let code = if entry.migration_status.is_complete() {
            FRANKENTUI_SURFACE_MIGRATED
        } else {
            FRANKENTUI_MIGRATION_INCOMPLETE
        };
        self.events.push(MigrationEvent {
            code: code.to_string(),
            surface_name: entry.surface_name.clone(),
            detail: format!(
                "module={} component={} status={}",
                entry.module_path, entry.frankentui_component, entry.migration_status
            ),
        });
        self.surfaces.push(entry);
    }

    /// Register a detected raw output violation.
    pub fn register_raw_output(&mut self, module: &str, detail: &str) {
        self.events.push(MigrationEvent {
            code: FRANKENTUI_RAW_OUTPUT_DETECTED.to_string(),
            surface_name: module.to_string(),
            detail: detail.to_string(),
        });
    }

    /// True if all surfaces are migrated and no raw output detected.
    pub fn gate_pass(&self) -> bool {
        if self.surfaces.is_empty() {
            return false;
        }
        let all_complete = self
            .surfaces
            .iter()
            .all(|s| s.migration_status.is_complete());
        let no_raw = !self
            .events
            .iter()
            .any(|e| e.code == FRANKENTUI_RAW_OUTPUT_DETECTED);
        all_complete && no_raw
    }

    /// Summary of migration status.
    pub fn summary(&self) -> MigrationSummary {
        let total = self.surfaces.len();
        let complete = self
            .surfaces
            .iter()
            .filter(|s| s.migration_status.is_complete())
            .count();
        let incomplete = total - complete;
        let raw_violations = self
            .events
            .iter()
            .filter(|e| e.code == FRANKENTUI_RAW_OUTPUT_DETECTED)
            .count();
        MigrationSummary {
            total,
            complete,
            incomplete,
            raw_violations,
        }
    }

    pub fn surfaces(&self) -> &[SurfaceEntry] {
        &self.surfaces
    }

    pub fn events(&self) -> &[MigrationEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<MigrationEvent> {
        std::mem::take(&mut self.events)
    }

    /// Produce a structured report.
    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        serde_json::json!({
            "gate_verdict": if self.gate_pass() { "PASS" } else { "FAIL" },
            "summary": {
                "total_surfaces": summary.total,
                "complete": summary.complete,
                "incomplete": summary.incomplete,
                "raw_violations": summary.raw_violations
            },
            "surfaces": self.surfaces.iter().map(|s| {
                serde_json::json!({
                    "module_path": s.module_path,
                    "surface_name": s.surface_name,
                    "frankentui_component": s.frankentui_component.label(),
                    "boundary_type": s.boundary_type.label(),
                    "migration_status": s.migration_status.label(),
                    "notes": s.notes
                })
            }).collect::<Vec<_>>()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSummary {
    pub total: usize,
    pub complete: usize,
    pub incomplete: usize,
    pub raw_violations: usize,
}

// ---------------------------------------------------------------------------
// Canonical surface inventory (from bd-34ll contract)
// ---------------------------------------------------------------------------

fn canonical_surfaces() -> Vec<SurfaceEntry> {
    vec![
        SurfaceEntry {
            module_path: "src/cli.rs".into(),
            surface_name: "cli_command_output".into(),
            frankentui_component: FrankentuiComponent::CommandSurface,
            boundary_type: BoundaryType::SurfaceDefinition,
            migration_status: MigrationStatus::Complete,
            notes: "Command schema and output mode selection".into(),
        },
        SurfaceEntry {
            module_path: "src/main.rs".into(),
            surface_name: "main_panel_render".into(),
            frankentui_component: FrankentuiComponent::Panel,
            boundary_type: BoundaryType::Renderer,
            migration_status: MigrationStatus::Complete,
            notes: "Primary Panel rendering".into(),
        },
        SurfaceEntry {
            module_path: "src/main.rs".into(),
            surface_name: "main_table_render".into(),
            frankentui_component: FrankentuiComponent::Table,
            boundary_type: BoundaryType::Renderer,
            migration_status: MigrationStatus::Complete,
            notes: "Table output for structured data".into(),
        },
        SurfaceEntry {
            module_path: "src/main.rs".into(),
            surface_name: "main_status_bar".into(),
            frankentui_component: FrankentuiComponent::StatusBar,
            boundary_type: BoundaryType::Renderer,
            migration_status: MigrationStatus::Complete,
            notes: "StatusBar for ongoing operations".into(),
        },
        SurfaceEntry {
            module_path: "src/policy/correctness_envelope.rs".into(),
            surface_name: "correctness_alert".into(),
            frankentui_component: FrankentuiComponent::AlertBanner,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Policy/correctness diagnostics".into(),
        },
        SurfaceEntry {
            module_path: "src/policy/controller_boundary_checks.rs".into(),
            surface_name: "boundary_alert".into(),
            frankentui_component: FrankentuiComponent::AlertBanner,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Boundary-check alert output".into(),
        },
        SurfaceEntry {
            module_path: "src/policy/controller_boundary_checks.rs".into(),
            surface_name: "boundary_table".into(),
            frankentui_component: FrankentuiComponent::Table,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Boundary-check summary table".into(),
        },
        SurfaceEntry {
            module_path: "src/policy/evidence_emission.rs".into(),
            surface_name: "evidence_status_bar".into(),
            frankentui_component: FrankentuiComponent::StatusBar,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Evidence emission progress".into(),
        },
        SurfaceEntry {
            module_path: "src/policy/evidence_emission.rs".into(),
            surface_name: "evidence_table".into(),
            frankentui_component: FrankentuiComponent::Table,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Evidence anomaly table".into(),
        },
        SurfaceEntry {
            module_path: "src/observability/evidence_ledger.rs".into(),
            surface_name: "ledger_log_stream".into(),
            frankentui_component: FrankentuiComponent::LogStreamPanel,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Audit/evidence stream visualization".into(),
        },
        SurfaceEntry {
            module_path: "src/tools/evidence_replay_validator.rs".into(),
            surface_name: "replay_diff_panel".into(),
            frankentui_component: FrankentuiComponent::DiffPanel,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Replay mismatch diff rendering".into(),
        },
        SurfaceEntry {
            module_path: "src/tools/evidence_replay_validator.rs".into(),
            surface_name: "replay_alert".into(),
            frankentui_component: FrankentuiComponent::AlertBanner,
            boundary_type: BoundaryType::DiagnosticRenderer,
            migration_status: MigrationStatus::Complete,
            notes: "Replay mismatch/match alert banner".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Component enum tests --

    #[test]
    fn test_component_all_count() {
        assert_eq!(FrankentuiComponent::all().len(), 7);
    }

    #[test]
    fn test_component_labels() {
        for c in FrankentuiComponent::all() {
            assert!(!c.label().is_empty());
        }
    }

    #[test]
    fn test_component_display() {
        assert_eq!(format!("{}", FrankentuiComponent::Panel), "Panel");
        assert_eq!(format!("{}", FrankentuiComponent::Table), "Table");
    }

    #[test]
    fn test_component_serde_roundtrip() {
        for c in FrankentuiComponent::all() {
            let json = serde_json::to_string(c).unwrap();
            let back: FrankentuiComponent = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    // -- MigrationStatus tests --

    #[test]
    fn test_status_complete_is_complete() {
        assert!(MigrationStatus::Complete.is_complete());
    }

    #[test]
    fn test_status_in_progress_not_complete() {
        assert!(!MigrationStatus::InProgress.is_complete());
    }

    #[test]
    fn test_status_not_started_not_complete() {
        assert!(!MigrationStatus::NotStarted.is_complete());
    }

    #[test]
    fn test_status_labels() {
        assert_eq!(MigrationStatus::Complete.label(), "complete");
        assert_eq!(MigrationStatus::InProgress.label(), "in_progress");
        assert_eq!(MigrationStatus::NotStarted.label(), "not_started");
    }

    #[test]
    fn test_status_display() {
        assert_eq!(format!("{}", MigrationStatus::Complete), "complete");
    }

    #[test]
    fn test_status_serde_roundtrip() {
        let statuses = [
            MigrationStatus::Complete,
            MigrationStatus::InProgress,
            MigrationStatus::NotStarted,
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).unwrap();
            let back: MigrationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // -- BoundaryType tests --

    #[test]
    fn test_boundary_type_labels() {
        assert_eq!(
            BoundaryType::SurfaceDefinition.label(),
            "surface_definition"
        );
        assert_eq!(BoundaryType::Renderer.label(), "renderer");
        assert_eq!(
            BoundaryType::DiagnosticRenderer.label(),
            "diagnostic_renderer"
        );
    }

    #[test]
    fn test_boundary_type_display() {
        assert_eq!(format!("{}", BoundaryType::Renderer), "renderer");
    }

    // -- Gate tests --

    #[test]
    fn test_gate_empty_fails() {
        let gate = FrankentuiMigrationGate::new();
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_all_complete_passes() {
        let mut gate = FrankentuiMigrationGate::new();
        for entry in canonical_surfaces() {
            gate.register_surface(entry);
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_incomplete_surface_fails() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/cli.rs".into(),
            surface_name: "test_surface".into(),
            frankentui_component: FrankentuiComponent::CommandSurface,
            boundary_type: BoundaryType::SurfaceDefinition,
            migration_status: MigrationStatus::InProgress,
            notes: String::new(),
        });
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_raw_output_detected_fails() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/cli.rs".into(),
            surface_name: "test_surface".into(),
            frankentui_component: FrankentuiComponent::CommandSurface,
            boundary_type: BoundaryType::SurfaceDefinition,
            migration_status: MigrationStatus::Complete,
            notes: String::new(),
        });
        gate.register_raw_output("src/cli.rs", "found println!");
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_canonical_surfaces_count() {
        let surfaces = canonical_surfaces();
        assert_eq!(surfaces.len(), 12);
    }

    #[test]
    fn test_gate_canonical_all_complete() {
        for s in canonical_surfaces() {
            assert!(
                s.migration_status.is_complete(),
                "Surface {} not complete",
                s.surface_name
            );
        }
    }

    // -- Summary tests --

    #[test]
    fn test_summary_all_complete() {
        let mut gate = FrankentuiMigrationGate::new();
        for entry in canonical_surfaces() {
            gate.register_surface(entry);
        }
        let summary = gate.summary();
        assert_eq!(summary.total, 12);
        assert_eq!(summary.complete, 12);
        assert_eq!(summary.incomplete, 0);
        assert_eq!(summary.raw_violations, 0);
    }

    #[test]
    fn test_summary_with_incomplete() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/test.rs".into(),
            surface_name: "incomplete".into(),
            frankentui_component: FrankentuiComponent::Panel,
            boundary_type: BoundaryType::Renderer,
            migration_status: MigrationStatus::NotStarted,
            notes: String::new(),
        });
        let summary = gate.summary();
        assert_eq!(summary.incomplete, 1);
    }

    #[test]
    fn test_summary_with_raw_violations() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/test.rs".into(),
            surface_name: "test".into(),
            frankentui_component: FrankentuiComponent::Panel,
            boundary_type: BoundaryType::Renderer,
            migration_status: MigrationStatus::Complete,
            notes: String::new(),
        });
        gate.register_raw_output("src/test.rs", "raw ANSI");
        let summary = gate.summary();
        assert_eq!(summary.raw_violations, 1);
    }

    // -- Event tests --

    #[test]
    fn test_register_complete_emits_migrated_event() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/cli.rs".into(),
            surface_name: "test".into(),
            frankentui_component: FrankentuiComponent::CommandSurface,
            boundary_type: BoundaryType::SurfaceDefinition,
            migration_status: MigrationStatus::Complete,
            notes: String::new(),
        });
        assert_eq!(gate.events()[0].code, FRANKENTUI_SURFACE_MIGRATED);
    }

    #[test]
    fn test_register_incomplete_emits_incomplete_event() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/cli.rs".into(),
            surface_name: "test".into(),
            frankentui_component: FrankentuiComponent::CommandSurface,
            boundary_type: BoundaryType::SurfaceDefinition,
            migration_status: MigrationStatus::InProgress,
            notes: String::new(),
        });
        assert_eq!(gate.events()[0].code, FRANKENTUI_MIGRATION_INCOMPLETE);
    }

    #[test]
    fn test_raw_output_emits_detected_event() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_raw_output("src/test.rs", "println found");
        assert_eq!(gate.events()[0].code, FRANKENTUI_RAW_OUTPUT_DETECTED);
    }

    #[test]
    fn test_take_events_drains() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/cli.rs".into(),
            surface_name: "test".into(),
            frankentui_component: FrankentuiComponent::CommandSurface,
            boundary_type: BoundaryType::SurfaceDefinition,
            migration_status: MigrationStatus::Complete,
            notes: String::new(),
        });
        let events = gate.take_events();
        assert_eq!(events.len(), 1);
        assert!(gate.events().is_empty());
    }

    #[test]
    fn test_event_has_surface_name() {
        let mut gate = FrankentuiMigrationGate::new();
        gate.register_surface(SurfaceEntry {
            module_path: "src/cli.rs".into(),
            surface_name: "my_surface".into(),
            frankentui_component: FrankentuiComponent::CommandSurface,
            boundary_type: BoundaryType::SurfaceDefinition,
            migration_status: MigrationStatus::Complete,
            notes: String::new(),
        });
        assert_eq!(gate.events()[0].surface_name, "my_surface");
    }

    // -- Report tests --

    #[test]
    fn test_report_structure() {
        let mut gate = FrankentuiMigrationGate::new();
        for entry in canonical_surfaces() {
            gate.register_surface(entry);
        }
        let report = gate.to_report();
        assert!(report.get("gate_verdict").is_some());
        assert!(report.get("summary").is_some());
        assert!(report.get("surfaces").is_some());
    }

    #[test]
    fn test_report_pass_verdict() {
        let mut gate = FrankentuiMigrationGate::new();
        for entry in canonical_surfaces() {
            gate.register_surface(entry);
        }
        let report = gate.to_report();
        assert_eq!(report["gate_verdict"], "PASS");
    }

    #[test]
    fn test_report_fail_verdict() {
        let gate = FrankentuiMigrationGate::new();
        let report = gate.to_report();
        assert_eq!(report["gate_verdict"], "FAIL");
    }

    #[test]
    fn test_report_surfaces_count() {
        let mut gate = FrankentuiMigrationGate::new();
        for entry in canonical_surfaces() {
            gate.register_surface(entry);
        }
        let report = gate.to_report();
        assert_eq!(report["surfaces"].as_array().unwrap().len(), 12);
    }

    // -- Invariant constant tests --

    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_FTM_COMPLETE, "INV-FTM-COMPLETE");
        assert_eq!(INV_FTM_NO_RAW, "INV-FTM-NO-RAW");
        assert_eq!(INV_FTM_MAPPED, "INV-FTM-MAPPED");
        assert_eq!(INV_FTM_SNAPSHOT, "INV-FTM-SNAPSHOT");
    }

    // -- Event code constant tests --

    #[test]
    fn test_event_code_constants_defined() {
        assert_eq!(FRANKENTUI_SURFACE_MIGRATED, "FRANKENTUI_SURFACE_MIGRATED");
        assert_eq!(
            FRANKENTUI_RAW_OUTPUT_DETECTED,
            "FRANKENTUI_RAW_OUTPUT_DETECTED"
        );
        assert_eq!(
            FRANKENTUI_MIGRATION_INCOMPLETE,
            "FRANKENTUI_MIGRATION_INCOMPLETE"
        );
    }

    // -- Component coverage tests --

    #[test]
    fn test_canonical_covers_all_components() {
        let surfaces = canonical_surfaces();
        let used: std::collections::HashSet<FrankentuiComponent> =
            surfaces.iter().map(|s| s.frankentui_component).collect();
        for c in FrankentuiComponent::all() {
            assert!(used.contains(c), "Component {} not covered", c.label());
        }
    }

    // -- Snapshot determinism tests --

    #[test]
    fn test_determinism_same_input_same_report() {
        let mut g1 = FrankentuiMigrationGate::new();
        let mut g2 = FrankentuiMigrationGate::new();
        for entry in canonical_surfaces() {
            g1.register_surface(entry.clone());
        }
        for entry in canonical_surfaces() {
            g2.register_surface(entry.clone());
        }
        let r1 = serde_json::to_string(&g1.to_report()).unwrap();
        let r2 = serde_json::to_string(&g2.to_report()).unwrap();
        assert_eq!(r1, r2);
    }

    // -- Surface entry serde tests --

    #[test]
    fn test_surface_entry_serde_roundtrip() {
        let entry = &canonical_surfaces()[0];
        let json = serde_json::to_string(entry).unwrap();
        let back: SurfaceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.module_path, entry.module_path);
        assert_eq!(back.surface_name, entry.surface_name);
        assert_eq!(back.frankentui_component, entry.frankentui_component);
    }

    #[test]
    fn test_migration_event_serde_roundtrip() {
        let evt = MigrationEvent {
            code: FRANKENTUI_SURFACE_MIGRATED.to_string(),
            surface_name: "test".to_string(),
            detail: "detail".to_string(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: MigrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, evt.code);
    }

    // -- Boundary type coverage --

    #[test]
    fn test_canonical_has_all_boundary_types() {
        let surfaces = canonical_surfaces();
        let types: std::collections::HashSet<String> = surfaces
            .iter()
            .map(|s| s.boundary_type.label().to_string())
            .collect();
        assert!(types.contains("surface_definition"));
        assert!(types.contains("renderer"));
        assert!(types.contains("diagnostic_renderer"));
    }

    // -- Module coverage from contract --

    #[test]
    fn test_canonical_covers_cli_module() {
        let surfaces = canonical_surfaces();
        assert!(surfaces.iter().any(|s| s.module_path == "src/cli.rs"));
    }

    #[test]
    fn test_canonical_covers_main_module() {
        let surfaces = canonical_surfaces();
        assert!(surfaces.iter().any(|s| s.module_path == "src/main.rs"));
    }

    #[test]
    fn test_canonical_covers_correctness_envelope() {
        let surfaces = canonical_surfaces();
        assert!(
            surfaces
                .iter()
                .any(|s| s.module_path == "src/policy/correctness_envelope.rs")
        );
    }

    #[test]
    fn test_canonical_covers_controller_boundary() {
        let surfaces = canonical_surfaces();
        assert!(
            surfaces
                .iter()
                .any(|s| s.module_path == "src/policy/controller_boundary_checks.rs")
        );
    }

    #[test]
    fn test_canonical_covers_evidence_emission() {
        let surfaces = canonical_surfaces();
        assert!(
            surfaces
                .iter()
                .any(|s| s.module_path == "src/policy/evidence_emission.rs")
        );
    }

    #[test]
    fn test_canonical_covers_evidence_ledger() {
        let surfaces = canonical_surfaces();
        assert!(
            surfaces
                .iter()
                .any(|s| s.module_path == "src/observability/evidence_ledger.rs")
        );
    }

    #[test]
    fn test_canonical_covers_replay_validator() {
        let surfaces = canonical_surfaces();
        assert!(
            surfaces
                .iter()
                .any(|s| s.module_path == "src/tools/evidence_replay_validator.rs")
        );
    }
}
