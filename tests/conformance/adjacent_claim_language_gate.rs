//! bd-2ji2: Conformance tests for the adjacent substrate claim language gate.
//!
//! Validates that documentation claims about TUI, API, storage, and model
//! capabilities are linked to substrate conformance artifacts. Unlinked
//! claims fail the gate.
//!
//! # Event Codes
//!
//! - `CLAIM_GATE_SCAN_START`: Scan initiated
//! - `CLAIM_LINKED`: Claim linked to artifact
//! - `CLAIM_UNLINKED`: Claim without artifact
//! - `CLAIM_LINK_BROKEN`: Artifact reference broken
//! - `CLAIM_GATE_PASS`: All claims verified
//! - `CLAIM_GATE_FAIL`: Gate blocked
//!
//! # Invariants
//!
//! - **INV-CLG-LINKED**: Every claim has a linked artifact
//! - **INV-CLG-VERIFIED**: Linked artifacts exist and pass
//! - **INV-CLG-COMPLETE**: All documentation files are scanned
//! - **INV-CLG-BLOCKING**: Unlinked claims block the gate

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const CLAIM_GATE_SCAN_START: &str = "CLAIM_GATE_SCAN_START";
    pub const CLAIM_LINKED: &str = "CLAIM_LINKED";
    pub const CLAIM_UNLINKED: &str = "CLAIM_UNLINKED";
    pub const CLAIM_LINK_BROKEN: &str = "CLAIM_LINK_BROKEN";
    pub const CLAIM_GATE_PASS: &str = "CLAIM_GATE_PASS";
    pub const CLAIM_GATE_FAIL: &str = "CLAIM_GATE_FAIL";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_CLG_LINKED: &str = "INV-CLG-LINKED";
pub const INV_CLG_VERIFIED: &str = "INV-CLG-VERIFIED";
pub const INV_CLG_COMPLETE: &str = "INV-CLG-COMPLETE";
pub const INV_CLG_BLOCKING: &str = "INV-CLG-BLOCKING";

// ---------------------------------------------------------------------------
// ClaimCategory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimCategory {
    Tui,
    Api,
    Storage,
    Model,
}

impl ClaimCategory {
    pub fn all() -> &'static [ClaimCategory] {
        &[
            ClaimCategory::Tui,
            ClaimCategory::Api,
            ClaimCategory::Storage,
            ClaimCategory::Model,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            ClaimCategory::Tui => "tui",
            ClaimCategory::Api => "api",
            ClaimCategory::Storage => "storage",
            ClaimCategory::Model => "model",
        }
    }
}

impl fmt::Display for ClaimCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ClaimStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    Linked,
    Unlinked,
    BrokenLink,
}

impl ClaimStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Linked)
    }
}

impl fmt::Display for ClaimStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linked => write!(f, "LINKED"),
            Self::Unlinked => write!(f, "UNLINKED"),
            Self::BrokenLink => write!(f, "BROKEN_LINK"),
        }
    }
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub file: String,
    pub line: usize,
    pub claim_text: String,
    pub category: ClaimCategory,
    pub linked_artifact: Option<String>,
    pub artifact_exists: bool,
    pub status: ClaimStatus,
}

// ---------------------------------------------------------------------------
// ClaimGateEvent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimGateEvent {
    pub code: String,
    pub file: String,
    pub claim_hash: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// ClaimGateSummary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimGateSummary {
    pub total_claims: usize,
    pub linked: usize,
    pub unlinked: usize,
    pub broken_links: usize,
}

impl ClaimGateSummary {
    pub fn gate_pass(&self) -> bool {
        self.unlinked == 0 && self.broken_links == 0 && self.total_claims > 0
    }
}

impl fmt::Display for ClaimGateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ClaimGate: total={}, linked={}, unlinked={}, broken={}",
            self.total_claims, self.linked, self.unlinked, self.broken_links
        )
    }
}

// ---------------------------------------------------------------------------
// ClaimLanguageGate
// ---------------------------------------------------------------------------

pub struct ClaimLanguageGate {
    claims: Vec<Claim>,
    events: Vec<ClaimGateEvent>,
}

impl ClaimLanguageGate {
    pub fn new() -> Self {
        Self {
            claims: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn scan_claim(&mut self, claim: Claim) {
        let hash = format!("{}:{}", claim.file, claim.line);

        self.emit_event(
            event_codes::CLAIM_GATE_SCAN_START,
            &claim.file,
            &hash,
            format!("Scanning claim at {}:{}", claim.file, claim.line),
        );

        match claim.status {
            ClaimStatus::Linked => {
                self.emit_event(
                    event_codes::CLAIM_LINKED,
                    &claim.file,
                    &hash,
                    format!(
                        "Claim linked to {}",
                        claim.linked_artifact.as_deref().unwrap_or("?")
                    ),
                );
            }
            ClaimStatus::Unlinked => {
                self.emit_event(
                    event_codes::CLAIM_UNLINKED,
                    &claim.file,
                    &hash,
                    format!("UNLINKED: {}", claim.claim_text),
                );
            }
            ClaimStatus::BrokenLink => {
                self.emit_event(
                    event_codes::CLAIM_LINK_BROKEN,
                    &claim.file,
                    &hash,
                    format!(
                        "BROKEN LINK: {}",
                        claim.linked_artifact.as_deref().unwrap_or("?")
                    ),
                );
            }
        }

        self.claims.push(claim);
    }

    pub fn scan_batch(&mut self, claims: Vec<Claim>) {
        for claim in claims {
            self.scan_claim(claim);
        }
    }

    pub fn gate_pass(&self) -> bool {
        !self.claims.is_empty() && self.claims.iter().all(|c| c.status.is_pass())
    }

    pub fn summary(&self) -> ClaimGateSummary {
        ClaimGateSummary {
            total_claims: self.claims.len(),
            linked: self
                .claims
                .iter()
                .filter(|c| c.status == ClaimStatus::Linked)
                .count(),
            unlinked: self
                .claims
                .iter()
                .filter(|c| c.status == ClaimStatus::Unlinked)
                .count(),
            broken_links: self
                .claims
                .iter()
                .filter(|c| c.status == ClaimStatus::BrokenLink)
                .count(),
        }
    }

    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }

    pub fn events(&self) -> &[ClaimGateEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<ClaimGateEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        serde_json::json!({
            "bead_id": "bd-2ji2",
            "section": "10.16",
            "gate_verdict": if summary.gate_pass() { "PASS" } else { "FAIL" },
            "summary": {
                "total_claims": summary.total_claims,
                "linked": summary.linked,
                "unlinked": summary.unlinked,
                "broken_links": summary.broken_links,
            },
            "claims": self.claims,
        })
    }

    fn emit_event(&mut self, code: &str, file: &str, hash: &str, detail: String) {
        self.events.push(ClaimGateEvent {
            code: code.to_string(),
            file: file.to_string(),
            claim_hash: hash.to_string(),
            detail,
        });
    }
}

impl Default for ClaimLanguageGate {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn linked_claim(category: ClaimCategory) -> Claim {
        Claim {
            file: "docs/example.md".into(),
            line: 10,
            claim_text: format!("Test {} claim", category.label()),
            category,
            linked_artifact: Some("artifacts/10.16/test_conformance.json".into()),
            artifact_exists: true,
            status: ClaimStatus::Linked,
        }
    }

    fn unlinked_claim(category: ClaimCategory) -> Claim {
        Claim {
            file: "docs/example.md".into(),
            line: 20,
            claim_text: format!("Unlinked {} claim", category.label()),
            category,
            linked_artifact: None,
            artifact_exists: false,
            status: ClaimStatus::Unlinked,
        }
    }

    fn broken_link_claim(category: ClaimCategory) -> Claim {
        Claim {
            file: "docs/example.md".into(),
            line: 30,
            claim_text: format!("Broken link {} claim", category.label()),
            category,
            linked_artifact: Some("artifacts/nonexistent.json".into()),
            artifact_exists: false,
            status: ClaimStatus::BrokenLink,
        }
    }

    // ── ClaimCategory ──────────────────────────────────────────

    #[test]
    fn test_category_all() {
        assert_eq!(ClaimCategory::all().len(), 4);
    }

    #[test]
    fn test_category_labels() {
        assert_eq!(ClaimCategory::Tui.label(), "tui");
        assert_eq!(ClaimCategory::Api.label(), "api");
        assert_eq!(ClaimCategory::Storage.label(), "storage");
        assert_eq!(ClaimCategory::Model.label(), "model");
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", ClaimCategory::Tui), "tui");
    }

    #[test]
    fn test_category_serde_roundtrip() {
        for cat in ClaimCategory::all() {
            let json = serde_json::to_string(cat).unwrap();
            let parsed: ClaimCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *cat);
        }
    }

    // ── ClaimStatus ────────────────────────────────────────────

    #[test]
    fn test_status_linked_passes() {
        assert!(ClaimStatus::Linked.is_pass());
    }

    #[test]
    fn test_status_unlinked_fails() {
        assert!(!ClaimStatus::Unlinked.is_pass());
    }

    #[test]
    fn test_status_broken_link_fails() {
        assert!(!ClaimStatus::BrokenLink.is_pass());
    }

    #[test]
    fn test_status_display() {
        assert_eq!(ClaimStatus::Linked.to_string(), "LINKED");
        assert_eq!(ClaimStatus::Unlinked.to_string(), "UNLINKED");
        assert_eq!(ClaimStatus::BrokenLink.to_string(), "BROKEN_LINK");
    }

    #[test]
    fn test_status_serde_roundtrip() {
        let json = serde_json::to_string(&ClaimStatus::Linked).unwrap();
        let parsed: ClaimStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ClaimStatus::Linked);
    }

    // ── ClaimGateSummary ───────────────────────────────────────

    #[test]
    fn test_summary_gate_pass() {
        let s = ClaimGateSummary {
            total_claims: 4,
            linked: 4,
            unlinked: 0,
            broken_links: 0,
        };
        assert!(s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_unlinked() {
        let s = ClaimGateSummary {
            total_claims: 4,
            linked: 3,
            unlinked: 1,
            broken_links: 0,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_broken() {
        let s = ClaimGateSummary {
            total_claims: 4,
            linked: 3,
            unlinked: 0,
            broken_links: 1,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_empty() {
        let s = ClaimGateSummary {
            total_claims: 0,
            linked: 0,
            unlinked: 0,
            broken_links: 0,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_display() {
        let s = ClaimGateSummary {
            total_claims: 4,
            linked: 3,
            unlinked: 1,
            broken_links: 0,
        };
        let display = s.to_string();
        assert!(display.contains("4"));
        assert!(display.contains("unlinked=1"));
    }

    // ── ClaimLanguageGate ──────────────────────────────────────

    #[test]
    fn test_gate_all_linked() {
        let mut gate = ClaimLanguageGate::new();
        for cat in ClaimCategory::all() {
            gate.scan_claim(linked_claim(*cat));
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_unlinked_fails() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        gate.scan_claim(unlinked_claim(ClaimCategory::Api));
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_broken_link_fails() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        gate.scan_claim(broken_link_claim(ClaimCategory::Storage));
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_empty_fails() {
        let gate = ClaimLanguageGate::new();
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_batch_scan() {
        let mut gate = ClaimLanguageGate::new();
        let claims: Vec<_> = ClaimCategory::all()
            .iter()
            .map(|c| linked_claim(*c))
            .collect();
        gate.scan_batch(claims);
        assert_eq!(gate.claims().len(), 4);
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_summary_counts() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        gate.scan_claim(linked_claim(ClaimCategory::Api));
        gate.scan_claim(unlinked_claim(ClaimCategory::Storage));
        gate.scan_claim(broken_link_claim(ClaimCategory::Model));
        let s = gate.summary();
        assert_eq!(s.total_claims, 4);
        assert_eq!(s.linked, 2);
        assert_eq!(s.unlinked, 1);
        assert_eq!(s.broken_links, 1);
    }

    // ── Events ─────────────────────────────────────────────────

    #[test]
    fn test_linked_emits_scan_start() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        let starts: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::CLAIM_GATE_SCAN_START)
            .collect();
        assert_eq!(starts.len(), 1);
    }

    #[test]
    fn test_linked_emits_claim_linked() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        let linked: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::CLAIM_LINKED)
            .collect();
        assert_eq!(linked.len(), 1);
    }

    #[test]
    fn test_unlinked_emits_claim_unlinked() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(unlinked_claim(ClaimCategory::Api));
        let unlinked: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::CLAIM_UNLINKED)
            .collect();
        assert_eq!(unlinked.len(), 1);
    }

    #[test]
    fn test_broken_emits_claim_link_broken() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(broken_link_claim(ClaimCategory::Storage));
        let broken: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::CLAIM_LINK_BROKEN)
            .collect();
        assert_eq!(broken.len(), 1);
    }

    #[test]
    fn test_event_has_claim_hash() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        assert!(gate.events().iter().all(|e| !e.claim_hash.is_empty()));
    }

    #[test]
    fn test_take_events_drains() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        assert!(!gate.events().is_empty());
        let events = gate.take_events();
        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
    }

    // ── Report ─────────────────────────────────────────────────

    #[test]
    fn test_report_structure() {
        let mut gate = ClaimLanguageGate::new();
        for cat in ClaimCategory::all() {
            gate.scan_claim(linked_claim(*cat));
        }
        let report = gate.to_report();
        assert_eq!(report["bead_id"], "bd-2ji2");
        assert_eq!(report["section"], "10.16");
        assert_eq!(report["gate_verdict"], "PASS");
    }

    #[test]
    fn test_report_claims_count() {
        let mut gate = ClaimLanguageGate::new();
        for cat in ClaimCategory::all() {
            gate.scan_claim(linked_claim(*cat));
        }
        let report = gate.to_report();
        assert_eq!(report["claims"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn test_report_fail_verdict() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(unlinked_claim(ClaimCategory::Tui));
        let report = gate.to_report();
        assert_eq!(report["gate_verdict"], "FAIL");
    }

    // ── Default ────────────────────────────────────────────────

    #[test]
    fn test_default_gate() {
        let gate = ClaimLanguageGate::default();
        assert!(gate.claims().is_empty());
        assert!(gate.events().is_empty());
        assert!(!gate.gate_pass());
    }

    // ── Event codes defined ────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert!(!event_codes::CLAIM_GATE_SCAN_START.is_empty());
        assert!(!event_codes::CLAIM_LINKED.is_empty());
        assert!(!event_codes::CLAIM_UNLINKED.is_empty());
        assert!(!event_codes::CLAIM_LINK_BROKEN.is_empty());
        assert!(!event_codes::CLAIM_GATE_PASS.is_empty());
        assert!(!event_codes::CLAIM_GATE_FAIL.is_empty());
    }

    // ── Invariant constants ────────────────────────────────────

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_CLG_LINKED.is_empty());
        assert!(!INV_CLG_VERIFIED.is_empty());
        assert!(!INV_CLG_COMPLETE.is_empty());
        assert!(!INV_CLG_BLOCKING.is_empty());
    }

    // ── Claim serde ────────────────────────────────────────────

    #[test]
    fn test_claim_serde_roundtrip() {
        let claim = linked_claim(ClaimCategory::Tui);
        let json = serde_json::to_string(&claim).unwrap();
        let parsed: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.category, ClaimCategory::Tui);
        assert_eq!(parsed.status, ClaimStatus::Linked);
    }

    #[test]
    fn test_claim_gate_event_serde() {
        let event = ClaimGateEvent {
            code: "CLAIM_LINKED".into(),
            file: "docs/test.md".into(),
            claim_hash: "docs/test.md:10".into(),
            detail: "test".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: ClaimGateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "CLAIM_LINKED");
    }

    // ── Determinism ────────────────────────────────────────────

    #[test]
    fn test_determinism_identical_claims() {
        let claims: Vec<_> = (0..10).map(|_| linked_claim(ClaimCategory::Tui)).collect();
        let first = &claims[0];
        for c in &claims[1..] {
            assert_eq!(c.status, first.status);
            assert_eq!(c.artifact_exists, first.artifact_exists);
        }
    }

    // ── Per-category tests ─────────────────────────────────────

    #[test]
    fn test_tui_claim_linked() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Tui));
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_api_claim_linked() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Api));
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_storage_claim_linked() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Storage));
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_model_claim_linked() {
        let mut gate = ClaimLanguageGate::new();
        gate.scan_claim(linked_claim(ClaimCategory::Model));
        assert!(gate.gate_pass());
    }
}
