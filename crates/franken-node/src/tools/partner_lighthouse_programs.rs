//! bd-31tg: Partner and lighthouse programs (Section 15).
//!
//! Implements partner/lighthouse adoption programs proving category-shift
//! outcomes. Tracks partner onboarding, lighthouse deployments, and outcome
//! measurement across adoption tiers.
//!
//! # Capabilities
//!
//! - Partner tier management (5 tiers)
//! - Lighthouse deployment tracking
//! - Outcome metric collection
//! - Category-shift evidence generation
//! - Adoption funnel analytics
//! - Program versioning and audit trail
//!
//! # Invariants
//!
//! - **INV-PLP-TIERED**: Every partner has a tier classification.
//! - **INV-PLP-TRACKED**: Every deployment records measurable outcomes.
//! - **INV-PLP-DETERMINISTIC**: Same inputs produce same analytics output.
//! - **INV-PLP-GATED**: Tier promotions require minimum outcome thresholds.
//! - **INV-PLP-VERSIONED**: Schema version embedded in every export.
//! - **INV-PLP-AUDITABLE**: Every mutation produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
const MAX_DEPLOYMENTS: usize = 4096;
const MAX_OUTCOMES: usize = 4096;

pub mod event_codes {
    pub const PLP_PARTNER_ENROLLED: &str = "PLP-001";
    pub const PLP_DEPLOYMENT_CREATED: &str = "PLP-002";
    pub const PLP_OUTCOME_RECORDED: &str = "PLP-003";
    pub const PLP_TIER_PROMOTED: &str = "PLP-004";
    pub const PLP_ANALYTICS_GENERATED: &str = "PLP-005";
    pub const PLP_EVIDENCE_EXPORTED: &str = "PLP-006";
    pub const PLP_FUNNEL_COMPUTED: &str = "PLP-007";
    pub const PLP_PARTNER_UPDATED: &str = "PLP-008";
    pub const PLP_VERSION_EMBEDDED: &str = "PLP-009";
    pub const PLP_CATALOG_GENERATED: &str = "PLP-010";
    pub const PLP_ERR_DUPLICATE_PARTNER: &str = "PLP-ERR-001";
    pub const PLP_ERR_INSUFFICIENT_OUTCOMES: &str = "PLP-ERR-002";
    pub const PLP_ERR_DUPLICATE_DEPLOYMENT: &str = "PLP-ERR-003";
    pub const PLP_ERR_DUPLICATE_OUTCOME: &str = "PLP-ERR-004";
}

pub mod invariants {
    pub const INV_PLP_TIERED: &str = "INV-PLP-TIERED";
    pub const INV_PLP_TRACKED: &str = "INV-PLP-TRACKED";
    pub const INV_PLP_DETERMINISTIC: &str = "INV-PLP-DETERMINISTIC";
    pub const INV_PLP_GATED: &str = "INV-PLP-GATED";
    pub const INV_PLP_VERSIONED: &str = "INV-PLP-VERSIONED";
    pub const INV_PLP_AUDITABLE: &str = "INV-PLP-AUDITABLE";
}

pub const SCHEMA_VERSION: &str = "plp-v1.0";
pub const MIN_OUTCOMES_FOR_PROMOTION: usize = 3;

/// Partner adoption tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartnerTier {
    Prospect,
    Pilot,
    Lighthouse,
    Strategic,
    Flagship,
}

impl PartnerTier {
    pub fn all() -> &'static [PartnerTier] {
        &[
            Self::Prospect,
            Self::Pilot,
            Self::Lighthouse,
            Self::Strategic,
            Self::Flagship,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Prospect => "prospect",
            Self::Pilot => "pilot",
            Self::Lighthouse => "lighthouse",
            Self::Strategic => "strategic",
            Self::Flagship => "flagship",
        }
    }
    pub fn next(&self) -> Option<PartnerTier> {
        match self {
            Self::Prospect => Some(Self::Pilot),
            Self::Pilot => Some(Self::Lighthouse),
            Self::Lighthouse => Some(Self::Strategic),
            Self::Strategic => Some(Self::Flagship),
            Self::Flagship => None,
        }
    }
}

/// A partner organization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Partner {
    pub partner_id: String,
    pub name: String,
    pub tier: PartnerTier,
    pub enrolled_at: String,
    pub deployment_count: usize,
    pub outcome_count: usize,
}

/// A lighthouse deployment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LighthouseDeployment {
    pub deployment_id: String,
    pub partner_id: String,
    pub description: String,
    pub started_at: String,
    pub completed: bool,
}

/// A measured outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutcomeRecord {
    pub outcome_id: String,
    pub deployment_id: String,
    pub metric_name: String,
    pub metric_value: f64,
    pub evidence_ref: String,
    pub recorded_at: String,
}

/// Adoption funnel analytics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdoptionFunnel {
    pub funnel_id: String,
    pub timestamp: String,
    pub schema_version: String,
    pub partners_by_tier: BTreeMap<String, usize>,
    pub total_partners: usize,
    pub total_deployments: usize,
    pub total_outcomes: usize,
    pub content_hash: String,
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlpAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// Partner lighthouse programs engine.
#[derive(Debug, Clone)]
pub struct PartnerLighthousePrograms {
    schema_version: String,
    partners: BTreeMap<String, Partner>,
    deployments: Vec<LighthouseDeployment>,
    outcomes: Vec<OutcomeRecord>,
    audit_log: Vec<PlpAuditRecord>,
}

impl Default for PartnerLighthousePrograms {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            partners: BTreeMap::new(),
            deployments: Vec::new(),
            outcomes: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl PartnerLighthousePrograms {
    pub fn enroll_partner(
        &mut self,
        mut partner: Partner,
        trace_id: &str,
    ) -> Result<String, String> {
        if partner.partner_id.trim().is_empty() {
            return Err("partner id must not be empty".to_string());
        }
        if partner.partner_id.trim() != partner.partner_id {
            return Err("partner id must not include surrounding whitespace".to_string());
        }
        if partner.name.trim().is_empty() {
            return Err("partner name must not be empty".to_string());
        }
        if self.partners.contains_key(&partner.partner_id) {
            self.log(
                event_codes::PLP_ERR_DUPLICATE_PARTNER,
                trace_id,
                serde_json::json!({"id": &partner.partner_id}),
            );
            return Err(format!("duplicate partner: {}", partner.partner_id));
        }
        partner.enrolled_at = Utc::now().to_rfc3339();
        partner.deployment_count = 0;
        partner.outcome_count = 0;
        let pid = partner.partner_id.clone();
        self.log(
            event_codes::PLP_PARTNER_ENROLLED,
            trace_id,
            serde_json::json!({"partner_id": &pid, "tier": partner.tier.label()}),
        );
        self.partners.insert(pid.clone(), partner);
        Ok(pid)
    }

    pub fn create_deployment(
        &mut self,
        mut dep: LighthouseDeployment,
        trace_id: &str,
    ) -> Result<String, String> {
        if dep.deployment_id.trim().is_empty() {
            return Err("deployment id must not be empty".to_string());
        }
        if dep.deployment_id.trim() != dep.deployment_id {
            return Err("deployment id must not include surrounding whitespace".to_string());
        }
        if dep.description.trim().is_empty() {
            return Err("deployment description must not be empty".to_string());
        }
        if self
            .deployments
            .iter()
            .any(|d| d.deployment_id == dep.deployment_id)
        {
            self.log(
                event_codes::PLP_ERR_DUPLICATE_DEPLOYMENT,
                trace_id,
                serde_json::json!({"deployment_id": &dep.deployment_id}),
            );
            return Err(format!("duplicate deployment: {}", dep.deployment_id));
        }
        if !self.partners.contains_key(&dep.partner_id) {
            return Err(format!("partner not found: {}", dep.partner_id));
        }
        dep.started_at = Utc::now().to_rfc3339();
        dep.completed = false;
        let did = dep.deployment_id.clone();
        let pid = dep.partner_id.clone();
        self.log(
            event_codes::PLP_DEPLOYMENT_CREATED,
            trace_id,
            serde_json::json!({"deployment_id": &did, "partner_id": &pid}),
        );
        push_bounded(&mut self.deployments, dep, MAX_DEPLOYMENTS);
        if let Some(p) = self.partners.get_mut(&pid) {
            p.deployment_count = p.deployment_count.saturating_add(1);
        }
        Ok(did)
    }

    pub fn record_outcome(
        &mut self,
        mut outcome: OutcomeRecord,
        trace_id: &str,
    ) -> Result<String, String> {
        if outcome.outcome_id.trim().is_empty() {
            return Err("outcome id must not be empty".to_string());
        }
        if outcome.outcome_id.trim() != outcome.outcome_id {
            return Err("outcome id must not include surrounding whitespace".to_string());
        }
        if outcome.metric_name.trim().is_empty() {
            return Err("outcome metric name must not be empty".to_string());
        }
        if outcome.evidence_ref.trim().is_empty() {
            return Err("outcome evidence ref must not be empty".to_string());
        }
        if self
            .outcomes
            .iter()
            .any(|o| o.outcome_id == outcome.outcome_id)
        {
            self.log(
                event_codes::PLP_ERR_DUPLICATE_OUTCOME,
                trace_id,
                serde_json::json!({"outcome_id": &outcome.outcome_id}),
            );
            return Err(format!("duplicate outcome: {}", outcome.outcome_id));
        }
        if !outcome.metric_value.is_finite() {
            return Err("metric_value must be finite".to_string());
        }
        if !self
            .deployments
            .iter()
            .any(|d| d.deployment_id == outcome.deployment_id)
        {
            return Err(format!("deployment not found: {}", outcome.deployment_id));
        }
        outcome.recorded_at = Utc::now().to_rfc3339();
        let oid = outcome.outcome_id.clone();
        let did = outcome.deployment_id.clone();

        // Find partner for this deployment
        let partner_id = self
            .deployments
            .iter()
            .find(|d| d.deployment_id == did)
            .map(|d| d.partner_id.clone());

        self.log(
            event_codes::PLP_OUTCOME_RECORDED,
            trace_id,
            serde_json::json!({"outcome_id": &oid, "metric": &outcome.metric_name}),
        );
        push_bounded(&mut self.outcomes, outcome, MAX_OUTCOMES);

        if let Some(pid) = partner_id
            && let Some(p) = self.partners.get_mut(&pid)
        {
            p.outcome_count = p.outcome_count.saturating_add(1);
        }
        Ok(oid)
    }

    pub fn promote_partner(
        &mut self,
        partner_id: &str,
        trace_id: &str,
    ) -> Result<PartnerTier, String> {
        let outcome_count = self
            .partners
            .get(partner_id)
            .ok_or_else(|| format!("partner not found: {partner_id}"))?
            .outcome_count;

        if outcome_count < MIN_OUTCOMES_FOR_PROMOTION {
            self.log(
                event_codes::PLP_ERR_INSUFFICIENT_OUTCOMES,
                trace_id,
                serde_json::json!({
                    "partner_id": partner_id,
                    "outcomes": outcome_count,
                    "required": MIN_OUTCOMES_FOR_PROMOTION,
                }),
            );
            return Err(format!(
                "insufficient outcomes: {outcome_count} < {MIN_OUTCOMES_FOR_PROMOTION}"
            ));
        }

        let current_tier = self.partners[partner_id].tier;
        let next = current_tier
            .next()
            .ok_or_else(|| "already at highest tier".to_string())?;

        let partner = self
            .partners
            .get_mut(partner_id)
            .ok_or_else(|| format!("partner not found: {partner_id}"))?;
        partner.tier = next;
        partner.outcome_count = 0; // Reset so next promotion requires fresh outcomes
        self.log(
            event_codes::PLP_TIER_PROMOTED,
            trace_id,
            serde_json::json!({
                "partner_id": partner_id, "from": current_tier.label(), "to": next.label(),
            }),
        );
        Ok(next)
    }

    pub fn generate_funnel(&mut self, trace_id: &str) -> AdoptionFunnel {
        let mut by_tier: BTreeMap<String, usize> = BTreeMap::new();
        for p in self.partners.values() {
            let count = by_tier.entry(p.tier.label().to_string()).or_default();
            *count = count.saturating_add(1);
        }
        let total_p = self.partners.len();
        let total_d = self.deployments.len();
        let total_o = self.outcomes.len();
        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"partner_lighthouse_hash_v1:");
            h.update((u64::try_from(self.schema_version.len()).unwrap_or(u64::MAX)).to_le_bytes());
            h.update(self.schema_version.as_bytes());
            h.update((total_p as u64).to_le_bytes());
            h.update((total_d as u64).to_le_bytes());
            h.update((total_o as u64).to_le_bytes());
            h.update((u64::try_from(by_tier.len()).unwrap_or(u64::MAX)).to_le_bytes());
            for (tier_name, count) in &by_tier {
                h.update((u64::try_from(tier_name.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(tier_name.as_bytes());
                h.update((*count as u64).to_le_bytes());
            }
            hex::encode(h.finalize())
        };

        self.log(
            event_codes::PLP_FUNNEL_COMPUTED,
            trace_id,
            serde_json::json!({"partners": total_p}),
        );
        self.log(
            event_codes::PLP_ANALYTICS_GENERATED,
            trace_id,
            serde_json::json!({"tiers": by_tier.len()}),
        );
        self.log(
            event_codes::PLP_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"version": &self.schema_version}),
        );
        self.log(
            event_codes::PLP_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({"total": total_p}),
        );
        self.log(
            event_codes::PLP_EVIDENCE_EXPORTED,
            trace_id,
            serde_json::json!({"outcomes": total_o}),
        );

        AdoptionFunnel {
            funnel_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            schema_version: self.schema_version.clone(),
            partners_by_tier: by_tier,
            total_partners: total_p,
            total_deployments: total_d,
            total_outcomes: total_o,
            content_hash,
        }
    }

    pub fn partners(&self) -> &BTreeMap<String, Partner> {
        &self.partners
    }
    pub fn deployments(&self) -> &[LighthouseDeployment] {
        &self.deployments
    }
    pub fn outcomes(&self) -> &[OutcomeRecord] {
        &self.outcomes
    }
    pub fn audit_log(&self) -> &[PlpAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for r in &self.audit_log {
            lines.push(serde_json::to_string(r)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            PlpAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_partner(id: &str) -> Partner {
        Partner {
            partner_id: id.to_string(),
            name: format!("Partner {id}"),
            tier: PartnerTier::Prospect,
            enrolled_at: String::new(),
            deployment_count: 0,
            outcome_count: 0,
        }
    }

    fn sample_deployment(id: &str, partner: &str) -> LighthouseDeployment {
        LighthouseDeployment {
            deployment_id: id.to_string(),
            partner_id: partner.to_string(),
            description: "Test deployment".to_string(),
            started_at: String::new(),
            completed: false,
        }
    }

    fn sample_outcome(id: &str, dep: &str) -> OutcomeRecord {
        OutcomeRecord {
            outcome_id: id.to_string(),
            deployment_id: dep.to_string(),
            metric_name: "latency_reduction".to_string(),
            metric_value: 0.42,
            evidence_ref: "artifact-ref".to_string(),
            recorded_at: String::new(),
        }
    }

    #[test]
    fn five_tiers() {
        assert_eq!(PartnerTier::all().len(), 5);
    }
    #[test]
    fn tier_labels_nonempty() {
        for t in PartnerTier::all() {
            assert!(!t.label().is_empty());
        }
    }
    #[test]
    fn tier_progression() {
        assert_eq!(PartnerTier::Prospect.next(), Some(PartnerTier::Pilot));
    }
    #[test]
    fn flagship_no_next() {
        assert_eq!(PartnerTier::Flagship.next(), None);
    }

    #[test]
    fn enroll_partner_ok() {
        let mut e = PartnerLighthousePrograms::default();
        assert!(e.enroll_partner(sample_partner("p1"), &trace()).is_ok());
        assert_eq!(e.partners().len(), 1);
    }

    #[test]
    fn enroll_duplicate_fails() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        assert!(e.enroll_partner(sample_partner("p1"), &trace()).is_err());
    }

    #[test]
    fn enroll_empty_partner_id_rejected_without_audit() {
        let mut e = PartnerLighthousePrograms::default();

        let err = e
            .enroll_partner(sample_partner(""), "trace-empty-partner")
            .expect_err("empty partner id should be rejected");

        assert!(err.contains("partner id"));
        assert!(e.partners().is_empty());
        assert!(e.audit_log().is_empty());
    }

    #[test]
    fn enroll_trim_required_partner_id_rejected_without_insert() {
        let mut e = PartnerLighthousePrograms::default();

        let err = e
            .enroll_partner(sample_partner(" p1"), "trace-space-partner")
            .expect_err("partner id with surrounding whitespace should be rejected");

        assert!(err.contains("surrounding whitespace"));
        assert!(e.partners().is_empty());
        assert!(e.audit_log().is_empty());
    }

    #[test]
    fn enroll_whitespace_partner_name_rejected_without_insert() {
        let mut e = PartnerLighthousePrograms::default();
        let mut partner = sample_partner("p-blank-name");
        partner.name = " \n\t ".to_string();

        let err = e
            .enroll_partner(partner, "trace-blank-partner-name")
            .expect_err("blank partner name should be rejected");

        assert!(err.contains("partner name"));
        assert!(e.partners().is_empty());
        assert!(e.audit_log().is_empty());
    }

    #[test]
    fn duplicate_partner_rejection_preserves_original_partner() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        let before_audit_len = e.audit_log().len();
        let mut replacement = sample_partner("p1");
        replacement.name = "Replacement".to_string();
        replacement.tier = PartnerTier::Flagship;
        replacement.deployment_count = 99;
        replacement.outcome_count = 99;

        let err = e
            .enroll_partner(replacement, "trace-duplicate-partner")
            .expect_err("duplicate partner should be rejected");

        assert!(err.contains("duplicate partner"));
        assert_eq!(e.partners().len(), 1);
        assert_eq!(e.partners()["p1"].name, "Partner p1");
        assert_eq!(e.partners()["p1"].tier, PartnerTier::Prospect);
        assert_eq!(e.partners()["p1"].deployment_count, 0);
        assert_eq!(e.partners()["p1"].outcome_count, 0);
        assert_eq!(e.audit_log().len(), before_audit_len.saturating_add(1));
    }

    #[test]
    fn create_deployment_ok() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        assert!(
            e.create_deployment(sample_deployment("d1", "p1"), &trace())
                .is_ok()
        );
    }

    #[test]
    fn deployment_increments_count() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        assert_eq!(e.partners()["p1"].deployment_count, 1);
    }

    #[test]
    fn deployment_missing_partner() {
        let mut e = PartnerLighthousePrograms::default();
        assert!(
            e.create_deployment(sample_deployment("d1", "missing"), &trace())
                .is_err()
        );
    }

    #[test]
    fn create_empty_deployment_id_rejected_without_count_drift() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        let before_audit_len = e.audit_log().len();

        let err = e
            .create_deployment(sample_deployment("", "p1"), "trace-empty-deployment")
            .expect_err("empty deployment id should be rejected");

        assert!(err.contains("deployment id"));
        assert!(e.deployments().is_empty());
        assert_eq!(e.partners()["p1"].deployment_count, 0);
        assert_eq!(e.audit_log().len(), before_audit_len);
    }

    #[test]
    fn create_whitespace_deployment_description_rejected_without_count_drift() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        let before_audit_len = e.audit_log().len();
        let mut deployment = sample_deployment("d-blank-description", "p1");
        deployment.description = " \n\t ".to_string();

        let err = e
            .create_deployment(deployment, "trace-blank-deployment-description")
            .expect_err("blank deployment description should be rejected");

        assert!(err.contains("description"));
        assert!(e.deployments().is_empty());
        assert_eq!(e.partners()["p1"].deployment_count, 0);
        assert_eq!(e.audit_log().len(), before_audit_len);
    }

    #[test]
    fn duplicate_deployment_rejected_without_count_drift() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();

        let err = e
            .create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap_err();
        assert!(err.contains("duplicate deployment"));
        assert_eq!(e.partners()["p1"].deployment_count, 1);
        assert_eq!(e.deployments().len(), 1);

        let codes: Vec<&str> = e
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::PLP_ERR_DUPLICATE_DEPLOYMENT));
    }

    #[test]
    fn record_outcome_ok() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        assert!(
            e.record_outcome(sample_outcome("o1", "d1"), &trace())
                .is_ok()
        );
    }

    #[test]
    fn outcome_missing_deployment() {
        let mut e = PartnerLighthousePrograms::default();
        assert!(
            e.record_outcome(sample_outcome("o1", "missing"), &trace())
                .is_err()
        );
    }

    #[test]
    fn record_empty_outcome_id_rejected_without_audit() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        let before_audit_len = e.audit_log().len();

        let err = e
            .record_outcome(sample_outcome("", "d1"), "trace-empty-outcome")
            .expect_err("empty outcome id should be rejected");

        assert!(err.contains("outcome id"));
        assert!(e.outcomes().is_empty());
        assert_eq!(e.partners()["p1"].outcome_count, 0);
        assert_eq!(e.audit_log().len(), before_audit_len);
    }

    #[test]
    fn record_whitespace_metric_name_rejected_without_count_drift() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        let before_audit_len = e.audit_log().len();
        let mut outcome = sample_outcome("o-blank-metric", "d1");
        outcome.metric_name = " \n\t ".to_string();

        let err = e
            .record_outcome(outcome, "trace-blank-metric")
            .expect_err("blank metric name should be rejected");

        assert!(err.contains("metric name"));
        assert!(e.outcomes().is_empty());
        assert_eq!(e.partners()["p1"].outcome_count, 0);
        assert_eq!(e.audit_log().len(), before_audit_len);
    }

    #[test]
    fn record_whitespace_evidence_ref_rejected_without_count_drift() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        let before_audit_len = e.audit_log().len();
        let mut outcome = sample_outcome("o-blank-evidence", "d1");
        outcome.evidence_ref = " \n\t ".to_string();

        let err = e
            .record_outcome(outcome, "trace-blank-evidence-ref")
            .expect_err("blank evidence ref should be rejected");

        assert!(err.contains("evidence ref"));
        assert!(e.outcomes().is_empty());
        assert_eq!(e.partners()["p1"].outcome_count, 0);
        assert_eq!(e.audit_log().len(), before_audit_len);
    }

    #[test]
    fn outcome_increments_count() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        e.record_outcome(sample_outcome("o1", "d1"), &trace())
            .unwrap();
        assert_eq!(e.partners()["p1"].outcome_count, 1);
    }

    #[test]
    fn duplicate_outcome_rejected_without_count_drift() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        e.record_outcome(sample_outcome("o1", "d1"), &trace())
            .unwrap();

        let err = e
            .record_outcome(sample_outcome("o1", "d1"), &trace())
            .unwrap_err();
        assert!(err.contains("duplicate outcome"));
        assert_eq!(e.partners()["p1"].outcome_count, 1);
        assert_eq!(e.outcomes().len(), 1);

        let codes: Vec<&str> = e
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::PLP_ERR_DUPLICATE_OUTCOME));
    }

    #[test]
    fn promote_insufficient_outcomes() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        assert!(e.promote_partner("p1", &trace()).is_err());
    }

    #[test]
    fn promote_with_outcomes() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d1", "p1"), &trace())
            .unwrap();
        for i in 0..MIN_OUTCOMES_FOR_PROMOTION {
            e.record_outcome(sample_outcome(&format!("o{i}"), "d1"), &trace())
                .unwrap();
        }
        let new_tier = e.promote_partner("p1", &trace()).unwrap();
        assert_eq!(new_tier, PartnerTier::Pilot);
    }

    #[test]
    fn generate_funnel_empty() {
        let mut e = PartnerLighthousePrograms::default();
        let f = e.generate_funnel(&trace());
        assert_eq!(f.total_partners, 0);
        assert_eq!(f.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn funnel_tracks_tiers() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        let f = e.generate_funnel(&trace());
        assert!(f.partners_by_tier.contains_key("prospect"));
    }

    #[test]
    fn funnel_hash_deterministic() {
        let mut e1 = PartnerLighthousePrograms::default();
        let mut e2 = PartnerLighthousePrograms::default();
        assert_eq!(
            e1.generate_funnel(&trace()).content_hash,
            e2.generate_funnel(&trace()).content_hash
        );
    }

    #[test]
    fn audit_populated() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        assert!(!e.audit_log().is_empty());
    }

    #[test]
    fn audit_has_codes() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        let codes: Vec<&str> = e
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::PLP_PARTNER_ENROLLED));
    }

    #[test]
    fn export_jsonl() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        let jsonl = e.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn default_version() {
        let e = PartnerLighthousePrograms::default();
        assert_eq!(e.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn enroll_sets_timestamp() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        assert!(!e.partners()["p1"].enrolled_at.is_empty());
    }

    // === bd-3sfrf: funnel hash coverage regression ===

    #[test]
    fn funnel_hash_changes_with_tier_distribution() {
        // Same total partners but different tier distributions
        // must produce different content hashes.
        let mut e1 = PartnerLighthousePrograms::default();
        let mut e2 = PartnerLighthousePrograms::default();
        e1.enroll_partner(sample_partner("p1"), &trace()).unwrap();
        let mut p2 = sample_partner("p1");
        p2.tier = PartnerTier::Strategic;
        e2.enroll_partner(p2, &trace()).unwrap();
        let f1 = e1.generate_funnel(&trace());
        let f2 = e2.generate_funnel(&trace());
        assert_eq!(f1.total_partners, f2.total_partners);
        assert_ne!(
            f1.content_hash, f2.content_hash,
            "Different tier distributions must produce different funnel hash"
        );
    }

    #[test]
    fn push_bounded_zero_capacity_discards_stale_entries() {
        let mut items = vec!["old-deployment", "old-outcome"];

        push_bounded(&mut items, "new-entry", 0);

        assert!(
            items.is_empty(),
            "zero-capacity bounded buffers must not retain stale program records"
        );
    }

    #[test]
    fn missing_partner_deployment_does_not_emit_audit_or_store_deployment() {
        let mut e = PartnerLighthousePrograms::default();

        let err = e
            .create_deployment(sample_deployment("d-missing", "missing-partner"), &trace())
            .expect_err("deployment for missing partner must fail");

        assert!(err.contains("missing-partner"));
        assert!(e.deployments().is_empty());
        assert!(
            e.audit_log().is_empty(),
            "missing partner should fail before deployment audit records"
        );
    }

    #[test]
    fn nan_metric_value_rejected_without_recording_outcome() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p-nan"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d-nan", "p-nan"), &trace())
            .unwrap();
        let audit_count_before = e.audit_log().len();
        let mut outcome = sample_outcome("o-nan", "d-nan");
        outcome.metric_value = f64::NAN;

        let err = e
            .record_outcome(outcome, &trace())
            .expect_err("NaN metrics must be rejected");

        assert!(err.contains("finite"));
        assert!(e.outcomes().is_empty());
        assert_eq!(e.partners()["p-nan"].outcome_count, 0);
        assert_eq!(
            e.audit_log().len(),
            audit_count_before,
            "non-finite metrics must not append outcome audit records"
        );
    }

    #[test]
    fn infinite_metric_value_rejected_without_partner_count_drift() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p-inf"), &trace()).unwrap();
        e.create_deployment(sample_deployment("d-inf", "p-inf"), &trace())
            .unwrap();
        let mut outcome = sample_outcome("o-inf", "d-inf");
        outcome.metric_value = f64::INFINITY;

        let err = e
            .record_outcome(outcome, &trace())
            .expect_err("infinite metrics must be rejected");

        assert!(err.contains("finite"));
        assert_eq!(e.partners()["p-inf"].outcome_count, 0);
        assert!(
            e.audit_log()
                .iter()
                .all(|record| record.event_code != event_codes::PLP_OUTCOME_RECORDED),
            "rejected infinite metrics must not be reported as recorded"
        );
    }

    #[test]
    fn missing_deployment_outcome_does_not_update_partner_counts() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p-no-dep"), &trace())
            .unwrap();
        let audit_count_before = e.audit_log().len();

        let err = e
            .record_outcome(sample_outcome("o-no-dep", "missing-deployment"), &trace())
            .expect_err("missing deployment must reject outcomes");

        assert!(err.contains("missing-deployment"));
        assert!(e.outcomes().is_empty());
        assert_eq!(e.partners()["p-no-dep"].outcome_count, 0);
        assert_eq!(e.audit_log().len(), audit_count_before);
    }

    #[test]
    fn promote_missing_partner_does_not_log_insufficient_outcomes() {
        let mut e = PartnerLighthousePrograms::default();

        let err = e
            .promote_partner("missing-partner", &trace())
            .expect_err("missing partner must fail");

        assert!(err.contains("missing-partner"));
        assert!(
            e.audit_log().is_empty(),
            "missing partner must fail before insufficient-outcome audit logging"
        );
    }

    #[test]
    fn flagship_partner_with_enough_outcomes_cannot_promote() {
        let mut e = PartnerLighthousePrograms::default();
        e.enroll_partner(sample_partner("p-flagship"), &trace())
            .unwrap();
        {
            let partner = e
                .partners
                .get_mut("p-flagship")
                .expect("partner should exist");
            partner.tier = PartnerTier::Flagship;
            partner.outcome_count = MIN_OUTCOMES_FOR_PROMOTION;
        }

        let err = e
            .promote_partner("p-flagship", &trace())
            .expect_err("flagship is already the final tier");

        assert!(err.contains("highest tier"));
        assert_eq!(e.partners()["p-flagship"].tier, PartnerTier::Flagship);
        assert_eq!(
            e.partners()["p-flagship"].outcome_count,
            MIN_OUTCOMES_FOR_PROMOTION
        );
        assert!(
            e.audit_log()
                .iter()
                .all(|record| record.event_code != event_codes::PLP_TIER_PROMOTED),
            "failed final-tier promotion must not emit promotion audit records"
        );
    }

    #[test]
    fn empty_audit_log_exports_empty_jsonl() {
        let e = PartnerLighthousePrograms::default();

        assert_eq!(e.export_audit_log_jsonl().unwrap(), "");
    }
}
