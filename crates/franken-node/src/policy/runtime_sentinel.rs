//! Canonical `RuntimeSentinelObservation` schema and deterministic multi-signal
//! ingestion for the Bayesian Runtime Sentinel (bd-f5b04.3.1.1).
//!
//! The Sentinel consumes a stream of typed malice/health signals about an
//! extension and turns them into an anytime-valid posterior plus an
//! expected-loss containment action. Before any of that math runs, the signal
//! stream itself must be a *canonical, schema-versioned, replay-deterministic*
//! record: the e-value the Sentinel computes is only re-derivable by the
//! Verifier SDK if every node ingests exactly the same bytes in exactly the
//! same order.
//!
//! This module owns that contract. It deliberately keeps every externally
//! serialized magnitude in integer basis points so the canonical serializer's
//! `INV-CAN-NO-FLOAT` contract holds (no float non-determinism leaks into the
//! evidence log). Signals inside an observation are sorted by a total canonical
//! key, observations inside the log are keyed by `(epoch, sequence,
//! extension_id)` in a `BTreeMap`, and the log exposes a chained digest so a
//! verifier can prove it replayed the identical evidence stream.
//!
//! What this module is NOT: it does not compute the posterior, run the
//! mixture-SPRT, or choose an action. Those live in the e-process core
//! (bd-f5b04.3.1.2) and the decision/loss policy, and consume the canonical
//! observations produced here.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ed25519_dalek::SigningKey;

use crate::connector::canonical_serializer::canonical_bytes;
use crate::observability::evidence_ledger::{DecisionKind, EvidenceEntry, sign_evidence_entry};
use crate::security::conformal::{ConformalRiskSet, LABEL_POSITIVE};
use crate::security::quarantine_controller::ControlAction;

use super::hardening_state_machine::HardeningLevel;

/// Schema version for a single canonical observation record.
pub const RUNTIME_SENTINEL_OBSERVATION_SCHEMA_VERSION: &str = "runtime_sentinel.observation.v1";

/// Domain separator prepended before the canonical bytes when hashing an
/// observation. Distinct from every other trust-artifact domain so an
/// observation hash can never be confused with another canonical payload.
const OBSERVATION_HASH_DOMAIN: &[u8] = b"runtime_sentinel_observation_v1:";

/// Domain separator for the chained log digest.
const LOG_DIGEST_DOMAIN: &[u8] = b"runtime_sentinel_observation_log_v1:";

/// Upper bound (inclusive) for a signal magnitude expressed in basis points.
pub const SENTINEL_SIGNAL_MAX_MAGNITUDE_BP: u16 = 10_000;

/// Maximum number of distinct signals retained per observation. Bounded to keep
/// the canonical payload size deterministic under adversarial flooding.
pub const MAX_SIGNALS_PER_OBSERVATION: usize = 256;

/// Maximum number of observations retained in a single in-memory log.
pub const MAX_OBSERVATIONS_PER_LOG: usize = 100_000;

/// Schema version for Runtime Sentinel expected-loss decisions.
pub const RUNTIME_SENTINEL_DECISION_SCHEMA_VERSION: &str = "runtime_sentinel.decision.v1";

/// Runtime Sentinel selected an expected-loss containment action.
pub const FN_SENTINEL_EXPECTED_LOSS_SELECTED: &str = "FN-SENTINEL-007";

/// Runtime Sentinel produced a signed escalation receipt payload.
pub const FN_SENTINEL_ESCALATION_RECEIPT_SIGNED: &str = "FN-SENTINEL-008";

const PROBABILITY_SCALE_BP: u16 = 10_000;
const PPM_PER_BP: u64 = 100;

/// Errors raised while constructing or ingesting Sentinel observations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SentinelObservationError {
    /// The extension identifier was empty.
    #[error("runtime sentinel observation requires a non-empty extension_id")]
    EmptyExtensionId,
    /// A canonical string field contained a control or null character, which
    /// would make canonical framing ambiguous.
    #[error("field `{field}` contains a forbidden control character")]
    ForbiddenControlChar { field: &'static str },
    /// A signal magnitude exceeded the basis-point ceiling.
    #[error("signal from `{signal_source}` has magnitude {magnitude_bp} bp > {max} bp")]
    MagnitudeOutOfRange {
        signal_source: String,
        magnitude_bp: u16,
        max: u16,
    },
    /// More than [`MAX_SIGNALS_PER_OBSERVATION`] distinct signals were supplied.
    #[error("observation carries {count} signals > max {max}")]
    TooManySignals { count: usize, max: usize },
    /// The same `(epoch, sequence, extension_id)` key was ingested twice with
    /// differing canonical bytes — a replay-determinism violation.
    #[error(
        "conflicting observation for extension `{extension_id}` at epoch {epoch} sequence {sequence}"
    )]
    ConflictingObservation {
        extension_id: String,
        epoch: u64,
        sequence: u64,
    },
}

/// Errors raised while constructing expected-loss Sentinel decisions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SentinelDecisionError {
    #[error("sentinel decision field `{field}` must not be empty")]
    EmptyField { field: &'static str },
    #[error("sentinel decision field `{field}` contains a forbidden control character")]
    ForbiddenControlChar { field: &'static str },
    #[error("probability field `{field}` has {value} bp > 10000 bp")]
    ProbabilityOutOfRange { field: &'static str, value: u16 },
    #[error("expected-loss matrix must contain one row for every containment ladder action")]
    IncompleteLossMatrix,
    #[error("duplicate expected-loss row for action `{action}`")]
    DuplicateAction { action: &'static str },
    #[error("expected-loss value for action `{action}` must be finite in basis points")]
    InvalidLoss { action: &'static str },
    #[error("unsupported Sentinel decision schema version `{version}`")]
    InvalidSchemaVersion { version: String },
    #[error("hash field `{field}` must be sha256:<64 lowercase-or-uppercase hex chars>")]
    InvalidHash { field: &'static str },
    #[error("evidence_count must be positive for a signed Sentinel decision")]
    EmptyEvidence,
    #[error("failed to serialize Sentinel decision payload: {0}")]
    PayloadSerialization(String),
}

/// The category of evidence a [`SentinelSignal`] carries.
///
/// The discriminant ordering here is the canonical rank used when sorting
/// signals within an observation; do not reorder existing variants without
/// bumping [`RUNTIME_SENTINEL_OBSERVATION_SCHEMA_VERSION`], because it would
/// change canonical bytes for historical evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelSignalKind {
    /// BPET phenotype / evolution-risk drift for the extension.
    BpetPhenotypeDrift,
    /// Camouflage hint (e.g. `PhaseShift`, `GradualCreep`) from trajectory gaming.
    CamouflageHint,
    /// DGIS dependency-graph topology / SPOF risk.
    DgisTopologyRisk,
    /// ATC (adjacent-threat-context) prior contribution.
    AtcPrior,
    /// A capability/host-effect invocation observed for the extension.
    CapabilityInvocation,
    /// A policy violation (guardrail block, ambient-authority denial, etc.).
    PolicyViolation,
    /// A module-resolution anomaly surfaced by the admission gate.
    ModuleResolutionAnomaly,
    /// Replay divergence between recorded and re-executed behavior.
    ReplayDivergence,
    /// Revocation-freshness staleness for the extension's trust material.
    RevocationFreshness,
    /// Fleet incident state (quarantine / revocation) touching the extension.
    FleetIncidentState,
    /// Effect-receipt anomaly from the Phase 1 effect ledger.
    EffectReceiptAnomaly,
}

impl SentinelSignalKind {
    /// Stable canonical tag for the signal kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BpetPhenotypeDrift => "bpet_phenotype_drift",
            Self::CamouflageHint => "camouflage_hint",
            Self::DgisTopologyRisk => "dgis_topology_risk",
            Self::AtcPrior => "atc_prior",
            Self::CapabilityInvocation => "capability_invocation",
            Self::PolicyViolation => "policy_violation",
            Self::ModuleResolutionAnomaly => "module_resolution_anomaly",
            Self::ReplayDivergence => "replay_divergence",
            Self::RevocationFreshness => "revocation_freshness",
            Self::FleetIncidentState => "fleet_incident_state",
            Self::EffectReceiptAnomaly => "effect_receipt_anomaly",
        }
    }

    /// Canonical sort rank (matches declaration order).
    #[must_use]
    pub const fn canonical_rank(self) -> u8 {
        match self {
            Self::BpetPhenotypeDrift => 0,
            Self::CamouflageHint => 1,
            Self::DgisTopologyRisk => 2,
            Self::AtcPrior => 3,
            Self::CapabilityInvocation => 4,
            Self::PolicyViolation => 5,
            Self::ModuleResolutionAnomaly => 6,
            Self::ReplayDivergence => 7,
            Self::RevocationFreshness => 8,
            Self::FleetIncidentState => 9,
            Self::EffectReceiptAnomaly => 10,
        }
    }
}

/// A single typed evidence signal about an extension at one observation point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelSignal {
    /// The evidence category.
    pub kind: SentinelSignalKind,
    /// The producing subsystem / instance identifier (e.g. `bpet:evolution`).
    pub source: String,
    /// Signal strength in integer basis points (`0..=10000`). Integer basis
    /// points avoid float non-determinism in the canonical evidence log.
    pub magnitude_bp: u16,
    /// Canonical descriptor of the signal. Must NOT carry raw secret bytes —
    /// only salted commitments / canonical descriptors per the lineage rules.
    pub detail: String,
}

impl SentinelSignal {
    /// Construct a validated signal.
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] if the magnitude is out of range or
    /// a string field carries a forbidden control character.
    pub fn new(
        kind: SentinelSignalKind,
        source: impl Into<String>,
        magnitude_bp: u16,
        detail: impl Into<String>,
    ) -> Result<Self, SentinelObservationError> {
        let signal = Self {
            kind,
            source: source.into(),
            magnitude_bp,
            detail: detail.into(),
        };
        signal.validate()?;
        Ok(signal)
    }

    /// Validate field invariants.
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] on an out-of-range magnitude or a
    /// control character in `source`/`detail`.
    pub fn validate(&self) -> Result<(), SentinelObservationError> {
        if self.magnitude_bp > SENTINEL_SIGNAL_MAX_MAGNITUDE_BP {
            return Err(SentinelObservationError::MagnitudeOutOfRange {
                signal_source: self.source.clone(),
                magnitude_bp: self.magnitude_bp,
                max: SENTINEL_SIGNAL_MAX_MAGNITUDE_BP,
            });
        }
        reject_control_chars("signal.source", &self.source)?;
        reject_control_chars("signal.detail", &self.detail)?;
        Ok(())
    }

    /// Total canonical sort key: `(kind rank, source, detail, magnitude)`.
    fn canonical_sort_key(&self) -> (u8, &str, &str, u16) {
        (
            self.kind.canonical_rank(),
            self.source.as_str(),
            self.detail.as_str(),
            self.magnitude_bp,
        )
    }
}

/// Runtime Sentinel containment ladder ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelContainmentAction {
    Allow,
    Harden,
    SafeMode,
    Quarantine,
}

impl SentinelContainmentAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Harden => "harden",
            Self::SafeMode => "safe_mode",
            Self::Quarantine => "quarantine",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Harden => 1,
            Self::SafeMode => 2,
            Self::Quarantine => 3,
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Allow, Self::Harden, Self::SafeMode, Self::Quarantine]
    }

    #[must_use]
    pub const fn requires_safe_mode(self) -> bool {
        matches!(self, Self::SafeMode | Self::Quarantine)
    }

    #[must_use]
    pub const fn hardening_floor(self) -> Option<HardeningLevel> {
        match self {
            Self::Allow => None,
            Self::Harden => Some(HardeningLevel::Enhanced),
            Self::SafeMode => Some(HardeningLevel::Maximum),
            Self::Quarantine => Some(HardeningLevel::Critical),
        }
    }

    #[must_use]
    pub const fn quarantine_control_action(self) -> Option<ControlAction> {
        match self {
            Self::Allow => None,
            Self::Harden => Some(ControlAction::Throttle),
            Self::SafeMode => Some(ControlAction::Isolate),
            Self::Quarantine => Some(ControlAction::Quarantine),
        }
    }

    #[must_use]
    pub const fn decision_kind(self) -> DecisionKind {
        match self {
            Self::Allow => DecisionKind::Admit,
            Self::Harden | Self::SafeMode => DecisionKind::Escalate,
            Self::Quarantine => DecisionKind::Quarantine,
        }
    }
}

/// One action row in the Sentinel expected-loss matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelActionLoss {
    pub action: SentinelContainmentAction,
    pub benign_loss_bp: u32,
    pub malicious_loss_bp: u32,
}

impl SentinelActionLoss {
    #[must_use]
    pub const fn new(
        action: SentinelContainmentAction,
        benign_loss_bp: u32,
        malicious_loss_bp: u32,
    ) -> Self {
        Self {
            action,
            benign_loss_bp,
            malicious_loss_bp,
        }
    }
}

/// Expected-loss score for one containment action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelActionScore {
    pub action: SentinelContainmentAction,
    pub expected_loss_bp: u64,
    pub benign_component_bp: u64,
    pub malicious_component_bp: u64,
    pub dominant_outcome: String,
}

/// Inputs committed into a Runtime Sentinel action receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelDecisionInput {
    pub principal_id: String,
    pub trace_id: String,
    pub epoch: u64,
    pub posterior_malice_bp: u16,
    pub e_value_ppm: u64,
    pub false_alarm_bound_ppm: u64,
    pub evidence_count: u64,
    pub evidence_hash: String,
    pub observation_log_digest: String,
}

impl SentinelDecisionInput {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        principal_id: impl Into<String>,
        trace_id: impl Into<String>,
        epoch: u64,
        posterior_malice_bp: u16,
        e_value_ppm: u64,
        false_alarm_bound_ppm: u64,
        evidence_count: u64,
        evidence_hash: impl Into<String>,
        observation_log_digest: impl Into<String>,
    ) -> Self {
        Self {
            principal_id: principal_id.into(),
            trace_id: trace_id.into(),
            epoch,
            posterior_malice_bp,
            e_value_ppm,
            false_alarm_bound_ppm,
            evidence_count,
            evidence_hash: evidence_hash.into(),
            observation_log_digest: observation_log_digest.into(),
        }
    }

    fn validate(&self) -> Result<(), SentinelDecisionError> {
        reject_decision_string("principal_id", &self.principal_id)?;
        reject_decision_string("trace_id", &self.trace_id)?;
        if self.posterior_malice_bp > PROBABILITY_SCALE_BP {
            return Err(SentinelDecisionError::ProbabilityOutOfRange {
                field: "posterior_malice_bp",
                value: self.posterior_malice_bp,
            });
        }
        if self.evidence_count == 0 {
            return Err(SentinelDecisionError::EmptyEvidence);
        }
        validate_hash("evidence_hash", &self.evidence_hash)?;
        validate_hash("observation_log_digest", &self.observation_log_digest)?;
        Ok(())
    }
}

/// Counterfactual threshold note committed into an escalation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelCounterfactualReceipt {
    pub observation_ref: String,
    pub prior_action: SentinelContainmentAction,
    pub posterior_action: SentinelContainmentAction,
    pub prior_e_value_ppm: u64,
    pub posterior_e_value_ppm: u64,
    pub threshold_action: SentinelContainmentAction,
    pub rationale: String,
}

impl SentinelCounterfactualReceipt {
    #[must_use]
    pub fn threshold_crossing(
        observation_ref: impl Into<String>,
        prior_action: SentinelContainmentAction,
        posterior_action: SentinelContainmentAction,
        prior_e_value_ppm: u64,
        posterior_e_value_ppm: u64,
        threshold_action: SentinelContainmentAction,
    ) -> Self {
        let observation_ref = observation_ref.into();
        Self {
            rationale: format!(
                "observation_ref={observation_ref} moved action from {} to {} at threshold {}",
                prior_action.as_str(),
                posterior_action.as_str(),
                threshold_action.as_str()
            ),
            observation_ref,
            prior_action,
            posterior_action,
            prior_e_value_ppm,
            posterior_e_value_ppm,
            threshold_action,
        }
    }
}

/// Deterministic expected-loss containment policy for the Runtime Sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelExpectedLossPolicy {
    pub schema_version: String,
    pub guardrail_floor: SentinelContainmentAction,
    pub losses: Vec<SentinelActionLoss>,
}

impl SentinelExpectedLossPolicy {
    /// Construct a schema-versioned expected-loss policy over the full ladder.
    ///
    /// # Errors
    /// Returns [`SentinelDecisionError`] when the loss matrix is incomplete or
    /// contains duplicate action rows.
    pub fn new(
        losses: Vec<SentinelActionLoss>,
        guardrail_floor: SentinelContainmentAction,
    ) -> Result<Self, SentinelDecisionError> {
        validate_loss_rows(&losses)?;
        Ok(Self {
            schema_version: RUNTIME_SENTINEL_DECISION_SCHEMA_VERSION.to_string(),
            guardrail_floor,
            losses,
        })
    }

    /// Select the minimum expected-loss action after applying the guardrail floor.
    ///
    /// # Errors
    /// Returns [`SentinelDecisionError`] when the policy schema is unsupported,
    /// the loss matrix is invalid, or the decision input fails validation.
    pub fn decide(
        &self,
        input: SentinelDecisionInput,
        counterfactual: Option<SentinelCounterfactualReceipt>,
    ) -> Result<SentinelActionDecision, SentinelDecisionError> {
        if self.schema_version != RUNTIME_SENTINEL_DECISION_SCHEMA_VERSION {
            return Err(SentinelDecisionError::InvalidSchemaVersion {
                version: self.schema_version.clone(),
            });
        }
        validate_loss_rows(&self.losses)?;
        input.validate()?;

        let mut scores = self
            .losses
            .iter()
            .map(|row| score_loss_row(row, input.posterior_malice_bp))
            .collect::<Result<Vec<_>, _>>()?;
        scores.sort_by(|left, right| {
            left.expected_loss_bp
                .cmp(&right.expected_loss_bp)
                .then_with(|| left.action.rank().cmp(&right.action.rank()))
        });

        let raw_selected_action = scores
            .first()
            .map(|score| score.action)
            .ok_or(SentinelDecisionError::IncompleteLossMatrix)?;
        let selected_action = raw_selected_action.max(self.guardrail_floor);
        let selected_score = scores
            .iter()
            .find(|score| score.action == selected_action)
            .cloned()
            .ok_or(SentinelDecisionError::IncompleteLossMatrix)?;
        let guardrail_applied = selected_action != raw_selected_action;
        let decision_id = sentinel_decision_id(&input, selected_action);
        let confidence_bp = confidence_bp_from_false_alarm(input.false_alarm_bound_ppm);
        let rationale = format!(
            "selected_action={};raw_argmin={};posterior_malice_bp={};e_value_ppm={};false_alarm_bound_ppm={};guardrail_floor={};guardrail_applied={};dominant_outcome={}",
            selected_action.as_str(),
            raw_selected_action.as_str(),
            input.posterior_malice_bp,
            input.e_value_ppm,
            input.false_alarm_bound_ppm,
            self.guardrail_floor.as_str(),
            guardrail_applied,
            selected_score.dominant_outcome
        );

        Ok(SentinelActionDecision {
            schema_version: RUNTIME_SENTINEL_DECISION_SCHEMA_VERSION.to_string(),
            event_code: FN_SENTINEL_EXPECTED_LOSS_SELECTED.to_string(),
            decision_id,
            principal_id: input.principal_id,
            trace_id: input.trace_id,
            epoch: input.epoch,
            posterior_malice_bp: input.posterior_malice_bp,
            e_value_ppm: input.e_value_ppm,
            false_alarm_bound_ppm: input.false_alarm_bound_ppm,
            evidence_count: input.evidence_count,
            evidence_hash: input.evidence_hash,
            observation_log_digest: input.observation_log_digest,
            raw_selected_action,
            guardrail_floor: self.guardrail_floor,
            guardrail_applied,
            selected_action,
            selected_expected_loss_bp: selected_score.expected_loss_bp,
            confidence_bp,
            scores,
            rationale,
            counterfactual,
        })
    }
}

impl Default for SentinelExpectedLossPolicy {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_SENTINEL_DECISION_SCHEMA_VERSION.to_string(),
            guardrail_floor: SentinelContainmentAction::Allow,
            losses: vec![
                SentinelActionLoss::new(SentinelContainmentAction::Allow, 0, 10_000),
                SentinelActionLoss::new(SentinelContainmentAction::Harden, 800, 5_200),
                SentinelActionLoss::new(SentinelContainmentAction::SafeMode, 2_500, 2_200),
                SentinelActionLoss::new(SentinelContainmentAction::Quarantine, 7_000, 400),
            ],
        }
    }
}

/// Receipt-ready decision selected by [`SentinelExpectedLossPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelActionDecision {
    pub schema_version: String,
    pub event_code: String,
    pub decision_id: String,
    pub principal_id: String,
    pub trace_id: String,
    pub epoch: u64,
    pub posterior_malice_bp: u16,
    pub e_value_ppm: u64,
    pub false_alarm_bound_ppm: u64,
    pub evidence_count: u64,
    pub evidence_hash: String,
    pub observation_log_digest: String,
    pub raw_selected_action: SentinelContainmentAction,
    pub guardrail_floor: SentinelContainmentAction,
    pub guardrail_applied: bool,
    pub selected_action: SentinelContainmentAction,
    pub selected_expected_loss_bp: u64,
    pub confidence_bp: u16,
    pub scores: Vec<SentinelActionScore>,
    pub rationale: String,
    pub counterfactual: Option<SentinelCounterfactualReceipt>,
}

impl SentinelActionDecision {
    /// Sign this Sentinel action decision as an evidence-ledger entry.
    ///
    /// # Errors
    /// Returns [`SentinelDecisionError`] if the JSON payload cannot be serialized.
    pub fn to_signed_evidence_entry(
        &self,
        decision_time: impl Into<String>,
        timestamp_ms: u64,
        signing_key: &SigningKey,
    ) -> Result<EvidenceEntry, SentinelDecisionError> {
        let payload = serde_json::json!({
            "event_code": FN_SENTINEL_ESCALATION_RECEIPT_SIGNED,
            "decision": self,
        });
        let mut entry = EvidenceEntry {
            schema_version: self.schema_version.clone(),
            entry_id: None,
            decision_id: self.decision_id.clone(),
            decision_kind: self.selected_action.decision_kind(),
            decision_time: decision_time.into(),
            timestamp_ms,
            trace_id: self.trace_id.clone(),
            epoch_id: self.epoch,
            payload,
            size_bytes: 0,
            signature: String::new(),
            prev_entry_hash: String::new(),
        };
        serde_json::to_vec(&entry.payload)
            .map_err(|err| SentinelDecisionError::PayloadSerialization(err.to_string()))?;
        sign_evidence_entry(&mut entry, signing_key);
        Ok(entry)
    }
}

/// Convert a conformal risk set into a Sentinel likelihood signal.
///
/// The magnitude is the calibrated score only when the positive label remains
/// inside the conformal set; otherwise the Sentinel receives a zero-likelihood
/// signal while the detail string still records the audited quantile context.
pub fn sentinel_signal_from_conformal_risk_set(
    kind: SentinelSignalKind,
    source: impl Into<String>,
    risk_set: &ConformalRiskSet,
) -> Result<SentinelSignal, SentinelObservationError> {
    SentinelSignal::new(
        kind,
        source,
        conformal_positive_likelihood_bp(risk_set),
        conformal_signal_detail(risk_set),
    )
}

/// Push a conformal risk-set signal onto an observation.
///
/// This is a convenience wrapper for integration surfaces that already own the
/// observation lifecycle and only need to add calibrated BPET/DGIS likelihoods.
pub fn push_conformal_risk_set_signal(
    observation: &mut RuntimeSentinelObservation,
    kind: SentinelSignalKind,
    source: impl Into<String>,
    risk_set: &ConformalRiskSet,
) -> Result<(), SentinelObservationError> {
    let signal = sentinel_signal_from_conformal_risk_set(kind, source, risk_set)?;
    observation.push_signal(signal)
}

fn conformal_positive_likelihood_bp(risk_set: &ConformalRiskSet) -> u16 {
    if risk_set
        .included_labels
        .iter()
        .any(|label| label == LABEL_POSITIVE)
    {
        risk_set.score_bp
    } else {
        0
    }
}

fn conformal_signal_detail(risk_set: &ConformalRiskSet) -> String {
    let labels = if risk_set.included_labels.is_empty() {
        "none".to_string()
    } else {
        risk_set.included_labels.join("+")
    };
    format!(
        "sample_id={};risk_class={};score_bp={};quantile_bp={};labels={}",
        risk_set.sample_id, risk_set.risk_class, risk_set.score_bp, risk_set.quantile_bp, labels
    )
}

/// A canonical, schema-versioned record of all Sentinel evidence observed for a
/// single extension at one `(epoch, sequence)` point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSentinelObservation {
    /// Schema version tag — always [`RUNTIME_SENTINEL_OBSERVATION_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Subject extension identifier.
    pub extension_id: String,
    /// Control epoch the observation belongs to.
    pub epoch: u64,
    /// Monotonic sequence number within the epoch (deterministic replay order).
    pub sequence: u64,
    /// Deterministic RFC-3339 observation timestamp supplied by the caller's
    /// canonical clock (never `SystemNow` inside this module).
    pub observed_at: String,
    /// The evidence signals; kept in canonical order via [`Self::canonicalize`].
    pub signals: Vec<SentinelSignal>,
}

impl RuntimeSentinelObservation {
    /// Construct an empty observation for the given subject/point.
    #[must_use]
    pub fn new(
        extension_id: impl Into<String>,
        epoch: u64,
        sequence: u64,
        observed_at: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: RUNTIME_SENTINEL_OBSERVATION_SCHEMA_VERSION.to_string(),
            extension_id: extension_id.into(),
            epoch,
            sequence,
            observed_at: observed_at.into(),
            signals: Vec::new(),
        }
    }

    /// Push a validated signal, enforcing the per-observation cap with the
    /// shared bounded-push helper.
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] if the signal fails validation.
    pub fn push_signal(&mut self, signal: SentinelSignal) -> Result<(), SentinelObservationError> {
        signal.validate()?;
        // Bounded push (drop-oldest on overflow), mirroring the shared
        // `push_bounded` invariant without depending on the `advanced-features`
        // `encoding` module that hosts it.
        if self.signals.len() >= MAX_SIGNALS_PER_OBSERVATION {
            let overflow = self
                .signals
                .len()
                .saturating_sub(MAX_SIGNALS_PER_OBSERVATION)
                .saturating_add(1);
            self.signals.drain(0..overflow.min(self.signals.len()));
        }
        self.signals.push(signal);
        Ok(())
    }

    /// Builder-style variant of [`Self::push_signal`].
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] if the signal fails validation.
    pub fn with_signal(mut self, signal: SentinelSignal) -> Result<Self, SentinelObservationError> {
        self.push_signal(signal)?;
        Ok(self)
    }

    /// Validate the whole observation: subject, framing, signal bounds, and each
    /// signal's invariants.
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] on the first violation found.
    pub fn validate(&self) -> Result<(), SentinelObservationError> {
        if self.extension_id.is_empty() {
            return Err(SentinelObservationError::EmptyExtensionId);
        }
        reject_control_chars("extension_id", &self.extension_id)?;
        reject_control_chars("observed_at", &self.observed_at)?;
        if self.signals.len() > MAX_SIGNALS_PER_OBSERVATION {
            return Err(SentinelObservationError::TooManySignals {
                count: self.signals.len(),
                max: MAX_SIGNALS_PER_OBSERVATION,
            });
        }
        for signal in &self.signals {
            signal.validate()?;
        }
        Ok(())
    }

    /// Sort signals into the total canonical order so identical evidence (in any
    /// insertion order) produces identical canonical bytes.
    pub fn canonicalize(&mut self) {
        self.signals
            .sort_by(|a, b| a.canonical_sort_key().cmp(&b.canonical_sort_key()));
    }

    /// Deterministic ordering key for placing this observation in a log.
    #[must_use]
    pub fn ordering_key(&self) -> (u64, u64, String) {
        (self.epoch, self.sequence, self.extension_id.clone())
    }

    /// Produce the canonical serialized bytes (signals sorted, keys canonical,
    /// no floats). The returned bytes are stable across runs and machines.
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] if validation fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SentinelObservationError> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.canonicalize();
        // serde_json::to_value cannot fail for these plain integer/string types;
        // canonical_bytes then enforces key ordering and the no-float contract.
        let value = serde_json::to_value(&canonical)
            .expect("RuntimeSentinelObservation serializes to a float-free JSON value");
        Ok(canonical_bytes(&value))
    }

    /// SHA-256 (hex) over the domain separator and canonical bytes — the stable
    /// content address the Verifier SDK recomputes.
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] if validation fails.
    pub fn observation_hash(&self) -> Result<String, SentinelObservationError> {
        let bytes = self.to_canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(OBSERVATION_HASH_DOMAIN);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}

/// A deterministic, replay-safe ingestion log of canonical observations.
///
/// Observations are keyed by `(epoch, sequence, extension_id)` in a `BTreeMap`,
/// so iteration order is total and independent of ingestion order. Re-ingesting
/// the identical observation is idempotent; re-ingesting a *different* payload
/// under the same key is rejected as a replay-determinism violation.
#[derive(Debug, Clone, Default)]
pub struct SentinelObservationLog {
    observations: BTreeMap<(u64, u64, String), RuntimeSentinelObservation>,
}

impl SentinelObservationLog {
    /// Create an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct observations retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Whether the log holds no observations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Ingest one observation.
    ///
    /// The observation is validated and canonicalized before storage. If the
    /// same key already holds a byte-identical observation the call is a no-op;
    /// a differing payload under the same key is a [`SentinelObservationError::ConflictingObservation`].
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] on validation failure, a key
    /// conflict, or when the log is already at [`MAX_OBSERVATIONS_PER_LOG`].
    pub fn ingest(
        &mut self,
        mut observation: RuntimeSentinelObservation,
    ) -> Result<(), SentinelObservationError> {
        observation.validate()?;
        observation.canonicalize();
        let key = observation.ordering_key();

        if let Some(existing) = self.observations.get(&key) {
            // Idempotent re-ingest only if canonical bytes match exactly.
            if existing.to_canonical_bytes()? == observation.to_canonical_bytes()? {
                return Ok(());
            }
            return Err(SentinelObservationError::ConflictingObservation {
                extension_id: observation.extension_id,
                epoch: observation.epoch,
                sequence: observation.sequence,
            });
        }

        if self.observations.len() >= MAX_OBSERVATIONS_PER_LOG {
            return Err(SentinelObservationError::TooManySignals {
                count: self.observations.len().saturating_add(1),
                max: MAX_OBSERVATIONS_PER_LOG,
            });
        }

        self.observations.insert(key, observation);
        Ok(())
    }

    /// Observations in canonical replay order.
    #[must_use]
    pub fn ordered(&self) -> Vec<&RuntimeSentinelObservation> {
        self.observations.values().collect()
    }

    /// Chained SHA-256 (hex) digest over every observation hash in canonical
    /// order. A verifier that replays the identical evidence stream recomputes
    /// the same digest; any reorder, omission, or mutation changes it.
    ///
    /// # Errors
    /// Returns [`SentinelObservationError`] if any stored observation fails to
    /// canonicalize.
    pub fn digest(&self) -> Result<String, SentinelObservationError> {
        let mut hasher = Sha256::new();
        hasher.update(LOG_DIGEST_DOMAIN);
        hasher.update((self.observations.len() as u64).to_le_bytes());
        for observation in self.observations.values() {
            let hash = observation.observation_hash()?;
            hasher.update((hash.len() as u64).to_le_bytes());
            hasher.update(hash.as_bytes());
        }
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}

/// Reject control / null characters that would make canonical framing ambiguous.
fn reject_control_chars(field: &'static str, value: &str) -> Result<(), SentinelObservationError> {
    if value.chars().any(|c| c.is_control()) {
        return Err(SentinelObservationError::ForbiddenControlChar { field });
    }
    Ok(())
}

fn reject_decision_string(field: &'static str, value: &str) -> Result<(), SentinelDecisionError> {
    if value.trim().is_empty() {
        return Err(SentinelDecisionError::EmptyField { field });
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(SentinelDecisionError::ForbiddenControlChar { field });
    }
    Ok(())
}

fn validate_hash(field: &'static str, value: &str) -> Result<(), SentinelDecisionError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SentinelDecisionError::InvalidHash { field });
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SentinelDecisionError::InvalidHash { field });
    }
    Ok(())
}

fn validate_loss_rows(losses: &[SentinelActionLoss]) -> Result<(), SentinelDecisionError> {
    if losses.len() != SentinelContainmentAction::all().len() {
        return Err(SentinelDecisionError::IncompleteLossMatrix);
    }

    let mut seen = [false; 4];
    for row in losses {
        let index = usize::from(row.action.rank());
        let Some(slot) = seen.get_mut(index) else {
            return Err(SentinelDecisionError::InvalidLoss {
                action: row.action.as_str(),
            });
        };
        if *slot {
            return Err(SentinelDecisionError::DuplicateAction {
                action: row.action.as_str(),
            });
        }
        *slot = true;
    }

    if seen.iter().all(|value| *value) {
        Ok(())
    } else {
        Err(SentinelDecisionError::IncompleteLossMatrix)
    }
}

fn score_loss_row(
    row: &SentinelActionLoss,
    posterior_malice_bp: u16,
) -> Result<SentinelActionScore, SentinelDecisionError> {
    let posterior = u64::from(posterior_malice_bp);
    let benign = u64::from(PROBABILITY_SCALE_BP.saturating_sub(posterior_malice_bp));
    let benign_component_bp = weighted_loss_component(row.benign_loss_bp, benign, row.action)?;
    let malicious_component_bp =
        weighted_loss_component(row.malicious_loss_bp, posterior, row.action)?;
    let expected_loss_bp = benign_component_bp.saturating_add(malicious_component_bp);
    let dominant_outcome = if malicious_component_bp >= benign_component_bp {
        "malicious"
    } else {
        "benign"
    }
    .to_string();

    Ok(SentinelActionScore {
        action: row.action,
        expected_loss_bp,
        benign_component_bp,
        malicious_component_bp,
        dominant_outcome,
    })
}

fn weighted_loss_component(
    loss_bp: u32,
    probability_bp: u64,
    action: SentinelContainmentAction,
) -> Result<u64, SentinelDecisionError> {
    let weighted = u128::from(loss_bp) * u128::from(probability_bp);
    let rounded = weighted.saturating_add(u128::from(PROBABILITY_SCALE_BP / 2))
        / u128::from(PROBABILITY_SCALE_BP);
    u64::try_from(rounded).map_err(|_| SentinelDecisionError::InvalidLoss {
        action: action.as_str(),
    })
}

fn confidence_bp_from_false_alarm(false_alarm_bound_ppm: u64) -> u16 {
    let false_alarm_bp = false_alarm_bound_ppm.div_ceil(PPM_PER_BP);
    let confidence = u64::from(PROBABILITY_SCALE_BP).saturating_sub(false_alarm_bp);
    u16::try_from(confidence.min(u64::from(PROBABILITY_SCALE_BP))).unwrap_or(PROBABILITY_SCALE_BP)
}

fn sentinel_decision_id(
    input: &SentinelDecisionInput,
    action: SentinelContainmentAction,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"runtime_sentinel_decision_v1:");
    hasher.update(len_to_u64(input.principal_id.len()).to_le_bytes());
    hasher.update(input.principal_id.as_bytes());
    hasher.update(len_to_u64(input.trace_id.len()).to_le_bytes());
    hasher.update(input.trace_id.as_bytes());
    hasher.update(input.epoch.to_le_bytes());
    hasher.update(input.posterior_malice_bp.to_le_bytes());
    hasher.update(input.e_value_ppm.to_le_bytes());
    hasher.update(input.false_alarm_bound_ppm.to_le_bytes());
    hasher.update(input.evidence_count.to_le_bytes());
    hasher.update(len_to_u64(input.evidence_hash.len()).to_le_bytes());
    hasher.update(input.evidence_hash.as_bytes());
    hasher.update(len_to_u64(input.observation_log_digest.len()).to_le_bytes());
    hasher.update(input.observation_log_digest.as_bytes());
    hasher.update([action.rank()]);
    format!("sentinel-{}", hex::encode(hasher.finalize()))
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(kind: SentinelSignalKind, source: &str, mag: u16, detail: &str) -> SentinelSignal {
        SentinelSignal::new(kind, source, mag, detail).expect("valid signal")
    }

    fn sample_observation() -> RuntimeSentinelObservation {
        RuntimeSentinelObservation::new("ext-alpha", 7, 3, "2026-06-09T00:00:00Z")
            .with_signal(signal(
                SentinelSignalKind::BpetPhenotypeDrift,
                "bpet:evolution",
                4200,
                "phenotype-shift",
            ))
            .expect("push 1")
            .with_signal(signal(
                SentinelSignalKind::CamouflageHint,
                "trajectory:gaming",
                3100,
                "GradualCreep",
            ))
            .expect("push 2")
    }

    fn positive_risk_set() -> ConformalRiskSet {
        ConformalRiskSet {
            event_code: "FN-CONFORMAL-001".to_string(),
            sample_id: "npm:@acme/risky@1.0.0".to_string(),
            risk_class: "bpet_evolution".to_string(),
            score_bp: 9_500,
            quantile_bp: 1_000,
            included_labels: vec!["positive".to_string()],
        }
    }

    #[test]
    fn schema_version_is_pinned() {
        let obs = RuntimeSentinelObservation::new("ext-1", 1, 1, "2026-06-09T00:00:00Z");
        assert_eq!(
            obs.schema_version,
            RUNTIME_SENTINEL_OBSERVATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn signal_kind_str_and_rank_are_total_and_unique() {
        let kinds = [
            SentinelSignalKind::BpetPhenotypeDrift,
            SentinelSignalKind::CamouflageHint,
            SentinelSignalKind::DgisTopologyRisk,
            SentinelSignalKind::AtcPrior,
            SentinelSignalKind::CapabilityInvocation,
            SentinelSignalKind::PolicyViolation,
            SentinelSignalKind::ModuleResolutionAnomaly,
            SentinelSignalKind::ReplayDivergence,
            SentinelSignalKind::RevocationFreshness,
            SentinelSignalKind::FleetIncidentState,
            SentinelSignalKind::EffectReceiptAnomaly,
        ];
        let mut ranks: Vec<u8> = kinds.iter().map(|k| k.canonical_rank()).collect();
        ranks.sort_unstable();
        ranks.dedup();
        assert_eq!(ranks.len(), kinds.len(), "ranks must be unique");
        // String tags must be unique too.
        let mut tags: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), kinds.len(), "tags must be unique");
    }

    #[test]
    fn canonical_bytes_are_insertion_order_independent() {
        // Same evidence pushed in two different orders must canonicalize equal.
        let a = sample_observation();
        let b = RuntimeSentinelObservation::new("ext-alpha", 7, 3, "2026-06-09T00:00:00Z")
            .with_signal(signal(
                SentinelSignalKind::CamouflageHint,
                "trajectory:gaming",
                3100,
                "GradualCreep",
            ))
            .expect("push")
            .with_signal(signal(
                SentinelSignalKind::BpetPhenotypeDrift,
                "bpet:evolution",
                4200,
                "phenotype-shift",
            ))
            .expect("push");
        assert_eq!(
            a.to_canonical_bytes().unwrap(),
            b.to_canonical_bytes().unwrap()
        );
        assert_eq!(a.observation_hash().unwrap(), b.observation_hash().unwrap());
    }

    #[test]
    fn canonical_bytes_are_deterministic_across_calls() {
        let obs = sample_observation();
        assert_eq!(
            obs.to_canonical_bytes().unwrap(),
            obs.to_canonical_bytes().unwrap()
        );
    }

    #[test]
    fn distinct_evidence_changes_hash() {
        let base = sample_observation();
        let mut mutated = sample_observation();
        mutated
            .push_signal(signal(
                SentinelSignalKind::DgisTopologyRisk,
                "dgis:topology",
                900,
                "spof",
            ))
            .expect("push");
        assert_ne!(
            base.observation_hash().unwrap(),
            mutated.observation_hash().unwrap()
        );
    }

    #[test]
    fn calibrated_conformal_risk_set_signal_feeds_positive_likelihood() {
        let risk_set = positive_risk_set();
        let signal = sentinel_signal_from_conformal_risk_set(
            SentinelSignalKind::BpetPhenotypeDrift,
            "bpet:evolution",
            &risk_set,
        )
        .unwrap();

        assert_eq!(signal.magnitude_bp, 9_500);
        assert!(signal.detail.contains("risk_class=bpet_evolution"));
        assert!(signal.detail.contains("labels=positive"));

        let mut observation =
            RuntimeSentinelObservation::new("ext-calibrated", 9, 1, "2026-06-09T00:00:00Z");
        push_conformal_risk_set_signal(
            &mut observation,
            SentinelSignalKind::BpetPhenotypeDrift,
            "bpet:evolution",
            &risk_set,
        )
        .unwrap();

        assert_eq!(observation.signals.len(), 1);
        assert!(
            observation
                .observation_hash()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn empty_extension_id_rejected() {
        let obs = RuntimeSentinelObservation::new("", 1, 1, "2026-06-09T00:00:00Z");
        assert_eq!(
            obs.validate(),
            Err(SentinelObservationError::EmptyExtensionId)
        );
    }

    #[test]
    fn magnitude_over_ceiling_rejected() {
        let err = SentinelSignal::new(
            SentinelSignalKind::AtcPrior,
            "atc",
            SENTINEL_SIGNAL_MAX_MAGNITUDE_BP + 1,
            "d",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SentinelObservationError::MagnitudeOutOfRange { .. }
        ));
    }

    #[test]
    fn control_chars_rejected() {
        let err = SentinelSignal::new(SentinelSignalKind::PolicyViolation, "src\u{0}", 10, "d")
            .unwrap_err();
        assert_eq!(
            err,
            SentinelObservationError::ForbiddenControlChar {
                field: "signal.source"
            }
        );
    }

    #[test]
    fn signal_cap_is_enforced_by_bounded_push() {
        let mut obs = RuntimeSentinelObservation::new("ext", 1, 1, "2026-06-09T00:00:00Z");
        for i in 0..(MAX_SIGNALS_PER_OBSERVATION + 10) {
            obs.push_signal(signal(
                SentinelSignalKind::CapabilityInvocation,
                "cap",
                (i % 10_000) as u16,
                "invoke",
            ))
            .expect("push");
        }
        assert_eq!(obs.signals.len(), MAX_SIGNALS_PER_OBSERVATION);
        obs.validate().expect("bounded observation stays valid");
    }

    #[test]
    fn log_orders_observations_deterministically() {
        let mut log = SentinelObservationLog::new();
        // Ingest out of order.
        log.ingest(RuntimeSentinelObservation::new("ext-b", 2, 1, "t"))
            .unwrap();
        log.ingest(RuntimeSentinelObservation::new("ext-a", 1, 5, "t"))
            .unwrap();
        log.ingest(RuntimeSentinelObservation::new("ext-a", 1, 2, "t"))
            .unwrap();
        let order: Vec<(u64, u64, &str)> = log
            .ordered()
            .iter()
            .map(|o| (o.epoch, o.sequence, o.extension_id.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![(1, 2, "ext-a"), (1, 5, "ext-a"), (2, 1, "ext-b")]
        );
    }

    #[test]
    fn log_idempotent_reingest_is_noop() {
        let mut log = SentinelObservationLog::new();
        log.ingest(sample_observation()).unwrap();
        log.ingest(sample_observation()).unwrap();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn log_conflicting_payload_rejected() {
        let mut log = SentinelObservationLog::new();
        log.ingest(sample_observation()).unwrap();
        let mut conflicting = sample_observation();
        conflicting
            .push_signal(signal(
                SentinelSignalKind::ReplayDivergence,
                "replay",
                10,
                "diverge",
            ))
            .unwrap();
        let err = log.ingest(conflicting).unwrap_err();
        assert!(matches!(
            err,
            SentinelObservationError::ConflictingObservation { .. }
        ));
    }

    #[test]
    fn log_digest_changes_with_membership_and_is_stable() {
        let mut log = SentinelObservationLog::new();
        log.ingest(sample_observation()).unwrap();
        let d1 = log.digest().unwrap();
        assert_eq!(d1, log.digest().unwrap(), "digest stable across calls");

        log.ingest(RuntimeSentinelObservation::new("ext-zeta", 9, 1, "t"))
            .unwrap();
        assert_ne!(d1, log.digest().unwrap(), "digest changes with membership");
    }

    #[test]
    fn log_digest_is_ingestion_order_independent() {
        let obs1 = RuntimeSentinelObservation::new("ext-a", 1, 1, "t");
        let obs2 = RuntimeSentinelObservation::new("ext-b", 1, 1, "t");

        let mut forward = SentinelObservationLog::new();
        forward.ingest(obs1.clone()).unwrap();
        forward.ingest(obs2.clone()).unwrap();

        let mut reverse = SentinelObservationLog::new();
        reverse.ingest(obs2).unwrap();
        reverse.ingest(obs1).unwrap();

        assert_eq!(forward.digest().unwrap(), reverse.digest().unwrap());
    }
}
