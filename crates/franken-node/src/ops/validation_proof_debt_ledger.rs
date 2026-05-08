//! Deterministic debt ledger for validation proof attempts.
//!
//! The ledger is intentionally derived from broker status records instead of
//! rereading artifacts from disk. That keeps doctor/readiness/dashboard callers
//! on one normalized contract while preserving the original recorder paths and
//! receipt references for operators.

use crate::ops::validation_broker::{
    FlightRecorderAdapterOutcomeClass, ProofEvidenceSource, ProofStatusKind, QueueState,
    TimeoutClass, ValidationErrorClass, ValidationExitKind, ValidationProofStatus,
    flight_recorder_reason_codes,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VALIDATION_PROOF_DEBT_LEDGER_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-debt-ledger/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofDebtClass {
    CargoContention,
    DiskPressure,
    ProductFailure,
    ProofCacheReuse,
    SiblingDependencyBlocker,
    SourceOnlyFallback,
    StaleLease,
    WaitingForCapacity,
    WorkerInfra,
    Unknown,
}

impl ValidationProofDebtClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CargoContention => "cargo_contention",
            Self::DiskPressure => "disk_pressure",
            Self::ProductFailure => "product_failure",
            Self::ProofCacheReuse => "proof_cache_reuse",
            Self::SiblingDependencyBlocker => "sibling_dependency_blocker",
            Self::SourceOnlyFallback => "source_only_fallback",
            Self::StaleLease => "stale_lease",
            Self::WaitingForCapacity => "waiting_for_capacity",
            Self::WorkerInfra => "worker_infra",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofDebtState {
    Blocked,
    Retryable,
    Informational,
}

impl ValidationProofDebtState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Retryable => "retryable",
            Self::Informational => "informational",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofDebtFreshness {
    Fresh,
    Stale,
    Unknown,
}

impl ValidationProofDebtFreshness {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofDebtLedger {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub summary: ValidationProofDebtLedgerSummary,
    pub entries: Vec<ValidationProofDebtLedgerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofDebtLedgerSummary {
    pub total_entries: usize,
    pub retryable_entries: usize,
    pub blocked_entries: usize,
    pub stale_entries: usize,
    pub product_failures: usize,
    pub source_only_fallbacks: usize,
    pub proof_cache_reuses: usize,
    pub entries_blocking_other_beads: usize,
    pub by_class: BTreeMap<ValidationProofDebtClass, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofDebtLedgerEntry {
    pub bead_id: String,
    pub thread_id: String,
    pub request_id: Option<String>,
    pub queue_id: Option<String>,
    pub owner_agent: Option<String>,
    pub producer_bead_id: Option<String>,
    pub debt_class: ValidationProofDebtClass,
    pub debt_state: ValidationProofDebtState,
    pub freshness: ValidationProofDebtFreshness,
    pub status: String,
    pub proof_source: String,
    pub queue_state: Option<String>,
    pub deduplicated: bool,
    pub retryable: bool,
    pub product_failure: bool,
    pub blocks_other_bead: bool,
    pub command_digest_hex: Option<String>,
    pub latest_recorder_path: Option<String>,
    pub receipt_path: Option<String>,
    pub cache_key_hex: Option<String>,
    pub worker_id: Option<String>,
    pub reason_code: Option<String>,
    pub event_code: Option<String>,
    pub required_action: String,
    pub diagnostic: String,
    pub freshness_expires_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
}

#[must_use]
pub fn build_validation_proof_debt_ledger<I, S>(
    statuses: &[ValidationProofStatus],
    generated_at: DateTime<Utc>,
    beads_blocking_other_work: I,
) -> ValidationProofDebtLedger
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let blocking_beads = beads_blocking_other_work
        .into_iter()
        .map(|bead_id| bead_id.as_ref().to_string())
        .collect::<BTreeSet<_>>();
    let mut entries = statuses
        .iter()
        .filter_map(|status| entry_for_status(status, generated_at, &blocking_beads))
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        (
            left.debt_class.as_str(),
            left.bead_id.as_str(),
            left.thread_id.as_str(),
            left.request_id.as_deref().unwrap_or(""),
            left.queue_id.as_deref().unwrap_or(""),
            left.command_digest_hex.as_deref().unwrap_or(""),
        )
            .cmp(&(
                right.debt_class.as_str(),
                right.bead_id.as_str(),
                right.thread_id.as_str(),
                right.request_id.as_deref().unwrap_or(""),
                right.queue_id.as_deref().unwrap_or(""),
                right.command_digest_hex.as_deref().unwrap_or(""),
            ))
    });

    let summary = summarize_entries(&entries);
    ValidationProofDebtLedger {
        schema_version: VALIDATION_PROOF_DEBT_LEDGER_SCHEMA_VERSION.to_string(),
        generated_at,
        summary,
        entries,
    }
}

fn entry_for_status(
    status: &ValidationProofStatus,
    generated_at: DateTime<Utc>,
    blocking_beads: &BTreeSet<String>,
) -> Option<ValidationProofDebtLedgerEntry> {
    let debt_class = classify_status(status);
    if !should_include_status(status, debt_class) {
        return None;
    }

    let retryable = is_retryable(status, debt_class);
    let product_failure = is_product_failure(status, debt_class);
    let debt_state = debt_state(debt_class, retryable);
    let freshness_expires_at = freshness_expires_at(status);
    let freshness = match freshness_expires_at {
        Some(expires_at) if expires_at < generated_at => ValidationProofDebtFreshness::Stale,
        Some(_) => ValidationProofDebtFreshness::Fresh,
        None => ValidationProofDebtFreshness::Unknown,
    };

    Some(ValidationProofDebtLedgerEntry {
        bead_id: status.bead_id.clone(),
        thread_id: status.thread_id.clone(),
        request_id: status.request_id.clone(),
        queue_id: status.queue_id.clone(),
        owner_agent: owner_agent(status),
        producer_bead_id: status
            .proof_coalescer
            .as_ref()
            .map(|coalescer| coalescer.producer_bead_id.clone()),
        debt_class,
        debt_state,
        freshness,
        status: status.status.as_str().to_string(),
        proof_source: status.proof_source.as_str().to_string(),
        queue_state: status
            .queue_state
            .map(QueueState::as_str)
            .map(str::to_string),
        deduplicated: status.deduplicated,
        retryable,
        product_failure,
        blocks_other_bead: blocking_beads.contains(&status.bead_id),
        command_digest_hex: status
            .command_digest
            .as_ref()
            .map(|digest| digest.hex.clone()),
        latest_recorder_path: status
            .flight_recorder_ref
            .as_ref()
            .map(|recorder| recorder.attempt_path.clone()),
        receipt_path: receipt_path(status),
        cache_key_hex: cache_key_hex(status),
        worker_id: status
            .flight_recorder_ref
            .as_ref()
            .and_then(|recorder| recorder.worker_id.clone()),
        reason_code: reason_code(status),
        event_code: event_code(status),
        required_action: required_action(status, debt_class),
        diagnostic: diagnostic(status, debt_class),
        freshness_expires_at,
        observed_at: status.observed_at,
    })
}

fn summarize_entries(
    entries: &[ValidationProofDebtLedgerEntry],
) -> ValidationProofDebtLedgerSummary {
    let mut by_class = BTreeMap::new();
    for entry in entries {
        *by_class.entry(entry.debt_class).or_insert(0) += 1;
    }

    ValidationProofDebtLedgerSummary {
        total_entries: entries.len(),
        retryable_entries: entries
            .iter()
            .filter(|entry| entry.debt_state == ValidationProofDebtState::Retryable)
            .count(),
        blocked_entries: entries
            .iter()
            .filter(|entry| entry.debt_state == ValidationProofDebtState::Blocked)
            .count(),
        stale_entries: entries
            .iter()
            .filter(|entry| entry.freshness == ValidationProofDebtFreshness::Stale)
            .count(),
        product_failures: entries.iter().filter(|entry| entry.product_failure).count(),
        source_only_fallbacks: entries
            .iter()
            .filter(|entry| entry.debt_class == ValidationProofDebtClass::SourceOnlyFallback)
            .count(),
        proof_cache_reuses: entries
            .iter()
            .filter(|entry| entry.debt_class == ValidationProofDebtClass::ProofCacheReuse)
            .count(),
        entries_blocking_other_beads: entries
            .iter()
            .filter(|entry| entry.blocks_other_bead)
            .count(),
        by_class,
    }
}

fn classify_status(status: &ValidationProofStatus) -> ValidationProofDebtClass {
    if status.proof_cache.is_some()
        || status.status == ProofStatusKind::Reused
        || status.proof_source == ProofEvidenceSource::ProofCacheHit
    {
        return ValidationProofDebtClass::ProofCacheReuse;
    }

    if is_stale_lease(status) {
        return ValidationProofDebtClass::StaleLease;
    }

    if is_sibling_dependency_blocker(status) {
        return ValidationProofDebtClass::SiblingDependencyBlocker;
    }

    if is_disk_pressure(status) {
        return ValidationProofDebtClass::DiskPressure;
    }

    if is_product_failure(status, ValidationProofDebtClass::Unknown) {
        return ValidationProofDebtClass::ProductFailure;
    }

    if is_source_only(status) {
        return ValidationProofDebtClass::SourceOnlyFallback;
    }

    if is_cargo_contention(status) {
        return ValidationProofDebtClass::CargoContention;
    }

    if is_waiting_for_capacity(status) {
        return ValidationProofDebtClass::WaitingForCapacity;
    }

    if is_worker_infra(status) {
        return ValidationProofDebtClass::WorkerInfra;
    }

    ValidationProofDebtClass::Unknown
}

fn should_include_status(
    status: &ValidationProofStatus,
    debt_class: ValidationProofDebtClass,
) -> bool {
    debt_class != ValidationProofDebtClass::Unknown
        || !matches!(status.status, ProofStatusKind::Passed)
}

fn is_retryable(status: &ValidationProofStatus, debt_class: ValidationProofDebtClass) -> bool {
    status.exit.as_ref().is_some_and(|exit| exit.retryable)
        || matches!(
            debt_class,
            ValidationProofDebtClass::CargoContention
                | ValidationProofDebtClass::StaleLease
                | ValidationProofDebtClass::WaitingForCapacity
                | ValidationProofDebtClass::WorkerInfra
        )
}

fn is_product_failure(
    status: &ValidationProofStatus,
    debt_class: ValidationProofDebtClass,
) -> bool {
    if debt_class == ValidationProofDebtClass::ProductFailure {
        return true;
    }
    if let Some(exit) = &status.exit {
        return matches!(exit.kind, ValidationExitKind::Failed)
            && !exit.retryable
            && matches!(
                exit.error_class,
                ValidationErrorClass::CompileError
                    | ValidationErrorClass::TestFailure
                    | ValidationErrorClass::ClippyWarning
                    | ValidationErrorClass::FormatFailure
            );
    }
    status.flight_recorder_ref.as_ref().is_some_and(|recorder| {
        matches!(
            recorder.outcome_class,
            FlightRecorderAdapterOutcomeClass::CommandFailed
                | FlightRecorderAdapterOutcomeClass::CompileFailed
                | FlightRecorderAdapterOutcomeClass::TestFailed
        )
    }) || status_text(status).contains("product_failure")
}

fn debt_state(debt_class: ValidationProofDebtClass, retryable: bool) -> ValidationProofDebtState {
    if debt_class == ValidationProofDebtClass::ProofCacheReuse {
        ValidationProofDebtState::Informational
    } else if retryable {
        ValidationProofDebtState::Retryable
    } else {
        ValidationProofDebtState::Blocked
    }
}

fn is_stale_lease(status: &ValidationProofStatus) -> bool {
    status.proof_coalescer.as_ref().is_some_and(|coalescer| {
        let text = joined_lowercase([
            coalescer.lease_state.as_str(),
            coalescer.reason_code.as_str(),
            coalescer.required_action.as_str(),
            coalescer.diagnostic.as_str(),
        ]);
        text.contains("stale")
            || text.contains("new_fence")
            || text.contains("refresh_lease_fence")
            || coalescer.reason_code == flight_recorder_reason_codes::STALE_PROGRESS
            || coalescer.reason_code == flight_recorder_reason_codes::STALE_LEASE_FENCE
    })
}

fn is_sibling_dependency_blocker(status: &ValidationProofStatus) -> bool {
    let text = status_text(status);
    text.contains("sibling_dependency") || text.contains("sibling dependency")
}

fn is_disk_pressure(status: &ValidationProofStatus) -> bool {
    status
        .exit
        .as_ref()
        .is_some_and(|exit| exit.error_class == ValidationErrorClass::DiskPressure)
        || status_text(status).contains("disk_pressure")
        || status_text(status).contains("disk pressure")
}

fn is_source_only(status: &ValidationProofStatus) -> bool {
    matches!(status.status, ProofStatusKind::SourceOnly)
        || matches!(status.proof_source, ProofEvidenceSource::SourceOnlyFallback)
        || status.exit.as_ref().is_some_and(|exit| {
            matches!(exit.kind, ValidationExitKind::SourceOnly)
                || exit.error_class == ValidationErrorClass::SourceOnly
        })
        || status_text(status).contains("source_only")
}

fn is_waiting_for_capacity(status: &ValidationProofStatus) -> bool {
    matches!(status.queue_state, Some(QueueState::Queued))
        || status.status == ProofStatusKind::Queued
        || status_text(status).contains("wait_for_capacity")
}

fn is_cargo_contention(status: &ValidationProofStatus) -> bool {
    status.exit.as_ref().is_some_and(|exit| {
        exit.error_class == ValidationErrorClass::EnvironmentContention
            || exit.timeout_class == TimeoutClass::QueueWait
    }) || status.flight_recorder_ref.as_ref().is_some_and(|recorder| {
        recorder.outcome_class == FlightRecorderAdapterOutcomeClass::ContentionDeferred
    }) || status_text(status).contains("cargo_contention")
        || status_text(status).contains("contention")
}

fn is_worker_infra(status: &ValidationProofStatus) -> bool {
    status.exit.as_ref().is_some_and(|exit| {
        exit.error_class == ValidationErrorClass::WorkerInfra
            || exit.error_class == ValidationErrorClass::TransportTimeout
            || matches!(
                exit.timeout_class,
                TimeoutClass::RchDispatch
                    | TimeoutClass::SshCommand
                    | TimeoutClass::WorkerUnreachable
            )
    }) || status.flight_recorder_ref.as_ref().is_some_and(|recorder| {
        matches!(
            recorder.outcome_class,
            FlightRecorderAdapterOutcomeClass::WorkerTimeout
                | FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain
                | FlightRecorderAdapterOutcomeClass::WorkerFilesystemError
                | FlightRecorderAdapterOutcomeClass::LocalFallbackRefused
        )
    })
}

fn freshness_expires_at(status: &ValidationProofStatus) -> Option<DateTime<Utc>> {
    [
        status
            .readiness_ref
            .as_ref()
            .map(|readiness| readiness.freshness_expires_at),
        status
            .flight_recorder_ref
            .as_ref()
            .map(|recorder| recorder.freshness_expires_at),
    ]
    .into_iter()
    .flatten()
    .min()
}

fn owner_agent(status: &ValidationProofStatus) -> Option<String> {
    status
        .proof_coalescer
        .as_ref()
        .map(|coalescer| coalescer.producer_agent.clone())
        .or_else(|| {
            status
                .flight_recorder_ref
                .as_ref()
                .and_then(|recorder| recorder.worker_id.clone())
        })
}

fn receipt_path(status: &ValidationProofStatus) -> Option<String> {
    status
        .artifact_paths
        .as_ref()
        .map(|artifacts| artifacts.receipt_path.clone())
        .or_else(|| {
            status
                .proof_coalescer
                .as_ref()
                .and_then(|coalescer| coalescer.receipt_path.clone())
        })
        .or_else(|| {
            status
                .proof_cache
                .as_ref()
                .map(|cache| cache.receipt_path.clone())
        })
}

fn cache_key_hex(status: &ValidationProofStatus) -> Option<String> {
    status
        .proof_cache
        .as_ref()
        .map(|cache| cache.cache_key_hex.clone())
        .or_else(|| {
            status
                .proof_coalescer
                .as_ref()
                .map(|coalescer| coalescer.proof_cache_key_hex.clone())
        })
}

fn reason_code(status: &ValidationProofStatus) -> Option<String> {
    status
        .proof_coalescer
        .as_ref()
        .map(|coalescer| coalescer.reason_code.clone())
        .or_else(|| {
            status
                .proof_cache
                .as_ref()
                .map(|cache| cache.reason_code.clone())
        })
        .or_else(|| {
            status
                .readiness_ref
                .as_ref()
                .map(|readiness| readiness.reason_code.clone())
        })
        .or_else(|| {
            status
                .flight_recorder_ref
                .as_ref()
                .map(|recorder| recorder.reason_code.clone())
        })
}

fn event_code(status: &ValidationProofStatus) -> Option<String> {
    status
        .proof_coalescer
        .as_ref()
        .map(|coalescer| coalescer.event_code.clone())
        .or_else(|| {
            status
                .proof_cache
                .as_ref()
                .map(|cache| cache.event_code.clone())
        })
        .or_else(|| {
            status
                .readiness_ref
                .as_ref()
                .map(|readiness| readiness.event_code.clone())
        })
}

fn required_action(status: &ValidationProofStatus, debt_class: ValidationProofDebtClass) -> String {
    status
        .proof_coalescer
        .as_ref()
        .map(|coalescer| coalescer.required_action.clone())
        .or_else(|| {
            status
                .proof_cache
                .as_ref()
                .map(|cache| cache.required_action.clone())
        })
        .or_else(|| {
            status
                .readiness_ref
                .as_ref()
                .map(|readiness| readiness.required_action.clone())
        })
        .unwrap_or_else(|| default_required_action(debt_class).to_string())
}

fn default_required_action(debt_class: ValidationProofDebtClass) -> &'static str {
    match debt_class {
        ValidationProofDebtClass::CargoContention
        | ValidationProofDebtClass::WaitingForCapacity => "wait_for_capacity",
        ValidationProofDebtClass::DiskPressure => "relieve_disk_pressure",
        ValidationProofDebtClass::ProductFailure => "surface_product_failure",
        ValidationProofDebtClass::ProofCacheReuse => "reuse_receipt",
        ValidationProofDebtClass::SiblingDependencyBlocker => "fix_sibling_dependency_blocker",
        ValidationProofDebtClass::SourceOnlyFallback => "record_source_only_blocker",
        ValidationProofDebtClass::StaleLease => "refresh_lease_fence",
        ValidationProofDebtClass::WorkerInfra => "retry_remote",
        ValidationProofDebtClass::Unknown => "inspect_validation_proof",
    }
}

fn diagnostic(status: &ValidationProofStatus, debt_class: ValidationProofDebtClass) -> String {
    status
        .proof_coalescer
        .as_ref()
        .map(|coalescer| coalescer.diagnostic.clone())
        .or_else(|| {
            status
                .proof_cache
                .as_ref()
                .map(|cache| cache.diagnostic.clone())
        })
        .or_else(|| status.reason.clone())
        .unwrap_or_else(|| format!("validation proof debt class={}", debt_class.as_str()))
}

fn status_text(status: &ValidationProofStatus) -> String {
    let mut fields = Vec::new();
    fields.push(status.status.as_str().to_string());
    fields.push(status.proof_source.as_str().to_string());
    if let Some(reason) = &status.reason {
        fields.push(reason.clone());
    }
    if let Some(exit) = &status.exit {
        fields.push(format!("{:?}", exit.kind));
        fields.push(format!("{:?}", exit.timeout_class));
        fields.push(format!("{:?}", exit.error_class));
    }
    if let Some(readiness) = &status.readiness_ref {
        fields.push(readiness.reason_code.clone());
        fields.push(readiness.required_action.clone());
    }
    if let Some(recorder) = &status.flight_recorder_ref {
        fields.push(format!("{:?}", recorder.outcome_class));
        fields.push(recorder.reason_code.clone());
    }
    if let Some(coalescer) = &status.proof_coalescer {
        fields.push(coalescer.lease_state.clone());
        fields.push(coalescer.reason_code.clone());
        fields.push(coalescer.required_action.clone());
        fields.push(coalescer.diagnostic.clone());
    }
    if let Some(cache) = &status.proof_cache {
        fields.push(cache.reason_code.clone());
        fields.push(cache.required_action.clone());
        fields.push(cache.diagnostic.clone());
    }
    fields.join("\n").to_ascii_lowercase()
}

fn joined_lowercase<'a>(fields: impl IntoIterator<Item = &'a str>) -> String {
    fields
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase()
}
