//! Authenticated, package-scoped behavioral observations for BPET.
//!
//! A collector attests a measurement of one isolated package artifact under
//! a named, repeatable workload. The operator supplies the trusted collector
//! key independently. This does not attribute a whole application's effects
//! to its dependencies, or claim that a signature proves measurement quality.
//! Observations, their decisions and the trust-card update commit together in
//! the existing WAL-backed trust registry. Replays are idempotent; forks and
//! incomparable experiments are refused rather than mixed into a trajectory.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::certification::{EvidenceType, VerifiedEvidenceRef};
use super::trust_card::{
    MAX_CAMOUFLAGE_HINTS_ON_CARD, RiskLevel, SnapshotSourceContext, TrustCardError,
    TrustCardMutation, TrustCardRegistry, TrustCardRegistrySnapshot, get_registry_key,
};
use super::trust_card_registry_store::{SLOT_SNAPSHOT, TrustCardRegistryStore, read_slot};
use crate::config::TrustConfig;
use crate::security::bpet::camouflage_detector::{DetectorConfig, detect_camouflage};
use crate::security::constant_time;
use crate::security::trajectory_gaming::{CamouflageHint, TrajectorySample, TrajectorySeries};

pub const OBSERVATION_SCHEMA: &str = "franken-node/behavioral-observation/v1";
pub const INGESTION_SCHEMA: &str = "franken-node/behavioral-ingestion/v1";
pub const MAX_OBSERVATION_BYTES: usize = 1024 * 1024;
pub const MAX_OBSERVATIONS_PER_STREAM: usize = 1024;
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_ASSESSMENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ASSESSMENT_SAMPLES: usize = 65_536;
const MAX_CAPABILITY_DIMENSIONS: usize = 32;
const MAX_CAPABILITY_COUNT: u64 = 1_000_000_000;
const JOURNAL_SCHEMA: &str = "franken-node/behavioral-observation-journal/v1";
const SIGNATURE_DOMAIN: &[u8] = b"franken-node/behavioral-observation-signature/v1\0";
const ID_DOMAIN: &[u8] = b"franken-node/behavioral-observation-id/v1\0";
const STREAM_DOMAIN: &[u8] = b"franken-node/behavioral-observation-stream/v1\0";
const JOURNAL_DOMAIN: &[u8] = b"franken-node/behavioral-observation-journal-mac/v1\0";

/// Integer event counts under a collector-attested measurement contract.
/// Zero is a measured zero; unknown dimensions must not be supplied as zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralObservation {
    pub extension_id: String,
    pub package_version: String,
    /// Exact digest already present in the verified version's trust card.
    pub artifact_hash: String,
    /// Stable identifier for a repeatable experiment, not an observation UUID.
    pub workload_id: String,
    /// The only accepted scope is `isolated_package`.
    pub measurement_scope: String,
    /// Starts at zero and advances by exactly one within the stream.
    pub sequence: u64,
    pub observed_at_epoch_secs: u64,
    pub window_duration_ms: u64,
    /// Number of completed repetitions; both count maps contain totals across
    /// these repetitions and are normalized to events per repetition for BPET.
    pub workload_iterations: u64,
    pub previous_observation_id: Option<String>,
    #[serde(deserialize_with = "deserialize_unique_counts")]
    pub observed_capabilities: BTreeMap<String, u64>,
    #[serde(deserialize_with = "deserialize_unique_counts")]
    pub declared_capabilities: BTreeMap<String, u64>,
}

/// The embedded fingerprint identifies a collector but does not trust it.
/// Admission always verifies against an independently supplied public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBehavioralObservation {
    pub schema_version: String,
    pub observation: BehavioralObservation,
    pub collector_key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
struct ObservationPreimage<'a> {
    schema_version: &'a str,
    observation: &'a BehavioralObservation,
    collector_key_id: &'a str,
}

impl SignedBehavioralObservation {
    /// Sign the typed JSON preimage with the signature domain prepended.
    /// Field order follows these public structs, maps sort keys, optional
    /// predecessor is explicit JSON null, and signature itself is excluded.
    pub fn sign(observation: BehavioralObservation, key: &SigningKey) -> Result<Self> {
        validate_observation(&observation)?;
        let mut signed = Self {
            schema_version: OBSERVATION_SCHEMA.to_string(),
            observation,
            collector_key_id: collector_key_id(&key.verifying_key()),
            signature: String::new(),
        };
        signed.signature = hex::encode(key.sign(&signed.signing_bytes()?).to_bytes());
        Ok(signed)
    }

    /// Content identity of every signed semantic field. A transport's JSON
    /// whitespace or object-field order cannot create a second observation.
    pub fn observation_id(&self) -> Result<String> {
        Ok(domain_hash(ID_DOMAIN, &self.preimage()?))
    }

    fn preimage(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&ObservationPreimage {
            schema_version: &self.schema_version,
            observation: &self.observation,
            collector_key_id: &self.collector_key_id,
        })?)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok([SIGNATURE_DOMAIN, self.preimage()?.as_slice()].concat())
    }

    /// Authenticate every semantic field against an independently pinned key
    /// without accessing a registry. Historical observations are allowed;
    /// timestamps more than `MAX_FUTURE_SKEW_SECS` ahead are refused. Stream
    /// continuity and binding to an installed artifact are checked on ingest.
    pub fn verify(&self, trusted_collector: &VerifyingKey, now_secs: u64) -> Result<()> {
        ensure!(
            self.schema_version == OBSERVATION_SCHEMA,
            "unsupported behavioral observation schema"
        );
        validate_observation(&self.observation)?;
        ensure!(
            self.observation.observed_at_epoch_secs
                <= now_secs.saturating_add(MAX_FUTURE_SKEW_SECS),
            "behavioral observation timestamp is more than {MAX_FUTURE_SKEW_SECS} seconds in the future"
        );
        ensure!(
            constant_time::ct_eq(&self.collector_key_id, &collector_key_id(trusted_collector)),
            "behavioral observation collector does not match the operator-pinned key"
        );
        ensure!(
            is_lower_hex(&self.signature, 128),
            "behavioral observation signature must be 64 bytes of lowercase hex"
        );
        let mut bytes = [0_u8; 64];
        hex::decode_to_slice(&self.signature, &mut bytes)?;
        trusted_collector
            .verify_strict(&self.signing_bytes()?, &Signature::from_bytes(&bytes))
            .context("behavioral observation signature failed verification")
    }
}

#[must_use]
pub fn collector_key_id(key: &VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(Sha256::digest(key.as_bytes())))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehavioralIngestionStatus {
    Accepted,
    Duplicate,
}

impl fmt::Display for BehavioralIngestionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralIngestionReport {
    pub schema_version: String,
    pub status: BehavioralIngestionStatus,
    pub observation_id: String,
    pub stream_id: String,
    pub extension_id: String,
    pub package_version: String,
    pub artifact_hash: String,
    pub collector_key_id: String,
    pub workload_id: String,
    pub sample_count: usize,
    pub hints: Vec<CamouflageHint>,
    pub card_version: u64,
    pub card_hash: String,
    pub risk_level: RiskLevel,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    envelope: SignedBehavioralObservation,
    report: BehavioralIngestionReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationJournal {
    schema_version: String,
    stream_id: String,
    entries: Vec<JournalEntry>,
    mac: String,
}

impl ObservationJournal {
    fn compute_mac(&self, key: &[u8]) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.mac.clear();
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| anyhow::anyhow!("invalid behavioral journal authentication key"))?;
        mac.update(JOURNAL_DOMAIN);
        mac.update(&serde_json::to_vec(&unsigned)?);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn validate(&self, stream: &str, key: &[u8], collector: &VerifyingKey, now: u64) -> Result<()> {
        self.validate_admitted(stream, key, now)?;
        for entry in &self.entries {
            entry.envelope.verify(collector, now)?;
        }
        Ok(())
    }

    /// Authenticate the original admission, not a newly supplied collector.
    /// Collector signatures were checked before the journal was committed;
    /// its MAC covers those envelopes and their complete admission reports.
    fn validate_admitted(&self, stream: &str, key: &[u8], now: u64) -> Result<()> {
        ensure!(
            self.schema_version == JOURNAL_SCHEMA && self.stream_id == stream,
            "behavioral journal identity mismatch"
        );
        ensure!(
            !self.entries.is_empty() && self.entries.len() <= MAX_OBSERVATIONS_PER_STREAM,
            "invalid behavioral journal length"
        );
        ensure!(
            constant_time::ct_eq(&self.mac, &self.compute_mac(key)?),
            "behavioral journal failed authentication"
        );
        let mut prior: Option<&SignedBehavioralObservation> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            let envelope = &entry.envelope;
            let observation = &envelope.observation;
            ensure!(
                envelope.schema_version == OBSERVATION_SCHEMA,
                "unsupported admitted behavioral observation schema"
            );
            validate_observation(observation)?;
            ensure!(
                observation.observed_at_epoch_secs <= now.saturating_add(MAX_FUTURE_SKEW_SECS),
                "admitted behavioral observation is in the future"
            );
            ensure!(
                envelope.collector_key_id.strip_prefix("ed25519:")
                    .is_some_and(|digest| is_lower_hex(digest, 64))
                    && is_lower_hex(&envelope.signature, 128),
                "invalid admitted behavioral collector or signature encoding"
            );
            ensure!(
                stream_id(&entry.envelope)? == stream,
                "behavioral journal mixes measurement streams"
            );
            validate_successor(prior, &entry.envelope)?;
            ensure!(
                entry.report.observation_id == entry.envelope.observation_id()?,
                "behavioral journal observation identity mismatch"
            );
            ensure!(
                entry.report.schema_version == INGESTION_SCHEMA
                    && entry.report.sample_count == index + 1
                    && entry.report.status == BehavioralIngestionStatus::Accepted
                    && entry.report.stream_id == stream
                    && entry.report.extension_id == observation.extension_id
                    && entry.report.package_version == observation.package_version
                    && entry.report.artifact_hash == observation.artifact_hash
                    && entry.report.collector_key_id == envelope.collector_key_id
                    && entry.report.workload_id == observation.workload_id
                    && entry.report.evidence_ref == format!(
                        "behavioral-observation:{}",
                        entry.report.observation_id.trim_start_matches("sha256:")
                    ),
                "behavioral journal admission record mismatch"
            );
            prior = Some(&entry.envelope);
        }
        Ok(())
    }
}

/// A detector assessment of one authenticated, comparable measurement stream.
///
/// The registry authenticates prior collector admission. This is not a new
/// independent verification of the collector key or proof that its experiment
/// was honest. A severity is a detector output, not a calibrated probability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralStreamAssessment {
    pub stream_id: String,
    pub extension_id: String,
    pub package_version: String,
    pub artifact_hash: String,
    pub collector_key_id: String,
    pub workload_id: String,
    pub measurement_scope: String,
    pub sample_count: usize,
    pub last_observation_id: String,
    pub observed_at_epoch_secs: u64,
    /// False when the measured artifact is no longer the current trust card.
    pub current_artifact: bool,
    /// False means insufficient samples, not a clean behavioral verdict.
    pub detector_ready: bool,
    pub hints: Vec<CamouflageHint>,
    /// None for insufficient evidence; Some(0.0) for an evaluated clean stream.
    pub max_severity: Option<f64>,
}

/// Assess retained observations against the exact signed registry used by the
/// caller's graph. Every retained head must have a matching authenticated
/// journal: deletion, rollback and corruption fail rather than become "no data".
///
/// The snapshot is authenticated again, then compared with the durable snapshot
/// while reading journals in a single transaction. Concurrent updates require a
/// fresh graph instead of mixing observations and cards from different epochs.
/// Journals retain their original collector/workload boundaries; historical
/// versions may form a trajectory, but only its latest artifact is marked current.
/// Total input bytes and sample work are bounded; no prefix is silently reported
/// as complete. No trust card, observation or stream head is changed.
pub fn assess_observation_history(
    snapshot_path: &Path,
    trust_config: &TrustConfig,
    snapshot: &TrustCardRegistrySnapshot,
    now_secs: u64,
) -> Result<Vec<BehavioralStreamAssessment>> {
    let registry_key = Zeroizing::new(get_registry_key(trust_config)?);
    TrustCardRegistry::from_snapshot(snapshot.clone(), &registry_key, now_secs)?;
    // Configuration may override the cache TTL on load. It is not trust-state
    // identity; allow enough byte slack for any u64 TTL before authenticating.
    let snapshot_byte_budget = super::trust_card::to_canonical_json(snapshot)?
        .len().saturating_add(64);
    let store = TrustCardRegistryStore::open(snapshot_path)?;
    let journals = store.with_immediate_transaction(|connection, _| {
        let stored = read_assessment_slot(
            connection,
            SLOT_SNAPSHOT,
            snapshot_byte_budget,
            snapshot_path,
        )?.ok_or_else(|| TrustCardError::InvalidSnapshot(
            "behavioral assessment requires its durable registry snapshot".to_string(),
        ))?;
        let mut current: TrustCardRegistrySnapshot = serde_json::from_str(&stored)
            .map_err(|error| TrustCardError::SnapshotParse {
                path: snapshot_path.to_path_buf(),
                detail: format!("behavioral assessment registry: {error}"),
            })?;
        TrustCardRegistry::from_snapshot(current.clone(), &registry_key, now_secs)?;
        // Both signatures have been checked. Ignore only the configuration-local
        // TTL and its derived hash/signature; compare every trust-state field.
        current.cache_ttl_secs = snapshot.cache_ttl_secs;
        current.snapshot_hash.clone_from(&snapshot.snapshot_hash);
        current.registry_signature.clone_from(&snapshot.registry_signature);
        if current != *snapshot {
            return Err(TrustCardError::InvalidSnapshot(
                "behavioral assessment registry changed; reload the graph and retry".to_string(),
            ));
        }
        let mut remaining_bytes = MAX_ASSESSMENT_BYTES;
        let mut journals = Vec::with_capacity(snapshot.behavioral_observation_heads.len());
        for stream in snapshot.behavioral_observation_heads.keys() {
            let slot = format!("behavioral-observations:{stream}");
            let encoded = read_assessment_slot(
                connection,
                &slot,
                remaining_bytes.min(MAX_JOURNAL_BYTES),
                snapshot_path,
            )?
            .ok_or_else(|| TrustCardError::InvalidSnapshot(
                "behavioral journal is missing for a retained signed registry head".to_string(),
            ))?;
            remaining_bytes = remaining_bytes.saturating_sub(encoded.len());
            journals.push((stream.clone(), encoded));
        }
        Ok(journals)
    })?;
    let detector = DetectorConfig::default();
    let mut remaining_samples = MAX_ASSESSMENT_SAMPLES;
    let mut assessments = Vec::with_capacity(journals.len());
    for (stream, encoded) in journals {
        let journal: ObservationJournal = serde_json::from_str(&encoded)
            .context("invalid stored behavioral observation journal")?;
        ensure!(
            journal.entries.len() <= remaining_samples,
            "behavioral history exceeds the {MAX_ASSESSMENT_SAMPLES}-sample assessment budget"
        );
        remaining_samples = remaining_samples.saturating_sub(journal.entries.len());
        journal.validate_admitted(&stream, &registry_key, now_secs)?;
        let last = journal.entries.last()
            .context("behavioral history requires an admitted observation")?;
        ensure!(
            snapshot.behavioral_observation_heads.get(&stream)
                == Some(&last.report.observation_id),
            "behavioral journal does not match its retained signed registry head"
        );
        let series = measured_trajectory(journal.entries.iter().map(|entry| &entry.envelope))?;
        let detector_ready = series.samples.len() >= detector.min_samples_for_detection;
        let hints = if detector_ready {
            detect_camouflage(&series, &detector)?
        } else {
            Vec::new()
        };
        let max_severity = detector_ready.then(|| {
            hints.iter().map(|hint| hint.severity).fold(0.0_f64, f64::max)
        });
        let observation = &last.envelope.observation;
        let current_artifact = snapshot.cards_by_extension
            .get(&observation.extension_id)
            .and_then(|history| history.last())
            .is_some_and(|card| {
                card.extension.version == observation.package_version
                    && card.provenance_summary.artifact_hashes.contains(&observation.artifact_hash)
            });
        assessments.push(BehavioralStreamAssessment {
            stream_id: stream,
            extension_id: observation.extension_id.clone(),
            package_version: observation.package_version.clone(),
            artifact_hash: observation.artifact_hash.clone(),
            collector_key_id: last.envelope.collector_key_id.clone(),
            workload_id: observation.workload_id.clone(),
            measurement_scope: observation.measurement_scope.clone(),
            sample_count: series.samples.len(),
            last_observation_id: last.report.observation_id.clone(),
            observed_at_epoch_secs: observation.observed_at_epoch_secs,
            current_artifact,
            detector_ready,
            hints,
            max_severity,
        });
    }
    Ok(assessments)
}

/// Check the stored byte count before materializing an untrusted journal.
/// The caller holds a transaction, so the size and value belong to one snapshot.
fn read_assessment_slot(
    connection: &fsqlite::Connection,
    slot: &str,
    max_bytes: usize,
    snapshot_path: &Path,
) -> std::result::Result<Option<String>, TrustCardError> {
    let rows = connection.query_with_params(
        "SELECT length(CAST(canonical_json AS BLOB)) FROM registry_state WHERE slot = ?1;",
        &[fsqlite::SqliteValue::Text(slot.into())],
    ).map_err(|error| TrustCardError::SnapshotRead {
        path: snapshot_path.to_path_buf(),
        detail: format!("measure behavioral history slot: {error}"),
    })?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let Some(fsqlite::SqliteValue::Integer(length)) = row.values().first() else {
        return Err(TrustCardError::InvalidSnapshot(
            "behavioral history slot has an invalid byte length".to_string(),
        ));
    };
    if usize::try_from(*length).map_or(true, |length| length > max_bytes) {
        return Err(TrustCardError::InvalidSnapshot(format!(
            "behavioral history slot exceeds its {max_bytes}-byte assessment budget"
        )));
    }
    let encoded = read_slot(connection, slot)?;
    if encoded.as_ref().is_some_and(|value| value.len() > max_bytes) {
        return Err(TrustCardError::InvalidSnapshot(
            "behavioral history changed during bounded read".to_string(),
        ));
    }
    Ok(encoded)
}

fn measured_trajectory<'a>(
    envelopes: impl Iterator<Item = &'a SignedBehavioralObservation>,
) -> Result<TrajectorySeries> {
    let mut series = TrajectorySeries::default();
    for signed in envelopes {
        let observed = &signed.observation;
        let sample = TrajectorySample::new(
            i64::try_from(observed.observed_at_epoch_secs)?,
            measured_vector(&observed.observed_capabilities, observed.workload_iterations)?,
            measured_vector(&observed.declared_capabilities, observed.workload_iterations)?,
        )?;
        crate::security::trajectory_gaming::append_sample(&mut series, sample)?;
    }
    Ok(series)
}

/// Admit one signed observation and return the real resulting trust decision.
///
/// Verification precedes any store access. Every accepted observation adds
/// evidence to the exact current package version's card. Four comparable
/// samples enable the existing BPET detector; findings raise risk through
/// `mark_camouflage_suspected`. Revocation/quarantine are never cleared.
/// Card, journal and registry high-water commit in one existing fsqlite
/// transaction. Concurrent changes fail closed; retry from this entrypoint.
pub fn ingest_observation(
    snapshot_path: &Path,
    trust_config: &TrustConfig,
    envelope_bytes: &[u8],
    trusted_collector: &VerifyingKey,
    now_secs: u64,
) -> Result<BehavioralIngestionReport> {
    ensure!(
        envelope_bytes.len() <= MAX_OBSERVATION_BYTES,
        "behavioral observation exceeds {MAX_OBSERVATION_BYTES} bytes"
    );
    let envelope: SignedBehavioralObservation =
        serde_json::from_slice(envelope_bytes).context("invalid behavioral observation JSON")?;
    envelope.verify(trusted_collector, now_secs)?;
    let observation_id = envelope.observation_id()?;
    let stream_id = stream_id(&envelope)?;
    let slot = format!("behavioral-observations:{stream_id}");
    let registry_key = Zeroizing::new(get_registry_key(trust_config)?);
    let mut registry = TrustCardRegistry::load_authoritative_state_from_config(
        snapshot_path,
        trust_config,
        now_secs,
        SnapshotSourceContext::TrustedFile,
    )?;
    let store = TrustCardRegistryStore::open(snapshot_path)?;
    let encoded_previous =
        store.with_immediate_transaction(|connection, _| read_slot(connection, &slot))?;
    let mut journal = match encoded_previous.as_deref() {
        Some(encoded) => {
            ensure!(
                encoded.len() <= MAX_JOURNAL_BYTES,
                "behavioral observation journal exceeds size limit"
            );
            let journal: ObservationJournal = serde_json::from_str(encoded)
                .context("invalid stored behavioral observation journal")?;
            journal.validate(&stream_id, &registry_key, trusted_collector, now_secs)?;
            journal
        }
        None => ObservationJournal {
            schema_version: JOURNAL_SCHEMA.to_string(),
            stream_id: stream_id.clone(),
            entries: Vec::new(),
            mac: String::new(),
        },
    };
    validate_registry_anchor(&registry, &journal)?;
    if let Some(existing) = journal
        .entries
        .iter()
        .find(|entry| entry.report.observation_id == observation_id)
    {
        let mut report = existing.report.clone();
        report.status = BehavioralIngestionStatus::Duplicate;
        return Ok(report);
    }
    ensure!(
        journal.entries.len() < MAX_OBSERVATIONS_PER_STREAM,
        "behavioral stream reached its {MAX_OBSERVATIONS_PER_STREAM}-observation retention limit; choose a new explicit workload epoch"
    );
    validate_successor(
        journal.entries.last().map(|entry| &entry.envelope),
        &envelope,
    )?;
    let observation = &envelope.observation;
    let card = registry
        .read(
            &observation.extension_id,
            now_secs,
            "behavioral-observation-admission",
        )?
        .ok_or_else(|| {
            anyhow::anyhow!("behavioral observation requires an existing verified trust card")
        })?;
    ensure!(
        card.extension.version == observation.package_version,
        "behavioral observation package version does not match the current verified trust card"
    );
    ensure!(
        card.provenance_summary
            .artifact_hashes
            .contains(&observation.artifact_hash),
        "behavioral observation artifact digest is not bound to the current verified trust card"
    );

    let series = measured_trajectory(
        journal.entries.iter().map(|entry| &entry.envelope)
            .chain(std::iter::once(&envelope)),
    )?;
    let config = DetectorConfig::default();
    let hints = if series.samples.len() >= config.min_samples_for_detection {
        detect_camouflage(&series, &config)?
    } else {
        Vec::new()
    };
    let evidence_ref = format!(
        "behavioral-observation:{}",
        observation_id.trim_start_matches("sha256:")
    );
    let evidence = vec![VerifiedEvidenceRef {
        evidence_id: evidence_ref.clone(),
        evidence_type: EvidenceType::ReputationSignal,
        verified_at_epoch: now_secs,
        verification_receipt_hash: observation_id.clone(),
    }];
    let trace_id = observation_trace_id(&stream_id, &observation_id);
    let next_card = if hints.is_empty() {
        registry.update(
            &observation.extension_id,
            TrustCardMutation {
                certification_level: None,
                revocation_status: None,
                active_quarantine: None,
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: None,
                last_verified_timestamp: None,
                evidence_refs: Some(evidence),
            },
            now_secs,
            &trace_id,
        )?
    } else {
        // Detector reports can contain more findings than a card can retain.
        // Keep all findings in the authenticated report; carry the strongest
        // bounded subset onto the card without losing the maximum risk signal.
        let card_hints = strongest_card_hints(&hints);
        registry.mark_camouflage_suspected(
            &observation.extension_id,
            &card_hints,
            evidence,
            now_secs,
            &trace_id,
        )?
    };
    let report = BehavioralIngestionReport {
        schema_version: INGESTION_SCHEMA.to_string(),
        status: BehavioralIngestionStatus::Accepted,
        observation_id,
        stream_id,
        extension_id: observation.extension_id.clone(),
        package_version: observation.package_version.clone(),
        artifact_hash: observation.artifact_hash.clone(),
        collector_key_id: envelope.collector_key_id.clone(),
        workload_id: observation.workload_id.clone(),
        sample_count: journal.entries.len() + 1,
        hints,
        card_version: next_card.trust_card_version,
        card_hash: next_card.card_hash,
        risk_level: next_card.user_facing_risk_assessment.level,
        evidence_ref,
    };
    registry.advance_behavioral_observation_head(
        &report.stream_id,
        journal
            .entries
            .last()
            .map(|entry| entry.report.observation_id.as_str()),
        &report.observation_id,
    )?;
    journal.entries.push(JournalEntry {
        envelope,
        report: report.clone(),
    });
    journal.mac = journal.compute_mac(&registry_key)?;
    let encoded = serde_json::to_string(&journal)?;
    ensure!(
        encoded.len() <= MAX_JOURNAL_BYTES,
        "behavioral observation journal exceeds size limit"
    );
    registry.persist_authoritative_state_with_slot(
        snapshot_path,
        Some((&slot, encoded_previous.as_deref(), &encoded)),
    )?;
    Ok(report)
}

// Bind the journal's latest admitted observation to a non-evicting commitment
// in the signed registry snapshot. Card and audit history are bounded and are
// insufficient to distinguish a new stream from a deleted, aged-out stream.
fn validate_registry_anchor(
    registry: &TrustCardRegistry,
    journal: &ObservationJournal,
) -> Result<()> {
    let anchor = registry.behavioral_observation_head(&journal.stream_id);
    match (journal.entries.last(), anchor) {
        (None, None) => Ok(()),
        (Some(last), Some(anchor)) if anchor == last.report.observation_id => Ok(()),
        _ => bail!(
            "behavioral journal does not match its retained signed registry head; restore coherent evidence before retrying"
        ),
    }
}

fn observation_trace_prefix(stream: &str) -> String {
    format!("behavior:{}:", stream.trim_start_matches("sha256:"))
}

fn observation_trace_id(stream: &str, observation: &str) -> String {
    format!(
        "{}{}",
        observation_trace_prefix(stream),
        observation.trim_start_matches("sha256:")
    )
}

fn stream_id(envelope: &SignedBehavioralObservation) -> Result<String> {
    Ok(domain_hash(
        STREAM_DOMAIN,
        &serde_json::to_vec(&(
            &envelope.observation.extension_id,
            &envelope.collector_key_id,
            &envelope.observation.workload_id,
        ))?,
    ))
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn validate_successor(
    prior: Option<&SignedBehavioralObservation>,
    next: &SignedBehavioralObservation,
) -> Result<()> {
    let current = &next.observation;
    let Some(prior) = prior else {
        ensure!(
            current.sequence == 0 && current.previous_observation_id.is_none(),
            "first behavioral observation requires sequence zero and no predecessor"
        );
        return Ok(());
    };
    let previous = &prior.observation;
    ensure!(
        previous.sequence.checked_add(1) == Some(current.sequence),
        "behavioral observation sequence conflicts with or skips the stored head"
    );
    ensure!(
        current.previous_observation_id.as_deref() == Some(prior.observation_id()?.as_str()),
        "behavioral observation does not extend the stored content-hash chain"
    );
    ensure!(
        current.observed_at_epoch_secs > previous.observed_at_epoch_secs,
        "behavioral observation timestamp must advance strictly"
    );
    ensure!(
        current.extension_id == previous.extension_id
            && current.workload_id == previous.workload_id
            && current.measurement_scope == previous.measurement_scope
            && current.window_duration_ms == previous.window_duration_ms
            && current.workload_iterations == previous.workload_iterations
            && current.declared_capabilities == previous.declared_capabilities,
        "behavioral observation changes the measurement contract; use a new explicit workload id"
    );
    Ok(())
}

fn validate_observation(observation: &BehavioralObservation) -> Result<()> {
    for (field, value, max) in [
        ("extension_id", observation.extension_id.as_str(), 256),
        ("package_version", observation.package_version.as_str(), 128),
        ("workload_id", observation.workload_id.as_str(), 128),
    ] {
        ensure!(
            valid_label(value, max),
            "invalid behavioral observation {field}"
        );
    }
    ensure!(
        exact_package_version(&observation.package_version),
        "behavioral observation requires an exact semantic package version"
    );
    ensure!(
        valid_artifact_hash(&observation.artifact_hash),
        "behavioral observation artifact must be a canonical sha256 or sha512 digest"
    );
    ensure!(
        observation.measurement_scope == "isolated_package",
        "behavioral observation requires collector-attested isolated_package scope"
    );
    ensure!(
        i64::try_from(observation.observed_at_epoch_secs).is_ok(),
        "behavioral observation timestamp exceeds supported range"
    );
    ensure!(
        (1..=86_400_000).contains(&observation.window_duration_ms),
        "behavioral observation window must be positive and at most one day"
    );
    ensure!(
        (1..=1_000_000).contains(&observation.workload_iterations),
        "behavioral observation iterations must be in 1..=1000000"
    );
    if let Some(previous) = &observation.previous_observation_id {
        ensure!(
            previous
                .strip_prefix("sha256:")
                .is_some_and(|digest| is_lower_hex(digest, 64)),
            "behavioral observation predecessor must be a canonical sha256 content id"
        );
    }
    ensure!(
        !observation.declared_capabilities.is_empty()
            && observation.declared_capabilities.len() <= MAX_CAPABILITY_DIMENSIONS,
        "behavioral observation requires 1..={MAX_CAPABILITY_DIMENSIONS} measured dimensions"
    );
    ensure!(
        observation
            .observed_capabilities
            .keys()
            .eq(observation.declared_capabilities.keys()),
        "behavioral observation measured and declared dimensions must match exactly; missing evidence is not zero"
    );
    for (name, value) in &observation.declared_capabilities {
        ensure!(
            valid_label(name, 64),
            "invalid behavioral capability dimension"
        );
        ensure!(
            (1..=MAX_CAPABILITY_COUNT).contains(value),
            "declared behavioral capability counts must be positive and bounded"
        );
    }
    ensure!(
        observation
            .observed_capabilities
            .values()
            .all(|value| *value <= MAX_CAPABILITY_COUNT),
        "observed behavioral capability counts exceed the supported bound"
    );
    Ok(())
}

fn exact_package_version(version: &str) -> bool {
    let (without_build, build) = version
        .split_once('+')
        .map_or((version, None), |(base, suffix)| (base, Some(suffix)));
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(base, suffix)| (base, Some(suffix)));
    let core: Vec<_> = core.split('.').collect();
    if core.len() != 3
        || core.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return false;
    }
    if prerelease.is_some_and(|suffix| {
        suffix.split('.').any(|part| {
            part.len() > 1
                && part.starts_with('0')
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
    }) {
        return false;
    }
    [build, prerelease].into_iter().flatten().all(|suffix| {
        suffix.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    })
}

fn valid_artifact_hash(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
        || value
            .strip_prefix("sha512:")
            .is_some_and(|digest| is_lower_hex(digest, 128))
}

fn valid_label(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn measured_vector(
    counts: &BTreeMap<String, u64>,
    workload_iterations: u64,
) -> Result<BTreeMap<String, f64>> {
    ensure!(
        workload_iterations > 0,
        "behavioral workload requires completed iterations"
    );
    let iterations = f64::from(u32::try_from(workload_iterations)?);
    counts
        .iter()
        .map(|(name, count)| Ok((name.clone(), f64::from(u32::try_from(*count)?) / iterations)))
        .collect()
}

fn strongest_card_hints(hints: &[CamouflageHint]) -> Vec<CamouflageHint> {
    let mut retained = hints.to_vec();
    if retained.len() > MAX_CAMOUFLAGE_HINTS_ON_CARD {
        // Stable sorting keeps detector order for equal severities.
        retained.sort_by(|left, right| right.severity.total_cmp(&left.severity));
        retained.truncate(MAX_CAMOUFLAGE_HINTS_ON_CARD);
    }
    retained
}

fn deserialize_unique_counts<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, u64>, D::Error> {
    struct CountsVisitor;
    impl<'de> Visitor<'de> for CountsVisitor {
        type Value = BTreeMap<String, u64>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded object of unique capability names and integer counts")
        }
        fn visit_map<M: MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut counts = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, u64>()? {
                if counts.len() >= MAX_CAPABILITY_DIMENSIONS
                    || counts.insert(key.clone(), value).is_some()
                {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate or excessive behavioral capability dimension `{key}`"
                    )));
                }
            }
            Ok(counts)
        }
    }
    deserializer.deserialize_map(CountsVisitor)
}
