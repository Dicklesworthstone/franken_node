//! Independently authenticate enrolled supervisors' held native populations.
//!
//! Accepts the existing HTTP epoch-barrier response or `fleet certify-quiescence
//! --json` output. The caller supplies the complete enrolled audience, public
//! keys, project identities, reviewed action checkpoints, hold owners and a
//! trusted evaluation time separately from that evidence. Embedded public-key
//! identities never become trust anchors. No product crate, network, filesystem
//! access or guest execution is involved.
//!
//! Observation verification authenticates the supervisors' historical statements
//! and checks their relationship to the expected action context. The separate
//! epoch-commit API additionally requires an independently enrolled coordinator
//! and its authorization and committed-statement signatures. Neither API proves
//! that admission fences remain held now. The caller's checkpoint/hold pins must
//! come from its own reviewed action history. This reader does not reconstruct
//! that history or independently observe processes, external effects or
//! unrecorded sessions.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Datelike, SecondsFormat, Timelike, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::counterfactual::canonical_json_bytes;
use crate::incident_bundle::decode_evidence_json;

pub const MAX_FLEET_QUIESCENCE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FLEET_QUIESCENCE_POLICY_BYTES: usize = 1024 * 1024;
pub const FLEET_QUIESCENCE_POLICY_SCHEMA: &str = "franken-verifier/fleet-quiescence-policy/v1";
pub const FLEET_QUIESCENCE_OBSERVATIONS_SCHEMA: &str =
    "franken-verifier/fleet-quiescence-observations/v1";
pub const FLEET_EPOCH_COMMIT_SCHEMA: &str = "franken-verifier/fleet-epoch-commit/v1";
const MAX_PARTICIPANTS: usize = 1024;
const MAX_ACTIONS: u64 = 16_384;
const MAX_HOLDS: usize = 64;
const MAX_AGE_SECONDS: u64 = 300;
const CHECKPOINT_DOMAIN: &[u8] = b"franken-node/native-session-drain-checkpoint/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"franken-node/native-session-drain-signature/v1\0";
const EPOCH_RESPONSE_SCHEMA: &str = "franken-node/fleet-epoch-commit-response/v1";
const EPOCH_PROOF_SCHEMA: &str = "franken-node/fleet-epoch-commit-proof/v1";
const EPOCH_STATEMENT_SCHEMA: &str = "franken-node/fleet-epoch-commit-statement/v1";
const EPOCH_MANIFEST_DOMAIN: &[u8] = b"franken-node/fleet-epoch-quiescence-manifest/v1\0";
const EPOCH_AUTHORIZATION_DOMAIN: &[u8] = b"franken-node/fleet-epoch-authorization-signature/v1\0";
const EPOCH_COMMIT_DOMAIN: &[u8] = b"franken-node/fleet-epoch-commit-signature/v1\0";

/// An independently retained ordered action checkpoint, never a self-supplied
/// authority from the response being verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetActionCheckpoint {
    pub action_count: u64,
    pub actions_sha256: String,
}

/// One independently enrolled supervisor and its expected maintenance context.
/// `minimum_generation` retains the caller's anti-rollback floor. Session-set
/// commitments are authenticated statements by this supervisor, not an
/// independently inventoried population.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetSupervisorExpectation {
    pub zone_id: String,
    pub node_id: String,
    pub supervisor_public_key_hex: String,
    pub project_root_sha256: String,
    pub minimum_generation: u64,
    pub expected_applied_actions: FleetActionCheckpoint,
    pub expected_active_hold_ids: Vec<String>,
}

/// Caller-owned verification policy. Every participant must be present exactly
/// once; both the policy and response use strictly sorted `(zone_id, node_id)`
/// order. Keep this policy outside the evidence's untrusted transport.
///
/// `expected_pre_epoch` and `expected_trace_id` select the expected response
/// context. Observation verification alone does not authenticate those fields;
/// epoch-commit verification additionally requires a separately trusted
/// coordinator's signed statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetQuiescencePolicy {
    pub schema_version: String,
    pub evaluation_time: DateTime<Utc>,
    pub max_observation_age_secs: u64,
    pub expected_action_log: FleetActionCheckpoint,
    pub expected_pre_epoch: u64,
    pub expected_trace_id: String,
    pub participants: Vec<FleetSupervisorExpectation>,
}

/// Source-free facts. Unsupported stronger conclusions remain explicitly false,
/// even though the producer's certificate uses a "certified" scope label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FleetQuiescenceFacts {
    pub schema_version: &'static str,
    pub evidence_sha256: String,
    pub trust_policy_sha256: String,
    pub evaluation_time: String,
    pub observed_at: String,
    pub participant_count: usize,
    pub admitted_sessions: u64,
    pub terminal_sessions: u64,
    pub supervisor_signatures_verified: bool,
    pub expected_population_complete: bool,
    pub expected_action_context_matched: bool,
    pub epoch_commit_authenticated: bool,
    pub current_quiescence_proven: bool,
}

/// Independently retained coordinator enrollment, separate from both the
/// candidate response and the enrolled-supervisor policy. A key advertised by
/// the candidate can never substitute for this trust anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetCoordinatorTrust {
    pub coordinator_id: String,
    pub coordinator_public_key_hex: String,
}

/// Authenticated historical coordinator commit and enrolled local observations.
/// The exact retained epoch is authenticated; current fleet quiescence remains
/// explicitly unproven. Integer counters remain native u64 values for Rust
/// callers and are emitted as decimal strings by the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FleetEpochCommitFacts {
    pub schema_version: &'static str,
    pub evidence_sha256: String,
    pub trust_policy_sha256: String,
    pub evaluation_time: String,
    pub observed_at: String,
    pub participant_count: usize,
    pub admitted_sessions: u64,
    pub terminal_sessions: u64,
    pub supervisor_signatures_verified: bool,
    pub expected_population_complete: bool,
    pub expected_action_context_matched: bool,
    pub epoch_commit_authenticated: bool,
    pub current_quiescence_proven: bool,
    pub coordinator_id: String,
    pub coordinator_key_id: String,
    pub committed_epoch: u64,
    pub transition_id: String,
    pub statement_sha256: String,
}

/// Stable errors never echo evidence, private project paths, keys or node IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetQuiescenceError {
    InputTooLarge,
    JsonInvalid,
    PolicyInvalid,
    SchemaUnsupported,
    ContextMismatch,
    PopulationMismatch,
    ObservationInvalid,
    ObservationStale,
    SignerUntrusted,
    SignatureInvalid,
    CountOverflow,
    CoordinatorTrustInvalid,
    EpochProofMissing,
    EpochProofInvalid,
    CoordinatorUntrusted,
    EpochSignatureInvalid,
}

impl FleetQuiescenceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputTooLarge => "FLEET_INPUT_TOO_LARGE",
            Self::JsonInvalid => "FLEET_JSON_INVALID",
            Self::PolicyInvalid => "FLEET_POLICY_INVALID",
            Self::SchemaUnsupported => "FLEET_SCHEMA_UNSUPPORTED",
            Self::ContextMismatch => "FLEET_CONTEXT_MISMATCH",
            Self::PopulationMismatch => "FLEET_POPULATION_MISMATCH",
            Self::ObservationInvalid => "FLEET_OBSERVATION_INVALID",
            Self::ObservationStale => "FLEET_OBSERVATION_STALE",
            Self::SignerUntrusted => "FLEET_SIGNER_UNTRUSTED",
            Self::SignatureInvalid => "FLEET_SIGNATURE_INVALID",
            Self::CountOverflow => "FLEET_COUNT_OVERFLOW",
            Self::CoordinatorTrustInvalid => "FLEET_COORDINATOR_TRUST_INVALID",
            Self::EpochProofMissing => "FLEET_EPOCH_PROOF_MISSING",
            Self::EpochProofInvalid => "FLEET_EPOCH_PROOF_INVALID",
            Self::CoordinatorUntrusted => "FLEET_COORDINATOR_UNTRUSTED",
            Self::EpochSignatureInvalid => "FLEET_EPOCH_SIGNATURE_INVALID",
        }
    }
}

impl fmt::Display for FleetQuiescenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "fleet verification input exceeds its byte bound",
            Self::JsonInvalid => "fleet verification input has invalid or ambiguous JSON",
            Self::PolicyInvalid => "fleet verification policy is invalid",
            Self::SchemaUnsupported => "fleet quiescence evidence schema is unsupported",
            Self::ContextMismatch => "fleet response differs from the expected action context",
            Self::PopulationMismatch => "fleet response differs from the enrolled population",
            Self::ObservationInvalid => {
                "fleet supervisor observation is inconsistent or incomplete"
            }
            Self::ObservationStale => "fleet supervisor evidence is future-dated or expired",
            Self::SignerUntrusted => "fleet supervisor differs from its independent enrollment",
            Self::SignatureInvalid => "fleet supervisor signature verification failed",
            Self::CountOverflow => "fleet session population exceeds the aggregate count bound",
            Self::CoordinatorTrustInvalid => "fleet coordinator trust anchor is invalid",
            Self::EpochProofMissing => "fleet response has no authenticated coordinator commit",
            Self::EpochProofInvalid => "fleet coordinator proof is inconsistent or incomplete",
            Self::CoordinatorUntrusted => {
                "fleet coordinator differs from its independent enrollment"
            }
            Self::EpochSignatureInvalid => "fleet coordinator signature verification failed",
        })
    }
}

impl std::error::Error for FleetQuiescenceError {}

type Result<T> = std::result::Result<T, FleetQuiescenceError>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: String,
    evidence: Evidence,
    certificate: Certificate,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliResponse {
    schema_version: String,
    command: String,
    ok: bool,
    transport: String,
    live_control_plane: bool,
    control_plane_url: String,
    evidence: Evidence,
    certificate: Certificate,
}

// No Debug: the statement retains private maintenance trace/transition context.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochCommitStatement {
    schema_version: String,
    coordinator_id: String,
    coordinator_key_id: String,
    evidence_certificate_sha256: String,
    pre_epoch: u64,
    committed_epoch: u64,
    transition_id: String,
    trace_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochCommitProof {
    schema_version: String,
    statement: EpochCommitStatement,
    authorization_signature_hex: String,
    commit_signature_hex: String,
}

struct ParsedResponse {
    response: Response,
    commit_proof: Option<EpochCommitProof>,
    manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema_version: String,
    scope: String,
    observed_at: DateTime<Utc>,
    stale_after: FreshnessWindow,
    action_count: u64,
    complete: bool,
    fleet_quiescence_certified: bool,
    uncovered_zones: Vec<String>,
    nodes: Vec<NodeEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessWindow {
    secs: u64,
    nanos: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeEvidence {
    zone_id: String,
    node_id: String,
    expected_actions: FleetActionCheckpoint,
    last_seen: Option<DateTime<Utc>>,
    health: Option<String>,
    applied_actions: Option<FleetActionCheckpoint>,
    native_session_drain: Option<DrainCheckpoint>,
    ready: bool,
    reason: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainCheckpoint {
    applied_actions: FleetActionCheckpoint,
    session_set_sha256: String,
    admitted_sessions: u64,
    terminal_sessions: u64,
    pending_sessions: u64,
    indeterminate_sessions: u64,
    fence_held: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supervisor_attestation: Option<DrainAttestation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainAttestation {
    schema_version: String,
    node_id: String,
    zone_id: String,
    drain_id: String,
    generation: u64,
    project_root_sha256: String,
    observed_at: DateTime<Utc>,
    product_root_key_id: String,
    checkpoint_sha256: String,
    signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    schema_version: String,
    transition_id: String,
    pre_epoch: u64,
    committed_epoch: u64,
    initiator: String,
    reason: String,
    trace_id: String,
    certified_at: DateTime<Utc>,
    action_log_checkpoint: FleetActionCheckpoint,
    fleet_quiescence_certified: bool,
    participants: Vec<Participant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Participant {
    zone_id: String,
    node_id: String,
    stage: String,
    drain_id: String,
    generation: u64,
    admitted_sessions: u64,
    terminal_sessions: u64,
    session_set_sha256: String,
    checkpoint_sha256: String,
    supervisor_key_id: String,
    active_hold_ids: Vec<String>,
}

fn digest_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn text_shape(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

fn checkpoint_shape(checkpoint: &FleetActionCheckpoint) -> bool {
    checkpoint.action_count > 0
        && checkpoint.action_count <= MAX_ACTIONS
        && digest_shape(&checkpoint.actions_sha256)
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|_| FleetQuiescenceError::JsonInvalid)?;
    canonical_json_bytes(&value).map_err(|_| FleetQuiescenceError::JsonInvalid)
}

fn ct_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn public_key(encoded: &str) -> Result<VerifyingKey> {
    if !digest_shape(encoded) {
        return Err(FleetQuiescenceError::PolicyInvalid);
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| FleetQuiescenceError::PolicyInvalid)?;
    VerifyingKey::from_bytes(&bytes)
        .ok()
        .filter(|key| !key.is_weak())
        .ok_or(FleetQuiescenceError::PolicyInvalid)
}

fn timestamp_shape(value: DateTime<Utc>) -> bool {
    // Keep accepted typed timestamps in the same exact, non-leap RFC3339
    // range as the independent Python and JavaScript fact readers.
    (0..=9999).contains(&value.year()) && value.nanosecond() < 1_000_000_000
}

fn validate_policy(policy: &FleetQuiescencePolicy) -> Result<Vec<VerifyingKey>> {
    if policy.schema_version != FLEET_QUIESCENCE_POLICY_SCHEMA
        || !timestamp_shape(policy.evaluation_time)
        || !(1..=MAX_AGE_SECONDS).contains(&policy.max_observation_age_secs)
        || !checkpoint_shape(&policy.expected_action_log)
        || policy.expected_pre_epoch == u64::MAX
        || !text_shape(&policy.expected_trace_id)
        || policy.participants.is_empty()
        || policy.participants.len() > MAX_PARTICIPANTS
    {
        return Err(FleetQuiescenceError::PolicyInvalid);
    }
    let mut previous = None;
    let mut zones = BTreeMap::new();
    let mut roots = Vec::with_capacity(policy.participants.len());
    for participant in &policy.participants {
        let identity = (participant.zone_id.as_str(), participant.node_id.as_str());
        let holds = &participant.expected_active_hold_ids;
        if !identifier(&participant.zone_id)
            || participant.zone_id == "all"
            || !identifier(&participant.node_id)
            || previous.is_some_and(|value| value >= identity)
            || !digest_shape(&participant.project_root_sha256)
            || participant.minimum_generation == 0
            || !checkpoint_shape(&participant.expected_applied_actions)
            || participant.expected_applied_actions.action_count
                > policy.expected_action_log.action_count
            || holds.is_empty()
            || holds.len() > MAX_HOLDS
            || holds.iter().any(|hold| !identifier(hold))
            || holds.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(FleetQuiescenceError::PolicyInvalid);
        }
        previous = Some(identity);
        let context = (&participant.expected_applied_actions, holds);
        if zones
            .insert(participant.zone_id.as_str(), context)
            .is_some_and(|previous| previous != context)
        {
            return Err(FleetQuiescenceError::PolicyInvalid);
        }
        roots.push(public_key(&participant.supervisor_public_key_hex)?);
    }
    if canonical_bytes(policy)?.len() > MAX_FLEET_QUIESCENCE_POLICY_BYTES {
        return Err(FleetQuiescenceError::InputTooLarge);
    }
    Ok(roots)
}

/// Parse a separate caller-owned policy with duplicate-member rejection and
/// bounded allocation. The timestamp must use canonical UTC RFC3339 so policy
/// commitments are reproducible by command-line and language bindings.
pub fn parse_fleet_quiescence_policy(bytes: &[u8]) -> Result<FleetQuiescencePolicy> {
    if bytes.len() > MAX_FLEET_QUIESCENCE_POLICY_BYTES {
        return Err(FleetQuiescenceError::InputTooLarge);
    }
    let value = decode_evidence_json(bytes).map_err(|_| FleetQuiescenceError::JsonInvalid)?;
    let policy: FleetQuiescencePolicy =
        serde_json::from_value(value.clone()).map_err(|_| FleetQuiescenceError::PolicyInvalid)?;
    if value.get("evaluation_time").and_then(Value::as_str)
        != Some(
            policy
                .evaluation_time
                .to_rfc3339_opts(SecondsFormat::AutoSi, true)
                .as_str(),
        )
    {
        return Err(FleetQuiescenceError::PolicyInvalid);
    }
    validate_policy(&policy)?;
    Ok(policy)
}

fn parse_response(bytes: &[u8]) -> Result<ParsedResponse> {
    if bytes.len() > MAX_FLEET_QUIESCENCE_RESPONSE_BYTES {
        return Err(FleetQuiescenceError::InputTooLarge);
    }
    let mut value = decode_evidence_json(bytes).map_err(|_| FleetQuiescenceError::JsonInvalid)?;
    let schema = value
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or(FleetQuiescenceError::SchemaUnsupported)?;
    let signed = matches!(
        schema,
        EPOCH_RESPONSE_SCHEMA | "franken-node/fleet-quiescence-cli/v2"
    );
    let cli = matches!(
        schema,
        "franken-node/fleet-quiescence-cli/v1" | "franken-node/fleet-quiescence-cli/v2"
    );
    if !signed
        && !matches!(
            schema,
            "franken-node/fleet-http-api/v2" | "franken-node/fleet-quiescence-cli/v1"
        )
    {
        return Err(FleetQuiescenceError::SchemaUnsupported);
    }
    // Hash the raw, duplicate-checked JSON pair before typed timestamp parsing.
    // Re-encoding a DateTime would erase a lexical mutation such as Z -> +00:00.
    // Only the evidence/certificate pair is covered, never mutable CLI metadata.
    let manifest = canonical_bytes(&[&value["evidence"], &value["certificate"]])?;
    let mut hash = Sha256::new();
    hash.update(EPOCH_MANIFEST_DOMAIN);
    hash.update((manifest.len() as u64).to_be_bytes());
    hash.update(&manifest);
    let manifest_sha256 = hex::encode(hash.finalize());
    let commit_proof = if signed {
        let proof = value
            .as_object_mut()
            .and_then(|object| object.remove("commit_proof"))
            .ok_or(FleetQuiescenceError::EpochProofMissing)?;
        Some(serde_json::from_value(proof).map_err(|_| FleetQuiescenceError::EpochProofInvalid)?)
    } else {
        None
    };
    let response = if cli {
        let cli: CliResponse =
            serde_json::from_value(value).map_err(|_| FleetQuiescenceError::ObservationInvalid)?;
        if cli.schema_version
            != if signed {
                "franken-node/fleet-quiescence-cli/v2"
            } else {
                "franken-node/fleet-quiescence-cli/v1"
            }
            || !(cli.command == "fleet.certify-quiescence"
                || signed && cli.command == "fleet.export-epoch")
            || !cli.ok
            || cli.transport != "http"
            || !cli.live_control_plane
            || !text_shape(&cli.control_plane_url)
        {
            return Err(FleetQuiescenceError::ObservationInvalid);
        }
        Response {
            schema_version: "franken-node/fleet-http-api/v2".into(),
            evidence: cli.evidence,
            certificate: cli.certificate,
        }
    } else {
        if signed {
            value["schema_version"] = Value::String("franken-node/fleet-http-api/v2".into());
        }
        serde_json::from_value(value).map_err(|_| FleetQuiescenceError::ObservationInvalid)?
    };
    Ok(ParsedResponse {
        response,
        commit_proof,
        manifest_sha256,
    })
}

fn fresh(observed: DateTime<Utc>, now: DateTime<Utc>, seconds: u64) -> Result<()> {
    fresh_for(observed, now, chrono::Duration::seconds(seconds as i64))
}

fn fresh_for(
    observed: DateTime<Utc>,
    now: DateTime<Utc>,
    threshold: chrono::Duration,
) -> Result<()> {
    if !timestamp_shape(observed) || !timestamp_shape(now) {
        return Err(FleetQuiescenceError::ObservationInvalid);
    }
    if observed > now || now.signed_duration_since(observed) >= threshold {
        return Err(FleetQuiescenceError::ObservationStale);
    }
    Ok(())
}

fn checkpoint_digest(checkpoint: &DrainCheckpoint) -> Result<String> {
    let mut observation =
        serde_json::to_value(checkpoint).map_err(|_| FleetQuiescenceError::JsonInvalid)?;
    observation
        .as_object_mut()
        .ok_or(FleetQuiescenceError::JsonInvalid)?
        .remove("supervisor_attestation");
    let bytes = canonical_bytes(&observation)?;
    let mut digest = Sha256::new();
    digest.update(CHECKPOINT_DOMAIN);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

fn signature_payload(attestation: &DrainAttestation) -> Result<Vec<u8>> {
    let mut value =
        serde_json::to_value(attestation).map_err(|_| FleetQuiescenceError::JsonInvalid)?;
    value
        .as_object_mut()
        .ok_or(FleetQuiescenceError::JsonInvalid)?
        .remove("signature_hex");
    let bytes = canonical_bytes(&value)?;
    let mut payload = SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    payload.extend_from_slice(&bytes);
    Ok(payload)
}

/// Verify held terminal observations under the caller's complete enrolled
/// population. The positive result always leaves epoch-commit authentication
/// and current fleet quiescence false. A coordinator proof carried by the newer
/// envelope is not promoted into an authenticated commit by this API.
///
/// Every signature is checked against a caller-supplied key, freshness against
/// the caller's time, and all population/action/project bindings are checked
/// before aggregate facts are returned. Missing, extra, reordered, stale,
/// foreign, pending, indeterminate or released-fence participants fail closed.
pub fn verify_fleet_quiescence_observations(
    response_bytes: &[u8],
    policy: &FleetQuiescencePolicy,
) -> Result<FleetQuiescenceFacts> {
    let roots = validate_policy(policy)?;
    let parsed = parse_response(response_bytes)?;
    verify_observation_response(response_bytes, policy, &parsed.response, roots)
}

fn verify_observation_response(
    response_bytes: &[u8],
    policy: &FleetQuiescencePolicy,
    response: &Response,
    roots: Vec<VerifyingKey>,
) -> Result<FleetQuiescenceFacts> {
    let evidence = &response.evidence;
    let certificate = &response.certificate;
    if response.schema_version != "franken-node/fleet-http-api/v2"
        || evidence.schema_version != "franken-node/fleet-native-drain-evidence/v1"
        || evidence.scope != "enrolled_epoch_barrier_quiescence_certified"
        || certificate.schema_version != "franken-node/fleet-epoch-quiescence-certificate/v1"
    {
        return Err(FleetQuiescenceError::SchemaUnsupported);
    }
    if evidence.nodes.len() != policy.participants.len()
        || certificate.participants.len() != policy.participants.len()
        || !evidence.uncovered_zones.is_empty()
    {
        return Err(FleetQuiescenceError::PopulationMismatch);
    }
    if !evidence.complete
        || !evidence.fleet_quiescence_certified
        || !certificate.fleet_quiescence_certified
        || certificate.pre_epoch != policy.expected_pre_epoch
        || certificate.pre_epoch.checked_add(1) != Some(certificate.committed_epoch)
        || certificate.trace_id != policy.expected_trace_id
        || certificate.certified_at != evidence.observed_at
        || !text_shape(&certificate.transition_id)
        || !text_shape(&certificate.initiator)
        || !text_shape(&certificate.reason)
        || certificate.action_log_checkpoint != policy.expected_action_log
        || evidence.action_count != policy.expected_action_log.action_count
        || evidence.stale_after.nanos >= 1_000_000_000
        || (evidence.stale_after.secs == 0 && evidence.stale_after.nanos == 0)
        || evidence.stale_after.secs > policy.max_observation_age_secs
        || (evidence.stale_after.secs == policy.max_observation_age_secs
            && evidence.stale_after.nanos != 0)
    {
        return Err(FleetQuiescenceError::ContextMismatch);
    }
    fresh(
        evidence.observed_at,
        policy.evaluation_time,
        policy.max_observation_age_secs,
    )?;
    // The producer's declared window constrains both transport liveness and
    // the signed supervisor observation at certification time. A fresh
    // heartbeat cannot renew an older observation, even when the caller's
    // separate verification policy permits a longer historical lookback.
    let observation_window = chrono::Duration::seconds(evidence.stale_after.secs as i64)
        + chrono::Duration::nanoseconds(i64::from(evidence.stale_after.nanos));
    let mut admitted = 0_u64;
    let mut terminal = 0_u64;
    for (((node, participant), expected), root) in evidence
        .nodes
        .iter()
        .zip(&certificate.participants)
        .zip(&policy.participants)
        .zip(&roots)
    {
        if node.zone_id != expected.zone_id
            || node.node_id != expected.node_id
            || participant.zone_id != expected.zone_id
            || participant.node_id != expected.node_id
        {
            return Err(FleetQuiescenceError::PopulationMismatch);
        }
        if node.expected_actions != expected.expected_applied_actions
            || node.applied_actions.as_ref() != Some(&expected.expected_applied_actions)
            || participant.active_hold_ids != expected.expected_active_hold_ids
        {
            return Err(FleetQuiescenceError::ContextMismatch);
        }
        if !node.ready
            || node.reason != "ready"
            || node.health.as_deref() != Some("maintenance")
            || participant.stage != "epoch_barrier_certified"
        {
            return Err(FleetQuiescenceError::ObservationInvalid);
        }
        let last_seen = node
            .last_seen
            .ok_or(FleetQuiescenceError::ObservationInvalid)?;
        fresh_for(last_seen, evidence.observed_at, observation_window)?;
        fresh(
            last_seen,
            policy.evaluation_time,
            policy.max_observation_age_secs,
        )?;
        let drain = node
            .native_session_drain
            .as_ref()
            .ok_or(FleetQuiescenceError::ObservationInvalid)?;
        let attestation = drain
            .supervisor_attestation
            .as_ref()
            .ok_or(FleetQuiescenceError::ObservationInvalid)?;
        if drain.applied_actions != expected.expected_applied_actions
            || !drain.fence_held
            || drain.pending_sessions != 0
            || drain.indeterminate_sessions != 0
            || drain.admitted_sessions != drain.terminal_sessions
            || !digest_shape(&drain.session_set_sha256)
            || attestation.schema_version != "franken-node/native-session-drain-attestation/v1"
            || !canonical_uuid(&attestation.drain_id)
            || attestation.generation < expected.minimum_generation
            || participant.drain_id != attestation.drain_id
            || participant.generation != attestation.generation
            || participant.admitted_sessions != drain.admitted_sessions
            || participant.terminal_sessions != drain.terminal_sessions
            || participant.session_set_sha256 != drain.session_set_sha256
            || participant.checkpoint_sha256 != attestation.checkpoint_sha256
            || participant.supervisor_key_id != attestation.product_root_key_id
        {
            return Err(FleetQuiescenceError::ObservationInvalid);
        }
        if attestation.zone_id != expected.zone_id
            || attestation.node_id != expected.node_id
            || !ct_equal(
                &attestation.project_root_sha256,
                &expected.project_root_sha256,
            )
            || !ct_equal(
                &attestation.product_root_key_id,
                &format!("ed25519:{}", expected.supervisor_public_key_hex),
            )
        {
            return Err(FleetQuiescenceError::SignerUntrusted);
        }
        if !ct_equal(&attestation.checkpoint_sha256, &checkpoint_digest(drain)?) {
            return Err(FleetQuiescenceError::ObservationInvalid);
        }
        fresh_for(
            attestation.observed_at,
            evidence.observed_at,
            observation_window,
        )?;
        fresh(
            attestation.observed_at,
            policy.evaluation_time,
            policy.max_observation_age_secs,
        )?;
        if attestation.observed_at > last_seen
            || attestation.signature_hex.len() != 128
            || !attestation
                .signature_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FleetQuiescenceError::ObservationInvalid);
        }
        let mut signature = [0_u8; 64];
        hex::decode_to_slice(&attestation.signature_hex, &mut signature)
            .map_err(|_| FleetQuiescenceError::SignatureInvalid)?;
        root.verify_strict(
            &signature_payload(attestation)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| FleetQuiescenceError::SignatureInvalid)?;
        admitted = admitted
            .checked_add(drain.admitted_sessions)
            .ok_or(FleetQuiescenceError::CountOverflow)?;
        terminal = terminal
            .checked_add(drain.terminal_sessions)
            .ok_or(FleetQuiescenceError::CountOverflow)?;
    }
    Ok(FleetQuiescenceFacts {
        schema_version: FLEET_QUIESCENCE_OBSERVATIONS_SCHEMA,
        evidence_sha256: hex::encode(Sha256::digest(response_bytes)),
        trust_policy_sha256: hex::encode(Sha256::digest(canonical_bytes(policy)?)),
        evaluation_time: policy
            .evaluation_time
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
        observed_at: evidence
            .observed_at
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
        participant_count: policy.participants.len(),
        admitted_sessions: admitted,
        terminal_sessions: terminal,
        supervisor_signatures_verified: true,
        expected_population_complete: true,
        expected_action_context_matched: true,
        epoch_commit_authenticated: false,
        current_quiescence_proven: false,
    })
}

fn coordinator_key(trust: &FleetCoordinatorTrust) -> Result<VerifyingKey> {
    if !identifier(&trust.coordinator_id) {
        return Err(FleetQuiescenceError::CoordinatorTrustInvalid);
    }
    public_key(&trust.coordinator_public_key_hex)
        .map_err(|_| FleetQuiescenceError::CoordinatorTrustInvalid)
}

fn epoch_signature_payload(domain: &[u8], statement_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(domain.len() + 8 + statement_bytes.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&(statement_bytes.len() as u64).to_be_bytes());
    payload.extend_from_slice(statement_bytes);
    payload
}

fn verify_epoch_signature(
    key: &VerifyingKey,
    domain: &[u8],
    statement_bytes: &[u8],
    encoded_signature: &str,
) -> Result<()> {
    if encoded_signature.len() != 128
        || !encoded_signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FleetQuiescenceError::EpochProofInvalid);
    }
    let mut bytes = [0_u8; 64];
    hex::decode_to_slice(encoded_signature, &mut bytes)
        .map_err(|_| FleetQuiescenceError::EpochProofInvalid)?;
    key.verify_strict(
        &epoch_signature_payload(domain, statement_bytes),
        &Signature::from_bytes(&bytes),
    )
    .map_err(|_| FleetQuiescenceError::EpochSignatureInvalid)
}

/// Verify a coordinator's historical committed epoch and the exact enrolled
/// supervisors' held observations under independently supplied trust inputs.
///
/// Both authorization and commit signatures are mandatory and use distinct
/// domains over the same statement. An authorization alone is not a commit;
/// an old HMAC-only response or a self-selected coordinator key cannot upgrade
/// into this scope. The statement commits to the complete evidence/certificate
/// pair, including private context omitted from the returned facts.
///
/// This authenticates the trusted coordinator's statement that its transaction
/// committed. It does not independently read its durable database, prove current
/// fences, or replace freshness, complete enrollment and supervisor signatures.
pub fn verify_fleet_epoch_commit(
    response_bytes: &[u8],
    policy: &FleetQuiescencePolicy,
    coordinator: &FleetCoordinatorTrust,
) -> Result<FleetEpochCommitFacts> {
    let key = coordinator_key(coordinator)?;
    let roots = validate_policy(policy)?;
    let parsed = parse_response(response_bytes)?;
    let proof = parsed
        .commit_proof
        .as_ref()
        .ok_or(FleetQuiescenceError::EpochProofMissing)?;
    let statement = &proof.statement;
    let certificate = &parsed.response.certificate;
    if proof.schema_version != EPOCH_PROOF_SCHEMA
        || statement.schema_version != EPOCH_STATEMENT_SCHEMA
        || !identifier(&statement.coordinator_id)
        || !digest_shape(&statement.evidence_certificate_sha256)
        || !text_shape(&statement.transition_id)
        || !text_shape(&statement.trace_id)
    {
        return Err(FleetQuiescenceError::EpochProofInvalid);
    }
    let key_id = format!("ed25519:{}", coordinator.coordinator_public_key_hex);
    if !ct_equal(&statement.coordinator_id, &coordinator.coordinator_id)
        || !ct_equal(&statement.coordinator_key_id, &key_id)
    {
        return Err(FleetQuiescenceError::CoordinatorUntrusted);
    }
    if !ct_equal(
        &statement.evidence_certificate_sha256,
        &parsed.manifest_sha256,
    ) || statement.pre_epoch != certificate.pre_epoch
        || statement.committed_epoch != certificate.committed_epoch
        || statement.transition_id != certificate.transition_id
        || statement.trace_id != certificate.trace_id
    {
        return Err(FleetQuiescenceError::EpochProofInvalid);
    }
    let statement_bytes = canonical_bytes(statement)?;
    verify_epoch_signature(
        &key,
        EPOCH_AUTHORIZATION_DOMAIN,
        &statement_bytes,
        &proof.authorization_signature_hex,
    )?;
    verify_epoch_signature(
        &key,
        EPOCH_COMMIT_DOMAIN,
        &statement_bytes,
        &proof.commit_signature_hex,
    )?;
    let observations =
        verify_observation_response(response_bytes, policy, &parsed.response, roots)?;
    Ok(FleetEpochCommitFacts {
        schema_version: FLEET_EPOCH_COMMIT_SCHEMA,
        evidence_sha256: observations.evidence_sha256,
        trust_policy_sha256: observations.trust_policy_sha256,
        evaluation_time: observations.evaluation_time,
        observed_at: observations.observed_at,
        participant_count: observations.participant_count,
        admitted_sessions: observations.admitted_sessions,
        terminal_sessions: observations.terminal_sessions,
        supervisor_signatures_verified: observations.supervisor_signatures_verified,
        expected_population_complete: observations.expected_population_complete,
        expected_action_context_matched: observations.expected_action_context_matched,
        epoch_commit_authenticated: true,
        current_quiescence_proven: false,
        coordinator_id: coordinator.coordinator_id.clone(),
        coordinator_key_id: key_id,
        committed_epoch: statement.committed_epoch,
        transition_id: statement.transition_id.clone(),
        statement_sha256: hex::encode(Sha256::digest(&statement_bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    fn fixture() -> (Value, FleetQuiescencePolicy) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/fleet_quiescence_observations.json"
        ))
        .unwrap();
        assert_eq!(fixture["live_execution_performed"], false);
        let policy =
            parse_fleet_quiescence_policy(&serde_json::to_vec(&fixture["policy"]).unwrap())
                .unwrap();
        (fixture["http_response"].clone(), policy)
    }

    fn verify(value: &Value, policy: &FleetQuiescencePolicy) -> Result<FleetQuiescenceFacts> {
        verify_fleet_quiescence_observations(&serde_json::to_vec(value).unwrap(), policy)
    }

    fn epoch_fixture() -> (Value, FleetQuiescencePolicy, FleetCoordinatorTrust, Value) {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/fleet_epoch_commit.json"))
                .unwrap();
        assert_eq!(fixture["live_execution_performed"], false);
        let policy =
            parse_fleet_quiescence_policy(&serde_json::to_vec(&fixture["policy"]).unwrap())
                .unwrap();
        let trust = serde_json::from_value(fixture["coordinator_trust"].clone()).unwrap();
        (
            fixture["http_response"].clone(),
            policy,
            trust,
            fixture["expected"].clone(),
        )
    }

    fn verify_epoch(
        value: &Value,
        policy: &FleetQuiescencePolicy,
        trust: &FleetCoordinatorTrust,
    ) -> Result<FleetEpochCommitFacts> {
        verify_fleet_epoch_commit(&serde_json::to_vec(value).unwrap(), policy, trust)
    }

    // Only mutation tests re-sign coordinator proofs here. The immutable
    // positive fixture uses Node crypto and independently encoded wire bytes.
    // Do not repair redundant statement context: tests must expose mismatches.
    fn resign_epoch(value: &mut Value, key: &SigningKey) {
        let bytes = canonical_bytes(&[&value["evidence"], &value["certificate"]]).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"franken-node/fleet-epoch-quiescence-manifest/v1\0");
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        value["commit_proof"]["statement"]["evidence_certificate_sha256"] =
            json!(hex::encode(hash.finalize()));
        let bytes = canonical_bytes(&value["commit_proof"]["statement"]).unwrap();
        for (field, domain) in [
            (
                "authorization_signature_hex",
                b"franken-node/fleet-epoch-authorization-signature/v1\0".as_slice(),
            ),
            (
                "commit_signature_hex",
                b"franken-node/fleet-epoch-commit-signature/v1\0".as_slice(),
            ),
        ] {
            let mut payload = domain.to_vec();
            payload.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            payload.extend_from_slice(&bytes);
            value["commit_proof"][field] = json!(hex::encode(key.sign(&payload).to_bytes()));
        }
    }

    // Negative vectors are re-signed to ensure cryptographic success cannot
    // conceal missing semantic checks. Positive vectors use fixed signatures
    // generated independently in Python, not these helpers or production code.
    fn resign(value: &mut Value, index: usize, key: &SigningKey) {
        let drain = &mut value["evidence"]["nodes"][index]["native_session_drain"];
        let mut observation = drain.clone();
        observation
            .as_object_mut()
            .unwrap()
            .remove("supervisor_attestation");
        let bytes = serde_json::to_vec(&observation).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"franken-node/native-session-drain-checkpoint/v1\0");
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
        let checkpoint_sha256 = hex::encode(hash.finalize());
        let attestation = &mut drain["supervisor_attestation"];
        attestation["checkpoint_sha256"] = json!(checkpoint_sha256);
        let mut payload = attestation.clone();
        payload.as_object_mut().unwrap().remove("signature_hex");
        let bytes = serde_json::to_vec(&payload).unwrap();
        let mut preimage = b"franken-node/native-session-drain-signature/v1\0".to_vec();
        preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        preimage.extend_from_slice(&bytes);
        attestation["signature_hex"] = json!(hex::encode(key.sign(&preimage).to_bytes()));
        value["certificate"]["participants"][index]["checkpoint_sha256"] = json!(checkpoint_sha256);
    }

    #[test]
    fn independent_wire_signatures_authenticate_exact_enrolled_populations() {
        let (response, policy) = fixture();
        let facts = verify(&response, &policy).unwrap();
        assert_eq!(facts.participant_count, 2);
        assert_eq!(facts.admitted_sessions, 5);
        assert_eq!(facts.terminal_sessions, 5);
        assert_eq!(facts.evaluation_time, "2026-11-23T01:00:10Z");
        assert_eq!(facts.observed_at, "2026-11-23T01:00:05Z");
        assert!(facts.supervisor_signatures_verified);
        assert!(facts.expected_population_complete);
        assert!(facts.expected_action_context_matched);
        assert!(!facts.epoch_commit_authenticated);
        assert!(!facts.current_quiescence_proven);
        assert_eq!(
            facts.evidence_sha256,
            hex::encode(Sha256::digest(serde_json::to_vec(&response).unwrap()))
        );
        let serialized = serde_json::to_string(&facts).unwrap();
        for private in [
            "node-a",
            "node-b",
            "hold-east",
            "hold-west",
            "trace-maintenance",
        ] {
            assert!(!serialized.contains(private));
        }
        let pretty = serde_json::to_vec_pretty(&response).unwrap();
        let pretty_facts = verify_fleet_quiescence_observations(&pretty, &policy).unwrap();
        assert_ne!(pretty_facts.evidence_sha256, facts.evidence_sha256);
        assert_eq!(pretty_facts.trust_policy_sha256, facts.trust_policy_sha256);
    }

    #[test]
    fn cli_envelope_preserves_observation_scope_and_rejects_extra_claims() {
        let (response, policy) = fixture();
        let mut cli = json!({
            "schema_version": "franken-node/fleet-quiescence-cli/v1",
            "command": "fleet.certify-quiescence", "ok": true,
            "transport": "http", "live_control_plane": true,
            "control_plane_url": "https://coordinator.invalid/",
            "evidence": response["evidence"], "certificate": response["certificate"],
        });
        let facts = verify(&cli, &policy).unwrap();
        assert_eq!(facts.admitted_sessions, 5);
        assert!(!facts.epoch_commit_authenticated);
        cli["ok"] = json!(false);
        assert_eq!(
            verify(&cli, &policy),
            Err(FleetQuiescenceError::ObservationInvalid)
        );
        cli["ok"] = json!(true);
        cli["unexpected"] = json!("ignored-authority");
        assert_eq!(
            verify(&cli, &policy),
            Err(FleetQuiescenceError::ObservationInvalid)
        );
    }

    #[test]
    fn embedded_keys_and_valid_foreign_signatures_never_enroll_a_supervisor() {
        let (mut response, policy) = fixture();
        let key = SigningKey::from_bytes(&[91; 32]);
        let foreign = format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes()));
        response["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]["product_root_key_id"] =
            json!(foreign);
        response["certificate"]["participants"][0]["supervisor_key_id"] = json!(foreign);
        resign(&mut response, 0, &key);
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::SignerUntrusted)
        );
    }

    #[test]
    fn project_identity_and_generation_floor_survive_valid_resigning() {
        let (response, policy) = fixture();
        let key = SigningKey::from_bytes(&[41; 32]);
        let mut foreign = response.clone();
        foreign["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]["project_root_sha256"] =
            json!("ef".repeat(32));
        resign(&mut foreign, 0, &key);
        assert_eq!(
            verify(&foreign, &policy),
            Err(FleetQuiescenceError::SignerUntrusted)
        );
        let mut rolled_back = response;
        rolled_back["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]["generation"] =
            json!(6);
        rolled_back["certificate"]["participants"][0]["generation"] = json!(6);
        resign(&mut rolled_back, 0, &key);
        assert_eq!(
            verify(&rolled_back, &policy),
            Err(FleetQuiescenceError::ObservationInvalid)
        );
    }

    #[test]
    fn fresh_heartbeats_and_redated_certificates_cannot_renew_old_signatures() {
        let (mut response, mut policy) = fixture();
        policy.evaluation_time = "2026-11-23T01:00:33Z".parse().unwrap();
        response["evidence"]["observed_at"] = json!("2026-11-23T01:00:33Z");
        response["certificate"]["certified_at"] = json!("2026-11-23T01:00:33Z");
        for node in response["evidence"]["nodes"].as_array_mut().unwrap() {
            node["last_seen"] = json!("2026-11-23T01:00:33Z");
        }
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::ObservationStale)
        );
    }

    #[test]
    fn missing_extra_duplicate_reordered_and_renamed_participants_cannot_disappear() {
        let (response, policy) = fixture();
        for mutation in 0..6 {
            let mut altered = response.clone();
            match mutation {
                0 => {
                    altered["evidence"]["nodes"].as_array_mut().unwrap().pop();
                    altered["certificate"]["participants"]
                        .as_array_mut()
                        .unwrap()
                        .pop();
                }
                1 => {
                    let extra = altered["evidence"]["nodes"][0].clone();
                    altered["evidence"]["nodes"]
                        .as_array_mut()
                        .unwrap()
                        .push(extra);
                }
                2 => {
                    altered["evidence"]["nodes"][1] = altered["evidence"]["nodes"][0].clone();
                    altered["certificate"]["participants"][1] =
                        altered["certificate"]["participants"][0].clone();
                }
                3 => {
                    altered["evidence"]["nodes"]
                        .as_array_mut()
                        .unwrap()
                        .swap(0, 1);
                    altered["certificate"]["participants"]
                        .as_array_mut()
                        .unwrap()
                        .swap(0, 1);
                }
                4 => altered["evidence"]["nodes"][0]["node_id"] = json!("renamed"),
                _ => altered["evidence"]["uncovered_zones"] = json!(["missing-zone"]),
            }
            assert_eq!(
                verify(&altered, &policy),
                Err(FleetQuiescenceError::PopulationMismatch),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn freshness_uses_the_callers_clock_and_strict_expiry_boundary() {
        let (response, mut policy) = fixture();
        policy.evaluation_time = "2026-11-23T01:00:32.999999999Z".parse().unwrap();
        assert!(verify(&response, &policy).is_ok());
        policy.evaluation_time = "2026-11-23T01:00:33Z".parse().unwrap();
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::ObservationStale)
        );
        policy.evaluation_time = "2026-11-23T01:00:04Z".parse().unwrap();
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::ObservationStale)
        );
    }

    #[test]
    fn timestamps_preserve_the_same_exact_range_for_rust_cli_and_language_clients() {
        let (response, original) = fixture();
        let leap: DateTime<Utc> = "2026-11-23T01:00:60Z".parse().unwrap();
        let year_time = |year| {
            chrono::NaiveDate::from_ymd_opt(year, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
        };
        for invalid in [leap, year_time(-1), year_time(10_000)] {
            let mut policy = original.clone();
            policy.evaluation_time = invalid;
            policy.max_observation_age_secs = 120;
            assert_eq!(
                verify(&response, &policy),
                Err(FleetQuiescenceError::PolicyInvalid)
            );
            assert_eq!(
                parse_fleet_quiescence_policy(&serde_json::to_vec(&policy).unwrap()),
                Err(FleetQuiescenceError::PolicyInvalid)
            );
            assert_eq!(
                fresh_for(invalid, invalid, chrono::Duration::seconds(1)),
                Err(FleetQuiescenceError::ObservationInvalid)
            );
        }
        for year in [0, 9999] {
            let mut policy = original.clone();
            policy.evaluation_time = year_time(year);
            assert_eq!(
                parse_fleet_quiescence_policy(&serde_json::to_vec(&policy).unwrap()),
                Ok(policy)
            );
        }

        let mut policy = original;
        policy.evaluation_time = "2026-11-23T01:01:03Z".parse().unwrap();
        policy.max_observation_age_secs = 120;
        let mut response = response;
        // This population remains valid under the timestamp-shape test's
        // explicit 120-second bound; freshness limits are tested separately.
        response["evidence"]["stale_after"] = json!({"secs": 120, "nanos": 0});
        response["evidence"]["observed_at"] = json!("2026-11-23T01:01:02Z");
        response["certificate"]["certified_at"] = json!("2026-11-23T01:01:02Z");
        for node in response["evidence"]["nodes"].as_array_mut().unwrap() {
            node["last_seen"] = json!("2026-11-23T01:01:01Z");
        }
        assert!(verify(&response, &policy).is_ok());
        for timestamp in ["aggregate", "heartbeat", "signed"] {
            let mut altered = response.clone();
            match timestamp {
                "aggregate" => {
                    altered["evidence"]["observed_at"] = json!(leap);
                    altered["certificate"]["certified_at"] = json!(leap);
                }
                "heartbeat" => {
                    altered["evidence"]["nodes"][0]["last_seen"] = json!(leap);
                }
                _ => {
                    altered["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]
                        ["observed_at"] = json!(leap);
                    resign(&mut altered, 0, &SigningKey::from_bytes(&[41; 32]));
                }
            }
            assert_eq!(
                verify(&altered, &policy),
                Err(FleetQuiescenceError::ObservationInvalid),
                "{timestamp}"
            );
        }
    }

    #[test]
    fn future_or_post_heartbeat_supervisor_observations_are_rejected() {
        let (response, policy) = fixture();
        let key = SigningKey::from_bytes(&[41; 32]);
        for time in ["2026-11-23T01:00:04.001Z", "2026-11-23T01:00:11Z"] {
            let mut altered = response.clone();
            altered["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]["observed_at"] =
                json!(time);
            resign(&mut altered, 0, &key);
            assert!(verify(&altered, &policy).is_err());
        }
    }

    #[test]
    fn pending_indeterminate_or_released_populations_fail_even_with_valid_signatures() {
        let (response, policy) = fixture();
        let key = SigningKey::from_bytes(&[41; 32]);
        for mutation in 0..5 {
            let mut altered = response.clone();
            let drain = &mut altered["evidence"]["nodes"][0]["native_session_drain"];
            match mutation {
                0 => drain["fence_held"] = json!(false),
                1 => {
                    drain["pending_sessions"] = json!(1);
                    drain["terminal_sessions"] = json!(1);
                }
                2 => {
                    drain["indeterminate_sessions"] = json!(1);
                    drain["terminal_sessions"] = json!(1);
                }
                3 => drain["admitted_sessions"] = json!(3),
                _ => drain["terminal_sessions"] = json!(3),
            }
            resign(&mut altered, 0, &key);
            assert_eq!(
                verify(&altered, &policy),
                Err(FleetQuiescenceError::ObservationInvalid),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn action_snapshot_and_hold_owners_are_caller_pinned_not_certificate_selected() {
        let (response, policy) = fixture();
        for mutation in 0..6 {
            let mut altered = response.clone();
            match mutation {
                0 => {
                    altered["certificate"]["action_log_checkpoint"]["actions_sha256"] =
                        json!("99".repeat(32))
                }
                1 => {
                    altered["evidence"]["nodes"][0]["expected_actions"]["actions_sha256"] =
                        json!("99".repeat(32))
                }
                2 => {
                    altered["certificate"]["participants"][0]["active_hold_ids"] =
                        json!(["another-owner"])
                }
                3 => altered["certificate"]["trace_id"] = json!("another-request"),
                4 => {
                    altered["certificate"]["pre_epoch"] = json!(8);
                    altered["certificate"]["committed_epoch"] = json!(9);
                }
                _ => altered["certificate"]["committed_epoch"] = json!(10),
            }
            assert_eq!(
                verify(&altered, &policy),
                Err(FleetQuiescenceError::ContextMismatch),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn forged_counts_hashes_and_signatures_are_not_hidden_by_complete_flags() {
        let (response, policy) = fixture();
        for mutation in 0..7 {
            let mut altered = response.clone();
            let node = &mut altered["evidence"]["nodes"][0];
            match mutation {
                0 => node["native_session_drain"] = Value::Null,
                1 => node["native_session_drain"]["supervisor_attestation"] = Value::Null,
                2 => {
                    node["native_session_drain"]["supervisor_attestation"]["signature_hex"] =
                        json!("00".repeat(64))
                }
                3 => node["native_session_drain"]["session_set_sha256"] = json!("99".repeat(32)),
                4 => node["health"] = json!("healthy"),
                5 => node["ready"] = json!(false),
                _ => altered["certificate"]["participants"][0]["admitted_sessions"] = json!(0),
            }
            assert!(verify(&altered, &policy).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn new_checkpoint_hash_still_requires_its_supervisors_signature() {
        let (mut response, policy) = fixture();
        let original_signature = response["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]["signature_hex"].clone();
        response["evidence"]["nodes"][0]["native_session_drain"]["admitted_sessions"] = json!(4);
        response["evidence"]["nodes"][0]["native_session_drain"]["terminal_sessions"] = json!(4);
        response["certificate"]["participants"][0]["admitted_sessions"] = json!(4);
        response["certificate"]["participants"][0]["terminal_sessions"] = json!(4);
        resign(&mut response, 0, &SigningKey::from_bytes(&[41; 32]));
        response["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]["signature_hex"] =
            original_signature;
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::SignatureInvalid)
        );
    }

    #[test]
    fn duplicate_unknown_and_oversized_json_fails_closed() {
        let (response, policy) = fixture();
        let raw = serde_json::to_string(&response).unwrap();
        let duplicate = raw.replacen(
            "\"complete\":true",
            "\"complete\":false,\"complete\":true",
            1,
        );
        assert_ne!(raw, duplicate);
        assert_eq!(
            verify_fleet_quiescence_observations(duplicate.as_bytes(), &policy),
            Err(FleetQuiescenceError::JsonInvalid)
        );
        let mut unknown = response;
        unknown["evidence"]["nodes"][0]["native_session_drain"]["extra_claim"] = json!(true);
        assert_eq!(
            verify(&unknown, &policy),
            Err(FleetQuiescenceError::ObservationInvalid)
        );
        assert_eq!(
            verify_fleet_quiescence_observations(
                &vec![b' '; MAX_FLEET_QUIESCENCE_RESPONSE_BYTES + 1],
                &policy
            ),
            Err(FleetQuiescenceError::InputTooLarge)
        );
        assert_eq!(
            parse_fleet_quiescence_policy(&vec![b' '; MAX_FLEET_QUIESCENCE_POLICY_BYTES + 1]),
            Err(FleetQuiescenceError::InputTooLarge)
        );
    }

    #[test]
    fn policy_rejects_empty_unsorted_weak_and_unbounded_enrollment() {
        let (response, original) = fixture();
        for mutation in 0..12 {
            let mut policy = original.clone();
            match mutation {
                0 => policy.participants.clear(),
                1 => policy.participants.swap(0, 1),
                2 => policy.participants[1] = policy.participants[0].clone(),
                3 => policy.participants[0].supervisor_public_key_hex = "00".repeat(32),
                4 => policy.participants[0].minimum_generation = 0,
                5 => policy.participants[0].zone_id = "all".into(),
                6 => policy.max_observation_age_secs = 0,
                7 => policy.max_observation_age_secs = 301,
                8 => policy.expected_action_log.action_count = MAX_ACTIONS + 1,
                9 => policy.expected_pre_epoch = u64::MAX,
                10 => {
                    policy.participants[0].expected_active_hold_ids =
                        vec!["same".into(), "same".into()]
                }
                _ => {
                    policy.participants = vec![policy.participants[0].clone(); MAX_PARTICIPANTS + 1]
                }
            }
            assert_eq!(
                verify(&response, &policy),
                Err(FleetQuiescenceError::PolicyInvalid),
                "mutation {mutation}"
            );
        }
        let raw = serde_json::to_string(&original).unwrap();
        let duplicate = raw.replacen(
            "\"max_observation_age_secs\":30",
            "\"max_observation_age_secs\":300,\"max_observation_age_secs\":30",
            1,
        );
        assert_eq!(
            parse_fleet_quiescence_policy(duplicate.as_bytes()),
            Err(FleetQuiescenceError::JsonInvalid)
        );
        let noncanonical = raw.replace("2026-11-23T01:00:10Z", "2026-11-23T01:00:10+00:00");
        assert_eq!(
            parse_fleet_quiescence_policy(noncanonical.as_bytes()),
            Err(FleetQuiescenceError::PolicyInvalid)
        );
    }

    #[test]
    fn fractional_heartbeat_windows_preserve_the_exact_expiry_boundary() {
        let (mut response, policy) = fixture();
        // Keep signed observations as recent as their heartbeats so this
        // test isolates the transport timestamp's fractional expiry bound.
        // The immutable fixture's original, older signatures remain covered
        // by the separate supervisor-freshness regression below.
        for index in 0..2 {
            let last_seen = response["evidence"]["nodes"][index]["last_seen"].clone();
            let drain = &mut response["evidence"]["nodes"][index]["native_session_drain"];
            drain["supervisor_attestation"]["observed_at"] = last_seen;
            resign(
                &mut response,
                index,
                &SigningKey::from_bytes(&[41 + index as u8; 32]),
            );
        }
        response["evidence"]["stale_after"] = json!({"secs": 1, "nanos": 1});
        assert!(verify(&response, &policy).is_ok());
        response["evidence"]["stale_after"] = json!({"secs": 1, "nanos": 0});
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::ObservationStale)
        );
        response["evidence"]["stale_after"] = json!({"secs": 0, "nanos": 1_000_000_000});
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::ContextMismatch)
        );
    }

    #[test]
    fn signed_observations_obey_the_declared_fractional_freshness_window() {
        let (mut response, policy) = fixture();
        // The independently signed observations are at :03; the certificate
        // is at :05. Fresh transport observations do not change those
        // signatures or the caller's longer 30-second verification bound.
        for node in response["evidence"]["nodes"].as_array_mut().unwrap() {
            node["last_seen"] = json!("2026-11-23T01:00:05Z");
        }
        response["evidence"]["stale_after"] = json!({"secs": 2, "nanos": 1});
        let facts = verify(&response, &policy).unwrap();
        assert!(facts.supervisor_signatures_verified);
        assert!(!facts.current_quiescence_proven);

        response["evidence"]["stale_after"] = json!({"secs": 2, "nanos": 0});
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::ObservationStale)
        );
    }

    #[test]
    fn coordinator_signatures_cannot_override_the_declared_supervisor_window() {
        let (mut response, mut policy, trust, _) = epoch_fixture();
        policy.max_observation_age_secs = MAX_AGE_SECONDS;
        for node in response["evidence"]["nodes"].as_array_mut().unwrap() {
            node["last_seen"] = json!("2026-11-23T01:00:05Z");
        }
        let coordinator = SigningKey::from_bytes(&[43; 32]);
        response["evidence"]["stale_after"] = json!({"secs": 2, "nanos": 1});
        resign_epoch(&mut response, &coordinator);
        assert!(verify_epoch(&response, &policy, &trust).is_ok());

        response["evidence"]["stale_after"] = json!({"secs": 2, "nanos": 0});
        resign_epoch(&mut response, &coordinator);
        assert_eq!(
            verify_epoch(&response, &policy, &trust),
            Err(FleetQuiescenceError::ObservationStale)
        );
    }

    #[test]
    fn signed_counts_cannot_overflow_the_aggregate_population() {
        let (mut response, policy) = fixture();
        for index in 0..2 {
            let drain = &mut response["evidence"]["nodes"][index]["native_session_drain"];
            drain["admitted_sessions"] = json!(u64::MAX);
            drain["terminal_sessions"] = json!(u64::MAX);
            response["certificate"]["participants"][index]["admitted_sessions"] = json!(u64::MAX);
            response["certificate"]["participants"][index]["terminal_sessions"] = json!(u64::MAX);
            resign(
                &mut response,
                index,
                &SigningKey::from_bytes(&[41 + index as u8; 32]),
            );
        }
        assert_eq!(
            verify(&response, &policy),
            Err(FleetQuiescenceError::CountOverflow)
        );
    }

    #[test]
    fn unsigned_epoch_changes_remain_context_checks_not_authenticated_commits() {
        let (mut response, mut policy) = fixture();
        response["certificate"]["pre_epoch"] = json!(700);
        response["certificate"]["committed_epoch"] = json!(701);
        policy.expected_pre_epoch = 700;
        let facts = verify(&response, &policy).unwrap();
        assert!(facts.supervisor_signatures_verified);
        assert!(!facts.epoch_commit_authenticated);
        assert!(!facts.current_quiescence_proven);
    }

    #[test]
    fn independent_coordinator_wire_proves_a_historical_commit_with_local_observations() {
        let (response, policy, trust, expected) = epoch_fixture();
        let facts = verify_epoch(&response, &policy, &trust).unwrap();
        assert_eq!(facts.schema_version, FLEET_EPOCH_COMMIT_SCHEMA);
        assert_eq!(facts.coordinator_id, trust.coordinator_id);
        assert_eq!(
            facts.coordinator_key_id,
            format!("ed25519:{}", trust.coordinator_public_key_hex)
        );
        assert_eq!(facts.committed_epoch, 8);
        assert_eq!(facts.transition_id, "epoch-transition-7-to-8");
        assert_eq!(facts.statement_sha256, expected["statement_sha256"]);
        assert_eq!(
            parse_response(&serde_json::to_vec(&response).unwrap())
                .unwrap()
                .manifest_sha256,
            expected["manifest_sha256"]
        );
        assert_eq!(facts.participant_count, 2);
        assert_eq!(facts.admitted_sessions, 5);
        assert_eq!(facts.terminal_sessions, 5);
        assert!(facts.supervisor_signatures_verified);
        assert!(facts.expected_population_complete);
        assert!(facts.expected_action_context_matched);
        assert!(facts.epoch_commit_authenticated);
        assert!(!facts.current_quiescence_proven);
        let serialized = serde_json::to_string(&facts).unwrap();
        for private in [
            "node-a",
            "node-b",
            "hold-east",
            "hold-west",
            "trace-maintenance",
        ] {
            assert!(!serialized.contains(private));
        }
        let observations = verify(&response, &policy).unwrap();
        assert!(!observations.epoch_commit_authenticated);
        assert!(!observations.current_quiescence_proven);
        assert_eq!(facts.evidence_sha256, observations.evidence_sha256);
        assert_eq!(facts.trust_policy_sha256, observations.trust_policy_sha256);

        let pretty = serde_json::to_vec_pretty(&response).unwrap();
        let pretty_facts = verify_fleet_epoch_commit(&pretty, &policy, &trust).unwrap();
        assert_ne!(pretty_facts.evidence_sha256, facts.evidence_sha256);
        assert_eq!(pretty_facts.statement_sha256, facts.statement_sha256);
    }

    #[test]
    fn signed_cli_certification_and_retained_export_preserve_both_api_scopes() {
        let (response, policy, trust, _) = epoch_fixture();
        for command in ["fleet.certify-quiescence", "fleet.export-epoch"] {
            let mut cli = json!({
                "schema_version": "franken-node/fleet-quiescence-cli/v2",
                "command": command, "ok": true,
                "transport": "http", "live_control_plane": true,
                "control_plane_url": "https://coordinator.invalid/",
                "evidence": response["evidence"],
                "certificate": response["certificate"],
                "commit_proof": response["commit_proof"],
            });
            assert!(
                verify_epoch(&cli, &policy, &trust)
                    .unwrap()
                    .epoch_commit_authenticated
            );
            assert!(!verify(&cli, &policy).unwrap().epoch_commit_authenticated);
            cli["ok"] = json!(false);
            assert_eq!(
                verify_epoch(&cli, &policy, &trust),
                Err(FleetQuiescenceError::ObservationInvalid)
            );
        }
    }

    #[test]
    fn legacy_responses_and_authorization_alone_cannot_upgrade_to_epoch_commits() {
        let (response, policy, trust, _) = epoch_fixture();
        let (mut legacy, _) = fixture();
        assert_eq!(
            verify_epoch(&legacy, &policy, &trust),
            Err(FleetQuiescenceError::EpochProofMissing)
        );
        legacy["commit_proof"] = response["commit_proof"].clone();
        assert_eq!(
            verify_epoch(&legacy, &policy, &trust),
            Err(FleetQuiescenceError::ObservationInvalid)
        );
        let mut missing = response.clone();
        missing.as_object_mut().unwrap().remove("commit_proof");
        assert_eq!(
            verify_epoch(&missing, &policy, &trust),
            Err(FleetQuiescenceError::EpochProofMissing)
        );
        for field in ["authorization_signature_hex", "commit_signature_hex"] {
            let mut missing = response.clone();
            missing["commit_proof"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(
                verify_epoch(&missing, &policy, &trust),
                Err(FleetQuiescenceError::EpochProofInvalid),
                "missing {field}"
            );
        }
    }

    #[test]
    fn authorization_and_commit_domains_and_length_frames_are_not_interchangeable() {
        let (response, policy, trust, _) = epoch_fixture();
        let key = SigningKey::from_bytes(&[43; 32]);
        for field in ["authorization_signature_hex", "commit_signature_hex"] {
            let other = if field == "authorization_signature_hex" {
                "commit_signature_hex"
            } else {
                "authorization_signature_hex"
            };
            let mut swapped = response.clone();
            swapped["commit_proof"][field] = response["commit_proof"][other].clone();
            assert_eq!(
                verify_epoch(&swapped, &policy, &trust),
                Err(FleetQuiescenceError::EpochSignatureInvalid),
                "wrong domain for {field}"
            );
            // The observation API does not claim either coordinator signature.
            assert!(
                !verify(&swapped, &policy)
                    .unwrap()
                    .epoch_commit_authenticated
            );

            let mut unframed = response.clone();
            let bytes = canonical_bytes(&unframed["commit_proof"]["statement"]).unwrap();
            unframed["commit_proof"][field] = json!(hex::encode(key.sign(&bytes).to_bytes()));
            assert_eq!(
                verify_epoch(&unframed, &policy, &trust),
                Err(FleetQuiescenceError::EpochSignatureInvalid),
                "unframed {field}"
            );
        }
    }

    #[test]
    fn coordinators_are_independently_enrolled_and_weak_or_invalid_trust_is_rejected() {
        let (response, policy, trust, _) = epoch_fixture();
        let foreign = SigningKey::from_bytes(&[91; 32]);
        let mut other_id = trust.clone();
        other_id.coordinator_id = "another-coordinator".into();
        let mut other_key = trust.clone();
        other_key.coordinator_public_key_hex = hex::encode(foreign.verifying_key().as_bytes());
        for untrusted in [other_id, other_key] {
            assert_eq!(
                verify_epoch(&response, &policy, &untrusted),
                Err(FleetQuiescenceError::CoordinatorUntrusted)
            );
        }
        let mut self_selected = response.clone();
        self_selected["commit_proof"]["statement"]["coordinator_key_id"] = json!(format!(
            "ed25519:{}",
            hex::encode(foreign.verifying_key().as_bytes())
        ));
        resign_epoch(&mut self_selected, &foreign);
        assert_eq!(
            verify_epoch(&self_selected, &policy, &trust),
            Err(FleetQuiescenceError::CoordinatorUntrusted)
        );

        for mutation in 0..6 {
            let mut invalid = trust.clone();
            match mutation {
                0 => invalid.coordinator_id.clear(),
                1 => invalid.coordinator_id = "coordinator..test".into(),
                2 => invalid.coordinator_id = "coordinator/test".into(),
                3 => invalid.coordinator_public_key_hex = "00".repeat(32),
                4 => invalid.coordinator_public_key_hex = "01".to_owned() + &"00".repeat(31),
                _ => invalid.coordinator_public_key_hex.make_ascii_uppercase(),
            }
            assert_eq!(
                verify_epoch(&response, &policy, &invalid),
                Err(FleetQuiescenceError::CoordinatorTrustInvalid),
                "invalid trust mutation {mutation}"
            );
        }
    }

    #[test]
    fn epoch_proof_covers_the_entire_raw_manifest_including_timestamp_spelling() {
        let (response, policy, trust, _) = epoch_fixture();
        for mutation in 0..5 {
            let mut altered = response.clone();
            match mutation {
                0 => altered["certificate"]["reason"] = json!("another-reason"),
                1 => altered["certificate"]["initiator"] = json!("another-operator"),
                2 => altered["evidence"]["action_count"] = json!(200),
                3 => {
                    altered["evidence"]["observed_at"] = json!("2026-11-23T01:00:05+00:00");
                }
                _ => {
                    altered["certificate"]["certified_at"] = json!("2026-11-23T01:00:05+00:00");
                }
            }
            assert_eq!(
                verify_epoch(&altered, &policy, &trust),
                Err(FleetQuiescenceError::EpochProofInvalid),
                "manifest mutation {mutation}"
            );
            if mutation != 2 {
                assert!(
                    !verify(&altered, &policy)
                        .unwrap()
                        .epoch_commit_authenticated
                );
            }
        }
    }

    #[test]
    fn correctly_signed_epoch_statements_must_match_certificate_and_caller_context() {
        let (response, policy, trust, _) = epoch_fixture();
        let key = SigningKey::from_bytes(&[43; 32]);
        for field in ["pre_epoch", "committed_epoch", "transition_id", "trace_id"] {
            let mut mismatch = response.clone();
            mismatch["commit_proof"]["statement"][field] = match field {
                "pre_epoch" => json!(700),
                "committed_epoch" => json!(701),
                _ => json!("another-context"),
            };
            resign_epoch(&mut mismatch, &key);
            assert_eq!(
                verify_epoch(&mismatch, &policy, &trust),
                Err(FleetQuiescenceError::EpochProofInvalid),
                "mismatched {field}"
            );
        }
        let mut another_epoch = response;
        for object in ["certificate", "statement"] {
            let target = if object == "certificate" {
                &mut another_epoch["certificate"]
            } else {
                &mut another_epoch["commit_proof"]["statement"]
            };
            target["pre_epoch"] = json!(700);
            target["committed_epoch"] = json!(701);
        }
        resign_epoch(&mut another_epoch, &key);
        assert_eq!(
            verify_epoch(&another_epoch, &policy, &trust),
            Err(FleetQuiescenceError::ContextMismatch)
        );
    }

    #[test]
    fn trusted_coordinator_cannot_replace_complete_population_or_local_supervisor_checks() {
        let (response, policy, trust, _) = epoch_fixture();
        let coordinator = SigningKey::from_bytes(&[43; 32]);
        let mut missing = response.clone();
        missing["evidence"]["nodes"].as_array_mut().unwrap().pop();
        missing["certificate"]["participants"]
            .as_array_mut()
            .unwrap()
            .pop();
        resign_epoch(&mut missing, &coordinator);
        assert_eq!(
            verify_epoch(&missing, &policy, &trust),
            Err(FleetQuiescenceError::PopulationMismatch)
        );
        let mut unsigned_supervisor = response.clone();
        unsigned_supervisor["evidence"]["nodes"][0]["native_session_drain"]["supervisor_attestation"]
            ["signature_hex"] = json!("00".repeat(64));
        resign_epoch(&mut unsigned_supervisor, &coordinator);
        assert_eq!(
            verify_epoch(&unsigned_supervisor, &policy, &trust),
            Err(FleetQuiescenceError::SignatureInvalid)
        );
        let mut released = response;
        released["evidence"]["nodes"][0]["native_session_drain"]["fence_held"] = json!(false);
        resign(&mut released, 0, &SigningKey::from_bytes(&[41; 32]));
        resign_epoch(&mut released, &coordinator);
        assert_eq!(
            verify_epoch(&released, &policy, &trust),
            Err(FleetQuiescenceError::ObservationInvalid)
        );
    }

    #[test]
    fn coordinator_resigning_cannot_renew_expired_supervisor_observations() {
        let (mut response, mut policy, trust, _) = epoch_fixture();
        policy.evaluation_time = "2026-11-23T01:00:33Z".parse().unwrap();
        response["evidence"]["observed_at"] = json!("2026-11-23T01:00:33Z");
        response["certificate"]["certified_at"] = json!("2026-11-23T01:00:33Z");
        for node in response["evidence"]["nodes"].as_array_mut().unwrap() {
            node["last_seen"] = json!("2026-11-23T01:00:33Z");
        }
        resign_epoch(&mut response, &SigningKey::from_bytes(&[43; 32]));
        assert_eq!(
            verify_epoch(&response, &policy, &trust),
            Err(FleetQuiescenceError::ObservationStale)
        );
    }

    #[test]
    fn epoch_commit_json_rejects_ambiguous_unknown_or_incomplete_proof_fields() {
        let (response, policy, trust, _) = epoch_fixture();
        for mutation in 0..6 {
            let mut malformed = response.clone();
            match mutation {
                0 => malformed["commit_proof"]["extra_authority"] = json!(true),
                1 => malformed["commit_proof"]["statement"]["extra_authority"] = json!(true),
                2 => malformed["commit_proof"]["schema_version"] = json!("unknown"),
                3 => malformed["commit_proof"]["statement"]["schema_version"] = json!("unknown"),
                4 => malformed["commit_proof"]["commit_signature_hex"] = json!("00"),
                _ => malformed["commit_proof"] = Value::Null,
            }
            assert_eq!(
                verify_epoch(&malformed, &policy, &trust),
                Err(FleetQuiescenceError::EpochProofInvalid),
                "malformed proof mutation {mutation}"
            );
        }
        let raw = serde_json::to_string(&response).unwrap();
        let duplicate = raw.replacen(
            "\"coordinator_id\":\"coordinator-test\"",
            "\"coordinator_id\":\"foreign\",\"coordinator_id\":\"coordinator-test\"",
            1,
        );
        assert_ne!(raw, duplicate);
        assert_eq!(
            verify_fleet_epoch_commit(duplicate.as_bytes(), &policy, &trust),
            Err(FleetQuiescenceError::JsonInvalid)
        );
    }

    #[test]
    fn epoch_commits_retain_exact_u64_precision_through_the_maximum_epoch() {
        let (mut response, mut policy, trust, _) = epoch_fixture();
        policy.expected_pre_epoch = u64::MAX - 1;
        response["certificate"]["pre_epoch"] = json!(u64::MAX - 1);
        response["certificate"]["committed_epoch"] = json!(u64::MAX);
        response["commit_proof"]["statement"]["pre_epoch"] = json!(u64::MAX - 1);
        response["commit_proof"]["statement"]["committed_epoch"] = json!(u64::MAX);
        resign_epoch(&mut response, &SigningKey::from_bytes(&[43; 32]));
        let facts = verify_epoch(&response, &policy, &trust).unwrap();
        assert_eq!(facts.committed_epoch, u64::MAX);
        assert!(facts.epoch_commit_authenticated);
        assert!(!facts.current_quiescence_proven);
    }
}
