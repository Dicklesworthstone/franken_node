use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteCap, RemoteCapAuditEvent, RemoteCapError,
    RemoteOperation, RemoteScope,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tempfile::TempDir;

const REMOTE_CAP_REPLAY_TOKEN_STATE_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/remote_cap_replay_token_state_vectors.json");
const SHARED_SECRET: &str = "conformance-remote-cap-replay-secret";
const ISSUER: &str = "ops@example";

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct CoverageRow {
    spec_section: String,
    invariant: String,
    level: String,
    tested: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReplayStoreMode {
    Memory,
    Durable,
}

#[derive(Debug, Clone, Deserialize)]
struct IssuedTokenVector {
    label: String,
    trace_id: String,
    issued_at_epoch_secs: u64,
    ttl_secs: u64,
    single_use: bool,
    operations: Vec<RemoteOperation>,
    endpoint_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct ExpectedTranscriptStep {
    step: String,
    kind: TranscriptKind,
    token: Option<String>,
    status: TranscriptStatus,
    error_code: Option<String>,
    audit_event_code: Option<String>,
    denial_code: Option<String>,
    audit_log_len_after: usize,
    durable_marker_count: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TranscriptKind {
    Recheck,
    Authorize,
    RestartGate,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TranscriptStatus {
    Allowed,
    Denied,
    Restarted,
}

#[derive(Debug)]
struct ReplayHarness {
    provider: CapabilityProvider,
    store_mode: ReplayStoreMode,
    durable_store: Option<TempDir>,
}

impl ReplayHarness {
    fn new(store_mode: ReplayStoreMode) -> Result<Self, String> {
        let provider = CapabilityProvider::new(SHARED_SECRET)
            .map_err(|err| format!("provider setup failed: {err}"))?;
        let durable_store = match store_mode {
            ReplayStoreMode::Memory => None,
            ReplayStoreMode::Durable => Some(
                tempfile::tempdir()
                    .map_err(|err| format!("durable replay tempdir failed: {err}"))?,
            ),
        };
        Ok(Self {
            provider,
            store_mode,
            durable_store,
        })
    }

    fn gate(&self) -> Result<CapabilityGate, String> {
        match (&self.store_mode, &self.durable_store) {
            (ReplayStoreMode::Memory, _) => CapabilityGate::new(SHARED_SECRET)
                .map_err(|err| format!("memory replay gate setup failed: {err}")),
            (ReplayStoreMode::Durable, Some(store)) => {
                CapabilityGate::with_durable_replay_store(SHARED_SECRET, store.path())
                    .map_err(|err| format!("durable replay gate setup failed: {err}"))
            }
            (ReplayStoreMode::Durable, None) => {
                Err("durable replay mode requires a durable store".to_string())
            }
        }
    }

    fn issue_token(&self, token: &IssuedTokenVector) -> Result<RemoteCap, String> {
        self.provider
            .issue(
                ISSUER,
                RemoteScope::new(token.operations.clone(), token.endpoint_prefixes.clone()),
                token.issued_at_epoch_secs,
                token.ttl_secs,
                true,
                token.single_use,
                &token.trace_id,
            )
            .map(|(cap, _)| cap)
            .map_err(|err| format!("{} token issuance failed: {err}", token.label))
    }

    fn durable_marker_count(&self) -> Result<Option<usize>, String> {
        let Some(store) = &self.durable_store else {
            return Ok(None);
        };
        let consumed_dir = store.path().join("consumed");
        if !consumed_dir.exists() {
            return Ok(Some(0));
        }
        std::fs::read_dir(&consumed_dir)
            .map_err(|err| format!("reading durable replay marker dir failed: {err}"))
            .map(|entries| Some(entries.count()))
    }
}

#[derive(Debug, Deserialize)]
struct ActionVector {
    step: String,
    kind: TranscriptKind,
    token: Option<String>,
    operation: Option<RemoteOperation>,
    endpoint: Option<String>,
    now_epoch_secs: Option<u64>,
    trace_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplayTokenStateVectorRaw {
    name: String,
    store_mode: ReplayStoreMode,
    issued_tokens: Vec<IssuedTokenVector>,
    actions: Vec<ActionVector>,
    transcript: Vec<ExpectedTranscriptStep>,
}

fn load_vectors() -> Result<(String, Vec<CoverageRow>, Vec<ReplayTokenStateVectorRaw>), String> {
    #[derive(Debug, Deserialize)]
    struct RawVectors {
        schema_version: String,
        coverage: Vec<CoverageRow>,
        vectors: Vec<ReplayTokenStateVectorRaw>,
    }

    let parsed: RawVectors = serde_json::from_str(REMOTE_CAP_REPLAY_TOKEN_STATE_VECTORS_JSON)
        .map_err(|err| format!("remote-cap replay token vectors must parse: {err}"))?;
    Ok((parsed.schema_version, parsed.coverage, parsed.vectors))
}

fn last_audit_event(gate: &CapabilityGate) -> Result<&RemoteCapAuditEvent, String> {
    gate.audit_log()
        .last()
        .ok_or_else(|| "audit log must record the step outcome".to_string())
}

fn execute_vector(
    vector: &ReplayTokenStateVectorRaw,
) -> Result<Vec<ExpectedTranscriptStep>, String> {
    let harness = ReplayHarness::new(vector.store_mode)?;
    let mut gate = harness.gate()?;
    let mut issued_tokens = BTreeMap::new();

    for token in &vector.issued_tokens {
        issued_tokens.insert(token.label.clone(), harness.issue_token(token)?);
    }

    let mut actual = Vec::with_capacity(vector.actions.len());

    for action in &vector.actions {
        match action.kind {
            TranscriptKind::RestartGate => {
                gate = harness.gate()?;
                actual.push(ExpectedTranscriptStep {
                    step: action.step.clone(),
                    kind: action.kind,
                    token: None,
                    status: TranscriptStatus::Restarted,
                    error_code: None,
                    audit_event_code: None,
                    denial_code: None,
                    audit_log_len_after: gate.audit_log().len(),
                    durable_marker_count: harness.durable_marker_count()?,
                });
            }
            TranscriptKind::Authorize | TranscriptKind::Recheck => {
                let token_label = action
                    .token
                    .as_ref()
                    .ok_or_else(|| format!("{} must reference a token", action.step))?;
                let token = issued_tokens.get(token_label).ok_or_else(|| {
                    format!("{} references unknown token `{token_label}`", action.step)
                })?;
                let operation = action
                    .operation
                    .ok_or_else(|| format!("{} must declare an operation", action.step))?;
                let endpoint = action
                    .endpoint
                    .as_deref()
                    .ok_or_else(|| format!("{} must declare an endpoint", action.step))?;
                let now_epoch_secs = action
                    .now_epoch_secs
                    .ok_or_else(|| format!("{} must declare now_epoch_secs", action.step))?;
                let trace_id = action
                    .trace_id
                    .as_deref()
                    .ok_or_else(|| format!("{} must declare trace_id", action.step))?;

                let result = match action.kind {
                    TranscriptKind::Authorize => gate.authorize_network(
                        Some(token),
                        operation,
                        endpoint,
                        now_epoch_secs,
                        trace_id,
                    ),
                    TranscriptKind::Recheck => gate.recheck_network(
                        Some(token),
                        operation,
                        endpoint,
                        now_epoch_secs,
                        trace_id,
                    ),
                    TranscriptKind::RestartGate => unreachable!(),
                };

                let event = last_audit_event(&gate)?;
                let status = if result.is_ok() {
                    TranscriptStatus::Allowed
                } else {
                    TranscriptStatus::Denied
                };
                let error_code = result
                    .as_ref()
                    .err()
                    .map(RemoteCapError::code)
                    .map(str::to_string);
                actual.push(ExpectedTranscriptStep {
                    step: action.step.clone(),
                    kind: action.kind,
                    token: Some(token_label.clone()),
                    status,
                    error_code,
                    audit_event_code: Some(event.event_code.clone()),
                    denial_code: event.denial_code.clone(),
                    audit_log_len_after: gate.audit_log().len(),
                    durable_marker_count: harness.durable_marker_count()?,
                });
            }
        }
    }

    Ok(actual)
}

#[test]
fn remote_cap_replay_token_state_vectors_cover_required_invariants() -> TestResult {
    let (schema_version, coverage, vectors) = load_vectors()?;
    assert_eq!(
        schema_version,
        "franken-node/remote-cap-replay-token-state-conformance/v1"
    );
    assert_eq!(
        vectors.len(),
        3,
        "conformance vectors must cover memory replay, non-consuming denial, and durable restart replay"
    );

    for required in [
        "INV-REMOTECAP-FAIL-CLOSED",
        "INV-REMOTECAP-AUDIT",
        "verify-without-consuming-single-use",
        "use-consumes-single-use",
    ] {
        assert!(
            coverage.iter().any(|row| {
                row.spec_section == "docs/specs/remote_cap_contract.md"
                    && row.invariant == required
                    && row.level == "MUST"
                    && row.tested
            }),
            "{required} must be covered by the replay-token state conformance matrix"
        );
    }

    Ok(())
}

#[test]
fn remote_cap_replay_token_state_machine_matches_golden_vectors() -> TestResult {
    let (_, _, vectors) = load_vectors()?;

    for vector in &vectors {
        let actual = execute_vector(vector)?;
        assert_eq!(
            actual, vector.transcript,
            "{} replay-token transcript drifted from the checked-in golden vector",
            vector.name
        );
    }

    Ok(())
}
