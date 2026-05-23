use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteCap, RemoteCapAuditEvent, RemoteCapError,
    RemoteOperation, RemoteScope,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tempfile::TempDir;

const REMOTE_CAP_REPLAY_TOKEN_STATE_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/remote_cap_replay_token_state_vectors.json");
const CONFORMANCE_SIGNING_MATERIAL: &str = "remote-cap-replay-conformance-fixture";
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
        let provider = CapabilityProvider::new(CONFORMANCE_SIGNING_MATERIAL)
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
            (ReplayStoreMode::Memory, _) => CapabilityGate::new(CONFORMANCE_SIGNING_MATERIAL)
                .map_err(|err| format!("memory replay gate setup failed: {err}")),
            (ReplayStoreMode::Durable, Some(store)) => CapabilityGate::with_durable_replay_store(
                CONFORMANCE_SIGNING_MATERIAL,
                store.path(),
            )
            .map_err(|err| format!("durable replay gate setup failed: {err}")),
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
                    TranscriptKind::RestartGate => {
                        return Err(format!(
                            "{} restart action reached token branch",
                            action.step
                        ));
                    }
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

fn durable_marker_paths(store: &TempDir) -> Result<Vec<PathBuf>, String> {
    let consumed_dir = store.path().join("consumed");
    if !consumed_dir.exists() {
        return Ok(Vec::new());
    }
    let mut markers = Vec::new();
    for entry in std::fs::read_dir(&consumed_dir)
        .map_err(|err| format!("reading durable replay marker dir failed: {err}"))?
    {
        markers.push(
            entry
                .map_err(|err| format!("reading durable replay marker entry failed: {err}"))?
                .path(),
        );
    }
    markers.sort();
    Ok(markers)
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
fn durable_replay_marker_contract_uses_length_prefixes_and_redacts_signature() -> TestResult {
    let harness = ReplayHarness::new(ReplayStoreMode::Durable)?;
    let vector = IssuedTokenVector {
        label: "marker-contract".to_string(),
        trace_id: "trace-durable-marker-contract-issue".to_string(),
        issued_at_epoch_secs: 1_700_203_000,
        ttl_secs: 300,
        single_use: true,
        operations: vec![RemoteOperation::TelemetryExport],
        endpoint_prefixes: vec!["https://telemetry.example.com/v1".to_string()],
    };
    let cap = harness.issue_token(&vector)?;
    let mut gate = harness.gate()?;

    gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://telemetry.example.com/v1/export",
        1_700_203_005,
        "trace-durable-marker-contract-consume",
    )
    .map_err(|err| format!("initial durable authorization failed: {err}"))?;

    let store = harness
        .durable_store
        .as_ref()
        .ok_or_else(|| "durable marker contract requires a durable store".to_string())?;
    let markers = durable_marker_paths(store)?;
    assert_eq!(
        markers.len(),
        1,
        "single durable consume must create exactly one replay marker"
    );

    let marker_path = markers
        .first()
        .ok_or_else(|| "durable marker list unexpectedly empty".to_string())?;
    let marker_name = marker_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "durable marker path is not UTF-8: {}",
                marker_path.display()
            )
        })?;
    let replay_key = marker_name
        .strip_suffix(".seen")
        .ok_or_else(|| format!("durable marker name must end with .seen: {marker_name}"))?;
    assert_eq!(
        replay_key.len(),
        64,
        "replay key must be a SHA-256 hex digest"
    );
    assert!(
        replay_key.chars().all(|ch| ch.is_ascii_hexdigit()),
        "replay key filename must be hex-only"
    );

    let marker_body = std::fs::read_to_string(marker_path).map_err(|err| {
        format!(
            "read durable replay marker {}: {err}",
            marker_path.display()
        )
    })?;
    assert!(
        marker_body.starts_with("remote_cap_replay_marker_v1\n"),
        "durable marker must carry the replay marker schema header"
    );
    assert!(
        marker_body.contains(&format!("replay_key={replay_key}\n")),
        "durable marker body must bind itself to the filename replay key"
    );
    assert!(
        marker_body.contains(&format!(
            "token_id_len={}:{}\n",
            cap.token_id().len(),
            cap.token_id()
        )),
        "token id must be length-prefixed to avoid delimiter ambiguity"
    );
    assert!(
        marker_body.contains(&format!(
            "issuer_len={}:{}\n",
            cap.issuer_identity().len(),
            cap.issuer_identity()
        )),
        "issuer identity must be length-prefixed to avoid delimiter ambiguity"
    );
    assert!(
        marker_body.contains(&format!("issued_at={}\n", cap.issued_at_epoch_secs())),
        "marker must persist the issued-at boundary"
    );
    assert!(
        marker_body.contains(&format!("expires_at={}\n", cap.expires_at_epoch_secs())),
        "marker must persist the expiry boundary"
    );
    assert!(
        marker_body.contains("single_use=true\n"),
        "marker must record that a single-use token was consumed"
    );
    assert!(
        !marker_body.contains(cap.signature()),
        "durable replay markers must not persist signature material"
    );

    let mut restarted_gate = harness.gate()?;
    let replay_error = restarted_gate
        .recheck_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/v1/export",
            1_700_203_006,
            "trace-durable-marker-contract-restart",
        )
        .expect_err("restart must preserve the consumed single-use denial");
    assert_eq!(
        replay_error,
        RemoteCapError::ReplayDetected {
            token_id: cap.token_id().to_string()
        }
    );

    Ok(())
}

#[test]
fn remote_cap_duplicate_renewal_request_is_idempotent_for_authorization() -> TestResult {
    let harness = ReplayHarness::new(ReplayStoreMode::Memory)?;
    let renewal = IssuedTokenVector {
        label: "renewal".to_string(),
        trace_id: "trace-renewal-idempotent".to_string(),
        issued_at_epoch_secs: 1_700_001_000,
        ttl_secs: 3_600,
        single_use: false,
        operations: vec![RemoteOperation::RevocationFetch],
        endpoint_prefixes: vec!["revocation://global-feed".to_string()],
    };
    let mut divergent = renewal.clone();
    divergent.trace_id = "trace-renewal-idempotent-divergent".to_string();

    let first = harness.issue_token(&renewal)?;
    let second = harness.issue_token(&renewal)?;
    let divergent = harness.issue_token(&divergent)?;

    assert_eq!(first, second);
    assert_ne!(first.token_id(), divergent.token_id());
    assert_eq!(first.expires_at_epoch_secs(), 1_700_004_600);
    assert_eq!(harness.provider.audit_log().len(), 3);

    let mut gate = harness.gate()?;
    for (cap, trace_id) in [
        (&first, "trace-renewal-first-use"),
        (&second, "trace-renewal-duplicate-use"),
    ] {
        gate.authorize_network(
            Some(cap),
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
            1_700_001_100,
            trace_id,
        )
        .map_err(|err| format!("{trace_id} authorization failed: {err}"))?;
    }
    assert_eq!(gate.audit_log().len(), 2);

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
