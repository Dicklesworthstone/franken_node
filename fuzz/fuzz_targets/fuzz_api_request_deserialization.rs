#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::api::{
    fleet_quarantine::{
        DecisionReceipt, DecisionReceiptPayload, DecisionReceiptScope, DecisionReceiptSignature,
        QuarantineRequest, QuarantineScope, ReleaseRequest, RevocationScope, RevocationSeverity,
        RevokeRequest, StatusRequest,
    },
    operator_routes::{
        ComponentStatus, ConfigView, HealthCheck, HealthComponent,
        NodeStatus as OperatorNodeStatus, RolloutState,
    },
    session_auth::{AuthenticatedMessage, MessageDirection, SessionConfig, SessionEvent},
    trust_card_routes::{PageMeta, Pagination},
};
use libfuzzer_sys::fuzz_target;

// Fuzz target for API request deserialization.
//
// Priority targets:
// - Fleet quarantine: QuarantineRequest, RevokeRequest, ReleaseRequest,
//   StatusRequest, DecisionReceipt
// - Session auth: SessionConfig, AuthenticatedMessage, SessionEvent
// - Operator routes: NodeStatus, HealthCheck, ConfigView, RolloutState
// - Trust card routes: PageMeta, Pagination
macro_rules! round_trip_json {
    ($value:expr, $ty:ty) => {{
        let value = $value;
        if let Ok(json) = serde_json::to_string(&value) {
            // Round-trip property: deserialize(serialize(value)) should succeed
            let parsed = serde_json::from_str::<$ty>(&json);
            assert!(parsed.is_ok(), "Round-trip deserialization from string should succeed");

            let parsed_bytes = serde_json::from_slice::<$ty>(json.as_bytes());
            assert!(parsed_bytes.is_ok(), "Round-trip deserialization from bytes should succeed");
        }

        if let Ok(json_pretty) = serde_json::to_string_pretty(&value) {
            let parsed_pretty = serde_json::from_str::<$ty>(&json_pretty);
            assert!(parsed_pretty.is_ok(), "Pretty-printed JSON should deserialize correctly");

            let parsed_pretty_bytes = serde_json::from_slice::<$ty>(json_pretty.as_bytes());
            assert!(parsed_pretty_bytes.is_ok(), "Pretty-printed JSON bytes should deserialize correctly");
        }

        if let Ok(json_value) = serde_json::to_value(&value) {
            let parsed_value = serde_json::from_value::<$ty>(json_value);
            assert!(parsed_value.is_ok(), "JSON value round-trip should succeed");
        }
    }};
}

fuzz_target!(|data: FuzzInput| {
    match data {
        FuzzInput::QuarantineRequestStruct(req) => {
            round_trip_json!(req.into_request(), QuarantineRequest);
        }
        FuzzInput::RevokeRequestStruct(req) => {
            round_trip_json!(req.into_request(), RevokeRequest);
        }
        FuzzInput::ReleaseRequestStruct(req) => {
            round_trip_json!(req.into_request(), ReleaseRequest);
        }
        FuzzInput::StatusRequestStruct(req) => {
            round_trip_json!(req.into_request(), StatusRequest);
        }
        FuzzInput::DecisionReceiptStruct(receipt) => {
            round_trip_json!(receipt.into_receipt(), DecisionReceipt);
        }
        FuzzInput::SessionConfigStruct(config) => {
            round_trip_json!(config.into_config(), SessionConfig);
        }
        FuzzInput::AuthenticatedMessageStruct(message) => {
            round_trip_json!(message.into_message(), AuthenticatedMessage);
        }
        FuzzInput::SessionEventStruct(event) => {
            round_trip_json!(event.into_event(), SessionEvent);
        }
        FuzzInput::OperatorStatusStruct(status) => {
            round_trip_json!(status.into_status(), OperatorNodeStatus);
        }
        FuzzInput::OperatorHealthStruct(health) => {
            round_trip_json!(health.into_health(), HealthCheck);
        }
        FuzzInput::OperatorConfigStruct(config) => {
            round_trip_json!(config.into_config(), ConfigView);
        }
        FuzzInput::OperatorRolloutStruct(rollout) => {
            round_trip_json!(rollout.into_rollout(), RolloutState);
        }
        FuzzInput::TrustCardPagination(pagination) => fuzz_trust_card_pagination(pagination),
        FuzzInput::RawJsonBytes(bytes) => fuzz_api_request_raw_bytes(&bytes),
    }
});

fn fuzz_api_request_raw_bytes(bytes: &[u8]) {
    if bytes.len() > 5_000_000 {
        return;
    }

    if let Ok(json_str) = std::str::from_utf8(bytes) {
        fuzz_api_request_json(json_str);
    }

    // Test deterministic behavior - same input should give same result
    let quarantine_result1 = serde_json::from_slice::<QuarantineRequest>(bytes);
    let quarantine_result2 = serde_json::from_slice::<QuarantineRequest>(bytes);
    assert_eq!(quarantine_result1.is_ok(), quarantine_result2.is_ok(), "Quarantine deserialization should be deterministic");

    let revoke_result = serde_json::from_slice::<RevokeRequest>(bytes);
    let release_result = serde_json::from_slice::<ReleaseRequest>(bytes);
    let status_result = serde_json::from_slice::<StatusRequest>(bytes);
    let receipt_result = serde_json::from_slice::<DecisionReceipt>(bytes);
    let session_config_result = serde_json::from_slice::<SessionConfig>(bytes);
    let auth_msg_result = serde_json::from_slice::<AuthenticatedMessage>(bytes);
    let session_event_result = serde_json::from_slice::<SessionEvent>(bytes);
    let operator_status_result = serde_json::from_slice::<OperatorNodeStatus>(bytes);
    let health_result = serde_json::from_slice::<HealthCheck>(bytes);
    let config_result = serde_json::from_slice::<ConfigView>(bytes);
    let rollout_result = serde_json::from_slice::<RolloutState>(bytes);
    let page_meta_result = serde_json::from_slice::<PageMeta>(bytes);
    let pagination_result = serde_json::from_slice::<Pagination>(bytes);
    let json_value_result = serde_json::from_slice::<serde_json::Value>(bytes);

    // Malformed single-byte inputs should be rejected
    if !bytes.is_empty() {
        let single_byte = &bytes[..1];
        let single_quarantine = serde_json::from_slice::<QuarantineRequest>(single_byte);
        let single_session = serde_json::from_slice::<SessionConfig>(single_byte);
        let single_operator = serde_json::from_slice::<OperatorNodeStatus>(single_byte);

        // Single bytes are very unlikely to be valid JSON for complex structures
        assert!(single_quarantine.is_err(), "Single byte should not parse as QuarantineRequest");
        assert!(single_session.is_err(), "Single byte should not parse as SessionConfig");
        assert!(single_operator.is_err(), "Single byte should not parse as OperatorNodeStatus");

        if bytes.len() > 2 {
            let partial = &bytes[..bytes.len() / 2];
            let partial_receipt = serde_json::from_slice::<DecisionReceipt>(partial);
            let partial_auth = serde_json::from_slice::<AuthenticatedMessage>(partial);
            let partial_health = serde_json::from_slice::<HealthCheck>(partial);

            // Truncated JSON should generally be rejected
            if partial.len() < 10 {
                assert!(partial_receipt.is_err(), "Truncated bytes too short for DecisionReceipt");
                assert!(partial_auth.is_err(), "Truncated bytes too short for AuthenticatedMessage");
                assert!(partial_health.is_err(), "Truncated bytes too short for HealthCheck");
            }

            if bytes.len() > 10 {
                let oversized = [bytes, &[0u8; 10]].concat();
                let oversized_release = serde_json::from_slice::<ReleaseRequest>(&oversized);
                let oversized_pagination = serde_json::from_slice::<Pagination>(&oversized);

                // Oversized with null padding should be rejected
                assert!(oversized_release.is_err(), "Null-padded oversized input should be rejected for ReleaseRequest");
                assert!(oversized_pagination.is_err(), "Null-padded oversized input should be rejected for Pagination");
            }
        }
    }
}

fn fuzz_api_request_json(json_str: &str) {
    // Test deterministic parsing behavior
    let quarantine_result1 = serde_json::from_str::<QuarantineRequest>(json_str);
    let quarantine_result2 = serde_json::from_str::<QuarantineRequest>(json_str);
    assert_eq!(quarantine_result1.is_ok(), quarantine_result2.is_ok(), "JSON parsing should be deterministic for QuarantineRequest");

    let revoke_result = serde_json::from_str::<RevokeRequest>(json_str);
    let release_result = serde_json::from_str::<ReleaseRequest>(json_str);
    let status_result = serde_json::from_str::<StatusRequest>(json_str);
    let receipt_result = serde_json::from_str::<DecisionReceipt>(json_str);
    let session_config_result = serde_json::from_str::<SessionConfig>(json_str);
    let auth_msg_result = serde_json::from_str::<AuthenticatedMessage>(json_str);
    let session_event_result = serde_json::from_str::<SessionEvent>(json_str);
    let operator_status_result = serde_json::from_str::<OperatorNodeStatus>(json_str);
    let health_result = serde_json::from_str::<HealthCheck>(json_str);
    let config_result = serde_json::from_str::<ConfigView>(json_str);
    let rollout_result = serde_json::from_str::<RolloutState>(json_str);
    let page_meta_result = serde_json::from_str::<PageMeta>(json_str);
    let pagination_result = serde_json::from_str::<Pagination>(json_str);

    let json_value_result1 = serde_json::from_str::<serde_json::Value>(json_str);
    let json_value_result2 = serde_json::from_str::<serde_json::Value>(json_str);
    assert_eq!(json_value_result1.is_ok(), json_value_result2.is_ok(), "JSON Value parsing should be deterministic");

    test_api_json_edge_cases(json_str);

    // Test round-trip property for valid JSON
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Ok(reencoded) = serde_json::to_string(&value) {
            let reencoded_result = serde_json::from_str::<serde_json::Value>(&reencoded);
            assert!(reencoded_result.is_ok(), "Re-encoded JSON should parse successfully");
        }

        if let Ok(pretty) = serde_json::to_string_pretty(&value) {
            let pretty_result = serde_json::from_str::<serde_json::Value>(&pretty);
            assert!(pretty_result.is_ok(), "Pretty-printed JSON should parse successfully");
        }
    }
}

fn test_api_json_edge_cases(json_str: &str) {
    if json_str.len() < 2 {
        return;
    }

    // Truncated JSON should generally be rejected
    let truncated = &json_str[..json_str.len() - 1];
    let truncated_value = serde_json::from_str::<serde_json::Value>(truncated);
    let truncated_receipt = serde_json::from_str::<DecisionReceipt>(truncated);
    let truncated_auth = serde_json::from_str::<AuthenticatedMessage>(truncated);
    let truncated_health = serde_json::from_str::<HealthCheck>(truncated);

    // Malformed JSON with extra brace should be rejected
    let extended = format!("{json_str}}}");
    let extended_result = serde_json::from_str::<serde_json::Value>(&extended);
    assert!(extended_result.is_err(), "JSON with extra closing brace should be rejected");

    // Valid envelope structure should parse as JSON Value
    let request_envelope = format!("{{\"request\": {json_str}}}");
    if serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
        let envelope_result = serde_json::from_str::<serde_json::Value>(&request_envelope);
        assert!(envelope_result.is_ok(), "Valid JSON in envelope should parse");
    }

    // Valid batch structure should parse as JSON Value
    let batch_request = format!("[{json_str}]");
    if serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
        let batch_result = serde_json::from_str::<serde_json::Value>(&batch_request);
        assert!(batch_result.is_ok(), "Valid JSON in array should parse");
    }

    // Valid metadata structure should parse
    let with_metadata = format!("{{\"data\": {json_str}, \"meta\": {{\"timestamp\": 1234567890}}}}");
    if serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
        let metadata_result = serde_json::from_str::<serde_json::Value>(&with_metadata);
        assert!(metadata_result.is_ok(), "Valid JSON with metadata should parse");
    }

    // JSON with surrounding whitespace should parse if original was valid
    let with_spaces = format!(" \t\n{json_str}\n\t ");
    let original_quarantine = serde_json::from_str::<QuarantineRequest>(json_str);
    let spaced_quarantine = serde_json::from_str::<QuarantineRequest>(&with_spaces);
    assert_eq!(original_quarantine.is_ok(), spaced_quarantine.is_ok(), "Whitespace should not affect parsing result");

    let original_session = serde_json::from_str::<SessionConfig>(json_str);
    let spaced_session = serde_json::from_str::<SessionConfig>(&with_spaces);
    assert_eq!(original_session.is_ok(), spaced_session.is_ok(), "Whitespace should not affect SessionConfig parsing");

    let original_operator = serde_json::from_str::<OperatorNodeStatus>(json_str);
    let spaced_operator = serde_json::from_str::<OperatorNodeStatus>(&with_spaces);
    assert_eq!(original_operator.is_ok(), spaced_operator.is_ok(), "Whitespace should not affect OperatorNodeStatus parsing");

    let original_value = serde_json::from_str::<serde_json::Value>(json_str);
    let spaced_value = serde_json::from_str::<serde_json::Value>(&with_spaces);
    assert_eq!(original_value.is_ok(), spaced_value.is_ok(), "Whitespace should not affect JSON Value parsing");

    // Deeply nested valid JSON should parse successfully
    if json_str.len() < 100 && serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
        let deeply_nested = format!("{{\"level1\": {{\"level2\": {{\"level3\": {json_str}}}}}}}");
        let nested_result = serde_json::from_str::<serde_json::Value>(&deeply_nested);
        assert!(nested_result.is_ok(), "Deeply nested valid JSON should parse successfully");
    }
}

fn fuzz_trust_card_pagination(pagination: TrustCardFuzzData) {
    match pagination {
        TrustCardFuzzData::PageMeta(meta) => {
            round_trip_json!(meta, PageMeta);
        }
        TrustCardFuzzData::Pagination(page) => {
            round_trip_json!(page, Pagination);
        }
    }
}

#[derive(Arbitrary, Debug)]
enum TrustCardFuzzData {
    PageMeta(PageMeta),
    Pagination(Pagination),
}

#[derive(Arbitrary, Debug)]
enum FuzzRevocationSeverity {
    Advisory,
    Mandatory,
    Emergency,
}

impl FuzzRevocationSeverity {
    fn into_severity(self) -> RevocationSeverity {
        match self {
            Self::Advisory => RevocationSeverity::Advisory,
            Self::Mandatory => RevocationSeverity::Mandatory,
            Self::Emergency => RevocationSeverity::Emergency,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzQuarantineRequest {
    extension_id: String,
    zone_id: String,
    tenant_id: Option<String>,
    affected_nodes: u32,
    reason: String,
}

impl FuzzQuarantineRequest {
    fn into_request(self) -> QuarantineRequest {
        QuarantineRequest {
            extension_id: bounded_text(self.extension_id, 128),
            scope: QuarantineScope {
                zone_id: bounded_text(self.zone_id, 128),
                tenant_id: self.tenant_id.map(|tenant| bounded_text(tenant, 128)),
                affected_nodes: self.affected_nodes,
                reason: bounded_text(self.reason, 256),
            },
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzRevokeRequest {
    extension_id: String,
    zone_id: String,
    tenant_id: Option<String>,
    severity: FuzzRevocationSeverity,
    reason: String,
}

impl FuzzRevokeRequest {
    fn into_request(self) -> RevokeRequest {
        RevokeRequest {
            extension_id: bounded_text(self.extension_id, 128),
            scope: RevocationScope {
                zone_id: bounded_text(self.zone_id, 128),
                tenant_id: self.tenant_id.map(|tenant| bounded_text(tenant, 128)),
                severity: self.severity.into_severity(),
                reason: bounded_text(self.reason, 256),
            },
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzReleaseRequest {
    incident_id: String,
}

impl FuzzReleaseRequest {
    fn into_request(self) -> ReleaseRequest {
        ReleaseRequest {
            incident_id: bounded_text(self.incident_id, 128),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzStatusRequest {
    zone_id: String,
}

impl FuzzStatusRequest {
    fn into_request(self) -> StatusRequest {
        StatusRequest {
            zone_id: bounded_text(self.zone_id, 128),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDecisionReceipt {
    operation_id: String,
    receipt_id: String,
    issuer: String,
    issued_at: String,
    zone_id: String,
    payload_hash: String,
    decision_payload: FuzzDecisionReceiptPayload,
    signature: Option<FuzzDecisionReceiptSignature>,
}

impl FuzzDecisionReceipt {
    fn into_receipt(self) -> DecisionReceipt {
        DecisionReceipt {
            operation_id: bounded_text(self.operation_id, 128),
            receipt_id: bounded_text(self.receipt_id, 128),
            issuer: bounded_text(self.issuer, 128),
            issued_at: bounded_text(self.issued_at, 64),
            zone_id: bounded_text(self.zone_id, 128),
            payload_hash: bounded_text(self.payload_hash, 128),
            decision_payload: self.decision_payload.into_payload(),
            signature: self
                .signature
                .map(FuzzDecisionReceiptSignature::into_signature),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDecisionReceiptPayload {
    action_type: String,
    extension_id: Option<String>,
    incident_id: Option<String>,
    zone_id: String,
    tenant_id: Option<String>,
    affected_nodes: Option<u32>,
    revocation_severity: Option<FuzzRevocationSeverity>,
    reason: String,
    event_code: String,
}

impl FuzzDecisionReceiptPayload {
    fn into_payload(self) -> DecisionReceiptPayload {
        DecisionReceiptPayload {
            action_type: bounded_text(self.action_type, 64),
            extension_id: self
                .extension_id
                .map(|extension| bounded_text(extension, 128)),
            incident_id: self.incident_id.map(|incident| bounded_text(incident, 128)),
            scope: DecisionReceiptScope {
                zone_id: bounded_text(self.zone_id, 128),
                tenant_id: self.tenant_id.map(|tenant| bounded_text(tenant, 128)),
                affected_nodes: self.affected_nodes,
                revocation_severity: self
                    .revocation_severity
                    .map(FuzzRevocationSeverity::into_severity),
            },
            reason: bounded_text(self.reason, 256),
            event_code: bounded_text(self.event_code, 64),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDecisionReceiptSignature {
    algorithm: String,
    public_key_hex: String,
    key_id: String,
    key_source: String,
    signing_identity: String,
    trust_scope: String,
    signed_payload_sha256: String,
    signature_hex: String,
}

impl FuzzDecisionReceiptSignature {
    fn into_signature(self) -> DecisionReceiptSignature {
        DecisionReceiptSignature {
            algorithm: bounded_text(self.algorithm, 64),
            public_key_hex: bounded_text(self.public_key_hex, 128),
            key_id: bounded_text(self.key_id, 128),
            key_source: bounded_text(self.key_source, 128),
            signing_identity: bounded_text(self.signing_identity, 128),
            trust_scope: bounded_text(self.trust_scope, 128),
            signed_payload_sha256: bounded_text(self.signed_payload_sha256, 128),
            signature_hex: bounded_text(self.signature_hex, 256),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzSessionConfig {
    replay_window: u64,
    max_sessions: usize,
    session_timeout_ms: u64,
}

impl FuzzSessionConfig {
    fn into_config(self) -> SessionConfig {
        SessionConfig {
            replay_window: self.replay_window,
            max_sessions: self.max_sessions.min(16_384),
            session_timeout_ms: self.session_timeout_ms,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzMessageDirection {
    Send,
    Receive,
}

impl FuzzMessageDirection {
    fn into_direction(self) -> MessageDirection {
        match self {
            Self::Send => MessageDirection::Send,
            Self::Receive => MessageDirection::Receive,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzAuthenticatedMessage {
    session_id: String,
    sequence: u64,
    direction: FuzzMessageDirection,
    payload_hash: String,
    verified_mac: [u8; 32],
}

impl FuzzAuthenticatedMessage {
    fn into_message(self) -> AuthenticatedMessage {
        AuthenticatedMessage {
            session_id: bounded_text(self.session_id, 128),
            sequence: self.sequence,
            direction: self.direction.into_direction(),
            payload_hash: bounded_text(self.payload_hash, 128),
            verified_mac: self.verified_mac,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzSessionEvent {
    event_code: String,
    session_id: String,
    trace_id: String,
    detail: String,
    timestamp: u64,
}

impl FuzzSessionEvent {
    fn into_event(self) -> SessionEvent {
        SessionEvent {
            event_code: bounded_text(self.event_code, 64),
            session_id: bounded_text(self.session_id, 128),
            trace_id: bounded_text(self.trace_id, 128),
            detail: bounded_text(self.detail, 512),
            timestamp: self.timestamp,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzOperatorStatus {
    node_id: String,
    version: String,
    uptime_seconds: u64,
    policy_profile: String,
    active_extensions: u32,
    quarantined_extensions: u32,
    control_epoch: u64,
}

impl FuzzOperatorStatus {
    fn into_status(self) -> OperatorNodeStatus {
        OperatorNodeStatus {
            node_id: bounded_text(self.node_id, 128),
            version: bounded_text(self.version, 64),
            uptime_seconds: self.uptime_seconds,
            policy_profile: bounded_text(self.policy_profile, 64),
            active_extensions: self.active_extensions,
            quarantined_extensions: self.quarantined_extensions,
            control_epoch: self.control_epoch,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzComponentStatus {
    Ok,
    Degraded,
    Down,
}

impl FuzzComponentStatus {
    fn into_status(self) -> ComponentStatus {
        match self {
            Self::Ok => ComponentStatus::Ok,
            Self::Degraded => ComponentStatus::Degraded,
            Self::Down => ComponentStatus::Down,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzHealthComponent {
    name: String,
    status: FuzzComponentStatus,
    detail: Option<String>,
}

impl FuzzHealthComponent {
    fn into_component(self) -> HealthComponent {
        HealthComponent {
            name: bounded_text(self.name, 128),
            status: self.status.into_status(),
            detail: self.detail.map(|detail| bounded_text(detail, 256)),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzOperatorHealth {
    live: bool,
    ready: bool,
    checks: Vec<FuzzHealthComponent>,
}

impl FuzzOperatorHealth {
    fn into_health(self) -> HealthCheck {
        HealthCheck {
            live: self.live,
            ready: self.ready,
            checks: self
                .checks
                .into_iter()
                .take(32)
                .map(FuzzHealthComponent::into_component)
                .collect(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzOperatorConfig {
    profile: String,
    compatibility_mode: String,
    trust_revocation_fresh: bool,
    quarantine_on_high_risk: bool,
    replay_persist_high_severity: bool,
    fleet_convergence_timeout_seconds: u32,
    observability_namespace: String,
}

impl FuzzOperatorConfig {
    fn into_config(self) -> ConfigView {
        ConfigView {
            profile: bounded_text(self.profile, 64),
            compatibility_mode: bounded_text(self.compatibility_mode, 64),
            trust_revocation_fresh: self.trust_revocation_fresh,
            quarantine_on_high_risk: self.quarantine_on_high_risk,
            replay_persist_high_severity: self.replay_persist_high_severity,
            fleet_convergence_timeout_seconds: self.fleet_convergence_timeout_seconds,
            observability_namespace: bounded_text(self.observability_namespace, 128),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzOperatorRollout {
    current_phase: String,
    target_version: String,
    canary_percentage: u8,
    healthy_nodes: u32,
    total_nodes: u32,
    last_transition: String,
}

impl FuzzOperatorRollout {
    fn into_rollout(self) -> RolloutState {
        RolloutState {
            current_phase: bounded_text(self.current_phase, 64),
            target_version: bounded_text(self.target_version, 64),
            canary_percentage: self.canary_percentage,
            healthy_nodes: self.healthy_nodes,
            total_nodes: self.total_nodes,
            last_transition: bounded_text(self.last_transition, 64),
        }
    }
}

fn bounded_text(value: String, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    QuarantineRequestStruct(FuzzQuarantineRequest),
    RevokeRequestStruct(FuzzRevokeRequest),
    ReleaseRequestStruct(FuzzReleaseRequest),
    StatusRequestStruct(FuzzStatusRequest),
    DecisionReceiptStruct(FuzzDecisionReceipt),
    SessionConfigStruct(FuzzSessionConfig),
    AuthenticatedMessageStruct(FuzzAuthenticatedMessage),
    SessionEventStruct(FuzzSessionEvent),
    OperatorStatusStruct(FuzzOperatorStatus),
    OperatorHealthStruct(FuzzOperatorHealth),
    OperatorConfigStruct(FuzzOperatorConfig),
    OperatorRolloutStruct(FuzzOperatorRollout),
    TrustCardPagination(TrustCardFuzzData),
    RawJsonBytes(Vec<u8>),
}
