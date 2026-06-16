use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::api::mcp::{
    FN_MCP_CATALOG_BUILT, FN_MCP_MUTATION_DISPATCHED, FN_MCP_READ_DISPATCHED,
    FN_MCP_SESSION_REPLAY_BUILT, FN_MCP_TOOL_REJECTED, McpMutationContext, McpMutationRequest,
    McpReplayableAgentSession, McpReplayableSessionMetadata, McpSessionContext, McpToolAccess,
    McpToolRequest, build_mcp_control_surface,
};
use frankenengine_node::control_plane::audience_token::{
    ActionScope, AudienceBoundToken, ERR_ABT_ATTENUATION_VIOLATION, ERR_ABT_AUDIENCE_MISMATCH,
    TokenChain, TokenError, TokenId, TokenValidator,
};
use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
use frankenengine_node::security::decision_receipt::verify_receipt;
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn fixture_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[14_u8; 32])
}

fn sign_token(token: &mut AudienceBoundToken, signing_key: &SigningKey) {
    token.signature.clear();
    token.signature = hex::encode(signing_key.sign(&token.signature_preimage()).to_bytes());
}

fn capabilities(scopes: &[ActionScope]) -> BTreeSet<ActionScope> {
    scopes.iter().copied().collect()
}

fn token_chain_with_scope(token_id: &str, audience: &str, scope: ActionScope) -> TokenChain {
    let signing_key = fixture_signing_key();
    let mut token = AudienceBoundToken {
        token_id: TokenId::new(token_id),
        issuer: "issuer-1".to_string(),
        audience: vec![audience.to_string()],
        capabilities: capabilities(&[scope]),
        issued_at: 1_000,
        expires_at: 100_000,
        nonce: format!("nonce-{token_id}"),
        parent_token_hash: None,
        signature: String::new(),
        max_delegation_depth: 1,
    };
    sign_token(&mut token, &signing_key);
    TokenChain::new(token).expect("fixture token chain is valid")
}

fn delegated_token_chain(
    root_id: &str,
    child_id: &str,
    audience: &str,
    root_scopes: &[ActionScope],
    child_scopes: &[ActionScope],
) -> Result<TokenChain, TokenError> {
    let signing_key = fixture_signing_key();
    let mut root = AudienceBoundToken {
        token_id: TokenId::new(root_id),
        issuer: "issuer-1".to_string(),
        audience: vec![audience.to_string()],
        capabilities: capabilities(root_scopes),
        issued_at: 1_000,
        expires_at: 100_000,
        nonce: format!("nonce-{root_id}"),
        parent_token_hash: None,
        signature: String::new(),
        max_delegation_depth: 2,
    };
    sign_token(&mut root, &signing_key);

    let mut child = AudienceBoundToken {
        token_id: TokenId::new(child_id),
        issuer: "issuer-1".to_string(),
        audience: vec![audience.to_string()],
        capabilities: capabilities(child_scopes),
        issued_at: 2_000,
        expires_at: 90_000,
        nonce: format!("nonce-{child_id}"),
        parent_token_hash: Some(root.hash()),
        signature: String::new(),
        max_delegation_depth: 1,
    };
    sign_token(&mut child, &signing_key);

    let mut chain = TokenChain::new(root)?;
    chain.append(child)?;
    Ok(chain)
}

fn trusted_validator(epoch_id: u64) -> TokenValidator {
    TokenValidator::new(epoch_id)
        .with_trusted_issuer_key("issuer-1", fixture_signing_key().verifying_key())
}

#[test]
fn mcp_control_surface_exposes_stable_route_contracts() {
    let surface = build_mcp_control_surface();
    let catalog = surface.catalog_json();

    assert_eq!(catalog["event_code"], FN_MCP_CATALOG_BUILT);
    assert_eq!(catalog["transport"], "in_process_catalog");
    assert!(surface.tools().contains_key("operator_health_read"));
    assert!(surface.tools().contains_key("operator_status_read"));
    assert!(surface.tools().contains_key("fleet_quarantine_execute"));

    let health = surface
        .tools()
        .get("operator_health_read")
        .expect("operator health read tool is exposed");
    assert_eq!(health.access, McpToolAccess::Read);
    assert!(!health.requires_capability_token);
    assert_eq!(health.required_action_scope, None);
    assert_eq!(health.route_method, "GET");
    assert_eq!(health.route_path, "/v1/operator/health");
    assert_eq!(health.route_auth_method, "none");

    let status = surface
        .tools()
        .get("operator_status_read")
        .expect("operator status read tool is exposed");
    assert_eq!(status.access, McpToolAccess::Read);
    assert!(!status.requires_capability_token);
    assert_eq!(status.route_auth_method, "api_key");

    let quarantine = surface
        .tools()
        .get("fleet_quarantine_execute")
        .expect("fleet quarantine mutating tool is exposed");
    assert_eq!(quarantine.access, McpToolAccess::Mutating);
    assert!(quarantine.requires_capability_token);
    assert_eq!(quarantine.required_action_scope.as_deref(), Some("revoke"));
    assert_eq!(quarantine.route_method, "POST");
}

#[test]
fn mcp_control_surface_dispatches_reads_and_fails_closed_for_mutations() {
    let surface = build_mcp_control_surface();

    let read = surface
        .dispatch_read(McpToolRequest {
            tool_name: "operator_health_read".to_string(),
            arguments: json!({"format": "json"}),
            trace_id: "trace-mcp-contract-read".to_string(),
            principal: "agent-reader".to_string(),
        })
        .expect("read tools dispatch without capability token");
    assert!(read.ok);
    assert_eq!(read.event_code, FN_MCP_READ_DISPATCHED);
    assert_eq!(read.output["arguments"]["format"], "json");
    assert_eq!(read.descriptor.policy_hook, "operator.health.read");

    let mutation = surface
        .dispatch_read(McpToolRequest {
            tool_name: "fleet_quarantine_execute".to_string(),
            arguments: json!({"extension_id": "pkg.bad"}),
            trace_id: "trace-mcp-contract-mutation".to_string(),
            principal: "agent-mutator".to_string(),
        })
        .expect_err("mutating tools fail closed until capability gating is wired");
    assert_eq!(mutation.event_code, FN_MCP_TOOL_REJECTED);
    assert_eq!(mutation.code, "FN_MCP_CAPABILITY_REQUIRED");

    let unknown = surface
        .dispatch_read(McpToolRequest {
            tool_name: "missing_tool".to_string(),
            arguments: Value::Null,
            trace_id: "trace-mcp-contract-unknown".to_string(),
            principal: "agent-reader".to_string(),
        })
        .expect_err("unknown tools fail closed");
    assert_eq!(unknown.event_code, FN_MCP_TOOL_REJECTED);
    assert_eq!(unknown.code, "FN_MCP_UNKNOWN_TOOL");
}

#[test]
fn mcp_mutating_dispatch_validates_token_and_records_signed_receipt() {
    let surface = build_mcp_control_surface();
    let receipt_signing_key = fixture_signing_key();
    let mut token_validator = trusted_validator(42);
    let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(8, 16_384));

    let response = {
        let mut context = McpMutationContext {
            token_validator: &mut token_validator,
            evidence_ledger: &mut evidence_ledger,
            receipt_signing_key: &receipt_signing_key,
            now_ms: 10_000,
            epoch_id: 42,
        };
        surface
            .dispatch_mutation(
                McpMutationRequest {
                    tool_name: "fleet_quarantine_execute".to_string(),
                    arguments: json!({"extension_id": "pkg.bad"}),
                    trace_id: "trace-mcp-contract-mutate-ok".to_string(),
                    principal: "agent-mutator".to_string(),
                    audience: "franken-node-mcp".to_string(),
                    token_chain: token_chain_with_scope(
                        "token-mcp-revoke",
                        "franken-node-mcp",
                        ActionScope::Revoke,
                    ),
                    rollback_command: "franken-node fleet release pkg.bad".to_string(),
                    session: None,
                },
                &mut context,
            )
            .expect("mutating tool dispatches with a scoped audience token")
    };

    assert!(response.ok);
    assert_eq!(response.event_code, FN_MCP_MUTATION_DISPATCHED);
    assert_eq!(response.required_action_scope, "revoke");
    assert_eq!(response.ledger_entry_id, "E-00000001");
    assert_eq!(
        response.receipt.receipt.action_name,
        "mcp.fleet_quarantine_execute"
    );
    assert_eq!(response.receipt.receipt.actor_identity, "agent-mutator");
    assert_eq!(response.receipt.receipt.audience, "franken-node-mcp");
    assert_eq!(
        response.receipt.receipt.rollback_command,
        "franken-node fleet release pkg.bad"
    );
    assert_eq!(response.output["authorized"], true);
    assert_eq!(response.output["token_id"], "token-mcp-revoke");
    assert_eq!(evidence_ledger.len(), 1);
    assert!(
        verify_receipt(&response.receipt, &receipt_signing_key.verifying_key())
            .expect("receipt verification succeeds")
    );
}

#[test]
fn mcp_mutating_dispatch_fails_closed_for_bad_token_scope_audience_and_rollback() {
    let surface = build_mcp_control_surface();
    let receipt_signing_key = fixture_signing_key();

    let missing_scope = {
        let mut token_validator = trusted_validator(42);
        let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(8, 16_384));
        let mut context = McpMutationContext {
            token_validator: &mut token_validator,
            evidence_ledger: &mut evidence_ledger,
            receipt_signing_key: &receipt_signing_key,
            now_ms: 10_000,
            epoch_id: 42,
        };
        surface
            .dispatch_mutation(
                McpMutationRequest {
                    tool_name: "fleet_quarantine_execute".to_string(),
                    arguments: json!({"extension_id": "pkg.bad"}),
                    trace_id: "trace-mcp-contract-scope-denied".to_string(),
                    principal: "agent-mutator".to_string(),
                    audience: "franken-node-mcp".to_string(),
                    token_chain: token_chain_with_scope(
                        "token-mcp-configure",
                        "franken-node-mcp",
                        ActionScope::Configure,
                    ),
                    rollback_command: "franken-node fleet release pkg.bad".to_string(),
                    session: None,
                },
                &mut context,
            )
            .expect_err("token without revoke scope must fail closed")
    };
    assert_eq!(missing_scope.event_code, FN_MCP_TOOL_REJECTED);
    assert_eq!(missing_scope.code, "FN_MCP_CAPABILITY_SCOPE_DENIED");

    let audience_mismatch = {
        let mut token_validator = trusted_validator(43);
        let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(8, 16_384));
        let mut context = McpMutationContext {
            token_validator: &mut token_validator,
            evidence_ledger: &mut evidence_ledger,
            receipt_signing_key: &receipt_signing_key,
            now_ms: 10_000,
            epoch_id: 43,
        };
        surface
            .dispatch_mutation(
                McpMutationRequest {
                    tool_name: "fleet_quarantine_execute".to_string(),
                    arguments: json!({"extension_id": "pkg.bad"}),
                    trace_id: "trace-mcp-contract-audience-denied".to_string(),
                    principal: "agent-mutator".to_string(),
                    audience: "franken-node-mcp".to_string(),
                    token_chain: token_chain_with_scope(
                        "token-mcp-other-audience",
                        "other-audience",
                        ActionScope::Revoke,
                    ),
                    rollback_command: "franken-node fleet release pkg.bad".to_string(),
                    session: None,
                },
                &mut context,
            )
            .expect_err("wrong audience must fail closed")
    };
    assert_eq!(audience_mismatch.event_code, FN_MCP_TOOL_REJECTED);
    assert_eq!(audience_mismatch.code, ERR_ABT_AUDIENCE_MISMATCH);

    let missing_rollback = {
        let mut token_validator = trusted_validator(44);
        let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(8, 16_384));
        let mut context = McpMutationContext {
            token_validator: &mut token_validator,
            evidence_ledger: &mut evidence_ledger,
            receipt_signing_key: &receipt_signing_key,
            now_ms: 10_000,
            epoch_id: 44,
        };
        surface
            .dispatch_mutation(
                McpMutationRequest {
                    tool_name: "fleet_quarantine_execute".to_string(),
                    arguments: json!({"extension_id": "pkg.bad"}),
                    trace_id: "trace-mcp-contract-rollback-required".to_string(),
                    principal: "agent-mutator".to_string(),
                    audience: "franken-node-mcp".to_string(),
                    token_chain: token_chain_with_scope(
                        "token-mcp-missing-rollback",
                        "franken-node-mcp",
                        ActionScope::Revoke,
                    ),
                    rollback_command: String::new(),
                    session: None,
                },
                &mut context,
            )
            .expect_err("rollback command is required for mutating receipts")
    };
    assert_eq!(missing_rollback.event_code, FN_MCP_TOOL_REJECTED);
    assert_eq!(missing_rollback.code, "FN_MCP_ROLLBACK_REQUIRED");
}

#[test]
fn mcp_delegated_sub_agent_session_is_signed_replayable_and_attenuated() {
    let surface = build_mcp_control_surface();
    let receipt_signing_key = fixture_signing_key();
    let mut token_validator = trusted_validator(45);
    let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(8, 32_768));

    let response_two = {
        let mut context = McpMutationContext {
            token_validator: &mut token_validator,
            evidence_ledger: &mut evidence_ledger,
            receipt_signing_key: &receipt_signing_key,
            now_ms: 10_000,
            epoch_id: 45,
        };
        surface
            .dispatch_mutation(
                McpMutationRequest {
                    tool_name: "fleet_quarantine_execute".to_string(),
                    arguments: json!({"extension_id": "pkg.bad.two"}),
                    trace_id: "trace-mcp-session-op-2".to_string(),
                    principal: "agent-child".to_string(),
                    audience: "franken-node-mcp".to_string(),
                    token_chain: delegated_token_chain(
                        "token-root-2",
                        "token-child-2",
                        "franken-node-mcp",
                        &[ActionScope::Revoke, ActionScope::Configure],
                        &[ActionScope::Revoke],
                    )
                    .expect("attenuated delegated chain is valid"),
                    rollback_command: "franken-node fleet release pkg.bad.two".to_string(),
                    session: Some(McpSessionContext {
                        session_id: "mcp-session-attenuated-1".to_string(),
                        root_trace_id: "trace-mcp-session-root".to_string(),
                        sequence: 2,
                        control_session_id: Some("scc-session-1".to_string()),
                        delegated_from: Some("agent-parent".to_string()),
                        remote_capability_token_id: Some("remote-cap-token-1".to_string()),
                    }),
                },
                &mut context,
            )
            .expect("delegated sub-agent mutation dispatches")
    };

    let response_one = {
        let mut context = McpMutationContext {
            token_validator: &mut token_validator,
            evidence_ledger: &mut evidence_ledger,
            receipt_signing_key: &receipt_signing_key,
            now_ms: 10_001,
            epoch_id: 45,
        };
        surface
            .dispatch_mutation(
                McpMutationRequest {
                    tool_name: "fleet_quarantine_execute".to_string(),
                    arguments: json!({"extension_id": "pkg.bad.one"}),
                    trace_id: "trace-mcp-session-op-1".to_string(),
                    principal: "agent-child".to_string(),
                    audience: "franken-node-mcp".to_string(),
                    token_chain: delegated_token_chain(
                        "token-root-1",
                        "token-child-1",
                        "franken-node-mcp",
                        &[ActionScope::Revoke],
                        &[ActionScope::Revoke],
                    )
                    .expect("second attenuated delegated chain is valid"),
                    rollback_command: "franken-node fleet release pkg.bad.one".to_string(),
                    session: Some(McpSessionContext {
                        session_id: "mcp-session-attenuated-1".to_string(),
                        root_trace_id: "trace-mcp-session-root".to_string(),
                        sequence: 1,
                        control_session_id: Some("scc-session-1".to_string()),
                        delegated_from: Some("agent-parent".to_string()),
                        remote_capability_token_id: Some("remote-cap-token-1".to_string()),
                    }),
                },
                &mut context,
            )
            .expect("second delegated sub-agent mutation dispatches")
    };

    let op_two = response_two
        .session_operation
        .clone()
        .expect("session operation is emitted");
    assert_eq!(op_two.sequence, 2);
    assert_eq!(op_two.token_id, "token-child-2");
    assert_eq!(op_two.token_chain_depth, 2);
    assert_eq!(op_two.delegated_from.as_deref(), Some("agent-parent"));
    assert_eq!(op_two.control_session_id.as_deref(), Some("scc-session-1"));
    assert_eq!(
        op_two.remote_capability_token_id.as_deref(),
        Some("remote-cap-token-1")
    );
    assert_eq!(op_two.token_chain_hashes.len(), 2);
    assert!(
        verify_receipt(&op_two.signed_receipt, &receipt_signing_key.verifying_key())
            .expect("operation receipt verifies")
    );

    let op_one = response_one
        .session_operation
        .clone()
        .expect("first session operation is emitted");
    let metadata = McpReplayableSessionMetadata {
        session_id: "mcp-session-attenuated-1".to_string(),
        root_trace_id: "trace-mcp-session-root".to_string(),
        control_session_id: Some("scc-session-1".to_string()),
        remote_capability_token_id: Some("remote-cap-token-1".to_string()),
        principal: "agent-child".to_string(),
        audience: "franken-node-mcp".to_string(),
        epoch_id: 45,
        started_at_ms: 10_000,
    };
    let bundle_from_unsorted = McpReplayableAgentSession::from_operations(
        metadata.clone(),
        vec![op_two.clone(), op_one.clone()],
    );
    let bundle_from_sorted =
        McpReplayableAgentSession::from_operations(metadata, vec![op_one, op_two]);

    assert_eq!(bundle_from_unsorted.event_code, FN_MCP_SESSION_REPLAY_BUILT);
    assert_eq!(bundle_from_unsorted.operation_count, 2);
    assert_eq!(bundle_from_unsorted.operations[0].sequence, 1);
    assert_eq!(bundle_from_unsorted.operations[1].sequence, 2);
    assert!(bundle_from_unsorted.verify_digest());
    assert_eq!(
        bundle_from_unsorted.session_digest_sha256, bundle_from_sorted.session_digest_sha256,
        "session digest must be independent of caller operation vector order"
    );
    assert_eq!(evidence_ledger.len(), 2);

    let expanded_child = delegated_token_chain(
        "token-root-expanded",
        "token-child-expanded",
        "franken-node-mcp",
        &[ActionScope::Revoke],
        &[ActionScope::Revoke, ActionScope::Configure],
    )
    .expect_err("sub-agent delegation must not expand parent scope");
    assert_eq!(expanded_child.code, ERR_ABT_ATTENUATION_VIOLATION);
}
