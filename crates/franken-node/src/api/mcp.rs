//! In-process MCP tool catalog for stable franken_node API contracts.
//!
//! This module exposes the existing control-plane route metadata as MCP-style
//! tool descriptors. It is intentionally an in-process catalog/dispatch surface,
//! matching `api::service`: it does not bind a socket or claim to be a live MCP
//! transport. Read tools are callable without an audience capability token;
//! mutating tools require an audience-bound token chain and emit a signed
//! agent-action receipt into the evidence ledger.

use crate::control_plane::audience_token::{ActionScope, TokenChain, TokenError, TokenValidator};
use crate::observability::evidence_ledger::{
    DecisionKind, EntryId, EvidenceEntry, EvidenceLedger, LedgerError,
};
use crate::security::decision_receipt::{
    Decision, Ed25519PrivateKey, Receipt, ReceiptError, SignedReceipt, sign_receipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::middleware::{AuthMethod, RouteMetadata};
use super::service;

/// MCP catalog built from current route metadata.
pub const FN_MCP_CATALOG_BUILT: &str = "FN-MCP-001";
/// Read-only MCP tool dispatched through the in-process contract surface.
pub const FN_MCP_READ_DISPATCHED: &str = "FN-MCP-002";
/// MCP tool rejected by fail-closed dispatch rules.
pub const FN_MCP_TOOL_REJECTED: &str = "FN-MCP-003";
/// Mutating MCP tool authorized and recorded in the agent-action ledger.
pub const FN_MCP_MUTATION_DISPATCHED: &str = "FN-MCP-004";

const MCP_AGENT_ACTION_LEDGER_SCHEMA_VERSION: &str = "mcp-agent-action-ledger-v1";

/// Whether an MCP tool can mutate product state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolAccess {
    Read,
    Mutating,
}

impl McpToolAccess {
    fn from_route(route: &RouteMetadata) -> Self {
        match route.method.as_str() {
            "GET" => Self::Read,
            _ => Self::Mutating,
        }
    }

    pub const fn requires_capability_token(self) -> bool {
        matches!(self, Self::Mutating)
    }
}

/// MCP-facing descriptor for one stable route contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolDescriptor {
    pub name: String,
    pub route_method: String,
    pub route_path: String,
    pub endpoint_group: String,
    pub lifecycle: String,
    pub access: McpToolAccess,
    pub requires_capability_token: bool,
    pub required_action_scope: Option<String>,
    pub route_auth_method: String,
    pub policy_hook: String,
    pub trace_propagation: bool,
    pub source_contract: String,
}

impl McpToolDescriptor {
    fn from_route(route: &RouteMetadata) -> Self {
        let access = McpToolAccess::from_route(route);
        Self {
            name: mcp_tool_name(route),
            route_method: route.method.clone(),
            route_path: route.path.clone(),
            endpoint_group: route.group.as_str().to_string(),
            lifecycle: route.lifecycle.as_str().to_string(),
            access,
            requires_capability_token: access.requires_capability_token(),
            required_action_scope: required_action_scope_for_route(route)
                .map(|scope| scope.label().to_string()),
            route_auth_method: auth_method_label(&route.auth_method).to_string(),
            policy_hook: route.policy_hook.hook_id.clone(),
            trace_propagation: route.trace_propagation,
            source_contract: "api::service::all_route_metadata".to_string(),
        }
    }
}

/// Request envelope for in-process MCP tool dispatch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolRequest {
    pub tool_name: String,
    #[serde(default)]
    pub arguments: Value,
    pub trace_id: String,
    pub principal: String,
}

/// Request envelope for mutating MCP tool dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMutationRequest {
    pub tool_name: String,
    #[serde(default)]
    pub arguments: Value,
    pub trace_id: String,
    pub principal: String,
    pub audience: String,
    pub token_chain: TokenChain,
    pub rollback_command: String,
}

/// Response envelope for read-only in-process MCP dispatch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolResponse {
    pub ok: bool,
    pub event_code: String,
    pub tool_name: String,
    pub trace_id: String,
    pub principal: String,
    pub descriptor: McpToolDescriptor,
    pub output: Value,
}

/// Mutable dependencies for one mutating MCP dispatch.
pub struct McpMutationContext<'a> {
    pub token_validator: &'a mut TokenValidator,
    pub evidence_ledger: &'a mut EvidenceLedger,
    pub receipt_signing_key: &'a Ed25519PrivateKey,
    pub now_ms: u64,
    pub epoch_id: u64,
}

/// Response envelope for authorized mutating MCP dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMutationResponse {
    pub ok: bool,
    pub event_code: String,
    pub tool_name: String,
    pub trace_id: String,
    pub principal: String,
    pub audience: String,
    pub descriptor: McpToolDescriptor,
    pub required_action_scope: String,
    pub receipt: SignedReceipt,
    pub ledger_entry_id: String,
    pub output: Value,
}

/// Fail-closed errors for MCP catalog/dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpError {
    pub event_code: String,
    pub code: String,
    pub detail: String,
    pub trace_id: String,
}

impl McpError {
    fn unknown_tool(tool_name: &str, trace_id: &str) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: "FN_MCP_UNKNOWN_TOOL".to_string(),
            detail: format!("unknown MCP tool: {tool_name}"),
            trace_id: trace_id.to_string(),
        }
    }

    fn capability_required(descriptor: &McpToolDescriptor, trace_id: &str) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: "FN_MCP_CAPABILITY_REQUIRED".to_string(),
            detail: format!(
                "MCP tool '{}' maps to {} {} and requires an audience capability token",
                descriptor.name, descriptor.route_method, descriptor.route_path
            ),
            trace_id: trace_id.to_string(),
        }
    }

    fn read_tool_not_mutating(descriptor: &McpToolDescriptor, trace_id: &str) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: "FN_MCP_READ_TOOL_NOT_MUTATING".to_string(),
            detail: format!(
                "MCP tool '{}' maps to read-only route {} {}",
                descriptor.name, descriptor.route_method, descriptor.route_path
            ),
            trace_id: trace_id.to_string(),
        }
    }

    fn rollback_required(descriptor: &McpToolDescriptor, trace_id: &str) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: "FN_MCP_ROLLBACK_REQUIRED".to_string(),
            detail: format!(
                "MCP mutating tool '{}' requires a rollback_command in its signed receipt",
                descriptor.name
            ),
            trace_id: trace_id.to_string(),
        }
    }

    fn token_rejected(descriptor: &McpToolDescriptor, trace_id: &str, source: &TokenError) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: source.code.clone(),
            detail: format!(
                "MCP tool '{}' audience-token validation failed: {}",
                descriptor.name, source.message
            ),
            trace_id: trace_id.to_string(),
        }
    }

    fn scope_denied(
        descriptor: &McpToolDescriptor,
        trace_id: &str,
        required_scope: ActionScope,
    ) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: "FN_MCP_CAPABILITY_SCOPE_DENIED".to_string(),
            detail: format!(
                "MCP tool '{}' requires '{}' scope",
                descriptor.name,
                required_scope.label()
            ),
            trace_id: trace_id.to_string(),
        }
    }

    fn receipt_failed(
        descriptor: &McpToolDescriptor,
        trace_id: &str,
        source: &ReceiptError,
    ) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: "FN_MCP_RECEIPT_SIGNING_FAILED".to_string(),
            detail: format!(
                "MCP tool '{}' could not produce a signed decision receipt: {source}",
                descriptor.name
            ),
            trace_id: trace_id.to_string(),
        }
    }

    fn ledger_append_failed(
        descriptor: &McpToolDescriptor,
        trace_id: &str,
        source: &LedgerError,
    ) -> Self {
        Self {
            event_code: FN_MCP_TOOL_REJECTED.to_string(),
            code: "FN_MCP_LEDGER_APPEND_FAILED".to_string(),
            detail: format!(
                "MCP tool '{}' could not append agent-action evidence: {source}",
                descriptor.name
            ),
            trace_id: trace_id.to_string(),
        }
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for McpError {}

/// In-process MCP catalog surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpControlSurface {
    tools: BTreeMap<String, McpToolDescriptor>,
}

impl McpControlSurface {
    pub fn new() -> Self {
        let tools = service::all_route_metadata()
            .into_iter()
            .map(|route| {
                let descriptor = McpToolDescriptor::from_route(&route);
                (descriptor.name.clone(), descriptor)
            })
            .collect();
        Self { tools }
    }

    pub fn tools(&self) -> &BTreeMap<String, McpToolDescriptor> {
        &self.tools
    }

    pub fn catalog_json(&self) -> Value {
        json!({
            "event_code": FN_MCP_CATALOG_BUILT,
            "transport": "in_process_catalog",
            "source_contract": "api::service::all_route_metadata",
            "tools": self.tools.values().collect::<Vec<_>>(),
        })
    }

    pub fn dispatch_read(&self, request: McpToolRequest) -> Result<McpToolResponse, McpError> {
        let descriptor = self
            .tools
            .get(&request.tool_name)
            .ok_or_else(|| McpError::unknown_tool(&request.tool_name, &request.trace_id))?;

        if descriptor.access.requires_capability_token() {
            return Err(McpError::capability_required(descriptor, &request.trace_id));
        }

        Ok(McpToolResponse {
            ok: true,
            event_code: FN_MCP_READ_DISPATCHED.to_string(),
            tool_name: request.tool_name,
            trace_id: request.trace_id,
            principal: request.principal,
            descriptor: descriptor.clone(),
            output: json!({
                "contract": descriptor,
                "arguments": request.arguments,
            }),
        })
    }

    pub fn dispatch_mutation(
        &self,
        request: McpMutationRequest,
        context: &mut McpMutationContext<'_>,
    ) -> Result<McpMutationResponse, McpError> {
        let descriptor = self
            .tools
            .get(&request.tool_name)
            .ok_or_else(|| McpError::unknown_tool(&request.tool_name, &request.trace_id))?;

        if !descriptor.access.requires_capability_token() {
            return Err(McpError::read_tool_not_mutating(
                descriptor,
                &request.trace_id,
            ));
        }

        if request.rollback_command.trim().is_empty() {
            return Err(McpError::rollback_required(descriptor, &request.trace_id));
        }

        let required_scope = required_action_scope_for_descriptor(descriptor);
        context
            .token_validator
            .verify_chain(
                &request.token_chain,
                &request.audience,
                context.now_ms,
                &request.trace_id,
            )
            .map_err(|source| McpError::token_rejected(descriptor, &request.trace_id, &source))?;

        let leaf = request
            .token_chain
            .leaf()
            .ok_or_else(|| McpError::capability_required(descriptor, &request.trace_id))?;
        if !leaf.capabilities.contains(&required_scope) {
            return Err(McpError::scope_denied(
                descriptor,
                &request.trace_id,
                required_scope,
            ));
        }

        let output = json!({
            "authorized": true,
            "contract": descriptor,
            "arguments": request.arguments.clone(),
            "required_action_scope": required_scope.label(),
            "token_id": leaf.token_id.as_str(),
        });
        let receipt_input = json!({
            "tool_name": request.tool_name.as_str(),
            "route_method": descriptor.route_method.as_str(),
            "route_path": descriptor.route_path.as_str(),
            "policy_hook": descriptor.policy_hook.as_str(),
            "principal": request.principal.as_str(),
            "audience": request.audience.as_str(),
            "required_action_scope": required_scope.label(),
            "token_id": leaf.token_id.as_str(),
            "arguments": request.arguments.clone(),
        });
        let receipt = Receipt::new(
            &format!("mcp.{}", descriptor.name),
            &request.principal,
            &request.audience,
            &receipt_input,
            &output,
            Decision::Approved,
            "MCP mutating tool authorized by audience-bound capability token",
            vec![format!("mcp-tool:{}", descriptor.name)],
            vec![
                "FN-MCP-MUTATION-GATE".to_string(),
                "INV-ABT-AUDIENCE".to_string(),
                "INV-ABT-ATTENUATION".to_string(),
            ],
            1.0,
            &request.rollback_command,
        )
        .map_err(|source| McpError::receipt_failed(descriptor, &request.trace_id, &source))?;
        let signed_receipt = sign_receipt(&receipt, context.receipt_signing_key)
            .map_err(|source| McpError::receipt_failed(descriptor, &request.trace_id, &source))?;

        let ledger_entry_id = append_agent_action_entry(
            context.evidence_ledger,
            context.epoch_id,
            context.now_ms,
            &request.trace_id,
            decision_kind_for_scope(required_scope),
            &signed_receipt,
            descriptor,
        )
        .map_err(|source| McpError::ledger_append_failed(descriptor, &request.trace_id, &source))?;

        Ok(McpMutationResponse {
            ok: true,
            event_code: FN_MCP_MUTATION_DISPATCHED.to_string(),
            tool_name: request.tool_name,
            trace_id: request.trace_id,
            principal: request.principal,
            audience: request.audience,
            descriptor: descriptor.clone(),
            required_action_scope: required_scope.label().to_string(),
            receipt: signed_receipt,
            ledger_entry_id: ledger_entry_id.to_string(),
            output,
        })
    }
}

impl Default for McpControlSurface {
    fn default() -> Self {
        Self::new()
    }
}

pub fn build_mcp_control_surface() -> McpControlSurface {
    McpControlSurface::new()
}

fn mcp_tool_name(route: &RouteMetadata) -> String {
    route.policy_hook.hook_id.replace('.', "_")
}

fn required_action_scope_for_route(route: &RouteMetadata) -> Option<ActionScope> {
    if !McpToolAccess::from_route(route).requires_capability_token() {
        return None;
    }

    let route_text = format!("{} {}", route.path, route.policy_hook.hook_id);
    Some(required_action_scope_for_text(&route_text))
}

fn required_action_scope_for_descriptor(descriptor: &McpToolDescriptor) -> ActionScope {
    let route_text = format!("{} {}", descriptor.route_path, descriptor.policy_hook);
    required_action_scope_for_text(&route_text)
}

fn required_action_scope_for_text(route_text: &str) -> ActionScope {
    if route_text.contains("rollback") {
        ActionScope::Rollback
    } else if route_text.contains("migrate") {
        ActionScope::Migrate
    } else if route_text.contains("release") || route_text.contains("promote") {
        ActionScope::Promote
    } else if route_text.contains("quarantine") || route_text.contains("revoke") {
        ActionScope::Revoke
    } else {
        ActionScope::Configure
    }
}

fn decision_kind_for_scope(scope: ActionScope) -> DecisionKind {
    match scope {
        ActionScope::Migrate | ActionScope::Configure => DecisionKind::Escalate,
        ActionScope::Rollback => DecisionKind::Rollback,
        ActionScope::Promote => DecisionKind::Release,
        ActionScope::Revoke => DecisionKind::Quarantine,
    }
}

fn append_agent_action_entry(
    evidence_ledger: &mut EvidenceLedger,
    epoch_id: u64,
    now_ms: u64,
    trace_id: &str,
    decision_kind: DecisionKind,
    signed_receipt: &SignedReceipt,
    descriptor: &McpToolDescriptor,
) -> Result<EntryId, LedgerError> {
    evidence_ledger.append(EvidenceEntry {
        schema_version: MCP_AGENT_ACTION_LEDGER_SCHEMA_VERSION.to_string(),
        entry_id: None,
        decision_id: signed_receipt.receipt.receipt_id.clone(),
        decision_kind,
        decision_time: signed_receipt.receipt.timestamp.clone(),
        timestamp_ms: now_ms,
        trace_id: trace_id.to_string(),
        epoch_id,
        payload: json!({
            "event_code": FN_MCP_MUTATION_DISPATCHED,
            "tool": descriptor,
            "receipt": signed_receipt,
        }),
        size_bytes: 0,
        signature: String::new(),
        prev_entry_hash: String::new(),
    })
}

fn auth_method_label(method: &AuthMethod) -> &'static str {
    match method {
        AuthMethod::MtlsClientCert => "mtls_client_cert",
        AuthMethod::ApiKey => "api_key",
        AuthMethod::BearerToken => "bearer_token",
        AuthMethod::None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool<'a>(surface: &'a McpControlSurface, name: &str) -> &'a McpToolDescriptor {
        surface.tools().get(name).expect("tool descriptor exists")
    }

    #[test]
    fn mcp_catalog_is_built_from_route_metadata() {
        let surface = build_mcp_control_surface();
        let routes = service::all_route_metadata();

        assert_eq!(surface.tools().len(), routes.len());
        assert!(surface.tools().contains_key("operator_health_read"));
        assert!(surface.tools().contains_key("fleet_status_read"));
        assert!(surface.tools().contains_key("fleet_quarantine_execute"));
        assert!(
            surface
                .tools()
                .values()
                .all(|descriptor| descriptor.source_contract == "api::service::all_route_metadata")
        );
    }

    #[test]
    fn read_tools_are_capability_free_but_preserve_route_auth() {
        let surface = build_mcp_control_surface();
        let health = tool(&surface, "operator_health_read");
        let status = tool(&surface, "operator_status_read");

        assert_eq!(health.access, McpToolAccess::Read);
        assert!(!health.requires_capability_token);
        assert_eq!(health.route_auth_method, "none");

        assert_eq!(status.access, McpToolAccess::Read);
        assert!(!status.requires_capability_token);
        assert_eq!(status.route_auth_method, "api_key");
        assert_eq!(status.policy_hook, "operator.status.read");
    }

    #[test]
    fn mutating_tools_are_discoverable_but_capability_gated() {
        let surface = build_mcp_control_surface();
        let quarantine = tool(&surface, "fleet_quarantine_execute");

        assert_eq!(quarantine.access, McpToolAccess::Mutating);
        assert!(quarantine.requires_capability_token);
        assert_eq!(quarantine.route_method, "POST");
        assert_eq!(quarantine.route_path, "/v1/fleet/quarantine");
    }

    #[test]
    fn read_dispatch_returns_the_stable_route_contract() {
        let surface = build_mcp_control_surface();
        let response = surface
            .dispatch_read(McpToolRequest {
                tool_name: "operator_health_read".to_string(),
                arguments: json!({"format": "json"}),
                trace_id: "trace-mcp-read".to_string(),
                principal: "agent-reader".to_string(),
            })
            .expect("read tool dispatches without capability token");

        assert!(response.ok);
        assert_eq!(response.event_code, FN_MCP_READ_DISPATCHED);
        assert_eq!(response.descriptor.route_method, "GET");
        assert_eq!(response.descriptor.route_path, "/v1/operator/health");
        assert_eq!(response.output["arguments"]["format"], "json");
    }

    #[test]
    fn mutating_dispatch_fails_closed_until_capability_gate_is_wired() {
        let surface = build_mcp_control_surface();
        let error = surface
            .dispatch_read(McpToolRequest {
                tool_name: "fleet_quarantine_execute".to_string(),
                arguments: json!({"extension_id": "pkg.bad"}),
                trace_id: "trace-mcp-mutate".to_string(),
                principal: "agent-mutator".to_string(),
            })
            .expect_err("mutating tool must require capability token");

        assert_eq!(error.event_code, FN_MCP_TOOL_REJECTED);
        assert_eq!(error.code, "FN_MCP_CAPABILITY_REQUIRED");
        assert!(error.detail.contains("fleet_quarantine_execute"));
    }

    #[test]
    fn unknown_tool_dispatch_fails_closed() {
        let surface = build_mcp_control_surface();
        let error = surface
            .dispatch_read(McpToolRequest {
                tool_name: "unknown_tool".to_string(),
                arguments: Value::Null,
                trace_id: "trace-mcp-unknown".to_string(),
                principal: "agent-reader".to_string(),
            })
            .expect_err("unknown tool must fail closed");

        assert_eq!(error.event_code, FN_MCP_TOOL_REJECTED);
        assert_eq!(error.code, "FN_MCP_UNKNOWN_TOOL");
    }
}
