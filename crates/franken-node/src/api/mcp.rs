//! In-process MCP tool catalog for stable franken_node API contracts.
//!
//! This module exposes the existing control-plane route metadata as MCP-style
//! tool descriptors. It is intentionally an in-process catalog/dispatch surface,
//! matching `api::service`: it does not bind a socket or claim to be a live MCP
//! transport. Read tools are callable without an audience capability token;
//! mutating tools are discoverable but fail closed until the follow-on mutation
//! gating bead wires audience-token verification and receipt emission.

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
