use frankenengine_node::api::mcp::{
    FN_MCP_CATALOG_BUILT, FN_MCP_READ_DISPATCHED, FN_MCP_TOOL_REJECTED, McpToolAccess,
    McpToolRequest, build_mcp_control_surface,
};
use serde_json::{Value, json};

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
