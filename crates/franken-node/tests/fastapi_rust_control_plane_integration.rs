use std::sync::{Mutex, MutexGuard, OnceLock};

use fastapi_rust::{App, Method, Request, RequestContext, Response, StatusCode, TestClient};
use frankenengine_node::api::error::ApiError;
use frankenengine_node::api::fleet_quarantine::{
    FLEET_NOT_ACTIVATED, FLEET_RECONCILE_COMPLETED,
    activate_shared_fleet_control_manager_for_tests, handle_reconcile,
    reset_shared_fleet_control_manager_for_tests,
};
use frankenengine_node::api::middleware::{
    AuthIdentity, AuthMethod, TraceContext, span_id_from_unix_nanos_for_tests,
};
use frankenengine_node::api::operator_routes::assert_process_start_cleanup_lock_order_for_tests;
use frankenengine_node::api::service::TransportBoundaryKind;
use frankenengine_node::api::{
    ApiState, ServiceConfig, build_api_service, build_default_api_service,
};
use serde::Deserialize;
use serde_json::Value;

const RECONCILE_TRACE_ID: &str = "fastapi-rust-reconcile-trace";
const RECONCILE_ROUTE_PATH: &str = "/v1/fleet/reconcile";
const CONTROL_PLANE_AUTH_HEADER: &str = "x-mtls-client-id";
const TRUSTED_FLEET_ADMIN: &str = "fastapi-rust-fleet-admin";
const NON_ADMIN_IDENTITY: &str = "fastapi-rust-readonly-operator";
const MAX_RECONCILE_PAYLOAD_BYTES: usize = 1024;
const RECONCILE_TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

#[derive(Debug, Deserialize)]
struct ReconcileRouteRequest {
    request_id: String,
}

fn lock_shared_fleet_state() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("fastapi fleet quarantine integration lock");
    reset_shared_fleet_control_manager_for_tests();
    guard
}

#[test]
fn operator_process_start_cleanup_uses_init_lock_before_data_locks() {
    assert_process_start_cleanup_lock_order_for_tests();
}

#[test]
fn canonical_api_service_builder_exports_full_control_plane_catalog() {
    let api = build_default_api_service();
    let catalog = api.catalog();
    let report = api.report();

    assert_eq!(catalog.len(), report.endpoints.len());
    assert!(catalog.iter().any(|entry| entry.group == "operator"));
    assert!(catalog.iter().any(|entry| entry.group == "verifier"));
    assert!(catalog.iter().any(|entry| entry.group == "fleet_control"));
    assert!(catalog.iter().all(|entry| !entry.policy_hook.is_empty()));
    assert!(report.middleware_coverage.auth_coverage);
    assert!(report.middleware_coverage.policy_hook_coverage);
    assert!(report.middleware_coverage.tracing_coverage);
    assert!(report.middleware_coverage.error_formatting_coverage);
    assert!(report.middleware_coverage.rate_limiting_coverage);
}

#[test]
fn canonical_api_service_builder_preserves_public_state_config() {
    let api = build_api_service(ApiState::new(ServiceConfig {
        bind_target_hint: "10.0.0.25:9443".to_string(),
        otel_enabled: true,
        ..Default::default()
    }));

    assert_eq!(api.config().bind_target_hint, "10.0.0.25:9443");
    assert!(api.config().otel_enabled);
    assert_eq!(
        api.transport_boundary().kind,
        TransportBoundaryKind::InProcessCatalog
    );
    assert!(!api.transport_boundary().owns_listener);
}

#[test]
fn trace_span_id_generation_saturates_oversized_unix_nanos() {
    let oversized_nanos = u128::from(u64::MAX).saturating_add(1);
    let span_id = span_id_from_unix_nanos_for_tests(oversized_nanos);

    assert_eq!(span_id, u64::MAX ^ 0x517c_c1b7_2722_0a95);
    assert_ne!(span_id, 0x517c_c1b7_2722_0a95);
}

fn fleet_admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "mtls:fastapi-rust-fleet-admin".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn request_header<'request>(req: &'request Request, name: &str) -> Option<&'request str> {
    req.headers()
        .get(name)
        .and_then(|value| std::str::from_utf8(value).ok())
}

/// Maximum byte length of a W3C traceparent header (`00-{32-hex}-{16-hex}-{2-hex}`).
///
/// bd-uxu46 hardening: reject the header before splitting so a malformed input
/// cannot drive the parser through an arbitrary number of `-`-separated
/// segments. Mirrors `crates/franken-node/src/api/middleware.rs::TRACEPARENT_HEADER_LEN`.
const TRACEPARENT_HEADER_LEN: usize = 55;

fn parse_traceparent(header: &str) -> Option<TraceContext> {
    // bd-uxu46: bound the parser at the byte level *and* the segment level
    // before doing any allocation. `split('-')` returns a lazy iterator, but
    // without these guards a malformed/oversized header still drives every
    // call site through unbounded scanning. `splitn(5, '-')` caps the
    // iteration at 5 calls; the exact-length check rejects anything that is
    // not exactly the canonical W3C size up front.
    if header.len() != TRACEPARENT_HEADER_LEN {
        return None;
    }
    let mut parts = header.splitn(5, '-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let trace_flags = parts.next()?;
    if parts.next().is_some()
        || version != "00"
        || trace_id.len() != 32
        || span_id.len() != 16
        || trace_flags.len() != 2
        || !trace_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !span_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !trace_flags.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(TraceContext {
        trace_id: trace_id.to_ascii_lowercase(),
        span_id: span_id.to_ascii_lowercase(),
        trace_flags: u8::from_str_radix(trace_flags, 16).ok()?,
    })
}

#[cfg(test)]
mod traceparent_parser_hardening {
    //! bd-uxu46 regression: the integration-test traceparent parser must
    //! reject oversized + dash-flooded headers up front so it never walks an
    //! attacker-controlled number of segments.

    use super::{TRACEPARENT_HEADER_LEN, TraceContext, parse_traceparent};

    /// Canonical 55-byte W3C traceparent shape: `00-32hex-16hex-2hex`.
    const VALID: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    #[test]
    fn accepts_canonical_header() {
        assert_eq!(VALID.len(), TRACEPARENT_HEADER_LEN);
        let parsed = parse_traceparent(VALID).expect("canonical header parses");
        assert_eq!(parsed.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(parsed.span_id, "b7ad6b7169203331");
        assert_eq!(parsed.trace_flags, 1);
    }

    #[test]
    fn rejects_oversized_header_before_splitting() {
        // 4 KiB of dashes should never scan the whole input.
        let dash_flood = "-".repeat(4096);
        assert!(parse_traceparent(&dash_flood).is_none());

        // Canonical-looking but oversized: append junk after a valid prefix.
        let mut oversized = String::from(VALID);
        oversized.push_str(&"-extra".repeat(1024));
        assert!(parse_traceparent(&oversized).is_none());
    }

    #[test]
    fn rejects_undersized_header() {
        assert!(parse_traceparent("").is_none());
        assert!(parse_traceparent("00").is_none());
        assert!(parse_traceparent("00-deadbeef-cafef00d-01").is_none());
    }

    #[test]
    fn rejects_correct_length_but_extra_dash_segments() {
        // 55-byte header where extra dashes inside fields create a 5th segment.
        // Exactly 55 bytes total, but split into 5+ segments so the
        // post-split is_some check trips and parser rejects.
        let weird: String = "00-0af7651916cd43dd8448eb211c80319-b7ad6b71-9203331-01".to_string();
        assert_eq!(weird.len(), TRACEPARENT_HEADER_LEN);
        assert!(parse_traceparent(&weird).is_none());
    }

    #[test]
    fn rejects_non_hex_in_fields() {
        // Same length, valid layout, but non-hex characters in trace_id.
        let bad_hex = "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01";
        assert_eq!(bad_hex.len(), TRACEPARENT_HEADER_LEN);
        assert!(parse_traceparent(bad_hex).is_none());
    }

    #[test]
    fn type_is_traceparent_compatible() {
        // Compile-time assertion that parse returns the expected type so
        // refactors don't silently change the contract.
        let parsed: Option<TraceContext> = parse_traceparent(VALID);
        assert!(parsed.is_some());
    }
}

fn problem_response(
    status: StatusCode,
    code: &str,
    title: &str,
    detail: impl Into<String>,
    trace_id: &str,
) -> Response {
    Response::with_status(status)
        .header("content-type", b"application/problem+json".to_vec())
        .body(fastapi_rust::ResponseBody::Bytes(
            serde_json::to_vec(&serde_json::json!({
                "type": format!("https://errors.franken-node.dev/{code}"),
                "title": title,
                "status": status.as_u16(),
                "detail": detail.into(),
                "instance": RECONCILE_ROUTE_PATH,
                "code": code,
                "trace_id": trace_id,
            }))
            .expect("serialize problem detail"),
        ))
}

fn trace_from_request(req: &Request) -> Result<TraceContext, Response> {
    let header = request_header(req, "traceparent").ok_or_else(|| {
        problem_response(
            StatusCode::BAD_REQUEST,
            "FASTAPI_BAD_REQUEST",
            "Bad request",
            "missing traceparent header",
            RECONCILE_TRACE_ID,
        )
    })?;
    parse_traceparent(header).ok_or_else(|| {
        problem_response(
            StatusCode::BAD_REQUEST,
            "FASTAPI_BAD_REQUEST",
            "Bad request",
            "malformed traceparent header",
            RECONCILE_TRACE_ID,
        )
    })
}

fn identity_from_request(req: &Request, trace: &TraceContext) -> Result<AuthIdentity, Response> {
    let propagated = request_header(req, CONTROL_PLANE_AUTH_HEADER)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            problem_response(
                StatusCode::UNAUTHORIZED,
                "FASTAPI_AUTH_FAIL",
                "Authentication failed",
                "mTLS client identity not propagated",
                &trace.trace_id,
            )
        })?;

    match propagated {
        TRUSTED_FLEET_ADMIN => Ok(fleet_admin_identity()),
        NON_ADMIN_IDENTITY => Ok(AuthIdentity {
            principal: format!("mtls:{NON_ADMIN_IDENTITY}"),
            method: AuthMethod::MtlsClientCert,
            roles: vec!["operator".to_string()],
        }),
        _ => Err(problem_response(
            StatusCode::UNAUTHORIZED,
            "FASTAPI_AUTH_FAIL",
            "Authentication failed",
            "invalid mTLS client identity",
            &trace.trace_id,
        )),
    }
}

fn enforce_fleet_admin(identity: &AuthIdentity, trace: &TraceContext) -> Result<(), Response> {
    if identity.roles.iter().any(|role| role == "fleet-admin") {
        return Ok(());
    }
    Err(problem_response(
        StatusCode::FORBIDDEN,
        "FASTAPI_POLICY_DENY",
        "Policy denied",
        "fleet.reconcile.execute requires fleet-admin role",
        &trace.trace_id,
    ))
}

fn api_error_response(err: ApiError, trace: &TraceContext) -> Response {
    match err {
        ApiError::BadRequest { detail, .. } if detail.contains(FLEET_NOT_ACTIVATED) => {
            problem_response(
                StatusCode::from_u16(409),
                "FASTAPI_CONFLICT",
                "Conflict",
                detail,
                &trace.trace_id,
            )
        }
        ApiError::BadRequest { detail, .. } => problem_response(
            StatusCode::BAD_REQUEST,
            "FASTAPI_BAD_REQUEST",
            "Bad request",
            detail,
            &trace.trace_id,
        ),
        ApiError::Internal { detail, .. } => problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FASTAPI_INTERNAL_ERROR",
            "Internal server error",
            detail,
            &trace.trace_id,
        ),
        other => problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FASTAPI_INTERNAL_ERROR",
            "Internal server error",
            other.to_string(),
            &trace.trace_id,
        ),
    }
}

fn fleet_reconcile_fastapi_route(
    _ctx: &RequestContext,
    req: &mut Request,
) -> std::future::Ready<Response> {
    std::future::ready(match trace_from_request(req) {
        Ok(trace) => match identity_from_request(req, &trace)
            .and_then(|identity| enforce_fleet_admin(&identity, &trace).map(|()| identity))
        {
            Ok(identity) => {
                let body = req.take_body().into_bytes();
                if body.len() > MAX_RECONCILE_PAYLOAD_BYTES {
                    return std::future::ready(problem_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "FASTAPI_PAYLOAD_TOO_LARGE",
                        "Payload too large",
                        format!(
                            "fleet reconcile request body is {} bytes; limit is {MAX_RECONCILE_PAYLOAD_BYTES}",
                            body.len()
                        ),
                        &trace.trace_id,
                    ));
                }

                let request = match serde_json::from_slice::<ReconcileRouteRequest>(&body) {
                    Ok(request) => request,
                    Err(err) => {
                        return std::future::ready(problem_response(
                            StatusCode::BAD_REQUEST,
                            "FASTAPI_BAD_REQUEST",
                            "Bad request",
                            format!("invalid fleet reconcile JSON: {err}"),
                            &trace.trace_id,
                        ));
                    }
                };
                if request.request_id.trim().is_empty() {
                    return std::future::ready(problem_response(
                        StatusCode::BAD_REQUEST,
                        "FASTAPI_BAD_REQUEST",
                        "Bad request",
                        "request_id must not be empty",
                        &trace.trace_id,
                    ));
                }

                match handle_reconcile(&identity, &trace) {
                    Ok(body) => Response::json(&body).expect("serialize reconcile response"),
                    Err(err) => api_error_response(err, &trace),
                }
            }
            Err(response) => response,
        },
        Err(response) => response,
    })
}

fn control_plane_app() -> App {
    App::builder()
        .route(
            RECONCILE_ROUTE_PATH,
            Method::Post,
            fleet_reconcile_fastapi_route,
        )
        .build()
}

fn authorized_reconcile_request<'client>(
    client: &'client TestClient<App>,
    body: impl Into<Vec<u8>>,
) -> fastapi_rust::RequestBuilder<'client, App> {
    client
        .post(RECONCILE_ROUTE_PATH)
        .header_str("traceparent", RECONCILE_TRACEPARENT)
        .header_str(CONTROL_PLANE_AUTH_HEADER, TRUSTED_FLEET_ADMIN)
        .header("content-type", b"application/json".to_vec())
        .body(body)
}

fn problem_body(response: &fastapi_rust::TestResponse) -> Value {
    assert_eq!(response.content_type(), Some("application/problem+json"));
    response.json().expect("problem detail json")
}

fn reconcile_body(request_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "request_id": request_id,
    }))
    .expect("serialize reconcile request")
}

#[test]
fn fleet_quarantine_reconcile_serves_through_fastapi_rust_route_handler() {
    let _guard = lock_shared_fleet_state();
    activate_shared_fleet_control_manager_for_tests();

    let client = TestClient::new(control_plane_app());

    let response =
        authorized_reconcile_request(&client, reconcile_body("reconcile-happy-path")).send();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.content_type(), Some("application/json"));

    let body: Value = response.json().expect("json reconcile response");
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["action_type"], "reconcile");
    assert_eq!(body["data"]["event_code"], FLEET_RECONCILE_COMPLETED);
    assert_eq!(body["data"]["trace_id"], RECONCILE_TRACE_ID);
    assert_eq!(body["data"]["success"], true);
    assert_eq!(body["data"]["convergence"]["progress_pct"], 100);
}

#[test]
fn control_plane_fastapi_reconcile_route_rejects_unauthorized_request() {
    let _guard = lock_shared_fleet_state();
    let client = TestClient::new(control_plane_app());
    let response = client
        .post(RECONCILE_ROUTE_PATH)
        .header_str("traceparent", RECONCILE_TRACEPARENT)
        .json(&serde_json::json!({
            "request_id": "missing-auth",
        }))
        .send();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let problem = problem_body(&response);
    assert_eq!(problem["code"], "FASTAPI_AUTH_FAIL");
    assert_eq!(problem["trace_id"], "0123456789abcdef0123456789abcdef");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("mTLS client identity not propagated"))
    );
}

#[test]
fn control_plane_fastapi_reconcile_route_rejects_non_admin_identity() {
    let _guard = lock_shared_fleet_state();
    let client = TestClient::new(control_plane_app());
    let response = client
        .post(RECONCILE_ROUTE_PATH)
        .header_str("traceparent", RECONCILE_TRACEPARENT)
        .header_str(CONTROL_PLANE_AUTH_HEADER, NON_ADMIN_IDENTITY)
        .header("content-type", b"application/json".to_vec())
        .body(reconcile_body("operator-without-fleet-admin-role"))
        .send();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let problem = problem_body(&response);
    assert_eq!(problem["code"], "FASTAPI_POLICY_DENY");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("requires fleet-admin role"))
    );
}

#[test]
fn control_plane_fastapi_reconcile_route_rejects_malformed_payload() {
    let _guard = lock_shared_fleet_state();
    let client = TestClient::new(control_plane_app());
    let response = authorized_reconcile_request(&client, b"{\"request_id\":".to_vec()).send();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = problem_body(&response);
    assert_eq!(problem["code"], "FASTAPI_BAD_REQUEST");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("invalid fleet reconcile JSON"))
    );
}

#[test]
fn control_plane_fastapi_reconcile_route_rejects_missing_fields() {
    let _guard = lock_shared_fleet_state();
    let client = TestClient::new(control_plane_app());
    let response = authorized_reconcile_request(
        &client,
        serde_json::to_vec(&serde_json::json!({})).expect("serialize missing-field request"),
    )
    .send();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = problem_body(&response);
    assert_eq!(problem["code"], "FASTAPI_BAD_REQUEST");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("missing field `request_id`"))
    );
}

#[test]
fn control_plane_fastapi_reconcile_route_rejects_oversized_payload() {
    let _guard = lock_shared_fleet_state();
    let client = TestClient::new(control_plane_app());
    let oversized_request_id = "x".repeat(MAX_RECONCILE_PAYLOAD_BYTES);
    let response =
        authorized_reconcile_request(&client, reconcile_body(&oversized_request_id)).send();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let problem = problem_body(&response);
    assert_eq!(problem["code"], "FASTAPI_PAYLOAD_TOO_LARGE");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("limit is 1024"))
    );
}

#[test]
fn control_plane_fastapi_reconcile_route_rejects_malformed_trace_context() {
    let _guard = lock_shared_fleet_state();
    let client = TestClient::new(control_plane_app());
    let response = client
        .post(RECONCILE_ROUTE_PATH)
        .header_str("traceparent", "not-a-traceparent")
        .header_str(CONTROL_PLANE_AUTH_HEADER, TRUSTED_FLEET_ADMIN)
        .header("content-type", b"application/json".to_vec())
        .body(reconcile_body("malformed-trace"))
        .send();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = problem_body(&response);
    assert_eq!(problem["code"], "FASTAPI_BAD_REQUEST");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("malformed traceparent"))
    );
}

#[test]
fn control_plane_fastapi_reconcile_route_reports_conflict_when_manager_inactive() {
    let _guard = lock_shared_fleet_state();
    let workspace = tempfile::tempdir().expect("reconcile request workspace");
    let request_id = workspace
        .path()
        .join("inactive-manager")
        .display()
        .to_string();
    let client = TestClient::new(control_plane_app());

    let response = authorized_reconcile_request(&client, reconcile_body(&request_id)).send();

    assert_eq!(response.status(), StatusCode::from_u16(409));
    let problem = problem_body(&response);
    assert_eq!(problem["code"], "FASTAPI_CONFLICT");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(FLEET_NOT_ACTIVATED))
    );
}
