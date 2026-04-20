use std::sync::{Mutex, MutexGuard, OnceLock};

use fastapi_rust::{App, Method, Request, RequestContext, Response, StatusCode, TestClient};
use frankenengine_node::api::fleet_quarantine::{
    FLEET_RECONCILE_COMPLETED, activate_shared_fleet_control_manager_for_tests, handle_reconcile,
    reset_shared_fleet_control_manager_for_tests,
};
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};
use serde_json::Value;

const RECONCILE_TRACE_ID: &str = "fastapi-rust-reconcile-trace";
const RECONCILE_ROUTE_PATH: &str = "/v1/fleet/reconcile";

fn lock_shared_fleet_state() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("fastapi fleet quarantine integration lock");
    reset_shared_fleet_control_manager_for_tests();
    guard
}

fn fleet_admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "mtls:fastapi-rust-fleet-admin".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn reconcile_trace() -> TraceContext {
    TraceContext {
        trace_id: RECONCILE_TRACE_ID.to_string(),
        span_id: "00000000000000fa".to_string(),
        trace_flags: 1,
    }
}

fn fleet_reconcile_fastapi_route(
    _ctx: &RequestContext,
    _req: &mut Request,
) -> std::future::Ready<Response> {
    std::future::ready(
        match handle_reconcile(&fleet_admin_identity(), &reconcile_trace()) {
            Ok(body) => Response::json(&body).expect("serialize reconcile response"),
            Err(err) => Response::with_status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", b"application/json".to_vec())
                .body(fastapi_rust::ResponseBody::Bytes(
                    serde_json::to_vec(&serde_json::json!({
                        "ok": false,
                        "error": format!("{err:?}"),
                    }))
                    .expect("serialize error response"),
                )),
        },
    )
}

#[test]
fn fleet_quarantine_reconcile_serves_through_fastapi_rust_route_handler() {
    let _guard = lock_shared_fleet_state();
    activate_shared_fleet_control_manager_for_tests();

    let app = App::builder()
        .route(
            RECONCILE_ROUTE_PATH,
            Method::Post,
            fleet_reconcile_fastapi_route,
        )
        .build();
    let client = TestClient::new(app);

    let response = client.post(RECONCILE_ROUTE_PATH).send();

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
