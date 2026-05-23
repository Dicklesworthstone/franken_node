use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteCap, RemoteCapError, RemoteOperation, RemoteScope,
};

const MAC_MATERIAL: &str = "r110-remote-cap-scope-tightening-material";
const ISSUE_TIME: u64 = 1_777_200_000;
const USE_TIME: u64 = 1_777_200_030;
const ISSUER: &str = "ops-scope-tightening";
const SCOPE_PREFIX: &str = "https://api.example.com/root";

type TestResult<T = ()> = Result<T, String>;

fn issue_single_use_cap() -> TestResult<RemoteCap> {
    let provider = CapabilityProvider::new(MAC_MATERIAL)
        .map_err(|err| format!("provider creation failed: {err}"))?;
    let scope = RemoteScope::new(
        vec![RemoteOperation::NetworkEgress],
        vec![SCOPE_PREFIX.to_string()],
    );
    let (cap, _event) = provider
        .issue(
            ISSUER,
            scope,
            ISSUE_TIME,
            300,
            true,
            true,
            "trace-r110-scope-tightening-issue",
        )
        .map_err(|err| format!("capability issuance failed: {err}"))?;
    Ok(cap)
}

fn expect_scope_denial(
    gate: &mut CapabilityGate,
    cap: &RemoteCap,
    endpoint: &str,
    trace_id: &str,
) -> TestResult {
    match gate.authorize_network(
        Some(cap),
        RemoteOperation::NetworkEgress,
        endpoint,
        USE_TIME,
        trace_id,
    ) {
        Err(RemoteCapError::ScopeDenied {
            endpoint: denied, ..
        }) if denied == endpoint => Ok(()),
        Err(err) => Err(format!(
            "expected REMOTECAP_SCOPE_DENIED for {endpoint}, got {}",
            err.code()
        )),
        Ok(()) => Err(format!("endpoint {endpoint} escaped scope tightening")),
    }
}

#[test]
fn scope_denials_do_not_consume_single_use_capability() -> TestResult {
    let cap = issue_single_use_cap()?;
    let mut gate =
        CapabilityGate::new(MAC_MATERIAL).map_err(|err| format!("gate creation failed: {err}"))?;

    for (endpoint, trace_id) in [
        (
            "https://api.example.com/rooted",
            "trace-r110-scope-denied-rooted-prefix",
        ),
        (
            "https://api.example.com.evil/root",
            "trace-r110-scope-denied-host-confusion",
        ),
        (
            "https://api.example.com/root/../admin",
            "trace-r110-scope-denied-path-traversal",
        ),
    ] {
        expect_scope_denial(&mut gate, &cap, endpoint, trace_id)?;
    }

    gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        "https://api.example.com/root/allowed",
        USE_TIME.saturating_add(1),
        "trace-r110-scope-allowed-after-denials",
    )
    .map_err(|err| format!("valid scoped endpoint should remain usable: {err}"))?;

    match gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        "https://api.example.com/root/allowed",
        USE_TIME.saturating_add(2),
        "trace-r110-scope-replay-after-consume",
    ) {
        Err(RemoteCapError::ReplayDetected { .. }) => {}
        Err(err) => {
            return Err(format!(
                "expected consumed token to report REMOTECAP_REPLAY, got {}",
                err.code()
            ));
        }
        Ok(()) => return Err("consumed single-use token was accepted twice".to_string()),
    }

    let denial_count = gate
        .audit_log()
        .iter()
        .filter(|event| matches!(event.denial_code.as_deref(), Some("REMOTECAP_SCOPE_DENIED")))
        .count();
    if denial_count != 3 {
        return Err(format!(
            "expected three scope denials before consumption, saw {denial_count}"
        ));
    }
    let consumed_count = gate
        .audit_log()
        .iter()
        .filter(|event| matches!(event.event_code.as_str(), "REMOTECAP_CONSUMED"))
        .count();
    if consumed_count != 1 {
        return Err(format!(
            "expected exactly one successful single-use consumption, saw {consumed_count}"
        ));
    }

    Ok(())
}
