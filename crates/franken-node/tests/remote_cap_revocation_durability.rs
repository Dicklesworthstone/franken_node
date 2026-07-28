//! bd-z5k66 path (2): a live revocation must survive an unbounded flood of later
//! revocations.
//!
//! `CapabilityGate` keeps two bounded sets, and they are NOT interchangeable:
//!
//! * the **replay** set remembers consumed single-use tokens. FIFO eviction there
//!   is harmless — dropping the oldest entry only ever permits replaying a token
//!   that expired long ago.
//! * the **revocation** set remembers capabilities the operator has withdrawn.
//!   Dropping an entry there turns a revoked capability back into a valid one.
//!
//! The revocation set used to share the replay set's FIFO eviction at 4096
//! entries. That gave an attacker a pure-volume bypass: revoke capability `C`
//! while it is still well inside its TTL, then cause 4096 further revocations,
//! and `C` falls out the front — after which `authorize_network(Some(&C))`
//! returns `Ok` again. `security::network_guard` already refuses to evict egress
//! deny rules for exactly this reason.
//!
//! These tests pin the fixed contract through the public API only, so they run in
//! the default `cargo test` lane rather than the inline-`#[cfg(test)]` lane.

use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteCap, RemoteCapError, RemoteOperation, RemoteScope,
};

const SHARED_SECRET: &str = "remote-cap-revocation-durability-secret";
const ISSUER: &str = "ops@example";
const BASE_TIME: u64 = 1_700_100_000;
const ENDPOINT_PREFIX: &str = "https://control.example.com/v1";
const ENDPOINT: &str = "https://control.example.com/v1/sync";

/// Comfortably past the module's internal revocation bound (4096) so the flood
/// would certainly have evicted the victim under the old FIFO behavior.
const FLOOD_SIZE: usize = 4_200;

/// Long enough that nothing under test expires on its own during the flood; the
/// point is that eviction pressure — not expiry — used to release the victim.
const LONG_TTL_SECS: u64 = 86_400;

fn provider() -> CapabilityProvider {
    CapabilityProvider::new(SHARED_SECRET).expect("provider")
}

fn issue(provider: &CapabilityProvider, trace_id: &str, ttl_secs: u64) -> RemoteCap {
    provider
        .issue(
            ISSUER,
            RemoteScope::new(
                vec![RemoteOperation::FederationSync],
                vec![ENDPOINT_PREFIX.to_string()],
            ),
            BASE_TIME,
            ttl_secs,
            true,
            false,
            trace_id,
        )
        .expect("issue capability")
        .0
}

fn authorize(
    gate: &mut CapabilityGate,
    cap: &RemoteCap,
    now_epoch_secs: u64,
    trace_id: &str,
) -> Result<(), RemoteCapError> {
    gate.authorize_network(
        Some(cap),
        RemoteOperation::FederationSync,
        ENDPOINT,
        now_epoch_secs,
        trace_id,
    )
}

#[test]
fn revocation_survives_a_flood_of_later_revocations() {
    let provider = provider();
    let mut gate = CapabilityGate::new(SHARED_SECRET).expect("gate");

    let victim = issue(&provider, "trace-victim", LONG_TTL_SECS);

    // Baseline: the capability is usable before revocation.
    authorize(&mut gate, &victim, BASE_TIME + 10, "trace-baseline")
        .expect("capability must authorize before it is revoked");

    let revoked = gate.revoke(&victim, BASE_TIME + 20, "trace-revoke-victim");
    assert_eq!(revoked.event_code, "REMOTECAP_REVOKED");
    assert!(revoked.allowed, "the victim's revocation must be recorded");

    // Flood the gate with further live revocations, past the old FIFO bound.
    for index in 0..FLOOD_SIZE {
        let filler = issue(&provider, &format!("trace-filler-{index:05}"), LONG_TTL_SECS);
        gate.revoke(&filler, BASE_TIME + 30, &format!("trace-revoke-{index:05}"));
    }

    // The victim is still inside its TTL, so revocation is the only thing that
    // can deny it — and it must still deny it.
    let err = authorize(&mut gate, &victim, BASE_TIME + 40, "trace-post-flood")
        .expect_err("a live revocation must not be laundered away by later revocations");

    assert_eq!(
        err,
        RemoteCapError::Revoked {
            token_id: victim.token_id().to_string(),
        }
    );
    assert_eq!(err.code(), "REMOTECAP_REVOKED");
}

#[test]
fn overflowing_the_revocation_store_refuses_loudly_instead_of_evicting() {
    // Bounded storage plus "never launder a live revocation" together imply that
    // a full store must refuse the newest request. The refusal has to be visible
    // in the audit log, because a capability the operator believes is revoked
    // will otherwise still authorize.
    let provider = provider();
    let mut gate = CapabilityGate::new(SHARED_SECRET).expect("gate");

    let first = issue(&provider, "trace-first-revocation", LONG_TTL_SECS);
    gate.revoke(&first, BASE_TIME + 20, "trace-revoke-first");

    let mut refusals = 0usize;
    for index in 0..FLOOD_SIZE {
        let filler = issue(&provider, &format!("trace-fill-{index:05}"), LONG_TTL_SECS);
        let event = gate.revoke(&filler, BASE_TIME + 30, &format!("trace-fill-rev-{index:05}"));
        if event.event_code == "REMOTECAP_REVOKE_REFUSED" {
            refusals = refusals.saturating_add(1);
            assert!(!event.allowed);
            assert_eq!(
                event.denial_code.as_deref(),
                Some("REMOTECAP_REVOCATION_CAPACITY")
            );
        }
    }

    assert!(
        refusals > 0,
        "flooding past the bound must surface refusals rather than silently evicting"
    );

    // The very first revocation — the one an eviction policy would have dropped
    // first — is still enforced.
    let err = authorize(&mut gate, &first, BASE_TIME + 40, "trace-first-recheck")
        .expect_err("the oldest revocation must still be enforced");
    assert_eq!(err.code(), "REMOTECAP_REVOKED");
}

#[test]
fn revocation_records_retire_only_after_their_capability_expires() {
    // A revocation record exists to stop a capability that would otherwise still
    // be valid. Once the capability has expired on its own terms the gate denies
    // it as `Expired` regardless, so retiring the record then is safe — and is
    // what keeps the store's bound meaningful without ever laundering anything.
    let provider = provider();
    let mut gate = CapabilityGate::new(SHARED_SECRET).expect("gate");

    let short_ttl = 60u64;
    let cap = issue(&provider, "trace-short-lived", short_ttl);
    gate.revoke(&cap, BASE_TIME + 1, "trace-revoke-short-lived");

    // Inside the TTL: denied as revoked.
    let err = authorize(&mut gate, &cap, BASE_TIME + 30, "trace-inside-ttl")
        .expect_err("revoked capability must be denied inside its TTL");
    assert_eq!(err.code(), "REMOTECAP_REVOKED");

    // Past the TTL: still denied, now on expiry grounds. This is the property
    // that makes retiring the record safe.
    let err = authorize(
        &mut gate,
        &cap,
        BASE_TIME + short_ttl + 1,
        "trace-outside-ttl",
    )
    .expect_err("expired capability must be denied regardless of revocation state");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
}
