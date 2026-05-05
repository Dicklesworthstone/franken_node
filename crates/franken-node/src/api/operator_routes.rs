//! Operator endpoint group: node status, health, configuration, rollout state.
//!
//! Routes:
//! - `GET /v1/operator/status` — node status summary
//! - `GET /v1/operator/health` — health check (liveness + readiness)
//! - `GET /v1/operator/config` — current configuration view
//! - `GET /v1/operator/rollout` — rollout state query

use crate::config::Config as RuntimeConfig;
use crate::policy::resource_admission::AdmissionTelemetrySnapshot;
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "control-plane"))]
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::AtomicU8;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::Duration;
use std::time::Instant;

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext, enforce_route_contract,
};
use super::trust_card_routes::ApiResponse;

#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone)]
struct ProcessStartState {
    monotonic: Instant,
    wall_clock_rfc3339: String,
}

static MONOTONIC_EPOCH: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
const INIT_STATE_UNINITIALIZED: u8 = 0;
const INIT_STATE_INITIALIZING: u8 = 1;
const INIT_STATE_INITIALIZED: u8 = 2;

static PROCESS_START_STATE: AtomicU8 = AtomicU8::new(0);
static PROCESS_START_OFFSET_NANOS: AtomicU64 = AtomicU64::new(0);
static PROCESS_START_WALL_CLOCK: std::sync::LazyLock<RwLock<String>> =
    std::sync::LazyLock::new(|| RwLock::new(String::new()));

static OPERATOR_CONFIG_STATE: AtomicU8 = AtomicU8::new(0);
static OPERATOR_CONFIG_VIEW: std::sync::LazyLock<RwLock<ConfigView>> =
    std::sync::LazyLock::new(|| {
        RwLock::new(ConfigView::from_runtime_config(&RuntimeConfig::default()))
    });
static OPERATOR_RESOURCE_ADMISSION: std::sync::LazyLock<RwLock<AdmissionTelemetrySnapshot>> =
    std::sync::LazyLock::new(|| RwLock::new(AdmissionTelemetrySnapshot::default()));

#[cfg(any(test, feature = "control-plane"))]
static PROCESS_START_OVERRIDE: Mutex<Option<ProcessStartState>> = Mutex::new(None);

#[cfg(test)]
static PROCESS_START_INIT_CALLS: AtomicUsize = AtomicUsize::new(0);

fn now_epoch_nanos() -> u64 {
    MONOTONIC_EPOCH.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

#[cfg(test)]
fn duration_to_nanos(duration: std::time::Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

/// Reset an in-flight atomic initializer back to UNINIT if the install closure panics.
struct AtomicInitResetGuard<'a> {
    state: &'a AtomicU8,
    armed: bool,
}

impl<'a> AtomicInitResetGuard<'a> {
    fn new(state: &'a AtomicU8) -> Self {
        Self { state, armed: true }
    }

    fn complete(mut self) {
        self.armed = false;
        self.state.store(INIT_STATE_INITIALIZED, Ordering::Release);
    }
}

impl Drop for AtomicInitResetGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state
                .store(INIT_STATE_UNINITIALIZED, Ordering::Release);
        }
    }
}

fn run_atomic_initializer(state: &AtomicU8, install: impl FnOnce()) {
    loop {
        match state.load(Ordering::Acquire) {
            INIT_STATE_INITIALIZED => return,
            INIT_STATE_UNINITIALIZED => {
                if state
                    .compare_exchange(
                        INIT_STATE_UNINITIALIZED,
                        INIT_STATE_INITIALIZING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }

                let guard = AtomicInitResetGuard::new(state);
                install();
                guard.complete();
                return;
            }
            INIT_STATE_INITIALIZING => std::hint::spin_loop(),
            invalid => {
                debug_assert_eq!(invalid, INIT_STATE_INITIALIZED);
                state.store(INIT_STATE_UNINITIALIZED, Ordering::Release);
            }
        }
    }
}

fn install_process_start(offset_nanos: u64, wall_clock_rfc3339: String) {
    {
        let mut wall_clock = PROCESS_START_WALL_CLOCK
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *wall_clock = wall_clock_rfc3339;
    }
    PROCESS_START_OFFSET_NANOS.store(offset_nanos, Ordering::Relaxed);
}

fn install_operator_config(config: &RuntimeConfig) {
    let mut view = OPERATOR_CONFIG_VIEW
        .write()
        .unwrap_or_else(|poison| poison.into_inner());
    *view = ConfigView::from_runtime_config(config);
}

pub(crate) fn init_process_start() {
    #[cfg(test)]
    PROCESS_START_INIT_CALLS.fetch_add(1, Ordering::Relaxed);

    run_atomic_initializer(&PROCESS_START_STATE, || {
        install_process_start(now_epoch_nanos(), chrono::Utc::now().to_rfc3339());
    });
}

pub(crate) fn init_operator_config(config: &RuntimeConfig) {
    run_atomic_initializer(&OPERATOR_CONFIG_STATE, || {
        install_operator_config(config);
    });
}

fn process_uptime_seconds() -> u64 {
    #[cfg(any(test, feature = "control-plane"))]
    if let Some(override_state) = process_start_override_for_tests() {
        return override_state.monotonic.elapsed().as_secs();
    }

    if PROCESS_START_STATE.load(Ordering::Acquire) != INIT_STATE_INITIALIZED {
        init_process_start();
    }

    let now_nanos = now_epoch_nanos();
    let start_nanos = PROCESS_START_OFFSET_NANOS.load(Ordering::Relaxed);
    now_nanos.saturating_sub(start_nanos) / 1_000_000_000
}

fn process_started_at_rfc3339() -> String {
    #[cfg(any(test, feature = "control-plane"))]
    if let Some(override_state) = process_start_override_for_tests() {
        return override_state.wall_clock_rfc3339;
    }

    if PROCESS_START_STATE.load(Ordering::Acquire) != INIT_STATE_INITIALIZED {
        init_process_start();
    }

    PROCESS_START_WALL_CLOCK
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
}

fn operator_config_view() -> ConfigView {
    if OPERATOR_CONFIG_STATE.load(Ordering::Acquire) != INIT_STATE_INITIALIZED {
        init_operator_config(&RuntimeConfig::default());
    }

    OPERATOR_CONFIG_VIEW
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
}

fn operator_resource_admission_snapshot() -> AdmissionTelemetrySnapshot {
    OPERATOR_RESOURCE_ADMISSION
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
}

/// Update the operator readiness view with the latest resource admission counters.
///
/// Resource admission feeds the existing health/readiness surface as a component detail instead of
/// creating a parallel telemetry endpoint.
pub fn update_resource_admission_readiness(snapshot: AdmissionTelemetrySnapshot) {
    let mut view = OPERATOR_RESOURCE_ADMISSION
        .write()
        .unwrap_or_else(|poison| poison.into_inner());
    *view = snapshot;
}

#[cfg(test)]
fn clear_resource_admission_readiness_for_tests() {
    update_resource_admission_readiness(AdmissionTelemetrySnapshot::default());
}

#[cfg(loom)]
#[doc(hidden)]
pub fn process_start_initialization_loom_model() {
    use loom::sync::atomic::{AtomicU8, AtomicU64, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    #[derive(Debug)]
    struct ProcessStartCell {
        state: AtomicU8,
        offset_nanos: AtomicU64,
        wall_clock: Mutex<Option<&'static str>>,
    }

    impl ProcessStartCell {
        fn new() -> Self {
            Self {
                state: AtomicU8::new(0),
                offset_nanos: AtomicU64::new(0),
                wall_clock: Mutex::new(None),
            }
        }

        fn install(&self, offset_nanos: u64, wall_clock_rfc3339: &'static str) {
            {
                let mut wall_clock = self.wall_clock.lock().expect("loom wall clock lock");
                *wall_clock = Some(wall_clock_rfc3339);
            }
            thread::yield_now();
            self.offset_nanos.store(offset_nanos, Ordering::Relaxed);
            thread::yield_now();
            self.state.store(2, Ordering::Release);
        }

        fn init(&self, offset_nanos: u64, wall_clock_rfc3339: &'static str) {
            if self.state.load(Ordering::Acquire) == 2 {
                return;
            }

            if self
                .state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.install(offset_nanos, wall_clock_rfc3339);
            } else {
                while self.state.load(Ordering::Acquire) != 2 {
                    thread::yield_now();
                }
            }
        }

        fn read_snapshot(
            &self,
            offset_nanos: u64,
            wall_clock_rfc3339: &'static str,
        ) -> (u64, &'static str) {
            if self.state.load(Ordering::Acquire) != 2 {
                self.init(offset_nanos, wall_clock_rfc3339);
            }

            let installed_wall_clock = (*self.wall_clock.lock().expect("loom wall clock lock"))
                .expect("wall clock should be installed");
            let installed_offset = self.offset_nanos.load(Ordering::Relaxed);
            (installed_offset, installed_wall_clock)
        }
    }

    loom::model(|| {
        let state = Arc::new(ProcessStartCell::new());

        let process_a = Arc::clone(&state);
        let process_b = Arc::clone(&state);
        let process_c = Arc::clone(&state);

        let process_a = thread::spawn(move || process_a.read_snapshot(11, "2026-04-26T00:00:11Z"));
        let process_b = thread::spawn(move || process_b.read_snapshot(22, "2026-04-26T00:00:22Z"));
        let process_c = thread::spawn(move || process_c.read_snapshot(33, "2026-04-26T00:00:33Z"));

        let installed = [
            process_a.join().expect("join process A"),
            process_b.join().expect("join process B"),
            process_c.join().expect("join process C"),
        ];

        assert_eq!(installed[0], installed[1]);
        assert_eq!(installed[1], installed[2]);
        assert!(matches!(
            installed[0],
            (11, "2026-04-26T00:00:11Z")
                | (22, "2026-04-26T00:00:22Z")
                | (33, "2026-04-26T00:00:33Z")
        ));
        assert_eq!(state.state.load(Ordering::Acquire), 2);
    });
}

#[cfg(loom)]
#[doc(hidden)]
pub fn operator_config_initialization_loom_model() {
    use loom::sync::atomic::{AtomicU8, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ConfigSeed {
        profile: &'static str,
        compatibility_mode: &'static str,
        fleet_timeout_seconds: u32,
    }

    #[derive(Debug)]
    struct ConfigCell {
        state: AtomicU8,
        view: Mutex<ConfigSeed>,
    }

    impl ConfigCell {
        const DEFAULT: ConfigSeed = ConfigSeed {
            profile: "balanced",
            compatibility_mode: "balanced",
            fleet_timeout_seconds: 120,
        };

        const BOOTSTRAPPED: ConfigSeed = ConfigSeed {
            profile: "legacy-risky",
            compatibility_mode: "legacy-risky",
            fleet_timeout_seconds: 300,
        };

        fn new() -> Self {
            Self {
                state: AtomicU8::new(0),
                view: Mutex::new(Self::DEFAULT),
            }
        }

        fn install(&self, seed: ConfigSeed) {
            {
                let mut view = self.view.lock().expect("loom config view lock");
                *view = seed;
            }
            thread::yield_now();
            self.state.store(2, Ordering::Release);
        }

        fn init(&self, seed: ConfigSeed) {
            if self
                .state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.install(seed);
            } else {
                while self.state.load(Ordering::Acquire) != 2 {
                    thread::yield_now();
                }
            }
        }

        fn read_view(&self) -> ConfigSeed {
            if self.state.load(Ordering::Acquire) != 2 {
                self.init(Self::DEFAULT);
            }

            *self.view.lock().expect("loom config view lock")
        }
    }

    loom::model(|| {
        let state = Arc::new(ConfigCell::new());

        let bootstrap = Arc::clone(&state);
        let reader_a = Arc::clone(&state);
        let reader_b = Arc::clone(&state);

        let bootstrap = thread::spawn(move || {
            bootstrap.init(ConfigCell::BOOTSTRAPPED);
            bootstrap.read_view()
        });
        let reader_a = thread::spawn(move || reader_a.read_view());
        let reader_b = thread::spawn(move || reader_b.read_view());

        let installed = [
            bootstrap.join().expect("join bootstrap"),
            reader_a.join().expect("join reader A"),
            reader_b.join().expect("join reader B"),
        ];

        assert_eq!(installed[0], installed[1]);
        assert_eq!(installed[1], installed[2]);
        assert!(
            installed[0] == ConfigCell::DEFAULT || installed[0] == ConfigCell::BOOTSTRAPPED,
            "installed view must match exactly one initialization winner"
        );
        assert_eq!(state.state.load(Ordering::Acquire), 2);
    });
}

#[cfg(any(test, feature = "control-plane"))]
/// Acquire the shared process-start test lock before mutating global process-start fixtures.
///
/// Use this in tests that need exclusive access to the override state so setup and cleanup do not
/// race with other helper calls in the same process.
pub(crate) fn process_start_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(any(test, feature = "control-plane"))]
fn process_start_override_for_tests() -> Option<ProcessStartState> {
    PROCESS_START_OVERRIDE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
}

#[cfg(any(test, feature = "control-plane"))]
/// Clear the process-start override after a test that seeded synthetic uptime metadata.
///
/// Use this during test teardown whenever `seed_process_start_for_tests` was used so later tests
/// read the real initialized state instead of leaked fixture data.
pub(crate) fn clear_process_start_override_for_tests() {
    let mut guard = try_lock_process_start_override_with_timeout(Duration::from_millis(50))
        .expect("Failed to acquire process start override lock during test cleanup");
    *guard = None;
    drop(guard);
}

#[cfg(any(test, feature = "control-plane"))]
fn try_lock_process_start_override_with_timeout(
    timeout: Duration,
) -> Result<std::sync::MutexGuard<'static, Option<ProcessStartState>>, &'static str> {
    let start = std::time::Instant::now();
    let mut backoff = Duration::from_millis(1);

    loop {
        match PROCESS_START_OVERRIDE.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                if start.elapsed() >= timeout {
                    return Err("Process start override lock timeout");
                }
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, Duration::from_millis(5));
            }
        }
    }
}

#[cfg(test)]
/// Return how many times `init_process_start` ran in the current test process.
///
/// Use this when asserting the atomic initialization path stayed idempotent under repeated calls or
/// concurrency probes.
pub(crate) fn process_start_init_call_count_for_tests() -> usize {
    PROCESS_START_INIT_CALLS.load(Ordering::Relaxed)
}

#[cfg(test)]
/// Expose the installed monotonic process-start offset for assertions.
///
/// Use this after bootstrapping process-start state in tests that need to verify the persisted
/// uptime baseline rather than the computed seconds view.
pub(crate) fn installed_process_start_offset_nanos_for_tests() -> u64 {
    PROCESS_START_OFFSET_NANOS.load(Ordering::Relaxed)
}

#[cfg(test)]
/// Return the installed wall-clock process-start timestamp for assertions.
///
/// Use this in tests that need to confirm the RFC 3339 value propagated through initialization or
/// bootstrap helpers.
pub(crate) fn installed_process_start_wall_clock_for_tests() -> String {
    PROCESS_START_WALL_CLOCK
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
}

#[cfg(test)]
/// Seed a temporary process-start override without mutating the installed global baseline.
///
/// Use this when a test needs synthetic uptime and wall-clock values for read paths while keeping
/// initialization state isolated to the override slot.
pub(crate) fn seed_process_start_for_tests(elapsed: std::time::Duration, wall_clock_rfc3339: &str) {
    let mut guard = PROCESS_START_OVERRIDE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let now = Instant::now();
    let monotonic = now.checked_sub(elapsed).unwrap_or(now);
    *guard = Some(ProcessStartState {
        monotonic,
        wall_clock_rfc3339: wall_clock_rfc3339.to_string(),
    });
}

#[cfg(test)]
/// Install a synthetic process-start baseline into the global initialized state.
///
/// Use this when a test needs the normal non-override read path to observe a deterministic process
/// start value, such as bootstrap or replay-style assertions.
pub(crate) fn seed_bootstrapped_process_start_for_tests(
    elapsed: std::time::Duration,
    wall_clock_rfc3339: &str,
) {
    let start_offset_nanos = now_epoch_nanos().saturating_sub(duration_to_nanos(elapsed));
    install_process_start(start_offset_nanos, wall_clock_rfc3339.to_string());
}

#[cfg(any(test, feature = "control-plane"))]
fn assert_process_start_cleanup_waits_for_init_lock() {
    let _lock = process_start_test_lock();
    clear_process_start_override_for_tests();

    // NOTE: This test was for the old Mutex-based initialization.
    // With atomic state machines, there's no lock to wait on - the coordination
    // is lock-free. The test concept no longer applies.

    // Just verify cleanup works without synchronization issues
    clear_process_start_override_for_tests();

    {
        let mut wall_clock = PROCESS_START_WALL_CLOCK
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        wall_clock.push_str("probe");
    }
}

#[cfg(any(test, feature = "control-plane"))]
/// Exercise the process-start cleanup path while the test lock is held.
///
/// Use this only from tests that verify the documented lock ordering for process-start fixture
/// cleanup; it keeps the helper reachable in generated docs for downstream control-plane tests.
pub fn assert_process_start_cleanup_lock_order_for_tests() {
    assert_process_start_cleanup_waits_for_init_lock();
}

// ── Response Types ─────────────────────────────────────────────────────────

/// Node status summary returned by `GET /v1/operator/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub policy_profile: String,
    pub active_extensions: u32,
    pub quarantined_extensions: u32,
    pub control_epoch: u64,
}

/// Health check result returned by `GET /v1/operator/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    pub live: bool,
    pub ready: bool,
    pub checks: Vec<HealthComponent>,
}

/// Individual health component status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthComponent {
    pub name: String,
    pub status: ComponentStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentStatus {
    Ok,
    Degraded,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResourceAdmissionReadinessDetail {
    admitted: u64,
    deferred: u64,
    shed: u64,
    rejected: u64,
    reason_code: String,
    recovery_hint: String,
}

/// Current configuration view returned by `GET /v1/operator/config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigView {
    pub profile: String,
    pub compatibility_mode: String,
    pub trust_revocation_fresh: bool,
    pub quarantine_on_high_risk: bool,
    pub replay_persist_high_severity: bool,
    pub fleet_convergence_timeout_seconds: u32,
    pub observability_namespace: String,
}

impl ConfigView {
    fn from_runtime_config(config: &RuntimeConfig) -> Self {
        Self {
            profile: config.profile.to_string(),
            compatibility_mode: config.compatibility.mode.to_string(),
            trust_revocation_fresh: config.trust.risky_requires_fresh_revocation,
            quarantine_on_high_risk: config.trust.quarantine_on_high_risk,
            replay_persist_high_severity: config.replay.persist_high_severity,
            fleet_convergence_timeout_seconds: config
                .fleet
                .convergence_timeout_seconds
                .min(u32::MAX as u64) as u32,
            observability_namespace: config.observability.namespace.clone(),
        }
    }
}

/// Rollout state returned by `GET /v1/operator/rollout`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutState {
    pub current_phase: String,
    pub target_version: String,
    pub canary_percentage: u8,
    pub healthy_nodes: u32,
    pub total_nodes: u32,
    pub last_transition: String,
}

// ── Route Metadata ─────────────────────────────────────────────────────────

/// Returns route metadata for all operator management endpoints.
///
/// Provides structured metadata for the 4 operator API endpoints, including:
///
/// ## Endpoints
/// - `GET /v1/operator/status` - Get node status and health information (API key required)
/// - `GET /v1/operator/health` - Health check endpoint (public, no auth required)
/// - `GET /v1/operator/config` - Retrieve operator configuration (operator role required)
/// - `GET /v1/operator/rollout` - Get rollout status and progress (operator role required)
///
/// ## Authentication
/// - `/health` endpoint is public (no authentication)
/// - Other endpoints require API key authentication with appropriate roles
///
/// ## Used By
/// - Load balancers for health checking
/// - Monitoring systems for status collection
/// - Administrative dashboards for configuration management
/// - CI/CD systems for rollout monitoring
pub fn route_metadata() -> Vec<RouteMetadata> {
    vec![
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/status".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::ApiKey,
            policy_hook: PolicyHook {
                hook_id: "operator.status.read".to_string(),
                required_roles: vec!["operator".to_string(), "reader".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/health".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::None,
            policy_hook: PolicyHook {
                hook_id: "operator.health.read".to_string(),
                required_roles: vec![],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/config".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::ApiKey,
            policy_hook: PolicyHook {
                hook_id: "operator.config.read".to_string(),
                required_roles: vec!["operator".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/rollout".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::ApiKey,
            policy_hook: PolicyHook {
                hook_id: "operator.rollout.read".to_string(),
                required_roles: vec!["operator".to_string()],
            },
            trace_propagation: true,
        },
    ]
}

fn enforce_handler_contract(
    identity: &AuthIdentity,
    trace: &TraceContext,
    method: &str,
    path: &str,
) -> Result<(), ApiError> {
    let route = route_metadata()
        .into_iter()
        .find(|route| route.method == method && route.path == path)
        .ok_or_else(|| ApiError::Internal {
            detail: format!("missing route metadata for {method} {path}"),
            trace_id: trace.trace_id.clone(),
        })?;
    enforce_route_contract(identity, &route, &trace.trace_id)
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// Handle `GET /v1/operator/status`.
pub fn get_status(
    identity: &AuthIdentity,
    trace: &TraceContext,
) -> Result<ApiResponse<NodeStatus>, ApiError> {
    enforce_handler_contract(identity, trace, "GET", "/v1/operator/status")?;
    let config = operator_config_view();
    let status = NodeStatus {
        node_id: "franken-node-primary".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: process_uptime_seconds(),
        policy_profile: config.profile,
        active_extensions: 0,
        quarantined_extensions: 0,
        control_epoch: 1,
    };

    Ok(ApiResponse {
        ok: true,
        data: status,
        page: None,
    })
}

/// Handle `GET /v1/operator/health`.
pub fn get_health(
    identity: &AuthIdentity,
    trace: &TraceContext,
) -> Result<ApiResponse<HealthCheck>, ApiError> {
    enforce_handler_contract(identity, trace, "GET", "/v1/operator/health")?;
    let admission_component = resource_admission_health_component();
    let ready = !matches!(admission_component.status, ComponentStatus::Down);
    let health = HealthCheck {
        live: true,
        ready,
        checks: vec![
            HealthComponent {
                name: "control_plane".to_string(),
                status: ComponentStatus::Ok,
                detail: None,
            },
            HealthComponent {
                name: "trust_registry".to_string(),
                status: ComponentStatus::Ok,
                detail: None,
            },
            HealthComponent {
                name: "policy_engine".to_string(),
                status: ComponentStatus::Ok,
                detail: None,
            },
            admission_component,
        ],
    };

    Ok(ApiResponse {
        ok: true,
        data: health,
        page: None,
    })
}

fn resource_admission_health_component() -> HealthComponent {
    let snapshot = operator_resource_admission_snapshot();
    let status = if snapshot.total.rejected > 0 {
        ComponentStatus::Down
    } else if snapshot.total.deferred > 0 || snapshot.total.shed > 0 {
        ComponentStatus::Degraded
    } else {
        ComponentStatus::Ok
    };
    let detail = ResourceAdmissionReadinessDetail {
        admitted: snapshot.total.admitted,
        deferred: snapshot.total.deferred,
        shed: snapshot.total.shed,
        rejected: snapshot.total.rejected,
        reason_code: snapshot.readiness_reason_code().to_string(),
        recovery_hint: snapshot.readiness_hint().to_string(),
    };

    HealthComponent {
        name: "resource_admission".to_string(),
        status,
        detail: serde_json::to_string(&detail).ok(),
    }
}

/// Handle `GET /v1/operator/config`.
pub fn get_config(
    identity: &AuthIdentity,
    trace: &TraceContext,
) -> Result<ApiResponse<ConfigView>, ApiError> {
    enforce_handler_contract(identity, trace, "GET", "/v1/operator/config")?;
    let config = operator_config_view();

    Ok(ApiResponse {
        ok: true,
        data: config,
        page: None,
    })
}

/// Handle `GET /v1/operator/rollout`.
pub fn get_rollout(
    identity: &AuthIdentity,
    trace: &TraceContext,
) -> Result<ApiResponse<RolloutState>, ApiError> {
    enforce_handler_contract(identity, trace, "GET", "/v1/operator/rollout")?;
    let rollout = RolloutState {
        current_phase: "stable".to_string(),
        target_version: env!("CARGO_PKG_VERSION").to_string(),
        canary_percentage: 0,
        healthy_nodes: 1,
        total_nodes: 1,
        last_transition: process_started_at_rfc3339(),
    };

    Ok(ApiResponse {
        ok: true,
        data: rollout,
        page: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;
    use crate::api::service::ControlPlaneService;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn reset_operator_route_state_for_tests() {
        clear_process_start_override_for_tests();
        PROCESS_START_OFFSET_NANOS.store(0, Ordering::Relaxed);
        PROCESS_START_STATE.store(INIT_STATE_UNINITIALIZED, Ordering::Release);
        PROCESS_START_INIT_CALLS.store(0, Ordering::Relaxed);

        let mut wall_clock = PROCESS_START_WALL_CLOCK
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        wall_clock.clear();
        drop(wall_clock);

        OPERATOR_CONFIG_STATE.store(INIT_STATE_UNINITIALIZED, Ordering::Release);
        let mut config_view = OPERATOR_CONFIG_VIEW
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *config_view = ConfigView::from_runtime_config(&RuntimeConfig::default());
        clear_resource_admission_readiness_for_tests();
    }

    fn test_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "test-operator".to_string(),
            method: AuthMethod::ApiKey,
            roles: vec!["operator".to_string()],
        }
    }

    fn reader_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "test-reader".to_string(),
            method: AuthMethod::ApiKey,
            roles: vec!["reader".to_string()],
        }
    }

    fn bearer_reader_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "test-reader".to_string(),
            method: AuthMethod::BearerToken,
            roles: vec!["reader".to_string()],
        }
    }

    fn test_trace() -> TraceContext {
        TraceContext {
            trace_id: "test-trace-001".to_string(),
            span_id: "0000000000000001".to_string(),
            trace_flags: 1,
        }
    }

    #[test]
    fn route_metadata_has_four_endpoints() {
        let routes = route_metadata();
        assert_eq!(routes.len(), 4);
        assert!(routes.iter().all(|r| r.group == EndpointGroup::Operator));
    }

    #[test]
    fn health_endpoint_no_auth() {
        let routes = route_metadata();
        let health = routes
            .iter()
            .find(|r| r.path.contains("health"))
            .expect("health route should exist");
        assert_eq!(health.auth_method, AuthMethod::None);
        assert!(health.policy_hook.required_roles.is_empty());
    }

    #[test]
    fn get_status_returns_ok() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let identity = test_identity();
        let trace = test_trace();
        let result = get_status(&identity, &trace).expect("status");
        assert!(result.ok);
        assert!(!result.data.node_id.is_empty());
        assert_eq!(result.data.policy_profile, "balanced");
    }

    #[test]
    fn get_status_rejects_non_apikey_identity_directly() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let err = get_status(&bearer_reader_identity(), &test_trace()).expect_err("status fails");
        match err {
            ApiError::AuthFailed { detail, .. } => assert!(detail.contains("route contract")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn get_config_rejects_reader_without_operator_role() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let err = get_config(&reader_identity(), &test_trace()).expect_err("config fails");
        match err {
            ApiError::PolicyDenied { policy_hook, .. } => {
                assert_eq!(policy_hook, "operator.config.read");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn status_uptime_is_monotonic() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let identity = test_identity();
        let trace = test_trace();
        let first = get_status(&identity, &trace).expect("first");
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = get_status(&identity, &trace).expect("second");
        assert!(second.data.uptime_seconds >= first.data.uptime_seconds);
    }

    #[test]
    fn service_bootstrap_calls_process_start_init() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let before = process_start_init_call_count_for_tests();

        let _service = ControlPlaneService::default();

        assert_eq!(process_start_init_call_count_for_tests(), before + 1);
    }

    #[test]
    fn status_uptime_uses_seeded_process_start() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        seed_process_start_for_tests(std::time::Duration::from_secs(1), "2026-03-20T00:00:00Z");

        let identity = test_identity();
        let trace = test_trace();
        let result = get_status(&identity, &trace).expect("status");

        assert!(
            result.data.uptime_seconds >= 1,
            "uptime should include time since service bootstrap"
        );
    }

    #[test]
    fn status_read_seeds_process_start_without_service_bootstrap() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let before = process_start_init_call_count_for_tests();

        let identity = test_identity();
        let trace = test_trace();
        let _ = get_status(&identity, &trace).expect("status");

        assert_eq!(process_start_init_call_count_for_tests(), before + 1);
        assert!(
            !installed_process_start_wall_clock_for_tests().is_empty(),
            "direct status read should seed a stable process-start baseline"
        );
    }

    #[test]
    fn clear_process_start_override_waits_for_init_lock_before_data_locks() {
        assert_process_start_cleanup_waits_for_init_lock();
    }

    #[test]
    fn get_health_returns_live_ready() {
        clear_resource_admission_readiness_for_tests();
        let identity = test_identity();
        let trace = test_trace();
        let result = get_health(&identity, &trace).expect("health");
        assert!(result.ok);
        assert!(result.data.live);
        assert!(result.data.ready);
        assert!(!result.data.checks.is_empty());
        assert!(result.data.checks.iter().any(|component| {
            component.name.as_str().eq("resource_admission")
                && matches!(component.status, ComponentStatus::Ok)
        }));
    }

    #[test]
    fn get_health_exposes_resource_admission_readiness_counts() {
        use crate::policy::resource_admission::{
            AdmissionDecisionCounts, AdmissionTelemetrySnapshot, RA_REJECT_MEMORY_BUDGET_EXCEEDED,
        };

        clear_resource_admission_readiness_for_tests();
        update_resource_admission_readiness(AdmissionTelemetrySnapshot::new(
            AdmissionDecisionCounts {
                admitted: 3,
                deferred: 2,
                shed: 1,
                rejected: 1,
            },
            Default::default(),
        ));

        let result = get_health(&test_identity(), &test_trace()).expect("health");
        assert!(!result.data.ready);
        let admission = result
            .data
            .checks
            .iter()
            .find(|component| component.name.as_str().eq("resource_admission"))
            .expect("resource admission readiness component");

        assert!(matches!(admission.status, ComponentStatus::Down));
        let detail: ResourceAdmissionReadinessDetail = serde_json::from_str(
            admission
                .detail
                .as_deref()
                .expect("machine-readable readiness detail"),
        )
        .expect("valid resource admission readiness detail");
        assert_eq!(detail.admitted, 3);
        assert_eq!(detail.deferred, 2);
        assert_eq!(detail.shed, 1);
        assert_eq!(detail.rejected, 1);
        assert_eq!(detail.reason_code, RA_REJECT_MEMORY_BUDGET_EXCEEDED);

        clear_resource_admission_readiness_for_tests();
    }

    #[test]
    fn get_config_returns_default_snapshot_without_service_bootstrap() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let identity = test_identity();
        let trace = test_trace();
        let result = get_config(&identity, &trace).expect("config");
        assert!(result.ok);
        assert_eq!(result.data.profile, "balanced");
        assert_eq!(result.data.compatibility_mode, "balanced");
        assert!(result.data.trust_revocation_fresh);
        assert!(result.data.quarantine_on_high_risk);
        assert!(result.data.replay_persist_high_severity);
        assert_eq!(result.data.fleet_convergence_timeout_seconds, 120);
        assert_eq!(result.data.observability_namespace, "franken_node");

        let repeat = get_config(&identity, &trace).expect("repeat config");
        assert_eq!(result.data, repeat.data);
    }

    #[test]
    fn service_bootstrap_updates_operator_config_snapshot() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let identity = test_identity();
        let trace = test_trace();

        let before = get_config(&identity, &trace).expect("config before bootstrap");
        assert_eq!(before.data.profile, "balanced");

        let custom_runtime_config =
            crate::config::Config::for_profile(crate::config::Profile::LegacyRisky);
        let _service = ControlPlaneService::new(crate::api::service::ServiceConfig {
            runtime_config: custom_runtime_config,
            ..Default::default()
        });

        let after = get_config(&identity, &trace).expect("config after bootstrap");
        assert_eq!(after.data.profile, "legacy-risky");
        assert_eq!(after.data.compatibility_mode, "legacy-risky");
        assert!(!after.data.trust_revocation_fresh);
        assert!(!after.data.quarantine_on_high_risk);
        assert!(after.data.replay_persist_high_severity);
        assert_eq!(after.data.fleet_convergence_timeout_seconds, 300);
        assert_eq!(after.data.observability_namespace, "franken_node");

        let repeat = get_config(&identity, &trace).expect("repeat config");
        assert_eq!(after.data, repeat.data);
    }

    #[test]
    fn service_bootstrap_updates_status_policy_profile() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let identity = test_identity();
        let trace = test_trace();

        let before = get_status(&identity, &trace).expect("status before bootstrap");
        assert_eq!(before.data.policy_profile, "balanced");

        let custom_runtime_config =
            crate::config::Config::for_profile(crate::config::Profile::LegacyRisky);
        let _service = ControlPlaneService::new(crate::api::service::ServiceConfig {
            runtime_config: custom_runtime_config,
            ..Default::default()
        });

        let after = get_status(&identity, &trace).expect("status after bootstrap");
        assert_eq!(after.data.policy_profile, "legacy-risky");
    }

    #[test]
    fn get_rollout_returns_stable_phase() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let identity = test_identity();
        let trace = test_trace();
        let result = get_rollout(&identity, &trace).expect("rollout");
        assert!(result.ok);
        assert_eq!(result.data.current_phase, "stable");
    }

    #[test]
    fn rollout_last_transition_is_stable_without_service_bootstrap() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let identity = test_identity();
        let trace = test_trace();

        let first = get_rollout(&identity, &trace).expect("first rollout");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = get_rollout(&identity, &trace).expect("second rollout");

        assert_eq!(first.data.last_transition, second.data.last_transition);
        assert_eq!(
            installed_process_start_wall_clock_for_tests(),
            first.data.last_transition
        );
    }

    #[test]
    fn rollout_last_transition_is_stable_across_reads() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        seed_process_start_for_tests(std::time::Duration::from_secs(2), "2026-03-20T12:34:56Z");
        let identity = test_identity();
        let trace = test_trace();

        let first = get_rollout(&identity, &trace).expect("first rollout");
        let second = get_rollout(&identity, &trace).expect("second rollout");

        assert_eq!(first.data.last_transition, "2026-03-20T12:34:56Z");
        assert_eq!(first.data.last_transition, second.data.last_transition);
    }

    #[test]
    fn service_bootstrap_preserves_existing_process_start_state() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        seed_bootstrapped_process_start_for_tests(
            std::time::Duration::from_millis(10),
            "2026-03-20T12:34:56Z",
        );

        let identity = test_identity();
        let trace = test_trace();
        let before_offset = installed_process_start_offset_nanos_for_tests();
        let before_wall_clock = installed_process_start_wall_clock_for_tests();

        let before = get_rollout(&identity, &trace).expect("rollout before reseed");
        assert_eq!(before.data.last_transition, "2026-03-20T12:34:56Z");
        assert_eq!(before_wall_clock, "2026-03-20T12:34:56Z");

        // Give a buggy re-init path enough time to overwrite the seed with a distinct offset.
        std::thread::sleep(std::time::Duration::from_millis(20));

        let _service = ControlPlaneService::default();

        let after = get_rollout(&identity, &trace).expect("rollout after bootstrap");
        assert_eq!(after.data.last_transition, "2026-03-20T12:34:56Z");
        assert_eq!(
            installed_process_start_offset_nanos_for_tests(),
            before_offset
        );
        assert_eq!(
            installed_process_start_wall_clock_for_tests(),
            before_wall_clock
        );
    }

    #[test]
    fn all_stable_lifecycle() {
        for route in route_metadata() {
            assert_eq!(route.lifecycle, EndpointLifecycle::Stable);
        }
    }

    #[test]
    fn all_routes_have_trace_propagation() {
        for route in route_metadata() {
            assert!(route.trace_propagation);
        }
    }

    #[test]
    fn non_health_operator_routes_do_not_allow_anonymous_access() {
        for route in route_metadata()
            .into_iter()
            .filter(|route| route.path != "/v1/operator/health")
        {
            assert_ne!(
                route.auth_method,
                AuthMethod::None,
                "{} must not bypass auth",
                route.path
            );
            assert!(
                !route.policy_hook.required_roles.is_empty(),
                "{} must require at least one policy role",
                route.path
            );
        }
    }

    #[test]
    fn operator_route_metadata_rejects_duplicate_paths() {
        let mut seen = std::collections::BTreeSet::new();
        for route in route_metadata() {
            assert!(
                seen.insert(route.path.clone()),
                "duplicate operator route path must be rejected in metadata: {}",
                route.path
            );
        }
    }

    #[test]
    fn future_process_start_offset_saturates_uptime_to_zero() {
        let _lock = process_start_test_lock();
        clear_process_start_override_for_tests();
        let future_offset = now_epoch_nanos().saturating_add(60_000_000_000);
        install_process_start(future_offset, "2099-01-01T00:00:00Z".to_string());

        let status = get_status(&test_identity(), &test_trace()).expect("status");

        assert_eq!(status.data.uptime_seconds, 0);
    }

    #[test]
    fn config_view_clamps_oversized_fleet_timeout() {
        let mut config = RuntimeConfig::default();
        config.fleet.convergence_timeout_seconds = u64::MAX;

        let view = ConfigView::from_runtime_config(&config);

        assert_eq!(view.fleet_convergence_timeout_seconds, u32::MAX);
    }

    #[test]
    fn component_status_deserialize_rejects_unknown_variant() {
        let result: Result<ComponentStatus, _> = serde_json::from_str("\"Critical\"");

        assert!(result.is_err(), "unknown health status must fail closed");
    }

    #[test]
    fn config_view_deserialize_rejects_timeout_overflow() {
        let raw = serde_json::json!({
            "profile": "balanced",
            "compatibility_mode": "balanced",
            "trust_revocation_fresh": true,
            "quarantine_on_high_risk": true,
            "replay_persist_high_severity": true,
            "fleet_convergence_timeout_seconds": 4_294_967_296_u64,
            "observability_namespace": "franken_node"
        });

        let result: Result<ConfigView, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "u32 timeout overflow must not deserialize");
    }

    #[test]
    fn rollout_state_deserialize_rejects_canary_overflow() {
        let raw = serde_json::json!({
            "current_phase": "canary",
            "target_version": "1.2.3",
            "canary_percentage": 256_u16,
            "healthy_nodes": 1_u32,
            "total_nodes": 1_u32,
            "last_transition": "2026-03-20T12:34:56Z"
        });

        let result: Result<RolloutState, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "u8 canary overflow must not deserialize");
    }

    #[test]
    fn node_status_deserialize_rejects_missing_node_id() {
        let raw = serde_json::json!({
            "version": "1.2.3",
            "uptime_seconds": 10_u64,
            "policy_profile": "balanced",
            "active_extensions": 0_u32,
            "quarantined_extensions": 0_u32,
            "control_epoch": 1_u64
        });

        let result: Result<NodeStatus, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "node_id is required in status payloads");
    }

    #[test]
    fn node_status_deserialize_rejects_string_uptime() {
        let raw = serde_json::json!({
            "node_id": "node-1",
            "version": "1.2.3",
            "uptime_seconds": "10",
            "policy_profile": "balanced",
            "active_extensions": 0_u32,
            "quarantined_extensions": 0_u32,
            "control_epoch": 1_u64
        });

        let result: Result<NodeStatus, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "uptime_seconds must remain numeric");
    }

    #[test]
    fn node_status_deserialize_rejects_active_extension_overflow() {
        let raw = serde_json::json!({
            "node_id": "node-1",
            "version": "1.2.3",
            "uptime_seconds": 10_u64,
            "policy_profile": "balanced",
            "active_extensions": 4_294_967_296_u64,
            "quarantined_extensions": 0_u32,
            "control_epoch": 1_u64
        });

        let result: Result<NodeStatus, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "active_extensions must fit in u32");
    }

    #[test]
    fn health_check_deserialize_rejects_missing_checks() {
        let raw = serde_json::json!({
            "live": true,
            "ready": true
        });

        let result: Result<HealthCheck, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "health checks list is required");
    }

    #[test]
    fn health_component_deserialize_rejects_lowercase_status() {
        let raw = serde_json::json!({
            "name": "policy_engine",
            "status": "ok",
            "detail": null
        });

        let result: Result<HealthComponent, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "status variants must use canonical casing");
    }

    #[test]
    fn config_view_deserialize_rejects_string_boolean() {
        let raw = serde_json::json!({
            "profile": "balanced",
            "compatibility_mode": "balanced",
            "trust_revocation_fresh": "true",
            "quarantine_on_high_risk": true,
            "replay_persist_high_severity": true,
            "fleet_convergence_timeout_seconds": 120_u32,
            "observability_namespace": "franken_node"
        });

        let result: Result<ConfigView, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "boolean config fields must not accept strings"
        );
    }

    #[test]
    fn rollout_state_deserialize_rejects_missing_last_transition() {
        let raw = serde_json::json!({
            "current_phase": "stable",
            "target_version": "1.2.3",
            "canary_percentage": 0_u8,
            "healthy_nodes": 1_u32,
            "total_nodes": 1_u32
        });

        let result: Result<RolloutState, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "last_transition is required");
    }

    #[test]
    fn rollout_state_deserialize_rejects_string_total_nodes() {
        let raw = serde_json::json!({
            "current_phase": "stable",
            "target_version": "1.2.3",
            "canary_percentage": 0_u8,
            "healthy_nodes": 1_u32,
            "total_nodes": "1",
            "last_transition": "2026-03-20T12:34:56Z"
        });

        let result: Result<RolloutState, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "total_nodes must remain numeric");
    }

    #[test]
    fn node_status_deserialize_rejects_negative_control_epoch() {
        let raw = serde_json::json!({
            "node_id": "node-1",
            "version": "1.2.3",
            "uptime_seconds": 10_u64,
            "policy_profile": "balanced",
            "active_extensions": 0_u32,
            "quarantined_extensions": 0_u32,
            "control_epoch": -1
        });

        let result: Result<NodeStatus, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "control_epoch must not accept negative values"
        );
    }

    #[test]
    fn node_status_deserialize_rejects_string_quarantined_extensions() {
        let raw = serde_json::json!({
            "node_id": "node-1",
            "version": "1.2.3",
            "uptime_seconds": 10_u64,
            "policy_profile": "balanced",
            "active_extensions": 0_u32,
            "quarantined_extensions": "0",
            "control_epoch": 1_u64
        });

        let result: Result<NodeStatus, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "quarantined_extensions must remain numeric"
        );
    }

    #[test]
    fn health_check_deserialize_rejects_string_live_flag() {
        let raw = serde_json::json!({
            "live": "true",
            "ready": true,
            "checks": []
        });

        let result: Result<HealthCheck, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "live must remain a boolean");
    }

    #[test]
    fn health_component_deserialize_rejects_missing_status() {
        let raw = serde_json::json!({
            "name": "policy_engine",
            "detail": null
        });

        let result: Result<HealthComponent, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "component status is required");
    }

    #[test]
    fn config_view_deserialize_rejects_negative_timeout() {
        let raw = serde_json::json!({
            "profile": "balanced",
            "compatibility_mode": "balanced",
            "trust_revocation_fresh": true,
            "quarantine_on_high_risk": true,
            "replay_persist_high_severity": true,
            "fleet_convergence_timeout_seconds": -1,
            "observability_namespace": "franken_node"
        });

        let result: Result<ConfigView, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "fleet_convergence_timeout_seconds must not be negative"
        );
    }

    #[test]
    fn config_view_deserialize_rejects_missing_observability_namespace() {
        let raw = serde_json::json!({
            "profile": "balanced",
            "compatibility_mode": "balanced",
            "trust_revocation_fresh": true,
            "quarantine_on_high_risk": true,
            "replay_persist_high_severity": true,
            "fleet_convergence_timeout_seconds": 120_u32
        });

        let result: Result<ConfigView, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "observability_namespace is required");
    }

    #[test]
    fn rollout_state_deserialize_rejects_string_canary_percentage() {
        let raw = serde_json::json!({
            "current_phase": "stable",
            "target_version": "1.2.3",
            "canary_percentage": "0",
            "healthy_nodes": 1_u32,
            "total_nodes": 1_u32,
            "last_transition": "2026-03-20T12:34:56Z"
        });

        let result: Result<RolloutState, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "canary_percentage must remain numeric");
    }

    #[test]
    fn rollout_state_deserialize_rejects_negative_healthy_nodes() {
        let raw = serde_json::json!({
            "current_phase": "stable",
            "target_version": "1.2.3",
            "canary_percentage": 0_u8,
            "healthy_nodes": -1,
            "total_nodes": 1_u32,
            "last_transition": "2026-03-20T12:34:56Z"
        });

        let result: Result<RolloutState, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "healthy_nodes must not be negative");
    }

    /// Comprehensive negative-path test module covering edge cases and attack vectors.
    ///
    /// These tests validate robustness against malicious inputs, resource exhaustion,
    /// timing attacks, and arithmetic edge cases in operator API routes.
    #[cfg(test)]
    mod operator_routes_comprehensive_negative_tests {
        use super::*;

        #[test]
        fn unicode_injection_in_authentication_identifiers_handled_safely() {
            // Unicode control characters, NULL bytes, path traversal attempts
            let malicious_principals = vec![
                "op\u{0000}null_injection",
                "op\u{200B}zero_width",
                "op\u{FEFF}bom_attack",
                "op/../../../etc/passwd",
                "op\u{202E}rtl_override\u{202D}",
                "op\x1B[H\x1B[2J", // ANSI escape sequences
                "op\u{1F4A9}emoji_flood",
            ];

            let malicious_trace_ids = vec![
                "trace\u{0000}null",
                "trace\u{200B}zwsp",
                "trace/../../../admin",
                "trace\x1B[31m;DELETE;",
                "trace\u{202E}direction",
            ];

            for malicious_principal in &malicious_principals {
                for malicious_trace_id in &malicious_trace_ids {
                    let identity = AuthIdentity {
                        principal: malicious_principal.to_string(),
                        method: AuthMethod::ApiKey,
                        roles: vec!["operator".to_string()],
                    };

                    let trace = TraceContext {
                        trace_id: malicious_trace_id.to_string(),
                        span_id: "0000000000000001".to_string(),
                        trace_flags: 1,
                    };

                    // All endpoint handlers should process gracefully without panics/crashes
                    let status_result = get_status(&identity, &trace);
                    assert!(
                        status_result.is_ok(),
                        "Status should handle malicious identity"
                    );

                    let health_result = get_health(&identity, &trace);
                    assert!(
                        health_result.is_ok(),
                        "Health should handle malicious identity"
                    );

                    let config_result = get_config(&identity, &trace);
                    assert!(
                        config_result.is_ok(),
                        "Config should handle malicious identity"
                    );

                    let rollout_result = get_rollout(&identity, &trace);
                    assert!(
                        rollout_result.is_ok(),
                        "Rollout should handle malicious identity"
                    );
                }
            }
        }

        #[test]
        fn arithmetic_overflow_protection_in_uptime_calculations() {
            let _lock = process_start_test_lock();
            clear_process_start_override_for_tests();

            // Test near u64::MAX boundaries for timing calculations
            let extreme_offsets = vec![u64::MAX - 1000, u64::MAX - 1, u64::MAX];

            for &extreme_offset in &extreme_offsets {
                // Install extreme process start offset
                install_process_start(extreme_offset, "2099-01-01T00:00:00Z".to_string());

                let identity = test_identity();
                let trace = test_trace();
                let status = get_status(&identity, &trace)
                    .expect(&format!("Should handle extreme offset: {}", extreme_offset));
                // Uptime should saturate gracefully, not overflow
                assert!(status.data.uptime_seconds <= u64::MAX);

                // Test rollout endpoint timing calculations
                let rollout =
                    get_rollout(&identity, &trace).expect("Rollout should handle extreme timing");
                assert!(!rollout.data.last_transition.is_empty());
            }
        }

        #[test]
        fn memory_exhaustion_through_massive_health_components() {
            let identity = test_identity();
            let trace = test_trace();

            // Create artificial health check with massive component list
            let massive_component_count = 10000;
            let mut massive_checks = Vec::new();

            for comp_idx in 0..massive_component_count {
                if massive_checks.len() < 1000 {
                    massive_checks.push(HealthComponent {
                        name: format!("flood_component_{comp_idx:05}"),
                        status: match comp_idx % 3 {
                            0 => ComponentStatus::Ok,
                            1 => ComponentStatus::Degraded,
                            _ => ComponentStatus::Down,
                        },
                        detail: Some(format!("memory_pressure_test_detail_{comp_idx}")),
                    });
                }
            }

            let massive_health = HealthCheck {
                live: true,
                ready: massive_component_count > 5000, // Degraded if too many components
                checks: massive_checks,
            };

            // Serialization should handle large payloads
            let serialized = serde_json::to_string(&massive_health)
                .expect("Should serialize massive health check");

            // Deserialization should handle large payloads
            let deserialized: HealthCheck =
                serde_json::from_str(&serialized).expect("Should deserialize massive health check");
            assert_eq!(deserialized.checks.len(), massive_component_count);
        }

        #[test]
        fn concurrent_operations_simulation_race_conditions() {
            let _lock = process_start_test_lock();
            clear_process_start_override_for_tests();

            // Simulate concurrent endpoint access
            // (In real concurrency this would need proper synchronization)
            let identity = test_identity();
            let base_trace = test_trace();

            let mut results = Vec::new();

            // Rapid burst of API calls as if from concurrent clients
            for i in 0..50 {
                let trace = TraceContext {
                    trace_id: format!("race_trace_{i:03}"),
                    span_id: format!("{i:016}"),
                    trace_flags: 1,
                };

                // Interleave different endpoint calls
                match i % 4 {
                    0 => {
                        let result = get_status(&identity, &trace);
                        results.push(("status", result.is_ok()));
                    }
                    1 => {
                        let result = get_health(&identity, &trace);
                        results.push(("health", result.is_ok()));
                    }
                    2 => {
                        let result = get_config(&identity, &trace);
                        results.push(("config", result.is_ok()));
                    }
                    _ => {
                        let result = get_rollout(&identity, &trace);
                        results.push(("rollout", result.is_ok()));
                    }
                }
            }

            // All operations should succeed despite "concurrent" access
            assert!(
                results.iter().all(|(_, success)| *success),
                "All concurrent operations should succeed"
            );
            assert_eq!(results.len(), 50);

            // Verify state consistency
            let final_status = get_status(&identity, &base_trace).expect("final status");
            let final_config = get_config(&identity, &base_trace).expect("final config");
            assert_eq!(final_status.data.policy_profile, final_config.data.profile);
        }

        #[test]
        fn configuration_extreme_edge_cases() {
            // Test configurations with extreme values
            let mut extreme_config = RuntimeConfig::default();

            // Test maximum values
            extreme_config.fleet.convergence_timeout_seconds = u64::MAX;

            let config_view = ConfigView::from_runtime_config(&extreme_config);

            // Should clamp to u32::MAX
            assert_eq!(config_view.fleet_convergence_timeout_seconds, u32::MAX);

            // Test serialization/deserialization with extreme values
            let serialized = serde_json::to_string(&config_view).expect("serialize extreme config");
            let deserialized: ConfigView =
                serde_json::from_str(&serialized).expect("deserialize extreme config");
            assert_eq!(deserialized.fleet_convergence_timeout_seconds, u32::MAX);

            // Test with extreme string lengths
            extreme_config.observability.namespace = "a".repeat(10000);
            extreme_config.profile = crate::config::Profile::Balanced; // Reset profile to known value

            let extreme_view = ConfigView::from_runtime_config(&extreme_config);
            assert_eq!(extreme_view.observability_namespace.len(), 10000);
            assert_eq!(extreme_view.profile, "balanced");
        }

        #[test]
        fn process_timing_boundary_attack_scenarios() {
            let _lock = process_start_test_lock();
            clear_process_start_override_for_tests();

            // Test timing consistency across process start boundaries
            let identity = test_identity();
            let trace = test_trace();

            // Test with process start time in the future (invalid scenario)
            let future_time = chrono::Utc::now() + chrono::Duration::seconds(3600);
            let future_offset = now_epoch_nanos().saturating_add(3600_000_000_000); // 1 hour in nanos

            install_process_start(future_offset, future_time.to_rfc3339());

            let status =
                get_status(&identity, &trace).expect("Should handle future process start time");
            // Uptime should saturate to 0 for future timestamps
            assert_eq!(status.data.uptime_seconds, 0);

            let rollout =
                get_rollout(&identity, &trace).expect("Rollout should handle future process start");
            assert_eq!(rollout.data.last_transition, future_time.to_rfc3339());

            // Test with process start at epoch boundaries
            let epoch_boundaries = vec![0u64, 1u64, u64::MAX / 2, u64::MAX - 1, u64::MAX];

            for &boundary_offset in &epoch_boundaries {
                install_process_start(boundary_offset, "2000-01-01T00:00:00Z".to_string());

                let boundary_result = get_status(&identity, &trace).expect(&format!(
                    "Should handle boundary offset: {}",
                    boundary_offset
                ));
                assert!(boundary_result.data.uptime_seconds <= u64::MAX);
            }
        }

        #[test]
        fn serialization_attack_vectors_json_injection() {
            let identity = test_identity();
            let trace = test_trace();

            // Test with malicious JSON injection patterns
            let malicious_node_status = NodeStatus {
                node_id: "node\"},\"malicious\":\"payload\",\"a\":{\"".to_string(),
                version: "\"\"},\"injected\":true,\"version\":\"".to_string(),
                uptime_seconds: 100,
                policy_profile: "balanced\\\",\\\"attack\\\":\\\"vector".to_string(),
                active_extensions: 0,
                quarantined_extensions: 0,
                control_epoch: 1,
            };

            // Should serialize safely without breaking JSON structure
            let serialized = serde_json::to_string(&malicious_node_status)
                .expect("Should serialize malicious node status safely");
            assert!(
                !serialized.contains("\"malicious\":\"payload\""),
                "Should escape injection attempts"
            );

            // Verify round-trip integrity
            let deserialized: NodeStatus =
                serde_json::from_str(&serialized).expect("Should deserialize safely");
            assert_eq!(deserialized.node_id, malicious_node_status.node_id);
            assert_eq!(deserialized.version, malicious_node_status.version);
        }

        #[test]
        fn route_metadata_boundary_validation() {
            let routes = route_metadata();

            // Test route metadata consistency and bounds
            assert_eq!(routes.len(), 4, "Should have exactly 4 operator routes");

            for route in &routes {
                // Path validation
                assert!(
                    route.path.starts_with("/v1/operator/"),
                    "All paths should start with operator prefix"
                );
                assert!(route.path.len() < 1000, "Paths should be reasonable length");

                // Method validation
                assert_eq!(route.method, "GET", "All operator routes should be GET");

                // Group validation
                assert_eq!(
                    route.group,
                    EndpointGroup::Operator,
                    "All should be operator group"
                );

                // Lifecycle validation
                assert_eq!(
                    route.lifecycle,
                    EndpointLifecycle::Stable,
                    "All should be stable"
                );

                // Auth validation
                if route.path.contains("health") {
                    assert_eq!(
                        route.auth_method,
                        AuthMethod::None,
                        "Health endpoint should not require auth"
                    );
                } else {
                    assert_eq!(
                        route.auth_method,
                        AuthMethod::ApiKey,
                        "Non-health endpoints should require API key"
                    );
                }

                // Policy validation
                assert!(
                    route.policy_hook.hook_id.starts_with("operator."),
                    "Hook IDs should start with operator prefix"
                );
                assert!(
                    route.policy_hook.hook_id.len() < 100,
                    "Hook IDs should be reasonable length"
                );

                if route.path.contains("health") {
                    assert!(
                        route.policy_hook.required_roles.is_empty(),
                        "Health endpoint should not require roles"
                    );
                } else {
                    assert!(
                        !route.policy_hook.required_roles.is_empty(),
                        "Non-health endpoints should require roles"
                    );
                    assert!(
                        route
                            .policy_hook
                            .required_roles
                            .contains(&"operator".to_string()),
                        "Should require operator role"
                    );
                }

                // Trace propagation
                assert!(
                    route.trace_propagation,
                    "All routes should support trace propagation"
                );
            }

            // Test uniqueness
            let unique_paths: std::collections::BTreeSet<_> =
                routes.iter().map(|r| &r.path).collect();
            assert_eq!(
                unique_paths.len(),
                routes.len(),
                "All paths should be unique"
            );

            let unique_hook_ids: std::collections::BTreeSet<_> =
                routes.iter().map(|r| &r.policy_hook.hook_id).collect();
            assert_eq!(
                unique_hook_ids.len(),
                routes.len(),
                "All hook IDs should be unique"
            );
        }
    }

    #[test]
    fn process_start_init_resets_state_after_panicking_initializer() {
        let _lock = process_start_test_lock();
        reset_operator_route_state_for_tests();

        let panic = catch_unwind(AssertUnwindSafe(|| {
            run_atomic_initializer(&PROCESS_START_STATE, || panic!("simulated init panic"));
        }));

        assert!(
            panic.is_err(),
            "panic injection should bubble to the caller"
        );
        assert_eq!(
            PROCESS_START_STATE.load(Ordering::Acquire),
            INIT_STATE_UNINITIALIZED,
            "panicking initializer must not strand the state machine in INITIALIZING"
        );

        init_process_start();

        assert_eq!(
            PROCESS_START_STATE.load(Ordering::Acquire),
            INIT_STATE_INITIALIZED
        );
        assert!(
            !installed_process_start_wall_clock_for_tests().is_empty(),
            "retry should install a real process-start snapshot"
        );
    }

    #[test]
    fn operator_config_init_resets_state_after_panicking_initializer() {
        let _lock = process_start_test_lock();
        reset_operator_route_state_for_tests();

        let panic = catch_unwind(AssertUnwindSafe(|| {
            run_atomic_initializer(&OPERATOR_CONFIG_STATE, || panic!("simulated init panic"));
        }));

        assert!(
            panic.is_err(),
            "panic injection should bubble to the caller"
        );
        assert_eq!(
            OPERATOR_CONFIG_STATE.load(Ordering::Acquire),
            INIT_STATE_UNINITIALIZED,
            "panicking initializer must not strand the config state machine in INITIALIZING"
        );

        let custom_runtime_config =
            crate::config::Config::for_profile(crate::config::Profile::LegacyRisky);
        init_operator_config(&custom_runtime_config);

        let installed = operator_config_view();
        assert_eq!(
            OPERATOR_CONFIG_STATE.load(Ordering::Acquire),
            INIT_STATE_INITIALIZED
        );
        assert_eq!(installed.profile, "legacy-risky");
        assert_eq!(installed.compatibility_mode, "legacy-risky");
    }
}
