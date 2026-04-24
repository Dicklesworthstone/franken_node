use std::time::Duration;

// Config defaults.
pub const COMPAT_DEFAULT_RECEIPT_TTL_SECS: u64 = 3_600;
pub const COMPAT_DEFAULT_RECEIPT_TTL: Duration =
    Duration::from_secs(COMPAT_DEFAULT_RECEIPT_TTL_SECS);
pub const TRUST_CARD_CACHE_TTL_SECS: u64 = 60;
pub const TRUST_CARD_CACHE_TTL: Duration = Duration::from_secs(TRUST_CARD_CACHE_TTL_SECS);
pub const TRUST_FRESHNESS_WINDOW_SECS: u64 = 30 * 24 * 3_600;
pub const TRUST_FRESHNESS_WINDOW: Duration = Duration::from_secs(TRUST_FRESHNESS_WINDOW_SECS);
pub const REPLAY_CAPSULE_FRESHNESS_SECS: u64 = 3_600;
pub const REPLAY_CAPSULE_FRESHNESS: Duration = Duration::from_secs(REPLAY_CAPSULE_FRESHNESS_SECS);
pub const REMOTE_IDEMPOTENCY_TTL_SECS: u64 = 604_800;
pub const REMOTE_IDEMPOTENCY_TTL: Duration = Duration::from_secs(REMOTE_IDEMPOTENCY_TTL_SECS);
pub const SECURITY_MAX_DEGRADED_DURATION_SECS: u64 = 3_600;
pub const SECURITY_MAX_DEGRADED_DURATION: Duration =
    Duration::from_secs(SECURITY_MAX_DEGRADED_DURATION_SECS);

// Fleet defaults.
pub const FLEET_STRICT_CONVERGENCE_TIMEOUT_SECS: u64 = 60;
pub const FLEET_BALANCED_CONVERGENCE_TIMEOUT_SECS: u64 = 120;
pub const FLEET_LEGACY_CONVERGENCE_TIMEOUT_SECS: u64 = 300;
pub const FLEET_BARRIER_TIMEOUT_MS: u64 = 30_000;
pub const FLEET_BARRIER_TIMEOUT: Duration = Duration::from_millis(FLEET_BARRIER_TIMEOUT_MS);
pub const FLEET_CONVERGENCE_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const FLEET_AGENT_POLL_SLEEP_SLICE: Duration = Duration::from_millis(100);
pub const FLEET_LOCK_RETRY_BACKOFF_MILLIS: [u64; 5] = [100, 200, 400, 800, 1_600];

// Runtime drain and cancellation defaults.
pub const RUNTIME_DRAIN_TIMEOUT_MS: u64 = 30_000;
pub const RUNTIME_DRAIN_TIMEOUT: Duration = Duration::from_millis(RUNTIME_DRAIN_TIMEOUT_MS);
pub const EPOCH_TRANSITION_DRAIN_TIMEOUT_MS: u64 = 10_000;
pub const EPOCH_TRANSITION_DRAIN_TIMEOUT: Duration =
    Duration::from_millis(EPOCH_TRANSITION_DRAIN_TIMEOUT_MS);
pub const CANCELLABLE_TASK_MIN_DRAIN_TIMEOUT_MS: u64 = 500;
pub const CANCELLATION_PROTOCOL_MIN_DRAIN_TIMEOUT_MS: u64 = 1_000;

// Migration runtime validation.
pub const MIGRATION_VALIDATE_RUNTIME_TIMEOUT: Duration = Duration::from_secs(10);
pub const MIGRATION_RUNTIME_PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
pub const MIGRATION_RUNTIME_PROCESS_KILL_GRACE: Duration = Duration::from_millis(50);
pub const MIGRATION_RUNTIME_POLL_INTERVAL: Duration = Duration::from_millis(25);

// External command and runtime execution.
pub const REGISTRY_GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
pub const EXTERNAL_COMMAND_PIPE_DRAIN_GRACE: Duration = Duration::from_millis(100);
pub const EXTERNAL_COMMAND_TERMINATE_GRACE: Duration = Duration::from_millis(25);
pub const EXTERNAL_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(25);
pub const ENGINE_DISPATCH_PIPE_READER_TIMEOUT: Duration = Duration::from_secs(2);
pub const ENGINE_DISPATCH_DEFAULT_TIMEOUT_SECS: u64 = 300;
pub const ENGINE_DISPATCH_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub const COUNTERFACTUAL_REPLAY_MAX_WALL_CLOCK_MS: u64 = 30_000;
pub const LOCKSTEP_RUNTIME_TIMEOUT: Duration = Duration::from_secs(30);
pub const LOCKSTEP_RUNTIME_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const LOCKSTEP_PROCESS_KILL_GRACE: Duration = Duration::from_millis(50);
pub const LOCKSTEP_PIPE_DRAIN_GRACE_EXTENSION: Duration = Duration::from_millis(100);
pub const LOCKSTEP_PIPE_DRAIN_JOIN_TIMEOUT_MS: u64 = 2_000;
pub const LOCKSTEP_PIPE_DRAIN_JOIN_TIMEOUT: Duration =
    Duration::from_millis(LOCKSTEP_PIPE_DRAIN_JOIN_TIMEOUT_MS);
pub const LOCKSTEP_PIPE_DRAIN_JOIN_POLL_MS: u64 = 10;
pub const LOCKSTEP_PIPE_DRAIN_JOIN_POLL: Duration =
    Duration::from_millis(LOCKSTEP_PIPE_DRAIN_JOIN_POLL_MS);

// Telemetry bridge timing.
pub const TELEMETRY_ENQUEUE_TIMEOUT_MS: u64 = 50;
pub const TELEMETRY_ACCEPT_POLL_INTERVAL_MS: u64 = 100;
pub const TELEMETRY_CONNECTION_READ_TIMEOUT_MS: u64 = 500;
pub const TELEMETRY_DEFAULT_DRAIN_TIMEOUT_MS: u64 = 5_000;
pub const TELEMETRY_ACCEPT_POLL_INTERVAL: Duration =
    Duration::from_millis(TELEMETRY_ACCEPT_POLL_INTERVAL_MS);
pub const TELEMETRY_CONNECTION_READ_TIMEOUT: Duration =
    Duration::from_millis(TELEMETRY_CONNECTION_READ_TIMEOUT_MS);
pub const TELEMETRY_DEFAULT_DRAIN_TIMEOUT: Duration =
    Duration::from_millis(TELEMETRY_DEFAULT_DRAIN_TIMEOUT_MS);
pub const TELEMETRY_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(TELEMETRY_ENQUEUE_TIMEOUT_MS);
pub const TELEMETRY_WORKER_JOIN_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub const TELEMETRY_CONNECTION_TIMEOUT_GRACE: Duration = Duration::from_millis(100);
pub const TELEMETRY_CONNECTION_TIMEOUT_GRACE_POLL: Duration = Duration::from_millis(5);
pub const TELEMETRY_ENQUEUE_RETRY_DELAY: Duration = Duration::from_millis(1);

// Capability and lock probes.
pub const OCI_RUNTIME_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
pub const OCI_RUNTIME_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(25);
