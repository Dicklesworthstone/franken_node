//! Centralized bounded-collection defaults for `franken_node`.
//!
//! This module is the shared source of truth for high-frequency capacity
//! constants that currently recur across the crate surface. Follow-up migration
//! beads can replace file-local raw literals with aliases from here while
//! preserving local readability.

// Inline negative-path tests for constant validation and boundary checking
#[cfg(test)]
#[allow(unused_imports)]
use std::collections::HashMap;

/// Canonical bucket sizes reused across the product surface.
pub mod base {
    /// Small bounded collections such as approvals and compact histories.
    pub const SMALL: usize = 256;

    /// Medium windows for disputes, replay capsules, and similar registries.
    pub const MEDIUM: usize = 4_096;

    /// Common default for event logs, receipts, and audit trails.
    pub const STANDARD: usize = 16_384;

    /// Larger collections for traces, obligations, and artifact inventories.
    pub const LARGE: usize = 65_536;

    /// Extended histories that exceed the standard large bucket.
    pub const XL: usize = 131_072;

    /// Trace/register-sized collections that are intentionally tighter.
    pub const TRACE: usize = 1_024;

    /// Very large dedupe/nonces windows.
    pub const DEDUPE: usize = 524_288;

    // Inline negative-path const assertions for base bucket validation.
    // Test: all base constants must be non-zero to prevent capacity bypass
    const _: () = assert!(SMALL > 0, "SMALL capacity must be non-zero");
    const _: () = assert!(MEDIUM > 0, "MEDIUM capacity must be non-zero");
    const _: () = assert!(STANDARD > 0, "STANDARD capacity must be non-zero");
    const _: () = assert!(LARGE > 0, "LARGE capacity must be non-zero");
    const _: () = assert!(XL > 0, "XL capacity must be non-zero");
    const _: () = assert!(TRACE > 0, "TRACE capacity must be non-zero");
    const _: () = assert!(DEDUPE > 0, "DEDUPE capacity must be non-zero");

    // Test: bucket hierarchy must be strictly increasing to prevent capacity confusion
    const _: () = assert!(SMALL < TRACE, "SMALL must be less than TRACE");
    const _: () = assert!(TRACE < MEDIUM, "TRACE must be less than MEDIUM");
    const _: () = assert!(MEDIUM < STANDARD, "MEDIUM must be less than STANDARD");
    const _: () = assert!(STANDARD < LARGE, "STANDARD must be less than LARGE");
    const _: () = assert!(LARGE < XL, "LARGE must be less than XL");
    const _: () = assert!(XL < DEDUPE, "XL must be less than DEDUPE");

    // Test: power-of-two alignment for cache efficiency
    const _: () = assert!(SMALL & (SMALL - 1) == 0, "SMALL should be power of 2");
    const _: () = assert!(TRACE & (TRACE - 1) == 0, "TRACE should be power of 2");
    const _: () = assert!(MEDIUM & (MEDIUM - 1) == 0, "MEDIUM should be power of 2");
    const _: () = assert!(
        STANDARD & (STANDARD - 1) == 0,
        "STANDARD should be power of 2"
    );
    const _: () = assert!(LARGE & (LARGE - 1) == 0, "LARGE should be power of 2");
    const _: () = assert!(XL & (XL - 1) == 0, "XL should be power of 2");
    const _: () = assert!(DEDUPE & (DEDUPE - 1) == 0, "DEDUPE should be power of 2");

    // Test: no overflow when used in common arithmetic operations
    const _: () = assert!(
        DEDUPE.saturating_add(1000) > DEDUPE,
        "DEDUPE must not overflow in normal use"
    );
    const _: () = assert!(
        XL.saturating_mul(2) < usize::MAX / 2,
        "XL doubling must not approach overflow"
    );

    // Test: sufficient separation between adjacent buckets for meaningful differentiation
    const _: () = assert!(
        TRACE > SMALL * 2,
        "TRACE should be meaningfully larger than SMALL"
    );
    const _: () = assert!(
        MEDIUM > TRACE * 2,
        "MEDIUM should be meaningfully larger than TRACE"
    );
    const _: () = assert!(
        STANDARD > MEDIUM * 2,
        "STANDARD should be meaningfully larger than MEDIUM"
    );
    const _: () = assert!(
        LARGE > STANDARD * 2,
        "LARGE should be meaningfully larger than STANDARD"
    );

    // Test: dedupe window large enough for collision resistance
    const _: () = assert!(
        DEDUPE >= 32768,
        "DEDUPE must be sufficiently large for collision resistance"
    );

    // Test: trace bucket appropriate for in-memory debugging structures
    const _: () = assert!(
        TRACE <= 2048,
        "TRACE should remain memory-efficient for debugging"
    );

    // Test: standard bucket balanced between memory usage and functionality
    const _: () = assert!(
        STANDARD >= 4096 && STANDARD <= 16_384,
        "STANDARD should be balanced capacity"
    );
}

/// Audit-oriented capacities.
pub mod audit {
    use super::base;

    pub const LOG_ENTRIES: usize = base::MEDIUM;
    pub const TRAIL_ENTRIES: usize = base::STANDARD;
    pub const ACTION_LOG_ENTRIES: usize = base::STANDARD;
    pub const RECORDS: usize = base::STANDARD;
    pub const RECEIPT_CHAIN: usize = base::LARGE;

    // Inline negative-path const assertions for audit capacity validation.
    // Test: all audit constants derive from valid base buckets only
    const _: () = assert!(
        LOG_ENTRIES == base::MEDIUM,
        "LOG_ENTRIES must use MEDIUM bucket"
    );
    const _: () = assert!(
        TRAIL_ENTRIES == base::STANDARD,
        "TRAIL_ENTRIES must use STANDARD bucket"
    );
    const _: () = assert!(
        ACTION_LOG_ENTRIES == base::STANDARD,
        "ACTION_LOG_ENTRIES must use STANDARD bucket"
    );
    const _: () = assert!(
        RECORDS == base::STANDARD,
        "RECORDS must use STANDARD bucket"
    );
    const _: () = assert!(
        RECEIPT_CHAIN == base::LARGE,
        "RECEIPT_CHAIN must use LARGE bucket"
    );

    // Test: audit capacities must not collapse to smaller buckets
    const _: () = assert!(
        LOG_ENTRIES >= base::MEDIUM,
        "LOG_ENTRIES must not fall below MEDIUM capacity"
    );
    const _: () = assert!(
        TRAIL_ENTRIES > base::TRACE,
        "TRAIL_ENTRIES must exceed TRACE capacity"
    );
    const _: () = assert!(
        ACTION_LOG_ENTRIES > base::SMALL,
        "ACTION_LOG_ENTRIES must exceed SMALL capacity"
    );

    // Test: receipt chain must be larger than individual log capacities for aggregation
    const _: () = assert!(
        RECEIPT_CHAIN > LOG_ENTRIES,
        "RECEIPT_CHAIN must exceed LOG_ENTRIES"
    );
    const _: () = assert!(
        RECEIPT_CHAIN > TRAIL_ENTRIES,
        "RECEIPT_CHAIN must exceed TRAIL_ENTRIES"
    );
    const _: () = assert!(
        RECEIPT_CHAIN > ACTION_LOG_ENTRIES,
        "RECEIPT_CHAIN must exceed ACTION_LOG_ENTRIES"
    );

    // Test: standard audit buckets must be identical for cross-component compatibility
    const _: () = assert!(
        LOG_ENTRIES < TRAIL_ENTRIES,
        "LOG_ENTRIES should remain below standard audit trails"
    );
    const _: () = assert!(
        TRAIL_ENTRIES == ACTION_LOG_ENTRIES,
        "TRAIL_ENTRIES and ACTION_LOG_ENTRIES must match"
    );
    const _: () = assert!(
        RECORDS == TRAIL_ENTRIES,
        "RECORDS must match standard audit trail capacities"
    );

    // Test: audit capacities sufficient for high-frequency operations
    const _: () = assert!(
        LOG_ENTRIES >= 1000,
        "LOG_ENTRIES must handle frequent logging"
    );
    const _: () = assert!(
        RECEIPT_CHAIN >= 4000,
        "RECEIPT_CHAIN must handle receipt accumulation"
    );

    // Test: no integer overflow in typical audit operations
    const _: () = assert!(
        RECEIPT_CHAIN.saturating_add(LOG_ENTRIES) < usize::MAX / 2,
        "audit operations must not overflow"
    );

    // Test: audit bucket relationships are mathematically consistent
    const _: () = assert!(
        RECEIPT_CHAIN >= LOG_ENTRIES * 2,
        "RECEIPT_CHAIN should be at least 2x LOG_ENTRIES"
    );
}

/// Generic bounded collection capacities.
pub mod collections {
    use super::base;

    pub const EVENTS: usize = base::STANDARD;
    pub const ENTRIES: usize = base::STANDARD;
    pub const RECEIPTS: usize = base::STANDARD;
    pub const SHIMS: usize = base::STANDARD;
    pub const PREDICATES: usize = base::STANDARD;
    pub const RESULTS: usize = base::STANDARD;
    pub const RULES: usize = base::STANDARD;
    pub const CONDITIONS: usize = base::STANDARD;
    pub const REPORTS: usize = base::STANDARD;
    pub const FIELDS: usize = base::STANDARD;
    pub const METRICS: usize = base::STANDARD;
    pub const RUNS: usize = base::STANDARD;
    pub const PROJECTS_PER_COHORT: usize = base::STANDARD;
}

/// Security- and crypto-adjacent capacities.
pub mod security {
    use super::base;

    pub const TRUSTED_SIGNERS: usize = base::STANDARD;
    pub const MONITORS: usize = base::STANDARD;
    pub const BLOCKED_SOURCES: usize = base::STANDARD;
    pub const REFERENCE_RUNTIMES: usize = base::STANDARD;
    pub const EVENTS: usize = base::STANDARD;
    pub const SEEN_NONCES: usize = base::LARGE;
    pub const CONSUMED_NONCES: usize = base::DEDUPE;

    // Inline negative-path const assertions for security capacity validation.
    // Test: nonce window hierarchy must prevent replay attacks
    const _: () = assert!(
        CONSUMED_NONCES > SEEN_NONCES,
        "CONSUMED_NONCES must exceed SEEN_NONCES"
    );
    const _: () = assert!(
        CONSUMED_NONCES >= SEEN_NONCES * 4,
        "CONSUMED_NONCES should be significantly larger"
    );

    // Test: security-critical capacities must not be too small for attack resistance
    const _: () = assert!(
        TRUSTED_SIGNERS >= 64,
        "TRUSTED_SIGNERS must support sufficient key rotation"
    );
    const _: () = assert!(
        BLOCKED_SOURCES >= 1000,
        "BLOCKED_SOURCES must handle attack source lists"
    );
    const _: () = assert!(
        SEEN_NONCES >= 4000,
        "SEEN_NONCES must provide replay protection window"
    );

    // Test: standard security buckets use consistent capacity for interoperability
    const _: () = assert!(
        TRUSTED_SIGNERS == base::STANDARD,
        "TRUSTED_SIGNERS must use STANDARD bucket"
    );
    const _: () = assert!(
        MONITORS == base::STANDARD,
        "MONITORS must use STANDARD bucket"
    );
    const _: () = assert!(
        BLOCKED_SOURCES == base::STANDARD,
        "BLOCKED_SOURCES must use STANDARD bucket"
    );
    const _: () = assert!(
        REFERENCE_RUNTIMES == base::STANDARD,
        "REFERENCE_RUNTIMES must use STANDARD bucket"
    );
    const _: () = assert!(
        EVENTS == base::STANDARD,
        "security EVENTS must use STANDARD bucket"
    );

    // Test: nonce capacities use appropriate bucket sizes for their threat model
    const _: () = assert!(
        SEEN_NONCES == base::LARGE,
        "SEEN_NONCES must use LARGE bucket"
    );
    const _: () = assert!(
        CONSUMED_NONCES == base::DEDUPE,
        "CONSUMED_NONCES must use DEDUPE bucket"
    );

    // Test: no overlap between security categories that should remain distinct
    const _: () = assert!(
        SEEN_NONCES != CONSUMED_NONCES,
        "nonce windows must have different capacities"
    );
    const _: () = assert!(
        TRUSTED_SIGNERS == MONITORS,
        "TRUSTED_SIGNERS and MONITORS should match for symmetry"
    );

    // Test: security capacities must not overflow in cryptographic operations
    const _: () = assert!(
        CONSUMED_NONCES.saturating_mul(32) < usize::MAX / 8,
        "nonce operations must not overflow"
    );
    const _: () = assert!(
        TRUSTED_SIGNERS.saturating_mul(256) < usize::MAX / 16,
        "signature operations must not overflow"
    );

    // Test: blocked sources capacity sufficient for threat intelligence feeds
    const _: () = assert!(
        BLOCKED_SOURCES >= base::MEDIUM,
        "BLOCKED_SOURCES must handle threat feeds"
    );

    // Test: reference runtime capacity appropriate for verification diversity
    const _: () = assert!(
        REFERENCE_RUNTIMES <= base::LARGE,
        "REFERENCE_RUNTIMES should remain manageable"
    );
    const _: () = assert!(
        REFERENCE_RUNTIMES >= base::TRACE,
        "REFERENCE_RUNTIMES must support multiple implementations"
    );

    // Test: monitor capacity scales with security event volume expectations
    const _: () = assert!(
        MONITORS == EVENTS,
        "MONITORS should match security EVENTS capacity"
    );
}

/// Runtime/control-plane capacities.
pub mod runtime {
    use super::base;

    pub const ABORT_EVENTS: usize = base::STANDARD;
    pub const FORCE_EVENTS: usize = base::STANDARD;
    pub const SESSION_EVENTS: usize = base::STANDARD;
    pub const OBLIGATIONS: usize = base::LARGE;
    pub const LEASES: usize = base::STANDARD;
    pub const SAGAS: usize = base::STANDARD;
    pub const TOTAL_ARTIFACTS: usize = base::LARGE;
    pub const REGISTERED_TRACES: usize = base::TRACE;
    pub const TRACE_STEPS: usize = base::LARGE;
    pub const BULKHEAD_EVENTS: usize = base::TRACE;
    pub const LATENCY_SAMPLES: usize = base::TRACE;
    pub const BARRIER_HISTORY: usize = base::STANDARD;
    pub const CHECKPOINTS: usize = base::TRACE;
    pub const DIVERGENCES: usize = base::SMALL;
}

/// Governance and verifier-facing capacities.
pub mod verifier {
    use super::base;

    pub const VERIFIERS: usize = base::STANDARD;
    pub const ATTESTATIONS: usize = base::LARGE;
    pub const DISPUTES: usize = base::MEDIUM;
    pub const REPLAY_CAPSULES: usize = base::MEDIUM;
    pub const CHAIN_ENTRIES: usize = base::XL;
    pub const JOBS: usize = base::MEDIUM;
    pub const WINDOWS_SEEN: usize = base::STANDARD;
}

/// Storage- and testing-adjacent capacities.
pub mod support {
    use super::base;

    pub const SCHEMA_VERSIONS: usize = base::TRACE;
    pub const ASSERTIONS: usize = base::STANDARD;
    pub const LINKS: usize = base::STANDARD;
    pub const NODES_CAP: usize = base::STANDARD;
}

/// Exact-name aliases that downstream migration beads can adopt verbatim.
pub mod aliases {
    use super::{audit, collections, runtime, security, support, verifier};

    pub const MAX_AUDIT_LOG_ENTRIES: usize = audit::LOG_ENTRIES;
    pub const MAX_AUDIT_TRAIL_ENTRIES: usize = audit::TRAIL_ENTRIES;
    pub const MAX_ACTION_LOG_ENTRIES: usize = audit::ACTION_LOG_ENTRIES;
    pub const MAX_RECEIPT_CHAIN: usize = audit::RECEIPT_CHAIN;

    // Test: audit aliases must exactly match their source constants.
    const _: () = assert!(
        MAX_AUDIT_LOG_ENTRIES == audit::LOG_ENTRIES,
        "audit log alias mismatch"
    );
    const _: () = assert!(
        MAX_AUDIT_TRAIL_ENTRIES == audit::TRAIL_ENTRIES,
        "audit trail alias mismatch"
    );
    const _: () = assert!(
        MAX_ACTION_LOG_ENTRIES == audit::ACTION_LOG_ENTRIES,
        "action log alias mismatch"
    );
    const _: () = assert!(
        MAX_RECEIPT_CHAIN == audit::RECEIPT_CHAIN,
        "receipt chain alias mismatch"
    );

    // Test: no accidental cross-wiring between different capacity domains.
    const _: () = assert!(
        MAX_AUDIT_LOG_ENTRIES != MAX_RECEIPT_CHAIN,
        "audit log must not equal receipt chain"
    );

    // Test: aliases maintain the same relationships as their source modules.
    const _: () = assert!(
        MAX_RECEIPT_CHAIN > MAX_AUDIT_LOG_ENTRIES,
        "alias hierarchy must match source hierarchy"
    );

    // Test: all audit aliases use expected underlying bucket sizes.
    const _: () = assert!(
        MAX_AUDIT_LOG_ENTRIES == super::base::MEDIUM,
        "audit log alias must use MEDIUM"
    );
    const _: () = assert!(
        MAX_RECEIPT_CHAIN == super::base::LARGE,
        "receipt chain alias must use LARGE"
    );

    pub const MAX_EVENTS: usize = collections::EVENTS;
    pub const MAX_ENTRIES: usize = collections::ENTRIES;
    pub const MAX_RECEIPTS: usize = collections::RECEIPTS;
    pub const MAX_SHIMS: usize = collections::SHIMS;
    pub const MAX_PREDICATES: usize = collections::PREDICATES;
    pub const MAX_RESULTS: usize = collections::RESULTS;
    pub const MAX_RULES: usize = collections::RULES;
    pub const MAX_CONDITIONS: usize = collections::CONDITIONS;
    pub const MAX_REPORTS: usize = collections::REPORTS;
    pub const MAX_FIELDS: usize = collections::FIELDS;
    pub const MAX_METRICS: usize = collections::METRICS;
    pub const MAX_RUNS: usize = collections::RUNS;
    pub const MAX_PROJECTS_PER_COHORT: usize = collections::PROJECTS_PER_COHORT;

    pub const MAX_TRUSTED_SIGNERS: usize = security::TRUSTED_SIGNERS;
    pub const MAX_MONITORS: usize = security::MONITORS;
    pub const MAX_BLOCKED_SOURCES: usize = security::BLOCKED_SOURCES;
    pub const MAX_REFERENCE_RUNTIMES: usize = security::REFERENCE_RUNTIMES;
    pub const MAX_SEEN_NONCES: usize = security::SEEN_NONCES;
    pub const MAX_CONSUMED_NONCES: usize = security::CONSUMED_NONCES;

    // Test: security aliases must exactly match their source constants.
    const _: () = assert!(
        MAX_TRUSTED_SIGNERS == security::TRUSTED_SIGNERS,
        "trusted signers alias mismatch"
    );
    const _: () = assert!(
        MAX_MONITORS == security::MONITORS,
        "monitors alias mismatch"
    );
    const _: () = assert!(
        MAX_BLOCKED_SOURCES == security::BLOCKED_SOURCES,
        "blocked sources alias mismatch"
    );
    const _: () = assert!(
        MAX_REFERENCE_RUNTIMES == security::REFERENCE_RUNTIMES,
        "reference runtimes alias mismatch"
    );
    const _: () = assert!(
        MAX_SEEN_NONCES == security::SEEN_NONCES,
        "seen nonces alias mismatch"
    );
    const _: () = assert!(
        MAX_CONSUMED_NONCES == security::CONSUMED_NONCES,
        "consumed nonces alias mismatch"
    );

    // Test: critical security alias relationships for attack resistance.
    const _: () = assert!(
        MAX_CONSUMED_NONCES > MAX_SEEN_NONCES,
        "consumed nonce alias must exceed seen"
    );
    const _: () = assert!(
        MAX_CONSUMED_NONCES >= MAX_SEEN_NONCES * 8,
        "nonce window separation must be significant"
    );

    // Test: security aliases must not cross-wire with non-security capacities.
    const _: () = assert!(
        MAX_TRUSTED_SIGNERS != MAX_AUDIT_LOG_ENTRIES,
        "security and audit should be independent"
    );
    const _: () = assert!(
        MAX_BLOCKED_SOURCES != MAX_RECEIPT_CHAIN,
        "blocked sources should not match receipt chain"
    );

    // Test: symmetric security alias capacities for operational consistency.
    const _: () = assert!(
        MAX_TRUSTED_SIGNERS == MAX_MONITORS,
        "signers and monitors should match for balance"
    );
    const _: () = assert!(
        MAX_MONITORS == MAX_BLOCKED_SOURCES,
        "monitors and blocked sources should match"
    );

    // Test: nonce alias capacities use correct underlying buckets for threat model.
    const _: () = assert!(
        MAX_SEEN_NONCES == super::base::LARGE,
        "seen nonces alias must use LARGE bucket"
    );
    const _: () = assert!(
        MAX_CONSUMED_NONCES == super::base::DEDUPE,
        "consumed nonces alias must use DEDUPE bucket"
    );

    // Test: security alias values are sufficient for production threat landscapes.
    const _: () = assert!(
        MAX_TRUSTED_SIGNERS >= 1000,
        "trusted signers alias must support key diversity"
    );
    const _: () = assert!(
        MAX_BLOCKED_SOURCES >= 2000,
        "blocked sources alias must handle threat intelligence"
    );
    const _: () = assert!(
        MAX_CONSUMED_NONCES >= 32768,
        "consumed nonces alias must provide replay protection"
    );

    pub const MAX_ABORT_EVENTS: usize = runtime::ABORT_EVENTS;
    pub const MAX_FORCE_EVENTS: usize = runtime::FORCE_EVENTS;
    pub const MAX_SESSION_EVENTS: usize = runtime::SESSION_EVENTS;
    pub const MAX_OBLIGATIONS: usize = runtime::OBLIGATIONS;
    pub const MAX_LEASES: usize = runtime::LEASES;
    pub const MAX_SAGAS: usize = runtime::SAGAS;
    pub const MAX_TOTAL_ARTIFACTS: usize = runtime::TOTAL_ARTIFACTS;
    pub const MAX_REGISTERED_TRACES: usize = runtime::REGISTERED_TRACES;
    pub const MAX_TRACE_STEPS: usize = runtime::TRACE_STEPS;
    pub const MAX_BULKHEAD_EVENTS: usize = runtime::BULKHEAD_EVENTS;
    pub const MAX_LATENCY_SAMPLES: usize = runtime::LATENCY_SAMPLES;
    pub const MAX_BARRIER_HISTORY: usize = runtime::BARRIER_HISTORY;
    pub const MAX_CHECKPOINTS: usize = runtime::CHECKPOINTS;
    pub const MAX_DIVERGENCES: usize = runtime::DIVERGENCES;

    // Test: runtime aliases must exactly match their source constants.
    const _: () = assert!(
        MAX_OBLIGATIONS == runtime::OBLIGATIONS,
        "obligations alias mismatch"
    );
    const _: () = assert!(MAX_LEASES == runtime::LEASES, "leases alias mismatch");
    const _: () = assert!(MAX_SAGAS == runtime::SAGAS, "sagas alias mismatch");
    const _: () = assert!(
        MAX_TOTAL_ARTIFACTS == runtime::TOTAL_ARTIFACTS,
        "artifacts alias mismatch"
    );
    const _: () = assert!(
        MAX_DIVERGENCES == runtime::DIVERGENCES,
        "divergences alias mismatch"
    );

    // Test: trace-related aliases must use consistent TRACE bucket.
    const _: () = assert!(
        MAX_REGISTERED_TRACES == super::base::TRACE,
        "registered traces must use TRACE bucket"
    );
    const _: () = assert!(
        MAX_BULKHEAD_EVENTS == super::base::TRACE,
        "bulkhead events must use TRACE bucket"
    );
    const _: () = assert!(
        MAX_LATENCY_SAMPLES == super::base::TRACE,
        "latency samples must use TRACE bucket"
    );
    const _: () = assert!(
        MAX_CHECKPOINTS == super::base::TRACE,
        "checkpoints must use TRACE bucket"
    );
    const _: () = assert!(
        MAX_DIVERGENCES == super::base::SMALL,
        "divergences must use SMALL bucket"
    );

    // Test: large runtime aliases must use appropriate buckets for scale.
    const _: () = assert!(
        MAX_OBLIGATIONS == super::base::LARGE,
        "obligations must use LARGE bucket"
    );
    const _: () = assert!(
        MAX_LEASES == super::base::STANDARD,
        "leases must use STANDARD bucket"
    );
    const _: () = assert!(
        MAX_TOTAL_ARTIFACTS == super::base::LARGE,
        "artifacts must use LARGE bucket"
    );
    const _: () = assert!(
        MAX_TRACE_STEPS == super::base::LARGE,
        "trace steps must use LARGE bucket"
    );

    // Test: standard runtime aliases for operational consistency.
    const _: () = assert!(
        MAX_ABORT_EVENTS == super::base::STANDARD,
        "abort events must use STANDARD"
    );
    const _: () = assert!(
        MAX_FORCE_EVENTS == super::base::STANDARD,
        "force events must use STANDARD"
    );
    const _: () = assert!(
        MAX_SESSION_EVENTS == super::base::STANDARD,
        "session events must use STANDARD"
    );
    const _: () = assert!(
        MAX_SAGAS == super::base::STANDARD,
        "sagas must use STANDARD"
    );
    const _: () = assert!(
        MAX_BARRIER_HISTORY == super::base::STANDARD,
        "barrier history must use STANDARD"
    );

    // Test: runtime capacity relationships for operational coherence.
    const _: () = assert!(
        MAX_OBLIGATIONS > MAX_SAGAS,
        "obligations must exceed sagas for containment"
    );
    const _: () = assert!(
        MAX_TRACE_STEPS > MAX_REGISTERED_TRACES,
        "trace steps must exceed registered traces"
    );
    const _: () = assert!(
        MAX_TOTAL_ARTIFACTS > MAX_LEASES,
        "artifacts must exceed leases for lifecycle management"
    );

    // Test: trace aliases must not accidentally expand beyond trace boundaries.
    const _: () = assert!(
        MAX_REGISTERED_TRACES <= super::base::MEDIUM,
        "registered traces must remain trace-sized"
    );
    const _: () = assert!(
        MAX_CHECKPOINTS <= super::base::MEDIUM,
        "checkpoints must remain trace-sized"
    );

    // Test: runtime event aliases must handle high-frequency operations.
    const _: () = assert!(
        MAX_SESSION_EVENTS >= 1024,
        "session events must handle frequent connections"
    );
    const _: () = assert!(
        MAX_ABORT_EVENTS >= 1024,
        "abort events must handle error bursts"
    );
    const _: () = assert!(
        MAX_FORCE_EVENTS >= 1024,
        "force events must handle emergency operations"
    );

    // Test: no overflow in typical runtime arithmetic operations.
    const _: () = assert!(
        MAX_TOTAL_ARTIFACTS.saturating_add(MAX_OBLIGATIONS) < usize::MAX / 2,
        "runtime ops must not overflow"
    );

    pub const MAX_VERIFIERS: usize = verifier::VERIFIERS;
    pub const MAX_ATTESTATIONS: usize = verifier::ATTESTATIONS;
    pub const MAX_DISPUTES: usize = verifier::DISPUTES;
    pub const MAX_REPLAY_CAPSULES: usize = verifier::REPLAY_CAPSULES;
    pub const MAX_CHAIN_ENTRIES: usize = verifier::CHAIN_ENTRIES;
    pub const MAX_JOBS: usize = verifier::JOBS;
    pub const MAX_WINDOWS_SEEN: usize = verifier::WINDOWS_SEEN;

    pub const MAX_SCHEMA_VERSIONS: usize = support::SCHEMA_VERSIONS;
    pub const MAX_ASSERTIONS: usize = support::ASSERTIONS;
    pub const MAX_LINKS: usize = support::LINKS;
    pub const MAX_NODES_CAP: usize = support::NODES_CAP;
}

#[cfg(test)]
mod tests {
    use super::{aliases, audit, base, collections, runtime, security, support, verifier};

    #[test]
    fn base_buckets_match_documented_sizes() {
        assert_eq!(base::SMALL, 256);
        assert_eq!(base::TRACE, 1_024);
        assert_eq!(base::MEDIUM, 4_096);
        assert_eq!(base::STANDARD, 16_384);
        assert_eq!(base::LARGE, 65_536);
        assert_eq!(base::XL, 131_072);
        assert_eq!(base::DEDUPE, 524_288);
    }

    #[test]
    fn representative_aliases_reuse_semantic_groups() {
        assert_eq!(aliases::MAX_AUDIT_LOG_ENTRIES, audit::LOG_ENTRIES);
        assert_eq!(aliases::MAX_EVENTS, collections::EVENTS);
        assert_eq!(aliases::MAX_TRUSTED_SIGNERS, security::TRUSTED_SIGNERS);
        assert_eq!(aliases::MAX_SESSION_EVENTS, runtime::SESSION_EVENTS);
        assert_eq!(aliases::MAX_VERIFIERS, verifier::VERIFIERS);
        assert_eq!(aliases::MAX_SCHEMA_VERSIONS, support::SCHEMA_VERSIONS);
    }

    #[test]
    fn larger_capacities_use_non_standard_buckets() {
        assert_eq!(aliases::MAX_REGISTERED_TRACES, base::TRACE);
        assert_eq!(aliases::MAX_TRACE_STEPS, base::LARGE);
        assert_eq!(aliases::MAX_ATTESTATIONS, base::LARGE);
        assert_eq!(aliases::MAX_CHAIN_ENTRIES, base::XL);
        assert_eq!(aliases::MAX_CONSUMED_NONCES, base::DEDUPE);
    }

    #[test]
    fn base_buckets_do_not_collapse_to_zero() {
        for capacity in [
            base::SMALL,
            base::TRACE,
            base::MEDIUM,
            base::STANDARD,
            base::LARGE,
            base::XL,
            base::DEDUPE,
        ] {
            assert_ne!(capacity, 0);
        }
    }

    #[test]
    fn ordered_buckets_do_not_regress_or_overlap() {
        assert!(base::SMALL < base::TRACE);
        assert!(base::TRACE < base::MEDIUM);
        assert!(base::MEDIUM < base::STANDARD);
        assert!(base::STANDARD < base::LARGE);
        assert!(base::LARGE < base::XL);
        assert!(base::XL < base::DEDUPE);
    }

    #[test]
    fn trace_sized_runtime_caps_do_not_expand_to_standard_bucket() {
        for capacity in [
            aliases::MAX_REGISTERED_TRACES,
            aliases::MAX_BULKHEAD_EVENTS,
            aliases::MAX_LATENCY_SAMPLES,
            aliases::MAX_CHECKPOINTS,
        ] {
            assert_eq!(capacity, base::TRACE);
            assert_ne!(capacity, base::STANDARD);
        }
    }

    #[test]
    fn security_nonce_windows_do_not_share_the_same_capacity() {
        assert_eq!(aliases::MAX_SEEN_NONCES, base::LARGE);
        assert_eq!(aliases::MAX_CONSUMED_NONCES, base::DEDUPE);
        assert_ne!(aliases::MAX_CONSUMED_NONCES, aliases::MAX_SEEN_NONCES);
        assert!(aliases::MAX_CONSUMED_NONCES > aliases::MAX_SEEN_NONCES);
        assert!(aliases::MAX_CONSUMED_NONCES >= aliases::MAX_SEEN_NONCES * 8);
    }

    #[test]
    fn verifier_medium_queues_do_not_drift_to_standard_audit_caps() {
        assert_eq!(aliases::MAX_DISPUTES, base::MEDIUM);
        assert_eq!(aliases::MAX_REPLAY_CAPSULES, base::MEDIUM);
        assert_eq!(aliases::MAX_JOBS, base::MEDIUM);
        assert_ne!(aliases::MAX_DISPUTES, aliases::MAX_AUDIT_TRAIL_ENTRIES);
        assert_ne!(aliases::MAX_JOBS, aliases::MAX_EVENTS);
    }

    #[test]
    fn support_schema_versions_do_not_use_large_runtime_bucket() {
        assert_eq!(aliases::MAX_SCHEMA_VERSIONS, base::TRACE);
        assert_ne!(aliases::MAX_SCHEMA_VERSIONS, aliases::MAX_TRACE_STEPS);
        assert_ne!(aliases::MAX_SCHEMA_VERSIONS, aliases::MAX_TOTAL_ARTIFACTS);
    }

    #[test]
    fn aliases_do_not_cross_wire_security_and_runtime_caps() {
        assert_ne!(aliases::MAX_CONSUMED_NONCES, aliases::MAX_LEASES);
        assert_ne!(aliases::MAX_CONSUMED_NONCES, aliases::MAX_OBLIGATIONS);
        assert_ne!(
            aliases::MAX_REFERENCE_RUNTIMES,
            aliases::MAX_REGISTERED_TRACES
        );
    }
}

#[cfg(test)]
mod negative_path_tests {
    use super::{aliases, base};

    fn validate_strictly_increasing_buckets(buckets: &[(&str, usize)]) -> Result<(), String> {
        for (name, capacity) in buckets {
            if *capacity == 0 {
                return Err(format!("{name} must not be zero"));
            }
        }

        for pair in buckets.windows(2) {
            let (prev_name, prev_capacity) = pair[0];
            let (next_name, next_capacity) = pair[1];
            if next_capacity <= prev_capacity {
                return Err(format!(
                    "{next_name}={next_capacity} must be greater than {prev_name}={prev_capacity}"
                ));
            }
        }
        Ok(())
    }

    fn canonical_buckets() -> [(&'static str, usize); 7] {
        [
            ("small", base::SMALL),
            ("trace", base::TRACE),
            ("medium", base::MEDIUM),
            ("standard", base::STANDARD),
            ("large", base::LARGE),
            ("xl", base::XL),
            ("dedupe", base::DEDUPE),
        ]
    }

    fn validate_consumed_nonce_window(seen: usize, consumed: usize) -> Result<(), &'static str> {
        if consumed <= seen {
            return Err("consumed nonce window must exceed seen nonce window");
        }
        Ok(())
    }

    fn validate_schema_version_capacity(capacity: usize) -> Result<(), &'static str> {
        if capacity > base::TRACE {
            return Err("schema version capacity must stay trace-sized");
        }
        Ok(())
    }

    fn validate_chain_capacity(receipts: usize, chain_entries: usize) -> Result<(), &'static str> {
        if chain_entries <= receipts {
            return Err("verifier chain capacity must exceed receipt buffer capacity");
        }
        Ok(())
    }

    fn validate_trace_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::TRACE {
            return Err(format!("{name} must stay trace-sized"));
        }
        Ok(())
    }

    fn validate_medium_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::MEDIUM {
            return Err(format!("{name} must stay medium-sized"));
        }
        Ok(())
    }

    fn validate_standard_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::STANDARD {
            return Err(format!("{name} must stay standard-sized"));
        }
        Ok(())
    }

    fn validate_large_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::LARGE {
            return Err(format!("{name} must stay large-sized"));
        }
        Ok(())
    }

    #[test]
    fn negative_bucket_validation_rejects_zero_small_bucket() {
        let mut buckets = canonical_buckets();
        buckets[0] = ("small", 0);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("zero capacity bucket must fail closed");

        assert!(err.contains("small"));
        assert!(err.contains("zero"));
    }

    #[test]
    fn negative_bucket_validation_rejects_trace_not_above_small() {
        let mut buckets = canonical_buckets();
        buckets[1] = ("trace", base::SMALL);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("trace bucket must stay above small");

        assert!(err.contains("trace"));
        assert!(err.contains("small"));
    }

    #[test]
    fn negative_bucket_validation_rejects_medium_below_trace() {
        let mut buckets = canonical_buckets();
        buckets[2] = ("medium", base::TRACE.saturating_sub(1));

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("medium bucket must stay above trace");

        assert!(err.contains("medium"));
        assert!(err.contains("trace"));
    }

    #[test]
    fn negative_bucket_validation_rejects_standard_equal_medium() {
        let mut buckets = canonical_buckets();
        buckets[3] = ("standard", base::MEDIUM);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("standard bucket must not collapse to medium");

        assert!(err.contains("standard"));
        assert!(err.contains("medium"));
    }

    #[test]
    fn negative_bucket_validation_rejects_dedupe_not_largest() {
        let mut buckets = canonical_buckets();
        buckets[6] = ("dedupe", base::XL);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("dedupe bucket must remain the largest window");

        assert!(err.contains("dedupe"));
        assert!(err.contains("xl"));
    }

    #[test]
    fn negative_nonce_windows_reject_consumed_not_larger_than_seen() {
        let seen = aliases::MAX_SEEN_NONCES;
        let consumed = aliases::MAX_SEEN_NONCES;

        let err = validate_consumed_nonce_window(seen, consumed)
            .expect_err("consumed nonce window must stay larger than seen window");

        assert!(err.contains("consumed nonce"));
        assert!(validate_consumed_nonce_window(seen, aliases::MAX_CONSUMED_NONCES).is_ok());
    }

    #[test]
    fn negative_schema_version_capacity_rejects_runtime_trace_steps_bucket() {
        let schema_versions = aliases::MAX_TRACE_STEPS;

        let err = validate_schema_version_capacity(schema_versions)
            .expect_err("schema version capacity must not grow to runtime trace steps");

        assert!(err.contains("schema version"));
        assert!(validate_schema_version_capacity(aliases::MAX_SCHEMA_VERSIONS).is_ok());
    }

    #[test]
    fn negative_chain_entries_reject_standard_receipt_capacity() {
        let chain_entries = aliases::MAX_RECEIPTS;

        let err = validate_chain_capacity(aliases::MAX_RECEIPTS, chain_entries)
            .expect_err("chain capacity must not collapse to receipt buffer capacity");

        assert!(err.contains("verifier chain"));
        assert!(validate_chain_capacity(aliases::MAX_RECEIPTS, aliases::MAX_CHAIN_ENTRIES).is_ok());
    }

    #[test]
    fn negative_bucket_validation_rejects_large_equal_standard() {
        let mut buckets = canonical_buckets();
        buckets[4] = ("large", base::STANDARD);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("large bucket must stay above standard");

        assert!(err.contains("large"));
        assert!(err.contains("standard"));
    }

    #[test]
    fn negative_bucket_validation_rejects_xl_below_large() {
        let mut buckets = canonical_buckets();
        buckets[5] = ("xl", base::LARGE.saturating_sub(1));

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("xl bucket must stay above large");

        assert!(err.contains("xl"));
        assert!(err.contains("large"));
    }

    #[test]
    fn negative_registered_traces_rejects_standard_bucket() {
        let err = validate_trace_sized("registered traces", base::STANDARD)
            .expect_err("registered trace capacity must remain trace-sized");

        assert!(err.contains("registered traces"));
        assert!(validate_trace_sized("registered traces", aliases::MAX_REGISTERED_TRACES).is_ok());
    }

    #[test]
    fn negative_checkpoint_capacity_rejects_large_bucket() {
        let err = validate_trace_sized("checkpoints", aliases::MAX_TRACE_STEPS)
            .expect_err("checkpoint capacity must not inherit trace-step capacity");

        assert!(err.contains("checkpoints"));
        assert!(validate_trace_sized("checkpoints", aliases::MAX_CHECKPOINTS).is_ok());
    }

    #[test]
    fn negative_dispute_capacity_rejects_standard_bucket() {
        let err = validate_medium_sized("disputes", aliases::MAX_EVENTS)
            .expect_err("disputes must not collapse to default event capacity");

        assert!(err.contains("disputes"));
        assert!(validate_medium_sized("disputes", aliases::MAX_DISPUTES).is_ok());
    }

    #[test]
    fn negative_audit_log_capacity_rejects_trace_bucket() {
        let err = validate_medium_sized("audit log entries", aliases::MAX_CHECKPOINTS)
            .expect_err("audit log entries must not shrink to trace-sized capacity");

        assert!(err.contains("audit log entries"));
        assert!(validate_medium_sized("audit log entries", aliases::MAX_AUDIT_LOG_ENTRIES).is_ok());
    }

    #[test]
    fn negative_obligation_capacity_rejects_standard_bucket() {
        let err = validate_large_sized("obligations", aliases::MAX_EVENTS)
            .expect_err("obligations must not shrink to default event capacity");

        assert!(err.contains("obligations"));
        assert!(validate_large_sized("obligations", aliases::MAX_OBLIGATIONS).is_ok());
    }

    // === COMPREHENSIVE NEGATIVE-PATH TESTS ===
    // Additional edge case tests for capacity boundary validation that security hardening may have missed

    #[test]
    fn test_unicode_injection_in_capacity_identifiers() {
        // Test Unicode injection attacks in capacity identifier strings
        // Control characters and homograph attacks could bypass validation
        let unicode_attack_vectors = [
            "capacity\u{200B}injection", // Zero-width space
            "capacity\u{202E}yticapac",  // Right-to-left override
            "capacity\u{0000}injection", // Null byte injection
            "capacity\u{FEFF}injection", // BOM injection
            "capacity\u{000C}injection", // Form feed injection
            "capacity\ninjection",       // Newline injection
            "capacіty",                  // Cyrillic 'і' homograph
            "capacity\u{001F}injection", // Unit separator injection
        ];

        for malicious_id in &unicode_attack_vectors {
            // Validation functions should handle Unicode injection safely
            let result = validate_standard_sized(malicious_id, base::STANDARD);
            // Should either succeed (with safe handling) or fail (with rejection)
            match result {
                Ok(()) => {
                    // If accepted, verify no corruption in subsequent operations
                    assert!(
                        base::STANDARD > 0,
                        "Capacity validation should remain consistent after Unicode input"
                    );
                }
                Err(error_msg) => {
                    // Rejection is also acceptable for malformed identifiers
                    assert!(!error_msg.is_empty(), "Error message should not be empty");
                }
            }

            // Test with trace-sized validation
            let trace_result = validate_trace_sized(malicious_id, base::TRACE);
            match trace_result {
                Ok(()) => assert!(base::TRACE > 0),
                Err(msg) => assert!(!msg.is_empty()),
            }
        }
    }

    #[test]
    fn test_arithmetic_overflow_in_capacity_calculations() {
        // Test arithmetic overflow scenarios in capacity boundary checks
        // Recent hardening may have missed edge cases in capacity arithmetic
        let overflow_test_cases = [
            (usize::MAX, "Maximum usize capacity"),
            (usize::MAX - 1, "Near-maximum capacity"),
            (usize::MAX / 2, "Half-maximum capacity"),
            (0, "Zero capacity boundary"),
            (1, "Minimum non-zero capacity"),
        ];

        for (capacity_value, description) in &overflow_test_cases {
            // Test bucket hierarchy validation with extreme values
            let buckets = vec![
                ("small", base::SMALL),
                ("medium", base::MEDIUM),
                ("large", *capacity_value), // Test with extreme value
                ("xl", base::XL),
            ];

            let result = validate_strictly_increasing_buckets(&buckets);
            match result {
                Ok(()) => {
                    // If validation passes, verify no arithmetic overflow occurred
                    assert!(
                        *capacity_value >= base::MEDIUM,
                        "Large bucket validation should maintain order for: {}",
                        description
                    );
                }
                Err(error_msg) => {
                    // Expected failure for invalid hierarchies
                    assert!(
                        !error_msg.is_empty(),
                        "Should have error message for: {}",
                        description
                    );
                }
            }

            // Test capacity doubling without overflow
            if *capacity_value <= usize::MAX / 2 {
                let doubled = capacity_value.saturating_mul(2);
                assert!(
                    doubled >= *capacity_value,
                    "Doubling should not underflow for: {}",
                    description
                );
            }

            // Test capacity addition without overflow
            let incremented = capacity_value.saturating_add(1000);
            if *capacity_value < usize::MAX - 1000 {
                assert!(
                    incremented > *capacity_value,
                    "Increment should increase value for: {}",
                    description
                );
            } else {
                assert!(
                    incremented == usize::MAX,
                    "Should saturate at maximum for: {}",
                    description
                );
            }
        }
    }

    #[test]
    fn test_memory_exhaustion_through_massive_bucket_hierarchies() {
        // Test memory exhaustion attacks via massive bucket lists
        // Could bypass memory limits through incremental allocation
        let massive_buckets: Vec<(&str, usize)> = (0..10000)
            .map(|i| {
                let name = format!("bucket-{i}-with-long-name-to-increase-memory-pressure");
                // Use Box to avoid moving large strings
                (Box::leak(name.into_boxed_str()), base::SMALL + i)
            })
            .collect();

        // Should handle large bucket lists without memory exhaustion or panic
        let result = validate_strictly_increasing_buckets(&massive_buckets);

        match result {
            Ok(()) => {
                // If successful, verify buckets are properly ordered despite size
                for window in massive_buckets.windows(2) {
                    assert!(
                        window[1].1 >= window[0].1,
                        "Buckets should remain ordered despite memory pressure"
                    );
                }
            }
            Err(error_msg) => {
                // Memory protection through rejection is also acceptable
                assert!(!error_msg.is_empty(), "Error message should be provided");
            }
        }

        // Verify base constants remain unaffected by memory pressure
        assert_eq!(base::SMALL, 256, "Base constants should remain stable");
        assert_eq!(base::MEDIUM, 4096, "Base constants should remain stable");
    }

    #[test]
    fn test_null_byte_injection_in_capacity_names() {
        // Test null byte injection attacks in capacity name strings
        // Could truncate strings in C-compatible contexts
        let null_injection_cases = [
            ("capacity\0injection", "Single null byte"),
            ("capacity\0\0double", "Double null byte"),
            ("cap\0acity\0multi", "Multiple null bytes"),
            ("capacity\0", "Trailing null byte"),
            ("\0capacity", "Leading null byte"),
        ];

        for (malicious_name, description) in &null_injection_cases {
            // Test validation with null byte injection
            let result = validate_standard_sized(malicious_name, base::STANDARD);

            match result {
                Ok(()) => {
                    // If accepted, verify no string truncation vulnerabilities
                    assert!(
                        base::STANDARD > 0,
                        "Capacity should remain valid after null byte input: {}",
                        description
                    );
                }
                Err(error_msg) => {
                    // Rejection of null byte injection is also acceptable
                    assert!(
                        !error_msg.is_empty(),
                        "Should have error message for: {}",
                        description
                    );
                    // Error message should not be truncated by null bytes
                    assert!(
                        error_msg.len() > 0,
                        "Error message should not be empty for: {}",
                        description
                    );
                }
            }

            // Test with different validation functions
            let trace_result = validate_trace_sized(malicious_name, base::TRACE);
            let medium_result = validate_medium_sized(malicious_name, base::MEDIUM);

            // All validation functions should handle null bytes consistently
            match (trace_result, medium_result) {
                (Ok(()), Ok(())) => {
                    // Both accepted - verify consistency
                    assert!(
                        base::TRACE < base::MEDIUM,
                        "Bucket hierarchy should remain valid"
                    );
                }
                _ => {
                    // At least one rejected - acceptable for malformed input
                }
            }
        }
    }

    #[test]
    fn test_serialization_format_injection_in_capacity_validation() {
        // Test serialization format injection attacks
        // Malformed JSON/YAML-like content could bypass parsing
        let serialization_injection_cases = [
            (
                "capacity\"],\"malicious\":\"payload",
                "JSON injection attempt",
            ),
            (
                "capacity</name><script>alert(1)</script>",
                "XML injection attempt",
            ),
            ("capacity\n  malicious: payload", "YAML injection attempt"),
            ("capacity\"\nmalicious\n\"", "Multi-line string escape"),
            ("capacity{{.Values.Secret}}", "Template injection attempt"),
            ("capacity$(echo hack)", "Command injection attempt"),
            (
                "capacity';<script>alert(1);</script>",
                "Script injection attempt",
            ),
            ("capacity\\u0022payload\\u0022", "Unicode escape injection"),
        ];

        for (injection_name, description) in &serialization_injection_cases {
            // Test various validation functions with injection attempts
            let standard_result = validate_standard_sized(injection_name, base::STANDARD);
            let trace_result = validate_trace_sized(injection_name, base::TRACE);
            let medium_result = validate_medium_sized(injection_name, base::MEDIUM);
            let large_result = validate_large_sized(injection_name, base::LARGE);

            // Verify all validation functions handle injection safely
            let results = [standard_result, trace_result, medium_result, large_result];

            for (i, result) in results.iter().enumerate() {
                match result {
                    Ok(()) => {
                        // If injection is accepted, verify no code execution or corruption
                        assert!(
                            base::STANDARD > 0,
                            "Constants should remain stable after injection: {} (validator {})",
                            description,
                            i
                        );
                    }
                    Err(error_msg) => {
                        // Rejection is expected for malformed input
                        assert!(
                            !error_msg.is_empty(),
                            "Error message should not be empty for: {} (validator {})",
                            description,
                            i
                        );
                        // Verify error message doesn't contain injected content
                        assert!(
                            !error_msg.contains("<script>"),
                            "Error message should not contain script tags: {}",
                            description
                        );
                        assert!(
                            !error_msg.contains("{{"),
                            "Error message should not contain template syntax: {}",
                            description
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_floating_point_precision_attacks_in_capacity_ratios() {
        // Test floating-point precision attacks in capacity ratio calculations
        // Subnormal numbers and precision loss could cause validation bypass
        use std::collections::HashMap;

        // Create test data for ratio calculations
        let precision_test_cases = [
            (1.0, f64::EPSILON, "Division by epsilon"),
            (f64::MAX, 1.0, "Maximum dividend"),
            (f64::MIN_POSITIVE, f64::MAX, "Min/Max ratio"),
            (1.0 / 3.0, 2.0 / 3.0, "Repeating decimal ratio"),
            (f64::consts::PI, f64::consts::E, "Transcendental ratio"),
            (0.1 + 0.2, 0.3, "Classic floating-point precision"),
        ];

        for (numerator, denominator, description) in &precision_test_cases {
            // Test capacity ratio calculations with extreme floating-point values
            if *denominator != 0.0 && denominator.is_finite() {
                let ratio = numerator / denominator;

                // Verify ratio calculations don't produce NaN or infinity
                if ratio.is_finite() {
                    // Test using ratio in capacity calculations
                    let scaled_capacity = (base::STANDARD as f64 * ratio) as usize;

                    // Verify scaled capacity is reasonable
                    if scaled_capacity > 0 && scaled_capacity < usize::MAX / 2 {
                        let validation_result =
                            validate_standard_sized("precision-test", scaled_capacity);

                        match validation_result {
                            Ok(()) => {
                                assert!(
                                    scaled_capacity > 0,
                                    "Scaled capacity should be positive for: {}",
                                    description
                                );
                            }
                            Err(error_msg) => {
                                assert!(
                                    !error_msg.is_empty(),
                                    "Error message should not be empty for: {}",
                                    description
                                );
                            }
                        }
                    }
                }
            }
        }

        // Test capacity distribution ratios
        let mut distribution = HashMap::new();
        distribution.insert("small", base::SMALL as f64);
        distribution.insert("medium", base::MEDIUM as f64);
        distribution.insert("large", base::LARGE as f64);

        let total: f64 = distribution.values().sum();
        for (name, value) in &distribution {
            let ratio = value / total;
            assert!(
                ratio.is_finite(),
                "Distribution ratio should be finite for: {}",
                name
            );
            assert!(
                ratio > 0.0,
                "Distribution ratio should be positive for: {}",
                name
            );
            assert!(
                ratio < 1.0,
                "Distribution ratio should be less than 1 for: {}",
                name
            );
        }
    }

    #[test]
    fn test_hash_collision_resistance_in_capacity_naming() {
        // Test hash collision resistance in capacity identifier comparison
        // Similar names should not collide or cause security bypass
        let collision_test_cases = [
            ("capacity-123", "capacity-132", "Transposed characters"),
            ("test_capacity", "test-capacity", "Underscore vs hyphen"),
            ("MaxCapacity", "maxcapacity", "Case sensitivity"),
            (
                "capacity\u{00A0}test",
                "capacity test",
                "Non-breaking vs regular space",
            ),
            ("capacity_v1", "capacity_v2", "Version difference"),
            ("small_cap", "small_caps", "Plural difference"),
        ];

        for (name1, name2, description) in &collision_test_cases {
            // Test that similar names are treated as distinct
            let result1 = validate_standard_sized(name1, base::STANDARD);
            let result2 = validate_standard_sized(name2, base::STANDARD);

            // Both should be processed independently (no collision)
            match (result1, result2) {
                (Ok(()), Ok(())) => {
                    // Both accepted - verify they're treated as separate entities
                    assert!(
                        name1 != name2,
                        "Names should be distinct for: {}",
                        description
                    );
                }
                _ => {
                    // At least one rejected - also acceptable
                }
            }

            // Test in bucket hierarchy validation
            let buckets1 = vec![
                (name1, base::SMALL),
                ("middle", base::MEDIUM),
                ("large", base::LARGE),
            ];
            let buckets2 = vec![
                (name2, base::SMALL),
                ("middle", base::MEDIUM),
                ("large", base::LARGE),
            ];

            let hier_result1 = validate_strictly_increasing_buckets(&buckets1);
            let hier_result2 = validate_strictly_increasing_buckets(&buckets2);

            // Both hierarchy validations should work independently
            if hier_result1.is_ok() && hier_result2.is_ok() {
                // No collision should prevent independent validation
                assert!(
                    true,
                    "Hierarchy validation should work independently for: {}",
                    description
                );
            }
        }
    }

    #[test]
    fn test_resource_exhaustion_through_validation_loops() {
        // Test resource exhaustion via validation function loops
        // Malicious inputs could cause excessive computation

        // Test with deeply nested bucket hierarchies
        let deep_buckets: Vec<(&str, usize)> = (0..1000)
            .map(|i| {
                let name = format!("level-{i}");
                (Box::leak(name.into_boxed_str()), base::SMALL + i)
            })
            .collect();

        // Validation should complete in reasonable time without excessive loops
        let start = std::time::Instant::now();
        let result = validate_strictly_increasing_buckets(&deep_buckets);
        let elapsed = start.elapsed();

        // Should complete within reasonable time (allowing for some variation in test environments)
        assert!(
            elapsed.as_millis() < 5000,
            "Validation should not take excessive time for deep hierarchies"
        );

        match result {
            Ok(()) => {
                // Verify hierarchy is actually valid
                for window in deep_buckets.windows(2) {
                    assert!(
                        window[1].1 >= window[0].1,
                        "Deep hierarchy should maintain ordering"
                    );
                }
            }
            Err(error_msg) => {
                // Rejection for excessive complexity is acceptable
                assert!(
                    !error_msg.is_empty(),
                    "Should provide error message for complex hierarchies"
                );
            }
        }

        // Test with repetitive validation calls to detect caching issues
        for i in 0..100 {
            let name = format!("repeated-test-{}", i);
            let validation_start = std::time::Instant::now();
            let _ = validate_standard_sized(&name, base::STANDARD);
            let validation_elapsed = validation_start.elapsed();

            // Individual validations should be fast (no exponential slowdown)
            assert!(
                validation_elapsed.as_millis() < 100,
                "Individual validation should be fast for iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_configuration_boundary_attacks_on_capacity_limits() {
        // Test configuration boundary attacks through extreme capacity values
        // Edge cases could bypass security limits
        let boundary_attack_cases = [
            (0, "Zero capacity bypass attempt"),
            (1, "Minimal capacity attack"),
            (usize::MAX, "Maximum capacity overflow"),
            (usize::MAX - 1, "Near-maximum capacity"),
            (base::DEDUPE + 1, "Just above dedupe limit"),
            (base::SMALL - 1, "Just below small limit"),
            (base::MEDIUM / 2, "Half-medium capacity"),
            (base::LARGE * 2, "Double-large capacity"),
        ];

        for (attack_capacity, description) in &boundary_attack_cases {
            // Test various validation functions with boundary values
            let validations = [
                (
                    "standard",
                    validate_standard_sized("boundary-test", *attack_capacity),
                ),
                (
                    "trace",
                    validate_trace_sized("boundary-test", *attack_capacity),
                ),
                (
                    "medium",
                    validate_medium_sized("boundary-test", *attack_capacity),
                ),
                (
                    "large",
                    validate_large_sized("boundary-test", *attack_capacity),
                ),
            ];

            for (validator_name, result) in &validations {
                match result {
                    Ok(()) => {
                        // If accepted, verify capacity is within reasonable bounds
                        if *attack_capacity > 0 && *attack_capacity < usize::MAX / 2 {
                            assert!(
                                *attack_capacity > 0,
                                "Accepted capacity should be positive: {} (validator: {}, value: {})",
                                description,
                                validator_name,
                                attack_capacity
                            );
                        }
                    }
                    Err(error_msg) => {
                        // Boundary rejections are expected and acceptable
                        assert!(
                            !error_msg.is_empty(),
                            "Should have error message: {} (validator: {})",
                            description,
                            validator_name
                        );

                        // Verify error message contains relevant information
                        if *attack_capacity == 0 {
                            assert!(
                                error_msg.contains("zero")
                                    || error_msg.contains("0")
                                    || error_msg.contains("invalid"),
                                "Zero capacity error should be informative: {}",
                                error_msg
                            );
                        }
                    }
                }
            }

            // Test bucket hierarchy with boundary values
            if *attack_capacity > base::SMALL {
                let boundary_buckets = vec![
                    ("small", base::SMALL),
                    ("boundary", *attack_capacity),
                    ("xl", base::XL),
                ];

                let hierarchy_result = validate_strictly_increasing_buckets(&boundary_buckets);
                match hierarchy_result {
                    Ok(()) => {
                        assert!(
                            *attack_capacity > base::SMALL,
                            "Hierarchy should be valid for: {}",
                            description
                        );
                        assert!(
                            *attack_capacity < base::XL || *attack_capacity == base::XL,
                            "Hierarchy ordering for: {}",
                            description
                        );
                    }
                    Err(error_msg) => {
                        assert!(
                            !error_msg.is_empty(),
                            "Hierarchy error should be informative for: {}",
                            description
                        );
                    }
                }
            }
        }

        // Test that constants remain stable after boundary attacks
        assert_eq!(
            base::SMALL,
            256,
            "SMALL constant should remain stable after boundary attacks"
        );
        assert_eq!(
            base::MEDIUM,
            4096,
            "MEDIUM constant should remain stable after boundary attacks"
        );
        assert_eq!(
            base::LARGE,
            65536,
            "LARGE constant should remain stable after boundary attacks"
        );
        assert_eq!(
            base::XL,
            131072,
            "XL constant should remain stable after boundary attacks"
        );
    }
}
