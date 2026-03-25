//! Centralized bounded-collection defaults for `franken_node`.
//!
//! This module is the shared source of truth for high-frequency capacity
//! constants that currently recur across the crate surface. Follow-up migration
//! beads can replace file-local raw literals with aliases from here while
//! preserving local readability.

/// Canonical bucket sizes reused across the product surface.
pub mod base {
    /// Small bounded collections such as approvals and compact histories.
    pub const SMALL: usize = 256;

    /// Medium windows for disputes, replay capsules, and similar registries.
    pub const MEDIUM: usize = 2_048;

    /// Common default for event logs, receipts, and audit trails.
    pub const STANDARD: usize = 4_096;

    /// Larger collections for traces, obligations, and artifact inventories.
    pub const LARGE: usize = 8_192;

    /// Extended histories that exceed the standard large bucket.
    pub const XL: usize = 16_384;

    /// Trace/register-sized collections that are intentionally tighter.
    pub const TRACE: usize = 1_024;

    /// Very large dedupe/nonces windows.
    pub const DEDUPE: usize = 65_536;
}

/// Audit-oriented capacities.
pub mod audit {
    use super::base;

    pub const LOG_ENTRIES: usize = base::STANDARD;
    pub const TRAIL_ENTRIES: usize = base::STANDARD;
    pub const ACTION_LOG_ENTRIES: usize = base::STANDARD;
    pub const RECORDS: usize = base::STANDARD;
    pub const RECEIPT_CHAIN: usize = base::LARGE;
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
}

/// Runtime/control-plane capacities.
pub mod runtime {
    use super::base;

    pub const ABORT_EVENTS: usize = base::STANDARD;
    pub const FORCE_EVENTS: usize = base::STANDARD;
    pub const SESSION_EVENTS: usize = base::STANDARD;
    pub const OBLIGATIONS: usize = base::LARGE;
    pub const LEASES: usize = base::LARGE;
    pub const SAGAS: usize = base::STANDARD;
    pub const TOTAL_ARTIFACTS: usize = base::LARGE;
    pub const REGISTERED_TRACES: usize = base::TRACE;
    pub const TRACE_STEPS: usize = base::LARGE;
    pub const BULKHEAD_EVENTS: usize = base::TRACE;
    pub const LATENCY_SAMPLES: usize = base::TRACE;
    pub const BARRIER_HISTORY: usize = base::STANDARD;
    pub const CHECKPOINTS: usize = base::TRACE;
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
        assert_eq!(base::MEDIUM, 2_048);
        assert_eq!(base::STANDARD, 4_096);
        assert_eq!(base::LARGE, 8_192);
        assert_eq!(base::XL, 16_384);
        assert_eq!(base::DEDUPE, 65_536);
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
}
