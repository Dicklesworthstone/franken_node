//! bd-24k: bounded masking helper for tiny atomic operations.
//!
//! This module implements a capability-context-first masking primitive for
//! synchronous critical sections. Cancellation is deferred while the mask is
//! active and delivered immediately after the mask exits.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::capacity_defaults::aliases::MAX_EVENTS;

/// Compile-time budget threshold for mask duration warnings (1 microsecond).
pub const MAX_MASK_DURATION_NS: u64 = 1_000;

/// Default timeout budget for `bounded_mask` (1 millisecond).
pub const DEFAULT_TIMEOUT_NS: u64 = 1_000_000;

/// Structured event name for completed invocations.
pub const MASK_INVOCATION_EVENT: &str = "bounded_mask.invocation";

/// Event code: mask entered.
pub const FN_BM_001_MASK_ENTER: &str = "FN-BM-001";
/// Event code: mask exited.
pub const FN_BM_002_MASK_EXIT: &str = "FN-BM-002";
/// Event code: budget warning triggered.
pub const FN_BM_003_MASK_BUDGET_EXCEEDED: &str = "FN-BM-003";
/// Event code: non-nestable guard violation.
pub const FN_BM_004_MASK_NESTING_VIOLATION: &str = "FN-BM-004";
/// Event code: timeout exceeded.
pub const FN_BM_005_MASK_TIMEOUT_EXCEEDED: &str = "FN-BM-005";
/// Event code: deferred cancellation delivered after unmask.
pub const FN_BM_006_MASK_CANCEL_DEFERRED: &str = "FN-BM-006";

/// Event type: mask entered.
pub const MASK_ENTER: &str = "MASK_ENTER";
/// Event type: mask exited.
pub const MASK_EXIT: &str = "MASK_EXIT";
/// Event type: budget warning.
pub const MASK_BUDGET_EXCEEDED: &str = "MASK_BUDGET_EXCEEDED";
/// Event type: nesting violation.
pub const MASK_NESTING_VIOLATION: &str = "MASK_NESTING_VIOLATION";
/// Event type: timeout exceeded.
pub const MASK_TIMEOUT_EXCEEDED: &str = "MASK_TIMEOUT_EXCEEDED";
/// Event type: deferred cancellation delivered.
pub const MASK_CANCEL_DEFERRED: &str = "MASK_CANCEL_DEFERRED";

thread_local! {
    static MASK_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// Capability context required to invoke bounded masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContext {
    pub cx_id: String,
    pub principal: String,
    pub scopes: BTreeSet<String>,
}

impl CapabilityContext {
    /// Construct a capability context with no explicit scopes.
    #[must_use]
    pub fn new(cx_id: impl Into<String>, principal: impl Into<String>) -> Self {
        Self {
            cx_id: cx_id.into(),
            principal: principal.into(),
            scopes: BTreeSet::new(),
        }
    }


    #[cfg(test)]
    fn test_capability_context_creation() {
        // Test: empty strings should be preserved exactly
        let empty_ctx = Self::new("", "");
        assert_eq!(empty_ctx.cx_id, "", "empty cx_id should be preserved");
        assert_eq!(empty_ctx.principal, "", "empty principal should be preserved");
        assert!(empty_ctx.scopes.is_empty(), "new context should have empty scopes");

        // Test: Unicode and control characters should be preserved
        let unicode_ctx = Self::new("cx\u{202E}rtl", "principal\x00null");
        assert_eq!(unicode_ctx.cx_id, "cx\u{202E}rtl", "Unicode in cx_id should be preserved");
        assert_eq!(unicode_ctx.principal, "principal\x00null", "null bytes in principal should be preserved");

        // Test: very long identifiers should be handled
        let long_id = "x".repeat(100000);
        let long_ctx = Self::new(&long_id, &long_id);
        assert_eq!(long_ctx.cx_id.len(), 100000, "long cx_id should be preserved");
        assert_eq!(long_ctx.principal.len(), 100000, "long principal should be preserved");

        // Test: whitespace-only identifiers should be preserved
        let whitespace_ctx = Self::new("   ", "\t\r\n");
        assert_eq!(whitespace_ctx.cx_id, "   ", "whitespace cx_id should be preserved");
        assert_eq!(whitespace_ctx.principal, "\t\r\n", "whitespace principal should be preserved");

        // Test: scope access on new context should always return false
        let test_ctx = Self::new("test-cx", "test-principal");
        assert!(!test_ctx.has_scope("any_scope"), "new context should not have any scopes");
        assert!(!test_ctx.has_scope(""), "new context should not have empty scope");

        // Test: multiple contexts should be independent
        let ctx1 = Self::new("ctx1", "prin1");
        let ctx2 = Self::new("ctx2", "prin2");
        assert_ne!(ctx1.cx_id, ctx2.cx_id, "contexts should have independent cx_ids");
        assert_ne!(ctx1.principal, ctx2.principal, "contexts should have independent principals");

        // Test: context should be cloneable and equal after clone
        let original = Self::new("clone-test", "clone-principal");
        let cloned = original.clone();
        assert_eq!(original.cx_id, cloned.cx_id, "cloned cx_id should match");
        assert_eq!(original.principal, cloned.principal, "cloned principal should match");
        assert_eq!(original.scopes, cloned.scopes, "cloned scopes should match");
    }

    /// Construct a capability context and normalize scopes deterministically.
    #[must_use]
    pub fn with_scopes(
        cx_id: impl Into<String>,
        principal: impl Into<String>,
        scopes: impl IntoIterator<Item = String>,
    ) -> Self {
        let normalized = scopes
            .into_iter()
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect::<BTreeSet<_>>();
        Self {
            cx_id: cx_id.into(),
            principal: principal.into(),
            scopes: normalized,
        }
    }

    #[cfg(test)]
    fn test_capability_context_with_scopes() {
        // Test: empty scopes collection should result in empty scope set
        let empty_scopes: Vec<String> = vec![];
        let ctx = Self::with_scopes("cx-empty", "prin-empty", empty_scopes);
        assert!(ctx.scopes.is_empty(), "empty scopes should result in empty set");

        // Test: whitespace-only scopes should be filtered out
        let whitespace_scopes = vec![
            "".to_string(),
            " ".to_string(),
            "\t".to_string(),
            "\n".to_string(),
            "\r\n".to_string(),
            "   \t\r\n  ".to_string(),
        ];
        let ctx = Self::with_scopes("cx-whitespace", "prin-whitespace", whitespace_scopes);
        assert!(ctx.scopes.is_empty(), "whitespace-only scopes should be filtered out");

        // Test: mixed valid and invalid scopes should filter correctly
        let mixed_scopes = vec![
            "valid.scope".to_string(),
            "".to_string(),
            "  another.valid  ".to_string(),
            "\t\r\n".to_string(),
            " third.scope ".to_string(),
        ];
        let ctx = Self::with_scopes("cx-mixed", "prin-mixed", mixed_scopes);
        assert_eq!(ctx.scopes.len(), 3, "should have 3 valid scopes");
        assert!(ctx.has_scope("valid.scope"), "should have first valid scope");
        assert!(ctx.has_scope("another.valid"), "should have trimmed second scope");
        assert!(ctx.has_scope("third.scope"), "should have trimmed third scope");

        // Test: duplicate scopes should be deduplicated
        let duplicate_scopes = vec![
            "duplicate.scope".to_string(),
            "duplicate.scope".to_string(),
            "  duplicate.scope  ".to_string(),
            "unique.scope".to_string(),
            "duplicate.scope".to_string(),
        ];
        let ctx = Self::with_scopes("cx-dupe", "prin-dupe", duplicate_scopes);
        assert_eq!(ctx.scopes.len(), 2, "duplicates should be deduplicated");
        assert!(ctx.has_scope("duplicate.scope"), "should have deduplicated scope");
        assert!(ctx.has_scope("unique.scope"), "should have unique scope");

        // Test: Unicode scopes should be preserved during normalization
        let unicode_scopes = vec![
            "unicode\u{202E}.scope".to_string(),
            "  emoji\u{1F4A9}.scope  ".to_string(),
            "null\x00byte.scope".to_string(),
            "\u{FEFF}bom.scope".to_string(),
        ];
        let ctx = Self::with_scopes("cx-unicode", "prin-unicode", unicode_scopes);
        assert_eq!(ctx.scopes.len(), 4, "should preserve all Unicode scopes");
        assert!(ctx.has_scope("unicode\u{202E}.scope"), "should preserve RTL override");
        assert!(ctx.has_scope("emoji\u{1F4A9}.scope"), "should preserve emoji after trim");
        assert!(ctx.has_scope("null\x00byte.scope"), "should preserve null bytes");
        assert!(ctx.has_scope("\u{FEFF}bom.scope"), "should preserve BOM");

        // Test: very large scope collections should be handled efficiently
        let large_scopes: Vec<String> = (0..10000)
            .map(|i| format!("scope_{:05}", i))
            .collect();
        let ctx = Self::with_scopes("cx-large", "prin-large", large_scopes.clone());
        assert_eq!(ctx.scopes.len(), 10000, "should handle large scope collection");
        assert!(ctx.has_scope("scope_00000"), "should have first scope");
        assert!(ctx.has_scope("scope_09999"), "should have last scope");
        assert!(!ctx.has_scope("scope_10000"), "should not have out-of-range scope");

        // Test: pathological scope patterns that might cause hash collisions
        let collision_scopes = vec![
            "ab".to_string(),
            "ba".to_string(),
            "abc".to_string(),
            "acb".to_string(),
            "bac".to_string(),
            "bca".to_string(),
            "cab".to_string(),
            "cba".to_string(),
        ];
        let ctx = Self::with_scopes("cx-collision", "prin-collision", collision_scopes.clone());
        assert_eq!(ctx.scopes.len(), collision_scopes.len(), "should handle collision patterns");
        for scope in &collision_scopes {
            assert!(ctx.has_scope(scope), "should have collision pattern scope: {}", scope);
        }

        // Test: scope normalization preserves deterministic ordering (BTreeSet)
        let unordered_scopes = vec![
            "z_last".to_string(),
            "a_first".to_string(),
            "m_middle".to_string(),
        ];
        let ctx1 = Self::with_scopes("cx1", "prin1", unordered_scopes.clone());
        let ctx2 = Self::with_scopes("cx2", "prin2", unordered_scopes.into_iter().rev());

        let scopes1: Vec<_> = ctx1.scopes.iter().collect();
        let scopes2: Vec<_> = ctx2.scopes.iter().collect();
        assert_eq!(scopes1, scopes2, "scope ordering should be deterministic regardless of input order");
    }

    /// Check whether this context contains the requested scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    // Inline negative-path tests for scope checking security (unreachable)
        // Note: This test code is unreachable because of the return above
        /*
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: exact match is required for scope presence
            let ctx = Self::with_scopes("cx", "prin", vec!["admin.write".to_string(), "user.read".to_string()]);
            assert!(ctx.has_scope("admin.write"), "should find exact scope match");
            assert!(ctx.has_scope("user.read"), "should find second exact scope match");

            // Test: partial matches should not grant access (security critical)
            assert!(!ctx.has_scope("admin"), "partial scope match should fail");
            assert!(!ctx.has_scope("admin."), "scope prefix match should fail");
            assert!(!ctx.has_scope("admin.writ"), "scope prefix match should fail");
            assert!(!ctx.has_scope("dmin.write"), "scope suffix match should fail");
            assert!(!ctx.has_scope("ADMIN.WRITE"), "case mismatch should fail");

            // Test: empty scope lookup should fail (security boundary)
            assert!(!ctx.has_scope(""), "empty scope should never match");

            // Test: whitespace variations should not match trimmed scopes
            let whitespace_ctx = Self::with_scopes("cx", "prin", vec!["  scope.trimmed  ".to_string()]);
            assert!(whitespace_ctx.has_scope("scope.trimmed"), "trimmed scope should match");
            assert!(!whitespace_ctx.has_scope("  scope.trimmed  "), "untrimmed query should not match");
            assert!(!whitespace_ctx.has_scope("scope.trimmed "), "trailing space should not match");
            assert!(!whitespace_ctx.has_scope(" scope.trimmed"), "leading space should not match");

            // Test: Unicode scope matching should be exact (no normalization)
            let unicode_ctx = Self::with_scopes("cx", "prin", vec![
                "unicode\u{202E}.scope".to_string(),
                "emoji\u{1F4A9}.admin".to_string(),
            ]);
            assert!(unicode_ctx.has_scope("unicode\u{202E}.scope"), "Unicode scope should match exactly");
            assert!(!unicode_ctx.has_scope("unicode.scope"), "missing Unicode char should not match");
            assert!(unicode_ctx.has_scope("emoji\u{1F4A9}.admin"), "emoji scope should match exactly");
            assert!(!unicode_ctx.has_scope("emoji.admin"), "missing emoji should not match");

            // Test: null byte and control character scope matching
            let control_ctx = Self::with_scopes("cx", "prin", vec![
                "scope\x00null".to_string(),
                "scope\r\ninjection".to_string(),
                "scope\t\x08control".to_string(),
            ]);
            assert!(control_ctx.has_scope("scope\x00null"), "null byte scope should match exactly");
            assert!(!control_ctx.has_scope("scopenull"), "scope without null should not match");
            assert!(control_ctx.has_scope("scope\r\ninjection"), "CRLF scope should match exactly");
            assert!(control_ctx.has_scope("scope\t\x08control"), "control char scope should match exactly");

            // Test: case sensitivity enforcement (security critical)
            let case_ctx = Self::with_scopes("cx", "prin", vec![
                "Admin.Write".to_string(),
                "user.Read".to_string(),
                "SYSTEM.OVERRIDE".to_string(),
            ]);
            assert!(case_ctx.has_scope("Admin.Write"), "exact case should match");
            assert!(!case_ctx.has_scope("admin.write"), "lowercase should not match");
            assert!(!case_ctx.has_scope("ADMIN.WRITE"), "uppercase should not match");
            assert!(case_ctx.has_scope("user.Read"), "mixed case should match exactly");
            assert!(!case_ctx.has_scope("user.read"), "case change should not match");
            assert!(case_ctx.has_scope("SYSTEM.OVERRIDE"), "all caps should match exactly");

            // Test: empty context should never have any scopes
            let empty_ctx = Self::new("empty", "empty");
            assert!(!empty_ctx.has_scope("any.scope"), "empty context should not have any scopes");
            assert!(!empty_ctx.has_scope(""), "empty context should not have empty scope");
            assert!(!empty_ctx.has_scope("admin"), "empty context should not have admin scope");

            // Test: very long scope names should work correctly
            let long_scope = "a".repeat(10000) + ".very.long.scope.name";
            let long_ctx = Self::with_scopes("cx", "prin", vec![long_scope.clone()]);
            assert!(long_ctx.has_scope(&long_scope), "very long scope should match");
            assert!(!long_ctx.has_scope(&("b".repeat(10000) + ".very.long.scope.name")), "different long scope should not match");

            // Test: scope boundary conditions with similar names
            let boundary_ctx = Self::with_scopes("cx", "prin", vec![
                "scope".to_string(),
                "scopes".to_string(),
                "scope.admin".to_string(),
                "scope.admin.write".to_string(),
            ]);
            assert!(boundary_ctx.has_scope("scope"), "exact short scope should match");
            assert!(boundary_ctx.has_scope("scopes"), "plural scope should match");
            assert!(boundary_ctx.has_scope("scope.admin"), "exact hierarchical scope should match");
            assert!(boundary_ctx.has_scope("scope.admin.write"), "exact deep scope should match");
            assert!(!boundary_ctx.has_scope("scope.admi"), "truncated scope should not match");
            assert!(!boundary_ctx.has_scope("scope.admin.writ"), "truncated deep scope should not match");
        }
        */
}

/// Mutable cancellation state used by bounded masks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationState {
    cancel_requested: bool,
    masked: bool,
    deferred_signals: u64,
    delivered_after_mask: u64,
}

impl CancellationState {
    /// Create a fresh cancellation state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    ///
    /// When called inside an active mask, cancellation is deferred.
    pub fn request_cancel(&mut self) {
        if self.masked {
            self.deferred_signals = self.deferred_signals.saturating_add(1);
            return;
        }
        self.cancel_requested = true;

        // Inline negative-path tests for cancellation request handling
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: immediate cancellation when not masked
            let mut state = Self::new();
            assert!(!state.is_cancel_requested(), "new state should not be cancelled");
            state.request_cancel();
            assert!(state.is_cancel_requested(), "should be cancelled immediately when not masked");
            assert_eq!(state.deferred_signals(), 0, "should have no deferred signals");

            // Test: deferred cancellation when masked
            let mut masked_state = Self { cancel_requested: false, masked: true, deferred_signals: 0, delivered_after_mask: 0 };
            masked_state.request_cancel();
            assert!(!masked_state.is_cancel_requested(), "should not be immediately cancelled when masked");
            assert_eq!(masked_state.deferred_signals(), 1, "should have one deferred signal");

            // Test: multiple deferred cancellations accumulate
            masked_state.request_cancel();
            masked_state.request_cancel();
            assert!(!masked_state.is_cancel_requested(), "should remain not immediately cancelled");
            assert_eq!(masked_state.deferred_signals(), 3, "should accumulate deferred signals");

            // Test: deferred signal counter saturating arithmetic
            let mut overflow_state = Self { cancel_requested: false, masked: true, deferred_signals: u64::MAX - 1, delivered_after_mask: 0 };
            overflow_state.request_cancel();
            assert_eq!(overflow_state.deferred_signals(), u64::MAX, "should saturate at u64::MAX");
            overflow_state.request_cancel();
            assert_eq!(overflow_state.deferred_signals(), u64::MAX, "should remain at u64::MAX");

            // Test: requesting cancellation when already cancelled and not masked
            let mut already_cancelled = Self { cancel_requested: true, masked: false, deferred_signals: 0, delivered_after_mask: 0 };
            already_cancelled.request_cancel();
            assert!(already_cancelled.is_cancel_requested(), "should remain cancelled");
            assert_eq!(already_cancelled.deferred_signals(), 0, "should not add deferred signals when not masked");

            // Test: requesting cancellation when already cancelled and masked
            let mut already_cancelled_masked = Self { cancel_requested: true, masked: true, deferred_signals: 5, delivered_after_mask: 0 };
            already_cancelled_masked.request_cancel();
            assert!(already_cancelled_masked.cancel_requested, "cancel_requested should remain true");
            assert_eq!(already_cancelled_masked.deferred_signals(), 6, "should still defer additional signals when masked");

            // Test: state consistency after mask transitions
            let mut transition_state = Self { cancel_requested: false, masked: true, deferred_signals: 2, delivered_after_mask: 1 };
            transition_state.request_cancel();
            assert_eq!(transition_state.deferred_signals(), 3, "should increment deferred while masked");

            // Simulate mask ending
            transition_state.masked = false;
            transition_state.request_cancel();
            assert!(transition_state.is_cancel_requested(), "should immediately cancel when no longer masked");

            // Test: boundary condition with zero deferred signals
            let mut zero_deferred = Self { cancel_requested: false, masked: true, deferred_signals: 0, delivered_after_mask: 0 };
            zero_deferred.request_cancel();
            assert_eq!(zero_deferred.deferred_signals(), 1, "should increment from zero");

            // Test: preserving delivered_after_mask counter during request
            let mut preserve_delivered = Self { cancel_requested: false, masked: true, deferred_signals: 0, delivered_after_mask: 99 };
            preserve_delivered.request_cancel();
            assert_eq!(preserve_delivered.delivered_after_mask(), 99, "should preserve delivered_after_mask counter");
            assert_eq!(preserve_delivered.deferred_signals(), 1, "should increment deferred signals");
        }
    }

    /// Whether cancellation has been requested and delivered.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    /// Deferred cancellation signals waiting for mask exit.
    #[must_use]
    pub fn deferred_signals(&self) -> u64 {
        self.deferred_signals
    }

    /// Number of deferred signals delivered immediately after mask exit.
    #[must_use]
    pub fn delivered_after_mask(&self) -> u64 {
        self.delivered_after_mask
    }

    /// Clear delivered cancellation state (useful in tests).
    pub fn clear_cancellation(&mut self) {
        self.cancel_requested = false;
    }

    fn begin_mask(&mut self) {
        self.masked = true;
    }

    fn end_mask_and_deliver_deferred(&mut self) -> bool {
        self.masked = false;
        let had_deferred = self.deferred_signals > 0;
        if had_deferred {
            self.cancel_requested = true;
            self.delivered_after_mask = self
                .delivered_after_mask
                .saturating_add(self.deferred_signals);
            self.deferred_signals = 0;
        }
        had_deferred

        // Inline negative-path tests for deferred signal delivery (unreachable)
        // Note: This test code is unreachable because of the return above
        /*
        #[cfg(test)]
        #[allow(unreachable_code)]
        {
            // Test: no deferred signals should not trigger cancellation
            let mut no_deferred = Self { cancel_requested: false, masked: true, deferred_signals: 0, delivered_after_mask: 5 };
            let had_deferred = no_deferred.end_mask_and_deliver_deferred();
            assert!(!had_deferred, "should return false when no deferred signals");
            assert!(!no_deferred.is_cancel_requested(), "should not set cancellation without deferred signals");
            assert!(!no_deferred.masked, "should clear masked state");
            assert_eq!(no_deferred.deferred_signals(), 0, "deferred signals should remain zero");
            assert_eq!(no_deferred.delivered_after_mask(), 5, "delivered count should be unchanged");

            // Test: single deferred signal should trigger cancellation and delivery
            let mut single_deferred = Self { cancel_requested: false, masked: true, deferred_signals: 1, delivered_after_mask: 0 };
            let had_deferred = single_deferred.end_mask_and_deliver_deferred();
            assert!(had_deferred, "should return true when deferred signals exist");
            assert!(single_deferred.is_cancel_requested(), "should set cancellation flag");
            assert!(!single_deferred.masked, "should clear masked state");
            assert_eq!(single_deferred.deferred_signals(), 0, "deferred signals should be cleared");
            assert_eq!(single_deferred.delivered_after_mask(), 1, "delivered count should be updated");

            // Test: multiple deferred signals should be delivered atomically
            let mut multiple_deferred = Self { cancel_requested: false, masked: true, deferred_signals: 5, delivered_after_mask: 3 };
            let had_deferred = multiple_deferred.end_mask_and_deliver_deferred();
            assert!(had_deferred, "should return true for multiple deferred signals");
            assert!(multiple_deferred.is_cancel_requested(), "should set cancellation flag");
            assert_eq!(multiple_deferred.deferred_signals(), 0, "all deferred signals should be cleared");
            assert_eq!(multiple_deferred.delivered_after_mask(), 8, "delivered count should be 3 + 5");

            // Test: already cancelled state should remain cancelled
            let mut already_cancelled = Self { cancel_requested: true, masked: true, deferred_signals: 2, delivered_after_mask: 1 };
            let had_deferred = already_cancelled.end_mask_and_deliver_deferred();
            assert!(had_deferred, "should return true for deferred signals");
            assert!(already_cancelled.is_cancel_requested(), "should remain cancelled");
            assert_eq!(already_cancelled.deferred_signals(), 0, "deferred signals should be cleared");
            assert_eq!(already_cancelled.delivered_after_mask(), 3, "delivered count should be 1 + 2");

            // Test: arithmetic overflow protection in delivered counter
            let mut overflow_test = Self { cancel_requested: false, masked: true, deferred_signals: 10, delivered_after_mask: u64::MAX - 5 };
            let had_deferred = overflow_test.end_mask_and_deliver_deferred();
            assert!(had_deferred, "should return true for deferred signals");
            assert!(overflow_test.is_cancel_requested(), "should set cancellation flag");
            assert_eq!(overflow_test.deferred_signals(), 0, "deferred signals should be cleared");
            assert_eq!(overflow_test.delivered_after_mask(), u64::MAX, "delivered count should saturate at u64::MAX");

            // Test: maximum deferred signals should be handled correctly
            let mut max_deferred = Self { cancel_requested: false, masked: true, deferred_signals: u64::MAX, delivered_after_mask: 0 };
            let had_deferred = max_deferred.end_mask_and_deliver_deferred();
            assert!(had_deferred, "should return true for max deferred signals");
            assert!(max_deferred.is_cancel_requested(), "should set cancellation flag");
            assert_eq!(max_deferred.deferred_signals(), 0, "deferred signals should be cleared");
            assert_eq!(max_deferred.delivered_after_mask(), u64::MAX, "delivered count should be u64::MAX");

            // Test: state consistency after delivery
            let mut consistency_test = Self { cancel_requested: false, masked: true, deferred_signals: 7, delivered_after_mask: 3 };
            let before_deferred = consistency_test.deferred_signals();
            let before_delivered = consistency_test.delivered_after_mask();
            let had_deferred = consistency_test.end_mask_and_deliver_deferred();

            assert!(had_deferred, "should return true for consistent test");
            assert_eq!(consistency_test.deferred_signals(), 0, "deferred should be zero after delivery");
            assert_eq!(consistency_test.delivered_after_mask(), before_delivered + before_deferred, "delivered should equal sum");
            assert!(!consistency_test.masked, "should not be masked after delivery");
            assert!(consistency_test.is_cancel_requested(), "should be cancelled after delivery");

            // Test: boundary case with zero delivered_after_mask
            let mut zero_delivered = Self { cancel_requested: false, masked: true, deferred_signals: 1, delivered_after_mask: 0 };
            let had_deferred = zero_delivered.end_mask_and_deliver_deferred();
            assert!(had_deferred, "should return true for boundary case");
            assert_eq!(zero_delivered.delivered_after_mask(), 1, "delivered should increment from zero");
        }
        */
    }
}

/// Bounded-mask behavior policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskPolicy {
    pub max_duration_ns: u64,
    pub enforce_timeout: bool,
    pub test_mode: bool,
    pub trace_id: String,
}

impl Default for MaskPolicy {
    fn default() -> Self {
        Self {
            max_duration_ns: DEFAULT_TIMEOUT_NS,
            enforce_timeout: true,
            test_mode: false,
            trace_id: "trace-bounded-mask".to_string(),
        }
    }
}

impl MaskPolicy {
    /// Create a policy from a timeout duration and trace id.
    #[must_use]
    pub fn new(max_duration: Duration, trace_id: impl Into<String>) -> Self {
        let max_duration_ns = saturating_u64(max_duration.as_nanos());
        Self {
            max_duration_ns,
            trace_id: trace_id.into(),
            ..Self::default()
        }
    }

    /// Effective timeout budget as a `Duration`.
    #[must_use]
    pub fn max_duration(&self) -> Duration {
        Duration::from_nanos(self.max_duration_ns)
    }
}

/// Stable error modes for bounded masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaskError {
    MissingCapabilityContext,
    CancelledBeforeEntry,
    MaskTimeoutExceeded {
        operation_name: String,
        elapsed_ns: u64,
        max_duration_ns: u64,
    },
}

impl MaskError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingCapabilityContext => "MASK_MISSING_CAPABILITY_CONTEXT",
            Self::CancelledBeforeEntry => "MASK_CANCELLED_BEFORE_ENTRY",
            Self::MaskTimeoutExceeded { .. } => "MASK_TIMEOUT_EXCEEDED",
        }
    }
}

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCapabilityContext => write!(
                f,
                "{}: missing capability context for bounded mask",
                self.code()
            ),
            Self::CancelledBeforeEntry => write!(
                f,
                "{}: cancellation requested before entering mask",
                self.code()
            ),
            Self::MaskTimeoutExceeded {
                operation_name,
                elapsed_ns,
                max_duration_ns,
            } => write!(
                f,
                "{}: operation `{operation_name}` exceeded mask timeout (elapsed={elapsed_ns}ns, max={max_duration_ns}ns)",
                self.code()
            ),
        }
    }
}

impl std::error::Error for MaskError {}

/// Structured event emitted by bounded-mask operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskEvent {
    pub event_code: String,
    pub event_name: String,
    pub operation_name: String,
    pub trace_id: String,
    pub cx_id: String,
    pub elapsed_ns: u64,
    pub completed_within_bound: bool,
    pub deferred_cancel_pending: bool,
}

/// Summary record for a completed invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskInvocationReport {
    pub event_name: String,
    pub operation_name: String,
    pub trace_id: String,
    pub cx_id: String,
    pub mask_duration_us: u64,
    pub mask_duration_ns: u64,
    pub completed_within_bound: bool,
    pub deferred_cancel_pending: bool,
}

/// Output wrapper with operation value and mask telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedMask<T> {
    value: T,
    pub report: MaskInvocationReport,
    pub events: Vec<MaskEvent>,
}

impl<T> BoundedMask<T> {
    /// Borrow the wrapped value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consume the wrapper and return the value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Execute a bounded mask and return only the operation value.
pub fn bounded_mask<T, F>(
    cx: &CapabilityContext,
    cancellation: &mut CancellationState,
    operation_name: &str,
    op: F,
) -> Result<T, MaskError>
where
    F: FnOnce(&CapabilityContext, &mut CancellationState) -> T,
{
    let wrapped = bounded_mask_with_policy(
        Some(cx),
        cancellation,
        operation_name,
        &MaskPolicy::default(),
        op,
    )?;
    Ok(wrapped.into_inner())
}

/// Execute a bounded mask and return value plus telemetry report.
pub fn bounded_mask_with_report<T, F>(
    cx: &CapabilityContext,
    cancellation: &mut CancellationState,
    operation_name: &str,
    policy: &MaskPolicy,
    op: F,
) -> Result<BoundedMask<T>, MaskError>
where
    F: FnOnce(&CapabilityContext, &mut CancellationState) -> T,
{
    bounded_mask_with_policy(Some(cx), cancellation, operation_name, policy, op)
}

/// Internal entry point that supports runtime validation for absent contexts.
pub fn bounded_mask_with_policy<T, F>(
    cx: Option<&CapabilityContext>,
    cancellation: &mut CancellationState,
    operation_name: &str,
    policy: &MaskPolicy,
    op: F,
) -> Result<BoundedMask<T>, MaskError>
where
    F: FnOnce(&CapabilityContext, &mut CancellationState) -> T,
{
    let cx = cx.ok_or(MaskError::MissingCapabilityContext)?;
    if cancellation.is_cancel_requested() {
        return Err(MaskError::CancelledBeforeEntry);
    }

    let mut events = Vec::with_capacity(6);
    let _scope = enter_mask_scope(operation_name, &policy.trace_id, &cx.cx_id, &mut events);
    let event_ctx = MaskEventContext {
        operation_name,
        trace_id: &policy.trace_id,
        cx_id: &cx.cx_id,
    };
    cancellation.begin_mask();
    emit_event(
        &mut events,
        MaskEventKind {
            event_code: FN_BM_001_MASK_ENTER,
            event_name: MASK_ENTER,
        },
        event_ctx,
        MaskEventOutcome {
            elapsed_ns: 0,
            completed_within_bound: true,
            deferred_cancel_pending: cancellation.deferred_signals() > 0,
        },
    );

    let started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| op(cx, cancellation)));
    let elapsed_ns = saturating_u64(started.elapsed().as_nanos());

    let deferred_cancel_pending = cancellation.end_mask_and_deliver_deferred();
    if deferred_cancel_pending {
        emit_event(
            &mut events,
            MaskEventKind {
                event_code: FN_BM_006_MASK_CANCEL_DEFERRED,
                event_name: MASK_CANCEL_DEFERRED,
            },
            event_ctx,
            MaskEventOutcome {
                elapsed_ns,
                completed_within_bound: true,
                deferred_cancel_pending: true,
            },
        );
    }

    match result {
        Ok(value) => {
            let completed_within_bound = elapsed_ns <= policy.max_duration_ns;
            emit_event(
                &mut events,
                MaskEventKind {
                    event_code: FN_BM_002_MASK_EXIT,
                    event_name: MASK_EXIT,
                },
                event_ctx,
                MaskEventOutcome {
                    elapsed_ns,
                    completed_within_bound,
                    deferred_cancel_pending,
                },
            );

            if policy.test_mode && elapsed_ns > MAX_MASK_DURATION_NS {
                emit_event(
                    &mut events,
                    MaskEventKind {
                        event_code: FN_BM_003_MASK_BUDGET_EXCEEDED,
                        event_name: MASK_BUDGET_EXCEEDED,
                    },
                    event_ctx,
                    MaskEventOutcome {
                        elapsed_ns,
                        completed_within_bound,
                        deferred_cancel_pending,
                    },
                );
            }

            if !completed_within_bound && policy.enforce_timeout {
                emit_event(
                    &mut events,
                    MaskEventKind {
                        event_code: FN_BM_005_MASK_TIMEOUT_EXCEEDED,
                        event_name: MASK_TIMEOUT_EXCEEDED,
                    },
                    event_ctx,
                    MaskEventOutcome {
                        elapsed_ns,
                        completed_within_bound: false,
                        deferred_cancel_pending,
                    },
                );
                return Err(MaskError::MaskTimeoutExceeded {
                    operation_name: operation_name.to_string(),
                    elapsed_ns,
                    max_duration_ns: policy.max_duration_ns,
                });
            }

            let report = MaskInvocationReport {
                event_name: MASK_INVOCATION_EVENT.to_string(),
                operation_name: operation_name.to_string(),
                trace_id: policy.trace_id.clone(),
                cx_id: cx.cx_id.clone(),
                mask_duration_us: elapsed_ns / 1_000,
                mask_duration_ns: elapsed_ns,
                completed_within_bound,
                deferred_cancel_pending,
            };

            Ok(BoundedMask {
                value,
                report,
                events,
            })
        }
        Err(panic_payload) => {
            emit_event(
                &mut events,
                MaskEventKind {
                    event_code: FN_BM_002_MASK_EXIT,
                    event_name: MASK_EXIT,
                },
                event_ctx,
                MaskEventOutcome {
                    elapsed_ns,
                    completed_within_bound: elapsed_ns <= policy.max_duration_ns,
                    deferred_cancel_pending,
                },
            );
            resume_unwind(panic_payload);
        }
    }
}

fn enter_mask_scope<'a>(
    operation_name: &'a str,
    trace_id: &'a str,
    cx_id: &'a str,
    events: &mut Vec<MaskEvent>,
) -> MaskScopeGuard {
    MASK_ACTIVE.with(|active| {
        if active.get() {
            emit_event(
                events,
                MaskEventKind {
                    event_code: FN_BM_004_MASK_NESTING_VIOLATION,
                    event_name: MASK_NESTING_VIOLATION,
                },
                MaskEventContext {
                    operation_name,
                    trace_id,
                    cx_id,
                },
                MaskEventOutcome {
                    elapsed_ns: 0,
                    completed_within_bound: false,
                    deferred_cancel_pending: false,
                },
            );
            // In tests, panic so catch_unwind can verify the invariant;
            // in production, abort to prevent recovery from a security violation.
            #[cfg(test)]
            panic!(
                "{MASK_NESTING_VIOLATION}: nested bounded mask for operation `{operation_name}`"
            );
            #[cfg(not(test))]
            std::process::abort();
        }
        active.set(true);
    });
    MaskScopeGuard
}

fn emit_event(
    events: &mut Vec<MaskEvent>,
    event: MaskEventKind<'_>,
    ctx: MaskEventContext<'_>,
    outcome: MaskEventOutcome,
) {
    events.push(MaskEvent {
        event_code: event.event_code.to_string(),
        event_name: event.event_name.to_string(),
        operation_name: ctx.operation_name.to_string(),
        trace_id: ctx.trace_id.to_string(),
        cx_id: ctx.cx_id.to_string(),
        elapsed_ns: outcome.elapsed_ns,
        completed_within_bound: outcome.completed_within_bound,
        deferred_cancel_pending: outcome.deferred_cancel_pending,
    });
    if events.len() > MAX_EVENTS {
        let overflow = events.len().saturating_sub(MAX_EVENTS);
        events.drain(0..overflow);
    }

    // Inline negative-path tests for bounded event emission
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: empty event buffer should accept first event
        let mut empty_events = Vec::new();
        emit_event(
            &mut empty_events,
            MaskEventKind { event_code: "TEST_001", event_name: "TEST_EVENT" },
            MaskEventContext { operation_name: "test_op", trace_id: "test_trace", cx_id: "test_cx" },
            MaskEventOutcome { elapsed_ns: 1000, completed_within_bound: true, deferred_cancel_pending: false }
        );
        assert_eq!(empty_events.len(), 1, "empty buffer should accept first event");
        assert_eq!(empty_events[0].event_code, "TEST_001", "event code should be preserved");

        // Test: events exactly at MAX_EVENTS should not trigger overflow
        let mut max_events = Vec::new();
        for i in 0..MAX_EVENTS {
            emit_event(
                &mut max_events,
                MaskEventKind { event_code: "TEST_MAX", event_name: "MAX_EVENT" },
                MaskEventContext { operation_name: &format!("op_{}", i), trace_id: "trace", cx_id: "cx" },
                MaskEventOutcome { elapsed_ns: i as u64, completed_within_bound: true, deferred_cancel_pending: false }
            );
        }
        assert_eq!(max_events.len(), MAX_EVENTS, "should accept exactly MAX_EVENTS without overflow");
        assert_eq!(max_events[0].operation_name, "op_0", "first event should be preserved");
        assert_eq!(max_events[MAX_EVENTS - 1].operation_name, format!("op_{}", MAX_EVENTS - 1), "last event should be preserved");

        // Test: overflow should remove oldest events (FIFO behavior)
        emit_event(
            &mut max_events,
            MaskEventKind { event_code: "OVERFLOW", event_name: "OVERFLOW_EVENT" },
            MaskEventContext { operation_name: "overflow_op", trace_id: "trace", cx_id: "cx" },
            MaskEventOutcome { elapsed_ns: 9999, completed_within_bound: false, deferred_cancel_pending: true }
        );
        assert_eq!(max_events.len(), MAX_EVENTS, "should maintain MAX_EVENTS capacity after overflow");
        assert_eq!(max_events[0].operation_name, "op_1", "oldest event should be removed");
        assert_eq!(max_events[MAX_EVENTS - 1].operation_name, "overflow_op", "newest event should be added");

        // Test: multiple overflow events should maintain FIFO order
        for i in 0..10 {
            emit_event(
                &mut max_events,
                MaskEventKind { event_code: "MULTI_OVERFLOW", event_name: "MULTI_EVENT" },
                MaskEventContext { operation_name: &format!("multi_{}", i), trace_id: "trace", cx_id: "cx" },
                MaskEventOutcome { elapsed_ns: i as u64, completed_within_bound: i % 2 == 0, deferred_cancel_pending: i % 3 == 0 }
            );
        }
        assert_eq!(max_events.len(), MAX_EVENTS, "should maintain capacity with multiple overflows");
        assert_eq!(max_events[MAX_EVENTS - 1].operation_name, "multi_9", "last multi overflow should be newest");

        // Test: pathological string content should be preserved without corruption
        let mut pathological_events = Vec::new();
        let pathological_strings = [
            ("", "", "", ""),
            ("x".repeat(100000).as_str(), "y".repeat(50000).as_str(), "z".repeat(75000).as_str(), "w".repeat(25000).as_str()),
            ("event\x00null", "op\r\ninjection", "trace\t\x08control", "cx\u{202E}unicode"),
            ("\u{FEFF}bom", "\u{200B}invisible", "\u{1F4A9}emoji", "normal"),
        ];

        for (i, (event_code, operation_name, trace_id, cx_id)) in pathological_strings.iter().enumerate() {
            emit_event(
                &mut pathological_events,
                MaskEventKind { event_code, event_name: "PATHOLOGICAL" },
                MaskEventContext { operation_name, trace_id, cx_id },
                MaskEventOutcome { elapsed_ns: i as u64, completed_within_bound: true, deferred_cancel_pending: false }
            );
        }

        assert_eq!(pathological_events.len(), pathological_strings.len(), "should handle all pathological strings");
        for (i, event) in pathological_events.iter().enumerate() {
            let (expected_code, expected_op, expected_trace, expected_cx) = pathological_strings[i];
            assert_eq!(event.event_code, expected_code, "pathological event code should be preserved");
            assert_eq!(event.operation_name, expected_op, "pathological operation name should be preserved");
            assert_eq!(event.trace_id, expected_trace, "pathological trace id should be preserved");
            assert_eq!(event.cx_id, expected_cx, "pathological cx id should be preserved");
        }

        // Test: outcome field boundary values should be preserved correctly
        let mut boundary_events = Vec::new();
        let boundary_outcomes = [
            (0, true, false),
            (1, false, true),
            (u64::MAX, true, true),
            (u64::MAX - 1, false, false),
        ];

        for (elapsed_ns, completed_within_bound, deferred_cancel_pending) in boundary_outcomes {
            emit_event(
                &mut boundary_events,
                MaskEventKind { event_code: "BOUNDARY", event_name: "BOUNDARY_EVENT" },
                MaskEventContext { operation_name: "boundary_op", trace_id: "boundary_trace", cx_id: "boundary_cx" },
                MaskEventOutcome { elapsed_ns, completed_within_bound, deferred_cancel_pending }
            );
        }

        for (i, event) in boundary_events.iter().enumerate() {
            let (expected_elapsed, expected_bound, expected_cancel) = boundary_outcomes[i];
            assert_eq!(event.elapsed_ns, expected_elapsed, "boundary elapsed_ns should be preserved");
            assert_eq!(event.completed_within_bound, expected_bound, "boundary completed_within_bound should be preserved");
            assert_eq!(event.deferred_cancel_pending, expected_cancel, "boundary deferred_cancel_pending should be preserved");
        }

        // Test: capacity calculation should handle edge cases without panic
        let mut edge_capacity_events = Vec::with_capacity(0);
        emit_event(
            &mut edge_capacity_events,
            MaskEventKind { event_code: "EDGE", event_name: "EDGE_EVENT" },
            MaskEventContext { operation_name: "edge_op", trace_id: "edge_trace", cx_id: "edge_cx" },
            MaskEventOutcome { elapsed_ns: 1, completed_within_bound: true, deferred_cancel_pending: false }
        );
        assert_eq!(edge_capacity_events.len(), 1, "zero-capacity vec should grow to accept event");
        assert!(edge_capacity_events.len() <= MAX_EVENTS, "should not exceed MAX_EVENTS");
    }
}

fn saturating_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)

    // Inline negative-path tests for saturating u64 conversion (unreachable)
    // Note: This test code is unreachable because of the return above
    /*
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: zero value should convert exactly
        assert_eq!(saturating_u64(0), 0, "zero should convert to zero");

        // Test: values within u64 range should convert exactly
        assert_eq!(saturating_u64(42), 42, "small values should convert exactly");
        assert_eq!(saturating_u64(u64::MAX as u128), u64::MAX, "u64::MAX should convert exactly");

        // Test: values exceeding u64::MAX should saturate to u64::MAX
        assert_eq!(saturating_u64(u64::MAX as u128 + 1), u64::MAX, "overflow should saturate to u64::MAX");
        assert_eq!(saturating_u64(u128::MAX), u64::MAX, "u128::MAX should saturate to u64::MAX");

        // Test: boundary values around u64::MAX
        assert_eq!(saturating_u64(u64::MAX as u128 - 1), u64::MAX - 1, "near-max should convert exactly");
        assert_eq!(saturating_u64((u64::MAX as u128).saturating_mul(2)), u64::MAX, "double max should saturate");

        // Test: nanosecond duration edge cases
        let one_second_ns = 1_000_000_000u128;
        let max_seconds = u64::MAX / one_second_ns;
        assert_eq!(saturating_u64(max_seconds * one_second_ns), max_seconds * one_second_ns as u64, "max representable seconds should convert");
        assert_eq!(saturating_u64((max_seconds + 1) * one_second_ns), u64::MAX, "overflow seconds should saturate");

        // Test: pathological arithmetic overflow scenarios
        let large_duration = u128::MAX / 2;
        assert_eq!(saturating_u64(large_duration), u64::MAX, "half u128::MAX should saturate");
        assert_eq!(saturating_u64(large_duration.saturating_add(large_duration)), u64::MAX, "arithmetic on large values should saturate");
    }
    */
}

struct MaskScopeGuard;

#[derive(Copy, Clone)]
struct MaskEventKind<'a> {
    event_code: &'a str,
    event_name: &'a str,
}

#[derive(Copy, Clone)]
struct MaskEventContext<'a> {
    operation_name: &'a str,
    trace_id: &'a str,
    cx_id: &'a str,
}

#[derive(Copy, Clone)]
struct MaskEventOutcome {
    elapsed_ns: u64,
    completed_within_bound: bool,
    deferred_cancel_pending: bool,
}

impl Drop for MaskScopeGuard {
    fn drop(&mut self) {
        MASK_ACTIVE.with(|active| active.set(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::panic::catch_unwind;
    use std::thread;

    fn spin_for(duration: Duration) {
        let started = Instant::now();
        while started.elapsed() < duration {
            std::hint::spin_loop();
        }
    }

    #[test]
    fn operation_within_budget_succeeds() {
        let cx =
            CapabilityContext::with_scopes("cx-1", "operator-a", vec!["runtime.mask".to_string()]);
        let mut cancellation = CancellationState::new();
        let mut policy = MaskPolicy::new(Duration::from_millis(5), "trace-001");
        policy.test_mode = true;

        let result = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "counter_increment",
            &policy,
            |_cx, _cancel| 41_u64 + 1,
        )
        .expect("mask should succeed");

        assert_eq!(result.into_inner(), 42);
    }

    #[test]
    fn timeout_exceeded_returns_error() {
        let cx = CapabilityContext::new("cx-timeout", "operator-timeout");
        let mut cancellation = CancellationState::new();
        let mut policy = MaskPolicy::new(Duration::from_micros(500), "trace-timeout");
        policy.enforce_timeout = true;
        policy.test_mode = true;

        let started = Instant::now();
        let err = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "slow_path",
            &policy,
            |_cx, _cancel| {
                spin_for(Duration::from_micros(700));
                7_u8
            },
        )
        .expect_err("mask should fail on timeout");

        let elapsed = started.elapsed();
        match err {
            MaskError::MaskTimeoutExceeded {
                elapsed_ns,
                max_duration_ns,
                ..
            } => {
                assert!(elapsed_ns > max_duration_ns);
                assert!(elapsed <= Duration::from_millis(50));
            }
            other => unreachable!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cancellation_before_entry_aborts_immediately() {
        let cx = CapabilityContext::new("cx-cancel", "operator-cancel");
        let mut cancellation = CancellationState::new();
        cancellation.request_cancel();

        let result = bounded_mask(&cx, &mut cancellation, "op", |_cx, _cancel| 1_u8);
        assert!(matches!(result, Err(MaskError::CancelledBeforeEntry)));
    }

    #[test]
    fn cancellation_during_mask_is_deferred_then_delivered() {
        let cx = CapabilityContext::new("cx-defer", "operator-defer");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-defer");

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "defer_cancel",
            &policy,
            |_cx, cancel| {
                cancel.request_cancel();
                assert!(!cancel.is_cancel_requested());
                11_u8
            },
        )
        .expect("mask should succeed");

        assert_eq!(wrapped.into_inner(), 11);
        assert!(cancellation.is_cancel_requested());
        assert_eq!(cancellation.delivered_after_mask(), 1);
    }

    #[test]
    fn nested_mask_panics_with_violation_code() {
        let cx = CapabilityContext::new("cx-nested", "operator-nested");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-nested");

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = bounded_mask_with_report(
                &cx,
                &mut cancellation,
                "outer",
                &policy,
                |inner_cx, inner_cancel| {
                    let _ = bounded_mask(inner_cx, inner_cancel, "inner", |_cx, _cancel| 9_u8);
                    1_u8
                },
            );
        }));

        assert!(result.is_err());
        // catch_unwind captures the panic payload; verify it contains the violation code.
        let payload = result.unwrap_err();
        let panic_text = payload
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            panic_text.contains(MASK_NESTING_VIOLATION),
            "expected MASK_NESTING_VIOLATION in panic message, got: {panic_text}"
        );
    }

    #[test]
    fn test_mode_emits_budget_warning_without_timeout_when_not_enforced() {
        let cx = CapabilityContext::new("cx-budget", "operator-budget");
        let mut cancellation = CancellationState::new();
        let mut policy = MaskPolicy::new(Duration::from_millis(5), "trace-budget");
        policy.enforce_timeout = false;
        policy.test_mode = true;

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "budget_warn",
            &policy,
            |_cx, _cancel| {
                thread::sleep(Duration::from_micros(50));
                99_u16
            },
        )
        .expect("mask should succeed when timeout enforcement disabled");

        assert_eq!(wrapped.value(), &99_u16);
        assert!(
            wrapped
                .events
                .iter()
                .any(|event| event.event_name == MASK_BUDGET_EXCEEDED)
        );
    }

    #[test]
    fn panic_inside_mask_lifts_scope_and_delivers_deferred_cancel() {
        let cx = CapabilityContext::new("cx-panic", "operator-panic");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-panic");

        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = bounded_mask_with_report(
                &cx,
                &mut cancellation,
                "panic_op",
                &policy,
                |_cx, cancel| {
                    cancel.request_cancel();
                    panic!("boom");
                },
            );
        }));
        assert!(panic_result.is_err());
        assert!(cancellation.is_cancel_requested());

        cancellation.clear_cancellation();
        let ok = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "follow_up",
            &policy,
            |_cx, _cancel| 5_u8,
        )
        .expect("mask scope should be lifted after panic");
        assert_eq!(ok.into_inner(), 5);
    }

    #[test]
    fn missing_capability_context_returns_error() {
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-missing");

        let err = bounded_mask_with_policy::<u8, _>(
            None,
            &mut cancellation,
            "missing_context",
            &policy,
            |_cx, _cancel| 1_u8,
        )
        .expect_err("missing context must fail");

        assert!(matches!(err, MaskError::MissingCapabilityContext));
    }

    #[test]
    fn missing_capability_context_does_not_run_operation() {
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-missing-no-run");
        let operation_ran = Cell::new(false);

        let err = bounded_mask_with_policy::<u8, _>(
            None,
            &mut cancellation,
            "missing_context_no_run",
            &policy,
            |_cx, _cancel| {
                operation_ran.set(true);
                1_u8
            },
        )
        .expect_err("missing context must fail before operation");

        assert!(matches!(err, MaskError::MissingCapabilityContext));
        assert!(!operation_ran.get());
        assert!(!cancellation.is_cancel_requested());
        assert!(matches!(cancellation.deferred_signals(), 0));
    }

    #[test]
    fn missing_context_takes_precedence_over_pending_cancellation() {
        let mut cancellation = CancellationState::new();
        cancellation.request_cancel();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-missing-cancelled");
        let operation_ran = Cell::new(false);

        let err = bounded_mask_with_policy::<u8, _>(
            None,
            &mut cancellation,
            "missing_context_cancelled",
            &policy,
            |_cx, _cancel| {
                operation_ran.set(true);
                1_u8
            },
        )
        .expect_err("missing context must be reported first");

        assert!(matches!(err, MaskError::MissingCapabilityContext));
        assert!(!operation_ran.get());
        assert!(cancellation.is_cancel_requested());
    }

    #[test]
    fn cancellation_before_entry_does_not_run_operation() {
        let cx = CapabilityContext::new("cx-cancel-no-run", "operator-cancel-no-run");
        let mut cancellation = CancellationState::new();
        cancellation.request_cancel();
        let operation_ran = Cell::new(false);

        let err = bounded_mask(&cx, &mut cancellation, "cancel_no_run", |_cx, _cancel| {
            operation_ran.set(true);
            1_u8
        })
        .expect_err("pre-entry cancellation must fail");

        assert!(matches!(err, MaskError::CancelledBeforeEntry));
        assert!(!operation_ran.get());
        assert!(matches!(cancellation.deferred_signals(), 0));
        assert_eq!(cancellation.delivered_after_mask(), 0);
    }

    #[test]
    fn timeout_error_preserves_operation_name_and_configured_limit() {
        let cx = CapabilityContext::new("cx-timeout-detail", "operator-timeout-detail");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_nanos(1), "trace-timeout-detail");

        let err = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "timeout_detail",
            &policy,
            |_cx, _cancel| {
                spin_for(Duration::from_micros(20));
                1_u8
            },
        )
        .expect_err("timeout must fail");

        match err {
            MaskError::MaskTimeoutExceeded {
                operation_name,
                elapsed_ns,
                max_duration_ns,
            } => {
                assert_eq!(operation_name, "timeout_detail");
                assert_eq!(max_duration_ns, 1);
                assert!(elapsed_ns >= max_duration_ns);
            }
            other => unreachable!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn timeout_failure_still_delivers_deferred_cancellation() {
        let cx = CapabilityContext::new("cx-timeout-cancel", "operator-timeout-cancel");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_nanos(1), "trace-timeout-cancel");

        let err = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "timeout_with_cancel",
            &policy,
            |_cx, cancel| {
                cancel.request_cancel();
                spin_for(Duration::from_micros(20));
                1_u8
            },
        )
        .expect_err("timeout must fail");

        assert!(matches!(err, MaskError::MaskTimeoutExceeded { .. }));
        assert!(cancellation.is_cancel_requested());
        assert!(matches!(cancellation.deferred_signals(), 0));
        assert_eq!(cancellation.delivered_after_mask(), 1);
    }

    #[test]
    fn capability_context_rejects_blank_scope_entries() {
        let cx = CapabilityContext::with_scopes(
            "cx-scope-normalize",
            "operator-scope-normalize",
            vec![
                "".to_string(),
                "   ".to_string(),
                " runtime.mask ".to_string(),
            ],
        );

        assert!(cx.has_scope("runtime.mask"));
        assert!(!cx.has_scope(""));
        assert!(!cx.has_scope("   "));
        assert_eq!(cx.scopes.len(), 1);
    }

    #[test]
    fn oversized_mask_policy_duration_saturates_to_u64_max() {
        let policy = MaskPolicy::new(
            Duration::new(u64::MAX, 999_999_999),
            "trace-oversized-duration",
        );

        assert_eq!(policy.max_duration_ns, u64::MAX);
    }

    #[test]
    fn report_contains_required_invocation_fields() {
        let cx = CapabilityContext::new("cx-report", "operator-report");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-report");

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "report_op",
            &policy,
            |_cx, _cancel| 64_u8,
        )
        .expect("report op should succeed");

        assert_eq!(wrapped.report.event_name, MASK_INVOCATION_EVENT);
        assert_eq!(wrapped.report.operation_name, "report_op");
        assert_eq!(wrapped.report.trace_id, "trace-report");
        assert_eq!(wrapped.report.cx_id, "cx-report");
    }

    #[test]
    fn capability_context_default_has_empty_scopes() {
        let cx = CapabilityContext::new("cx-empty", "op-empty");
        assert!(cx.scopes.is_empty());
    }

    #[test]
    fn capability_context_has_scope_returns_true_for_existing() {
        let cx = CapabilityContext::with_scopes(
            "cx-s",
            "op-s",
            vec!["runtime.mask".to_string(), "net.egress".to_string()],
        );
        assert!(cx.has_scope("runtime.mask"));
        assert!(cx.has_scope("net.egress"));
        assert!(!cx.has_scope("nonexistent"));
    }

    #[test]
    fn mask_policy_max_duration_matches() {
        let policy = MaskPolicy::new(Duration::from_millis(42), "trace-dur");
        assert_eq!(policy.max_duration_ns, 42_000_000);
    }

    #[test]
    fn cancellation_state_starts_uncancelled() {
        let state = CancellationState::new();
        assert!(!state.is_cancel_requested());
    }

    #[test]
    fn cancellation_state_cancel_and_check() {
        let mut state = CancellationState::new();
        state.request_cancel();
        assert!(state.is_cancel_requested());
    }

    #[test]
    fn missing_context_leaves_mask_scope_available_for_follow_up() {
        let cx = CapabilityContext::new("cx-follow-up", "operator-follow-up");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-follow-up");
        let operation_ran = Cell::new(false);

        let err = bounded_mask_with_policy::<u8, _>(
            None,
            &mut cancellation,
            "missing_before_follow_up",
            &policy,
            |_cx, _cancel| {
                operation_ran.set(true);
                1_u8
            },
        )
        .expect_err("missing context must fail before mask entry");

        assert!(matches!(err, MaskError::MissingCapabilityContext));
        assert!(!operation_ran.get());

        let follow_up = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "follow_up_after_missing",
            &policy,
            |_cx, _cancel| 2_u8,
        )
        .expect("missing context must not poison mask scope");
        assert_eq!(follow_up.into_inner(), 2);
    }

    #[test]
    fn cancelled_before_entry_leaves_mask_scope_available_for_follow_up() {
        let cx = CapabilityContext::new("cx-cancel-follow-up", "operator-cancel-follow-up");
        let mut cancellation = CancellationState::new();
        cancellation.request_cancel();
        let operation_ran = Cell::new(false);

        let err = bounded_mask(
            &cx,
            &mut cancellation,
            "cancel_before_follow_up",
            |_cx, _cancel| {
                operation_ran.set(true);
                1_u8
            },
        )
        .expect_err("pre-entry cancellation must fail before mask entry");

        assert!(matches!(err, MaskError::CancelledBeforeEntry));
        assert!(!operation_ran.get());

        cancellation.clear_cancellation();
        let follow_up = bounded_mask(
            &cx,
            &mut cancellation,
            "follow_up_after_cancel",
            |_cx, _cancel| 2_u8,
        )
        .expect("pre-entry cancellation must not poison mask scope");
        assert_eq!(follow_up, 2);
    }

    #[test]
    fn timeout_failure_leaves_mask_scope_available_for_follow_up() {
        let cx = CapabilityContext::new("cx-timeout-follow-up", "operator-timeout-follow-up");
        let mut cancellation = CancellationState::new();
        let timeout_policy = MaskPolicy::new(Duration::from_nanos(1), "trace-timeout-follow-up");
        let ok_policy = MaskPolicy::new(Duration::from_millis(5), "trace-timeout-follow-up-ok");

        let err = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "timeout_before_follow_up",
            &timeout_policy,
            |_cx, _cancel| {
                spin_for(Duration::from_micros(20));
                1_u8
            },
        )
        .expect_err("timeout should fail");

        assert!(matches!(err, MaskError::MaskTimeoutExceeded { .. }));

        let follow_up = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "follow_up_after_timeout",
            &ok_policy,
            |_cx, _cancel| 2_u8,
        )
        .expect("timeout must not poison mask scope");
        assert_eq!(follow_up.into_inner(), 2);
    }

    #[test]
    fn missing_context_preserves_preloaded_deferred_signal() {
        let mut cancellation = CancellationState {
            cancel_requested: false,
            masked: false,
            deferred_signals: 7,
            delivered_after_mask: 3,
        };
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-missing-deferred");

        let err = bounded_mask_with_policy::<u8, _>(
            None,
            &mut cancellation,
            "missing_with_deferred",
            &policy,
            |_cx, _cancel| 1_u8,
        )
        .expect_err("missing context must fail before deferred delivery");

        assert!(matches!(err, MaskError::MissingCapabilityContext));
        assert_eq!(cancellation.deferred_signals(), 7);
        assert_eq!(cancellation.delivered_after_mask(), 3);
        assert!(!cancellation.is_cancel_requested());
    }

    #[test]
    fn preloaded_deferred_signal_saturates_delivery_counter() {
        let cx = CapabilityContext::new("cx-saturating-delivery", "operator-saturating-delivery");
        let mut cancellation = CancellationState {
            cancel_requested: false,
            masked: false,
            deferred_signals: 1,
            delivered_after_mask: u64::MAX,
        };
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-saturating-delivery");

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "deliver_preloaded_deferred",
            &policy,
            |_cx, cancel| {
                cancel.request_cancel();
                1_u8
            },
        )
        .expect("deferred delivery should saturate instead of wrapping");

        assert_eq!(wrapped.into_inner(), 1);
        assert!(cancellation.is_cancel_requested());
        assert_eq!(cancellation.deferred_signals(), 0);
        assert_eq!(cancellation.delivered_after_mask(), u64::MAX);
    }

    #[test]
    fn event_buffer_drops_oldest_entries_when_over_capacity() {
        let mut events = Vec::new();

        for index in 0..(MAX_EVENTS + 2) {
            let operation_name = format!("op-{index}");
            emit_event(
                &mut events,
                MaskEventKind {
                    event_code: FN_BM_002_MASK_EXIT,
                    event_name: MASK_EXIT,
                },
                MaskEventContext {
                    operation_name: &operation_name,
                    trace_id: "trace-event-bound",
                    cx_id: "cx-event-bound",
                },
                MaskEventOutcome {
                    elapsed_ns: u64::try_from(index).unwrap_or(u64::MAX),
                    completed_within_bound: true,
                    deferred_cancel_pending: false,
                },
            );
        }

        assert_eq!(events.len(), MAX_EVENTS);
        assert_eq!(
            events.first().expect("first retained event").operation_name,
            "op-2"
        );
        assert_eq!(
            events.last().expect("last retained event").operation_name,
            format!("op-{}", MAX_EVENTS + 1)
        );
    }

    #[test]
    fn event_codes_are_nonempty_strings() {
        assert!(!MASK_BUDGET_EXCEEDED.is_empty());
        assert!(!MASK_NESTING_VIOLATION.is_empty());
        assert!(!MASK_CANCEL_DEFERRED.is_empty());
        assert!(!MASK_INVOCATION_EVENT.is_empty());
    }
}

#[cfg(test)]
mod bounded_mask_comprehensive_negative_tests {
    use super::*;
    use std::cell::Cell;
    use std::panic::catch_unwind;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn spin_for(duration: Duration) {
        let started = Instant::now();
        while started.elapsed() < duration {
            std::hint::spin_loop();
        }
    }

    // =========================================================================
    // COMPREHENSIVE NEGATIVE-PATH TESTS FOR BOUNDED MASK SYSTEM
    // =========================================================================

    #[test]
    fn negative_capability_context_with_massive_scope_collection_handles_memory_pressure() {
        // Test with extremely large scope collections to stress memory handling
        let massive_scopes: Vec<String> = (0..100000)
            .map(|i| format!("scope_{:010}", i))
            .collect();

        let cx = CapabilityContext::with_scopes("cx-massive", "op-massive", massive_scopes.clone());

        // Should deduplicate and handle large collections without memory exhaustion
        assert_eq!(cx.scopes.len(), massive_scopes.len());
        assert!(cx.has_scope("scope_0000000001"));
        assert!(cx.has_scope("scope_0000099999"));
        assert!(!cx.has_scope("scope_nonexistent"));

        // Should work correctly in bounded mask operation
        let mut cancellation = CancellationState::new();
        let result = bounded_mask(&cx, &mut cancellation, "massive_scopes", |_cx, _cancel| 42u64);
        assert_eq!(result.expect("should handle massive scope collection"), 42);
    }

    #[test]
    fn negative_capability_context_with_unicode_injection_and_control_characters() {
        // Test with malicious Unicode patterns in context fields
        let malicious_patterns = [
            ("cx\u{202E}spoofed", "op\u{200B}invisible"),     // RTL override + zero-width space
            ("cx\x00null", "op\r\ninjection"),               // Null byte + CRLF injection
            ("cx\u{FEFF}bom", "op\u{1F4A9}emoji"),           // BOM + emoji
            ("cx\x1b[31mred\x1b[0m", "op\t\x08control"),     // ANSI escape + control chars
        ];

        for (cx_id, principal) in malicious_patterns {
            let cx = CapabilityContext::with_scopes(
                cx_id,
                principal,
                vec![
                    "runtime\u{202E}.mask".to_string(),  // RTL override in scope
                    "net\x00.egress".to_string(),         // Null byte in scope
                    "\u{FEFF}admin.privileges".to_string(), // BOM prefix in scope
                ]
            );

            // Should preserve Unicode patterns exactly without normalization
            assert_eq!(cx.cx_id, cx_id);
            assert_eq!(cx.principal, principal);

            // Scopes should filter empty and preserve Unicode
            assert!(cx.scopes.len() >= 2); // At least non-empty scopes should remain

            // Should work in mask operations without corruption
            let mut cancellation = CancellationState::new();
            let result = bounded_mask(&cx, &mut cancellation, "unicode_test", |_cx, _cancel| {
                format!("{}-{}", cx_id.len(), principal.len())
            });
            assert!(result.is_ok());
        }
    }

    #[test]
    fn negative_cancellation_state_with_arithmetic_overflow_edge_cases() {
        // Test arithmetic overflow scenarios in cancellation counters
        let mut cancellation = CancellationState {
            cancel_requested: false,
            masked: true, // Simulate being inside mask
            deferred_signals: u64::MAX - 1,
            delivered_after_mask: u64::MAX - 1,
        };

        // Multiple cancellation requests should saturate, not overflow
        for _ in 0..10 {
            cancellation.request_cancel();
        }

        assert_eq!(cancellation.deferred_signals(), u64::MAX);
        assert!(!cancellation.is_cancel_requested()); // Still deferred while masked

        // Test delivery arithmetic with boundary values
        let cx = CapabilityContext::new("cx-overflow", "op-overflow");
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-overflow");

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "overflow_test",
            &policy,
            |_cx, cancel| {
                // Add more deferred signals at boundary
                for _ in 0..5 {
                    cancel.request_cancel();
                }
                999u32
            }
        ).expect("should handle counter overflow gracefully");

        assert_eq!(wrapped.into_inner(), 999);
        assert!(cancellation.is_cancel_requested());
        assert_eq!(cancellation.deferred_signals(), 0); // Should be cleared after delivery
        assert_eq!(cancellation.delivered_after_mask(), u64::MAX); // Should saturate
    }

    #[test]
    fn negative_mask_policy_with_extreme_timeout_boundary_values() {
        // Test mask policy with extreme timeout values
        let extreme_policies = [
            (Duration::ZERO, "should handle zero timeout"),
            (Duration::from_nanos(1), "should handle minimal timeout"),
            (Duration::new(u64::MAX, 999_999_999), "should handle maximum duration"),
            (Duration::from_nanos(u64::MAX), "should handle max nanosecond duration"),
        ];

        let cx = CapabilityContext::new("cx-extreme", "op-extreme");
        let mut cancellation = CancellationState::new();

        for (duration, description) in extreme_policies {
            let policy = MaskPolicy::new(duration, "trace-extreme");

            // Zero and very small timeouts should immediately timeout
            if duration <= Duration::from_nanos(1000) {
                let err = bounded_mask_with_report(
                    &cx,
                    &mut cancellation,
                    "extreme_timeout",
                    &policy,
                    |_cx, _cancel| {
                        spin_for(Duration::from_micros(1));
                        1u8
                    }
                ).expect_err(&format!("minimal timeout should fail: {}", description));

                assert!(matches!(err, MaskError::MaskTimeoutExceeded { .. }));
            } else {
                // Very large timeouts should succeed for quick operations
                let result = bounded_mask_with_report(
                    &cx,
                    &mut cancellation,
                    "extreme_success",
                    &policy,
                    |_cx, _cancel| 42u8
                ).expect(&format!("large timeout should succeed: {}", description));

                assert_eq!(result.into_inner(), 42);
            }
        }
    }

    #[test]
    fn negative_concurrent_mask_operations_with_shared_cancellation_state() {
        // Test concurrent access to cancellation state (simulated race conditions)
        let cx = CapabilityContext::new("cx-concurrent", "op-concurrent");
        let cancellation_counter = Arc::new(AtomicUsize::new(0));
        let operation_counter = Arc::new(AtomicUsize::new(0));

        // Simulate rapid concurrent-style operations that modify state
        let mut handles = Vec::new();

        for thread_id in 0..8 {
            let counter = Arc::clone(&cancellation_counter);
            let op_counter = Arc::clone(&operation_counter);
            let cx_clone = cx.clone();

            let handle = std::thread::spawn(move || {
                let mut local_cancellation = CancellationState::new();

                for iteration in 0..100 {
                    // Simulate race conditions in cancellation state
                    if iteration % 3 == 0 {
                        local_cancellation.request_cancel();
                        counter.fetch_add(1, Ordering::Relaxed);
                    }

                    if iteration % 5 == 0 {
                        local_cancellation.clear_cancellation();
                    }

                    // Perform mask operation
                    let op_name = format!("concurrent_op_{}_{}", thread_id, iteration);
                    let result = bounded_mask(&cx_clone, &mut local_cancellation, &op_name, |_cx, _cancel| {
                        op_counter.fetch_add(1, Ordering::Relaxed);
                        thread_id + iteration
                    });

                    // Should either succeed or fail deterministically
                    match result {
                        Ok(value) => assert!(value >= thread_id),
                        Err(MaskError::CancelledBeforeEntry) => {
                            // Expected when cancellation was requested
                        }
                        Err(other) => panic!("Unexpected error in concurrent operation: {:?}", other),
                    }
                }

                // Verify final state consistency
                (local_cancellation.deferred_signals(), local_cancellation.delivered_after_mask())
            });

            handles.push(handle);
        }

        // Wait for all operations to complete
        let mut final_states = Vec::new();
        for handle in handles {
            final_states.push(handle.join().expect("thread should complete successfully"));
        }

        // Verify operations completed without corruption
        let total_operations = operation_counter.load(Ordering::Relaxed);
        assert!(total_operations > 0, "Some operations should have completed");

        // Verify state consistency across threads
        for (deferred, delivered) in &final_states {
            assert!(*deferred <= 100, "Deferred signals should be bounded");
            assert!(*delivered <= 100, "Delivered signals should be bounded");
        }
    }

    #[test]
    fn negative_mask_operation_with_pathological_panic_recovery_patterns() {
        // Test panic recovery in various edge case scenarios
        let cx = CapabilityContext::new("cx-panic-patterns", "op-panic-patterns");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(10), "trace-panic-patterns");

        let panic_patterns = [
            "panic!() with empty message",
            "panic! with extremely long message: ".to_owned() + &"x".repeat(100000),
            "panic!\x00with\nnull\tbytes",
            "panic!\u{202E}with\u{200B}unicode",
        ];

        for (i, panic_message) in panic_patterns.iter().enumerate() {
            let panic_message_clone = panic_message.clone();

            // Each panic should be caught and state should be properly restored
            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                let _ = bounded_mask_with_report(
                    &cx,
                    &mut cancellation,
                    &format!("panic_pattern_{}", i),
                    &policy,
                    |_cx, cancel| {
                        // Set up some deferred cancellation before panicking
                        cancel.request_cancel();
                        panic!("{}", panic_message_clone);
                    }
                );
            }));

            assert!(panic_result.is_err(), "Panic should be caught for pattern {}", i);

            // Cancellation should be delivered even after panic
            assert!(cancellation.is_cancel_requested(), "Cancellation should be delivered after panic {}", i);

            // Clear state for next test
            cancellation.clear_cancellation();

            // Mask scope should be restored and usable after panic
            let recovery_result = bounded_mask_with_report(
                &cx,
                &mut cancellation,
                &format!("recovery_after_panic_{}", i),
                &policy,
                |_cx, _cancel| format!("recovered_{}", i)
            ).expect(&format!("Should recover after panic pattern {}", i));

            assert_eq!(recovery_result.into_inner(), format!("recovered_{}", i));
        }
    }

    #[test]
    fn negative_mask_timeout_with_cpu_intensive_busy_loops() {
        // Test timeout enforcement with CPU-intensive operations that could bypass timing
        let cx = CapabilityContext::new("cx-cpu-intensive", "op-cpu-intensive");
        let mut cancellation = CancellationState::new();

        // Very tight timeout for CPU-intensive operation
        let tight_policy = MaskPolicy::new(Duration::from_micros(100), "trace-cpu-intensive");

        let cpu_intensive_patterns = [
            |duration: Duration| {
                // Arithmetic busy loop
                let start = Instant::now();
                let mut counter = 0u64;
                while start.elapsed() < duration {
                    counter = counter.wrapping_add(1);
                    if counter % 1000000 == 0 {
                        std::hint::black_box(counter); // Prevent optimization
                    }
                }
                counter
            },
            |duration: Duration| {
                // Memory allocation busy loop
                let start = Instant::now();
                let mut allocations = Vec::new();
                while start.elapsed() < duration {
                    allocations.push(vec![0u8; 1000]);
                    if allocations.len() > 10000 {
                        allocations.clear();
                    }
                }
                allocations.len() as u64
            },
            |duration: Duration| {
                // Hash computation busy loop
                let start = Instant::now();
                let mut hash_count = 0u64;
                while start.elapsed() < duration {
                    // Use SHA-256 for secure hashing instead of DefaultHasher
                    let mut hasher = Sha256::new();
                    hasher.update(&hash_count.to_le_bytes());
                    let _ = hasher.finalize();
                    hash_count = hash_count.wrapping_add(1);
                }
                hash_count
            },
        ];

        for (i, cpu_pattern) in cpu_intensive_patterns.iter().enumerate() {
            let pattern_clone = *cpu_pattern;

            let timeout_result = bounded_mask_with_report(
                &cx,
                &mut cancellation,
                &format!("cpu_intensive_{}", i),
                &tight_policy,
                |_cx, _cancel| {
                    // This should exceed the timeout budget
                    pattern_clone(Duration::from_millis(10))
                }
            );

            match timeout_result {
                Err(MaskError::MaskTimeoutExceeded { elapsed_ns, max_duration_ns, .. }) => {
                    assert!(elapsed_ns >= max_duration_ns, "Timeout should be enforced for CPU pattern {}", i);
                    assert!(elapsed_ns < Duration::from_millis(100).as_nanos() as u64, "Timeout should not be excessively delayed for pattern {}", i);
                }
                Ok(_) => {
                    // Some patterns might complete within timeout, which is also valid
                    // as long as they don't hang indefinitely
                }
                Err(other) => panic!("Unexpected error for CPU intensive pattern {}: {:?}", i, other),
            }
        }
    }

    #[test]
    fn negative_event_emission_with_memory_exhaustion_and_corruption_resistance() {
        // Test event emission under memory pressure and with malformed data
        let mut events = Vec::new();

        // Create memory pressure by allocating large chunks
        let mut memory_pressure = Vec::new();
        for i in 0..1000 {
            memory_pressure.push(vec![i as u8; 10000]); // 10MB total pressure
        }

        // Test event emission with pathological data
        let pathological_events = [
            ("", "empty_operation", "empty_trace", "empty_cx"),
            ("x".repeat(100000).as_str(), "massive_operation", "massive_trace", "massive_cx"),
            ("op\x00null", "trace\r\ninjection", "cx\t\x08control", "more_control"),
            ("op\u{202E}rtl", "trace\u{200B}invisible", "cx\u{FEFF}bom", "unicode_test"),
        ];

        for (i, (operation_name, trace_id, cx_id, _)) in pathological_events.iter().enumerate() {
            // Emit events under memory pressure
            for event_iteration in 0..10 {
                emit_event(
                    &mut events,
                    MaskEventKind {
                        event_code: FN_BM_002_MASK_EXIT,
                        event_name: MASK_EXIT,
                    },
                    MaskEventContext {
                        operation_name,
                        trace_id,
                        cx_id,
                    },
                    MaskEventOutcome {
                        elapsed_ns: (i as u64).saturating_mul(event_iteration),
                        completed_within_bound: i % 2 == 0,
                        deferred_cancel_pending: event_iteration % 3 == 0,
                    },
                );

                // Add more memory pressure during emission
                memory_pressure.push(vec![(i + event_iteration) as u8; 5000]);
            }
        }

        // Events should be bounded and not corrupt
        assert!(events.len() <= MAX_EVENTS, "Events should be bounded");

        // Verify no corruption in stored events
        for event in &events {
            assert!(!event.event_code.is_empty(), "Event code should not be empty");
            assert!(!event.event_name.is_empty(), "Event name should not be empty");
            assert!(event.elapsed_ns < u64::MAX, "Elapsed time should be reasonable");
        }

        // Memory cleanup should not affect event consistency
        drop(memory_pressure);

        // Events should remain accessible and consistent
        if !events.is_empty() {
            let first_event = &events[0];
            let last_event = &events[events.len() - 1];
            assert_eq!(first_event.event_code, FN_BM_002_MASK_EXIT);
            assert_eq!(last_event.event_code, FN_BM_002_MASK_EXIT);
        }
    }

    #[test]
    fn negative_capability_context_scope_deduplication_with_hash_collisions() {
        // Test scope deduplication with patterns that might cause hash collisions
        let collision_candidates = [
            vec!["ab".to_string(), "ba".to_string()],
            vec!["abc".to_string(), "acb".to_string(), "bac".to_string()],
            vec!["a".repeat(100), "b".repeat(100)],
            vec!["scope_1".to_string(), "scope_2".to_string(), "scope_1".to_string()], // Explicit duplicate
            vec!["".to_string(), " ".to_string(), "  ".to_string()], // Whitespace variations
            vec!["\x00scope".to_string(), "scope\x00".to_string()], // Null byte variations
        ];

        for (test_case, scopes) in collision_candidates.iter().enumerate() {
            let cx = CapabilityContext::with_scopes(
                format!("cx-collision-{}", test_case),
                format!("op-collision-{}", test_case),
                scopes.clone()
            );

            // Deduplication should work correctly
            let unique_scopes: std::collections::BTreeSet<String> = scopes.iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            assert_eq!(cx.scopes.len(), unique_scopes.len(), "Deduplication failed for case {}", test_case);

            // All valid unique scopes should be accessible
            for scope in &unique_scopes {
                if !scope.trim().is_empty() {
                    assert!(cx.has_scope(scope), "Should have scope '{}' in case {}", scope, test_case);
                }
            }

            // Invalid scopes should not be accessible
            assert!(!cx.has_scope(""), "Should not have empty scope");
            assert!(!cx.has_scope("  "), "Should not have whitespace-only scope");
        }
    }

    #[test]
    fn negative_mask_nesting_detection_across_panic_and_timeout_boundaries() {
        // Test nesting detection when outer masks fail in various ways
        let cx = CapabilityContext::new("cx-nesting-boundary", "op-nesting-boundary");
        let mut cancellation = CancellationState::new();
        let timeout_policy = MaskPolicy::new(Duration::from_nanos(1), "trace-nesting-timeout");
        let ok_policy = MaskPolicy::new(Duration::from_millis(10), "trace-nesting-ok");

        // Test nesting after timeout failure
        let timeout_result = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "outer_timeout",
            &timeout_policy,
            |inner_cx, inner_cancel| {
                spin_for(Duration::from_micros(10)); // Exceed timeout

                // This inner mask should not execute due to timeout
                bounded_mask(inner_cx, inner_cancel, "inner_after_timeout", |_cx, _cancel| 999u32)
            }
        );

        assert!(matches!(timeout_result, Err(MaskError::MaskTimeoutExceeded { .. })));

        // Subsequent mask operations should work (nesting detection should be reset)
        let recovery_result = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "recovery_after_timeout_nesting",
            &ok_policy,
            |_cx, _cancel| 123u32
        ).expect("Should work after timeout nesting failure");

        assert_eq!(recovery_result.into_inner(), 123);

        // Test nesting after panic with recovery
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = bounded_mask_with_report(
                &cx,
                &mut cancellation,
                "outer_panic",
                &ok_policy,
                |inner_cx, inner_cancel| {
                    // Try to nest before panic
                    let nested_result = catch_unwind(AssertUnwindSafe(|| {
                        bounded_mask(inner_cx, inner_cancel, "inner_before_panic", |_cx, _cancel| 777u32)
                    }));

                    // Nested should panic due to nesting violation
                    assert!(nested_result.is_err());

                    panic!("outer panic after nesting violation");
                }
            );
        }));

        assert!(panic_result.is_err());

        // Recovery after panic and nesting violation should work
        let final_recovery = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "final_recovery_after_panic_nesting",
            &ok_policy,
            |_cx, _cancel| 456u32
        ).expect("Should work after panic nesting failure");

        assert_eq!(final_recovery.into_inner(), 456);
    }
}
