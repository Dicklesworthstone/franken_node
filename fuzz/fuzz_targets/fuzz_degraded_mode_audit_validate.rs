#![no_main]

//! Fuzz harness for
//! `frankenengine_node::security::degraded_mode_audit::{validate_schema,
//! DegradedModeAuditLog::emit}` at
//! `crates/franken-node/src/security/degraded_mode_audit.rs:55` and
//! `:122`. The audit log records every stale-revocation override —
//! a regression that admits an empty `action_id` or a wrong
//! `event_type` would let an attacker emit an unidentifiable
//! "override" entry that downstream auditors cannot correlate to
//! the originating action.
//!
//! Existing fuzz coverage of this audit surface: **zero**.
//!
//! Five invariants pinned per call:
//!
//!   (A) **INV-DM-PANIC-FREE** — arbitrary inputs MUST NOT panic the
//!       validator or the audit log.
//!
//!   (B) **INV-DM-SCHEMA-EMPTY-REJECT** — `validate_schema` MUST
//!       return `Err(MissingField { .. })` when ANY required field
//!       is empty-after-trim. The harness asserts that every
//!       successfully-validated event carries non-trim-empty values
//!       for every required string field.
//!
//!   (C) **INV-DM-SCHEMA-EVENT-TYPE-FIXED** — `validate_schema` MUST
//!       return `Err(SchemaViolation)` when `event_type` is anything
//!       other than `"degraded_mode_override"`. Catches a regression
//!       where the event_type guard is dropped.
//!
//!   (D) **INV-DM-EMIT-FAIL-NO-APPEND** — `emit(event)` on an invalid
//!       event MUST leave the log's `count()` unchanged.
//!
//!   (E) **INV-DM-EMIT-OK-APPENDS-ONCE** — `emit(event)` on a valid
//!       event MUST advance `count()` by exactly 1, and
//!       `find_by_action(action_id)` MUST return at least one entry
//!       for the event's action_id.

use arbitrary::Arbitrary;
use frankenengine_node::security::degraded_mode_audit::{
    validate_schema, AuditError, DegradedModeAuditLog, DegradedModeEvent,
};
use libfuzzer_sys::fuzz_target;

const MAX_FIELD_BYTES: usize = 256;
const EVENT_TYPE_CANONICAL: &str = "degraded_mode_override";

#[derive(Debug, Arbitrary)]
struct DegradedModeAuditFuzzCase {
    event_type: String,
    action_id: String,
    actor: String,
    tier: String,
    revocation_age_secs: u64,
    max_age_secs: u64,
    override_reason: String,
    trace_id: String,
    timestamp: String,
    force_event_type_canonical: bool,
}

fuzz_target!(|case: DegradedModeAuditFuzzCase| {
    let event_type = if case.force_event_type_canonical {
        EVENT_TYPE_CANONICAL.to_string()
    } else {
        bounded(&case.event_type, MAX_FIELD_BYTES)
    };
    let event = DegradedModeEvent {
        event_type: event_type.clone(),
        action_id: bounded(&case.action_id, MAX_FIELD_BYTES),
        actor: bounded(&case.actor, MAX_FIELD_BYTES),
        tier: bounded(&case.tier, MAX_FIELD_BYTES),
        revocation_age_secs: case.revocation_age_secs,
        max_age_secs: case.max_age_secs,
        override_reason: bounded(&case.override_reason, MAX_FIELD_BYTES),
        trace_id: bounded(&case.trace_id, MAX_FIELD_BYTES),
        timestamp: bounded(&case.timestamp, MAX_FIELD_BYTES),
    };

    // ── (A) Panic-freedom: validate_schema call itself is the assertion ─
    let validation = validate_schema(&event);

    // ── (B) Schema empty-reject: a Ok validation MUST mean every
    //    required string field is non-trim-empty.
    if validation.is_ok() {
        assert!(
            !event.event_type.trim().is_empty(),
            "INV-DM-SCHEMA-EMPTY-REJECT violated: event_type accepted as empty-after-trim"
        );
        assert!(
            !event.action_id.trim().is_empty(),
            "INV-DM-SCHEMA-EMPTY-REJECT violated: action_id accepted as empty"
        );
        assert!(
            !event.actor.trim().is_empty(),
            "INV-DM-SCHEMA-EMPTY-REJECT violated: actor accepted as empty"
        );
        assert!(
            !event.tier.trim().is_empty(),
            "INV-DM-SCHEMA-EMPTY-REJECT violated: tier accepted as empty"
        );
        assert!(
            !event.override_reason.trim().is_empty(),
            "INV-DM-SCHEMA-EMPTY-REJECT violated: override_reason accepted as empty"
        );
        assert!(
            !event.trace_id.trim().is_empty(),
            "INV-DM-SCHEMA-EMPTY-REJECT violated: trace_id accepted as empty"
        );
        assert!(
            !event.timestamp.trim().is_empty(),
            "INV-DM-SCHEMA-EMPTY-REJECT violated: timestamp accepted as empty"
        );

        // ── (C) event_type must equal the canonical string when Ok.
        assert_eq!(
            event.event_type, EVENT_TYPE_CANONICAL,
            "INV-DM-SCHEMA-EVENT-TYPE-FIXED violated: validate_schema accepted \
             event_type={:?}, must be {EVENT_TYPE_CANONICAL:?}",
            event.event_type
        );
    } else {
        // Rejection must surface a documented error variant.
        let err = validation.as_ref().err().expect("checked is_ok above");
        match err {
            AuditError::MissingField { .. } | AuditError::SchemaViolation { .. } => {
                // Both rejection variants are valid; pin the error class.
            }
            AuditError::EventNotFound { .. } => {
                panic!(
                    "INV-DM-SCHEMA validate_schema returned EventNotFound — \
                     should only surface MissingField or SchemaViolation: {err:?}"
                );
            }
        }
    }

    // ── (D)/(E) emit() respects validation outcome ─────────────────
    let mut log = DegradedModeAuditLog::new();
    let pre_count = log.count();
    assert_eq!(pre_count, 0, "fresh DegradedModeAuditLog must be empty");

    let emit_result = log.emit(event.clone());
    let post_count = log.count();

    if emit_result.is_ok() {
        // (E) successful emit must append exactly one event.
        assert_eq!(
            post_count, 1,
            "INV-DM-EMIT-OK-APPENDS-ONCE violated: successful emit produced \
             count={post_count}, expected 1"
        );
        let found = log.find_by_action(&event.action_id);
        assert!(
            !found.is_empty(),
            "INV-DM-EMIT-OK-APPENDS-ONCE violated: find_by_action({:?}) returned \
             no entries after successful emit",
            event.action_id
        );
    } else {
        // (D) failed emit must leave count unchanged.
        assert_eq!(
            post_count, pre_count,
            "INV-DM-EMIT-FAIL-NO-APPEND violated: rejected emit changed count \
             from {pre_count} to {post_count}"
        );
    }
});

fn bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}
