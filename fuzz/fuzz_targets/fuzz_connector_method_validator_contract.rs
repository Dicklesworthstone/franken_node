#![no_main]

//! Fuzz harness for
//! `frankenengine_node::conformance::connector_method_validator::validate_contract`
//! at `crates/franken-node/src/conformance/connector_method_validator.rs:142`.
//! The function validates a connector's `MethodDeclaration` set against
//! the pinned `STANDARD_METHODS` specification — a regression admitting
//! a required-method-missing declaration or a version-incompatible
//! version would let a non-conformant connector pass admission and
//! corrupt the runtime's method-dispatch contract.
//!
//! Existing fuzz coverage of this validator: **zero**.
//!
//! Five invariants pinned per call:
//!
//!   (A) **INV-CMV-PANIC-FREE** — arbitrary declarations MUST NOT
//!       panic the validator.
//!
//!   (B) **INV-CMV-TOTAL-METHODS-FIXED** — `report.summary.total_methods`
//!       equals `STANDARD_METHODS.len()` (currently 9) regardless of
//!       input declaration list. Catches a regression that double-counts
//!       declarations or drops a standard method from the iteration.
//!
//!   (C) **INV-CMV-COUNT-CONSERVATION** — `passing + failing + skipped`
//!       equals `total_methods`. Catches a regression where a method
//!       is classified into more than one bucket or none.
//!
//!   (D) **INV-CMV-DETERMINISM** — `validate_contract(id, decls)`
//!       called twice produces structurally-equal reports (same
//!       summary counters, same number of method results).
//!
//!   (E) **INV-CMV-EMPTY-INPUT-ALL-REQUIRED-FAIL** — when declarations
//!       is empty, every REQUIRED method MUST fail with
//!       `MethodMissing`. Catches a regression where missing required
//!       methods are silently classified as "skipped" rather than
//!       "failing".

use arbitrary::Arbitrary;
use frankenengine_node::conformance::connector_method_validator::{
    validate_contract, MethodDeclaration,
};
use libfuzzer_sys::fuzz_target;

const MAX_DECLARATIONS: usize = 32;
const MAX_NAME_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 32;
const MAX_CONNECTOR_ID_BYTES: usize = 256;

// Pinned in connector_method_validator.rs:331 — `assert_eq!(STANDARD_METHODS.len(), 9)`.
const EXPECTED_TOTAL_METHODS: usize = 9;

#[derive(Debug, Arbitrary)]
struct ConnectorContractFuzzCase {
    connector_id: String,
    declarations: Vec<RawDeclaration>,
}

#[derive(Debug, Arbitrary)]
struct RawDeclaration {
    name: String,
    version: String,
    has_input_schema: bool,
    has_output_schema: bool,
}

fuzz_target!(|case: ConnectorContractFuzzCase| {
    let connector_id = bounded(&case.connector_id, MAX_CONNECTOR_ID_BYTES);
    let declarations: Vec<MethodDeclaration> = case
        .declarations
        .iter()
        .take(MAX_DECLARATIONS)
        .map(|r| MethodDeclaration {
            name: bounded(&r.name, MAX_NAME_BYTES),
            version: bounded(&r.version, MAX_VERSION_BYTES),
            has_input_schema: r.has_input_schema,
            has_output_schema: r.has_output_schema,
        })
        .collect();

    // ── (A) Panic-freedom: the call IS the assertion ────────────────
    let report = validate_contract(&connector_id, &declarations);

    // ── (B) Total methods = STANDARD_METHODS.len() = 9
    assert_eq!(
        report.summary.total_methods, EXPECTED_TOTAL_METHODS,
        "INV-CMV-TOTAL-METHODS-FIXED violated: report.summary.total_methods={} \
         but STANDARD_METHODS.len() should be {EXPECTED_TOTAL_METHODS}",
        report.summary.total_methods,
    );
    assert_eq!(
        report.methods.len(),
        EXPECTED_TOTAL_METHODS,
        "INV-CMV-TOTAL-METHODS-FIXED violated: results.len()={} != \
         STANDARD_METHODS.len()={EXPECTED_TOTAL_METHODS}",
        report.methods.len(),
    );

    // ── (C) Count conservation
    assert_eq!(
        report.summary.passing + report.summary.failing + report.summary.skipped,
        report.summary.total_methods,
        "INV-CMV-COUNT-CONSERVATION violated: passing({}) + failing({}) + skipped({}) \
         != total_methods({})",
        report.summary.passing,
        report.summary.failing,
        report.summary.skipped,
        report.summary.total_methods,
    );

    // ── (D) Determinism: second call must produce structurally-identical report.
    let report2 = validate_contract(&connector_id, &declarations);
    assert_eq!(
        report.summary, report2.summary,
        "INV-CMV-DETERMINISM violated: summary differs across consecutive calls"
    );
    assert_eq!(
        report.methods.len(),
        report2.methods.len(),
        "INV-CMV-DETERMINISM violated: results.len() differs"
    );
    for (r1, r2) in report.methods.iter().zip(report2.methods.iter()) {
        assert_eq!(
            r1.method, r2.method,
            "INV-CMV-DETERMINISM violated: method name order differs"
        );
        assert_eq!(
            r1.status, r2.status,
            "INV-CMV-DETERMINISM violated: status differs for {:?}",
            r1.method
        );
    }

    // ── (E) Empty-input → every required method FAILS.
    let empty_report = validate_contract(&connector_id, &[]);
    assert_eq!(
        empty_report.summary.total_methods, EXPECTED_TOTAL_METHODS,
        "empty input total_methods must equal STANDARD_METHODS.len()"
    );
    let required_methods = empty_report.summary.required_methods;
    assert_eq!(
        empty_report.summary.failing, required_methods,
        "INV-CMV-EMPTY-INPUT-ALL-REQUIRED-FAIL violated: with empty declarations, \
         failing({}) must equal required_methods({required_methods})",
        empty_report.summary.failing,
    );
    assert_eq!(
        empty_report.summary.passing, 0,
        "INV-CMV-EMPTY-INPUT-ALL-REQUIRED-FAIL violated: empty declarations \
         should not pass any methods, got passing={}",
        empty_report.summary.passing
    );
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
