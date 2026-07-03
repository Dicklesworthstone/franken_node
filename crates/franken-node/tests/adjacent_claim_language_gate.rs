#[path = "../../../tests/conformance/adjacent_claim_language_gate.rs"]
mod adjacent_claim_language_gate;
// Surface the conformance module's public items one level up so sibling test
// modules (e.g. claims_golden_tests) can `use crate::adjacent_claim_language_gate::{...}`
// directly. Without this re-export the #[path] shim nests the real types a second
// module level deep and keeps that inner module private (E0432 + E0603).
pub use adjacent_claim_language_gate::*;
