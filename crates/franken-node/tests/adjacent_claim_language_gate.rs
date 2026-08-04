// bd-6r7c4: `clippy::module_inception` fires because this `#[path]` shim gives
// the inner module the same name as the target. Renaming it would break the
// `crate::adjacent_claim_language_gate::{...}` paths the sibling golden tests
// use, so the shim keeps its name and the lint is allowed here.
#[allow(clippy::module_inception)]
#[path = "../../../tests/conformance/adjacent_claim_language_gate.rs"]
mod adjacent_claim_language_gate;
// Surface the conformance module's public items one level up so sibling test
// modules (e.g. claims_golden_tests) can `use crate::adjacent_claim_language_gate::{...}`
// directly. Without this re-export the #[path] shim nests the real types a second
// module level deep and keeps that inner module private (E0432 + E0603).
pub use adjacent_claim_language_gate::*;
