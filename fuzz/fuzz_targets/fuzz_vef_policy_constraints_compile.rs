#![no_main]
#![forbid(unsafe_code)]

//! Fuzz `connector::vef_policy_constraints::compile_policy` +
//! `round_trip_semantics` + `proof_generator_accepts` at
//! `crates/franken-node/src/connector/vef_policy_constraints.rs`.
//!
//! `RuntimePolicy` is `#[derive(Deserialize)]` and is the input boundary
//! for the VEF policy compiler. Peer commit `1ae41a1f`
//! (`fix(vef_policy_constraints): reject control chars in policy_id/rule_id`)
//! just hardened the identifier-validation seam; the module has no
//! existing fuzz harness.
//!
//! Invariants pinned on every JSON input that parses to a `RuntimePolicy`:
//!
//!   1. `compile_policy(&policy, "fuzz-trace")` never panics — it returns
//!      either `Ok(envelope)` or `Err(ConstraintCompileError)`.
//!   2. **Compile→accept consistency**: if `compile_policy` returns Ok,
//!      then `proof_generator_accepts(&envelope)` MUST return true. The
//!      production contract is that any successfully compiled envelope is
//!      shaped acceptably for the proof worker — a divergence between
//!      compiler and acceptance gate would let an internally-malformed
//!      envelope reach the proof step.
//!   3. **Semantic round-trip**: if `round_trip_semantics(&policy, ...)`
//!      returns `Ok(false)`, that's a real bug (semantic loss between
//!      compile and decompile). The function is documented as returning
//!      `Ok(true)` on the success path; a `false` from the success path
//!      means `compile_policy(decompile_projection(compile_policy(p)))`
//!      drifted from `p` — a load-bearing determinism failure.
//!
//! Inputs are length-capped at 256 KiB to keep per-iteration cost bounded.

use frankenengine_node::connector::vef_policy_constraints::{
    compile_policy, proof_generator_accepts, round_trip_semantics, RuntimePolicy,
};
use libfuzzer_sys::fuzz_target;
use std::str;

const FUZZ_TRACE_ID: &str = "fuzz-trace-001";

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let Ok(json_str) = str::from_utf8(data) else {
        return;
    };

    let Ok(policy) = serde_json::from_str::<RuntimePolicy>(json_str) else {
        return;
    };

    // Invariant 1: compile_policy never panics.
    let envelope = match compile_policy(&policy, FUZZ_TRACE_ID) {
        Ok(env) => env,
        Err(_) => {
            // Compile error is a valid outcome. Also pin that
            // round_trip_semantics agrees — if the compiler rejects, the
            // round-trip function must also surface the same Err (it
            // calls compile_policy internally).
            assert!(
                round_trip_semantics(&policy, FUZZ_TRACE_ID).is_err(),
                "round_trip_semantics must Err when compile_policy Errs (it shares the compile path)"
            );
            return;
        }
    };

    // Invariant 2: a compiled envelope must be accepted by the proof gate.
    // The compiler and the acceptance gate must agree on what "valid" means.
    assert!(
        proof_generator_accepts(&envelope),
        "compile_policy returned Ok but proof_generator_accepts rejected the envelope — \
         compiler/acceptor consistency violated"
    );

    // Invariant 3: semantic round-trip succeeds for any compilable policy.
    match round_trip_semantics(&policy, FUZZ_TRACE_ID) {
        Ok(true) => {
            // Documented success path.
        }
        Ok(false) => {
            // Documented as "no semantic loss"; Ok(false) means the
            // decompile-then-recompile didn't match the original — a
            // determinism / loss-of-information bug.
            panic!(
                "round_trip_semantics returned Ok(false) — semantic projection lost information \
                 between compile and decompile (load-bearing determinism invariant)"
            );
        }
        Err(_) => {
            // The compile already succeeded, so round_trip_semantics
            // should not be able to surface a compile error here. If it
            // does, the two paths have diverged.
            panic!(
                "round_trip_semantics Err after compile_policy Ok — the two compile paths diverged"
            );
        }
    }
});
