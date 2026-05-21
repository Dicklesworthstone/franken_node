//! Fuzz target: byte-parity between the OLD canonicalize-then-serialise
//! encoder and the NEW streaming canonical_bytes encoder (bd-98xo5.4.7).
//!
//! ## What this harness pins
//!
//! The bd-98xo5.4.2 streaming encoder shipped at commit b6a75037
//! replaced trust_card's canonicalize_value (move-based tree rebuild)
//! + serde_json::to_string chain. The optimisation is only safe if
//! every input produces byte-identical canonical bytes through both
//! paths — a divergence means an existing card_hash on disk would
//! silently mismatch its recomputed value after the swap, breaking
//! the entire trust chain.
//!
//! Inline tests (bd-98xo5.4.2 + 4.3) cover the property at 256-1024
//! cases. This fuzz harness extends coverage to libfuzzer's
//! arbitrary-input space, which exercises a much wider set of
//! Value shapes (key collisions, deeply-recursive arrays, escape
//! corner cases) than the proptest strategies reach.
//!
//! The harness pulls a `serde_json::Value` from `Unstructured` via
//! `Arbitrary`. For each value, it computes:
//!
//!   OLD = canon_then_to_vec(value)        — move-based tree rebuild + to_vec
//!   NEW = canonical_bytes(&value)         — streaming, borrow-based
//!
//! and asserts OLD == NEW. libfuzzer panics on any divergence and
//! shrinks the offending input automatically.
//!
//! ## Out of scope
//!
//! - This harness operates on serde_json::Value, not on the TrustCard
//!   struct directly. Trust-card-specific fuzzing would require a
//!   feature gate plus an Arbitrary derive on TrustCard, and the
//!   parity property holds at the Value level regardless of where
//!   the Value came from.
//! - Non-finite f64 inputs cannot be constructed via
//!   serde_json::Number::from_f64 (it returns None), so the fuzz
//!   harness never sees a Value::Number(NaN) etc. — this matches
//!   production reality.

#![no_main]

use libfuzzer_sys::fuzz_target;

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_node::connector::canonical_serializer::canonical_bytes;
use serde_json::Value;

/// Move-based reference encoder mirroring the OLD
/// supply_chain::trust_card::canonicalize_value pattern: collect
/// entries via into_iter(), sort by key, rebuild Map, then
/// serde_json::to_vec the rebuilt tree. NO Value::clone() — same
/// move semantics as production used to use.
fn old_canonicalize_then_serialize(value: Value) -> Vec<u8> {
    fn canon(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut entries: Vec<_> = map.into_iter().collect();
                entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
                let mut out = serde_json::Map::with_capacity(entries.len());
                for (k, v) in entries {
                    out.insert(k, canon(v));
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.into_iter().map(canon).collect()),
            other => other,
        }
    }
    let rebuilt = canon(value);
    serde_json::to_vec(&rebuilt).expect("rebuilt canonical value must serialise")
}

/// Lightweight Value generator from Unstructured. Avoids deriving
/// Arbitrary on serde_json::Value directly (which would pull in the
/// `arbitrary` feature on serde_json, an indirect dep change) by
/// constructing the Value tree from primitive Arbitrary impls.
fn arbitrary_value(u: &mut Unstructured<'_>, depth: u8) -> arbitrary::Result<Value> {
    // Cap recursion depth so libfuzzer doesn't stack-overflow on
    // deeply-nested adversarial inputs.
    if depth == 0 {
        let leaf_kind = u8::arbitrary(u)? % 4;
        return Ok(match leaf_kind {
            0 => Value::Null,
            1 => Value::Bool(bool::arbitrary(u)?),
            2 => Value::Number(i64::arbitrary(u)?.into()),
            _ => Value::String(String::arbitrary(u)?),
        });
    }
    let kind = u8::arbitrary(u)? % 6;
    match kind {
        0 => Ok(Value::Null),
        1 => Ok(Value::Bool(bool::arbitrary(u)?)),
        2 => Ok(Value::Number(i64::arbitrary(u)?.into())),
        3 => Ok(Value::Number(u64::arbitrary(u)?.into())),
        4 => {
            // Array with up to 8 children.
            let len = (u8::arbitrary(u)? % 8) as usize;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(arbitrary_value(u, depth - 1)?);
            }
            Ok(Value::Array(arr))
        }
        _ => {
            // Object with up to 8 keys. Insertion order is preserved
            // by serde_json::Map, but the canonical encoders sort, so
            // duplicate keys (from arbitrary input) collapse to one
            // entry via the last-write-wins Map insert semantics.
            let len = (u8::arbitrary(u)? % 8) as usize;
            let mut map = serde_json::Map::new();
            for _ in 0..len {
                let key = String::arbitrary(u)?;
                let val = arbitrary_value(u, depth - 1)?;
                map.insert(key, val);
            }
            Ok(Value::Object(map))
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(value) = arbitrary_value(&mut u, 4) else {
        return;
    };

    let new_bytes = canonical_bytes(&value);
    let old_bytes = old_canonicalize_then_serialize(value);

    assert_eq!(
        new_bytes, old_bytes,
        "canonical_bytes divergence: NEW streaming encoder vs OLD canonicalize-then-serialise"
    );
});
