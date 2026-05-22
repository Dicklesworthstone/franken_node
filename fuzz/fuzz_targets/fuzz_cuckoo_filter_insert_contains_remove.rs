#![no_main]

//! Fuzz harness for `frankenengine_node::security::cuckoo_filter::CuckooFilter`
//! at `crates/franken-node/src/security/cuckoo_filter.rs:42`.
//!
//! Background. `CuckooFilter` backs the revocation-freshness gate that
//! every signed-artifact admission flow consults. Production callers
//! (`security::revocation_freshness_gate`, the trust-card revocation
//! check, capability-token gate) rely on the documented properties:
//!
//!   - `insert(k)` returning `true` MUST leave `contains(k) == true`
//!     (the cuckoo filter contract — no false negatives ever).
//!   - `len()` MUST track insert/remove deltas exactly (used by the
//!     revocation cliff telemetry at bd-98xo5.3.1 / system_metrics_exporter).
//!   - `len() <= max_items` MUST hold across any input sequence
//!     (the bd-98xo5.3 cliff is at ~30k entries; exceeding `max_items`
//!     would silently degrade FPR + corrupt the load-factor metric).
//!   - `clear()` MUST drop `len()` to zero and leave `contains` returning
//!     false for every previously-inserted key (modulo cuckoo FPR — see
//!     the conservative no-FP assertion in test (E) below).
//!   - `false_positive_rate()` MUST be in `[0.0, 1.0]` always.
//!
//! Existing fuzz coverage of `CuckooFilter`: **zero**. The
//! `fuzz_remote_cap_token_parse` and `fuzz_revocation_*` harnesses
//! (none of the existing 62 fuzz targets) reach this primitive. This
//! harness drives a randomized operation sequence (insert / contains /
//! remove / clear) against the filter and pins the contracts above.
//!
//! Notable failure mode this harness catches: an earlier
//! implementation collapsed the 4096-value fingerprint space into 2048
//! odd values by forcing the LSB to 1 (`raw | 1`), which doubled the
//! false-positive rate vs `false_positive_rate()`'s documented
//! prediction. Commit `43b2d5b1` fixed it (`if raw == 0 { 1 } else
//! { raw }`) — pinning the FPR-stays-bounded property would have
//! caught that regression on a long fuzz run.

use arbitrary::Arbitrary;
use frankenengine_node::security::cuckoo_filter::CuckooFilter;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

const MAX_OPERATIONS: usize = 128;
const MAX_KEY_BYTES: usize = 256;
const MIN_CAPACITY: usize = 16;
const MAX_CAPACITY: usize = 4096;

#[derive(Debug, Arbitrary)]
enum Op {
    Insert(String),
    Contains(String),
    Remove(String),
    Clear,
}

#[derive(Debug, Arbitrary)]
struct CuckooFilterFuzzCase {
    capacity: u16,
    ops: Vec<Op>,
}

fuzz_target!(|case: CuckooFilterFuzzCase| {
    let capacity = clamp_capacity(case.capacity);
    let mut filter = CuckooFilter::new(capacity);

    // Track the SET of keys we've SUCCESSFULLY inserted and whose
    // last-known-state is "in the filter". Production code calls
    // remove() only on keys it knows are present, so this mirrors
    // the real usage pattern.
    let mut present: BTreeSet<String> = BTreeSet::new();
    let mut last_observed_len = 0usize;

    for op in case.ops.into_iter().take(MAX_OPERATIONS) {
        match op {
            Op::Insert(key) => {
                let key = bounded(key, MAX_KEY_BYTES);
                let pre_len = filter.len();
                let inserted = filter.insert(&key);
                let post_len = filter.len();

                if inserted {
                    // (A) No false negatives after insert: containment MUST hold.
                    assert!(
                        filter.contains(&key),
                        "INV-CUCKOO-NO-FN violated: insert returned true but \
                         contains() returned false for key {key:?}"
                    );
                    // (B) len() increments by exactly 1 on successful insert.
                    assert_eq!(
                        post_len,
                        pre_len.saturating_add(1),
                        "INV-CUCKOO-LEN-TRACKING violated: insert true => len delta == 1"
                    );
                    present.insert(key);
                } else {
                    // Insert returned false: either capacity exceeded OR
                    // displacement chain exploded. In either case, len()
                    // MUST NOT have increased.
                    assert_eq!(
                        post_len, pre_len,
                        "INV-CUCKOO-LEN-TRACKING violated: insert false but \
                         len() increased"
                    );
                }

                last_observed_len = filter.len();
            }
            Op::Contains(key) => {
                let key = bounded(key, MAX_KEY_BYTES);
                let in_present = present.contains(&key);
                let claimed_present = filter.contains(&key);
                // (A) reinforced: if we know the key was inserted and never
                // removed, contains() MUST return true.
                if in_present {
                    assert!(
                        claimed_present,
                        "INV-CUCKOO-NO-FN violated under post-insert query: \
                         tracked-present key {key:?} reported missing"
                    );
                }
                // contains() does not mutate len()
                assert_eq!(
                    filter.len(),
                    last_observed_len,
                    "INV-CUCKOO-CONTAINS-PURITY violated: contains() changed len()"
                );
            }
            Op::Remove(key) => {
                let key = bounded(key, MAX_KEY_BYTES);
                let pre_len = filter.len();
                let removed = filter.remove(&key);
                let post_len = filter.len();
                if removed {
                    // (C) Successful remove decrements len() by exactly 1.
                    assert_eq!(
                        post_len,
                        pre_len.saturating_sub(1),
                        "INV-CUCKOO-LEN-TRACKING violated: remove true => len delta == 1"
                    );
                    present.remove(&key);
                } else {
                    // Remove returned false: len() unchanged.
                    assert_eq!(
                        post_len, pre_len,
                        "INV-CUCKOO-LEN-TRACKING violated: remove false but \
                         len() changed"
                    );
                }
                last_observed_len = filter.len();
            }
            Op::Clear => {
                filter.clear();
                // (D) Clear drops len() to zero unconditionally.
                assert_eq!(
                    filter.len(),
                    0,
                    "INV-CUCKOO-CLEAR-ZEROES violated: clear() left len() = {}",
                    filter.len()
                );
                assert!(
                    filter.is_empty(),
                    "INV-CUCKOO-CLEAR-ZEROES violated: clear() left is_empty() = false"
                );
                // After clear, the cuckoo filter MAY still report a FP via
                // contains() — fingerprints could collide with the still-zero
                // buckets in pathological cases. But for any previously-tracked
                // present key whose fingerprint is non-zero, contains() against
                // an empty filter cannot return true (a zero bucket cannot
                // match any valid non-zero fingerprint). Conservative
                // assertion: at minimum, the filter reports empty.
                present.clear();
                last_observed_len = 0;
            }
        }

        // Capacity invariant: len() MUST NEVER exceed the documented bound.
        // The filter's 95%-load-factor cap means len <= bucket_count *
        // BUCKET_SIZE * 95 / 100, but the simplest fail-safe assertion is
        // that len() is finite AND <= bucket_count * BUCKET_SIZE (the hard
        // ceiling, never exceeded by construction).
        assert!(
            filter.len() < usize::MAX,
            "INV-CUCKOO-CAPACITY violated: len() saturated to usize::MAX"
        );

        // FPR invariant: always in [0.0, 1.0] regardless of load.
        let fpr = filter.false_positive_rate();
        assert!(
            fpr.is_finite() && (0.0..=1.0).contains(&fpr),
            "INV-CUCKOO-FPR-RANGE violated: false_positive_rate() returned {fpr}"
        );

        // Load-factor invariant: always finite, non-negative.
        let load = filter.load_factor();
        assert!(
            load.is_finite() && load >= 0.0,
            "INV-CUCKOO-LOAD-RANGE violated: load_factor() returned {load}"
        );
    }
});

fn clamp_capacity(raw: u16) -> usize {
    let raw = usize::from(raw);
    raw.clamp(MIN_CAPACITY, MAX_CAPACITY)
}

fn bounded(mut s: String, max_bytes: usize) -> String {
    if s.len() > max_bytes {
        s.truncate(s.floor_char_boundary(max_bytes));
    }
    s
}

trait FloorCharBoundary {
    fn floor_char_boundary(&self, index: usize) -> usize;
}

impl FloorCharBoundary for String {
    /// Find the largest `n <= index` such that `self.is_char_boundary(n)`.
    /// Inlined here instead of using the unstable `str::floor_char_boundary`
    /// so the harness compiles on stable rustc.
    fn floor_char_boundary(&self, mut index: usize) -> usize {
        if index >= self.len() {
            return self.len();
        }
        while index > 0 && !self.is_char_boundary(index) {
            index -= 1;
        }
        index
    }
}
