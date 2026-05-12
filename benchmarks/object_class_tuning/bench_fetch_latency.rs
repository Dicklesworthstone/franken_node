//! bd-8tvs benchmark artifact: fetch-latency policy rows for object tuning.
//!
//! This file records the deterministic latency budget used to assign fetch
//! priority and prefetch policy for each canonical object class.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FetchLatencyRow {
    pub class_id: &'static str,
    pub fetch_priority: &'static str,
    pub prefetch_policy: &'static str,
    pub p50_fetch_us: f64,
    pub p99_fetch_us: f64,
    pub max_inflight_hint: u32,
}

pub const FETCH_LATENCY_ROWS: &[FetchLatencyRow] = &[
    FetchLatencyRow {
        class_id: "critical_marker",
        fetch_priority: "critical",
        prefetch_policy: "eager",
        p50_fetch_us: 5.2,
        p99_fetch_us: 9.4,
        max_inflight_hint: 512,
    },
    FetchLatencyRow {
        class_id: "trust_receipt",
        fetch_priority: "normal",
        prefetch_policy: "lazy",
        p50_fetch_us: 11.7,
        p99_fetch_us: 24.6,
        max_inflight_hint: 256,
    },
    FetchLatencyRow {
        class_id: "replay_bundle",
        fetch_priority: "background",
        prefetch_policy: "none",
        p50_fetch_us: 44.8,
        p99_fetch_us: 96.2,
        max_inflight_hint: 64,
    },
    FetchLatencyRow {
        class_id: "telemetry_artifact",
        fetch_priority: "background",
        prefetch_policy: "none",
        p50_fetch_us: 19.4,
        p99_fetch_us: 42.0,
        max_inflight_hint: 128,
    },
];

pub fn rows_as_csv() -> String {
    use std::fmt::Write as _;

    let mut csv = String::from(
        "class_id,fetch_priority,prefetch_policy,p50_fetch_us,p99_fetch_us,max_inflight_hint\n",
    );
    for row in FETCH_LATENCY_ROWS {
        let _ = writeln!(
            &mut csv,
            "{},{},{},{:.1},{:.1},{}",
            row.class_id,
            row.fetch_priority,
            row.prefetch_policy,
            row.p50_fetch_us,
            row.p99_fetch_us,
            row.max_inflight_hint
        );
    }
    csv
}

#[cfg(test)]
mod tests {
    use super::FETCH_LATENCY_ROWS;

    fn ensure(condition: bool, message: &str) -> Result<(), String> {
        if condition {
            Ok(())
        } else {
            Err(message.to_string())
        }
    }

    #[test]
    fn benchmark_rows_cover_all_canonical_classes() -> Result<(), String> {
        let class_ids: Vec<&str> = FETCH_LATENCY_ROWS.iter().map(|row| row.class_id).collect();

        ensure(
            class_ids
                == vec![
                    "critical_marker",
                    "trust_receipt",
                    "replay_bundle",
                    "telemetry_artifact",
                ],
            "canonical class coverage drifted",
        )
    }

    #[test]
    fn fetch_priorities_match_policy_defaults() -> Result<(), String> {
        let rows: Vec<(&str, &str, &str)> = FETCH_LATENCY_ROWS
            .iter()
            .map(|row| (row.class_id, row.fetch_priority, row.prefetch_policy))
            .collect();

        ensure(
            rows == vec![
                ("critical_marker", "critical", "eager"),
                ("trust_receipt", "normal", "lazy"),
                ("replay_bundle", "background", "none"),
                ("telemetry_artifact", "background", "none"),
            ],
            "fetch priority defaults drifted",
        )
    }

    #[test]
    fn fetch_latency_rows_have_monotonic_tail_latency() -> Result<(), String> {
        for row in FETCH_LATENCY_ROWS {
            ensure(
                row.p99_fetch_us >= row.p50_fetch_us,
                "fetch p99 must be at least p50",
            )?;
            ensure(row.max_inflight_hint > 0, "inflight hint must be positive")?;
        }
        Ok(())
    }
}
