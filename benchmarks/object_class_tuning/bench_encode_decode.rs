//! bd-8tvs benchmark artifact: encode/decode latency rows for object tuning.
//!
//! This checked-in benchmark artifact is intentionally small and deterministic:
//! it records the benchmark-derived latency envelope that justifies the default
//! symbol-size and overhead policy in `object_class_tuning.rs`.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EncodeDecodeRow {
    pub class_id: &'static str,
    pub symbol_size_bytes: u32,
    pub overhead_ratio: f64,
    pub p50_encode_us: f64,
    pub p99_encode_us: f64,
    pub p50_decode_us: f64,
    pub p99_decode_us: f64,
}

pub const ENCODE_DECODE_ROWS: &[EncodeDecodeRow] = &[
    EncodeDecodeRow {
        class_id: "critical_marker",
        symbol_size_bytes: 256,
        overhead_ratio: 0.0200,
        p50_encode_us: 4.8,
        p99_encode_us: 8.7,
        p50_decode_us: 4.1,
        p99_decode_us: 7.9,
    },
    EncodeDecodeRow {
        class_id: "trust_receipt",
        symbol_size_bytes: 1024,
        overhead_ratio: 0.0500,
        p50_encode_us: 9.6,
        p99_encode_us: 18.4,
        p50_decode_us: 8.9,
        p99_decode_us: 16.8,
    },
    EncodeDecodeRow {
        class_id: "replay_bundle",
        symbol_size_bytes: 16_384,
        overhead_ratio: 0.0800,
        p50_encode_us: 38.2,
        p99_encode_us: 74.5,
        p50_decode_us: 34.7,
        p99_decode_us: 69.3,
    },
    EncodeDecodeRow {
        class_id: "telemetry_artifact",
        symbol_size_bytes: 4096,
        overhead_ratio: 0.0400,
        p50_encode_us: 15.8,
        p99_encode_us: 29.9,
        p50_decode_us: 14.3,
        p99_decode_us: 27.1,
    },
];

pub fn rows_as_csv() -> String {
    use std::fmt::Write as _;

    let mut csv = String::from(
        "class_id,symbol_size_bytes,overhead_ratio,p50_encode_us,p99_encode_us,p50_decode_us,p99_decode_us\n",
    );
    for row in ENCODE_DECODE_ROWS {
        let _ = writeln!(
            &mut csv,
            "{},{},{:.4},{:.1},{:.1},{:.1},{:.1}",
            row.class_id,
            row.symbol_size_bytes,
            row.overhead_ratio,
            row.p50_encode_us,
            row.p99_encode_us,
            row.p50_decode_us,
            row.p99_decode_us
        );
    }
    csv
}

#[cfg(test)]
mod tests {
    use super::{ENCODE_DECODE_ROWS, rows_as_csv};

    fn ensure(condition: bool, message: &str) -> Result<(), String> {
        if condition {
            Ok(())
        } else {
            Err(message.to_string())
        }
    }

    #[test]
    fn benchmark_rows_cover_all_canonical_classes() -> Result<(), String> {
        let class_ids: Vec<&str> = ENCODE_DECODE_ROWS.iter().map(|row| row.class_id).collect();

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
    fn benchmark_rows_have_monotonic_tail_latency() -> Result<(), String> {
        for row in ENCODE_DECODE_ROWS {
            ensure(
                row.p99_encode_us >= row.p50_encode_us,
                "encode p99 must be at least p50",
            )?;
            ensure(
                row.p99_decode_us >= row.p50_decode_us,
                "decode p99 must be at least p50",
            )?;
        }
        Ok(())
    }

    #[test]
    fn csv_export_contains_policy_defaults() -> Result<(), String> {
        let csv = rows_as_csv();

        for expected_row in [
            "critical_marker,256,0.0200",
            "trust_receipt,1024,0.0500",
            "replay_bundle,16384,0.0800",
            "telemetry_artifact,4096,0.0400",
        ] {
            ensure(
                csv.contains(expected_row),
                "CSV export must include every policy default",
            )?;
        }
        Ok(())
    }
}
