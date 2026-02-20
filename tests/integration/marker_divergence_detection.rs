//! Integration tests: marker-stream divergence detection (bd-xwk5).
//!
//! These scenarios exercise the normative fork-detection behavior required
//! by section 10.14: exact divergence boundary, no-divergence behavior,
//! divergence-at-zero handling, and logarithmic search evidence.

#[path = "../../crates/franken-node/src/control_plane/marker_stream.rs"]
mod marker_stream;

use marker_stream::{find_divergence_point, MarkerEventType, MarkerStream};

fn build_pair(total: u64, divergence_at: Option<u64>) -> (MarkerStream, MarkerStream) {
    let mut local = MarkerStream::new();
    let mut remote = MarkerStream::new();

    for i in 0..total {
        let event = MarkerEventType::all()[(i as usize) % MarkerEventType::all().len()];
        let trace = format!("trace-{i:06}");

        let (local_payload, remote_payload) = match divergence_at {
            Some(point) if i >= point => (
                format!("local-payload-{i:06}"),
                format!("remote-payload-{i:06}"),
            ),
            _ => {
                let shared = format!("shared-payload-{i:06}");
                (shared.clone(), shared)
            }
        };

        local
            .append(event, &local_payload, 1000 + i, &trace)
            .expect("append local marker");
        remote
            .append(event, &remote_payload, 1000 + i, &trace)
            .expect("append remote marker");
    }

    (local, remote)
}

fn build_shared(count: u64) -> MarkerStream {
    let mut stream = MarkerStream::new();
    for i in 0..count {
        let event = MarkerEventType::all()[(i as usize) % MarkerEventType::all().len()];
        let payload = format!("shared-payload-{i:06}");
        let trace = format!("shared-trace-{i:06}");
        stream
            .append(event, &payload, 1000 + i, &trace)
            .expect("append shared marker");
    }
    stream
}

fn ceil_log2(n: u64) -> u32 {
    if n <= 1 {
        0
    } else {
        64 - (n - 1).leading_zeros()
    }
}

#[test]
fn divergence_boundary_at_1000_is_exact() {
    let (local, remote) = build_pair(1_400, Some(1_000));
    let result = find_divergence_point(&local, &remote);

    assert!(result.has_divergence);
    assert!(result.has_common_prefix);
    assert_eq!(result.common_prefix_seq, 999);
    assert_eq!(result.divergence_seq, 1_000);
}

#[test]
fn identical_streams_report_no_divergence() {
    let (local, remote) = build_pair(256, None);
    let result = find_divergence_point(&local, &remote);

    assert!(!result.has_divergence);
    assert!(result.has_common_prefix);
    assert_eq!(result.common_prefix_seq, 255);
    assert_eq!(result.divergence_seq, 256);
}

#[test]
fn divergence_at_sequence_zero_has_no_common_prefix() {
    let (local, remote) = build_pair(128, Some(0));
    let result = find_divergence_point(&local, &remote);

    assert!(result.has_divergence);
    assert!(!result.has_common_prefix);
    assert_eq!(result.divergence_seq, 0);
}

#[test]
fn one_stream_shorter_diverges_at_short_length() {
    let local = build_shared(500);
    let remote = build_shared(300);
    let result = find_divergence_point(&local, &remote);

    assert!(result.has_divergence);
    assert!(result.has_common_prefix);
    assert_eq!(result.common_prefix_seq, 299);
    assert_eq!(result.divergence_seq, 300);
    assert!(result.local_hash_at_divergence.is_some());
    assert!(result.remote_hash_at_divergence.is_none());
}

#[test]
fn comparison_count_stays_logarithmic() {
    let size = 20_000_u64;
    let (local, remote) = build_pair(size, Some(12_345));
    let result = find_divergence_point(&local, &remote);
    let bound = ceil_log2(size) as usize;

    assert!(
        result.evidence.comparison_count <= bound,
        "comparison count {} exceeded logarithmic bound {}",
        result.evidence.comparison_count,
        bound
    );
}
