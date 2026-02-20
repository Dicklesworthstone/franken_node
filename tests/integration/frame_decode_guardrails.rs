//! Integration tests for bd-3tzl: Bounded parser guardrails.

use frankenengine_node::connector::frame_parser::*;

fn config() -> ParserConfig {
    ParserConfig { max_frame_bytes: 1000, max_nesting_depth: 10, max_decode_cpu_ms: 50 }
}

fn frame(id: &str, bytes: u64, depth: u32, cpu: u64) -> FrameInput {
    FrameInput { frame_id: id.into(), raw_bytes_len: bytes, nesting_depth: depth, decode_cpu_ms: cpu }
}

#[test]
fn inv_bpg_size_bounded() {
    let f = frame("f1", 1001, 5, 20);
    let (v, _) = check_frame(&f, &config(), "ts").unwrap();
    assert!(!v.allowed, "INV-BPG-SIZE-BOUNDED: oversized frame must be rejected");
}

#[test]
fn inv_bpg_depth_bounded() {
    let f = frame("f1", 500, 11, 20);
    let (v, _) = check_frame(&f, &config(), "ts").unwrap();
    assert!(!v.allowed, "INV-BPG-DEPTH-BOUNDED: deep nesting must be rejected");
}

#[test]
fn inv_bpg_cpu_bounded() {
    let f = frame("f1", 500, 5, 51);
    let (v, _) = check_frame(&f, &config(), "ts").unwrap();
    assert!(!v.allowed, "INV-BPG-CPU-BOUNDED: CPU-heavy frame must be rejected");
}

#[test]
fn inv_bpg_auditable() {
    let f = frame("f1", 500, 5, 20);
    let (_, audit) = check_frame(&f, &config(), "2026-01-01").unwrap();
    assert_eq!(audit.frame_id, "f1");
    assert_eq!(audit.timestamp, "2026-01-01");
    assert!(!audit.verdict.is_empty(), "INV-BPG-AUDITABLE: verdict must be present");
    assert_eq!(audit.size_limit, 1000);
    assert_eq!(audit.depth_limit, 10);
}
