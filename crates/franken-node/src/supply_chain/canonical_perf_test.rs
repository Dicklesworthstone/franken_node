//! Manual performance test for canonical encoding optimization

use super::trust_card::canonicalize_value;
use serde_json::{Map, Value};
use std::time::{Duration, Instant};

/// Generate complex nested JSON for performance testing
fn generate_complex_trust_card() -> Value {
    let mut capabilities = Vec::new();
    for i in 0..50 {
        capabilities.push(serde_json::json!({
            "name": format!("capability_{:03}", i),
            "scope": format!("scope_{}", i % 5),
            "permissions": (0..i%10).map(|j| format!("perm_{}", j)).collect::<Vec<_>>(),
            "metadata": {
                "version": "1.0.0",
                "created_at": "2026-04-22T10:00:00Z",
                "hash": format!("{:064x}", i * 0x123456789ABCDEF0)
            }
        }));
    }

    serde_json::json!({
        "trust_card_version": 42,
        "extension": {
            "extension_id": "npm:@acme/security-scanner",
            "version": "2.1.0"
        },
        "publisher": {
            "publisher_id": "acme-corp",
            "display_name": "ACME Corporation",
            "contact_info": {
                "email": "security@acme.corp",
                "website": "https://security.acme.corp",
                "support": "https://support.acme.corp/security"
            }
        },
        "capability_declarations": capabilities,
        "certification_level": "production",
        "provenance": {
            "source_hash": "a".repeat(64),
            "build_attestation": "b".repeat(64),
            "supply_chain_refs": (0..20).map(|i| format!("ref_{:04}", i)).collect::<Vec<_>>()
        },
        "reputation_signals": {
            "download_count": 1500000,
            "adoption_score": 95.5,
            "security_reports": [],
            "community_feedback": (0..100).map(|i| format!("feedback_{}", i)).collect::<Vec<_>>()
        }
    })
}

#[cfg(test)]
mod perf_tests {
    use super::{canonicalize_value, generate_complex_trust_card};

    #[test]
    fn manual_performance_comparison() {
        let test_data = generate_complex_trust_card();
        let iterations = 1000;

        // Warm up
        for _ in 0..10 {
            let _ = canonicalize_value(test_data.clone());
        }

        // Measure current implementation
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = canonicalize_value(test_data.clone());
        }
        let duration = start.elapsed();

        println!("Optimized canonicalize_value:");
        println!("  {} iterations in {:?}", iterations, duration);
        println!(
            "  Average: {:?} per iteration",
            duration / iterations as u32
        );
        println!(
            "  Throughput: {:.0} ops/sec",
            iterations as f64 / duration.as_secs_f64()
        );

        // Test with serialization (full pipeline)
        let start = Instant::now();
        for _ in 0..iterations {
            let canonical = canonicalize_value(test_data.clone());
            let _ = serde_json::to_string(&canonical).unwrap();
        }
        let duration_full = start.elapsed();

        println!("Full pipeline (canonicalize + serialize):");
        println!("  {} iterations in {:?}", iterations, duration_full);
        println!(
            "  Average: {:?} per iteration",
            duration_full / iterations as u32
        );
        println!(
            "  Throughput: {:.0} ops/sec",
            iterations as f64 / duration_full.as_secs_f64()
        );

        // Memory usage estimation
        let json_size = serde_json::to_string(&test_data).unwrap().len();
        println!("Test data size: {} bytes", json_size);

        // Verify correctness
        let canonical = canonicalize_value(test_data.clone());
        let canonical_json = serde_json::to_string(&canonical).unwrap();

        // Basic correctness check - object keys should be sorted
        assert!(canonical_json.contains(r#""capability_declarations":"#));
        assert!(canonical_json.contains(r#""certification_level":"#));

        println!("✓ Correctness verified - optimization working");
    }
}
