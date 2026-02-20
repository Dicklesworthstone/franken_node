//! Integration tests for bd-29ct: Adversarial fuzz corpus gates.

use frankenengine_node::connector::fuzz_corpus::*;

fn populated_corpus() -> FuzzCorpus {
    let mut c = FuzzCorpus::new(3);
    c.add_target(FuzzTarget {
        name: "parser_fuzz".into(),
        category: FuzzCategory::ParserInput,
        description: "parser input fuzzing".into(),
    });
    c.add_target(FuzzTarget {
        name: "handshake_fuzz".into(),
        category: FuzzCategory::HandshakeReplay,
        description: "handshake replay/splice".into(),
    });
    c.add_target(FuzzTarget {
        name: "token_fuzz".into(),
        category: FuzzCategory::TokenValidation,
        description: "token validation".into(),
    });
    c.add_target(FuzzTarget {
        name: "dos_fuzz".into(),
        category: FuzzCategory::DecodeDos,
        description: "decode DoS".into(),
    });

    for target in ["parser_fuzz", "handshake_fuzz", "token_fuzz", "dos_fuzz"] {
        for i in 0..3 {
            c.add_seed(FuzzSeed {
                target: target.to_string(),
                input_data: format!("input_{i}"),
                expected: SeedOutcome::Handled,
            })
            .unwrap();
        }
    }
    c
}

#[test]
fn inv_fcg_targets() {
    let c = populated_corpus();
    assert_eq!(c.target_count(), 4);
    c.validate().unwrap();
}

#[test]
fn inv_fcg_corpus() {
    let c = populated_corpus();
    for target in ["parser_fuzz", "handshake_fuzz", "token_fuzz", "dos_fuzz"] {
        assert!(c.seed_count(target) >= 3, "target {target} needs >= 3 seeds");
    }
}

#[test]
fn inv_fcg_triage() {
    let mut c = populated_corpus();
    c.add_seed(FuzzSeed {
        target: "parser_fuzz".into(),
        input_data: "crash_trigger".into(),
        expected: SeedOutcome::Rejected,
    })
    .unwrap();
    let verdict = c.run_gate();
    assert_eq!(verdict.verdict, "FAIL");
    assert!(!verdict.untriaged.is_empty());
    assert!(verdict.untriaged[0].reproducer.contains("parser_fuzz"));
}

#[test]
fn inv_fcg_gate() {
    let c = populated_corpus();
    let verdict = c.run_gate();
    assert_eq!(verdict.verdict, "PASS");
    assert!(verdict.untriaged.is_empty());
}
