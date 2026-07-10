//! bd-qr5i2.2: real-run producer for the L1 proof-carrying host-effect
//! evidence (`proof_carrying_effects` v2).
//!
//! The dual-oracle close-condition gate (`ops::close_condition`) does not
//! trust a declared evidence summary: the v2 schema embeds the full
//! `receipt_chain_entries` and the gate re-derives chain integrity,
//! per-receipt validity, subjects, and counts from them, failing closed on
//! any declared↔derived mismatch. This module is the matching producer: it
//! executes ONE tiny guest program through the PUBLIC
//! `EngineDispatcher::dispatch_run` native path — a REAL run, no mocks —
//! covering every subject in
//! [`crate::schema_versions::L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS`]
//! (`fs.write` + `fs.read` against the run sandbox, `http.request` against a
//! loopback sink the producer allowlists for exactly one request), harvests
//! the signed `host_effect_ledger`, verifies it natively with the same
//! primitives the gate uses, and emits the v2 block whose declared summary
//! equals the derived values by construction.
//!
//! Fail-closed: a dispatch failure, a fallback-runtime run, a missing
//! ledger, a chain-integrity failure, an invalid or denied receipt, a
//! missing acceptance subject, or an egress that never reached the loopback
//! sink each abort evidence production with an error rather than emitting
//! weaker evidence.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::runtime::effect_receipt::EffectReceiptChainEntry;

/// Producer identity recorded in the emitted evidence block.
pub const PROOF_CARRYING_EVIDENCE_PRODUCER: &str = "franken-node ops proof-carrying-evidence";

/// Key under which the compatibility-corpus results artifact carries the
/// proof-carrying evidence block (the path the close-condition gate reads).
pub const PROOF_CARRYING_EFFECTS_KEY: &str = "proof_carrying_effects";

/// Upper bound for the corpus-results artifact read (parser-bomb defense).
const MAX_CORPUS_RESULTS_BYTES: u64 = 16 * 1024 * 1024;

/// The `proof_carrying_effects` v2 evidence block.
///
/// The summary fields (`verified_subjects`, `effect_receipts_verified`,
/// `invalid_receipts`, `receipt_chain_verified`) are DERIVED from the
/// embedded `receipt_chain_entries` using the same rules the close-condition
/// gate applies on read, so a well-formed producer artifact re-derives
/// cleanly and a tampered one fails closed at the gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCarryingEffectsEvidence {
    /// Always [`crate::schema_versions::L1_PROOF_CARRYING_EFFECTS_V2`].
    pub schema_version: String,
    /// Workflow trace id of the producing run (matches every embedded receipt).
    pub trace_id: String,
    /// RFC 3339 timestamp of evidence production.
    pub produced_at: String,
    /// Producer identity ([`PROOF_CARRYING_EVIDENCE_PRODUCER`]).
    pub producer: String,
    /// Acceptance subjects evidenced by allowed, valid receipts (sorted).
    pub verified_subjects: Vec<String>,
    /// Count of allowed, valid receipts mapping to an acceptance subject.
    pub effect_receipts_verified: u64,
    /// Count of embedded receipts failing validation (always 0 on emit; the
    /// producer refuses to emit evidence containing an invalid receipt).
    pub invalid_receipts: u64,
    /// Whether the embedded chain re-derives (always true on emit; the
    /// producer refuses to emit a chain that fails integrity re-derivation).
    pub receipt_chain_verified: bool,
    /// The full hash-chained receipt entries harvested from the run's signed
    /// host-effect ledger. Wire-identical to the verifier SDK's
    /// `EffectReceiptChainEntry`, so third parties re-derive the chain
    /// offline without trusting this producer.
    pub receipt_chain_entries: Vec<EffectReceiptChainEntry>,
}

/// Execute the producer guest program through the native engine path and
/// emit verified v2 proof-carrying evidence.
///
/// The guest program performs, in one run (one receipt chain):
/// 1. `fs.writeFileSync` — the `fs.write` acceptance subject;
/// 2. `fs.readFileSync` — the `fs.read` acceptance subject;
/// 3. `http.get` to a loopback sink bound by the producer — the
///    `http.request` acceptance subject. The sink is allowlisted via the
///    standard `[security.network_policy]` mechanism (host + exact port),
///    so the product-layer SSRF gate authorizes exactly this egress; the
///    default fail-closed policy still governs everything else.
///
/// Errors instead of emitting evidence whenever any part of the run or its
/// native re-verification falls short of the acceptance bar.
#[cfg(feature = "engine")]
pub fn produce_proof_carrying_effects_evidence() -> Result<ProofCarryingEffectsEvidence> {
    use crate::config::{Config, NetworkAllowlistEntry, PreferredRuntime, Profile};
    use crate::ops::engine_dispatcher::EngineDispatcher;
    use crate::runtime::effect_receipt::{EffectReceiptChain, PolicyOutcome};
    use crate::schema_versions::{
        L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS, L1_PROOF_CARRYING_EFFECTS_V2,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    // Loopback sink for the http.request subject. Bound BEFORE the run so the
    // guest's connect always finds it listening. The engine performs a
    // single-socket request/response round trip: read the (half-closed)
    // request to EOF, then reply and close so the guest's response read
    // terminates.
    let listener = TcpListener::bind("127.0.0.1:0").context("bind loopback proof sink")?;
    let sink_addr = listener
        .local_addr()
        .context("resolve loopback proof sink address")?;
    let sink = std::thread::spawn(move || -> Vec<u8> {
        let Ok((mut stream, _peer)) = listener.accept() else {
            return Vec::new();
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        );
        let _ = stream.flush();
        received
    });

    // The guest app lives in its own scratch directory, which is also the
    // run's sandboxed host-I/O root — the fs effects really hit this
    // directory and are cleaned up with it.
    let sandbox = tempfile::TempDir::new().context("create producer sandbox directory")?;
    let guest_source = format!(
        "require('fs').writeFileSync('l1_evidence.txt', 'l1 proof-carrying evidence bytes');\n\
         require('fs').readFileSync('l1_evidence.txt');\n\
         require('http').get('http://{sink_addr}/');\n"
    );
    let app_path = sandbox.path().join("l1_evidence_app.js");
    std::fs::write(&app_path, guest_source).context("write producer guest program")?;

    // Dispatch-plan resolution requires the engine path to EXIST; with the
    // `engine` feature (required by this function) the FrankenEngine plan
    // executes IN-PROCESS via the native path and never runs the file, so a
    // placeholder keeps the producer hermetic on hosts without an installed
    // engine binary. It lives in its own scratch directory so the run's
    // sandbox root (the app directory) carries only what the guest program
    // does to it. This mirrors the native-engine e2e suites.
    let engine_dir = tempfile::TempDir::new().context("create engine placeholder directory")?;
    let engine_placeholder = engine_dir.path().join("franken-engine-native-placeholder");
    std::fs::write(&engine_placeholder, b"#!/bin/sh\nexit 0\n")
        .context("write engine placeholder for dispatch-plan resolution")?;

    // legacy-risky grants fs_read/fs_write/network_egress at the engine
    // capability layer so every acceptance-subject effect is authorized to
    // EXECUTE (an unexecuted subject cannot be proof-carrying). The
    // product-layer SSRF gate still governs the endpoint: the default policy
    // fail-closes loopback, so the producer allowlists exactly its own sink
    // (host + port) through the standard operator mechanism.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: Some(sink_addr.port()),
            reason: "l1 proof-carrying evidence producer loopback sink".to_string(),
        });

    let dispatcher =
        EngineDispatcher::new(Some(engine_placeholder), PreferredRuntime::FrankenEngine);
    let dispatch = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .context("producer guest run failed to dispatch")?;

    // Unblock the sink's accept if the guest never egressed (the connect is
    // refused when the sink already served the guest and exited), then
    // collect what the sink observed.
    let _ = TcpStream::connect(sink_addr);
    let received = match sink.join() {
        Ok(bytes) => bytes,
        Err(_) => bail!("loopback proof sink thread panicked"),
    };

    if dispatch.used_fallback_runtime {
        bail!(
            "producer run fell back to runtime '{}'; proof-carrying evidence requires the native franken_engine path",
            dispatch.runtime
        );
    }
    let ledger = dispatch
        .host_effect_ledger
        .as_ref()
        .context("native producer run surfaced no host-effect ledger")?;

    // The egress must have really reached the sink — an http_request receipt
    // whose bytes never left the process is not proof-carrying.
    let wire = String::from_utf8_lossy(&received);
    if !wire.starts_with("GET / HTTP/1.1\r\n") {
        bail!(
            "loopback proof sink never observed the guest's framed GET request \
             ({} bytes observed); refusing to emit http.request evidence",
            received.len()
        );
    }

    // Native re-verification with the SAME primitives the close-condition
    // gate uses, so the emitted declared summary equals the gate's derived
    // values by construction.
    let entries = ledger.entries.clone();
    EffectReceiptChain::verify_entries_integrity(&entries)
        .map_err(|err| anyhow::anyhow!("producer receipt chain failed integrity check: {err}"))?;

    let mut derived_subjects: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();
    let mut derived_verified: u64 = 0;
    for entry in &entries {
        entry.receipt.validate().map_err(|err| {
            anyhow::anyhow!(
                "producer receipt at chain index {} failed validation: {err}",
                entry.index
            )
        })?;
        match &entry.receipt.policy_outcome {
            PolicyOutcome::Allowed { .. } => {}
            PolicyOutcome::Denied { reason } => bail!(
                "producer run recorded a denied {} effect ({reason}); \
                 every acceptance-subject effect must execute",
                entry.receipt.effect_kind.label()
            ),
        }
        if let Some(subject) = entry.receipt.effect_kind.l1_acceptance_subject()
            && L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS.contains(&subject)
        {
            derived_subjects.insert(subject);
            derived_verified = derived_verified.saturating_add(1);
        }
    }
    for subject in L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS {
        if !derived_subjects.contains(subject) {
            bail!("producer run evidenced no verified receipt for acceptance subject {subject}");
        }
    }

    Ok(ProofCarryingEffectsEvidence {
        schema_version: L1_PROOF_CARRYING_EFFECTS_V2.to_string(),
        trace_id: ledger.trace_id.clone(),
        produced_at: chrono::Utc::now().to_rfc3339(),
        producer: PROOF_CARRYING_EVIDENCE_PRODUCER.to_string(),
        verified_subjects: derived_subjects.iter().map(ToString::to_string).collect(),
        effect_receipts_verified: derived_verified,
        invalid_receipts: 0,
        receipt_chain_verified: true,
        receipt_chain_entries: entries,
    })
}

/// Merge produced evidence into a compatibility-corpus results JSON artifact
/// (the file the close-condition gate reads), replacing any existing
/// `proof_carrying_effects` block in place. The rest of the artifact —
/// parity totals, thresholds, corpus metadata — is preserved byte-for-byte
/// at the value level.
pub fn merge_into_corpus_results(
    corpus_path: &Path,
    evidence: &ProofCarryingEffectsEvidence,
) -> Result<()> {
    let raw = crate::bounded_read_to_string(corpus_path, MAX_CORPUS_RESULTS_BYTES)
        .with_context(|| format!("read corpus results {}", corpus_path.display()))?;
    let mut data: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse corpus results {}", corpus_path.display()))?;
    let Some(object) = data.as_object_mut() else {
        bail!(
            "corpus results {} must be a JSON object to carry {PROOF_CARRYING_EFFECTS_KEY}",
            corpus_path.display()
        );
    };
    object.insert(
        PROOF_CARRYING_EFFECTS_KEY.to_string(),
        serde_json::to_value(evidence).context("serialize proof-carrying evidence")?,
    );
    std::fs::write(
        corpus_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&data).context("render corpus results")?
        ),
    )
    .with_context(|| format!("write corpus results {}", corpus_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence() -> ProofCarryingEffectsEvidence {
        ProofCarryingEffectsEvidence {
            schema_version: crate::schema_versions::L1_PROOF_CARRYING_EFFECTS_V2.to_string(),
            trace_id: "trace-proof-evidence-unit".to_string(),
            produced_at: "2026-07-10T00:00:00+00:00".to_string(),
            producer: PROOF_CARRYING_EVIDENCE_PRODUCER.to_string(),
            verified_subjects: vec![
                "fs.read".to_string(),
                "fs.write".to_string(),
                "http.request".to_string(),
            ],
            effect_receipts_verified: 3,
            invalid_receipts: 0,
            receipt_chain_verified: true,
            receipt_chain_entries: Vec::new(),
        }
    }

    #[test]
    fn evidence_serializes_gate_required_keys() {
        let value = serde_json::to_value(sample_evidence()).expect("serialize evidence");
        for key in [
            "schema_version",
            "verified_subjects",
            "effect_receipts_verified",
            "invalid_receipts",
            "receipt_chain_verified",
            "receipt_chain_entries",
        ] {
            assert!(value.get(key).is_some(), "evidence must carry {key}");
        }
        assert_eq!(
            value["schema_version"],
            crate::schema_versions::L1_PROOF_CARRYING_EFFECTS_V2
        );
    }

    #[test]
    fn merge_replaces_proof_block_and_preserves_siblings() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let corpus_path = dir.path().join("compatibility_corpus_results.json");
        std::fs::write(
            &corpus_path,
            r#"{"totals": {"total_test_cases": 7}, "proof_carrying_effects": {"schema_version": "franken-node/l1-proof-carrying-effects/v1"}}"#,
        )
        .expect("write corpus fixture");

        merge_into_corpus_results(&corpus_path, &sample_evidence()).expect("merge evidence");

        let merged: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&corpus_path).expect("read merged corpus"),
        )
        .expect("parse merged corpus");
        assert_eq!(merged["totals"]["total_test_cases"], 7);
        assert_eq!(
            merged[PROOF_CARRYING_EFFECTS_KEY]["schema_version"],
            crate::schema_versions::L1_PROOF_CARRYING_EFFECTS_V2
        );
        assert_eq!(
            merged[PROOF_CARRYING_EFFECTS_KEY]["effect_receipts_verified"],
            3
        );
    }

    #[test]
    fn merge_refuses_non_object_corpus() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let corpus_path = dir.path().join("corpus.json");
        std::fs::write(&corpus_path, "[1, 2, 3]").expect("write corpus fixture");
        let err = merge_into_corpus_results(&corpus_path, &sample_evidence())
            .expect_err("non-object corpus must refuse");
        assert!(err.to_string().contains("must be a JSON object"));
    }
}
