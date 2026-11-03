//! Independent authentication of the original receipt-authority run statement.
//!
//! The signed record is carried as raw JSON text: finite telemetry floats in
//! the original record must not enter the incident bundle's float-free JSON
//! integrity view. Parsing rejects duplicate members before recursively sorting
//! objects for the existing producer signature protocol. No key, path or code
//! in this record is executed or used as a source of authority.

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{IncidentBundleError, MAX_INCIDENT_BUNDLE_BYTES, decode_evidence_json};

const ORIGIN_SCHEMA: &str = "franken-node/incident-run-origin/v1";
const RECORD_SCHEMA: &str = "franken-node/run-host-effect-ledger-record/v1";
const RECEIPT_SCHEMA: &str = "franken-node/run-execution-receipt/v1";
const LEDGER_SCHEMA: &str = "host-effect-ledger-v3.0";
const SIGNATURE_DOMAIN: &[u8] = b"franken-node/run-host-effect-ledger-record-signature/v1\0";

/// Privacy-safe identity of the independently authenticated run statement.
/// The receipt identity is bound by the original signature. Its typed product
/// hash preimage and the engine session signature are not recomputed here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerifiedRunOrigin {
    pub receipt_id: String,
    pub receipt_hash: String,
    pub signer_public_key_hex: String,
    /// SHA-256 of the exact original record bytes carried by this bundle.
    pub record_sha256: String,
}

type Result<T> = std::result::Result<T, IncidentBundleError>;

fn invalid(reason: &'static str) -> IncidentBundleError {
    IncidentBundleError::RunOriginInvalid { reason }
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("expected a recorded object"))
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    object
        .get(name)
        .ok_or_else(|| invalid("missing required recorded field"))
}

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    field(object, name)?
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid("expected a nonempty recorded string"))
}

fn equal(left: &Value, right: &Value, reason: &'static str) -> Result<()> {
    if left != right {
        return Err(invalid(reason));
    }
    Ok(())
}

fn bind(
    left: &Map<String, Value>,
    left_name: &str,
    right: &Map<String, Value>,
    right_name: &str,
    reason: &'static str,
) -> Result<()> {
    equal(field(left, left_name)?, field(right, right_name)?, reason)
}

fn failure_marker(receipt: &Map<String, Value>) -> Result<Option<&Value>> {
    match receipt.get("execution_failure") {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(receipt.get("execution_failure")),
        Some(_) => Err(invalid("invalid execution failure declaration")),
    }
}

/// Called only after the complete enclosing bundle has passed verification.
pub(super) fn verify(
    bundle: &Value,
    trusted_run_signer: &VerifyingKey,
) -> Result<VerifiedRunOrigin> {
    let initial = object(&bundle["initial_state_snapshot"])?;
    let origin = initial
        .get("run_origin")
        .ok_or(IncidentBundleError::RunOriginMissing)?;
    let origin = object(origin)?;
    if origin.len() != 2
        || origin.get("schema_version").and_then(Value::as_str) != Some(ORIGIN_SCHEMA)
    {
        return Err(invalid("unsupported or malformed run-origin envelope"));
    }
    let raw = text(origin, "record_json")?;
    if raw.len() > MAX_INCIDENT_BUNDLE_BYTES {
        return Err(invalid("original run record exceeds its byte bound"));
    }
    let record_value = decode_evidence_json(raw.as_bytes())
        .map_err(|_| invalid("original run record must be bounded unambiguous JSON"))?;
    let record = object(&record_value)?;
    if record.get("schema_version").and_then(Value::as_str) != Some(RECORD_SCHEMA) {
        return Err(invalid("unsupported original run-record schema"));
    }

    // Verify the complete statement before interpreting its binding fields.
    // Unknown signed record members remain in the preimage; ONLY the detached
    // signature is excluded. This protocol has no added length prefix.
    let signature_hex = record
        .get("record_signature")
        .and_then(Value::as_str)
        .ok_or(IncidentBundleError::RunOriginSignatureMalformed)?;
    let mut signature = [0_u8; 64];
    hex::decode_to_slice(signature_hex, &mut signature)
        .map_err(|_| IncidentBundleError::RunOriginSignatureMalformed)?;
    let mut canonical = record_value.clone();
    canonical
        .as_object_mut()
        .expect("validated object")
        .remove("record_signature");
    canonical.sort_all_objects();
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + raw.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    serde_json::to_writer(&mut preimage, &canonical)
        .map_err(|_| invalid("cannot encode original signature preimage"))?;
    trusted_run_signer
        .verify_strict(&preimage, &Signature::from_bytes(&signature))
        .map_err(|_| IncidentBundleError::RunOriginSignatureInvalid)?;

    for name in [
        "receipt_id",
        "receipt_hash",
        "receipt_path",
        "app_path",
        "policy_mode",
        "trace_id",
    ] {
        text(record, name)?;
    }
    let receipt_id = text(record, "receipt_id")?;
    if receipt_id.len() > 128
        || !receipt_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid("invalid original receipt identifier"));
    }
    let receipt_hash = text(record, "receipt_hash")?;
    if !receipt_hash.strip_prefix("sha256:").is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        return Err(invalid("invalid original receipt hash declaration"));
    }
    let receipt = object(field(record, "receipt_snapshot")?)?;
    if receipt.get("schema_version").and_then(Value::as_str) != Some(RECEIPT_SCHEMA) {
        return Err(invalid("unsupported original receipt schema"));
    }
    for name in [
        "receipt_id",
        "receipt_hash",
        "app_path",
        "policy_mode",
        "ssrf_violations",
    ] {
        bind(
            record,
            name,
            receipt,
            name,
            "original record disagrees with its receipt snapshot",
        )?;
    }
    let violations = field(record, "ssrf_violations")?
        .as_array()
        .ok_or_else(|| invalid("invalid original security-control declaration"))?;
    if !violations.iter().all(Value::is_string) {
        return Err(invalid("invalid original security-control declaration"));
    }
    let sentinel = field(record, "sentinel_enforced")?
        .as_bool()
        .ok_or_else(|| invalid("invalid original sentinel declaration"))?;
    let receipt_sentinel = receipt
        .get("sentinel_enforcement")
        .filter(|value| !value.is_null());
    if receipt_sentinel.is_some_and(|value| !value.is_object())
        || sentinel != receipt_sentinel.is_some()
    {
        return Err(invalid(
            "original sentinel declaration disagrees with receipt snapshot",
        ));
    }
    if receipt
        .get("interruption_evidence")
        .is_some_and(|value| !value.is_null())
    {
        return Err(invalid(
            "interrupted execution cannot establish a finalized run origin",
        ));
    }
    bind(
        record,
        "receipt_id",
        initial,
        "run_receipt_id",
        "bundle names a different original receipt",
    )?;
    bind(
        record,
        "receipt_hash",
        initial,
        "run_receipt_hash",
        "bundle names a different original receipt",
    )?;
    for name in ["ssrf_violations", "sentinel_enforced"] {
        bind(
            record,
            name,
            initial,
            name,
            "bundle security controls differ from the original run",
        )?;
    }
    if bundle["policy_version"] != *field(record, "policy_mode")? {
        return Err(invalid("bundle policy differs from the original run"));
    }
    if failure_marker(receipt)? != initial.get("execution_failure") {
        return Err(invalid(
            "bundle failure declaration differs from the original run",
        ));
    }

    let original_capture = record.get("native_replay").filter(|value| !value.is_null());
    if original_capture != initial.get("native_replay") {
        return Err(invalid(
            "bundle native capture differs from the original run",
        ));
    }
    match original_capture {
        Some(capture) => {
            let capture = object(capture)?;
            bind(
                receipt,
                "native_replay_payload_sha256",
                capture,
                "payload_sha256",
                "original native capture differs from its signed receipt binding",
            )?;
            // The bundle verifier already checked the full native envelope,
            // source capsule bytes, terminal declaration and timeline binding.
        }
        None if receipt.contains_key("native_replay_payload_sha256") => {
            return Err(invalid("original receipt names an absent native capture"));
        }
        None => {}
    }

    let ledger = object(field(record, "host_effect_ledger")?)?;
    if ledger.get("schema_version").and_then(Value::as_str) != Some(LEDGER_SCHEMA) {
        return Err(invalid("unsupported original host-effect ledger schema"));
    }
    text(ledger, "trace_id")?;
    bind(
        ledger,
        "chain_head_hash",
        initial,
        "host_effect_chain_head",
        "bundle effect chain differs from the original run",
    )?;
    for name in [
        "effect_count",
        "allowed_count",
        "denied_count",
        "failed_count",
    ] {
        if field(ledger, name)?.as_u64().is_none() {
            return Err(invalid("invalid original effect count"));
        }
        bind(
            ledger,
            name,
            initial,
            name,
            "bundle effect counts differ from the original run",
        )?;
    }
    let entries = field(ledger, "entries")?
        .as_array()
        .ok_or_else(|| invalid("original effect entries must be an array"))?;
    let timeline = bundle["timeline"]
        .as_array()
        .ok_or_else(|| invalid("bundle timeline must be an array"))?;
    let recorded: Vec<&Value> = timeline
        .iter()
        .filter_map(|event| event["payload"].get("effect_receipt_chain_entry"))
        .collect();
    if entries.len() != recorded.len() || entries.iter().zip(recorded).any(|(a, b)| a != b) {
        return Err(invalid(
            "bundle effect entries differ from the original run",
        ));
    }
    if entries.is_empty() {
        // For a run without effects, the producer uses its signed receipt end
        // time for the sole native terminal event. Bundle normalization renders
        // that instant as UTC microseconds, including offset-form receipt times.
        let ended_at = DateTime::parse_from_rfc3339(text(receipt, "end_time_utc")?)
            .map_err(|_| invalid("invalid original run end time"))?
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Micros, true);
        if timeline
            .first()
            .and_then(|event| event["timestamp"].as_str())
            != Some(ended_at.as_str())
        {
            return Err(invalid(
                "bundle terminal time differs from the original run",
            ));
        }
    }
    // Ledger traces are internal engine identities. The record's trace_id is
    // the operator trace and must not be forced equal to that separate identity.
    if entries
        .iter()
        .any(|entry| entry["receipt"]["trace_id"] != ledger["trace_id"])
    {
        return Err(invalid(
            "original effect entries disagree with their ledger trace",
        ));
    }
    Ok(VerifiedRunOrigin {
        receipt_id: receipt_id.to_owned(),
        receipt_hash: receipt_hash.to_owned(),
        signer_public_key_hex: hex::encode(trusted_run_signer.as_bytes()),
        record_sha256: hex::encode(Sha256::digest(raw.as_bytes())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident_bundle::structure::tests::{
        refresh_timeline_metadata, resign, run_bundle, set_chunks,
    };
    use crate::incident_bundle::{verify_incident_bundle, verify_incident_bundle_with_run_key};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn bundle_key() -> VerifyingKey {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            &mut bytes,
        )
        .unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    fn run_key() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    // Explicitly synthetic protocol fixtures. These exercise signatures and
    // cross-binding, not native engine execution or typed receipt generation.
    // The separate integration fixture uses the actual production signers and
    // effect-receipt implementation, still with synthetic execution metadata.
    fn record_for(bundle: &mut Value) -> Value {
        bundle["initial_state_snapshot"]["run_receipt_hash"] =
            json!(format!("sha256:{}", "a".repeat(64)));
        bundle["initial_state_snapshot"]["ssrf_violations"] = json!([]);
        bundle["initial_state_snapshot"]["sentinel_enforced"] = json!(false);
        let initial = &bundle["initial_state_snapshot"];
        let entries: Vec<Value> = bundle["timeline"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["payload"].get("effect_receipt_chain_entry").cloned())
            .collect();
        let mut receipt = json!({
            "schema_version":RECEIPT_SCHEMA, "receipt_id":initial["run_receipt_id"],
            "receipt_hash":initial["run_receipt_hash"], "app_path":"PRIVATE-app.js",
            "policy_mode":bundle["policy_version"], "ssrf_violations":[],
            "end_time_utc":bundle["created_at"],
            // A known difficult f64: parsing without float_roundtrip changes
            // its bits to 51.24817837550541 and breaks the authentic signature.
            "telemetry":{"wall_time_ms":51.248178375505404},
        });
        if let Some(failure) = initial.get("execution_failure") {
            receipt["execution_failure"] = failure.clone();
        }
        if let Some(capture) = initial.get("native_replay") {
            receipt["native_replay_payload_sha256"] = capture["payload_sha256"].clone();
        }
        let mut record = json!({
            "schema_version":RECORD_SCHEMA, "receipt_id":initial["run_receipt_id"],
            "receipt_hash":initial["run_receipt_hash"], "receipt_path":"PRIVATE-receipt.json",
            "app_path":"PRIVATE-app.js", "policy_mode":bundle["policy_version"],
            "trace_id":"operator-trace-distinct-from-engine", "ssrf_violations":[],
            "sentinel_enforced":false, "receipt_snapshot":receipt,
            "host_effect_ledger":{
                "schema_version":LEDGER_SCHEMA,
                "trace_id":entries.first().map(|entry| entry["receipt"]["trace_id"].clone()).unwrap_or(json!("engine-trace")),
                "chain_head_hash":initial["host_effect_chain_head"],
                "effect_count":initial["effect_count"], "allowed_count":initial["allowed_count"],
                "denied_count":initial["denied_count"], "failed_count":initial["failed_count"],
                "entries":entries,
            },
            "unknown_signed_extension":{"private":"PRIVATE-extension","number":-93.31137037688033},
        });
        if let Some(capture) = initial.get("native_replay") {
            record["native_replay"] = capture.clone();
        }
        // Zero-effect terminal markers are generated before the fixture's
        // canonical receipt hash is installed above; update only that binding.
        for event in bundle["timeline"].as_array_mut().unwrap() {
            for field in ["native_execution_completed", "native_execution_failed"] {
                if let Some(marker) = event["payload"].get_mut(field) {
                    marker["run_receipt_hash"] = record["receipt_hash"].clone();
                }
            }
        }
        record
    }

    fn signed_record(record: &Value) -> String {
        let mut record = record.clone();
        record.as_object_mut().unwrap().remove("record_signature");
        record.sort_all_objects();
        let mut payload = SIGNATURE_DOMAIN.to_vec();
        serde_json::to_writer(&mut payload, &record).unwrap();
        record["record_signature"] = json!(hex::encode(run_key().sign(&payload).to_bytes()));
        serde_json::to_string_pretty(&record).unwrap()
    }

    fn embed(bundle: &mut Value, raw: &str) -> Vec<u8> {
        bundle["initial_state_snapshot"]["run_origin"] =
            json!({"schema_version":ORIGIN_SCHEMA,"record_json":raw});
        refresh_timeline_metadata(bundle);
        let length = bundle["timeline"].as_array().unwrap().len();
        set_chunks(bundle, std::slice::from_ref(&(0..length)));
        resign(bundle)
    }

    fn assert_origin_refused(mut bundle: Value, raw: &str) -> IncidentBundleError {
        let bytes = embed(&mut bundle, raw);
        // Every negative reaches the original-run gate through an otherwise
        // valid outer signature and complete consistent replay structure.
        verify_incident_bundle(&bytes, &bundle_key()).unwrap();
        verify_incident_bundle_with_run_key(&bytes, &bundle_key(), &run_key().verifying_key())
            .unwrap_err()
    }

    #[test]
    fn separate_run_authority_authenticates_complete_statement_and_exact_raw_bytes() {
        let mut bundle = run_bundle();
        let record = record_for(&mut bundle);
        let raw = signed_record(&record);
        assert!(raw.contains("51.248178375505404"));
        let bytes = embed(&mut bundle, &raw);
        let verified =
            verify_incident_bundle_with_run_key(&bytes, &bundle_key(), &run_key().verifying_key())
                .unwrap();
        assert_eq!(verified.run_origin.receipt_id, record["receipt_id"]);
        assert_eq!(
            verified.run_origin.record_sha256,
            hex::encode(Sha256::digest(raw.as_bytes()))
        );
        assert_eq!(
            verified.run_origin.signer_public_key_hex,
            hex::encode(run_key().verifying_key().as_bytes())
        );
        assert_ne!(
            verified.run_origin.signer_public_key_hex,
            verified.bundle.signer_public_key_hex
        );
        assert!(!format!("{verified:?}").contains("PRIVATE-"));
    }

    #[test]
    fn requesting_run_authentication_requires_an_origin_and_an_independent_anchor() {
        let mut bundle = run_bundle();
        let record = record_for(&mut bundle);
        let legacy = resign(&mut bundle);
        verify_incident_bundle(&legacy, &bundle_key()).unwrap();
        assert_eq!(
            verify_incident_bundle_with_run_key(&legacy, &bundle_key(), &run_key().verifying_key()),
            Err(IncidentBundleError::RunOriginMissing)
        );
        let bytes = embed(&mut bundle, &signed_record(&record));
        assert_eq!(
            verify_incident_bundle_with_run_key(&bytes, &bundle_key(), &bundle_key()),
            Err(IncidentBundleError::RunOriginSignatureInvalid)
        );
    }

    #[test]
    fn valid_exporter_signature_cannot_rewrite_any_original_signed_member() {
        let mut bundle = run_bundle();
        let record = record_for(&mut bundle);
        let raw = signed_record(&record);
        for (pointer, replacement) in [
            ("/receipt_path", json!("PRIVATE-substitute-path")),
            (
                "/receipt_snapshot/telemetry/wall_time_ms",
                json!(51.24817837550541),
            ),
            (
                "/unknown_signed_extension/private",
                json!("PRIVATE-substitute-extension"),
            ),
        ] {
            let mut changed: Value = serde_json::from_str(&raw).unwrap();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let error =
                assert_origin_refused(bundle.clone(), &serde_json::to_string(&changed).unwrap());
            assert_eq!(
                error,
                IncidentBundleError::RunOriginSignatureInvalid,
                "{pointer}"
            );
            assert!(!format!("{error}").contains("PRIVATE-"));
        }
    }

    #[test]
    fn duplicate_nested_members_and_malformed_signatures_are_rejected_without_disclosing_record() {
        let mut bundle = run_bundle();
        let record = record_for(&mut bundle);
        let raw = signed_record(&record);
        let duplicate = raw.replacen(
            "\"wall_time_ms\":",
            "\"wall_time_ms\":0,\"wall_time_ms\":",
            1,
        );
        assert!(matches!(
            assert_origin_refused(bundle.clone(), &duplicate),
            IncidentBundleError::RunOriginInvalid { .. }
        ));
        let mut malformed: Value = serde_json::from_str(&raw).unwrap();
        malformed["record_signature"] = json!("PRIVATE-not-a-signature");
        assert_eq!(
            assert_origin_refused(bundle, &serde_json::to_string(&malformed).unwrap()),
            IncidentBundleError::RunOriginSignatureMalformed
        );
    }

    #[test]
    fn original_receipt_snapshot_security_controls_and_ledger_must_match_exactly() {
        let mut bundle = run_bundle();
        let record = record_for(&mut bundle);
        for (pointer, replacement) in [
            ("/receipt_snapshot/receipt_id", json!("different-run")),
            (
                "/receipt_snapshot/receipt_hash",
                json!(format!("sha256:{}", "b".repeat(64))),
            ),
            ("/receipt_snapshot/app_path", json!("other.js")),
            ("/receipt_snapshot/policy_mode", json!("other-policy")),
            ("/receipt_snapshot/ssrf_violations", json!(["blocked"])),
            ("/sentinel_enforced", json!(true)),
            (
                "/host_effect_ledger/trace_id",
                json!("another-engine-trace"),
            ),
            ("/host_effect_ledger/chain_head_hash", json!("other-head")),
            ("/host_effect_ledger/allowed_count", json!(2)),
            // Same declared count/head is insufficient: every original entry
            // must equal the already verified bundle chain entry.
            (
                "/host_effect_ledger/entries/1/chain_hash",
                json!("other-entry"),
            ),
        ] {
            let mut changed = record.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                matches!(
                    assert_origin_refused(bundle.clone(), &signed_record(&changed)),
                    IncidentBundleError::RunOriginInvalid { .. }
                ),
                "{pointer}"
            );
        }
        let mut interrupted = record.clone();
        interrupted["receipt_snapshot"]["interruption_evidence"] = json!({"signal":"SIGINT"});
        assert!(matches!(
            assert_origin_refused(bundle, &signed_record(&interrupted)),
            IncidentBundleError::RunOriginInvalid { .. }
        ));
    }

    #[test]
    fn exporter_cannot_relabel_run_identity_policy_or_security_controls() {
        let mut bundle = run_bundle();
        let record = record_for(&mut bundle);
        let raw = signed_record(&record);
        for (pointer, replacement) in [
            ("/initial_state_snapshot/run_receipt_id", json!("other-run")),
            (
                "/initial_state_snapshot/run_receipt_hash",
                json!(format!("sha256:{}", "b".repeat(64))),
            ),
            ("/policy_version", json!("other-policy")),
            (
                "/initial_state_snapshot/ssrf_violations",
                json!(["different-control"]),
            ),
            ("/initial_state_snapshot/sentinel_enforced", json!(true)),
        ] {
            let mut changed = bundle.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                matches!(
                    assert_origin_refused(changed, &raw),
                    IncidentBundleError::RunOriginInvalid { .. }
                ),
                "{pointer}"
            );
        }
    }

    fn native_bundle(state: &str) -> (Value, Value) {
        use crate::incident_bundle::native_capture::tests::{signed_bundle, with_run_context};
        let bytes = signed_bundle(with_run_context(state));
        let mut bundle: Value = serde_json::from_slice(&bytes).unwrap();
        let record = record_for(&mut bundle);
        (bundle, record)
    }

    #[test]
    fn native_capture_and_original_terminal_state_are_bound_for_every_outcome() {
        for state in ["completed", "uncaught_exception", "engine_failure"] {
            let (mut bundle, record) = native_bundle(state);
            let raw = signed_record(&record);
            let bytes = embed(&mut bundle, &raw);
            verify_incident_bundle_with_run_key(&bytes, &bundle_key(), &run_key().verifying_key())
                .unwrap();

            let mut changed = record.clone();
            changed["receipt_snapshot"]["native_replay_payload_sha256"] = json!("0".repeat(64));
            assert!(matches!(
                assert_origin_refused(bundle.clone(), &signed_record(&changed)),
                IncidentBundleError::RunOriginInvalid { .. }
            ));
            let mut changed = record.clone();
            changed["native_replay"]["payload_json"] = json!("PRIVATE-substituted-capture");
            assert!(matches!(
                assert_origin_refused(bundle.clone(), &signed_record(&changed)),
                IncidentBundleError::RunOriginInvalid { .. }
            ));
            let mut changed = record.clone();
            changed["receipt_snapshot"]["execution_failure"] = json!("PRIVATE-other-failure");
            assert!(matches!(
                assert_origin_refused(bundle, &signed_record(&changed)),
                IncidentBundleError::RunOriginInvalid { .. }
            ));
        }
    }

    #[test]
    fn zero_effect_terminal_time_comes_from_original_receipt_after_utc_normalization() {
        let (mut bundle, mut record) = native_bundle("completed");
        record["receipt_snapshot"]["end_time_utc"] = json!("2026-02-20T11:00:00.000100+01:00");
        let raw = signed_record(&record);
        let bytes = embed(&mut bundle, &raw);
        verify_incident_bundle_with_run_key(&bytes, &bundle_key(), &run_key().verifying_key())
            .unwrap();
        bundle["timeline"][0]["timestamp"] = json!("2026-02-20T10:00:00.000200Z");
        assert!(matches!(
            assert_origin_refused(bundle, &raw),
            IncidentBundleError::RunOriginInvalid { .. }
        ));
    }
}
