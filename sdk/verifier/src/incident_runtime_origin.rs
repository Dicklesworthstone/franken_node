//! Portable, independent verification of the product's runtime-evidence chain.
//!
//! Public wire mirrors preserve the producer's JSON field order, not generic
//! object-map ordering. The protocols are owned by engine_dispatcher.rs and
//! franken_engine/evidence_ledger.rs; no engine, filesystem or guest execution
//! dependency is introduced here. Call only after bundle and run-origin checks.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{IncidentBundleError, ct_str_eq, decode_evidence_json};
use crate::bundle::EffectReceiptChainEntry;

const CAPTURE_SCHEMA: &str = "franken-node/runtime-evidence-identity-capture/v1";
const CAPTURE_DOMAIN: &[u8] = b"franken-node.runtime-evidence-identity-capture.v1";
const KEY_ID_DOMAIN: &[u8] = b"franken-engine.evidence-signing-key.v1";
const LEDGER_DOMAIN: &[u8] = b"franken-node:host-effect-ledger-signature:v3\0";
const DETACHED_DOMAIN: &str = "franken-engine.detached-evidence-signature.v1";
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
// The product refuses native responses larger than this bound, including their
// ledger. Bounding before decimal byte-array expansion also bounds the outer
// detached-signature preimage to at most 4x this size plus its small envelope.
const MAX_LEDGER_BYTES: usize = 24 * 1024 * 1024;

type Result<T> = std::result::Result<T, IncidentBundleError>;

/// Public identity established by root and session signature verification.
/// This is historical ledger attribution, not current execution authority,
/// cleanup certification or proof that external effects committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedRuntimeOrigin {
    pub session_nonce: String,
    pub product_root_key_id: String,
    pub producer_id: String,
    pub evidence_key_id: String,
    /// Serialized as a decimal string so JavaScript preserves every u64 epoch.
    #[serde(serialize_with = "serialize_epoch")]
    pub signed_epoch: u64,
}

fn serialize_epoch<S: serde::Serializer>(
    epoch: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&epoch.to_string())
}

// These types intentionally have no Debug implementations: invalid evidence
// must not expose private paths, source bytes or attacker-controlled text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    inner: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyProvenance {
    authority_class: String,
    key_id: String,
    activation_epoch: u64,
    rotation_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_key_id: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    producer_id: String,
    key_provenance: KeyProvenance,
    verification_key: PublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityCapture {
    schema_version: String,
    session_nonce: String,
    product_root_key_id: String,
    product_root_verification_key_hex: String,
    evidence_verification_identity: Identity,
    signature_hex: String,
}

#[derive(Serialize)]
struct CapturePayload<'a> {
    schema_version: &'a str,
    session_nonce: &'a str,
    product_root_key_id: &'a str,
    product_root_verification_key_hex: &'a str,
    evidence_verification_identity: &'a Identity,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureBytes {
    lower: [u8; 32],
    upper: [u8; 32],
}

impl SignatureBytes {
    fn signature(&self) -> Signature {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.lower);
        bytes[32..].copy_from_slice(&self.upper);
        Signature::from_bytes(&bytes)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    producer_id: String,
    key_provenance: KeyProvenance,
    signed_epoch: u64,
    verification_key: PublicKey,
    signature: SignatureBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema_version: String,
    trace_id: String,
    chain_head_hash: String,
    effect_count: u64,
    allowed_count: u64,
    denied_count: u64,
    failed_count: u64,
    entries: Vec<EffectReceiptChainEntry>,
    signature: Envelope,
}

#[derive(Serialize)]
struct LedgerPayload<'a> {
    schema_version: &'a str,
    trace_id: &'a str,
    chain_head_hash: &'a str,
    effect_count: u64,
    allowed_count: u64,
    denied_count: u64,
    failed_count: u64,
    entries: &'a [EffectReceiptChainEntry],
}

fn invalid(reason: &'static str) -> IncidentBundleError {
    IncidentBundleError::RuntimeOriginInvalid { reason }
}

fn encoded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    // Unlike to_vec followed by a length check, this caps allocation while the
    // encoder is running, including the detached protocol's byte-array form.
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("runtime evidence encoding exceeds its bound or is invalid"))?;
    Ok(output.bytes)
}

fn framed(domain: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let length = u64::try_from(payload.len())
        .map_err(|_| invalid("runtime evidence length is not representable"))?;
    let mut output = Vec::with_capacity(domain.len() + 8 + payload.len());
    output.extend_from_slice(domain);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn capture_preimage(capture: &IdentityCapture) -> Result<Vec<u8>> {
    framed(
        CAPTURE_DOMAIN,
        &encoded(
            &CapturePayload {
                schema_version: &capture.schema_version,
                session_nonce: &capture.session_nonce,
                product_root_key_id: &capture.product_root_key_id,
                product_root_verification_key_hex: &capture.product_root_verification_key_hex,
                evidence_verification_identity: &capture.evidence_verification_identity,
            },
            MAX_CAPTURE_BYTES,
        )?,
    )
}

fn ledger_preimage(ledger: &Ledger) -> Result<Vec<u8>> {
    let payload = encoded(
        &LedgerPayload {
            schema_version: &ledger.schema_version,
            trace_id: &ledger.trace_id,
            chain_head_hash: &ledger.chain_head_hash,
            effect_count: ledger.effect_count,
            allowed_count: ledger.allowed_count,
            denied_count: ledger.denied_count,
            failed_count: ledger.failed_count,
            entries: &ledger.entries,
        },
        MAX_LEDGER_BYTES,
    )?;
    let framed = framed(LEDGER_DOMAIN, &payload)?;
    let mut envelope = ledger.signature.clone();
    envelope.signature = SignatureBytes {
        lower: [0; 32],
        upper: [0; 32],
    };
    encoded(
        &(DETACHED_DOMAIN, framed, envelope),
        4 * MAX_LEDGER_BYTES + MAX_CAPTURE_BYTES,
    )
}

fn canonical_nonce(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

/// Called only after the run record and the enclosing bundle were verified.
pub(super) fn verify(bundle: &Value, trusted_root: &VerifyingKey) -> Result<VerifiedRuntimeOrigin> {
    let initial = &bundle["initial_state_snapshot"];
    let capture = initial
        .get("runtime_evidence_identity_capture")
        .ok_or(IncidentBundleError::RuntimeOriginMissing)?;
    let capture: IdentityCapture = serde_json::from_slice(&encoded(capture, MAX_CAPTURE_BYTES)?)
        .map_err(|_| invalid("malformed runtime identity capture"))?;
    if capture.schema_version != CAPTURE_SCHEMA || !canonical_nonce(&capture.session_nonce) {
        return Err(invalid(
            "unsupported runtime identity schema or session nonce",
        ));
    }
    let expected_root_hex = hex::encode(trusted_root.as_bytes());
    let root_id = format!("ed25519:{expected_root_hex}");
    if trusted_root.is_weak()
        || !ct_str_eq(
            &capture.product_root_verification_key_hex,
            &expected_root_hex,
        )
        || !ct_str_eq(&capture.product_root_key_id, &root_id)
    {
        return Err(IncidentBundleError::RuntimeOriginSignerNotTrusted);
    }
    let identity = &capture.evidence_verification_identity;
    let provenance = &identity.key_provenance;
    let session_key = VerifyingKey::from_bytes(&identity.verification_key.inner)
        .map_err(|_| invalid("invalid runtime evidence public key"))?;
    if session_key.is_weak()
        || identity.producer_id.trim().is_empty()
        || identity.producer_id.len() > 512
    {
        return Err(invalid("invalid runtime evidence key or producer identity"));
    }
    let mut hash = Sha256::new();
    hash.update(KEY_ID_DOMAIN);
    hash.update(session_key.as_bytes());
    let key_id = format!("ed25519:{}", hex::encode(hash.finalize()));
    // The v1 capture authenticates one fresh session identity, not a rotation
    // chain. The product's singleton trust-snapshot validator also refuses a
    // rotated identity lacking its authenticated predecessor.
    if provenance.authority_class != "runtime"
        || !ct_str_eq(&provenance.key_id, &key_id)
        || provenance.rotation_sequence != 1
        || provenance.previous_key_id.is_some()
    {
        return Err(invalid(
            "unsupported or inconsistent runtime evidence provenance",
        ));
    }
    let mut signature = [0_u8; 64];
    hex::decode_to_slice(&capture.signature_hex, &mut signature)
        .map_err(|_| invalid("malformed runtime identity capture signature"))?;
    trusted_root
        .verify_strict(
            &capture_preimage(&capture)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| IncidentBundleError::RuntimeOriginCaptureSignatureInvalid)?;

    let raw = initial["run_origin"]["record_json"]
        .as_str()
        .ok_or_else(|| invalid("missing original signed run record"))?;
    let record = decode_evidence_json(raw.as_bytes())
        .map_err(|_| invalid("invalid original signed run record"))?;
    let ledger: Ledger = serde_json::from_value(record["host_effect_ledger"].clone())
        .map_err(|_| invalid("malformed signed engine ledger"))?;
    if ledger.schema_version != "host-effect-ledger-v3.0" {
        return Err(invalid("unsupported signed engine ledger schema"));
    }
    let envelope = &ledger.signature;
    if envelope.producer_id != identity.producer_id
        || envelope.key_provenance != identity.key_provenance
        || envelope.verification_key != identity.verification_key
        || envelope.signed_epoch < provenance.activation_epoch
    {
        return Err(invalid(
            "engine ledger signer or epoch disagrees with authenticated session",
        ));
    }
    session_key
        .verify_strict(&ledger_preimage(&ledger)?, &envelope.signature.signature())
        .map_err(|_| IncidentBundleError::RuntimeOriginLedgerSignatureInvalid)?;
    Ok(VerifiedRuntimeOrigin {
        session_nonce: capture.session_nonce,
        product_root_key_id: root_id,
        producer_id: identity.producer_id.clone(),
        evidence_key_id: key_id,
        signed_epoch: envelope.signed_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use crate::incident_bundle::structure::tests::resign;
    use crate::incident_bundle::{
        verify_incident_bundle_with_run_key, verify_incident_bundle_with_runtime_keys,
    };

    const NONCE: &str = "0199abcd-1234-7000-8000-123456789abc";

    fn root_key() -> SigningKey {
        SigningKey::from_bytes(&[0x53; 32])
    }
    fn session_key() -> SigningKey {
        SigningKey::from_bytes(&[0x64; 32])
    }
    fn run_key() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }
    fn exporter() -> VerifyingKey {
        let mut bytes = [0; 32];
        hex::decode_to_slice(
            include_str!("../tests/fixtures/run_origin_protocol/bundle-authority.pub").trim(),
            &mut bytes,
        )
        .unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    fn sign_record(record: &Value) -> String {
        let mut value = record.clone();
        value.as_object_mut().unwrap().remove("record_signature");
        value.sort_all_objects();
        let mut payload = b"franken-node/run-host-effect-ledger-record-signature/v1\0".to_vec();
        serde_json::to_writer(&mut payload, &value).unwrap();
        value["record_signature"] = json!(hex::encode(run_key().sign(&payload).to_bytes()));
        serde_json::to_string(&value).unwrap()
    }

    fn seal(bundle: &mut Value, record: &Value) -> Vec<u8> {
        bundle["initial_state_snapshot"]["run_origin"]["record_json"] = json!(sign_record(record));
        resign(bundle)
    }

    fn signed_capture(capture: &mut IdentityCapture) {
        capture.signature_hex = hex::encode(
            root_key()
                .sign(&capture_preimage(capture).unwrap())
                .to_bytes(),
        );
    }

    // Protocol fixtures use actual Ed25519 signatures with three distinct
    // authorities and the producer's existing effect-chain fixture. These are
    // cryptographic interoperability controls, not claims of guest execution.
    fn fixture() -> (Value, Value, IdentityCapture) {
        let bundle: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/run_origin_protocol/producer-run.fnbundle"
        ))
        .unwrap();
        let mut record: Value = serde_json::from_str(
            bundle["initial_state_snapshot"]["run_origin"]["record_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let key = session_key().verifying_key();
        let mut hash = Sha256::new();
        hash.update(KEY_ID_DOMAIN);
        hash.update(key.as_bytes());
        let identity = Identity {
            producer_id: format!(
                "franken-node.native-session:ed25519:{}:{NONCE}",
                hex::encode(root_key().verifying_key().as_bytes())
            ),
            key_provenance: KeyProvenance {
                authority_class: "runtime".into(),
                key_id: format!("ed25519:{}", hex::encode(hash.finalize())),
                activation_epoch: 7,
                rotation_sequence: 1,
                previous_key_id: None,
            },
            verification_key: PublicKey {
                inner: key.to_bytes(),
            },
        };
        let mut capture = IdentityCapture {
            schema_version: CAPTURE_SCHEMA.into(),
            session_nonce: NONCE.into(),
            product_root_key_id: format!(
                "ed25519:{}",
                hex::encode(root_key().verifying_key().as_bytes())
            ),
            product_root_verification_key_hex: hex::encode(root_key().verifying_key().as_bytes()),
            evidence_verification_identity: identity.clone(),
            signature_hex: String::new(),
        };
        signed_capture(&mut capture);
        let envelope = Envelope {
            producer_id: identity.producer_id,
            key_provenance: identity.key_provenance,
            signed_epoch: 7,
            verification_key: identity.verification_key,
            signature: SignatureBytes {
                lower: [0; 32],
                upper: [0; 32],
            },
        };
        record["host_effect_ledger"]["signature"] = serde_json::to_value(envelope).unwrap();
        let ledger: Ledger = serde_json::from_value(record["host_effect_ledger"].clone()).unwrap();
        let signature = session_key()
            .sign(&ledger_preimage(&ledger).unwrap())
            .to_bytes();
        record["host_effect_ledger"]["signature"]["signature"] =
            json!({"lower":&signature[..32],"upper":&signature[32..]});
        (bundle, record, capture)
    }

    fn attach(bundle: &mut Value, capture: &IdentityCapture) {
        bundle["initial_state_snapshot"]["runtime_evidence_identity_capture"] =
            serde_json::to_value(capture).unwrap();
    }

    fn strong(
        bytes: &[u8],
    ) -> std::result::Result<
        super::super::VerifiedIncidentBundleWithRuntimeOrigin,
        IncidentBundleError,
    > {
        verify_incident_bundle_with_runtime_keys(
            bytes,
            &exporter(),
            &run_key().verifying_key(),
            &root_key().verifying_key(),
        )
    }

    #[test]
    fn runtime_origin_authenticates_the_root_session_and_original_effect_ledger() {
        let (mut bundle, record, capture) = fixture();
        attach(&mut bundle, &capture);
        let bytes = seal(&mut bundle, &record);
        let verified = strong(&bytes).unwrap();
        assert_eq!(verified.runtime_origin.session_nonce, NONCE);
        assert_eq!(verified.runtime_origin.signed_epoch, 7);
        assert_eq!(
            verified.runtime_origin.evidence_key_id,
            capture.evidence_verification_identity.key_provenance.key_id
        );
        assert_eq!(verified.bundle.event_count, 1);
        assert_ne!(
            verified.run_origin.signer_public_key_hex,
            capture.product_root_verification_key_hex
        );
        assert!(!format!("{verified:?}").contains("PRIVATE-"));
        verify_incident_bundle_with_run_key(&bytes, &exporter(), &run_key().verifying_key())
            .unwrap();
    }

    #[test]
    fn runtime_origin_requires_a_portable_capture_and_an_independent_root() {
        let (mut bundle, record, capture) = fixture();
        let historical = seal(&mut bundle, &record);
        verify_incident_bundle_with_run_key(&historical, &exporter(), &run_key().verifying_key())
            .unwrap();
        assert_eq!(
            strong(&historical),
            Err(IncidentBundleError::RuntimeOriginMissing)
        );
        attach(&mut bundle, &capture);
        let bytes = seal(&mut bundle, &record);
        assert_eq!(
            verify_incident_bundle_with_runtime_keys(
                &bytes,
                &exporter(),
                &run_key().verifying_key(),
                &session_key().verifying_key()
            ),
            Err(IncidentBundleError::RuntimeOriginSignerNotTrusted)
        );
        bundle["initial_state_snapshot"]["runtime_evidence_identity_capture"] = Value::Null;
        assert!(matches!(
            strong(&seal(&mut bundle, &record)),
            Err(IncidentBundleError::RuntimeOriginInvalid { .. })
        ));
    }

    #[test]
    fn an_authenticated_exporter_cannot_substitute_session_capture_fields() {
        let (bundle, record, capture) = fixture();
        for (field, replacement, expected) in [
            (
                "session_nonce",
                json!("0199abcd-1234-7000-8000-123456789abd"),
                IncidentBundleError::RuntimeOriginCaptureSignatureInvalid,
            ),
            (
                "signature_hex",
                json!("00".repeat(64)),
                IncidentBundleError::RuntimeOriginCaptureSignatureInvalid,
            ),
            (
                "product_root_key_id",
                json!("ed25519:00"),
                IncidentBundleError::RuntimeOriginSignerNotTrusted,
            ),
        ] {
            let mut changed = bundle.clone();
            attach(&mut changed, &capture);
            changed["initial_state_snapshot"]["runtime_evidence_identity_capture"][field] =
                replacement;
            assert_eq!(
                strong(&seal(&mut changed, &record)),
                Err(expected),
                "{field}"
            );
        }
    }

    #[test]
    fn signed_lab_rotated_or_inconsistent_identity_cannot_authorize_a_runtime_ledger() {
        let (bundle, record, _) = fixture();
        for mutation in 0..6 {
            let (_, _, mut capture) = fixture();
            let provenance = &mut capture.evidence_verification_identity.key_provenance;
            match mutation {
                0 => provenance.authority_class = "lab_fixture".into(),
                1 => provenance.rotation_sequence = 0,
                2 => provenance.rotation_sequence = 2,
                3 => provenance.previous_key_id = Some("another-key".into()),
                4 => provenance.key_id = "ed25519:invalid".into(),
                _ => {
                    capture
                        .evidence_verification_identity
                        .verification_key
                        .inner = [0; 32]
                }
            }
            signed_capture(&mut capture);
            let mut changed = bundle.clone();
            attach(&mut changed, &capture);
            let error = strong(&seal(&mut changed, &record)).unwrap_err();
            assert!(
                matches!(error, IncidentBundleError::RuntimeOriginInvalid { .. }),
                "mutation {mutation}: {error}"
            );
        }
    }

    #[test]
    fn run_and_exporter_signatures_cannot_forge_the_original_engine_signature() {
        let (bundle, record, capture) = fixture();
        for (pointer, replacement, signature_failure) in [
            ("/signature/signature/lower/0", json!(255), true),
            ("/signature/signed_epoch", json!(8), true),
            ("/signature/signed_epoch", json!(6), false),
            ("/signature/producer_id", json!("PRIVATE-substitute"), false),
            (
                "/signature/key_provenance/activation_epoch",
                json!(6),
                false,
            ),
        ] {
            let mut changed_record = record.clone();
            *changed_record["host_effect_ledger"]
                .pointer_mut(pointer)
                .unwrap() = replacement;
            let mut changed_bundle = bundle.clone();
            attach(&mut changed_bundle, &capture);
            let bytes = seal(&mut changed_bundle, &changed_record);
            // Both outer authorities approve these bytes, but neither owns the
            // authenticated session's engine evidence signing key.
            verify_incident_bundle_with_run_key(&bytes, &exporter(), &run_key().verifying_key())
                .unwrap();
            let error = strong(&bytes).unwrap_err();
            if signature_failure {
                assert_eq!(
                    error,
                    IncidentBundleError::RuntimeOriginLedgerSignatureInvalid,
                    "{pointer}"
                );
            } else {
                assert!(
                    matches!(error, IncidentBundleError::RuntimeOriginInvalid { .. }),
                    "{pointer}"
                );
            }
            assert!(!format!("{error:?}").contains("PRIVATE-"));
        }
    }

    #[test]
    fn runtime_origin_refuses_unknown_fields_and_oversized_public_captures() {
        let (bundle, record, capture) = fixture();
        for mutation in 0..4 {
            let mut changed = bundle.clone();
            attach(&mut changed, &capture);
            let identity =
                &mut changed["initial_state_snapshot"]["runtime_evidence_identity_capture"];
            match mutation {
                0 => identity["unexpected"] = json!(true),
                1 => identity["evidence_verification_identity"]["unexpected"] = json!(true),
                2 => identity["session_nonce"] = json!("PRIVATE-not-a-uuid"),
                _ => identity["signature_hex"] = json!("0".repeat(MAX_CAPTURE_BYTES)),
            }
            assert!(matches!(
                strong(&seal(&mut changed, &record)),
                Err(IncidentBundleError::RuntimeOriginInvalid { .. })
            ));
        }
        assert!(encoded(&vec![0; 100], 10).is_err());
    }
}
