use std::error::Error;

use frankenengine_node::supply_chain::artifact_signing::{
    ArtifactSigningError, generate_artifact_signing_key, sign_bytes, signing_key_from_seed_bytes,
    signing_key_from_seed_hex, verify_signature,
};

#[test]
fn generated_artifact_signing_key_signs_and_verifies() -> Result<(), Box<dyn Error>> {
    let signing_key = generate_artifact_signing_key();
    let payload = b"artifact-signing-key-loading";
    let signature = sign_bytes(&signing_key, payload);

    verify_signature(&signing_key.verifying_key(), payload, &signature)?;

    Ok(())
}

#[test]
fn configured_seed_hex_matches_seed_bytes() -> Result<(), Box<dyn Error>> {
    let seed = [31_u8; 32];
    let from_bytes = signing_key_from_seed_bytes(&seed)?;
    let from_hex = signing_key_from_seed_hex(&format!("hex:{}", hex::encode(seed)))?;

    assert_eq!(
        from_bytes.verifying_key().as_bytes(),
        from_hex.verifying_key().as_bytes()
    );

    Ok(())
}

#[test]
fn configured_key_loader_rejects_malformed_material() {
    assert!(matches!(
        signing_key_from_seed_bytes(&[1_u8; 31]),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
    assert!(matches!(
        signing_key_from_seed_bytes(&[1_u8; 33]),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
    assert!(matches!(
        signing_key_from_seed_hex("not-hex"),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
    assert!(matches!(
        signing_key_from_seed_hex(&hex::encode([1_u8; 31])),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
}
