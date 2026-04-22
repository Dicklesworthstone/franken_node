use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::epoch_scoped_keys::{
    RootSecret, derive_epoch_key, sign_epoch_artifact, verify_epoch_signature,
};

#[test]
fn epoch_domain_shift_preserves_determinism_and_cross_pair_rejection() -> Result<(), String> {
    let root = RootSecret::from_bytes([0x42; 32]);
    let payloads: [&[u8]; 3] = [
        b"runtime-manifest".as_slice(),
        b"policy-bundle".as_slice(),
        b"barrier-ack".as_slice(),
    ];
    let domains = ["manifest", "policy", "barrier"];

    for epoch_value in 1_u64..=8 {
        for domain in domains {
            let base_epoch = ControlEpoch::new(epoch_value);
            let shifted_epoch = ControlEpoch::new(epoch_value.saturating_add(1));
            let shifted_domain = format!("{domain}-shifted");

            let base_key = derive_epoch_key(&root, base_epoch, domain);
            let shifted_key = derive_epoch_key(&root, shifted_epoch, &shifted_domain);
            let repeated_base_key = derive_epoch_key(&root, base_epoch, domain);
            if base_key != repeated_base_key {
                return Err(
                    "same root/epoch/domain must deterministically derive the same key material"
                        .to_string(),
                );
            }
            if base_key == shifted_key {
                return Err(
                    "metamorphic epoch/domain shift must change derived key material".to_string(),
                );
            }

            for payload in payloads {
                let base_signature = sign_epoch_artifact(payload, base_epoch, domain, &root)
                    .map_err(|err| {
                        format!("base signature should be generated for {domain}: {err}")
                    })?;
                let shifted_signature =
                    sign_epoch_artifact(payload, shifted_epoch, &shifted_domain, &root).map_err(
                        |err| {
                            format!(
                                "shifted signature should be generated for {shifted_domain}: {err}"
                            )
                        },
                    )?;

                if verify_epoch_signature(payload, &base_signature, base_epoch, domain, &root)
                    .is_err()
                {
                    return Err("base signature should verify for its own epoch/domain".to_string());
                }
                if verify_epoch_signature(
                    payload,
                    &shifted_signature,
                    shifted_epoch,
                    &shifted_domain,
                    &root,
                )
                .is_err()
                {
                    return Err(
                        "shifted signature should verify for its own epoch/domain".to_string()
                    );
                }
                if verify_epoch_signature(
                    payload,
                    &base_signature,
                    shifted_epoch,
                    &shifted_domain,
                    &root,
                )
                .is_ok()
                {
                    return Err(
                        "base signature must not verify under shifted epoch/domain".to_string()
                    );
                }
                if verify_epoch_signature(payload, &shifted_signature, base_epoch, domain, &root)
                    .is_ok()
                {
                    return Err(
                        "shifted signature must not verify under base epoch/domain".to_string()
                    );
                }
            }
        }
    }
    Ok(())
}
