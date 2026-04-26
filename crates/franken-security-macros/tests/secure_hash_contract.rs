use franken_security_macros::secure_hash;

fn manual_hash(domain: &str, data: &[u8]) -> String {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, b"interface_hash_v1:");
    sha2::Digest::update(
        &mut hasher,
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    sha2::Digest::update(&mut hasher, domain.as_bytes());
    sha2::Digest::update(
        &mut hasher,
        u64::try_from(data.len()).unwrap_or(u64::MAX).to_le_bytes(),
    );
    sha2::Digest::update(&mut hasher, data);
    hex::encode(sha2::Digest::finalize(hasher))
}

#[test]
fn secure_hash_preserves_domain_separated_length_framing() {
    let domain = "connector.v1";
    let data = b"payload";

    let macro_hash = secure_hash!("interface_hash_v1:", domain.as_bytes(), data);

    assert_eq!(macro_hash, manual_hash(domain, data));
}
