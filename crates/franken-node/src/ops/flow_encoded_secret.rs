//! Allocation-free decoded views of outbound bytes for the live flow gate.
//!
//! This is detection, not request normalization: the provider always receives
//! the original request. A percent escape is decoded exactly once; '+' is not
//! interpreted as a space. Invalid/incomplete escapes retain their literal
//! bytes. No source bytes, decoded bytes or match positions enter diagnostics.
//!
//! Base64 views recognize a complete sample inside a larger encoded message,
//! independent of the sample's byte alignment or the run's character alignment.
//! Standard and URL-safe alphabets, optional padding and ASCII whitespace are
//! accepted conservatively. Non-alphabet separators (including padding) reset
//! the view; separately encoded fields are not joined across those separators.
//! Inspect raw Base64 and Base64 under one percent-encoding transport layer.
//! Eight small decoder states share the existing sample and KMP table; no
//! decoded buffer, extra secret copy or input-sized allocation is constructed.
//! These bounded views are not recursive decoding or general dataflow tracking.

/// Scan supported decoded views against the already compiled raw sample.
/// `failure` is the private KMP table built by `SecretPattern`, not wire data.
pub(super) fn contains(secret: &[u8], failure: &[u32], outbound: &[u8]) -> bool {
    if secret.is_empty() || secret.len() > outbound.len() {
        return false;
    }
    let mut base64 = Base64Matcher::new(secret, failure);
    if outbound.iter().copied().any(|byte| base64.push(byte)) {
        return true;
    }
    if !outbound.contains(&b'%') {
        return false;
    }
    let mut matcher = Matcher::new(secret, failure);
    let mut base64 = Base64Matcher::new(secret, failure);
    PercentDecoded::new(outbound).any(|byte| matcher.push(byte) || base64.push(byte))
}

struct Matcher<'a> {
    secret: &'a [u8],
    failure: &'a [u32],
    matched: usize,
}

impl<'a> Matcher<'a> {
    fn new(secret: &'a [u8], failure: &'a [u32]) -> Self {
        Self { secret, failure, matched: 0 }
    }

    fn push(&mut self, byte: u8) -> bool {
        while self.matched > 0 && byte != self.secret[self.matched] {
            self.matched = self.failure[self.matched - 1] as usize;
        }
        if byte == self.secret[self.matched] {
            self.matched += 1;
        }
        self.matched == self.secret.len()
    }
}

struct Base64State<'a> {
    matcher: Matcher<'a>,
    buffer: u16,
    bits: u8,
    skip: usize,
}

impl Base64State<'_> {
    fn reset(&mut self, alignment: usize) {
        self.matcher.matched = 0;
        self.buffer = 0;
        self.bits = 0;
        self.skip = alignment;
    }

    fn push(&mut self, value: u8) -> bool {
        if self.skip > 0 {
            self.skip -= 1;
            return false;
        }
        // At most six bits survive the previous call, so appending one
        // sextet cannot overflow u16. At most one octet is emitted per call.
        self.buffer = (self.buffer << 6) | u16::from(value);
        self.bits += 6;
        if self.bits < 8 {
            return false;
        }
        self.bits -= 8;
        let byte = u8::try_from(self.buffer >> self.bits).expect("decoded base64 octet");
        self.buffer &= (1_u16 << self.bits) - 1;
        self.matcher.push(byte)
    }
}

struct Base64Matcher<'a> {
    states: [Base64State<'a>; 4],
}

impl<'a> Base64Matcher<'a> {
    fn new(secret: &'a [u8], failure: &'a [u32]) -> Self {
        Self {
            states: std::array::from_fn(|alignment| Base64State {
                matcher: Matcher::new(secret, failure),
                buffer: 0,
                bits: 0,
                skip: alignment,
            }),
        }
    }

    fn push(&mut self, byte: u8) -> bool {
        // HTTP framing may adjoin alphabet characters to the encoded field.
        // Four parallel starts cover every possible quartet boundary without
        // rescanning suffixes. KMP also handles every source-byte alignment.
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => return false,
            _ => {
                for (alignment, state) in self.states.iter_mut().enumerate() {
                    state.reset(alignment);
                }
                return false;
            }
        };
        self.states.iter_mut().any(|state| state.push(value))
    }
}

struct PercentDecoded<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PercentDecoded<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl Iterator for PercentDecoded<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.offset)?;
        self.offset += 1;
        if byte == b'%'
            && let Some(digits) = self.bytes.get(self.offset..self.offset.saturating_add(2))
            && let (Some(high), Some(low)) = (hex_digit(digits[0]), hex_digit(digits[1]))
        {
            self.offset += 2;
            return Some((high << 4) | low);
        }
        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{FlowGatedHostIo, SecretPattern, SecretSample};
    use base64::{Engine as _, engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD}};
    use frankenengine_extension_host::host_io::{
        DenyAllHostIo, FsOperation,
        HostIoCapability, HostIoControl, HostIoError, HostIoOutcome, HostIoProvider,
        HostIoRequest, HostIoResponse, UnrestrictedHostIoControl,
    };
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    fn matched(secret: &[u8], outbound: &[u8]) -> bool {
        let pattern = SecretPattern::new(secret.to_vec(), false);
        contains(secret, &pattern.failure, outbound)
    }

    #[test]
    fn percent_view_matches_mixed_escapes_without_changing_case_or_plus() {
        assert!(matched(b"secret/token?x=a+b", b"q=sec%72et%2ftoken%3Fx%3da%2Bb&ok=1"));
        assert!(!matched(b"Secret/token", b"secret%2Ftoken"));
        assert!(!matched(b"a b", b"a+b%21"));
        assert!(matched(b"a+b!", b"a+b%21"));
        assert!(!matched(b"secret/token", b"secret%252Ftoken"));
        assert!(!matched(b"", b"%00"));
    }

    #[test]
    fn percent_view_preserves_invalid_escapes_and_arbitrary_octets() {
        for (encoded, decoded) in [
            (&b"%"[..], &b"%"[..]), (&b"%0"[..], &b"%0"[..]),
            (&b"%GG"[..], &b"%GG"[..]), (&b"%%41"[..], &b"%A"[..]),
            (&b"%00%ff%Ff"[..], &b"\0\xff\xff"[..]),
            (&b"%25%32%46"[..], &b"%2F"[..]),
        ] {
            assert_eq!(PercentDecoded::new(encoded).collect::<Vec<_>>(), decoded);
        }
        assert!(matched("秘密/clé".as_bytes(), b"x=%E7%A7%98%E5%AF%86%2Fcl%C3%A9"));
        assert!(matched(b"\0\xff", b"x=%00%ff"));
        assert!(!matched(b"\0\xfe", b"x=%00%ff"));
    }

    #[test]
    fn percent_view_matches_every_byte_and_repeated_prefixes() {
        for byte in 0_u8..=255 {
            let encoded = format!("prefix%{byte:02x}suffix");
            assert!(matched(&[byte], encoded.as_bytes()));
        }
        let mut outbound = "%61".repeat(65_536);
        assert!(!matched(b"aaaaab", outbound.as_bytes()));
        outbound.push_str("%62");
        assert!(matched(b"aaaaab", outbound.as_bytes()));
        assert!(SecretSample::new(b"secret/token").occurs_in(b"secret%2Ftoken"));
    }

    #[test]
    fn framed_base64_closes_the_surrounding_data_counterexample() {
        let sample = SecretSample::new(b"secret-token");
        let encoded = STANDARD.encode(b"xsecret-tokeny");
        assert!(!sample.patterns.iter().any(|pattern| pattern.occurs_in(encoded.as_bytes())));
        assert!(sample.occurs_in(encoded.as_bytes()));
        assert!(!sample.occurs_in(STANDARD.encode(b"xpublic-tokeny").as_bytes()));
    }

    #[test]
    fn framed_base64_covers_every_quartet_byte_alignment_alphabet_and_padding() {
        let bytes = [0xfb, 0xff, 0xfe, 0x80, 0, 0x11, 0x90, 0xee, 0x8a, 0xbb, 0xcc, 0xfd];
        for length in 8..=bytes.len() {
            let secret = &bytes[..length];
            for prefix in 0..6 {
                for suffix in 0..4 {
                    let message = [vec![b'x'; prefix], secret.to_vec(), vec![b'y'; suffix]].concat();
                    for encoded in [STANDARD.encode(&message), STANDARD_NO_PAD.encode(&message),
                        URL_SAFE.encode(&message), URL_SAFE_NO_PAD.encode(&message)] {
                        for lead in 0..4 {
                            let framed = format!("Authorization Basic {}{encoded}!", "Z".repeat(lead));
                            assert!(matched(secret, framed.as_bytes()), "length={length} prefix={prefix} suffix={suffix} lead={lead}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn framed_base64_handles_whitespace_and_one_percent_transport_layer() {
        let secret = b"\xfb\xffsecret-token\xfe";
        for encoded in [STANDARD.encode([b"x".as_slice(), secret, b"yz"].concat()),
            URL_SAFE_NO_PAD.encode([b"x".as_slice(), secret, b"yz"].concat())] {
            let folded = encoded.as_bytes().chunks(3)
                .map(|chunk| std::str::from_utf8(chunk).unwrap()).collect::<Vec<_>>().join("\r\n\t");
            assert!(matched(secret, folded.as_bytes()));
            let escaped = folded.bytes().map(|byte| format!("%{byte:02X}")).collect::<String>();
            assert!(matched(secret, format!("payload={escaped}&done=1").as_bytes()));
        }
        assert!(!matched(b"secret-token", b"c2VjcmV0!LXRva2Vu"));
        assert!(!matched(b"secret-token", b"c2VjcmV0=LXRva2Vu"));
        assert!(!matched(b"secret-token", b"c2VjcmV0\0LXRva2Vu"));
        assert!(matched(b"secret-token", b"c2VjcmV0\r\nLXRva2Vu"));
    }

    #[test]
    fn framed_base64_rejects_changed_samples_and_handles_long_repeated_prefixes() {
        let secret = b"a-secret-with-repeated-prefix-aaaaab";
        for changed in 0..secret.len() {
            let mut different = secret.to_vec();
            different[changed] ^= 1;
            let encoded = STANDARD.encode([b"prefix".as_slice(), &different, b"suffix"].concat());
            assert!(!matched(secret, encoded.as_bytes()), "changed byte {changed}");
        }
        let secret = [vec![b'a'; 4_095], vec![b'b']].concat();
        let mut message = vec![b'a'; 131_072];
        assert!(!matched(&secret, STANDARD.encode(&message).as_bytes()));
        message.push(b'b');
        assert!(matched(&secret, STANDARD.encode(&message).as_bytes()));
    }

    #[test]
    fn framed_encoding_labels_local_writes_before_failed_delegation() {
        let gate = FlowGatedHostIo::new(DenyAllHostIo, "encoded-local-lineage");
        gate.record_secret(b"secret-token");
        let encoded = STANDARD.encode(b"xsecret-tokeny").into_bytes();
        let fragment = encoded[..8].to_vec();
        assert!(gate.gate_outbound(&fragment).is_ok());
        let write = HostIoRequest::FsMeta {
            operation: FsOperation::Append, path: "public-cache".into(),
            arguments: Vec::new(), data: encoded,
        };
        let original_failure = Err(HostIoError::Io { detail: "partial local write".into() });
        assert_eq!(gate.gate(&write, &[write.required_capability()], &|_, _| original_failure.clone()), original_failure);
        assert!(gate.lineage.lock().unwrap().is_sensitive("public-cache"));
        let read = HostIoRequest::FsRead { path: "public-cache".into() };
        gate.gate(&read, &[read.required_capability()], &|_, _| {
            Ok(HostIoResponse::FsRead { bytes: fragment.clone() })
        }).unwrap();
        assert!(matches!(gate.gate_outbound(&fragment), Err(HostIoError::Denied { .. })));
    }

    #[derive(Debug)]
    struct Probe(Arc<AtomicUsize>);

    impl HostIoProvider for Probe {
        fn name(&self) -> &str { "encoded-egress-probe" }

        fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
            if matches!(request, HostIoRequest::FsRead { .. }) {
                return Ok(HostIoResponse::FsRead { bytes: b"capture secret/one".to_vec() });
            }
            if matches!(request, HostIoRequest::EnvRead { .. }) {
                return Ok(HostIoResponse::EnvRead { value: Some("capture secret/one".into()) });
            }
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(HostIoError::Io { detail: "original request delegated".to_string() })
        }

        fn perform_controlled(
            &self, request: &HostIoRequest, granted: &[HostIoCapability],
            control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            control.checkpoint()?;
            self.perform(request, granted)
        }
    }

    #[test]
    fn live_gate_refuses_percent_encoded_payloads_and_destinations_before_dispatch() {
        for controlled in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = FlowGatedHostIo::new(Probe(Arc::clone(&calls)), "encoded-egress-test");
            gate.perform(&HostIoRequest::FsRead { path: ".env".into() }, &[HostIoCapability::FsRead]).unwrap();
            for request in [
                HostIoRequest::NetworkSend { endpoint: "allowed.example:443".into(), payload: b"token=capture%20secret%2Fone".to_vec() },
                HostIoRequest::NetworkSend { endpoint: "capture%20secret%2Fone.example:443".into(), payload: Vec::new(), },
                HostIoRequest::NetworkRecv { endpoint: "capture%20secret%2Fone.example:443".into(), max_len: 1 },
            ] {
                let granted = [request.required_capability()];
                let result = if controlled {
                    gate.perform_controlled(&request, &granted, Arc::new(UnrestrictedHostIoControl))
                } else { gate.perform(&request, &granted) };
                assert!(matches!(result, Err(HostIoError::Denied { ref reason }) if reason.starts_with("flow_policy:")));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
            let clean = HostIoRequest::NetworkSend { endpoint: "allowed.example:443".into(), payload: b"unrelated%20data".to_vec() };
            assert!(matches!(gate.perform(&clean, &[HostIoCapability::NetworkSend]), Err(HostIoError::Io { .. })));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn live_gate_refuses_framed_base64_from_environment_before_plain_or_tls_network_io() {
        for controlled in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = FlowGatedHostIo::new(Probe(Arc::clone(&calls)), "framed-egress-test");
            let source = HostIoRequest::EnvRead { name: "EXPLICIT_FIXTURE".into() };
            gate.perform(&source, &[HostIoCapability::EnvRead]).unwrap();
            let message = b"prefix:capture secret/one:suffix";
            let payload = STANDARD.encode(message).into_bytes();
            let endpoint = format!("{}.example:443", URL_SAFE_NO_PAD.encode(message));
            let requests = [
                HostIoRequest::NetworkSend { endpoint: "allowed.example:443".into(), payload: payload.clone() },
                HostIoRequest::NetworkRequest { endpoint: "allowed.example:443".into(), payload: payload.clone(), max_len: 1, use_tls: false },
                HostIoRequest::NetworkRequest { endpoint: "allowed.example:443".into(), payload, max_len: 1, use_tls: true },
                HostIoRequest::NetworkRecv { endpoint, max_len: 1 },
            ];
            for request in requests {
                let granted = [request.required_capability()];
                let outcome = if controlled {
                    gate.perform_controlled(&request, &granted, Arc::new(UnrestrictedHostIoControl))
                } else { gate.perform(&request, &granted) };
                assert!(matches!(outcome, Err(HostIoError::Denied { ref reason }) if reason.starts_with("flow_policy:")));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
            let clean = HostIoRequest::NetworkSend {
                endpoint: "allowed.example:443".into(), payload: STANDARD.encode(b"harmless public message").into_bytes(),
            };
            assert!(matches!(gate.perform(&clean, &[HostIoCapability::NetworkSend]), Err(HostIoError::Io { .. })));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(gate.secrets.lock().unwrap().samples.len(), 1);
        }
    }
}
