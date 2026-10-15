//! Allocation-free decoded views of outbound bytes for the live flow gate.
//!
//! This is detection, not request normalization: the provider always receives
//! the original request. A percent escape is decoded exactly once; '+' is not
//! interpreted as a space. Invalid/incomplete escapes retain their literal
//! bytes. No source bytes, decoded bytes or match positions enter diagnostics.

/// Scan one URI-percent-decoded view against the already compiled raw sample.
/// `failure` is the private KMP table built by `SecretPattern`, not wire data.
pub(super) fn contains(secret: &[u8], failure: &[u32], outbound: &[u8]) -> bool {
    if secret.is_empty() || !outbound.contains(&b'%') {
        return false;
    }
    let mut matcher = Matcher::new(secret, failure);
    PercentDecoded::new(outbound).any(|byte| matcher.push(byte))
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
    use frankenengine_extension_host::host_io::{
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

    #[derive(Debug)]
    struct Probe(Arc<AtomicUsize>);

    impl HostIoProvider for Probe {
        fn name(&self) -> &str { "encoded-egress-probe" }

        fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
            if matches!(request, HostIoRequest::FsRead { .. }) {
                return Ok(HostIoResponse::FsRead { bytes: b"capture secret/one".to_vec() });
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
                HostIoRequest::NetworkSend { endpoint: "capture%20secret%2Fone.example:443".into(), payload: Vec::new() },
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
}
