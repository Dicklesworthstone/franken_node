//! One bounded HTTP exchange after the product's durable RemoteCap admission.
//!
//! This module prepares immutable request bytes and the existing native network
//! provider before a caller consumes a capability. It grants no RemoteCap by
//! itself: the CLI must durably record admission and authorize the exact
//! `endpoint()` immediately before calling `execute`. DNS, address pinning, TLS,
//! HTTP framing and the socket deadline use the same engine mechanism as native
//! guest egress. Product SSRF policy remains in `SsrfGatedHostIo`.
//!
//! A complete HTTP response establishes an observed response, not remote
//! application commit or an exactly-once guarantee. Every error after dispatch
//! remains indeterminate. No redirect, proxy, cookie jar, authentication header,
//! application retry or response decompression is introduced here.

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoProvider, HostIoRequest, HostIoResponse, SandboxedHostIo,
    parse_http_response,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

use crate::config::NetworkPolicyConfig;
use crate::ops::ssrf_gated_host_io::SsrfGatedHostIo;

pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_RESPONSE_WIRE_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_URL_BYTES: usize = 4096;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_ERROR_CHARS: usize = 512;

/// Public commitment to the exact prepared request. Body bytes are deliberately
/// omitted; their length and digest are retained in the signed invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCapHttpRequestSummary {
    pub method: String,
    pub endpoint: String,
    pub content_type: Option<String>,
    pub request_sha256: String,
    pub request_body_sha256: String,
    pub request_body_bytes: u64,
    pub timeout_ms: u64,
    pub response_wire_limit_bytes: u64,
}

/// Request bytes cannot be changed after validation or accidentally logged by
/// `Debug`. The whole HTTP exchange is bound to one transport preparation.
pub struct PreparedRemoteCapHttpRequest {
    summary: RemoteCapHttpRequestSummary,
    request: HostIoRequest,
}

impl std::fmt::Debug for PreparedRemoteCapHttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRemoteCapHttpRequest")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl PreparedRemoteCapHttpRequest {
    /// Prepare a single origin-form HTTP/1.1 exchange. GET and HEAD have no
    /// body. The fixed headers are the complete outgoing header inventory.
    pub fn new(
        method: &str,
        endpoint: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
        timeout_ms: u64,
        response_wire_limit_bytes: u64,
    ) -> Result<Self> {
        ensure!(
            matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"),
            "RemoteCap HTTP method must be GET, HEAD, POST, PUT, PATCH or DELETE"
        );
        ensure!(
            body.len() <= MAX_REQUEST_BODY_BYTES,
            "RemoteCap HTTP request body exceeds 1 MiB"
        );
        ensure!(
            !matches!(method, "GET" | "HEAD") || body.is_empty(),
            "RemoteCap HTTP GET and HEAD cannot carry a body"
        );
        ensure!(
            (1..=MAX_TIMEOUT_MS).contains(&timeout_ms),
            "RemoteCap HTTP timeout must be between 1 and 60000 milliseconds"
        );
        ensure!(
            (1..=MAX_RESPONSE_WIRE_BYTES).contains(&response_wire_limit_bytes),
            "RemoteCap HTTP response limit must be between 1 byte and 1 MiB"
        );
        ensure!(
            !endpoint.is_empty()
                && endpoint.len() <= MAX_URL_BYTES
                && endpoint.is_ascii()
                && !endpoint
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
                && !endpoint.contains(['\\', '#']),
            "RemoteCap HTTP URL must be bounded ASCII without controls, whitespace, backslashes or fragments"
        );
        let url = url::Url::parse(endpoint).context("invalid RemoteCap HTTP URL")?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && !url.cannot_be_a_base()
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "RemoteCap HTTP URL requires HTTP(S), a host and no credentials or fragment"
        );
        // Do not let URL parser normalization select a different resource than
        // the one a human/token scope names. A missing empty-path slash is the
        // sole accepted normalization and is exposed by endpoint() for gating.
        let canonical = url.as_str();
        ensure!(
            canonical == endpoint
                || (url.path() == "/"
                    && url.query().is_none()
                    && canonical.strip_suffix('/') == Some(endpoint)),
            "RemoteCap HTTP URL must use canonical spelling; path normalization is not authorized"
        );
        ensure!(
            unambiguous_encoded_path(url.path()),
            "RemoteCap HTTP path contains malformed escapes or encoded routing delimiters"
        );
        let port = url
            .port_or_known_default()
            .context("RemoteCap HTTP URL has no port")?;
        ensure!(port != 0, "RemoteCap HTTP URL port cannot be zero");
        let host = url.host_str().context("RemoteCap HTTP URL has no host")?;
        ensure!(
            host.len() <= 253 && !host.ends_with('.'),
            "RemoteCap HTTP hostname must be bounded and have no trailing dot"
        );
        // host_str retains brackets for IPv6, exactly as the native endpoint
        // and Host field require. Explicit default ports were refused above.
        let socket_endpoint = format!("{host}:{port}");
        let authority = if url.port().is_some() {
            socket_endpoint.clone()
        } else {
            host.to_string()
        };
        if let Some(content_type) = content_type {
            ensure!(
                !content_type.is_empty()
                    && content_type.len() <= MAX_CONTENT_TYPE_BYTES
                    && content_type == content_type.trim()
                    && content_type
                        .bytes()
                        .all(|byte| (0x20..=0x7e).contains(&byte)),
                "RemoteCap HTTP content type must be a bounded printable header value"
            );
        }
        let target = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        };
        let mut head = format!(
            "{method} {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: franken_node-agent (+https://github.com/Dicklesworthstone/franken_node)\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        if let Some(content_type) = content_type {
            head.push_str("Content-Type: ");
            head.push_str(content_type);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let request_body_sha256 = hex::encode(Sha256::digest(&body));
        let request_body_bytes = u64::try_from(body.len()).context("request length overflow")?;
        let mut payload = head.into_bytes();
        payload.extend_from_slice(&body);
        let summary = RemoteCapHttpRequestSummary {
            method: method.to_string(),
            endpoint: canonical.to_string(),
            content_type: content_type.map(str::to_string),
            request_sha256: hex::encode(Sha256::digest(&payload)),
            request_body_sha256,
            request_body_bytes,
            timeout_ms,
            response_wire_limit_bytes,
        };
        Ok(Self {
            summary,
            request: HostIoRequest::NetworkRequest {
                endpoint: socket_endpoint,
                payload,
                max_len: response_wire_limit_bytes,
                use_tls: url.scheme() == "https",
            },
        })
    }

    #[must_use]
    pub fn summary(&self) -> &RemoteCapHttpRequestSummary {
        &self.summary
    }

    /// Exact normalized URL the capability gate must authorize.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.summary.endpoint
    }
}

/// Capability endpoint scopes are lexical path prefixes. A server decoding an
/// encoded separator, dot segment or percent escape must not reinterpret an
/// authorized prefix as a different route. Query data is not path authority
/// and is deliberately excluded from this check.
fn unambiguous_encoded_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(encoded) = bytes.get(index + 1..index + 3) else {
            return false;
        };
        let high = char::from(encoded[0]).to_digit(16);
        let low = char::from(encoded[1]).to_digit(16);
        let (Some(high), Some(low)) = (high, low) else {
            return false;
        };
        let decoded = high * 16 + low;
        if decoded <= 0x1f
            || decoded == 0x7f
            || matches!(decoded, 0x23 | 0x25 | 0x2e | 0x2f | 0x3f | 0x5c)
        {
            return false;
        }
        index += 3;
    }
    true
}

/// Owned, one-shot native transport, prepared without DNS or network I/O.
pub struct PreparedRemoteCapHttpTransport {
    provider: SsrfGatedHostIo<SandboxedHostIo>,
    request_summary: RemoteCapHttpRequestSummary,
    network_policy_sha256: String,
}

impl PreparedRemoteCapHttpTransport {
    pub fn new(
        project_root: &Path,
        policy: &NetworkPolicyConfig,
        trace_id: &str,
        request: &PreparedRemoteCapHttpRequest,
    ) -> Result<Self> {
        ensure!(
            !trace_id.is_empty()
                && trace_id.len() <= 256
                && !trace_id.chars().any(char::is_control),
            "RemoteCap HTTP trace ID must be bounded and contain no controls"
        );
        let root = project_root
            .canonicalize()
            .context("RemoteCap HTTP project root is unavailable")?;
        ensure!(
            root.is_dir(),
            "RemoteCap HTTP project root is not a directory"
        );
        // The provider's byte cap covers the complete framed outgoing request,
        // while NetworkRequest.max_len separately caps the wire response.
        let HostIoRequest::NetworkRequest { payload, .. } = &request.request else {
            anyhow::bail!("RemoteCap HTTP prepared a non-network request");
        };
        let max_bytes = request
            .summary
            .response_wire_limit_bytes
            .max(u64::try_from(payload.len()).context("request length overflow")?);
        let mut provider = SandboxedHostIo::with_root_and_limits(&root, max_bytes, 0)
            .context("failed preparing RemoteCap HTTP native provider")?
            .with_network_timeout(Duration::from_millis(request.summary.timeout_ms))
            .context("invalid RemoteCap HTTP native timeout")?;
        ensure!(
            provider.root() == root,
            "RemoteCap HTTP project root changed during preparation"
        );
        let mut policy_hash = Sha256::new();
        policy_hash.update(b"franken-node/remotecap-http-network-policy/v1\0");
        let policy_bytes = serde_json::to_vec(policy)?;
        policy_hash.update((policy_bytes.len() as u64).to_le_bytes());
        policy_hash.update(&policy_bytes);
        if let Some(path) = &policy.tls_extra_roots_pem_path {
            // Resolve configured relative anchors within the selected operator
            // project. Invalid/missing roots fail before token consumption.
            let roots_path = root.join(path);
            let roots = crate::bounded_read(&roots_path, 1024 * 1024)
                .context("failed reading RemoteCap HTTP configured TLS roots")?;
            provider = provider
                .with_extra_tls_roots_pem(&roots)
                .context("invalid RemoteCap HTTP configured TLS roots")?;
            policy_hash.update([1]);
            policy_hash.update(Sha256::digest(&roots));
        } else {
            policy_hash.update([0]);
        }
        Ok(Self {
            provider: SsrfGatedHostIo::from_network_policy(provider, policy, trace_id),
            request_summary: request.summary.clone(),
            network_policy_sha256: hex::encode(policy_hash.finalize()),
        })
    }

    #[must_use]
    pub fn network_policy_sha256(&self) -> &str {
        &self.network_policy_sha256
    }

    /// Consume this transport exactly once after durable capability admission.
    /// Complete HTTP error and redirect responses remain observed responses;
    /// they never trigger a second request or establish application success.
    #[must_use]
    pub fn execute(self, request: &PreparedRemoteCapHttpRequest) -> RemoteCapHttpOutcome {
        if self.request_summary != request.summary {
            return RemoteCapHttpOutcome::indeterminate(
                "prepared transport does not match the admitted HTTP request",
            );
        }
        match self
            .provider
            .perform(&request.request, &[HostIoCapability::NetworkSend])
        {
            Ok(HostIoResponse::NetworkRequest { response }) => {
                match observed_response(&response, &request.summary.method) {
                    Ok(outcome) => outcome,
                    Err(error) => RemoteCapHttpOutcome::indeterminate(&error.to_string()),
                }
            }
            Ok(_) => RemoteCapHttpOutcome::indeterminate(
                "native transport returned an incompatible HTTP outcome",
            ),
            Err(error) => RemoteCapHttpOutcome::indeterminate(&error.to_string()),
        }
    }
}

/// Outcome of one admitted HTTP invocation. `ResponseObserved` says nothing
/// about a remote transaction's commit, durable storage, or later effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteCapHttpOutcome {
    ResponseObserved {
        status: u16,
        response_wire_sha256: String,
        response_wire_bytes: u64,
        response_body_sha256: String,
        response_body_bytes: u64,
        body_base64: String,
        redirect_not_followed: bool,
    },
    Indeterminate {
        error: String,
    },
}

impl RemoteCapHttpOutcome {
    fn indeterminate(error: &str) -> Self {
        Self::Indeterminate {
            error: error
                .chars()
                .filter(|character| !character.is_control())
                .take(MAX_ERROR_CHARS)
                .collect(),
        }
    }
}

fn observed_response(response: &[u8], method: &str) -> Result<RemoteCapHttpOutcome> {
    let parsed = parse_http_response(response, method)
        .context("native HTTP response does not have complete framing")?;
    let body = parsed
        .body_bytes()
        .context("native HTTP response body could not be decoded")?;
    Ok(RemoteCapHttpOutcome::ResponseObserved {
        status: parsed.status,
        response_wire_sha256: hex::encode(Sha256::digest(response)),
        response_wire_bytes: response.len() as u64,
        response_body_sha256: hex::encode(Sha256::digest(&body)),
        response_body_bytes: body.len() as u64,
        body_base64: STANDARD.encode(&body),
        redirect_not_followed: (300..400).contains(&parsed.status),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkAllowlistEntry;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn request(method: &str, endpoint: &str, body: &[u8]) -> PreparedRemoteCapHttpRequest {
        PreparedRemoteCapHttpRequest::new(
            method,
            endpoint,
            Some("application/octet-stream"),
            body.to_vec(),
            1000,
            MAX_RESPONSE_WIRE_BYTES,
        )
        .unwrap()
    }

    fn loopback_policy(port: u16) -> NetworkPolicyConfig {
        NetworkPolicyConfig {
            allowlist: vec![NetworkAllowlistEntry {
                host: "127.0.0.1".into(),
                port: Some(port),
                reason: "explicit loopback integration fixture".into(),
            }],
            ..NetworkPolicyConfig::default()
        }
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            if let Some(head_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = std::str::from_utf8(&bytes[..head_end]).unwrap();
                let content_length = head
                    .split("\r\n")
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                if bytes.len() >= head_end + 4 + content_length {
                    return bytes;
                }
            }
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "request ended before its declared body");
            bytes.extend_from_slice(&chunk[..count]);
            assert!(bytes.len() <= MAX_REQUEST_BODY_BYTES + 8192);
        }
    }

    fn accept_bounded(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "HTTP fixture accepted no request"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("HTTP fixture accept failed: {error}"),
            }
        }
    }

    #[test]
    fn http_preparation_rejects_ambiguous_or_unbounded_authority() {
        for endpoint in [
            "file:///etc/passwd",
            "https://user:secret@example.test/",
            "https://example.test/#fragment",
            "https://EXAMPLE.test/",
            "https://example.test:443/",
            "http://127.1/",
            "http://127.0.0.1:0/",
            "https://example.test/parent/../secret",
            "https://example.test/%2e%2e/secret",
            "https://example.test/allowed/%2fsecret",
            "https://example.test/allowed/%5Csecret",
            "https://example.test/allowed/%252e%252e/secret",
            "https://example.test/allowed/%3fquery",
            "https://example.test/allowed/%00suffix",
            "https://example.test/allowed/%",
            "https://example.test/allowed/%zz",
            "https://example.test/\r\nInjected:yes",
            "https://example.test/\\secret",
            "https://example.test./",
        ] {
            assert!(
                PreparedRemoteCapHttpRequest::new("GET", endpoint, None, Vec::new(), 1000, 1024)
                    .is_err(),
                "accepted ambiguous endpoint {endpoint:?}"
            );
        }
        for (method, body, content_type, timeout, response_limit) in [
            ("CONNECT", Vec::new(), None, 1000, 1024),
            ("get", Vec::new(), None, 1000, 1024),
            ("HEAD", vec![1], None, 1000, 1024),
            ("GET", vec![1], None, 1000, 1024),
            (
                "POST",
                vec![0; MAX_REQUEST_BODY_BYTES + 1],
                None,
                1000,
                1024,
            ),
            (
                "POST",
                Vec::new(),
                Some("text/plain\r\nX-Inject:yes"),
                1000,
                1024,
            ),
            ("POST", Vec::new(), None, 0, 1024),
            ("POST", Vec::new(), None, MAX_TIMEOUT_MS + 1, 1024),
            ("POST", Vec::new(), None, 1000, 0),
            ("POST", Vec::new(), None, 1000, MAX_RESPONSE_WIRE_BYTES + 1),
        ] {
            assert!(
                PreparedRemoteCapHttpRequest::new(
                    method,
                    "https://example.test/",
                    content_type,
                    body,
                    timeout,
                    response_limit,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn request_commitment_binds_method_resource_body_and_exact_fixed_headers() {
        let first = request("POST", "https://example.test/api?version=1", b"payload");
        let changed = [
            request("PUT", "https://example.test/api?version=1", b"payload"),
            request("POST", "https://example.test/api?version=2", b"payload"),
            request("POST", "https://example.test/api?version=1", b"changed"),
        ];
        assert!(changed.iter().all(|other| other.summary != first.summary));
        let HostIoRequest::NetworkRequest { payload, .. } = &first.request else {
            panic!("network request");
        };
        assert!(payload.starts_with(b"POST /api?version=1 HTTP/1.1\r\nHost: example.test\r\n"));
        let head = std::str::from_utf8(payload).unwrap();
        assert!(head.contains("Connection: close\r\n"));
        assert!(head.contains("Accept-Encoding: identity\r\n"));
        assert!(head.contains("Content-Length: 7\r\n"));
        assert!(!head.contains("Authorization:"));
        assert!(!head.contains("Cookie:"));
        assert!(!head.contains("Proxy-Authorization:"));
        assert!(!format!("{first:?}").contains("payload"));
        assert_eq!(
            request("GET", "https://example.test", b"").endpoint(),
            "https://example.test/"
        );
        assert_eq!(
            request("GET", "https://example.test/a%20b?value=%2F%252e", b"").endpoint(),
            "https://example.test/a%20b?value=%2F%252e",
            "encoded query values do not change path authority"
        );
        let ipv6 = request("GET", "https://[2001:db8::1]:9443/", b"");
        let HostIoRequest::NetworkRequest {
            endpoint,
            payload,
            use_tls,
            ..
        } = ipv6.request
        else {
            panic!("network request");
        };
        assert_eq!(endpoint, "[2001:db8::1]:9443");
        assert!(use_tls);
        assert!(
            std::str::from_utf8(&payload)
                .unwrap()
                .contains("Host: [2001:db8::1]:9443\r\n")
        );
    }

    #[test]
    fn actual_native_http_exchange_preserves_bytes_and_decodes_chunked_reply() {
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut stream = accept_bounded(&listener);
            let received = read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na\0b\r\n0\r\n\r\n")
                .unwrap();
            received
        });
        let prepared = request(
            "POST",
            &format!("http://{address}/upload?q=1"),
            b"\0\xffdata",
        );
        let transport = PreparedRemoteCapHttpTransport::new(
            root.path(),
            &loopback_policy(address.port()),
            "trace-real-http",
            &prepared,
        )
        .unwrap();
        assert_eq!(transport.network_policy_sha256().len(), 64);
        let outcome = transport.execute(&prepared);
        let received = peer.join().unwrap();
        let HostIoRequest::NetworkRequest { payload, .. } = &prepared.request else {
            panic!("network request");
        };
        assert_eq!(&received, payload);
        let RemoteCapHttpOutcome::ResponseObserved {
            status,
            response_body_sha256,
            response_body_bytes,
            body_base64,
            redirect_not_followed,
            ..
        } = outcome
        else {
            panic!("complete response was not observed: {outcome:?}");
        };
        assert_eq!(status, 201);
        assert_eq!(STANDARD.decode(body_base64).unwrap(), b"a\0b");
        assert_eq!(response_body_bytes, 3);
        assert_eq!(response_body_sha256, hex::encode(Sha256::digest(b"a\0b")));
        assert!(!redirect_not_followed);
    }

    #[test]
    fn native_redirect_is_observed_without_contacting_second_destination() {
        let root = tempfile::tempdir().unwrap();
        let redirect_target = TcpListener::bind("127.0.0.1:0").unwrap();
        redirect_target.set_nonblocking(true).unwrap();
        let target = redirect_target.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut stream = accept_bounded(&listener);
            read_request(&mut stream);
            write!(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target}/second\r\nContent-Length: 0\r\n\r\n").unwrap();
        });
        let prepared = request("POST", &format!("http://{address}/first"), b"body");
        let outcome = PreparedRemoteCapHttpTransport::new(
            root.path(),
            &loopback_policy(address.port()),
            "trace-no-redirect",
            &prepared,
        )
        .unwrap()
        .execute(&prepared);
        peer.join().unwrap();
        assert!(matches!(
            outcome,
            RemoteCapHttpOutcome::ResponseObserved {
                status: 307,
                redirect_not_followed: true,
                ..
            }
        ));
        assert_eq!(
            redirect_target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn private_network_policy_refuses_before_opening_a_socket() {
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let prepared = request(
            "GET",
            &format!("http://{}/", listener.local_addr().unwrap()),
            b"",
        );
        let outcome = PreparedRemoteCapHttpTransport::new(
            root.path(),
            &NetworkPolicyConfig::default(),
            "trace-private-denied",
            &prepared,
        )
        .unwrap()
        .execute(&prepared);
        assert!(
            matches!(outcome, RemoteCapHttpOutcome::Indeterminate { ref error } if error.contains("ssrf"))
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn incomplete_and_oversized_native_replies_remain_indeterminate_without_retry() {
        for (response, limit) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort".as_slice(),
                1024,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n123456".as_slice(),
                40,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let response = response.to_vec();
            let peer = std::thread::spawn(move || {
                let mut stream = accept_bounded(&listener);
                read_request(&mut stream);
                stream.write_all(&response).unwrap();
                drop(stream);
                listener.set_nonblocking(true).unwrap();
                listener
            });
            let prepared = PreparedRemoteCapHttpRequest::new(
                "GET",
                &format!("http://{address}/"),
                None,
                Vec::new(),
                1000,
                limit,
            )
            .unwrap();
            let outcome = PreparedRemoteCapHttpTransport::new(
                root.path(),
                &loopback_policy(address.port()),
                "trace-incomplete",
                &prepared,
            )
            .unwrap()
            .execute(&prepared);
            let listener = peer.join().unwrap();
            assert!(
                matches!(outcome, RemoteCapHttpOutcome::Indeterminate { .. }),
                "{outcome:?}"
            );
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn native_http_deadline_retains_an_incomplete_remote_effect() {
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release, finish) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut stream = accept_bounded(&listener);
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\na")
                .unwrap();
            finish.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        let prepared = PreparedRemoteCapHttpRequest::new(
            "POST",
            &format!("http://{address}/effect"),
            None,
            b"admitted".to_vec(),
            100,
            1024,
        )
        .unwrap();
        let transport = PreparedRemoteCapHttpTransport::new(
            root.path(),
            &loopback_policy(address.port()),
            "trace-timeout",
            &prepared,
        )
        .unwrap();
        let began = std::time::Instant::now();
        let outcome = transport.execute(&prepared);
        release.send(()).unwrap();
        peer.join().unwrap();
        assert!(began.elapsed() < Duration::from_secs(2));
        assert!(
            matches!(outcome, RemoteCapHttpOutcome::Indeterminate { .. }),
            "a partial response cannot certify the remote effect: {outcome:?}"
        );
    }

    #[test]
    fn transport_binds_prepared_request_and_invalid_tls_roots_fail_during_preparation() {
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let first = request("POST", &format!("http://{address}/first"), b"first");
        let second = request("POST", &format!("http://{address}/second"), b"second");
        let policy = loopback_policy(address.port());
        let transport =
            PreparedRemoteCapHttpTransport::new(root.path(), &policy, "trace-bound", &first)
                .unwrap();
        assert!(matches!(
            transport.execute(&second),
            RemoteCapHttpOutcome::Indeterminate { .. }
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let invalid_roots = NetworkPolicyConfig {
            tls_extra_roots_pem_path: Some("missing.pem".into()),
            ..policy
        };
        assert!(
            PreparedRemoteCapHttpTransport::new(root.path(), &invalid_roots, "trace-roots", &first)
                .is_err()
        );
    }

    #[test]
    fn response_decoder_distinguishes_head_errors_and_transfer_from_content_encoding() {
        for (raw, method, status, body) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n".as_slice(),
                "HEAD",
                200,
                b"".as_slice(),
            ),
            (
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nnope".as_slice(),
                "GET",
                403,
                b"nope".as_slice(),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: gzip\r\n\r\nxyz"
                    .as_slice(),
                "GET",
                200,
                b"xyz".as_slice(),
            ),
        ] {
            let RemoteCapHttpOutcome::ResponseObserved {
                status: actual,
                body_base64,
                ..
            } = observed_response(raw, method).unwrap()
            else {
                panic!("complete response");
            };
            assert_eq!(actual, status);
            assert_eq!(STANDARD.decode(body_base64).unwrap(), body);
        }
    }
}
