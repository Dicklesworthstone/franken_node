//! Bounded cancellation frames for an authenticated native-session control stream.
//!
//! The existing launch handshake authenticates the stream. A frame only requests
//! cooperative cancellation of that launch; it does not acknowledge worker exit,
//! effect completion, or quiescence. Repeated matching requests are idempotent.
//! Callers retain their existing fail-closed behavior on EOF or protocol failure
//! and impose their own I/O deadlines. Neither function reads beyond one frame.

use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"FNCTRL\0\0";
const VERSION: u8 = 1;
const CANCEL: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 2;
const FRAME_LEN: usize = HEADER_LEN + 16;

fn session_uuid(nonce: &str) -> io::Result<uuid::Uuid> {
    uuid::Uuid::parse_str(nonce).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "native-session control nonce is not a UUID",
        )
    })
}

/// Write and flush one cancellation request without allocating a payload buffer.
/// The nonce must be the UUID established by the authenticated launch handshake.
pub(crate) fn write_cancel_request(writer: &mut impl Write, nonce: &str) -> io::Result<()> {
    let nonce = session_uuid(nonce)?;
    let mut frame = [0_u8; FRAME_LEN];
    frame[..MAGIC.len()].copy_from_slice(MAGIC);
    frame[MAGIC.len()] = VERSION;
    frame[MAGIC.len() + 1] = CANCEL;
    frame[HEADER_LEN..].copy_from_slice(nonce.as_bytes());
    writer.write_all(&frame)?;
    writer.flush()
}

/// Read exactly one cancellation request for the authenticated launch UUID.
/// EOF, a truncated frame, an unknown protocol, or a different session is an error.
pub(crate) fn read_cancel_request(reader: &mut impl Read, expected_nonce: &str) -> io::Result<()> {
    let nonce = session_uuid(expected_nonce)?;
    let mut frame = [0_u8; FRAME_LEN];
    reader.read_exact(&mut frame)?;
    if &frame[..MAGIC.len()] != MAGIC
        || frame[MAGIC.len()] != VERSION
        || frame[MAGIC.len() + 1] != CANCEL
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native-session control frame",
        ));
    }
    if &frame[HEADER_LEN..] != nonce.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native-session control frame belongs to a different launch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, ErrorKind};

    const NONCE: &str = "018f2c91-5eba-7a91-8150-f756af5ae782";
    const OTHER_NONCE: &str = "018f2c91-5eba-7a91-8150-f756af5ae783";

    fn frame() -> Vec<u8> {
        let mut bytes = Vec::new();
        write_cancel_request(&mut bytes, NONCE).unwrap();
        bytes
    }

    #[test]
    fn wire_format_is_fixed_and_versioned() {
        assert_eq!(
            frame(),
            b"FNCTRL\0\0\x01\x01\x01\x8f\x2c\x91\x5e\xba\x7a\x91\x81\x50\xf7\x56\xaf\x5a\xe7\x82"
        );
    }

    #[test]
    fn round_trip_consumes_exactly_one_frame() {
        let mut bytes = frame();
        bytes.extend_from_slice(b"next message");
        let mut reader = Cursor::new(bytes);
        read_cancel_request(&mut reader, NONCE).unwrap();
        assert_eq!(reader.position(), 26);
        let mut remainder = String::new();
        reader.read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, "next message");
    }

    #[test]
    fn repeated_matching_requests_are_accepted_individually() {
        let mut bytes = frame();
        bytes.extend_from_slice(&frame());
        let mut reader = Cursor::new(bytes);
        read_cancel_request(&mut reader, NONCE).unwrap();
        assert_eq!(reader.position(), 26);
        read_cancel_request(&mut reader, NONCE).unwrap();
        assert_eq!(reader.position(), 52);
        assert_eq!(
            read_cancel_request(&mut reader, NONCE).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn every_truncated_frame_is_rejected() {
        let bytes = frame();
        for end in 0..bytes.len() {
            assert_eq!(
                read_cancel_request(&mut &bytes[..end], NONCE)
                    .unwrap_err()
                    .kind(),
                ErrorKind::UnexpectedEof,
                "truncation at byte {end}"
            );
        }
    }

    #[test]
    fn malformed_magic_version_and_opcode_are_rejected() {
        for index in 0..HEADER_LEN {
            let mut bytes = frame();
            bytes[index] ^= 0xff;
            assert_eq!(
                read_cancel_request(&mut bytes.as_slice(), NONCE)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData,
                "malformed header byte {index}"
            );
        }
    }

    #[test]
    fn a_request_for_another_launch_is_rejected() {
        assert_eq!(
            read_cancel_request(&mut frame().as_slice(), OTHER_NONCE)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
        for index in HEADER_LEN..FRAME_LEN {
            let mut bytes = frame();
            bytes[index] ^= 1;
            assert_eq!(
                read_cancel_request(&mut bytes.as_slice(), NONCE)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData,
                "changed nonce byte {index}"
            );
        }
    }

    #[test]
    fn invalid_local_nonce_does_not_touch_the_stream() {
        for invalid in ["", "not-a-uuid", "018f2c91-5eba-7a91-8150-f756af5ae78z"] {
            let mut writer = Vec::new();
            assert_eq!(
                write_cancel_request(&mut writer, invalid)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            assert!(writer.is_empty());
            let mut reader = Cursor::new(frame());
            assert_eq!(
                read_cancel_request(&mut reader, invalid)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            assert_eq!(reader.position(), 0);
        }
    }

    struct Fragmented<T> {
        inner: T,
        interrupt_next: bool,
        flushes: usize,
    }

    impl<T: Read> Read for Fragmented<T> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.interrupt_next = !self.interrupt_next;
            if self.interrupt_next {
                return Err(ErrorKind::Interrupted.into());
            }
            let length = bytes.len().min(1);
            self.inner.read(&mut bytes[..length])
        }
    }

    impl<T: Write> Write for Fragmented<T> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.interrupt_next = !self.interrupt_next;
            if self.interrupt_next {
                return Err(ErrorKind::Interrupted.into());
            }
            self.inner.write(&bytes[..bytes.len().min(2)])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            self.inner.flush()
        }
    }

    #[test]
    fn interrupted_and_short_reads_and_writes_complete_one_frame() {
        let mut writer = Fragmented {
            inner: Vec::new(),
            interrupt_next: false,
            flushes: 0,
        };
        write_cancel_request(&mut writer, NONCE).unwrap();
        assert_eq!(writer.inner, frame());
        assert_eq!(writer.flushes, 1);
        let mut reader = Fragmented {
            inner: Cursor::new(writer.inner),
            interrupt_next: false,
            flushes: 0,
        };
        read_cancel_request(&mut reader, NONCE).unwrap();
        assert_eq!(reader.inner.position(), 26);
    }

    #[test]
    fn stalled_writer_is_not_reported_as_a_delivered_request() {
        let mut storage = [0_u8; FRAME_LEN - 1];
        assert_eq!(
            write_cancel_request(&mut storage.as_mut_slice(), NONCE)
                .unwrap_err()
                .kind(),
            ErrorKind::WriteZero
        );
    }

    #[test]
    fn flush_failure_is_propagated() {
        struct FlushFailure(Vec<u8>);
        impl Write for FlushFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(ErrorKind::BrokenPipe.into())
            }
        }
        let mut writer = FlushFailure(Vec::new());
        assert_eq!(
            write_cancel_request(&mut writer, NONCE).unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
        assert_eq!(writer.0, frame());
    }

    #[cfg(unix)]
    #[test]
    fn unix_stream_accepts_fragmented_request_then_reports_parent_eof() {
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let (mut parent, mut worker) = UnixStream::pair().unwrap();
        parent
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        worker
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let sender = std::thread::spawn(move || {
            for fragment in frame().chunks(3) {
                parent.write_all(fragment).unwrap();
            }
            parent.shutdown(Shutdown::Write).unwrap();
        });
        read_cancel_request(&mut worker, NONCE).unwrap();
        assert_eq!(
            read_cancel_request(&mut worker, NONCE).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
        sender.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_stream_parent_eof_never_becomes_a_cancellation_frame() {
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        for prefix in [0, 1, HEADER_LEN, FRAME_LEN - 1] {
            let (mut parent, mut worker) = UnixStream::pair().unwrap();
            worker
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            parent.write_all(&frame()[..prefix]).unwrap();
            parent.shutdown(Shutdown::Write).unwrap();
            assert_eq!(
                read_cancel_request(&mut worker, NONCE).unwrap_err().kind(),
                ErrorKind::UnexpectedEof,
                "parent closed after {prefix} bytes"
            );
        }
    }
}
