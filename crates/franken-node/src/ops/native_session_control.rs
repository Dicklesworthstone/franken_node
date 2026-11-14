//! Bounded frames for an authenticated native-session control stream.
//!
//! The existing launch handshake authenticates the stream. Cancellation requests
//! do not acknowledge worker exit, effect completion, or quiescence. A durable
//! admission acknowledgment permits only its exact pending host-effect request;
//! the parent must persist that admission before sending it. Neither frame proves
//! that a provider ran or that its externally visible effect committed.
//! Callers retain their existing fail-closed behavior on EOF or protocol failure
//! and impose their own I/O deadlines. Decoding never reads beyond one frame.

use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

const MAGIC: &[u8; 8] = b"FNCTRL\0\0";
const VERSION: u8 = 1;
const CANCEL: u8 = 1;
const DURABLE_EFFECT_ADMITTED: u8 = 2;
const HEADER_LEN: usize = MAGIC.len() + 2;
const FRAME_LEN: usize = HEADER_LEN + 16;
const EFFECT_ADMISSION_ACK_FRAME_LEN: usize = FRAME_LEN + 8 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeSessionControlFrame {
    Cancel,
    DurableEffectAdmitted {
        sequence: u64,
        request_hash: [u8; 32],
    },
}

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

/// Acknowledge one durably retained admission on the authenticated control stream.
/// The parent must finish persisting the matching admission before calling this.
pub(crate) fn write_effect_admission_ack(
    writer: &mut impl Write,
    nonce: &str,
    sequence: u64,
    request_hash: [u8; 32],
) -> io::Result<()> {
    let nonce = session_uuid(nonce)?;
    let mut frame = [0_u8; EFFECT_ADMISSION_ACK_FRAME_LEN];
    frame[..MAGIC.len()].copy_from_slice(MAGIC);
    frame[MAGIC.len()] = VERSION;
    frame[MAGIC.len() + 1] = DURABLE_EFFECT_ADMITTED;
    frame[HEADER_LEN..FRAME_LEN].copy_from_slice(nonce.as_bytes());
    frame[FRAME_LEN..FRAME_LEN + 8].copy_from_slice(&sequence.to_le_bytes());
    frame[FRAME_LEN + 8..].copy_from_slice(&request_hash);
    writer.write_all(&frame)?;
    writer.flush()
}

/// Read one bounded control frame for the authenticated launch UUID.
/// EOF, truncation, an unknown protocol, or a different launch is an error.
pub(crate) fn read_control_frame(
    reader: &mut impl Read,
    expected_nonce: &str,
) -> io::Result<NativeSessionControlFrame> {
    let nonce = session_uuid(expected_nonce)?;
    let mut frame = [0_u8; FRAME_LEN];
    reader.read_exact(&mut frame)?;
    if &frame[..MAGIC.len()] != MAGIC || frame[MAGIC.len()] != VERSION {
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
    match frame[MAGIC.len() + 1] {
        CANCEL => Ok(NativeSessionControlFrame::Cancel),
        DURABLE_EFFECT_ADMITTED => {
            let mut sequence = [0_u8; 8];
            let mut request_hash = [0_u8; 32];
            reader.read_exact(&mut sequence)?;
            reader.read_exact(&mut request_hash)?;
            Ok(NativeSessionControlFrame::DurableEffectAdmitted {
                sequence: u64::from_le_bytes(sequence),
                request_hash,
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native-session control opcode",
        )),
    }
}

/// Read one cancellation request, rejecting effect acknowledgments as well as
/// malformed frames. Replay workers that cannot issue live effects use this
/// narrower interface. A repeated matching cancellation remains idempotent.
pub(crate) fn read_cancel_request(reader: &mut impl Read, expected_nonce: &str) -> io::Result<()> {
    match read_control_frame(reader, expected_nonce)? {
        NativeSessionControlFrame::Cancel => Ok(()),
        NativeSessionControlFrame::DurableEffectAdmitted { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected effect acknowledgment on cancellation-only control stream",
        )),
    }
}

#[derive(Debug, Clone, Copy)]
enum AdmissionGateFailure {
    Cancelled,
    Failed,
}

impl AdmissionGateFailure {
    fn error(self) -> io::Error {
        match self {
            Self::Cancelled => io::Error::new(
                io::ErrorKind::Interrupted,
                "native effect admission was cancelled",
            ),
            Self::Failed => io::Error::new(
                io::ErrorKind::BrokenPipe,
                "native effect admission acknowledgment gate failed",
            ),
        }
    }
}

#[derive(Debug)]
struct PendingEffectAdmission {
    sequence: u64,
    request_hash: [u8; 32],
    acknowledged: bool,
    waiting: bool,
}

#[derive(Debug)]
struct EffectAdmissionState {
    next_sequence: u64,
    pending: Option<PendingEffectAdmission>,
    failure: Option<AdmissionGateFailure>,
}

#[derive(Debug)]
struct EffectAdmissionShared {
    state: Mutex<EffectAdmissionState>,
    changed: Condvar,
}

/// The worker's one-shot permission gate for each live provider call.
///
/// Register `begin` before writing the admission frame, then `wait` only after
/// the frame flushes. The authenticated control reader supplies `acknowledge`.
/// Cancellation, control EOF, and protocol failures must call `cancel` or `fail`
/// so a provider cannot proceed from a buffered acknowledgment after shutdown.
/// This object has no mode that permits effects without an acknowledgment.
#[derive(Debug, Clone)]
pub(crate) struct NativeEffectAdmissionAcks {
    shared: Arc<EffectAdmissionShared>,
}

impl NativeEffectAdmissionAcks {
    pub(crate) fn new() -> Self {
        Self {
            shared: Arc::new(EffectAdmissionShared {
                state: Mutex::new(EffectAdmissionState {
                    next_sequence: 0,
                    pending: None,
                    failure: None,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    fn lock_state(&self) -> io::Result<MutexGuard<'_, EffectAdmissionState>> {
        match self.shared.state.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.failure = Some(AdmissionGateFailure::Failed);
                self.shared.changed.notify_all();
                Err(AdmissionGateFailure::Failed.error())
            }
        }
    }

    fn reject(&self, state: &mut EffectAdmissionState, message: &'static str) -> io::Error {
        state.failure = Some(AdmissionGateFailure::Failed);
        self.shared.changed.notify_all();
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    pub(crate) fn begin(&self, sequence: u64, request_hash: [u8; 32]) -> io::Result<()> {
        let mut state = self.lock_state()?;
        if let Some(failure) = state.failure {
            return Err(failure.error());
        }
        if state.pending.is_some()
            || sequence != state.next_sequence
            || sequence.checked_add(1).is_none()
        {
            return Err(self.reject(
                &mut state,
                "native effect admission is overlapping or out of sequence",
            ));
        }
        state.pending = Some(PendingEffectAdmission {
            sequence,
            request_hash,
            acknowledged: false,
            waiting: false,
        });
        Ok(())
    }

    pub(crate) fn acknowledge(&self, sequence: u64, request_hash: [u8; 32]) -> io::Result<()> {
        let mut state = self.lock_state()?;
        if let Some(failure) = state.failure {
            return Err(failure.error());
        }
        match state.pending.as_mut() {
            Some(pending)
                if pending.sequence == sequence
                    && pending.request_hash == request_hash
                    && !pending.acknowledged =>
            {
                pending.acknowledged = true;
                self.shared.changed.notify_all();
                Ok(())
            }
            _ => Err(self.reject(
                &mut state,
                "native effect acknowledgment is unexpected, duplicated, or mismatched",
            )),
        }
    }

    pub(crate) fn wait(&self, sequence: u64, request_hash: [u8; 32]) -> io::Result<()> {
        let mut state = self.lock_state()?;
        if let Some(failure) = state.failure {
            return Err(failure.error());
        }
        match state.pending.as_mut() {
            Some(pending)
                if pending.sequence == sequence
                    && pending.request_hash == request_hash
                    && !pending.waiting =>
            {
                pending.waiting = true;
            }
            _ => {
                return Err(self.reject(
                    &mut state,
                    "native effect acknowledgment wait is unexpected or mismatched",
                ));
            }
        }
        loop {
            if let Some(failure) = state.failure {
                return Err(failure.error());
            }
            if state.pending.as_ref().is_some_and(|pending| {
                pending.sequence == sequence
                    && pending.request_hash == request_hash
                    && pending.acknowledged
            }) {
                let Some(next_sequence) = sequence.checked_add(1) else {
                    return Err(self.reject(
                        &mut state,
                        "native effect acknowledgment sequence overflowed",
                    ));
                };
                state.pending = None;
                state.next_sequence = next_sequence;
                return Ok(());
            }
            state = match self.shared.changed.wait(state) {
                Ok(state) => state,
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    state.failure = Some(AdmissionGateFailure::Failed);
                    self.shared.changed.notify_all();
                    return Err(AdmissionGateFailure::Failed.error());
                }
            };
        }
    }

    fn close(&self, failure: AdmissionGateFailure) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.failure.is_none() {
            state.failure = Some(failure);
        }
        self.shared.changed.notify_all();
    }

    pub(crate) fn cancel(&self) {
        self.close(AdmissionGateFailure::Cancelled);
    }

    pub(crate) fn fail(&self) {
        self.close(AdmissionGateFailure::Failed);
    }
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

    const REQUEST_HASH: [u8; 32] = [0x5a; 32];

    fn acknowledgment_frame(sequence: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_effect_admission_ack(&mut bytes, NONCE, sequence, REQUEST_HASH).unwrap();
        bytes
    }

    #[test]
    fn effect_acknowledgment_wire_format_is_fixed_and_binds_request() {
        let bytes = acknowledgment_frame(0x0102_0304_0506_0708);
        let mut expected =
            b"FNCTRL\0\0\x01\x02\x01\x8f\x2c\x91\x5e\xba\x7a\x91\x81\x50\xf7\x56\xaf\x5a\xe7\x82"
                .to_vec();
        expected.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        expected.extend_from_slice(&[0x5a; 32]);
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 66);
        assert_eq!(
            read_control_frame(&mut bytes.as_slice(), NONCE).unwrap(),
            NativeSessionControlFrame::DurableEffectAdmitted {
                sequence: 0x0102_0304_0506_0708,
                request_hash: REQUEST_HASH,
            }
        );
    }

    #[test]
    fn mixed_control_frames_consume_only_their_own_bytes() {
        let mut bytes = acknowledgment_frame(0);
        bytes.extend_from_slice(&frame());
        bytes.extend_from_slice(b"next message");
        let mut reader = Cursor::new(bytes);
        assert!(matches!(
            read_control_frame(&mut reader, NONCE).unwrap(),
            NativeSessionControlFrame::DurableEffectAdmitted { sequence: 0, .. }
        ));
        assert_eq!(reader.position(), 66);
        assert_eq!(
            read_control_frame(&mut reader, NONCE).unwrap(),
            NativeSessionControlFrame::Cancel
        );
        assert_eq!(reader.position(), 92);
        let mut remainder = String::new();
        reader.read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, "next message");
        assert_eq!(
            read_cancel_request(&mut acknowledgment_frame(0).as_slice(), NONCE)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn effect_acknowledgment_rejects_every_truncation_and_foreign_launch() {
        let bytes = acknowledgment_frame(0);
        for end in 0..bytes.len() {
            assert_eq!(
                read_control_frame(&mut &bytes[..end], NONCE)
                    .unwrap_err()
                    .kind(),
                ErrorKind::UnexpectedEof,
                "acknowledgment truncated at byte {end}"
            );
        }
        assert_eq!(
            read_control_frame(&mut bytes.as_slice(), OTHER_NONCE)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
        for index in 0..FRAME_LEN {
            let mut invalid = bytes.clone();
            invalid[index] ^= 0xff;
            assert_eq!(
                read_control_frame(&mut invalid.as_slice(), NONCE)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData,
                "invalid acknowledgment binding byte {index}"
            );
        }
    }

    #[test]
    fn effect_acknowledgment_handles_short_io_and_propagates_write_failures() {
        let mut writer = Fragmented {
            inner: Vec::new(),
            interrupt_next: false,
            flushes: 0,
        };
        write_effect_admission_ack(&mut writer, NONCE, 0, REQUEST_HASH).unwrap();
        assert_eq!(writer.inner, acknowledgment_frame(0));
        assert_eq!(writer.flushes, 1);
        let mut reader = Fragmented {
            inner: Cursor::new(writer.inner),
            interrupt_next: false,
            flushes: 0,
        };
        assert_eq!(
            read_control_frame(&mut reader, NONCE).unwrap(),
            NativeSessionControlFrame::DurableEffectAdmitted {
                sequence: 0,
                request_hash: REQUEST_HASH,
            }
        );
        assert_eq!(reader.inner.position(), 66);

        let mut short = [0_u8; EFFECT_ADMISSION_ACK_FRAME_LEN - 1];
        assert_eq!(
            write_effect_admission_ack(&mut short.as_mut_slice(), NONCE, 0, REQUEST_HASH)
                .unwrap_err()
                .kind(),
            ErrorKind::WriteZero
        );
        struct FlushFailure;
        impl Write for FlushFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(
            write_effect_admission_ack(&mut FlushFailure, NONCE, 0, REQUEST_HASH)
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
        let mut untouched = Vec::new();
        assert_eq!(
            write_effect_admission_ack(&mut untouched, "invalid", 0, REQUEST_HASH)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        assert!(untouched.is_empty());
    }

    fn assert_gate_closed(gate: &NativeEffectAdmissionAcks) {
        assert!(gate.begin(0, REQUEST_HASH).is_err());
        assert!(gate.acknowledge(0, REQUEST_HASH).is_err());
        assert!(gate.wait(0, REQUEST_HASH).is_err());
    }

    #[test]
    fn admission_gate_blocks_provider_until_exact_acknowledgment() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        let gate = NativeEffectAdmissionAcks::new();
        gate.begin(0, REQUEST_HASH).unwrap();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&provider_calls);
        let waiter = gate.clone();
        let (sent, received) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = waiter.wait(0, REQUEST_HASH);
            if result.is_ok() {
                calls.fetch_add(1, Ordering::SeqCst);
            }
            sent.send(result).unwrap();
        });
        // An unrelated wakeup must not manufacture permission.
        gate.shared.changed.notify_all();
        let before_ack = received.recv_timeout(Duration::from_millis(30));
        let calls_before_ack = provider_calls.load(Ordering::SeqCst);
        gate.acknowledge(0, REQUEST_HASH).unwrap();
        received
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(matches!(before_ack, Err(RecvTimeoutError::Timeout)));
        assert_eq!(calls_before_ack, 0);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        gate.begin(1, [0x6b; 32]).unwrap();
        gate.acknowledge(1, [0x6b; 32]).unwrap();
        gate.wait(1, [0x6b; 32]).unwrap();
        assert!(gate.wait(1, [0x6b; 32]).is_err());
        assert_gate_closed(&gate);
    }

    #[test]
    fn admission_gate_poisoned_by_unexpected_duplicate_stale_or_mismatched_ack() {
        let gate = NativeEffectAdmissionAcks::new();
        assert!(gate.acknowledge(0, REQUEST_HASH).is_err());
        assert_gate_closed(&gate);

        for (sequence, hash) in [(1, REQUEST_HASH), (0, [0x6b; 32])] {
            let gate = NativeEffectAdmissionAcks::new();
            gate.begin(0, REQUEST_HASH).unwrap();
            assert!(gate.acknowledge(sequence, hash).is_err());
            assert_gate_closed(&gate);
        }

        let gate = NativeEffectAdmissionAcks::new();
        gate.begin(0, REQUEST_HASH).unwrap();
        gate.acknowledge(0, REQUEST_HASH).unwrap();
        assert!(gate.acknowledge(0, REQUEST_HASH).is_err());
        assert_gate_closed(&gate);

        let gate = NativeEffectAdmissionAcks::new();
        gate.begin(0, REQUEST_HASH).unwrap();
        gate.acknowledge(0, REQUEST_HASH).unwrap();
        gate.wait(0, REQUEST_HASH).unwrap();
        gate.begin(1, REQUEST_HASH).unwrap();
        assert!(gate.acknowledge(0, REQUEST_HASH).is_err());
        assert_gate_closed(&gate);
    }

    #[test]
    fn admission_gate_rejects_overlapping_skipped_reused_and_wrong_waits() {
        for invalid_first in [1, u64::MAX] {
            let gate = NativeEffectAdmissionAcks::new();
            assert!(gate.begin(invalid_first, REQUEST_HASH).is_err());
            assert_gate_closed(&gate);
        }
        for duplicate in [0, 1] {
            let gate = NativeEffectAdmissionAcks::new();
            gate.begin(0, REQUEST_HASH).unwrap();
            assert!(gate.begin(duplicate, REQUEST_HASH).is_err());
            assert_gate_closed(&gate);
        }
        let gate = NativeEffectAdmissionAcks::new();
        gate.begin(0, REQUEST_HASH).unwrap();
        gate.acknowledge(0, REQUEST_HASH).unwrap();
        gate.wait(0, REQUEST_HASH).unwrap();
        assert!(gate.begin(0, REQUEST_HASH).is_err());
        assert_gate_closed(&gate);

        for (sequence, hash) in [(1, REQUEST_HASH), (0, [0x6b; 32])] {
            let gate = NativeEffectAdmissionAcks::new();
            gate.begin(0, REQUEST_HASH).unwrap();
            gate.acknowledge(0, REQUEST_HASH).unwrap();
            assert!(gate.wait(sequence, hash).is_err());
            assert_gate_closed(&gate);
        }
        let gate = NativeEffectAdmissionAcks::new();
        assert!(gate.wait(0, REQUEST_HASH).is_err());
        assert_gate_closed(&gate);
    }

    #[test]
    fn admission_gate_cancellation_or_failure_overrides_a_buffered_ack() {
        for cancel in [false, true] {
            let gate = NativeEffectAdmissionAcks::new();
            gate.begin(0, REQUEST_HASH).unwrap();
            gate.acknowledge(0, REQUEST_HASH).unwrap();
            if cancel {
                gate.cancel();
            } else {
                gate.fail();
            }
            assert_eq!(
                gate.wait(0, REQUEST_HASH).unwrap_err().kind(),
                if cancel {
                    ErrorKind::Interrupted
                } else {
                    ErrorKind::BrokenPipe
                }
            );
            assert_gate_closed(&gate);
        }
    }

    #[test]
    fn admission_gate_cancellation_and_failure_wake_blocked_provider() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        for cancel in [false, true] {
            let gate = NativeEffectAdmissionAcks::new();
            gate.begin(0, REQUEST_HASH).unwrap();
            let waiter = gate.clone();
            let (sent, received) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                sent.send(waiter.wait(0, REQUEST_HASH)).unwrap();
            });
            let before_close = received.recv_timeout(Duration::from_millis(30));
            if cancel {
                gate.cancel();
            } else {
                gate.fail();
            }
            let error = received
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap_err();
            worker.join().unwrap();
            assert!(matches!(before_close, Err(RecvTimeoutError::Timeout)));
            assert_eq!(
                error.kind(),
                if cancel {
                    ErrorKind::Interrupted
                } else {
                    ErrorKind::BrokenPipe
                }
            );
            assert_gate_closed(&gate);
        }
    }

    #[test]
    fn admission_gate_protocol_errors_wake_waiters_without_permission() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        for wrong_sequence in [false, true] {
            let gate = NativeEffectAdmissionAcks::new();
            gate.begin(0, REQUEST_HASH).unwrap();
            let waiter = gate.clone();
            let (sent, received) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                sent.send(waiter.wait(0, REQUEST_HASH)).unwrap();
            });
            let before_error = received.recv_timeout(Duration::from_millis(30));
            let result = if wrong_sequence {
                gate.acknowledge(1, REQUEST_HASH)
            } else {
                gate.acknowledge(0, [0x6b; 32])
            };
            let permission = received.recv_timeout(Duration::from_secs(5)).unwrap();
            worker.join().unwrap();
            assert!(matches!(before_error, Err(RecvTimeoutError::Timeout)));
            assert!(result.is_err());
            assert!(permission.is_err());
            assert_gate_closed(&gate);
        }
    }

    #[test]
    fn admission_gate_concurrent_duplicate_waiters_cannot_share_permission() {
        use std::sync::{Barrier, mpsc};
        use std::time::Duration;

        let gate = NativeEffectAdmissionAcks::new();
        gate.begin(0, REQUEST_HASH).unwrap();
        let start = Arc::new(Barrier::new(3));
        let (sent, received) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let waiter = gate.clone();
            let start = Arc::clone(&start);
            let sent = sent.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                sent.send(waiter.wait(0, REQUEST_HASH)).unwrap();
            }));
        }
        start.wait();
        for _ in 0..2 {
            assert!(
                received
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .is_err()
            );
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_gate_closed(&gate);
    }

    #[cfg(unix)]
    #[test]
    fn parent_eof_or_truncated_ack_wakes_gate_without_provider_permission() {
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::sync::mpsc;
        use std::time::Duration;

        for prefix in [0, FRAME_LEN, EFFECT_ADMISSION_ACK_FRAME_LEN - 1] {
            let (mut parent, mut control) = UnixStream::pair().unwrap();
            control
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let gate = NativeEffectAdmissionAcks::new();
            gate.begin(0, REQUEST_HASH).unwrap();
            let reader_gate = gate.clone();
            let reader = std::thread::spawn(move || {
                let error = read_control_frame(&mut control, NONCE).unwrap_err();
                reader_gate.fail();
                error.kind()
            });
            let waiter = gate.clone();
            let (sent, received) = mpsc::channel();
            let provider = std::thread::spawn(move || {
                sent.send(waiter.wait(0, REQUEST_HASH)).unwrap();
            });
            parent
                .write_all(&acknowledgment_frame(0)[..prefix])
                .unwrap();
            parent.shutdown(Shutdown::Write).unwrap();
            assert!(
                received
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .is_err()
            );
            assert_eq!(reader.join().unwrap(), ErrorKind::UnexpectedEof);
            provider.join().unwrap();
            assert_gate_closed(&gate);
        }
    }
}
