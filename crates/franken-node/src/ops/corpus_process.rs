//! Linux corpus process capture over the shared production process owner.
//!
//! Hash all observed bytes, retaining only a bounded diagnostic prefix. A
//! timed-out stream is a prefix observation, never evidence of equivalence.
//! Cleanup failures are errors and must abort corpus artifact publication.
//! Process groups do not contain descendants that deliberately escape them.

use crate::migration::smoke_supervisor::{StopReason, Stream, supervise_with_observer};
use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::io;
use std::process::{Command, ExitStatus, Output};
use std::time::{Duration, Instant};

const MAX_RETAINED_BYTES: usize = 1_048_576;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const PROBE_RETAINED_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(super) struct CapturedStream {
    pub(super) retained_bytes: Vec<u8>,
    pub(super) sha256: String,
    pub(super) total_bytes: u64,
    pub(super) capture_truncated: bool,
}

#[derive(Debug)]
pub(super) struct ProcessCapture {
    pub(super) status: ExitStatus,
    pub(super) stdout: CapturedStream,
    pub(super) stderr: CapturedStream,
    pub(super) timed_out: bool,
    pub(super) elapsed_ms: u64,
}

struct Accumulator {
    retained: Vec<u8>,
    hash: Sha256,
    total_bytes: u64,
    limit: usize,
}

impl Accumulator {
    fn new(limit: usize) -> Self {
        Self {
            retained: Vec::new(),
            hash: Sha256::new(),
            total_bytes: 0,
            limit,
        }
    }

    fn receive(&mut self, bytes: &[u8]) -> io::Result<()> {
        let count = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("runtime output length exceeds u64"))?;
        let total = self
            .total_bytes
            .checked_add(count)
            .ok_or_else(|| io::Error::other("runtime output byte count overflowed u64"))?;
        self.hash.update(bytes);
        self.total_bytes = total;
        let keep = bytes
            .len()
            .min(self.limit.saturating_sub(self.retained.len()));
        self.retained.extend_from_slice(&bytes[..keep]);
        Ok(())
    }

    fn finish(self) -> CapturedStream {
        CapturedStream {
            capture_truncated: self.total_bytes > self.retained.len() as u64,
            retained_bytes: self.retained,
            sha256: format!("sha256:{}", hex::encode(self.hash.finalize())),
            total_bytes: self.total_bytes,
        }
    }
}

/// The hook is trusted product code with its own bounded authentication
/// handshake. It receives only the owned child's PID. Its duration consumes
/// the leg deadline; it must not reap the child or change SIGCHLD handling.
pub(super) fn capture(
    command: &mut Command,
    timeout: Duration,
    retained_limit: usize,
    after_spawn: impl FnOnce(u32) -> Result<()>,
) -> Result<ProcessCapture> {
    ensure!(
        retained_limit > 0 && retained_limit <= MAX_RETAINED_BYTES,
        "invalid corpus output retention limit"
    );
    let started = Instant::now();
    let mut stdout = Accumulator::new(retained_limit);
    let mut stderr = Accumulator::new(retained_limit);
    let completion = supervise_with_observer(
        command,
        timeout,
        DRAIN_TIMEOUT,
        after_spawn,
        |stream, bytes| match stream {
            Stream::Stdout => stdout.receive(bytes),
            Stream::Stderr => stderr.receive(bytes),
        },
    );
    let completion = completion.map_err(|error| {
        // Failure diagnostics must not wait for EOF. The supervisor already
        // collected immediately available bytes and terminated the group.
        let diagnostic = sanitize_excerpt(if stderr.retained.is_empty() {
            &stdout.retained
        } else {
            &stderr.retained
        });
        if diagnostic.is_empty() {
            error
        } else {
            error.context(format!("runtime leg diagnostic: {diagnostic}"))
        }
    })?;
    Ok(ProcessCapture {
        status: completion.status,
        timed_out: completion.reason != StopReason::Exited,
        stdout: stdout.finish(),
        stderr: stderr.finish(),
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// Probe version, runtime identity, or workspace initialization without an
/// unbounded Command::output. A partial probe can never establish identity.
pub(super) fn probe(command: &mut Command, timeout: Duration) -> Result<Output> {
    let result = capture(command, timeout, PROBE_RETAINED_BYTES, |_| Ok(()))?;
    if result.timed_out {
        bail!("runtime probe timed out or left output pipes open");
    }
    ensure!(
        !result.stdout.capture_truncated && !result.stderr.capture_truncated,
        "runtime probe output exceeded the capture budget"
    );
    Ok(Output {
        status: result.status,
        stdout: result.stdout.retained_bytes,
        stderr: result.stderr.retained_bytes,
    })
}

fn sanitize_excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    let line = line.split("fix_command=").next().unwrap_or("");
    line.chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::thread;

    fn shell(source: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", source]);
        command
    }

    fn run(source: &str, cap: usize) -> ProcessCapture {
        capture(&mut shell(source), Duration::from_secs(5), cap, |_| Ok(())).unwrap()
    }

    fn assert_stopped(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                Ok(stat)
                    if stat.rsplit_once(") ").is_some_and(|(_, rest)| {
                        rest.starts_with('Z') || rest.starts_with('X')
                    }) =>
                {
                    return;
                }
                _ => {
                    assert!(
                        Instant::now() < deadline,
                        "owned process {pid} still running"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    #[test]
    fn exact_binary_output_and_exit_are_preserved() {
        let result = run("printf 'a\\000b\\377\\n'; printf 'err\\n' >&2; exit 7", 64);
        assert_eq!(result.status.code(), Some(7));
        assert!(!result.timed_out);
        assert_eq!(result.stdout.retained_bytes, [b'a', 0, b'b', 255, b'\n']);
        assert_eq!(result.stderr.retained_bytes, b"err\n");
        assert_eq!(result.stdout.total_bytes, 5);
        assert!(!result.stdout.capture_truncated);
        assert_eq!(
            result.stdout.sha256,
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest([b'a', 0, b'b', 255, b'\n']))
            )
        );
    }

    #[test]
    fn full_hashes_continue_past_bounded_prefixes_on_both_streams() {
        let result = run("head -c 65553 /dev/zero; head -c 70001 /dev/zero >&2", 16);
        assert!(!result.timed_out);
        for (stream, count) in [(&result.stdout, 65553_usize), (&result.stderr, 70001)] {
            assert_eq!(stream.retained_bytes, [0; 16]);
            assert_eq!(stream.total_bytes, count as u64);
            assert!(stream.capture_truncated);
            assert_eq!(
                stream.sha256,
                format!("sha256:{}", hex::encode(Sha256::digest(vec![0; count])))
            );
        }
    }

    #[test]
    fn an_exact_prefix_limit_is_not_truncation() {
        let result = run("printf 1234; printf 5678 >&2", 4);
        assert!(!result.stdout.capture_truncated && !result.stderr.capture_truncated);
        assert_eq!(result.stdout.total_bytes, 4);
        assert_eq!(result.stderr.total_bytes, 4);
    }

    #[test]
    fn equal_prefixes_cannot_hide_different_tails() {
        let first = run("printf abcdX", 4);
        let second = run("printf abcdY", 4);
        assert_eq!(first.stdout.retained_bytes, second.stdout.retained_bytes);
        assert_ne!(first.stdout.sha256, second.stdout.sha256);
        assert!(first.stdout.capture_truncated && second.stdout.capture_truncated);
    }

    #[test]
    fn timeout_retains_partial_measurements_without_claiming_completion() {
        let result = capture(
            &mut shell("printf started; exec /bin/sleep 60"),
            Duration::from_millis(200),
            64,
            |_| Ok(()),
        )
        .unwrap();
        assert!(result.timed_out);
        assert_eq!(result.stdout.retained_bytes, b"started");
        assert_eq!(result.stdout.total_bytes, 7);
        assert!(result.elapsed_ms < 3000);
    }

    #[test]
    fn infinite_output_keeps_memory_bounded_and_cannot_starve_deadline() {
        let result = capture(
            &mut shell("while :; do printf abcdefgh; printf err >&2; done"),
            Duration::from_millis(200),
            64,
            |_| Ok(()),
        )
        .unwrap();
        assert!(result.timed_out);
        assert_eq!(result.stdout.retained_bytes.len(), 64);
        assert_eq!(result.stderr.retained_bytes.len(), 64);
        assert!(result.stdout.total_bytes > 64 && result.stderr.total_bytes > 64);
        assert!(result.elapsed_ms < 3000);
    }

    #[test]
    fn inherited_pipes_are_measured_as_timeout_even_when_leader_exits_zero() {
        let result = run("/bin/sleep 60 & printf '%s' \"$!\"; exit 0", 64);
        assert!(result.timed_out);
        assert_eq!(result.status.code(), Some(0));
        assert!(result.elapsed_ms < 3000);
        assert_stopped(
            std::str::from_utf8(&result.stdout.retained_bytes)
                .unwrap()
                .parse()
                .unwrap(),
        );
    }

    #[test]
    fn successful_leader_cannot_leave_silent_group_members_running() {
        let result = run(
            "/bin/sleep 60 >/dev/null 2>&1 & printf '%s' \"$!\"; exit 0",
            64,
        );
        assert!(!result.timed_out);
        assert!(result.status.success());
        assert_stopped(
            std::str::from_utf8(&result.stdout.retained_bytes)
                .unwrap()
                .parse()
                .unwrap(),
        );
    }

    #[test]
    fn authentication_error_keeps_diagnostics_and_never_joins_an_inherited_pipe() {
        let marker = tempfile::tempdir().unwrap();
        let path = marker.path().join("ready");
        let mut command =
            shell("printf 'auth-error\\n' >&2; /bin/sleep 60 & printf ready > \"$MARKER\"; wait");
        command.env("MARKER", &path);
        let started = Instant::now();
        let mut child = None;
        let error = capture(&mut command, Duration::from_secs(5), 64, |pid| {
            child = Some(pid);
            let deadline = Instant::now() + Duration::from_secs(2);
            while !path.exists() {
                ensure!(Instant::now() < deadline, "child did not start");
                thread::sleep(Duration::from_millis(5));
            }
            bail!("authority rejected");
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("authority rejected"), "{message}");
        assert!(message.contains("auth-error"), "{message}");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_stopped(child.unwrap());
    }

    #[test]
    fn signal_status_is_not_replaced_by_the_cleanup_signal() {
        let result = run("kill -TERM $$", 16);
        assert!(!result.timed_out);
        assert_eq!(result.status.signal(), Some(15));
    }

    #[test]
    fn probes_refuse_hangs_and_oversized_identity_responses() {
        assert!(
            probe(
                &mut shell("printf node; /bin/sleep 60 & exit 0"),
                Duration::from_millis(200)
            )
            .is_err()
        );
        assert!(
            probe(
                &mut shell("head -c 20000 /dev/zero"),
                Duration::from_secs(3)
            )
            .unwrap_err()
            .to_string()
            .contains("capture budget")
        );
        let result = probe(&mut shell("printf v22.1.0"), Duration::from_secs(3)).unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"v22.1.0");
    }

    #[test]
    fn invalid_limits_and_counter_overflow_fail_closed() {
        for cap in [0, MAX_RETAINED_BYTES + 1] {
            assert!(
                capture(
                    &mut Command::new("/missing/runtime"),
                    Duration::from_secs(1),
                    cap,
                    |_| Ok(())
                )
                .unwrap_err()
                .to_string()
                .contains("retention limit")
            );
        }
        let mut accumulator = Accumulator::new(4);
        accumulator.total_bytes = u64::MAX;
        assert!(accumulator.receive(b"x").is_err());
        assert!(accumulator.retained.is_empty());
    }
}
