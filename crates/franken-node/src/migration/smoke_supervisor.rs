//! Shared Linux migration and compatibility-corpus process supervision.
//!
//! Own the child, its process group and both nonblocking pipes until cleanup.
//! No pipe-reader thread or PATH-resolved kill command can outlive a check.
//! waitid(NOWAIT) leaves the leader unreaped until group cleanup, so its PID
//! cannot be recycled into an unrelated group during the final drain window.
//! This module must be the exclusive waiter for its children. Process groups
//! are cleanup boundaries, not sandboxes: a descendant may deliberately escape.

use anyhow::{Context, Result, bail};
use rustix::fd::AsFd;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, getpgrp, kill_process_group, waitid};
use std::io::{self, Read, Seek, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_INPUT_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);

fn checked_group(raw: u32) -> io::Result<Pid> {
    let pid = i32::try_from(raw)
        .ok()
        .filter(|raw| *raw > 1)
        .and_then(Pid::from_raw);
    match pid {
        Some(pid) if pid != getpgrp() => Ok(pid),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing reserved or caller-owned runtime smoke process group",
        )),
    }
}

/// A private owner, never handed to an external reaper or arbitrary caller.
struct OwnedSmokeChild {
    child: Child,
    group: Pid,
    active: bool,
}

impl OwnedSmokeChild {
    fn spawn(command: &mut Command, input: Stdio) -> Result<Self> {
        command.stdin(input).stdout(Stdio::piped()).stderr(Stdio::piped());
        command.process_group(0);
        let mut child = command
            .spawn()
            .context("failed launching runtime smoke command")?;
        let group = match checked_group(child.id()) {
            Ok(group) => group,
            Err(error) => {
                // A direct Child kill is never a broadcast, even for a rejected
                // group ID. Still avoid an unbounded wait after a failed kill.
                let _ = child.kill();
                let _ = reap_bounded(&mut child);
                return Err(error).context("invalid spawned runtime smoke group");
            }
        };
        Ok(Self {
            child,
            group,
            active: true,
        })
    }

    fn exited_without_reaping(&mut self) -> io::Result<bool> {
        match waitid(
            WaitId::Pid(self.group),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.is_some()),
            Err(Errno::INTR) => Ok(false),
            Err(Errno::CHILD) => {
                // Another waiter or a SIGCHLD disposition violated ownership.
                // Without the unreaped leader, numerical group signalling can
                // hit a recycled PID. Fail, and disarm that unsafe cleanup.
                self.active = false;
                Err(io::Error::other(
                    "runtime smoke child was reaped outside its owner",
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn finish(&mut self) -> io::Result<ExitStatus> {
        if !self.active {
            return Err(io::Error::other(
                "runtime smoke child ownership already ended",
            ));
        }
        // Signal the group BEFORE reaping the pinned leader. Attempt the direct
        // kill and reap even when signalling the group fails. ESRCH is benign:
        // an exited group is already gone, not a reason to skip child cleanup.
        let group_result = kill_process_group(self.group, Signal::KILL);
        let kill_result = self.child.kill();
        let status = reap_bounded(&mut self.child);
        self.active = false;
        let status = status?;
        if let Err(error) = group_result
            && error != Errno::SRCH
        {
            return Err(io::Error::other(format!(
                "runtime smoke group cleanup failed: {error}"
            )));
        }
        if let Err(error) = kill_result
            && error.raw_os_error() != Some(Errno::SRCH.raw_os_error())
        {
            return Err(io::Error::other(format!(
                "runtime smoke child cleanup failed: {error}"
            )));
        }
        Ok(status)
    }
}

impl Drop for OwnedSmokeChild {
    fn drop(&mut self) {
        if self.active {
            let _ = self.finish();
        }
    }
}

fn reap_bounded(child: &mut Child) -> io::Result<ExitStatus> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        if started.elapsed() >= REAP_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime smoke child could not be reaped within cleanup budget",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn nonblocking(pipe: &impl AsFd) -> io::Result<()> {
    let flags = fcntl_getfl(pipe)?;
    fcntl_setfl(pipe, flags | OFlags::NONBLOCK)?;
    Ok(())
}

struct PipeCapture<R> {
    pipe: R,
    eof: bool,
}

impl<R: Read> PipeCapture<R> {
    fn new(pipe: R) -> Self {
        Self { pipe, eof: false }
    }

    /// Read at most one chunk so a stdout flood cannot starve stderr, child
    /// exit checks or deadlines. The trusted observer owns its retention cap.
    fn pump(&mut self, receive: &mut impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut buffer = [0_u8; 64 * 1024];
        match self.pipe.read(&mut buffer) {
            Ok(0) => {
                self.eof = true;
                Ok(true)
            }
            Ok(count) => {
                receive(&buffer[..count])?;
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

/// The input transport is part of the captured request, not an implementation
/// detail: a regular file is seekable, whereas a pipe is not. Keep both modes
/// explicit and share the same child owner, deadlines and output drain.
enum InputTransport<'a> {
    Redirected(Stdio),
    Pipe(&'a [u8]),
}

struct PipeInput<'a, W> {
    pipe: Option<W>,
    bytes: &'a [u8],
    queued: usize,
}

impl<'a, W: Write> PipeInput<'a, W> {
    fn new(pipe: W, bytes: &'a [u8]) -> Self {
        Self {
            // An explicitly empty request still uses a pipe, immediately
            // closed to deliver EOF rather than retaining a writer forever.
            pipe: if bytes.is_empty() { None } else { Some(pipe) },
            bytes,
            queued: 0,
        }
    }

    /// Attempt only one bounded write per polling round. In particular, never
    /// write_all() to a guest that may fill stdout before it reads stdin.
    fn pump(&mut self) -> io::Result<bool> {
        let Some(pipe) = self.pipe.as_mut() else {
            return Ok(false);
        };
        let end = self.bytes.len().min(self.queued.saturating_add(64 * 1024));
        match pipe.write(&self.bytes[self.queued..end]) {
            Ok(0) => Err(io::Error::new(io::ErrorKind::WriteZero, "runtime stdin made no progress")),
            Ok(count) => {
                self.queued += count;
                if self.queued == self.bytes.len() {
                    self.close();
                }
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                // Preserve the native exit and diagnostic streams. A zero
                // exit with an incomplete request is rejected by the caller.
                self.close();
                Ok(true)
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn close(&mut self) {
        drop(self.pipe.take());
    }
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
    label: &'static str,
}

impl BoundedBytes {
    fn receive(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime smoke {} output exceeds {} bytes",
                    self.label, self.limit
                ),
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    Exited,
    RuntimeTimeout,
    PipeTimeout,
}

#[derive(Debug)]
pub(crate) struct Completion {
    pub(crate) status: ExitStatus,
    pub(crate) reason: StopReason,
}

/// Execute one native smoke leg. The deadline includes pipe draining; cleanup
/// has a separate bounded reap allowance and also runs on setup/I/O errors.
pub(super) fn run_command_with_timeout(
    command: &mut Command,
    timeout: Duration,
    pipe_drain_timeout: Duration,
) -> Result<Output> {
    run_command_with_input(command, timeout, pipe_drain_timeout, None)
}

/// Supply bounded captured bytes through a fresh anonymous regular file. Each
/// invocation starts at offset zero, even if a preceding guest seeks/writes.
/// There is no pipe-writer thread, inherited terminal, or blocked stdin join.
/// This models redirected file input, not a terminal or interactive pipe.
pub(super) fn run_command_with_input(
    command: &mut Command,
    timeout: Duration,
    pipe_drain_timeout: Duration,
    input: Option<&[u8]>,
) -> Result<Output> {
    run_bounded_input(command, timeout, pipe_drain_timeout, MAX_STREAM_BYTES, input)
}

/// Supply a bounded immutable request through a real pipe, multiplexed with
/// stdout/stderr on the supervisor thread. Queued bytes are transport progress,
/// not proof of guest consumption. A zero exit before the whole request is
/// queued is an error; native failures retain their original exit status.
pub(super) fn run_command_with_pipe_input(
    command: &mut Command,
    timeout: Duration,
    pipe_drain_timeout: Duration,
    input: &[u8],
) -> Result<Output> {
    capture_command(command, timeout, pipe_drain_timeout, MAX_STREAM_BYTES, InputTransport::Pipe(input))
}

#[cfg(test)]
fn run_bounded(command: &mut Command, timeout: Duration, drain_timeout: Duration, limit: usize) -> Result<Output> {
    run_bounded_input(command, timeout, drain_timeout, limit, None)
}

fn run_bounded_input(
    command: &mut Command,
    timeout: Duration,
    drain_timeout: Duration,
    limit: usize,
    input: Option<&[u8]>,
) -> Result<Output> {
    if timeout.is_zero() || drain_timeout.is_zero() || limit == 0 || limit > MAX_STREAM_BYTES {
        bail!("runtime smoke requires positive bounded time and output limits");
    }
    let deadline = Instant::now().checked_add(timeout).context("runtime smoke deadline overflow")?;
    let stdin = if let Some(bytes) = input {
        if bytes.len() > MAX_INPUT_BYTES { bail!("captured stdin exceeds 1 MiB"); }
        let mut file = tempfile::tempfile().context("create private captured stdin")?;
        file.write_all(bytes).context("stage captured stdin")?;
        file.rewind().context("rewind captured stdin")?;
        Stdio::from(file)
    } else { Stdio::null() };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() { bail!("runtime smoke timed out preparing captured stdin"); }
    capture_command(command, remaining, drain_timeout, limit, InputTransport::Redirected(stdin))
}

fn capture_command(
    command: &mut Command,
    timeout: Duration,
    drain_timeout: Duration,
    limit: usize,
    input: InputTransport<'_>,
) -> Result<Output> {
    if timeout.is_zero() || drain_timeout.is_zero() || limit == 0 || limit > MAX_STREAM_BYTES {
        bail!("runtime smoke requires positive bounded time and output limits");
    }
    let requested = match &input {
        InputTransport::Pipe(bytes) => Some(bytes.len()),
        InputTransport::Redirected(_) => None,
    };
    let mut stdout = BoundedBytes { bytes: Vec::new(), limit, label: "stdout" };
    let mut stderr = BoundedBytes { bytes: Vec::new(), limit, label: "stderr" };
    let observer = |stream, bytes: &[u8]| match stream {
        Stream::Stdout => stdout.receive(bytes),
        Stream::Stderr => stderr.receive(bytes),
    };
    let (completion, queued) = supervise_with_input(command, timeout, drain_timeout, input, |_| Ok(()), observer)?;
    match completion.reason {
        StopReason::RuntimeTimeout => bail!(
            "runtime smoke command timed out after {}ms",
            timeout.as_millis()
        ),
        StopReason::PipeTimeout => bail!(
            "runtime smoke command exited but output pipes remained open beyond {}ms",
            drain_timeout.as_millis()
        ),
        StopReason::Exited => {
            if let Some(requested) = requested
                && completion.status.success()
                && queued != requested
            {
                bail!("runtime exited zero before complete stdin delivery: queued {queued} of {requested} bytes");
            }
            Ok(Output {
                status: completion.status,
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            })
        }
    }
}

/// Run with a trusted, bounded in-process stream observer. The observer may
/// retain a capped prefix while hashing later bytes; it must not block. The
/// startup hook receives only a PID (not the child/wait ownership), and must
/// enforce its own bounded handshake. Its elapsed time is included in the
/// leg's deadline, never followed by a fresh full runtime allowance.
///
/// A timeout is a measured incomplete outcome, not successful execution. The
/// caller must refuse equivalence on either timeout reason. Setup, observer,
/// hook and cleanup errors remain errors, with cleanup attempted on every exit.
pub(crate) fn supervise_with_observer(
    command: &mut Command,
    timeout: Duration,
    drain_timeout: Duration,
    after_spawn: impl FnOnce(u32) -> Result<()>,
    observe: impl FnMut(Stream, &[u8]) -> io::Result<()>,
) -> Result<Completion> {
    supervise_with_input(command, timeout, drain_timeout, InputTransport::Redirected(Stdio::null()), after_spawn, observe)
        .map(|(completion, _)| completion)
}

fn supervise_with_input(
    command: &mut Command,
    timeout: Duration,
    drain_timeout: Duration,
    input: InputTransport<'_>,
    after_spawn: impl FnOnce(u32) -> Result<()>,
    mut observe: impl FnMut(Stream, &[u8]) -> io::Result<()>,
) -> Result<(Completion, usize)> {
    if timeout.is_zero() || drain_timeout.is_zero() {
        bail!("runtime smoke requires positive bounded time and output limits");
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("runtime smoke deadline overflow")?;
    let (stdin, pipe_bytes) = match input {
        InputTransport::Redirected(stdin) => (stdin, None),
        InputTransport::Pipe(bytes) => {
            if bytes.len() > MAX_INPUT_BYTES {
                bail!("captured stdin exceeds 1 MiB");
            }
            (Stdio::piped(), Some(bytes))
        }
    };
    let mut owned = OwnedSmokeChild::spawn(command, stdin)?;
    let mut queued = 0;
    let result = (|| -> Result<StopReason> {
        let stdout = owned
            .child
            .stdout
            .take()
            .context("runtime smoke stdout pipe unavailable")?;
        let stderr = owned
            .child
            .stderr
            .take()
            .context("runtime smoke stderr pipe unavailable")?;
        nonblocking(&stdout).context("configure runtime smoke stdout")?;
        nonblocking(&stderr).context("configure runtime smoke stderr")?;
        let mut stdout = PipeCapture::new(stdout);
        let mut stderr = PipeCapture::new(stderr);
        let mut input = if let Some(bytes) = pipe_bytes {
            let pipe = owned.child.stdin.take().context("runtime smoke stdin pipe unavailable")?;
            nonblocking(&pipe).context("configure runtime smoke stdin")?;
            Some(PipeInput::new(pipe, bytes))
        } else {
            None
        };
        if let Err(error) = after_spawn(owned.child.id()) {
            // Retain available diagnostics without waiting for inherited pipes.
            let _ = stdout.pump(&mut |bytes| observe(Stream::Stdout, bytes));
            let _ = stderr.pump(&mut |bytes| observe(Stream::Stderr, bytes));
            return Err(error).context("runtime startup hook failed");
        }
        let mut exited_at = None;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(StopReason::RuntimeTimeout);
            }
            // Pin the leader through cleanup as before, but stop delivering
            // application input as soon as its exit has been observed.
            let exited = owned.exited_without_reaping()?;
            if exited && let Some(input) = input.as_mut() {
                input.close();
            }
            let out_progress = stdout
                .pump(&mut |bytes| observe(Stream::Stdout, bytes))
                .context("failed reading runtime smoke stdout")?;
            let err_progress = stderr
                .pump(&mut |bytes| observe(Stream::Stderr, bytes))
                .context("failed reading runtime smoke stderr")?;
            if exited {
                if stdout.eof && stderr.eof {
                    return Ok(StopReason::Exited);
                }
                let exited = *exited_at.get_or_insert(now);
                if now.duration_since(exited) >= drain_timeout {
                    return Ok(StopReason::PipeTimeout);
                }
            }
            if Instant::now() >= deadline {
                return Ok(StopReason::RuntimeTimeout);
            }
            let input_progress = if let Some(input) = input.as_mut() {
                let progress = input.pump().context("failed writing runtime smoke stdin")?;
                queued = input.queued;
                progress
            } else {
                false
            };
            if !out_progress && !err_progress && !input_progress {
                thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
    })();
    // The pipe owners have been dropped here, even when an escaped descendant
    // still holds a write end. No blocked reader thread survives this function.
    let cleanup = owned.finish();
    match (result, cleanup) {
        (Ok(reason), Ok(status)) => Ok((Completion { status, reason }, queued)),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("runtime smoke cleanup failed"),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("runtime smoke cleanup also failed: {cleanup}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::process::ExitStatusExt;

    fn shell(source: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", source]);
        command
    }

    fn run(source: &str) -> Result<Output> {
        run_command_with_timeout(
            &mut shell(source),
            Duration::from_secs(3),
            Duration::from_millis(100),
        )
    }

    #[test]
    fn empty_output_and_successful_exit_are_preserved() {
        let output = run("exit 0").expect("empty output");
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn binary_streams_and_trailing_newlines_remain_distinct() {
        let output =
            run("printf 'a\\000b\\377\\n\\n'; printf 'error\\n' >&2").expect("binary output");
        assert_eq!(output.stdout, [b'a', 0, b'b', 255, b'\n', b'\n']);
        assert_eq!(output.stderr, b"error\n");
    }

    #[test]
    fn nonzero_exit_is_not_replaced_by_cleanup_status() {
        assert_eq!(run("exit 7").expect("nonzero process").status.code(), Some(7));
    }

    #[test]
    fn signal_exit_is_not_replaced_by_cleanup_status() {
        assert_eq!(run("kill -TERM $$").expect("signal exit").status.signal(), Some(Signal::TERM.as_raw()));
    }

    #[test]
    fn both_streams_allow_the_exact_limit() {
        let output = run_bounded(&mut shell("printf 1234; printf 5678 >&2"),
            Duration::from_secs(3), Duration::from_secs(1), 4).expect("exact output caps");
        assert_eq!(output.stdout, b"1234");
        assert_eq!(output.stderr, b"5678");
    }

    #[test]
    fn overflow_on_either_stream_is_not_truncated_success() {
        for (source, label) in [("printf 12345", "stdout"), ("printf 12345 >&2", "stderr")] {
            let error = run_bounded(&mut shell(source), Duration::from_secs(3), Duration::from_secs(1), 4)
                .expect_err("overflow");
            let message = format!("{error:#}");
            assert!(message.contains(label), "{message}");
            assert!(message.contains("exceeds 4 bytes"), "{message}");
        }
    }

    #[test]
    fn flood_is_stopped_before_the_runtime_deadline() {
        let started = Instant::now();
        let error = run_bounded(&mut shell("while :; do printf abcdefgh; done"),
            Duration::from_secs(30), Duration::from_secs(1), 64).expect_err("flood must terminate");
        assert!(format!("{error:#}").contains("exceeds 64 bytes"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn closed_pipes_do_not_hide_a_running_child() {
        let started = Instant::now();
        let error = run_bounded(&mut shell("exec 1>&- 2>&-; exec /bin/sleep 60"),
            Duration::from_millis(150), Duration::from_secs(1), 64).expect_err("running child");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn inherited_pipes_are_bounded_after_leader_exits() {
        let started = Instant::now();
        let error = run("/bin/sleep 60 & exit 0").expect_err("inherited pipes");
        assert!(error.to_string().contains("output pipes remained open"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn ignored_sigterm_does_not_prevent_cleanup() {
        let error = run_bounded(&mut shell("trap '' TERM; exec /bin/sleep 60"),
            Duration::from_millis(150), Duration::from_secs(1), 64).expect_err("deadline");
        assert!(error.to_string().contains("timed out"));
        assert!(!format!("{error:#}").contains("cleanup also failed"));
    }

    #[test]
    fn reserved_and_caller_group_ids_are_rejected_without_signalling() {
        for raw in [0, 1, u32::MAX, u32::try_from(getpgrp().as_raw_pid()).expect("positive group")] {
            assert_eq!(checked_group(raw).expect_err("unsafe group").kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn leader_remains_waitable_until_cleanup() {
        let mut owned = OwnedSmokeChild::spawn(&mut shell("exit 7"), Stdio::null()).expect("child");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !owned.exited_without_reaping().expect("observe exit") {
            assert!(Instant::now() < deadline);
            thread::sleep(POLL_INTERVAL);
        }
        assert!(owned.exited_without_reaping().expect("leader still pinned"));
        assert_eq!(owned.finish().expect("reap").code(), Some(7));
        assert!(!owned.active);
    }

    #[test]
    fn owner_drop_terminates_and_reaps_child() {
        let owned = OwnedSmokeChild::spawn(&mut shell("exec /bin/sleep 60"), Stdio::null()).expect("child");
        let pid = owned.group;
        drop(owned);
        assert!(matches!(waitid(WaitId::Pid(pid), WaitIdOptions::EXITED | WaitIdOptions::NOHANG), Err(Errno::CHILD)));
    }

    #[test]
    fn success_still_stops_background_group_members() {
        let output = run("/bin/sleep 60 >/dev/null 2>&1 & printf '%s' \"$!\"; exit 0").expect("background child");
        assert!(output.status.success());
        let pid: u32 = std::str::from_utf8(&output.stdout).expect("pid output").parse().expect("pid");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Ok(stat) if stat.rsplit_once(") ").is_some_and(|(_, rest)| rest.starts_with('Z') || rest.starts_with('X')) => break,
                _ => {
                    assert!(Instant::now() < deadline, "background group member still running");
                    thread::sleep(POLL_INTERVAL);
                }
            }
        }
    }

    #[test]
    fn invalid_budget_is_refused_before_spawn() {
        let mut command = Command::new("/definitely/missing/native-smoke-executable");
        let error = run_command_with_timeout(&mut command, Duration::ZERO, Duration::from_secs(1)).expect_err("zero budget");
        assert!(error.to_string().contains("positive bounded"));
    }

    #[test]
    fn capture_never_retains_the_overflow_probe_byte() {
        let mut capture = PipeCapture::new(Cursor::new(b"12345"));
        let mut retained = BoundedBytes { bytes: Vec::new(), limit: 4, label: "stdout" };
        assert!(capture.pump(&mut |bytes| retained.receive(bytes)).is_err());
        assert!(retained.bytes.len() <= 4);
        let mut empty = PipeCapture::new(io::empty());
        assert!(empty.pump(&mut |bytes| retained.receive(bytes)).expect("EOF"));
        assert!(empty.eof);
    }

    #[test]
    fn observer_keeps_timeout_distinct_from_a_successful_leader_exit() {
        let mut bytes = Vec::new();
        let result = supervise_with_observer(&mut shell("printf captured; /bin/sleep 60 & exit 0"),
            Duration::from_secs(3), Duration::from_millis(100), |_| Ok(()), |stream, chunk| {
                if stream == Stream::Stdout { bytes.extend_from_slice(chunk); }
                Ok(())
            }).unwrap();
        assert_eq!(result.reason, StopReason::PipeTimeout);
        assert_eq!(result.status.code(), Some(0));
        assert_eq!(bytes, b"captured");
    }

    #[test]
    fn startup_time_consumes_the_original_leg_deadline() {
        let started = Instant::now();
        let result = supervise_with_observer(&mut shell("exec /bin/sleep 0.4"),
            Duration::from_millis(150), Duration::from_millis(100), |_| {
                thread::sleep(Duration::from_millis(300)); Ok(())
            }, |_, _| Ok(())).unwrap();
        assert_eq!(result.reason, StopReason::RuntimeTimeout);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn startup_failure_cleans_up_without_joining_inherited_pipes() {
        let mut pid = None;
        let started = Instant::now();
        let error = supervise_with_observer(&mut shell("/bin/sleep 60 & wait"),
            Duration::from_secs(3), Duration::from_millis(100), |raw| {
                pid = Pid::from_raw(i32::try_from(raw).unwrap()); bail!("rejected authority");
            }, |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("rejected authority"));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(waitid(WaitId::Pid(pid.unwrap()), WaitIdOptions::EXITED | WaitIdOptions::NOHANG), Err(Errno::CHILD)));
    }

    #[test]
    fn observer_failure_also_terminates_and_reaps_the_leader() {
        let mut pid = None;
        let error = supervise_with_observer(&mut shell("while :; do printf output; done"),
            Duration::from_secs(3), Duration::from_millis(100), |raw| {
                pid = Pid::from_raw(i32::try_from(raw).unwrap()); Ok(())
            }, |_, _| Err(io::Error::other("observer refused bytes"))).unwrap_err();
        assert!(format!("{error:#}").contains("observer refused bytes"));
        assert!(matches!(waitid(WaitId::Pid(pid.unwrap()), WaitIdOptions::EXITED | WaitIdOptions::NOHANG), Err(Errno::CHILD)));
    }

    #[test]
    fn captured_binary_stdin_is_fresh_for_every_command_and_has_eof() {
        let input = [0, 255, b'x', b'\n', b'\n'];
        let mut command = Command::new("/bin/cat");
        for _ in 0..2 {
            let output = run_command_with_input(&mut command, Duration::from_secs(3),
                Duration::from_secs(1), Some(&input)).unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, input);
        }
        assert!(run_command_with_input(&mut command, Duration::from_secs(3),
            Duration::from_secs(1), Some(&[])).unwrap().stdout.is_empty());
        assert!(run_command_with_timeout(&mut command, Duration::from_secs(3),
            Duration::from_secs(1)).unwrap().stdout.is_empty());
    }

    #[test]
    fn full_input_does_not_block_a_guest_that_never_reads_or_exits_early() {
        let input = vec![b'x'; MAX_INPUT_BYTES];
        let output = run_command_with_input(&mut Command::new("/bin/true"), Duration::from_secs(3),
            Duration::from_secs(1), Some(&input)).unwrap();
        assert!(output.status.success());
        let started = Instant::now();
        let error = run_command_with_input(&mut shell("exec /bin/sleep 60"), Duration::from_millis(150),
            Duration::from_secs(1), Some(&input)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn exact_input_limit_round_trips_and_oversize_never_spawns() {
        let input = vec![b'x'; MAX_INPUT_BYTES];
        let output = run_command_with_input(&mut Command::new("/bin/cat"), Duration::from_secs(5),
            Duration::from_secs(1), Some(&input)).unwrap();
        assert_eq!(output.stdout, input);
        let error = run_command_with_input(&mut Command::new("/definitely/absent"), Duration::from_secs(3),
            Duration::from_secs(1), Some(&vec![b'x'; MAX_INPUT_BYTES + 1])).unwrap_err();
        assert!(error.to_string().contains("stdin exceeds"));
    }

    #[test]
    fn captured_input_keeps_output_limits_and_pipe_cleanup_mandatory() {
        let error = run_bounded_input(&mut Command::new("/bin/cat"), Duration::from_secs(3),
            Duration::from_secs(1), 4, Some(b"12345")).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds 4 bytes"));
        let error = run_command_with_input(&mut shell("/bin/cat; /bin/sleep 60 & exit 0"),
            Duration::from_secs(3), Duration::from_millis(100), Some(b"input")).unwrap_err();
        assert!(error.to_string().contains("output pipes remained open"));
    }

    fn pipe_run(source: &str, input: &[u8]) -> Result<Output> {
        run_command_with_pipe_input(
            &mut shell(source), Duration::from_secs(5), Duration::from_millis(100), input,
        )
    }

    #[test]
    fn pipe_input_preserves_transport_binary_bytes_and_empty_eof() {
        for input in [&[0, 255, b'x', b'\n', b'\n'][..], &[][..]] {
            let output = pipe_run("test -p /proc/self/fd/0 || exit 9; exec /bin/cat", input).unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, input);
            assert!(output.stderr.is_empty());
        }
        let file = run_command_with_input(
            &mut shell("test -f /proc/self/fd/0 || exit 9; exec /bin/cat"),
            Duration::from_secs(3), Duration::from_secs(1), Some(b"file mode"),
        ).unwrap();
        assert!(file.status.success());
        assert_eq!(file.stdout, b"file mode");
    }

    #[test]
    fn pipe_input_round_trips_the_exact_limit_and_rejects_oversize_before_spawn() {
        let input: Vec<u8> = (0..=255).cycle().take(MAX_INPUT_BYTES).collect();
        let output = pipe_run("exec /bin/cat", &input).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, input);
        let error = run_command_with_pipe_input(
            &mut Command::new("/definitely/missing-pipe-input-executable"),
            Duration::from_secs(3), Duration::from_secs(1), &vec![0; MAX_INPUT_BYTES + 1],
        ).unwrap_err();
        assert!(error.to_string().contains("stdin exceeds"));
    }

    #[test]
    fn pipe_input_multiplexes_both_large_outputs_before_the_guest_reads() {
        let input = vec![b'r'; MAX_INPUT_BYTES];
        let output = pipe_run(
            "/bin/dd if=/dev/zero bs=65536 count=8 2>/dev/null; \
             /bin/dd if=/dev/zero bs=65536 count=8 >&2 2>/dev/null; exec /bin/cat",
            &input,
        ).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, [vec![0; 512 * 1024], input].concat());
        assert_eq!(output.stderr, vec![0; 512 * 1024]);
    }

    #[test]
    fn pipe_input_nonreading_guest_cannot_disable_timeout_or_reaping() {
        let input = vec![0; MAX_INPUT_BYTES];
        let mut pid = None;
        let started = Instant::now();
        let (completion, queued) = supervise_with_input(
            &mut shell("exec /bin/sleep 60"), Duration::from_millis(150),
            Duration::from_millis(100), InputTransport::Pipe(&input),
            |raw| { pid = Pid::from_raw(i32::try_from(raw).unwrap()); Ok(()) },
            |_, _| Ok(()),
        ).unwrap();
        assert_eq!(completion.reason, StopReason::RuntimeTimeout);
        assert!(queued < input.len());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(matches!(waitid(WaitId::Pid(pid.unwrap()), WaitIdOptions::EXITED | WaitIdOptions::NOHANG), Err(Errno::CHILD)));
    }

    #[test]
    fn pipe_input_early_close_rejects_zero_but_preserves_native_failure() {
        let input = vec![0; MAX_INPUT_BYTES];
        let error = pipe_run("exec 0<&-; printf early; /bin/sleep 0.05; exit 0", &input).unwrap_err();
        assert!(error.to_string().contains("before complete stdin delivery"));
        let output = pipe_run("exec 0<&-; printf failed >&2; exit 7", &input).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stderr, b"failed");
    }

    #[test]
    fn pipe_input_timeout_is_not_relabelled_as_incomplete_input() {
        let error = run_command_with_pipe_input(
            &mut shell("exec 0<&-; exec /bin/sleep 60"), Duration::from_millis(150),
            Duration::from_millis(100), &vec![0; MAX_INPUT_BYTES],
        ).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(!error.to_string().contains("complete stdin delivery"));
    }

    #[test]
    fn pipe_input_keeps_stream_quotas_and_inherited_pipe_deadlines() {
        let error = capture_command(
            &mut Command::new("/bin/cat"), Duration::from_secs(3),
            Duration::from_millis(100), 4, InputTransport::Pipe(b"12345"),
        ).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds 4 bytes"));
        let error = pipe_run("/bin/cat; /bin/sleep 60 & exit 0", b"input").unwrap_err();
        assert!(error.to_string().contains("output pipes remained open"));
    }

    #[test]
    fn pipe_input_startup_rejection_never_feeds_request_and_reaps_child() {
        let mut pid = None;
        let error = supervise_with_input(
            &mut shell("exec /bin/cat"), Duration::from_secs(3), Duration::from_millis(100),
            InputTransport::Pipe(b"request must not be delivered"),
            |raw| { pid = Pid::from_raw(i32::try_from(raw).unwrap()); bail!("admission refused") },
            |_, bytes| { assert!(bytes.is_empty()); Ok(()) },
        ).unwrap_err();
        assert!(format!("{error:#}").contains("admission refused"));
        assert!(matches!(waitid(WaitId::Pid(pid.unwrap()), WaitIdOptions::EXITED | WaitIdOptions::NOHANG), Err(Errno::CHILD)));
    }

    #[test]
    fn pipe_input_observer_failure_still_reaps_the_owned_scope() {
        let mut pid = None;
        let error = supervise_with_input(
            &mut shell("printf output; exec /bin/sleep 60"), Duration::from_secs(3),
            Duration::from_millis(100), InputTransport::Pipe(b"request"),
            |raw| { pid = Pid::from_raw(i32::try_from(raw).unwrap()); Ok(()) },
            |_, _| Err(io::Error::other("observer refused pipe run")),
        ).unwrap_err();
        assert!(format!("{error:#}").contains("observer refused pipe run"));
        assert!(matches!(waitid(WaitId::Pid(pid.unwrap()), WaitIdOptions::EXITED | WaitIdOptions::NOHANG), Err(Errno::CHILD)));
    }

    #[derive(Default)]
    struct WriteProbe {
        actions: std::collections::VecDeque<io::Result<usize>>,
        received: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        dropped: std::rc::Rc<std::cell::Cell<bool>>,
        largest_request: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl WriteProbe {
        fn with_actions(actions: impl Into<std::collections::VecDeque<io::Result<usize>>>) -> Self {
            Self {
                actions: actions.into(),
                received: Default::default(),
                dropped: Default::default(),
                largest_request: Default::default(),
            }
        }
    }

    impl Write for WriteProbe {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.largest_request.set(self.largest_request.get().max(bytes.len()));
            let count = self.actions.pop_front().unwrap_or(Ok(bytes.len()))?;
            assert!(count <= bytes.len());
            self.received.borrow_mut().extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    impl Drop for WriteProbe {
        fn drop(&mut self) { self.dropped.set(true); }
    }

    #[test]
    fn pipe_input_short_writes_and_retryable_errors_preserve_every_byte() {
        let probe = WriteProbe::with_actions([Ok(2), Err(io::ErrorKind::WouldBlock.into()),
            Err(io::ErrorKind::Interrupted.into()), Ok(1)]);
        let received = probe.received.clone();
        let dropped = probe.dropped.clone();
        let mut input = PipeInput::new(probe, b"abcdef");
        assert!(input.pump().unwrap());
        assert!(!input.pump().unwrap());
        assert!(!input.pump().unwrap());
        assert_eq!(input.queued, 2);
        assert!(input.pump().unwrap());
        assert!(input.pump().unwrap());
        assert_eq!(*received.borrow(), b"abcdef");
        assert_eq!(input.queued, 6);
        assert!(dropped.get());
        assert!(!input.pump().unwrap());
    }

    #[test]
    fn pipe_input_empty_request_closes_the_writer_without_a_write() {
        let probe = WriteProbe::default();
        let dropped = probe.dropped.clone();
        let mut input = PipeInput::new(probe, b"");
        assert!(dropped.get());
        assert!(!input.pump().unwrap());
        assert_eq!(input.queued, 0);
    }

    #[test]
    fn pipe_input_broken_pipe_records_partial_progress_and_closes_writer() {
        let probe = WriteProbe::with_actions([Ok(2), Err(io::ErrorKind::BrokenPipe.into())]);
        let dropped = probe.dropped.clone();
        let mut input = PipeInput::new(probe, b"request");
        assert!(input.pump().unwrap());
        assert!(input.pump().unwrap());
        assert_eq!(input.queued, 2);
        assert!(dropped.get());
        assert!(!input.pump().unwrap());
    }

    #[test]
    fn pipe_input_zero_and_hard_write_errors_are_not_successful_progress() {
        for action in [Ok(0), Err(io::ErrorKind::Other.into())] {
            let probe = WriteProbe::with_actions([action]);
            let dropped = probe.dropped.clone();
            let mut input = PipeInput::new(probe, b"request");
            assert!(input.pump().is_err());
            assert_eq!(input.queued, 0);
            drop(input);
            assert!(dropped.get());
        }
    }

    #[test]
    fn pipe_input_never_writes_more_than_one_chunk_per_poll() {
        let bytes = vec![0; MAX_INPUT_BYTES];
        let probe = WriteProbe::default();
        let largest = probe.largest_request.clone();
        let mut input = PipeInput::new(probe, &bytes);
        assert!(input.pump().unwrap());
        assert_eq!(input.queued, 64 * 1024);
        assert_eq!(largest.get(), 64 * 1024);
        assert!(input.pipe.is_some());
    }
}
