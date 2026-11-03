//! Operating on a container that already exists: `start`, `kill` and `delete`.
//!
//! None of these commands is the parent of the container's init. After `create` exits, init is
//! re-parented to the nearest *subreaper* (a process that called `PR_SET_CHILD_SUBREAPER`, such as
//! containerd's shim or, in hull's tests, the test process), or to the host's PID 1. Whoever that
//! is reaps it and learns its exit code. These commands therefore only ever *talk about* init:
//! through `/proc`, a FIFO and pidfds.
//!
//! # Signalling the right process
//!
//! The state file records init's PID. A PID is not an identity: if init exited and the kernel
//! handed the number to an unrelated process, `kill <id>` would hit that process. So every command
//! goes through `open_init`, which:
//!
//! 1. opens a pidfd for the PID, then
//! 2. checks that the process behind the PID still has the start time recorded at `create`.
//!
//! The order is what makes it sound. A pidfd refers to the process that held the PID at the
//! moment `pidfd_open` ran, and signals sent through it can only ever reach that process. If the
//! check in step 2 sees init's start time, init was alive at step 2, so it was alive at step 1
//! as well (a process cannot come back), and the pidfd refers to init. Done the other way round,
//! check first and open second, init could exit and its PID be reused in between, and the pidfd
//! would point at the newcomer.

use std::os::fd::OwnedFd;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, Signal};

use crate::procfs::ProcStat;
use crate::state::{State, StateStore, Status};
use crate::{ContainerId, Context, Error, Result};

/// How long `start` waits for init to acknowledge, and `delete --force` waits for it to die.
const WAIT: Duration = Duration::from_secs(10);

/// Start a `created` container: let its init `execve` the user's program.
///
/// Opening the FIFO's read end unblocks init, which is waiting in `open(O_WRONLY)`. Init then
/// writes one byte; reading it proves that init really proceeded (as opposed to having died), and
/// removing the FIFO afterwards makes a second `start` impossible.
pub fn start(store: &StateStore, id: &ContainerId) -> Result<()> {
    let dir = store.open(id)?;
    let mut state = store.load(id)?;
    if state.status != Status::Created {
        return Err(Error::Unsupported(format!(
            "container {id} is {}, not created; only a created container can be started",
            status_name(state.status)
        )));
    }
    let pidfd =
        open_init(&state)?.ok_or_else(|| Error::InitVanished("init exited before start".into()))?;

    let path = dir.exec_fifo();
    // O_NONBLOCK: a plain O_RDONLY open would block forever if init had already died, because a
    // FIFO's read end waits for a writer.
    let fifo =
        rustix::fs::open(&path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())
            .context(|| format!("open {}", path.display()))?;
    wait_for_byte(&fifo, &pidfd)?;
    std::fs::remove_file(&path).context(|| format!("remove {}", path.display()))?;

    state.status = Status::Running;
    dir.save(&state)
}

fn wait_for_byte(fifo: &OwnedFd, pidfd: &OwnedFd) -> Result<()> {
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(Error::Unsupported(format!(
                "init did not respond to start within {WAIT:?}"
            )));
        }
        let mut fds = [PollFd::new(fifo, PollFlags::IN), PollFd::new(pidfd, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&timespec(left))) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(e) => return Err(e).context(|| "poll exec FIFO".into()),
        }
        if fds[0].revents().contains(PollFlags::IN) {
            let mut byte = [0u8; 1];
            match rustix::io::read(fifo, &mut byte) {
                Ok(1) => return Ok(()),
                Ok(_) => {
                    return Err(Error::InitVanished(
                        "init closed the exec FIFO without starting".into(),
                    ));
                }
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(e) => return Err(e).context(|| "read exec FIFO".into()),
            }
        }
        if fds[0].revents().contains(PollFlags::HUP) || fds[1].revents().contains(PollFlags::IN) {
            return Err(Error::InitVanished("init exited instead of starting".into()));
        }
    }
}

/// Send `signal` to the container's init.
pub fn kill(store: &StateStore, id: &ContainerId, signal: Signal) -> Result<()> {
    let state = store.load(id)?;
    if !matches!(state.status, Status::Created | Status::Running | Status::Paused) {
        return Err(Error::Unsupported(format!(
            "container {id} is {}; there is no process to signal",
            status_name(state.status)
        )));
    }
    let pidfd = open_init(&state)?
        .ok_or_else(|| Error::Unsupported(format!("container {id} has already exited")))?;
    rustix::process::pidfd_send_signal(&pidfd, signal)
        .context(|| format!("send {signal:?} to container {id}"))
}

/// Remove a container. A running container is only removed with `force`, which kills it first.
/// A `created` container is killed and removed without `force`, like runc does: it never ran.
pub fn delete(store: &StateStore, id: &ContainerId, force: bool) -> Result<()> {
    let dir = store.open(id)?;
    let state = store.load(id)?;
    match state.status {
        Status::Stopped => {}
        Status::Created | Status::Creating => kill_and_wait(&state)?,
        Status::Running | Status::Paused if force => kill_and_wait(&state)?,
        Status::Running | Status::Paused => {
            return Err(Error::Unsupported(format!(
                "container {id} is {}; stop it first, or use --force to kill it",
                status_name(state.status)
            )));
        }
    }
    dir.destroy()
}

fn kill_and_wait(state: &State) -> Result<()> {
    let Some(pidfd) = open_init(state)? else { return Ok(()) };
    rustix::process::pidfd_send_signal(&pidfd, Signal::KILL)
        .context(|| format!("kill container {}", state.id))?;
    // A pidfd becomes readable when its process exits, even if we are not its parent.
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    loop {
        match rustix::event::poll(&mut fds, Some(&timespec(WAIT))) {
            Ok(0) => {
                return Err(Error::Unsupported(format!(
                    "container {} did not die within {WAIT:?}",
                    state.id
                )));
            }
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => {}
            Err(e) => return Err(e).context(|| "wait for container to exit".into()),
        }
    }
}

/// A pidfd for the container's init, or `None` if init no longer exists (see the module docs for
/// why the pidfd is opened *before* the identity check).
fn open_init(state: &State) -> Result<Option<OwnedFd>> {
    let Some(pid) = Pid::from_raw(state.pid) else { return Ok(None) };
    let pidfd = match rustix::process::pidfd_open(pid, PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(Errno::SRCH) => return Ok(None),
        Err(e) => return Err(e).context(|| format!("pidfd_open {}", state.pid)),
    };
    match ProcStat::read(state.pid) {
        Ok(stat) if stat.state != 'Z' && Some(stat.start_time) == state.init_start_time => {
            Ok(Some(pidfd))
        }
        // Gone, a zombie, or a different process that got the same PID.
        _ => Ok(None),
    }
}

/// Parse a signal given as a name (`TERM`, `SIGTERM`, `term`) or a number (`15`).
pub fn parse_signal(text: &str) -> Result<Signal> {
    let invalid = || Error::Unsupported(format!("unknown signal {text:?}"));
    if let Ok(number) = text.parse::<i32>() {
        return Signal::from_named_raw(number).ok_or_else(invalid);
    }
    let upper = text.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    SIGNALS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s).ok_or_else(invalid)
}

const SIGNALS: [(&str, Signal); 30] = [
    ("HUP", Signal::HUP),
    ("INT", Signal::INT),
    ("QUIT", Signal::QUIT),
    ("ILL", Signal::ILL),
    ("TRAP", Signal::TRAP),
    ("ABRT", Signal::ABORT),
    ("BUS", Signal::BUS),
    ("FPE", Signal::FPE),
    ("KILL", Signal::KILL),
    ("USR1", Signal::USR1),
    ("SEGV", Signal::SEGV),
    ("USR2", Signal::USR2),
    ("PIPE", Signal::PIPE),
    ("ALRM", Signal::ALARM),
    ("TERM", Signal::TERM),
    ("CHLD", Signal::CHILD),
    ("CONT", Signal::CONT),
    ("STOP", Signal::STOP),
    ("TSTP", Signal::TSTP),
    ("TTIN", Signal::TTIN),
    ("TTOU", Signal::TTOU),
    ("URG", Signal::URG),
    ("XCPU", Signal::XCPU),
    ("XFSZ", Signal::XFSZ),
    ("VTALRM", Signal::VTALARM),
    ("PROF", Signal::PROF),
    ("WINCH", Signal::WINCH),
    ("IO", Signal::IO),
    ("PWR", Signal::POWER),
    ("SYS", Signal::SYS),
];

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Creating => "creating",
        Status::Created => "created",
        Status::Running => "running",
        Status::Stopped => "stopped",
        Status::Paused => "paused",
    }
}

fn timespec(duration: Duration) -> Timespec {
    Timespec {
        tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: duration.subsec_nanos().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_signal_names_and_numbers() {
        for text in ["TERM", "SIGTERM", "term", "SigTerm", "15"] {
            assert_eq!(parse_signal(text).unwrap(), Signal::TERM, "{text}");
        }
        assert_eq!(parse_signal("9").unwrap(), Signal::KILL);
        assert_eq!(parse_signal("ABRT").unwrap(), Signal::ABORT);
        for text in ["", "SIG", "TERMINATE", "0", "-1", "999"] {
            assert!(parse_signal(text).is_err(), "{text:?} should be rejected");
        }
    }

    #[test]
    fn a_dead_or_recycled_init_is_never_signalled() {
        let mut state = crate::state::tests_support::state("c");
        state.pid = i32::MAX;
        assert!(open_init(&state).unwrap().is_none(), "no such process");

        // Our own PID with the wrong start time: exactly what a recycled PID looks like.
        state.pid = std::process::id().try_into().unwrap();
        state.init_start_time = Some(1);
        assert!(open_init(&state).unwrap().is_none(), "recycled PID");

        state.init_start_time = Some(ProcStat::read(state.pid).unwrap().start_time);
        assert!(open_init(&state).unwrap().is_some(), "the real process");
    }
}
