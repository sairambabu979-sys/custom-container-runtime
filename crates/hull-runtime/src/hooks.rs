//! OCI hooks: programs the runtime runs at fixed points in a container's life.
//!
//! Each phase differs in *when* it runs, *who* runs it (and therefore in which namespaces), and
//! what a failure means (runtime-spec `config.md`, "POSIX-platform Hooks"):
//!
//! | Phase | When | Run by | Namespaces | On failure |
//! |---|---|---|---|---|
//! | `prestart` (deprecated) | after the mounts, before `pivot_root` | the runtime | the runtime's | abort `create` |
//! | `createRuntime` | same moment as `prestart` | the runtime | the runtime's | abort `create` |
//! | `createContainer` | right after `createRuntime` | container init | the container's, but before `pivot_root`, so paths resolve on the host | abort `create` |
//! | `startContainer` | during `start`, before the user's program | container init | the container's, after `pivot_root` | abort `start` |
//! | `poststart` | after the user's program started | the runtime (`start`) | the runtime's | warn, carry on |
//! | `poststop` | after the container was deleted | the runtime (`delete`) | the runtime's | warn, carry on |
//!
//! Every hook gets the container's OCI state as JSON on standard input, only the environment its
//! config lists (nothing inherited), and the `args` from its config as `argv`, including
//! `argv[0]`.
//!
//! The typical user is containerd's network setup: a `createRuntime` hook sees the new network
//! namespace through the state's PID and configures it before the program starts.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use hull_spec::oci::{Hook, Spec};
use rustix::event::{PollFd, PollFlags, Timespec};
use serde_json::{Value, json};

use crate::state::{State, Status};
use crate::{Context, Error, Result};

/// At most this much of a failing hook's stderr is quoted in the error.
const STDERR_TAIL: usize = 4096;

/// The six hook phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Deprecated alias of `createRuntime`'s moment.
    Prestart,
    /// In the runtime's namespaces, after the container's namespaces and mounts exist.
    CreateRuntime,
    /// In the container's namespaces, before `pivot_root`.
    CreateContainer,
    /// In the container, right before the user's program runs.
    StartContainer,
    /// After the user's program started.
    Poststart,
    /// After the container was deleted.
    Poststop,
}

impl Phase {
    /// The phase's name in `config.json`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Prestart => "prestart",
            Self::CreateRuntime => "createRuntime",
            Self::CreateContainer => "createContainer",
            Self::StartContainer => "startContainer",
            Self::Poststart => "poststart",
            Self::Poststop => "poststop",
        }
    }

    /// Whether a failing hook aborts the operation (otherwise it only produces a warning).
    fn fatal(self) -> bool {
        !matches!(self, Self::Poststart | Self::Poststop)
    }

    /// The status the hooks of this phase see in their state.
    fn status(self) -> Status {
        match self {
            Self::Prestart | Self::CreateRuntime | Self::CreateContainer => Status::Creating,
            Self::StartContainer => Status::Created,
            Self::Poststart => Status::Running,
            Self::Poststop => Status::Stopped,
        }
    }

    fn hooks(self, spec: &Spec) -> &[Hook] {
        let Some(hooks) = spec.hooks() else { return &[] };
        let list = match self {
            Self::Prestart => hooks.prestart(),
            Self::CreateRuntime => hooks.create_runtime(),
            Self::CreateContainer => hooks.create_container(),
            Self::StartContainer => hooks.start_container(),
            Self::Poststart => hooks.poststart(),
            Self::Poststop => hooks.poststop(),
        };
        list.as_deref().unwrap_or_default()
    }
}

/// The OCI state passed to hooks: exactly the fields the spec defines, nothing hull-specific.
pub fn oci_state(state: &State, status: Status) -> Value {
    json!({
        "ociVersion": state.oci_version,
        "id": state.id,
        "status": status,
        "pid": state.pid,
        "bundle": state.bundle,
        "annotations": state.annotations,
    })
}

/// Run the hooks of `phase`, in order. For fatal phases the first failure is returned; for
/// `poststart` and `poststop` failures are logged and the remaining hooks still run.
pub fn run(phase: Phase, spec: &Spec, state: &State) -> Result<()> {
    let hooks = phase.hooks(spec);
    if hooks.is_empty() {
        return Ok(());
    }
    let input = oci_state(state, phase.status()).to_string();
    for (index, hook) in hooks.iter().enumerate() {
        if let Err(e) = run_one(hook, input.as_bytes()) {
            let error = Error::Hook {
                phase: phase.name(),
                index,
                path: hook.path().display().to_string(),
                message: crate::render_chain(&e),
            };
            if phase.fatal() {
                return Err(error);
            }
            tracing::warn!("{error} (continuing: {} failures are not fatal)", phase.name());
            eprintln!("hull-runtime: warning: {error}");
        }
    }
    Ok(())
}

fn run_one(hook: &Hook, input: &[u8]) -> Result<()> {
    let args = hook.args().as_deref().unwrap_or_default();
    let mut command = Command::new(hook.path());
    if let Some((argv0, rest)) = args.split_first() {
        command.arg0(argv0).args(rest);
    }
    command.env_clear();
    for entry in hook.env().iter().flatten() {
        if let Some((key, value)) = entry.split_once('=') {
            command.env(key, value);
        }
    }
    command.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    hull_sys::signal::clear_mask_in_child(&mut command);

    let mut child = command.spawn().context(|| format!("start {}", hook.path().display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A hook that never reads its input is allowed; ignore EPIPE.
        let _ = stdin.write_all(input);
    }
    let timeout = hook.timeout().and_then(|t| u64::try_from(t).ok()).map(Duration::from_secs);
    let (status, stderr) = wait(&mut child, timeout)?;
    if status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&stderr);
    let stderr = stderr.trim();
    Err(Error::Unsupported(if stderr.is_empty() {
        format!("{status}")
    } else {
        format!("{status}; stderr: {stderr}")
    }))
}

/// Wait for `child`, collecting its stderr, and kill it if it outlives `timeout`.
///
/// Waiting is a poll loop rather than a reader thread because hull-runtime never starts
/// threads (see `hull_sys::thread`).
fn wait(child: &mut Child, timeout: Option<Duration>) -> Result<(ExitStatus, Vec<u8>)> {
    let deadline = timeout.map(|t| Instant::now() + t);
    let mut stderr_pipe = child.stderr.take();
    let mut stderr = Vec::new();
    loop {
        if let Some(status) = child.try_wait().context(|| "wait for hook".into())? {
            if let Some(mut pipe) = stderr_pipe.take() {
                let _ = pipe.read_to_end(&mut stderr);
            }
            let keep = stderr.len().saturating_sub(STDERR_TAIL);
            return Ok((status, stderr.split_off(keep)));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = child.kill();
            let _ = child.wait();
            let seconds = timeout.unwrap_or_default().as_secs();
            return Err(Error::Unsupported(format!("timed out after {seconds}s and was killed")));
        }
        // Drain stderr while waiting, so a chatty hook cannot fill the pipe and stall.
        if let Some(pipe) = &mut stderr_pipe {
            let mut fds = [PollFd::new(pipe, PollFlags::IN)];
            let tick = Timespec { tv_sec: 0, tv_nsec: 20_000_000 };
            if rustix::event::poll(&mut fds, Some(&tick)).unwrap_or(0) > 0 {
                let mut chunk = [0u8; 4096];
                match pipe.read(&mut chunk) {
                    Ok(0) => stderr_pipe = None,
                    Ok(n) => stderr.extend_from_slice(&chunk[..n]),
                    Err(_) => {}
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
