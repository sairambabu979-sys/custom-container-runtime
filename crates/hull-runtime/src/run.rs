//! `hull-runtime run`: create a container, run its process in the foreground, clean up.
//!
//! This is the parent side. Its job, in order:
//!
//! 1. Validate everything that can be validated before touching the system.
//! 2. Register the container (state directory + lock).
//! 3. Block the signals it will forward, *before* `clone3`, so no signal can slip through a gap.
//! 4. `clone3` the init process into its namespaces.
//! 5. Drive the sync protocol (ID maps → `Continue` → `Ready` → EOF).
//! 6. Forward signals to the container and wait for it to exit.
//! 7. Remove all state, on success and on every error path.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use hull_spec::oci::{LinuxNamespaceType, Spec};
use hull_sys::clone::{ChildProcess, CloneArgs, Forked, Namespaces, clone3};
use hull_sys::signal::SigSet;
use rustix::event::{PollFd, PollFlags};
use rustix::process::{Signal, WaitId, WaitIdOptions, WaitIdStatus};

use crate::init::{ChildContext, child_main};
use crate::procfs::ProcStat;
use crate::rootfs::RootfsPlan;
use crate::state::{ContainerDir, State, StateStore, Status};
use crate::sync::{ChildMessage, ParentMessage};
use crate::{ContainerId, Context, Error, Result};

/// Signals the runtime relays to the container while it runs in the foreground.
const FORWARDED_SIGNALS: [i32; 6] = [
    libc_signal::SIGHUP,
    libc_signal::SIGINT,
    libc_signal::SIGQUIT,
    libc_signal::SIGTERM,
    libc_signal::SIGUSR1,
    libc_signal::SIGUSR2,
];

/// After this many Ctrl-C presses, stop forwarding politely and kill the container.
const INTERRUPTS_BEFORE_KILL: u32 = 3;

/// Signal numbers, so this crate does not need `libc` itself.
mod libc_signal {
    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGQUIT: i32 = 3;
    pub const SIGUSR1: i32 = 10;
    pub const SIGUSR2: i32 = 12;
    pub const SIGTERM: i32 = 15;
}

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// The container ID.
    pub id: ContainerId,
    /// The bundle directory (contains `config.json`).
    pub bundle: PathBuf,
    /// Where to write the init process's PID, if anywhere.
    pub pid_file: Option<PathBuf>,
    /// How long container setup may take before it is aborted.
    pub setup_timeout: Duration,
}

/// Run a container in the foreground and return the exit code the runtime should exit with.
pub fn run(store: &StateStore, options: &RunOptions) -> Result<i32> {
    if !rustix::process::geteuid().is_root() {
        return Err(Error::Unsupported(
            "hull-runtime must run as root for now (rootless containers are milestone M5)".into(),
        ));
    }
    let bundle = std::fs::canonicalize(&options.bundle)
        .context(|| format!("resolve bundle {}", options.bundle.display()))?;
    let loaded = hull_spec::load(&bundle.join("config.json"))?;
    for field in &loaded.unknown_fields {
        tracing::warn!("ignoring unknown config property {field:?}");
    }
    let spec = loaded.spec;
    hull_spec::validate(&spec)?;
    let rootfs = resolve_rootfs(&bundle, &spec)?;
    let namespaces = namespace_flags(&spec);

    let dir = store.create(&options.id)?;
    let plan = RootfsPlan { bundle, rootfs, user_namespace: namespaces.contains(Namespaces::USER) };
    let result = run_registered(&dir, &spec, plan, namespaces, options);
    let cleanup = dir.destroy();
    let code = result?;
    cleanup?;
    Ok(code)
}

fn resolve_rootfs(bundle: &Path, spec: &Spec) -> Result<PathBuf> {
    let root =
        spec.root().as_ref().ok_or_else(|| Error::Unsupported("config has no root".into()))?;
    let path = bundle.join(root.path());
    let rootfs =
        std::fs::canonicalize(&path).context(|| format!("resolve rootfs {}", path.display()))?;
    if !rootfs.is_dir() {
        return Err(Error::Unsupported(format!("rootfs {} is not a directory", rootfs.display())));
    }
    Ok(rootfs)
}

fn namespace_flags(spec: &Spec) -> Namespaces {
    let mut flags = Namespaces::empty();
    let list = spec.linux().as_ref().and_then(|l| l.namespaces().clone()).unwrap_or_default();
    for ns in list {
        flags |= match ns.typ() {
            LinuxNamespaceType::Mount => Namespaces::MOUNT,
            LinuxNamespaceType::Cgroup => Namespaces::CGROUP,
            LinuxNamespaceType::Uts => Namespaces::UTS,
            LinuxNamespaceType::Ipc => Namespaces::IPC,
            LinuxNamespaceType::User => Namespaces::USER,
            LinuxNamespaceType::Pid => Namespaces::PID,
            LinuxNamespaceType::Network => Namespaces::NET,
            LinuxNamespaceType::Time => Namespaces::TIME,
        };
    }
    flags
}

fn run_registered(
    dir: &ContainerDir,
    spec: &Spec,
    plan: RootfsPlan,
    namespaces: Namespaces,
    options: &RunOptions,
) -> Result<i32> {
    let mut state = State {
        oci_version: spec.version().clone(),
        id: dir.id().to_string(),
        status: Status::Creating,
        pid: 0,
        bundle: plan.bundle.clone(),
        annotations: spec
            .annotations()
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        rootfs: plan.rootfs.clone(),
        created: crate::time::rfc3339(SystemTime::now()),
        init_start_time: None,
    };
    dir.save(&state)?;

    let forwarded = SigSet::of(&FORWARDED_SIGNALS);
    let previous_mask = hull_sys::signal::block(&forwarded).context(|| "block signals".into())?;
    let result = spawn_and_supervise(dir, &mut state, spec, plan, namespaces, options, &forwarded);
    let restore =
        hull_sys::signal::set_mask(&previous_mask).context(|| "restore signal mask".into());
    let code = result?;
    restore?;
    Ok(code)
}

fn spawn_and_supervise(
    dir: &ContainerDir,
    state: &mut State,
    spec: &Spec,
    plan: RootfsPlan,
    namespaces: Namespaces,
    options: &RunOptions,
    forwarded: &SigSet,
) -> Result<i32> {
    let signals = hull_sys::signal::signalfd(forwarded).context(|| "create signalfd".into())?;
    let (parent_sock, child_sock) = crate::sync::pair().context(|| "create sync socket".into())?;

    // The child gets a copy of any unflushed output buffer; flush so nothing is printed twice.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    let child = match clone3(&CloneArgs { namespaces, cgroup: None }) {
        Ok(Forked::Child) => {
            drop(parent_sock);
            drop(signals);
            child_main(&ChildContext { spec, rootfs: plan, sync: child_sock })
        }
        Ok(Forked::Parent(child)) => child,
        Err(e) => {
            return Err(Error::Io {
                context: "create container init".into(),
                source: std::io::Error::other(e),
            });
        }
    };
    // Close our copy of the child's end, or we would never see EOF on ours.
    drop(child_sock);
    let mut init = Init::new(child);
    tracing::debug!(pid = init.child.pid.as_raw_nonzero().get(), "init process created");

    if namespaces.contains(Namespaces::USER) {
        let linux = spec.linux().as_ref();
        let uid = linux.and_then(|l| l.uid_mappings().clone()).unwrap_or_default();
        let gid = linux.and_then(|l| l.gid_mappings().clone()).unwrap_or_default();
        crate::idmap::write_id_maps(init.child.pid, &uid, &gid)?;
    }
    parent_sock.send(&ParentMessage::Continue).map_err(|e| sync_error(&e))?;

    // Setup phase: the child either reports Ready or explains why it failed.
    match parent_sock.recv::<ChildMessage>(Some(options.setup_timeout)) {
        Ok(Some(ChildMessage::Ready)) => {}
        Ok(Some(ChildMessage::Failed(e))) => return Err(init.failed(e)),
        Ok(None) => return Err(Error::InitVanished(init.reap_description())),
        Err(e) => return Err(sync_error(&e)),
    }

    let pid = init.child.pid.as_raw_nonzero().get();
    state.pid = pid;
    state.init_start_time =
        Some(ProcStat::read(pid).context(|| format!("read /proc/{pid}/stat"))?.start_time);
    state.status = Status::Running;
    dir.save(state)?;
    if let Some(pid_file) = &options.pid_file {
        write_pid_file(pid_file, pid)?;
    }

    // Exec phase: EOF means execve succeeded and closed the child's (close-on-exec) socket.
    match parent_sock.recv::<ChildMessage>(Some(options.setup_timeout)) {
        Ok(None) => {}
        Ok(Some(ChildMessage::Failed(e))) => return Err(init.failed(e)),
        Ok(Some(ChildMessage::Ready)) => {
            return Err(Error::Unsupported("sync protocol violation: second Ready".into()));
        }
        Err(e) => return Err(sync_error(&e)),
    }

    let status = init.wait_forwarding_signals(&signals)?;
    state.status = Status::Stopped;
    dir.save(state)?;
    Ok(exit_code(&status))
}

fn sync_error(e: &crate::sync::SyncError) -> Error {
    Error::Io {
        context: "communicate with container init".into(),
        source: std::io::Error::other(e.to_string()),
    }
}

fn write_pid_file(path: &Path, pid: i32) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Unsupported(format!("bad pid file path {}", path.display())))?;
    hull_fs::atomic_write(dir, name, pid.to_string().as_bytes())
        .context(|| format!("write pid file {}", path.display()))
}

/// Shell convention: the exit status, or 128 + the signal number for a killed process.
fn exit_code(status: &WaitIdStatus) -> i32 {
    if let Some(code) = status.exit_status() {
        code
    } else if let Some(signal) = status.terminating_signal() {
        128 + signal
    } else {
        255
    }
}

/// The parent's handle on the init process. Whatever happens, it never leaks the process: if this
/// value is dropped before the process was reaped, it is killed and reaped.
struct Init {
    child: ChildProcess,
    reaped: bool,
}

impl Init {
    fn new(child: ChildProcess) -> Self {
        Self { child, reaped: false }
    }

    fn signal(&self, signal: Signal) {
        if let Err(e) = rustix::process::pidfd_send_signal(&self.child.pidfd, signal) {
            tracing::debug!("signal {signal:?} to init failed: {e}");
        }
    }

    fn wait(&mut self) -> Result<WaitIdStatus> {
        loop {
            match rustix::process::waitid(
                WaitId::PidFd(self.child.pidfd.as_fd()),
                WaitIdOptions::EXITED,
            ) {
                Ok(Some(status)) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Ok(None) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e).context(|| "wait for container init".into()),
            }
        }
    }

    /// The child reported a setup failure; reap it and turn the report into an error.
    fn failed(&mut self, e: crate::sync::InitError) -> Error {
        let _ = self.wait();
        Error::Init { stage: e.stage, message: e.message, exit_code: e.exit_code }
    }

    fn reap_description(&mut self) -> String {
        match self.wait() {
            Ok(status) => format!("exit code {}", exit_code(&status)),
            Err(e) => e.to_string(),
        }
    }

    fn wait_forwarding_signals(&mut self, signals: &std::os::fd::OwnedFd) -> Result<WaitIdStatus> {
        let mut interrupts = 0;
        loop {
            let mut fds = [
                PollFd::new(&self.child.pidfd, PollFlags::IN),
                PollFd::new(signals, PollFlags::IN),
            ];
            match rustix::event::poll(&mut fds, None) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e).context(|| "poll".into()),
            }
            let exited = fds[0].revents().contains(PollFlags::IN);
            let signalled = fds[1].revents().contains(PollFlags::IN);
            if signalled {
                let number = hull_sys::signal::read_signalfd(signals.as_fd())
                    .context(|| "read signalfd".into())?;
                if number == libc_signal::SIGINT {
                    interrupts += 1;
                }
                if interrupts >= INTERRUPTS_BEFORE_KILL {
                    tracing::warn!("received {interrupts} interrupts; killing the container");
                    self.signal(Signal::KILL);
                } else if let Some(signal) = Signal::from_named_raw(number) {
                    tracing::debug!("forwarding signal {number} to the container");
                    self.signal(signal);
                }
            }
            if exited {
                return self.wait();
            }
        }
    }
}

impl Drop for Init {
    fn drop(&mut self) {
        if !self.reaped {
            self.signal(Signal::KILL);
            let _ = self.wait();
        }
    }
}
