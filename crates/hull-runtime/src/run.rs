//! Bringing a container into existence: `run` (foreground) and `create` (wait for `start`).
//!
//! Both share one spawn path. The parent:
//!
//! 1. Validates everything that can be validated before touching the system.
//! 2. Registers the container (state directory + lock).
//! 3. `clone3`s the init process into its namespaces.
//! 4. Drives the sync protocol (ID maps → `Continue` → `Ready`).
//!
//! What happens after `Ready` is the only difference:
//!
//! | | `run` | `create` |
//! |---|---|---|
//! | Init after `Ready` | `execve`s immediately | blocks on `exec.fifo` until `start` |
//! | The runtime process | forwards signals, waits, removes all state | records `created` and exits |
//! | Who reaps init | the runtime | whoever inherits it (the nearest subreaper; see `lifecycle`) |
//!
//! Why split `create` from `start` at all? Because the layers above need a gap between "the
//! namespaces exist" and "the program runs": containerd uses it to wire up networking in the new
//! network namespace, and the OCI `createRuntime`/`createContainer` hooks run in it.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use hull_spec::oci::{LinuxNamespaceType, Spec};
use hull_sys::clone::{ChildProcess, CloneArgs, Forked, Namespaces, clone3};
use hull_sys::signal::SigSet;
use rustix::event::{PollFd, PollFlags};
use rustix::fs::{CWD, FileType, Mode, OFlags};
use rustix::process::{Signal, WaitId, WaitIdOptions, WaitIdStatus};

use crate::init::{ChildContext, child_main};
use crate::procfs::ProcStat;
use crate::rootfs::RootfsPlan;
use crate::state::{ContainerDir, State, StateStore, Status};
use crate::sync::{ChildMessage, ParentMessage, SyncSocket};
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

/// Options for [`run`] and [`create`].
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
    let prepared = prepare(options)?;
    let dir = store.create(&options.id)?;
    let result = run_registered(&dir, &prepared, options);
    let cleanup = dir.destroy();
    let code = result?;
    cleanup?;
    Ok(code)
}

/// Create a container whose init waits for [`crate::lifecycle::start`]. Returns once the
/// container is in the `created` state; the container keeps existing after this process exits.
pub fn create(store: &StateStore, options: &RunOptions) -> Result<()> {
    let prepared = prepare(options)?;
    if !mounts_proc(&prepared.spec) {
        return Err(Error::Unsupported(
            "create needs a mount at /proc: init hands the exec FIFO across pivot_root through \
             /proc/self/fd (run does not need this)"
                .into(),
        ));
    }
    let dir = store.create(&options.id)?;
    let result = create_registered(&dir, &prepared, options);
    if result.is_err() {
        let _ = dir.destroy();
    }
    result
}

/// Everything validated and resolved before any side effect.
struct Prepared {
    spec: Spec,
    plan: RootfsPlan,
    namespaces: Namespaces,
}

fn prepare(options: &RunOptions) -> Result<Prepared> {
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
    let plan = RootfsPlan { bundle, rootfs, user_namespace: namespaces.contains(Namespaces::USER) };
    Ok(Prepared { spec, plan, namespaces })
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

fn mounts_proc(spec: &Spec) -> bool {
    spec.mounts()
        .iter()
        .flatten()
        .any(|m| hull_fs::clean_absolute(m.destination()) == Path::new("/proc"))
}

fn initial_state(dir: &ContainerDir, prepared: &Prepared) -> State {
    State {
        oci_version: prepared.spec.version().clone(),
        id: dir.id().to_string(),
        status: Status::Creating,
        pid: 0,
        bundle: prepared.plan.bundle.clone(),
        annotations: prepared
            .spec
            .annotations()
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        rootfs: prepared.plan.rootfs.clone(),
        created: crate::time::rfc3339(SystemTime::now()),
        init_start_time: None,
    }
}

fn run_registered(dir: &ContainerDir, prepared: &Prepared, options: &RunOptions) -> Result<i32> {
    let mut state = initial_state(dir, prepared);
    dir.save(&state)?;

    // Block the forwarded signals *before* clone3, so that none can arrive in the gap between
    // the child existing and the signalfd being read. The child unblocks them before execve.
    let forwarded = SigSet::of(&FORWARDED_SIGNALS);
    let previous_mask = hull_sys::signal::block(&forwarded).context(|| "block signals".into())?;
    let result = supervise_foreground(dir, &mut state, prepared, options, &forwarded);
    let restore =
        hull_sys::signal::set_mask(&previous_mask).context(|| "restore signal mask".into());
    let code = result?;
    restore?;
    Ok(code)
}

fn supervise_foreground(
    dir: &ContainerDir,
    state: &mut State,
    prepared: &Prepared,
    options: &RunOptions,
    forwarded: &SigSet,
) -> Result<i32> {
    let signals = hull_sys::signal::signalfd(forwarded).context(|| "create signalfd".into())?;
    let (mut init, sync) = spawn(dir, state, prepared, options, None)?;

    // Exec phase: EOF means execve succeeded and closed the child's (close-on-exec) socket.
    match sync.recv::<ChildMessage>(Some(options.setup_timeout)) {
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

fn create_registered(dir: &ContainerDir, prepared: &Prepared, options: &RunOptions) -> Result<()> {
    let mut state = initial_state(dir, prepared);
    dir.save(&state)?;
    let fifo = make_exec_fifo(&dir.exec_fifo())?;
    let (init, _sync) = spawn(dir, &mut state, prepared, options, Some(fifo.as_fd()))?;
    // Setup succeeded and the state says `created`. The container must outlive us now.
    init.release();
    Ok(())
}

/// Create the exec FIFO and return an `O_PATH` handle to it for the child.
fn make_exec_fifo(path: &Path) -> Result<OwnedFd> {
    // 0622: the container's process may run as any user by the time it opens the write end, but
    // only root (the runtime) may read, i.e. start the container.
    let mode = Mode::from_raw_mode(0o622);
    rustix::fs::mknodat(CWD, path, FileType::Fifo, mode, 0)
        .context(|| format!("create {}", path.display()))?;
    // mknod applies the umask, which would strip the write bits for other users.
    rustix::fs::chmod(path, mode).context(|| format!("chmod {}", path.display()))?;
    rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
        .context(|| format!("open {}", path.display()))
}

/// Clone the init process and drive the sync protocol until it reports `Ready`.
///
/// On success the state is saved as `created` (with `exec_fifo`) or `running` (without), and the
/// caller owns the returned [`Init`], which kills the process if dropped without being released.
fn spawn(
    dir: &ContainerDir,
    state: &mut State,
    prepared: &Prepared,
    options: &RunOptions,
    exec_fifo: Option<BorrowedFd<'_>>,
) -> Result<(Init, SyncSocket)> {
    let (parent_sock, child_sock) = crate::sync::pair().context(|| "create sync socket".into())?;

    // The child gets a copy of any unflushed output buffer; flush so nothing is printed twice.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    let child = match clone3(&CloneArgs { namespaces: prepared.namespaces, cgroup: None }) {
        Ok(Forked::Child) => {
            drop(parent_sock);
            child_main(&ChildContext {
                spec: &prepared.spec,
                rootfs: prepared.plan.clone(),
                sync: child_sock,
                exec_fifo: exec_fifo.map(|fd| fd.as_raw_fd()),
            })
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

    if prepared.namespaces.contains(Namespaces::USER) {
        let linux = prepared.spec.linux().as_ref();
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
    state.status = if exec_fifo.is_some() { Status::Created } else { Status::Running };
    dir.save(state)?;
    if let Some(pid_file) = &options.pid_file {
        write_pid_file(pid_file, pid)?;
    }
    Ok((init, parent_sock))
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
/// value is dropped before the process was reaped or deliberately released, it is killed and
/// reaped.
struct Init {
    child: ChildProcess,
    /// True once nothing is left to clean up: the process was reaped, or handed off on purpose.
    done: bool,
}

impl Init {
    fn new(child: ChildProcess) -> Self {
        Self { child, done: false }
    }

    /// Let the process live on after this handle (and this runtime process) are gone.
    fn release(mut self) {
        self.done = true;
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
                    self.done = true;
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

    fn wait_forwarding_signals(&mut self, signals: &OwnedFd) -> Result<WaitIdStatus> {
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
        if !self.done {
            self.signal(Signal::KILL);
            let _ = self.wait();
        }
    }
}
