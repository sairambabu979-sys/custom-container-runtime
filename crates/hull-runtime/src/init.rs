//! The container's init process: everything between `clone3` and `execve`.
//!
//! This code runs in the child. It is a copy of the runtime's memory, so it can use the same data
//! structures, but it must never *return* into the runtime's code paths: those belong to the parent
//! and would, for example, delete the container's state directory. [`child_main`] therefore
//! returns `!`. It ends in `execve` or in `_exit`, with panics caught and reported the same way as
//! errors.

use std::convert::Infallible;
use std::panic::{AssertUnwindSafe, catch_unwind};

use hull_spec::oci::Spec;
use hull_sys::signal::SigSet;
use rustix::io::Errno;
use rustix::process::{DumpableBehavior, Gid, Signal, Uid};

use crate::process::ExecPlan;
use crate::rootfs::RootfsPlan;
use crate::sync::{ChildMessage, InitError, ParentMessage, Stage, SyncSocket};
use crate::{Context, Error, Result, render_chain};

/// What the child needs, prepared by the parent before `clone3`.
#[derive(Debug)]
pub(crate) struct ChildContext<'a> {
    pub spec: &'a Spec,
    pub rootfs: RootfsPlan,
    pub sync: SyncSocket,
    /// For `create`: the descriptor number of an `O_PATH` handle to `exec.fifo`, inherited from
    /// the parent. `None` for `run`, which execs as soon as setup is done.
    pub exec_fifo: Option<i32>,
}

/// Entry point of the child after `clone3`. Never returns.
pub(crate) fn child_main(ctx: &ChildContext<'_>) -> ! {
    let error = match catch_unwind(AssertUnwindSafe(|| run(ctx))) {
        Ok(Ok(never)) => match never {},
        Ok(Err(error)) => error,
        Err(panic) => InitError {
            stage: Stage::Exec,
            message: format!("container init panicked: {}", panic_message(panic.as_ref())),
            exit_code: None,
        },
    };
    // After `create` has returned, the parent is gone and the socket is closed. Then the only
    // place left to report to is the container's own stderr (the caller of `create`'s stderr).
    if ctx.sync.send(&ChildMessage::Failed(error.clone())).is_err() {
        eprintln!("hull-runtime: container init failed during {}: {}", error.stage, error.message);
    }
    hull_sys::exec::exit_immediately(error.exit_code.unwrap_or(1))
}

fn run(ctx: &ChildContext<'_>) -> Result<Infallible, InitError> {
    let at =
        |stage| move |e: Error| InitError { stage, message: render_chain(&e), exit_code: None };

    join_parent(ctx).map_err(at(Stage::Namespaces))?;
    crate::rootfs::setup(&ctx.rootfs, ctx.spec)
        .map_err(|e| explain_userns_permission_error(e, ctx.rootfs.user_namespace))
        .map_err(at(Stage::Rootfs))?;
    let process = ctx.spec.process().as_ref().ok_or_else(|| InitError {
        stage: Stage::Process,
        message: "config has no process".into(),
        exit_code: None,
    })?;
    let plan = crate::process::prepare(process).map_err(at(Stage::Process))?;

    // From here on the container must outlive the runtime process: `create` exits as soon as it
    // reads Ready. A parent-death signal still armed at that moment would kill the container.
    rustix::process::set_parent_process_death_signal(None).map_err(|e| {
        at(Stage::Process)(Error::Io {
            context: "clear parent-death signal".into(),
            source: e.into(),
        })
    })?;
    ctx.sync.send(&ChildMessage::Ready).map_err(|e| InitError {
        stage: Stage::Exec,
        message: e.to_string(),
        exit_code: None,
    })?;
    if let Some(fifo) = ctx.exec_fifo {
        wait_for_start(fifo).map_err(at(Stage::Start))?;
    }
    Err(exec(&plan))
}

/// Block until `hull-runtime start` opens the read end of the exec FIFO, then tell it we are going.
///
/// The FIFO lives in the state directory on the host, which no path can reach after `pivot_root`.
/// The parent therefore opened it with `O_PATH` before `clone3`. That descriptor still refers to
/// the FIFO, and reopening it through the `/proc/self/fd` magic link turns it into a real write end.
/// (This is the one place where following a magic link is the point, so it does not go through
/// `SafeRoot`.) Opening a FIFO for writing blocks until there is a reader, and that blocking *is*
/// the wait for `start`.
fn wait_for_start(fifo: i32) -> Result<()> {
    use std::io::Write as _;
    let path = format!("/proc/self/fd/{fifo}");
    let mut file = loop {
        match std::fs::OpenOptions::new().write(true).open(&path) {
            Ok(file) => break file,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context(|| format!("reopen exec FIFO via {path}")),
        }
    };
    file.write_all(b"0").context(|| "signal start over the exec FIFO".into())
}

/// Wait for the parent, then take on the namespace's identity and hostname.
fn join_parent(ctx: &ChildContext<'_>) -> Result<()> {
    // If the runtime dies while we are half set up, die with it instead of lingering.
    rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
        .context(|| "set parent-death signal".into())?;
    // Until execve, nobody in the container may ptrace us or open /proc/<our pid>/exe, which
    // still points at the runtime binary on the host (the CVE-2019-5736 attack surface).
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .context(|| "mark init non-dumpable".into())?;

    match ctx.sync.recv::<ParentMessage>(None) {
        Ok(Some(ParentMessage::Continue)) => {}
        Ok(None) => {
            return Err(Error::Unsupported("runtime exited before setup could continue".into()));
        }
        Err(e) => return Err(Error::Unsupported(e.to_string())),
    }

    if ctx.rootfs.user_namespace {
        // Right after the maps are written we are an *unmapped* host root: full capabilities in
        // the new namespace, but files we create would have no valid owner (EOVERFLOW). Become
        // the namespace's root properly. Validation guarantees that id 0 is mapped.
        let root_group = Gid::from_raw(0);
        let root_user = Uid::from_raw(0);
        rustix::thread::set_thread_res_gid(root_group, root_group, root_group)
            .context(|| "setresgid 0 in user namespace".into())?;
        rustix::thread::set_thread_res_uid(root_user, root_user, root_user)
            .context(|| "setresuid 0 in user namespace".into())?;
    }

    if let Some(hostname) = ctx.spec.hostname().as_deref().filter(|h| !h.is_empty()) {
        rustix::system::sethostname(hostname.as_bytes())
            .context(|| format!("sethostname {hostname:?}"))?;
    }
    if let Some(domain) = ctx.spec.domainname().as_deref().filter(|d| !d.is_empty()) {
        rustix::system::setdomainname(domain.as_bytes())
            .context(|| format!("setdomainname {domain:?}"))?;
    }
    Ok(())
}

/// The point of no return. Only returns (with the error) if `execve` fails.
fn exec(plan: &ExecPlan) -> InitError {
    // A clean signal state: nothing ignored, nothing blocked (see hull_sys::signal for why).
    hull_sys::signal::reset_dispositions();
    if let Err(e) = hull_sys::signal::set_mask(&SigSet::empty()) {
        return InitError {
            stage: Stage::Exec,
            message: format!("unblock signals: {e}"),
            exit_code: None,
        };
    }
    if let Err(e) = hull_sys::fd::set_cloexec_from(3) {
        return InitError {
            stage: Stage::Exec,
            message: format!("close_range: {e}"),
            exit_code: None,
        };
    }

    let error = hull_sys::exec::execve(&plan.path, &plan.argv, &plan.envp);
    // The shell convention, which Docker also follows: 127 "not found", 126 "found but not
    // executable".
    let errno = error.raw_os_error().map(Errno::from_raw_os_error);
    let exit_code = match errno {
        Some(Errno::NOENT) => 127,
        _ => 126,
    };
    InitError {
        stage: Stage::Exec,
        message: format!("exec {}: {error}", plan.path.to_string_lossy()),
        exit_code: Some(exit_code),
    }
}

/// "Permission denied" while building the rootfs inside a user namespace almost always means the
/// rootfs is owned by a host user that is not mapped into the container. Root inside the
/// namespace has no power over unmapped files, which surprises everyone the first time.
fn explain_userns_permission_error(error: Error, user_namespace: bool) -> Error {
    match error {
        Error::Io { context, source }
            if user_namespace && source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            Error::Io {
                context: format!(
                    "{context} (in a user namespace the rootfs must be owned by an id that is mapped \
                     into the container, e.g. `chown -R <hostID>:<hostID> rootfs`)"
                ),
                source,
            }
        }
        other => other,
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_owned()
    }
}
