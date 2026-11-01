//! Performing the mounts listed in `config.json` with the kernel's fd-based mount API.
//!
//! The classic `mount(2)` takes two path strings. Between the moment the runtime checks a
//! destination and the moment the kernel resolves it again inside `mount(2)`, a process in the
//! container can swap a directory for a symlink. That race is CVE-2021-30465.
//!
//! The new API (Linux 5.2) splits mounting into steps that pass file descriptors around:
//!
//! ```text
//!  fsopen("tmpfs") ──► fsconfig(mode=755, ...) ──► fsconfig(CREATE) ──► fsmount() ─┐
//!                                                                                  ├─► mnt_fd
//!  open_tree("/host/src", OPEN_TREE_CLONE)  (bind mounts) ─────────────────────────┘
//!
//!  mount_setattr(mnt_fd, ro/nosuid/...)            configure while detached and invisible
//!  target_fd = SafeRoot::mkdir_all(destination)   resolve once, inside the rootfs
//!  move_mount(mnt_fd ──► target_fd)                attach: no path is resolved here at all
//! ```

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use hull_fs::SafeRoot;
use hull_spec::mounts::{FsOption, MountKind, ParsedMount};
use hull_sys::mount::{AttrChange, mount_setattr};
use rustix::fs::{CWD, Mode};
use rustix::mount::{FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, OpenTreeFlags};

use crate::{Context, Error, Result};

/// Mount one entry inside `root`. Relative bind sources are resolved against `bundle`.
pub fn mount_entry(root: &SafeRoot, bundle: &Path, m: &ParsedMount) -> Result<()> {
    let dest = m.destination.display();
    let (mnt, source_is_dir) = match &m.kind {
        MountKind::Filesystem { fstype } => (create_filesystem(fstype, m)?, true),
        MountKind::Bind { recursive } => {
            let source = bind_source(bundle, m)?;
            let mut flags = OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC;
            if *recursive {
                flags |= OpenTreeFlags::AT_RECURSIVE;
            }
            let tree = rustix::mount::open_tree(CWD, &source, flags)
                .context(|| format!("clone mount tree at {}", source.display()))?;
            let is_dir = std::fs::metadata(&source)
                .context(|| format!("stat bind source {}", source.display()))?
                .is_dir();
            (tree, is_dir)
        }
    };

    // Configure the detached mount before anyone can see it.
    let without_propagation = AttrChange { propagation: None, ..m.attrs };
    mount_setattr(mnt.as_fd(), false, &without_propagation)
        .context(|| format!("set attributes on mount for {dest}"))?;
    mount_setattr(mnt.as_fd(), true, &m.recursive_attrs)
        .context(|| format!("set recursive attributes on mount for {dest}"))?;

    // Resolve (and create) the destination exactly once, inside the rootfs.
    let target = if source_is_dir {
        root.mkdir_all(&m.destination, Mode::from_raw_mode(0o755))
    } else {
        root.ensure_file(&m.destination, Mode::from_raw_mode(0o644))
    }
    .context(|| format!("prepare mount destination {dest}"))?;

    attach(mnt.as_fd(), target.as_fd()).context(|| format!("attach mount at {dest}"))?;

    // Propagation can only be changed once the mount is attached to a namespace.
    if let Some((propagation, recursive)) = m.propagation {
        let change = AttrChange { propagation: Some(propagation), ..AttrChange::default() };
        mount_setattr(mnt.as_fd(), recursive, &change)
            .context(|| format!("set propagation on {dest}"))?;
    }
    Ok(())
}

/// Attach the detached mount `mnt` on top of `target`, both given as file descriptors.
pub fn attach(mnt: BorrowedFd<'_>, target: BorrowedFd<'_>) -> rustix::io::Result<()> {
    rustix::mount::move_mount(
        mnt,
        "",
        target,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
}

fn bind_source(bundle: &Path, m: &ParsedMount) -> Result<PathBuf> {
    let source = m
        .source
        .as_deref()
        .ok_or_else(|| Error::Unsupported("bind mount without source".into()))?;
    Ok(if source.is_absolute() { source.to_owned() } else { bundle.join(source) })
}

fn create_filesystem(fstype: &str, m: &ParsedMount) -> Result<OwnedFd> {
    let fs = rustix::mount::fsopen(fstype, FsOpenFlags::FSOPEN_CLOEXEC)
        .context(|| format!("fsopen({fstype:?})"))?;
    let source = m.source.as_deref().map_or_else(|| fstype.to_owned(), |s| s.display().to_string());
    configure(&fs, "source", Some(&source), fstype)?;
    for option in &m.fs_options {
        match option {
            FsOption::Flag(key) => configure(&fs, key, None, fstype)?,
            FsOption::Value(key, value) => configure(&fs, key, Some(value), fstype)?,
        }
    }
    rustix::mount::fsconfig_create(&fs)
        .map_err(|e| kernel_message(&fs, e))
        .context(|| format!("create {fstype} filesystem"))?;

    // Attributes known now are passed to fsmount; the rest are applied with mount_setattr.
    let attrs = MountAttrFlags::from_bits_retain(u32::try_from(m.attrs.set.bits()).unwrap_or(0));
    rustix::mount::fsmount(&fs, FsMountFlags::FSMOUNT_CLOEXEC, attrs)
        .context(|| format!("fsmount {fstype}"))
}

fn configure(fs: &OwnedFd, key: &str, value: Option<&str>, fstype: &str) -> Result<()> {
    let result = match value {
        Some(value) => rustix::mount::fsconfig_set_string(fs, key, value),
        None => rustix::mount::fsconfig_set_flag(fs, key),
    };
    result.map_err(|e| kernel_message(fs, e)).context(|| match value {
        Some(value) => format!("{fstype}: set {key}={value}"),
        None => format!("{fstype}: set {key}"),
    })
}

/// The new mount API lets the kernel explain *why* an `fsconfig` call failed: it queues
/// human-readable messages that are read from the filesystem-context fd. Fold them into the error.
fn kernel_message(fs: &OwnedFd, errno: rustix::io::Errno) -> std::io::Error {
    let mut messages = Vec::new();
    let mut buf = [0u8; 512];
    while let Ok(n) = rustix::io::read(fs, &mut buf) {
        if n == 0 {
            break;
        }
        // Each message is "e <text>", "w <text>" or "i <text>" (error/warning/info).
        messages.push(String::from_utf8_lossy(&buf[..n]).trim().to_owned());
    }
    let base = std::io::Error::from(errno);
    if messages.is_empty() {
        base
    } else {
        std::io::Error::new(base.kind(), format!("{base} (kernel says: {})", messages.join("; ")))
    }
}
