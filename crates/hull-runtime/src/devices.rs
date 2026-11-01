//! The device nodes and `/dev` symlinks every OCI container gets.
//!
//! The runtime spec requires these regardless of `config.json` (runtime-spec `config-linux.md`,
//! "Default Devices"). Without `/dev/null`, a surprising amount of software breaks.
//!
//! Inside a user namespace, `mknod` is not allowed (device access is checked against the *host*
//! user namespace), so the host's nodes are bind-mounted instead. That is also how rootless
//! containers get their devices.

use std::path::Path;

use hull_fs::SafeRoot;
use rustix::fs::{FileType, Mode};

use crate::mounts::attach;
use crate::{Context, Result};

/// A character device the container gets by default.
struct Device {
    path: &'static str,
    major: u32,
    minor: u32,
}

/// In runc's order, so that differential tests can compare mount tables entry by entry.
const DEFAULT_DEVICES: [Device; 6] = [
    Device { path: "/dev/null", major: 1, minor: 3 },
    Device { path: "/dev/random", major: 1, minor: 8 },
    Device { path: "/dev/full", major: 1, minor: 7 },
    Device { path: "/dev/tty", major: 5, minor: 0 },
    Device { path: "/dev/zero", major: 1, minor: 5 },
    Device { path: "/dev/urandom", major: 1, minor: 9 },
];

/// Symlinks that make `/dev/fd/N`, `/dev/stdin` and friends work.
const DEFAULT_SYMLINKS: [(&str, &str); 4] = [
    ("/proc/self/fd", "/dev/fd"),
    ("/proc/self/fd/0", "/dev/stdin"),
    ("/proc/self/fd/1", "/dev/stdout"),
    ("/proc/self/fd/2", "/dev/stderr"),
];

/// Create the default devices and symlinks inside `root`.
///
/// `bind_from_host` selects bind-mounting instead of `mknod` (required in a user namespace).
pub fn create_default_devices(root: &SafeRoot, bind_from_host: bool) -> Result<()> {
    for device in &DEFAULT_DEVICES {
        if bind_from_host {
            bind_host_device(root, device)?;
        } else {
            make_node(root, device)?;
        }
    }
    for (target, link) in DEFAULT_SYMLINKS {
        root.symlink(Path::new(target), Path::new(link))
            .context(|| format!("symlink {link} -> {target}"))?;
    }
    // runc adds /dev/core when the host has /proc/kcore (this runs before pivot_root, so the
    // path is the host's). The differential test on a CI host caught its absence.
    if Path::new("/proc/kcore").exists() {
        root.symlink(Path::new("/proc/kcore"), Path::new("/dev/core"))
            .context(|| "symlink /dev/core -> /proc/kcore".into())?;
    }
    // The container gets its own pseudo-terminal multiplexer from its private devpts instance.
    if root.resolve(Path::new("/dev/pts/ptmx")).is_ok() {
        root.symlink(Path::new("pts/ptmx"), Path::new("/dev/ptmx"))
            .context(|| "symlink /dev/ptmx -> pts/ptmx".into())?;
    }
    Ok(())
}

fn make_node(root: &SafeRoot, device: &Device) -> Result<()> {
    let (dir, name) =
        root.parent_of(Path::new(device.path)).context(|| format!("prepare {}", device.path))?;
    // If the image ships a regular file here, replace it with the real device.
    match rustix::fs::unlinkat(&dir, &name, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(e).context(|| format!("remove existing {}", device.path)),
    }
    let dev = rustix::fs::makedev(device.major, device.minor);
    let mode = Mode::from_raw_mode(0o666);
    rustix::fs::mknodat(&dir, &name, FileType::CharacterDevice, mode, dev)
        .context(|| format!("mknod {}", device.path))?;
    // mknod applies the umask; set the intended mode explicitly.
    rustix::fs::chmodat(&dir, &name, mode, rustix::fs::AtFlags::empty())
        .context(|| format!("chmod {}", device.path))
}

fn bind_host_device(root: &SafeRoot, device: &Device) -> Result<()> {
    let flags = rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
        | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC;
    let mnt = rustix::mount::open_tree(rustix::fs::CWD, device.path, flags)
        .context(|| format!("clone host {}", device.path))?;
    let target = root
        .ensure_file(Path::new(device.path), Mode::from_raw_mode(0o666))
        .context(|| format!("create mount point {}", device.path))?;
    attach(std::os::fd::AsFd::as_fd(&mnt), std::os::fd::AsFd::as_fd(&target))
        .context(|| format!("bind host {}", device.path))
}
