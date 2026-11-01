//! Turning a directory into the container's `/`.
//!
//! This runs in the child, inside its new mount namespace, which starts as a *copy* of the host's
//! mount table. The sequence:
//!
//! 1. Make every mount in our copy a **slave**. Then nothing we mount or unmount propagates back
//!    to the host, but host changes can still flow in. Skip this and, on a systemd host where `/`
//!    is shared, the container's `/proc` would appear in the host's mount table.
//! 2. **Bind-mount the rootfs onto itself.** `pivot_root` requires the new root to be a mount
//!    point, and a plain directory usually is not one.
//! 3. Open a [`SafeRoot`] on the *new* mount and perform every `config.json` mount through it.
//! 4. Create the default devices.
//! 5. **`pivot_root(".", ".")`**: make the rootfs `/` and stack the old root on top of it, then
//!    detach the old root with `umount2(MNT_DETACH)`. After this, the host filesystem is
//!    unreachable by path. (`chroot` would leave it reachable: a process with `CAP_SYS_CHROOT` can
//!    walk back out with `..`.)
//! 6. Make `/` read-only if `root.readonly` is set.

use std::path::{Path, PathBuf};

use hull_fs::SafeRoot;
use hull_spec::oci::Spec;
use hull_sys::mount::{AttrChange, MountAttrs, Propagation, mount_setattr};
use rustix::fs::CWD;
use rustix::mount::{MountPropagationFlags, OpenTreeFlags, UnmountFlags};

use crate::devices::create_default_devices;
use crate::mounts::{attach, mount_entry};
use crate::{Context, Result};

/// Everything rootfs setup needs, resolved by the parent before `clone3`.
#[derive(Debug, Clone)]
pub struct RootfsPlan {
    /// Absolute host path of the bundle.
    pub bundle: PathBuf,
    /// Absolute host path of the root filesystem.
    pub rootfs: PathBuf,
    /// Whether a new user namespace is in use (selects bind-mounted devices).
    pub user_namespace: bool,
}

/// Build the root filesystem and switch into it.
pub fn setup(plan: &RootfsPlan, spec: &Spec) -> Result<()> {
    // 1. Stop propagation towards the host.
    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::DOWNSTREAM | MountPropagationFlags::REC,
    )
    .context(|| "make / a recursive slave mount".into())?;

    // 2. The rootfs becomes a mount point.
    bind_onto_itself(&plan.rootfs)?;
    if let Some(propagation) = spec.linux().as_ref().and_then(|l| l.rootfs_propagation().clone()) {
        apply_rootfs_propagation(&plan.rootfs, &propagation)?;
    }

    // 3. Opened *after* the bind mount, so it refers to the new mount and not the directory below.
    let root = SafeRoot::open(&plan.rootfs)
        .context(|| format!("open rootfs {}", plan.rootfs.display()))?;
    for mount in spec.mounts().iter().flatten() {
        // Validation already parsed every entry successfully; parse again to get the plan.
        let parsed = hull_spec::mounts::parse_mount(mount)
            .map_err(|e| crate::Error::Unsupported(format!("{e:?}")))?;
        mount_entry(&root, &plan.bundle, &parsed)?;
    }

    // 4. Devices. Re-open the root: /dev may now be a tmpfs mounted over the image's /dev.
    let root = SafeRoot::open(&plan.rootfs)
        .context(|| format!("reopen rootfs {}", plan.rootfs.display()))?;
    create_default_devices(&root, plan.user_namespace)?;

    // 5. Switch roots.
    pivot_into(&plan.rootfs)?;

    // 6. Read-only root. Not recursive: /proc, /dev etc. keep their own flags.
    if spec.root().as_ref().and_then(hull_spec::oci::Root::readonly).unwrap_or(false) {
        let root_fd = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .context(|| "open new /".into())?;
        let change = AttrChange { set: MountAttrs::RDONLY, ..AttrChange::default() };
        mount_setattr(std::os::fd::AsFd::as_fd(&root_fd), false, &change)
            .context(|| "make / read-only".into())?;
    }
    Ok(())
}

fn bind_onto_itself(rootfs: &Path) -> Result<()> {
    let tree = rustix::mount::open_tree(
        CWD,
        rootfs,
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_RECURSIVE,
    )
    .context(|| format!("clone rootfs mount {}", rootfs.display()))?;
    let target = rustix::fs::open(
        rootfs,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .context(|| format!("open {}", rootfs.display()))?;
    attach(std::os::fd::AsFd::as_fd(&tree), std::os::fd::AsFd::as_fd(&target))
        .context(|| format!("bind rootfs {} onto itself", rootfs.display()))
}

fn apply_rootfs_propagation(rootfs: &Path, propagation: &str) -> Result<()> {
    let (kind, recursive) = match propagation {
        "private" => (Propagation::Private, false),
        "rprivate" => (Propagation::Private, true),
        "slave" => (Propagation::Slave, false),
        "rslave" => (Propagation::Slave, true),
        "shared" => (Propagation::Shared, false),
        "rshared" => (Propagation::Shared, true),
        "unbindable" => (Propagation::Unbindable, false),
        // Validation guarantees nothing else reaches this point.
        _ => (Propagation::Unbindable, true),
    };
    let fd = rustix::fs::open(
        rootfs,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .context(|| format!("open {}", rootfs.display()))?;
    let change = AttrChange { propagation: Some(kind), ..AttrChange::default() };
    mount_setattr(std::os::fd::AsFd::as_fd(&fd), recursive, &change)
        .context(|| format!("set rootfs propagation {propagation}"))
}

fn pivot_into(rootfs: &Path) -> Result<()> {
    rustix::process::chdir(rootfs).context(|| format!("chdir {}", rootfs.display()))?;
    rustix::process::pivot_root(".", ".")
        .context(|| format!("pivot_root into {}", rootfs.display()))?;
    // The old root is now stacked on top of "/". Detach it (lazily, since the host's mounts are
    // still in use by other processes; MNT_DETACH just removes them from *our* view).
    rustix::mount::unmount(".", UnmountFlags::DETACH).context(|| "detach old root".into())?;
    rustix::process::chdir("/").context(|| "chdir /".into())
}
