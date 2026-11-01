//! `mount_setattr(2)` (Linux 5.12).
//!
//! The old `mount(2)` API needs a separate "remount" call to make a bind mount read-only, and it
//! cannot change flags on a whole mount tree at once. `mount_setattr` changes the attributes and
//! the propagation type of a mount, optionally recursively, and it works on an fd, so it can act on
//! a *detached* mount (one created by `open_tree` or `fsmount` that is not attached anywhere yet).
//! Setting flags before attaching means the mount is never visible in a half-configured state.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use bitflags::bitflags;

bitflags! {
    /// Per-mount attributes (`MOUNT_ATTR_*` from `<linux/mount.h>`).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct MountAttrs: u64 {
        /// Read-only.
        const RDONLY = 0x0000_0001;
        /// Ignore set-user-ID and set-group-ID bits.
        const NOSUID = 0x0000_0002;
        /// Disallow access to device special files.
        const NODEV = 0x0000_0004;
        /// Disallow program execution.
        const NOEXEC = 0x0000_0008;
        /// The access-time mode field (two bits). Clear it before setting one of the modes below.
        const ATIME_MASK = 0x0000_0070;
        /// Update atime relative to mtime/ctime (the kernel default; value 0 within the mask).
        const RELATIME = 0x0000_0000;
        /// Never update atime.
        const NOATIME = 0x0000_0010;
        /// Always update atime.
        const STRICTATIME = 0x0000_0020;
        /// Do not update directory access times.
        const NODIRATIME = 0x0000_0080;
        /// Idmapped mount (milestone M5).
        const IDMAP = 0x0010_0000;
        /// Do not follow symlinks.
        const NOSYMFOLLOW = 0x0020_0000;
    }
}

/// A mount propagation type (`mount_namespaces(7)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Propagation {
    /// Events neither propagate to nor from peers.
    Private,
    /// Events propagate in both directions within the peer group.
    Shared,
    /// Events propagate from the master into this mount, never back out.
    Slave,
    /// Private, and the mount cannot be the source of a bind mount.
    Unbindable,
}

impl Propagation {
    fn as_raw(self) -> u64 {
        let flag = match self {
            Self::Private => libc::MS_PRIVATE,
            Self::Shared => libc::MS_SHARED,
            Self::Slave => libc::MS_SLAVE,
            Self::Unbindable => libc::MS_UNBINDABLE,
        };
        // `c_ulong` is 32 bits on 32-bit targets, so the conversion is not always a no-op.
        #[allow(clippy::useless_conversion)]
        u64::from(flag)
    }
}

/// A change to apply with [`mount_setattr`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrChange {
    /// Attributes to set.
    pub set: MountAttrs,
    /// Attributes to clear (applied before `set`).
    pub clear: MountAttrs,
    /// New propagation type, if any.
    pub propagation: Option<Propagation>,
}

impl AttrChange {
    /// True if applying this change would do nothing.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.clear.is_empty() && self.propagation.is_none()
    }
}

/// `struct mount_attr` from `<linux/mount.h>`.
#[repr(C)]
struct RawMountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const AT_RECURSIVE: libc::c_uint = 0x8000;
const AT_EMPTY_PATH: libc::c_uint = 0x1000;

/// Apply `change` to the mount that `fd` refers to (and, if `recursive`, to every mount below it).
pub fn mount_setattr(fd: BorrowedFd<'_>, recursive: bool, change: &AttrChange) -> io::Result<()> {
    if change.is_empty() {
        return Ok(());
    }
    let mut attr = RawMountAttr {
        attr_set: change.set.bits(),
        attr_clr: change.clear.bits(),
        propagation: change.propagation.map_or(0, Propagation::as_raw),
        userns_fd: 0,
    };
    let flags = AT_EMPTY_PATH | if recursive { AT_RECURSIVE } else { 0 };
    let empty: &CStr = c"";
    // SAFETY: `fd` is a valid open descriptor for the duration of the call, the path is a valid
    // empty C string (meaning "the fd itself" with AT_EMPTY_PATH), and `attr` is a correctly
    // laid-out struct mount_attr whose size we pass.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd.as_raw_fd(),
            empty.as_ptr(),
            flags,
            &raw mut attr,
            std::mem::size_of::<RawMountAttr>(),
        )
    };
    crate::cvt(ret).map(drop)
}
