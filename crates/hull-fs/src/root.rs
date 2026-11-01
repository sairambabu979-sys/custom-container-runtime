use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use crate::clean_absolute;

/// `RESOLVE_IN_ROOT`: resolve as if the root directory were `/` (absolute symlinks and `..` stay
/// inside). `RESOLVE_NO_MAGICLINKS`: refuse `/proc/<pid>/fd/*`-style "magic links", which jump to
/// arbitrary files regardless of the root and are the classic way to escape a chroot.
const RESOLVE: ResolveFlags = ResolveFlags::IN_ROOT.union(ResolveFlags::NO_MAGICLINKS);

/// `openat2` returns `EAGAIN` when a concurrent rename *might* have let a lookup escape. The
/// kernel asks us to retry instead of guessing. A small bound turns a pathological race into an
/// error instead of a livelock.
const MAX_EAGAIN_RETRIES: usize = 128;

/// A directory treated as the root of every path resolved through it.
///
/// See the [crate documentation](crate) for the attack this prevents.
#[derive(Debug)]
pub struct SafeRoot {
    fd: OwnedFd,
    path: PathBuf,
}

impl SafeRoot {
    /// Open `path` (a host path the caller trusts) as a root.
    ///
    /// Important: the descriptor refers to whatever is mounted at `path` *at this moment*. If you
    /// mount something on `path` afterwards, open a new `SafeRoot`, or you will keep operating on
    /// the directory underneath the new mount.
    pub fn open(path: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { fd, path: path.to_owned() })
    }

    /// The host path this root was opened from (for messages only; never re-resolve it).
    pub fn host_path(&self) -> &Path {
        &self.path
    }

    /// Open `path`, interpreted inside this root, with the given flags.
    pub fn open_at(&self, path: &Path, flags: OFlags, mode: Mode) -> io::Result<OwnedFd> {
        let path = clean_absolute(path);
        let flags = flags | OFlags::CLOEXEC;
        for _ in 0..MAX_EAGAIN_RETRIES {
            match rustix::fs::openat2(&self.fd, &path, flags, mode, RESOLVE) {
                Err(Errno::AGAIN) => {}
                other => return other.map_err(io::Error::from),
            }
        }
        Err(io::Error::from(Errno::AGAIN))
    }

    /// Get an `O_PATH` handle to `path`. Such a handle can be used as a mount target, as a
    /// directory for `*at` calls, or with `fstat`, but not for reading or writing.
    pub fn resolve(&self, path: &Path) -> io::Result<OwnedFd> {
        self.open_at(path, OFlags::PATH, Mode::empty())
    }

    /// Create `path` and any missing parent directories inside this root, and return an `O_PATH`
    /// handle to the final directory.
    ///
    /// Each component is created with `mkdirat` relative to its *already resolved* parent
    /// descriptor, so a symlink planted anywhere along the way can redirect creation only to
    /// another place inside the root. A symlink whose target does not exist yet (common in images,
    /// e.g. `/var/run -> /run`) is followed the same way, so the directory is created where the
    /// symlink points, inside the root.
    pub fn mkdir_all(&self, path: &Path, mode: Mode) -> io::Result<OwnedFd> {
        let mut path = clean_absolute(path);
        for _ in 0..=MAX_SYMLINK_FOLLOWS {
            match self.mkdir_all_step(&path, mode)? {
                Step::Done(fd) => return Ok(fd),
                Step::Redirect(next) => path = next,
            }
        }
        Err(Errno::LOOP.into())
    }

    fn mkdir_all_step(&self, path: &Path, mode: Mode) -> io::Result<Step> {
        let dir_flags = OFlags::PATH | OFlags::DIRECTORY;
        match self.open_at(path, dir_flags, Mode::empty()) {
            Err(e) if is_enoent(&e) => {}
            other => return other.map(Step::Done),
        }

        let names: Vec<&OsStr> = normal_components(path).collect();
        let mut current = self.open_at(Path::new("/"), dir_flags, Mode::empty())?;
        let mut prefix = PathBuf::from("/");
        for (i, name) in names.iter().enumerate() {
            prefix.push(name);
            current = match self.open_at(&prefix, dir_flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(e) if is_enoent(&e) => match rustix::fs::mkdirat(&current, *name, mode) {
                    Ok(()) => self.open_at(&prefix, dir_flags, Mode::empty())?,
                    // Something exists but did not resolve: a dangling symlink (or a concurrent
                    // mkdir). Follow the symlink ourselves and start over with the new path.
                    Err(Errno::EXIST) => {
                        if let Some(next) = redirect(&current, name, &prefix, &names[i + 1..])? {
                            return Ok(Step::Redirect(next));
                        }
                        self.open_at(&prefix, dir_flags, Mode::empty())?
                    }
                    Err(e) => return Err(e.into()),
                },
                Err(e) => return Err(e),
            };
        }
        Ok(Step::Done(current))
    }

    /// Return an `O_PATH` handle to `path`'s parent directory (creating it if needed) together
    /// with the final path component.
    pub fn parent_of(&self, path: &Path) -> io::Result<(OwnedFd, OsString)> {
        let path = clean_absolute(path);
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
            .to_owned();
        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        Ok((self.mkdir_all(parent, Mode::from_raw_mode(0o755))?, name))
    }

    /// Make sure a non-directory exists at `path` (creating an empty regular file if nothing is
    /// there) and return an `O_PATH` handle to it. Used for bind-mounting files. A dangling
    /// symlink at `path` is followed inside the root, and the file is created at its target.
    pub fn ensure_file(&self, path: &Path, mode: Mode) -> io::Result<OwnedFd> {
        let mut path = clean_absolute(path);
        for _ in 0..=MAX_SYMLINK_FOLLOWS {
            match self.resolve(&path) {
                Err(e) if is_enoent(&e) => {}
                other => return other,
            }
            let (dir, name) = self.parent_of(&path)?;
            let flags =
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            match rustix::fs::openat(&dir, &name, flags, mode) {
                Ok(_) => return self.resolve(&path),
                Err(Errno::EXIST) => match redirect(&dir, &name, &path, &[])? {
                    Some(next) => path = next,
                    None => return self.resolve(&path),
                },
                Err(e) => return Err(e.into()),
            }
        }
        Err(Errno::LOOP.into())
    }

    /// Create a symlink at `path` pointing to `target`. Succeeds if an identical symlink already
    /// exists.
    pub fn symlink(&self, target: &Path, path: &Path) -> io::Result<()> {
        let (dir, name) = self.parent_of(path)?;
        match rustix::fs::symlinkat(target, &dir, &name) {
            Ok(()) => Ok(()),
            Err(Errno::EXIST) => {
                let existing = rustix::fs::readlinkat(&dir, &name, Vec::new())?;
                if existing.as_bytes() == target.as_os_str().as_encoded_bytes() {
                    Ok(())
                } else {
                    Err(Errno::EXIST.into())
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Read a whole file inside this root, refusing files larger than `max_len` bytes.
    pub fn read(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        use std::io::Read;
        let fd = self.open_at(path, OFlags::RDONLY, Mode::empty())?;
        let mut data = Vec::new();
        std::fs::File::from(fd).take(max_len + 1).read_to_end(&mut data)?;
        if data.len() as u64 > max_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
        }
        Ok(data)
    }
}

impl AsFd for SafeRoot {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// The kernel's limit on symlinks followed during one lookup (`MAXSYMLINKS`).
const MAX_SYMLINK_FOLLOWS: usize = 40;

enum Step {
    Done(OwnedFd),
    Redirect(PathBuf),
}

fn is_enoent(e: &io::Error) -> bool {
    e.raw_os_error() == Some(Errno::NOENT.raw_os_error())
}

/// If `parent/name` (whose path inside the root is `link_path`) is a symlink, return the path that
/// replaces it: the link target (absolute targets are relative to the root, relative ones to the
/// link's directory) followed by the not-yet-resolved components `rest`.
///
/// This is computed lexically, but that is only a *suggestion*: the result is resolved again with
/// `openat2(RESOLVE_IN_ROOT)`, so no target, however crafted, can lead outside the root.
fn redirect(
    parent: &OwnedFd,
    name: &OsStr,
    link_path: &Path,
    rest: &[&OsStr],
) -> io::Result<Option<PathBuf>> {
    use std::os::unix::ffi::OsStringExt;
    let target = match rustix::fs::readlinkat(parent, name, Vec::new()) {
        Ok(target) => PathBuf::from(OsString::from_vec(target.into_bytes())),
        Err(Errno::INVAL) => return Ok(None), // Not a symlink.
        Err(e) => return Err(e.into()),
    };
    let mut next = link_path.parent().unwrap_or_else(|| Path::new("/")).join(target);
    next.extend(rest);
    Ok(Some(clean_absolute(&next)))
}

fn normal_components(path: &Path) -> impl Iterator<Item = &OsStr> {
    path.components().filter_map(|c| match c {
        Component::Normal(name) => Some(name),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// base/
    ///   outside/secret      <- must never be reachable
    ///   root/               <- the `SafeRoot`
    fn fixture() -> (tempfile::TempDir, PathBuf, SafeRoot) {
        let base = tempfile::tempdir().unwrap();
        let outside = base.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), "host data").unwrap();
        let root_path = base.path().join("root");
        std::fs::create_dir(&root_path).unwrap();
        let root = SafeRoot::open(&root_path).unwrap();
        (base, outside, root)
    }

    #[test]
    fn absolute_symlink_cannot_escape() {
        let (_base, outside, root) = fixture();
        symlink(&outside, root.host_path().join("link")).unwrap();
        let err = root.resolve(Path::new("/link/secret")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc_enoent()));
    }

    #[test]
    fn dotdot_symlink_cannot_escape() {
        let (_base, _outside, root) = fixture();
        symlink("../../../outside", root.host_path().join("up")).unwrap();
        let err = root.resolve(Path::new("/up/secret")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc_enoent()));
    }

    #[test]
    fn relative_symlink_inside_root_works() {
        let (_base, _outside, root) = fixture();
        std::fs::create_dir(root.host_path().join("real")).unwrap();
        std::fs::write(root.host_path().join("real/file"), "ok").unwrap();
        symlink("real", root.host_path().join("alias")).unwrap();
        assert_eq!(root.read(Path::new("/alias/file"), 16).unwrap(), b"ok");
    }

    #[test]
    fn mkdir_all_creates_nested_dirs() {
        let (_base, _outside, root) = fixture();
        root.mkdir_all(Path::new("/a/b/../c/d"), Mode::from_raw_mode(0o755)).unwrap();
        assert!(root.host_path().join("a/c/d").is_dir());
        assert!(!root.host_path().join("a/b").exists());
    }

    #[test]
    fn mkdir_all_through_escaping_symlink_stays_inside() {
        let (_base, outside, root) = fixture();
        symlink(&outside, root.host_path().join("evil")).unwrap();
        // The absolute target is reinterpreted inside the root, never on the host.
        root.mkdir_all(Path::new("/evil/pwned"), Mode::from_raw_mode(0o755)).unwrap();
        assert!(!outside.join("pwned").exists(), "created on the host");
        let inside = root.host_path().join(outside.strip_prefix("/").unwrap()).join("pwned");
        assert!(inside.is_dir(), "expected {}", inside.display());
    }

    #[test]
    fn dangling_relative_symlink_is_followed_for_files() {
        // The shape of /etc/resolv.conf in many images.
        let (_base, _outside, root) = fixture();
        std::fs::create_dir(root.host_path().join("etc")).unwrap();
        symlink("../run/resolve/stub.conf", root.host_path().join("etc/resolv.conf")).unwrap();
        root.ensure_file(Path::new("/etc/resolv.conf"), Mode::from_raw_mode(0o644)).unwrap();
        assert!(root.host_path().join("run/resolve/stub.conf").is_file());
    }

    #[test]
    fn symlink_loops_end_in_eloop() {
        let (_base, _outside, root) = fixture();
        symlink("/b", root.host_path().join("a")).unwrap();
        symlink("/a", root.host_path().join("b")).unwrap();
        let err = root.mkdir_all(Path::new("/a/x"), Mode::from_raw_mode(0o755)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(Errno::LOOP.raw_os_error()));
    }

    #[test]
    fn ensure_file_and_symlink() {
        let (_base, _outside, root) = fixture();
        root.ensure_file(Path::new("/etc/hostname"), Mode::from_raw_mode(0o644)).unwrap();
        assert!(root.host_path().join("etc/hostname").is_file());
        // Idempotent.
        root.ensure_file(Path::new("/etc/hostname"), Mode::from_raw_mode(0o644)).unwrap();

        root.symlink(Path::new("/proc/self/fd"), Path::new("/dev/fd")).unwrap();
        root.symlink(Path::new("/proc/self/fd"), Path::new("/dev/fd")).unwrap();
        assert!(root.symlink(Path::new("/elsewhere"), Path::new("/dev/fd")).is_err());
    }

    #[test]
    fn read_enforces_size_limit() {
        let (_base, _outside, root) = fixture();
        std::fs::write(root.host_path().join("big"), vec![b'x'; 100]).unwrap();
        assert!(root.read(Path::new("/big"), 99).is_err());
        assert_eq!(root.read(Path::new("/big"), 100).unwrap().len(), 100);
    }

    fn libc_enoent() -> i32 {
        Errno::NOENT.raw_os_error()
    }
}
