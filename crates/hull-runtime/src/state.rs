//! The on-disk state of containers.
//!
//! ```text
//! <root>/                 (default /run/hull, mode 0700)
//!   <id>/                 (mode 0700)
//!     lock                flock(2)ed by whichever hull-runtime process is changing the container
//!     state.json          the OCI state, replaced atomically
//! ```
//!
//! `/run` is a tmpfs, so state disappears on reboot, exactly like the containers it describes.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::procfs::ProcStat;
use crate::{ContainerId, Context, Error, Result};

/// The OCI lifecycle status of a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The runtime is still setting the container up.
    Creating,
    /// Set up; the user's program has not started (milestone M2).
    Created,
    /// The user's program is running.
    Running,
    /// The program has exited.
    Stopped,
    /// Frozen (milestone M3).
    Paused,
}

/// The persisted state of one container, in the format `hull-runtime state` prints.
///
/// The first six fields are the OCI state (runtime-spec `runtime.md`). The rest are extensions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    /// OCI runtime-spec version the state complies with.
    pub oci_version: String,
    /// The container ID.
    pub id: String,
    /// Lifecycle status.
    pub status: Status,
    /// PID of the container's init process in the runtime's PID namespace (0 if none).
    #[serde(default)]
    pub pid: i32,
    /// Absolute path to the bundle.
    pub bundle: PathBuf,
    /// Annotations from `config.json`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// Absolute path to the root filesystem.
    pub rootfs: PathBuf,
    /// Creation time (RFC 3339).
    pub created: String,
    /// Start time of the init process (`/proc/<pid>/stat` field 22), used to detect PID reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_start_time: Option<u64>,
}

impl State {
    /// Whether the recorded init process still exists and is the same process we started.
    ///
    /// A PID alone is not an identity. If the container exited and the kernel handed its PID to
    /// some unrelated process, signalling "the container" would hit that process instead.
    pub fn init_is_alive(&self) -> bool {
        if self.pid <= 0 {
            return false;
        }
        match ProcStat::read(self.pid) {
            Ok(stat) => stat.state != 'Z' && Some(stat.start_time) == self.init_start_time,
            Err(_) => false,
        }
    }

    /// Correct `status` if the init process has gone away since the state was written.
    pub fn refresh(&mut self) {
        let live_states = [Status::Created, Status::Running, Status::Paused];
        if live_states.contains(&self.status) && !self.init_is_alive() {
            self.status = Status::Stopped;
        }
    }
}

/// The directory holding the state of all containers.
#[derive(Debug, Clone)]
pub struct StateStore {
    root: PathBuf,
}

impl StateStore {
    /// A store rooted at `root`. Nothing is created until a container is.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The store's root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Register a new container and lock it. Fails if the ID is taken.
    pub fn create(&self, id: &ContainerId) -> Result<ContainerDir> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .context(|| format!("create state root {}", self.root.display()))?;
        let path = self.root.join(id.as_str());
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(Error::AlreadyExists(id.to_string()));
            }
            Err(e) => return Err(e).context(|| format!("create {}", path.display())),
        }
        match ContainerDir::lock(id, path.clone()) {
            Ok(dir) => Ok(dir),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&path);
                Err(e)
            }
        }
    }

    /// Read a container's state (without locking) and refresh its status.
    pub fn load(&self, id: &ContainerId) -> Result<State> {
        let path = self.root.join(id.as_str()).join("state.json");
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::NotFound(id.to_string()));
            }
            Err(e) => return Err(e).context(|| format!("read {}", path.display())),
        };
        let mut state: State = serde_json::from_str(&text)
            .map_err(io::Error::other)
            .context(|| format!("parse {}", path.display()))?;
        state.refresh();
        Ok(state)
    }

    /// The state of every container, sorted by ID. Entries that cannot be read are skipped.
    pub fn list(&self) -> Result<Vec<State>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context(|| format!("list {}", self.root.display())),
        };
        let mut states = Vec::new();
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(id) = ContainerId::new(&name) else { continue };
            match self.load(&id) {
                Ok(state) => states.push(state),
                Err(e) => tracing::warn!(container = %id, "skipping unreadable state: {e}"),
            }
        }
        states.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(states)
    }
}

/// A container's state directory, locked for the lifetime of this value.
#[derive(Debug)]
pub struct ContainerDir {
    id: ContainerId,
    path: PathBuf,
    // Held only for its lock. The lock is released when the descriptor is closed, which also
    // happens automatically if this process dies, so a crash can never leave a container locked.
    _lock: OwnedFd,
}

impl ContainerDir {
    fn lock(id: &ContainerId, path: PathBuf) -> Result<Self> {
        let lock_path = path.join("lock");
        let fd = rustix::fs::open(
            &lock_path,
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .context(|| format!("open {}", lock_path.display()))?;
        match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { id: id.clone(), path, _lock: fd }),
            Err(Errno::WOULDBLOCK) => Err(Error::Locked(id.to_string())),
            Err(e) => Err(e).context(|| format!("lock {}", lock_path.display())),
        }
    }

    /// The container ID.
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist `state` atomically.
    pub fn save(&self, state: &State) -> Result<()> {
        let json = serde_json::to_vec_pretty(state)
            .map_err(io::Error::other)
            .context(|| "serialize state".into())?;
        hull_fs::atomic_write(&self.path, "state.json", &json)
            .context(|| format!("write {}/state.json", self.path.display()))
    }

    /// Remove the container's state entirely.
    pub fn destroy(self) -> Result<()> {
        std::fs::remove_dir_all(&self.path).context(|| format!("remove {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(id: &str) -> State {
        State {
            oci_version: "1.1.0".into(),
            id: id.into(),
            status: Status::Creating,
            pid: 0,
            bundle: "/b".into(),
            annotations: BTreeMap::new(),
            rootfs: "/b/rootfs".into(),
            created: "2026-01-01T00:00:00Z".into(),
            init_start_time: None,
        }
    }

    #[test]
    fn create_save_load_list_destroy() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path().join("hull"));
        let id = ContainerId::new("web").unwrap();

        let dir = store.create(&id).unwrap();
        dir.save(&state("web")).unwrap();
        assert_eq!(store.load(&id).unwrap().status, Status::Creating);
        assert_eq!(store.list().unwrap().len(), 1);

        assert!(matches!(store.create(&id), Err(Error::AlreadyExists(_))));

        dir.destroy().unwrap();
        assert!(matches!(store.load(&id), Err(Error::NotFound(_))));
        assert_eq!(store.list().unwrap().len(), 0);
    }

    #[test]
    fn lock_is_exclusive() {
        let tmp = tempfile::tempdir().unwrap();
        let id = ContainerId::new("c").unwrap();
        let path = tmp.path().join("c");
        std::fs::create_dir(&path).unwrap();
        let _held = ContainerDir::lock(&id, path.clone()).unwrap();
        assert!(matches!(ContainerDir::lock(&id, path), Err(Error::Locked(_))));
    }

    #[test]
    fn dead_init_reads_as_stopped() {
        let mut s = state("c");
        s.status = Status::Running;
        s.pid = i32::MAX; // No such process.
        s.refresh();
        assert_eq!(s.status, Status::Stopped);

        // Our own PID, but a start time that does not match: a recycled PID.
        let mut s = state("c");
        s.status = Status::Running;
        s.pid = std::process::id().try_into().unwrap();
        s.init_start_time = Some(1);
        s.refresh();
        assert_eq!(s.status, Status::Stopped);
    }
}
