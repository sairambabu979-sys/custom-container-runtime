//! Test harness for hull's privileged integration tests.
//!
//! The tests need things a normal `cargo test` does not have: root, a root filesystem image, and a
//! statically linked probe binary. `scripts/test-integration.sh` provides all three, then runs the
//! `#[ignore]`d tests. Every helper here fails loudly with instructions instead of skipping, so a
//! misconfigured run cannot silently pass.

#![forbid(unsafe_code)]
// Test helpers report problems by panicking, which is how a test fails.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

const HOW_TO_RUN: &str = "run the integration tests with scripts/test-integration.sh";

/// Panic unless running as root.
pub fn require_root() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let euid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .unwrap_or("");
    assert_eq!(euid, "0", "integration tests need root; {HOW_TO_RUN}");
}

/// The repository root.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("workspace root")
}

/// The busybox root filesystem fixture (`$HULL_TEST_ROOTFS`, or `.fixtures/busybox/rootfs`).
pub fn fixture_rootfs() -> PathBuf {
    let path = std::env::var_os("HULL_TEST_ROOTFS")
        .map_or_else(|| workspace_root().join(".fixtures/busybox/rootfs"), PathBuf::from);
    assert!(path.join("bin/sh").exists(), "no rootfs fixture at {}; {HOW_TO_RUN}", path.display());
    path
}

/// The statically linked probe binary (`$HULL_PROBE`).
pub fn probe_binary() -> PathBuf {
    let path = std::env::var_os("HULL_PROBE").map(PathBuf::from).unwrap_or_default();
    assert!(path.is_file(), "HULL_PROBE does not point at the hull-probe binary; {HOW_TO_RUN}");
    path
}

/// A unique container ID for this test process.
pub fn unique_id(prefix: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!("{prefix}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

/// An OCI bundle in a temporary directory: a private copy of the fixture rootfs plus a config
/// that starts as hull's default and can be edited as JSON.
#[derive(Debug)]
pub struct Bundle {
    dir: tempfile::TempDir,
    /// The `config.json` contents, written by [`Bundle::write`].
    pub config: Value,
}

impl Default for Bundle {
    fn default() -> Self {
        Self::new()
    }
}

impl Bundle {
    /// A fresh bundle with the default config.
    pub fn new() -> Self {
        let dir = tempfile::Builder::new().prefix("hull-bundle-").tempdir().expect("tempdir");
        let status = Command::new("cp")
            .arg("-a")
            .arg(fixture_rootfs())
            .arg(dir.path().join("rootfs"))
            .status()
            .expect("run cp");
        assert!(status.success(), "copying the rootfs fixture failed");
        let config = serde_json::from_str(hull_spec::DEFAULT_CONFIG_JSON).expect("default config");
        Self { dir, config }
    }

    /// The bundle directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The bundle's rootfs directory.
    pub fn rootfs(&self) -> PathBuf {
        self.dir.path().join("rootfs")
    }

    /// Set `process.args`.
    pub fn args(&mut self, args: &[&str]) -> &mut Self {
        self.config["process"]["args"] = args.iter().map(|&a| Value::from(a)).collect();
        self
    }

    /// Run `script` with the image's `sh -c`.
    pub fn sh(&mut self, script: &str) -> &mut Self {
        self.args(&["sh", "-c", script])
    }

    /// Copy `hull-probe` into the rootfs and make it the container's process.
    pub fn probe(&mut self) -> &mut Self {
        std::fs::copy(probe_binary(), self.rootfs().join("hull-probe")).expect("copy probe");
        self.args(&["/hull-probe"])
    }

    /// Change the config with a closure.
    pub fn edit(&mut self, f: impl FnOnce(&mut Value)) -> &mut Self {
        f(&mut self.config);
        self
    }

    /// Write `config.json`.
    pub fn write(&self) {
        let json = serde_json::to_string_pretty(&self.config).expect("serialize config");
        std::fs::write(self.path().join("config.json"), json).expect("write config.json");
    }
}

/// The result of running a container.
#[derive(Debug)]
pub struct Outcome {
    /// The runtime's exit code.
    pub code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

impl Outcome {
    /// Parse standard output as JSON (for probe runs).
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!("stdout is not JSON ({e}):\n{}\nstderr:\n{}", self.stdout, self.stderr)
        })
    }

    /// Panic with full output unless the exit code is `code`.
    pub fn assert_code(&self, code: i32) -> &Self {
        assert_eq!(
            self.code, code,
            "unexpected exit code\nstdout:\n{}\nstderr:\n{}",
            self.stdout, self.stderr
        );
        self
    }
}

fn outcome(mut command: Command) -> Outcome {
    let output = command.stdin(Stdio::null()).output().expect("spawn runtime");
    Outcome {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A `hull-runtime` binary with a private state root.
#[derive(Debug)]
pub struct Hull {
    binary: PathBuf,
    root: tempfile::TempDir,
}

impl Hull {
    /// Use `binary` (pass `env!("CARGO_BIN_EXE_hull-runtime")`).
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        require_root();
        let root = tempfile::Builder::new().prefix("hull-state-").tempdir().expect("tempdir");
        Self { binary: binary.into(), root }
    }

    /// The state root passed as `--root`.
    pub fn state_root(&self) -> &Path {
        self.root.path()
    }

    /// A command for this runtime with `--root` set.
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg("--root").arg(self.root.path());
        command
    }

    /// Write the bundle's config and `run` it to completion.
    pub fn run(&self, bundle: &Bundle, id: &str) -> Outcome {
        bundle.write();
        let mut command = self.command();
        command.arg("run").arg("--bundle").arg(bundle.path()).arg(id);
        outcome(command)
    }
}

impl Hull {
    /// Run `hull-runtime <args...>` and capture its output.
    pub fn cmd(&self, args: &[&str]) -> Outcome {
        let mut command = self.command();
        command.args(args);
        outcome(command)
    }

    /// Write the bundle's config and `create` it. The container's stdout and stderr go to
    /// `bundle/output` (see [`Bundle::output`]); `create`'s own errors land there too.
    ///
    /// Pipes would not work here: the container inherits `create`'s stdout, so a pipe would stay
    /// open long after `create` has exited, and reading it to the end would hang.
    pub fn create(&self, bundle: &Bundle, id: &str) -> Outcome {
        become_subreaper();
        bundle.write();
        let file = std::fs::File::create(bundle.output_path()).expect("create output file");
        let status = self
            .command()
            .arg("create")
            .arg("--bundle")
            .arg(bundle.path())
            .arg(id)
            .stdin(Stdio::null())
            .stdout(file.try_clone().expect("dup output file"))
            .stderr(file)
            .status()
            .expect("spawn hull-runtime create");
        Outcome {
            code: status.code().unwrap_or(-1),
            stdout: String::new(),
            stderr: bundle.output(),
        }
    }

    /// The container's state as JSON, or `None` if `state` fails (e.g. it was deleted).
    pub fn state(&self, id: &str) -> Option<Value> {
        let outcome = self.cmd(&["state", id]);
        (outcome.code == 0).then(|| serde_json::from_str(&outcome.stdout).expect("state JSON"))
    }

    /// The PID of the container's init, from `state`.
    pub fn pid(&self, id: &str) -> i32 {
        let state = self.state(id).expect("container exists");
        i32::try_from(state["pid"].as_i64().expect("pid")).expect("pid fits in i32")
    }

    /// `create`, `start`, wait for exit and `delete`. Returns the container's exit code and
    /// output, like [`Hull::run`] does for `run`.
    pub fn create_start_wait(&self, bundle: &Bundle, id: &str) -> Outcome {
        self.create(bundle, id).assert_code(0);
        let pid = self.pid(id);
        self.cmd(&["start", id]).assert_code(0);
        let code = wait_exit(pid);
        self.cmd(&["delete", id]).assert_code(0);
        Outcome { code, stdout: bundle.output(), stderr: String::new() }
    }
}

impl Bundle {
    /// Where [`Hull::create`] sends the container's output.
    pub fn output_path(&self) -> PathBuf {
        self.path().join("output")
    }

    /// Everything the container has written so far.
    pub fn output(&self) -> String {
        std::fs::read_to_string(self.output_path()).unwrap_or_default()
    }
}

/// Make this test process a *child subreaper* (`PR_SET_CHILD_SUBREAPER`).
///
/// `hull-runtime create` exits while the container's init lives on, and an orphaned process is
/// re-parented to its nearest subreaper ancestor, or to PID 1. Being that subreaper lets a test
/// collect the container's exit code with `waitpid`, exactly as containerd's shim does (and as
/// `hull-shim` will in M7).
pub fn become_subreaper() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let me = rustix::process::getpid();
        rustix::process::set_child_subreaper(Some(me)).expect("PR_SET_CHILD_SUBREAPER");
    });
}

/// Wait (up to 10 s) for the orphaned container init `pid` to exit and return its exit code,
/// using the shell convention of 128 + signal for a killed process.
pub fn wait_exit(pid: i32) -> i32 {
    use rustix::process::{Pid, WaitOptions};
    let pid = Pid::from_raw(pid).expect("valid pid");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match rustix::process::waitpid(Some(pid), WaitOptions::NOHANG) {
            Ok(Some((_, status))) => {
                return status
                    .exit_status()
                    .or_else(|| status.terminating_signal().map(|s| 128 + s))
                    .expect("process exited or was killed");
            }
            Ok(None) => {}
            Err(e) => panic!("waitpid({pid:?}) failed: {e} (is this test process its subreaper?)"),
        }
        assert!(std::time::Instant::now() < deadline, "process {pid:?} did not exit within 10 s");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Whether a `runc` binary is available for differential tests.
pub fn runc_available() -> bool {
    Command::new("runc").arg("--version").output().is_ok_and(|o| o.status.success())
}

/// Write the bundle's config and run it with `runc`.
pub fn runc_run(bundle: &Bundle, id: &str) -> Outcome {
    bundle.write();
    let root = tempfile::Builder::new().prefix("runc-state-").tempdir().expect("tempdir");
    let mut command = Command::new("runc");
    command.arg("--root").arg(root.path()).arg("run").arg("--bundle").arg(bundle.path()).arg(id);
    outcome(command)
}

/// The host's mount table, captured to prove that containers leave nothing behind.
#[derive(Debug, PartialEq, Eq)]
pub struct HostMounts(Vec<String>);

impl HostMounts {
    /// Capture `(mount point, fstype)` of every host mount.
    pub fn capture() -> Self {
        let text = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        let mut mounts: Vec<String> = text
            .lines()
            .filter_map(|line| {
                let (left, right) = line.split_once(" - ")?;
                let mount_point = left.split(' ').nth(4)?;
                let fs_type = right.split(' ').next()?;
                Some(format!("{mount_point} {fs_type}"))
            })
            .collect();
        mounts.sort();
        Self(mounts)
    }

    /// Panic if the host's mounts changed since `self` was captured.
    pub fn assert_unchanged(&self) {
        let now = Self::capture();
        let added: Vec<_> = now.0.iter().filter(|m| !self.0.contains(m)).collect();
        let removed: Vec<_> = self.0.iter().filter(|m| !now.0.contains(m)).collect();
        assert!(
            added.is_empty() && removed.is_empty(),
            "host mounts leaked: added {added:?}, removed {removed:?}"
        );
    }
}
