//! End-to-end tests of `hull-runtime run` against real namespaces.
//!
//! They need root, a rootfs fixture and the probe binary, so they are `#[ignore]`d by default.
//! Run them with `scripts/test-integration.sh`.

// Helpers in integration-test files are not `#[test]` functions, so clippy's test exemption
// does not cover them. A panic is exactly how a test helper should report failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use hull_testkit::{Bundle, HostMounts, Hull, unique_id};
use serde_json::{Value, json};

const HULL: &str = env!("CARGO_BIN_EXE_hull-runtime");
fn hull() -> Hull {
    Hull::new(HULL)
}

fn chown_recursive(path: &Path, id: u32) {
    let owner = format!("{id}:{id}");
    let status =
        std::process::Command::new("chown").args(["-R", &owner]).arg(path).status().unwrap();
    assert!(status.success());
}

fn host_namespace(ns: &str) -> String {
    std::fs::read_link(format!("/proc/self/ns/{ns}")).unwrap().display().to_string()
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn exit_code_is_propagated() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.sh("exit 42");
    hull.run(&bundle, &unique_id("exit")).assert_code(42);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn container_is_pid_1_in_fresh_namespaces() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe();
    let report = hull.run(&bundle, &unique_id("ns")).assert_code(0).json();
    assert_eq!(report["pid"], 1);
    for ns in ["pid", "net", "ipc", "uts", "mnt"] {
        assert_ne!(report["namespaces"][ns], host_namespace(ns), "{ns} namespace must be private");
    }
    for ns in ["user", "cgroup", "time"] {
        assert_eq!(
            report["namespaces"][ns],
            host_namespace(ns),
            "{ns} namespace was not requested"
        );
    }
    assert_eq!(report["hostname"], "hull");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn every_requested_namespace_is_created() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe().edit(|c| {
        c["linux"]["namespaces"] = json!([
            {"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"},
            {"type": "mount"}, {"type": "cgroup"}, {"type": "time"}
        ]);
    });
    let report = hull.run(&bundle, &unique_id("allns")).assert_code(0).json();
    for ns in ["pid", "net", "ipc", "uts", "mnt", "cgroup", "time"] {
        assert_ne!(report["namespaces"][ns], host_namespace(ns), "{ns} namespace must be private");
    }
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn mounts_follow_the_config() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe();
    let report = hull.run(&bundle, &unique_id("mounts")).assert_code(0).json();
    let mounts = report["mounts"].as_array().unwrap();
    let find = |point: &str| {
        mounts
            .iter()
            .find(|m| m["mount_point"] == point)
            .unwrap_or_else(|| panic!("{point} not mounted: {mounts:#?}"))
    };
    assert_eq!(find("/proc")["fs_type"], "proc");
    assert_eq!(find("/dev")["fs_type"], "tmpfs");
    assert_eq!(find("/dev/pts")["fs_type"], "devpts");
    assert_eq!(find("/dev/mqueue")["fs_type"], "mqueue");
    let sys = find("/sys");
    assert_eq!(sys["fs_type"], "sysfs");
    assert!(sys["options"].as_str().unwrap().starts_with("ro,"), "sysfs must be read-only: {sys}");
    let root = find("/");
    assert!(root["options"].as_str().unwrap().starts_with("ro,"), "root must be read-only: {root}");
    // The old root must be gone: nothing else is mounted.
    assert_eq!(mounts.len(), 7, "unexpected mounts: {mounts:#?}");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn root_filesystem_is_read_only() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.sh("touch /should-fail 2>/dev/null && exit 1; exit 0");
    hull.run(&bundle, &unique_id("ro")).assert_code(0);
    assert!(!bundle.rootfs().join("should-fail").exists());
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn default_devices_work() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe();
    let report = hull.run(&bundle, &unique_id("dev")).assert_code(0).json();
    let dev = &report["dev"];
    assert_eq!(dev["null"], "char 1:3 666");
    assert_eq!(dev["zero"], "char 1:5 666");
    assert_eq!(dev["urandom"], "char 1:9 666");
    assert_eq!(dev["tty"], "char 5:0 666");
    assert_eq!(dev["fd"], "symlink -> /proc/self/fd");
    assert_eq!(dev["ptmx"], "symlink -> pts/ptmx");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn process_settings_are_applied() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe().edit(|c| {
        c["process"]["user"] =
            json!({"uid": 1000, "gid": 1001, "additionalGids": [10, 20], "umask": 0o077});
        c["process"]["cwd"] = json!("/tmp");
        c["process"]["env"] = json!(["PATH=/bin", "GREETING=hello world"]);
        c["process"]["rlimits"] = json!([{"type": "RLIMIT_NOFILE", "soft": 256, "hard": 512}]);
    });
    let report = hull.run(&bundle, &unique_id("proc")).assert_code(0).json();
    let status = &report["status"];
    assert_eq!(status["Uid"], "1000 1000 1000 1000");
    assert_eq!(status["Gid"], "1001 1001 1001 1001");
    assert_eq!(status["Groups"], "10 20");
    assert_eq!(status["Umask"], "0077");
    assert_eq!(status["NoNewPrivs"], "1");
    assert_eq!(report["cwd"], "/tmp");
    assert_eq!(report["rlimits"]["Max open files"], json!(["256", "512"]));
    let env: Vec<&str> =
        report["env"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        env,
        ["GREETING=hello world", "HOME=/", "PATH=/bin"],
        "HOME defaults from /etc/passwd, or /"
    );
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn signal_state_is_clean() {
    // The runtime blocks signals and Rust ignores SIGPIPE; neither may leak into the container.
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe();
    let report = hull.run(&bundle, &unique_id("sig")).assert_code(0).json();
    assert_eq!(report["status"]["SigBlk"], "0000000000000000");
    assert_eq!(report["status"]["SigIgn"], "0000000000000000");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn no_file_descriptors_leak_into_the_container() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe();
    let report = hull.run(&bundle, &unique_id("fds")).assert_code(0).json();
    let fds: Vec<&String> = report["fds"].as_object().unwrap().keys().collect();
    assert_eq!(fds, ["0", "1", "2"], "only stdio may be inherited: {}", report["fds"]);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn user_namespace_maps_ids() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe().edit(|c| {
        c["linux"]["namespaces"].as_array_mut().unwrap().push(json!({"type": "user"}));
        c["linux"]["uidMappings"] = json!([{"containerID": 0, "hostID": 100_000, "size": 65536}]);
        c["linux"]["gidMappings"] = json!([{"containerID": 0, "hostID": 100_000, "size": 65536}]);
    });
    // Without this, the container's root is an unmapped host root and cannot create /proc in it.
    let unmapped = hull.run(&bundle, &unique_id("userns-unmapped"));
    unmapped.assert_code(125);
    assert!(
        unmapped.stderr.contains("must be owned by an id that is mapped"),
        "{}",
        unmapped.stderr
    );

    chown_recursive(&bundle.rootfs(), 100_000);
    let report = hull.run(&bundle, &unique_id("userns")).assert_code(0).json();
    assert_ne!(report["namespaces"]["user"], host_namespace("user"));
    assert_eq!(report["uid_map"], "0     100000      65536");
    assert_eq!(report["status"]["Uid"], "0 0 0 0", "init must adopt the namespace's root identity");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn bind_mounts_respect_read_only() {
    let hull = hull();
    let host_dir = tempfile::tempdir().unwrap();
    std::fs::write(host_dir.path().join("data.txt"), "from the host").unwrap();
    let mut bundle = Bundle::new();
    bundle.sh("cat /data/data.txt && ! touch /data/new 2>/dev/null").edit(|c| {
        c["mounts"].as_array_mut().unwrap().push(json!({
            "destination": "/data", "source": host_dir.path(), "options": ["rbind", "ro", "nosuid"]
        }));
    });
    let outcome = hull.run(&bundle, &unique_id("bind"));
    outcome.assert_code(0);
    assert_eq!(outcome.stdout, "from the host");
    assert!(!host_dir.path().join("new").exists());
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn symlinked_mount_destination_cannot_escape_the_rootfs() {
    // The image plants /evil -> <a host directory>. A runtime that joins path strings would mount
    // onto the host directory. hull must resolve the symlink *inside* the rootfs instead.
    let hull = hull();
    let host_target = tempfile::tempdir().unwrap();
    let mut bundle = Bundle::new();
    std::os::unix::fs::symlink(host_target.path(), bundle.rootfs().join("evil")).unwrap();
    bundle.sh("true").edit(|c| {
        c["mounts"].as_array_mut().unwrap().push(json!({
            "destination": "/evil/mnt", "type": "tmpfs", "source": "tmpfs"
        }));
    });
    let before = HostMounts::capture();
    let outcome = hull.run(&bundle, &unique_id("escape"));
    before.assert_unchanged();
    assert!(!host_target.path().join("mnt").exists(), "a directory was created on the host");
    // Mounting succeeded, but inside the rootfs at the symlink's target path.
    outcome.assert_code(0);
    let inside = bundle.rootfs().join(host_target.path().strip_prefix("/").unwrap()).join("mnt");
    assert!(inside.is_dir(), "expected the mount point at {}", inside.display());
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn exec_failures_use_shell_exit_codes() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.args(&["/no/such/program"]);
    let outcome = hull.run(&bundle, &unique_id("enoent"));
    outcome.assert_code(127);
    assert!(outcome.stderr.contains("exec"), "{}", outcome.stderr);

    let mut bundle = Bundle::new();
    bundle.args(&["/etc/passwd"]);
    hull.run(&bundle, &unique_id("eacces")).assert_code(126);

    let mut bundle = Bundle::new();
    bundle.args(&["not-in-path"]);
    hull.run(&bundle, &unique_id("nopath")).assert_code(125);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn unimplemented_features_fail_before_anything_happens() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.sh("true").edit(|c| {
        c["linux"]["seccomp"] = json!({"defaultAction": "SCMP_ACT_ERRNO"});
        c["process"]["capabilities"] = json!({"bounding": ["CAP_KILL"]});
    });
    let outcome = hull.run(&bundle, &unique_id("unsupported"));
    outcome.assert_code(125);
    assert!(
        outcome.stderr.contains("linux.seccomp: not implemented yet (planned for M4"),
        "{}",
        outcome.stderr
    );
    assert!(outcome.stderr.contains("process.capabilities"), "{}", outcome.stderr);
    assert_eq!(std::fs::read_dir(hull.state_root()).unwrap().count(), 0, "no state may be created");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn failed_setup_cleans_up_everything() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.sh("true").edit(|c| {
        c["mounts"].as_array_mut().unwrap().push(json!({
            "destination": "/broken", "type": "no-such-filesystem", "source": "x"
        }));
    });
    let before = HostMounts::capture();
    let outcome = hull.run(&bundle, &unique_id("broken"));
    outcome.assert_code(125);
    assert!(outcome.stderr.contains("root filesystem setup"), "{}", outcome.stderr);
    assert!(outcome.stderr.contains("no-such-filesystem"), "{}", outcome.stderr);
    before.assert_unchanged();
    assert_eq!(std::fs::read_dir(hull.state_root()).unwrap().count(), 0, "state must be removed");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn state_and_list_while_running() {
    let hull = hull();
    let id = unique_id("live");
    let mut bundle = Bundle::new();
    bundle.args(&["sleep", "30"]);
    bundle.write();
    let pid_file = bundle.path().join("pid");
    let mut child = hull
        .command()
        .args(["run", "--bundle"])
        .arg(bundle.path())
        .arg("--pid-file")
        .arg(&pid_file)
        .arg(&id)
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let state = wait_for_running(&hull, &id);
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    assert_eq!(state["pid"].to_string(), pid);
    assert_eq!(state["bundle"], json!(bundle.path().canonicalize().unwrap()));

    let list = hull.command().args(["list", "--quiet"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&list.stdout).trim(), id);

    // A second container with the same ID must be refused.
    let duplicate = hull.run(&bundle, &id);
    duplicate.assert_code(125);
    assert!(duplicate.stderr.contains("already exists"), "{}", duplicate.stderr);

    // `sleep` is PID 1 and installs no handler, so a forwarded SIGTERM is ignored by the kernel.
    // Three interrupts make hull escalate to SIGKILL.
    let runtime_pid = child.id();
    for _ in 0..3 {
        signal(runtime_pid, "INT");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(137), "128 + SIGKILL");
    assert_eq!(std::fs::read_dir(hull.state_root()).unwrap().count(), 0);
}

fn wait_for_running(hull: &Hull, id: &str) -> Value {
    for _ in 0..100 {
        let output = hull.command().args(["state", id]).output().unwrap();
        if output.status.success() {
            let state: Value = serde_json::from_slice(&output.stdout).unwrap();
            if state["status"] == "running" {
                return state;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("container {id} never reached running");
}

fn signal(pid: u32, name: &str) {
    let status = std::process::Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn spec_command_writes_a_config_that_runs() {
    let hull = hull();
    let dir = tempfile::tempdir().unwrap();
    let status = hull.command().arg("spec").arg("--bundle").arg(dir.path()).status().unwrap();
    assert!(status.success());
    assert!(Path::new(&dir.path().join("config.json")).exists());
    // Refuses to overwrite.
    let again = hull.command().arg("spec").arg("--bundle").arg(dir.path()).output().unwrap();
    assert!(!again.status.success());
}
