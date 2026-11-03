//! The OCI lifecycle: `create`, `start`, `kill`, `delete`, against real namespaces.
//!
//! Needs root and fixtures, so the tests are `#[ignore]`d by default. Run them with
//! `scripts/test-integration.sh lifecycle`.

// Helpers in integration-test files are not `#[test]` functions, so clippy's test exemption
// does not cover them. A panic is exactly how a test helper should report failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::Path;
use std::time::{Duration, Instant};

use hull_testkit::{Bundle, HostMounts, Hull, unique_id, wait_exit};

const HULL: &str = env!("CARGO_BIN_EXE_hull-runtime");

fn hull() -> Hull {
    Hull::new(HULL)
}

/// Wait until `bundle`'s output contains `text`.
fn wait_for_output(bundle: &Bundle, text: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !bundle.output().contains(text) {
        assert!(
            Instant::now() < deadline,
            "never saw {text:?}; output so far: {:?}",
            bundle.output()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn is_alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(')').next().is_some_and(|rest| !rest.trim_start().starts_with('Z'))
    })
}

fn assert_no_state(hull: &Hull) {
    assert_eq!(std::fs::read_dir(hull.state_root()).unwrap().count(), 0, "state must be removed");
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn create_waits_for_start_then_runs() {
    let hull = hull();
    let id = unique_id("created");
    let mut bundle = Bundle::new();
    bundle.sh("echo started");

    hull.create(&bundle, &id).assert_code(0);
    let state = hull.state(&id).unwrap();
    assert_eq!(state["status"], "created");
    let pid = hull.pid(&id);

    // Init exists and is fully set up, but it is still a copy of hull-runtime: the user's program
    // has not been exec'd, so it has printed nothing.
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
    assert_eq!(exe, Path::new(HULL).canonicalize().unwrap());
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(bundle.output(), "", "the program must not run before start");

    hull.cmd(&["start", &id]).assert_code(0);
    assert_eq!(wait_exit(pid), 0);
    assert_eq!(bundle.output(), "started\n");
    assert_eq!(hull.state(&id).unwrap()["status"], "stopped");

    hull.cmd(&["delete", &id]).assert_code(0);
    assert_no_state(&hull);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn start_is_only_valid_on_a_created_container() {
    let hull = hull();
    let id = unique_id("start-twice");
    let mut bundle = Bundle::new();
    bundle.args(&["sleep", "30"]);
    hull.create(&bundle, &id).assert_code(0);
    let pid = hull.pid(&id);

    hull.cmd(&["start", &id]).assert_code(0);
    let again = hull.cmd(&["start", &id]);
    again.assert_code(125);
    assert!(again.stderr.contains("is running, not created"), "{}", again.stderr);
    assert!(
        !hull.state_root().join(&id).join("exec.fifo").exists(),
        "the FIFO is removed by start"
    );

    hull.cmd(&["kill", &id, "KILL"]).assert_code(0);
    assert_eq!(wait_exit(pid), 137);
    let stopped = hull.cmd(&["start", &id]);
    stopped.assert_code(125);
    assert!(stopped.stderr.contains("is stopped"), "{}", stopped.stderr);
    hull.cmd(&["delete", &id]).assert_code(0);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn kill_delivers_the_requested_signal() {
    let hull = hull();
    let id = unique_id("kill-term");
    let mut bundle = Bundle::new();
    bundle.sh("trap 'exit 42' TERM; echo ready; while :; do sleep 0.1; done");
    hull.create(&bundle, &id).assert_code(0);
    let pid = hull.pid(&id);
    hull.cmd(&["start", &id]).assert_code(0);
    wait_for_output(&bundle, "ready");

    // No signal argument means SIGTERM, as with runc. The shell installed a handler, so even as
    // PID 1 it receives the signal.
    hull.cmd(&["kill", &id]).assert_code(0);
    assert_eq!(wait_exit(pid), 42);
    hull.cmd(&["delete", &id]).assert_code(0);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn pid_1_ignores_signals_it_has_no_handler_for() {
    let hull = hull();
    let id = unique_id("kill-pid1");
    let mut bundle = Bundle::new();
    bundle.args(&["sleep", "30"]);
    hull.create(&bundle, &id).assert_code(0);
    let pid = hull.pid(&id);
    hull.cmd(&["start", &id]).assert_code(0);

    // `sleep` installs no SIGTERM handler, and the kernel does not deliver unhandled signals to a
    // PID namespace's init, not even from outside. Only SIGKILL (and SIGSTOP) get through.
    hull.cmd(&["kill", &id, "SIGTERM"]).assert_code(0);
    std::thread::sleep(Duration::from_millis(300));
    assert!(is_alive(pid), "PID 1 without a handler must survive SIGTERM");

    hull.cmd(&["kill", &id, "9"]).assert_code(0);
    assert_eq!(wait_exit(pid), 137);

    let bad = hull.cmd(&["kill", &id, "NOT-A-SIGNAL"]);
    bad.assert_code(125);
    assert!(bad.stderr.contains("unknown signal"), "{}", bad.stderr);
    hull.cmd(&["delete", &id]).assert_code(0);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn delete_needs_force_for_a_running_container() {
    let hull = hull();
    let id = unique_id("delete-running");
    let mut bundle = Bundle::new();
    bundle.args(&["sleep", "30"]);
    hull.create(&bundle, &id).assert_code(0);
    let pid = hull.pid(&id);
    hull.cmd(&["start", &id]).assert_code(0);

    let refused = hull.cmd(&["delete", &id]);
    refused.assert_code(125);
    assert!(refused.stderr.contains("--force"), "{}", refused.stderr);
    assert!(is_alive(pid));

    hull.cmd(&["delete", "--force", &id]).assert_code(0);
    assert_eq!(wait_exit(pid), 137);
    assert_no_state(&hull);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn deleting_a_created_container_kills_its_init() {
    let hull = hull();
    let id = unique_id("delete-created");
    let mut bundle = Bundle::new();
    bundle.sh("echo should never run");
    let before = HostMounts::capture();
    hull.create(&bundle, &id).assert_code(0);
    let pid = hull.pid(&id);

    hull.cmd(&["delete", &id]).assert_code(0);
    assert_eq!(wait_exit(pid), 137);
    assert_eq!(bundle.output(), "");
    assert_no_state(&hull);
    before.assert_unchanged();
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn a_created_container_inherits_no_runtime_descriptors() {
    // The create path holds two extra descriptors across clone3: the state lock and an O_PATH
    // handle to the exec FIFO. Neither may survive into the user's program.
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.probe();
    let outcome = hull.create_start_wait(&bundle, &unique_id("fds"));
    outcome.assert_code(0);
    let report: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    let fds: Vec<&String> = report["fds"].as_object().unwrap().keys().collect();
    assert_eq!(fds, ["0", "1", "2"], "only stdio may be inherited: {}", report["fds"]);
    assert_no_state(&hull);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn create_requires_a_proc_mount() {
    let hull = hull();
    let mut bundle = Bundle::new();
    bundle.sh("true").edit(|c| {
        c["mounts"].as_array_mut().unwrap().retain(|m| m["destination"] != "/proc");
    });
    let outcome = hull.create(&bundle, &unique_id("noproc"));
    outcome.assert_code(125);
    assert!(outcome.stderr.contains("needs a mount at /proc"), "{}", outcome.stderr);
    assert_no_state(&hull);
}

#[test]
#[ignore = "needs root and fixtures: run scripts/test-integration.sh"]
fn unfinished_features_say_so() {
    let hull = hull();
    let id = unique_id("unfinished");
    let mut bundle = Bundle::new();
    bundle.args(&["sleep", "30"]);
    hull.create(&bundle, &id).assert_code(0);

    let all = hull.cmd(&["kill", "--all", &id, "KILL"]);
    all.assert_code(125);
    assert!(all.stderr.contains("milestone M3"), "{}", all.stderr);

    bundle.write();
    let detach = hull.cmd(&["run", "--detach", "--bundle", bundle.path().to_str().unwrap(), "x"]);
    detach.assert_code(125);
    assert!(detach.stderr.contains("exercise"), "{}", detach.stderr);

    hull.cmd(&["delete", &id]).assert_code(0);
}
