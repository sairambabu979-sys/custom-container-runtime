//! Differential testing: run the same bundle under runc and under hull, and compare what the
//! container sees.
//!
//! runc is the reference implementation of the OCI runtime spec. Where hull and runc disagree,
//! hull is wrong unless the difference is listed in [`KNOWN_DIFFERENCES`] with a reason.

// Helpers in integration-test files are not `#[test]` functions, so clippy's test exemption
// does not cover them. A panic is exactly how a test helper should report failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use hull_testkit::{Bundle, Hull, runc_available, runc_run, unique_id};
use serde_json::{Value, json};

const HULL: &str = env!("CARGO_BIN_EXE_hull-runtime");

/// Fields that differ by design, and why.
const KNOWN_DIFFERENCES: [(&str, &str); 3] = [
    (
        "/namespaces",
        "namespace inode numbers are unique per container; compared as 'private or not' below",
    ),
    (
        "/fds",
        "runc proxies stdio through pipes in foreground mode; hull passes the caller's stdio through",
    ),
    ("/pid", "both are PID 1; compared explicitly"),
];

fn normalize(mut report: Value) -> Value {
    let host =
        |ns: &str| std::fs::read_link(format!("/proc/self/ns/{ns}")).unwrap().display().to_string();
    let private: serde_json::Map<String, Value> = report["namespaces"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(ns, link)| (ns.clone(), json!(link.as_str() != Some(host(ns).as_str()))))
        .collect();
    report["namespaces_private"] = Value::Object(private);
    for (pointer, _why) in KNOWN_DIFFERENCES {
        if let Some(v) = report.pointer_mut(pointer) {
            *v = Value::Null;
        }
    }
    // The cgroup mount does not exist in hull until M3, and runc places the container in a cgroup;
    // neither shows up in mountinfo with the default config, so mounts compare as-is.
    report
}

fn diff(path: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for key in x.keys().chain(y.keys().filter(|k| !x.contains_key(*k))) {
                diff(
                    &format!("{path}/{key}"),
                    x.get(key).unwrap_or(&Value::Null),
                    y.get(key).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (u, v)) in x.iter().zip(y).enumerate() {
                diff(&format!("{path}/{i}"), u, v, out);
            }
        }
        _ if a != b => out.push(format!("{path}:\n    runc: {a}\n    hull: {b}")),
        _ => {}
    }
}

fn compare(bundle: &mut Bundle, name: &str) {
    assert!(runc_available(), "runc is required for differential tests (apt install runc)");
    bundle.probe();
    let runc =
        normalize(runc_run(bundle, &unique_id(&format!("{name}-runc"))).assert_code(0).json());
    let hull = normalize(
        Hull::new(HULL).run(bundle, &unique_id(&format!("{name}-hull"))).assert_code(0).json(),
    );
    let mut differences = Vec::new();
    diff("", &runc, &hull, &mut differences);
    assert!(differences.is_empty(), "hull and runc disagree:\n{}", differences.join("\n"));
}

#[test]
#[ignore = "needs root, fixtures and runc: run scripts/test-integration.sh"]
fn default_config_matches_runc() {
    compare(&mut Bundle::new(), "default");
}

#[test]
#[ignore = "needs root, fixtures and runc: run scripts/test-integration.sh"]
fn non_root_user_matches_runc() {
    let mut bundle = Bundle::new();
    bundle.edit(|c| {
        c["process"]["user"] = json!({"uid": 1000, "gid": 1000, "additionalGids": [5]});
        c["process"]["cwd"] = json!("/tmp");
        c["process"]["env"] = json!(["PATH=/bin:/usr/bin", "LANG=C.UTF-8"]);
    });
    compare(&mut bundle, "user");
}

#[test]
#[ignore = "needs root, fixtures and runc: run scripts/test-integration.sh"]
fn user_namespace_matches_runc() {
    let mut bundle = Bundle::new();
    bundle.edit(|c| {
        c["linux"]["namespaces"].as_array_mut().unwrap().push(json!({"type": "user"}));
        c["linux"]["uidMappings"] = json!([{"containerID": 0, "hostID": 200_000, "size": 65536}]);
        c["linux"]["gidMappings"] = json!([{"containerID": 0, "hostID": 200_000, "size": 65536}]);
    });
    // The rootfs belongs to host root, which is unmapped inside; give it to the mapped root.
    std::process::Command::new("chown")
        .args(["-R", "200000:200000"])
        .arg(bundle.rootfs())
        .status()
        .unwrap();
    compare(&mut bundle, "userns");
}

#[test]
#[ignore = "needs root, fixtures and runc: run scripts/test-integration.sh"]
fn writable_root_and_extra_mounts_match_runc() {
    let mut bundle = Bundle::new();
    bundle.edit(|c| {
        c["root"]["readonly"] = json!(false);
        let mounts = c["mounts"].as_array_mut().unwrap();
        mounts.push(json!({"destination": "/scratch", "type": "tmpfs", "source": "tmpfs", "options": ["noexec", "size=1m", "mode=1777"]}));
        mounts.push(json!({"destination": "/etc/hostname-copy", "source": "/etc/hostname", "options": ["bind", "ro"]}));
    });
    compare(&mut bundle, "mounts");
}
