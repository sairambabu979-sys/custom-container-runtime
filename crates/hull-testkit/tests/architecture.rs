//! The crate graph must point strictly downward (`docs/PLAN.md` §3):
//!
//! ```text
//! bins -> hull-runtime -> hull-spec -> hull-fs -> hull-sys
//! ```
//!
//! A crate that reaches *up* the stack (say, `hull-fs` using `hull-runtime`) makes the layers
//! meaningless: the "unsafe only in hull-sys" rule, for example, only holds if nothing below the
//! runtime can call back into it. This test reads the real dependency graph from `cargo metadata`
//! and fails on any edge that is not listed below.

// A panic is how a test reports failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// Every workspace crate and the workspace crates it may use as normal or build dependencies.
/// A new crate must be added here, which forces a decision about where it sits.
const ALLOWED: &[(&str, &[&str])] = &[
    ("hull-sys", &[]),
    ("hull-fs", &["hull-sys"]),
    ("hull-spec", &["hull-sys", "hull-fs"]),
    ("hull-runtime", &["hull-sys", "hull-fs", "hull-spec"]),
    // Test support drives the *binary*, so it must not reach into runtime internals.
    ("hull-testkit", &["hull-spec"]),
    ("hull-runtime-cli", &["hull-runtime", "hull-spec"]),
    // Runs inside containers: it must not link any of the runtime.
    ("hull-probe", &[]),
];

/// Workspace crates any crate may use as a *dev*-dependency.
const ALLOWED_DEV: &[&str] = &["hull-testkit"];

fn metadata() -> Value {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--offline", "--format-version", "1", "--manifest-path"])
        .arg(manifest)
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse cargo metadata")
}

#[test]
fn workspace_dependencies_point_downward() {
    let metadata = metadata();
    let packages = metadata["packages"].as_array().unwrap();
    let workspace: Vec<&str> = packages.iter().map(|p| p["name"].as_str().unwrap()).collect();

    let mut violations = Vec::new();
    for package in packages {
        let name = package["name"].as_str().unwrap();
        let Some((_, allowed)) = ALLOWED.iter().find(|(crate_name, _)| *crate_name == name) else {
            violations
                .push(format!("{name} is not listed in ALLOWED; decide which layer it belongs to"));
            continue;
        };
        for dep in package["dependencies"].as_array().unwrap() {
            let dep_name = dep["name"].as_str().unwrap();
            if !workspace.contains(&dep_name) {
                continue; // Third-party crate.
            }
            let is_dev = dep["kind"].as_str() == Some("dev");
            let ok = if is_dev {
                ALLOWED_DEV.contains(&dep_name) || allowed.contains(&dep_name)
            } else {
                allowed.contains(&dep_name)
            };
            if !ok {
                let kind = if is_dev { "dev-dependency" } else { "dependency" };
                violations.push(format!("{name} -> {dep_name} ({kind}) points up or sideways"));
            }
        }
    }
    assert!(violations.is_empty(), "crate layering violated:\n  {}", violations.join("\n  "));
}
