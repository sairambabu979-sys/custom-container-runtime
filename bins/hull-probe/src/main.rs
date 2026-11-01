//! `hull-probe`: runs *inside* a container and prints a JSON description of what it can see.
//!
//! The integration tests copy this (statically linked) binary into a container's rootfs, run it
//! under hull and under runc, and compare the two outputs. Anything that differs is either a bug
//! in hull or a documented, deliberate difference.
//!
//! It only reads from `/proc` and the filesystem and has no dependencies besides `serde_json`, so
//! it works in any image.
//!
//! # Why `#![no_main]`
//!
//! Before calling `main`, the Rust runtime sets `SIGPIPE` to "ignored". The probe would then
//! report its *own* runtime's change instead of the signal state the container runtime handed
//! over. With `no_main`, the C library calls our `main` directly and nothing is touched. (This
//! is not hypothetical: the first version of this probe hid exactly that bug in hull itself.)

#![no_main]
// The one unsafe construct here is the unmangled C `main` symbol, required by `no_main`.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use serde_json::{Map, Value, json};

/// The `/proc/self/status` lines worth comparing between runtimes.
const STATUS_KEYS: [&str; 13] = [
    "Uid",
    "Gid",
    "Groups",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
    "SigBlk",
    "SigIgn",
    "Umask",
];

const NAMESPACES: [&str; 8] = ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"];

// SAFETY: this is the process entry point that the C runtime calls exactly once. Exporting the
// symbol `main` unmangled is what `no_main` requires; no other code defines it.
#[unsafe(no_mangle)]
extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    report();
    0
}

fn report() {
    let report = json!({
        "pid": std::process::id(),
        "cwd": std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        "hostname": read_trimmed("/proc/sys/kernel/hostname"),
        "domainname": read_trimmed("/proc/sys/kernel/domainname"),
        "uid_map": read_trimmed("/proc/self/uid_map"),
        "gid_map": read_trimmed("/proc/self/gid_map"),
        "status": status(),
        "namespaces": namespaces(),
        "mounts": mounts(),
        "rlimits": rlimits(),
        "env": env(),
        "fds": fds(),
        "dev": dev(),
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path).map(|s| s.trim().to_owned()).unwrap_or_default()
}

fn status() -> Value {
    let text = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut out = Map::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':')
            && STATUS_KEYS.contains(&key)
        {
            let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
            out.insert(key.to_owned(), Value::String(normalized));
        }
    }
    Value::Object(out)
}

fn namespaces() -> Value {
    let mut out = Map::new();
    for ns in NAMESPACES {
        let link = fs::read_link(format!("/proc/self/ns/{ns}"))
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        out.insert(ns.to_owned(), Value::String(link));
    }
    Value::Object(out)
}

/// `/proc/self/mountinfo`, one object per mount, without the fields that differ run to run
/// (mount IDs, device numbers).
fn mounts() -> Value {
    let text = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mounts = text
        .lines()
        .filter_map(|line| {
            // Format: id parent major:minor root mount_point options [optional...] - fstype source super_options
            let (left, right) = line.split_once(" - ")?;
            let left: Vec<&str> = left.split(' ').collect();
            let right: Vec<&str> = right.split(' ').collect();
            Some(json!({
                "root": left.get(3)?,
                "mount_point": left.get(4)?,
                "options": left.get(5)?,
                "optional": left.get(6..).unwrap_or_default().join(" "),
                "fs_type": right.first()?,
                "source": right.get(1)?,
                "super_options": right.get(2)?,
            }))
        })
        .collect();
    Value::Array(mounts)
}

fn rlimits() -> Value {
    let text = fs::read_to_string("/proc/self/limits").unwrap_or_default();
    let mut out = BTreeMap::new();
    for line in text.lines().skip(1) {
        // "Max open files            1024                 1024                 files"
        let name = line.get(..26).unwrap_or_default().trim();
        let rest: Vec<&str> = line.get(26..).unwrap_or_default().split_whitespace().collect();
        if let (Some(soft), Some(hard)) = (rest.first(), rest.get(1)) {
            out.insert(name.to_owned(), json!([soft, hard]));
        }
    }
    json!(out)
}

fn env() -> Value {
    let mut vars: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    vars.sort();
    json!(vars)
}

fn fds() -> Value {
    let mut out = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/proc/self/fd") else { return json!(out) };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // The directory handle used by read_dir itself shows up too and is not interesting.
        if let Ok(target) = fs::read_link(entry.path())
            && !target.to_string_lossy().contains("/fd")
        {
            out.insert(name, target.display().to_string());
        }
    }
    json!(out)
}

fn dev() -> Value {
    let mut out = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/dev") else { return json!(out) };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
        let kind = meta.file_type();
        let description = if kind.is_symlink() {
            format!(
                "symlink -> {}",
                fs::read_link(entry.path()).map(|p| p.display().to_string()).unwrap_or_default()
            )
        } else if kind.is_char_device() {
            let rdev = meta.rdev();
            format!(
                "char {}:{} {:o}",
                (rdev >> 8) & 0xfff,
                (rdev & 0xff) | ((rdev >> 12) & 0xfff00),
                meta.mode() & 0o7777
            )
        } else if kind.is_dir() {
            format!("dir {:o}", meta.mode() & 0o7777)
        } else {
            format!("file {:o}", meta.mode() & 0o7777)
        };
        out.insert(name, description);
    }
    json!(out)
}
