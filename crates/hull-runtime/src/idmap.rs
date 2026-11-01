//! Writing user-namespace ID maps.
//!
//! A new user namespace starts with *no* mapping: every ID inside is the overflow ID (65534), and
//! the process can do very little. The parent fills in `/proc/<pid>/uid_map` and `gid_map`, each
//! line meaning "container IDs `inside..inside+count` are host IDs `outside..outside+count`".
//!
//! The kernel's rules are strict: each map can be written exactly once, in a single `write(2)`,
//! by a process with the right capabilities in the *parent* user namespace. That is why the
//! parent writes them while the child waits.

use std::io::Write;
use std::path::Path;

use rustix::process::Pid;

use crate::{Context, Result};
use hull_spec::oci::LinuxIdMapping;

/// Format maps in the kernel's `inside outside count` line format.
fn format_map(maps: &[LinuxIdMapping]) -> String {
    use std::fmt::Write as _;
    maps.iter().fold(String::new(), |mut out, m| {
        let _ = writeln!(out, "{} {} {}", m.container_id(), m.host_id(), m.size());
        out
    })
}

fn write_once(path: &Path, content: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .context(|| format!("open {}", path.display()))?;
    // `write`, not `write_all`: a short write would leave the map half-written forever.
    let written = file.write(content.as_bytes()).context(|| format!("write {}", path.display()))?;
    if written != content.len() {
        return Err(std::io::Error::other("short write"))
            .context(|| format!("write {}", path.display()));
    }
    Ok(())
}

/// Write the UID and GID maps of the process `pid`.
pub fn write_id_maps(pid: Pid, uid: &[LinuxIdMapping], gid: &[LinuxIdMapping]) -> Result<()> {
    let proc = format!("/proc/{}", pid.as_raw_nonzero());
    write_once(Path::new(&proc).join("uid_map").as_path(), &format_map(uid))?;
    write_once(Path::new(&proc).join("gid_map").as_path(), &format_map(gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_kernel_lines() {
        let maps: Vec<LinuxIdMapping> = serde_json::from_str(
            r#"[{"containerID":0,"hostID":100000,"size":65536},{"containerID":65536,"hostID":1000,"size":1}]"#,
        )
        .unwrap();
        assert_eq!(format_map(&maps), "0 100000 65536\n65536 1000 1\n");
    }
}
