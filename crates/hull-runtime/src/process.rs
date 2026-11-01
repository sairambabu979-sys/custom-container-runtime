//! Preparing the container's process: limits, identity, working directory, executable.
//!
//! Order matters. Each step needs privileges that a later step gives up:
//!
//! | Step | Why here |
//! |---|---|
//! | `setrlimit` | Raising a hard limit needs `CAP_SYS_RESOURCE`, gone after the uid change |
//! | `setgroups`, `setresgid`, `setresuid` | Changing identity; uid last, since it drops the power to change gids |
//! | `umask` | Affects only files the program creates |
//! | `chdir` | *After* the uid change, so permissions are checked as the container user |
//! | `PATH` lookup | After `chdir` (relative `PATH` entries) and as the container user (exec permission) |
//! | `no_new_privs` | Last before exec; from here on, setuid binaries cannot gain privileges |

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use hull_spec::oci::{PosixRlimitType, Process};
use rustix::fs::Access;
use rustix::process::{Gid, Resource, Rlimit, Uid};

use crate::{Context, Error, Result};

/// The default `umask` when `process.user.umask` is not set (the same default as runc).
const DEFAULT_UMASK: u32 = 0o022;

/// The `execve` arguments, computed after everything else is set up.
#[derive(Debug)]
pub struct ExecPlan {
    /// Resolved absolute (or cwd-relative) path of the program.
    pub path: CString,
    /// `argv`, including `argv[0]`.
    pub argv: Vec<CString>,
    /// The environment.
    pub envp: Vec<CString>,
}

/// Apply `process` to the current (child) process and return what to `execve`.
pub fn prepare(process: &Process) -> Result<ExecPlan> {
    for rlimit in process.rlimits().iter().flatten() {
        let resource = resource(rlimit.typ());
        let limit = Rlimit { current: finite(rlimit.soft()), maximum: finite(rlimit.hard()) };
        rustix::process::setrlimit(resource, limit)
            .context(|| format!("setrlimit {}", rlimit.typ()))?;
    }

    let user = process.user();
    // Read /etc/passwd while we are still root: it may not be readable by the container user.
    let mut env: Vec<String> = process.env().clone().unwrap_or_default();
    if !env.iter().any(|e| e.starts_with("HOME=")) {
        env.push(format!("HOME={}", home_directory(user.uid())));
    }
    let groups: Vec<Gid> =
        user.additional_gids().iter().flatten().map(|&g| Gid::from_raw(g)).collect();
    rustix::thread::set_thread_groups(&groups).context(|| format!("setgroups {groups:?}"))?;
    let gid = Gid::from_raw(user.gid());
    rustix::thread::set_thread_res_gid(gid, gid, gid)
        .context(|| format!("setresgid {}", user.gid()))?;
    let uid = Uid::from_raw(user.uid());
    rustix::thread::set_thread_res_uid(uid, uid, uid)
        .context(|| format!("setresuid {}", user.uid()))?;

    rustix::process::umask(rustix::fs::Mode::from_raw_mode(user.umask().unwrap_or(DEFAULT_UMASK)));

    let cwd = process.cwd();
    rustix::process::chdir(cwd).context(|| format!("chdir {}", cwd.display()))?;
    verify_cwd_is_reachable()?;

    let args = process.args().as_deref().unwrap_or_default();
    let program = args.first().ok_or_else(|| Error::Unsupported("process.args is empty".into()))?;
    let path = find_executable(program, &env)?;

    if process.no_new_privileges().unwrap_or(false) {
        rustix::thread::set_no_new_privs(true).context(|| "set no_new_privs".into())?;
    }

    Ok(ExecPlan {
        path: cstring(path.as_os_str().as_bytes())?,
        argv: args.iter().map(|a| cstring(a.as_bytes())).collect::<Result<_>>()?,
        envp: env.iter().map(|e| cstring(e.as_bytes())).collect::<Result<_>>()?,
    })
}

/// The home directory of `uid` according to the container's `/etc/passwd`, or `/`.
///
/// runc sets `HOME` this way when the config does not, and programs rely on it, so hull does the
/// same. (The differential test against runc is what caught this.) The file belongs to the image,
/// so it is read through a [`hull_fs::SafeRoot`] and with a size limit.
fn home_directory(uid: u32) -> String {
    const MAX_PASSWD: u64 = 4 * 1024 * 1024;
    let passwd = hull_fs::SafeRoot::open(Path::new("/"))
        .and_then(|root| root.read(Path::new("/etc/passwd"), MAX_PASSWD))
        .unwrap_or_default();
    home_from_passwd(&String::from_utf8_lossy(&passwd), uid).unwrap_or_else(|| "/".to_owned())
}

/// Find `uid`'s home directory in `/etc/passwd` content (`name:pw:uid:gid:gecos:home:shell`).
fn home_from_passwd(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let home = fields.get(5).filter(|h| !h.is_empty())?;
        (fields.get(2)?.parse::<u32>().ok()? == uid).then(|| (*home).to_owned())
    })
}

/// Refuse to run with a working directory outside the root filesystem.
///
/// If a host directory fd ever leaks into the container, `chdir("/proc/self/fd/N")` lands
/// *outside* the root, and the kernel reports such a cwd as `(unreachable)/...`. This is exactly
/// how CVE-2024-21626 escaped. hull does not leak descriptors, and this check makes sure that
/// staying true is not a matter of luck.
fn verify_cwd_is_reachable() -> Result<()> {
    let cwd = rustix::process::getcwd(Vec::new()).context(|| "getcwd".into())?;
    if cwd.as_bytes().starts_with(b"(unreachable)") {
        return Err(Error::Unsupported(format!(
            "working directory {} is outside the container's root filesystem",
            String::from_utf8_lossy(cwd.as_bytes())
        )));
    }
    Ok(())
}

/// Resolve `program` like `execvp(3)` does, using the *container's* `PATH`.
///
/// A program containing `/` is used as is. Otherwise each `PATH` entry is tried in order, and the
/// first regular file the current user may execute wins. Like runc, there is no fallback when
/// `PATH` is unset.
pub fn find_executable(program: &str, env: &[String]) -> Result<PathBuf> {
    if program.contains('/') {
        return Ok(PathBuf::from(program));
    }
    let path_var = env.iter().rev().find_map(|e| e.strip_prefix("PATH=")).unwrap_or("");
    for dir in path_var.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let candidate = Path::new(dir).join(program);
        let is_file = std::fs::metadata(&candidate).is_ok_and(|m| m.is_file());
        if is_file && rustix::fs::access(&candidate, Access::EXEC_OK).is_ok() {
            return Ok(candidate);
        }
    }
    Err(Error::Io {
        context: format!("executable {program:?} not found in PATH {path_var:?}"),
        source: std::io::Error::from(rustix::io::Errno::NOENT),
    })
}

fn cstring(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| {
        Error::Unsupported(format!("\"{}\" contains a NUL byte", bytes.escape_ascii()))
    })
}

/// `RLIM_INFINITY` is represented as `u64::MAX` in the spec and as `None` by rustix.
fn finite(value: u64) -> Option<u64> {
    (value != u64::MAX).then_some(value)
}

fn resource(typ: PosixRlimitType) -> Resource {
    match typ {
        PosixRlimitType::RlimitCpu => Resource::Cpu,
        PosixRlimitType::RlimitFsize => Resource::Fsize,
        PosixRlimitType::RlimitData => Resource::Data,
        PosixRlimitType::RlimitStack => Resource::Stack,
        PosixRlimitType::RlimitCore => Resource::Core,
        PosixRlimitType::RlimitRss => Resource::Rss,
        PosixRlimitType::RlimitNproc => Resource::Nproc,
        PosixRlimitType::RlimitNofile => Resource::Nofile,
        PosixRlimitType::RlimitMemlock => Resource::Memlock,
        PosixRlimitType::RlimitAs => Resource::As,
        PosixRlimitType::RlimitLocks => Resource::Locks,
        PosixRlimitType::RlimitSigpending => Resource::Sigpending,
        PosixRlimitType::RlimitMsgqueue => Resource::Msgqueue,
        PosixRlimitType::RlimitNice => Resource::Nice,
        PosixRlimitType::RlimitRtprio => Resource::Rtprio,
        PosixRlimitType::RlimitRttime => Resource::Rttime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_lookup_uses_the_given_path_not_ours() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("tool");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        let not_exec = dir.path().join("data");
        std::fs::write(&not_exec, "").unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let env = vec![format!("PATH=/nonexistent:{}", dir.path().display())];
        assert_eq!(find_executable("tool", &env).unwrap(), bin);
        assert!(find_executable("data", &env).is_err(), "non-executable files are skipped");
        assert!(find_executable("tool", &[]).is_err(), "no PATH means no search");
        assert_eq!(find_executable("./x", &[]).unwrap(), PathBuf::from("./x"));
    }

    #[test]
    fn home_lookup() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\n# comment\nweird\nwww:x:33:33::/var/www:\nnohome:x:7:7:::\n";
        assert_eq!(home_from_passwd(passwd, 0).as_deref(), Some("/root"));
        assert_eq!(home_from_passwd(passwd, 33).as_deref(), Some("/var/www"));
        assert_eq!(home_from_passwd(passwd, 7), None);
        assert_eq!(home_from_passwd(passwd, 1000), None);
    }

    #[test]
    fn infinity_maps_to_none() {
        assert_eq!(finite(u64::MAX), None);
        assert_eq!(finite(1024), Some(1024));
    }
}
