//! Translating OCI mount entries into kernel operations.
//!
//! An OCI mount is written in the vocabulary of `mount(8)`: a type, a source and a list of option
//! strings like `"nosuid"`, `"mode=755"` or `"rbind"`. The kernel's new mount API wants something
//! different, split three ways:
//!
//! | Option kind | Example | Kernel mechanism |
//! |---|---|---|
//! | How to create the mount | `bind`, `rbind` | `open_tree` instead of `fsopen` |
//! | Per-mount attributes | `ro`, `nosuid`, `noatime` | `fsmount` / `mount_setattr` |
//! | Propagation | `rslave`, `private` | `mount_setattr` |
//! | Filesystem parameters | `mode=755`, `size=64k`, `newinstance` | `fsconfig` |
//!
//! [`parse_mount`] does that split once, during validation, so that an option hull does not
//! understand is reported before anything is mounted.

use std::path::PathBuf;

use hull_sys::mount::{AttrChange, MountAttrs, Propagation};

use crate::Milestone;
use crate::oci::Mount;

/// How the mount is created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountKind {
    /// A bind mount of `source`. Recursive (`rbind`) includes the mounts below `source`.
    Bind {
        /// True for `rbind`.
        recursive: bool,
    },
    /// A new instance of a filesystem type such as `proc` or `tmpfs`.
    Filesystem {
        /// The filesystem type passed to `fsopen`.
        fstype: String,
    },
}

/// A filesystem parameter passed to `fsconfig`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsOption {
    /// A flag such as `newinstance`.
    Flag(String),
    /// A `key=value` parameter such as `mode=755`.
    Value(String, String),
}

/// A mount entry translated into kernel terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMount {
    /// Where to mount, inside the container (lexically cleaned, absolute).
    pub destination: PathBuf,
    /// The source as written in the config (relative bind sources are relative to the bundle).
    pub source: Option<PathBuf>,
    /// How to create the mount.
    pub kind: MountKind,
    /// Attributes for the mount itself.
    pub attrs: AttrChange,
    /// Attributes for the mount and everything below it (`rro`, `rnosuid`, ...).
    pub recursive_attrs: AttrChange,
    /// Propagation type, and whether it applies recursively (`rslave` vs `slave`).
    pub propagation: Option<(Propagation, bool)>,
    /// Filesystem parameters (only for [`MountKind::Filesystem`]).
    pub fs_options: Vec<FsOption>,
}

/// Why a mount entry cannot be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountError {
    /// The entry is malformed.
    Invalid(String),
    /// The entry is valid but needs a feature from a later milestone.
    NotYetImplemented(Milestone, String),
}

/// One of the per-mount attribute options, in its non-recursive spelling.
fn attr_option(name: &str) -> Option<fn(&mut AttrChange)> {
    fn set_atime(c: &mut AttrChange, mode: MountAttrs) {
        c.clear |= MountAttrs::ATIME_MASK;
        c.set = (c.set - MountAttrs::ATIME_MASK) | mode;
    }
    Some(match name {
        "ro" => |c| c.set |= MountAttrs::RDONLY,
        "rw" => |c| c.clear |= MountAttrs::RDONLY,
        "nosuid" => |c| c.set |= MountAttrs::NOSUID,
        "suid" => |c| c.clear |= MountAttrs::NOSUID,
        "nodev" => |c| c.set |= MountAttrs::NODEV,
        "dev" => |c| c.clear |= MountAttrs::NODEV,
        "noexec" => |c| c.set |= MountAttrs::NOEXEC,
        "exec" => |c| c.clear |= MountAttrs::NOEXEC,
        "noatime" => |c| set_atime(c, MountAttrs::NOATIME),
        "strictatime" | "norelatime" => |c| set_atime(c, MountAttrs::STRICTATIME),
        "relatime" | "atime" | "nostrictatime" => |c| set_atime(c, MountAttrs::RELATIME),
        "nodiratime" => |c| c.set |= MountAttrs::NODIRATIME,
        "diratime" => |c| c.clear |= MountAttrs::NODIRATIME,
        "nosymfollow" => |c| c.set |= MountAttrs::NOSYMFOLLOW,
        "symfollow" => |c| c.clear |= MountAttrs::NOSYMFOLLOW,
        _ => return None,
    })
}

fn propagation_option(name: &str) -> Option<(Propagation, bool)> {
    Some(match name {
        "private" => (Propagation::Private, false),
        "rprivate" => (Propagation::Private, true),
        "shared" => (Propagation::Shared, false),
        "rshared" => (Propagation::Shared, true),
        "slave" => (Propagation::Slave, false),
        "rslave" => (Propagation::Slave, true),
        "unbindable" => (Propagation::Unbindable, false),
        "runbindable" => (Propagation::Unbindable, true),
        _ => return None,
    })
}

/// A superblock option: either a flag `fsconfig` must receive, or a spelling of the default.
#[derive(Clone, Copy)]
enum Superblock {
    Flag(&'static str),
    Default,
}

/// Superblock flags that `fsconfig` understands for every filesystem type.
fn superblock_option(name: &str) -> Option<Superblock> {
    Some(match name {
        "sync" => Superblock::Flag("sync"),
        "dirsync" => Superblock::Flag("dirsync"),
        "lazytime" => Superblock::Flag("lazytime"),
        "mand" => Superblock::Flag("mand"),
        "async" | "nolazytime" | "nomand" => Superblock::Default,
        _ => return None,
    })
}

/// The options of one mount entry, sorted by the kernel mechanism that consumes them.
#[derive(Default)]
#[allow(clippy::struct_field_names)] // `fs_options` mirrors the public `ParsedMount` field.
struct Options<'a> {
    bind: Option<bool>,
    attrs: AttrChange,
    recursive_attrs: AttrChange,
    propagation: Option<(Propagation, bool)>,
    fs_options: Vec<FsOption>,
    superblock: Vec<(&'a str, Superblock)>,
}

fn classify_options(options: &[String]) -> Result<Options<'_>, MountError> {
    let mut out = Options::default();
    for option in options {
        let option = option.as_str();
        if option == "bind" || option == "rbind" {
            out.bind = Some(option == "rbind");
        } else if option == "defaults" {
            // Means "no change"; nothing to do.
        } else if let Some(apply) = attr_option(option) {
            apply(&mut out.attrs);
        } else if let Some(apply) = option.strip_prefix('r').and_then(attr_option) {
            apply(&mut out.recursive_attrs);
        } else if let Some(p) = propagation_option(option) {
            out.propagation = Some(p);
        } else if let Some(sb) = superblock_option(option) {
            out.superblock.push((option, sb));
        } else if matches!(option, "idmap" | "ridmap") {
            return Err(MountError::NotYetImplemented(Milestone::M5, "idmapped mounts".into()));
        } else if matches!(option, "remount" | "tmpcopyup" | "move") {
            return Err(MountError::Invalid(format!("unsupported mount option {option:?}")));
        } else if let Some((key, value)) = option.split_once('=') {
            out.fs_options.push(FsOption::Value(key.to_owned(), value.to_owned()));
        } else {
            out.fs_options.push(FsOption::Flag(option.to_owned()));
        }
    }
    Ok(out)
}

/// Translate one OCI mount entry.
pub fn parse_mount(mount: &Mount) -> Result<ParsedMount, MountError> {
    let destination = mount.destination();
    if !destination.is_absolute() {
        return Err(MountError::Invalid(format!(
            "destination {} must be an absolute path",
            destination.display()
        )));
    }
    let destination = hull_fs::clean_absolute(destination);
    if destination.as_os_str() == "/" {
        return Err(MountError::Invalid("cannot mount over the container's root".into()));
    }
    if mount.uid_mappings().is_some() || mount.gid_mappings().is_some() {
        return Err(MountError::NotYetImplemented(Milestone::M5, "idmapped mounts".into()));
    }

    let mut options = classify_options(mount.options().as_deref().unwrap_or_default())?;

    let typ = mount.typ().as_deref();
    let kind = match (options.bind, typ) {
        (Some(recursive), _) => MountKind::Bind { recursive },
        (None, Some("bind")) => MountKind::Bind { recursive: false },
        (None, Some("cgroup" | "cgroup2")) => {
            return Err(MountError::NotYetImplemented(Milestone::M3, "cgroup mounts".into()));
        }
        (None, Some(fstype)) if !fstype.is_empty() && fstype != "none" => {
            MountKind::Filesystem { fstype: fstype.to_owned() }
        }
        (None, _) => {
            return Err(MountError::Invalid(
                "a type is required unless the options contain \"bind\" or \"rbind\"".into(),
            ));
        }
    };

    match kind {
        MountKind::Bind { .. } => {
            if mount.source().is_none() {
                return Err(MountError::Invalid("bind mounts require a source".into()));
            }
            if let Some(FsOption::Flag(o) | FsOption::Value(o, _)) = options.fs_options.first() {
                return Err(MountError::Invalid(format!(
                    "unknown bind-mount option {o:?} (filesystem parameters have no effect on a bind mount)"
                )));
            }
            if let Some((o, _)) = options.superblock.first() {
                return Err(MountError::Invalid(format!(
                    "superblock option {o:?} has no effect on a bind mount"
                )));
            }
        }
        MountKind::Filesystem { .. } => {
            if !options.recursive_attrs.is_empty() {
                return Err(MountError::Invalid(
                    "recursive attributes (rro, rnosuid, ...) only apply to bind mounts".into(),
                ));
            }
            // `ro` on a new filesystem means a read-only *superblock* too, as with mount(8) and
            // runc: the filesystem instance itself refuses writes, not just this one mount of it.
            // (The differential test against runc caught the mount-only version.)
            if options.attrs.set.contains(MountAttrs::RDONLY) {
                options.fs_options.push(FsOption::Flag("ro".into()));
            }
            for (_, sb) in &options.superblock {
                if let Superblock::Flag(flag) = sb {
                    options.fs_options.push(FsOption::Flag((*flag).to_owned()));
                }
            }
        }
    }

    Ok(ParsedMount {
        destination,
        source: mount.source().clone(),
        kind,
        attrs: options.attrs,
        recursive_attrs: options.recursive_attrs,
        propagation: options.propagation,
        fs_options: options.fs_options,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(json: &str) -> Mount {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn tmpfs_with_attributes_and_parameters() {
        let parsed = parse_mount(&mount(
            r#"{"destination":"/dev","type":"tmpfs","source":"tmpfs",
                "options":["nosuid","strictatime","mode=755","size=65536k"]}"#,
        ))
        .unwrap();
        assert_eq!(parsed.kind, MountKind::Filesystem { fstype: "tmpfs".into() });
        assert_eq!(parsed.attrs.set, MountAttrs::NOSUID | MountAttrs::STRICTATIME);
        assert!(parsed.attrs.clear.contains(MountAttrs::ATIME_MASK));
        assert_eq!(
            parsed.fs_options,
            [
                FsOption::Value("mode".into(), "755".into()),
                FsOption::Value("size".into(), "65536k".into())
            ]
        );
    }

    #[test]
    fn read_only_filesystems_get_a_read_only_superblock() {
        let parsed = parse_mount(&mount(
            r#"{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","ro"]}"#,
        ))
        .unwrap();
        assert!(parsed.attrs.set.contains(MountAttrs::RDONLY));
        assert_eq!(parsed.fs_options, [FsOption::Flag("ro".into())]);
    }

    #[test]
    fn rbind_with_recursive_readonly_and_propagation() {
        let parsed = parse_mount(&mount(
            r#"{"destination":"/data","source":"/srv","options":["rbind","rro","rslave","nosuid"]}"#,
        ))
        .unwrap();
        assert_eq!(parsed.kind, MountKind::Bind { recursive: true });
        assert_eq!(parsed.recursive_attrs.set, MountAttrs::RDONLY);
        assert_eq!(parsed.attrs.set, MountAttrs::NOSUID);
        assert_eq!(parsed.propagation, Some((Propagation::Slave, true)));
    }

    #[test]
    fn relatime_and_rw_are_not_mistaken_for_recursive_options() {
        let parsed = parse_mount(&mount(
            r#"{"destination":"/x","type":"tmpfs","options":["rw","relatime"]}"#,
        ))
        .unwrap();
        assert_eq!(parsed.recursive_attrs, AttrChange::default());
        assert!(parsed.attrs.clear.contains(MountAttrs::RDONLY));
    }

    #[test]
    fn rejects_problems_before_mounting() {
        let cases = [
            r#"{"destination":"relative","type":"tmpfs"}"#,
            r#"{"destination":"/","type":"tmpfs"}"#,
            r#"{"destination":"/x"}"#,
            r#"{"destination":"/x","options":["bind"]}"#,
            r#"{"destination":"/x","source":"/y","options":["bind","size=1k"]}"#,
            r#"{"destination":"/x","type":"tmpfs","options":["rro"]}"#,
            r#"{"destination":"/x","type":"tmpfs","options":["remount"]}"#,
        ];
        for case in cases {
            assert!(matches!(parse_mount(&mount(case)), Err(MountError::Invalid(_))), "{case}");
        }
    }

    #[test]
    fn names_the_milestone_for_unimplemented_features() {
        let cgroup = parse_mount(&mount(r#"{"destination":"/sys/fs/cgroup","type":"cgroup"}"#));
        assert!(matches!(cgroup, Err(MountError::NotYetImplemented(Milestone::M3, _))));
        let idmap =
            parse_mount(&mount(r#"{"destination":"/x","source":"/y","options":["bind","idmap"]}"#));
        assert!(matches!(idmap, Err(MountError::NotYetImplemented(Milestone::M5, _))));
    }
}
