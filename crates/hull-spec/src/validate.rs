use std::collections::HashSet;
use std::fmt;

use crate::Milestone;
use crate::mounts::{MountError, parse_mount};
use crate::oci::{Linux, LinuxIdMapping, LinuxNamespaceType, Process, Spec};

/// One problem found in a config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The JSON path of the offending field, like `process.args` or `mounts[3]`.
    pub field: String,
    /// What is wrong.
    pub kind: ViolationKind,
}

/// The two kinds of problems.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// The config is wrong according to the OCI spec (or a rule hull enforces for safety).
    Invalid(String),
    /// The config is fine, but hull does not implement this yet, and running without it could
    /// silently weaken isolation.
    NotYetImplemented(Milestone),
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ViolationKind::Invalid(reason) => write!(f, "{}: {reason}", self.field),
            ViolationKind::NotYetImplemented(m) => write!(
                f,
                "{}: not implemented yet (planned for {m}); remove it to run without it",
                self.field
            ),
        }
    }
}

/// Every problem found in a config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<Violation>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid container configuration ({} problem", self.0.len())?;
        if self.0.len() != 1 {
            f.write_str("s")?;
        }
        f.write_str("):")?;
        for violation in &self.0 {
            write!(f, "\n  - {violation}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

#[derive(Default)]
struct Checker(Vec<Violation>);

impl Checker {
    fn invalid(&mut self, field: impl Into<String>, reason: impl Into<String>) {
        self.0.push(Violation { field: field.into(), kind: ViolationKind::Invalid(reason.into()) });
    }

    fn later(&mut self, field: impl Into<String>, milestone: Milestone) {
        self.0.push(Violation {
            field: field.into(),
            kind: ViolationKind::NotYetImplemented(milestone),
        });
    }

    /// Reject `field` if `present`, because it belongs to `milestone`.
    fn unsupported(&mut self, present: bool, field: &str, milestone: Milestone) {
        if present {
            self.later(field, milestone);
        }
    }
}

/// Check `spec` against the OCI runtime spec and against what hull currently implements.
#[allow(clippy::too_many_lines)] // A flat checklist reads better than a dozen tiny functions.
pub fn validate(spec: &Spec) -> Result<(), ValidationErrors> {
    let mut c = Checker::default();

    if !spec.version().starts_with("1.") {
        c.invalid("ociVersion", format!("unsupported version {:?} (need 1.x)", spec.version()));
    }

    match spec.root() {
        None => c.invalid("root", "required on Linux"),
        Some(root) if root.path().as_os_str().is_empty() => {
            c.invalid("root.path", "must not be empty");
        }
        Some(_) => {}
    }

    match spec.process() {
        None => c.invalid("process", "required to run a container"),
        Some(process) => check_process(&mut c, process),
    }

    for (i, mount) in spec.mounts().iter().flatten().enumerate() {
        match parse_mount(mount) {
            Ok(_) => {}
            Err(MountError::Invalid(reason)) => c.invalid(format!("mounts[{i}]"), reason),
            Err(MountError::NotYetImplemented(m, what)) => {
                c.later(format!("mounts[{i}] ({what})"), m);
            }
        }
    }

    c.unsupported(spec.hooks().is_some(), "hooks", Milestone::M2);
    c.unsupported(
        spec.uid_mappings().is_some() || spec.gid_mappings().is_some(),
        "uidMappings/gidMappings (top level)",
        Milestone::Unscheduled,
    );

    let namespaces =
        spec.linux().as_ref().map(|linux| check_linux(&mut c, linux)).unwrap_or_default();

    let has = |ns: LinuxNamespaceType| namespaces.contains(&ns);
    if spec.hostname().as_deref().is_some_and(|h| !h.is_empty()) && !has(LinuxNamespaceType::Uts) {
        c.invalid("hostname", "setting a hostname requires a new uts namespace");
    }
    if spec.domainname().as_deref().is_some_and(|d| !d.is_empty()) && !has(LinuxNamespaceType::Uts)
    {
        c.invalid("domainname", "setting a domain name requires a new uts namespace");
    }

    if c.0.is_empty() { Ok(()) } else { Err(ValidationErrors(c.0)) }
}

fn check_process(c: &mut Checker, process: &Process) {
    match process.args().as_deref() {
        None | Some([]) => c.invalid("process.args", "at least one argument is required"),
        Some(args) => {
            if args.iter().any(|a| a.contains('\0')) {
                c.invalid("process.args", "arguments must not contain NUL bytes");
            }
        }
    }
    for (i, var) in process.env().iter().flatten().enumerate() {
        if !var.contains('=') || var.starts_with('=') || var.contains('\0') {
            c.invalid(format!("process.env[{i}]"), format!("{var:?} is not of the form KEY=value"));
        }
    }
    if !process.cwd().is_absolute() {
        c.invalid("process.cwd", "must be an absolute path");
    }
    if process.user().umask().is_some_and(|m| m > 0o777) {
        c.invalid("process.user.umask", "must be at most 0777");
    }

    let mut seen = HashSet::new();
    for (i, rlimit) in process.rlimits().iter().flatten().enumerate() {
        if !seen.insert(rlimit.typ().to_string()) {
            c.invalid(format!("process.rlimits[{i}]"), format!("duplicate {}", rlimit.typ()));
        }
        if rlimit.soft() > rlimit.hard() {
            c.invalid(format!("process.rlimits[{i}]"), "soft limit exceeds hard limit");
        }
    }

    c.unsupported(process.terminal().unwrap_or(false), "process.terminal", Milestone::M2);
    c.unsupported(process.capabilities().is_some(), "process.capabilities", Milestone::M4);
    c.unsupported(process.apparmor_profile().is_some(), "process.apparmorProfile", Milestone::M4);
    c.unsupported(process.selinux_label().is_some(), "process.selinuxLabel", Milestone::M4);
    c.unsupported(process.oom_score_adj().is_some(), "process.oomScoreAdj", Milestone::M4);
    c.unsupported(process.io_priority().is_some(), "process.ioPriority", Milestone::Unscheduled);
    c.unsupported(process.scheduler().is_some(), "process.scheduler", Milestone::Unscheduled);
    c.unsupported(
        process.exec_cpu_affinity().is_some(),
        "process.execCPUAffinity",
        Milestone::Unscheduled,
    );
}

/// Validate `linux` and return the set of namespace types that will be newly created.
fn check_linux(c: &mut Checker, linux: &Linux) -> HashSet<LinuxNamespaceType> {
    let mut created = HashSet::new();
    for (i, ns) in linux.namespaces().iter().flatten().enumerate() {
        if !created.insert(ns.typ()) {
            c.invalid(
                format!("linux.namespaces[{i}]"),
                format!("duplicate {} namespace", ns.typ()),
            );
        }
        if ns.path().is_some() {
            c.later(
                format!("linux.namespaces[{i}].path (joining an existing namespace)"),
                Milestone::M2,
            );
        }
    }

    let has_userns = created.contains(&LinuxNamespaceType::User);
    let uid_maps = linux.uid_mappings().as_deref().unwrap_or_default();
    let gid_maps = linux.gid_mappings().as_deref().unwrap_or_default();
    if has_userns {
        check_id_map(c, "linux.uidMappings", uid_maps);
        check_id_map(c, "linux.gidMappings", gid_maps);
    } else if !uid_maps.is_empty() || !gid_maps.is_empty() {
        c.invalid("linux.uidMappings", "id mappings require a new user namespace");
    }

    if let Some(propagation) = linux.rootfs_propagation().as_deref()
        && !matches!(
            propagation,
            "private"
                | "rprivate"
                | "slave"
                | "rslave"
                | "shared"
                | "rshared"
                | "unbindable"
                | "runbindable"
        )
    {
        c.invalid("linux.rootfsPropagation", format!("unknown propagation {propagation:?}"));
    }

    c.unsupported(linux.resources().is_some(), "linux.resources", Milestone::M3);
    c.unsupported(linux.cgroups_path().is_some(), "linux.cgroupsPath", Milestone::M3);
    c.unsupported(
        linux.devices().as_ref().is_some_and(|d| !d.is_empty()),
        "linux.devices",
        Milestone::M3,
    );
    c.unsupported(linux.seccomp().is_some(), "linux.seccomp", Milestone::M4);
    c.unsupported(
        linux.sysctl().as_ref().is_some_and(|s| !s.is_empty()),
        "linux.sysctl",
        Milestone::M4,
    );
    c.unsupported(
        linux.masked_paths().as_ref().is_some_and(|p| !p.is_empty()),
        "linux.maskedPaths",
        Milestone::M4,
    );
    c.unsupported(
        linux.readonly_paths().as_ref().is_some_and(|p| !p.is_empty()),
        "linux.readonlyPaths",
        Milestone::M4,
    );
    c.unsupported(linux.mount_label().is_some(), "linux.mountLabel", Milestone::M4);
    c.unsupported(linux.personality().is_some(), "linux.personality", Milestone::M4);
    // Offsets must be written before the first process exists in the time namespace, which needs
    // a different process-creation sequence than clone3 gives us. See docs/learn/02-namespaces.md.
    c.unsupported(linux.time_offsets().is_some(), "linux.timeOffsets", Milestone::M2);
    c.unsupported(linux.net_devices().is_some(), "linux.netDevices", Milestone::M8);
    c.unsupported(linux.intel_rdt().is_some(), "linux.intelRdt", Milestone::Unscheduled);
    c.unsupported(linux.memory_policy().is_some(), "linux.memoryPolicy", Milestone::Unscheduled);
    created
}

/// The kernel accepts at most 340 lines in `/proc/<pid>/uid_map` (Linux 4.15+).
const MAX_ID_MAP_LINES: usize = 340;

fn check_id_map(c: &mut Checker, field: &str, maps: &[LinuxIdMapping]) {
    if maps.is_empty() {
        c.invalid(field, "a new user namespace needs at least one mapping");
        return;
    }
    if maps.len() > MAX_ID_MAP_LINES {
        c.invalid(field, format!("at most {MAX_ID_MAP_LINES} mappings are allowed"));
    }
    for (i, m) in maps.iter().enumerate() {
        if m.size() == 0 {
            c.invalid(format!("{field}[{i}]"), "size must be greater than zero");
        }
        if m.container_id().checked_add(m.size()).is_none()
            || m.host_id().checked_add(m.size()).is_none()
        {
            c.invalid(format!("{field}[{i}]"), "range overflows 32 bits");
        }
    }
    // hull switches to uid/gid 0 inside the namespace right after the maps are written, so that
    // files it creates while building the rootfs have a valid owner. That requires 0 to be mapped.
    if !maps.iter().any(|m| m.container_id() == 0) {
        c.invalid(field, "container id 0 must be mapped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(patch: serde_json::Value) -> Spec {
        let mut base: serde_json::Value = serde_json::from_str(crate::DEFAULT_CONFIG_JSON).unwrap();
        merge(&mut base, patch);
        serde_json::from_value(base).unwrap()
    }

    fn merge(base: &mut serde_json::Value, patch: serde_json::Value) {
        match (base, patch) {
            (serde_json::Value::Object(b), serde_json::Value::Object(p)) => {
                for (k, v) in p {
                    merge(b.entry(k).or_insert(serde_json::Value::Null), v);
                }
            }
            (b, p) => *b = p,
        }
    }

    fn fields(result: Result<(), ValidationErrors>) -> Vec<String> {
        result.unwrap_err().0.into_iter().map(|v| v.field).collect()
    }

    #[test]
    fn collects_every_problem_at_once() {
        let s = spec(serde_json::json!({
            "process": {"args": [], "cwd": "relative", "env": ["NOEQUALS"]},
            "linux": {"seccomp": {"defaultAction": "SCMP_ACT_ALLOW"}},
        }));
        let got = fields(validate(&s));
        assert_eq!(got, ["process.args", "process.env[0]", "process.cwd", "linux.seccomp"]);
    }

    #[test]
    fn unimplemented_security_features_fail_closed_with_milestone() {
        let s = spec(serde_json::json!({
            "process": {"capabilities": {"bounding": ["CAP_KILL"]}},
            "linux": {"maskedPaths": ["/proc/kcore"]},
        }));
        let err = validate(&s).unwrap_err();
        assert!(err.0.iter().all(|v| v.kind == ViolationKind::NotYetImplemented(Milestone::M4)));
        assert!(err.to_string().contains("planned for M4 (security)"));
    }

    #[test]
    fn hostname_requires_uts_namespace() {
        let s = spec(serde_json::json!({"linux": {"namespaces": [{"type": "pid"}]}}));
        assert_eq!(fields(validate(&s)), ["hostname"]);
    }

    #[test]
    fn user_namespace_rules() {
        let s = spec(serde_json::json!({"linux": {
            "namespaces": [{"type": "user"}, {"type": "uts"}],
            "uidMappings": [{"containerID": 1, "hostID": 100_000, "size": 0}],
        }}));
        let got = fields(validate(&s));
        assert_eq!(
            got,
            ["linux.uidMappings[0]", "linux.uidMappings", "linux.gidMappings"],
            "size 0, container id 0 unmapped, and gid mappings missing"
        );

        let ok = spec(serde_json::json!({"linux": {
            "namespaces": [{"type": "user"}, {"type": "uts"}],
            "uidMappings": [{"containerID": 0, "hostID": 100_000, "size": 65_536}],
            "gidMappings": [{"containerID": 0, "hostID": 100_000, "size": 65_536}],
        }}));
        validate(&ok).unwrap();
    }

    #[test]
    fn mappings_without_user_namespace_are_rejected() {
        let s = spec(serde_json::json!({"linux": {
            "uidMappings": [{"containerID": 0, "hostID": 100_000, "size": 1}],
        }}));
        assert_eq!(fields(validate(&s)), ["linux.uidMappings"]);
    }

    #[test]
    fn duplicate_namespaces_and_rlimits() {
        let s = spec(serde_json::json!({
            "linux": {"namespaces": [{"type": "pid"}, {"type": "pid"}, {"type": "uts"}]},
            "process": {"rlimits": [
                {"type": "RLIMIT_NOFILE", "soft": 1, "hard": 1},
                {"type": "RLIMIT_NOFILE", "soft": 2, "hard": 1}
            ]},
        }));
        assert_eq!(
            fields(validate(&s)),
            ["process.rlimits[1]", "process.rlimits[1]", "linux.namespaces[1]"]
        );
    }
}
