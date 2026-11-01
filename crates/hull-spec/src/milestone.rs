use std::fmt;

/// The milestone (see `docs/PLAN.md` §14) that will implement a currently unsupported feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Milestone {
    /// Full OCI lifecycle: create/start/kill/delete, hooks, terminals, joining namespaces.
    M2,
    /// Cgroups: resource limits, devices, cgroup mounts.
    M3,
    /// Security: capabilities, seccomp, masked paths, LSMs, sysctls.
    M4,
    /// Rootless containers and idmapped mounts.
    M5,
    /// Networking.
    M8,
    /// Not on the roadmap yet.
    Unscheduled,
}

impl fmt::Display for Milestone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::M2 => "M2 (OCI lifecycle)",
            Self::M3 => "M3 (cgroups)",
            Self::M4 => "M4 (security)",
            Self::M5 => "M5 (rootless)",
            Self::M8 => "M8 (networking)",
            Self::Unscheduled => "a future milestone",
        })
    }
}
