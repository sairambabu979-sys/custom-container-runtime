# OCI runtime-spec coverage

What `hull-runtime` does with each `config.json` field today. "Rejected" means validation fails
with the milestone that will add the feature. It does not mean "ignored". Running without a
security feature someone asked for is worse than not running.

| Field | Status | Milestone |
|---|---|---|
| `ociVersion` | Supported (1.x) | — |
| `root.path`, `root.readonly` | Supported | M1 |
| `mounts[]`: any filesystem type, `bind`/`rbind`, all attribute options, recursive (`rro`, ...) options, propagation, superblock flags, `key=value` parameters | Supported (fd-based mount API) | M1 |
| `mounts[]` of type `cgroup`/`cgroup2` | Rejected | M3 |
| `mounts[].uidMappings` / `idmap` options | Rejected | M5 |
| `process.args`, `env`, `cwd` | Supported (`PATH` lookup inside the container) | M1 |
| `process.user.uid`, `gid`, `additionalGids`, `umask` | Supported | M1 |
| `process.rlimits` | Supported | M1 |
| `process.noNewPrivileges` | Supported | M1 |
| `process.terminal`, `consoleSize` | Rejected | M2 |
| `process.capabilities` | Rejected | M4 |
| `process.apparmorProfile`, `selinuxLabel`, `oomScoreAdj` | Rejected | M4 |
| `process.ioPriority`, `scheduler`, `execCPUAffinity` | Rejected | unscheduled |
| `hostname`, `domainname` | Supported (require a UTS namespace) | M1 |
| `linux.namespaces` (all 8 types, newly created) | Supported | M1 |
| `linux.namespaces[].path` (join existing) | Rejected | M2 |
| `linux.uidMappings`, `gidMappings` | Supported (as root; rootless via `newuidmap` in M5) | M1 |
| `linux.rootfsPropagation` | Supported | M1 |
| `linux.timeOffsets` | Rejected | M2 |
| `linux.resources`, `cgroupsPath`, `devices` | Rejected | M3 |
| `linux.seccomp`, `sysctl`, `maskedPaths`, `readonlyPaths`, `mountLabel`, `personality` | Rejected | M4 |
| `linux.netDevices` | Rejected | M8 |
| `linux.intelRdt`, `memoryPolicy` | Rejected | unscheduled |
| `hooks` | Rejected | M2 |
| `annotations` | Supported (recorded in state) | M1 |
| Unknown properties | Ignored with a warning (the spec requires ignoring them) | — |

## Commands

| Command | Status |
|---|---|
| `spec`, `run`, `state`, `list` | Supported |
| `run --detach`, `create`, `start`, `kill`, `delete`, `exec`, `ps`, `features` | M2 |
| `pause`, `resume`, `update`, `events` | M3 |

## Behaviour that matches runc (verified by the differential tests)

Under the default config, a non-root user, a user namespace, and extra tmpfs and bind mounts, the
container sees the same capability sets, `no_new_privs`, seccomp mode, blocked and ignored signals,
umask, UIDs, GIDs and groups, environment (including `HOME`), rlimits, `/dev` contents, and the
same mount table, entry by entry. Two known differences are listed in
`bins/hull-runtime/tests/differential.rs`.
