# `hull` — a container engine from first principles

> Working name: **hull**. Rename freely; it appears only in binary and crate names.
>
> Status: **M1 done; M0 done except a first green CI run** (see §14 and [STATUS.md](STATUS.md)). Decisions are recorded in §16.
>
> Confidence tags used in this document: **[C]** certain (verified or hard evidence),
> **[L]** likely (strong inference, verify during implementation), **[G]** guess (estimate).

---

## 0. The thesis

"Similar to Docker" is the wrong target. Docker is really six systems bundled together: an OCI
runtime, a supervisor, image distribution, a snapshotter, a network stack, and a build system,
all behind a daemon and an API. If we try to rebuild all of it, we get a wide, shallow toy, and
that is exactly what a world-class engineer would *not* ship.

Instead we build the **same layered architecture the real ecosystem uses**, and we make every
layer **provably correct against an external oracle**:

| Layer | Real-world equivalent | Our deliverable | Oracle that proves it works |
|---|---|---|---|
| Low-level runtime | runc, crun, youki | `hull-runtime`, an OCI Runtime Spec 1.2 implementation with a runc-compatible CLI | `opencontainers/runtime-tools` validation suite, **differential testing against runc**, and `podman --runtime=hull-runtime` |
| Supervisor | containerd-shim, conmon | `hull-shim`, a per-container subreaper, log writer and exit-code recorder | Fault-injection and leak-detection tests |
| Images and storage | containerd content store and snapshotters | OCI Distribution client, OCI Image Layout store, overlayfs snapshotter | Digest verification, `skopeo` interop, tar-traversal fuzzing |
| Networking | CNI bridge, netavark | Native netlink bridge/veth, IPAM, nftables NAT, port publishing | Connectivity tests, a leak detector for links, rules and netns |
| UX | docker / podman CLI | `hull`, a daemonless Docker-style CLI | Scripted end-to-end scenarios |

What makes this read as world-class is **evidence**: a passing conformance suite, a
CVE-driven security regression suite, a written threat model, and zero leaked kernel objects
after ten thousand fault-injected runs. The amount of code does not make it look world-class.

### Explicit non-goals

These are out of scope by design, not deferred:

- A long-running daemon or a Docker Engine API. We are daemonless, like Podman.
- `build` / Dockerfile, compose, swarm or orchestration.
- Windows/macOS, VM-isolated runtimes, CRIU checkpoint/restore.
- Container-name DNS, overlay networks across hosts, IPv6 in the first release (IPv6 is a stretch goal).
- Linux kernels older than **5.14** (see ADR-002).

---

## 1. Environment facts that shape this design (probed 2026-11-01 in the dev sandbox)

| Fact | Evidence | Consequence |
|---|---|---|
| Running as root, full capability set, kernel 6.18 (Firecracker VM) | `id`, `/proc/self/status`, `uname` **[C]** | We can run privileged integration tests locally. |
| All 8 namespace types can be created (user, pid, mnt, uts, ipc, net, cgroup, time) | `unshare` probes **[C]** | Full namespace coverage is testable here. |
| **cgroup v1 hybrid**: all controllers are bound to v1 and the v2 `unified` mount has only `hugetlb` | `/sys/fs/cgroup/unified/cgroup.controllers` **[C]** | **The v1 backend is required** to verify resource limits locally. The v2 backend is verified in CI on GitHub's `ubuntu-24.04`, which is pure v2 **[L]**. |
| The sandbox's own processes live in v1 `memory` cgroups (`process_api`, `sbx-telemetry`) | `ls /sys/fs/cgroup/memory` **[C]** | We must never remount or reorganise the host hierarchy. All work stays under `/hull`. |
| overlayfs mounts work | test mount **[C]** | The overlay snapshotter is testable here. |
| seccomp is available (`kill_process … user_notif …`) | `/proc/sys/kernel/seccomp/actions_avail` **[C]** | Includes the user-notify action. |
| No LSM is exposed (`/sys/kernel/security` is empty) | probe **[C]** | AppArmor/SELinux code paths can only be verified in CI (Ubuntu runners use AppArmor). |
| `runc 1.5.2` is installed | `runc --version` **[C]** | Differential-testing oracle is available locally. |
| Docker Hub and GHCR are reachable through the egress proxy (401 challenge, token endpoint 200) | `curl` **[C]** | Real registry tests work. The HTTP client **must honour `HTTPS_PROXY` and a custom CA bundle**. |
| Rust 1.97, Go 1.24, gcc and clang installed. `libseccomp2` runtime is present, `-dev` headers are not | probes **[C]** | `libseccomp-dev` must be installed (or vendored) for the seccomp crate. |
| `ip` (iproute2) is **not** installed and `ip_forward=0`. `nft` and `iptables` are present | probes **[C]** | Networking must not shell out to `ip`; native netlink is mandatory anyway. |

---

## 2. Architecture decisions

These summaries are the ADRs for now. They move to `docs/adr/` when one needs more room than a
section.

### ADR-001: Rust, not Go and not C

- **Go is structurally wrong for the runtime layer.** `setns(CLONE_NEWUSER)` and
  `setns(CLONE_NEWNS)` fail with `EINVAL` in a multi-threaded process, and the Go runtime is
  always multi-threaded. runc works around this with `nsexec.c`, a C constructor that runs before
  the Go runtime starts **[C]**. That means two languages and a hand-written state machine in C.
- **C** (the crun approach) is fast but puts JSON parsing, registry HTTP and tar extraction (all
  hostile input) into a memory-unsafe language.
- **Rust** lets us control threads exactly (no runtime), call `clone3` directly, and confine
  `unsafe` to one auditable crate. youki is prior art showing this works **[C]**.
- **Hard invariant:** the `hull-runtime` process is **single-threaded** from `main` to `clone3`.
  This is enforced by a check of `Threads: 1` in `/proc/self/status` before any namespace
  operation. Violating it is a bug, not a warning.

### ADR-002: Kernel floor 5.14, with no fallback paths

Every feature below becomes mandatory. This deletes an entire class of fallback code paths and
the doubled test matrix that comes with them:

| Feature | Since | Used for |
|---|---|---|
| `clone3` + `CLONE_INTO_CGROUP` | 5.3 / 5.7 **[C]** | Child is born inside its cgroup, so it never runs unaccounted |
| `pidfd_open`, `pidfd_send_signal`, `setns(pidfd, …)` | 5.3 / 5.1 / 5.8 **[C]** | Signals without PID-reuse races; `exec` joins all namespaces atomically |
| `openat2` (`RESOLVE_IN_ROOT`, `RESOLVE_NO_MAGICLINKS`, …) | 5.6 **[C]** | Path resolution that symlinks inside the rootfs cannot escape |
| `fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree` | 5.2 **[C]** | Mounts target file descriptors instead of paths, which closes TOCTOU races |
| `mount_setattr` and idmapped mounts | 5.12 **[C]** | Recursive read-only, propagation, and rootless volume ownership |
| `close_range(CLOSE_RANGE_CLOEXEC)` | 5.9 / 5.11 **[L]** | No host fd leaks into the container |
| `cgroup.kill` | 5.14 **[C]** | Atomic kill of a whole container on v2 |
| overlayfs in a userns + `userxattr` | 5.11 **[C]** | Rootless overlay |
| Time namespace | 5.6 **[C]** | Spec `timeOffsets` |

Distributions covered: RHEL 9 (5.14), Ubuntu 22.04+ (5.15+), Debian 12+ (6.1+). Distributions
excluded: RHEL 8 and Debian 11. We accept that. `hull-runtime features` reports what was probed,
and startup fails loudly below the floor.

### ADR-003: cgroups behind a trait, with v2 primary and v1 supported

v2 is the future. v1 is the reality of this dev environment and of some long-lived hosts. Both
backends implement one `CgroupManager` trait and pass **one shared test suite**. The systemd
driver (D-Bus transient units) is a stretch goal behind the same trait. On v1 we support exactly
`cpu`, `cpuacct`, `cpuset`, `memory`, `pids`, `devices`, `freezer`, `blkio` and `hugetlb`, and
nothing more.

### ADR-004: libseccomp for seccomp, not a hand-rolled BPF compiler

OCI seccomp profiles (including Moby's default profile) use libseccomp semantics: multi-arch
filters, 64-bit argument comparisons, `SCMP_CMP_MASKED_EQ`, and `SCMP_ACT_NOTIFY`. Re-deriving
that compiler is a separate project and a correctness risk. We use the `libseccomp` crate and link
it statically in release builds. We considered `seccompiler` (Firecracker) and rejected it: it has
no OCI-profile semantics and no notify support.

The cgroup-v2 **device filter**, by contrast, is a tiny eBPF program, so we **do** generate that
ourselves (see §4.4).

### ADR-005: No async runtime anywhere in the workspace

The runtime must be single-threaded. The CLI's I/O is a few parallel layer downloads at most.
Blocking I/O plus `std::thread::scope` is simpler, has fewer dependencies, and makes the
fork-safety audit trivial. This rules out `tokio` and therefore `rtnetlink` and `reqwest`. We use
`ureq` (rustls) and `netlink-packet-route` with synchronous `netlink-sys`.

### ADR-006: Three binaries, not one multi-call binary

- `hull-runtime` is minimal. It has no TLS, HTTP or tar code. A small attack surface also keeps
  the per-invocation memfd self-clone cheap (§5).
- `hull-shim` is one small, long-lived process per container.
- `hull` is the user-facing CLI and holds all heavy dependencies.

### ADR-007: Reuse `oci-spec` types; own the validation

We use the `oci-spec` crate (containers org) for serde types rather than re-typing the spec,
which would be busywork. **All semantic validation is ours.** It runs before any side effect, and
every rule cites the spec section it enforces.

### ADR-008: `unsafe` lives in exactly one crate

`hull-sys` holds every `unsafe` block. Each block carries a `// SAFETY:` justification, and each
function has a safe, typed wrapper. Every other crate declares `#![forbid(unsafe_code)]`.
`rustix` is used wherever it already provides a safe API. `hull-sys` fills only the gaps: `clone3`,
`capset`, `bpf`, seccomp FFI glue, and `ioctl`s.

---

## 3. Workspace layout

```
.
├── Cargo.toml                  # workspace; shared [lints]; release: lto="fat", codegen-units=1, panic="abort"
├── crates/
│   ├── hull-sys/               # the ONLY unsafe crate: clone3, capset, bpf(2), ioctls, prctl gaps
│   ├── hull-fs/                # SafeRoot (openat2 RESOLVE_IN_ROOT), ProcfsHandle, atomic writes, mountinfo parser
│   ├── hull-spec/              # oci-spec re-export + validation + Docker-equivalent defaults
│   ├── hull-cgroups/           # CgroupManager trait, v2, v1, device eBPF generator, stats, OOM events
│   ├── hull-seccomp/           # OCI LinuxSeccomp → libseccomp; notify-fd hand-off
│   ├── hull-runtime/           # lifecycle, container init, sync protocol, state store, hooks, console, exec
│   ├── hull-image/             # reference parser, distribution client, auth, OCI layout store, unpacker
│   ├── hull-snapshot/          # overlay + vfs snapshotters, chainID, refcount/GC
│   ├── hull-net/               # netlink, bridge/veth, IPAM, nftables, port proxy, resolv.conf/hosts
│   ├── hull-shim/              # supervisor library
│   └── hull-testkit/           # bundle builder, fixtures, leak detector, differential runner
├── bins/
│   ├── hull-runtime/           # runc-compatible OCI CLI
│   ├── hull-shim/
│   ├── hull/                   # Docker-style CLI
│   └── hull-probe/             # static binary run *inside* containers; dumps a JSON "fingerprint"
├── tests/                      # privileged integration, conformance, CVE regression suites
├── fuzz/                       # cargo-fuzz targets
├── xtask/                      # cargo xtask {fixtures,test-integration,conformance,diff-runc,bench,release}
└── docs/
    ├── PLAN.md                 # this file
    ├── ARCHITECTURE.md
    ├── SECURITY.md             # threat model
    ├── DEPENDENCIES.md         # every dependency, justified
    ├── adr/
    └── man/                    # generated by clap_mangen
```

Dependency direction is strictly downward: `hull` → `{hull-image, hull-snapshot, hull-net,
hull-shim}` → `hull-runtime` → `{hull-cgroups, hull-seccomp, hull-spec}` → `hull-fs` →
`hull-sys`. `cargo xtask` checks this, and a cycle or upward edge fails CI.

---

## 4. The runtime (`hull-runtime`) in depth

### 4.1 Lifecycle state machine

```
               create                 start               (process exits)
  (none) ───────────────► created ───────────► running ─────────────────► stopped
                              │                 │   ▲                          │
                              │           pause │   │ resume                   │ delete
                              │                 ▼   │                          ▼
                              │                paused                       (none)
                              └──────── delete --force / kill ──────────────────┘
```

- State lives in `--root` (default `/run/hull`; rootless default `$XDG_RUNTIME_DIR/hull`) at
  `<root>/<id>/{state.json, exec.fifo, lock}`.
- Every transition takes an exclusive `flock` on `<id>/lock`. `state.json` is written atomically
  (temp file, `fsync`, `rename`, `fsync(dir)`).
- Container IDs are validated against `^[A-Za-z0-9][A-Za-z0-9_.-]{0,1023}$`, which makes path
  traversal through an ID impossible.
- **PID-reuse safety:** state stores `pid` plus the process start time (`/proc/<pid>/stat`
  field 22). Every command revalidates both, then works only through a `pidfd`.

### 4.2 `create` and `start`, step by step

```
hull-runtime create <id> --bundle B [--console-socket S] [--pid-file P]
 │
 ├─ 1. Parse and VALIDATE config.json completely. No side effects happen before this succeeds.
 ├─ 2. memfd self-clone check (§5, CVE-2019-5736)
 ├─ 3. Lock <root>/<id>, write state "creating", mkfifo exec.fifo (0600)
 ├─ 4. Cgroup: create, apply resources, open dirfd (v2) for CLONE_INTO_CGROUP
 ├─ 5. socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC): message boundaries without framing code
 ├─ 6. clone3(CLONE_NEW{USER,PID,NS,UTS,IPC,NET,CGROUP,TIME} as configured | CLONE_PIDFD | CLONE_INTO_CGROUP)
 │       The kernel creates the userns FIRST and makes it own the sibling namespaces.  [C]
 │
 │  PARENT                                         CHILD (PID 1 of the new pidns)
 │  ──────                                         ─────────────────────────────
 │                                                 prctl(PR_SET_PDEATHSIG, SIGKILL)   ← setup only
 │                                                 prctl(PR_SET_DUMPABLE, 0)
 │                                         ◄────── WaitIdMap
 │  write uid_map / gid_map
 │  (rootless: newuidmap/newgidmap)
 │  v1: attach pid to cgroups
 │  IdMapDone ─────────────────────────────►
 │                                                 setns() into any namespaces given by `path`
 │                                                 rootfs preparation (§4.3, up to before pivot_root)
 │                                         ◄────── RunCreateRuntimeHooks
 │  run createRuntime hooks (runtime ns)
 │  HooksDone ─────────────────────────────►
 │                                                 run createContainer hooks (container ns)
 │                                                 pivot_root, masked/ro paths, sysctls, hostname
 │                                                 terminal: open /dev/ptmx inside the container,
 │                                                   send the master fd to S via SCM_RIGHTS
 │                                                 prctl(PR_SET_PDEATHSIG, 0)  ← `create` is about to exit by design
 │                                         ◄────── Ready
 │  write state "created", pid file                open(/proc/self/fd/<fifo O_PATH fd>, O_WRONLY)
 │  exit 0                                           ── BLOCKS until `start` ──
 │
hull-runtime start <id>
 ├─ open exec.fifo O_RDONLY, read 1 byte ──────►   unblocked
 ├─ run poststart hooks, write state "running"     run startContainer hooks
 └─ exit 0                                         finalize the process (§4.5) → execve(user program)
```

Design properties:

- **The parent never hangs.** It `poll`s on both the sync socket and the child's pidfd, which
  becomes readable when the child dies, with a timeout. Child death at any stage produces a precise
  error and a full cleanup.
- **Errors cross the namespace boundary.** The child sends `Error { stage, op, path, errno, chain }`
  over the socket, and the parent prints something like
  `container init failed at stage rootfs: mount "proc" on "/proc": EPERM (operation not permitted)`.
  It never prints a bare `exit status 1`.
- **The exec FIFO is reopened through an `O_PATH` fd captured before `pivot_root`.** The host path
  is invisible after `pivot_root`. This is the same technique runc uses **[C]**.
- **The parent-death signal is armed only during setup.** `create` exits while the container is
  blocked on the FIFO, so a permanent `PDEATHSIG` would kill every container the moment `create`
  returns. The child is reparented to the nearest subreaper, which is `hull-shim` (§8). After the
  signal is cleared, an EOF on the sync socket still aborts a half-built child.
- Sync messages are a versioned `enum` serialized with `serde_json`. A version mismatch is a hard
  error, because a stale binary must never half-speak the protocol.

### 4.3 Root filesystem and mounts

All of this happens in the child, inside the new mount namespace. **Every mount targets an fd
obtained through `SafeRoot`, never a path string.**

1. Make `/` `MS_REC | MS_SLAVE` (or the configured `rootfsPropagation`) so nothing propagates back
   to the host.
2. Bind-mount the rootfs onto itself, because `pivot_root` requires a mount point.
3. For each `mounts[]` entry, in spec order:
   - resolve the destination with `openat2(rootfd, dest, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`,
     creating missing components with `mkdirat` on resolved dirfds, one component at a time.
   - Filesystem mounts (`proc`, `sysfs`, `tmpfs`, `devpts`, `mqueue`, `cgroup2`) use `fsopen` →
     `fsconfig` → `fsmount`.
   - Bind mounts use `open_tree(OPEN_TREE_CLONE | AT_RECURSIVE)`.
   - Attributes (`ro`, `nosuid`, `nodev`, `noexec`, `relatime`, idmap) use `mount_setattr`, with
     `AT_RECURSIVE` for `rbind`/`rro`.
   - Attach with `move_mount(fd, "", target_fd, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)`.
   - This structurally eliminates the symlink-exchange race (CVE-2021-30465).
4. `/dev`: a `tmpfs` (`nosuid,strictatime,mode=755,size=65536k`). Device nodes come from `mknod`
   when privileged, or are bind-mounted from the host inside a userns. The default set is `null`,
   `zero`, `full`, `random`, `urandom` and `tty`, plus `devpts` (`newinstance,ptmxmode=0666`),
   `/dev/ptmx → pts/ptmx`, `/dev/{fd,stdin,stdout,stderr}` symlinks, `/dev/shm` and `/dev/mqueue`.
5. `pivot_root(".", ".")` then `umount2(".", MNT_DETACH)`. This is the no-`put_old`-directory
   trick, followed by `chdir("/")`.
6. **Masked paths:** bind `/dev/null` over files and a read-only empty `tmpfs` over directories.
   The source is opened with `O_PATH | O_NOFOLLOW`, `fstat`-verified to be the character device
   `1:3`, and bound **by fd** (`open_tree` on that fd). The container cannot swap it for a symlink
   between the check and the mount (CVE-2025-31133 class). **Read-only paths** use a self-bind plus `mount_setattr(RDONLY)`.
7. `readonly: true` rootfs: `mount_setattr(MOUNT_ATTR_RDONLY)` on `/`.
8. **Sysctls** are written through `ProcfsHandle` and checked against the namespaced allowlist
   (`kernel.msg*`, `kernel.sem`, `kernel.shm*`, `fs.mqueue.*`, and `net.*` only when the netns is
   private). Anything else is rejected at validation time.

### 4.4 Cgroups (`hull-cgroups`)

```rust
pub trait CgroupManager {
    fn create(&self) -> Result<CgroupHandle>;                // idempotent
    fn apply(&self, r: &LinuxResources) -> Result<()>;      // also implements `update`
    fn add_task(&self, pid: Pid) -> Result<()>;              // v1 only; v2 uses CLONE_INTO_CGROUP
    fn freeze(&self, state: FreezerState) -> Result<()>;     // waits until frozen, not just requested
    fn kill_all(&self, sig: Signal) -> Result<()>;           // v2: cgroup.kill; v1: freeze→signal→thaw
    fn stats(&self) -> Result<Stats>;
    fn oom_events(&self) -> Result<OomWatcher>;              // v2: inotify memory.events; v1: eventfd
    fn destroy(&self) -> Result<()>;                         // waits for populated=0, then rmdir
}
```

- **v2:** enable controllers in every ancestor's `cgroup.subtree_control`, then write
  `memory.{max,high,low,min,swap.max}`, `cpu.{max,weight}` (shares→weight conversion copied from the **pinned runc version**, then
  property-tested against it. Upstream replaced the old linear formula
  `1 + ((shares-2)·9999)/262142` in 2025 so that 1024 shares map to the default weight of 100
  **[L]**), `cpuset.{cpus,mems}`,
  `pids.max`, `io.{max,weight}`, `hugetlb.*`, and the `unified` pass-through map, which is validated
  against a key allowlist.
- **Device control on v2** has no file interface. It requires a `BPF_PROG_TYPE_CGROUP_DEVICE`
  program **[C]**. We compile `linux.resources.devices` (ordered allow/deny, type `a|b|c`, wildcard
  major/minor, `rwm`) into raw eBPF instructions, load it with `bpf(BPF_PROG_LOAD)`, and attach it
  with `BPF_F_ALLOW_MULTI`. This needs about 300 lines, plus a golden-file test of the emitted
  program and kernel-level tests (`mknod` and open of `/dev/sda` must be denied).
- **Stats:** memory, cpu, pids, io, hugetlb and PSI (`*.pressure`), all exposed through
  `hull-runtime events --stats`.

### 4.5 Finalizing the process (child, after `start`)

The order is load-bearing. Each step depends on capabilities that a later step removes:

| # | Step | Why here |
|---|---|---|
| 1 | `startContainer` hooks | The spec requires them before the user program **[C]** |
| 2 | `setsid`, `TIOCSCTTY` if `terminal` | Needs the pty from §4.2 |
| 3 | `setrlimit` for each `rlimits[]`; `oom_score_adj` | Raising hard limits needs `CAP_SYS_RESOURCE` |
| 4 | LSM exec label: AppArmor (`attr/apparmor/exec`) or SELinux (`attr/exec`) through `ProcfsHandle` | Must take effect at `execve` |
| 5 | Drop the bounding set (`PR_CAPBSET_DROP`) | Needs `CAP_SETPCAP`, which disappears after the uid change |
| 6 | **If `noNewPrivileges == false`:** load seccomp now | Without NNP, loading requires `CAP_SYS_ADMIN` **[C]**. The filter must then allow the remaining setup syscalls (`setresuid`, `capset`, `execve`, …) |
| 7 | `PR_SET_KEEPCAPS=1`, `setgroups`, `setresgid`, `setresuid`, `PR_SET_KEEPCAPS=0` | Identity switch |
| 8 | `capset` effective, permitted and inheritable, then raise ambient | Inheritable stays **empty** unless the spec requests it (CVE-2022-29162 **[L]**) |
| 9 | `chdir(cwd)` as the target user; check that the result is reachable (`getcwd` must not return `(unreachable)`) | Leaky Vessels (CVE-2024-21626) **[C]** |
| 10 | `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, sparing `preserve_fds` and `LISTEN_FDS` | No host fd survives `execve` |
| 11 | **If NNP:** `prctl(PR_SET_NO_NEW_PRIVS)`, then load seccomp **last** | The filter then never needs to allow the runtime's own syscalls |
| 12 | `execve` (`PATH` resolved inside the container, using the container's env) | |

### 4.6 `exec`, `kill`, `delete`, hooks, console

- **`exec`:** take a pidfd of the container's init, `setns(pidfd, <all of its namespace flags>)`,
  which joins atomically and lets the kernel order the namespaces (5.8+), then
  `clone3(CLONE_INTO_CGROUP = the container's cgroup)`. The new process goes through the same §4.5
  finalization, using the `--process` JSON or CLI flags.
- **`kill`:** `pidfd_send_signal`. `--all` uses `CgroupManager::kill_all`.
- **`delete`:** refuses while running unless `--force` is given, in which case it kills everything
  and waits. Then it runs `poststop` hooks (failures are logged, not fatal, per the spec), destroys
  the cgroup and removes state. It is idempotent: deleting a half-created container cleans up
  whatever exists.
- **Hooks:** the state JSON goes on stdin, `timeout` is enforced with `SIGKILL`, and the namespace
  rules follow the spec exactly. `prestart` is supported but deprecated.
- **Console:** `--console-socket` receives the pty master fd through `SCM_RIGHTS`, and
  `process.consoleSize` is applied with `TIOCSWINSZ`.

### 4.7 CLI compatibility contract

Compatibility is the integration test: if containerd and Podman can drive `hull-runtime`, it is a
real runtime. It must accept what `containerd-shim-runc-v2` and `conmon` actually send **[L]**:

- **Global flags:** `--root`, `--log`, `--log-format {text,json}`, `--systemd-cgroup`, `--debug`.
- **Commands:** `create`, `start`, `run`, `state`, `kill`, `delete`, `exec`, `ps`, `list`, `pause`,
  `resume`, `update`, `events`, `features`, `spec`.

---

## 5. Security model (`docs/SECURITY.md` expands this)

**Threat model:** the workload, including container root, is **hostile**. The bundle author and
the operator invoking `hull` are trusted. Images and registries are **untrusted input**.

### Defaults (`hull run`)

All of these are copied verbatim from Moby at a pinned commit, never retyped from memory:

- **Capabilities:** Docker's 14-capability default set (`CHOWN DAC_OVERRIDE FSETID FOWNER MKNOD
  NET_RAW SETGID SETUID SETFCAP SETPCAP NET_BIND_SERVICE SYS_CHROOT KILL AUDIT_WRITE`) **[C]**.
- **Seccomp:** Moby's `profiles/seccomp/default.json`.
- **Masked and read-only paths:** Moby's `oci/defaults.go` lists.
- **Devices:** the default allowlist.
- `noNewPrivileges` is on.

### Design driven by runc's CVE history

Each row becomes a **named regression test** that runs the actual attack and asserts that it fails:

| CVE | Attack class | Our structural mitigation |
|---|---|---|
| CVE-2019-5736 **[C]** | Container overwrites the host runtime binary via `/proc/<pid>/exe` | `PR_SET_DUMPABLE=0` until `execve`. The runtime re-executes from a **sealed `memfd`** copy of itself (`F_SEAL_{SEAL,SHRINK,GROW,WRITE}`), so `/proc/<pid>/exe` never points to the host file |
| CVE-2021-30465 **[C]** | Symlink-exchange race on a mount destination | fd-based mount API, with targets resolved through `openat2(RESOLVE_IN_ROOT)` |
| CVE-2024-21626 "Leaky Vessels" **[C]** | Leaked host fd plus `cwd=/proc/self/fd/N` escapes to the host | `O_CLOEXEC` everywhere, `close_range` before `execve`, and a reachability check on `cwd` |
| CVE-2022-29162 **[L]** | Non-empty inheritable capabilities | Inheritable is empty by default and is asserted in a test |
| CVE-2016-9962 **[L]** | Container ptraces the runtime during `exec` | Non-dumpable until `execve`, and fds are closed before joining |
| CVE-2025-31133 / -52565 / -52881 **[L]** | `maskedPaths` `/dev/null` swapped for a symlink, `/dev/console` mount races, procfs writes redirected through attacker-controlled mounts | `fstat`-verify bind sources; `ProcfsHandle` uses a **private `fsopen("proc")` instance**, `RESOLVE_NO_MAGICLINKS \| RESOLVE_NO_XDEV`, and an `fstatfs == PROC_SUPER_MAGIC` check |

Tags marked **[L]** are re-verified against the upstream advisories before their tests are written.

---

## 6. Rootless mode

- **User namespace:** use `newuidmap`/`newgidmap` (setuid helpers from the shadow suite) with the
  `/etc/subuid` and `/etc/subgid` ranges. If those are absent, fall back to a single-ID mapping
  (`0 → $UID`) with `setgroups deny`.
- **Cgroups:** on v2, use a systemd-delegated subtree when one is available (`user@.service`).
  Otherwise skip resource limits with an **explicit warning**, matching runc's behaviour.
- **Storage:** overlay with `userxattr` (5.11+) and whiteouts as `mknod c 0 0` inside the userns
  **[L]**. vfs is the fallback.
- **Networking:** `none` or `host`. Rootless bridge networking (slirp4netns/pasta) is a non-goal,
  but an existing `pasta` binary can be invoked if one is present.
- **CI:** Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor
  (`kernel.apparmor_restrict_unprivileged_userns=1`) **[C]**. The rootless CI job sets this sysctl
  explicitly and documents why.

---

## 7. Images and storage (`hull-image`, `hull-snapshot`)

### 7.1 Distribution client

- **References:** full Docker reference grammar (`[host[:port]/]path[:tag][@sha256:…]`), with
  normalization such as `alpine` → `docker.io/library/alpine:latest`. Table tests are ported from
  `distribution/reference` test vectors, and the parser is fuzzed.
- **Auth:** the `WWW-Authenticate: Bearer realm=…,service=…,scope=…` challenge flow with tokens
  cached per scope. Basic credentials come from `~/.docker/config.json` / `$REGISTRY_AUTH_FILE`.
  Credential helpers are a stretch goal.
- **Manifests:** request OCI index, OCI manifest, Docker manifest list and Docker v2s2 media types.
  **Schema1 is rejected.** Platform matching covers os, arch and variant, with ARM variant
  normalization. Both the `Docker-Content-Digest` header and the received bytes are verified.
- **Blobs:** streamed to a temp file while hashing, then size and digest are verified, followed by
  `fsync` and `rename`. Downloads retry with jittered backoff and resume with `Range`, with 3 in
  parallel by default.
  - **The `Authorization` header is dropped on cross-origin redirects** to CDN storage.
- **Transport:** `ureq` with rustls, configured to honour `HTTPS_PROXY`/`NO_PROXY` and loads extra CAs from
  `SSL_CERT_FILE`, which this sandbox requires.

### 7.2 Content store

- The store **is** an OCI Image Layout (`oci-layout`, `index.json`, `blobs/sha256/…`) under
  `/var/lib/hull/images`. Interop test: `skopeo copy oci:/var/lib/hull/images:alpine …` must work.

### 7.3 Unpacking

This is the most dangerous code in the project, because it parses hostile tar files as root.

- Decompress gzip, zstd or plain. **Verify each layer's `diff_id`** (the sha256 of the uncompressed
  stream) against `config.rootfs.diff_ids`. Many implementations skip this check.
- Every entry is created through `SafeRoot` (`openat2(RESOLVE_IN_ROOT)`). `..`, absolute paths and
  pre-planted symlinks cannot escape. Hardlink targets are resolved the same way.
- **Whiteouts:** `.wh.<name>` becomes an overlay whiteout (`c 0 0`), and `.wh..wh..opq` becomes an
  opaque directory (`trusted.overlay.opaque=y`, or `user.overlay.opaque` when rootless).
- Modes, ownership (shifted by the idmap when rootless), mtimes and xattrs are preserved, including
  `security.capability` so `ping` keeps working. Device nodes are created only when privileged.
- **Fuzz invariant:** for any input archive, nothing is created, modified or followed outside the
  target directory. A tmpfs sentinel tree is checked after every iteration.

### 7.4 Snapshotter

- Snapshots are keyed by **chainID** (image-spec algorithm), with parent links, refcounts and
  mark-and-sweep GC rooted at the image index and existing containers.
- Snapshot directories use **short numeric IDs** so that the overlay `lowerdir=` string stays below
  the page-size option limit. This is the same reason containerd uses numeric IDs **[L]**. On 6.8+
  we use `fsconfig("lowerdir+")` per layer instead **[L]**.
- Each container gets an `upperdir` and `workdir` and an overlay mount. If `/var/lib/hull` is itself
  on overlayfs (nested), we detect that and use the `vfs` (full-copy) snapshotter.

### 7.5 Image config to runtime spec

- Docker's semantics are reproduced exactly: CLI args replace `Cmd`; `--entrypoint` replaces
  `Entrypoint` **and clears `Cmd`**; `Env` merges with the CLI taking precedence; `WorkingDir`;
  `User` resolved through the container's `/etc/passwd` and `/etc/group`, **read through
  `SafeRoot`**, never through host-path joins.

---

## 8. Supervision (`hull-shim`) and logs

Without a shim, nothing waits on a detached container. Toy engines skip this, and it is where they
fall apart.

```
hull run -d nginx
  └─ spawns hull-shim (double-fork, setsid, PR_SET_CHILD_SUBREAPER)
       ├─ hull-runtime create --console-socket <shim sock> | stdio pipes
       ├─ hull-runtime start
       ├─ reaps the container (it is the subreaper); records exit code and timestamp atomically
       ├─ owns stdio / the pty master for the container's whole life
       ├─ attach socket: SOCK_SEQPACKET, framed {stdin, resize, detach}; serves `run -it`, `attach`
       ├─ log pump: stdout/stderr → JSON-lines {time, stream, log}, partial-line aware, size-rotated
       ├─ loopback port proxy for -p (see §9)
       └─ on exit: hull-runtime delete, network teardown, --rm cleanup
```

- `hull logs -f` tails through inotify. `hull run -it` and `hull attach` connect to the shim's
  attach socket: the CLI puts the terminal in raw mode, forwards `SIGWINCH` as a resize frame, and
  the shim applies `TIOCSWINSZ`. The shim, not the CLI, holds the pty master, so closing the
  terminal never sends SIGHUP to a detached container. This is the conmon model.
- `hull stop` sends `SIGTERM`, waits a grace period, then `SIGKILL`s the whole cgroup.
- **Crash consistency:** if the shim dies, the container keeps running. The next `hull ps`
  reconciles state through pidfd and start-time checks and marks the container `unknown`. State is
  never silently wrong.

---

## 9. Networking (`hull-net`)

The runtime only joins a netns **path**. Networking belongs to the `hull` layer, which is the same
split containerd/CRI uses.

- **Netns lifecycle:** a dedicated thread runs `unshare(CLONE_NEWNET)`, which is per-task and so
  does not affect the CLI's main thread. The namespace is bind-mounted at `/run/hull/netns/<id>`
  and passed through `linux.namespaces[].path`.
- **Bridge mode (default):**
  - Create bridge `hull0` with default subnet `10.123.0.0/16`, which is configurable and avoids
    Docker's `172.17/16` and Podman's `10.88/16`.
  - Create a veth pair, move the peer into the netns, and rename it to `eth0`.
  - Assign the address, bring up `lo`, and add a default route.
  - All of this goes over **native netlink** (`netlink-packet-route`), with no `ip` binary (it is
    absent here anyway).
- **IPAM:** a file-locked JSON lease database keyed by container ID, reconciled against live
  containers on every allocation.
- **Firewall:** one dedicated nftables table, `inet hull`. We never touch other tables. It is
  applied as **one atomic transaction** (`nft -j -f -`, with JSON generated from typed Rust), and
  native nftables netlink is a stretch goal. Rules are masquerade for the subnet and DNAT for
  published ports. `ip_forward` is enabled and restored on teardown when we were the ones who
  turned it on.
- **Localhost port publishing goes through a userland proxy in the shim, not `route_localnet=1`.**
  `route_localnet` exposes host loopback services to the L2 segment (CVE-2020-8558, kube-proxy)
  **[C]**.
- **Coexistence gotcha:** Docker sets the iptables `filter/FORWARD` policy to `DROP`, and in
  nftables a drop verdict in *any* base chain is final **[C]**. We detect this and either insert an
  accept rule in `DOCKER-USER` (with `--allow-docker-coexist`) or fail with an actionable message.
- **DNS and hosts:** `resolv.conf` is derived from the host. A systemd-resolved stub (`127.0.0.53`)
  is rewritten to the upstream servers from `/run/systemd/resolve/resolv.conf`. `/etc/hosts` and
  `/etc/hostname` are generated per container and bind-mounted.
- **Leak detector** (used in every integration test): it snapshots links, addresses, routes, the
  nft ruleset, netns mounts and IPAM leases before and after each test. Any difference fails the
  test.

---

## 10. User-facing CLI (`hull`)

| Command | Notable flags |
|---|---|
| `pull`, `images`, `rmi`, `image prune` | `--platform` |
| `run`, `create`, `start` | `-d -it --rm --name -e --env-file -v src:dst[:ro] -p host:ctr[/proto] --network {bridge,host,none} --memory --memory-swap --cpus --cpuset-cpus --pids-limit --user --workdir --entrypoint --read-only --cap-add/--cap-drop --security-opt {seccomp=,no-new-privileges,apparmor=} --privileged --hostname --init` |
| `ps`, `inspect`, `logs`, `stats`, `top` | `-a`, `-f`, `--format json` |
| `exec`, `stop`, `kill`, `rm`, `pause`, `unpause`, `container prune` | `-it`, `-t <grace>`, `-s`, `-f` |
| `system info`, `system check` | `system check` prints each kernel and feature probe, with a fix for each failure |

Output and errors are designed to be read: a JSON form of every listing for scripting, an exit code
taxonomy (`125` engine error, `126` cannot execute, `127` not found, and the program's code
otherwise, matching Docker **[C]**), and every error states what failed, why (errno or cause), and
what to do.

---

## 11. Errors, logging, observability

- Library crates use `thiserror` enums with structured context (operation, path, errno). The CLIs
  render the full cause chain. **`unwrap`/`expect` are banned outside tests** (clippy `deny`).
- `panic = "abort"` in release builds. A panic in the post-`clone3` child must never unwind into
  parent-only code. The child entry point is wrapped so that any failure becomes an `Error` message
  on the sync socket followed by `_exit(1)`.
- `tracing` with a synchronous writer only, because a background log thread would break the
  single-thread invariant. `--log-format json` matches what containerd expects.

---

## 12. Verification strategy

Correctness is shown by **independent oracles**, not by tests we wrote against our own
assumptions.

| Level | What | Where it runs |
|---|---|---|
| Unit and property | Spec validation, shares→weight, reference parsing, whiteout mapping, IPAM, nft JSON generation, device-BPF golden files (`proptest`) | Everywhere, unprivileged |
| **Differential vs runc** | The same bundle runs under runc and under hull. `hull-probe` (static, run inside the container) dumps a JSON fingerprint: namespace inodes, id maps, all 5 capability sets, NNP, seccomp mode, rlimits, normalized `mountinfo`, cgroup path and limits, env, cwd, uid/gids, open fds, hostname. **The diff must be empty** apart from an allowlisted set of fields | Local (runc 1.5.2) and CI |
| **OCI conformance** | `opencontainers/runtime-tools` validation suite at a **pinned commit**. Upstream is under-maintained **[L]**, so a reviewed `conformance/skip.toml` gives a reason for every skip | CI |
| **Ecosystem** | `podman --runtime=$(which hull-runtime) run --rm alpine true`, plus a curated subset of Podman's system tests; optionally `ctr` with containerd | CI |
| **Security regression** | The §5 CVE table, each as an actual exploit attempt | Local and CI |
| **Fault injection** | A test-only `fault-injection` cargo feature (compiled out of release) kills the child at each sync stage. Afterwards the leak detector checks for no mounts, cgroups, state dirs, netns, links or nft rules left behind | Local and CI |
| **Fuzzing** | `cargo-fuzz` targets: config validation, image reference, manifest/index, `WWW-Authenticate`, tar unpack (escape invariant), mountinfo parser, seccomp translation. 60 s per target per PR, 1 h nightly | CI |
| **Benchmarks** | `hyperfine` for `run true` and create→start→delete, hull vs runc vs crun. Results are published and informational, not gating, because shared runners are noisy | CI and local |

**CI matrix (GitHub Actions):**

- `ubuntu-24.04` x86_64: cgroup v2, AppArmor, rootful and rootless.
- `ubuntu-24.04-arm` aarch64: seccomp multi-arch and the BPF device program on ARM.
- Lint job: `rustfmt`, `clippy -D warnings` (pedantic subset), `cargo-deny` (advisories, licenses,
  bans: **no OpenSSL**), `cargo doc -D warnings`, MSRV check, dependency-direction check.
- Release job: static `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` binaries with
  libseccomp vendored, plus SHA256SUMS.

**Coverage gap:** cgroup v1 is **not available on hosted CI runners**. v1 is verified in the dev
sandbox through `cargo xtask test-integration`, and the README states this. A self-hosted v1 VM
job is optional.

---

## 13. Code quality bar

- Edition 2024. MSRV is pinned (currently 1.88, for let-chains), checked in CI, and bumped
  deliberately, never by accident. The *development* toolchain is pinned too
  (`rust-toolchain.toml`), so a new stable release cannot turn CI red with a lint that nobody
  saw locally. (That happened on the first CI run.)
- `#![forbid(unsafe_code)]` in every crate except `hull-sys`, and every `unsafe` block carries a
  `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks = deny`).
- `#![deny(missing_docs)]` on library crates. Module docs explain *why*, not *what*.
- `docs/DEPENDENCIES.md` justifies every third-party crate. Adding one requires an entry.
- Reviewable history: one milestone is one PR series, each PR stays green, and each PR is small
  enough to review in one sitting.

---

## 14. Milestones and exit criteria

Each milestone ends with something demonstrable and a gate that an outside oracle verifies.

| # | Milestone | Exit criterion (must be true to proceed) |
|---|---|---|
| **M0** ✅ (CI: verify first run) | Foundation: workspace, CI, lints, `hull-sys` skeleton, state store, spec validation, `spec` command, fixture fetcher (pinned busybox digests), `hull-probe` | CI green. `hull-runtime spec` output is accepted by `runc run` |
| **M1** ✅ | Namespaces and rootfs: `clone3`, sync protocol, fd-based mounts, `/dev`, `pivot_root`, hostname, `execve` | `hull-runtime run` starts busybox. **Differential probe vs runc is clean** for namespaces and mountinfo. *Delivered beyond that: user namespaces, rlimits, user identity, `no_new_privs`, and a probe diff that also covers capabilities, signals, environment and `/dev`.* |
| **M2** | Full OCI lifecycle: create/start/state/kill/delete/list/ps, exec FIFO, pidfds, locking, all hooks, console socket, `exec` | runtime-tools lifecycle, hooks and state tests pass. Fault-injection shows no leaks |
| **M3** | Cgroups: v1 and v2 backends, device eBPF, pause/resume, update, events/stats, OOM | Shared cgroup suite passes on v1 (sandbox) and v2 (CI). runtime-tools resource tests pass |
| **M4** | Security: capabilities, NNP, seccomp (Moby default), masked/ro paths, rlimits, sysctls, LSM labels, memfd self-clone, `ProcfsHandle` | **Full runtime-tools suite passes, subject to the reviewed skip list.** `podman --runtime` smoke tests pass. CVE suite passes |
| **M5** | Rootless | Rootless CI job passes the runtime-tools rootless subset and the `hull run` scenarios |
| **M6** | Images and storage (can proceed in parallel with M3–M5) | `pull` + `run` of `alpine`, `nginx` and `ubuntu` across platforms with digest and `diff_id` verification. The tar-escape fuzzer runs clean for 1 h |
| **M7** | Shim and UX: detached mode, logs, stop/rm/inspect/stats, `-it` with resize | Scripted scenario `run -d nginx` → `logs -f` → `stop` → `rm` leaves zero residue |
| **M8** | Networking | `run -d -p 8080:80 nginx`, then `curl` succeeds from the host (external and loopback) and from a second container. The leak detector stays clean after `rm` |
| **M9** | Hardening and release: fuzz soak, benchmarks, complete docs, man pages, static releases, demo recording | v0.1.0 tagged |

**Rough size [G]:** 20–30k lines of Rust including tests. `hull-runtime` plus its dependencies is
about 40% of that, and that is where most of the risk sits.

---

## 15. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| runtime-tools tests are stale or broken on modern kernels | High **[L]** | Pin the commit, keep a reviewed skip list, and make the runc differential the primary oracle |
| Each cgroup backend has only one test environment (v1 local, v2 CI) | Certain | One trait and one shared suite. Both environments run the *entire* suite, not a subset |
| A dependency spawns a thread inside `hull-runtime` | Medium | Runtime check of `Threads: 1` before `clone3`. `DEPENDENCIES.md` review. No background log writers |
| Static linking libseccomp against musl is fiddly | Medium | `xtask` builds a vendored libseccomp. glibc-dynamic builds as a fallback artifact |
| Docker on the same host drops forwarded traffic | High where Docker is installed | Detection plus `DOCKER-USER` integration or an actionable error (§9) |
| `/var/lib/hull` sits on overlayfs (nested containers) | Medium | Detect it and fall back to the vfs snapshotter |
| Scope creep toward Docker parity (build, compose, API) | High | The non-goals in §0 are binding. Any new scope requires a new ADR |
| **You must be able to defend this design** | — | Every non-obvious decision has an ADR written so that *you* can explain the reasoning in a review or interview |

---

## 16. Decisions (resolved 2026-11-01)

| Decision | Outcome |
|---|---|
| Goal and audience | **Learning.** Every milestone ships with a chapter in [`docs/learn/`](learn/README.md), with exercises that change the code and are judged by tests. Milestones stay in scope, but each is cut so that it can be understood in one sitting. |
| Language | Rust (ADR-001) |
| Name | `hull` |
| License | Apache-2.0 |
| cgroup v1 | Kept (ADR-003): the development sandbox is a v1 hybrid |

### What "learning" changes in this plan

- **Readable over clever.** Module docs explain *why*, including the CVE or bug behind a design.
  When a test catches a real bug, the story goes into the learning chapter.
- **Exercises are part of the deliverable.** Each chapter ends with "change hull" tasks. Some
  intentionally preview the next milestone (for example joining a network namespace, or
  `--detach`), so you can implement the first slice of a milestone yourself before reading the
  full version.
- **Mutation-check the tests.** A test that has never been seen failing is not trusted. Chapter 5
  shows the case that made this rule necessary.
