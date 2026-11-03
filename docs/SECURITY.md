# Security model

> **Today, hull is not a security boundary.** A container started by `hull-runtime` keeps the
> full capability set of root, has no seccomp filter, and has no resource limits. Anyone with
> root inside the container should be assumed able to reach the host. Do not run untrusted code
> with hull until milestone M4 is done. This document explains what is already defended, what is
> not, and why the order is what it is.

## Threat model

| Party | Trust | Why |
|---|---|---|
| The operator running `hull-runtime` (root on the host) | Trusted | They can do anything on the host anyway |
| The bundle author (`config.json`) | Trusted for *intent*, untrusted for *correctness* | A config may ask for a weak setup, which is their right. But a config hull cannot honour must be refused, not half-applied |
| The container's root filesystem (the image) | **Untrusted** | It is data from the internet. Symlinks, device files and odd ownership in it are attack tools |
| The process inside the container, including container root | **Hostile** | Once it runs, it will try to reach the host |
| Registries and the network (M6+) | **Untrusted** | Every byte is verified against a digest before use |

The goal, once M4 is complete, is that a hostile process with root inside the container cannot:
read or write host files outside its mounts, see or signal host processes, change the host's
mounts, gain privileges the config did not grant, or exhaust host resources beyond its limits.

## What is defended today (M1 and the M2 lifecycle)

These are structural defences: they remove a class of bug rather than patching one instance.

| Attack | Defence | Where |
|---|---|---|
| A symlink in the image redirects a mount, a `mkdir` or a file creation onto the host (the CVE-2021-30465 class) | Every path inside the rootfs is resolved with `openat2(RESOLVE_IN_ROOT \| RESOLVE_NO_MAGICLINKS)`, and mounts attach by file descriptor (`move_mount`), so nothing is re-resolved between check and use | `crates/hull-fs/src/root.rs`, `crates/hull-runtime/src/mounts.rs` |
| Container mounts leak into the host's mount table, or host mounts propagate into the container | The container's copy of the mount table becomes a recursive slave first, the rootfs's parent mount is made private before the self-bind, and `pivot_root` detaches the old root | `crates/hull-runtime/src/rootfs.rs` |
| A host file descriptor leaks into the container and is used to escape the root, e.g. with `cwd=/proc/self/fd/N` (CVE-2024-21626) | Every descriptor ≥ 3 is made close-on-exec right before `execve`, and the working directory is checked for reachability after `chdir` | `crates/hull-sys/src/fd.rs`, `crates/hull-runtime/src/process.rs` |
| The container opens `/proc/<init>/exe` (still the runtime binary until `execve`) or ptraces init during setup (the CVE-2019-5736 and CVE-2016-9962 classes) | Init is non-dumpable from `clone3` until `execve` | `crates/hull-runtime/src/init.rs` |
| A config asks for a protection hull does not implement yet (seccomp, capabilities, masked paths, ...) and the container silently runs without it | Validation rejects such configs before anything is created, naming the milestone that adds the feature | `crates/hull-spec/src/validate.rs` |
| A recycled PID makes `kill` or `delete` hit an unrelated process | The state file records the init's start time, every command re-checks it, and signals go through a pidfd, which cannot be recycled | `crates/hull-runtime/src/state.rs`, `crates/hull-runtime/src/lifecycle.rs` |
| The state lock or the exec FIFO handle leaks into the user's program | Both are close-on-exec, every descriptor ≥ 3 is marked close-on-exec before `execve`, and the lock is released explicitly because `clone3` shares it with init | `crates/hull-runtime/src/state.rs`, `crates/hull-runtime/src/init.rs` |
| Signal state set by the runtime (blocked signals, ignored `SIGPIPE`) leaks into the container | Mask and dispositions are reset before `execve` | `crates/hull-sys/src/signal.rs` |

Each row has at least one test that performs the attack or reproduces the leak. Several of them
were found by comparing hull against runc (see `docs/learn/05-testing-a-runtime.md`).

## What is not defended yet

| Gap | Consequence | Milestone |
|---|---|---|
| No capability dropping | Container root holds every capability, including `CAP_SYS_ADMIN`: it can mount, load modules, change the clock | M4 |
| No seccomp filter | Every syscall is reachable, including the rarely used ones where kernel bugs live | M4 |
| No masked or read-only `/proc` and `/sys` paths | `/proc/sysrq-trigger`, `/proc/kcore`, `/sys/firmware` are exposed | M4 |
| No cgroups | A fork bomb or memory hog affects the whole host | M3 |
| No device cgroup | Container root can `mknod` and open host block devices | M3 |
| No LSM profiles (AppArmor, SELinux) | No mandatory access control backstop | M4 |
| The runtime binary is not re-executed from a sealed `memfd` | Non-dumpable init narrows the CVE-2019-5736 window but is not the full mitigation | M4 |
| No rootless mode | The runtime needs host root; there is no unprivileged deployment option | M5 |

The order is deliberate: M3 and M4 add *confinement*, which only makes sense once the
*isolation* below it (namespaces, mounts, the lifecycle) is correct and tested.

## CVE regression plan

When M4 lands, each of these becomes a test that performs the actual attack (`docs/PLAN.md` §5):
CVE-2019-5736, CVE-2021-30465, CVE-2024-21626, CVE-2022-29162, CVE-2016-9962, and the November 2025
runc trio (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881). The descriptions of the last four are
re-verified against the upstream advisories before their tests are written.

## Reporting a problem

This is a learning project, not a product, so there is no embargo process. Open a GitHub issue,
and include the `config.json` and the command that shows the problem.
