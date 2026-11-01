# 5. Testing a runtime

## The idea

Tests you write against your own understanding of the spec share your blind spots. hull's main
oracle is therefore not its own assertions. It is **runc**, the reference implementation:

1. `hull-probe` is a static binary that dumps what a process can see: namespaces, ID maps, every
   capability set, `no_new_privs`, seccomp mode, blocked and ignored signals, umask, rlimits,
   environment, open fds, the full mount table, and `/dev`.
2. The test copies it into a bundle and runs the bundle under runc, then under hull.
3. Any difference fails the test, unless it is in `KNOWN_DIFFERENCES` with a reason
   (`bins/hull-runtime/tests/differential.rs`).

## What it found

These bugs got past every hand-written test, and the differential test found them the first
time it ran:

| Difference | Cause | Fix |
|---|---|---|
| `HOME=/root` under runc, missing under hull | runc sets `HOME` from the container's `/etc/passwd` when the config does not | `home_directory()` in `process.rs` |
| `/sys` superblock `ro` under runc, `rw` under hull | `ro` on a *new* filesystem should make the superblock read-only too, not just the mount | `parse_mount` adds the `ro` superblock flag |
| Device bind mounts in a different order | Cosmetic, but exact comparison needs a stable order | Same order as runc |

Then the same tests ran in CI, on a GitHub Ubuntu runner, and found two more that the
development machine could not show:

| Difference | Cause | Fix |
|---|---|---|
| Container `/` was a slave of the host's root (`master:1` in mountinfo) | On a systemd host `/` is *shared*. A bind mount copies the propagation of its source, so the rootfs became a slave of the host. Host mounts under the bundle would have appeared inside the container. The dev machine's `/` is *private*, so the bug was invisible there | Make the rootfs's parent mount private before the self-bind, as runc does (`rootfs.rs`) |
| runc adds `/dev/core -> /proc/kcore` | Only when the host has `/proc/kcore`, which the dev VM does not | Same condition in `devices.rs` |

The first bug was reproduced locally with `mount --make-shared /` before it was fixed, and the
suite now passes under both settings. Run your tests on more than one kind of host: your own
machine's configuration is a hidden input.

And one bug in the *test tool* itself: the probe is a Rust program, and the Rust runtime ignores
`SIGPIPE` before `main`. The probe reported its own runtime's signal state, which happened to agree
under both runtimes, so the comparison passed while the probe was blind. `#![no_main]` fixed it,
and a mutation test (chapter 4, exercise 2) now proves the check can fail.

The lesson: **an oracle is only as good as its instruments.** Check that each check *can* fail.

## Other layers

- **Leak detection.** `HostMounts::assert_unchanged` snapshots the host mount table around a
  test. Every failure-path test also checks that the state directory is empty.
- **Attack tests.** `symlinked_mount_destination_cannot_escape_the_rootfs` plants the symlink an
  attacker would, and the `hull-fs` unit tests do the same with `..` and symlink loops.
- **Fail closed.** `unimplemented_features_fail_before_anything_happens` proves that a config
  asking for seccomp is refused before any state exists.

## Exercises

**1.** Add `/proc/self/oom_score_adj` and `/proc/self/attr/current` to the probe. Do both
runtimes still agree?

**2.** Find a config where hull and runc disagree. Try `process.user.umask`, unusual `rlimits`,
or a bind mount with `rprivate`. Either hull is wrong (fix it) or the difference is deliberate
(document it in `KNOWN_DIFFERENCES`).

**3.** Read about the OCI conformance suite (`opencontainers/runtime-tools`, `validation/`). The
plan makes passing it the exit criterion for M4. Which of its tests would fail today, and which
milestone fixes each one?
