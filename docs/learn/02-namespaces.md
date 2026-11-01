# 2. Namespaces

## The idea

There are three ways to put a process into a namespace:

| Syscall | Effect |
|---|---|
| `clone`/`clone3` with `CLONE_NEW*` | The *new* child is born in new namespaces |
| `unshare(CLONE_NEW*)` | The *caller* moves into new namespaces, **except** PID and time, which apply only to its future children |
| `setns(fd)` | The caller joins an *existing* namespace (`/proc/<pid>/ns/*`, or a pidfd) |

hull uses `clone3`, so the container's first process is PID 1 from birth and needs no second fork.

### User namespaces and ID maps

A user namespace gives a process a full set of capabilities, but only over resources *owned by*
that namespace. The new namespace starts with **no ID mapping**: every UID inside is 65534
("nobody"), and nothing useful works. Someone in the parent namespace must write
`/proc/<pid>/uid_map` and `gid_map`:

```text
0 100000 65536      # container IDs 0..65535 are host IDs 100000..165535
```

Each map may be written **once**, in a **single** `write(2)`, by a process with `CAP_SETUID` in
the *parent* namespace. That is why the runtime (parent) writes the maps while the child waits,
and why there must be a protocol between them (chapter 4).

When `CLONE_NEWUSER` is combined with other `CLONE_NEW*` flags, the kernel creates the user
namespace *first* and makes it the owner of the others. That ownership is what lets the child,
root only inside its user namespace, mount `/proc` and set a hostname.

### PID 1 is special

The first process in a PID namespace is its `init`. If it dies, the kernel kills everything else
in the namespace. And it gets a protection no other process has: **signals with no handler
installed are not delivered to it**, not even from outside, with the exception of `SIGKILL` and
`SIGSTOP`.

So if your container runs `sleep 1000` and you press Ctrl-C, nothing happens: `sleep` installs no
`SIGINT` handler. This is why Docker has `--init` (a tiny init that forwards signals) and why
`docker stop` waits 10 seconds before it sends `SIGKILL`. hull forwards signals and, after three
Ctrl-Cs, sends `SIGKILL` (`crates/hull-runtime/src/run.rs`, `INTERRUPTS_BEFORE_KILL`).

### Why time namespaces are rejected for now

A time namespace's clock offsets can only be set *before* any process enters it. With `clone3` the
child is born inside, which is already too late. Supporting `linux.timeOffsets` needs
`unshare(CLONE_NEWTIME)`, then writing the offsets, then forking. That is a milestone M2 change to
the process-creation sequence.

## Read the code

- `crates/hull-sys/src/clone.rs`: the `clone3` wrapper. Read the `SAFETY` comment and
  `crates/hull-sys/src/thread.rs`: why a fork-like clone is only sound in a single-threaded
  process, and why that rules out Go for this layer.
- `crates/hull-runtime/src/idmap.rs`: writing the maps. Note `write` versus `write_all`.
- `crates/hull-runtime/src/init.rs`, `join_parent`: after the maps are written, the child switches
  to UID 0 *inside* the namespace. Read the comment to see why skipping this breaks file creation.

## Exercises

**1. User namespaces without root** (run this as your normal user, not with `sudo`):

```bash
unshare --user --map-root-user sh -c 'id; cat /proc/self/uid_map; touch /etc/x'
```

You are "root" and `/etc` still refuses you. Capabilities in a user namespace mean nothing for
files owned by users outside the mapping.

**2. Watch PID 1 ignore a signal:**

```bash
sudo unshare --pid --fork sleep 1000 &
```

```bash
sudo kill -TERM "$(pgrep -n sleep)"; sleep 0.5; pgrep -n sleep && echo "still alive"
```

Then `kill -KILL` it. The test `state_and_list_while_running` checks the same behaviour in hull.

**3. Change hull: support `linux.domainname` without a hostname.** It already works. Write the
test that proves it: add a case to `bins/hull-runtime/tests/runtime.rs` that sets `domainname` and
reads `/proc/sys/kernel/domainname` through the probe (it reports `domainname`). Then remove the
UTS namespace from the config and check that validation rejects it.

**4. Change hull: join an existing network namespace** (a preview of M2). Today
`linux.namespaces[].path` is rejected in `crates/hull-spec/src/validate.rs`. Allow it for
`network` only: open the path in the parent before `clone3`, leave `CLONE_NEWNET` out of the
flags, and call `setns(fd, CLONE_NEWNET)` in the child before rootfs setup. Test it with
`ip netns add test` and `"path": "/run/netns/test"`.
