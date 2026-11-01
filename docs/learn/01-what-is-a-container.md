# 1. What a container is

## The idea

There is no "container" object in the Linux kernel. A container is an ordinary process that the
kernel shows a different view of the system:

| The process sees its own... | Kernel feature | hull milestone |
|---|---|---|
| process tree (it is PID 1) | PID namespace | M1 |
| filesystem tree | mount namespace + `pivot_root` | M1 |
| hostname | UTS namespace | M1 |
| network interfaces | network namespace | M1 (empty), M8 (connected) |
| user IDs (root inside, nobody outside) | user namespace | M1 |
| share of CPU, memory, PIDs | cgroups | M3 |
| allowed syscalls and privileges | capabilities, seccomp, `no_new_privs` | M1–M4 |

A **container runtime** like runc, crun or `hull-runtime` sets up that view and then `execve`s the
program. Everything Docker adds on top (images, networks, a daemon, an API) is somebody else's
job. The [plan](../PLAN.md) builds those later.

The contract between the two layers is the **OCI runtime spec**. A *bundle* is a directory holding
a `config.json` (what to set up) and a root filesystem (what the process sees as `/`).

## Read the code

- `crates/hull-spec/src/default-config.json` is the config `hull-runtime spec` writes. Read it
  top to bottom; every field maps to a row in the table above.
- `crates/hull-runtime/src/run.rs` is the whole lifecycle in one file. The module comment lists the
  seven steps. The rest of this course zooms into each one.

## Exercises

**1. A container with no runtime at all.** `unshare` is a thin wrapper around the same syscalls:

```bash
sudo unshare --pid --fork --mount-proc --uts --net sh -c 'hostname box; hostname; echo pid=$$; ps; ip link'
```

You are PID 1, `ps` shows almost nothing, the hostname changed only inside, and there is only a
loopback interface. Notice what is *missing*: your files are all still there. A namespace changes
what you see of the process tree, but nothing yet changes your filesystem.

**2. Find the namespaces of a process.** Every namespace is a file:

```bash
ls -l /proc/self/ns/
```

```bash
sudo unshare --uts readlink /proc/self/ns/uts /proc/1/ns/uts
```

Two different inode numbers mean two different namespaces. hull's probe compares exactly these to
decide whether a namespace is private.

**3. Run your first hull container**, then edit `config.json` so that the process runs
`cat /proc/self/status` and find the `NoNewPrivs` line. Set `"noNewPrivileges": false`, run it
again, and see the line change.
