# 4. The process

## The idea

After `clone3` there are two processes, and they must take turns. The protocol in
`crates/hull-runtime/src/sync.rs` is four messages over a `SOCK_SEQPACKET` socket pair:

```text
parent: write ID maps ──► Continue
child:                        hostname, mounts, pivot_root, rlimits, user, cwd ──► Ready
child:                        execve ──► (socket closes) ──► parent reads EOF = "exec worked"
child, at any point:          Failed { stage, message, exit_code }
```

Two design points to notice:

- `SEQPACKET` keeps message boundaries, so there is no framing code to get wrong.
- The socket is **close-on-exec**. A successful `execve` closes it, so the parent learns "exec
  worked" from an EOF. Nothing has to be sent after the point of no return.

### The order of privilege drops

`crates/hull-runtime/src/process.rs` applies settings in an order where each step still has the
privilege it needs. Raise rlimits while you still have `CAP_SYS_RESOURCE`. Change GIDs before the
UID, because changing the UID removes the right to change GIDs. Run `chdir` *after* the UID
change, so the permission check uses the container user. In M4 this table grows
(capabilities, seccomp), and getting the order wrong either fails or, worse, silently leaves
privileges in place.

### Three traps that cost real runtimes real bugs

1. **Ignored signals survive `execve`.** Handlers are reset, but `SIG_IGN` is inherited. The Rust
   standard library ignores `SIGPIPE` before `main` runs. Without `reset_dispositions()`, every
   container would ignore `SIGPIPE`. The signal *mask* is inherited too, and hull blocks signals to
   read them from a signalfd. See `crates/hull-sys/src/signal.rs`.
2. **File descriptors leak.** Any fd without `O_CLOEXEC` survives into the container. In runc
   CVE-2024-21626 a leaked fd to a host directory, plus `cwd = /proc/self/fd/7`, put the container
   process outside its root. hull marks every fd ≥ 3 close-on-exec right before `execve`, and
   verifies after `chdir` that the working directory is reachable from the root.
3. **The child must never return.** The child is a copy of the parent, including all of its
   cleanup code. If the child returned an error up the call stack, it would run the parent's
   cleanup and delete the container's state while the parent is still using it.
   `child_main` returns `!`, catches panics, reports them over the socket, and leaves via `_exit`.

### Exit codes

`hull-runtime run` exits with the container's exit code, or `128 + signal`. Its own failures use
`125`, and the shell conventions `126` (found but not executable) and `127` (not found) cover
`execve` errors. These are the same conventions Docker uses, so scripts can tell "my program
failed" from "the runtime failed".

## Read the code

- `crates/hull-runtime/src/init.rs`: the whole child, top to bottom. Find where the parent-death
  signal is armed and where it is cleared, and work out why it must be cleared before `execve`.
- `crates/hull-runtime/src/run.rs`: the `Init` type. Its `Drop` makes it impossible to leak a
  half-started container on any error path.

## Exercises

**1. See an inherited signal state:**

```bash
(trap '' PIPE; sh -c 'grep SigIgn /proc/self/status')
```

Bit 13 (`0x1000`) is `SIGPIPE`, ignored because the parent shell ignored it.

**2. Mutation test.** Comment out `hull_sys::signal::reset_dispositions();` in `init.rs` and run
`scripts/test-integration.sh signal_state`. The test fails with `SigIgn = 0x1000`. A test you
have never seen fail is a test you have no reason to trust.

**3. Change hull: implement `process.oomScoreAdj`.** Write the value to
`/proc/self/oom_score_adj` in the child, *before* the UID change (lowering it needs
`CAP_SYS_RESOURCE`). Remove the rejection in `validate.rs` and add a test. Then read
`docs/PLAN.md` §5 for why M4 does this through a hardened procfs handle, not a plain path.

**4. Change hull: implement `run --detach`.** This exercise has moved to
[chapter 6](06-the-lifecycle.md), exercise 3. Now that `create` and `start` exist, read that
chapter first.
