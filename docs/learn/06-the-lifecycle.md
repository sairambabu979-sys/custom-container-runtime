# 6. The lifecycle: create, start, kill, delete

## The idea

`run` does everything in one go. The OCI lifecycle splits it in two:

```text
create ──► created ──► start ──► running ──► (process exits) ──► stopped ──► delete
```

Why would anyone want a container that exists but does not run? Because the layers above need
the gap. Between `create` and `start`, containerd moves a network interface into the new network
namespace and configures it, and the OCI `createRuntime` and `createContainer` hooks run. The
program then starts with its network already up.

### What "created" looks like

After `create` returns, the container's init is fully set up: namespaces, mounts, `pivot_root`,
user identity. But it is still **a copy of hull-runtime**, blocked in one system call:

```text
open("/proc/self/fd/7", O_WRONLY)      ← the write end of a FIFO; blocks until there is a reader
```

`start` is nothing more than opening the read end of that FIFO.

### The exec FIFO trick

The FIFO lives in the state directory, `/run/hull/<id>/exec.fifo`, on the *host*. After
`pivot_root`, no path inside the container can reach it. So the parent opens it with `O_PATH`
*before* `clone3`, and init inherits that descriptor. An `O_PATH` descriptor still refers to the
file even when no path leads there. Reopening it through the `/proc/self/fd/N` "magic link"
turns it into a real write end. This is the same technique runc uses.

Two details in `start` are worth noticing:

- It opens the read end with `O_NONBLOCK`. A plain `O_RDONLY` open of a FIFO also blocks until
  there is a writer, so if init had died, `start` would hang forever.
- After unblocking, init writes one byte, and `start` waits for it. That byte proves that init
  really went on to `execve`. Then `start` deletes the FIFO, so a second `start` has nothing to
  open.

### Who reaps the container?

`create` exits while init lives on. An orphaned process is re-parented to its nearest
**subreaper**, a process that called `prctl(PR_SET_CHILD_SUBREAPER)`, or to the host's PID 1.
Whoever that is will `waitpid` it and learn its exit code. This is why containerd runs a *shim*
per container and Podman runs `conmon`: each is a subreaper that holds the container's exit code.
hull's tests make the test process a subreaper (`hull_testkit::become_subreaper`) for the same
reason, a small preview of `hull-shim` in M7.

### Signalling the right process

The state file records init's PID, but a PID is just a number the kernel will hand out again.
`kill` therefore opens a **pidfd** for the PID first, and only then checks that the process
behind the PID has the start time recorded at `create`. Signals sent through the pidfd can only
reach the process that held the PID when the pidfd was opened. The order of those two steps
matters, and the module docs of `crates/hull-runtime/src/lifecycle.rs` prove it.

Remember chapter 2: PID 1 ignores every signal it has no handler for. `kill <id>` sends SIGTERM,
so a container running `sleep` survives it. That is also why `delete` of a created container
uses SIGKILL: init is still hull-runtime, and it installs no handlers.

### The bug the first manual test found

The very first `create` followed by `start` failed with "another hull-runtime process holds its
lock", although no other process existed. The cause: a `flock` lock belongs to the *open file
description*, not to the process. `clone3` gave init a copy of `create`'s lock descriptor, and
init keeps it until `execve` closes it. That happens after `start`, and `start` needed the lock
to get there. `ContainerDir`'s `Drop` now calls `flock(LOCK_UN)`, which releases the lock on the
description, no matter who else holds a copy.

The lesson: **fork copies more than memory.** Every descriptor, and everything a descriptor
carries (locks, socket connections, pipe ends), is shared with the child until something closes
it.

## Read the code

- `crates/hull-runtime/src/run.rs`: `create`, `make_exec_fifo`, and how `spawn` serves both modes.
- `crates/hull-runtime/src/init.rs`: `wait_for_start`, and why the parent-death signal is cleared
  *before* `Ready` (what would happen to the container if it were cleared after?).
- `crates/hull-runtime/src/lifecycle.rs`: `start`, `kill`, `delete`, `open_init`.
- `crates/hull-runtime/src/state.rs`: `impl Drop for ContainerDir`.
- `bins/hull-runtime/tests/lifecycle.rs`: each test is one rule from this chapter.

## Exercises

**1. Look at a created container.** Create one, then inspect its init from the host:

```bash
sudo hull-runtime create --bundle /tmp/demo web < /dev/null
```

```bash
P=$(sudo hull-runtime state web | grep '"pid"' | tr -dc 0-9); sudo ls -l /proc/$P/exe /proc/$P/fd
```

`exe` is still hull-runtime. Besides stdio, init holds three of the runtime's descriptors, which
all close at `execve`:

| fd (typically) | Target | What it is |
|---|---|---|
| 3 | `/run/hull/web/lock` | The state lock, shared with `create` by `clone3`: the cause of this chapter's bug |
| 4 | `/run/hull/web/exec.fifo` | The `O_PATH` handle. Its permissions show as `l---------`, because an `O_PATH` descriptor cannot read or write |
| 6 | `socket:[...]` | Init's end of the sync socket from chapter 4 |

Run `sudo hull-runtime start web`, then look at `exe` and `fd` again. Clean up with
`sudo hull-runtime delete --force web`.

**2. Why `O_NONBLOCK`?** First see the FIFO rule for yourself. Opening a FIFO for reading blocks
until a writer appears:

```bash
mkfifo /tmp/f && timeout 2 cat /tmp/f; echo "exit $?"; rm /tmp/f
```

Exit 124 means `timeout` had to kill a `cat` stuck in `open`. Now read `lifecycle::start`. It
checks that init is alive (`open_init`) and only then opens the FIFO. What happens without
`O_NONBLOCK` if init dies *between* those two steps? Which line then reports the problem instead
of hanging?

**3. Change hull: implement `run --detach`.** This is the M2 exercise from chapter 4. Now that
`create` and `start` exist, `run --detach` is both of them in one command. Before you write it,
answer two questions: where does the container's stdout go once `run` has exited, and who reaps
the container? Then write an integration test in `bins/hull-runtime/tests/lifecycle.rs` in the
style of `create_waits_for_start_then_runs`.

**4. Join an existing network namespace.** This is chapter 2's exercise 4, and the lifecycle now
lets you do it the way containerd does. Create a namespace with `sudo ip netns add test`, give
the config `{"type": "network", "path": "/run/netns/test"}` (after implementing `path` support),
then `create`, configure the namespace, and `start`.

**5. Mutation test.** In `crates/hull-runtime/src/state.rs`, replace the body of
`ContainerDir::drop` with nothing and run `scripts/test-integration.sh lifecycle`. Almost every
test fails. Read one failure message and connect it to "fork copies more than memory".
