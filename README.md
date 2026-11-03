# hull

A container engine built from first principles on Linux namespaces, cgroups and `pivot_root`,
written in Rust to learn how runc, containerd and Docker actually work.

```text
$ sudo hull-runtime run --bundle ./demo web
/ # echo "pid=$$ host=$(hostname) uid=$(id -u)"
pid=1 host=hull uid=0
```

> **Status: milestone M2 of 9 in progress.** `hull-runtime run` starts a real OCI container (namespaces,
> user namespaces, fd-based mounts, `pivot_root`, devices, rlimits, user identity), and the
> differential tests show it behaving like runc in every scenario they cover. It is **not a
> security boundary yet**: there is no
> capability dropping, seccomp or cgroups until M3–M4, and hull refuses configs that ask for them
> rather than silently running without them. See [docs/STATUS.md](docs/STATUS.md).

## Why this exists

This is a learning project, and the code is written to be read. Every module explains *why* it
does what it does, including the bugs and CVEs that shaped the design.

- Start with **[docs/learn/](docs/learn/README.md)**: six chapters that walk through the code,
  each with exercises.
- The roadmap and architecture are in **[docs/PLAN.md](docs/PLAN.md)**.

## Quick start

You need Linux 5.14+ and root. `rust-toolchain.toml` pins the Rust version that development
and CI use; the minimum supported version is 1.88.

```bash
cargo build --release -p hull-runtime-cli
```

```bash
scripts/fetch-rootfs.sh
```

```bash
mkdir -p /tmp/demo && cp -a .fixtures/busybox/rootfs /tmp/demo/rootfs
```

```bash
./target/release/hull-runtime spec --bundle /tmp/demo
```

```bash
sudo ./target/release/hull-runtime run --bundle /tmp/demo hello
```

That gives you a busybox shell as PID 1 in its own PID, mount, network, IPC and UTS namespaces.
Edit `/tmp/demo/config.json` to change what runs.

| Command | What it does |
|---|---|
| `hull-runtime spec [--bundle DIR]` | Write a default `config.json` |
| `hull-runtime run [--bundle DIR] [--pid-file F] ID` | Create the container and run it in the foreground |
| `hull-runtime create [--bundle DIR] [--pid-file F] ID` | Set the container up; its process waits for `start` |
| `hull-runtime start ID` | Let a created container's process run |
| `hull-runtime kill ID [SIGNAL]` | Signal the container's init (default `TERM`) |
| `hull-runtime delete [--force] ID` | Remove a stopped container (`--force` kills a running one) |
| `hull-runtime state ID` | Print the OCI state as JSON |
| `hull-runtime list [--format json] [-q]` | List containers |

## How it is tested

| Layer | What | Command |
|---|---|---|
| Unit | Parsers, validation, path resolution, the sync protocol, symlink-escape attempts | `cargo test --workspace` |
| Integration | 26 scenarios against real namespaces: isolation, mounts, devices, IDs, signals, fd leaks, symlink attacks, cleanup after failure, and the create/start/kill/delete lifecycle | `scripts/test-integration.sh` |
| Differential | The same bundle under **runc** and hull; a probe inside the container compares capabilities, IDs, signal state, mounts, devices, rlimits and environment, and any difference fails the test | `scripts/test-integration.sh` |

The differential tests have already caught five behaviour gaps that hand-written assertions
missed. Two of them only showed up on CI's systemd host: a container root that stayed a
propagation slave of the host, and a missing `/dev/core`. [Chapter 5](docs/learn/05-testing-a-runtime.md) tells the
story.

## Layout

```text
crates/
  hull-sys/       the only crate allowed to use `unsafe`: clone3, execve, signals, mount_setattr
  hull-fs/        SafeRoot: path resolution that symlinks inside an image cannot escape
  hull-spec/      config.json loading and fail-closed validation
  hull-runtime/   the runtime: state, sync protocol, rootfs, process setup, run
  hull-testkit/   integration-test harness (bundles, runc comparison, leak checks)
bins/
  hull-runtime/   the runc-compatible CLI
  hull-probe/     static binary that reports what a container can see
```

## License

Apache-2.0, the same as runc, containerd and the OCI specifications.
