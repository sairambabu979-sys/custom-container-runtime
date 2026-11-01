# 3. The root filesystem

## The idea

A new mount namespace starts as a **copy** of the parent's mount table. The runtime then has to
build the container's `/` and make the host's tree disappear. The steps are in
`crates/hull-runtime/src/rootfs.rs`, and each one exists for a reason.

### 1. Propagation: stop leaks to the host

Mounts can be *shared*: on most systemd hosts `/` is shared, so a mount made in one namespace
appears in its peers. If the runtime mounted `/proc` into the container's rootfs without changing
that, the mount would show up on the host. The first thing hull does is make every mount in its
copy a recursive **slave**: events flow in from the host but never back out.

### 2. The fd-based mount API: no paths, no races

Classic `mount(source, target, ...)` takes path strings, and the kernel resolves `target` when
the call happens. Suppose the runtime checked that `/rootfs/data` is a directory. Between that
check and the `mount` call, a process in the container replaces `data` with a symlink to
`/etc`. The runtime has now mounted over the *host's* `/etc`. This is CVE-2021-30465 in runc.

Linux 5.2 split mounting into fd-based steps:

```text
fsopen("tmpfs") → fsconfig(...) → fsmount() → mnt_fd        (or open_tree() for bind mounts)
mount_setattr(mnt_fd, ro/nosuid/...)                        configure while invisible
target_fd = openat2(rootfs_fd, "data", RESOLVE_IN_ROOT)    resolve once, inside the root
move_mount(mnt_fd → target_fd)                              attach: no path is looked up
```

### 3. `SafeRoot`: resolving paths inside an untrusted tree

`openat2(RESOLVE_IN_ROOT)` makes the kernel treat a directory fd as `/` for one lookup: absolute
symlinks and `..` cannot leave it. `crates/hull-fs/src/root.rs` builds `mkdir_all`, `ensure_file`
and `symlink` on top of that. Its tests try to escape with absolute symlinks, `..` symlinks and
symlink loops.

One subtlety cost a real bug here. Images contain *dangling* symlinks (`/etc/resolv.conf ->
../run/systemd/resolve/stub-resolv.conf`), and runtimes are expected to create the target. The
first version of `mkdir_all` refused, which was safe but incompatible. The fix follows the symlink
*lexically*, then resolves the result with `RESOLVE_IN_ROOT` again, so a crafted target can still
only point inside the root.

### 4. `pivot_root`, not `chroot`

`chroot` changes how *paths* are resolved, but the old root stays mounted and reachable: a process
with `CAP_SYS_CHROOT` can `chroot` again into a subdirectory and walk out with `..`.
`pivot_root` swaps the mounts themselves. After `pivot_root(".", ".")` and
`umount2(".", MNT_DETACH)`, the host's tree is no longer attached to the container's mount table
at all.

## Read the code

- `crates/hull-spec/src/mounts.rs`: how one OCI option list splits four ways (creation,
  attributes, propagation, filesystem parameters). Note why `relatime` is not a "recursive `elatime`".
- `crates/hull-runtime/src/mounts.rs`: the fd pipeline. `kernel_message` reads the kernel's own
  explanation of an `fsconfig` failure, a feature most runtimes ignore.
- `crates/hull-runtime/src/rootfs.rs`: why the `SafeRoot` is opened *after* the self-bind mount.
  Hint: an fd refers to whatever was mounted at that moment.

## Exercises

**1. See propagation:**

```bash
findmnt -o TARGET,PROPAGATION /
```

```bash
sudo unshare --mount --propagation unchanged sh -c 'mount -t tmpfs x /mnt; sleep 30' & sleep 1; findmnt /mnt
```

With `unchanged` on a shared `/`, the tmpfs appears on the host. Repeat with
`--propagation slave` and it does not.

**2. The race, by hand.** In a bundle, make `rootfs/data` a symlink to `/tmp/victim` (a host
path) and add a tmpfs mount at `/data/x`. Run hull and check that `/tmp/victim/x` was **not**
created on the host, but `rootfs/tmp/victim/x` was. That is what the test
`symlinked_mount_destination_cannot_escape_the_rootfs` automates.

**3. Change hull: break it on purpose.** In `crates/hull-runtime/src/rootfs.rs`, remove the
`mount_change(... DOWNSTREAM | REC)` call, then run `scripts/test-integration.sh`. What happens
depends on your host, which is the point of the exercise:

- If `findmnt -o PROPAGATION /` says **shared** (any systemd host), every test fails: the kernel
  refuses `pivot_root` with `EINVAL` when the new root's parent mount is shared, precisely to stop
  this kind of leak (see `pivot_root(2)`).
- If it says **private** (as in hull's development sandbox), every test still passes and nothing
  visibly breaks.

So a runtime that "works on my machine" without this call is relying on host configuration it
does not control. Put the call back.

**4. Change hull: support `linux.readonlyPaths`** (a piece of M4). For each path: resolve it
through `SafeRoot`, `open_tree(OPEN_TREE_CLONE)` it, `mount_setattr(RDONLY)` the clone, and
`move_mount` it back onto itself. Skip paths that do not exist. Then remove the rejection in
`validate.rs` and use the probe to check that `/proc/sys` is read-only.
