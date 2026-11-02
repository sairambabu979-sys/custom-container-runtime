# hull: notes for coding agents

hull is a **learning project**: an OCI container runtime written from first principles in Rust.
The owner is learning how containers work, so explain *why*, prefer readable code, and favour
exercises that the owner implements over large changes they only read.

## Where things stand

- Milestones M0 and M1 are done (`hull-runtime run`, namespaces, mounts, `pivot_root`, process
  setup). CI is green on x86_64 and aarch64.
- Read first: `docs/PLAN.md` (architecture, ADRs in §2, milestones in §14, decisions in §16),
  then `docs/STATUS.md` (what each config.json field does today), then `docs/learn/`.
- Suggested next step for the owner: exercises in `docs/learn/02-namespaces.md` #4 (join an
  existing network namespace) and `docs/learn/04-the-process.md` #4 (`run --detach`). Both are the
  first slice of M2. Review their attempt rather than writing it for them.
- Active branch: `claude/quirky-ride-6c8z0x` (currently the repository's default branch).

## Rules the code depends on

- **Linux only, root only** (kernel 5.14+). Nothing here builds a useful binary on macOS/Windows.
- `unsafe` lives only in `crates/hull-sys`, every block has a `// SAFETY:` comment, and every other
  crate has `#![forbid(unsafe_code)]`.
- `hull-runtime` must stay **single-threaded** until `clone3` (`hull_sys::thread`). No async
  runtime, no background threads, no logging writers that spawn threads.
- **Fail closed:** a config field hull understands but does not implement is rejected in
  `crates/hull-spec/src/validate.rs` with the milestone that adds it. Never parse-and-ignore.
- Every fallible syscall gets context via `.context(|| ...)` that names the operation and path.
- The child after `clone3` never returns into parent code. It ends in `execve` or `_exit`.

## Definition of done for a change

1. `cargo fmt --all --check`
2. `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets`
3. `cargo test --workspace`
4. `scripts/test-integration.sh` (needs root and `runc`; runs real containers and the runc
   differential tests)
5. `cargo +1.88 check --workspace --all-targets` (MSRV)
6. New behaviour has an integration test, and a differential test against runc where runc
   implements the same feature. Mutation-check new tests: break the code, see the test fail.
7. `docs/STATUS.md` and the relevant `docs/learn/` chapter are updated.
8. Each commit builds on its own. Commit messages explain why, not just what.

## Known open items

- PRs #1 and #2 (Copilot lint fixes) are redundant with commit `ebb51f8` and can be closed.
- The development toolchain is pinned in `rust-toolchain.toml`; bump it deliberately, together
  with the version in `.github/workflows/ci.yml`.
