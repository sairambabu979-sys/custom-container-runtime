#!/usr/bin/env bash
# Run hull's privileged integration tests.
#
# Usage: scripts/test-integration.sh [runtime|lifecycle|differential] [TEST NAME FILTER...]
#
#   scripts/test-integration.sh                      everything
#   scripts/test-integration.sh lifecycle            one test file (bins/hull-runtime/tests/*.rs)
#   scripts/test-integration.sh signal_state         tests whose name contains "signal_state"
#
# What it does, and why each step is needed:
#   1. Fetches the pinned busybox rootfs that containers run in.
#   2. Builds hull-probe as a *static* binary, so it runs in any image regardless of its libc.
#      (A static glibc build via +crt-static. The musl target does not link on aarch64 with
#      current toolchains: compiler-builtins needs getauxval before libc is on the link line.)
#   3. Runs the #[ignore]d tests as root. If you are not root, everything is built as you and only
#      the test binaries run under `sudo` (via cargo's target runner setting).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

arch="$(uname -m)"
host_target="${arch}-unknown-linux-gnu"

scripts/fetch-rootfs.sh

# An explicit --target keeps the static probe's artifacts apart from the normal build, so the
# extra RUSTFLAGS do not force everything else to rebuild.
RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static" \
  cargo build --release -p hull-probe --target "$host_target"

export HULL_PROBE="$PWD/target/$host_target/release/hull-probe"
export HULL_TEST_ROOTFS="$PWD/.fixtures/busybox/rootfs"

if [[ $EUID -ne 0 ]]; then
  runner_var="CARGO_TARGET_$(echo "$host_target" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
  export "$runner_var"="sudo -E"
  echo "test-integration: not root; test binaries will run via sudo"
fi

if ! command -v runc >/dev/null; then
  echo "test-integration: runc not found; the differential tests will fail (install runc)" >&2
fi

# A first argument naming a test file selects that file; everything else filters test names.
test_file=()
if [[ $# -gt 0 && -f "bins/hull-runtime/tests/$1.rs" ]]; then
  test_file=(--test "$1")
  shift
fi

# --no-fail-fast: show every failing test binary, not just the first.
cargo test --no-fail-fast -p hull-runtime-cli "${test_file[@]}" -- --ignored "$@"
