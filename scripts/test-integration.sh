#!/usr/bin/env bash
# Run hull's privileged integration tests.
#
# Usage: scripts/test-integration.sh [TEST FILTER...]
#
# What it does, and why each step is needed:
#   1. Fetches the pinned busybox rootfs that containers run in.
#   2. Builds hull-probe as a *static* binary, so it runs in any image regardless of its libc.
#   3. Runs the #[ignore]d tests as root. If you are not root, everything is built as you and only
#      the test binaries run under `sudo` (via cargo's target runner setting).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

arch="$(uname -m)"
musl_target="${arch}-unknown-linux-musl"
host_target="${arch}-unknown-linux-gnu"

scripts/fetch-rootfs.sh

if ! rustup target list --installed 2>/dev/null | grep -qx "$musl_target"; then
  rustup target add "$musl_target"
fi
cargo build --release -p hull-probe --target "$musl_target"

export HULL_PROBE="$PWD/target/$musl_target/release/hull-probe"
export HULL_TEST_ROOTFS="$PWD/.fixtures/busybox/rootfs"

if [[ $EUID -ne 0 ]]; then
  runner_var="CARGO_TARGET_$(echo "$host_target" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
  export "$runner_var"="sudo -E"
  echo "test-integration: not root; test binaries will run via sudo"
fi

if ! command -v runc >/dev/null; then
  echo "test-integration: runc not found; the differential tests will fail (install runc)" >&2
fi

cargo test -p hull-runtime-cli -- --ignored "$@"
