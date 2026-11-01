#!/usr/bin/env bash
# Fetch the busybox root filesystem used by the integration tests, verified by digest.
#
# Usage: scripts/fetch-rootfs.sh [DEST]      (default: .fixtures/busybox)
#
# The layer is pinned by content digest, so the bytes are exactly what the tests were written
# against, whatever the "busybox" tag points to today. Pinned image:
#   docker.io/library/busybox:1.37.0 (glibc variant)
#   index  sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
#   amd64  manifest sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4
#   arm64  manifest sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c
#
# This is the whole OCI distribution protocol in miniature: get an anonymous token, download a
# blob by digest, verify the digest. Milestone M6 replaces it with a real client.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:-$repo_root/.fixtures/busybox}"
repo="library/busybox"

case "$(uname -m)" in
  x86_64) layer="sha256:68fe9bff2ad4ad46da3e58db03faa64eb73c0ff16d546b0c42539eaa9854cb7f" ;;
  aarch64) layer="sha256:af820adcc158da1182aefa4259d1eb0a2e72416663faf00f6700f5415111974e" ;;
  *) echo "fetch-rootfs: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

if [[ -x "$dest/rootfs/bin/sh" && "$(cat "$dest/digest" 2>/dev/null || true)" == "$layer" ]]; then
  echo "fetch-rootfs: up to date ($dest)"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "fetch-rootfs: downloading $repo layer $layer"
token="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[[ -n "$token" ]] || { echo "fetch-rootfs: could not get a registry token" >&2; exit 1; }

curl -fsSL -H "Authorization: Bearer $token" \
  "https://registry-1.docker.io/v2/${repo}/blobs/${layer}" -o "$tmp/layer.tar.gz"
echo "${layer#sha256:}  $tmp/layer.tar.gz" | sha256sum --check --quiet -

rm -rf "$dest"
mkdir -p "$dest/rootfs"
tar -xzf "$tmp/layer.tar.gz" -C "$dest/rootfs"
echo "$layer" > "$dest/digest"
echo "fetch-rootfs: ready at $dest/rootfs"
