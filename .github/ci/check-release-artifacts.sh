#!/usr/bin/env bash
set -euo pipefail

# Usage: check-release-artifacts.sh <prefix>, where <prefix> is `debug` or the formal tag (e.g. v0.1.0-rc.1).
prefix=${1:?usage: check-release-artifacts.sh <debug|tag>}

check() {
  local artifact=$1
  if [[ ! -f "$artifact" || ! -s "$artifact" ]]; then
    printf '::error::Missing or empty release artifact: %s. Re-run all jobs to rebuild the complete set.\n' "$artifact" >&2
    exit 1
  fi
}

# This fork ships the static musl full build only, for both gateway architectures.
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  check "dist/honk-core-$prefix-$target-full.tar.gz"
done
