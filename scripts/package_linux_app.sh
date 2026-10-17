#!/usr/bin/env bash
set -euo pipefail

usage() { echo "usage: $0 --binary PATH --output PATH" >&2; exit 2; }
binary= output=
while (($#)); do case "$1" in --binary) shift; binary=${1:-};; --output) shift; output=${1:-};; *) usage;; esac; shift; done
[[ -x "$binary" && -n "$output" ]] || usage
root="$(cd "$(dirname "$0")/.." && pwd)"
stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
install -D -m 0755 "$binary" "$stage/obstaclebridge-linux/bin/obstaclebridge-linux"
install -D -m 0755 "$root/scripts/install_linux_service.sh" "$stage/obstaclebridge-linux/install-linux-service.sh"
install -D -m 0644 "$root/packaging/linux/systemd/obstaclebridge-linux.service.in" "$stage/obstaclebridge-linux/systemd/obstaclebridge-linux.service.in"
tar -C "$stage" -czf "$output" obstaclebridge-linux
