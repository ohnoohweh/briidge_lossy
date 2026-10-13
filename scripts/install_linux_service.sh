#!/usr/bin/env bash
set -euo pipefail

usage() { echo "usage: $0 --binary PATH --config PATH --user USER [--unit-dir DIR] [--state-dir DIR] [--admin-port PORT] [--dry-run]" >&2; exit 2; }
binary= config= user= unit_dir=/etc/systemd/system state_dir=/var/lib/obstaclebridge admin_port=0 dry_run=0
while (($#)); do case "$1" in
  --binary|--config|--user|--unit-dir|--state-dir|--admin-port) key="${1#--}"; shift; (($# > 0)) || usage; case "$key" in binary) binary=$1;; config) config=$1;; user) user=$1;; unit-dir) unit_dir=$1;; state-dir) state_dir=$1;; admin-port) admin_port=$1;; esac;;
  --dry-run) dry_run=1;; *) usage;; esac; shift; done
[[ -x "$binary" && -f "$config" && -n "$user" && "$admin_port" =~ ^[0-9]+$ ]] || usage
template="$(cd "$(dirname "$0")/.." && pwd)/packaging/linux/systemd/obstaclebridge-linux.service.in"
rendered="$(sed -e "s|@BINARY@|$binary|g" -e "s|@CONFIG@|$config|g" -e "s|@USER@|$user|g" -e "s|@STATE_DIR@|$state_dir|g" -e "s|@ADMIN_PORT@|$admin_port|g" "$template")"
if ((dry_run)); then printf '%s\n' "$rendered"; exit 0; fi
install -d -m 0755 "$unit_dir" "$state_dir"
printf '%s\n' "$rendered" > "$unit_dir/obstaclebridge-linux.service"
systemctl daemon-reload
echo "Installed obstaclebridge-linux.service. Enable deliberately with: systemctl enable --now obstaclebridge-linux"
