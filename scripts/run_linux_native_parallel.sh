#!/usr/bin/env bash
set -euo pipefail

# Starts a native Linux test client beside the normal Python client. The
# generated configuration has one local HTTP-proxy listener and avoids every
# local socket and TUN address owned by Python.
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
base_config="${OBSTACLEBRIDGE_CONFIG:-${repo_root}/ObstacleBridge.cfg}"
binary="${OBSTACLEBRIDGE_LINUX_BINARY:-${repo_root}/build/linux/ObstacleBridgeLinux}"

if ! command -v jq >/dev/null 2>&1; then
    echo "run_linux_native_parallel: jq is required" >&2
    exit 1
fi
if [[ ! -r "${base_config}" ]]; then
    echo "run_linux_native_parallel: configuration is not readable: ${base_config}" >&2
    exit 1
fi
if [[ ! -x "${binary}" ]]; then
    echo "run_linux_native_parallel: Linux binary is not executable: ${binary}" >&2
    exit 1
fi

native_config="$(mktemp "${TMPDIR:-/tmp}/obstaclebridge-linux-native-parallel.XXXXXX.json")"
chmod 600 "${native_config}"
trap 'rm -f -- "${native_config}"' EXIT

jq '
  .admin_web.admin_web_port = 18091 |
  .debug_logging.log_file = "/tmp/ObstacleBridge_linux_native.log" |
  .TUN_routing.enabled_on_startup = false |
  .channel_mux.own_servers = [
    .channel_mux.own_servers[]
    | select(.name == "HttpProxy")
    | .listen.port = 3129
    | .target.port = 13881
  ] |
  .channel_mux.remote_servers = []
' "${base_config}" > "${native_config}"

echo "Native test client: http://127.0.0.1:18091/; proxy: 127.0.0.1:3129 -> peer-side TCP/13881" >&2
"${binary}" --config "${native_config}"
