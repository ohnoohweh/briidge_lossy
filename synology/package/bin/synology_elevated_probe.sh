#!/bin/sh
set -eu

PKG_ID="${1:-obstaclebridge}"
VAR_DIR="${2:-/var/packages/${PKG_ID}/var}"
LOG_DIR="${VAR_DIR}/log"
PROBE_LOG="${LOG_DIR}/elevated-probe.log"
PROBE_STATE="${VAR_DIR}/elevated-probe.json"

mkdir -p "${LOG_DIR}"

uid="$(id -u)"
gid="$(id -g)"
user_name="$(id -un 2>/dev/null || echo unknown)"
group_name="$(id -gn 2>/dev/null || echo unknown)"
tun_exists="false"
tun_rw="false"

if [ -e /dev/net/tun ]; then
    tun_exists="true"
fi

if [ -r /dev/net/tun ] && [ -w /dev/net/tun ]; then
    tun_rw="true"
fi

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat >"${PROBE_STATE}" <<EOF
{
  "timestamp_utc": "${timestamp}",
  "uid": ${uid},
  "gid": ${gid},
  "user": "${user_name}",
  "group": "${group_name}",
  "dev_net_tun_exists": ${tun_exists},
  "dev_net_tun_read_write": ${tun_rw}
}
EOF

echo "[synology-elevated-probe] ${timestamp} uid=${uid} gid=${gid} user=${user_name} group=${group_name} /dev/net/tun exists=${tun_exists} rw=${tun_rw}" >>"${PROBE_LOG}"
