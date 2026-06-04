#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${PEER_ADDR:?missing PEER_ADDR}"
TUN_ADDR6="${TUN_ADDR6:-}"
PEER_ADDR6="${PEER_ADDR6:-}"

TUN_ADDR_IP="${TUN_ADDR%%/*}"
TUN_ADDR6_IP="${TUN_ADDR6%%/*}"
TUN_ADDR6_PREFIX="${TUN_ADDR6##*/}"

case "$ACTION" in
  up)
    ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$PEER_ADDR" up
    if [[ -n "$TUN_ADDR6" ]]; then
      ifconfig "$IFNAME" inet6 "$TUN_ADDR6_IP" prefixlen "$TUN_ADDR6_PREFIX" alias >/dev/null 2>&1 || true
    fi
    ;;
  down)
    if [[ -n "$TUN_ADDR6" ]]; then
      ifconfig "$IFNAME" inet6 "$TUN_ADDR6_IP" delete >/dev/null 2>&1 || true
    fi
    ifconfig "$IFNAME" down >/dev/null 2>&1 || true
    ;;
  *)
    echo "unknown action: $ACTION" >&2
    exit 2
    ;;
esac
