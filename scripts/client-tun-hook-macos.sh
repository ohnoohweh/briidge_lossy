#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${TUN_GW:?missing TUN_GW}"
TUN_ADDR6="${TUN_ADDR6:-}"
TUN_GW6="${TUN_GW6:-}"
OVERLAY_PEER_IP="${OVERLAY_PEER_IP:-${OB_OVERLAY_PEER_HOST:-}}"

STATE_DIR="/tmp/obbridge"
STATE_FILE="${STATE_DIR}/${IFNAME}.default-route"
STATE_FILE6="${STATE_DIR}/${IFNAME}.default-route6"

mkdir -p "$STATE_DIR"

TUN_ADDR_IP="${TUN_ADDR%%/*}"
TUN_ADDR6_IP="${TUN_ADDR6%%/*}"
TUN_ADDR6_PREFIX="${TUN_ADDR6##*/}"

normalize_overlay_peer_ip() {
  local candidate="$1"
  if [[ "$candidate" =~ ^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  printf '%s' "$candidate"
}

detect_underlay_gw() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  if [[ -z "$normalized_ip" ]]; then
    return 1
  fi
  route -n get "$normalized_ip" 2>/dev/null | awk '/gateway:/{print $2; exit}'
}

save_default_routes() {
  local current_gw
  current_gw="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}' || true)"
  if [[ -n "$current_gw" ]]; then
    printf '%s\n' "$current_gw" > "$STATE_FILE"
  fi

  local current_gw6
  current_gw6="$(route -n get -inet6 default 2>/dev/null | awk '/gateway:/{print $2; exit}' || true)"
  if [[ -n "$current_gw6" ]]; then
    printf '%s\n' "$current_gw6" > "$STATE_FILE6"
  fi
}

restore_default_routes() {
  if [[ -s "$STATE_FILE" ]]; then
    route -n delete default >/dev/null 2>&1 || true
    route -n add default "$(cat "$STATE_FILE")" >/dev/null 2>&1 || true
  fi
  if [[ -s "$STATE_FILE6" ]]; then
    route -n delete -inet6 default >/dev/null 2>&1 || true
    route -n add -inet6 default "$(cat "$STATE_FILE6")" >/dev/null 2>&1 || true
  fi
}

case "$ACTION" in
  up)
    ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$TUN_GW" up
    if [[ -n "$TUN_ADDR6" ]]; then
      ifconfig "$IFNAME" inet6 "$TUN_ADDR6_IP" prefixlen "$TUN_ADDR6_PREFIX" alias >/dev/null 2>&1 || true
    fi

    local_underlay_gw="$(detect_underlay_gw || true)"
    save_default_routes

    if [[ -n "$OVERLAY_PEER_IP" && -n "$local_underlay_gw" ]]; then
      route -n add -host "$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")" "$local_underlay_gw" >/dev/null 2>&1 || true
    fi

    route -n delete default >/dev/null 2>&1 || true
    route -n add default "$TUN_GW" >/dev/null 2>&1 || true
    if [[ -n "$TUN_GW6" ]]; then
      route -n delete -inet6 default >/dev/null 2>&1 || true
      route -n add -inet6 default "$TUN_GW6" >/dev/null 2>&1 || true
    fi
    ;;
  down)
    if [[ -n "$OVERLAY_PEER_IP" ]]; then
      route -n delete -host "$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")" >/dev/null 2>&1 || true
    fi
    restore_default_routes
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
