#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${TUN_GW:?missing TUN_GW}"
OVERLAY_PEER_IP="${OVERLAY_PEER_IP:-${OB_OVERLAY_PEER_HOST:-}}"
: "${OVERLAY_PEER_IP:?missing OVERLAY_PEER_IP or OB_OVERLAY_PEER_HOST}"
UNDERLAY_IF="${UNDERLAY_IF:-auto}"
UNDERLAY_GW="${UNDERLAY_GW:-auto}"
DNS1="${DNS1:-}"
DNS2="${DNS2:-}"

STATE_DIR="/run/obbridge"
STATE_FILE="${STATE_DIR}/${IFNAME}.default-route"

mkdir -p "$STATE_DIR"

overlay_route_prefix() {
  if [[ "$OVERLAY_PEER_IP" == *:* ]]; then
    printf '%s/128' "$OVERLAY_PEER_IP"
  else
    printf '%s/32' "$OVERLAY_PEER_IP"
  fi
}

detect_underlay() {
  local route_line
  route_line="$(ip route get "$OVERLAY_PEER_IP" 2>/dev/null | head -n1 || true)"
  if [[ -z "$route_line" ]]; then
    echo "unable to detect route to overlay peer ${OVERLAY_PEER_IP}" >&2
    exit 1
  fi
  if [[ "$UNDERLAY_IF" == "auto" || -z "$UNDERLAY_IF" ]]; then
    UNDERLAY_IF="$(awk '{for (i=1; i<NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<<"$route_line")"
  fi
  if [[ "$UNDERLAY_GW" == "auto" || -z "$UNDERLAY_GW" ]]; then
    UNDERLAY_GW="$(awk '{for (i=1; i<NF; i++) if ($i == "via") {print $(i+1); exit}}' <<<"$route_line")"
  fi
  if [[ -z "$UNDERLAY_IF" ]]; then
    echo "unable to detect underlay interface from: ${route_line}" >&2
    exit 1
  fi
}

save_default_route() {
  ip route show default | head -n1 > "$STATE_FILE" || true
}

restore_default_route() {
  if [[ -s "$STATE_FILE" ]]; then
    local current_default
    current_default="$(cat "$STATE_FILE")"
    ip route replace $current_default
  fi
}

set_dns() {
  if command -v resolvectl >/dev/null 2>&1; then
    if [[ -n "$DNS1" && -n "$DNS2" ]]; then
      resolvectl dns "$IFNAME" "$DNS1" "$DNS2" || true
    elif [[ -n "$DNS1" ]]; then
      resolvectl dns "$IFNAME" "$DNS1" || true
    fi
    resolvectl domain "$IFNAME" "~." || true
    resolvectl default-route "$IFNAME" yes || true
  fi
}

clear_dns() {
  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl revert "$IFNAME" || true
  fi
}

case "$ACTION" in
  up)
    detect_underlay
    ip addr replace "$TUN_ADDR" dev "$IFNAME"
    ip link set dev "$IFNAME" up

    save_default_route

    if [[ -n "$UNDERLAY_GW" ]]; then
      ip route replace "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF"
    else
      ip route replace "$(overlay_route_prefix)" dev "$UNDERLAY_IF"
    fi
    ip route replace default via "$TUN_GW" dev "$IFNAME"

    set_dns
    ;;
  down)
    detect_underlay
    ip route del default via "$TUN_GW" dev "$IFNAME" 2>/dev/null || true
    restore_default_route
    if [[ -n "$UNDERLAY_GW" ]]; then
      ip route del "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF" 2>/dev/null || true
    else
      ip route del "$(overlay_route_prefix)" dev "$UNDERLAY_IF" 2>/dev/null || true
    fi

    clear_dns
    ip addr del "$TUN_ADDR" dev "$IFNAME" 2>/dev/null || true
    ;;
  *)
    echo "unknown action: $ACTION" >&2
    exit 2
    ;;
esac
