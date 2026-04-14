#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${PEER_ADDR:?missing PEER_ADDR}"
: "${WAN_IF:?missing WAN_IF}"
: "${TUN_SUBNET:?missing TUN_SUBNET}"
ENABLE_TCPMSS="${ENABLE_TCPMSS:-0}"

ipt_add_unique() {
  local table="$1"; shift
  local chain="$1"; shift
  if ! iptables ${table:+-t "$table"} -C "$chain" "$@" 2>/dev/null; then
    iptables ${table:+-t "$table"} -A "$chain" "$@"
  fi
}

ipt_del_if_exists() {
  local table="$1"; shift
  local chain="$1"; shift
  while iptables ${table:+-t "$table"} -C "$chain" "$@" 2>/dev/null; do
    iptables ${table:+-t "$table"} -D "$chain" "$@"
  done
}

case "$ACTION" in
  up)
    ip addr replace "$TUN_ADDR" dev "$IFNAME"
    ip link set dev "$IFNAME" up

    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ipt_add_unique "" FORWARD -i "$IFNAME" -o "$WAN_IF" -j ACCEPT
    ipt_add_unique "" FORWARD -i "$WAN_IF" -o "$IFNAME" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ipt_add_unique nat POSTROUTING -s "$TUN_SUBNET" -o "$WAN_IF" -j MASQUERADE

    if [[ "$ENABLE_TCPMSS" == "1" ]]; then
      ipt_add_unique mangle FORWARD -i "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      ipt_add_unique mangle FORWARD -o "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    fi
    ;;
  down)
    ipt_del_if_exists "" FORWARD -i "$IFNAME" -o "$WAN_IF" -j ACCEPT
    ipt_del_if_exists "" FORWARD -i "$WAN_IF" -o "$IFNAME" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ipt_del_if_exists nat POSTROUTING -s "$TUN_SUBNET" -o "$WAN_IF" -j MASQUERADE

    if [[ "$ENABLE_TCPMSS" == "1" ]]; then
      ipt_del_if_exists mangle FORWARD -i "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      ipt_del_if_exists mangle FORWARD -o "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    fi

    ip addr del "$TUN_ADDR" dev "$IFNAME" 2>/dev/null || true
    ;;
  *)
    echo "unknown action: $ACTION" >&2
    exit 2
    ;;
esac
