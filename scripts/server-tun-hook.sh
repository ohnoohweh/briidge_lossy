#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${WAN_IF:?missing WAN_IF}"
: "${TUN_SUBNET:?missing TUN_SUBNET}"
TUN_ADDR6="${TUN_ADDR6:-}"
PEER_ADDR6="${PEER_ADDR6:-}"
TUN_SUBNET6="${TUN_SUBNET6:-}"
ENABLE_TCPMSS="${ENABLE_TCPMSS:-0}"
ENABLE_TUN_TCPDUMP="${ENABLE_TUN_TCPDUMP:-0}"
TCPDUMP_BIN="${TCPDUMP_BIN:-tcpdump}"
TCPDUMP_PCAP_PATH="${TCPDUMP_PCAP_PATH:-/tmp/ObstacleBridge-${IFNAME}.pcap}"
TCPDUMP_PIDFILE="${TCPDUMP_PIDFILE:-/tmp/ObstacleBridge-${IFNAME}.tcpdump.pid}"
TCPDUMP_STDERR_LOG="${TCPDUMP_STDERR_LOG:-/tmp/ObstacleBridge-${IFNAME}.tcpdump.log}"

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

ip6t_add_unique() {
  local table="$1"; shift
  local chain="$1"; shift
  if ! ip6tables ${table:+-t "$table"} -C "$chain" "$@" 2>/dev/null; then
    ip6tables ${table:+-t "$table"} -A "$chain" "$@"
  fi
}

ip6t_del_if_exists() {
  local table="$1"; shift
  local chain="$1"; shift
  while ip6tables ${table:+-t "$table"} -C "$chain" "$@" 2>/dev/null; do
    ip6tables ${table:+-t "$table"} -D "$chain" "$@"
  done
}

tcpdump_start_if_enabled() {
  if [[ "$ENABLE_TUN_TCPDUMP" != "1" ]]; then
    return
  fi
  if ! command -v "$TCPDUMP_BIN" >/dev/null 2>&1; then
    echo "tcpdump capture requested but '$TCPDUMP_BIN' was not found" >&2
    return
  fi
  if [[ -f "$TCPDUMP_PIDFILE" ]]; then
    local existing_pid
    existing_pid="$(cat "$TCPDUMP_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
      return
    fi
    rm -f "$TCPDUMP_PIDFILE"
  fi
  local started_pid=""
  if nohup "$TCPDUMP_BIN" -U -ni "$IFNAME" -w "$TCPDUMP_PCAP_PATH" >"$TCPDUMP_STDERR_LOG" 2>&1 & then
    started_pid="$!"
    if [[ -n "$started_pid" ]]; then
      echo "$started_pid" > "$TCPDUMP_PIDFILE" || true
      if ! kill -0 "$started_pid" 2>/dev/null; then
        echo "tcpdump capture requested but process exited immediately; see ${TCPDUMP_STDERR_LOG}" >&2
        rm -f "$TCPDUMP_PIDFILE"
      fi
    fi
  else
    echo "tcpdump capture requested but could not be started; see ${TCPDUMP_STDERR_LOG}" >&2
  fi
}

tcpdump_stop_if_enabled() {
  if [[ "$ENABLE_TUN_TCPDUMP" != "1" ]]; then
    return
  fi
  if [[ -f "$TCPDUMP_PIDFILE" ]]; then
    local existing_pid
    existing_pid="$(cat "$TCPDUMP_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$existing_pid" ]]; then
      kill "$existing_pid" 2>/dev/null || true
    fi
    rm -f "$TCPDUMP_PIDFILE"
  fi
}

case "$ACTION" in
  up)
    ip addr replace "$TUN_ADDR" dev "$IFNAME"
    if [[ -n "$TUN_ADDR6" ]]; then
      ip -6 addr replace "$TUN_ADDR6" dev "$IFNAME"
    fi
    ip link set dev "$IFNAME" up

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    if [[ -n "$TUN_SUBNET6" ]]; then
      sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    fi

    ipt_add_unique "" FORWARD -i "$IFNAME" -o "$WAN_IF" -j ACCEPT
    ipt_add_unique "" FORWARD -i "$WAN_IF" -o "$IFNAME" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ipt_add_unique nat POSTROUTING -s "$TUN_SUBNET" -o "$WAN_IF" -j MASQUERADE
    if [[ -n "$TUN_SUBNET6" ]]; then
      ip6t_add_unique "" FORWARD -i "$IFNAME" -o "$WAN_IF" -j ACCEPT
      ip6t_add_unique "" FORWARD -i "$WAN_IF" -o "$IFNAME" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
      ip6t_add_unique nat POSTROUTING -s "$TUN_SUBNET6" -o "$WAN_IF" -j MASQUERADE
    fi

    if [[ "$ENABLE_TCPMSS" == "1" ]]; then
      ipt_add_unique mangle FORWARD -i "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      ipt_add_unique mangle FORWARD -o "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      if [[ -n "$TUN_SUBNET6" ]]; then
        ip6t_add_unique mangle FORWARD -i "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        ip6t_add_unique mangle FORWARD -o "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      fi
    fi
    tcpdump_start_if_enabled
    ;;
  down)
    ipt_del_if_exists "" FORWARD -i "$IFNAME" -o "$WAN_IF" -j ACCEPT
    ipt_del_if_exists "" FORWARD -i "$WAN_IF" -o "$IFNAME" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ipt_del_if_exists nat POSTROUTING -s "$TUN_SUBNET" -o "$WAN_IF" -j MASQUERADE
    if [[ -n "$TUN_SUBNET6" ]]; then
      ip6t_del_if_exists "" FORWARD -i "$IFNAME" -o "$WAN_IF" -j ACCEPT
      ip6t_del_if_exists "" FORWARD -i "$WAN_IF" -o "$IFNAME" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
      ip6t_del_if_exists nat POSTROUTING -s "$TUN_SUBNET6" -o "$WAN_IF" -j MASQUERADE
    fi

    if [[ "$ENABLE_TCPMSS" == "1" ]]; then
      ipt_del_if_exists mangle FORWARD -i "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      ipt_del_if_exists mangle FORWARD -o "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      if [[ -n "$TUN_SUBNET6" ]]; then
        ip6t_del_if_exists mangle FORWARD -i "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        ip6t_del_if_exists mangle FORWARD -o "$IFNAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      fi
    fi

    tcpdump_stop_if_enabled

    if [[ -n "$TUN_ADDR6" ]]; then
      ip -6 addr del "$TUN_ADDR6" dev "$IFNAME" 2>/dev/null || true
    fi
    ip addr del "$TUN_ADDR" dev "$IFNAME" 2>/dev/null || true
    ;;
  *)
    echo "unknown action: $ACTION" >&2
    exit 2
    ;;
esac
