#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="${LOG_DIR:-ios/.logs/fedora}"
TUN_IF="${TUN_IF:-obexp0}"
TUN_MTU="${TUN_MTU:-${MTU:-1600}}"
mkdir -p "${LOG_DIR}"

echo "[run_test] starting fedora_udp_tun_bridge with mtu=${TUN_MTU}"
if ip link show "${TUN_IF}" >/dev/null 2>&1; then
  echo "[run_test] existing ${TUN_IF} link:"
  ip link show "${TUN_IF}"
fi

DROP_IPV6_ARGS=()
if [[ "${DROP_IPV6:-0}" == "1" ]]; then
  echo "[run_test] IPv6 drop mode enabled"
  DROP_IPV6_ARGS+=(--drop-ipv6)
else
  echo "[run_test] IPv6 forwarding enabled"
fi

exec python3 -m obstacle_bridge.tools.fedora_udp_tun_bridge \
  --ifname "${TUN_IF}" \
  --mtu "${TUN_MTU}" \
  --bind-host "${BIND_HOST:-0.0.0.0}" \
  --bind-port "${BIND_PORT:-5555}" \
  --peer-host "${PEER_HOST:-10.10.0.176}" \
  --peer-port "${PEER_PORT:-5555}" \
  "${DROP_IPV6_ARGS[@]}" \
  --log-jsonl "${LOG_JSONL:-${LOG_DIR}/fedora-udp-tun.jsonl}" \
  --pcap-tun-to-udp "${PCAP_TUN_TO_UDP:-${LOG_DIR}/fedora-tun-to-udp.pcap}" \
  --pcap-udp-to-tun "${PCAP_UDP_TO_TUN:-${LOG_DIR}/fedora-udp-to-tun.pcap}"
