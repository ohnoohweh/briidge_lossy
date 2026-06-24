#!/usr/bin/env bash
set -euo pipefail

TUN_IF="${TUN_IF:-obexp0}"
WG_IF="${WG_IF:-obtun0}"
UPLINK_IF="${UPLINK_IF:-wlp0s20f3}"
LOG_DIR="${LOG_DIR:-ios/.logs/fedora}"
STAMP="${STAMP:-$(date -u +%Y%m%d-%H%M%S)}"

IPV4_TEST_DST="${IPV4_TEST_DST:-1.1.1.1}"
IPV4_TEST_SRC="${IPV4_TEST_SRC:-192.168.106.1}"
IPV6_TEST_DST="${IPV6_TEST_DST:-2606:4700:4700::1111}"
IPV6_TEST_SRC="${IPV6_TEST_SRC:-fd20:106::1}"

mkdir -p "${LOG_DIR}"

DEBUG_OUT="${LOG_DIR}/fedora-udp-debug-${STAMP}.txt"
IPV6_OUT="${LOG_DIR}/fedora-ipv6-path-${STAMP}.txt"

echo "[log] writing ${DEBUG_OUT}"
python3 -m obstacle_bridge.tools.fedora_udp_tun_debug \
  --tun-if "${TUN_IF}" \
  --uplink-if "${UPLINK_IF}" \
  --output "${DEBUG_OUT}"

echo "[log] writing ${IPV6_OUT}"
{
  echo "# fedora_ipv6_path ${STAMP}"
  echo
  echo "## route_get_v4"
  ip route get "${IPV4_TEST_DST}" from "${IPV4_TEST_SRC}" iif "${TUN_IF}" || true
  echo
  echo "## route_get_v6"
  ip -6 route get "${IPV6_TEST_DST}" from "${IPV6_TEST_SRC}" iif "${TUN_IF}" || true
  echo
  echo "## ip6tables_nat"
  ip6tables -t nat -vnL POSTROUTING || true
  echo
  echo "## ip6tables_forward"
  ip6tables -vnL FORWARD || true
  echo
  echo "## wg_ipv6_addrs"
  ip -6 addr show dev "${WG_IF}" || true
  echo
  echo "## wg_ipv6_routes"
  ip -6 route show dev "${WG_IF}" || true
  echo
  echo "## ping6_via_wg0"
  ping -6 -I "${WG_IF}" -c 3 "${IPV6_TEST_DST}" || true
} > "${IPV6_OUT}"

echo "[log] latest snapshots:"
ls -1t "${LOG_DIR}"/fedora-udp-debug-*.txt "${LOG_DIR}"/fedora-ipv6-path-*.txt 2>/dev/null | head -10
