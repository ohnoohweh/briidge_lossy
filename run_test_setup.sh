#!/usr/bin/env bash
set -euo pipefail

ensure_iptables_rule() {
    local table="$1"
    shift
    if [[ "${table}" == "filter" ]]; then
        if ! iptables -C "$@" 2>/dev/null; then
            iptables -I "$@"
        fi
    else
        if ! iptables -t "${table}" -C "$@" 2>/dev/null; then
            iptables -t "${table}" -I "$@"
        fi
    fi
}

ensure_ip6tables_rule() {
    local table="$1"
    shift
    if [[ "${table}" == "filter" ]]; then
        if ! ip6tables -C "$@" 2>/dev/null; then
            ip6tables -I "$@"
        fi
    else
        if ! ip6tables -t "${table}" -C "$@" 2>/dev/null; then
            ip6tables -t "${table}" -I "$@"
        fi
    fi
}

TUN_IF="${TUN_IF:-obexp0}"
WG_IF="${WG_IF:-wg0}"
TUN_MTU="${TUN_MTU:-1600}"

IPV4_TUN_CIDR="${IPV4_TUN_CIDR:-192.168.105.2/30}"
IPV4_TUN_SUBNET="${IPV4_TUN_SUBNET:-192.168.105.0/30}"
IPV4_TUN_SRC="${IPV4_TUN_SRC:-192.168.105.1}"
IPV4_TEST_DST="${IPV4_TEST_DST:-1.1.1.1}"

IPV6_TUN_CIDR="${IPV6_TUN_CIDR:-fd20:105::2/126}"
IPV6_TUN_SUBNET="${IPV6_TUN_SUBNET:-fd20:105::/126}"
IPV6_TUN_SRC="${IPV6_TUN_SRC:-fd20:105::1}"
IPV6_TEST_DST="${IPV6_TEST_DST:-2606:4700:4700::1111}"

IPV4_RULE_PRIORITY="${IPV4_RULE_PRIORITY:-100}"
IPV6_RULE_PRIORITY="${IPV6_RULE_PRIORITY:-100}"

echo "[setup] configuring ${TUN_IF}"
ip addr replace "${IPV4_TUN_CIDR}" dev "${TUN_IF}"
ip -6 addr replace "${IPV6_TUN_CIDR}" dev "${TUN_IF}"
ip link set "${TUN_IF}" up
ip link set dev "${TUN_IF}" mtu "${TUN_MTU}"

echo "[setup] enabling forwarding"
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

echo "[setup] relaxing rp_filter for experiment"
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w "net.ipv4.conf.${TUN_IF}.rp_filter=0"
sysctl -w "net.ipv4.conf.${WG_IF}.rp_filter=0"

echo "[setup] pinning IPv4 tunnel traffic to WireGuard policy table"
ip rule del priority "${IPV4_RULE_PRIORITY}" 2>/dev/null || true
ip rule add from "${IPV4_TUN_SUBNET}" lookup 52178 priority "${IPV4_RULE_PRIORITY}"

echo "[setup] pinning IPv6 tunnel traffic to WireGuard policy table when available"
ip -6 rule del priority "${IPV6_RULE_PRIORITY}" 2>/dev/null || true
ip -6 rule add from "${IPV6_TUN_SUBNET}" lookup 52178 priority "${IPV6_RULE_PRIORITY}"

echo "[setup] ensuring IPv4 firewall/NAT rules"
ensure_iptables_rule filter FORWARD -i "${TUN_IF}" -o "${WG_IF}" -j ACCEPT
ensure_iptables_rule filter FORWARD -i "${WG_IF}" -o "${TUN_IF}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ensure_iptables_rule nat POSTROUTING -s "${IPV4_TUN_SUBNET}" -o "${WG_IF}" -j MASQUERADE

echo "[setup] ensuring IPv6 firewall/NAT rules"
ensure_ip6tables_rule filter FORWARD -i "${TUN_IF}" -o "${WG_IF}" -j ACCEPT
ensure_ip6tables_rule filter FORWARD -i "${WG_IF}" -o "${TUN_IF}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ensure_ip6tables_rule nat POSTROUTING -s "${IPV6_TUN_SUBNET}" -o "${WG_IF}" -j MASQUERADE

echo "[verify] IPv4 route lookup"
ip route get "${IPV4_TEST_DST}" from "${IPV4_TUN_SRC}" iif "${TUN_IF}"

echo "[verify] IPv6 route lookup"
ip -6 route get "${IPV6_TEST_DST}" from "${IPV6_TUN_SRC}" iif "${TUN_IF}"

echo "[verify] IPv4 NAT counters"
iptables -t nat -vnL POSTROUTING

echo "[verify] IPv6 NAT counters"
ip6tables -t nat -vnL POSTROUTING

echo "[verify] ${TUN_IF} link settings"
ip link show dev "${TUN_IF}"

ACTUAL_TUN_MTU="$(ip -o link show dev "${TUN_IF}" | awk '{for (i=1; i<=NF; i++) if ($i == "mtu") {print $(i+1); exit}}')"
if [[ "${ACTUAL_TUN_MTU}" != "${TUN_MTU}" ]]; then
    echo "[verify] expected ${TUN_IF} mtu ${TUN_MTU}, got ${ACTUAL_TUN_MTU}" >&2
    exit 1
fi
