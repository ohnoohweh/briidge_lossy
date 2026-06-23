from pathlib import Path
import argparse

from obstacle_bridge.bridge_tun_routing import auto_overlay_peer_excluded_routes


ROOT = Path(__file__).resolve().parents[2]


def test_auto_overlay_peer_excluded_routes_splits_multi_host_peer_list() -> None:
    cfg = {
        "overlay_transport": "myudp",
        "udp_peer": "38.180.143.5,[2001:ac8:29:60:0:6:0:47]",
        "udp_peer_port": 4433,
        "udp_peer_resolve_family": "prefer-ipv6",
        "udp_bind": "::",
    }

    routes4, routes6 = auto_overlay_peer_excluded_routes(cfg)

    assert "38.180.143.5/32" in routes4
    assert "2001:ac8:29:60:0:6:0:47/128" in routes6


def test_server_tun_hook_supports_optional_tcpdump_capture() -> None:
    script = (ROOT / "scripts" / "server-tun-hook.sh").read_text(encoding="utf-8")

    assert ': "${PEER_ADDR:?missing PEER_ADDR}"' not in script
    assert 'ENABLE_TUN_TCPDUMP="${ENABLE_TUN_TCPDUMP:-0}"' in script
    assert 'TCPDUMP_PCAP_PATH="${TCPDUMP_PCAP_PATH:-/tmp/ObstacleBridge-${IFNAME}.pcap}"' in script
    assert 'TCPDUMP_PIDFILE="${TCPDUMP_PIDFILE:-/tmp/ObstacleBridge-${IFNAME}.tcpdump.pid}"' in script
    assert 'nohup "$TCPDUMP_BIN" -U -ni "$IFNAME" -w "$TCPDUMP_PCAP_PATH"' in script
    assert "tcpdump_start_if_enabled" in script
    assert "tcpdump_stop_if_enabled" in script


def test_client_tun_hook_brings_interface_up_before_underlay_route_is_known() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'ip addr replace "$TUN_ADDR" dev "$IFNAME"' in script
    assert 'if ! detect_underlay; then' in script
    assert 'leaving ${IFNAME} addressed but skipping default-route changes for now' in script
    assert script.index('ip addr replace "$TUN_ADDR" dev "$IFNAME"') < script.index('if ! detect_underlay; then')


def test_client_tun_hook_preserves_saved_underlay_default_across_repeated_up() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'current_default="$(ip route show default | head -n1 || true)"' in script
    assert '"$current_default" != *" dev ${IFNAME}"*' in script
    assert 'current_default6="$(ip -6 route show default | head -n1 || true)"' in script
    assert '"$current_default6" != *" dev ${IFNAME}"*' in script


def test_client_tun_hook_normalizes_ipv4_mapped_ipv6_peer_for_route_programming() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'normalize_overlay_peer_ip() {' in script
    assert '^::ffff:([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$' in script
    assert 'normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"' in script
    assert 'printf \x27%s/32\x27 "$normalized_ip"' in script or "printf '%s/32' \"$normalized_ip\"" in script


def test_client_tun_hook_supports_excluded_route_programming() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'EXCLUDED_ROUTES="${EXCLUDED_ROUTES:-}"' in script
    assert 'EXCLUDED_ROUTES6="${EXCLUDED_ROUTES6:-}"' in script
    assert 'excluded_route_should_use_loopback4() {' in script
    assert 'excluded_route_should_use_loopback6() {' in script
    assert '127.0.0.0/8|127.0.0.1/32|127.0.0.1)' in script
    assert '::1/128|::1)' in script
    assert 'add_excluded_routes4() {' in script
    assert 'add_excluded_routes6() {' in script
    assert 'STATE_UNDERLAY4="${STATE_DIR}/${IFNAME}.underlay-route4"' in script
    assert 'STATE_UNDERLAY6="${STATE_DIR}/${IFNAME}.underlay-route6"' in script
    assert 'printf \'%s\\n\' "$route_line" > "$state_file"' in script or "printf '%s\\n' \"$route_line\" > \"$state_file\"" in script
    assert 'rm -f "$stale_state_file"' in script
    assert 'done < <(_load_saved_route_parts "$STATE_UNDERLAY4" "ip route show default")' in script
    assert 'done < <(_load_saved_route_parts "$STATE_UNDERLAY6" "ip -6 route show default")' in script
    assert 'skip explicit loopback route install for ${route_spec}; kernel loopback routes already cover it' in script
    assert 'skip explicit IPv6 loopback route install for ${route_spec}; kernel loopback routes already cover it' in script
    assert 'ip route replace "$route_spec" via "$gw" dev "$dev" src "$src"' in script
    assert 'delete_excluded_routes4() {' in script
    assert 'delete_excluded_routes6() {' in script
    assert 'protect_underlay_routes6() {' in script
    assert 'delete_protected_routes6() {' in script
    assert 'ip -6 route replace "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF" src "$overlay_src"' in script
    assert 'ip -6 route del "$(overlay_route_prefix)" via "$saved_gw" dev "$saved_dev" src "$saved_src"' in script
    assert 'protected_routes+=("$link_route")' not in script
    assert 'protected_routes+=("${src}/32")' not in script
    assert 'protected_routes+=("${gw}/32")' not in script
    assert 'protected_routes+=("${src}/128")' not in script
    assert 'protected_routes+=("${gw}/128")' not in script


def test_client_tun_hook_waits_for_interface_and_uses_onlink_default_routes() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'wait_for_interface() {' in script
    assert 'log_route_snapshot() {' in script
    assert 'log_diag() {' in script
    assert 'ip link show dev "$IFNAME"' in script
    assert 'wait_for_interface' in script
    assert 'stage=${stage} default4=' in script
    assert 'stage=${stage} overlay_route=' in script
    assert 'overlay_peer_is_ipv6() {' in script
    assert 'ip route replace "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF" src "$overlay_src"' in script
    assert 'add_included_routes4() {' in script
    assert 'add_included_routes6() {' in script
    assert 'delete_included_routes4() {' in script
    assert 'delete_included_routes6() {' in script
    assert 'is_full_tunnel_route4() {' in script
    assert 'is_full_tunnel_route6() {' in script
    assert 'ip route replace "$route_spec" via "$TUN_GW" dev "$IFNAME" onlink' in script
    assert 'ip -6 route replace "$route_spec" via "$TUN_GW6" dev "$IFNAME" metric 1 onlink' in script
    assert 'ip -6 route replace "$route_spec" via "$TUN_GW6" dev "$IFNAME" metric 1 onlink' in script
    assert 'add_included_routes4 || true' in script
    assert 'add_included_routes6 || true' in script
    assert ': > "$STATE_PROTECTED4"' in script
    assert ': > "$STATE_PROTECTED6"' in script


def test_client_tun_hook_uses_dedicated_policy_table_for_full_tunnel_linux() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'STATE_POLICY4="${STATE_DIR}/${IFNAME}.policy-rules4"' in script
    assert 'STATE_POLICY6="${STATE_DIR}/${IFNAME}.policy-rules6"' in script
    assert 'POLICY_TABLE4="${OB_POLICY_TABLE4:-52190}"' in script
    assert 'POLICY_TABLE6="${OB_POLICY_TABLE6:-52191}"' in script
    assert 'configure_policy_full_tunnel4() {' in script
    assert 'configure_policy_full_tunnel6() {' in script
    assert 'ip route replace table "$policy_table" default via "$TUN_GW" dev "$IFNAME" onlink' in script
    assert 'ip -6 route replace table "$policy_table" default via "$TUN_GW6" dev "$IFNAME" metric 1 onlink' in script
    assert 'policy_rule_add4 "$policy_pref" to 0.0.0.0/0 lookup "$policy_table"' in script
    assert 'policy_rule_add6 "$policy_pref" to ::/0 lookup "$policy_table"' in script
    assert 'connected_underlay_routes4() {' in script
    assert 'connected_underlay_routes6() {' in script
    assert 'connected_tun_routes4() {' in script
    assert 'connected_tun_routes6() {' in script
    assert 'policy_rule_add4 "$policy_pref" to "$route_spec" lookup main' in script
    assert 'policy_rule_add6 "$policy_pref" to "$route_spec" lookup main' in script
    assert 'delete_policy_rules4' in script
    assert 'delete_policy_rules6' in script


def test_macos_client_tun_hook_configures_point_to_point_utun_and_default_route() -> None:
    script = (ROOT / "scripts" / "client-tun-hook-macos.sh").read_text(encoding="utf-8")

    assert 'export PATH="/usr/sbin:/sbin:/usr/bin:/bin:${PATH:-}"' in script
    assert 'route_get_compact_v4() {' in script
    assert 'route_get_compact_v6() {' in script
    assert 'log_route_snapshot() {' in script
    assert 'debug_diag_enabled() {' in script
    assert 'log_debug() {' in script
    assert 'network_service_for_device() {' in script
    assert 'save_dns_state() {' in script
    assert 'apply_dns_servers() {' in script
    assert 'restore_dns_state() {' in script
    assert 'EXCLUDED_ROUTES="${EXCLUDED_ROUTES:-127.0.0.0/8}"' in script
    assert 'EXCLUDED_ROUTES6="${EXCLUDED_ROUTES6:-::1/128}"' in script
    assert 'ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$TUN_GW" netmask "$(ipv4_prefix_to_netmask "$TUN_ADDR_PREFIX")" up' in script
    assert 'route -n get default' in script
    assert 'netstat -rn -f inet' in script
    assert 'netstat -rn -f inet6' in script
    assert 'route -n add default -interface "$IFNAME"' in script
    assert 'default_matches_v4() {' in script
    assert 'expand_included_routes_v4() {' in script
    assert '"0.0.0.0/0"|"default")' in script
    assert 'printf \'%s\\n\' "0.0.0.0/1"' in script
    assert 'printf \'%s\\n\' "128.0.0.0/1"' in script
    assert 'route_spec_probe_host_v4() {' in script
    assert 'route -n get "$probe"' in script
    assert 'failed to install IPv4 split full-tunnel routes via $IFNAME; keeping underlay defaults' in script
    assert 'expand_included_routes_v6() {' in script
    assert 'full_tunnel_v6_matches() {' in script
    assert 'case "$route_spec" in' in script
    assert '"::/0"|"default"|"::0/0")' in script
    assert 'printf \'%s\\n\' "::/1"' in script
    assert 'printf \'%s\\n\' "8000::/1"' in script
    assert 'route -n delete default -interface "$IFNAME"' in script
    assert 'delete_included_routes_v6' in script
    assert 'add_excluded_routes_v4() {' in script
    assert 'add_excluded_routes_v6() {' in script
    assert 'delete_excluded_routes_v4() {' in script
    assert 'delete_excluded_routes_v6() {' in script
    assert 'snapshot_excluded_routes_v4() {' in script
    assert 'snapshot_excluded_routes_v6() {' in script
    assert 'route_add_or_change_v4() {' in script
    assert 'route_add_or_change_v6() {' in script
    assert 'overlay_peer_route_matches_underlay_v4() {' in script
    assert 'enforce_overlay_peer_underlay_v4() {' in script
    assert 'is_ipv4_mapped_host_route_v6() {' in script
    assert 'route_spec_addr "$route_spec")" =~ ^::ffff:' in script
    assert 'is_ipv4_mapped_host_route_v6 "$route_spec"' in script
    assert 'ifname="$OVERLAY_UNDERLAY_IF"' in script
    assert 'route_delete_v4() {' in script
    assert 'route_delete_v6() {' in script
    assert 'is_host_route_v4() {' in script
    assert 'is_host_route_v6() {' in script
    assert 'route_kind="-host"' in script
    assert 'route_target="$(route_spec_addr "$route_spec")"' in script
    assert 'local fallback_gw="${1:-}"' in script
    assert 'if [[ -z "$gateway" && -z "$ifname" && -n "$fallback_gw" ]] && is_host_route_v4 "$route_spec"; then' in script
    assert 'if [[ -z "$underlay_gw" && -z "$underlay_if" ]] && is_host_route_v4 "$route_spec"; then' in script
    assert "while IFS='|' read -r route_spec _underlay_gw _underlay_if; do" in script
    assert 'route -n get -inet6 "$probe"' in script
    assert "while IFS='|' read -r route_spec underlay_gw underlay_if; do" in script
    assert 'add_excluded_routes_v4' in script
    assert 'add_excluded_routes_v6' in script
    assert 'normalize_overlay_peer_ip() {' in script
    assert 'detect_underlay_if() {' in script
    assert 'OVERLAY_UNDERLAY_GW="${OB_OVERLAY_UNDERLAY_GW:-}"' in script
    assert 'OVERLAY_UNDERLAY_IF="${OB_OVERLAY_UNDERLAY_IF:-}"' in script
    assert 'if [[ -n "$OVERLAY_UNDERLAY_GW" ]]; then' in script
    assert 'if [[ -n "$OVERLAY_UNDERLAY_IF" ]]; then' in script
    assert 'cleanup_stale_managed_routes() {' in script
    assert 'delete_included_routes_v4_from_file() {' in script
    assert 'delete_included_routes_v6_from_file() {' in script
    assert 'delete_excluded_routes_v4_from_file() {' in script
    assert 'delete_excluded_routes_v6_from_file() {' in script
    assert 'for file in "$STATE_DIR"/*.routes4; do' in script
    assert 'for file in "$STATE_DIR"/*.routes6; do' in script
    assert 'fallback_underlay_gw_v4() {' in script
    assert 'fallback_underlay_if_v4() {' in script
    assert 'netstat_default_gateway_v4() {' in script
    assert 'netstat_default_interface_v4() {' in script
    assert 'wait_for_underlay_v4() {' in script
    assert 'netstat -rn -f inet 2>/dev/null | awk -v ifname="$IFNAME"' in script
    assert 'wait_for_underlay_v4 || true' in script
    assert 'cleanup_stale_managed_routes' in script
    assert 'underlay detected peer=${OVERLAY_PEER_IP:-<none>}' in script
    assert 'STATE_DNS_SERVICE="${STATE_DIR}/${IFNAME}.dns-service"' in script
    assert 'STATE_DNS_SERVERS="${STATE_DIR}/${IFNAME}.dns-servers"' in script
    assert 'networksetup -listnetworkserviceorder' in script
    assert 'networksetup -getdnsservers "$service_name"' in script
    assert "printf 'EMPTY\\n' > \"$STATE_DNS_SERVERS\"" in script
    assert 'networksetup -setdnsservers "$service_name" "${dns_servers[@]}"' in script
    assert 'networksetup -setdnsservers "$service_name" Empty' in script
    assert 'underlay_service_name="$(network_service_for_device "$local_underlay_if" || true)"' in script
    assert 'save_dns_state "$underlay_service_name"' in script
    assert 'apply_dns_servers "$underlay_service_name" "${dns_servers[@]}"' in script
    assert 'restore_dns_state' in script
    assert 'rm -f "$STATE_DNS_SERVICE" "$STATE_DNS_SERVERS"' in script
    assert 'log_route_snapshot "after-ifconfig"' in script
    assert 'log_route_snapshot "after-overlay-peer-protect"' in script
    assert 'log_route_snapshot "after-route-install"' in script
    assert 'log_route_snapshot "after-ipv4-revert"' in script
    assert 'log_route_snapshot "after-full-tunnel-v4-failed"' in script
    assert 'log_route_snapshot "after-full-tunnel-v6-failed"' in script
    assert 'log_route_snapshot "final-up"' in script
    assert 'log_route_snapshot "before-down"' in script
    assert 'log_route_snapshot "after-down"' in script
    assert 'route-snapshot stage=${stage} peer4=${peer4} peer6=${peer6} internet4=${internet4} internet6=${internet6} tun_gw4=${tunnel4} tun_gw6=${tunnel6}' in script
    assert 'route_matches_underlay_v4 "${normalized_ip}/32" "$expected_gw" "$expected_if"' in script
    assert 'log_debug "overlay peer route preserved peer=${normalized_ip} gw=${expected_gw:-<none>} if=${expected_if:-<none>} attempt=${attempt}"' in script
    assert 'log "warning: overlay peer route fell out of underlay peer=${normalized_ip} gw=${expected_gw:-<none>} if=${expected_if:-<none>}"' in script
    assert 'if ! enforce_overlay_peer_underlay_v4 "$local_underlay_gw" "$local_underlay_if"; then' in script
    assert 'log "failed to preserve IPv4 overlay peer route; reverting IPv4 full-tunnel route install on $IFNAME"' in script
    assert 'enforce_overlay_peer_underlay_v4 "$local_underlay_gw" "$local_underlay_if" || true' in script
    up_block = script[script.index('  up)') : script.index('  down)')]
    assert up_block.index('add_excluded_routes_v4 "$local_underlay_gw" "$local_underlay_if"') < up_block.index('add_included_routes_v4')
    assert 'route_add_or_change_v4 "${normalized_overlay_peer_ip}/32" "$local_underlay_gw" "$local_underlay_if"' in script
    assert 'add_excluded_routes_v4' in script
    assert 'add_excluded_routes_v6' in script


def test_macos_server_tun_hook_brings_utun_up_with_peer_identity() -> None:
    script = (ROOT / "scripts" / "server-tun-hook-macos.sh").read_text(encoding="utf-8")

    assert 'ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$PEER_ADDR" up' in script
    assert 'ifconfig "$IFNAME" down' in script
