#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/sbin:/sbin:/usr/bin:/bin:${PATH:-}"

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${TUN_GW:?missing TUN_GW}"
TUN_ADDR6="${TUN_ADDR6:-}"
TUN_GW6="${TUN_GW6:-}"
INCLUDED_ROUTES="${INCLUDED_ROUTES:-0.0.0.0/0}"
EXCLUDED_ROUTES="${EXCLUDED_ROUTES:-127.0.0.0/8}"
INCLUDED_ROUTES6="${INCLUDED_ROUTES6:-::/0}"
EXCLUDED_ROUTES6="${EXCLUDED_ROUTES6:-::1/128}"
OVERLAY_PEER_IP="${OVERLAY_PEER_IP:-${OB_OVERLAY_PEER_HOST:-}}"
OVERLAY_UNDERLAY_GW="${OB_OVERLAY_UNDERLAY_GW:-}"
OVERLAY_UNDERLAY_IF="${OB_OVERLAY_UNDERLAY_IF:-}"

STATE_DIR="/tmp/obbridge"
STATE_FILE="${STATE_DIR}/${IFNAME}.default-route"
STATE_FILE6="${STATE_DIR}/${IFNAME}.default-route6"
STATE_ROUTES4="${STATE_DIR}/${IFNAME}.routes4"
STATE_ROUTES6="${STATE_DIR}/${IFNAME}.routes6"
STATE_EXCLUDED4="${STATE_DIR}/${IFNAME}.excluded4"
STATE_EXCLUDED6="${STATE_DIR}/${IFNAME}.excluded6"
STATE_DNS_SERVICE="${STATE_DIR}/${IFNAME}.dns-service"
STATE_DNS_SERVERS="${STATE_DIR}/${IFNAME}.dns-servers"

mkdir -p "$STATE_DIR"

TUN_ADDR_IP="${TUN_ADDR%%/*}"
TUN_ADDR_PREFIX="${TUN_ADDR##*/}"
TUN_ADDR6_IP="${TUN_ADDR6%%/*}"
TUN_ADDR6_PREFIX="${TUN_ADDR6##*/}"

log() {
  printf '[client-tun-hook-macos] %s\n' "$*" >&2
}

debug_diag_enabled() {
  [[ "${OB_TUN_HOOK_DEBUG:-0}" == "1" ]]
}

log_debug() {
  if debug_diag_enabled; then
    log "$*"
  fi
}

network_service_for_device() {
  local device="$1"
  networksetup -listnetworkserviceorder 2>/dev/null | awk -v dev="$device" '
    /^\([0-9]+\)/ {
      service = $0
      sub(/^\([0-9]+\)[[:space:]]*/, "", service)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", service)
      next
    }
    /Device:/ {
      current = $0
      sub(/^.*Device:[[:space:]]*/, "", current)
      sub(/\).*$/, "", current)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", current)
      if (current == dev && service != "") {
        print service
        exit
      }
    }'
}

save_dns_state() {
  local service_name="$1"
  rm -f "$STATE_DNS_SERVICE" "$STATE_DNS_SERVERS"
  [[ -n "$service_name" ]] || return 0
  printf '%s\n' "$service_name" > "$STATE_DNS_SERVICE"
  local output
  output="$(networksetup -getdnsservers "$service_name" 2>&1 || true)"
  if grep -q "There aren't any DNS Servers set" <<<"$output"; then
    printf 'EMPTY\n' > "$STATE_DNS_SERVERS"
    return 0
  fi
  if [[ -n "$(printf '%s\n' "$output" | sed '/^[[:space:]]*$/d')" ]]; then
    printf '%s\n' "$output" | sed '/^[[:space:]]*$/d' > "$STATE_DNS_SERVERS"
  else
    printf 'EMPTY\n' > "$STATE_DNS_SERVERS"
  fi
}

apply_dns_servers() {
  local service_name="$1"
  shift || true
  local dns_servers=("$@")
  [[ -n "$service_name" ]] || return 0
  if [[ ${#dns_servers[@]} -eq 0 ]]; then
    log "skip dns apply: no DNS servers configured for service=${service_name}"
    return 0
  fi
  networksetup -setdnsservers "$service_name" "${dns_servers[@]}" >/dev/null
  log "applied dns service=${service_name} servers=${dns_servers[*]}"
}

restore_dns_state() {
  [[ -s "$STATE_DNS_SERVICE" ]] || return 0
  local service_name
  service_name="$(head -n1 "$STATE_DNS_SERVICE" 2>/dev/null || true)"
  [[ -n "$service_name" ]] || return 0
  if [[ ! -s "$STATE_DNS_SERVERS" ]]; then
    networksetup -setdnsservers "$service_name" Empty >/dev/null || true
    log "restored dns service=${service_name} servers=Empty"
    return 0
  fi
  local first_line
  first_line="$(head -n1 "$STATE_DNS_SERVERS" 2>/dev/null || true)"
  if [[ "$first_line" == "EMPTY" ]]; then
    networksetup -setdnsservers "$service_name" Empty >/dev/null || true
    log "restored dns service=${service_name} servers=Empty"
    return 0
  fi
  mapfile -t dns_servers < "$STATE_DNS_SERVERS"
  if [[ ${#dns_servers[@]} -gt 0 ]]; then
    networksetup -setdnsservers "$service_name" "${dns_servers[@]}" >/dev/null || true
    log "restored dns service=${service_name} servers=${dns_servers[*]}"
  fi
}

route_get_compact_v4() {
  local host="$1"
  route -n get "$host" 2>/dev/null | awk '
    /destination:/{dest=$2}
    /mask:/{mask=$2}
    /gateway:/{gw=$2}
    /interface:/{iface=$2}
    END{
      if (dest != "" || gw != "" || iface != "") {
        printf "host=%s dest=%s mask=%s gw=%s if=%s", "'"$host"'", dest, mask, gw, iface
      }
    }'
}

route_get_compact_v6() {
  local host="$1"
  route -n get -inet6 "$host" 2>/dev/null | awk '
    /destination:/{dest=$2}
    /mask:/{mask=$2}
    /gateway:/{gw=$2}
    /interface:/{iface=$2}
    END{
      if (dest != "" || gw != "" || iface != "") {
        printf "host=%s dest=%s mask=%s gw=%s if=%s", "'"$host"'", dest, mask, gw, iface
      }
    }'
}

log_route_snapshot() {
  local stage="$1"
  local normalized_overlay_peer_ip
  normalized_overlay_peer_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  local peer4="<none>"
  local peer6="<none>"
  local internet4="<none>"
  local internet6="<none>"
  local tunnel4="<none>"
  local tunnel6="<none>"
  if [[ -n "$normalized_overlay_peer_ip" && "$normalized_overlay_peer_ip" == *.* && "$normalized_overlay_peer_ip" != *:* ]]; then
    peer4="$(route_get_compact_v4 "$normalized_overlay_peer_ip" || true)"
  fi
  if [[ -n "${TUN_GW:-}" ]]; then
    tunnel4="$(route_get_compact_v4 "$TUN_GW" || true)"
  fi
  if [[ -n "${TUN_GW6:-}" ]]; then
    tunnel6="$(route_get_compact_v6 "$TUN_GW6" || true)"
  fi
  if csv_to_lines "$INCLUDED_ROUTES" | grep -qxE '(0\.0\.0\.0/0|default)'; then
    internet4="$(route_get_compact_v4 "142.251.20.94" || true)"
  fi
  if csv_to_lines "$INCLUDED_ROUTES6" | grep -qxE '(::/0|default|::0/0)'; then
    internet6="$(route_get_compact_v6 "2a03:2880:f126:83:face:b00c:0:25de" || true)"
  fi
  if csv_to_lines "$EXCLUDED_ROUTES6" | grep -q '2001:ac8:29:60:0:6:0:47/128'; then
    peer6="$(route_get_compact_v6 "2001:ac8:29:60:0:6:0:47" || true)"
  fi
  log_debug "route-snapshot stage=${stage} peer4=${peer4} peer6=${peer6} internet4=${internet4} internet6=${internet6} tun_gw4=${tunnel4} tun_gw6=${tunnel6}"
}

normalize_overlay_peer_ip() {
  local candidate="$1"
  if [[ "$candidate" =~ ^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  printf '%s' "$candidate"
}

current_default_gateway_v4() {
  route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}'
}

current_default_interface_v4() {
  route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'
}

netstat_default_gateway_v4() {
  netstat -rn -f inet 2>/dev/null | awk -v ifname="$IFNAME" '$1=="default" && $4!=ifname {print $2; exit}'
}

netstat_default_interface_v4() {
  netstat -rn -f inet 2>/dev/null | awk -v ifname="$IFNAME" '$1=="default" && $4!=ifname {print $4; exit}'
}

current_default_gateway_v6() {
  route -n get -inet6 default 2>/dev/null | awk '/gateway:/{print $2; exit}'
}

current_default_interface_v6() {
  route -n get -inet6 default 2>/dev/null | awk '/interface:/{print $2; exit}'
}

has_route_v6_on_if() {
  local route_spec="$1"
  netstat -rn -f inet6 2>/dev/null | awk -v route="$route_spec" -v ifname="$IFNAME" '$1==route && $4==ifname {found=1} END{exit(found?0:1)}'
}

has_default_route_v4_on_if() {
  netstat -rn -f inet 2>/dev/null | awk -v ifname="$IFNAME" '$1=="default" && $4==ifname {found=1} END{exit(found?0:1)}'
}

has_default_route_v4_via_gw() {
  local expected_gw="$1"
  netstat -rn -f inet 2>/dev/null | awk -v gw="$expected_gw" '$1=="default" && $2==gw {found=1} END{exit(found?0:1)}'
}

has_default_route_v6_on_if() {
  netstat -rn -f inet6 2>/dev/null | awk -v ifname="$IFNAME" '$1=="default" && $4==ifname {found=1} END{exit(found?0:1)}'
}

has_default_route_v6_via_gw() {
  local expected_gw="$1"
  netstat -rn -f inet6 2>/dev/null | awk -v gw="$expected_gw" '$1=="default" && $2==gw {found=1} END{exit(found?0:1)}'
}

wait_for_default_gateway_v4() {
  local expected_gw="$1"
  local attempts="${2:-10}"
  local delay="${3:-0.2}"
  local i
  for ((i=0; i<attempts; i++)); do
    if default_matches_v4 "$expected_gw"; then
      return 0
    fi
    sleep "$delay"
  done
  default_matches_v4 "$expected_gw"
}

wait_for_full_tunnel_v4_routes() {
  local attempts="${1:-10}"
  local delay="${2:-0.2}"
  local i
  for ((i=0; i<attempts; i++)); do
    if full_tunnel_v4_matches; then
      return 0
    fi
    sleep "$delay"
  done
  full_tunnel_v4_matches
}

wait_for_full_tunnel_v6_routes() {
  local attempts="${1:-10}"
  local delay="${2:-0.2}"
  local i
  for ((i=0; i<attempts; i++)); do
    if full_tunnel_v6_matches; then
      return 0
    fi
    sleep "$delay"
  done
  full_tunnel_v6_matches
}

ipv4_prefix_to_netmask() {
  local prefix="$1"
  local remaining=$prefix
  local octets=()
  local value
  local index
  for index in 0 1 2 3; do
    if (( remaining >= 8 )); then
      value=255
      remaining=$((remaining - 8))
    elif (( remaining > 0 )); then
      value=$((256 - (1 << (8 - remaining))))
      remaining=0
    else
      value=0
    fi
    octets+=("$value")
  done
  printf '%s.%s.%s.%s' "${octets[0]}" "${octets[1]}" "${octets[2]}" "${octets[3]}"
}

csv_to_lines() {
  tr ',' '\n' <<<"${1:-}" | sed '/^[[:space:]]*$/d'
}

route_spec_probe_host() {
  local route_spec="$1"
  printf '%s' "${route_spec%%/*}"
}

route_spec_addr() {
  local route_spec="$1"
  printf '%s' "${route_spec%%/*}"
}

is_host_route_v4() {
  local route_spec="$1"
  [[ "$route_spec" == */32 ]]
}

is_host_route_v6() {
  local route_spec="$1"
  [[ "$route_spec" == */128 ]]
}

route_spec_probe_host_v4() {
  local route_spec="$1"
  case "$route_spec" in
    "0.0.0.0/1")
      printf '%s' "1.1.1.1"
      ;;
    "128.0.0.0/1")
      printf '%s' "142.251.20.94"
      ;;
    *)
      route_spec_probe_host "$route_spec"
      ;;
  esac
}

expand_included_routes_v4() {
  local route_spec
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    case "$route_spec" in
      "0.0.0.0/0"|"default")
        printf '%s\n' "0.0.0.0/1"
        printf '%s\n' "128.0.0.0/1"
        ;;
      *)
        printf '%s\n' "$route_spec"
        ;;
    esac
  done < <(csv_to_lines "$INCLUDED_ROUTES")
}

expand_included_routes_v6() {
  local route_spec
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    case "$route_spec" in
      "::/0"|"default"|"::0/0")
        printf '%s\n' "::/1"
        printf '%s\n' "8000::/1"
        ;;
      *)
        printf '%s\n' "$route_spec"
        ;;
    esac
  done < <(csv_to_lines "$INCLUDED_ROUTES6")
}

should_switch_default_v4() {
  csv_to_lines "$INCLUDED_ROUTES" | grep -qxE '(0\.0\.0\.0/0|default)'
}

should_switch_default_v6() {
  csv_to_lines "$INCLUDED_ROUTES6" | grep -qxE '(::/0|default|::0/0)'
}

default_matches_v4() {
  local expected_gw="$1"
  local current_if current_gw
  current_if="$(current_default_interface_v4 || true)"
  current_gw="$(current_default_gateway_v4 || true)"
  [[ "$current_if" == "$IFNAME" || "$current_gw" == "$expected_gw" ]] || \
    has_default_route_v4_on_if || has_default_route_v4_via_gw "$expected_gw"
}

has_route_v4_on_if() {
  local route_spec="$1"
  local probe current_if
  probe="$(route_spec_probe_host_v4 "$route_spec")"
  current_if="$(route -n get "$probe" 2>/dev/null | awk '/interface:/{print $2; exit}')"
  [[ "$current_if" == "$IFNAME" ]]
}

full_tunnel_v4_matches() {
  local route_spec
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if ! has_route_v4_on_if "$route_spec"; then
      return 1
    fi
  done < <(expand_included_routes_v4)
  return 0
}

full_tunnel_v6_matches() {
  local route_spec
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if ! has_route_v6_on_if "$route_spec"; then
      return 1
    fi
  done < <(expand_included_routes_v6)
  return 0
}

route_add_or_change_v4() {
  local route_spec="$1"
  local gateway="$2"
  local ifname="${3:-}"
  local route_kind="-net"
  local route_target="$route_spec"
  if is_host_route_v4 "$route_spec"; then
    route_kind="-host"
    route_target="$(route_spec_addr "$route_spec")"
  fi
  if [[ -n "$gateway" ]]; then
    route -n add "$route_kind" "$route_target" "$gateway" >/dev/null 2>&1 || \
      route -n change "$route_kind" "$route_target" "$gateway" >/dev/null 2>&1 || \
      { route -n delete "$route_kind" "$route_target" >/dev/null 2>&1 || true; route -n add "$route_kind" "$route_target" "$gateway" >/dev/null 2>&1 || true; }
  elif [[ -n "$ifname" ]]; then
    route -n add "$route_kind" "$route_target" -interface "$ifname" >/dev/null 2>&1 || \
      route -n change "$route_kind" "$route_target" -interface "$ifname" >/dev/null 2>&1 || \
      { route -n delete "$route_kind" "$route_target" >/dev/null 2>&1 || true; route -n add "$route_kind" "$route_target" -interface "$ifname" >/dev/null 2>&1 || true; }
  fi
}

route_add_or_change_v6() {
  local route_spec="$1"
  local gateway="$2"
  local ifname="${3:-}"
  local route_kind="-net"
  local route_target="$route_spec"
  if is_host_route_v6 "$route_spec"; then
    route_kind="-host"
    route_target="$(route_spec_addr "$route_spec")"
  fi
  if [[ -n "$gateway" ]]; then
    route -n add -inet6 "$route_kind" "$route_target" "$gateway" >/dev/null 2>&1 || \
      route -n change -inet6 "$route_kind" "$route_target" "$gateway" >/dev/null 2>&1 || \
      { route -n delete -inet6 "$route_kind" "$route_target" >/dev/null 2>&1 || true; route -n add -inet6 "$route_kind" "$route_target" "$gateway" >/dev/null 2>&1 || true; }
  elif [[ -n "$ifname" ]]; then
    route -n add -inet6 "$route_kind" "$route_target" -interface "$ifname" >/dev/null 2>&1 || \
      route -n change -inet6 "$route_kind" "$route_target" -interface "$ifname" >/dev/null 2>&1 || \
      { route -n delete -inet6 "$route_kind" "$route_target" >/dev/null 2>&1 || true; route -n add -inet6 "$route_kind" "$route_target" -interface "$ifname" >/dev/null 2>&1 || true; }
  fi
}

route_delete_v4() {
  local route_spec="$1"
  local route_kind="-net"
  local route_target="$route_spec"
  if is_host_route_v4 "$route_spec"; then
    route_kind="-host"
    route_target="$(route_spec_addr "$route_spec")"
  fi
  route -n delete "$route_kind" "$route_target" >/dev/null 2>&1 || true
}

route_delete_v6() {
  local route_spec="$1"
  local route_kind="-net"
  local route_target="$route_spec"
  if is_host_route_v6 "$route_spec"; then
    route_kind="-host"
    route_target="$(route_spec_addr "$route_spec")"
  fi
  route -n delete -inet6 "$route_kind" "$route_target" >/dev/null 2>&1 || true
}

install_tunnel_local_routes() {
  local subnet4="${TUN_SUBNET:-}"
  local subnet6="${TUN_SUBNET6:-}"

  route_add_or_change_v4 "${TUN_ADDR_IP}/32" "" "$IFNAME"
  route_add_or_change_v4 "${TUN_GW}/32" "" "$IFNAME"
  if [[ -n "$subnet4" ]]; then
    route_add_or_change_v4 "$subnet4" "" "$IFNAME"
  fi

  if [[ -n "$TUN_ADDR6_IP" ]]; then
    route_add_or_change_v6 "${TUN_ADDR6_IP}/128" "" "$IFNAME"
  fi
  if [[ -n "$TUN_GW6" ]]; then
    route_add_or_change_v6 "${TUN_GW6}/128" "" "$IFNAME"
  fi
  if [[ -n "$subnet6" ]]; then
    route_add_or_change_v6 "$subnet6" "" "$IFNAME"
  fi
}

remove_tunnel_local_routes() {
  local subnet4="${TUN_SUBNET:-}"
  local subnet6="${TUN_SUBNET6:-}"

  route_delete_v4 "${TUN_ADDR_IP}/32"
  route_delete_v4 "${TUN_GW}/32"
  if [[ -n "$subnet4" ]]; then
    route_delete_v4 "$subnet4"
  fi

  if [[ -n "$TUN_ADDR6_IP" ]]; then
    route_delete_v6 "${TUN_ADDR6_IP}/128"
  fi
  if [[ -n "$TUN_GW6" ]]; then
    route_delete_v6 "${TUN_GW6}/128"
  fi
  if [[ -n "$subnet6" ]]; then
    route_delete_v6 "$subnet6"
  fi
}

route_matches_underlay_v4() {
  local route_spec="$1"
  local expected_gw="$2"
  local expected_if="${3:-}"
  local probe current_gw current_if
  probe="$(route_spec_probe_host "$route_spec")"
  current_gw="$(route -n get "$probe" 2>/dev/null | awk '/gateway:/{print $2; exit}')"
  current_if="$(route -n get "$probe" 2>/dev/null | awk '/interface:/{print $2; exit}')"
  [[ -n "$expected_gw" && "$current_gw" == "$expected_gw" ]] || \
    [[ -n "$expected_if" && "$current_if" == "$expected_if" ]]
}

overlay_peer_route_matches_underlay_v4() {
  local expected_gw="$1"
  local expected_if="${2:-}"
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  [[ -n "$normalized_ip" ]] || return 0
  [[ "$normalized_ip" == *.* && "$normalized_ip" != *:* ]] || return 0
  route_matches_underlay_v4 "${normalized_ip}/32" "$expected_gw" "$expected_if"
}

route_matches_underlay_v6() {
  local route_spec="$1"
  local expected_gw="$2"
  local expected_if="${3:-}"
  local probe current_gw current_if
  probe="$(route_spec_probe_host "$route_spec")"
  current_gw="$(route -n get -inet6 "$probe" 2>/dev/null | awk '/gateway:/{print $2; exit}')"
  current_if="$(route -n get -inet6 "$probe" 2>/dev/null | awk '/interface:/{print $2; exit}')"
  [[ -n "$expected_gw" && "$current_gw" == "$expected_gw" ]] || \
    [[ -n "$expected_if" && "$current_if" == "$expected_if" ]]
}

enforce_overlay_peer_underlay_v4() {
  local expected_gw="$1"
  local expected_if="${2:-}"
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  [[ -n "$normalized_ip" ]] || return 0
  [[ "$normalized_ip" == *.* && "$normalized_ip" != *:* ]] || return 0
  local route_spec="${normalized_ip}/32"
  local attempt
  for attempt in 1 2 3; do
    route_add_or_change_v4 "$route_spec" "$expected_gw" "$expected_if"
    if overlay_peer_route_matches_underlay_v4 "$expected_gw" "$expected_if"; then
      log_debug "overlay peer route preserved peer=${normalized_ip} gw=${expected_gw:-<none>} if=${expected_if:-<none>} attempt=${attempt}"
      return 0
    fi
    sleep 0.2
  done
  log "warning: overlay peer route fell out of underlay peer=${normalized_ip} gw=${expected_gw:-<none>} if=${expected_if:-<none>}"
  return 1
}

add_included_routes_v4() {
  : > "$STATE_ROUTES4"
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    route -n add -net "$route_spec" -interface "$IFNAME" >/dev/null 2>&1 || \
      route -n change -net "$route_spec" -interface "$IFNAME" >/dev/null 2>&1 || true
    printf '%s\n' "$route_spec" >> "$STATE_ROUTES4"
  done < <(expand_included_routes_v4)
}

add_included_routes_v6() {
  : > "$STATE_ROUTES6"
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    route -n add -inet6 "$route_spec" -interface "$IFNAME" >/dev/null 2>&1 || \
      route -n change -inet6 "$route_spec" -interface "$IFNAME" >/dev/null 2>&1 || true
    printf '%s\n' "$route_spec" >> "$STATE_ROUTES6"
  done < <(expand_included_routes_v6)
}

snapshot_excluded_routes_v4() {
  local fallback_gw="${1:-}"
  local fallback_if="${2:-}"
  : > "$STATE_EXCLUDED4"
  local route_spec probe gateway ifname
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    probe="$(route_spec_probe_host "$route_spec")"
    gateway="$(route -n get "$probe" 2>/dev/null | awk '/gateway:/{print $2; exit}')"
    ifname="$(route -n get "$probe" 2>/dev/null | awk '/interface:/{print $2; exit}')"
    if [[ -z "$gateway" && -z "$ifname" && -n "$fallback_gw" ]] && is_host_route_v4 "$route_spec"; then
      gateway="$fallback_gw"
      ifname="$fallback_if"
    fi
    printf '%s|%s|%s\n' "$route_spec" "$gateway" "$ifname" >> "$STATE_EXCLUDED4"
  done < <(csv_to_lines "$EXCLUDED_ROUTES")
}

snapshot_excluded_routes_v6() {
  local fallback_gw="${1:-}"
  local fallback_if="${2:-}"
  : > "$STATE_EXCLUDED6"
  local route_spec probe gateway ifname
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    probe="$(route_spec_probe_host "$route_spec")"
    gateway="$(route -n get -inet6 "$probe" 2>/dev/null | awk '/gateway:/{print $2; exit}')"
    ifname="$(route -n get -inet6 "$probe" 2>/dev/null | awk '/interface:/{print $2; exit}')"
    if [[ -z "$gateway" && -z "$ifname" && -n "$fallback_gw" ]] && is_host_route_v6 "$route_spec"; then
      gateway="$fallback_gw"
      ifname="$fallback_if"
    fi
    printf '%s|%s|%s\n' "$route_spec" "$gateway" "$ifname" >> "$STATE_EXCLUDED6"
  done < <(csv_to_lines "$EXCLUDED_ROUTES6")
}

add_excluded_routes_v4() {
  if [[ ! -s "$STATE_EXCLUDED4" ]]; then
    return 0
  fi
  local fallback_gw="${1:-}"
  local fallback_if="${2:-}"
  local route_spec underlay_gw underlay_if
  while IFS='|' read -r route_spec underlay_gw underlay_if; do
    [[ -z "$route_spec" ]] && continue
    if [[ -z "$underlay_gw" && -z "$underlay_if" ]] && is_host_route_v4 "$route_spec"; then
      underlay_gw="$fallback_gw"
      underlay_if="$fallback_if"
    fi
    if [[ -n "$underlay_gw" || -n "$underlay_if" ]]; then
      route_add_or_change_v4 "$route_spec" "$underlay_gw" "$underlay_if"
      if ! route_matches_underlay_v4 "$route_spec" "$underlay_gw" "$underlay_if"; then
        log "warning: excluded IPv4 route $route_spec did not resolve via underlay gw=${underlay_gw:-<none>} if=${underlay_if:-<none>}"
      fi
    fi
  done < "$STATE_EXCLUDED4"
}

add_excluded_routes_v6() {
  if [[ ! -s "$STATE_EXCLUDED6" ]]; then
    return 0
  fi
  local fallback_gw="${1:-}"
  local fallback_if="${2:-}"
  local route_spec underlay_gw underlay_if
  while IFS='|' read -r route_spec underlay_gw underlay_if; do
    [[ -z "$route_spec" ]] && continue
    if [[ -z "$underlay_gw" && -z "$underlay_if" ]] && is_host_route_v6 "$route_spec"; then
      underlay_gw="$fallback_gw"
      underlay_if="$fallback_if"
    fi
    if [[ -n "$underlay_gw" || -n "$underlay_if" ]]; then
      route_add_or_change_v6 "$route_spec" "$underlay_gw" "$underlay_if"
      if ! route_matches_underlay_v6 "$route_spec" "$underlay_gw" "$underlay_if"; then
        log "warning: excluded IPv6 route $route_spec did not resolve via underlay gw=${underlay_gw:-<none>} if=${underlay_if:-<none>}"
      fi
    fi
  done < "$STATE_EXCLUDED6"
}

delete_included_routes_v4() {
  if [[ -s "$STATE_ROUTES4" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      route -n delete -net "$route_spec" >/dev/null 2>&1 || true
    done < "$STATE_ROUTES4"
  fi
}

delete_excluded_routes_v4() {
  if [[ -s "$STATE_EXCLUDED4" ]]; then
    while IFS='|' read -r route_spec _underlay_gw _underlay_if; do
      [[ -z "$route_spec" ]] && continue
      route_delete_v4 "$route_spec"
    done < "$STATE_EXCLUDED4"
  fi
}

delete_excluded_routes_v6() {
  if [[ -s "$STATE_EXCLUDED6" ]]; then
    while IFS='|' read -r route_spec _underlay_gw _underlay_if; do
      [[ -z "$route_spec" ]] && continue
      route_delete_v6 "$route_spec"
    done < "$STATE_EXCLUDED6"
  fi
}

delete_included_routes_v6() {
  if [[ -s "$STATE_ROUTES6" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      route -n delete -inet6 "$route_spec" >/dev/null 2>&1 || true
    done < "$STATE_ROUTES6"
  fi
}

delete_included_routes_v4_from_file() {
  local file="$1"
  [[ -s "$file" ]] || return 0
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    route -n delete -net "$route_spec" >/dev/null 2>&1 || true
  done < "$file"
}

delete_included_routes_v6_from_file() {
  local file="$1"
  [[ -s "$file" ]] || return 0
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    route -n delete -inet6 "$route_spec" >/dev/null 2>&1 || true
  done < "$file"
}

delete_excluded_routes_v4_from_file() {
  local file="$1"
  [[ -s "$file" ]] || return 0
  while IFS='|' read -r route_spec _underlay_gw _underlay_if; do
    [[ -z "$route_spec" ]] && continue
    route_delete_v4 "$route_spec"
  done < "$file"
}

delete_excluded_routes_v6_from_file() {
  local file="$1"
  [[ -s "$file" ]] || return 0
  while IFS='|' read -r route_spec _underlay_gw _underlay_if; do
    [[ -z "$route_spec" ]] && continue
    route_delete_v6 "$route_spec"
  done < "$file"
}

cleanup_stale_managed_routes() {
  local file
  shopt -s nullglob
  for file in "$STATE_DIR"/*.excluded4; do
    delete_excluded_routes_v4_from_file "$file"
  done
  for file in "$STATE_DIR"/*.excluded6; do
    delete_excluded_routes_v6_from_file "$file"
  done
  for file in "$STATE_DIR"/*.routes4; do
    delete_included_routes_v4_from_file "$file"
  done
  for file in "$STATE_DIR"/*.routes6; do
    delete_included_routes_v6_from_file "$file"
  done
  shopt -u nullglob
}

detect_underlay_gw() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  if [[ -z "$normalized_ip" ]]; then
    return 1
  fi
  route -n get "$normalized_ip" 2>/dev/null | awk '/gateway:/{print $2; exit}'
}

detect_underlay_if() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  if [[ -z "$normalized_ip" ]]; then
    return 1
  fi
  route -n get "$normalized_ip" 2>/dev/null | awk '/interface:/{print $2; exit}'
}

fallback_underlay_gw_v4() {
  if [[ -n "$OVERLAY_UNDERLAY_GW" ]]; then
    printf '%s' "$OVERLAY_UNDERLAY_GW"
    return
  fi
  local gw
  gw="$(current_default_gateway_v4 || true)"
  if [[ -n "$gw" && "$gw" != "index:" ]]; then
    printf '%s' "$gw"
    return
  fi
  netstat_default_gateway_v4 || true
}

fallback_underlay_if_v4() {
  if [[ -n "$OVERLAY_UNDERLAY_IF" ]]; then
    printf '%s' "$OVERLAY_UNDERLAY_IF"
    return
  fi
  local ifname
  ifname="$(current_default_interface_v4 || true)"
  if [[ -n "$ifname" && "$ifname" != "$IFNAME" ]]; then
    printf '%s' "$ifname"
    return
  fi
  netstat_default_interface_v4 || true
}

wait_for_underlay_v4() {
  local attempts="${1:-25}"
  local delay="${2:-0.2}"
  local i
  for ((i=0; i<attempts; i++)); do
    local_underlay_gw="$(detect_underlay_gw || true)"
    local_underlay_if="$(detect_underlay_if || true)"
    if [[ -z "$local_underlay_gw" || "$local_underlay_gw" == "index:" ]]; then
      local_underlay_gw="$(fallback_underlay_gw_v4)"
    fi
    if [[ -z "$local_underlay_if" || "$local_underlay_if" == "$IFNAME" ]]; then
      local_underlay_if="$(fallback_underlay_if_v4)"
    fi
    if [[ -n "$local_underlay_gw" || -n "$local_underlay_if" ]]; then
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

save_default_routes() {
  rm -f "$STATE_FILE" "$STATE_FILE6"
  local current_gw
  local current_if
  current_gw="$(current_default_gateway_v4 || true)"
  current_if="$(current_default_interface_v4 || true)"
  if [[ -n "$current_gw" && "$current_if" != "$IFNAME" && "$current_gw" != "$TUN_GW" ]]; then
    printf '%s\n' "$current_gw" > "$STATE_FILE"
  fi

  local current_gw6
  local current_if6
  current_gw6="$(current_default_gateway_v6 || true)"
  current_if6="$(current_default_interface_v6 || true)"
  if [[ -n "$current_gw6" && "$current_if6" != "$IFNAME" && "$current_gw6" != "$TUN_GW6" ]]; then
    printf '%s\n' "$current_gw6" > "$STATE_FILE6"
  fi
}

restore_default_route_v6_only() {
  delete_excluded_routes_v6
  delete_included_routes_v6
  route -n delete -inet6 default -interface "$IFNAME" >/dev/null 2>&1 || true
  if [[ -n "$TUN_GW6" ]]; then
    route -n delete -inet6 default "$TUN_GW6" >/dev/null 2>&1 || true
  fi
  if [[ -s "$STATE_FILE6" ]]; then
    route -n add -inet6 default "$(cat "$STATE_FILE6")" >/dev/null 2>&1 || true
  fi
}

restore_default_routes() {
  delete_excluded_routes_v4
  delete_excluded_routes_v6
  delete_included_routes_v4
  delete_included_routes_v6
  route -n delete default -interface "$IFNAME" >/dev/null 2>&1 || true
  route -n delete default "$TUN_GW" >/dev/null 2>&1 || true
  route -n delete -inet6 default -interface "$IFNAME" >/dev/null 2>&1 || true
  if [[ -n "$TUN_GW6" ]]; then
    route -n delete -inet6 default "$TUN_GW6" >/dev/null 2>&1 || true
  fi
  if [[ -s "$STATE_FILE" ]]; then
    route -n add default "$(cat "$STATE_FILE")" >/dev/null 2>&1 || true
  fi
  if [[ -s "$STATE_FILE6" ]]; then
    route -n add -inet6 default "$(cat "$STATE_FILE6")" >/dev/null 2>&1 || true
  fi
}

ensure_underlay_default_v4() {
  local expected_gw="${1:-}"
  if should_switch_default_v4; then
    return 0
  fi
  if [[ -z "$expected_gw" && -s "$STATE_FILE" ]]; then
    expected_gw="$(cat "$STATE_FILE" 2>/dev/null || true)"
  fi
  [[ -n "$expected_gw" ]] || return 0
  route -n add default "$expected_gw" >/dev/null 2>&1 || \
    route -n change default "$expected_gw" >/dev/null 2>&1 || true
}

ensure_underlay_default_v6() {
  local expected_gw="${1:-}"
  if should_switch_default_v6; then
    return 0
  fi
  if [[ -z "$expected_gw" && -s "$STATE_FILE6" ]]; then
    expected_gw="$(cat "$STATE_FILE6" 2>/dev/null || true)"
  fi
  [[ -n "$expected_gw" ]] || return 0
  route -n add -inet6 default "$expected_gw" >/dev/null 2>&1 || \
    route -n change -inet6 default "$expected_gw" >/dev/null 2>&1 || true
}

set_default_route_v4() {
  route -n change default -interface "$IFNAME" >/dev/null 2>&1 && return 0
  route -n delete default >/dev/null 2>&1 || true
  route -n add default -interface "$IFNAME" >/dev/null 2>&1 && return 0
  route -n add default "$TUN_GW" >/dev/null 2>&1
}

case "$ACTION" in
  up)
    log "bringing up $IFNAME addr=$TUN_ADDR peer=$TUN_GW addr6=${TUN_ADDR6:-<none>} peer6=${TUN_GW6:-<none>}"
    cleanup_stale_managed_routes
    ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$TUN_GW" netmask "$(ipv4_prefix_to_netmask "$TUN_ADDR_PREFIX")" up
    if [[ -n "$TUN_ADDR6" ]]; then
      ifconfig "$IFNAME" inet6 "$TUN_ADDR6_IP" prefixlen "$TUN_ADDR6_PREFIX" alias >/dev/null 2>&1 || true
    fi
    install_tunnel_local_routes
    log_route_snapshot "after-ifconfig"

    local_underlay_gw=""
    local_underlay_if=""
    wait_for_underlay_v4 || true
    local_underlay_gw6="$(current_default_gateway_v6 || true)"
    local_underlay_if6="$(current_default_interface_v6 || true)"
    log "underlay detected peer=${OVERLAY_PEER_IP:-<none>} ipv4_gw=${local_underlay_gw:-<none>} ipv4_if=${local_underlay_if:-<none>} ipv6_gw=${local_underlay_gw6:-<none>} ipv6_if=${local_underlay_if6:-<none>}"
    underlay_service_name=""
    if [[ -n "$local_underlay_if" ]]; then
      underlay_service_name="$(network_service_for_device "$local_underlay_if" || true)"
    fi
    if [[ -n "$underlay_service_name" ]]; then
      save_dns_state "$underlay_service_name"
      declare -a dns_servers=()
      [[ -n "${DNS1:-}" ]] && dns_servers+=("$DNS1")
      [[ -n "${DNS2:-}" ]] && dns_servers+=("$DNS2")
      if (( ${#dns_servers[@]} > 0 )); then
        apply_dns_servers "$underlay_service_name" "${dns_servers[@]}"
      else
        log "skip dns apply: no DNS servers configured"
      fi
    else
      log "warning: unable to resolve network service for underlay interface=${local_underlay_if:-<none>}; dns unchanged"
    fi
    save_default_routes
    snapshot_excluded_routes_v4 "$local_underlay_gw" "$local_underlay_if"
    snapshot_excluded_routes_v6 "$local_underlay_gw6" "$local_underlay_if6"
    add_excluded_routes_v4 "$local_underlay_gw" "$local_underlay_if"
    add_excluded_routes_v6 "$local_underlay_gw6" "$local_underlay_if6"

    normalized_overlay_peer_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
    if [[ "$normalized_overlay_peer_ip" == *.* && "$normalized_overlay_peer_ip" != *:* && -n "$local_underlay_gw" ]]; then
      route_add_or_change_v4 "${normalized_overlay_peer_ip}/32" "$local_underlay_gw" "$local_underlay_if"
    fi
    log_route_snapshot "after-overlay-peer-protect"

    add_included_routes_v4
    add_included_routes_v6
    add_excluded_routes_v4 "$local_underlay_gw" "$local_underlay_if"
    add_excluded_routes_v6 "$local_underlay_gw6" "$local_underlay_if6"
    log_route_snapshot "after-route-install"
    if ! enforce_overlay_peer_underlay_v4 "$local_underlay_gw" "$local_underlay_if"; then
      log "failed to preserve IPv4 overlay peer route; reverting IPv4 full-tunnel route install on $IFNAME"
      delete_included_routes_v4
      log_route_snapshot "after-ipv4-revert"
    fi

    if should_switch_default_v4 && ! wait_for_full_tunnel_v4_routes; then
      log "failed to install IPv4 split full-tunnel routes via $IFNAME; keeping underlay defaults"
      delete_included_routes_v4
      log_route_snapshot "after-full-tunnel-v4-failed"
    fi
    add_excluded_routes_v4 "$local_underlay_gw" "$local_underlay_if"
    enforce_overlay_peer_underlay_v4 "$local_underlay_gw" "$local_underlay_if" || true

    if [[ -n "$TUN_GW6" ]] && should_switch_default_v6; then
      add_included_routes_v6
      if ! wait_for_full_tunnel_v6_routes; then
        log "failed to install IPv6 split full-tunnel routes via $IFNAME; keeping IPv4 route changes and restoring IPv6 only"
        restore_default_route_v6_only
        log_route_snapshot "after-full-tunnel-v6-failed"
      else
        add_excluded_routes_v6 "$local_underlay_gw6" "$local_underlay_if6"
      fi
    fi
    ensure_underlay_default_v4 "$local_underlay_gw"
    ensure_underlay_default_v6 "$local_underlay_gw6"
    enforce_overlay_peer_underlay_v4 "$local_underlay_gw" "$local_underlay_if" || true
    log_route_snapshot "final-up"
    log "default routes now ipv4_if=$(current_default_interface_v4 || true) ipv4_gw=$(current_default_gateway_v4 || true) ipv6_if=$(current_default_interface_v6 || true) ipv6_gw=$(current_default_gateway_v6 || true)"
    ;;
  down)
    log "bringing down $IFNAME"
    log_route_snapshot "before-down"
    restore_dns_state
    if [[ -n "$OVERLAY_PEER_IP" ]]; then
      route -n delete -host "$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")" >/dev/null 2>&1 || true
    fi
    cleanup_stale_managed_routes
    remove_tunnel_local_routes
    restore_default_routes
    if [[ -n "$TUN_ADDR6" ]]; then
      ifconfig "$IFNAME" inet6 "$TUN_ADDR6_IP" delete >/dev/null 2>&1 || true
    fi
    ifconfig "$IFNAME" down >/dev/null 2>&1 || true
    rm -f "$STATE_DNS_SERVICE" "$STATE_DNS_SERVERS"
    log_route_snapshot "after-down"
    ;;
  *)
    echo "unknown action: $ACTION" >&2
    exit 2
    ;;
esac
