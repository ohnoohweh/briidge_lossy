#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${TUN_GW:?missing TUN_GW}"
TUN_ADDR6="${TUN_ADDR6:-}"
TUN_GW6="${TUN_GW6:-}"
INCLUDED_ROUTES="${INCLUDED_ROUTES:-0.0.0.0/0}"
INCLUDED_ROUTES6="${INCLUDED_ROUTES6:-::/0}"
OVERLAY_PEER_IP="${OVERLAY_PEER_IP:-${OB_OVERLAY_PEER_HOST:-}}"

STATE_DIR="/tmp/obbridge"
STATE_FILE="${STATE_DIR}/${IFNAME}.default-route"
STATE_FILE6="${STATE_DIR}/${IFNAME}.default-route6"
STATE_ROUTES4="${STATE_DIR}/${IFNAME}.routes4"
STATE_ROUTES6="${STATE_DIR}/${IFNAME}.routes6"

mkdir -p "$STATE_DIR"

TUN_ADDR_IP="${TUN_ADDR%%/*}"
TUN_ADDR_PREFIX="${TUN_ADDR##*/}"
TUN_ADDR6_IP="${TUN_ADDR6%%/*}"
TUN_ADDR6_PREFIX="${TUN_ADDR6##*/}"

log() {
  printf '[client-tun-hook-macos] %s\n' "$*" >&2
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

wait_for_full_tunnel_v6_routes() {
  local attempts="${2:-10}"
  local delay="${3:-0.2}"
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

add_included_routes_v4() {
  : > "$STATE_ROUTES4"
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if [[ "$route_spec" == "0.0.0.0/0" || "$route_spec" == "default" ]]; then
      continue
    fi
    route -n add -net "$route_spec" -interface "$IFNAME" >/dev/null 2>&1 || \
      route -n change -net "$route_spec" -interface "$IFNAME" >/dev/null 2>&1 || true
    printf '%s\n' "$route_spec" >> "$STATE_ROUTES4"
  done < <(csv_to_lines "$INCLUDED_ROUTES")
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

delete_included_routes_v4() {
  if [[ -s "$STATE_ROUTES4" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      route -n delete -net "$route_spec" >/dev/null 2>&1 || true
    done < "$STATE_ROUTES4"
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

detect_underlay_gw() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  if [[ -z "$normalized_ip" ]]; then
    return 1
  fi
  route -n get "$normalized_ip" 2>/dev/null | awk '/gateway:/{print $2; exit}'
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

set_default_route_v4() {
  route -n change default -interface "$IFNAME" >/dev/null 2>&1 && return 0
  route -n delete default >/dev/null 2>&1 || true
  route -n add default -interface "$IFNAME" >/dev/null 2>&1 && return 0
  route -n add default "$TUN_GW" >/dev/null 2>&1
}

case "$ACTION" in
  up)
    log "bringing up $IFNAME addr=$TUN_ADDR peer=$TUN_GW addr6=${TUN_ADDR6:-<none>} peer6=${TUN_GW6:-<none>}"
    ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$TUN_GW" netmask "$(ipv4_prefix_to_netmask "$TUN_ADDR_PREFIX")" up
    if [[ -n "$TUN_ADDR6" ]]; then
      ifconfig "$IFNAME" inet6 "$TUN_ADDR6_IP" prefixlen "$TUN_ADDR6_PREFIX" alias >/dev/null 2>&1 || true
    fi

    local_underlay_gw="$(detect_underlay_gw || true)"
    save_default_routes
    add_included_routes_v4
    add_included_routes_v6

    if [[ -n "$OVERLAY_PEER_IP" && -n "$local_underlay_gw" ]]; then
      route -n add -host "$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")" "$local_underlay_gw" >/dev/null 2>&1 || true
    fi

    if should_switch_default_v4; then
      set_default_route_v4
      if ! wait_for_default_gateway_v4 "$TUN_GW"; then
        log "failed to switch IPv4 default route to $TUN_GW; restoring underlay routes"
        restore_default_routes
        exit 1
      fi
    fi

    if [[ -n "$TUN_GW6" ]] && should_switch_default_v6; then
      add_included_routes_v6
      if ! wait_for_full_tunnel_v6_routes; then
        log "failed to install IPv6 split full-tunnel routes via $IFNAME; keeping IPv4 route changes and restoring IPv6 only"
        restore_default_route_v6_only
      fi
    fi
    log "default routes now ipv4_if=$(current_default_interface_v4 || true) ipv4_gw=$(current_default_gateway_v4 || true) ipv6_if=$(current_default_interface_v6 || true) ipv6_gw=$(current_default_gateway_v6 || true)"
    ;;
  down)
    log "bringing down $IFNAME"
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
