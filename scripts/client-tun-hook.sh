#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?missing action}"
IFNAME="${2:?missing ifname}"

: "${TUN_ADDR:?missing TUN_ADDR}"
: "${TUN_GW:?missing TUN_GW}"
TUN_ADDR6="${TUN_ADDR6:-}"
TUN_GW6="${TUN_GW6:-}"
OVERLAY_PEER_IP="${OVERLAY_PEER_IP:-${OB_OVERLAY_PEER_HOST:-}}"
UNDERLAY_IF="${UNDERLAY_IF:-auto}"
UNDERLAY_GW="${UNDERLAY_GW:-auto}"
DNS1="${DNS1:-}"
DNS2="${DNS2:-}"
INCLUDED_ROUTES="${INCLUDED_ROUTES:-0.0.0.0/0}"
INCLUDED_ROUTES6="${INCLUDED_ROUTES6:-::/0}"
EXCLUDED_ROUTES="${EXCLUDED_ROUTES:-}"
EXCLUDED_ROUTES6="${EXCLUDED_ROUTES6:-}"

STATE_DIR="/run/obbridge"
STATE_FILE="${STATE_DIR}/${IFNAME}.default-route"
STATE_FILE6="${STATE_DIR}/${IFNAME}.default-route6"
STATE_INCLUDED4="${STATE_DIR}/${IFNAME}.included-routes4"
STATE_INCLUDED6="${STATE_DIR}/${IFNAME}.included-routes6"
STATE_EXCLUDED4="${STATE_DIR}/${IFNAME}.excluded-routes4"
STATE_EXCLUDED6="${STATE_DIR}/${IFNAME}.excluded-routes6"
STATE_UNDERLAY4="${STATE_DIR}/${IFNAME}.underlay-route4"
STATE_UNDERLAY6="${STATE_DIR}/${IFNAME}.underlay-route6"
STATE_PROTECTED4="${STATE_DIR}/${IFNAME}.protected-routes4"
STATE_PROTECTED6="${STATE_DIR}/${IFNAME}.protected-routes6"
STATE_POLICY4="${STATE_DIR}/${IFNAME}.policy-rules4"
STATE_POLICY6="${STATE_DIR}/${IFNAME}.policy-rules6"
STATE_POLICY_TABLE4="${STATE_DIR}/${IFNAME}.policy-table4"
STATE_POLICY_TABLE6="${STATE_DIR}/${IFNAME}.policy-table6"

POLICY_TABLE4="${OB_POLICY_TABLE4:-52190}"
POLICY_TABLE6="${OB_POLICY_TABLE6:-52191}"
POLICY_PREF4_BASE="${OB_POLICY_PREF4_BASE:-12000}"
POLICY_PREF6_BASE="${OB_POLICY_PREF6_BASE:-12050}"

mkdir -p "$STATE_DIR"

log_diag() {
  printf '[client-tun-hook] %s\n' "$*" >&2
}

log_route_snapshot() {
  local stage="$1"
  log_diag "stage=${stage} ifname=${IFNAME} tun_addr=${TUN_ADDR} tun_gw=${TUN_GW} tun_addr6=${TUN_ADDR6:-} tun_gw6=${TUN_GW6:-} overlay_peer_ip=${OVERLAY_PEER_IP:-} underlay_if=${UNDERLAY_IF:-} underlay_gw=${UNDERLAY_GW:-}"
  log_diag "stage=${stage} default4=$(ip route show default 2>/dev/null | tr '\n' ';' || true)"
  log_diag "stage=${stage} default6=$(ip -6 route show default 2>/dev/null | tr '\n' ';' || true)"
  log_diag "stage=${stage} ifaddr=$(ip addr show dev "$IFNAME" 2>/dev/null | tr '\n' ';' || true)"
  if [[ -n "${OVERLAY_PEER_IP:-}" ]]; then
    local normalized_ip
    normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
    if [[ "$normalized_ip" == *:* ]]; then
      log_diag "stage=${stage} overlay_route=$(ip -6 route get "$normalized_ip" 2>/dev/null | head -n1 || true)"
    else
      log_diag "stage=${stage} overlay_route=$(ip route get "$normalized_ip" 2>/dev/null | head -n1 || true)"
    fi
  fi
  if [[ -n "${EXCLUDED_ROUTES:-}" ]]; then
    log_diag "stage=${stage} excluded4=${EXCLUDED_ROUTES}"
  fi
  if [[ -n "${EXCLUDED_ROUTES6:-}" ]]; then
    log_diag "stage=${stage} excluded6=${EXCLUDED_ROUTES6}"
  fi
}

wait_for_interface() {
  local attempts="${1:-50}"
  local sleep_s="${2:-0.1}"
  local i
  for ((i=0; i<attempts; i++)); do
    if ip link show dev "$IFNAME" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$sleep_s"
  done
  echo "Cannot find device \"$IFNAME\"" >&2
  return 1
}

normalize_overlay_peer_ip() {
  local candidate="$1"
  if [[ "$candidate" =~ ^::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  printf '%s' "$candidate"
}

overlay_route_prefix() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  if [[ "$normalized_ip" == *:* ]]; then
    printf '%s/128' "$normalized_ip"
  else
    printf '%s/32' "$normalized_ip"
  fi
}

overlay_peer_is_ipv6() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "${OVERLAY_PEER_IP:-}")"
  [[ "$normalized_ip" == *:* ]]
}

detect_underlay() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  if [[ -z "$OVERLAY_PEER_IP" ]]; then
    echo "overlay peer IP not known yet; skipping underlay route detection" >&2
    return 1
  fi
  local route_line=""
  local route_cmd=""
  local state_file=""
  local stale_state_file=""
  if [[ "$normalized_ip" == *:* ]]; then
    route_cmd="ip -6 route get"
    state_file="$STATE_UNDERLAY6"
    stale_state_file="$STATE_UNDERLAY4"
  else
    route_cmd="ip route get"
    state_file="$STATE_UNDERLAY4"
    stale_state_file="$STATE_UNDERLAY6"
  fi
  route_line="$($route_cmd "$normalized_ip" 2>/dev/null | head -n1 || true)"
  if [[ -z "$route_line" ]]; then
    log_diag "unable to detect route to overlay peer ${normalized_ip}"
    return 1
  fi
  if [[ "$UNDERLAY_IF" == "auto" || -z "$UNDERLAY_IF" ]]; then
    UNDERLAY_IF="$(awk '{for (i=1; i<NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<<"$route_line")"
  fi
  if [[ "$UNDERLAY_GW" == "auto" || -z "$UNDERLAY_GW" ]]; then
    UNDERLAY_GW="$(awk '{for (i=1; i<NF; i++) if ($i == "via") {print $(i+1); exit}}' <<<"$route_line")"
  fi
  if [[ -z "$UNDERLAY_IF" ]]; then
    log_diag "unable to detect underlay interface from: ${route_line}"
    return 1
  fi
  if [[ -n "$state_file" ]]; then
    printf '%s\n' "$route_line" > "$state_file"
  fi
  if [[ -n "$stale_state_file" ]]; then
    rm -f "$stale_state_file"
  fi
  log_diag "detected underlay route=${route_line} dev=${UNDERLAY_IF} gw=${UNDERLAY_GW:-}"
  return 0
}

csv_to_lines() {
  tr ',' '\n' <<<"${1:-}" | sed '/^[[:space:]]*$/d'
}

is_full_tunnel_route4() {
  local route_spec="$1"
  case "$route_spec" in
    0.0.0.0/0|default)
      return 0
      ;;
  esac
  return 1
}

is_full_tunnel_route6() {
  local route_spec="$1"
  case "$route_spec" in
    ::/0|default|::0/0)
      return 0
      ;;
  esac
  return 1
}

excluded_route_should_use_loopback4() {
  local route_spec="$1"
  case "$route_spec" in
    127.0.0.0/8|127.0.0.1/32|127.0.0.1)
      return 0
      ;;
  esac
  return 1
}

excluded_route_should_use_loopback6() {
  local route_spec="$1"
  case "$route_spec" in
    ::1/128|::1)
      return 0
      ;;
  esac
  return 1
}

_parse_route_parts() {
  local route_line="$1"
  awk '
    {
      for (i = 1; i < NF; i++) {
        if ($i == "via" && gw == "") gw = $(i+1)
        if ($i == "dev" && dev == "") dev = $(i+1)
        if ($i == "src" && src == "") src = $(i+1)
      }
    }
    END {
      printf "gw=%s\n", gw
      printf "dev=%s\n", dev
      printf "src=%s\n", src
    }
  ' <<<"$route_line"
}

_load_saved_route_parts() {
  local state_file="$1"
  local command="$2"
  local route_line=""
  if [[ -s "$state_file" ]]; then
    route_line="$(cat "$state_file")"
  else
    route_line="$($command | head -n1 || true)"
  fi
  [[ -n "$route_line" ]] || return 1
  _parse_route_parts "$route_line"
}

snapshot_excluded_routes4() {
  : > "$STATE_EXCLUDED4"
  local route_spec route_line gw="" dev="" src="" probe=""
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if excluded_route_should_use_loopback4 "$route_spec"; then
      continue
    fi
    route_line="$(ip route show match "$route_spec" 2>/dev/null | head -n1 || true)"
    if [[ -z "$route_line" ]]; then
      probe="${route_spec%%/*}"
      if [[ -n "$probe" ]]; then
        route_line="$(ip route get "$probe" 2>/dev/null | head -n1 || true)"
      fi
    fi
    gw=""
    dev=""
    src=""
    if [[ -n "$route_line" ]]; then
      while IFS='=' read -r key value; do
        [[ "$key" == "gw" ]] && gw="$value"
        [[ "$key" == "dev" ]] && dev="$value"
        [[ "$key" == "src" ]] && src="$value"
      done < <(_parse_route_parts "$route_line")
    fi
    printf '%s|%s|%s|%s\n' "$route_spec" "$gw" "$dev" "$src" >> "$STATE_EXCLUDED4"
  done < <(csv_to_lines "$EXCLUDED_ROUTES")
}

snapshot_excluded_routes6() {
  : > "$STATE_EXCLUDED6"
  local route_spec route_line gw="" dev="" src="" probe=""
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if excluded_route_should_use_loopback6 "$route_spec"; then
      continue
    fi
    route_line="$(ip -6 route show match "$route_spec" 2>/dev/null | head -n1 || true)"
    if [[ -z "$route_line" ]]; then
      probe="${route_spec%%/*}"
      if [[ -n "$probe" ]]; then
        route_line="$(ip -6 route get "$probe" 2>/dev/null | head -n1 || true)"
      fi
    fi
    gw=""
    dev=""
    src=""
    if [[ -n "$route_line" ]]; then
      while IFS='=' read -r key value; do
        [[ "$key" == "gw" ]] && gw="$value"
        [[ "$key" == "dev" ]] && dev="$value"
        [[ "$key" == "src" ]] && src="$value"
      done < <(_parse_route_parts "$route_line")
    fi
    printf '%s|%s|%s|%s\n' "$route_spec" "$gw" "$dev" "$src" >> "$STATE_EXCLUDED6"
  done < <(csv_to_lines "$EXCLUDED_ROUTES6")
}

add_excluded_routes4() {
  local fallback_gw="" fallback_dev="" fallback_src=""
  while IFS='=' read -r key value; do
    [[ "$key" == "gw" ]] && fallback_gw="$value"
    [[ "$key" == "dev" ]] && fallback_dev="$value"
    [[ "$key" == "src" ]] && fallback_src="$value"
  done < <(_load_saved_route_parts "$STATE_UNDERLAY4" "ip route show default")
  [[ -n "$fallback_dev" ]] || return 0
  [[ -s "$STATE_EXCLUDED4" ]] || snapshot_excluded_routes4
  while IFS='|' read -r route_spec gw dev src; do
    [[ -z "$route_spec" ]] && continue
    if excluded_route_should_use_loopback4 "$route_spec"; then
      log_diag "skip explicit loopback route install for ${route_spec}; kernel loopback routes already cover it"
      continue
    fi
    if [[ -z "$dev" ]]; then
      gw="$fallback_gw"
      dev="$fallback_dev"
      src="$fallback_src"
    fi
    if [[ -n "$gw" ]]; then
      if [[ -n "$src" ]]; then
        ip route replace "$route_spec" via "$gw" dev "$dev" src "$src"
      else
        ip route replace "$route_spec" via "$gw" dev "$dev"
      fi
    else
      if [[ -n "$src" ]]; then
        ip route replace "$route_spec" dev "$dev" src "$src"
      else
        ip route replace "$route_spec" dev "$dev"
      fi
    fi
  done < "$STATE_EXCLUDED4"
}

protect_underlay_routes4() {
  : > "$STATE_PROTECTED4"
}

protect_underlay_routes6() {
  : > "$STATE_PROTECTED6"
}

save_policy_table_ids() {
  printf '%s\n' "$POLICY_TABLE4" > "$STATE_POLICY_TABLE4"
  printf '%s\n' "$POLICY_TABLE6" > "$STATE_POLICY_TABLE6"
}

load_policy_table4() {
  if [[ -s "$STATE_POLICY_TABLE4" ]]; then
    cat "$STATE_POLICY_TABLE4"
    return
  fi
  printf '%s\n' "$POLICY_TABLE4"
}

load_policy_table6() {
  if [[ -s "$STATE_POLICY_TABLE6" ]]; then
    cat "$STATE_POLICY_TABLE6"
    return
  fi
  printf '%s\n' "$POLICY_TABLE6"
}

policy_rule_add4() {
  local pref="$1"
  shift
  ip rule add pref "$pref" "$@"
  printf '%s|%s\n' "$pref" "$*" >> "$STATE_POLICY4"
}

policy_rule_add6() {
  local pref="$1"
  shift
  ip -6 rule add pref "$pref" "$@"
  printf '%s|%s\n' "$pref" "$*" >> "$STATE_POLICY6"
}

delete_policy_rules4() {
  local policy_table
  policy_table="$(load_policy_table4)"
  if [[ -s "$STATE_POLICY4" ]]; then
    while IFS='|' read -r pref spec; do
      [[ -z "$pref" || -z "$spec" ]] && continue
      ip rule del pref "$pref" $spec 2>/dev/null || true
    done < "$STATE_POLICY4"
  fi
  ip route flush table "$policy_table" 2>/dev/null || true
}

delete_policy_rules6() {
  local policy_table
  policy_table="$(load_policy_table6)"
  if [[ -s "$STATE_POLICY6" ]]; then
    while IFS='|' read -r pref spec; do
      [[ -z "$pref" || -z "$spec" ]] && continue
      ip -6 rule del pref "$pref" $spec 2>/dev/null || true
    done < "$STATE_POLICY6"
  fi
  ip -6 route flush table "$policy_table" 2>/dev/null || true
}

connected_underlay_routes4() {
  ip route show dev "$UNDERLAY_IF" proto kernel scope link 2>/dev/null | awk '{print $1}' | sed '/^[[:space:]]*$/d'
}

connected_underlay_routes6() {
  ip -6 route show dev "$UNDERLAY_IF" proto kernel 2>/dev/null | awk '{print $1}' | sed '/^[[:space:]]*$/d'
}

connected_tun_routes4() {
  ip route show dev "$IFNAME" proto kernel scope link 2>/dev/null | awk '{print $1}' | sed '/^[[:space:]]*$/d'
}

connected_tun_routes6() {
  ip -6 route show dev "$IFNAME" proto kernel 2>/dev/null | awk '{print $1}' | sed '/^[[:space:]]*$/d'
}

configure_policy_full_tunnel4() {
  local policy_table policy_pref
  policy_table="$(load_policy_table4)"
  policy_pref="$POLICY_PREF4_BASE"
  : > "$STATE_POLICY4"
  ip route flush table "$policy_table" 2>/dev/null || true
  ip route replace table "$policy_table" default via "$TUN_GW" dev "$IFNAME" onlink
  if [[ -n "${OVERLAY_PEER_IP:-}" ]]; then
    policy_rule_add4 "$policy_pref" to "$(overlay_route_prefix)" lookup main
    policy_pref=$((policy_pref + 1))
  fi
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    policy_rule_add4 "$policy_pref" to "$route_spec" lookup main
    policy_pref=$((policy_pref + 1))
  done < <(connected_underlay_routes4)
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    policy_rule_add4 "$policy_pref" to "$route_spec" lookup main
    policy_pref=$((policy_pref + 1))
  done < <(connected_tun_routes4)
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    policy_rule_add4 "$policy_pref" to "$route_spec" lookup main
    policy_pref=$((policy_pref + 1))
  done < <(csv_to_lines "$EXCLUDED_ROUTES")
  policy_rule_add4 "$policy_pref" to 0.0.0.0/0 lookup "$policy_table"
}

configure_policy_full_tunnel6() {
  [[ -n "$TUN_GW6" ]] || return 0
  local policy_table policy_pref
  policy_table="$(load_policy_table6)"
  policy_pref="$POLICY_PREF6_BASE"
  : > "$STATE_POLICY6"
  ip -6 route flush table "$policy_table" 2>/dev/null || true
  ip -6 route replace table "$policy_table" default via "$TUN_GW6" dev "$IFNAME" metric 1 onlink
  if [[ -n "${OVERLAY_PEER_IP:-}" ]] && overlay_peer_is_ipv6; then
    policy_rule_add6 "$policy_pref" to "$(overlay_route_prefix)" lookup main
    policy_pref=$((policy_pref + 1))
  fi
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    policy_rule_add6 "$policy_pref" to "$route_spec" lookup main
    policy_pref=$((policy_pref + 1))
  done < <(connected_underlay_routes6)
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    policy_rule_add6 "$policy_pref" to "$route_spec" lookup main
    policy_pref=$((policy_pref + 1))
  done < <(connected_tun_routes6)
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    policy_rule_add6 "$policy_pref" to "$route_spec" lookup main
    policy_pref=$((policy_pref + 1))
  done < <(csv_to_lines "$EXCLUDED_ROUTES6")
  policy_rule_add6 "$policy_pref" to ::/0 lookup "$policy_table"
}

add_excluded_routes6() {
  local fallback_gw="" fallback_dev="" fallback_src=""
  while IFS='=' read -r key value; do
    [[ "$key" == "gw" ]] && fallback_gw="$value"
    [[ "$key" == "dev" ]] && fallback_dev="$value"
    [[ "$key" == "src" ]] && fallback_src="$value"
  done < <(_load_saved_route_parts "$STATE_UNDERLAY6" "ip -6 route show default")
  [[ -n "$fallback_dev" ]] || return 0
  [[ -s "$STATE_EXCLUDED6" ]] || snapshot_excluded_routes6
  while IFS='|' read -r route_spec gw dev _src; do
    [[ -z "$route_spec" ]] && continue
    if excluded_route_should_use_loopback6 "$route_spec"; then
      log_diag "skip explicit IPv6 loopback route install for ${route_spec}; kernel loopback routes already cover it"
      continue
    fi
    if [[ -z "$dev" ]]; then
      gw="$fallback_gw"
      dev="$fallback_dev"
    fi
    if [[ -n "$gw" ]]; then
      ip -6 route replace "$route_spec" via "$gw" dev "$dev"
    else
      ip -6 route replace "$route_spec" dev "$dev"
    fi
  done < "$STATE_EXCLUDED6"
}

add_included_routes4() {
  : > "$STATE_INCLUDED4"
  local installed_default=0
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if is_full_tunnel_route4 "$route_spec"; then
      configure_policy_full_tunnel4
      printf '%s\n' "default" >> "$STATE_INCLUDED4"
      installed_default=1
      continue
    fi
    ip route replace "$route_spec" via "$TUN_GW" dev "$IFNAME" onlink
    printf '%s\n' "$route_spec" >> "$STATE_INCLUDED4"
  done < <(csv_to_lines "$INCLUDED_ROUTES")
  return "$installed_default"
}

add_included_routes6() {
  : > "$STATE_INCLUDED6"
  local installed_default=0
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if is_full_tunnel_route6 "$route_spec"; then
      if [[ -n "$TUN_GW6" ]]; then
        configure_policy_full_tunnel6
        printf '%s\n' "default" >> "$STATE_INCLUDED6"
        installed_default=1
      fi
      continue
    fi
    if [[ -n "$TUN_GW6" ]]; then
      ip -6 route replace "$route_spec" via "$TUN_GW6" dev "$IFNAME" metric 1 onlink
      printf '%s\n' "$route_spec" >> "$STATE_INCLUDED6"
    fi
  done < <(csv_to_lines "$INCLUDED_ROUTES6")
  return "$installed_default"
}

delete_included_routes4() {
  if [[ -s "$STATE_INCLUDED4" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      if [[ "$route_spec" == "default" ]]; then
        delete_policy_rules4
        ip route del default via "$TUN_GW" dev "$IFNAME" 2>/dev/null || true
      else
        ip route del "$route_spec" via "$TUN_GW" dev "$IFNAME" 2>/dev/null || true
        ip route del "$route_spec" dev "$IFNAME" 2>/dev/null || true
      fi
    done < "$STATE_INCLUDED4"
  fi
}

delete_included_routes6() {
  if [[ -s "$STATE_INCLUDED6" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      if [[ "$route_spec" == "default" ]]; then
        if [[ -n "$TUN_GW6" ]]; then
          delete_policy_rules6
          ip -6 route del default via "$TUN_GW6" dev "$IFNAME" 2>/dev/null || true
        fi
      else
        if [[ -n "$TUN_GW6" ]]; then
          ip -6 route del "$route_spec" via "$TUN_GW6" dev "$IFNAME" 2>/dev/null || true
        fi
        ip -6 route del "$route_spec" dev "$IFNAME" 2>/dev/null || true
      fi
    done < "$STATE_INCLUDED6"
  fi
}

delete_excluded_routes4() {
  if [[ -s "$STATE_EXCLUDED4" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      ip route del "$route_spec" 2>/dev/null || true
    done < "$STATE_EXCLUDED4"
  fi
}

delete_excluded_routes6() {
  if [[ -s "$STATE_EXCLUDED6" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      ip -6 route del "$route_spec" 2>/dev/null || true
    done < "$STATE_EXCLUDED6"
  fi
}

delete_protected_routes4() {
  if [[ -s "$STATE_PROTECTED4" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      ip route del "$route_spec" 2>/dev/null || true
    done < "$STATE_PROTECTED4"
  fi
}

delete_protected_routes6() {
  if [[ -s "$STATE_PROTECTED6" ]]; then
    while IFS= read -r route_spec; do
      [[ -z "$route_spec" ]] && continue
      ip -6 route del "$route_spec" 2>/dev/null || true
    done < "$STATE_PROTECTED6"
  fi
}

save_default_route() {
  local current_default
  current_default="$(ip route show default | head -n1 || true)"
  if [[ -n "$current_default" && "$current_default" != *" dev ${IFNAME}"* ]]; then
    printf '%s\n' "$current_default" > "$STATE_FILE"
  fi

  local current_default6
  current_default6="$(ip -6 route show default | head -n1 || true)"
  if [[ -n "$current_default6" && "$current_default6" != *" dev ${IFNAME}"* ]]; then
    printf '%s\n' "$current_default6" > "$STATE_FILE6"
  fi
}

restore_default_route() {
  if [[ -s "$STATE_FILE" ]]; then
    local current_default
    current_default="$(cat "$STATE_FILE")"
    ip route replace $current_default
  fi
  if [[ -s "$STATE_FILE6" ]]; then
    local current_default6
    current_default6="$(cat "$STATE_FILE6")"
    ip -6 route replace $current_default6
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
    wait_for_interface
    ip addr replace "$TUN_ADDR" dev "$IFNAME"
    if [[ -n "$TUN_ADDR6" ]]; then
      ip -6 addr replace "$TUN_ADDR6" dev "$IFNAME"
    fi
    ip link set dev "$IFNAME" up

    if ! detect_underlay; then
      log_route_snapshot "up-no-underlay"
      log_diag "underlay route not ready; leaving ${IFNAME} addressed but skipping default-route changes for now"
      exit 0
    fi

    save_default_route
    save_policy_table_ids
    snapshot_excluded_routes4
    snapshot_excluded_routes6
    add_excluded_routes4
    add_excluded_routes6
    protect_underlay_routes4
    protect_underlay_routes6

    overlay_src=""
    if overlay_peer_is_ipv6; then
      while IFS='=' read -r key value; do
        [[ "$key" == "src" ]] && overlay_src="$value"
      done < <(_load_saved_route_parts "$STATE_UNDERLAY6" "ip -6 route show default")
      if [[ -n "$UNDERLAY_GW" ]]; then
        if [[ -n "$overlay_src" ]]; then
          ip -6 route replace "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF" src "$overlay_src"
        else
          ip -6 route replace "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF"
        fi
      else
        if [[ -n "$overlay_src" ]]; then
          ip -6 route replace "$(overlay_route_prefix)" dev "$UNDERLAY_IF" src "$overlay_src"
        else
          ip -6 route replace "$(overlay_route_prefix)" dev "$UNDERLAY_IF"
        fi
      fi
    else
      while IFS='=' read -r key value; do
        [[ "$key" == "src" ]] && overlay_src="$value"
      done < <(_load_saved_route_parts "$STATE_UNDERLAY4" "ip route show default")
      if [[ -n "$UNDERLAY_GW" ]]; then
        if [[ -n "$overlay_src" ]]; then
          ip route replace "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF" src "$overlay_src"
        else
          ip route replace "$(overlay_route_prefix)" via "$UNDERLAY_GW" dev "$UNDERLAY_IF"
        fi
      else
        if [[ -n "$overlay_src" ]]; then
          ip route replace "$(overlay_route_prefix)" dev "$UNDERLAY_IF" src "$overlay_src"
        else
          ip route replace "$(overlay_route_prefix)" dev "$UNDERLAY_IF"
        fi
      fi
    fi
    add_included_routes4 || true
    add_included_routes6 || true
    ip route flush cache 2>/dev/null || true
    ip -6 route flush cache 2>/dev/null || true

    set_dns
    log_route_snapshot "up-complete"
    ;;
  down)
    if ! ip link show dev "$IFNAME" >/dev/null 2>&1; then
      clear_dns
      rm -f "$STATE_EXCLUDED4" "$STATE_EXCLUDED6"
      exit 0
    fi
    if detect_underlay; then
      delete_included_routes4
      delete_included_routes6
      restore_default_route
    fi
    delete_excluded_routes4
    delete_excluded_routes6
    delete_protected_routes4
    delete_protected_routes6
    if overlay_peer_is_ipv6 && [[ -s "$STATE_UNDERLAY6" ]]; then
      saved_gw=""
      saved_dev=""
      saved_src=""
      while IFS='=' read -r key value; do
        [[ "$key" == "gw" ]] && saved_gw="$value"
        [[ "$key" == "dev" ]] && saved_dev="$value"
        [[ "$key" == "src" ]] && saved_src="$value"
      done < <(_load_saved_route_parts "$STATE_UNDERLAY6" "ip -6 route show default")
      if [[ -n "$saved_dev" ]]; then
        if [[ -n "$saved_gw" ]]; then
          if [[ -n "$saved_src" ]]; then
            ip -6 route del "$(overlay_route_prefix)" via "$saved_gw" dev "$saved_dev" src "$saved_src" 2>/dev/null || true
          else
            ip -6 route del "$(overlay_route_prefix)" via "$saved_gw" dev "$saved_dev" 2>/dev/null || true
          fi
        else
          if [[ -n "$saved_src" ]]; then
            ip -6 route del "$(overlay_route_prefix)" dev "$saved_dev" src "$saved_src" 2>/dev/null || true
          else
            ip -6 route del "$(overlay_route_prefix)" dev "$saved_dev" 2>/dev/null || true
          fi
        fi
      fi
    elif [[ -s "$STATE_UNDERLAY4" ]]; then
      saved_gw=""
      saved_dev=""
      saved_src=""
      while IFS='=' read -r key value; do
        [[ "$key" == "gw" ]] && saved_gw="$value"
        [[ "$key" == "dev" ]] && saved_dev="$value"
        [[ "$key" == "src" ]] && saved_src="$value"
      done < <(_load_saved_route_parts "$STATE_UNDERLAY4" "ip route show default")
      if [[ -n "$saved_dev" ]]; then
        if [[ -n "$saved_gw" ]]; then
          if [[ -n "$saved_src" ]]; then
            ip route del "$(overlay_route_prefix)" via "$saved_gw" dev "$saved_dev" src "$saved_src" 2>/dev/null || true
          else
            ip route del "$(overlay_route_prefix)" via "$saved_gw" dev "$saved_dev" 2>/dev/null || true
          fi
        else
          if [[ -n "$saved_src" ]]; then
            ip route del "$(overlay_route_prefix)" dev "$saved_dev" src "$saved_src" 2>/dev/null || true
          else
            ip route del "$(overlay_route_prefix)" dev "$saved_dev" 2>/dev/null || true
          fi
        fi
      fi
    fi

    clear_dns
    if [[ -n "$TUN_ADDR6" ]]; then
      ip -6 addr del "$TUN_ADDR6" dev "$IFNAME" 2>/dev/null || true
    fi
    ip addr del "$TUN_ADDR" dev "$IFNAME" 2>/dev/null || true
    ip route flush cache 2>/dev/null || true
    ip -6 route flush cache 2>/dev/null || true
    log_route_snapshot "down-complete"
    ;;
  *)
    echo "unknown action: $ACTION" >&2
    exit 2
    ;;
esac
