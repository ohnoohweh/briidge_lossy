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
STATE_EXCLUDED4="${STATE_DIR}/${IFNAME}.excluded-routes4"
STATE_EXCLUDED6="${STATE_DIR}/${IFNAME}.excluded-routes6"
STATE_UNDERLAY4="${STATE_DIR}/${IFNAME}.underlay-route4"

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
    log_diag "stage=${stage} overlay_route=$(ip route get "$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")" 2>/dev/null | head -n1 || true)"
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

detect_underlay() {
  local normalized_ip
  normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"
  if [[ -z "$OVERLAY_PEER_IP" ]]; then
    echo "overlay peer IP not known yet; skipping underlay route detection" >&2
    return 1
  fi
  local route_line
  route_line="$(ip route get "$normalized_ip" 2>/dev/null | head -n1 || true)"
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
  if [[ -n "${STATE_UNDERLAY4:-}" ]]; then
    printf '%s\n' "$route_line" > "$STATE_UNDERLAY4"
  fi
  log_diag "detected underlay route=${route_line} dev=${UNDERLAY_IF} gw=${UNDERLAY_GW:-}"
  return 0
}

csv_to_lines() {
  tr ',' '\n' <<<"${1:-}" | sed '/^[[:space:]]*$/d'
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

add_excluded_routes4() {
  : > "$STATE_EXCLUDED4"
  local gw="" dev="" src=""
  while IFS='=' read -r key value; do
    [[ "$key" == "gw" ]] && gw="$value"
    [[ "$key" == "dev" ]] && dev="$value"
    [[ "$key" == "src" ]] && src="$value"
  done < <(_load_saved_route_parts "$STATE_UNDERLAY4" "ip route show default")
  [[ -n "$dev" ]] || return 0
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if excluded_route_should_use_loopback4 "$route_spec"; then
      ip route replace "$route_spec" dev lo
    elif [[ -n "$gw" ]]; then
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
    printf '%s\n' "$route_spec" >> "$STATE_EXCLUDED4"
  done < <(csv_to_lines "$EXCLUDED_ROUTES")
}

add_excluded_routes6() {
  : > "$STATE_EXCLUDED6"
  local gw="" dev=""
  while IFS='=' read -r key value; do
    [[ "$key" == "gw" ]] && gw="$value"
    [[ "$key" == "dev" ]] && dev="$value"
  done < <(_load_saved_route_parts "$STATE_FILE6" "ip -6 route show default")
  [[ -n "$dev" ]] || return 0
  while IFS= read -r route_spec; do
    [[ -z "$route_spec" ]] && continue
    if excluded_route_should_use_loopback6 "$route_spec"; then
      ip -6 route replace "$route_spec" dev lo
    elif [[ -n "$gw" ]]; then
      ip -6 route replace "$route_spec" via "$gw" dev "$dev"
    else
      ip -6 route replace "$route_spec" dev "$dev"
    fi
    printf '%s\n' "$route_spec" >> "$STATE_EXCLUDED6"
  done < <(csv_to_lines "$EXCLUDED_ROUTES6")
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
    add_excluded_routes4
    add_excluded_routes6

    overlay_src=""
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
    ip route replace default via "$TUN_GW" dev "$IFNAME" onlink
    if [[ -n "$TUN_GW6" ]]; then
      ip -6 route replace default via "$TUN_GW6" dev "$IFNAME" metric 1 onlink
    fi

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
      ip route del default via "$TUN_GW" dev "$IFNAME" 2>/dev/null || true
      if [[ -n "$TUN_GW6" ]]; then
        ip -6 route del default via "$TUN_GW6" dev "$IFNAME" 2>/dev/null || true
      fi
      restore_default_route
    fi
    delete_excluded_routes4
    delete_excluded_routes6
    if [[ -s "$STATE_UNDERLAY4" ]]; then
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
    log_route_snapshot "down-complete"
    ;;
  *)
    echo "unknown action: $ACTION" >&2
    exit 2
    ;;
esac
