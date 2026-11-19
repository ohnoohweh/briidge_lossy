#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux Swift privileged TUN qualification requires Linux." >&2
  exit 2
fi
if [[ "${OBSTACLEBRIDGE_PRIVILEGED_TUN:-}" != "1" ]]; then
  echo "Set OBSTACLEBRIDGE_PRIVILEGED_TUN=1 on an authorized host." >&2
  exit 2
fi
if [[ ! -e /dev/net/tun ]]; then
  echo "Linux Swift privileged TUN qualification requires /dev/net/tun." >&2
  exit 2
fi
effective_capabilities="$(awk '/^CapEff:/ { print $2; exit }' /proc/self/status)"
if [[ -z "$effective_capabilities" ]] || (( (16#$effective_capabilities & 0x1000) == 0 )); then
  echo "Linux Swift privileged TUN qualification requires effective CAP_NET_ADMIN." >&2
  exit 2
fi
for command in ip resolvectl iptables ip6tables; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Linux Swift privileged TUN qualification requires $command." >&2
    exit 2
  fi
done

./scripts/build_linux_app.sh
export OBSTACLEBRIDGE_LINUX_TEST_HELPER_EXECUTABLE="$(pwd)/build/linux/ObstacleBridgeLinux"
swift test --package-path swift --filter ObstacleBridgeLinuxTunHelperAdapterTests
python3 -m pytest -vv --timeout=180 --run-linux-elevated \
  tests/integration/test_linux_elevated.py::test_overlay_e2e_linux_elevated_swift_tun_helper_udp_tcp_webadmin_rekey_traffic
