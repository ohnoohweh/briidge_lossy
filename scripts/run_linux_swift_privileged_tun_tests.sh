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
for command in ip resolvectl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Linux Swift privileged TUN qualification requires $command." >&2
    exit 2
  fi
done

./scripts/build_linux_app.sh
swift test --package-path swift --filter ObstacleBridgeLinuxTunHelperAdapterTests
