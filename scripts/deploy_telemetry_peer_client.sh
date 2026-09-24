#!/usr/bin/env bash
# Deploy a Python telemetry-uploader mTLS identity over SSH. It never deploys the CA private key.
# Example:
# HOST=client.example.net bash scripts/deploy_telemetry_peer_client.sh

set -euo pipefail

PORT="${PORT:-18022}"
USER_NAME="${USER_NAME:-root}"
HOST="${HOST:?set HOST to the peer-client address}"
CA_CERT="${CA_CERT:-/var/lib/obstaclebridge/telemetry-ca/ca.cert.pem}"
CLIENT_KEY="${CLIENT_KEY:-/var/lib/obstaclebridge/telemetry-client/client.key.pem}"
CLIENT_CERT="${CLIENT_CERT:-/var/lib/obstaclebridge/telemetry-client/client.cert.pem}"
SERVICE_USER="${SERVICE_USER:-obstaclebridge}"
SERVICE_GROUP="${SERVICE_GROUP:-${SERVICE_USER}}"
SSH_IDENTITY="${SSH_IDENTITY:-}"

for source_file in "$CA_CERT" "$CLIENT_KEY" "$CLIENT_CERT"; do
    [[ -f "$source_file" ]] || { echo "missing regular file: $source_file" >&2; exit 2; }
done
[[ "$SERVICE_USER" =~ ^[A-Za-z0-9_.-]+$ && "$SERVICE_GROUP" =~ ^[A-Za-z0-9_.-]+$ ]] || {
    echo "SERVICE_USER and SERVICE_GROUP may contain only letters, numbers, dot, underscore, and hyphen" >&2
    exit 2
}

SSH=(ssh -p "$PORT")
SCP=(scp -P "$PORT")
if [[ -n "$SSH_IDENTITY" ]]; then
    SSH+=(-i "$SSH_IDENTITY")
    SCP+=(-i "$SSH_IDENTITY")
fi
REMOTE="${USER_NAME}@${HOST}"

remote_stage="$("${SSH[@]}" "$REMOTE" 'umask 077; mktemp -d /tmp/obstaclebridge-telemetry-client.XXXXXX')"
cleanup() {
    "${SSH[@]}" "$REMOTE" "rm -rf -- '$remote_stage'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${SCP[@]}" "$CA_CERT" "$REMOTE:$remote_stage/source-ca.cert.pem"
"${SCP[@]}" "$CLIENT_KEY" "$REMOTE:$remote_stage/source-client.key.pem"
"${SCP[@]}" "$CLIENT_CERT" "$REMOTE:$remote_stage/source-client.cert.pem"
"${SSH[@]}" "$REMOTE" bash -s -- "$remote_stage" "$SERVICE_USER" "$SERVICE_GROUP" <<'REMOTE_SCRIPT'
set -euo pipefail
stage="$1"
owner="$2"
group="$3"
install -d -o "$owner" -g "$group" -m 0750 /etc/obstaclebridge/telemetry-client
install -d -o "$owner" -g "$group" -m 0700 /var/lib/obstaclebridge/telemetry-client
install -o "$owner" -g "$group" -m 0600 "$stage/source-client.key.pem" /etc/obstaclebridge/telemetry-client/client.key.pem.new
install -o "$owner" -g "$group" -m 0644 "$stage/source-client.cert.pem" /etc/obstaclebridge/telemetry-client/client.cert.pem.new
install -o "$owner" -g "$group" -m 0644 "$stage/source-ca.cert.pem" /etc/obstaclebridge/telemetry-client/collector-ca.cert.pem.new
mv -f /etc/obstaclebridge/telemetry-client/client.key.pem.new /etc/obstaclebridge/telemetry-client/client.key.pem
mv -f /etc/obstaclebridge/telemetry-client/client.cert.pem.new /etc/obstaclebridge/telemetry-client/client.cert.pem
mv -f /etc/obstaclebridge/telemetry-client/collector-ca.cert.pem.new /etc/obstaclebridge/telemetry-client/collector-ca.cert.pem
REMOTE_SCRIPT

echo "Python uploader TLS material deployed to $REMOTE; restart the uploader only when ready."
