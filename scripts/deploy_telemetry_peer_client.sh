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
LOCAL_SUDO="${LOCAL_SUDO:-sudo}"

for source_file in "$CA_CERT" "$CLIENT_KEY" "$CLIENT_CERT"; do
    [[ -f "$source_file" ]] || "$LOCAL_SUDO" test -f "$source_file" || {
        echo "missing regular file: $source_file" >&2
        exit 2
    }
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

local_stage="$(mktemp -d "${TMPDIR:-/tmp}/obstaclebridge-telemetry-client.XXXXXX")"
chmod 0700 "$local_stage"
remote_stage=""
cleanup() {
    if [[ -n "$remote_stage" ]]; then
        "${SSH[@]}" "$REMOTE" "rm -rf -- '$remote_stage'" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$local_stage"
}
trap cleanup EXIT
copy_source() {
    local source_file="$1"
    local staged_name="$2"
    if [[ -r "$source_file" ]]; then
        install -m 0600 "$source_file" "$local_stage/$staged_name"
    else
        "$LOCAL_SUDO" install -m 0600 -o "$(id -u)" -g "$(id -g)" "$source_file" "$local_stage/$staged_name"
    fi
}
copy_source "$CA_CERT" source-ca.cert.pem
copy_source "$CLIENT_KEY" source-client.key.pem
copy_source "$CLIENT_CERT" source-client.cert.pem

remote_stage="$("${SSH[@]}" "$REMOTE" 'umask 077; mktemp -d /tmp/obstaclebridge-telemetry-client.XXXXXX')"

"${SCP[@]}" "$local_stage/source-ca.cert.pem" "$REMOTE:$remote_stage/source-ca.cert.pem"
"${SCP[@]}" "$local_stage/source-client.key.pem" "$REMOTE:$remote_stage/source-client.key.pem"
"${SCP[@]}" "$local_stage/source-client.cert.pem" "$REMOTE:$remote_stage/source-client.cert.pem"
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
