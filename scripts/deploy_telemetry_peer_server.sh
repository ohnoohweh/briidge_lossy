#!/usr/bin/env bash
# Deploy collector TLS material over SSH. It never deploys the CA private key.
# Example:
# HOST=collector.example.net CA_CERT=/safe/ca.cert.pem SERVER_KEY=/safe/server.key.pem \
# SERVER_CERT=/safe/server.cert.pem bash scripts/deploy_telemetry_peer_server.sh

set -euo pipefail

PORT="${PORT:-18022}"
USER_NAME="${USER_NAME:-root}"
HOST="${HOST:?set HOST to the peer-server address}"
CA_CERT="${CA_CERT:?set CA_CERT to the public client-CA certificate PEM}"
SERVER_KEY="${SERVER_KEY:?set SERVER_KEY to the collector private-key PEM}"
SERVER_CERT="${SERVER_CERT:?set SERVER_CERT to the collector certificate PEM}"
SERVICE_USER="${SERVICE_USER:-obstaclebridge}"
SERVICE_GROUP="${SERVICE_GROUP:-${SERVICE_USER}}"
SSH_IDENTITY="${SSH_IDENTITY:-}"

for source_file in "$CA_CERT" "$SERVER_KEY" "$SERVER_CERT"; do
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

remote_stage="$("${SSH[@]}" "$REMOTE" 'umask 077; mktemp -d /tmp/obstaclebridge-telemetry-server.XXXXXX')"
cleanup() {
    "${SSH[@]}" "$REMOTE" "rm -rf -- '$remote_stage'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${SCP[@]}" "$CA_CERT" "$REMOTE:$remote_stage/source-ca.cert.pem"
"${SCP[@]}" "$SERVER_KEY" "$REMOTE:$remote_stage/source-server.key.pem"
"${SCP[@]}" "$SERVER_CERT" "$REMOTE:$remote_stage/source-server.cert.pem"
"${SSH[@]}" "$REMOTE" bash -s -- "$remote_stage" "$SERVICE_USER" "$SERVICE_GROUP" <<'REMOTE_SCRIPT'
set -euo pipefail
stage="$1"
owner="$2"
group="$3"
install -d -o "$owner" -g "$group" -m 0750 /etc/obstaclebridge/telemetry
install -d -o "$owner" -g "$group" -m 0700 /var/lib/obstaclebridge/telemetry-ingest
install -o "$owner" -g "$group" -m 0600 "$stage/source-server.key.pem" /etc/obstaclebridge/telemetry/server.key.pem.new
install -o "$owner" -g "$group" -m 0644 "$stage/source-server.cert.pem" /etc/obstaclebridge/telemetry/server.cert.pem.new
install -o "$owner" -g "$group" -m 0644 "$stage/source-ca.cert.pem" /etc/obstaclebridge/telemetry/client-ca.cert.pem.new
mv -f /etc/obstaclebridge/telemetry/server.key.pem.new /etc/obstaclebridge/telemetry/server.key.pem
mv -f /etc/obstaclebridge/telemetry/server.cert.pem.new /etc/obstaclebridge/telemetry/server.cert.pem
mv -f /etc/obstaclebridge/telemetry/client-ca.cert.pem.new /etc/obstaclebridge/telemetry/client-ca.cert.pem
if [[ ! -e /var/lib/obstaclebridge/telemetry-ingest/revocations.json ]]; then
    printf '%s\n' '{"serials":[]}' > /var/lib/obstaclebridge/telemetry-ingest/revocations.json
    chown "$owner:$group" /var/lib/obstaclebridge/telemetry-ingest/revocations.json
    chmod 0600 /var/lib/obstaclebridge/telemetry-ingest/revocations.json
fi
REMOTE_SCRIPT

echo "Collector TLS material deployed to $REMOTE; restart the supervised collector only when ready."
