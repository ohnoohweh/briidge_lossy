#!/usr/bin/env bash
# Deploy collector TLS material over SSH. It never deploys the CA private key.
# Example:
# HOST=collector.example.net bash scripts/deploy_telemetry_peer_server.sh

set -euo pipefail

PORT="${PORT:-18022}"
USER_NAME="${USER_NAME:-root}"
HOST="${HOST:?set HOST to the peer-server address}"
CA_CERT="${CA_CERT:-/var/lib/obstaclebridge/telemetry-ca/ca.cert.pem}"
SERVER_KEY="${SERVER_KEY:-/etc/obstaclebridge/telemetry/server.key.pem}"
SERVER_CERT="${SERVER_CERT:-/etc/obstaclebridge/telemetry/server.cert.pem}"
SERVICE_USER="${SERVICE_USER:-obstaclebridge}"
SERVICE_GROUP="${SERVICE_GROUP:-${SERVICE_USER}}"
SSH_IDENTITY="${SSH_IDENTITY:-}"
LOCAL_SUDO="${LOCAL_SUDO:-sudo}"
REMOTE_SUDO="${REMOTE_SUDO:-sudo}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"

echo "Checking local telemetry material (local sudo may be requested)."
for source_file in "$CA_CERT" "$SERVER_KEY" "$SERVER_CERT"; do
    [[ -f "$source_file" ]] || "$LOCAL_SUDO" test -f "$source_file" || {
        echo "missing regular file: $source_file" >&2
        exit 2
    }
done
[[ "$SERVICE_USER" =~ ^[A-Za-z0-9_.-]+$ && "$SERVICE_GROUP" =~ ^[A-Za-z0-9_.-]+$ ]] || {
    echo "SERVICE_USER and SERVICE_GROUP may contain only letters, numbers, dot, underscore, and hyphen" >&2
    exit 2
}

[[ "$REMOTE_SUDO" =~ ^[A-Za-z0-9_./-]+$ ]] || { echo "REMOTE_SUDO must be a command path" >&2; exit 2; }
SSH=(ssh -p "$PORT" -o "ConnectTimeout=$CONNECT_TIMEOUT" -o ConnectionAttempts=1)
SSH_TTY=(ssh -tt -p "$PORT" -o "ConnectTimeout=$CONNECT_TIMEOUT" -o ConnectionAttempts=1)
SCP=(scp -P "$PORT" -o "ConnectTimeout=$CONNECT_TIMEOUT" -o ConnectionAttempts=1)
if [[ -n "$SSH_IDENTITY" ]]; then
    SSH+=(-i "$SSH_IDENTITY")
    SSH_TTY+=(-i "$SSH_IDENTITY")
    SCP+=(-i "$SSH_IDENTITY")
fi
REMOTE="${USER_NAME}@${HOST}"

echo "Preparing protected local telemetry material."
local_stage="$(mktemp -d "${TMPDIR:-/tmp}/obstaclebridge-telemetry-server.XXXXXX")"
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
copy_source "$SERVER_KEY" source-server.key.pem
copy_source "$SERVER_CERT" source-server.cert.pem

echo "Connecting to $REMOTE on SSH port $PORT and acquiring remote privilege."
"${SSH_TTY[@]}" "$REMOTE" "$REMOTE_SUDO" -v
echo "Creating private remote staging directory."
remote_stage="$("${SSH[@]}" "$REMOTE" 'umask 077; mktemp -d /tmp/obstaclebridge-telemetry-server.XXXXXX')"

echo "Uploading collector TLS material."
"${SCP[@]}" "$local_stage/source-ca.cert.pem" "$REMOTE:$remote_stage/source-ca.cert.pem"
"${SCP[@]}" "$local_stage/source-server.key.pem" "$REMOTE:$remote_stage/source-server.key.pem"
"${SCP[@]}" "$local_stage/source-server.cert.pem" "$REMOTE:$remote_stage/source-server.cert.pem"
echo "Installing collector TLS material."
"${SSH_TTY[@]}" "$REMOTE" "stty -echo; exec $REMOTE_SUDO bash -s -- '$remote_stage' '$SERVICE_USER' '$SERVICE_GROUP'" <<'REMOTE_SCRIPT'
set -euo pipefail
stage="$1"
owner="$2"
group="$3"
if ! getent group "$group" >/dev/null; then
    groupadd --system "$group"
fi
if ! id -u "$owner" >/dev/null 2>&1; then
    useradd --system --no-create-home --gid "$group" --shell /usr/sbin/nologin "$owner"
fi
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
