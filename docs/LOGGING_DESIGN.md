# Logging Design

## Purpose

ObstacleBridge logging is diagnostic data. It must not delay packet forwarding,
connection lifecycle work, TUN I/O, or the main event loops. The normal local
logging configuration remains available for simple deployments. For isolated,
high-volume, or multi-host operation, the runtime can send records to a
dedicated logging process using lossy UDP.

## Runtime roles

```text
bridge / helper / remote bridge
        |
        | one non-blocking UDP datagram per log record
        v
standalone log receiver -> local stdout, file rotation, and Admin log ring
```

## Current runtime boundary

The bridge, ChannelMux, Admin Web, and TUN helper have not been replaced by a
single IP logging service. Default Python logging still writes to its local
sinks. Python can optionally send ordinary log records to the independent
private UDP receiver shown above. Apple does not implement that UDP protocol;
it records bounded telemetry health/lifecycle events to its private spool and,
when enabled and provisioned, uploads batches through HTTPS.

`telemetry_endpoint` is already the client-side remote-address option. It is a
complete HTTPS URL, including the port and `/v1/telemetry/batches` path. For a
Python client and collector on the same machine, it may be
`https://127.0.0.1:18443/v1/telemetry/batches`. On an iPhone,
`127.0.0.1` means the phone itself, not the Mac or Python peer; the endpoint
must therefore name the collector host. The collector currently starts as a
separate Python service, not as part of a peer bridge process.

The sender is configured with `--log-udp-target HOST:PORT`. Combining it with
`--log-udp-only` removes local stdout, file, stderr-mirror, and Admin-ring
handlers from the application process; the only installed handler is the UDP
sender. `--log-udp-only` has that effect only when a target is configured; a
missing target leaves the normal local sinks active. Start a receiver on the
logging host with:

```bash
python -m obstacle_bridge.bridge_logging_ipc --bind 0.0.0.0:15140 \
  --log-file /var/log/obstaclebridge/bridge.log --file-level DEBUG
```

Each runtime then uses, for example:

```bash
ObstacleBridge --log-udp-target logger.example:15140 --log-udp-only
```

The receiver is intentionally an independent process. Its output and rotation
configuration use the established logging options, so a failed or restarted
receiver does not require a bridge restart.

### Admin Web log view

When `--log-udp-only` is enabled, `/api/logs` uses a separate bounded UDP
request/reply exchange with the receiver instead of the bridge's local ring.
The Admin-side query target defaults to `--log-udp-target`; use
`--log-admin-udp-target HOST:PORT` when the receiver's query endpoint differs.
It has a fixed 150 ms maximum wait, no retry, and no fallback I/O. A missing,
slow, malformed, or restarted receiver returns a successful Admin API response
with an empty `lines` array, `source: "remote_udp"`,
`logger_available: false`, and `logger_error: "logger unavailable"`.

The receiver answers from its own bounded log ring. Query/reply shares the
receiver's UDP port but uses explicit versioned `logs.query` and `logs.reply`
messages; ordinary log records remain one-way. The receiver bounds a reply to
one datagram and discards oldest lines if needed. Admin requests therefore
cannot reach the runtime's packet path or make the remote logger a dependency.

## Unified IP logging delivery plan

This plan replaces direct process-local operational logging with a dedicated
logging service while retaining a local-development mode. It is separate from
the bounded HTTPS telemetry stream: ordinary log records can contain richer
diagnostic text and therefore use a private-network transport until a later
public-safe log schema is approved. The collector address is a `host:port`
target for the IP logging protocol. `127.0.0.1` always means a collector on the
same operating-system host; a remote collector needs its routable name or IP.

### Python first

| Package | Scope | Definition of done |
| --- | --- | --- |
| UL1 — IP logging contract and configuration | Define one versioned, bounded IP logging record, health/status response, and configuration vocabulary. Producer options are `logging_delivery` (`local` or `ip`), `logging_server_target` (`host:port`), and `logging_server_required` (default `false`). Collector options are `logging_server_bind`, `logging_server_port`, storage settings, and an explicit enable flag. | Parser, saved configuration, and Admin Web show the same values. Invalid targets disable IP delivery rather than blocking startup. `127.0.0.1:port` is accepted only as a same-host target; no hidden peer-address inference exists. |
| UL2 — standalone Python logging service | Replace the ad-hoc receiver process with a managed, bounded Python logging service that owns its UDP/IP listener, rotation, recent-log ring, and status counters. It remains a separate process from the bridge and TUN helper. | Starting, stopping, unavailable storage, malformed datagrams, full rings, and listener restart leave every bridge process healthy. The service exposes a bounded local status response and never accepts an Admin-Web or overlay connection on its logging port. |
| UL3 — Python producer migration | Route Python bridge, ChannelMux, Admin Web, and TUN-helper process logs through one nonblocking client handler when `logging_delivery=ip`. Remove direct stdout/file/ring handlers from those producers in this mode; keep `local` mode for development. | Saturation, server loss, DNS/setup failure, and send errors only increment local drop counters. Packet forwarding, helper control, Admin API responses, and shutdown remain within their existing latency limits. A source-level and runtime test proves that no migrated Python component writes a direct logging sink in IP mode. |
| UL4 — Python operator view and peer deployment | Make the logging service’s bind/port and each client target visible in Admin Web, show connection/drop/last-send health without log payloads, and provide a peer-server deployment example. | A local client reaches `127.0.0.1:port`; a remote client reaches a peer-server logging host; Admin Web can report an unavailable logger without calling a bridge packet path. Operator instructions distinguish the logging-server address from overlay peer and Admin-Web addresses. |
| UL5 — Python failure and load qualification | Qualify the complete Python service and migrated producers under log floods, service restart, bad target, slow disk, and TUN-helper restart. | Measured bridge throughput and latency stay within an agreed baseline while the logger drops or restarts. The test report records producer drops, collector loss, recovery, and bounded Admin status behavior. |

### Swift, iOS, macOS, and Linux second

| Package | Scope | Definition of done |
| --- | --- | --- |
| UL6 — portable Swift client contract | Implement the UL1 wire contract and bounded nonblocking client in Swift Core, with the same field limits, priority/drop policy, and target parsing as Python. | Shared vectors pass in Python and Swift. Swift emission performs no DNS, file I/O, retry, or wait on a bridge/packet callback. |
| UL7 — macOS and Linux producers | Migrate macOS host-runner, macOS helper, and Linux Swift runtime operational logging to the Swift IP client. Provide the same `logging_delivery` and `logging_server_target` configuration fields. | Each runtime sends bounded records to the Python logging service in local and remote cases. Service loss leaves forwarding and helper lifecycle operational; parity tests compare Python and Swift status/drop behavior. |
| UL8 — iOS Packet Tunnel producer | Migrate iOS lifecycle, bridge, and bounded load evidence to the Swift IP client without packet-flow callback I/O. For an iPhone, a target must be remote unless an actual on-device collector exists. | Physical-device tests send records to a controlled Python logging service, cover collector loss/recovery and tunnel stop, and show no packet-flow latency regression. No iOS configuration maps loopback to a Mac or peer server. |
| UL9 — cross-platform qualification and retirement | Qualify mixed Python/Swift producers against one logging service and retire direct production sinks from migrated components. Keep a documented local-development mode only. | Python, macOS, Linux, and iOS produce compatible records and bounded status through one service. Migration tests prove no duplicate direct logs in IP mode, and operational runbooks cover collector upgrade, rollback, and failure isolation. |

## Delivery and performance contract

- A sender resolves and connects its UDP socket once during startup. `emit()`
  only serializes a bounded record and performs a non-blocking `send`.
- `BlockingIOError`, socket errors, receiver loss, malformed records, and
  receiver-side sink failures are contained. The sender increments its local
  dropped-record counter and returns; it does not retry, queue, wait, or print
  an error through logging.
- Datagram loss, reordering, duplication, and receiver restarts are accepted.
  Logs are not an audit trail and do not provide delivery guarantees.
- Each record is JSON, not Python pickle. The receiver accepts only the
  versioned fields it needs to rebuild a `LogRecord`. Datagrams are bounded;
  oversized messages are truncated rather than fragmented.
- The sender does not do DNS lookups, file I/O, network reconnects, or remote
  acknowledgements on the logging call path. DNS resolution is a setup-time
  operation. Operators who need a completely fixed hot path should use a
  numeric receiver address.

`--log-udp-target` without `--log-udp-only` mirrors records to both UDP and
the existing local handlers. This is useful for migration but preserves the
local handler's normal latency characteristics. The isolation guarantee is the
explicit `--log-udp-only` deployment mode.

## Scope and security

UDP ingestion is unauthenticated and encrypted nowhere by this component.
Bind a receiver to loopback for same-host IPC, or place remote logging on a
trusted private network/VPN with firewall rules. Do not expose its UDP port to
untrusted networks: arbitrary peers could inject misleading log lines or
consume receiver capacity.

The Admin query protocol has the same trust boundary. Its responses contain
recent diagnostic text, so bind it only to loopback or a trusted private
network/VPN and protect the UDP port with firewall rules.

This design intentionally does not attempt reliable transport, backpressure,
central ordering, durable queuing, or remote administration. If those are
required, use a separate collector/agent outside the bridge runtime so its
health still cannot block packet processing.

## Public-Internet iOS Network Extension diagnostics

### Deployment boundary

An iOS Packet Tunnel Provider can be terminated under load without leaving a
useful app-process trace. The diagnostic system must distinguish an orderly
stop, provider cancellation, resource-pressure symptom, transport failure, and
a process that simply ceased making progress, without allocating, blocking, or
retrying from the packet-flow callback path.

The delivered UDP logging and Admin-query protocol is **not approved for public
Internet exposure**. It lacks sender authentication, confidentiality, replay
protection, admission control, and safe query authorization. A public listener
would allow injection, reflection, diagnostic disclosure, and resource
exhaustion. Firewalling alone is not an adequate control.

The public deployment target is a separate HTTPS telemetry ingest service, not
the UDP receiver. The extension writes compact redacted events to an app-group,
crash-safe rotating spool. A low-priority uploader batches that spool to HTTPS;
it is outside packet forwarding and may lose, defer, or abandon events without
changing tunnel behavior. The containing app owns spool recovery and
presentation after an extension restart or termination.

```text
PacketTunnelProvider fast path
    -> bounded redacted event buffer -> app-group rotating spool
    -> low-priority batch uploader -- HTTPS/TLS --> Internet ingest
```

Events include schema version, pseudonymous installation ID, session ID,
monotonic/wall time, lifecycle state, tunnel start/readiness/stop reason,
transport selection, packet/read-write counters, queue/drop high-water marks,
and a bounded heartbeat. They must never include payloads, keys, PSKs, cookies,
authorization headers, or raw peer addresses without a separately approved
privacy policy. The app preserves the previous provider session's final spool
segment and displays `last_heartbeat`, `last_event`, and upload state. A
missing final event is evidence of unexpected loss, not proof of a cause.

Apple's [provider lifecycle](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel%28with%3Acompletionhandler%3A%29)
requires a prompt `stopTunnel` completion, and an unrecoverable provider error
should be recorded before cancellation when time permits. Background upload is
eventual delivery, not an immediate last-gasp guarantee: it is
[system-scheduled](https://developer.apple.com/documentation/Foundation/downloading-files-in-the-background).
An app-extension background `URLSession` also requires
[app-group shared-container coordination](https://developer.apple.com/documentation/foundation/urlerror/code/backgroundsessionrequiressharedcontainer)
and supports HTTPS, not custom UDP transport.

### Required hardening measures

| Control | Required design |
| --- | --- |
| Transport security | TLS 1.3, normal certificate validation, and production client authentication through mTLS device credentials or short-lived attested credentials. Pin with a controlled backup/rotation path. Never send diagnostic UDP directly over the Internet. |
| Identity, integrity, replay | Hardware-protected installation key where available; authenticated, rate-limited enrollment; expiring/revocable credentials. Each batch has installation/session identity, monotonic sequence range, nonce, and issued/expiry time. Ingest rejects stale and replayed batches. |
| Privacy | Allowlist-only schema at client and server; secret/payload field rejection; pseudonymous identifiers; audited operator access, retention, and deletion. |
| Load isolation | Packet callbacks only update bounded counters. Spool and upload run on separate workers with capped batches, one in-flight request, jittered backoff, byte/day budget, and oldest-low-priority-first eviction. |
| Collector resilience | Request-size caps, per-identity/source token buckets, concurrency limits, bounded parsing, WAF/DDoS protection, durable queue before indexing, rejection metrics, and no unauthenticated query/reflection endpoint. |
| Network routing | Exclude telemetry from the VPN tunnel or use a tested management path so diagnostics do not recursively depend on the failed tunnel. Test DNS, IPv4/IPv6, captive portal, cellular, and Low Data Mode. |
| Failure evidence | Bounded heartbeat/counter snapshots plus markers around settings apply, start, reassert, stop, and fatal errors. Correlate last persisted provider event with iOS tunnel status and next restart. |
| Operations | Signed configuration and rollback for pins, credentials, schema, sampling, priorities, and kill switches. Alert on auth/replay failures, upload backlog, spool eviction, and ingest shedding. |

### Python reference status

The Python reference implementation supplies a complete local, testable
telemetry path for the public-Internet design. It is a reference and
pre-production qualification target, not an approval to expose a collector to
the Internet. It is separate from, and does not alter, the private UDP logging
receiver.

| Capability | Present implementation |
| --- | --- |
| Event contract | `telemetry/v1` has an allowlist-only parser/serializer, bounded fields and event size, priority classes, secret-bearing field rejection, and canonical vectors in `docs/TELEMETRY_V1_VECTORS.json`. |
| Producer and spool | `TelemetryEmitter` uses a fixed-capacity queue and nonblocking emission. `TelemetrySpool` writes bounded, checksummed atomic segments, recovers valid segments, quarantines corrupt ones, evicts lower-priority data first, and removes only acknowledged sequence ranges. |
| Ingest | `bridge_telemetry_ingest` accepts only TLS connections on `POST /v1/telemetry/batches`, validates batches before durable acceptance, and exposes only `/healthz`; it has no public log-query endpoint. |
| Authentication and replay | The reference credential CLI creates a local CA and scoped mTLS certificates, supports revocation, verifies the client identity against the installation ID, and persists replay sequence state. |
| Uploader | `bridge_telemetry_uploader` performs single-flight mTLS HTTPS uploads with bounded batches, acknowledgement-scoped cleanup, timeout, jittered backoff, and a local byte budget. It is not on the logging, bridge, or packet path. |
| Admission control | The ingest reference applies bounded request parsing and local per-identity/source token buckets. Replayed or over-limit batches are rejected. |
| Operator evidence | `bridge_telemetry_status` and the authenticated Admin Web `/api/telemetry` endpoint expose bounded, redacted local spool status. The Admin endpoint times out its spool lookup and treats unavailable data as status, not an error for the bridge. |
| Local qualification | `python scripts/qualify_telemetry.py` exercises a saturated producer and reports bounded emission latency, capacity, and drops. It is a pre-qualification check only. |
| Runtime configuration | Python, macOS, and iOS expose exactly the same `telemetry` keys in their Admin configuration schema: `telemetry_enabled`, `telemetry_endpoint`, `telemetry_installation_id`, `telemetry_mtls_identity_label`, and `telemetry_spool_directory`. They are visible operational settings, not credential material. Python keeps the uploader process isolated from the bridge runtime; Apple resolves the identity label through Keychain. |

### Client-to-collector alignment

The telemetry endpoint is the common point where a peer client and a
peer-server-operated diagnostics service meet. An operator may host the
collector beside a bridge server, but it is a separate HTTPS collector process;
the peer bridge does not accept telemetry on its overlay or Admin Web ports.
Every client uses that same visible `telemetry_endpoint`, a unique visible
installation identifier, and its enrolled mTLS identity reference. The
collector trusts the corresponding client credentials and records the supplied
installation identifier with the bounded event batch.

The private UDP logger remains a Python-only trusted-network facility. A
Python client can target the independent UDP receiver running beside a peer
server, but neither iOS nor macOS uses that receiver and it is not suitable for
Internet diagnostics. Apple clients use the HTTPS collector endpoint instead.

### Telemetry credential generation, deployment, and storage

This section concerns the HTTPS telemetry collector, not the private UDP
logger.  The collector has a TLS **server** identity; every telemetry producer
has its own mTLS **client** identity.  The client-certificate common name must
equal that producer's `telemetry_installation_id`.  A distinct identity is
required for every installation, so revocation of one device does not disable
another device.

The reference helper creates a local CA and client certificate/key pair:

```text
python -m obstacle_bridge.bridge_telemetry_credentials init-ca ...
python -m obstacle_bridge.bridge_telemetry_credentials issue-client \
  --installation-id <installation-id> ...
```

For the Linux Python-to-Python deployment, the repository also supplies three
non-overwriting PEM-generation scripts.  Each private key is created with mode
`0600`; the target directory is created with mode `0700`.

```text
python scripts/generate_telemetry_ca.py \
  --common-name ObstacleBridge-Telemetry-CA \
  --key-out /var/lib/obstaclebridge/telemetry-ca/ca.key.pem \
  --cert-out /var/lib/obstaclebridge/telemetry-ca/ca.cert.pem

python scripts/generate_telemetry_server_certificate.py \
  --ca-key /var/lib/obstaclebridge/telemetry-ca/ca.key.pem \
  --ca-cert /var/lib/obstaclebridge/telemetry-ca/ca.cert.pem \
  --key-out /etc/obstaclebridge/telemetry/server.key.pem \
  --cert-out /etc/obstaclebridge/telemetry/server.cert.pem

python scripts/generate_telemetry_client_certificate.py \
  --ca-key /var/lib/obstaclebridge/telemetry-ca/ca.key.pem \
  --ca-cert /var/lib/obstaclebridge/telemetry-ca/ca.cert.pem \
  --installation-id linux-client-01 \
  --key-out /var/lib/obstaclebridge/telemetry-client/client.key.pem \
  --cert-out /var/lib/obstaclebridge/telemetry-client/client.cert.pem
```

The server-certificate script asks separately for an optional FQDN and optional
static IPv4 and IPv6 addresses; Enter omits any value. Every supplied value is
included in the certificate subject alternative name extension, so one
collector certificate works for direct IPv4, direct IPv6, and FQDN access.
For automated deployment, provide one or more of `--fqdn`, `--ipv4`, and
`--ipv6` instead of answering the prompts.

The CA private key belongs in an offline, root-owned issuance location, such
as `/var/lib/obstaclebridge/telemetry-ca`, and is not deployed to either the
collector or client service.  The collector server certificate/key belongs in
its root-owned configuration directory, such as
`/etc/obstaclebridge/telemetry`; the collector receives that pair, the public
client-CA certificate, and its revocation-list path.  The client certificate,
key, and public collector-CA certificate belong in a directory owned only by
the separate uploader account, such as
`/var/lib/obstaclebridge/telemetry-client`.  A client private key is never put
in `ObstacleBridge.cfg`, the app Documents directory, the iOS App Group, a log
spool, or an Admin response.

#### Linux Python reference artefact placement

The following is the required artefact inventory for the Python peer-server /
Python peer-client deployment. `ca.cert.pem`, `client-ca.cert.pem`, and
`collector-ca.cert.pem` contain the same public CA certificate in this
single-CA reference topology. They are deliberately named by their local
purpose, rather than copying the CA private-key directory to runtime hosts.

**Safe storage / certificate-issuing entity (offline, root-owned)**

```text
/var/lib/obstaclebridge/telemetry-ca/ca.key.pem       CA private key; issuance only; never deployed
/var/lib/obstaclebridge/telemetry-ca/ca.cert.pem      CA public certificate; source for runtime copies
```

**Peer server instance (Python collector)**

```text
/etc/obstaclebridge/telemetry/server.key.pem          collector TLS private key
/etc/obstaclebridge/telemetry/server.cert.pem         collector TLS public certificate
/etc/obstaclebridge/telemetry/client-ca.cert.pem      trusted public CA for mTLS client validation
/var/lib/obstaclebridge/telemetry-ingest/revocations.json  revoked client-certificate serials
/var/lib/obstaclebridge/telemetry-ingest/replay.json       accepted installation/session sequence state
/var/lib/obstaclebridge/telemetry-ingest/event-*.json      accepted telemetry spool segments
```

Run `bridge_telemetry_ingest` with the server certificate/key, the
`client-ca.cert.pem` copy, the revocation file, and the
`telemetry-ingest` directory as its spool directory. The collector account
must read only the TLS material it needs and write only its ingest-state
directory; it must not have the CA private key.

**Peer client instance (Python telemetry uploader)**

```text
/etc/obstaclebridge/telemetry-client/client.key.pem   client mTLS private key
/etc/obstaclebridge/telemetry-client/client.cert.pem  client mTLS public certificate
/etc/obstaclebridge/telemetry-client/collector-ca.cert.pem  trusted public CA for the collector
/var/lib/obstaclebridge/telemetry-client/event-*.json       pending telemetry spool segments
```

Construct `TelemetryUploader` with the client certificate/key and the
`collector-ca.cert.pem` copy; configure its `TelemetrySpool` with
`/var/lib/obstaclebridge/telemetry-client`. The uploader account must have no
access to the collector private key, collector ingest state, or CA private
key. The peer bridge process needs none of these private keys.

The SSH deployment scripts use a private remote staging directory, install
only the named role material with restrictive ownership/modes, and never copy
`ca.key.pem`. They use the project VPS default SSH account `root`, acquire
remote `sudo` before changing protected target paths, and create the dedicated
non-login `obstaclebridge` service user/group when it is absent. They use the
project VPS SSH default port `18022`. Override `USER_NAME`, `PORT`,
`REMOTE_SUDO`, `CONNECT_TIMEOUT`, `SERVICE_USER`, `SERVICE_GROUP`, and
`SSH_IDENTITY` as needed. They do not start or restart a bridge, uploader, or
collector.

The scripts default to the generation paths listed above. A normal deployment
therefore needs only the remote host:

```text
HOST=<peer-server> bash scripts/deploy_telemetry_peer_server.sh
HOST=<peer-client> bash scripts/deploy_telemetry_peer_client.sh
```

Set `CA_CERT`, `SERVER_KEY`, `SERVER_CERT`, `CLIENT_KEY`, or `CLIENT_CERT`
only when the source material is intentionally stored elsewhere.

The default source directories are root-only. When the invoking user cannot
read one of those files, the scripts invoke local `sudo` to copy only that
named file into an owner-only temporary staging directory, use the invoking
user's SSH identity to transfer it, then remove the local and remote staging
directories. The remote-sudo preflight and final installation allocate a TTY
so a non-root SSH user can enter its remote sudo password on hosts that require
one; the installation disables TTY echo while it receives the scripted input.
Set `LOCAL_SUDO` when the local privilege command is not `sudo`.

| Deployment use case | Generation and deployment | Required storage boundary | Present state and deployment DoD |
| --- | --- | --- | --- |
| 1. Python peer server on Linux + Python peer client on Linux | Issue one client certificate whose common name is the client's installation ID. Deploy the collector server certificate/key and trusted client CA to the supervised `bridge_telemetry_ingest` service. Deploy the client certificate/key and collector CA only to the separate Python telemetry-uploader service account. | Collector key, client key, and revocation state are separate owner-only files/directories. The server key is readable only by the collector account; the client key only by the uploader account. The peer bridge process does not need either private key. | The reference credential CLI, collector, and `TelemetryUploader(cafile, certfile, keyfile)` support this layout. DoD: ownership/mode checks, service-manager credentials, expiry/rotation, revocation drill, and a successful mTLS upload with the bridge and collector in separate processes. |
| 2. Python peer server on Linux + Swift peer client on macOS | Issue one client certificate whose common name is the macOS installation ID. Import the certificate and private key into the macOS Keychain under the configured `telemetry_mtls_identity_label`; deploy only the endpoint, installation ID, and label in configuration. | The private key stays in a Keychain `SecIdentity`; no PEM file is read by the Swift uploader. The collector retains its Linux server key and trusts the issuing client CA. | Swift resolves a `SecIdentity` by label and uses it for URLSession mTLS. DoD: a documented signed/importable macOS identity deployment, a Keychain access check under the production app identity, a real upload, rotation with overlap, and revocation evidence. |
| 3. Python peer server on Linux + Swift peer client on iOS | Issue one client certificate whose common name is the iPhone installation ID. Synchronize the non-secret telemetry configuration from app Documents to the shared App Group, then install the client identity through a managed profile/MDM or an approved enrolment flow. | The extension reads configuration and keeps its telemetry spool in the App Group. It must obtain the private key as an extension-accessible Keychain `SecIdentity`; PEM, `.p12`, and private-key files must not be copied into Documents or the App Group. | Documents-to-App-Group configuration synchronization and App-Group spooling exist. The extension only looks up an already-installed identity by label; it has no identity import/enrolment workflow. DoD: deploy an extension-accessible identity on a physical iPhone, show `identity_available` in status, complete an mTLS batch upload, prove offline/restart recovery, rotation, revocation, and no extension latency regression. |

For the Apple cases, `telemetry_mtls_identity_label` is a visible operational
reference, not a secret and not a certificate file path.  A configuration
sync is sufficient for the endpoint and label but cannot make a private key
available to the Network Extension.  The identity deployment must be completed
before enabling telemetry; otherwise the extension safely leaves telemetry
inactive.

### Swift/macOS implementation status

The Apple source tree has runtime-health snapshots and local `NSLog` calls. It
does not expose the private UDP logging protocol or operate the Python
collector/helper processes. `ObstacleBridgeTelemetry` in the portable Swift core provides the
`telemetry/v1` event and batch contract. It applies the same field allowlist,
size limits, priority classes, and metadata validation as Python. Its Swift
tests load the canonical vector from `docs/TELEMETRY_V1_VECTORS.json`, exercise
event and batch round trips, and reject malformed, secret-bearing, empty, and
oversized values. The macOS build script and generated iOS project include the
source in their application and extension targets. `ObstacleBridgeTelemetryEmitter`
provides a fixed-capacity immediate-loss queue with low-priority eviction for
critical evidence. `ObstacleBridgeTelemetrySpool` provides private atomic
checksum segments, corruption quarantine, bounded priority-aware eviction, and
installation/session-scoped acknowledgement. Its tests cover saturation,
concurrent emission, corrupt recovery, capacity eviction, and unavailable
storage setup.

### Apple delivery state

The Apple implementation contains the shared bounded emitter, private spool,
single-flight HTTPS upload policy, URLSession mTLS transport, and dedicated
host-runner and Packet Tunnel queues. The queues create telemetry only after a
valid HTTPS endpoint, installation identifier, and Keychain identity are
available; they drain on a five-second timer outside service and packet-flow
work. Shutdown persists its final marker and cancels any request in progress.
The provider emits compact lifecycle and runtime-health evidence, including
heartbeat, memory, backlog, and drop counters.

The macOS host target builds successfully. No iPhone-to-collector transfer has
yet been observed. The Python bridge peer process is not a collector: an
operator must run `bridge_telemetry_ingest` as a separate HTTPS service, which
may be on the same host as a peer server but uses a distinct port. For a real
device transfer, the collector must trust the iPhone client certificate and
the certificate common name must equal `telemetry_installation_id`.
Physical-device validation is the next Apple-runtime evidence; a simulator is
not a qualification target for this work.

| Package | Scope | Definition of done |
| --- | --- | --- |
| S2 — collector topology and configuration | Provide the operational connection model before general log shipping: a supervised collector service on a Python peer host with explicit bind address, HTTPS port, storage directory, TLS server identity, client CA, and revocation source. Clients use one full `telemetry_endpoint`; no duplicated host/port knobs. | A local Python client reaches a loopback collector; a remote client reaches a collector on a named host and port; an iPhone never treats `127.0.0.1` as its peer host. The collector has no overlay/Admin-Web listener role, refuses plaintext and unauthenticated connections, and reports bounded health without event content. |
| S3 — controlled collector interoperability | Exercise the implemented Apple uploader against the Python reference collector on a controlled HTTPS endpoint. | A physical Apple client uploads a batch to `bridge_telemetry_ingest` with mTLS; its certificate common name and configured installation identifier match; the collector returns an accepted sequence; the client removes only that acknowledged range. Offline, timeout, TLS failure, retryable response, duplicate acknowledgement, and restart cases preserve the spool and runtime path. |
| S4 — macOS runtime and evidence | Configure the macOS host runner through explicit telemetry settings, emit redacted lifecycle/load/bridge evidence outside forwarding callbacks, and expose redacted local telemetry status through authenticated Admin Web. Keep endpoints, installation identifiers, identity labels, and spool locations visible; hide only actual credentials. | Configuration parsing, disabled-by-default behavior, event redaction, Admin authorization, bounded status lookup, and overload isolation are covered by component tests. A fresh-proof, local-only credential reveal flow covers each real credential consistently in Python, macOS, and iOS. |
| S5 — Packet Tunnel integration | Connect the provider to the shared producer/spool using the app-group container, recording lifecycle and load evidence without payloads or callback I/O. | Physical-device evidence covers start, readiness, reassert, stop, fatal path, restart recovery, and saturated packet flow; the extension completes stop handling promptly when telemetry storage or upload fails. |

### Residual work before public deployment

**Public-Internet deployment is not approved.** The remaining work is
operational and security qualification around the reference implementation;
none of it may be bypassed by exposing the UDP receiver.

| Residual work | Definition of done |
| --- | --- |
| Independent security review | A documented threat model and independent review cover schema/privacy boundaries, mTLS trust, replay, denial of service, operator access, and deployment topology; material findings are resolved or formally accepted by the security owner. |
| Production collector edge | Deploy a managed TLS edge with request/body/deadline/concurrency limits, WAF/DDoS protection, distributed rate limits, durable queue/storage, restricted health access, monitoring, and no retrieval/reflection endpoint. Exercise overload and failover. |
| Credential lifecycle | Replace local reference issuance with authenticated, rate-limited enrollment; define secure client-key storage, scoped issuance, audit trails, revocation propagation, expiry, overlapping server-pin rotation, and rollback. Prove normal rotation and emergency revocation in a drill. |
| Uploader policy | Persist and reset byte-budget accounting deliberately, define scheduling and network-cost rules, and qualify DNS, IPv4/IPv6, captive portal, cellular, Low Data Mode, TLS failure, slow/429/5xx responses, restart, and offline-to-online behavior without affecting bridge latency. |
| Abuse and persistence qualification | Test multi-instance and restart behavior, request floods, credential spray, slow clients, malformed/compressed inputs, storage failure, and replay after collector restart. Show that one abusive identity cannot prevent a valid identity from ingesting within its quota. |
| Privacy and operations | Approve data inventory, retention/deletion, pseudonymous-identifier handling, access control, audit policy, configuration signing, kill switch, alerts, runbooks, ownership, and on-call response. Exercise rollback and incident response. |
| Deployment performance gate | In a production-like environment, sustain telemetry rejection, delay, loss, and collector failure while measuring bridge/TUN throughput and latency against an agreed baseline. Preserve enough redacted lifecycle evidence to classify the suspected high-load provider-loss case. |

The existing UDP sender remains restricted to trusted local or private-network
diagnostics. A future encrypted UDP mode would still require authenticated
enrollment, authenticated encryption, replay and amplification protection,
rate limits, key rotation, and independent review; it is not a shortcut around
the HTTPS telemetry path.

## Compatibility and remaining work

Existing logging CLI options and default local behavior are unchanged. The UDP
wire format is versioned (`v=1`) but is a private observability interface, not
an overlay protocol or Python/Swift behavior surface. The Swift/iOS runtime
does not implement the private UDP sender/receiver pair or the HTTPS telemetry
reference; its implementation sequence is defined above.
