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

### Swift/macOS implementation sequence

The Apple source tree has runtime-health snapshots and local `NSLog` calls, but
does not expose the private UDP logging protocol or the HTTPS telemetry
reference. `ObstacleBridgeTelemetry` in the portable Swift core provides the
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

The remaining packages bring macOS and iOS from the contract to an isolated
telemetry path. A package remains here only until its definition of done has
evidence in the repository; completed capabilities move to the status section.

S3 has an in-progress shared upload policy that accepts only HTTPS endpoints,
forms one identity-scoped batch at a time, enforces a byte budget, validates
acknowledgement ranges before deleting spool data, and schedules jittered
backoff after a failure. The Apple transport presents only a supplied enrolled
`SecIdentity` for a client-certificate challenge and leaves normal server-trust
validation enabled. The macOS status snapshot exposes only whether telemetry,
an HTTPS endpoint, and a Keychain identity label are configured; it never
returns the identity label, endpoint path, credentials, or event data.
On Apple platforms it also reports a boolean Keychain lookup result for the
configured label without returning the identity or certificate details.
Controlled-collector coverage, runtime invocation, and restart/network-failure
qualification remain required.

| Package | Scope | Definition of done |
| --- | --- | --- |
| S3 — mTLS uploader | Add one low-priority Swift uploader with TLS-only HTTPS, client credentials, bounded batches, one in-flight request, acknowledgement handling, timeout, jittered backoff, and byte budget. | A controlled local collector verifies mTLS and acknowledgement semantics; offline, timeout, TLS failure, retryable response, duplicate acknowledgement, and restart tests keep the spool bounded and preserve the runtime path. |
| S4 — macOS runtime and evidence | Configure the macOS host runner through explicit telemetry settings, emit redacted lifecycle/load/bridge evidence outside forwarding callbacks, and expose redacted local telemetry status through authenticated Admin Web. | Configuration parsing, disabled-by-default behavior, event redaction, Admin authorization, bounded status lookup, and overload isolation are covered by component tests. |
| S5 — Packet Tunnel integration | Connect the provider to the shared producer/spool using the app-group container, recording lifecycle and load evidence without payloads or callback I/O. | Device or simulator evidence covers start, readiness, reassert, stop, fatal path, restart recovery, and saturated packet flow; the extension completes stop handling promptly when telemetry storage or upload fails. |

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
