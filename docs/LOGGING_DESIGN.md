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

### Python hardened reference implementation sequence

Python is the required reference implementation. Swift/iOS work does not begin
until Python packages P0 through P7 are complete and P8 has passed its release
gate. These packages create an independently deployable Internet telemetry
path; they do not modify, expose, or upgrade the private UDP receiver.

Delivered local foundation: `bridge_telemetry.py` provides the P0 `telemetry/v1`
allowlist parser/serializer, canonical vector, bounded P1 producer, P2 atomic
local spool, a P3 TLS-required local-reference ingest process with durable
batch acknowledgement, P4 local mTLS issuance plus revocation verification,
P5 single-flight mTLS uploader with acknowledgement-scoped spool removal, and
P6 durable replay rejection plus per-identity/source admission buckets.
The P0 security review, P1 benchmark/concurrency evidence, P2 fault-injection
qualification, P3–P6 operations qualification, enrollment/rotation governance,
P5 network-policy/budget qualification, and P6 adversarial/load qualification
remain required acceptance work; P7–P8 remain unimplemented.

| Package | Concrete deliverable | Definition of done |
| --- | --- | --- |
| P0 — freeze security contract | Versioned `telemetry/v1` event and batch schema, threat model, redaction allowlist, size limits, priority classes, error taxonomy, and test vectors in `docs/` plus Python parser/serializer. | Security review signs the threat model; schema vectors round-trip deterministically; unknown fields, oversized values, secrets, invalid timestamps, duplicate sequence numbers, and malformed encodings are rejected; no payload-bearing field is representable. |
| P1 — bounded Python producer | A `TelemetryEmitter` with a nonblocking `emit()` API, fixed-capacity in-memory queue, monotonic counters, drop accounting, and runtime lifecycle/load probes. The existing logging handler may mirror only allowlisted records into it. | Microbenchmark proves the hot path performs no DNS, disk, network, lock contention beyond its bounded queue operation, or unbounded allocation; a full queue drops according to documented priority; producer/transport exceptions never reach bridge or TUN callbacks; focused tests cover saturation and concurrent emitters. |
| P2 — crash-safe local spool | A private-permission, rotating Python spool with atomic segment commit, bounded total bytes/files, checksummed envelopes, recovery scan, and oldest-low-priority-first eviction. | Power-loss/partial-write and corrupt-segment tests recover every committed event at most once locally and never block producer progress; full-disk, permission failure, and rotation failure become counters/health events; spool limits are enforced under stress. |
| P3 — hardened HTTPS ingest service | A separately runnable Python collector process with `POST /v1/telemetry/batches`, strict TLS configuration, request/body/time limits, schema validation, durable accepted-batch queue, and health/metrics endpoint. No log retrieval endpoint is public. | Plain HTTP is refused; malformed/oversized/compressed-bomb requests are rejected within configured CPU/memory bounds; accepted batches are durably acknowledged only after queue commit; restart recovery preserves queue integrity; integration tests exercise TLS, IPv4/IPv6, and collector restart. |
| P4 — enrollment and client authentication | Per-installation credential model, enrollment service/CLI, mTLS certificate issuance or short-lived signed token issuance, scoped credentials, server-side revocation list, and dual-pin rotation configuration. | Anonymous ingest, expired credential, wrong scope, revoked credential, and invalid chain are rejected; valid credential acceptance is audited; credential and pin rotation succeeds with overlap then rejects retired material; private keys never appear in logs, config dumps, or Admin APIs. |
| P5 — authenticated uploader | One Python uploader worker reading the spool, batching by byte/count/time cap, using TLS-authenticated HTTPS, idempotency key and sequence range, one in-flight upload, timeout, jittered backoff, and network/byte budgets. | Offline, DNS failure, TLS failure, slow collector, 429/5xx, duplicate acknowledgement, and restart tests preserve bounded behavior and eventual accepted delivery when connectivity returns; no retry executes on the logging or packet path; upload acknowledgement advances the spool only for the accepted range. |
| P6 — replay, quota, and abuse controls | Server replay store, per-credential/source token buckets, concurrency caps, deadline propagation, structured reject reasons, and collector-side overload shedding. | Replay, out-of-window clock, forged identity, credential spray, request flood, slow-client, and response-amplification tests show bounded CPU/memory and correct rejection metrics; one abusive identity cannot prevent a valid identity from ingesting within its quota. |
| P7 — operator evidence plane | Authenticated Admin/CLI read model for local spool and collector status: last accepted sequence, last upload attempt/acknowledgement, drops by reason, queue/spool occupancy, and lifecycle timeline. | Read access uses existing authenticated admin policy or separate collector auth; responses are bounded/redacted; an unavailable collector is reported as data; UI/API tests prove no secret or payload disclosure and no blocking call on the bridge runtime loop. |
| P8 — release qualification | Reproducible deployment, configuration reference, key/pin rotation and incident runbooks, metrics/alerts, retention job, privacy review, external security test, and soak/load harness. | Sustained overload and fault-injection tests demonstrate bridge/TUN throughput and latency stay within agreed baseline tolerance while telemetry is continuously rejected, delayed, or unavailable; security review and operational owner approve production exposure; rollback and credential-revocation drills succeed. |

P0–P2 are local-only and safe to develop without Internet exposure. P3–P8 use a
non-production collector and test credentials until P8 is complete. The first
iOS implementation package starts only after P8 and reuses the frozen P0 wire
schema, P2 spool semantics, P4 enrollment model, and P5 acknowledgement rules.

### Open measures and definition of done

No public deployment is permitted until every applicable DoD is met.

| Work package | Definition of done |
| --- | --- |
| Extension instrumentation | Swift provider emits the redacted lifecycle, heartbeat, load, queue/drop, and fatal-error schema from a bounded non-packet-callback path. Tests prove secret exclusion and no packet-flow delay under a saturated diagnostic path. |
| Crash-safe spool | Bounded, rotating, corruption-tolerant app-group spool survives termination and is read after restart. Tests cover partial writes, full storage, repeated launch, and eviction. |
| Authenticated ingest | HTTPS service accepts only authenticated, schema-validated, size-limited batches. Enrollment, credential/pin rotation, revocation, replay rejection, audit logging, integration tests, and security review are complete. |
| iOS uploader | One low-priority shared-container uploader resumes the spool with backoff/jitter and network-cost policy. Device coverage includes termination, offline-to-online, VPN up/down, cellular, and Low Data Mode; it is not treated as immediate last-gasp delivery. |
| Abuse resistance | Adversarial/load tests prove quotas, parser bounds, replay handling, no unauthenticated query/reflection, overload shedding, and isolation from collector/storage. SLOs define accepted loss and ingest latency. |
| Correlation | UI/API shows session timeline, last heartbeat, last upload acknowledgement, spool drops, provider stop reason, and ingest acceptance/rejection reason without secrets. A high-load qualification reproduces the suspected loss class and preserves classifying pre-loss evidence. |
| Privacy/operations | Data inventory, deletion/retention policy, access controls, redaction tests, key/pin rotation runbook, kill switch, rollback, monitoring, and on-call alerting are reviewed and exercised. |

The iOS work packages remain follow-on work after the Python reference release;
they are not an alternative path to public deployment. The existing UDP sender
remains for trusted local/private-network diagnostics.
A future encrypted UDP mode, if needed, must meet the same enrollment,
authenticated-encryption, anti-replay, anti-amplification, rate-limit,
key-rotation, and independent security-review DoD; it is not a shortcut around
the HTTPS ingest work.

## Compatibility and remaining work

Existing logging CLI options and default local behavior are unchanged. The UDP
wire format is versioned (`v=1`) but is a private observability interface,
not an overlay protocol or Python/Swift behavior surface. The Swift/iOS
runtime does not implement the private UDP sender/receiver pair or the public
HTTPS telemetry design; the iOS work packages above are its required parity and
hardening plan.
