# Architecture

This document describes the main runtime components and how they contribute to the overall behavior of the project.

## Architectural layers

The current runtime can be understood in eight layers:

1. transport/session layer
2. peer-address protocol layer
3. secure-link layer
4. compression layer
5. reliability and framing layer
6. channel/service multiplexing layer
7. runner and process orchestration layer
8. admin web and observability layer

The peer-address protocol is a delivered transport-adjacent layer. It obtains the address observed by the connected peer before optional SecureLink processing, and does not change connection readiness. SecureLink remains a delivered runtime slice above it and below the compression/reliability path.

## Desktop process isolation and exchangeability

### Status at a glance

This table is the authoritative desktop process-isolation snapshot. “Delivered
slice” means the stated process boundary exists in production code and has
focused evidence; it does not imply that the target exchangeability model is
complete. No work package below is complete yet.

| Boundary | Current ownership and delivered slice | Remaining gap before the target boundary is complete |
| --- | --- | --- |
| Admin Web | The Python runner can supervise a Python Admin child over private, correlated Unix-stream IPC. It owns the HTTP listener, authentication and browser sessions; replacement is bounded and retains the original bound port. The native macOS child can serve status from parent RPC through its own listener. | Native selection, full authenticated API/live-session parity, and mixed Python/native host qualification remain open; the Linux native child currently covers bootstrap only. |
| Logging | Python and native collectors are selectable by Python, macOS-native and Linux-native supervisors. Private inherited sockets carry bounded records, correlated log queries and owner-lifetime detection; collectors restart with a new generation. | This is a logging-specific protocol, not the common worker contract. Only selected producers are connected, aggregate drop accounting is incomplete, and cross-host/mixed-worker qualification is incomplete. |
| Peer stack | A Python supervisor can isolate one outbound TCP stack in a Python child on macOS/Linux or a native child on macOS/Linux. The child owns the transport-through-ChannelMux stack and has generation-fenced snapshots, replacement and owner-loss shutdown. | It is not per accepted/listener peer; it lacks the other transport modes, TUN/catalog ownership and a binary data-plane IPC contract. Native peer control is intentionally limited, and the common worker protocol is absent. |
| Shared TUN | Python and Swift privileged TUN helpers own device and host-policy operations across protocol-v1 IPC; macOS also has its existing XPC/helper path. | There is no separate shared-TUN routing worker. Peer/channel arbitration, packet routing and exchangeable Python/native ownership still run outside this boundary. |

### Design decisions already in force

- The desktop supervisor owns configuration, identity, startup order, worker
  selection, restart policy and aggregate status. A worker owns only its
  component I/O and protocol state.
- The privileged TUN helper and the planned shared-TUN routing worker are
  separate boundaries: privilege remains with the helper; routing and
  peer/channel arbitration belong to the shared-TUN worker.
- Private inherited descriptors are capabilities, not ambient loopback ports.
  They carry secrets and control frames without command-line or environment
  exposure, and owner loss closes the corresponding worker.
- A selected worker is never silently replaced by an in-process fallback.
  Replacement uses fresh capabilities and a new generation; existing browser,
  proxy and peer connections do not survive it.
- The current component-specific IPC mechanisms are intentionally transitional.
  The target is one versioned, language-neutral desktop worker protocol used by
  Python and native implementations on both macOS and Linux.

### Implementation evidence and current limits

On macOS and Linux, the Python runner and native hosts presently compose the
peer stack, Admin Web and proxy listeners by default, and most shared-TUN
coordination in the runtime process. A TUN helper can own privileged device and host-policy work
across a local IPC boundary; Python and native protocol-v1 helper servers exist,
but the Apple native app also has an XPC helper path and an in-process fallback.
These are not yet interchangeable shared-TUN routing workers. A standalone
Python UDP log receiver and nonblocking Python sender are available by
configuration. A separately launched native loopback-only collector accepts
the same Python UDP records and log queries. UDP is unauthenticated even on
loopback. The Python desktop runtime can instead select a Python or native
logging child through `--log-worker`: inherited Unix socket pairs provide a
private capability for bounded, nonblocking records and correlated Admin
queries, and a lifetime socket causes the child to exit on owner loss. A
Python monitor restarts the selected implementation with bounded backoff;
replacement sockets fence old queries, while the recent-log ring is lost on
restart. Admin reports the logging worker's generation, restart and drop
counts. The native collector keeps a 1,200-line / 1 MiB bounded ring; standalone
mode writes to stdout, while native supervisors discard stdout to avoid blocking.
The macOS and Linux native hosts can also select either collector
using `debug_logging.log_worker` (`off`, `python`, or `native`), with optional
`log_worker_python_executable` and `log_worker_native_executable` overrides.
Their shared supervisor exposes bounded queries and restart status to Admin;
the hosts currently emit only selected runtime lifecycle events, and their drop
counter does not include records rejected during lock contention. Unsupported
file and UDP sinks are rejected when this worker mode is selected. This is a
logging-specific slice, not the common worker protocol. The capability
protects against unprivileged processes without the inherited descriptors, not
a hostile debugger acting as the same user.

The Python supervisor's Admin and peer children and the Python/native proxy children of
either host feed the selected logging child through separate inherited
record-only datagram capabilities. The parent relay validates frame size and
rejects query messages,
then forwards records nonblockingly to the current collector generation. Thus
children cannot read Admin query replies, and a collector restart does not require
restarting those children; congestion or collector loss drops records. Native
hosts pass the proxy component's configured level to either proxy implementation,
using the Python managed logging ring's DEBUG root when no override is set.
Relay allocation failure counts as a dropped record and does not prevent proxy
startup. The rest of the native runtime producers, other
future workers, comprehensive producer-side drop aggregation, file/UDP sinks and
cross-host qualification remain open.

The Python runner can select `--proxy-provider-worker python` or `native`; the
macOS and Linux native hosts accept `proxy_provider.worker` (`python`, `native`,
or `off`) and optional `worker_python_executable` / `worker_native_executable`
paths. The Python executable must provide the installed ObstacleBridge module;
the packaged native worker is next to the host executable. The
selected child owns the HTTP and SOCKS listeners and client connections; the parent receives
periodic snapshots over a bounded inherited Unix stream and observes control
socket loss. Proxy credentials are handed over that socket, not command-line
arguments or the environment. Parent loss closes the child and listeners;
child loss is reported without falling back to an in-process proxy. Both the
Python runner and native hosts restart either selected child after process or
control loss using fresh capabilities and bounded backoff, retaining the first
bound ports and exposing generation, restart and failed-start counts. A
supervisor issues a positive generation in `proxy.start`; readiness and periodic
snapshots must echo it, and both desktop supervisors discard a mismatched or
retired generation without changing listeners or failure state. Existing proxy
connections are lost during replacement. Both workers accept IPv4 or IPv6
loopback listener binds, enforce the same destination policy, and support
direct and system egress. Each native session has independent scheduling and a
bounded duplex poll buffer; half-closes propagate after pending data is
delivered. The worker fails startup for unsupported settings. Native host
supervision bounds startup and health reads. Independently successful Linux
and macOS qualification covers Python/native selected workers, authenticated
HTTP CONNECT and SOCKS5 traffic, redacted status/log projection, replacement,
shutdown, and bundled native-worker discovery. This is a platform-local
boundary: it does not require a macOS process to execute a Linux worker or the
reverse.

The Python runner can select `--admin-web-worker python` to move the existing
HTTP listener, authentication and UI sessions into a child. A private inherited
stream carries bounded, correlated, deadline-bearing calls to an allowlisted
runner API; a separate inherited lifetime socket closes the listener on owner
loss. Credentials travel in startup/config frames rather than process arguments.
The default remains in-process. The Python supervisor replaces a lost child
or control stream with bounded backoff and reports generation, restarts and
failed starts; each replacement uses fresh capabilities and retains the first
bound port even if it was initially ephemeral. Existing browser sessions do
not survive replacement. Embedded restart callbacks are rejected in this
mode. This is an opt-in Python-only slice: native Admin and native supervision,
comprehensive API/security parity, and full operation-generation fencing
remain open. Synchronous runner calls execute on the runner loop;
deadlines cannot undo an operation already started.

The Python desktop runner can opt into `--peer-stack-worker python` for one
outbound TCP peer with TUN disabled. On macOS it can instead select
`--peer-stack-worker native` and point `--peer-stack-worker-native-executable`
at the signed `ObstacleBridgeHostRunner` (or resolve that executable on
`PATH`). The selected child owns transport, SecureLink, compression, ChannelMux
and its TCP/UDP services; startup configuration and credentials travel over an
inherited, size-bounded private control stream.
Correlated requests carry a peer identity and generation; the supervisor
projects generation-fenced status, peer and connection snapshots, restarts a
lost child with fresh capabilities and bounded backoff, and does not fall back
to an in-process peer. The child exits on owner loss and logs through a
record-only relay to either managed collector. Existing connections are lost
on replacement. TUN settings and TUN service catalogs, including catalogs
received from a remote peer, are rejected in this mode. Peer configuration
changes require stopping and restarting the runtime. Admin forwards reconnect,
rekey and material-reload requests over the same correlated, generation-fenced
channel, including when Admin is a child; a lost reply has an unknown outcome
and is not retried automatically. A cancelled control request terminates and
reaps a stalled child. The synchronous embedding controls still report that
peer-worker control is unsupported; asynchronous controls provide the worker
path. Without a managed collector, the child inherits the supervisor's
standard-error sink.

This is a Python-supervised, single-outbound-TCP slice. Its child can be Python
on macOS or Linux, or the native macOS host runner / Linux executable. The native child receives
only the inherited control descriptor: it starts neither Admin, proxy,
telemetry, runtime-health persistence nor TUN helper; it rejects TUN catalogs
and shared desktop-service settings. It returns generation-fenced status,
connections and peer snapshots, exits on control-owner loss, and is replaced
by the existing Python supervisor after failure. Native peer control requests
currently return an explicit unsupported result, and native-child stderr is
inherited rather than sent through the managed logging relay. The Linux child
uses the same no-file JSON admission path and currently admits only outbound
TCP without TUN or proxy ownership. Listener-side peer ownership, other transports,
broader peer-control qualification, live peer configuration, terminal status,
and shared-TUN routing/data IPC remain open; there is no shared-TUN worker yet.
The peer control stream is not yet the common cross-runtime worker protocol:
it has no capability negotiation, binary data-plane contract, write deadline,
or duplicate-key-rejecting native JSON parser.

The Python/Swift Admin component probe compiles against the shared runtime
policy and currently exposes three parity gaps: TUN routing summary/control
fields, status snapshot/UI metadata, and the live status payload shape. These
are independent of the worker boundary and remain to be resolved before
claiming Admin parity.

The existing TUN-helper protocol-v1 framing has a 1 MiB payload ceiling in
both Python and Swift, checked from the header before waiting for the body.
This protects that existing IPC boundary but does not implement the common
worker protocol, generation fencing, or worker supervision in `IPC-1`.

### Target ownership decisions

The desktop supervisor owns configuration, worker selection, identities,
startup order, restart policy, and aggregation, but not the workers' I/O or
protocol state. Admin Web, logging, each peer's complete transport / peer-address
protocol / SecureLink / compression / ChannelMux stack, the shared-TUN router,
and the proxy provider each have an independent process lifetime. Listener
acceptance may use a separate listener owner, but each admitted peer has an
isolated stack and explicit peer identity. The shared-TUN worker is distinct
from the privileged TUN helper: it owns peer/channel routing and packet
arbitration; the helper retains device and host-policy privilege.

### Control plane and data plane

The desktop supervisor is the **control-plane coordinator**, not a packet or
log-data switchboard. It starts and stops insulated bundle processes, selects
their Python/native implementation, grants fresh private capabilities, tracks
generation and health, applies bounded restart policy, and aggregates redacted
status. Its worker RPCs are bounded, correlated, deadline-bearing control
requests and lifecycle events. It may relay a bounded Admin log query or
subscription request to the selected collector, but it must not relay overlay
packets, TUN packets, service streams, or producer log records.

The **data plane** uses direct, bounded private channels between the owning
workers: a peer-stack worker exchanges packet/channel traffic with the
shared-TUN routing worker; that router exchanges packet/control traffic with
the privileged TUN helper; and every producer, including the shared-TUN
routing worker, has a dedicated record-only, nonblocking descriptor to the
logging collector. The collector never receives browser credentials or opens a
public listener. Admin Web serves browser HTTP/WebSocket traffic directly; its
bounded log-page and live-log control requests travel through the supervisor,
which returns only the collector's bounded, redacted result. Collector
unavailability or saturation drops the affected producer record and updates
drop accounting; it never delays packet routing. Collector replacement creates
a new generation and fresh producer descriptors, so a retired worker cannot
publish into the replacement collector.

Python and native workers implement the same versioned, language-neutral local
IPC contracts and can be selected independently on macOS and Linux. The
protocol must negotiate role, version, capabilities, and generation before
accepting operations. Control requests have bounded frames, correlation IDs,
explicit success/error replies and deadlines; asynchronous events identify
their worker and generation. Data-plane frames are bounded and preserve packet
boundaries or ordered stream semantics as appropriate. Local IPC endpoints and
credentials are restricted to the intended principals; secrets and payloads
are excluded from logs and status. Peer state from a retired generation cannot
be admitted after a restart. TCP backpressure, UDP/TUN shedding, authentication
gating, and existing per-peer routing remain enforced across process boundaries.
Each worker has bounded startup, health, shutdown and recovery behavior;
failure is reported without silently replacing the selected implementation.
iOS extensions and Windows retain their existing execution boundaries; this
desktop plan does not assert they can spawn these workers.
The Swift parity gate treats the desktop proxy and logging supervisors and
their respective macOS/Linux host adapters as desktop-specific boundaries;
iOS changes still require their own shared-Apple or macOS parity evidence.

### Remaining work packages

Packages are removed when all their criteria are evidenced, not merely when a
protocol type or test harness exists. A package names one execution host and
its implementation and acceptance evidence run only on that host. “Mixed” in
these packages means a Python/native implementation pairing on the named host,
never a macOS process executing a Linux binary or a Linux process executing a
macOS binary. The macOS and Linux sequences reproduce the same durable logging
contract independently; a later cross-platform review compares their recorded
contracts and evidence, not executable processes.

Logging separation is the active implementation focus. Its ordered,
platform-local packages are defined below. `IPC-1` remains the later convergence point that
replaces component-specific IPC across all worker roles; it is not a prerequisite
for completing the logging worker's selected-worker ownership boundary. Every package in
this table is open. A completed package is removed from this table and its
durable ownership decision is retained above instead of being restated as a
completed plan item.

### Delivered macOS logging producer boundary (`IPC-2M-1`)

The macOS private-collector producer inventory is: the Python runner owns
collector selection; its Python Admin, proxy, and peer children receive only
their inherited record relay; the macOS host emits payload-free operational and
runtime events to its selected collector; and the native proxy and native peer
children receive only an inherited producer descriptor. None has collector
query capability. The source guard names all seven producer/supervisor sources
and excludes direct stream/file sinks while private mode is active; the macOS
host matrix verifies the canonical `runtime.started` record arrives at either
selected collector and not the host's stdout or stderr. This closes `IPC-2M-1`;
collector lifecycle/accounting and broad operator qualification remain in
`IPC-2M-2` and `IPC-2M-3`.

Native Admin onboarding projections are shared across the desktop children: authenticated browser clients receive connection profiles and portable service blueprints derived only from bounded peer/connection parent snapshots. Both children also expose telemetry status only when configured, sourcing its bounded client snapshot through inherited RPC. The macOS native Admin now gives browser clients Python-compatible live defaults (`status`, `connections`, `peers`, and `meta`) plus the bounded `tun_routing` topic on request, including through `GET /api/live?topic=` and query-scoped version-13 WebSockets; its metadata publishes the standard process, uptime, transport/dashboard, milestone, build, and dependency fields. Broader browser-session/API parity remains the `IPC-1A2` residual.

| Package | Scope and definition of done | Gap to close |
| --- | --- | --- |
| `IPC-1` — common transport and supervision | Define and implement the bounded authenticated local control/data protocol, capability negotiation, worker generation fencing, startup handoff, and supervised teardown in Python and Swift. DoD: Python/native peers exchange requests, responses, events and binary data in both directions; malformed, oversized, unauthenticated, timed-out and stale-generation input fails closed; parent/child loss and restart do not leak workers, credentials or sockets on macOS and Linux. | The Python/Swift v1 codec defines bounded inherited-socket frames, control/data kinds, generation fields, strict Python control decoding, and mutual capability negotiation. Python-supervised peer control (including the Linux-native peer), Python/native proxy, Python Admin control, private Python/native logging, and the Python privileged helper exchange a generation-fenced capability hello before bootstrap or readiness; peer workers echo bounded opaque data only after negotiating `peer.binary-data`, while all privileged helpers bound unauthenticated initial admission and reject token-HELLO renegotiation. Linux CI starts, snapshots, stops, and exercises data exchange with the packaged native peer. Remaining common-IPC closure is partitioned into `IPC-1A` and `IPC-1Q` so each host executes only its own native evidence. |
| `IPC-1A` — native Admin worker ownership | Make the Python desktop supervisor able to select a native Admin child on macOS or Linux through common IPC, preserving the existing authenticated API, websocket/session, configuration-confirmation, log-query, and restart behavior. DoD: a Python supervisor launches either native host-local implementation with inherited capabilities only; the full API contract, recovery/status fields, and owner-loss cleanup match the existing Python Admin child on that host. | Both native children cover the inherited-descriptor bootstrap ABI, including generation-fenced HELLO/READY, bounded parent RPC, owner loss, and a child-owned status listener; the required Linux Swift lane executes its socketpair and status-HTTP qualification. The remaining work is authenticated API/session/configuration/log parity in `IPC-1A2` and Python-supervisor native selection in `IPC-1A3`. |
| `IPC-1A2` — native Admin HTTP/session parity | Give the native child the existing Admin HTTP, authentication, browser-session, websocket/live-topic, configuration-confirmation, log-query, and recovery/status semantics through bounded parent RPC. DoD: the native child owns the listener and sessions; every parent RPC is allowlisted, correlated, generation-fenced, deadline-bounded, and redacted; its observable API contract matches the Python child on that same host. | macOS owns authenticated browser asset delivery, standard process/uptime/transport/dashboard/build metadata, status/config-schema/log/connection/peer/read-only-TUN documents, the legacy `GET /api/live?topic=` fallback, and a query-scoped version-13 snapshot-first WebSocket session: it starts with Python's status/connection/peer/meta topics and exposes bounded `tun_routing` on demand through inherited RPC. Its packaged host probe qualifies those bounded live paths and metadata alongside the base asset, log/config request sequence, update-bound password confirmation, refreshed redacted configuration snapshot, secret-free live onboarding connection profiles, Core-owned invitation generation/PSK-masked preview, password-confirmed encrypted PSK reveal using the dedicated inherited invite-source snapshot, owner loss, and two concurrent authenticated status reads without cross-reply leakage. Its listener also translates authenticated remote-service replacement plus bearer-protected reconnect/rekey/reload, TUN-routing, TUN-helper repair, restart, and shutdown into allowlisted parent RPC, mapping browser `peer_id` to the supervisor’s `target_peer_id`. The Linux child owns the corresponding bounded allowlisted browser surface, including authenticated health/status/local metadata/configuration/log/telemetry/TUN/connection/peer/onboarding documents, confirmed writes and controls, and its three-topic live fallback/session contract. The residual is full browser-session and API compatibility with the Python Admin child; Python-supervisor selection remains A3. |
| `IPC-1A3` — native Admin selection and host qualification | Select Python or host-native Admin children from the Python desktop supervisor and qualify replacement, bind recovery, owner loss, stale replies, and concurrent authenticated clients on their respective hosts. DoD: Python/macOS-native and Python/Linux-native selections retain the port and redacted status contract across recovery; each host runs only its own executable and no selected child leaks sockets or credentials. | The desktop selector accepts native, resolves only a host-local executable, and passes inherited control/lifetime/log descriptors through the existing generation-fenced supervisor path. Linux CI and the packaged macOS host test launch the native executable, serve status, kill it, prove same-port supervised recovery, and retry after transient bind contention. The shared Swift Admin RPC poisons its control channel after an invalid or stale reply, preventing later consumption. Browser-session/API parity remains IPC-1A work. |
| `IPC-1Q` — teardown and host-local qualification | Close common supervision behavior and qualify every delivered common-IPC pair on its own supported host. DoD: one bounded deadline/retirement policy covers startup, malformed/stale input, parent loss, child loss, restart, and socket closure; macOS and Linux each build and run their native worker/helper/Admin evidence locally; no test requires a macOS binary on Linux or the reverse. | Worker slices have local focused coverage, but lifecycle bounds and host-local evidence are not yet complete for the helper and native Admin boundaries. |
| `IPC-2M-2` — macOS logging supervision and accounting | Complete macOS collector lifecycle behavior for the Python and native desktop supervisors. DoD: startup, owner loss, crash, malformed record/query, stale generation, saturation, relay-allocation failure, collector replacement, and shutdown are bounded; every in-scope producer and relay contributes to one redacted aggregate drop snapshot; Admin and the Admin-worker path return the same bounded status and recent-log envelope; and neither forwarding nor listener recovery waits for logging. | Existing lifecycle/restart coverage omits records rejected during lock contention and does not aggregate all producer/relay drops into one macOS snapshot. |
| `IPC-2M-3` — macOS logging qualification and operator contract | Qualify the completed macOS logging boundary with same-host Python/native selector combinations and publish its supported configuration, status fields, recovery behavior, and rollback. DoD: an automated macOS lane covers collector loss/restart under proxy, Admin, and peer-worker traffic; a packaged macOS host discovers the selected local worker without ambient endpoints; source/runtime checks prove private-worker mode installs no direct file, UDP, stdout, or stderr logging sink in migrated producers; and the operator documentation states the loss and restart semantics. | The macOS lane covers selected supervisor/proxy cases, but does not qualify the full producer inventory or packaged-worker discovery under collector loss. |
| `IPC-2L-1` — Linux logging producer boundary | Reproduce the macOS producer-boundary contract in the Linux native runtime and Python runner on Linux, using only Linux executables and local inherited capabilities. DoD: the Linux inventory covers its foreground lifecycle owner and every delivered Linux desktop worker; each in-scope producer has record-only delivery to either local Python or native collector; and local Python/native selection preserves the canonical redacted envelope and component-level policy. | Linux currently emits selected foreground lifecycle records and proxy-child records only; the full producer inventory and record-only boundary are not implemented. |
| `IPC-2L-2` — Linux logging supervision and accounting | Reproduce the macOS lifecycle and accounting contract in Linux supervisors. DoD: the same bounded failure matrix—startup, owner loss, crash, malformed input, stale generation, saturation, relay failure, replacement, and shutdown—passes on Linux; the aggregate drop snapshot includes all delivered Linux producers and relays; Admin returns the canonical bounded status/recent-log envelope; and collector failure cannot delay foreground overlay, proxy, Admin, or peer-worker progress. | Linux lacks full producer/relay drop aggregation and the matching supervisor failure matrix for every delivered worker. |
| `IPC-2L-3` — Linux logging qualification and operator contract | Qualify the completed Linux boundary with same-host Python/native selector combinations and record the Linux operator contract. DoD: an automated Linux lane covers collector loss/restart under delivered worker traffic; packaged Linux discovery has no ambient endpoint dependency; source/runtime checks prove migrated producers install no direct production sink in private-worker mode; and the documented recovery and rollback semantics match the macOS contract where the platform exposes the same feature. | The Linux lane exercises selected logging/proxy behavior, not the complete production inventory, sink exclusion, packaged discovery, and operator recovery contract. |
| `IPC-2R` — logging contract comparison | Compare the completed macOS and Linux evidence and reconcile only their portable logging contract. This is a review/package of artifacts, schemas, and platform-local test results; it executes no foreign binary. DoD: configuration vocabulary, canonical record/status envelopes, bounds, drop semantics, and documented unsupported features are either identical or explicitly platform-scoped; corresponding macOS and Linux tests prove each claim on its own host; and no desktop logging gap remains hidden behind a mixed-host test requirement. | Both platform sequences must first reach their own DoD; no evidence set exists yet for a portable-contract review. |
| `IPC-3` — Admin Web worker | Move HTTP/UI/auth/session ownership to an exchangeable process connected to supervisor and workers through IPC. DoD: existing APIs, live subscriptions, config confirmation/secrets, logs, restart and reconnect operations retain their security and semantics; worker failures and concurrent clients remain bounded and observable; Python/native Admin works with either supervisor on both hosts. | Only the opt-in Python Admin child exists; native ownership, full API/session parity, and platform-local mixed-worker qualification remain open. |
| `IPC-4` — per-peer stack workers | Isolate each peer's full transport-through-ChannelMux stack and provide explicit listener/accepted-peer ownership. DoD: all supported desktop transports, security modes, compression and TCP/UDP/TUN services interoperate with existing peers; peer-specific operations, snapshots, epochs, backpressure and reconnect survive independent worker failures without cross-peer state or plaintext leakage, for each Python/native pairing on both hosts. | The delivered slice isolates one outbound TCP peer without TUN; listener peers, other transports, catalogs, data IPC, and broad native control are absent. |
| `IPC-5` — shared TUN worker | Move shared-interface routing, ownership and peer/channel arbitration into a separate exchangeable worker while retaining the privileged helper boundary. DoD: real bidirectional TUN traffic, simultaneous peers, route/DNS lifecycle, authenticated readiness, restart fencing, helper loss and cleanup are verified with Python/native worker and helper combinations on authorized macOS and Linux hosts. | Privileged helper IPC exists, but no shared-TUN routing worker owns packet arbitration or exchangeable peer/channel routing. |
| `IPC-7` — integrated qualification and migration | Wire configuration, packaging, installation, process health and operator diagnostics into both desktop products. DoD: all supported Python/native worker combinations pass automated cross-process and mixed-overlay traffic, kill/restart, shutdown and resource-leak tests; privileged and signed-host evidence is recorded, existing deployments have a documented migration/rollback path, and no production path silently falls back to in-process ownership. | This depends on the unresolved worker boundaries and their platform-local qualification; complete migration and rollback evidence has not been assembled. |

### Proxy worker contract decisions

The selected proxy worker receives its version-1 startup dictionary only on an
inherited Unix control socket. The dictionary has explicit authentication,
loopback bind, listener-port, protocol, egress, and destination-policy
policy fields. Both selected implementations bind only to the explicit IPv4 or
IPv6 loopback address supplied by that dictionary. Invalid values are rejected
before a child is spawned with the
redacted `invalid_configuration` outcome; listener allocation failures return
`startup_failed` on that private channel. The readiness frame reports the
selected implementation, bounded listener snapshot, and versioned capability
declaration. Both desktop supervisors project capabilities at
`worker.capabilities` with lifecycle identity/state/generation/restart/failure
fields, listeners, and redacted `last_error`; configured status never exposes
token or password values. The capability declaration is authoritative for the
common selectable surface. Contract qualification runs each supervisor/worker
selection on its own macOS or Linux host.

The destination policy is enforced before every HTTP CONNECT, absolute-form
HTTP, and SOCKS5 CONNECT dial. `blocked_host_patterns` uses case-insensitive
`*` and `?` matching against the requested hostname before DNS lookup. With
`allow_private_destinations` disabled, a literal or every resolved direct-dial
address must be globally routable; the Python worker dials only the approved
numeric results. A denied HTTP destination receives `403`; a denied SOCKS5
destination receives reply code `0x02`. This makes the default policy fail
closed while preserving an explicit local-test or deployment opt-in for private
destinations.

For `system` egress on macOS and Linux, both workers select the deterministic
test override first and otherwise use `HTTPS_PROXY`/`HTTP_PROXY` and
`NO_PROXY`/`no_proxy`. A selected upstream is reached with an HTTP CONNECT
tunnel; a bypass or absent endpoint uses the direct policy-checked path. The
same listener snapshot and capability declaration report `direct` and
`system` egress as selectable.

Proxy control frames are generation-fenced at the worker boundary. The
supervisor assigns a positive generation in `proxy.start`; `proxy.ready` and
every `proxy.snapshot` echo it. A mismatched readiness or snapshot is invalid,
and a retired reader cannot clear or replace the active generation's listener
or failure state. This fences observation delivery independently of the fresh
control socket used for every replacement.

The lifecycle projection uses redacted stable failure codes: `unavailable` for
control or child loss, `startup_failed` when a replacement cannot become ready,
and `invalid_configuration` when its private startup dictionary is rejected.
Successful readiness clears the code. Both desktop supervisors and their host
projections retain the failed-start count while a retry is pending and expose
no listener snapshot for an unavailable generation.

Desktop native-worker discovery is deterministic. Python supervision prefers
the configured executable, then the validated `OBSTACLEBRIDGE_NATIVE_PROXY_WORKER`
deployment override, and finally the development `PATH` lookup. Native hosts
resolve the bundled worker beside their host executable. Every selected path
must be an executable regular file; invalid discovery fails before private
control IPC starts and never falls back to in-process proxy ownership.

Proxy-worker qualification is platform-local. A transient initial selected-worker
launch failure retains its bounded private configuration and follows the same
recovery path as later worker loss. The named Linux and macOS gates
each report `python-worker` and `packaged-native-worker`, and exercise the
selected worker's authenticated HTTP CONNECT/SOCKS5 traffic, redacted
status/log projection, forced replacement, and host shutdown. A native host
selects its sibling worker; no macOS process is used to qualify a Linux worker,
or the reverse.

PXY-3 lifecycle and observability qualification is complete: the independently
recorded macOS and Linux matrices exercise the generation-fenced lifecycle
schema, recovery outcomes, selected collector delivery, collector replacement,
bounded drop state, and host status projection. This is a same-host contract;
it does not require a macOS process to execute a Linux worker or the reverse.

Completed IPv6-listener, destination-policy, system-egress, platform-local
listener, proxy-worker selection, and PXY-3 lifecycle/observability
qualification work packages are represented by the durable contract decisions
above rather than retained as active packages.

## Connection lifecycle propagation and rotation

### Connection lifecycle contract

All client overlay stacks use one explicit, typed connection lifecycle contract.
The contract travels upward with the wrapper stack and carries at least:

- `state`: `disconnected` or `connected`
- `epoch`: a monotonically increasing connection epoch owned by the transport
- `reason`: a stable failure or transition category suitable for diagnostics and policy
- `changed_at`: the transition timestamp

The effective stack and propagation direction are:

```text
Transport -> Peer Address Protocol -> Security -> Compression -> ChannelMux
```

The control direction is the reverse and must never skip a layer:

```text
ChannelMux -> Compression -> Security -> Peer Address Protocol -> Transport
```

`ChannelMux` owns the policy decision to request a connection rotation. Each
wrapper owns forwarding that request to its immediate inner layer, so the
request follows the complete stack even where a wrapper has no rotation work of
its own. The transport is the only layer that chooses the next resolved peer
candidate and starts a new connection epoch.

#### Layer rules

Transport (`myudp`, WebSocket, QUIC, TCP):

- starts in `disconnected`
- publishes `connected` once its initial connection is established
- handles a recoverable transport loss locally, such as a closed WebSocket or
  TCP stream, without immediately changing the state reported upward
- remains `connected` while its local reconnect loop is still making progress
- publishes `disconnected` only when that reconnect attempt fails or its local
  retry budget is exhausted
- on a rotation request, advances to the next configured/resolved peer
  candidate, begins a new disconnected epoch, and continues connection
  attempts until a connected epoch is reported or the candidate budget ends

Peer address protocol:

- is transparent to application payloads and is active for `myudp`, TCP, WebSocket, and QUIC
- sends one versioned request on each client transport epoch
- has the receiving peer reply with the actual source IP it observed for that connection; the reply carries either an IPv4 or IPv6 literal
- clears the value on disconnect and exposes an empty value until a valid reply arrives
- does not authenticate, encrypt, compress, or delay the secure-link handshake and does not gate `connected` or `app_ready`

Security:

- starts in `disconnected`
- publishes `connected` only after the initial secure-link handshake succeeds
- remains `disconnected` while the initial handshake is incomplete or fails
- remains `connected` during a rekey; a rekey is not a transport disconnect
- bounds every initial handshake and pending rekey to the same 60-second lifecycle timeout on both client and listener roles; duplicate rekey control frames do not renew that deadline
- publishes `disconnected` when secure-link enters `failed`
- propagates a newer lower-transport epoch even when it is already
  `disconnected`, so ChannelMux can continue candidate rotation after a
  failed reauthentication
- forwards a rotation request to the transport after clearing security state
  for the next transport epoch

Compression:

- is transparent and stateless for connection lifecycle purposes
- mirrors the immediately lower layer's lifecycle state and epoch upward
- treats a compression/decompression failure as `disconnected` for the current
  epoch and drops affected traffic
- may return to `connected` only after the lower layer reports `connected` in
  a newer epoch
- forwards rotation requests to Security

ChannelMux and TUN:

- `ChannelMux` admits or starts services only while the outer lifecycle state is
  `connected`
- after the outer layer remains non-ready continuously for more than 15 seconds,
  `ChannelMux` requests one connection rotation through the wrapper stack
- a lower-layer rotation request that is rejected before it starts a new
  lifecycle epoch does not consume ChannelMux's one-per-epoch guard; while the
  outer layer remains non-ready, ChannelMux clears that guard and retries after
  the same grace window
- `channelmux_transport_delay_threshold_ms` is the shared ChannelMux overload
  parameter, defaulting to `5000` milliseconds. At or above it, TCP pauses local
  reads, UDP sheds new local datagrams, and TUN continues draining but sheds
  completed `DATA` / `DATA_FRAG` immediately before SecureLink; TUN `OPEN`
  control remains eligible.
- `channelmux_transport_delay_rotation_delay_ms` is the companion rotation
  duration parameter, defaulting to `30000` milliseconds. If estimated
  transport delay stays at or above the threshold for that duration
  while the outer lifecycle is connected, ChannelMux requests one normal
  connection rotation and waits for the next lifecycle epoch before another
  request. A rejected request clears the wait immediately and is retried after
  the configured delay rather than leaving the connection stuck.
- a raw transport `connected` event does not reset the candidate-cycle budget;
  ChannelMux resets it only after the outer lifecycle reports `connected`
- `TUN` ingress must not be admitted into `ChannelMux` unless ChannelMux has
  received the current `connected` state; probe generation follows the same
  gate
- a newly reported `connected` state with a new epoch causes the normal mux
  resynchronization and service reopening path
- a transport-epoch reset invalidates all prior TUN channel bindings and
  advances the local ChannelMux connection sequence before local forwarding
  resumes. Python proactively opens every configured local TUN listener and
  Swift proactively opens its configured client TUN endpoint after the
  authenticated overlay becomes ready; both send a fresh `OPEN` before any
  TUN `DATA` on a new channel.
- listener-side shared-TUN state uses `(peer_id, chan_id)` as its channel
  identity for bindings, OPEN lifecycle, fragments, counters, and outbound
  routing. Each peer has an independent channel-number sequence, so `chan=1`
  from two clients is two distinct TUN paths.
- the TUN/routing operator surface collapses all in-process holders of one
  shared device into one physical-interface row. Its overall traffic is
  derived from the configured peer bindings; per-holder channel aliases stay
  in the configured-peer detail rather than becoming duplicate interfaces.
- when a process shares one server-owned TUN device between listener and
  peer-specific ChannelMux instances, the listener-owned reader retains the
  mirrored peer/channel binding and emits replies through its peer-aware
  listener session. Sharing a device never makes its routing state local to
  the most recently attached mux instance.

#### Candidate budget and restart

The transport maintains an ordered list of configured and resolved peer
candidates. One rotation advances to the next candidate. After all candidates
have been attempted three complete times without a successful connected epoch,
the Runner requests an ObstacleBridge process restart. The cycle counter is
transport-owned and is reset only after a successful connected epoch. The
Runner performs the restart; neither SecureLink nor ChannelMux directly exits
or restarts the process.

This policy applies uniformly to `myudp`, WebSocket, QUIC, and TCP. A transport
may recover a short-lived break internally, but it must ultimately report a
definitive `disconnected` lifecycle event when it cannot recover, so the upper
layers can apply the common rotation policy.

### Current implementation boundary

The runtime uses typed transport lifecycle events with transport-specific
recovery paths:

- `myudp`, TCP, WebSocket, QUIC, SecureLink, and Compression publish
  `ConnectionLifecycleEvent` state edges with a transport-owned epoch;
  Runner dispatches each event to its corresponding ChannelMux
- SecureLink converts its app-ready state to disconnected on a security
  failure, and Runner then informs ChannelMux; ChannelMux disables service
  acceptance and closes channels
- Compression forwards lifecycle state and rotation requests, reports a
  decompression error as disconnected, and blocks traffic until a newer epoch
- SecureLink reports authentication failure as disconnected and forwards a
  rotation request only when its caller asks; ChannelMux requests one cascaded
  rotation after 15 seconds of continuous outer-layer non-readiness
- ChannelMux tracks continuous outer-layer disconnection, requests one
  cascaded rotation after 15 seconds, and waits for a newer lifecycle epoch
  before it can request another rotation. An accepted myUDP rotation publishes
  that newer disconnected epoch, so the policy continues through candidates
  rather than remaining stalled after its first request.
- ChannelMux separately watches estimated transport delay while connected. Its
  configurable `channelmux_transport_delay_threshold_ms` defaults to 5000 ms,
  and `channelmux_transport_delay_rotation_delay_ms` defaults to 30000 ms;
  sustained delay at or above that threshold for that duration requests the same
  one-per-epoch candidate rotation. Python and Swift share the 5000 ms default
  and 30-second grace.
- Security reports failed authentication without scheduling a transport
  reconnect; Runner watchdog supervision is independent of Security recovery
  status
- Swift macOS/iOS overlay owners share the same lifecycle event/epoch model at
  their transport-wrapper boundary, gate ChannelMux and TUN ingress on outer
  app readiness, and route delayed rotation requests through each transport's
  peer-candidate reconnect path. After three exhausted candidate cycles they
  publish an explicit restart-required event for host supervision.
- TUN ingress and internal connectivity probes are admitted only after the
  current outer lifecycle epoch reports `connected`.

SecureLink failure is observable as a disconnected lifecycle event. ChannelMux
owns the delayed rotation decision, and Runner restarts only after transport
candidate-cycle exhaustion or a missing lifecycle-event watchdog timeout.

Shared lifecycle contract: `ISession` defines `ConnectionLifecycleEvent` and
`ConnectionRotationResult`; all Python transports expose the lifecycle callback
and normalized lifecycle snapshot, and accept a transport-local rotation
request. Rotation results report the selected candidate, completed candidate
cycles, and whether three completed cycles require a restart. Runner consumes
that exhaustion result once; its watchdog is limited to sessions that have not
emitted lifecycle events.

### Rework work packages

1. Swift macOS/iOS lifecycle parity package is delivered for the shared
   transport-wrapper runtime: typed lifecycle events, candidate-cycle restart
   results, TUN admission gating, and peer-layer lifecycle diagnostics are
   applied across native UDP, TCP, WebSocket, and QUIC owners.


## Stable component IDs

The following component IDs are intended to stay stable so requirements, tests, and future design notes can point to architecture elements without depending on section wording.

| Component ID | Component | Primary scope |
|---|---|---|
| `ARC-CMP-001` | Transport and session layer | Transport-specific peer connectivity, listener/client state, and per-peer transport ownership |
| `ARC-CMP-002` | Reliability and framing layer | Reliable overlay framing, retransmission, RTT, inflight, and missed-frame tracking |
| `ARC-CMP-003` | Channel and service multiplexing layer | `own_servers`, `remote_servers`, channel routing, and peer-scoped service isolation |
| `ARC-CMP-004` | Runner and process orchestration layer | CLI/config composition, lifecycle wiring, restart/shutdown coordination, process startup, entrypoint supervision, and privilege handoff plus operator-facing elevation notices for local TUN startup when required |
| `ARC-CMP-005` | Admin web and observability layer | HTTP API/UI, auth/session control, runtime snapshots, logs, and operator visibility |
| `ARC-CMP-006` | Secure-link layer | Delivered PSK-based and certificate-based authentication, frame protection, replay defense, rekeying, and secure-link diagnostics between transport sessions and `ChannelMux` |
| `ARC-CMP-007` | Compression layer | Mux-aware per-frame compression/decompression between secure-link/session and `ChannelMux`, no-gain bypass, and compression observability counters |
| `ARC-CMP-008` | Peer-address protocol layer | Versioned request/reply control frames directly above every supported transport; server-reflected client IPv4/IPv6 observation for peer diagnostics without changing readiness |

## 1. Transport and session layer

Primary responsibility:

- establish peer-to-peer connectivity over `myudp`, `tcp`, `ws`, or `quic`

Main contribution:

- creates the underlying transport session
- owns peer connectivity state
- provides send/receive hooks into the higher framing layer

## 1a. Peer-address protocol layer

The peer-address protocol is anchored immediately above the concrete transport and below optional SecureLink. On each client connection epoch it sends a small `OBPA` version-2 request. The server consumes that request and replies with the endpoint address and source port observed by its active transport peer. IPv4 replies contain four address bytes and IPv6 replies contain sixteen, followed by a two-byte network-order port; malformed or unrelated frames pass to the next layer unchanged.

The client records only the most recent valid reply for its current transport epoch. The fields are published as `observed_public_ip` and `observed_public_port` in the active peer snapshot and rendered together as **Own Public IP** in the Transport section of the Peer page. It therefore shows the source tuple actually used by the selected overlay path, rather than a host-wide lookup result. IPv6 is rendered in brackets before the port. A dual-stack listener's IPv4-mapped IPv6 representation (`::ffff:a.b.c.d`) is encoded as the canonical IPv4 address so it remains unambiguous beside an IPv4 resolved peer. The layer is diagnostic only: a missing reply must never hold up overlay connection, SecureLink authentication, or ChannelMux readiness.

For accepted listener peers, the raw child transport session supplies peer-local metrics, while the outer stack supplies the layer inventory. The peer snapshot overlays SecureLink authentication and compression state from that peer's diagnostics onto the outer layer inventory, so a healthy accepted peer cannot be displayed as a disconnected wrapper stack.

Important behaviors:

- single-peer client mode
- listener mode
- multi-peer listener behavior for transports that support multiple concurrent peer clients
- transport-specific client bootstrap, such as proxy tunnel establishment and direct-path HTTP root preflight, before higher protocol handshakes
- endpoint-local auxiliary behavior, such as WebSocket pre-upgrade HTTP/static handling, must stay scoped to the originating socket/request and must not mutate unrelated peer sessions
- an accepted Python WebSocket listener peer has its own RTT liveness guard: failure to become live within 60 seconds, or loss after it was live, closes only that peer socket and withdraws its lower-transport readiness; native Swift WebSocket code is peer-client-only and has no listener-peer ownership surface
- every overlay transport must publish one transport-agnostic backpressure view upward: queue depth, inflight state where available, recent egress throughput, and delay/progress estimates

The current WebSocket-specific listener split, including direct static HTTP handling and same-socket upgrade considerations, is documented in [WEBSOCKET_DESIGN.md](WEBSOCKET_DESIGN.md).

Representative implementation area:

- [bridge.py](../src/obstacle_bridge/bridge.py)

Important proxy expectation:

- default WebSocket peer-client proxy behavior should follow platform-native settings unless application configuration explicitly overrides that behavior

### Payload-size accounting across the lower layers

There is no single project-wide "maximum packet size". The runtime applies size limits at each envelope boundary, and the effective application-data budget shrinks as more framing layers are stacked.

The current accounting model is:

1. `ChannelMux` builds a mux frame with an 8-byte header (`>HBHBH`).
2. Optional `SecureLink` wrapping adds its own secure-link frame header plus authenticated-encryption overhead before the wrapped session sees the data.
3. The concrete session (`UdpSession`, `TcpStreamSession`, `QuicSession`, or `WebSocketSession`) applies its own framing and transport-specific size limit.

Current lower-layer budgets in the runtime:

| Layer / component | What the upper layer may pass in | Additional bytes added before the next lower boundary | Current implementation note |
|---|---|---|---|
| `ChannelMux` | TCP/UDP service payload chunk | 8-byte mux header | `ChannelMux` drops a mux frame if its packed size exceeds the wrapped session's advertised app-payload limit |
| `SecureLinkPskSession` / cert mode | plaintext mux frame | 20-byte secure-link header + 16-byte AEAD tag for protected DATA frames | `get_max_app_payload_size()` subtracts this overhead from the wrapped session limit before `ChannelMux` sees it |
| `UdpSession` | session app payload | lower UDP/reliability/IP overhead below the `send_app()` boundary | Currently advertises `65535` as a software cap |
| `TcpStreamSession` | session app payload | 4-byte length prefix + 1-byte kind marker on the stream | Currently advertises `65535` as a software cap |
| `QuicSession` | session app payload | 4-byte length prefix + 1-byte kind marker inside the QUIC stream payload | Advertises configurable `quic_max_size` (default `65535`) |
| `WebSocketSession` | session app payload | 1-byte kind marker, then payload-codec expansion into the WS frame | Advertises `ws_max_size - 1` to reserve the kind byte |

From the mux perspective, the effective per-frame application-data budget is therefore:

- without secure-link: `session_limit - 8`
- with secure-link protected DATA: `session_limit - 36 - 8`

where `36 = 20-byte secure-link header + 16-byte AEAD tag`.

This same budget is also used to derive `ChannelMux._SAFE_TCP_READ`, so TCP application streams are read in chunks that fit into one mux DATA frame after headers are added. In other words, TCP stream handling does not try to preserve one large application write as one giant overlay frame; it slices the byte stream into chunks that fit the current session budget.

#### UDP

At the API boundary, `UdpSession` currently reports `65535` as its maximum application payload size. That value is a project-local software budget, not a literal statement that a `65535`-byte UDP payload is always valid on the wire.

Important caveat:

- real UDP datagrams still pay for UDP, IP, and ObstacleBridge reliability/session overhead below the `send_app()` boundary
- path MTU, IP version, and kernel/socket behavior can therefore make the true wire-safe datagram size smaller than the abstract `65535` session budget

For a concrete MTU example, assume a path MTU of `1550` bytes:

- IPv4 leaves at most `1550 - 20 - 8 = 1522` bytes for the UDP payload
- IPv6 leaves at most `1550 - 40 - 8 = 1502` bytes for the UDP payload

That is before any ObstacleBridge-specific framing inside the UDP payload. The `myudp` protocol layer then consumes another 19 bytes for `ptype + len + tx_time_ns + echo_time_ns`, so the maximum protocol payload becomes:

- IPv4: `1522 - 19 = 1503` bytes
- IPv6: `1502 - 19 = 1483` bytes

So the raw received UDP payload is already 28 bytes smaller than MTU for IPv4 and 48 bytes smaller for IPv6, and the maximum overlay protocol payload is 47 bytes smaller than MTU for IPv4 and 67 bytes smaller for IPv6. ChannelMux application data is smaller again once mux and optional secure-link headers are included.

So for UDP the current runtime is internally consistent at the `ChannelMux`/session interface, but that interface is more generous than a strict end-to-end wire budget. This is the main remaining systematic caveat in the size model.

Safety-by-design improvement:

- the mux layer now provides UDP service datagram fragmentation when one local UDP datagram would not fit into one effective session payload budget
- peer-side mux reassembles those fragments before emitting one local UDP datagram on the destination side
- the mux layer also enforces an explicit maximum UDP service datagram size and logs the active wrapped transport stack together with that cap at startup

The current mux-level fragment header carries:

- `datagram_id`
- `total_len`
- `offset`

so the receiving side can rebuild one original UDP service datagram before passing it to `sendto(...)`.

The implementation details and boundary rationale for this behavior are documented in [CHANNELMUX_DESIGN.md](./CHANNELMUX_DESIGN.md).

#### Who splits and who reassembles?

This is the key behavioral distinction once the effective session budget becomes smaller than the original local payload source.

For local TCP services:

- `ChannelMux` reads from the local TCP socket in chunks of at most `ChannelMux._SAFE_TCP_READ`
- each chunk becomes one mux `DATA` message
- on the far side, mux writes each received chunk directly into the destination TCP stream

So TCP service traffic is split by `ChannelMux` and implicitly reassembled by the receiving TCP byte stream. There is no separate mux-level message reassembly step for TCP services because the local application already consumes a stream, not message boundaries.

For local UDP services:

- each received local UDP datagram is forwarded as one mux `DATA` message
- if that one mux frame would exceed the effective session budget after mux, secure-link, and session framing are considered, `ChannelMux` fragments the UDP service datagram into multiple mux fragment messages
- the peer-side mux reassembles those fragments before emitting one local UDP datagram

So UDP service traffic no longer has to fit into one effective mux/session payload budget to survive the overlay path. Unlike TCP, however, the receiving side must preserve datagram boundaries, so reassembly happens explicitly at mux level before local delivery.

For the `myudp` transport itself, there is an additional lower-layer fragmentation and reassembly mechanism, but it sits below the session API:

- after `ChannelMux` has already produced one session payload, `UdpSession` can hand that payload into the reliable `myudp` framing layer
- that lower layer can fragment the session payload into multiple `DataPacket` frames over UDP
- the peer-side `myudp` session reassembles those fragments back into the original session payload before passing it upward to `ChannelMux`

That means there are now two separate fragmentation layers for different purposes:

- mux-level UDP fragmentation protects UDP service datagrams when the effective session budget is smaller than the original datagram
- `myudp` transport fragmentation protects one already-accepted session payload while it is being carried over the unreliable UDP transport

The `myudp` transport layer still sits below the session API; it is not the mechanism that preserves UDP service datagrams across tight mux/session budgets.

#### TCP

TCP itself is a stream, not a datagram protocol, so there is no protocol-level single-message ceiling analogous to UDP's length field. In this runtime, `TcpStreamSession` imposes a project-local application-frame budget of `65535` bytes and then adds:

- 4 bytes of stream-frame length
- 1 byte of frame kind (`APP`, `PING`, `PONG`)

The important point is that large TCP application traffic is handled by chunking at the mux layer, not by assuming one overlay APP frame must carry an arbitrarily large contiguous stream write.

#### QUIC

The current QUIC session uses the same internal `LEN(4) + KIND(1) + BYTES...` stream framing model as `TcpStreamSession`, but exposes a configurable upper-layer cap through `quic_max_size`.

Implementation boundary note:

- Python QUIC is implemented with `aioquic`
- native Swift QUIC on macOS/iOS is implemented with Network.framework

So parity for QUIC has to be established at the observable behavior level rather than assumed from one shared transport implementation.

That means:

- the QUIC session budget is explicit and configurable
- `ChannelMux` and `SecureLink` both account against that configured budget before sending
- QUIC send-side code also rejects application payloads above `quic_max_size`

So QUIC is conceptually aligned with TCP stream processing, but with an explicit knob rather than a hard-coded `65535` software budget.

Practical Swift note:

- mixed Swift/Python validation found a native Swift QUIC large-write boundary issue on the macOS host-runner service path
- the current Swift workaround splits larger outbound QUIC wires into smaller stream writes before handing them to Network.framework
- the detailed rationale and validation evidence live in [QUIC_DESIGN.md](./QUIC_DESIGN.md)

#### WebSocket

WebSocket has two distinct size concerns:

1. the raw session payload passed down from `ChannelMux` / `SecureLink`
2. the final WebSocket frame size after text encoding, when a text payload mode is enabled

The current runtime handles this by separating the two:

- `WebSocketSession.get_max_app_payload_size()` returns `ws_max_size - 1`, reserving one byte for the internal WS kind marker before payload encoding
- `_ws_frame_max_size` is then computed from the selected payload codec's `max_encoded_size(...)`
- inbound manual WS frame parsing rejects frames larger than `_ws_frame_max_size`

Current codec growth behavior:

- `binary`: no payload expansion beyond the 1-byte kind marker
- `base64`: expansion to `4 * ceil(n / 3)` bytes
- `json-base64`: base64 expansion plus the compact JSON wrapper `{"data":"..."}`
- `semi-text-shape`: expansion to `ceil((8 * n) / 6)` encoded symbols, plus one grouping space after each full group of 8 symbols, for a total of `symbols + floor((symbols - 1) / 8)` characters

Because `_ws_frame_max_size` is derived from the encoded size rather than the raw payload size, the text-oriented modes are explicitly accounted for. This is the code path that prevents healthy traffic from fitting the raw `ws_max_size` budget but then overflowing only after `base64`, `json-base64`, or `semi-text-shape` expansion.

For `semi-text-shape`, the spacing overhead is not data-dependent. The encoder first converts the entire byte stream into consecutive 6-bit symbols and then inserts a space between fixed groups of 8 emitted symbols. That means the worst case is already captured by the exact formula above; it does not depend on particular bit triples such as `000b` appearing in the payload.

### SecureLink encapsulation and growth

For protected application traffic, SecureLink does not change the mux payload semantics; it wraps the already-packed mux frame.

Protected DATA layout is conceptually:

- secure-link header (`version`, `type`, `flags/reserved`, `session_id`, `counter`)
- encrypted ciphertext carrying the plaintext mux frame
- AEAD authentication tag

This is why `SecureLinkPskSession.get_max_app_payload_size()` subtracts `20 + 16` bytes from the wrapped session limit before advertising its own limit upward.

Handshake and rekey control frames can be larger than protected DATA overhead alone:

- PSK mode carries nonces/proofs
- cert mode additionally carries canonical JSON plus base64-encoded certificate/signature/public-key material

Those control frames are still sent through the same wrapped session budget. The runtime does not currently provide a separate fragmentation layer just for SecureLink control frames, so unusually large control payloads still depend on the underlying session limit being large enough.

### Consistency conclusion

The current size-handling story is mostly consistent at the project-internal boundaries:

- `ChannelMux` enforces the wrapped session's advertised maximum application payload size
- `ChannelMux` now fragments oversized UDP service datagrams at mux level and reassembles them before local UDP delivery
- `SecureLink` subtracts its framing and AEAD overhead before advertising its own payload budget upward
- WebSocket text modes account for encoded-frame growth rather than only raw payload size
- TCP stream reads are chunked to fit the current mux/session budget instead of assuming one unbounded frame

The main systematic caveat is narrower and more specific:

- the generic `65535` budget exposed by `UdpSession` and `TcpStreamSession` is a software-layer application budget, not a rigorous proof that every lower-layer envelope or real network path can carry that amount unchanged on the wire

So the architecture is internally coherent now, and it avoids the earlier class of overflow bug where wrapped sessions under-reported their budgets. The remaining caution is that the abstract session budget should not be confused with a guaranteed path-safe wire budget, especially for UDP.

## 2. Secure-link layer

Primary responsibility:

- provide one transport-independent place for overlay authentication, protected carriage, and secure-link diagnostics

Current delivered boundary:

- the delivered secure-link runtime sits below `ChannelMux` and above the peer-address protocol / transport-session boundary

Current contribution:

- PSK-based and certificate-based peer authentication
- session-key establishment
- ciphertext/plaintext transition for mux payloads
- replay protection and rekey hooks
- bounded client-side retry/backoff after repeated auth failures
- secure-link status and failure diagnostics for admin/API consumers
- certificate-root, detached-signature, role, validity-window, deployment-scope, and revoked-serial enforcement in cert mode

Current boundary contract:

- input from transport/session layer:
  - connected byte or datagram path
  - transport lifecycle events such as connect, disconnect, and reconnect
- output to transport/session layer:
  - ciphertext frames or datagrams ready for transport send
- input from `ChannelMux` / framing side:
  - plaintext overlay frames after future integration
- output upward:
  - authenticated plaintext overlay frames only

Current ownership decisions:

- websocket proxy behavior stays in `ARC-CMP-001`; secure-link must not reimplement transport bootstrap
- retransmission policy and RTT/inflight metrics stay in `ARC-CMP-002` until an implementation phase deliberately reworks that boundary
- service publication, channel IDs, and remote catalog state stay in `ARC-CMP-003`
- secure-link config loading and lifecycle wiring belong to `ARC-CMP-004`
- transport bootstrap or websocket-open failures stay owned by the transport/session layer, but their user-visible failed-state reporting belongs to `ARC-CMP-005`
- peer identity visibility in admin APIs belongs to `ARC-CMP-005`
- passive listener rows may stay zeroed in admin snapshots, but live per-peer listener metrics such as RTT on accepted peers must come from peer-local runtime state rather than listener-global defaults
- encryption-layer status visibility in WebAdmin/API is a joint function:
  - `ARC-CMP-006` owns the underlying secure-link state machine and failure categories
  - `ARC-CMP-004` contributes snapshot aggregation and process-level wiring
  - `ARC-CMP-005` contributes HTTP payloads, live admin messages, and webpage rendering

Important non-responsibilities:

- transport-specific socket management remains in the transport/session layer
- service publication and channel semantics remain in `ChannelMux`
- admin rendering remains in the admin web layer
- transport/session implementations remain unaware of certificate policy, identity validation, and traffic ciphers
- `ChannelMux` remains unaware of certificate contents, peer-authentication policy, and traffic ciphers

Current status:

- the PSK-based Phase 1 runtime slice and the certificate-based Phase 2 slice are implemented and defended by unit and integration tests
- delivered runtime behavior currently includes:
  - `secure_link_mode=psk` on `myudp`, `tcp`, `ws`, and `quic`
  - `secure_link_mode=cert` on `myudp`, `tcp`, `ws`, and `quic`
  - authenticated protected carriage below `ChannelMux`
  - live rekey support
  - fail-closed malformed-input handling
  - bounded reconnect/failure throttling after repeated client-side auth failures
  - admin/API visibility of secure-link state and stronger operational diagnostics
- certificate-mode trust-anchor validation, detached signature verification, richer peer identity semantics, and trust-failure visibility are now delivered
- the design baseline and remaining planned work for this component are documented in [SECURE_LINK_DESIGN.md](SECURE_LINK_DESIGN.md)

## 2.5 Compression layer

Primary responsibility:

- reduce wire size for compressible mux payloads without changing `ChannelMux` semantics

Current delivered boundary:

- the compression wrapper sits below `ChannelMux` and above secure-link/session wrappers
- compressed mux frames are signaled by setting the `mtype` high bit (`0x80`)

Current contribution:

- per-frame stateless compression and decompression
- no-gain bypass (frames remain uncompressed when there is no size win)
- passive peer-server decode/activation so listener rows expose compression only for peers that selected it
- bounded decode guardrails for malformed or oversized compressed payloads
- aggregate and per-peer counters surfaced through Admin API and WebAdmin

Technology boundary:

- the current implementation deliberately uses state-of-the-art, battle-tested library compression (`zlib` / DEFLATE from Python stdlib)
- the project does not attempt to invent a custom tunneling codec in this layer

### Functional decomposition for secure-link status visibility

This decomposition applies to the delivered `REQ-AUT-004`, `REQ-AUT-008`, and `REQ-AUT-009` items in [REQUIREMENTS.md](REQUIREMENTS.md), and remains relevant for the planned certificate-mode follow-up.

| Component ID | Contribution to secure-link status visibility |
|---|---|
| `ARC-CMP-006` | Determines whether secure-link is disabled, handshaking, authenticated, failed, or listening; determines mode, failure reason, lifecycle event, retry window, and rekey/auth counters |
| `ARC-CMP-004` | Pulls secure-link state from the wrapped session and places it into process-level status and peer snapshots |
| `ARC-CMP-005` | Exposes the secure-link state through `/api/status`, `/api/peers`, live admin updates, and the WebAdmin page |

The webpage is therefore an explicit contributor to the overall function, not only the API payloads behind it.

The supporting architecture traceability manifest is maintained in [.github/architecture_traceability.yaml](../.github/architecture_traceability.yaml).

## 3. Reliability and framing layer

Primary responsibility:

- turn raw transport datagrams or frames into reliable overlay behavior

Main contribution:

- DATA and CONTROL framing
- retransmission
- missed-frame tracking
- RTT and inflight tracking

Important behaviors:

- cope with delay and loss on `myudp`
- keep counters and state needed for admin visibility
- preserve message integrity for large payloads

This layer is especially important for the `myudp` requirements in [REQUIREMENTS.md](REQUIREMENTS.md).

### Overload and freshness policy

The runtime is not intended to behave like an unbounded store-and-forward buffer.
For the delivered overlay behavior, bounded latency and forward progress are more important than preserving every queued payload indefinitely.

The architectural rule is:

- every buffering boundary must be bounded
- every buffered payload class must have a freshness budget
- overload must trigger backpressure or shedding that matches the traffic type

This matters most for `myudp`, but the policy is deliberately cross-layer because overload can build up at multiple seams in the conveyor belt:

- local TCP/UDP/TUN ingress
- `ChannelMux` channel queues
- reliable transport wait queues
- retransmit/inflight windows
- peer-side reassembly buffers

Under high load, the runtime must prefer:

- fresh control traffic over stale bulk payload
- retransmission of still-fresh missing frames over emission of very old queued frames
- bounded delay over unbounded reliability

The design intent is therefore a bounded real-time overlay, not a reliable archive of old traffic.

#### Traffic-class policy

Different traffic classes are allowed to react differently under overload.

`TUN` traffic:

- IP packets are freshness-sensitive
- queued packets may become semantically useless long before transport delivery would succeed
- the runtime is therefore allowed to drop stale queued TUN packets under pressure

`UDP` service traffic:

- datagram semantics already allow loss
- the runtime is allowed to drop queued or stale UDP datagrams under pressure rather than preserving them indefinitely

`TCP` service traffic:

- TCP already has built-in flow control
- the runtime should prefer reader throttling and socket backpressure over large user-space overlay queues
- if bounded buffering and backpressure are still insufficient, the runtime may fail an affected TCP channel rather than allowing arbitrarily stale backlog to accumulate

#### Safe reduction points vs unsafe drop points

The most important decomposition rule is that not every layer is a safe place to discard payload.
The runtime therefore distinguishes between:

- admission-time reduction, where the system may still choose not to accept more work
- post-admission transport behavior, where the system must preserve ordering/protection semantics for already-admitted work

Safe reduction points:

- before `ChannelMux` admits a local `TUN` packet into the ordered overlay path
- before `ChannelMux` admits a local UDP datagram into the ordered overlay path
- at local TCP read ingress, by pausing or slowing reads so kernel TCP flow control pushes back on the sender
- at TCP channel lifecycle boundaries, by failing a persistently overloaded stream rather than preserving arbitrarily stale backlog

Unsafe drop points:

- arbitrary drop of already-admitted `ChannelMux` TCP stream chunks
- arbitrary drop of secure-link handshake, rekey, or protected control traffic
- arbitrary drop of already-admitted reliable `myudp` data frames that higher layers now depend on for ordered delivery

Architectural implication:

- `UDP` and `TUN` should primarily shed at ingress before admission
- `TCP` should primarily backpressure at ingress before admission
- once payload has entered the ordered reliable protected pipeline, the runtime should either deliver it in order, or fail the owning stream/session; it should not silently discard selected interior frames as an overload tactic

This rule protects three important dependencies:

- `ChannelMux` expects monotonic ordered carriage for admitted stream chunks
- SecureLink expects its control and protected data flow to remain internally coherent
- `myudp` reliability should not be turned into a partial-delivery layer by downstream selective discard

#### Two-stage overload strategy

The intended overload strategy is therefore two-stage:

Stage A: admission control

- decide whether new local traffic may enter the overlay pipeline
- use stream backpressure for `TCP`
- use bounded stale-drop / throttled admission for `UDP` and `TUN`
- drive those `UDP` and `TUN` decisions from the same transport-reported
  backpressure snapshot, regardless of the active overlay protocol

Stage B: in-pipeline scheduling

- once traffic has been admitted, prefer control and fresh recovery work over stale bulk work
- keep already-admitted ordered/protected payload semantically coherent
- if coherence can no longer be preserved with bounded delay, fail the affected channel/session rather than emitting arbitrarily stale traffic much later

This decomposition is the main guardrail against the "inflatable balloon" failure mode where the runtime absorbs unbounded local traffic and releases it too late to remain useful.

#### Architectural consequences

The overload contract implies the following design rules:

- `ARC-CMP-002` must expose bounded inflight and wait-queue behavior, not only retransmission behavior
- `ARC-CMP-003` must distinguish stream-style backpressure (`TCP`) from datagram-style shedding (`UDP`, `TUN`)
- `ARC-CMP-004` must own runtime thresholds and the policy wiring between transport, mux, and service readers
- `ARC-CMP-005` must expose overload state, queue depth, queue age, and drop counters so operators can understand whether the runtime is delaying, shedding, or backpressuring traffic

This means the reliability layer is not only responsible for making loss survivable; it is also responsible for refusing to turn temporary congestion into arbitrarily stale delivery.

#### Required boundedness properties

For overload-safe behavior, the runtime should move toward explicit limits such as:

- maximum inflight frame count
- maximum queued frame count
- maximum queued payload bytes
- maximum queued age per traffic class
- explicit stale-drop thresholds
- explicit TCP reader pause / resume thresholds

The exact threshold values are an implementation concern, but the existence of hard bounds is an architectural concern.

#### Scheduling preference under pressure

When pressure is present, the intended send priority is:

1. liveness, ACK, and other control traffic
2. retransmission of still-fresh missing data
3. fresh interactive traffic
4. fresh bulk traffic
5. stale queued traffic that is already beyond its useful delivery window

The runtime is allowed to shed the last class rather than letting it dominate the tunnel and inflate end-to-end delay for all newer traffic.

#### Operator-visible overload state

The observability surface should eventually expose overload indicators in addition to RTT and transmit delay, for example:

- queue depth in packets/frames
- queue depth in bytes
- oldest queued age
- stale-drop counters by traffic class
- TCP backpressure events
- current overload state such as `normal`, `pressured`, or `shedding`

These signals are needed so rising `transmit_delay_ms` can be interpreted correctly: the operator should be able to tell whether the runtime is still carrying fresh traffic, is beginning to saturate, or is already discarding stale backlog by design.

At present, the implemented ingress-pressure response is based on a unified
transport backpressure snapshot rather than on transport-specific branches.
Every overlay transport contributes a `SessionMetrics` view that includes:

- queue depth / waiting-count
- inflight and max-inflight when the transport exposes them
- transmit-delay estimate
- recent egress throughput measured in rolling `100ms` windows

`ChannelMux` consumes that one snapshot for local admission control. For
freshness-sensitive ingress (`TUN` packets and local UDP datagrams), the next
`100ms` ingress window may admit only `90%` of the bytes that the overlay
actually carried in the previous `100ms` window only while the transport has
reached its configured inflight limit. If the same snapshot reports stalled
forward progress, new local
datagram/packet ingress is paused until progress resumes.

That admission control applies at two levels at once:

- a global local-ingress bucket shared by `TUN` and local UDP together
- a narrower per-scope bucket that preserves fairness between peer/channel
  delivery scopes

The shared bucket means a burst from one ingress source cannot consume overlay
capacity while another source continues admitting traffic as if the budget were
unused. `TUN` and UDP therefore compete for the same aggregate overlay-shaped
budget first, then for their own scope-local budget second.

This keeps `TUN` and UDP ingress aligned on one architecture rule: transports
measure, `ChannelMux` decides, and ingress shedding uses the same data whether
the active overlay is `myudp`, `ws`, `tcp`, or `quic`.

#### Component implementation checklist

The architecture implies the following implementation checklist across the main components.

`ARC-CMP-002` reliability and framing layer:

- add explicit queue-depth and queue-age accounting for reliable transport work
- add bounded wait-queue limits in frames and bytes
- keep control and retransmit traffic above fresh bulk traffic in send scheduling
- do not use selective drop of already-admitted reliable payload as the primary overload tactic
- expose overload state and queue metrics upward

`ARC-CMP-003` channel and service multiplexing layer:

- classify ingress by traffic type: `TCP`, `UDP`, and `TUN`
- add bounded ingress queues for datagram-style traffic
- add stale-drop policy for `UDP` and `TUN` before admission to the ordered overlay path
- add pause/resume backpressure hooks for local TCP readers before admission
- add overload-driven TCP channel failure policy for streams that cannot drain within bounded delay

`ARC-CMP-004` runner and orchestration layer:

- own the runtime thresholds, watermarks, and age budgets
- distribute those policy knobs into transport, mux, and admin subsystems
- ensure reconnect/restart behavior clears overload state cleanly
- keep configuration and defaults coherent across the end-to-end pipeline

`ARC-CMP-005` admin web and observability layer:

- expose queue depth, queue age, overload state, and drop/backpressure counters in `/api/status`
- expose per-peer/per-session overload state in `/api/peers` where relevant
- render those signals in the WebAdmin UI next to RTT/transmit-delay context
- preserve enough diagnostics to distinguish healthy delay, pressure, shedding, and collapse

Transport/session layer:

- provide the hooks needed for ingress pause/resume and datagram admission control
- avoid transport-specific buffering behavior that bypasses the shared overload policy
- preserve transport-local liveness/control paths even while bulk ingress is being reduced

Secure-link layer:

- ensure handshake, rekey, and protected control traffic are not treated as ordinary drop-eligible bulk payload
- tolerate admission-side reduction in outer traffic classes without leaving internal protocol state ambiguous
- fail and recover cleanly if bounded-delay guarantees can no longer be preserved for the protected session

These checklist items are intentionally architectural rather than code-local. They describe what each component must contribute so the overload policy becomes a property of the whole conveyor belt rather than a one-off queue cap in one layer.

## 4. Channel and service multiplexing layer

Primary responsibility:

- map overlay traffic to exposed TCP/UDP services

Main contribution:

- `own_servers` handling
- `remote_servers` handling
- per-channel open/data/close behavior
- per-peer service scoping

Important behaviors:

- multiple concurrent TCP channels on one peer
- mixed UDP and TCP services on one peer
- per-peer isolation in listener mode
- cleanup on disconnect
- peer-scoped mutation only: routing, remote catalog changes, and disconnect cleanup must always act on the owning peer rather than on listener-global shortcuts inherited from earlier single-peer designs
- transport-appropriate overload handling: backpressure for stream ingress where possible, bounded shedding for freshness-sensitive datagram ingress where necessary

This is the main realization layer for listener and mixed-service requirements.

## 5. Runner and process orchestration layer

Primary responsibility:

- compose the configured transports, mux, and admin systems into one runnable process
- supervise process restarts at the runtime entrypoint boundary

Main contribution:

- launcher entrypoint (`python -m obstacle_bridge`) handles restart supervision and runner-only options
- bridge runtime (`bridge.py`) owns the full transport/mux/admin CLI and in-process runtime behavior
- forwards non-launcher options from the launcher to `bridge.py` unchanged
- keeps restart policy outside `bridge.py` so the core runtime stays focused on one process lifecycle

Important behaviors:

- reconnect support
- restart handling
- process-safe event binding
- configuration persistence
- privilege handoff at the Python entrypoint boundary when desktop local TUN backends need elevation
- policy ownership for overload thresholds and whether a given ingress path should pause, drop stale payload, or fail a channel under sustained pressure

### Entrypoint split (`bridge.py` vs module launcher)

The runtime restart design is intentionally split:

- `src/obstacle_bridge/bridge.py`:
  - parses the full bridge/runtime CLI surface (`--config`, transport, mux, admin, secure-link, logging)
  - builds sessions and runs the in-process runtime (`Runner`)
  - can be called directly as `python -m obstacle_bridge.bridge`
- `python -m obstacle_bridge` (implemented by `src/obstacle_bridge/__main__.py` + `src/obstacle_bridge/launcher.py`):
  - provides restart supervision behavior
  - understands launcher-only options (`--interval`, `--no-redirect`, optional `--command`)
  - forwards unknown options to `bridge.py`, so bridge CLI flags remain first-class on the default entrypoint

## 6. Admin web and observability layer

Primary responsibility:

- make runtime state observable and manageable

Main contribution:

- health/status/peers/connections APIs
- configuration API and UI
- debug logs and log retrieval
- authentication and session control

Important behaviors:

- show connected peers and listener state
- show per-connection and aggregate transfer state
- isolate authenticated sessions per client
- support troubleshooting and regression validation
- expose overload diagnostics such as queue pressure, stale-drop behavior, backpressure activity, and transport freshness metrics so operators can distinguish healthy delay from overload collapse

## Component responsibilities

### Transport runtimes

Expected to own:

- transport-specific sockets/connections
- connect/listen behavior
- per-peer transport state where required
- transport-specific client bootstrap steps such as proxy discovery, tunnel setup, or transport preflight when those are needed before the overlay session can start

Expected not to own:

- service publication logic
- application protocol semantics

### Reliability/session logic

Expected to own:

- frame numbering
- missed-frame tracking
- retransmission decisions
- RTT and inflight metrics
- bounded wait-queue policy, queued-age accounting, and stale-drop eligibility for reliability-managed payload buffers

Expected not to own:

- UI concerns
- service binding policy

### ChannelMux and related service machinery

Expected to own:

- mapping between overlay channels and local TCP/UDP services
- peer-scoped remote service state
- listener lifecycle for published services
- ingress policy selection between backpressure and shedding based on traffic type

Expected not to own:

- transport-specific socket semantics beyond the abstraction it consumes

### Runner

Expected to own:

- composition
- startup/shutdown lifecycle
- config and argument integration
- platform-gated enablement of optional transport features such as Windows `Negotiate` proxy authentication, while preserving platform-default proxy discovery semantics
- wiring of overload thresholds and runtime policy knobs across transport, reliability, mux, and observability boundaries

Expected not to own:

- detailed transport framing policy
- detailed admin rendering logic

### Admin web

Expected to own:

- HTTP API
- auth session control
- presentation of runtime state
- exposure of overload, queue, delay, drop, and backpressure diagnostics in machine-readable and browser-visible form

Expected not to own:

- transport behavior itself

## WebSocket proxy tunneling

Scope:

- WebSocket peer client only
- HTTP proxy traversal with `CONNECT`
- default proxy discovery from platform-native settings
- proxy authentication via `Negotiate` / NTLM-style Windows credentials where supported

Intended layering:

1. the runner/configuration layer decides whether platform-default proxy behavior is used or consciously overridden for the websocket client
2. the transport/session layer performs proxy discovery from system settings or uses explicitly configured proxy settings
3. the transport/session layer establishes a TCP tunnel to the proxy target
4. after the tunnel is established, the existing websocket handshake continues over the tunneled socket
5. the higher reliability, mux, and admin layers remain unchanged

Architectural consequence:

- proxy support belongs in the websocket client bootstrap path, not in the overlay framing or channel mux logic
- this capability should be isolated so it does not accidentally appear as a cross-transport or listener-side feature before those variants are explicitly designed
- platform-specific details should stay below the shared websocket client contract: Windows may use system proxy APIs and `Negotiate`, while Linux/POSIX may use `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`

Functional decomposition:

- project-owned responsibilities:
  - decide the effective proxy mode for the websocket peer client: platform default, explicit manual proxy, or explicit direct-connect override
  - discover the proxy endpoint from Windows system settings or Linux/POSIX `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
  - keep proxy behavior scoped to websocket peer-client mode so listener mode and non-websocket transports do not silently inherit it
  - establish the HTTP `CONNECT` tunnel before starting the websocket handshake
  - handle proxy failure as an observable connection failure without corrupting the overlay state machine
  - neutralize library-level proxy autodiscovery when application configuration says to connect directly, so one clear proxy policy is enforced by the application
- library-owned responsibilities:
  - perform the websocket HTTP upgrade and websocket frame processing once the application has provided either a direct TCP path or a proxied tunnel
  - preserve normal websocket reconnect and I/O behavior above the socket path selected by the application
- ownership boundary:
  - proxy policy is an application contract, not a library default
  - the `websockets` dependency is used as the websocket protocol engine after proxy selection and tunnel bootstrap are complete
  - if the library offers independent proxy features, they must not compete with the application-owned proxy decision path

Concrete mapping in the current implementation:

- runner and CLI configuration select the effective proxy mode for each `WebSocketSession`
- runner and CLI configuration also select the client-advertised websocket payload form, while each accepted listener-side peer binds its own effective payload codec from the upgrade request metadata
- `WebSocketSession._get_ws_proxy_endpoint(...)` resolves the proxy endpoint from manual settings, platform defaults, or environment variables
- `WebSocketSession._open_ws_proxy_socket_blocking(...)` owns HTTP `CONNECT` setup and proxy authentication preconditions
- `WebSocketSession._suspend_library_proxy_env()` keeps the dependency from silently re-introducing proxy behavior that bypasses the application contract
- `websockets.connect(...)` owns the websocket handshake and framed transport after the direct socket or proxy tunnel already exists

## Test implications

This architecture implies a testing split:

- integration tests primarily defend requirements at the transport, listener, reconnect, and admin behavior level
- unit tests primarily defend component contracts such as ChannelMux scoping, snapshot formatting, runner event wiring, and websocket-specific behavior

The first traceability mappings for integration and unit coverage are maintained in [README_TESTING.md](README_TESTING.md), and should refer to the stable component IDs above where architecture-level traceability is needed.
