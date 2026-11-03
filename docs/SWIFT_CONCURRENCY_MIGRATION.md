# Swift concurrency migration inventory

## Current boundary

SwiftPM compiles the complete test graph with
`-strict-concurrency=complete`. New `@unchecked Sendable` conformances and new
synchronous coordination primitives in a legacy unchecked owner are rejected
by `scripts/check_swift_concurrency_guard.py`, except for the named,
machine-tested Apple serial bridges below.

The remaining unchecked conformances are a live migration inventory, not an
approval to add lock-based ownership. The inventory contains 44 declarations:

| Area | Owners |
| --- | ---: | --- |
| Shared Core | 0 |
| Desktop shared | 0 |
| Apple shared | 22 |
| Linux adapters/runtime | 22 |
| Executable workers | 0 |
| Test fixtures | 0 |

The authoritative live inventory is deliberately machine-checkable rather than
copied by hand:

```sh
rg -n '@unchecked Sendable' swift --glob '*.swift'
```

## Apple product strict-concurrency findings

The SwiftPM graph is not the full Apple product compile surface. The macOS
packaging build compiles the HostRunner, macOS application, shared Apple
transports, and the shared iOS tunnel-control source. Its initial complete
checking run produced 410 compiler warning records across 14 source files. The
first migration slice isolated the macOS AppKit entry point; the verified
current baseline is 94 warning records across 1 source file. The same
source can be compiled into more than one product, so this number is a
compiler-output baseline rather than a count of distinct code locations.

| Compile area | Warning records | Affected source files |
| --- | ---: | --- |
| macOS host | 108 | `ObstacleBridgeHostRunner.swift` (108) |

The macOS application entry point now isolates its AppKit and WebKit state with
`@MainActor`, and its timer callback explicitly re-enters that actor before
probing WebAdmin. Its control-request completion is an
`@MainActor @Sendable` closure so URLSession can transfer it back to the UI
owner without sharing non-Sendable state. The full macOS package build verifies
that `ObstacleBridgeMacAppMain.swift` emits no strict-concurrency diagnostics.

The telemetry uploader's upload completion is `@Sendable`, so the URLSession
callback does not transfer a non-Sendable completion. Certificate challenge
handling now lives in a dedicated URLSession delegate that owns only the
credential; the mutable policy and status uploader is no longer itself a
delegate. The verified macOS package build reduced this source from six warning
records to two: both are the uploader's `self` capture in the URLSession
completion, once for each product. An actor cannot simply retain the existing
policy while the synchronous admin projection retains it too: complete checking
correctly reports that transfer as a possible race.

The uploader now gives the policy one owner:
`ObstacleBridgeTelemetryLockedUploadState` owns the policy and all upload
counters behind one `NSLock`, and `statusSnapshot()` takes that same lock. The
URLSession completion captures only that state, never the uploader. Its
`@unchecked Sendable` conformance is the sole exception to the general ban,
constrained by an exact path, owner name, and test marker in the guard. The
verified macOS product build emits no telemetry-uploader diagnostics.

The UDP client and server connection drivers are likewise serial-owner bridges:
their mutable state and owner callbacks stay on the injected transport queue,
while Network callbacks transfer only their immutable callback values onto that
queue. Their audited Sendable conformances eliminate 18 diagnostics without
moving packet processing off its established synchronous owner.

The UDP overlay transport owner extends that same queue-confined boundary to
its overlay lifecycle and local UDP connection state. Its Network and overlay
callbacks bind an immutable owner before re-entering the transport queue. The
audited conformance eliminates 22 diagnostics while retaining its synchronous
owner-queue operations.

HostRunner itself is an audited serial bridge: its Network and XPC callbacks
synchronously re-enter `serviceStateQueue` (or the specific sibling queue
that owns the relevant state) before any mutation. This preserves lifecycle
ordering at imported-framework boundaries and avoids transferring mutable
proxy, service-specification, or callback-result state through an unowned
asynchronous closure.

Service specifications, their recursive JSON values, and TCP acceptance
snapshots are immutable `Sendable` value types. Network listener callbacks can
therefore carry configuration and acceptance effects across the imported
framework boundary without sharing a mutable runtime owner.

The UDP and TCP listener handlers synchronously enter that same service queue.
The UDP proxy registry uses an immutable UUID lifecycle key rather than a
captured mutable proxy variable, so proxy callbacks cannot race construction
or teardown.

XPC helper completions also synchronously refresh the host-owned helper
snapshot. Their result and client references therefore never cross a second
concurrently executing Dispatch closure after the imported XPC callback.

HostRunner telemetry is now a separate lock-owned state cell. Its timer,
upload drain, lifecycle events, health events, and admin snapshot retain only
that state cell, never the multi-domain HostRunner. This removes the telemetry
timer's HostRunner transfer warnings while preserving synchronous lifecycle
control.

HostRunner admin snapshots are likewise a lock-owned cache. Service refreshes
and the runtime-metrics task publish into that cache synchronously, so the
metrics task does not transfer HostRunner or its dictionary payload through a
nested Dispatch closure.

Remote service-catalog installation synchronously enters HostRunner's existing
service-state owner, preserving listener ordering without transferring the
runner or catalog payload to an unowned asynchronous closure.

Tunnel control now keeps its cross-callback manager, foreground-proxy, and
host-runner references in a lock-owned state cell, and its synchronous
privileged-host status request uses a separate lock-owned response cell. The
NetworkExtension import is explicitly preconcurrent: it is an imported Apple
framework boundary, while repository-owned references remain synchronized.
The verified macOS build emits no diagnostics from
`ObstacleBridgeTunnelControl.swift`.

The TCP overlay owner applies the same boundary to its lifecycle, local TCP and
UDP acceptance, and local TUN injection: each public mutation synchronously
marshals to its queue, and Network callbacks capture an immutable owner before
re-entering it. Its audited serial conformance eliminates 50 diagnostics while
preserving the existing owner-queue transport lifecycle.

The WebSocket overlay owner applies this serial boundary to URLSession delegate
work, Network callbacks, public lifecycle mutations, and send completions.
Its external completion type is explicitly Sendable and every completion
re-enters the owner queue through an immutable owner reference. The audited
conformance eliminates 42 diagnostics without changing WebSocket sequencing.

The proxy listener and each proxy session share one Network queue. Lifecycle
and snapshot operations synchronously enter that queue; request forwarding is
made immutable before send completion, and connect/reply continuations are
Sendable. This audited boundary eliminates 40 diagnostics.

The native TCP and UDP proxy connections follow the same serial-owner rule:
their Network connections start on the injected proxy queue, which owns every
mutable connection field and callback. Their audited conformances eliminate 16
diagnostics without changing the synchronous proxy lifecycle.

The WebAdmin server and its live sessions are confined to the server's serial
listener queue. Their audited conformances eliminate 18 diagnostics while
retaining the existing synchronous start-and-wait contract.

The XPC-helper bridge now gives reachability one synchronized owner and each
ping or command one lock-owned request state. That request state arbitrates the
reply, proxy-error, and timeout paths, records the winning result exactly once,
and invokes its completion outside the lock so a client may safely re-enter its
own lifecycle queue. The verified macOS product build emits no diagnostics from
`ObstacleBridgeTunHelperXPCTransport.swift`. The completion-owned helper client
is still captured by HostRunner callbacks without a Sendable boundary; that
remaining issue belongs to the HostRunner inventory. Marking the whole XPC
client Sendable would hide the callback transfer defect and is not an
acceptable substitute.

This is deliberately Apple-specific at the implementation boundary because it
owns `NSXPCConnection` reply/error callbacks. Linux has the same general
exactly-once request-completion requirement, but uses different IPC owners; it
must be audited in those owners rather than sharing an Apple XPC wrapper.

The findings fall into four migration groups:

1. Dispatch, Network, URLSession, XPC, and Network Extension callbacks capture
   non-Sendable owners, `self`, completion closures, or values such as
   `[String: Any]`, service specifications, and `NETunnelProviderManager`.
   Several of these diagnostics become errors in Swift 6 language mode.
2. Long-lived Network transport and proxy classes are inferred Sendable through
   imported callback protocols, while retaining mutable state or non-Sendable
   runtime and callback properties. The TCP, UDP, QUIC, ChannelMux, WebSocket,
   proxy, and telemetry owners require explicit actor or serial-executor
   ownership before they can satisfy that contract.
3. Shared mutable statics are not isolated: the HostRunner reference, Admin-Web
   proxy reference, and active tunnel manager are reported as
   non-concurrency-safe global state.
4. Callback implementations also capture mutable local variables such as
   `self`, connections, proxy references, forwarded bytes, and tunnel-control
   response payloads. Those values must be represented by immutable snapshots
   or retained inside the owning actor/serial boundary rather than captured by
   concurrently executing closures.

The remediation order is: first isolate global and callback-owner state, then
replace cross-boundary dictionaries and closures with Sendable value snapshots
or actor operations, then make each completion route re-enter its owner. Do
not address this baseline by adding `@unchecked Sendable`, locks, semaphores,
or warning suppression; those mechanisms would hide the ownership defects that
complete checking identifies. The documented telemetry state, queue-confined
Network bridges, reachability state, and XPC request states are narrow audited
synchronous exceptions with named ownership and regression evidence.
`@preconcurrency` is only appropriate at a
documented imported-framework boundary after the repository-owned callback
ownership is otherwise sound.

## Current ownership model

ChannelMux sessions, egress scheduling, packet reassembly, TUN binding state,
TUN drop accounting, overlay lifecycle coordination, service catalogs, myUDP
peer state, SecureLink PSK state, and telemetry producer, spool, and upload
state are non-Sendable values. Their modern concurrency boundaries exchange
only immutable `Sendable` effects, results, events, requests, and snapshots.
Their synchronous entrypoints retain their existing serialization semantics.

The desktop child log producer is non-Sendable child-local state. It publishes
only immutable record datagrams to its inherited producer-only descriptor.
The native Admin parent RPC is non-Sendable child-local state and returns only
decoded value results from its inherited control descriptor.
The desktop log relay is non-Sendable state owned by its descriptor-readiness
source and forwards only immutable record datagrams.
The desktop log-worker supervisor is non-Sendable. Its bounded query refresh is
correlated and completed inside its query-state boundary, so no Sendable
completion captures the supervisor.
The desktop proxy-worker control and lifecycle supervisors are non-Sendable;
their inherited-control reader and restart state remain within their serialized
ownership boundaries. The native proxy listener is actor-owned; every client
session receives immutable settings and reports immutable traffic deltas back to
the listener actor.

The ChannelMux reply policy is non-Sendable and remains private to its session
owner; it is not transferred between executors.
The peer traffic-rate sampler is non-Sendable and remains private to its Admin
owner; it is not transferred between executors.
Compression telemetry is non-Sendable and remains private to its configured
runtime/session ownership chain; it is not transferred between executors.

Runtime metrics aggregation is actor-owned. Its reporter sends measurements
asynchronously, while iOS, macOS, and Linux Admin status owners asynchronously
publish immutable metric-projection bytes into their existing status caches.
Status reads return the most recently completed projection without awaiting the
metrics actor.
The Linux foreground restart request is actor-owned; it records the request
before raising the shutdown signal, and shutdown consumes it exactly once.
The native log collector state is non-Sendable and owned by its main worker
loop, which drains the bounded descriptor directly.
The native proxy child logger is a checked Sendable immutable descriptor and
threshold value; its level is fixed before listeners are published.
Linux stream-listener peer accounting is non-Sendable and remains private to
the listener owner that serializes admission and write tracking.
The Linux native peer child control owner is non-Sendable and keeps its stream
decoder and inherited descriptor on one readiness queue.
The Linux QUIC and TLS-WebSocket connection, pipeline handlers, TLS
configuration handoff, and TLS-WebSocket accepted connection are non-Sendable
and remain owned by their channel pipelines.
The configured-runtime connection admission is non-Sendable and remains owned
by its transport lifecycle.
The Linux proxy relay is actor-owned; descriptor readiness callbacks re-enter
the relay actor and completion returns only a descriptor and outcome value.
The native-Admin live session is actor-owned; its descriptor and timer
callbacks asynchronously re-enter the actor and only its immutable control
values cross the boundary.
The Linux Admin security and configuration owners are non-Sendable. HTTP
handlers exchange decoded value requests, responses, snapshots, and updates
without transferring either mutable owner.
The Linux telemetry uploader is non-Sendable. Its private queue performs
network I/O and publishes immutable status snapshots.
The Linux observability owner is non-Sendable. Its dedicated file-I/O queue
publishes only telemetry and diagnostic value snapshots.
The receive-worker delivery fixture records immutable delivery snapshots in an
actor; its synchronous callback source remains test-local and non-Sendable.
The overlay async-delivery fixture is actor-owned; transport callbacks await
its immutable payload snapshot rather than sharing lock-backed mutable data.
The service-socket fixtures are actor-owned; listener and target callbacks
asynchronously record immutable frame and datagram snapshots before signaling
their test expectations.
The native-Admin HTTP response fixture is actor-owned; each HTTP worker records
its immutable response before asynchronously releasing its test expectation.
The Unix helper test peer is actor-owned. Its socket server and captured
operation, packet, and JSON payload values remain isolated; tests inspect only
immutable snapshots after the expected exchanges complete.
The Linux reconnect supervisor is actor-owned; its timer asynchronously
re-enters the actor, and retry state and snapshots never leave actor isolation.
The transport-specific lifecycle subclasses inherit the base lifecycle owner's
serialization boundary and introduce no mutable state or concurrency boundary
of their own.
The managed Linux TUN-helper process owner is non-Sendable and remains confined
to its foreground runtime; the checked compiler accepts every existing use
without a Sendable exemption.
The native Linux TUN-helper backend is non-Sendable and remains confined to
the helper server's request-processing boundary; callers exchange decoded
request and response values rather than transferring the backend.
The shared myUDP listener runtime is non-Sendable and remains confined to its
serialized listener queue; its reader handoff uses an explicit work item rather
than transferring the owner through a Sendable closure.
The TCP and cleartext-WebSocket listener is non-Sendable. Its concrete listener
and session-admission loop stay together in one serial work item, instead of
being captured by type-erased Sendable admission callbacks.
The shared myUDP transport listener is non-Sendable and remains in its
foreground listener runtime. Its per-peer synchronous receive handoff is a
separate remaining owner.

Each remaining unchecked owner has shared mutable lifetime, I/O, or
request-correlation state. Its migration requires callers to expose
asynchronous actor operations; a new lock, semaphore, synchronous wait, or
`Mutex` is not an accepted replacement.

## Compliance checks

```sh
swift test list
python scripts/check_swift_concurrency_guard.py --base-ref <base-sha>
pytest -q tests/unit/test_swift_concurrency_guard.py tests/unit/test_async_io_guards.py
```

These checks prove complete compiler checking, prevent new unchecked and
lock-based exemptions, and retain regression evidence while the inventory is
reduced.
