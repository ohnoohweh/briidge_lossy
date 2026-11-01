# Swift concurrency migration inventory

## Current boundary

SwiftPM compiles the complete test graph with
`-strict-concurrency=complete`. New `@unchecked Sendable` conformances and new
synchronous coordination primitives in a legacy unchecked owner are rejected
by `scripts/check_swift_concurrency_guard.py`.

The remaining unchecked conformances are a live migration inventory, not an
approval to add lock-based ownership. The inventory contains 47 declarations:

| Area | Owners |
| --- | ---: | --- |
| Shared Core | 0 |
| Desktop shared | 0 |
| Linux adapters/runtime | 37 |
| Executable workers | 1 |
| Test fixtures | 9 |

The authoritative live inventory is deliberately machine-checkable rather than
copied by hand:

```sh
rg -n '@unchecked Sendable' swift --glob '*.swift'
```

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
ownership boundaries.

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
The Linux Admin security and configuration owners are non-Sendable. HTTP
handlers exchange decoded value requests, responses, snapshots, and updates
without transferring either mutable owner.

The remaining unchecked owners still have shared mutable lifetime, I/O, or
request-correlation state. They retain the existing compatibility boundaries
until their callers expose asynchronous actor operations. A new lock,
semaphore, synchronous wait, or `Mutex` is not an accepted replacement.

## Compliance checks

```sh
swift test list
python scripts/check_swift_concurrency_guard.py --base-ref <base-sha>
pytest -q tests/unit/test_swift_concurrency_guard.py tests/unit/test_async_io_guards.py
```

These checks prove complete compiler checking, prevent new unchecked and
lock-based exemptions, and retain regression evidence while the inventory is
reduced.
