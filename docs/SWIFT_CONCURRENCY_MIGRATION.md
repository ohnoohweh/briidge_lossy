# Swift concurrency migration inventory

## Current boundary

SwiftPM compiles the complete test graph with
`-strict-concurrency=complete`. New `@unchecked Sendable` conformances and new
synchronous coordination primitives in a legacy unchecked owner are rejected
by `scripts/check_swift_concurrency_guard.py`.

The remaining unchecked conformances are a live migration inventory, not an
approval to add lock-based ownership. The inventory contains 63 declarations:

| Area | Owners |
| --- | ---: | --- |
| Shared Core | 4 |
| Desktop shared | 5 |
| Linux adapters/runtime | 42 |
| Executable workers | 3 |
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
