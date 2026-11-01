# Swift concurrency migration inventory

## Current boundary

SwiftPM compiles the complete test graph with
`-strict-concurrency=complete`. New `@unchecked Sendable` conformances and new
synchronous coordination primitives in a legacy unchecked owner are rejected
by `scripts/check_swift_concurrency_guard.py`.

The remaining unchecked conformances are a migration inventory, not an
approval to add lock-based ownership. The remaining inventory contains 75
declarations:

| Area | Owners | Migration direction |
| --- | ---: | --- |
| Shared Core | 15 | Isolate mutable protocol, telemetry, catalog, and metrics state in actors; return immutable `Sendable` effects and snapshots. |
| Desktop shared | 6 | Put worker lifecycle and IPC request state behind actor-owned asynchronous continuations. |
| Linux adapters/runtime | 42 | Keep descriptor callbacks on their existing serial asynchronous owner, expose actor-facing state/effects, and remove cross-queue mutable access. |
| Executable workers | 3 | Make the event-loop-owned state an actor or a non-Sendable executor-local value. |
| Test fixtures | 9 | Replace lock-backed sendability fixtures with actors or executor-confined test helpers. |

The authoritative live inventory is deliberately machine-checkable rather than
copied by hand:

```sh
rg -n '@unchecked Sendable' swift --glob '*.swift'
```

## Required conversion shape

1. Make the owner an `actor`, or keep it non-Sendable and confine it to one
   established asynchronous serial executor.
2. Replace synchronous `wait`, semaphore, and lock handoff with `await`, task
   continuations, or callback-to-async bridging at the I/O boundary.
3. Pass immutable `Sendable` request, effect, and snapshot values across the
   actor boundary. Do not pass an owner reference back across that boundary.
4. Make lifecycle cancellation explicit: a close/shutdown effect must resume
   or cancel every pending continuation exactly once.
5. Delete the `@unchecked Sendable` conformance only after the target compiles
   under complete checking and its close/reconnect/concurrency regression is
   exercised.

## Ordering

The migration is ordered by execution model rather than line count:

1. Core telemetry upload/emission and metrics state: these have bounded
   request/effect surfaces and can become actors without placing file or
   network work on the packet callback path.
2. Core protocol state machines (myUDP and SecureLink): convert their state
   transition to actor methods and retain pure codecs as `Sendable` values.
   ChannelMux sessions, egress scheduling, packet reassembly, TUN binding
   state, TUN drop accounting, overlay lifecycle coordination, and service
   catalogs are executor-confined non-Sendable state inside their transport
   runtimes; they publish only immutable effects, results, and snapshots.
3. Desktop worker supervisors: replace correlated reply maps and lifecycle
   flags with actor-owned continuations before changing child-process I/O.
4. Linux descriptor owners: preserve the existing nonblocking
   `DispatchSource`/NIO callbacks, but funnel callback facts through a single
   actor and publish immutable effects to resource code.
5. Executables and test fixtures: remove the remaining unchecked ownership
   after their production owner no longer requires it.

`ObstacleBridgeChannelMuxReplyPolicy` and the Admin peer-rate sampler are not
shortcuts for this work: both currently have synchronous callers. They must be
lifted through their callers to asynchronous actor operations; replacing their
locks with `Mutex` would violate this migration boundary.

## Compliance checks

```sh
swift test list
python scripts/check_swift_concurrency_guard.py --base-ref <base-sha>
pytest -q tests/unit/test_swift_concurrency_guard.py tests/unit/test_async_io_guards.py
```

These checks prove complete compiler checking, prevent new unchecked and
lock-based exemptions, and retain regression evidence while the inventory is
reduced.
