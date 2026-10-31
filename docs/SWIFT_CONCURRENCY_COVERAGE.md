# Swift unchecked-sendable concurrency coverage

## Scope

`@unchecked Sendable` is used only where an owner supplies an explicit
synchronization boundary that Swift cannot prove. The concurrency guard rejects
new mutable collection changes in these owners unless the changed diff includes
an `OBSTACLEBRIDGE-CONCURRENCY` marker naming that boundary and its exercising
test suite. The guard is run with the PR base SHA:

```sh
python scripts/check_swift_concurrency_guard.py --base-ref <base-sha>
```

The listed owners were already present when the guard was introduced. They are
explicitly marked below so subsequent edits cannot silently extend an unchecked
mutable state boundary without recorded synchronization and test coverage.

## Delivered coverage

| Owner | Synchronization boundary | Exercising coverage | Crash class prevented |
| --- | --- | --- | --- |
| `ObstacleBridgeAdminPeerTrafficRateSampler` | `NSLock` protects `previous` | `ObstacleBridgeTelemetryTests` | Concurrent dictionary mutation while sampling/removing peers |
| `ObstacleBridgeChannelMuxEgressSequencer` | `NSLock` protects queues and ready sets | `ObstacleBridgeChannelMuxEgressSequencerTests` | Concurrent queue/set mutation and corrupted egress order |
| `ObstacleBridgeNativeAdminWorker.ParentRPC` | `NSLock` serializes request/reply and failure state | `ObstacleBridgeWorkerIPCTests` | Interleaved parent RPC frames or stale reply state |
| `ObstacleBridgeLinuxAdminServer` | private serial dispatch queue owns client maps | `ObstacleBridgeLinuxAdminServerTests` | Concurrent HTTP client source/request-map mutation |
| `ObstacleBridgeLinuxConfiguredSession` | request and protocol locks protect handoff state | `ObstacleBridgeLinuxLiveRuntimeTests` | Concurrent handshake/reply state mutation during transport callbacks |
| `ObstacleBridgeLinuxLiveRuntime` | transport queue plus status/runtime-health locks | `ObstacleBridgeLinuxLiveRuntimeTests` | Service-owner/channel map mutation racing shutdown or Admin reads |
| `ObstacleBridgeLinuxQUICSession` | `NSLock` and condition-owned inbound state | `ObstacleBridgeLinuxOverlayTransportTests` | NIO callback/close races over channel and inbound state |
| `ObstacleBridgeLinuxServiceSocketOwner` | one private serial dispatch queue owns descriptors and channel maps | `ObstacleBridgeLinuxServiceSocketOwnerTests` | Socket readiness callbacks racing descriptor/channel teardown |
| `ObstacleBridgeLinuxTLSWebSocketConnection` | `NSLock` and condition-owned TLS state | `ObstacleBridgeLinuxOverlayTransportTests` | TLS/NIO callback racing close or handshake completion |
| `ObstacleBridgeLinuxTunHelperPacketDevice` | `NSLock` owns descriptor, generation, and lifecycle state | `ObstacleBridgeLinuxTunHelperAdapterTests` | Helper readiness callback racing stop/reconnect |
| `ObstacleBridgeLinuxTunHelperServer` | serial queue for client sources plus locks for cross-queue snapshots | `ObstacleBridgeLinuxTunHelperAdapterTests` | Client parser/source-map mutation racing watchdog/stop |
| `ObstacleBridgeNativeAdminLinuxService` | private serial dispatch queue owns HTTP client state | `ObstacleBridgeLinuxTunDeviceTests` | Native Admin client source/request-map mutation racing close |
| `CollectorState` | main-thread serial poll loop owns the log ring | `test_native_log_collector` | Concurrent log-ring mutation while datagrams are drained/replied |

## Known gaps and follow-up boundary

The named suites exercise lifecycle, round-trip, and close paths, but they are
not a general-purpose race detector. Linux-only integration suites cannot run
on macOS hosts; CI runs them on Linux. The remaining gap is adversarial,
high-contention scheduling (for example, randomized concurrent close/write
loops under Thread Sanitizer). That work is deliberately separate from the
runtime safety boundary: each production mutable collection is already owned
by a lock or serial executor, and future edits are rejected unless they retain
both that evidence and a named exercising test.
