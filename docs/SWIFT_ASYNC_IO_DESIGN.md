# Swift Asynchronous I/O Boundary Plan

Every long-lived Swift communication receiver is owned by a readiness callback
or a framework callback. A receiver must not hold an arbitrary worker thread
in `read`, `recv`, `FileHandle.read`, `NSCondition.wait`, or a polling loop
while it waits for peer input. Stream receivers retain partial bytes and decode
only complete records after the next callback. Closing an owner cancels its
readiness source before its descriptor or channel is released.

## Delivered boundaries

| Product | Boundary | Receive ownership | Evidence |
| --- | --- | --- | --- |
| Linux | myUDP, TCP, WebSocket, TLS WebSocket, QUIC outbound overlay | POSIX `DispatchSourceRead` or NIO inbound callback with incremental record buffers | `ObstacleBridgeLinuxOverlayTransportTests` |
| Linux | local TCP/UDP service sockets | nonblocking listener plus `MSG_DONTWAIT` drain on the serial service owner | `ObstacleBridgeLinuxServiceSocketOwnerTests` |
| Linux | inline TUN | `DispatchSourceRead` plus nonblocking TUN descriptor | `ObstacleBridgeLinuxTunDeviceTests` |
| Linux | long-lived helper packet/event IPC | `DispatchSourceRead` plus incremental OBIP frame buffer | `packetDeviceReceivesHelperPacketAndEventThroughReadinessSource` |
| macOS | Network.framework overlay, proxy, Admin, and service sockets | Network.framework receive completion | Apple host/simulator adapter tests |
| macOS | `utun` packet device | `DispatchSourceRead` plus `O_NONBLOCK` descriptor | macOS adapter tests |
| iOS | packet tunnel and Network.framework transport | `NEPacketTunnelFlow`/Network.framework callbacks | iOS extension tests and device qualification |

## Remaining conversion work

The following boundaries are intentionally not described as fallbacks: their
underlying POSIX, NIO, or XPC dependency has an asynchronous boundary, so they
must be converted rather than retained indefinitely.

| Boundary | Current synchronous operation | Required replacement |
| --- | --- | --- |
| Linux TCP and TLS-WebSocket listener admission | framed SecureLink and HTTP-upgrade reads | listener-owned readiness state machine with incremental HTTP/WebSocket/OBIP buffers |
| Linux foreground and native-child Admin web servers | per-client HTTP reads and live-WebSocket polling loops | per-client readiness source and timer-driven live-topic scheduler |
| Linux native peer/Admin worker IPC | `FileHandle` framed reads after bootstrap | descriptor readiness source with generation-fenced incremental OBIP decoder |
| Linux TUN helper control IPC | synchronous request/reply reads | callback-based correlated control requests; preserve independent request deadline |
| Linux and desktop logging collector/supervisor query | blocking poll/receive request paths | descriptor readiness handling and callback completion for bounded queries |
| macOS XPC helper control | semaphore wait around XPC reply | async XPC command completion propagated to the caller's lifecycle owner |

## Narrow bootstrap exception

A process may perform a bounded synchronous read only before it owns an event
loop, solely to authenticate and validate an inherited one-time bootstrap
descriptor. The descriptor must have a deadline, reject partial or stale
frames, and transition to a readiness owner before it begins a long-lived
runtime. This is a temporary compatibility boundary, not an excuse for a
long-lived receive loop. It is removed when the relevant worker bootstrap
adopts the same incremental OBIP readiness decoder.

## Safety invariants

- Readiness callbacks use `MSG_DONTWAIT` or a framework callback; a stale
  readiness notification must return without blocking.
- A stream frame is delivered only after its complete bounded header and body
  are buffered. Partial input remains private to its epoch.
- Timer, read, write, and close callbacks are fenced by the connection or IPC
  generation so an old descriptor cannot affect a replacement.
- Callback delivery never bypasses the owning request/reply or ChannelMux
  handoff; a received compatibility reply completes its waiter before normal
  unsolicited dispatch.
- A write path that shares a nonblocking descriptor owns a bounded output
  queue and write readiness source; it never assumes a full write.
