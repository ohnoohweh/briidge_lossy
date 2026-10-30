# Swift Asynchronous I/O Boundary Plan

Every long-lived Swift communication receiver is owned by a readiness callback
or a framework callback. A receiver must not hold an arbitrary worker thread
in `read`, `recv`, `FileHandle.read`, `NSCondition.wait`, or a polling loop
while it waits for peer input. Stream receivers retain partial bytes and decode
only complete records after the next callback. Closing an owner cancels its
readiness source before its descriptor or channel is released.

`scripts/check_swift_async_io_guard.py` is required in pull-request CI. It
rejects newly added Swift `read`, `recv`, and `recvfrom` calls unless the call
is nonblocking or carries an inline, bounded-bootstrap exception marker. It
also rejects synchronous `poll`/`select`, condition/future waits,
`FileHandle.availableData`, and sleep-poll additions without that marker. The
guard is diff-based and applies to every Swift product source root, including
iOS, macOS, Linux, and shared code, so it prevents recurrence in files outside
the focused runtime tests while the remaining conversions are completed.

## Delivered boundaries

| Product | Boundary | Receive ownership | Evidence |
| --- | --- | --- | --- |
| Linux | myUDP, TCP, WebSocket, TLS WebSocket, QUIC outbound overlay | POSIX `DispatchSourceRead` or NIO inbound callback with incremental record buffers | `ObstacleBridgeLinuxOverlayTransportTests` |
| Linux | local TCP/UDP service sockets | nonblocking listener plus `MSG_DONTWAIT` drain on the serial service owner | `ObstacleBridgeLinuxServiceSocketOwnerTests` |
| Linux | in-process HTTP/SOCKS proxy listener admission | nonblocking listener plus readiness-owned accept-queue drain | `ObstacleBridgeLinuxProxyProviderTests.listenerReadinessDrainAdmitsEveryQueuedSOCKSClient` |
| Linux | inline TUN | `DispatchSourceRead` plus nonblocking TUN descriptor | `ObstacleBridgeLinuxTunDeviceTests` |
| Linux | helper control, packet, and event IPC | nonblocking listener/client `DispatchSourceRead` sources plus the shared incremental OBIP frame buffer | `ObstacleBridgeWorkerIPCTests.incrementalDecoderRetainsPartialFrameUntilReadinessDeliversItsRemainder`, `packetDeviceReceivesHelperPacketAndEventThroughReadinessSource` |
| macOS | packaged TUN-helper control, packet, and event IPC | nonblocking accepted-client `DispatchSourceRead` sources plus the shared incremental OBIP frame buffer | `test_macos_tun_helper_package_skeleton_sources_exist` |
| macOS Python helper | `utun` packet device | asyncio descriptor readiness plus bounded nonblocking FIFO drain | `test_tun_helper_macos_backend.py` |
| Linux and desktop | logging collector datagrams | `DispatchSourceRead` plus nonblocking bounded datagram drain | collector UDP record/query probe |
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
| Linux foreground and native-child Admin web servers | live-WebSocket polling loops | ordinary HTTP requests use per-client readiness sources with bounded reassembly; replace live polling with a timer-driven live-topic scheduler |
| Linux in-process HTTP/SOCKS proxy client parsing and relay | blocking per-connection reads | per-client readiness state machine with incremental HTTP/SOCKS buffers and queued write readiness |
| Linux native peer/Admin worker IPC | `FileHandle` framed reads after bootstrap | descriptor readiness source with generation-fenced incremental OBIP decoder |
| Linux TUN helper control IPC | synchronous request/reply reads | callback-based correlated control requests; preserve independent request deadline |
| Desktop logging supervisor query | bounded poll/receive request path | descriptor readiness handling and callback completion for bounded queries |
| macOS XPC helper control | semaphore wait around XPC reply | async XPC command completion propagated to the caller's lifecycle owner |

No remaining row above is a permitted synchronous fallback: each boundary owns a
descriptor or framework callback that can expose readiness/completion.  The
only allowed bounded synchronous operation is bootstrap validation before an
event-loop owner exists, with a deadline and generation fence; it must not be
used for a long-lived receiver.

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
