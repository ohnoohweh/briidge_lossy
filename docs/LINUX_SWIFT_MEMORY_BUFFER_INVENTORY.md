# Linux Swift Buffer Ownership Inventory

## Scope

The Linux native runtime shares Core FIFO, ChannelMux, SecureLink, myUDP
codec, TCP, QUIC, and WebSocket retention contracts with the Apple products.
This inventory records the Linux-specific owners that cross POSIX socket or
Dispatch boundaries.

| Owner | Retain boundary | Release boundary | Bound |
| --- | --- | --- | --- |
| myUDP delivered payload FIFO | `ObstacleBridgeLinuxMyUDPTransportSession` accepts Core-delivered records before synchronous or readiness-driven delivery. | `popFirst` transfers one synchronous payload; `drainAll` transfers a readiness batch; expiry drops stale records. | 256 items, 2 MiB, 60 seconds; newest records drop on overflow. |
| myUDP deferred outbound-wire FIFO | A nonblocking POSIX `send` returning `EAGAIN` retains the validated wire until the timer retry. | Successful retry pops the wire; `close` clears the FIFO; expiry drops stale wires. | 512 items, 2 MiB, 60 seconds; newest records drop on overflow. Admin protocol stats project retained items, bytes, and drops. |
| initial authenticated payload FIFO | `ObstacleBridgeLinuxConfiguredSession` retains a protected frame that arrives while peer-address setup completes. | The receive owner transfers `popFirst`; `close` clears the FIFO. | 128 items, 2 MiB, 60 seconds; newest records drop on overflow. |
| native Admin live-session writes | A partially written WebSocket frame remains the one active POSIX write; later browser updates enter `LiveSession.pendingWrites`. | Partial writes shrink the active frame; completed frames advance the FIFO; session finish clears both. | One active frame plus 128 queued frames, 2 MiB, and 60 seconds; overflow closes the affected live session. |
| receive-worker handoff FIFO | `ObstacleBridgeLinuxReceiveWorker` accepts one lower-transport record before serial ChannelMux dispatch. | Dispatch transfers `popFirst` to the sink; `stop` clears the FIFO. | Default 128 items, 2 MiB, 60 seconds; newest records drop on overflow. Snapshot reports depth and retained bytes. |
| POSIX read drains | myUDP readiness and receive-worker dispatch drain already-ready records. | Each callback yields after its packet or byte budget, letting Dispatch schedule the next turn. | At most 64 records or 2 MiB per drain turn. |

## Contract

Persistent payload retention uses `ObstacleBridgeBoundedDataFIFO` on the
owner's existing lock or serial queue. Each owner declares item, byte, and age
limits, a drop policy, and a teardown release boundary. A raw persistent
`Data` queue is rejected by the Swift memory-safety diff gate unless it carries
an explicit ownership, bounds, and regression-test rationale. POSIX sends do
not create an unbounded retry history: one kernel submission is attempted at a
time and deferred wires remain inside the bounded FIFO.

The regression suite overfills the Linux receive-worker handoff while its sink
is blocked, verifies retained bytes never exceed the configured limit, verifies
the defined dropped-frame count, and verifies `stop()` releases all retained
bytes. Shared Core FIFO tests cover byte/item overflow policies, expiry, drain,
and explicit release.
