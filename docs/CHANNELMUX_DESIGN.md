# ChannelMux Design

## Purpose

This note records the current `ChannelMux` design as implemented in [bridge.py](../src/obstacle_bridge/bridge.py).

`ChannelMux` is the runtime boundary between:

- plaintext overlay session payloads coming from the transport and optional secure-link layers
- local TCP and UDP service sockets, plus Linux TUN packet interfaces, that are exposed through the overlay

Its job is not only routing. It also owns the service-facing semantics that differ between TCP streams, UDP datagrams, and packet-oriented TUN interfaces.

## Scope

This document covers:

- mux wire framing and channel identity
- local service publication and peer-installed services
- TCP control-plane setup for listeners, channels, and outbound dials
- TCP stream chunking at the service boundary
- UDP datagram forwarding at the service boundary
- Linux TUN interface setup and packet forwarding at the service boundary
- mux-level UDP fragmentation and reassembly
- mux-level TUN packet fragmentation and reassembly
- explicit UDP service-datagram caps and diagnostics

It does not redefine:

- lower transport/session framing in [ARCHITECTURE.md](./ARCHITECTURE.md)
- secure-link authentication and protection in [SECURE_LINK_DESIGN.md](./SECURE_LINK_DESIGN.md)
- black-box requirements in [REQUIREMENTS.md](./REQUIREMENTS.md)

## Current boundary

`ChannelMux` currently owns:

- channel ids and mux headers
- `OPEN`, `DATA`, `CLOSE`, and remote-service catalog control messages
- local TCP/UDP listener lifecycle for configured services
- local Linux TUN device lifecycle for configured services
- mapping between overlay channels and local TCP/UDP sockets or TUN devices
- TCP read chunking sized to the wrapped session budget
- UDP service datagram fragmentation when one mux `DATA` frame would exceed the effective session budget
- peer-side UDP service datagram reassembly before local `sendto(...)`
- TUN packet forwarding using nonblocking `/dev/net/tun` file descriptors
- TUN packet fragmentation when one mux `DATA` frame would exceed the effective session budget
- peer-side TUN packet reassembly before local interface injection
- per-channel counters and related diagnostics

`ChannelMux` does not own:

- transport-specific sockets for overlay carriage
- secure-link cryptography or identity policy
- `myudp` lower transport fragmentation and retransmission
- application-level protocol semantics above TCP or UDP payload forwarding

## Service and port setup

The mux starts from service specifications, not from ad-hoc per-connection rules.

Each `ServiceSpec` contains:

- `svc_id`
- `l_proto`, `l_bind`, `l_port`
- `r_proto`, `r_host`, `r_port`

The meaning is:

- the local side exposes a listener on `l_bind:l_port` using `l_proto`
- when traffic arrives on that listener, the peer is asked to reach `r_host:r_port` using `r_proto`

For TUN, the same six fields are reused with packet-interface meaning:

- `l_bind` is the local TUN interface name
- `l_port` is the local TUN MTU
- `r_host` is the peer-side TUN interface name
- `r_port` is the peer-side TUN MTU

For TCP, that means:

- a local TCP listener accepts real client connections on `l_bind:l_port`
- each accepted connection gets its own mux channel id
- the far side receives an `OPEN` control message that tells it which TCP target to dial
- the far side opens a normal TCP client connection to `r_host:r_port`

Services can come from two places:

- locally configured services
- peer-installed services received through `REMOTE_SERVICES_SET_V2`

That means the mux is responsible both for publishing local listeners and for materializing listeners requested by the connected peer.

### Example: one TCP service specification

Example service spec:

```text
svc_id=10
l_proto=tcp
l_bind=127.0.0.1
l_port=8080
r_proto=tcp
r_host=127.0.0.1
r_port=80
```

This means:

- the local mux listens on `127.0.0.1:8080`
- a local application connects to that listener
- `ChannelMux` allocates one TCP channel for that accepted socket
- the peer receives `OPEN(svc_id=10, l_bind=127.0.0.1, l_port=8080, r_host=127.0.0.1, r_port=80)`
- the peer dials `127.0.0.1:80`
- subsequent TCP bytes flow as mux `DATA` messages on that channel until one side emits `CLOSE`

So the mux listener port and the peer dial target port are intentionally different fields with different roles.

### Example: one UDP service specification

Example service spec:

```text
svc_id=20
l_proto=udp
l_bind=127.0.0.1
l_port=5353
r_proto=udp
r_host=127.0.0.1
r_port=5353
```

This means:

- the local mux binds a UDP socket on `127.0.0.1:5353`
- each local sender address tuple becomes one logical UDP channel context
- the peer is told, through the UDP `OPEN` metadata, which service and target tuple this traffic belongs to
- the peer creates or reuses the matching UDP client-side transport toward `127.0.0.1:5353`
- each UDP datagram remains one logical service message unless mux-level fragmentation is required

### Example: one TUN service specification

Example service spec:

```text
svc_id=30
l_proto=tun
l_bind=obtun0
l_port=1400
r_proto=tun
r_host=obtun1
r_port=1400
```

This means:

- the local mux creates Linux TUN interface `obtun0`
- the local interface MTU is set to `1400`
- packets read from `obtun0` are forwarded through one mux TUN channel
- the peer creates or reuses Linux TUN interface `obtun1`
- the peer-side interface MTU is set to `1400`
- packet boundaries are preserved end to end unless mux-level fragmentation is required

## Wire model

The primary mux header is:

- `chan_id:2`
- `proto:1`
- `counter:2`
- `mtype:1`
- `data_len:2`

That is an 8-byte header encoded as `>HBHBH`.

Current mux message types:

- `DATA`
- `OPEN`
- `CLOSE`
- `REMOTE_SERVICES_SET_V1`
- `REMOTE_SERVICES_SET_V2`
- `DATA_FRAG`

For TCP, the important control messages are:

- `OPEN`: begin one logical TCP channel and tell the peer which target to dial
- `DATA`: carry one TCP byte-stream chunk for that logical channel
- `CLOSE`: tear down that logical channel on the peer side

`DATA_FRAG` is the mux-level UDP service fragmentation message. Its payload starts with a fragment header:

- `datagram_id:4`
- `total_len:2`
- `offset:2`

followed by the fragment bytes for the original UDP service datagram.

For UDP, the important control and data messages are:

- `OPEN`: associate one logical UDP channel with a service and sender/target tuple
- `DATA`: carry one complete UDP service datagram when it fits inside the session budget
- `DATA_FRAG`: carry one fragment of a larger UDP service datagram
- `CLOSE`: tear down idle or obsolete UDP channel state

For TUN, the important control and data messages are:

- `OPEN`: associate one logical TUN channel with an interface name and MTU pair
- `DATA`: carry one complete TUN packet when it fits inside the session budget
- `DATA_FRAG`: carry one fragment of a larger TUN packet
- `CLOSE`: tear down the current channel binding while preserving configured service devices when appropriate

## TCP protocol

TCP in `ChannelMux` is connection-oriented. One accepted or dialed TCP socket maps to one mux channel id for the lifetime of that connection.

### TCP OPEN payload

The current TCP setup message uses the `OPEN v4` binary payload:

- magic: `O4`
- `instance_id:8`
- `connection_seq:4`
- `svc_id:2`
- `l_proto:1`
- `l_bind_len:1`
- `l_bind:l_bind_len`
- `l_port:2`
- `r_proto:1`
- `r_host_len:1`
- `r_host:r_host_len`
- `r_port:2`

For TCP channels, both `l_proto` and `r_proto` are expected to be `TCP`.

The extra metadata is not only descriptive. It is used for:

- validating that the channel setup really describes a TCP service
- binding channel identity to one service and one target tuple
- detecting peer epoch changes through `instance_id` and `connection_seq`
- avoiding stale channel reuse after reconnects or replayed control messages

Example decoded `OPEN v4` meaning:

```text
O4
instance_id=0x54A1...
connection_seq=12
svc_id=10
l_proto=tcp
l_bind=127.0.0.1
l_port=8080
r_proto=tcp
r_host=127.0.0.1
r_port=80
```

Interpretation:

- this `OPEN` belongs to mux runtime instance `0x54A1...`
- it was created during connection epoch `12`
- it corresponds to service `10`
- the originating side accepted traffic on local TCP listener `127.0.0.1:8080`
- the receiving side must dial TCP target `127.0.0.1:80`

### TCP listener-side flow

When a configured TCP listener accepts a local connection:

1. `ChannelMux` allocates a TCP channel id.
2. It records `svc_id`, the writer, and the channel role.
3. It sends one `OPEN` message carrying the `OPEN v4` payload.
4. It starts a read pump from the local TCP socket.
5. Each chunk read from the socket is emitted as one mux `DATA` message.
6. On EOF or error, it sends one mux `CLOSE` and tears down local state.

This is the server-facing half of the protocol: accept locally, signal remotely, then forward the stream as `DATA` chunks.

### TCP dialer-side flow

When the peer receives a TCP `OPEN` message:

1. It parses the `OPEN v4` payload.
2. It validates that the declared local and remote protocols are both TCP.
3. It checks peer epoch state using `instance_id` and `connection_seq`.
4. It builds an open-key from `peer_id`, `svc_id`, local bind tuple, and remote target tuple.
5. It stores that open-key against the channel.
6. It asynchronously dials `r_host:r_port` as a normal TCP client socket.
7. Once the socket is ready, it flushes any TCP `DATA` chunks that arrived before the dial completed.
8. It starts its own read pump from the newly dialed TCP socket back into mux `DATA` messages.

This is why TCP `DATA` can arrive before the outbound writer is ready: the mux allows a short pending queue during the asynchronous dial window.

### Example: end-to-end TCP channel lifecycle

```text
local app            mux A                    mux B               remote service
----------           ------------------       -----------------   --------------
connect -> 8080 ---> accept()
					 alloc chan=42
					 OPEN(chan=42, svc_id=10, r_host=127.0.0.1, r_port=80) ---->
												 parse OPEN
												 dial -> 127.0.0.1:80 ---------> connect

write "GET /" ----> DATA(chan=42, "GET /") -----------------------------------> write to TCP socket
												 DATA from remote socket <------- response bytes
<------------------ DATA(chan=42, response bytes)

close()              CLOSE(chan=42) -------------------------------------------->
												 close local dialed socket
```

Important points in this example:

- channel `42` names the logical TCP connection inside the overlay, not the OS file descriptor on either side
- one accepted TCP socket maps to one mux channel
- `DATA` carries ordered stream bytes, not request or response messages
- `CLOSE` tears down only that channel; the underlying overlay session can continue carrying other channels

### TCP DATA behavior

`DATA` messages for TCP carry raw byte-stream chunks only. They do not preserve application message boundaries.

Current behavior:

- local TCP reads are bounded by `SAFE_TCP_READ`
- each successful read becomes one mux `DATA` message
- received `DATA` is written directly to the mapped local TCP writer
- if the writer is not ready yet on the dialer side, the chunk is buffered temporarily

So TCP channel semantics are:

- preserve stream order
- do not preserve application write boundaries
- allow temporary buffering during channel establishment
- rely on the destination TCP stack to present a continuous byte stream to the application

### TCP CLOSE behavior

`CLOSE` is the symmetric teardown signal for one TCP channel.

It is emitted when:

- the listener-side accepted socket reaches EOF or pump failure
- the dialer-side outbound socket reaches EOF or pump failure
- the peer explicitly requests teardown for that channel

On receipt of `CLOSE`, `ChannelMux`:

- removes the channel from active TCP maps
- drops pending buffered data for that channel
- removes the stored open-key binding
- closes the local writer if it still exists

This keeps channel teardown explicit even though the underlying transport session may remain connected for other channels.

### Example: early DATA during asynchronous dial

There is a short race window where the receiver has accepted `OPEN` but has not yet finished `create_connection(...)`.

```text
1. mux A sends OPEN(chan=42)
2. mux A immediately sends DATA(chan=42, first bytes)
3. mux B has parsed OPEN but its outbound TCP writer is not ready yet
4. mux B stores the arriving DATA chunk in the per-channel pending queue
5. the outbound dial completes
6. mux B flushes pending DATA to the new TCP writer in arrival order
```

This avoids dropping the first TCP bytes just because the overlay control message and the local outbound connect complete at slightly different times.

### TCP channel identity and deduplication

TCP channel ids are not globally random. They are allocated from the local role-specific channel-id space and reused over time.

To keep reuse safe, the mux tracks:

- the active channel id
- the role of the channel
- the open-key tuple derived from the `OPEN v4` payload
- the peer epoch defined by `instance_id` and `connection_seq`

This combination prevents a stale `OPEN`, replayed control message, or reconnect boundary from being mistaken for a still-live TCP channel.

## TUN protocol

TUN in `ChannelMux` is packet-oriented, not stream-oriented.

The implementation is currently Linux-only and uses only Python standard-library facilities:

- `os.open` and `os.read` / `os.write`
- `fcntl.ioctl`
- event-loop `add_reader(...)`
- interface configuration through socket ioctls

### TUN OPEN payload

TUN uses the same `OPEN v4` payload shape as TCP and UDP.

For TUN channels:

- `l_proto` and `r_proto` are both `TUN`
- `l_bind` is interpreted as the source-side interface name
- `l_port` is interpreted as the source-side MTU
- `r_host` is interpreted as the destination-side interface name
- `r_port` is interpreted as the destination-side MTU

So the control plane stays structurally uniform even though the meaning of the bind and host fields is different from socket-based services.

### TUN listener-side flow

When a configured TUN service starts:

1. `ChannelMux` opens `/dev/net/tun`.
2. It creates the requested interface with `IFF_TUN | IFF_NO_PI`.
3. It sets the configured MTU.
4. It brings the interface up.
5. It registers an event-loop reader for the device file descriptor.

When a packet is read from the interface:

1. `ChannelMux` allocates a TUN channel id if the service has not been bound to one yet.
2. It sends one `OPEN` message carrying the interface-name and MTU metadata.
3. It sends the packet as one mux `DATA` message, or as `DATA_FRAG` messages if fragmentation is required.

### TUN dialer-side flow

When the peer receives a TUN `OPEN` message:

1. It parses the `OPEN v4` payload.
2. It validates that both protocol fields are `TUN`.
3. It checks the peer epoch using `instance_id` and `connection_seq`.
4. It binds the channel to an existing configured TUN service device when the requested interface name and MTU match.
5. Otherwise, it creates a non-service TUN device on demand using the requested peer interface name and MTU.
6. It registers the file descriptor with the event loop and binds the new channel to that device.

This keeps the control-plane symmetry with TCP and UDP while still allowing packet-interface semantics.

### TUN DATA behavior

`DATA` messages for TUN carry one complete packet.

Current behavior:

- packet boundaries are preserved end to end
- packets read from the local TUN file descriptor are forwarded as mux `DATA`
- packets received from the overlay are injected with `os.write(...)` into the bound peer TUN file descriptor
- packets larger than the device MTU are dropped at the local injection or receive side

So TUN channel semantics are closer to UDP than TCP:

- preserve packet boundaries
- do not merge adjacent packets into a stream
- require explicit reassembly when fragmented at mux level

### Example: end-to-end TUN lifecycle

```text
kernel/IP stack       mux A                     mux B                 kernel/IP stack
---------------       ---------------------     ------------------    ---------------
packet -> obtun0 -->  read(fd)
					  alloc chan=24
					  OPEN(chan=24, l_bind=obtun0, l_port=1400, r_host=obtun1, r_port=1400) --->
												parse OPEN
												create or reuse obtun1

IP packet --------->  DATA(chan=24, packet) --------------------------------------> write(fd)
```

The logical overlay channel represents the packet path between the two TUN devices, not a socket connection.

## Recovery-driven protocol changes

Several parts of the current mux protocol exist because connection recovery, reconnect, and replay-safe resynchronization turned out to be first-class requirements rather than edge cases.

### Problem: transport reconnect can leave stale channel state behind

The wrapped transport can disconnect and reconnect while the process stays alive.

Without extra mux identity, that creates ambiguity:

- an `OPEN` from the previous transport epoch can arrive late
- a peer can reconnect and start reusing channel ids
- the receiver can still have TCP writers, UDP transports, or installed listener state from the old epoch

If the mux protocol only used `chan_id`, old and new state could be confused.

### Applied change: epoch-tagged control messages

To solve that, `OPEN v4` and `REMOTE_SERVICES_SET_V2` carry:

- `instance_id`
- `connection_seq`

Current meaning:

- `instance_id` identifies the mux runtime instance
- `connection_seq` advances whenever the overlay reconnects or a hard transport resync occurs

The receiver tracks the latest `(instance_id, connection_seq)` seen per peer.

That allows it to:

- reject duplicate or replayed control messages from an older epoch
- recognize that a genuinely new peer epoch has started
- reset peer-owned channels before applying new control state

### Applied change: hard resync on transport epoch changes

When the transport reports an epoch change, the mux does not try to preserve half-open channel state.

Instead it performs a hard resync:

1. increment `connection_seq`
2. close all live TCP and UDP channel state
3. restart locally hosted services if the overlay is still connected
4. resend the remote service catalog

This is intentionally conservative. The protocol treats a transport epoch change as a boundary after which prior in-flight mux channel state is no longer trusted.

### Applied change: peer channel reset on new epoch

When a peer sends an `OPEN` or `REMOTE_SERVICES_SET_V2` from a newer epoch, the receiver first drops state that was created from the older peer epoch.

That includes:

- TCP channels created from prior `OPEN` messages
- UDP channels and their client transports created from prior `OPEN` messages
- TUN channels and their bound ephemeral TUN devices created from prior `OPEN` messages
- partial UDP fragment reassembly state
- partial TUN fragment reassembly state
- peer-installed listener services from the previous epoch

Only after that reset does the mux apply the new control message.

### Applied change: role-split channel-id space

The mux also splits channel ids by role:

- listener side uses even ids
- peer/client side uses odd ids

This reduces the risk of bidirectional `OPEN` collisions when both sides initiate channels around the same time.

Channel-id parity does not replace epoch tracking, but it makes simultaneous channel creation easier to reason about and reduces accidental overlap during recovery windows.

### Applied change: catalog-based listener resynchronization

Peer-installed listeners are synchronized with `REMOTE_SERVICES_SET_V2`, not by assuming that the previous listener set remains valid forever.

`REMOTE_SERVICES_SET_V2` carries:

- epoch metadata (`instance_id`, `connection_seq`)
- the full current service catalog requested by the peer

That means recovery is based on re-advertising the desired listener state, not trying to patch unknown leftover state incrementally.

This is one of the important reasons the current design uses a catalog message with epoch metadata rather than only per-channel setup messages.

### Hook-metadata transfer boundary

`REMOTE_SERVICES_SET_V2` currently transfers service endpoint fields only. It does not transfer service-level hook metadata such as `lifecycle_hooks` or `options`.

Implication:

- peer-installed services can be created from the advertised catalog
- hook execution for those peer-installed services requires an additional protocol extension if hooks are meant to execute on the receiving peer

Frame-budget constraint:

- any future hook-transfer extension must respect the effective session app-payload limit (commonly up to `65535` bytes, and sometimes lower depending on wrapping/session overhead)
- hook payloads (`argv`, `env`, per-event blocks, multiple services) can grow quickly, so a single-message naive embedding is not safe by default
- therefore remote hook transfer should use explicit sizing limits and, if needed, chunking/reassembly semantics in a versioned control message

### Recovery example: peer reconnect with stale channels

```text
1. peer A had TCP chan=42 and UDP chan=8 active
2. the transport drops and reconnects
3. peer A increments connection_seq and sends a new REMOTE_SERVICES_SET_V2
4. peer B sees a newer epoch for that peer
5. peer B drops TCP chan=42, UDP chan=8, and any partial UDP fragment state from the old epoch
6. peer B applies the newly advertised listener catalog
7. subsequent OPEN messages from the new epoch create fresh channels
```

This is the core recovery rule: epoch advancement wins over residual live channel state.

## TCP service behavior

TCP services are stream-oriented at the local boundary.

Current model:

- read from the local TCP socket in chunks of at most `SAFE_TCP_READ`
- wrap each chunk in one mux `DATA` message
- deliver each received mux `DATA` chunk directly to the destination TCP stream with `writer.write(...)`
- use backpressure helpers around the local writer so mux forwarding does not ignore TCP write-buffer growth

This means TCP does not require mux-level message reassembly. The destination TCP stack naturally reconstructs the byte stream.

## UDP service behavior

UDP services are datagram-oriented at the local boundary.

Current model:

- one local UDP datagram is treated as one logical service message
- if the full mux `DATA` message fits inside the effective session budget, it is sent directly
- if it would exceed the effective session budget, `ChannelMux` fragments the UDP service datagram into multiple `DATA_FRAG` mux messages
- the peer-side mux reassembles the original UDP service datagram before emitting one local UDP datagram with `sendto(...)`

This keeps the service-facing UDP contract intact even when the lower stack becomes tighter because of WebSocket text encoding, secure-link overhead, or other session-layer limits.

### Example: UDP datagram that fits in one mux DATA

```text
local app             mux A                           mux B               remote UDP service
---------             --------------------------      -----------------   ------------------
sendto("hi") -------> recvfrom()
							 DATA(chan=8, "hi") --------------------------------> sendto("hi")
																						  reply datagram <--------
<--------------------- DATA(chan=8, reply bytes)
```

In this case, the UDP service datagram fits within the effective session budget, so no mux fragmentation is needed.

### Example: UDP datagram carried through DATA_FRAG

```text
1. a local UDP datagram of 1400 bytes arrives on chan=8
2. mux A determines that one UDP DATA frame would exceed the current wrapped session budget
3. mux A assigns datagram_id=51
4. mux A emits:
	DATA_FRAG(chan=8, datagram_id=51, total_len=1400, offset=0, ...)
	DATA_FRAG(chan=8, datagram_id=51, total_len=1400, offset=chunk_size, ...)
	...
5. mux B stores fragments by (chan=8, datagram_id=51)
6. once all contiguous bytes are present, mux B rebuilds the original 1400-byte datagram
7. mux B emits one local UDP sendto(1400-byte datagram)
```

The service-facing UDP application still sees one datagram, even though the overlay carried it as several mux messages.

### Example: recovery while UDP fragments are in flight

```text
1. mux B has partial reassembly state for (chan=8, datagram_id=51)
2. a newer peer epoch is detected
3. mux B drops the old UDP channel state and fragment reassembly entry
4. fragments from the previous epoch are no longer allowed to complete delivery
5. the sender must re-establish traffic in the new epoch
```

This avoids reconstructing a UDP service datagram out of fragments that straddle a reconnect boundary.

## TUN service behavior

TUN services are packet-oriented at the local boundary.

Current model:

- one packet read from the local TUN file descriptor is treated as one logical service message
- if the full mux `DATA` message fits inside the effective session budget, it is sent directly
- if it would exceed the effective session budget, `ChannelMux` fragments the TUN packet into multiple `DATA_FRAG` mux messages
- the peer-side mux reassembles those fragments before injecting one packet into the destination TUN interface

This keeps packet boundaries intact for higher-layer IP traffic while still allowing the overlay budget to shrink because of SecureLink or text-encoded WebSocket transports.

### Example: TUN packet carried through DATA_FRAG

```text
1. a local TUN packet of 1400 bytes arrives on chan=24
2. mux A determines that one TUN DATA frame would exceed the current wrapped session budget
3. mux A assigns datagram_id=77
4. mux A emits several DATA_FRAG(chan=24, datagram_id=77, total_len=1400, offset=...)
5. mux B stores fragments by (chan=24, datagram_id=77)
6. once all contiguous bytes are present, mux B rebuilds the original 1400-byte packet
7. mux B injects one packet into the peer TUN file descriptor
```

### Example: recovery while TUN fragments are in flight

```text
1. mux B has partial reassembly state for (chan=24, datagram_id=77)
2. a newer peer epoch is detected
3. mux B drops the old TUN channel state and fragment reassembly entry
4. fragments from the previous epoch are no longer allowed to complete packet delivery
5. the sender must re-establish traffic in the new epoch
```

This avoids injecting a reconstructed packet into a TUN interface when the fragments belong to different reconnect epochs.

## Why mux-level UDP fragmentation exists

There are two different fragmentation problems in the system:

1. `ChannelMux` must preserve service-facing TCP/UDP semantics while respecting the wrapped session budget.
2. The `myudp` transport must carry one already-accepted session payload across unreliable UDP frames.

Those are different layers.

Mux-level UDP fragmentation solves the first problem.

`myudp` transport fragmentation solves the second problem.

Without mux-level UDP fragmentation, a local UDP service datagram that exceeded the current wrapped session budget would be dropped even though the lower transport might have been able to carry the resulting session payload across multiple packets.

## Explicit caps

The current implementation also enforces an explicit maximum UDP service datagram size.

Current cap inputs:

- local UDP payload ceiling: `65507`
- mux fragment header total-length field ceiling: `65535`

So the current maximum UDP service datagram that `ChannelMux` will accept or reassemble is:

$$
\min(65507, 65535) = 65507
$$

This cap is intentionally separate from the effective session payload budget.

The effective session payload budget determines:

- how large one mux `DATA` or `DATA_FRAG` message may be
- how large each UDP fragment chunk may be

The UDP service-datagram cap determines:

- the maximum size of the complete UDP datagram that the mux is willing to preserve end to end

## Diagnostics

At startup, `ChannelMux` logs:

- resolved session payload budget
- `SAFE_TCP_READ`
- UDP service datagram cap
- the active wrapped session stack description

That diagnostic is intended to make the effective runtime envelope explicit for operators.

Oversize UDP service datagrams are also logged when they are dropped:

- on local UDP ingress
- on direct overlay UDP delivery
- on UDP fragment reassembly

## Reassembly lifecycle and safety

Current UDP fragment reassembly state is keyed by:

- `chan_id`
- `datagram_id`

Safety controls currently include:

- TTL-based cleanup for incomplete reassemblies
- a cap on the number of in-flight reassembly entries
- bounds checks for `total_len`, `offset`, and fragment coverage
- cleanup on channel close and peer epoch reset

Current behavior is intentionally conservative:

- invalid fragment sequences are dropped
- oversize total lengths are dropped
- incomplete or expired reassemblies are discarded rather than partially delivered

## Open tradeoffs

The new mux-level UDP fragmentation makes the overlay safer by design, but it does not remove all lower-layer constraints.

Important remaining limits:

- the destination host must still be willing to accept the final reassembled UDP datagram size
- large UDP datagrams may still be a poor fit for real network paths even if the overlay can carry them internally
- memory usage and timeout policy for many concurrent fragmented UDP datagrams remain operational concerns

So the current design improves correctness at the overlay boundary, but it does not change the fundamental properties of UDP itself.
