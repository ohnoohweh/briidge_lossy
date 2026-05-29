# MyUDP Design

## Purpose

This document records the current `myudp` transport design as implemented in [bridge_transport_udp.py](../src/obstacle_bridge/bridge_transport_udp.py).

The whitepaper explains why a UDP-based reliable overlay exists at all. This note stays closer to the runtime:

- frame layout
- RTT measurement
- retransmission behavior
- receiver gap tracking
- the specific resend invariant that every transmitted frame must carry fresh transport timestamps

It is a design note for the delivered implementation, not a speculative rewrite plan.

## Scope

This document covers:

- the `Protocol` envelope used by `myudp`
- `DATA`, `CONTROL`, and `IDLE` frame responsibilities
- how RTT samples are derived from echoed transport timestamps
- how receiver gap tracking feeds retransmission
- why stale raw-frame resend is incorrect even when the application payload is unchanged

It does not redefine:

- product requirements in [REQUIREMENTS.md](./REQUIREMENTS.md)
- mux semantics in [CHANNELMUX_DESIGN.md](./CHANNELMUX_DESIGN.md)
- secure-link behavior in [SECURE_LINK_DESIGN.md](./SECURE_LINK_DESIGN.md)

## Layer split

`myudp` currently has one timestamp-bearing layer:

1. The protocol envelope header.

The important current rules are:

- RTT-relevant transport timestamps live in the outer protocol envelope, not in the `DataPacket` payload.
- `DataPacket` payloads are intentionally semantic-only and do not carry transport timestamps.

`DataPacket.build_payload(...)` is intentionally payload-only. It encodes:

- packet counter
- frame type
- total length or fragment offset
- chunk length
- payload bytes

The transport envelope added by `Protocol.build_frame(...)` then wraps that payload with:

- `ptype`
- payload length
- `tx_ns`
- `echo_ns`

That means a resend is not correct unless the outer protocol envelope is rebuilt.

## Frame roles

`myudp` currently uses three protocol-level frame classes:

- `IDLE`: keepalive and RTT refresh path
- `DATA`: application payload carriage with packet counters and fragmentation metadata
- `CONTROL`: ACK/loss feedback path carrying `last_in_order`, `highest_rx`, and a bounded missing-counter list

The receive side uses packet counters to track:

- what has been delivered in order
- what is pending out of order
- which counters are considered missing

The send side uses `CONTROL.missed` to decide which outstanding `DATA` counters need retransmission.

One recovery rule is especially important under loss:

- once a counter has been reported missing by the peer, omission from later feedback is not treated as a positive ACK by itself

That rule exists because `CONTROL` frames are lossy too. A sender must not assume that a previously missing counter is repaired merely because one later feedback sample did not mention it.

The missing list is also intentionally bounded by `CONTROL_MAX_MISSED`.
When feedback reaches that cap, omission from the list is even less trustworthy as evidence of repair, because the receiver may be truncating loss feedback rather than signaling successful delivery.

## RTT measurement

The RTT algorithm is deliberately lightweight.

When sending any protocol frame, `Protocol.build_frame(...)` stamps:

- `tx_ns`: local monotonic send time for this frame
- `echo_ns`: a local estimate derived from the most recently received peer frame

The current echo formula is:

```text
echo_ns = last_rx_tx_ns + (now_tx_ns - last_rx_wall_ns)
```

where:

- `last_rx_tx_ns` is the peer frame's original `tx_ns`
- `last_rx_wall_ns` is the local monotonic time when that peer frame was received
- `now_tx_ns` is the local monotonic time for the outgoing frame being built

On receive, if `echo_ns != 0`, the implementation treats:

```text
RTT sample = now_monotonic_ns - echo_ns
```

and feeds that sample into the transport EWMA.

So the RTT signal depends on the transport envelope timestamps of the frame that actually went onto the wire.

## Why resend must rebuild the frame

Resending a previously serialized raw datagram is wrong for RTT accounting.

If an older raw frame image is reused unchanged, then:

- `tx_ns` stays frozen at the original send attempt
- `echo_ns` stays frozen at the original echo basis
- the receiver sees a packet that looks like it was just received but claims to have been sent much earlier
- any RTT sample derived from its echoed timestamp path is biased by retransmission delay rather than representing the true transport turn

That makes the transport observability misleading in exactly the cases where we most need it:

- loss recovery
- reorder-heavy paths
- long retransmission windows
- device-to-host forensic log analysis

The correct resend invariant is:

- every actual wire send gets a freshly rebuilt protocol envelope with fresh `tx_ns`
- `echo_ns` is recomputed from the sender's latest receive-side view at the time of resend

The application payload bytes may be identical across attempts, but the transport envelope must not be identical.

## Transmit delay measurement

`myudp` now tracks a second transport-quality metric in addition to RTT:

- `transmit_delay_ms`

This metric is intentionally not the same as raw one-way propagation latency.
It is an estimate of the effective one-way delivery delay that a `DATA` frame experienced before it became acknowledged.

Current design rules:

- the first on-wire `tx_ns` for a `DATA` frame is stored when that counter is first emitted
- if the frame had to wait because `max_in_flight` was saturated, the sender also keeps the earlier local queue-entry timestamp
- retransmission does not overwrite those first-attempt timing references
- when feedback cumulatively acknowledges the frame and it leaves the send buffer, the sender computes:

```text
transmit_delay_sample_ms = ack_elapsed_ms - 0.5 * current_rtt_est_ms
```

where:

- `ack_elapsed_ms` is the local monotonic time since the start of the frame's effective send path
- `current_rtt_est_ms` is the sender's current RTT EWMA at ACK time

The effective send-path start is defined as:

- immediate send with no pre-buffering: the first emitted frame's stamped `tx_ns`
- queued send after in-flight saturation: the time when the segment first entered the local wait queue

The sample is clamped at `>= 0` and then fed into its own EWMA:

- `transmit_delay_sample_ms`
- `transmit_delay_est_ms`

This definition intentionally includes queueing and loss-recovery cost from the sender's point of view:

- if a frame is delivered on the first attempt with no local queue wait, transmit delay tends to stay close to one-way path plus normal sender/receiver scheduling cost
- if the sender had to pre-buffer because the in-flight window was full, that local queue wait is included
- if a frame requires retransmission, the metric grows because the first-attempt timing reference is preserved

That behavior is deliberate. The metric answers:

- "how long did this payload effectively take to get through the tunnel and become acknowledged?"

not:

- "what was the propagation delay of the last successful wire attempt?"

For operator observability that is usually the more useful number, because it rises under:

- congestion
- scheduler delay
- retransmission pressure
- ACK/recovery inefficiency

RTT and transmit delay should therefore be read together:

- RTT: transport round-trip responsiveness based on the frame that actually went onto the wire
- transmit delay: effective one-way payload delivery delay as experienced by acknowledged `DATA`, including sender-side pre-buffering and retransmission cost

The key consistency rule between the two metrics is:

- `tx_ns` in the protocol envelope must always reflect the actual emission time of that specific wire image, both for the first send and for every retransmission
- transmit-delay bookkeeping may preserve older first-attempt or queue-entry timing locally, but that local bookkeeping must never replace the on-wire `tx_ns` used for RTT

## Missing metadata and stale raw frames

The sender keeps two different representations of an in-flight `DATA` frame:

- semantic resend metadata in `send_meta`
- the last serialized raw bytes in `send_buf`

The semantic metadata is the authoritative source for retransmission because it lets the runtime rebuild a fresh frame.

The last raw bytes in `send_buf` are only a record of the most recent send image. They are not safe to replay as a fallback for RTT-correct retransmission.

Current design rule:

- if `send_meta[counter]` is missing, the transport skips retransmission for that counter instead of replaying the stale raw datagram from `send_buf[counter]`

That is a deliberate fail-safe:

- skipping one retransmit is preferable to polluting RTT and transport-debug signals with forged stale send timing
- a missing `send_meta` entry is itself diagnostic information and should be logged rather than hidden by a misleading raw resend

## Persistent Missing-Frame Retry

The current transport now distinguishes between:

- generic unconfirmed send state
- peer-reported missing counters

Generic unconfirmed state still matters for broad reliability, but peer-reported gaps need stronger handling because they are already known to be blocking forward progress somewhere on the far side.

Current design rule:

- once the peer reports a counter as missing, that counter enters a persistent missing set
- while it remains unconfirmed, the sender schedules another resend on roughly an RTT cadence
- the sender does not clear that obligation merely because a later `CONTROL` packet omits the counter
- the obligation is cleared only by real sender-side confirmation, primarily cumulative ACK progress that moves `last_in_order` past the counter

This protects the protocol against a very practical failure mode:

- frame `5000` is missing
- the receiver keeps operating at the edge of the flight window and continues to report evolving loss feedback
- one or more `CONTROL` packets are themselves lost or incomplete in diagnostic terms
- without persistent retry state, the sender can stop focusing on the oldest blocking frame even though that frame was never actually acknowledged

The intended resend behavior for a reported gap is therefore:

1. The first missing report triggers immediate retransmission eligibility.
2. If the frame still is not cumulatively acknowledged, the sender retries it again after about one RTT.
3. This continues until the sender has positive confirmation that the frame is no longer outstanding.

This is intentionally more robust than “resend only when the newest feedback still mentions the same counter”.

## Receiver gap tracking

The receiver maintains:

- `expected`
- `pending`
- `missing`

Behavior:

- an in-order `DATA` frame advances `expected`
- an ahead-of-expected frame is parked in `pending`
- skipped counters are inserted into `missing`
- when the missing frame arrives later, delivery resumes and any contiguous pending frames are drained

This state is what the sender sees indirectly through `CONTROL` feedback.

The retransmit path therefore depends on two contracts holding at once:

1. The receiver must report the correct missing counters.
2. The sender must rebuild fresh frames for those counters when retransmitting.

If either side is wrong, recovery may still appear to work at the payload layer while the RTT/debug picture becomes untrustworthy.

## Reset semantics

Sender reset and receiver gap tracking are intentionally separate concerns.

Resetting sender-side retransmission state should clear:

- queued/in-flight send bookkeeping
- resend attempt counters
- outstanding raw/send metadata

It should not silently rewrite receiver-side `expected`, `pending`, or `missing` state unless the design is explicitly resetting the receive epoch too.

That separation matters because reconnect and recovery bugs often show up as a mixture of:

- stale sender retransmission state
- still-valid receiver gap state
- misleading logs that make the two look equivalent

## Testing guidance

The missing-doc case that triggered this note is a good example of where unit tests are the right tool.

The most important unit-level transport invariants are:

- retransmission must rebuild a fresh protocol envelope
- retransmitted frames for the same packet counter must differ on the wire from the original send image
- the retransmit path should produce a later `tx_ns` than the original send
- once receive history exists, retransmit should also carry a non-zero freshly computed `echo_ns`
- if semantic resend metadata is missing, the runtime should skip stale raw-frame replay
- once a counter has been reported missing, later omission from feedback must not silently clear the resend obligation
- a peer-reported missing counter should continue to be retransmitted on an RTT cadence until cumulative ACK state confirms it
- acknowledged `DATA` frames should produce a transmit-delay sample from first-send time minus half the current RTT
- the averaged transmit-delay metric should become observable through the runtime status/dashboard path
- tests should cover operation near the in-flight window limit so head-of-line recovery is validated under pressure, not only in tiny toy sequences

Those checks are stronger than an end-to-end “payload still arrived” integration result, because payload delivery can succeed even while the RTT signal is already corrupted.

The current focused regression anchor for these invariants is [tests/unit/test_requirements_unit_gaps.py](../tests/unit/test_requirements_unit_gaps.py).
